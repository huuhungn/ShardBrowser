# G2-64 independent verification report

## Scope and revision

Repository: `C:\Users\User\dev\wt\shardbrowser-g264b-codex`.

Revision checked: `aef00845cb83bfa2c223d72dc0515c8f4bfbd729` (detached `HEAD`, clean worktree). No repository files were changed. The only output file created is this report. I did not read `.omc/`, `.omx/reports/`, or any scratch/report directory; the packet README, plan, ADR, source, tests, fixtures, manifests, and lockfiles were the sources used.

The `evidence-gate-verification` workflow was applied: the frozen plan/ADR were read first, checksums were verified, cited structures were enumerated, negative probes were run, command exit codes were preserved, and independent source/test coverage was compared.

## Commands and outcomes

| Check | Outcome |
|---|---|
| `python scripts/g2-evidence.py --check` | PASS: `120 files checked, 0 problems` |
| Packet row commands (G2-01 through G2-63, excluding the owner-deferred manual row) | 96 commands executed with `-j 2`; 70 exited 0 and 26 exited nonzero. All 266 unique cited test names were found as definitions; none were missing. No cited test had an adjacent `#[ignore]`. The few source `return` statements are environment/child-process branches, not empty tests. |
| `cargo +stable fmt --check` for `shared`, `server`, `src-tauri`, `sdks/rust` | 4/4 PASS |
| `cargo +stable clippy --locked --all-targets -- -D warnings` for `src-tauri`, `shared`, `server` | 3/3 PASS |
| Full `cargo test --locked` for `shared` | 281 passed, 19 failed, 0 ignored in the library run; failures are DPAPI-backed backup/cookie/snapshot tests and the unreachable SMB probe. |
| Full `cargo test --locked` for `server` | 104 passed, 2 failed, 2 ignored; both failures are SMB refusal tests aborting because the configured UNC path is unreachable. |
| `cargo test --locked --lib` for `src-tauri` | 405 passed, 98 failed, 11 ignored; the failures are overwhelmingly DPAPI-backed credential/team-sync paths, plus the SMB volume test. |
| MSRV checks (`cargo +1.87.0 check` shared, `+1.89.0` server, `+1.88.0` src-tauri; locked/all-targets, `-j 2`) | 3/3 PASS. All three toolchains were installed. |
| `cargo +stable build --locked --manifest-path server/Cargo.toml -j 2` | PASS |
| `npm.cmd run test:i18n` | 16/16 PASS |
| `npm.cmd run test:rust-strings` | 3/3 PASS |
| `npm.cmd run test:backend-locale` | 7/7 PASS |
| `npm.cmd run test:raw-error-toast` | 2/2 PASS |
| `cargo audit` with the packet’s ignore list | BLOCKED: the tool could not lock/update the read-only advisory database at `C:\Users\User\.cargo\advisory-db..lock`; no advisory result was obtained. |
| `gh run list` | BLOCKED by the environment’s denied GitHub API connection; no CI result for this revision was read. |

For every cargo test invocation I set `CARGO_TARGET_DIR=C:\Users\User\AppData\Local\Temp\g264-target-codex`, passed `-j 2`, and set `SHARDX_TEST_SMB_DIR=\\localhost\C$\Users\User\AppData\Local\Temp\g264-smb` as required. There was no `SKIPPED` line. Instead, SMB probes explicitly panicked with `... is not reachable`; PowerShell also reported access denied when probing that UNC path. The G2-55 network-data-directory test passed, but the shared/server SMB refusal branches could not execute to completion.

## Per-row findings and sampled source review

All packet citations were checked for file existence and all 266 cited test names resolved to real Rust test functions. The required deep sample and additional rows were read through the implementation paths they exercise:

| Row | Independent finding |
|---|---|
| G2-01 | Server approval replay/container equality/startup quarantine and shared authorization golden-vector tests exist and passed. |
| G2-07 | Snapshot payload/container field-defect, signer binding, sealed-envelope binding, and golden-vector tests exist and passed. |
| G2-10 | Closed-map, slot-context, slot/intention binding, open-map refusal, and vectors exist and passed. |
| G2-12 | Restore leaves/proofs, ordering/uniqueness, tamper and cross-context checks exist and passed. |
| G2-14 | Mutation map/closed-field/vectors and revocation activation-atomicity tests exist and passed. |
| G2-21 | Server lease/fence/replay passed. Launcher publish tests are real assertion-heavy tests, but both failed before the assertions at `src-tauri/src/team/sync.rs:4177` because DPAPI protection failed. |
| G2-27 | STREAM framing, final-frame, preamble, counter-bound and vectors exist and passed. |
| G2-28 | RFC HPKE vectors, info/AAD binding, wrong-device/tenant/epoch and fleet-key open tests exist and passed. |
| G2-29 | RFC8032, strict speccheck, issuer/bytes binding and signed-container vector tests exist and passed. |
| G2-30 (required) | `server/tests/v2_auth.rs:9609` mutates every persisted revocation field, tests response mismatch, startup quarantine, instance mismatch, runtime quarantine, repair and replay behavior. The server half passed. The launcher reload test at `src-tauri/src/team/sync.rs:6369` is assertion-heavy and correctly checks tenant/instance/key/container identity, but could not reach its assertions because DPAPI failed. |
| G2-31 (required) | The server custody matrix at `server/tests/v2_auth.rs:10642` and profile matrix at `server/tests/v2_profiles.rs:3971` perform real mutations, restart the same DB, compare stored response bytes and assert no second resource. Both server commands passed. The launcher replay command failed at DPAPI setup. The `OperationKind::ALL` match is exhaustive and asserts the expected ownership of every operation kind, including `LocalUnbind`. |
| G2-35 (required) | `src-tauri/src/team/records.rs:487` changes every mapped column with constraints disabled and demands a ledger-unreadable error for non-local drift; the second-self-grant/cross-instance FK and duplicate-row tests are substantive. The command reached and passed the record/ledger portions but two sync tests failed at DPAPI setup. |
| G2-41 (required) | Journal tests at `src-tauri/src/team/journal.rs:701` cover close/reopen phase order, terminal/repeat/skip refusal, fixed crash tables, digests and downgrade rollback. The downgrade crash tests passed. The sync unbind guard test failed at DPAPI setup. The packet explicitly records that the production restore writer is out of scope; this is a stated limitation rather than hidden evidence. |
| G2-42 (required) | Both local integer-range tests passed. They assert `0` and `i64::MAX` survive reopen, reject negatives/overflow/fractions/non-integer values, and accept only the Q-43 lossless SQLite coercions. The server G2-45 integer-domain tests also passed. |
| G2-43 (required) | The seven local replay/crash tests are real state-machine tests. The command could not execute the sync fixtures because DPAPI failed before setup. |
| G2-44 | Fresh/upgrade migration fixtures and the quarantine-hash migration tests passed. |
| G2-46 | Argon2id RFC vector and labelled-salt derivation tests passed; the packet’s p=1 local-backup deviation is documented. |
| G2-47 | All 17 cited secrecy/zeroization/debug/reference tests passed. The packet correctly calls this type-level evidence; no test observes freed-memory contents. |
| G2-49 (required) | Local durable-write/replace/kill tests passed. The local NTFS checks passed. The three SMB refusal tests failed at their reachability guard because the required UNC share returned access denied; they did not silently skip. |
| G2-50 | SQLite rollback-journal, kill ordering, busy-writer and launcher WAL refusal tests passed. The shared/server SMB portions failed for the same unreachable UNC path. |
| G2-52 | The full restore crash table test passed and the per-row restore tests were also executed. |
| G2-55 (required) | The durable-preparation, audit failure counting, K2 incident output, count-file corruption, and network-data-directory tests all passed. The K2 test itself creates an identity record for another instance and asserts the L2264/K2 classification, so the packet’s G2-59 cross-reference is substantive. |
| G2-61 | Pure backup/envelope tamper, truncation, splice and HPKE tests that do not require DPAPI passed. Backup-file and launcher profile/sync tests that call DPAPI failed during fixture sealing, so confidentiality/tamper behavior was only partially executable here. |
| G2-63 (required) | `shared/tests/registry_pins.rs` exhaustively checks domain/label uniqueness and numeric registry values; `shared/src/keys.rs` checks profile-label binding, length bounds, bucket padding, canonical padding and the golden vector. All eight tests passed. |

The sampled plan lines and ADR decisions matched the cited criteria: G2-30/G2-31 use the plan’s L2338 response/equality and L1424/L2048 replay requirements; G2-35 uses L2040/L2034/L2058; G2-41 uses L2046; G2-42 uses L2047 and ADR Q-43; G2-43 uses L2048; G2-49 uses L2337/L1175/L2250 and Q-30/Q-39; G2-55 uses L2262 and Q-38; and G2-63 uses L2341 and Q-41/D-8.

## B1–B7, N1–N2, and SMB follow-up

- **B1 (root-path exposure) and B2 (exposure forgotten after recollection):** `ledger.rs` now persists `trust_key_holdings` and `trust_fleet_activations`, computes the root bound from activation evidence, treats missing root evidence and a known custodian with no root holding as exposed, and never deletes holdings. `commit_blocked` reads those durable rows before allowing a commit. The regression tests `a_compromised_custodian_blocks_every_fleet_through_the_root` and `an_exposure_survives_a_recollection_that_omits_its_grant` are assertion-heavy and directly exercise the failure scenarios. They failed before their assertions with DPAPI, so source review supports closure but independent execution is blocked.
- **B3 (OPEN upload/checkout ordering):** `sync.rs` handles an `OPEN` upload before sending a stored finalize, calls the server abort endpoint, marks the local operation failed, releases the lease, and refuses a subsequent push before checkout. The tests `an_open_upload_is_aborted_once_a_compromise_is_counted`, `a_compromise_counted_mid_transfer_aborts_the_upload`, `a_stored_finalize_is_not_sent_once_a_compromise_is_counted`, and `a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code` encode the intended failure scenarios. They could not reach setup because DPAPI failed.
- **B4 (fleet-scoped revocation):** `src-tauri/src/lib.rs:3580` tests that a fleet-scoped `device.revoke` counts only for a member approved in that fleet, while a tenant-approved member requires tenant-scoped duty. The test is substantive; it failed at the DPAPI-backed launcher fixture setup. The server revocation route also validates the scope before filing.
- **B5 (activation list):** `shared/src/mutation.rs:1082-1111` accepts 0 through 65535 strictly sorted unique activations and rejects 65536 or malformed entries. `server/src/routes/v2_device_revoke.rs:689-729` applies each activation in the same transaction before inserting the revocation. The shared parser/vector and server atomicity commands passed; this finding is independently closed.
- **B6 (Q-43):** ADR Q-43 explicitly defines which SQLite REAL/TEXT coercions are rejected and which lossless values are accepted. Both local G2-42 tests and server integer-domain G2-45 tests passed. The decision is consistent with the server’s SQLite column behavior and the launcher’s typed `i64` bindings; this finding is independently closed.
- **B7 (operation matrix):** The two server matrix tests enumerate `OperationKind::ALL`, perform real route mutations, restart and replay exact bytes, assert state/resource counts, and reject a different request hash. A new enum variant would make the exhaustive match fail to compile. The server matrix passed. Launcher-side replay/LocalUnbind execution is blocked by DPAPI.
- **N1 (lost then compromised):** `ledger.rs:830-849` leaves the earliest evaluation count intact but explicitly updates a kept non-compromised revocation when the later counted record is `compromised`; a later non-compromised record cannot replace it. The named regression test asserts the block starts and remains. It could not run because DPAPI failed at setup.
- **N2 (stored FINALIZE):** The `OPEN` branch at `sync.rs:1492-1518` performs the compromise check before sending any stored finalize; `abort_compromised` calls the server abort endpoint and marks local state. The named regression test asserts the original finalize is the only attempted send and that no commit follows. It could not run because DPAPI failed at setup.
- **SMB gap:** The requested path was set exactly. The machine’s loopback administrative share was inaccessible, and shared/server tests reported `SHARDX_TEST_SMB_DIR ... is not reachable`; there were no skip lines. This is an essential unverified branch, not evidence that the branch passes.

## Discrepancies and coverage limits

1. The packet README says its “code under review” is `fe8c8e36`, while the checked-out and hashed tree is `aef00845cb83bfa2c223d72dc0515c8f4bfbd729`. `SHA256SUMS` is internally consistent with the current tree (`--check` passed), but the packet’s prose revision metadata is stale and there is no current CI result for `aef00845`.
2. G2-48 remains PENDING-MANUAL exactly as the owner directed. Its automated OS-store persistence test also failed here with `NoStorageAccess(PlatformError(1312))`; the owner’s release exception does not turn that into reproduced evidence.
3. Cargo audit could not run because its advisory database is on a read-only path and network access is denied. G2-62 therefore remains unverified for advisories in this environment, although the MSRV and manifest/lockfile checks completed.
4. The full launcher suite has 98 failures and the affected packet commands fail at DPAPI protection before their assertions. This prevents independent dynamic verification of the B1–B4/N1/N2 launcher fixes, G2-21/22/23/24/25/26/30/31/33/34/35/36/37/38/39/41/43, and the DPAPI-dependent portion of G2-61.
5. G2-47’s zeroization claim is explicitly type-level (`ZeroizeOnDrop`/redacted `Debug`); no test observes freed memory. That is documented in the packet and is not an undisclosed gap.
6. The packet’s accepted limitations remain visible and consistent: no Team UI, no production restore-journal writer in this scope, local backup p=1, and the accepted two-step revocation-row swap limit. I found no additional security property with a cited test that was absent from the source; the material unexecuted properties are the DPAPI, SMB, advisory DB, manual credential-store and current-CI items above.

## What could not be verified

A PASS requires the plan’s explicit reproducible evidence for credential-store persistence, directory/network-share durability, and all launcher paths. The current environment prevents those essential checks: DPAPI protection/credential-store access is unavailable, the requested SMB share is unreachable, cargo-audit cannot update its advisory DB, and GitHub Actions cannot be queried. The source and test review supports several fixes, and B5/B6 plus the server-side B7 matrix passed, but that is insufficient for a verifier PASS.

VERDICT: BLOCKED
