# Independent G2-64 verification report

Repository: C:/Users/User/dev/wt/shardbrowser-g264b-hermes
Commit: aef00845cb83bfa2c223d72dc0515c8f4bfbd729
Build directory: C:/Users/User/AppData/Local/Temp/g264-target-hermes
Verifier: independent repository-only run

## Scope and safety

I did not read `.omc/`, `.omx/reports/`, scratch directories, or the earlier verifier reports. I made no repository changes, commits, pushes, GitHub writes, production connections, or worktree changes. I did not run the tests which create/read/delete a real Windows Credential Manager entry, because the instruction expressly prohibited touching those entries. The only created report is this file.

## Commands and outcomes

- `python scripts/g2-evidence.py --check`: PASS — `120 files checked, 0 problems`.
- Repository state: detached HEAD at the requested SHA; clean status before and after verification.
- Toolchains: stable rustc/cargo 1.99.1; MSRV toolchains 1.87.0, 1.88.0 and 1.89.0 were installed.
- `cargo +stable fmt --check` for `shared`, `server` and `src-tauri`: 3/3 PASS.
- `cargo +stable clippy --locked --all-targets -- -D warnings` for `shared`, `server` and `src-tauri`: 3/3 PASS.
- `cargo +1.87.0 check --locked --all-targets` for `shared`: PASS.
- `cargo +1.89.0 check --locked --all-targets` for `server`: PASS.
- `cargo +1.88.0 check --locked --all-targets` for `src-tauri`: PASS.
- Shared full test run with the requested SMB variable and `-j 2`: PASS — 300 passed, 0 failed, 0 ignored. The SMB branch `volume::tests::an_smb_share_is_refused` ran and passed.
- Server full test run with the exact UNC value and `-j 2`: PASS, exit 0; the SMB branch `db::tests::storage_on_an_smb_share_is_refused` ran and passed. No `SKIPPED` line was observed in the corrected run.
- Launcher `cargo test --lib` run with the two tests that access the real OS credential store excluded: PASS, exit 0. The automated mock-store/key-file tests ran. The real Credential Manager tests were deliberately not run.
- The packet's per-row cargo commands for G2-01 through G2-63: 62 command headings were present and 62 command invocations completed with exit 0; no cited command reported a failed test. G2-48 is separately marked PENDING-MANUAL and was not treated as completed.
- Interface checks: `npm run test:i18n` 16/16 passed; `npm run test:rust-strings` 3/3 passed; `npm run test:backend-locale` passed; `npm run test:raw-error-toast` passed as part of the same npm gate.
- CI evidence: `gh run view 41343000374 --repo huuhungn/ShardBrowser --json ...` reports `success` for commit `aef00845...`; the read-only log contains successful shared, server and launcher test summaries and no relevant SMB skip. No GitHub write command was used.

An initial server invocation used a shell-escaped UNC value with two leading separators in the environment and correctly failed its SMB reachability assertion. I corrected the environment by constructing the exact UNC string (`\\localhost\C$\Users\User\AppData\Local\Temp\g264-smb`) directly in Python and reran. The corrected run reached the share and passed. This is an execution discrepancy, not a repository finding.

## Packet and row audit

The packet contains exactly 64 rows: 62 DONE, G2-48 PENDING-MANUAL, and G2-64 the packet's prior FAIL/verifier row. The commands section contains cited commands for G2-01 through G2-63; G2-64 is the independent verification deliverable rather than a normal cargo test row.

I checked every cited test name against the cited source file and read the implementations and nearby production paths. The cited tests are real Rust tests, have substantive assertions, and are not `#[ignore]` tests or unconditional early-return tests. The ignored child-process helpers are not used as the cited evidence; their parent crash-harness tests are the cited tests and execute the assertions.

Per-row sampled findings:

- G2-01 to G2-06: the authorization containers and server all-column comparisons exist and passed. The server tests compare stored columns against the signed container rather than merely checking status codes; the shared golden-vector tests pin the encoded records.
- G2-07 to G2-15: snapshot, envelope, slot, intent, grants, signing and idempotent-response tests exist and passed. The envelope tests exercise malformed preambles/frames and counter limits; the mutation tests compare byte-for-byte stored maps.
- G2-16 to G2-26: root/fleet mutations, leases, checkout, publish, commit, release and local unbind tests exist and passed. The response-loss/retry assertions require the stored response bytes and protect against a second resource allocation.
- G2-27: `shared/src/envelope_v2.rs` tests the draft XChaCha20-Poly1305 vector, golden objects, preamble grammar, frame grammar and provider counter maximum. The code path is `seal`/`open`, not a test-only encoder.
- G2-28: the RFC 9180 suite, the fixed info bytes, recipient restriction, tenant/epoch replay refusal, AAD construction and exact FKEK bytes are tested. The vector test is not only a round trip: the test pins the reviewed info hash/bytes.
- G2-29: issuer and signed-byte binding, small-order rejection, RFC 8032 vectors, the spec-check matrix and the signed-container hash vector passed.
- G2-30: all-column revocation equality, startup quarantine, other-instance fail-closed behavior, runtime quarantine, restart restoration, genuine-record swapping, corrupt-container handling, trust-evidence derivation and retry protection were tested. The launcher kept-record reload test also passed. The route stores DEVICE_REVOKE activations in the same `BEGIN IMMEDIATE` transaction and commits them together.
- G2-31: the durable response-loss tests cover approval, root bootstrap, custody operations, e2e operations, profile operations, upload recovery and restore-epoch replay. The server helper restarts the server, retries exact bytes, checks the exact response, checks idempotency mismatch, and compares all rows before/after. The full per-operation launcher matrix passed, including crash/retry paths.
- G2-35: the kept-revocation reload path reparses the exact signed container, verifies the domain, tenant, instance and subject-key association, and treats an unverifiable reason as compromised. The corresponding integrity/quarantine tests passed.
- G2-41: the journal tests cover every restore phase across close/reopen, illegal transitions, retirement, fixed crash resume tables, clone chains, downgrade rollback and digest persistence. The downgrade crash tests resume to a completed clone or restore the original and assert the discovery result. The packet's note that the pre-v2 restore journal has no production writer is explicit scope, not missing evidence for the stated v0.2.x probe.
- G2-42: both launcher integer-probe implementations reopen the database and test domain ends, fractional/out-of-range values, text/blob refusal and retained values. ADR Q-43 is consistent with the implementation: values are accepted only when SQLite stores the exact wire integer; coercions that alter it are refused. The server migration/domain checks also passed.
- G2-43: publish, checkout, upload, finalize, commit, unbind and release crash/replay tests execute the local mutation paths and compare stored bytes. The exact stored request/response bytes are reused after simulated loss.
- G2-44 to G2-45: fresh and upgrade migration fixtures, populated upgrade paths, forward-only generation behavior, quarantine append-only behavior and all signed integer-domain checks passed. The fixture tests reopen the resulting files.
- G2-46: Argon2id RFC 9106 and labelled-salt KEK tests passed. No claim beyond those tests was needed for this row.
- G2-47: debug redaction, token/seed/key absence, TRK reference storage, failure-closed store behavior, legacy migration/zeroization, crash ordering, reference isolation, nonce/key uniqueness and forget semantics all passed. The real OS-store subprocess tests were not run for safety and are the explicitly pending manual/real-store part of G2-48, not a reason to downgrade G2-47's mock/fallback evidence.
- G2-49: durable replacement, failed replacement, crash-at-every-step, back-to-back writes, no-overwrite creation and local-NTFS classification passed. The SMB identity preflight branch ran against the supplied loopback administrative share and passed.
- G2-50: rollback-journal configuration, killed transaction recovery, commit ordering, writer locking, SMB refusal and launcher WAL refusal passed. The corrected server run reached the UNC directory; there was no SMB `SKIPPED` line.
- G2-55: audit-write failure counts, incident output, read-only behavior, network-data-directory behavior, changed-episode retention/clearing and malformed count-file handling passed. The read-only K2 behavior matches ADR C-3: writes are closed while reads remain available.
- G2-63: `shared/tests/registry_pins.rs` enumerates every declared signing domain and hash label, requires distinct/versioned/NUL-terminated labels, and pins the reviewed numeric registry. The profile-label tests cover length bounds, padding, canonical form and context binding. All cited tests passed.

The remaining rows G2-04, G2-08 through G2-26, G2-32 through G2-34, G2-36 through G2-40, G2-44 through G2-62 were also reproduced by their packet commands; no row command failed and no cited test was missing or weakened. Their source implementations were spot-checked through the cited paths and adjacent route/database code rather than inferred from test names alone.

## Findings B1-B7, N1-N2 and SMB gap

- B1: CLOSED. `src-tauri/src/team/ledger.rs:634` and the holdings/activation persistence paths now derive the root exposure range. `a_compromised_custodian_blocks_every_fleet_through_the_root` exercises no-direct-fleet-grant exposure, fleet-first rotation, root-first release, and a higher PREPARING root. The failure scenario described by B1 now returns `sync.commitBlockedCompromised`.
- B2: CLOSED. Holdings and sightings are append-only and recollection cannot erase an exposure. `an_exposure_survives_a_recollection_that_omits_its_grant` passed. The failure scenario of collecting a generation again with pages that omit the earlier grant remains blocked.
- B3: CLOSED. `push` checks `ledger::commit_blocked` before checkout/commit, and `abort_compromised` calls the upload-abort route before releasing the local lease. `a_open_upload_is_aborted_once_a_compromise_is_counted`, `a_compromise_counted_mid_transfer_aborts_the_upload`, and the blocked-state test passed. The stored-finalize scenario does not send finalize or commit and leaves the server upload ABORTED.
- B4: CLOSED. Revocation scope is considered by the counting logic. `a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet` passed; a fleet-scoped compromise now blocks the applicable member path rather than being silently ignored.
- B5: CLOSED. The server route accepts the bounded activation set and applies it transactionally. The route uses `BEGIN IMMEDIATE` and commits the revocation and activations together; the activation matrix tests passed.
- B6: CLOSED and sound. ADR 0002 Q-43 explicitly defines exact-wire-integer preservation as the contract. It refuses fractional, negative, over-i64, non-integer and BLOB values; accepts only lossless in-range integer-form coercions; and documents the above-2^53 decimal/exponent rounding behavior as a refusal criterion when exactness would change. This is consistent with the server's G2-45 bounded INTEGER checks and with launcher code, which binds i64 values rather than arbitrary SQLite REAL/TEXT values. The launcher and server probe tests passed.
- B7: CLOSED. The durable response-loss matrix now covers each operation kind. The restart helper verifies exact response bytes, no second resource/state change, and ID mismatch rejection. `every_custody_operation_replays_its_lost_response_after_a_restart` and the profile/restore equivalents passed.
- N1: CLOSED. Schema version 8 permits only the specific replacement of a kept non-compromised DEVICE_REVOCATION container by a counted compromised one; the trigger rejects other changes and the earliest counted evaluation remains. `a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks` passed. The later-compromise-after-lost failure scenario now blocks.
- N2: CLOSED. The transfer/resume path checks and aborts an OPEN upload even when FINALIZE is already pending. `a_stored_finalize_is_not_sent_once_a_compromise_is_counted` passed; it asserts no second finalize, no commit, one local ABORTED row and an ABORTED server upload.
- SMB gap: CLOSED on this machine. The exact requested UNC path was reachable. Shared volume classification, server storage refusal and launcher identity preflight all exercised their SMB branches and passed. `SKIPPED` lines observed: none in the corrected runs. The first malformed-shell invocation failed only because the environment string was wrong; it was rerun with the exact UNC value.

## Discrepancies and limitations

1. The packet README still describes its historical code-under-review as `fe8c8e36` and retains the historical `G2-64 is FAIL` section. That is stale packet history; the SHA-256 check passes and the actual requested commit is `aef00845...`, whose commit message contains the rerun fixes.
2. The packet has 62 DONE, one PENDING-MANUAL and one historical FAIL status rather than a status line that anticipates this independent rerun. I treated G2-64 as the current verification task, not as a substantive failed implementation row.
3. G2-48 remains PENDING-MANUAL. I did not run the real OS Credential Manager subprocess tests because doing so would touch the machine's real credential store, which the instructions prohibited. The automated mock/fallback half passed, but restart/session-lock/no-store persistence is not independently verified here.
4. The Team UI for G2 commands is deferred by owner decision and was not treated as a gate failure.
5. I did not run cargo-audit, macOS compilation, Playwright or MCP checks; those are listed in the packet/CI workflow but are not required by the explicit local gates in this request. The read-only CI run for the reviewed commit was successful.
6. I did not treat ignored child helper tests as evidence; only their non-ignored parent harness tests were counted. The output includes ordinary harness child-test filtering where applicable, but no cited row relies on an ignored test.

## Security coverage conclusion

The ADR security properties have executable coverage for authorization-container equality, tenant/instance binding, revocation/quarantine, compromise blocking, replay/idempotency, stream framing, HPKE/signing domains, integer ranges, crash durability, local-NTFS/SMB refusal, symlink/tamper refusal, credential redaction and fallback failure-closed behavior. The only deliberately unverified property is the manual real-OS credential-store persistence portion of G2-48. It is explicitly pending and excluded by the owner's release decision; it is not silently being counted as DONE.

The other 63 rows have reproducible evidence on this tree, and I found no missing, incorrect or weakened DONE evidence that is material to the G2 contract.

VERDICT: PASS (excluding G2-48 PENDING-MANUAL)