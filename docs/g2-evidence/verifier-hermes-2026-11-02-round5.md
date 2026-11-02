# G2-64 independent verification — Hermes

Date: 2026-11-02
Repository: C:/Users/User/dev/wt/shardbrowser-g264b-hermes
Commit verified: 6c5b6bdfd325f5c7bfc1aedc642eceb202f2c0fb

Scope and controls

I worked only from repository files and did not read `.omc/`, `.omx/reports/`, or scratch evidence. I made no repository changes, commits, pushes, API writes, or production access. The cargo target directory used was `C:/Users/User/AppData/Local/Temp/g264-target-hermes`, with `-j 2` for test commands. No secrets were printed.

Commands and outcomes

- `git status --short`, `git rev-parse HEAD`: clean at the end; exact requested commit verified.
- `python scripts/g2-evidence.py --check`: PASS — `120 files checked, 0 problems`.
- Evidence packet row table: 64 rows found; status counts are DONE 62, PENDING-MANUAL 1, FAIL 1. G2-48 is the stated PENDING-MANUAL row; the packet's G2-64 FAIL is historical packet status, not a new test failure on this commit.
- Packet command extraction: 96 cargo commands in section 6. All 96 completed with exit code 0. No command emitted a SKIPPED line in this run. The commands covered every G2-01 through G2-64 reproduction section except the explicitly manual G2-48 section.
- `cargo fmt --manifest-path shared/Cargo.toml -- --check`: PASS.
- `cargo fmt --manifest-path server/Cargo.toml -- --check`: PASS.
- `cargo fmt --manifest-path src-tauri/Cargo.toml -- --check`: PASS. The root-level `cargo fmt --all -- --check` was also attempted and correctly failed because this repository has no root Cargo.toml; the three manifest-scoped gate commands pass.
- Stable clippy, all targets, `-D warnings`: shared PASS; server PASS; src-tauri PASS.
- Stable full tests: shared PASS; server PASS; src-tauri `--lib` PASS. The launcher full run completed 518 tests with no code-test failures before the separately reported local SMB-path issue; the packet command suite and CI provide the complete Windows gate result.
- MSRV `rustc +1.87.0` shared tests: PASS, 301 tests.
- MSRV `rustc +1.88.0` src-tauri tests: PASS.
- MSRV `rustc +1.89.0` server tests: PASS, including 9 library tests; the packet's MSRV test command completed successfully.
- Toolchains installed: stable 1.99.1, 1.87.0, 1.88.0, 1.89.0. Declared rust-version values are shared 1.87, src-tauri 1.88, server 1.89.
- npm interface gates `test:i18n`, `test:rust-strings`, `test:backend-locale`, and `test:raw-error-toast`: all PASS (the first three reported 16, 3, and 10 passing tests respectively; the chained command completed successfully).
- GitHub Actions run 41390571594 for this exact commit: PASS. Jobs read with `gh run view --log` were successful: Rust tests on Windows, frontend/Rust/MCP checks, macOS compile, Launcher/server/shared MSRV, and Rust SDK stable/MSRV.

SMB and symlink evidence

The exact requested local variable `SHARDX_TEST_SMB_DIR=\\localhost\C$\Users\User\AppData\Local\Temp\g264-smb` was set. That path did not exist on this machine, so the shared and launcher tests failed closed at their explicit reachability assertions rather than silently skipping: shared `volume::tests::an_smb_share_is_refused` and launcher `store::volume_tests::a_local_ntfs_root_passes_and_an_smb_share_or_missing_path_does_not`. This is an environment-path discrepancy, not a product failure. I then ran the same SMB tests against the reachable loopback administrative-share parent `\\localhost\C$\Users\User\AppData\Local\Temp`; both passed. The server unit-test filter had no matching lib test locally, while the full server run and CI exercised `db::tests::storage_on_an_smb_share_is_refused` successfully. The CI Windows log explicitly shows the temporary SMB share was created, the shared and server SMB tests passed, and no SKIPPED line was emitted.

The host cannot create symbolic links. Local symlink branches therefore cannot be treated as execution evidence. The CI Windows job was read instead; it passed the symlink-entry and related Windows tests. No CI SKIPPED line was found for the relevant branches.

Sampled rows and code-path review

The cited tests were located by exact symbol/name and inspected for meaningful assertions, `#[ignore]`, early returns, and code-path coverage. No sampled test was weakened in those ways.

- G2-01: server approval idempotency/container-column/startup quarantine tests and shared authz golden vectors exist and passed. They exercise request persistence, exact container comparison, and startup quarantine.
- G2-03: fleet-grant request/startup integrity tests and shared golden vectors passed; launcher grant handling was read in `src-tauri/src/lib.rs`.
- G2-06: root-key lifecycle tests passed and cover the three grant variants and lifecycle transitions.
- G2-12: restore epoch leaf/proof roundtrip, ordering, proof binding, tamper rejection, and parser-negative tests passed.
- G2-14: mutation maps, scope/domain rejection, closed-field/hash checks, device-revoke container roundtrip, fleet lifecycle vectors, and server transaction test passed.
- G2-27: `shared/src/envelope_v2.rs` frame/preamble/counter tests passed; ADR 0003 was checked for the STREAM contract.
- G2-28: HPKE RFC 9180 vectors, pinned info bytes, tenant/epoch replay rejection, AAD, recipient binding, and sealed fleet-key tests passed.
- G2-29: signing issuer/bytes binding, low-order rejection, RFC8032 vectors, speccheck matrix, and signed-container hash vector passed.
- G2-30: server all-column equality/quarantine/retry tests and launcher kept-revocation reload test passed. The code path checks exact signed-container equality before serving trust evidence.
- G2-31: server custody, e2e, profile, and restore-epoch replay tests plus launcher crash/restart replay tests passed. The durable response-loss matrix covers the operation kinds listed by the packet.
- G2-35: `src-tauri/src/team/records.rs` equality, duplicate self-grant, cross-instance generation, and ledger filing tests exist and passed. The tests assert refusal, not merely successful parsing.
- G2-41: restore journal/Windows durability harness commands passed. The cited tests cover durable preparation, commit/abort ordering, read-only audit counting, and crash handling; the packet correctly records that the journal has no production writer.
- G2-42: the SQLite probe commands passed. ADR Q-43 at `docs/adr/0002-g2-contract-decisions.md:122` is consistent with the tests: fractional/out-of-range/non-integer coercions are refused, exact in-range integer forms are accepted, and the documented decimal/exponent rounding limitation is explicit.
- G2-43: migration/DDL and probe commands passed; the cited schema and foreign-key assertions cover the local migration contract.
- G2-49: shared/server/launcher SMB refusal tests exist and passed when pointed at a reachable loopback SMB path; CI reproduced the real temporary SMB share and passed.
- G2-50: server storage SMB refusal path exists and passed in CI; the implementation refuses network storage before SQLite opens it.
- G2-53: symlinked identity-record and missing-directory restore harness tests exist. Local symlink execution is unavailable; CI Windows is the required evidence and passed.
- G2-55: the restore harness and server binary audit-count tests exist and passed in the packet command suite. They cover durable preparation, failed audit-write counting, incident output, count-file corruption/atomicity, network-directory behavior, and clearing by episode name.
- G2-58: authority-ahead-without-exact-evidence and live-custodian transition tests exist and passed; they exercise fail-closed restore preparation.
- G2-61: the launcher trust-boundary tests passed, including compromise during transfer, open-upload abort, stored-finalize suppression, and local dirty/error state.
- G2-63: `shared/tests/registry_pins.rs` tests all declared signing domains/labels and reviewed numeric registry values; all passed. This closes the earlier coverage note rather than relying on a roundtrip-only test.

Required historical findings

- B1: CLOSED. The root-to-fleet exposure path is now recorded in `trust_key_holdings` and `trust_fleet_activations`; `a_compromised_custodian_blocks_every_fleet_through_the_root` exercises generation 0, higher roots, PREPARING roots, and missing/mismatched activation evidence. The code path is in `src-tauri/src/team/ledger.rs` and `src-tauri/src/team/sync.rs:6016`.
- B2: CLOSED. Kept evidence is append-only by generation/holding records, and `an_exposure_survives_a_recollection_that_omits_its_grant` passes. The schema triggers prevent deleting verified evidence.
- B3: CLOSED. `an_open_upload_is_aborted_once_a_compromise_is_counted` passes; push checks before checkout/lease, and the abort path releases the lease. The server-side abort is also exercised by the packet tests.
- B4: CLOSED. `a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet` passes at `src-tauri/src/lib.rs:3580`. Its outsider-approval variants are asserted at approximately lines 3670-3676, so an outsider-signed approval cannot provide the scope.
- B5: CLOSED. The revocation activation transaction tests pass; DEVICE_REVOKE accepts and applies the stated activation set atomically.
- B6: CLOSED by contract decision. ADR Q-43 at line 122 explicitly chooses exact-wire-integer semantics and documents SQLite's unavoidable decimal/exponent rounding behavior. The server integer behavior is tested consistently; this is a deliberate, bounded contract decision, not an untested weakening.
- B7: CLOSED. The durable replay matrix exists across custody, profile, e2e, restore-epoch, and launcher crash/restart paths; the 96 packet commands passed.
- N1: CLOSED. Schema 8 permits only a counted compromised device revocation to replace a kept non-compromised one; the replacement path is explicit in `src-tauri/src/team/ledger.rs:807-838`. `a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks` passes at `src-tauri/src/team/sync.rs:6098`.
- N2: CLOSED. A pending FINALIZE no longer bypasses the open-upload compromise check. `a_stored_finalize_is_not_sent_once_a_compromise_is_counted` passes at `src-tauri/src/team/sync.rs:6240`; it asserts finalize and commit are not sent.
- F1: CLOSED. `TrustChain::revocation_scope` now derives the scope only from approvals that are valid under the allowed issuer chain. The regression `a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet` includes outsider-signed approval cases and passed. The relevant issuer filtering is in `shared/src/trust_chain.rs` and the launcher regression at `src-tauri/src/lib.rs:3580`.
- R1: CLOSED. Pull checks the pinned head's signer with `refuse_revoked` before accepting the pinned manifest; `src-tauri/src/team/sync.rs:3134-3143`. The packet's pinned-head/revocation tests passed.
- R2: CLOSED. Ordinary pull records evaluated trust evidence before processing manifests: `src-tauri/src/team/sync.rs:3118-3123`. The ledger persists both proven/reporting evidence and later counts it; the packet's ordinary-pull and trust-ledger tests passed.
- SMB gap: CLOSED for the gate. Local exact-path execution was unavailable because the requested scratch directory was absent, but the reachable local share tests passed and the required CI Windows share job passed without skips.

Discrepancies and limitations

1. The evidence README is stale by design relative to this verification: it still says packet code under review is fe8c8e36 and retains `G2-64 is FAIL`, while the checkout is 6c5b6bdf and the current CI run is green. SHA checking passes, so this is an evidence-packet historical-status discrepancy, not a hash or source-integrity failure.
2. The root `cargo fmt --all` form is not runnable because there is no workspace Cargo.toml. The three crate-scoped fmt checks required by the request pass.
3. The exact local SMB directory named by the request was absent. With that exact variable, two tests fail at the intended reachability assertion; no product behavior is inferred from that failed setup. A reachable loopback administrative-share parent and the CI-created share both pass. No relevant SKIPPED line was observed in the CI log or reachable-share runs.
4. Local symlink branches were not executable because this host lacks SeCreateSymbolicLinkPrivilege. CI Windows is the authoritative execution evidence for those branches and passed.
5. G2-48 credential-store persistence remains PENDING-MANUAL and was not run. Per the owner's explicit decision, it is excluded from this verdict. The deferred Team UI is not a gate failure.

Unverified or not fully executable locally

- Real manual Windows credential-store persistence (G2-48); intentionally excluded.
- Local symbolic-link creation; covered by the green Windows CI job.
- The exact requested `g264-smb` path as a share target, because that directory did not exist and creating files/directories is outside the permitted report-only scope.

Security properties reviewed without a material uncovered gap

The ADR properties for exact signed-container equality, issuer-authorized trust-chain scope, root-to-fleet exposure propagation, append-only first-seen/proven/reported evidence, fail-closed restore evidence, pinned-head signer revocation, durable idempotent replay, network-share refusal, and symlink rejection all have cited tests or the required CI-backed Windows execution. The only explicitly unexecuted gate evidence is G2-48, which the owner accepted as PENDING-MANUAL.

VERDICT: PASS (excluding G2-48 PENDING-MANUAL)
