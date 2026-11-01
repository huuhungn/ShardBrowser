G2-64 independent verification report

Repository and scope

Repository: ShardBrowser
Commit checked: 9e29a2c6a1ae39378b3fe269e3f1ee82a530b9e3
Worktree: C:/Users/User/dev/wt/shardbrowser-g264b-hermes
Target directory: C:/Users/User/AppData/Local/Temp/g264-target-hermes
Concurrency: -j 2

I did not inspect .omc/, .omx/reports/, or a scratch directory. I worked from the repository files named by the gate. The packet itself contains the historical verifier filename and the B1-B7 summary; I did not use that historical report's conclusions as evidence.

Commands and outcomes

- python scripts/g2-evidence.py --check
  118 files checked, 0 problems.
- Packet row commands: 96 Cargo invocations extracted from README section 6. All 96 returned exit 0. The commands exercised 320 named test filters; no named filter reported a failure.
- cargo +stable fmt --check for shared, server and src-tauri: PASS.
- cargo +stable clippy --locked --all-targets -- -D warnings for shared, server and src-tauri: PASS, 3 of 3.
- cargo +stable test --locked --manifest-path shared/Cargo.toml -j 2 --no-fail-fast: PASS. 314 tests passed, 0 failed, 1 ignored across the test binaries.
- cargo +stable test --locked --manifest-path server/Cargo.toml -j 2 --no-fail-fast: PASS. 347 tests passed, 0 failed, 3 ignored across the test binaries.
- cargo +stable test --locked --manifest-path src-tauri/Cargo.toml -j 2 --lib --no-fail-fast, with the real credential-store test excluded after the first unfiltered invocation: PASS. 496 passed, 0 failed, 11 ignored, 1 filtered out.
- The packet's focused SMB tests were also run with --nocapture. They returned PASS but did not exercise a real SMB share: SHARDX_TEST_SMB_DIR was unset and no reachable loopback administrative share was available.
- MSRV checks with --locked --all-targets and -j 2: PASS for shared on rustc 1.87.0, src-tauri on rustc 1.88.0, and server on rustc 1.89.0.
- npm interface checks listed by the packet: test:i18n PASS (16/16), test:rust-strings PASS (3/3), test:backend-locale PASS, and test:raw-error-toast PASS as part of the same command chain.
- cargo-audit 0.22.2 is installed, but I did not run the packet's network/advisory-database audit because the requested verification list did not include it and doing so would add an external dependency fetch. This is not treated as a G2 row failure; the committed dependency review and CI command were inspected.

Sampled rows and code-path findings

The following sample exceeds the required 15 rows and includes every specifically requested sample. Each cited command returned exit 0, and I read the relevant implementation and test code. Plan and ADR references were spot-checked against the row table and the cited plan/ADR sections.

- G2-01: PASS. Canonical DeviceApprovalV2/container parsing and signing tests exist and assert exact fields, signatures and malformed inputs. Plan L443-L508 and ADR D-2/Q-1/Q-13/Q-22 are consistent.
- G2-14: PASS. IdempotentMutationRequestV2 parsing and canonical request binding are exercised by the shared/server tests; the replay identity is not inferred from a loose JSON comparison. Plan L910-L1054 and ADR Q-5/Q-13 are consistent.
- G2-27: PASS. shared envelope_v2 tests cover golden objects, preamble rules, frame rules, final-frame/truncation behavior and the STREAM counter boundary. The implementation exposes strict check_public/open paths and the tests exercise them. Plan L1352-L1371 and ADR 0003/D-3 are consistent.
- G2-28: PASS. HPKE vectors, recipient-key restriction, tenant/epoch replay restriction, exact info/AAD construction and sealed fleet-key round trips are tested. shared/src/grants.rs:342-368 checks the recipient key ID before sealing. Plan L1358 and ADR D-8/D-5 are consistent.
- G2-29: PASS. RFC8032 vectors, strict signature verification, issuer binding and the golden signed-container hash are tested. The signing implementation has separate domain-prefixed input and strict verification. Plan L2335 and ADR D-8 are consistent.
- G2-30: PASS. The server v2_auth tests compare every device-revocation column with its signed container on each request, quarantine mismatches at startup/runtime, turn v2 off for a wrong server instance, and preserve a verified quarantine after restart. Plan L2338/L2034/L2058 and ADR Q-13/Q-38 are consistent.
- G2-31: PASS. server/tests/v2_profiles.rs:3921-3964 and v2_auth.rs:10587 onward snapshot all table rows, restart on the same database, retry exact request bytes, compare status/body and assert no additional resource/state. The exhaustive OperationKind match at v2_profiles.rs:4076-4103 requires every future kind to be covered. B7's failure scenario (lost response followed by a retry creating a second resource) is covered for profile and custody operations; LocalUnbind is explicitly covered by the local tombstone test.
- G2-32: PASS. Local schema reopen/migration and the eleven integer probes are tested. The schema is STRICT with explicit bounded INTEGER checks, and the tests reopen the database and preserve rows/settings.
- G2-35: PASS. src-tauri/src/team/records.rs:487-526 reloads six exact records, checks exact signed bytes, then attempts a changed value in every column and requires refusal. The companion tests cover duplicate/self/cross-instance grant state and revocation column equality. This is stronger than a happy-path parser test.
- G2-41: PASS. Restore journal tests persist every phase across close/reopen, reject skip/repeat/terminal transitions, and test downgrade crash/cut-off points. The journal implementation and tests show resumability rather than merely checking a final file.
- G2-42: PASS, with the contract qualification recorded below. src-tauri/src/team/db.rs:2800 onward tests local integer ranges across reopen and exact lossless conversion. server/tests/v2_integer_domain.rs:370 onward tests every server class, including fractional REAL, out-of-range REAL/TEXT, nonnumeric TEXT and BLOB refusal. ADR Q-43 explicitly and consistently accepts exact in-range REAL/TEXT coercions because SQLite has already converted them to the exact INTEGER before the CHECK sees them; the server and launcher tests use the same behavior.
- G2-43: PASS. The cited launcher response-loss/crash matrix contains exact stored-byte comparisons, restart/reopen behavior and no-second-resource assertions for publish, checkout, upload, finalize, release and unbind paths. The server matrix is separately exhaustive for server operation kinds.
- G2-45: PASS. Server migration and schema scans check upper bounds, INTEGER storage type, out-of-range values and non-integer values across all v2 integer columns. The tests include 2^63 and REAL/TEXT forms.
- G2-49: PARTIAL / not independently reproduced. The local NTFS acceptance and unsupported-volume tests run. However, the SMB refusal branch at shared/src/volume.rs:179-192 and the corresponding server tests contain an early return when no share is configured. This machine had no SHARDX_TEST_SMB_DIR and no reachable loopback admin share, so the essential network-share refusal was skipped.
- G2-50: PARTIAL / not independently reproduced for the same reason. The rollback-journal, synchronous FULL, kill/reopen and old-or-new state tests run, but the cited SMB refusal test was skipped. The packet marks this row DONE while its own README says the branch passes by skipping without SHARDX_TEST_SMB_DIR.
- G2-52: PASS. restore_epoch_harness.rs:1260-1295 enumerates prepare and commit crash points and resumes each state to the restored result, including temporary-file, replace, WAL and transaction points.
- G2-55: PASS for the exercised local audit-count and restore-state matrix; the network-data-directory subcase was not reproduced for the same missing SMB/UNC prerequisite. The non-network tests assert durable count, bad-line isolation, changed episode handling and clear-by-name behavior. Plan L2260 and the corresponding restore-epoch tests are consistent.
- G2-61: PASS. Shared backup tamper/truncation and cross-profile/key rejection tests run, and launcher pull/push tests cover profile binding and fleet-key misuse. The tests leave destinations untouched on refused backup input.
- G2-63: PASS. shared/tests/registry_pins.rs centralizes all published domains and numeric IDs and checks uniqueness/wire constants. The registry test and docs/security-review-g2.md agree on the pinned suites and domain separation. Plan L2335 and L2338 are consistent.

B1-B7 independent closure assessment

- B1: CLOSED. src-tauri/src/team/sync.rs:5923-5960 tests a compromised custodian whose grant is omitted from a later recollection and checks the root-exposure block across fleets. src-tauri/src/team/ledger.rs:613-653 documents and implements persistent exposure through holdings/activation evidence, including missing evidence as flagged. Failure scenario tried by the regression test: count compromise, recollect without the grant, then push; the push is refused before a lease.
- B2: CLOSED. The same test covers root-generation exposure, fleet-before-root ordering, root-before-fleet release, and a PREPARING higher root. The persistent schema uses append-only holdings/activation records and the code does not forget an exposure when a later collection omits its grant. Failure scenario: a fleet activation is under a compromised root that the current fleet grant does not expose; it remains blocked.
- B3: CLOSED. sync.rs:5985 onward creates an open upload, counts a compromise, and checks that the upload is aborted/released and the next push returns sync.commitBlockedCompromised before checkout/lease. push() at sync.rs:1454-1461 performs the pre-check before checkout.
- B4: CLOSED. src-tauri/src/lib.rs:3580 onward constructs a fleet-scoped compromised device revocation and distinguishes the named fleet from another fleet. The resulting ledger decision is consistent with ADR Q-18's scope rule. Failure scenario: a revocation valid only for fleet A must not block a member operation in fleet B, while it does block fleet A.
- B5: CLOSED. server/tests/v2_auth.rs:5946 onward tests a DEVICE_REVOKE carrying exact root/fleet activation payloads and verifies commit/transaction behavior; server/src/routes/v2_device_revoke.rs:687-703 checks each activation in the same transaction context and rejects wrong instance/epoch. Failure scenario: activation bytes are malformed, cross-instance or inconsistent; the revocation transaction refuses rather than partially applying it.
- B6: CLOSED as a contract decision, not as a new DDL rewrite. ADR 0002 Q-43 (line 122) says to refuse only coercions that would store a value other than the exact wire integer, while exact in-range 1.0/'1' conversions are accepted because SQLite has already stored INTEGER. The server's STRICT/upper-bound checks and v2_integer_domain tests implement the same semantics. This is sound and internally consistent; it does not claim that SQLite can observe the pre-affinity REAL/TEXT type at a CHECK constraint.
- B7: CLOSED. The server profile and custody replay helpers compare exact response bytes and complete database row snapshots across restart, and the OperationKind match forces every closed kind to be assigned to a replay test. The failure scenario (perform operation, lose response, retry exact bytes) is directly exercised for every listed operation kind and asserts no second resource/state transition.

Security properties and coverage gaps

- Canonical encoding, signature/domain separation, HPKE recipient binding, envelope authentication/final-frame/truncation, backup confidentiality/tamper detection, integer bounds, append-only trust evidence, restore crash ordering, and exact idempotent response replay have direct tests in the packet.
- G2-48 remains PENDING-MANUAL by owner decision and is excluded from the verdict as requested. I did not independently verify Windows credential-store persistence across restart, locked session and unavailable-store conditions. The repository has a real-store test and ignored child tests, but that is not the requested manual evidence.
- SMB/network-share refusal is not covered by an executed real-share test in this environment. This is material for G2-49 and G2-50 because those rows require fail-closed refusal on SMB, not merely a local-path classifier or a skipped test. G2-55's network-data-directory variant is likewise unverified, although its remaining audit-count matrix passed.
- The Team UI is deferred as allowed and is not a gate failure.
- The packet's G2-64 status is historical FAIL, while the B1-B7 rows and tests now indicate the fixes are present. I evaluated the fixes independently rather than accepting that historical status.
- The full launcher test command was initially started once without the credential-store exclusion; it was stopped from being used as evidence for G2-48, and the filtered launcher suite was rerun successfully. No credential or secret was printed. The build regenerated two tracked schema files with no content diff; I made no source edit, commit or push. This does not change the verdict, but it is recorded for auditability.

Every discrepancy

1. The packet marks G2-49 and G2-50 DONE, but the required SMB branch was skipped in this environment because no SMB share/SHARDX_TEST_SMB_DIR was available. The test code explicitly returns early at shared/src/volume.rs:179-186 and corresponding server tests.
2. The G2-55 network-data-directory test also returned early without a loopback share at server/tests/restore_epoch_harness.rs:2734-2737. Its local durable audit-count coverage passed.
3. G2-48 is PENDING-MANUAL, as explicitly permitted by the owner; no failure is assigned for that row.
4. The launcher full-suite execution includes 11 ignored tests and the real-store test was not accepted as manual evidence; the focused non-credential launcher suite passed with the real-store test filtered out.
5. The working tree acquired generated schema-file status changes during the build, with no textual diff. No repository content was intentionally edited.

What could not be verified

- A real SMB/UNC refusal for G2-49 and G2-50, and the G2-55 network-data-directory variant, because the machine had neither SHARDX_TEST_SMB_DIR nor a reachable loopback administrative share.
- G2-48's manual credential-store persistence run across restart, locked session and unavailable store.
- The deferred Team UI, which is outside the agreed G2 release gate.

The B1-B7 fixes are closed, including the ADR-only B6 decision. The remaining SMB evidence gap is material and is not one of the two exclusions authorized by the owner. Therefore the rest of the gate does not hold on this independent run.

VERDICT: FAIL