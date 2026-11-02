G2-64 independent verification report

Repository: C:/Users/User/dev/wt/shardbrowser-g264b-hermes
Commit: 80a62c1d564967cad6971f9957db82fb0110acc8
Scope: read-only repository verification. No repository files were changed. The report is the only file created.

Method and source readback

I read docs/g2-evidence/README.md, docs/g2-evidence/SHA256SUMS, scripts/g2-evidence.py, docs/adr/0002-g2-contract-decisions.md, the cited plan lines, and the cited source/test paths. I did not read .omc, .omx/reports, scratch directories, production hosts, ShardX launcher data, or Windows Credential Manager.

The packet has exactly 64 unique table rows, G2-01 through G2-64. scripts/g2-evidence.py --check reported:

120 files checked, 0 problems

The packet's SHA-256/checklist verification therefore passed. The packet itself still records G2-48 as PENDING-MANUAL and the historical packet status as G2-64 FAIL; those are evidence-state notes, not substituted for this independent run.

Commands and outcomes

1. Packet and repository checks

- python scripts/g2-evidence.py --check: PASS, 120 files checked, 0 problems.
- git rev-parse HEAD: 80a62c1d564967cad6971f9957db82fb0110acc8.
- CARGO_TARGET_DIR was C:/Users/User/AppData/Local/Temp/g264-target-hermes and cargo commands used -j 2.
- The worktree was detached at the requested commit. No repository write, commit, push, branch, merge, issue, PR, or external mutation was performed.
- Cited path audit: 191 cited path tokens existed; no missing cited repository path was found.
- G2 table audit: 64 rows, 64 unique, no missing IDs, no duplicate IDs.
- GitHub CI read-only lookup: run 41378777068, headSha 80a62c1d564967cad6971f9957db82fb0110acc8, conclusion success.

2. Static gates

- cargo +stable fmt --check --manifest-path shared/Cargo.toml: PASS.
- cargo +stable fmt --check --manifest-path server/Cargo.toml: PASS.
- cargo +stable fmt --check --manifest-path src-tauri/Cargo.toml: PASS.
- cargo +stable clippy -j 2 --locked --manifest-path shared/Cargo.toml --all-targets -- -D warnings: PASS.
- cargo +stable clippy -j 2 --locked --manifest-path server/Cargo.toml --all-targets -- -D warnings: PASS.
- cargo +stable clippy -j 2 --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings: PASS.

3. MSRV

All declared toolchains were installed and checked with --locked/all-targets:
- shared rust-version 1.87: cargo +1.87.0 check -j 2: PASS.
- server rust-version 1.89: cargo +1.89.0 check -j 2: PASS.
- src-tauri rust-version 1.88: cargo +1.88.0 check -j 2: PASS.

4. Full test suites

With SHARDX_TEST_SMB_DIR set to the requested loopback administrative-share path and CI unset for the final full local run:
- shared cargo test: PASS, 314 passed, 0 failed, 1 ignored across targets.
- server cargo test: PASS, 347 passed, 0 failed, 3 ignored across targets. The symlink branch reports SKIPPED because this host lacks the Windows symlink privilege; the ordinary directory/reparse refusal portion passed. This is an environment limitation, not a failed assertion.
- src-tauri cargo test --lib: PASS, 503 passed, 0 failed, 11 ignored.

The standalone SMB refusal test, run with a correctly escaped reachable UNC path, passed:
- shared volume::tests::an_smb_share_is_refused: 1 passed, 0 failed.

An initial shell invocation used an incorrectly escaped UNC value and failed the reachability assertion; I corrected the invocation and reran it successfully. The final full suite used the corrected reachable UNC value.

The explicit server identity symlink test was also run. It cannot create a symlink on this machine (Windows error 1314, required privilege not held). With CI=1 it fails as designed rather than silently skipping; with CI unset it emits the source's SKIPPED line and the rest of the test passes. This is the only essential branch I could not execute on this host.

5. Packet row command reproduction

I parsed and ran every command block in the packet's row-command section, replacing only the packet's bare cargo test executable with cargo +stable test -j 2 and setting the requested target and SMB environment. The runner found 62 row command headings in that section because G2-48 is intentionally represented in the packet's pending-manual section rather than the DONE command block; the table still contains all 64 rows. All executed row commands returned zero except the server symlink command when CI=1, for the host privilege limitation described above. G2-48's listed automated commands passed (6 passed, 0 failed for the selected launcher tests), but the owner-declared manual persistence phases were not performed and remain PENDING-MANUAL.

The final focused commands for the sampled later rows were all successful: G2-49 through G2-64, including the SMB refusal, path corpus, migration/restore, trust-boundary, registry, and profile-label commands. No G2 command emitted a code-level SKIPPED for the SMB branch when the corrected UNC path was supplied. The only SKIPPED output was the Windows symlink privilege limitation.

Per-row findings and sampled depth

All table rows G2-01 through G2-64 were checked against the packet's cited tests, cited plan line, and cited ADR/Q decision. The row table had no missing IDs or duplicate IDs. The cited test symbols were found in the cited source/test files; no cited sampled test had #[ignore], an empty assertion, or an unconditional early return in its exercised success path.

The following rows were sampled in depth, with source paths read and the cited commands executed:

- G2-01: PASS. Device approval/container parsing, signatures, exact columns, and malformed input tests exist and ran. The plan lines L443-L508 and ADR D-2/Q-1/Q-13/Q-22 citations agree.
- G2-14: PASS. Idempotent mutation request parsing, canonical binding, replay identity, and server request handling tests ran. No loose JSON-only replay acceptance was found.
- G2-27: PASS. Envelope v2/STREAM golden vectors, preamble/frame/final-frame/truncation and provider counter boundary tests ran. ADR 0003 is the cited D-3 contract.
- G2-30: PASS. The response-loss/no-second-resource-fence matrix ran; the tests exercise stored replay bytes and operation identity rather than merely checking status.
- G2-31: PASS. The tested operation/replay and restart paths ran, including server and launcher portions. The packet's cited plan line and ADR Q-34/Q-42 decisions are consistent.
- G2-35: PASS. Probe 3 ran. records.rs tests assert exact six-column reopen equality, reject a second self-grant and cross-instance generation, and verify duplicate/self-grant constraints; ledger/sync tests read back filed grant/revocation state. ADR Q-13/Q-26/Q-42 is consistent.
- G2-41: PASS with documented scope limitation. All cited journal phase, crash-point, downgrade rollback, digest, discovery, and unbind tests ran. The packet expressly records that the production restore writer is not present in this v0.2.x scope; that limitation is consistent with the cited plan/ADR and is not an unreported missing test.
- G2-42: PASS under ADR Q-43. The local integer range tests ran. They reject out-of-range/non-integer values and preserve lossless in-range values across reopen. The ADR explicitly accepts SQLite's REAL/TEXT conversion behavior where it stores a different integer and limits launcher writes to i64 bindings; this is a contract clarification, not an evidence mismatch.
- G2-43: PASS. Local mutation replay/crash-point tests ran and assert exact stored bytes, replay behavior, and no duplicate effects.
- G2-49: PASS. Durable replace/kill/write tests and local-volume tests ran. The packet's SMB path was reachable and the SMB refusal test passed.
- G2-55: PASS. Restore preparation/authority, audit failure count durability, read-only/network-directory behavior, and count-file recovery tests ran. The cited server code and tests match the row claim.
- G2-61: PASS. Trust-boundary tests ran for ciphertext secrecy, mutation/truncation/frame-splice detection, wrong profile/fleet/tenant/epoch, launcher cache behavior, compromised-generation blocking, upload abort behavior, identity authority, and quarantine.
- G2-63: PASS. Registry pins and profile-label canonicality/vector tests ran; no weak vector-only assertion was found.

Additional code-path readback included:
- shared/src/trust_chain.rs: revocation_scope filters approvals through approval_issuer_ok before deriving scope.
- src-tauri/src/team/ledger.rs: commit_blocked re-parses kept revocation containers, verifies domain, subject key, tenant/instance, and only blocks compromised revocations while enforcing root/fleet holding evidence.
- src-tauri/src/team/sync.rs: OPEN uploads are checked before transfer/finalize; a counted compromise aborts the upload, sends no further chunk/finalize/commit, and preserves the local dirty/available state as tested.
- src-tauri/src/lib.rs: the F1 regression test constructs an outsider-signed approval and verifies it does not determine the revocation scope.
- src-tauri/src/team/records.rs and team/db.rs: Q-43 integer-domain/reopen tests cover both record and sync table classes.

Earlier findings, independently judged

- B1: CLOSED. The holding and root/fleet activation evidence is persisted and consulted. The compromised-custodian-through-root scenario was rerun and passed; the failure scenario no longer permits a fleet generation under an exposed root to commit until root-first rotation releases it.
- B2: CLOSED. Exposure survives recollection that omits the grant, and the related holding/activation ledger is retained. The regression scenario was rerun and passed.
- B3: CLOSED. A compromised generation blocks before checkout/commit; an OPEN upload is aborted and the server-side upload becomes ABORTED. Mid-transfer tests passed.
- B4: CLOSED. Scope is derived from usable approvals only, and approval_issuer_ok checks the issuer's custody and DeviceApprove capability. The fleet-scope device-revocation test passed.
- B5: CLOSED. The cited activation-count/transaction tests ran and passed; no activation-count truncation or partial-transaction behavior was found in the tested path.
- B6: CLOSED by contract decision, not by pretending SQLite has a stricter type model. ADR Q-43 explicitly accepts lossless in-range coercions and rejects values that would store a different integer; server integer columns are checked separately by G2-45. This is sound and consistent with server behavior.
- B7: CLOSED. Durable response-loss/replay tests ran across the operation matrix and assert stored exact responses/effects rather than rerunning side effects.
- N1: CLOSED. The kept revocation update path permits a later compromised revocation to replace an earlier non-compromised one while retaining the earliest counted evaluation; the lost-then-compromised scenario passed.
- N2: CLOSED. A stored FINALIZE with an OPEN upload is aborted before finalize or commit is sent; the focused test passed.
- F1: CLOSED. trust_chain.rs now filters approval scope through approval_issuer_ok. The regression test a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet passed, including the outsider-signed approval failure scenario.
- SMB gap: CLOSED for the shared/server/launcher test setup on this machine. The corrected loopback administrative-share path was reachable and the SMB refusal test passed; no SMB SKIPPED line was emitted in the final corrected runs. The full server suite's unrelated symlink branch still emitted SKIPPED because Windows symlink creation privilege is unavailable.

Discrepancies and unverified items

1. The packet's historical status text says G2-64 is FAIL and that Hermes had no report; this report is the independent current verification and does not treat that historical prose as the verdict.
2. G2-48 remains PENDING-MANUAL by explicit owner decision. I did not perform the machine-restart/session-lock/no-store manual credential-store run. Its automated half passed, but the manual persistence property is not independently verified.
3. The full server test suite passes when CI is unset but its symlink branch emits a SKIPPED line on this host. With CI=1 the same branch fails at the deliberate privilege assertion. The symlink refusal behavior itself is not fully exercised here. This is a real verification limitation; it is not a fabricated pass.
4. The packet describes a CI-created SMB share. I used the requested loopback administrative share instead. It was reachable and the SMB-specific test passed.
5. The plan gate says any uncertainty about directory durability or MSRV is fail/blocked. MSRV checks passed. Directory durability tests passed; only the unrelated symlink privilege branch is unverified.
6. The final report is written to the requested absolute temporary path. No report contents include secrets.

Could not verify

- G2-48 manual credential-store persistence across restart, locked session, and unavailable/no-store logon session: not run, by explicit owner decision.
- Windows symlink/reparse-point branch in server/tests/identity_authority.rs: not executed because this host lacks the required privilege (error 1314). The test intentionally reports SKIPPED without CI and fails rather than hides the gap with CI=1.
- The deferred Team UI: not a G2 gate failure under the owner decision and not part of this repository evidence packet's automated row commands.

Verdict basis

Every non-G2-48 row has reproducible packet evidence, the cited tests exist and ran, the required static/MSRV/test gates passed, the requested sampled paths and previous B1-B7/N1/N2/F1/SMB scenarios were independently read and exercised, and no additional material security property in the ADR was found without either a cited test or an explicitly recorded accepted limitation. The two exceptions above are stated explicitly: G2-48 is owner-accepted PENDING-MANUAL, and the host cannot create symlinks.

VERDICT: BLOCKED
