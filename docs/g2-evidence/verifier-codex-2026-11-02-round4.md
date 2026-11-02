**Independent G2 verification — ShardBrowser, 2026-11-02**

Commit: 80a62c1d564967cad6971f9957db82fb0110acc8.
Repository: https://github.com/huuhungn/ShardBrowser
Worktree: C:/Users/User/dev/wt/shardbrowser-g264b-codex

The gate fails on two client trust-handling defects, R1 and R2 below. The existing test commands pass after removing interference between concurrent server test runs. The earlier B1–B7, N1, N2 and F1 fixes withstand the checked scenarios, and the requested SMB branches execute here. G2-48 remains PENDING-MANUAL under the owner's exception. The deferred Team UI is not a finding.

This review used the repository plan, ADRs, evidence README, fixtures, production source, tests and exact-commit CI. Earlier verifier report contents were not read. Section 8 of the packet supplied the descriptions of earlier findings, as requested; their closure judgments below come from source and executing the regressions. The hash checker necessarily read bytes of the earlier reports on its fixed artifact list, but their contents were not inspected. No .omc/, .omx/reports/ or scratch-directory reports were consulted.

No source changes, commits, pushes, branch changes, comments, issues or PRs were made. Git status was empty at the start and final check. Builds used the specified private target directory, with -j 2. Test fixtures used their temporary roots. The real ShardX profile and Windows Credential Manager were excluded: the one test that explicitly writes a real OS-store credential was filtered out. This report is the only authored file.

**Blocking findings**

R1 — A previously pinned snapshot is restored after its signer is proven revoked or reported revoked.

Location: src-tauri/src/team/sync.rs:3115, especially :3117 and :3135; the bypassed check is at :3174–3178. Downstream use is at :3202 and :3234.

ADR 0002:1548–1550 requires both strengths of revocation to reject the head and quarantine the binding. It explicitly includes an already pinned head. The exception at ADR:1532 preserves readability after expiry; it does not waive later revocation.

Failure scenario:

1. Reader R has a valid FKEK grant from honest custodian C. Author A is a distinct valid profile committer. R accepts and pins A's head H.
2. R subsequently counts a genuine revocation of A, or receives a current server report that A is revoked. C and R remain valid, and the cached key generation remains usable.
3. The listing returns exactly H at the pinned version and epoch, with its original manifest and ciphertext. There is no upload pending.
4. In pull, v == b.version takes the pinned branch. It compares the head hash and binding identity fields, assigns last, and continues before computing the signer or calling ledger::withdrawn. There is no revocation-driven quarantine.
5. verified_key checks C's delivering grant and R's eligibility, not A's authorship (sync.rs:1394; lib.rs:2726–2762). The envelope still authenticates. snapshot::unpack is reached and the revoked author's content is restored.

This does not require forging a signature, changing a pinned hash, or defeating the envelope. listed at sync.rs:892 checks version/hash/epoch, not author revocation. The command wrapper at sync_cmd.rs:320 calls this function without adding an author check.

Evidence weakness: a_pinned_head_is_read_back_only_as_the_bindings_own (sync.rs:8019, cited by G2-39) tests a cross-instance manifest. It does not add a subsequent revocation of a distinct author. The first-acceptance test at :6484 tests missing capability and expired approval, not this pinned case. Both pass. Thus G2-61's trust-boundary evidence is incomplete despite its DONE label; the G2-39 pin test is narrower than the full rule-6 security contract.

R2 — Ordinary pull evaluates newly received trust evidence but never records its signed revocations, reports or first-sight history.

Location: src-tauri/src/team/sync.rs:3101–3103 and :3257; src-tauri/src/team/ledger.rs:145, :762 and :803; shared/src/trust_chain.rs:194–230.

The normal pull path discards seen from ledger::evaluate, retains only chain, and returns without ledger::record or record_in. evaluate observes previously known lapses and builds a chain; it does not file newly seen revocations. Evidence::collect handles root grants, approvals, capability grants and DeviceHpkeGrant, then ignores the remaining payload kinds. Signed DeviceRevocation containers are counted by ledger::record_in, not by this chain builder. withdrawn consults only the persisted trust_proven_revocations table (ledger.rs:227). The only record calls elsewhere in sync.rs belong to restore-transition acceptance, which an ordinary same-epoch pull does not enter.

Failure scenario A, independent of R1:

1. A reader has prior trust history and a verified fleet key. It has not yet counted author A's revocation.
2. A same-epoch pull receives complete pages containing a valid, countable, signed DeviceRevocation of A, issued by a still-valid custodian with the required scope/capability. A hostile server omits the separate unsigned device_revocations report but supplies A's still-window-valid approval/capability and a new, correctly signed head.
3. Evidence::collect ignores that signed revocation payload. The persisted withdrawn(A) is false. No record call counts it before the new-head checks.
4. The new head passes the approval/capability checks and is restored. The revocation still has no first-sighting/count entry after the operation. A later ordinary push also lacks that newly delivered compromise cause.

Failure scenario B, showing the lost-report effect:

1. A pull sees an unsigned revocation report affecting a new head. The chain rejects that author, so pull returns sync.signerUntrusted at :3178.
2. That return neither records the report nor quarantines the binding.
3. On a later pull the server omits the report. No sticky entry preserves it, so the same otherwise-valid head can pass.

ADR 0002:1498 requires a ledger update after each evaluation. ADR:1465 identifies signed revocation containers in this evidence stream as the way other devices learn revocation; :1493–1495 describe the persistent first-sight rule, and :1548 requires quarantine. This is not the accepted residual case where the server withholds the signed revocation: here it was delivered.

Evidence weakness: a_reported_revocation_outlives_the_server_omitting_it tests the custody-collection path, which does call record (lib.rs:2694). The B1/B2/N1/N2 regressions exercise a ledger that already contains a counted cause. They do not establish that ordinary pull records the cause it just received. G2-61 therefore remains PARTIAL.

Both findings above are verified by tracing the actual call paths and the counterexample inputs against their branches. No new integration fixture was injected into this read-only checkout, and no claim is made that a newly authored runtime regression reproduced them. Four existing nearby tests were rerun together and all passed; their passing results expose the coverage gap rather than disprove it. The requested historical failure scenarios were exercised through the existing regression fixtures described below.

Additional ADR coverage gap: the rule-6 revert acceptance vectors at ADR:1552–1566 (one/two proven-revoked intervening heads, new device without a pin, rejection of reported-only skips, and skipped-head audit) are not represented by the cited row commands. The ordinary pull loop rejects an invalid intermediate signer at sync.rs:3178 and has no corresponding skip-and-audit path. This should receive explicit implementation-scope and test coverage before asserting that the complete rule-6 contract holds. R1 and R2 alone suffice for this verdict; this observation is not being used to turn deferred UI work into a blocker.

**Commands and outcomes**

Environment for compilation and tests:

~~~powershell
$env:CARGO_TARGET_DIR='C:/Users/User/AppData/Local/Temp/g264-target-codex'
$env:SHARDX_TEST_SMB_DIR='\\localhost\C$\Users\User\AppData\Local\Temp\g264-smb'
~~~

The SMB path was reachable. All shared, server and launcher runs used that setting. The G2-55 network-data test independently constructs its own temporary directory accessed through the same loopback administrative share.

| Check actually run | Outcome |
| --- | --- |
| python scripts/g2-evidence.py --check, initial and final | exit 0; exact output: 120 files checked, 0 problems |
| cargo +stable fmt --check --manifest-path <crate>/Cargo.toml, shared/server/src-tauri/sdks/rust | 4/4 exit 0 |
| cargo +stable clippy --locked -j 2 --manifest-path <crate>/Cargo.toml --all-targets -- -D warnings, shared/server/src-tauri | 3/3 exit 0 |
| cargo test --locked -j 2 --manifest-path shared/Cargo.toml -- --nocapture | 314 passed, 0 failed, 1 ignored |
| cargo +stable test --locked -j 2 --manifest-path server/Cargo.toml -- --nocapture, isolated final run | 347 passed, 0 failed, 3 ignored; exit 0 |
| cargo build --locked -j 2 --manifest-path server/Cargo.toml | exit 0 |
| cargo test --locked -j 2 --manifest-path src-tauri/Cargo.toml --lib -- --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process | 502 passed, 0 failed, 11 ignored, 1 filtered |
| README section 6, all 96 cargo invocations, with -j 2 and --nocapture | 95 initially exit 0; G2-03 server command initially failed during overlap; isolated rerun 2 passed, exit 0. All 96 have successful final executions, with the G2-48 exception below |
| cargo +1.87.0 check --locked -j 2 --all-targets --manifest-path shared/Cargo.toml | exit 0 |
| cargo +1.89.0 check --locked -j 2 --all-targets --manifest-path server/Cargo.toml | exit 0 |
| cargo +1.88.0 check --locked -j 2 --all-targets --manifest-path src-tauri/Cargo.toml | exit 0 |
| npm run test:i18n | 16 passed |
| npm run test:rust-strings | 3 passed |
| npm run test:backend-locale | 7 passed |
| npm run test:raw-error-toast | 2 passed |

The 314 shared tests comprise 300 library, 8 backup-file roundtrip, 3 G3 and 3 registry tests. The ignored test is the operator recovery drill. The final server total comprises 9 library + 106 binary + 10 earlier integration + 22 identity + 3 migration + 24 restore + 75 v2_auth + 6 durability + 9 e2e + 11 instance boundary + 5 integer + 3 nullable generation + 9 profile + 15 schema + 8/3/1/2/3 earlier upgrade + 23 upgrade-chain tests. Its ignored tests are two crash-harness subprocess entry points and the manual G6 case. Launcher ignores include subprocess entry points and manual updater/engine cases. The cited G2 tests were not hidden with #[ignore]; child entry points run through their parent harness where relevant.

Execution discrepancy: an earlier full server run overlapped the per-row runner on the server fixtures' fixed loopback ports. It ended in v2_auth with 74 passed and one failed (every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup), and the G2-03 startup-quarantine filter also failed during this overlap. No source or assertion was changed. The isolated full run passed all 75 v2_auth tests and all remaining server targets; the exact G2-03 two-filter command then passed. These initial failures are reported, but are not evidence of a product defect.

G2-48's row command ran five tests with the real OS-store test filtered out. That filter also applies to the full launcher run. The excluded test deliberately creates an OS credential and conflicts with the user's explicit machine-data restriction. The manual restart/locked-session/no-store script was not run. The owner exempts G2-48 from this gate judgment.

Additional focused command after finding R1/R2:

~~~text
cargo test --locked -j 2 --manifest-path src-tauri/Cargo.toml --lib -- a_head_whose_signer_may_not_commit_is_not_restored a_pinned_head_is_read_back_only_as_the_bindings_own a_reported_revocation_outlives_the_server_omitting_it a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet --nocapture
~~~

Result: 4 passed, 0 failed, 0 ignored, 510 filtered. The entire section-6 command ledger, with the arguments actually used, is included after the row assessment.

**Versions, hashes and CI**

Windows x86_64-pc-windows-msvc; stable rustc 1.99.1 (58cf8f9c3 2026-10-13), cargo 1.99.1 (5f94df478 2026-08-27); Python 3.12.10; Node v24.22.2. All requested MSRV toolchains were installed: 1.87.0 (17067e9ac 2025-05-09), 1.88.0 (6b00bc388 2025-06-23), 1.89.0 (29483883e 2025-08-04). None of the three MSRV checks was skipped.

SHA-256 below uses the packet's CRLF-to-LF normalization, not raw Windows checkout bytes:

| Artifact | SHA-256 |
| --- | --- |
| docs/g2-evidence/README.md | 60c15ded1cd03526e84b7b3d5d3588733520b0900195fadd237b45ce1cfd0d96 |
| docs/g2-evidence/SHA256SUMS | 532c6fdeb6c4933b9204d6798354db0316e30d6e5876c11ee0ac91c57c784fc8 |
| Plan | 8b9ef41a21e93d19b4e4fe4641aff06d96a123256cb00c0e8580f0fa70a5523e |
| docs/adr/0002-g2-contract-decisions.md | 11e7f0d2824c64e6589d9ec89db52372d208721e5a46858f18c5816d99939940 |
| shared/src/trust_chain.rs | 19aa9c0b75367dfdb7dc0c1da96250b026a9f4d5ffe21ff72cc694ca86b4daab |
| src-tauri/src/team/sync.rs | 2f22c922b298e3443928e54963e77b9883c60c30cfdd9c744b01497acaf88e1b |
| src-tauri/src/team/ledger.rs | c29aa26014a73f4d74daac81017ed7c9cc07e5f85eac9c49b3a4ca64ed2cab32 |
| src-tauri/src/lib.rs | 33623270994777aef2311fd5784fe6993873217748b74296af12f645b75eedd0 |

The 120 hashes in SHA256SUMS all match. The F1 implementation file shared/src/trust_chain.rs is not in that fixed artifact list; it is independently hashed above. The unchanged HEAD and that extra hash identify the reviewed fix.

Read-only CI commands included gh run view 41378777068 --json status,conclusion,headSha,jobs and gh run view 41378777068 --job <id> --log for jobs 125064753915, 125064754215 and 125064754294. Run: https://github.com/huuhungn/ShardBrowser/actions/runs/41378777068 . Head SHA exactly equals the reviewed commit. Final conclusion: success, all five required jobs successful, Windows finished at 2026-11-02T03:08:11Z. macOS compilation and frontend/Playwright/MCP evidence were read from this run, not executed locally.

The Windows CI log reports shared 314, server 347 and launcher library 503 passing tests. The local launcher count is one lower because of the credential-store filter. CI also executed launcher integration targets. The Windows symlink tests succeeded; their source asserts that CI must fail rather than silently skip if link creation fails.

The SDK/audit job executed the packet's cargo audit commands with the stated advisory ignores. It loaded 1395 advisories and scanned 120, 338 and 690 dependencies. All audit steps succeeded. There were 10 permitted unmaintained warnings: RUSTSEC-2024-0370, 2026-0192, 2025-0081, 2025-0075, 2025-0080, 2025-0100, 2025-0098, 2026-0371, 2026-0370 and 2026-0372. These categories are recorded in dependency-review.md. This is successful auditing under the documented exceptions, not a claim of an empty warning list. A local cargo-audit installation or advisory database update was not performed.

**Earlier findings, independently assessed**

| Finding | Judgment and checked scenario |
| --- | --- |
| B1 root-derived exposure | Closed. ledger.rs:452 derives holdings from key-carrying grants; :634 checks the fleet and root causes. Schema 7 stores immutable holdings/activations. The root-first/fleet-second, PREPARING-root, missing-activation and known-custodian-without-holding cases execute in a_compromised_custodian_blocks_every_fleet_through_the_root and a_known_custodian_with_no_root_holding_blocks. Newly recollected fleet evidence does not release the root block. |
| B2 recollection forgets exposure | Closed. ledger.rs:553 files holdings persistently; replacing cached pages does not delete them. an_exposure_survives_a_recollection_that_omits_its_grant supplies pages with the exposure grant removed and still observes the commit block. |
| B3 OPEN resume and pre-checkout ordering | Closed for a counted cause. sync.rs:1458 checks before checkout, :1496 handles OPEN, :2455 aborts, and :2516 rechecks during transfer. an_open_upload_is_aborted_once_a_compromise_is_counted, a_compromise_counted_mid_transfer_aborts_the_upload and a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code execute the formerly failing scenarios. DELETE reaches the upload endpoint; release and dirty/AVAILABLE error state are asserted. R2 concerns getting newly delivered evidence into that counted state. |
| B4 fleet-scoped revoke | Closed, including F1 below. ledger.rs:1044 derives required scope from the subject's legitimate approvals. The fixture exercises a fleet member and a revoke capability limited to that fleet. |
| B5 nonempty activations | Closed. DEVICE_REVOKE permits bounded sorted unique activation lists; server/tests/v2_auth.rs:5949 and :6141 execute fleet and root activation. An incomplete fleet activation fails without committing its revocation/session side effects; complete requests commit together. Both tests pass. |
| B6 integer affinity | Closed by the explicit Q-43 decision, ADR:122, with the qualifications below. Local G2-42 and server G2-45 tests pass. Typed checked i64 binding and SQLite INTEGER storage are consistent in both. |
| B7 all-operation response loss | Closed. server/tests/v2_auth.rs:10559 snapshots all table rows; :10592 restarts and compares exact response/status and rows; :10642 covers custody. The profile counterpart covers profile operations; exhaustive OperationKind matching requires new variants to acquire a case. Wrong request reuse is rejected. LocalUnbind is exercised locally. G2-31's 15 selected executions pass. |
| N1 lost then compromised | Closed. ledger.rs:809–846 upgrades a kept non-compromised record to compromised without moving its earliest count. Schema 8 permits that container update while protecting other fields. sync.rs:6075 runs lost -> compromised -> retired; the compromise starts the block and the later retirement does not weaken it. |
| N2 pending FINALIZE | Closed. The OPEN check precedes sending the stored finalize even when it is PENDING. a_stored_finalize_is_not_sent_once_a_compromise_is_counted at sync.rs:6217 asserts the finalize is not sent, the upload is aborted and the lease released. |
| F1 outsider approval changes revoke scope | Closed. shared/src/trust_chain.rs:529 filters approvals through approval_issuer_ok before taking their scopes. The lib.rs:3580 regression includes outsider-signed tenant and other-fleet approvals, preserves the genuine fleet-scoped revocation, rejects a real wrong-fleet revoke, and checks that a genuinely tenant-scoped approval needs tenant scope. It passed in G2-61, the full suite and the final focused run. |
| SMB branches | Closed here and in exact-head CI. shared::an_smb_share_is_refused, server storage and identity-preflight refusal, and G2-55 read-only network data all execute successfully with a reachable loopback share. No SMB SKIPPED line appeared. |

For B6 I also ran an in-memory Python sqlite3 probe (SQLite 3.49.1) using the actual local schema/migrations 1–8 and all server migrations, enabling the migration FK-off guard where required. The selected real columns were server_origins.last_restore_epoch and v2_server_state.restore_epoch. Both store 0 and i64::MAX exactly; lossless numeric text and REAL 1 become INTEGER. Both reject -1, real 2^63, text 9223372036854775808, fractional 0.5, nonnumeric text and blobs without replacing the prior valid row. Both store '9007199254740993.0' and '9.007199254740993e15' as 9007199254740992 because SQLite first rounds through floating point. Q-43 now explicitly states that behavior. It is sound for the implemented wire path, which decodes to u64 and checks i64 before binding; it is not a promise to preserve arbitrary SQL decimal lexemes. Two exploratory probe attempts first failed on a wrong seed column count and a migration FK precondition; the corrected probes exercised the actual DDL. No on-disk probe database was created.

**Sampling and evidence quality**

Every row's cited test names and source files were checked against the repository, and the section-6 filters were executed. Tests have substantive assertions or call helpers that do: in particular G2-44's short wrapper tests delegate to upgrade/fixtures_on assertions. The sampled code paths were read, not inferred from names or test counts. There was no cited test disabled with #[ignore], nor a vacuous unconditional early success in the sampled assertions.

There are conditional environmental exits: the SMB tests require a share, and the symlink tests require Windows privilege. SMB prerequisites were satisfied. Locally the following symlink diagnostics were observed or identified in the executing branch:

~~~text
SKIPPED: cannot create a symlink here: A required privilege is not held by the client. (os error 1314)
skipping: cannot create a symlink here: A required privilege is not held by the client. (os error 1314)
~~~

The uppercase line is from server/tests/restore_epoch_harness.rs:2876; the lowercase branch is server/tests/identity_authority.rs:220. The latter still tests the non-regular directory case before returning. This is a local coverage limit, not a passed symlink scenario. Exact-head Windows CI provides the missing symlink execution; CI turns privilege failures into assertions. No other runtime SKIPPED line was seen. CI's skipped failure-diagnostic upload steps are not skipped product tests.

The row table below lists every row, its plan/ADR citation and my assessment. “Reproduced” means the cited evidence supports that row's bounded claim; it is not a general proof of every security property of the feature. “Deep” denotes a sample whose implementation and adversarial assertions were followed in detail. More than 15 rows were examined deeply, including every mandatory sample.


| Row | Plan and ADR 0002 | Independent assessment |
| --- | --- | --- |
| G2-01 — DeviceApprovalV2 + container | L443-L508; D-2, Q-1, Q-13, Q-22 | Deep; reproduced. Signature/container golden bytes and per-column runtime/startup mismatch cases have positive and negative assertions. D-2 issuer restrictions remain enforced. |
| G2-02 — TenantCapabilityGrantV2 | L443-L508; Q-2, D-2, Q-13 | Reproduced. Every capability column is checked at request time and startup. The initial concurrent-run failure disappears in the isolated full suite. |
| G2-03 — FleetKeyGrantV2::DeviceHpkeGrant | L443-L508, L1358; D-8, D-9, Q-5, Q-13, Q-26 | Reproduced. HPKE-grant columns, recipient/key context and startup quarantine are exercised; isolated rerun: 2/2 server tests pass, plus the golden vector. |
| G2-04 — FleetKeyGrantV2::RecoveryGrant | L443-L508; D-5, D-9 | Reproduced. Recovery context, suite/length checks and wrong-root/wrong-FKEK opening are tested, with server column equality. |
| G2-05 — FleetKeyGrantV2::RotationGrant | L443-L508; D-5, D-9, Q-5 | Reproduced. Rotation bounds, generation window and counts are asserted; signed bytes and server equality remain covered. |
| G2-06 — TenantRootKeyGrantV2 (3 variants, lifecycle) | L760-L909; Q-1, D-4, Q-23, Q-24 | Reproduced within the stated scope. Root variants and lifecycle are exercised by shared/server tests; launcher production creation remains FirstRootSelfGrant only, as disclosed. |
| G2-07 — SnapshotManifestV2 / signed / head hash | L509-L589; Q-1, Q-36 | Deep; reproduced. snapshot_v2 parsers check field defects and closed containers; head hashing/signature binding are pinned to golden bytes and a real sealed envelope. |
| G2-08 — CommitRequestV2 | L509-L589; Q-34 | Reproduced. Real upload endpoint rejection table checks statuses/codes for malformed or mismatched commit requests. |
| G2-09 — CommitReceiptBindingV2 | L509-L589; none | Reproduced. Commit-once test checks stored receipt and next checkout's head, including identity/version binding. |
| G2-10 — DekSlotContextV2 / DekSlotV2 | L590-L759; D-3, ADR 0003, D-8 | Deep; reproduced. Envelope slot/context parsing, closed maps and intent equality are checked against encode/open code. Seven selected tests pass. |
| G2-11 — EnvelopeIntentV2 | L590-L759; D-3, ADR 0003 | Reproduced. Intent bounds and exact manifest-named intent/slot are enforced; genesis and ordinary vectors pin preimages. |
| G2-12 — RestoreEpochLeafV2 / inclusion proof | L590-L759; D-1, Q-1, Q-36 | Deep; reproduced. restore_epoch leaf/proof implementation and odd/singleton Merkle shapes were read. Tampering, directions, count, root and tenant/profile/instance/epoch binding are asserted; seven pass. |
| G2-13 — RestoreEpochTransitionV2 / signed | L590-L759; D-1, Q-33, Q-36 | Reproduced. Transition payload/container negatives and signature label/key binding pass. |
| G2-14 — IdempotentMutationRequestV2 | L910-L1054; Q-5, Q-13 | Deep; reproduced. B5 closed. Mutation maps are closed and domain/version checked; nonempty activation arrays are sorted/bounded and applied transactionally. Eight shared plus two server selected tests pass. |
| G2-15 — IdempotentStoredResponseV2 | L910-L1054; D-6, Q-34 | Reproduced. Stored-response maps round-trip exact bytes and reject wrong domain/version. |
| G2-16 — ROOT_GENERATION_CREATE | L915; Q-5, D-4, D-9, Q-28 | Reproduced. Root generation bootstrap returns the same response on retry and creates the first root once. |
| G2-17 — ROOT_GRANT_CREATE | L915; Q-5, D-4, D-9 | Reproduced. Root-grant denormalized columns are compared with the signed source on reads and after restart. |
| G2-18 — ROOT_GRANT_ACK | L915; Q-5, D-9 | Reproduced. ACK/readback accepts only the exact stored grant, not a substituted container. |
| G2-19 — ROOT_GENERATION_ACTIVATE | L915; Q-5, D-9, Q-24, Q-28 | Reproduced. Activation requires the acknowledged exact grant and pins the generation evidence. |
| G2-20 — ROOT_GRANT_REVOKE | L915; Q-5, Q-23 | Reproduced. Valid reason/outcome maps and protection of the last live root custodian are asserted. |
| G2-21 — PROFILE_PUBLISH_CREATE | L915, L1139; Q-41, Q-42 | Deep; reproduced. Publish binds initial lease/fence and persists exact request bytes across each injected crash; Q-41 label and Q-42 binding are consistent with the read paths. |
| G2-22 — PROFILE_CHECKOUT | L915, L1140; Q-34, Q-42 | Reproduced. Cross-binding lease replies, stale/expired replay and changed request identity are rejected; fresh checkout uses a new key. |
| G2-23 — CREATE_UPLOAD | L915, L1147-L1158; Q-34 | Reproduced. Lost create-upload response replays stored bytes; server rejection status/code matrix has assertions. |
| G2-24 — FINALIZE_UPLOAD | L915, L1159-L1219; Q-34 | Reproduced. Finalize/commit and reconciliation tests cover commit-once and crash resume. Counted-compromise OPEN handling is additionally checked under N2. |
| G2-25 — RELEASE_LEASE | L915, L1142; Q-34, Q-42 | Reproduced. Release replays the prior response even after the lease is gone, with cross-profile response checks. |
| G2-26 — LOCAL_UNBIND | L915, L2038, ADR D-7; D-7, Q-37, Q-40 | Reproduced. Local tombstone survives binding deletion; crash cuts preserve an atomic unbind, with version-zero and open-journal/lease refusal. |
| G2-27 — STREAM / preamble / final frame | L1352-L1371; D-3, ADR 0003 | Deep; reproduced. envelope_v2 read_head/open/frame_head enforce preamble, frame finality/counter and provider limit; draft XChaCha vector and golden objects are substantive. |
| G2-28 — HPKE TRK/FKEK grants | L1358; D-8, D-5 | Deep; reproduced. RFC 9180 vectors pin the chosen suite; info_bytes_match_g2_vector now asserts its expected hash. AAD, tenant/epoch and recipient/FKEK mismatch paths are exercised. |
| G2-29 — Signing suite | L2335; D-8 | Reproduced. Strict Ed25519 verification includes RFC8032, speccheck ambiguities, small-order issuer and signature/container mutation cases. |
| G2-30 — Grant ALL-column + HPKE equality (seven under Q-13) | L2338, L2040, L2058; Q-13, Q-38 | Deep; reproduced with accepted Q-38 limit. Ten server tests plus one launcher test pass. v2_device_revoke rechecks every stored column/container; quarantine marks bind the original hash, unreadable/missing authority shuts v2 off, restored genuine data is served again only under the prescribed rules. |
| G2-31 — Durable response-loss replay, every operation | L2338, L1424, L2048; Q-34, Q-42 | Deep; reproduced. 15 selected test executions across five commands pass. Actual server mutation/restart/replay checks exact response bytes/status and all-table state; exhaustive operation coverage closes B7. LocalUnbind stays local. |
| G2-32 — Local plan DDL + 11 probes | L1450-L2034, L2036; Q-1, Q-37, Q-42 | Reproduced. Local schema reopens and version-5/6 migration preserves rows, triggers and indexes; full suite also covers schema-7/8 changes. |
| G2-33 — Probe 1 UNBIND tombstone | L2038; D-7, Q-37 | Reproduced. Tombstone digest validation, atomic cuts and survival of transition/proof records after unbind are asserted. |
| G2-34 — Probe 2 RELEASE replay after lease gone | L2039; Q-34 | Reproduced. Release reply loss, unsent cancellation and unreadable reply retain the replay state correctly. |
| G2-35 — Probe 3 grant equality + second self-grant + cross-instance FK | L2040, L2034, L2058; Q-13, Q-26, Q-42 | Deep; reproduced. records.rs:487 mutates signed/root rows and asserts 326 security-relevant column failures (5*57+41); local metadata columns are deliberately excluded. Self-grant uniqueness, cross-instance FKs, actual key state and revocation reload are tested. Six pass. |
| G2-36 — Probe 4 upload resume + UNIQUE/FK | L2041; none | Reproduced. Upload identity uniqueness/FKs and remote HEAD-offset resume are asserted. |
| G2-37 — Probe 5 manifest/request replay, 3 crash points | L2042; none | Reproduced. Request/manifest replay keeps exact bytes across cuts; drifted stored columns are never sent. |
| G2-38 — Probe 6 receipt equality/readback | L2043; none | Reproduced for receipt/readback equality. Rejected receipt fields, successful push/pull and server commit behavior pass. This ordinary successful pull test does not cover R1/R2. |
| G2-39 — Probe 7 local epoch transition/proof | L2044; Q-1, Q-36, Q-37 | Deep; transition/proof evidence reproduced: 12 tests pass. Cross-tenant/epoch/proof, lapse, old lease and atomic transition persistence checks are substantive. Pinned-head test covers identity only; R1 is the uncovered rule-6 exception. |
| G2-40 — Probe 8 unknown/newer schema | L2045; none | Reproduced. Unknown schema and a database held in WAL mode fail closed without rewriting the unknown schema. |
| G2-41 — Probe 9 recovery/downgrade journals | L2046; Q-35, Q-40 | Deep; reproduced for probe 9. Fourteen tests assert ordered journal phases, forbidden skips/terminal moves, digests across reopen and actual downgrade kill/resume/rollback/discovery behavior. No production pre-v2 restore writer exists, as explicitly disclosed; journal tests do not claim that end-to-end writer. |
| G2-42 — Probe 10 local integer range | L2047; D-6, Q-43 | Deep; reproduced under Q-43. Both local integer-class matrices pass; independent actual-DDL SQLite probe agrees with server behavior. Numeric-affinity rounding qualification is stated above. |
| G2-43 — Probe 11 local mutation replay | L2048; D-7, Q-42 | Deep; reproduced. Seven crash/replay tests assert exact durable requests/responses, superseded operation closure and fresh retry; no second mutation or resource is inferred merely from an HTTP success. |
| G2-44 — Server migrations fresh + upgrade | L2080-L2222; Q-34, Q-38 | Deep; reproduced. Seven cited migration tests use real upgrade helpers and plan_assert.sql on fresh, v0.1.28 and populated 0016 files, reopen them and check backup restore, constraints and quarantine append-only behavior. Short wrappers delegate to assertion-bearing helpers. |
| G2-45 — Unsigned i64 domain (server) | L2343, L2338; D-6 | Deep; reproduced. All integer classes exercise endpoints/out-of-range/noninteger inputs and scan every v2 integer column; migration 0030 and reopen behavior are covered. Six selected tests pass. |
| G2-46 — Argon2id | L1377; D-5, Q-7, Q-21 | Reproduced. RFC9106 Argon2id and labelled salt tests pass. Recovery uses p=4; SHXBAK01 p=1 is explicitly retained by Q-7. |
| G2-47 — Secrecy/zeroization | L2335; D-5 | Deep; reproduced within the disclosed type-level limit. Seventeen tests cover debug redaction, reference-only bootstrap state, old cleartext migration, store failures, nonce/save ordering and crash resume. Freed-memory observation is not claimed. |
| G2-48 — Windows credential store | L1374-L1376, L2335, ADR Q-29; Q-29, D-5 | PENDING-MANUAL, owner-exempt. Five automated fixture tests pass; real-OS-store test filtered and manual script not run to respect machine credential restrictions. |
| G2-49 — Windows file durability (local NTFS, Q-30) | L2337, L1175, L2250; Q-30, Q-39 | Deep; reproduced. Five launcher durability, three volume, three server storage/identity and two restore-preflight tests pass. Process kills test old-or-new state and returned-write durability; local NTFS classification rejects reachable SMB. |
| G2-50 — SQLite WAL/busy/crash ordering | L2337, L2063; Q-16, Q-30, Q-31 | Deep; reproduced for the chosen DELETE/FULL policy. Busy-writer and killed-transaction ordering pass; launcher rejects a held WAL database. Plan L2063 conditions enabling WAL on proof, so this is not evidence that WAL was enabled. Reachable SMB refusal executed. |
| G2-51 — Windows path corpus | L2338; Q-30 | Deep; reproduced. Windows traversal/reserved-name/case-fold/long-path corpus and actual junction behavior are checked in pack/unpack; downgrade discovery finds old IDs outside the archive. Seven selected tests pass. |
| G2-52 — Restore-epoch FS harness | L2339, L2250-L2269; D-1, Q-30, Q-33, Q-35 | Deep; reproduced. One filesystem harness test walks the full crash table and asserts a unique class/resume outcome at each point; production classify/commit ordering was read. |
| G2-53 — Missing/corrupt record | L2260; D-1, Q-39 | Reproduced with CI supplement. Missing/corrupt record and non-regular entry tests pass locally. Actual symlink subbranch skips locally for privilege and passes in exact-head Windows CI; do not count the local skip as link coverage. |
| G2-54 — External = mirror, no preparation | L2261; D-1 | Reproduced. Matching external record/mirror with no preparation opens normally; old test line number is two below current plan numbering. |
| G2-55 — Preparation durable, authority E | L2262; D-1, Q-38 | Deep; reproduced. Nine harness plus seven binary tests pass. Durable preparation remains read-only; failed audits are counted/logged across restart, corrupt or changed episode data is preserved by name, commit clears only the concluded count, and network data produces no count write. |
| G2-56 — External E+1, live mirror E | L2263; D-1, Q-33 | Reproduced. External E+1 with live mirror E resumes installation only, with authority preserved. |
| G2-57 — E+1, restored mirror behind | L2264; D-1, Q-33 | Reproduced. Restored mirror behind authority is verified/rebuilt before normal service. |
| G2-58 — Ahead without evidence | L2265; D-1, Q-33, Q-36 | Reproduced. Ahead-without-exact-evidence fails closed; only a current qualified custodian's transition over computed leaves prepares. |
| G2-59 — Behind/different instance | L2266; D-1, Q-39 | Reproduced. K2 incident/audit count asserted by the cited test; record-behind and wrong-instance cases also execute in the complete restore harness. |
| G2-60 — Reconciled E+1, retire bundle | L2267; D-1, Q-28 | Reproduced. Reconciled epoch retires the bundle and a subsequent startup is normal. |
| G2-61 — Trust-boundary tests/docs | L2340; Q-13, Q-14, Q-18 | Deep; PARTIAL despite DONE in packet. Existing ciphertext tamper/context and counted-compromise regressions pass (7 shared lib +3 backup +14 launcher +1 identity +1 server). R1 and R2 invalidate the complete client trust claim. |
| G2-62 — Dependencies (license, advisories, MSRV, feature graph) | L2336, L2343; D-3, ADR 0003 | Reproduced with documentation corrections. Three local MSRV checks and exact-head CI RustSec audit pass. License/feature review matches the resolved dependencies except stale package counts and missing license metadata on the local workspace crates, detailed below. |
| G2-63 — Security review artifact | L2341; D-8, Q-41 | Deep; reproduced for provider/registry/label review. Three registry plus five label tests pass. All 105 domain/label declarations were matched to the registry, including re-exported snapshot-head label and 16 lease/upload/publish domains. Numeric IDs, HKDF context, AEAD/padding and canonical-open assertions were read. root_wrap_suite_id is pinned through the authz vectors/rejection test rather than directly by the numeric registry test. |
| G2-64 — Independent verifier PASS | L2343, L2512, L2565; Q-15, Q-32 | FAIL. This independent review finds R1/R2. Historical report contents were intentionally not read, and no author or prior verifier verdict was substituted for this review. |

**Other discrepancies and verification limits**

The README header still names fe8c8e36 and its older review branches; section 3 still says the packet commit has no pushed CI run. Its status totals remain 62 DONE, one manual and one FAIL. Those descriptions are stale for this checkout, and this report uses the full actual SHA and successful exact-head run above. Keeping G2-64 FAIL pending independent verification is appropriate; the header is not itself a security failure.

dependency-review.md:85–90 lists 118/335/687 packages and says every crate declares a license. Current resolved lockfile/audit counts are 120/338/690. Metadata inspection found license metadata on the external dependencies; the local workspace packages lack that manifest field. No newly identified GPL-only dependency or unreviewed runtime advisory was established. The counts and “every crate” wording need a documentation correction. Accepted RustSec ignores and unmaintained warnings remain disclosed.

The hash checker validates a fixed list, not every source file in the repository; its passing result is not a proof of complete coverage or implementation correctness. The additional trust_chain.rs hash closes the identification gap for the F1 code in this review.

The Q-38 two-step substitution limit, Q-42 second-origin key-state limitation, fast-device-clock lease handling, orphaned bootstrap keys, Q-7 local-backup KDF choice and type-level zeroization are disclosed contract limitations. No stronger guarantee is inferred from their tests. Custodian-event/join screens fall under the UI deferral; R1/R2 are implemented backend behavior, so that deferral does not close them.

Not locally verified: the manual credential persistence/restart/locked-session cases; an actual FAT/exFAT identity-volume fixture (the common classifier is unit-tested); the local privileged symlink subbranches; macOS compilation; local Playwright/MCP execution; freed-memory wiping or physical power-loss durability. CI supplies macOS, frontend/MCP and symlink evidence. The durability tests supply process-kill and filesystem-primitive evidence, not a physical power interruption. Optional mutation scripts were read but not executed because they edit source. No new adversarial source fixture was added for R1/R2 under the read-only rule.

The aggregate tests and CI are green, and the historical regressions tested here are closed. The rest of the gate does not hold: ordinary snapshot pull still violates the explicit revocation and evidence-history rules. G2-48 and the deferred UI play no part in that failure.

**Exact per-row cargo command ledger**

Each command below was executed with the environment printed above. They are the packet's section-6 commands, with -j 2 and --nocapture inserted. The G2-48 filter is explicit. Every command has a final exit-0 execution; the G2-03 initial failure and rerun are disclosed above. Counts in the sampled row descriptions include substring-filter matches, so overlapping rows do not represent distinct tests. G2-62 and G2-64 have documentary/CI evidence rather than a section-6 cargo invocation.


~~~text
# G2-01
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt every_approval_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_approvals_that_left_their_containers --nocapture

# G2-01
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture

# G2-02
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup --nocapture

# G2-02
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture

# G2-03
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_fleet_grants_that_left_their_containers --nocapture

# G2-03
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture

# G2-04
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- recovery_grant_binds_context_suite_and_lengths recovery_grant_opens_only_under_its_root_and_to_its_fkek authz_record::tests::golden_vectors --nocapture

# G2-04
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request --nocapture

# G2-05
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- rotation_grant_follows_its_generation_window_and_count_rules authz_record::tests::golden_vectors --nocapture

# G2-05
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request --nocapture

# G2-06
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup --nocapture

# G2-06
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture

# G2-07
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- snapshot_v2::tests::golden_vectors payload_rejects_every_field_level_defect container_rejects_every_field_level_defect signing_binds_the_signer_key manifest_binds_a_sealed_envelope_v2_object --nocapture

# G2-08
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- every_upload_refusal_has_its_status_and_code --nocapture

# G2-09
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head --nocapture

# G2-10
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_closed_maps_parse_what_the_builders_write every_dek_slot_context_rule_is_enforced every_dek_slot_rule_is_enforced a_slot_that_differs_from_the_intent_is_refused the_reader_refuses_an_open_map g2_golden_vector_dek_slot g2_golden_vector_dek_slot_context_hash --nocapture

# G2-11
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_intent_bounds_are_the_plans every_envelope_intent_rule_is_enforced the_intent_and_slot_must_be_the_ones_the_manifest_names manifest_binds_a_sealed_envelope_v2_object g2_golden_vector_intent g2_golden_vector_intent_genesis --nocapture

# G2-12
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- restore_epoch::tests::golden_vectors leaf_roundtrips_and_refuses_contract_violations leaf_sets_must_be_non_empty_sorted_and_unique every_leaf_proves_and_every_tampering_fails a_proof_binds_tenant_profile_instance_epochs_count_and_root proof_parser_refuses_every_contract_violation g2_golden_vectors_merkle_roots --nocapture

# G2-13
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- transition_roundtrips_and_verifies transition_payload_refuses_every_contract_violation signed_transition_refuses_every_container_defect transition_signature_binds_key_bytes_and_label --nocapture

# G2-14
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- mutation::tests::golden_vectors every_map_roundtrips_byte_for_byte every_map_refuses_another_domain_or_version every_kind_has_one_scope_and_the_scope_must_match hashes_and_closed_fields_are_checked device_revoke_maps_carry_one_container_and_roundtrip fleet_lifecycle::tests::golden_vectors --nocapture

# G2-14
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- a_revocation_commits_its_fleet_activation_or_nothing a_revocation_commits_its_root_activation --nocapture

# G2-15
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- mutation::tests::golden_vectors every_map_roundtrips_byte_for_byte every_map_refuses_another_domain_or_version --nocapture

# G2-16
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response --nocapture

# G2-17
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup --nocapture

# G2-18
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant --nocapture

# G2-19
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant --nocapture

# G2-20
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- a_revocation_names_a_known_reason_and_its_outcome --nocapture

# G2-20
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- a_custodian_revokes_a_root_grant_but_never_the_last_one --nocapture

# G2-21
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes --nocapture

# G2-21
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_profile_is_published_with_its_first_lease_and_then_pushed every_publish_crash_point_resumes_with_the_exact_stored_bytes --nocapture

# G2-22
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed --nocapture

# G2-22
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key --nocapture

# G2-23
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head every_upload_refusal_has_its_status_and_code --nocapture

# G2-23
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte --nocapture

# G2-24
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot --nocapture

# G2-24
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_crash_point_resumes_with_the_exact_stored_bytes --nocapture

# G2-25
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed --nocapture

# G2-25
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_release_whose_reply_was_lost_is_replayed_byte_for_byte --nocapture

# G2-26
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_unbind_maps_round_trip_and_pin_the_tombstone the_unbind_maps_refuse_what_l953_does_not_allow --nocapture

# G2-26
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unbind_tombstone_outlives_its_binding_and_replays_exactly an_unbind_at_version_zero_omits_the_head an_unbind_cut_off_at_any_write_leaves_the_binding_whole an_unbind_is_refused_while_a_lease_request_or_journal_is_open --nocapture

# G2-27
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- xchacha20poly1305_matches_the_draft_vector golden_objects every_preamble_rule_is_enforced every_frame_rule_is_enforced the_stream_counter_stops_at_the_provider_maximum --nocapture

# G2-28
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_pinned_suite_matches_the_rfc_9180_vectors info_bytes_match_g2_vector only_the_granted_device_can_open grant_cannot_be_replayed_into_another_tenant_or_epoch the_fleet_grant_aad_is_the_label_the_length_and_the_info a_device_fleet_grant_opens_only_to_the_key_it_names a_sealed_fleet_key_opens_to_the_exact_same_bytes --nocapture

# G2-29
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- signature_binds_issuer_and_bytes small_order_issuer_key_never_verifies rfc8032_vectors_sign_and_verify_strictly speccheck_matrix_accepts_only_the_unambiguous_case g2_golden_vector_signed_container_hash --nocapture

# G2-30
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_device_revocation_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_device_revocations_that_left_their_containers a_revocation_of_another_instance_turns_v2_off_until_it_is_put_back a_revocation_quarantined_at_runtime_refuses_the_trust_evidence a_quarantined_revocation_that_verifies_again_is_served_again_after_a_restart a_marked_row_swapped_for_another_genuine_revocation_is_not_served_again a_corrupt_container_is_marked_without_a_hash_and_served_again_once_restored the_trust_evidence_reports_a_revoked_device_from_its_record_not_its_column a_revocation_row_swapped_for_another_genuine_one_does_not_answer_a_retry a_revocation_row_the_startup_pass_cannot_read_turns_v2_off --nocapture

# G2-30
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_kept_revocation_reloads_with_every_column_equal --nocapture

# G2-31
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response every_custody_operation_replays_its_lost_response_after_a_restart --nocapture

# G2-31
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_e2e -- v2_operations_replay_the_stored_response --nocapture

# G2-31
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot every_profile_operation_replays_its_lost_response_after_a_restart --nocapture

# G2-31
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- d1_replays_of_rolled_back_results_answer_as_superseded_and_kept_ones_replay --nocapture

# G2-31
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_publish_crash_point_resumes_with_the_exact_stored_bytes a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte every_crash_point_resumes_with_the_exact_stored_bytes a_release_whose_reply_was_lost_is_replayed_byte_for_byte an_unbind_tombstone_outlives_its_binding_and_replays_exactly --nocapture

# G2-32
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_new_database_reopens_with_its_schema_and_settings a_version_5_file_with_data_moves_to_version_6_keeping_every_row the_triggers_and_indexes_of_a_version_5_file_survive_version_6 --nocapture

# G2-33
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unbind_tombstone_outlives_its_binding_and_replays_exactly an_unbind_cut_off_at_any_write_leaves_the_binding_whole a_tombstone_that_no_longer_recomputes_is_never_returned an_unbind_after_an_accepted_transition_keeps_its_evidence a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding --nocapture

# G2-34
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_release_whose_reply_was_lost_is_replayed_byte_for_byte an_unsent_cancel_release_is_retried_and_then_given_up an_unreadable_release_reply_is_reported_and_replayed --nocapture

# G2-35
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- six_records_reopen_exactly_and_refuse_every_changed_column a_second_self_grant_and_a_cross_instance_generation_are_refused only_a_self_grant_files_a_generation_and_a_duplicate_row_refuses a_filed_grant_files_the_key_state_it_names a_binding_and_its_rows_name_the_servers_account_and_key a_kept_revocation_reloads_with_every_column_equal --nocapture

# G2-36
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key an_interrupted_upload_resumes_at_the_offset_head_reports --nocapture

# G2-37
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_crash_point_resumes_with_the_exact_stored_bytes a_stored_column_that_drifts_from_its_bytes_is_never_sent a_stored_publish_that_drifts_from_its_bytes_is_never_sent --nocapture

# G2-38
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_receipt_or_readback_that_does_not_match_is_never_kept a_published_profile_pushes_and_another_device_pulls_it an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key --nocapture

# G2-38
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head every_upload_refusal_has_its_status_and_code --nocapture

# G2-39
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_verified_transition_moves_only_the_bindings_it_covers a_transition_that_does_not_verify_keeps_the_binding_quarantined a_restore_epoch_that_goes_back_is_a_rollback a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen a_leaf_head_is_accepted_only_as_a_new_head_is a_pinned_head_is_read_back_only_as_the_bindings_own a_lapsed_or_former_custodian_signs_no_transition an_unbind_after_an_accepted_transition_keeps_its_evidence a_binding_changed_during_acceptance_is_not_moved a_lease_from_before_the_restore_is_released_before_the_binding_moves a_custodian_not_yet_appointed_signs_no_transition a_failed_release_of_an_old_lease_is_retried_as_stored --nocapture

# G2-40
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unknown_schema_fails_closed_and_is_left_as_it_was a_database_held_in_wal_mode_is_refused --nocapture

# G2-41
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_restore_phase_survives_close_and_reopen_in_order a_restore_phase_cannot_skip_repeat_or_leave_a_terminal_one a_restore_journal_retires_only_when_settled the_restore_resume_table_is_fixed_per_crash_point a_clone_journal_walks_its_chain_with_every_phase_surviving_reopen a_downgrade_phase_cannot_skip_and_a_rollback_is_always_open the_resume_table_for_a_downgrade_journal_continues_every_open_phase the_digests_survive_reopen_byte_for_byte a_cut_off_at_every_step_resumes_to_the_same_finished_clone a_process_killed_at_every_step_resumes_to_the_same_finished_clone a_rollback_from_every_step_puts_the_original_back_and_frees_the_profile a_readback_that_v0_1_28_would_not_agree_with_fails_the_flow discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive an_unbind_is_refused_while_a_lease_request_or_journal_is_open --nocapture

# G2-42
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_sync_integer_class_keeps_its_range_across_a_reopen every_integer_class_keeps_its_range_across_a_reopen --nocapture

# G2-43
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_publish_crash_point_resumes_with_the_exact_stored_bytes a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte every_crash_point_resumes_with_the_exact_stored_bytes an_unbind_tombstone_outlives_its_binding_and_replays_exactly a_release_whose_reply_was_lost_is_replayed_byte_for_byte a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh --nocapture

# G2-44
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_upgrade_chain -- the_plan_assertions_hold_on_a_reopened_fresh_file the_plan_assertions_hold_on_a_reopened_v0_1_28_file_and_its_backup_restores fixtures_1_to_4_hold_on_a_fresh_file fixtures_1_to_4_hold_on_a_v0_1_28_file_after_its_upgrade fixtures_1_to_4_hold_on_a_populated_0016_file_after_its_upgrade m0017_root_generations_only_move_forward_on_upgraded_rows m0033_the_quarantine_gains_a_container_hash_and_stays_append_only --nocapture

# G2-45
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_upgrade_chain -- m0030_upgraded_integer_columns_refuse_values_that_are_no_integers --nocapture

# G2-45
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_integer_domain -- every_class_decodes_its_domain_ends_and_refuses_everything_else every_class_column_stores_its_domain_ends_and_its_check_refuses_the_rest every_integer_column_of_every_v2_table_has_an_upper_bound_check every_integer_column_of_every_v2_table_refuses_a_value_that_is_no_integer the_bound_scan_tells_bounded_from_unbounded_columns --nocapture

# G2-46
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- argon2id_matches_the_rfc_9106_vector the_kek_is_argon2id_over_the_labelled_salt --nocapture

# G2-47
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- debug_never_prints_the_token_or_a_seed debug_never_prints_a_key a_session_debug_print_hides_its_tokens the_trk_is_stored_and_the_saved_state_holds_only_its_reference a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written the_saved_state_never_prints_the_legacy_trk a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key a_reference_to_another_credential_is_refused_and_that_credential_is_kept the_activation_is_saved_before_the_key_is_forgotten the_run_nonce_is_saved_before_the_key_is_stored a_new_run_never_reuses_a_key_an_abandoned_run_left a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it a_forget_succeeds_only_once_the_key_is_confirmed_gone --nocapture

# G2-48
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_key_round_trips_and_is_forgotten references_are_separate_credentials a_failed_write_or_read_back_is_reported a_real_os_store_key_survives_into_a_fresh_process an_unavailable_store_fails_closed_in_a_fresh_process a_key_file_key_is_locked_then_served_in_a_fresh_process --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process

# G2-49
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_durable_write_replaces_the_file_and_leaves_no_temporary a_failed_replace_keeps_the_old_file_and_removes_the_temporary a_write_killed_at_any_step_leaves_the_old_or_the_new_file a_kill_during_back_to_back_writes_never_tears_or_loses_a_returned_write creating_a_file_that_exists_never_overwrites_it --nocapture

# G2-49
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- only_a_local_ntfs_disk_is_accepted a_local_ntfs_directory_is_accepted_and_a_missing_one_is_not an_smb_share_is_refused --nocapture

# G2-49
cargo test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- storage_that_cannot_be_resolved_is_refused storage_on_an_smb_share_is_refused preflight_refuses_an_identity_directory_on_an_smb_share --nocapture

# G2-49
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- an_identity_directory_the_preflight_refuses_never_falls_to_k1 an_empty_identity_directory_setting_refuses_to_start --nocapture

# G2-50
cargo test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- the_database_runs_a_synced_rollback_journal_and_survives_an_unclosed_pool a_killed_transaction_reopens_old_or_new_never_half a_kill_between_commits_keeps_every_returned_commit a_second_writer_waits_for_the_write_lock storage_on_an_smb_share_is_refused --nocapture

# G2-50
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_killed_transaction_reopens_old_or_new_never_half a_database_held_in_wal_mode_is_refused --nocapture

# G2-50
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- an_smb_share_is_refused --nocapture

# G2-51
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_windows_path_corpus_is_refused_in_every_position every_name_windows_rewrites_is_refused ntfs_case_fold_collisions_are_refused_and_distinct_names_kept long_paths_unpack_and_an_overlong_one_is_refused a_junction_is_neither_packed_through_nor_followed_on_replace --nocapture

# G2-51
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive a_trace_of_the_old_id_after_the_move_fails_the_discovery_scan --nocapture

# G2-52
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- g2_52_every_crash_point_maps_to_one_row_and_resumes_to_the_restored_state --nocapture

# G2-53
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test identity_authority -- a_symlinked_record_is_refused show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest --nocapture

# G2-53
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- an_identity_directory_that_is_not_there_is_missing_and_stops_the_server --nocapture

# G2-54
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2259_g2_54_a_record_equal_to_its_mirror_without_a_manifest_opens_normally --nocapture

# G2-55
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2260_g2_55_a_durable_preparation_at_e_keeps_writes_off_until_commit_or_abort g2_55_a_failed_read_only_audit_write_is_counted_in_restore_status g2_55_the_k2_incident_output_prints_the_audit_failure_count g2_55_a_directory_at_the_count_path_stops_a_read_only_start_by_name g2_55_restore_commit_prints_the_final_audit_failure_count_and_clears_it g2_55_a_read_only_start_logs_the_failed_audit_writes_counted_so_far g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count g2_55_a_count_under_a_changed_episode_key_is_kept_and_cleared_by_name g2_55_a_count_file_with_a_bad_line_is_set_aside_and_its_valid_lines_kept --nocapture

# G2-55
cargo test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- a_failed_read_only_audit_write_is_logged_and_counted the_count_continues_across_read_only_restarts_of_one_episode a_changed_episode_key_keeps_the_old_count_until_it_is_cleared_by_name one_bad_line_in_the_count_file_loses_only_itself a_crash_while_setting_a_file_aside_never_loses_the_valid_lines the_count_is_written_atomically_and_an_unreadable_one_is_reported a_directory_or_link_at_the_count_path_is_refused_by_name --nocapture

# G2-56
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2261_g2_56_an_authority_ahead_of_the_live_mirror_resumes_only_the_install --nocapture

# G2-57
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2262_g2_57_an_installed_db_behind_the_record_is_verified_then_rebuilt --nocapture

# G2-58
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2263_g2_58_an_authority_ahead_without_exact_evidence_fails_closed l2263_g2_58_only_a_live_custodian_transition_over_the_computed_leaves_prepares --nocapture

# G2-59
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- g2_55_the_k2_incident_output_prints_the_audit_failure_count --nocapture

# G2-60
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2265_g2_60_a_reconciled_epoch_retires_its_bundle_and_the_next_start_is_normal --nocapture

# G2-61
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- a_snapshot_sealed_for_another_profile_is_refused every_single_byte_mutation_is_detected truncation_at_any_length_is_detected cross_envelope_frame_splice_is_rejected another_fleet_key_cannot_open_it grant_cannot_be_replayed_into_another_tenant_or_epoch tampering_with_the_stored_info_fails_the_open --nocapture

# G2-61
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --test backup_file_roundtrip -- the_ciphertext_does_not_contain_the_plaintext a_tampered_backup_body_is_refused a_truncated_backup_is_refused_and_leaves_the_destination_untouched --nocapture

# G2-61
cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- pull_refuses_another_profiles_snapshot push_seals_under_the_passphrase_even_with_a_cached_fleet_key a_server_delivered_fleet_key_is_counted_but_never_cached a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet a_compromised_revocation_blocks_commits_under_an_exposed_generation a_compromised_custodian_blocks_every_fleet_through_the_root an_exposure_survives_a_recollection_that_omits_its_grant an_open_upload_is_aborted_once_a_compromise_is_counted a_compromise_counted_mid_transfer_aborts_the_upload a_known_custodian_with_no_root_holding_blocks a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks a_stored_finalize_is_not_sent_once_a_compromise_is_counted a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code a_version_6_file_with_unreadable_kept_pages_still_opens --nocapture

# G2-61
cargo test -j 2 --locked --manifest-path server/Cargo.toml --test identity_authority -- an_interrupted_init_is_reported_and_never_repaired --nocapture

# G2-61
cargo test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- wrong_domain_hpke_ids_are_quarantined_once --nocapture

# G2-63
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --test registry_pins -- every_signing_domain_is_distinct_and_versioned every_hash_label_is_distinct_and_nul_terminated the_numeric_registry_holds_the_reviewed_values --nocapture

# G2-63
cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- g2_golden_vector_profile_label a_profile_label_opens_only_where_it_was_sealed a_profile_label_has_a_length_bound_both_ways a_profile_label_is_padded_to_a_bucket a_profile_label_that_is_not_canonical_is_refused --nocapture
~~~

VERDICT: FAIL

