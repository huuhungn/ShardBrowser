# G2-64 verifier report: Codex, 2026-11-01

The first 152 lines of the report Codex wrote as the blind G2-64 verifier, kept
verbatim except for repaired punctuation. The full report, with its command ledger
and citation inventory, stayed on the verifier machine. The verdict is FAIL; see
section 8 of `README.md` for the owner's decision.

---


**Outcome: the remaining G2 gate fails.** G2-48 PENDING-MANUAL and the Team UI deferral are accepted. Neither is the reason for this result. Four source-traced client trust/enforcement defects and three exact-contract/evidence gaps are detailed as B1 to B7 below. Runtime restrictions additionally prevent a complete green reproduction; they are kept separate from the confirmed findings.

Repository: `https://github.com/huuhungn/ShardBrowser`  
Worktree: `C:/Users/User/dev/wt/shardbrowser-g264-codex`  
Verified detached revision: `2b35d84ff7334ed351952d956d2e92ce58afd42a`  
Report date: 2026-11-01, Asia/Bangkok  
Output: `C:/Users/User/AppData/Local/Temp/g264-out/g2-64-report-codex.md`

## Environment and evidence identity

- Windows `10.0.26300.0`, x86_64 MSVC; Python `3.12.10`.
- Stable rustc `1.99.1 (58cf8f9c3 2026-10-13)`; cargo `1.99.1 (5f94df478 2026-08-27)`.
- Installed MSRV toolchains: `1.87.0`, `1.88.0`, `1.89.0`, all `x86_64-pc-windows-msvc`. All three were used; none was missing.
- Build/test commands used `CARGO_TARGET_DIR=C:/Users/User/AppData/Local/Temp/g264-target-codex` and `-j 2`. Test runners set TMP and TEMP to this private target for synthetic fixtures. Formatting/audit commands do not accept the build jobs option.
- No source patches or mutation scripts were applied. Final `git status --short` is empty. Two generated schema side effects were restored as described in Verification boundaries.

`python scripts/g2-evidence.py --check` ran at the start and again at the end. Both exited 0 with exactly:

```text
117 files checked, 0 problems
```

The script normalizes CRLF to LF before SHA-256 (`scripts/g2-evidence.py:147`); these are content hashes under that convention, not raw Windows checkout byte hashes. The complete independently checked 117-entry manifest is reproduced at the end of this report. Fixtures include the v0.1.28 SQL files, plan_assert SQL, and the source-embedded cryptographic vectors. The README and SHA256SUMS are excluded from their own manifest by design.

## Commands and outcomes

The detailed command ledger below preserves each exact row invocation, exit code and test result. Additional read-only verification used `git rev-parse HEAD`, `git status --short`, `rustc --version`, `cargo --version`, `rustup toolchain list`, `python --version`, repository file reads and bounded `rg` searches.

| Command family actually run | Outcome |
| --- | --- |
| `cargo +stable fmt --check --manifest-path <crate>/Cargo.toml`, individually for shared, server, src-tauri and sdks/rust | 4/4 exit 0. The requested three crates all pass. |
| `cargo +stable clippy --locked --manifest-path <crate>/Cargo.toml -j 2 --all-targets -- -D warnings`, individually for shared, server and src-tauri | 3/3 exit 0. |
| `cargo +stable test --locked --manifest-path shared/Cargo.toml -j 2` | Exit 101; library 282 passed, 18 failed, 0 ignored; stopped at the failed library. |
| `cargo test --locked --manifest-path shared/Cargo.toml -j 2 --no-fail-fast` | Exit 101; aggregate **287 passed, 27 failed, 1 ignored** across all targets/doc tests. All 27 failures report DPAPI protect errors during fixture setup. The ignored test is the explicit operator recovery drill at `shared/tests/p_op_recovery_drill.rs:138`. |
| `cargo test --locked --manifest-path server/Cargo.toml -j 2` | Exit 101; library 9 passed, binary 106 passed/2 ignored, then e2e_sync 3 passed/7 failed. |
| `cargo build --locked --manifest-path server/Cargo.toml -j 2` | Exit 0. |
| `cargo test --locked --manifest-path server/Cargo.toml -j 2 --no-fail-fast -- --test-threads=1` | Exit 0; complete suite **343 passed, 0 failed, 3 ignored**. Conditional SMB/symlink skips are included in cargo's passed counts and are not treated as verified behavior. |
| `cargo +1.87.0 check --locked --all-targets --manifest-path shared/Cargo.toml -j 2` | Exit 0. |
| `cargo +1.89.0 check --locked --all-targets --manifest-path server/Cargo.toml -j 2` | Exit 0. |
| `cargo +1.88.0 check --locked --all-targets --manifest-path src-tauri/Cargo.toml -j 2` | Exit 0. |
| README section 6 per-row cargo commands, with `-j 2` added and G2-48 omitted | **94 invocations: 71 exit 0, 23 exit 101; 239 passing, 65 failing, 0 ignored test executions.** Tests repeat between rows. Every permitted command was attempted; none timed out. |
| Targeted server diagnostics | e2e_sync: first one isolated test passed, then all 10 passed serially. G2-16 and G2-17 root tests: both passed serially. The original failures remain recorded; I did not prove their underlying cause. |
| Focused launcher diagnosis | `a_profile_is_published_with_its_first_lease_and_then_pushed` failed at `src-tauri/src/team/sync.rs:4090` with `[[shardx:keyStore.protectFailed]]`, before replay/resource assertions. Two direct trust-ledger tests passed; the extra collected-key test hit the same DPAPI setup limitation. |
| SMB/symlink diagnostics with `--nocapture` | Shared SMB 1 reported pass but SKIPPED; server SMB 2 reported pass but SKIPPED; identity symlink test 1 reported pass after directory check, symlink branch skipped with error 1314. |
| `npm.cmd run test:i18n`, `test:rust-strings`, `test:backend-locale`, `test:raw-error-toast` | All exit 0: respectively 16, 3, 7 and 2 passed (28 total). Initial plain `npm` was blocked by PowerShell script execution policy; npm.cmd ran the intended checks. |
| Three packet `cargo +stable audit --deny unsound --deny yanked --file ...` commands, preserving each listed ignore | All exit 1 before audit: advisory database lock under `C:\Users\User\.cargo` is read-only in this execution environment. cargo-audit 0.22.2 was already installed. Advisory results remain unverified. Exact ignore lists and errors are in the ledger. |
| Unfiltered `cargo test --lib` for src-tauri | **Not run:** it includes an unignored test that writes the actual Windows Credential Manager, contrary to the explicit no-touch constraint. Filtered cited launcher tests and all-target compilation were run. This omission is not used to fail G2-48 on its own. |

## What remains unverified

The full launcher suite; behaviors behind failed DPAPI-dependent fixtures (including local replay/transition cases and part of the Windows path/tamper corpus); actual SMB refusal; the identity-record symlink branch; current RustSec advisory results; manual G2-48 persistence; remote exact-SHA CI and macOS/frontend/MCP workflow results. No physical power-loss test or freed-memory inspection was performed. These limits preclude claiming universal reproduction even apart from B1 to B7. They are not substitutions for, or evidence of, the source-level failure scenarios.

## Independent semantic review and blocking findings

The remaining gate does **not** hold after accepting G2-48 PENDING-MANUAL and the Team UI deferral. The findings below concern backend/client enforcement and exact contract evidence. They do not depend on implementing the deferred UI. These are source-traced findings; I did not modify the repository to add exploit/regression tests. Runtime fixture failures are reported separately and are not presented as proof of these security defects.

### B1: Compromised-root exposure is omitted from the commit block

**Locations:** `src-tauri/src/team/ledger.rs:446`, `src-tauri/src/team/ledger.rs:511`, `src-tauri/src/team/ledger.rs:514`; call sites `src-tauri/src/team/sync.rs:1655`, `src-tauri/src/team/sync.rs:1736`, `src-tauri/src/team/sync.rs:2118`. Contract: `docs/adr/0002-g2-contract-decisions.md:1718`, `:1720`, `:1722`, `:1724`, `:1726`, `:1729`, `:1736` (Q-13/C-1/Q-18).

`commit_blocked` explicitly documents that it does not derive exposure through a root. Once the fleet verification evaluation is later than the counted revocation, it checks only `DeviceHpkeGrant` issuer/subject keys. It does not check the activation-bound RecoveryGrant, exposed root generations (including higher PREPARING roots), or missing activation evidence. It also omits exposure through the issuers of RecoveryGrant/RotationGrant.

**Failure scenario:** a compromised custodian D knows TRK N but has no direct DeviceHpkeGrant to or from D for fleet F. The client counts D's signed compromised revocation. Another honest custodian rotates F before rotating the root, wrapping its new FKEK under still-exposed TRK N, and the client verifies that generation after the revocation. The function returns false, permitting new ciphertext under a key D can recover. The ADR requires this fleet to stay blocked until root-first, then fleet rotation. The direct-grant/timing test at `src-tauri/src/team/sync.rs:5686` contains no root-exposure or rotation-order fixture. ADR-required vectors at `docs/adr/0002-g2-contract-decisions.md:1769` and `:1775` have no corresponding enforcement test found. This materially qualifies G2-03/04/05/06/30/35/61/63.

### B2: Recollecting the same generation can erase an already known exposure

**Locations:** `src-tauri/src/team/ledger.rs:658`, `:662`, `:664`, together with `:469`, `:511`, `:514`; collection path `src-tauri/src/lib.rs:2673`, `:2684`, `:2694`; grant persistence `src-tauri/src/team/records.rs:196`. Contract: ADR `:1716` (exposure never clears), `:1725` (history keeps cached exposure), `:1736` (higher, unexposed generation required).

Collecting an already known generation updates its `verified_evaluation` and replaces its evidence pages, provided the FKEK identifier is unchanged. The commit block then scans only these replacement pages. The persisted sightings do not restore the omitted grant into that exposure scan.

**Failure scenario:** an honest issuer E has granted the same generation to both this client and compromised member M. The client has seen M's grant and counts M's signed compromised revocation. On a later collection, a hostile server returns the still-valid grant to this client from E but omits M's grant. Same-generation collection is allowed, moves `verified_evaluation` beyond the revocation, and replaces the page set. M is neither issuer nor subject of the remaining grant, so `commit_blocked` returns false without a rotation. M still knows the unchanged FKEK. This is distinct from B1: it also affects direct fleet exposure. Existing tests prove key substitution is rejected and that revocation records persist; they do not prove that an exposure persists across replacement of the evidence for the same key. No runtime proof was added; the failure follows from the update and the subsequent scan.

### B3: An OPEN upload is resumed after a newly counted compromise

**Locations:** `src-tauri/src/team/sync.rs:1463`, `:1478`, `:1480`, `:1492`, `:2427`, `:2462`, `:2547`. Contract: ADR `:1731`, required test vector `:1777`.

The Q-18 check is in initial snapshot sealing and publish sending. Once an upload/COMMIT operation exists, the OPEN branch resumes transfer and finalize without checking the compromise ledger. `stored()` at `src-tauri/src/team/sync.rs:663` checks column/request consistency, not compromise status. The READY path is allowed by the ADR, but OPEN is not.

**Failure scenario:** push seals under a key held by M, persists COMMIT, and stops with unsent chunks while its upload is OPEN. The client then counts M's compromised revocation. Resuming push sends the remaining chunks and finalizes them rather than aborting and ending with `ROTATION_REQUIRED_COMPROMISED`. The thief gains ciphertext the client was required to withhold. No cited replay test injects a compromise between persistence and OPEN-upload resumption. This affects G2-24/31/37/43/61. Separately, `push` takes a new lease at `:1456` before reaching the check at `:2118`; the existing Q-18 test at `:5728` expects a release, whereas ADR `:1730` and `:1768` require refusal before checkout. That is an additional ordering discrepancy, not the disclosure mechanism above.

### B4: Valid fleet-scoped device revocations never become counted revocations

**Locations:** `src-tauri/src/team/ledger.rs:767`, `:787`, `:589`; server acceptance at `server/src/routes/v2_device_revoke.rs:342`, `:400`. Contract: ADR `:743`, `:767`, `:1529`, `:1708`.

The server accepts a current custodian's device-scoped `device.revoke` capability scoped to the fleet covering the subject's approvals. The client counts only `Scope::Tenant`. The comment acknowledges the narrower implementation. Custodians being tenant-approved does not make every capability they hold tenant-scoped, and the subject may be a fleet-approved non-custodian.

**Failure scenario:** a legitimate custodian with fleet-scoped device.revoke revokes a compromised fleet member. The server files the signed revocation and the client receives it, but `counted` drops it. Without a proven revocation entry, sticky signed-record handling and the Q-18 cause do not start, even though the signed evidence is present. Omitting later unsigned server revocation reports can leave encryption under the member's known FKEK enabled. `src-tauri/src/lib.rs:3541` tests only the narrowed tenant-capability rule. Its focused rerun passed, demonstrating existing coverage of that narrower rule, not the ADR's fleet-scope rule. This qualifies G2-30/35/61/63.

### B5: The closed revoke map rejects ADR-valid optional activations

**Locations:** `shared/src/mutation.rs:1018`, `:1036`; `server/src/routes/v2_device_revoke.rs:8`. Contract: ADR `:1702` allows 0..65535 activations; `:1709` requires each included activation to be validated and committed atomically with the revocation.

The type has no activation payload and the parser accepts only an empty array. **Failure scenario:** a conforming client submits a signed device revocation with one valid prepared generation activation; parsing rejects the entire request, so neither action happens. This is a fail-closed interoperability/availability gap, not a confidentiality bypass. The comment says it is deferred until a client sends one, which is not an ADR amendment. `shared/src/mutation.rs:2286` tests the empty-map case and rejects a nonempty malformed example; it has no valid nonempty activation fixture. G2-14's exact contract claim and G2-61's Q-13 coverage are incomplete.

### B6: G2-42 proves lossless coercions succeed, opposite to the cited probe

**Locations:** plan `.omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md:2047`; `src-tauri/src/team/db.rs:2858`; related integer test `src-tauri/src/team/records.rs:674`; packet `docs/g2-evidence/README.md:232`.

Probe 10 explicitly says REAL/TEXT coercion fixtures reject before mutation. The test instead writes numeric TEXT and integral REAL successfully, then asserts SQLite stored an exact INTEGER. **Failure scenario:** submit the numeric TEXT form of the maximum value, or an integral REAL, to the local DDL; the cited test expects the write to succeed instead of the required rejection. Both G2-42 tests passed here, so this is a demonstrated expectation/contract mismatch. The storage-value range itself is preserved; I found no truncation/wrap vulnerability in this test. The cited D-6 decision does not amend this probe. Exact G2 conformance needs either the approved contract clarified or conforming enforcement/evidence.

### B7: G2-31's "durable response-loss replay, every operation" is not established by its cited matrix

**Locations:** packet `docs/g2-evidence/README.md:221`; generic replay test `server/tests/v2_e2e.rs:251`; closed operation set `shared/src/mutation.rs:84`; gate plan `:2343`.

The generic test sends prototype JSON `operation_kind = profile.push` to `/v2/operations`, manually completes it with arbitrary bytes, and replays without a restart. It does not exercise the 17 closed mutation kinds or their actual resource mutations. Other cited tests materially cover real approval/bootstrap/profile/lease/upload/commit/unbind behavior and some restart/restore cases, so this is not a claim that replay is wholly untested. But the cited G2-31 set does not supply a per-operation durable response-loss/reopen/no-second-resource matrix for the fleet lifecycle, root grant create/ack/activate/revoke and device revocation paths. **Failure scenario not ruled out by the evidence:** an omitted route persists its resource but loses or misbinds its idempotent response at a restart, and the retry executes again or returns a response for a different resource while the listed generic test remains green. This is an evidence blocker under the gate's explicit uncertainty rule, not a demonstrated duplicate-resource product bug.

## Other discrepancies and limits of the packet

- **G2-28 golden label overstates its test.** `shared/src/grants.rs:616` says the info bytes are pinned as a hash, but `info_bytes_match_g2_vector` at `:619` merely checks canonical roundtrip. A canonical field/preimage change can pass it. There is compensating exact root-grant-info evidence in `shared/src/authz_record.rs:2019` (length 460, SHA-256 `83cf05a9e2a487fa64210dfa9fdc2486e9e84615f1a4842d920c8190a42f1493`), run by the shared suite and other packet rows. Thus the misleading citation is not independently a missing-vector blocker.
- **Conditional passes are not completed evidence.** Shared SMB test `shared/src/volume.rs:179`, server SMB tests `server/src/db.rs:371` and `server/src/identity.rs:697` return early without a reachable share. Explicit nocapture runs printed SKIPPED. Restore harness network-only portions also depend on the same facility. G2-49/50 and the network part of G2-55 remain unverified locally. The README discloses this, and the repository CI workflow creates a share; that does not reproduce it in this run.
- **G2-53 symlink coverage partly skipped.** `server/tests/identity_authority.rs:194` first proves refusal of a directory at the record path. Its symlink branch at `:213` returns when Windows privilege is absent; the diagnostic run printed OS error 1314. Its cargo result is one passed test, but the actual symlink behavior was not exercised. CI makes that condition fatal.
- **Crash helpers are intentionally ignored, not missing parent tests.** The cited parent tests are active. Helpers run in child processes with `--ignored` and named reached-point markers; the parent asserts the marker/kill outcome. The isolated ignored helpers do not weaken their cited parent tests. The standalone shared full-suite ignored test is reported in the counts, not silently counted as evidence.
- **Stale line references:** G2-21/22/25 cite plan L1137/L1138/L1140, which do not identify their respective current routes exactly (publish/checkout/release). The broad L915 operation section is still relevant. G2-54..60 test names carry older plan line numbers, a discrepancy the packet already notes. G2-59's record-behind case is actually asserted in the G2-60 test at `server/tests/restore_epoch_harness.rs:2057`; its cited G2-55 test covers the other-instance incident. The combined row runs cover both.
- **Secrecy evidence is type-level.** G2-47's passing tests establish redacted Debug output, credential references, migration and ordering, and Zeroizing/ZeroizeOnDrop contracts. They do not inspect freed heap pages; the packet accurately says so. I checked the apparent enrollment fallback in `src-tauri/src/lib.rs:2145`: on Windows `team_config::save` calls DPAPI conceal at `src-tauri/src/team_config.rs:304`, so I do not report those seed fields as cleartext Windows storage.
- **Scope exceptions honored:** G2-48 remains PENDING-MANUAL by the owner's decision. No real credential-store test or manual persistence script was run. The Team UI deferral is accepted. G2-41's lack of a full production restore-journal writer is disclosed by the packet and does not invalidate the specified journal/probe test by itself.
- **Commit/CI scope:** verification is of the supplied detached PR tree. The packet's older CI run identifiers are not proof for this SHA. Under the repository-only instruction I did not query GitHub, and I did not assert that the future merge commit on main, macOS job, frontend/MCP checks, or release workflows passed. I did inspect the repository workflow's gate definitions. This report makes no release-main CI claim.

## Deep samples: evidence read against production paths, plan and ADR

The citation inventory earlier in this report resolves all 307 row-to-function citations (255 distinct functions), including helpers used for assertions. I checked for missing functions, ignored parents, assertion-free stand-ins and early returns. The following 20 rows received deeper production-path review. All mandatory sample rows are included. The all-row command ledger and final per-row counts distinguish passing code checks from runtime fixture limits.

| Row | Independent semantic finding and contract readback |
| --- | --- |
| G2-07 | Read manifest payload/container parsing, signer binding and seal-object hash/intent checks in `shared/src/snapshot_v2.rs`. The negative matrices alter fields and demand parse/verification failure; they are not success-only roundtrips. Six filtered tests passed. Plan L509-L589, Q-1/Q-36 are relevant. |
| G2-14 | The request/hash/domain/scope tests exercise actual closed-map parsers, including canonical request identity. Seven filtered tests passed. Plan L910-L1054 and Q-5/Q-13 match the family, but B5 means the Q-13 activation extension is not complete. |
| G2-27 | Read seal/open/preamble/frame validation and the matrix at `shared/src/envelope_v2.rs:1461`: bad framing, finality, trailing bytes and provider counter limits are rejected. Five tests passed. ADR 0003 selects StreamLE31; the older ADR 0002 provider discussion is not used to misidentify the final stream format. Plan L1352-L1371/D-3 checked. |
| G2-28 | Read root grant info, HPKE seal/open, fleet AAD construction and RFC 9180 vectors. Seven tests passed. Tenant/epoch/recipient binding is genuinely tested. Plan L1358/D-8/D-5 checked. The named info "golden" is weaker than claimed, with the compensating exact pin described above. |
| G2-29 | Read strict Ed25519 verification, RFC 8032 and speccheck cases, and signed-container hash preimages. Five tests passed; small-order/ambiguous inputs are asserted against strict verification. Plan L2335/D-8 checked. |
| G2-30 | Read the revocation all-column matrix at `server/tests/v2_auth.rs:9328`, startup quarantine and `server/src/routes/v2_device_revoke.rs`/`server/src/integrity.rs` reload paths. Ten server tests passed. The local reload test failed in fixture setup, not at the equality assertions. The other six record families are covered by G2-01..06 matrices; Q-13's seventh-record amendment is correctly represented. B1/B4 show that equality evidence is not complete revocation-policy evidence. |
| G2-31 | Read generic and real route replay tests and local persisted-operation paths. Seven server tests passed; six local tests failed at setup. Resource-count and exact-byte assertions exist for real profile workflows. The generic prototype test and the missing every-operation durability matrix are B7. Plan L1424/L2048/L2338 and Q-34/Q-42 checked. |
| G2-35 | Read `records::columns`, row conversion, keep/load, and `src-tauri/src/team/records.rs:487`. The all-column test asserts 5 x 57 + 41 = 326 mutations, close/reopen equality, second self-grant and cross-instance generation constraints; it is not just an assertion count. Four tests passed, two sync-fixture tests failed. The seventh record lives in the separate revocation ledger, consistent with Q-13's explicit exception for this local table. B2/B4 concern policy beyond the correctly scoped storage-equality matrix. |
| G2-41 | Read journal phase transitions/resume tables at `src-tauri/src/team/journal.rs:701` and production downgrade ordering/rollback, including real child kills at `src-tauri/src/team/downgrade.rs:1828`. Thirteen tests passed; the unbind guard test failed at sync setup. Close/reopen and old-version discovery/readback assertions are meaningful. Plan L2046/Q-35/Q-40 checked; optional mutation scripts were not run because they edit source. |
| G2-42 | Read local DDL integer domains and both integer-class probes (`db.rs:2746`, `records.rs:674`). Both passed and preserve max integers across reopen, while explicitly permitting lossless TEXT/REAL conversion. Plan L2047 disagrees with that expectation (B6); D-6 is not a waiver. |
| G2-43 | Read publish/crash/replay tests at `sync.rs:4516`, `:4271`, `:7276`, production operation persistence and response settlement. Tests compare exact stored request/response bytes and resource counters; World opens fresh DB handles. All seven cited local tests failed before these assertions due to fixture protection. Even if those tests pass elsewhere, the missing OPEN-compromise interruption is B3. Plan L2048/D-7/Q-42 checked. |
| G2-44 | Read fresh/v0.1.28/populated-0016 upgrade fixtures, plan_assert SQL, FK/UNIQUE checks and backup restore hash validation at `server/tests/v2_upgrade_chain.rs:1307`. Seven tests passed. These use real reopened files and preserve original backup bytes, not only an in-memory schema. Plan L2080-L2222/Q-34/Q-38 checked. |
| G2-45 | Read upgraded integer column migration and the domain/DDL scan, including a deliberately unbounded-column control. Six tests passed. The fixture checks integer storage/domain limits and rejects overflow values, rather than trusting Rust casts. Plan L2338/L2343/D-6 checked. |
| G2-47 | Read bootstrap TRK storage, migration, run nonce, credential-reference ownership, save-before-forget and failure ordering, plus redaction/zeroization declarations. Seventeen tests passed with mock credentials. Real credential persistence is a separate accepted deferral. Plan L2335/D-5 checked. |
| G2-49 | Read production durable replace/create, sync_all and Windows MoveFileEx WRITE_THROUGH, plus kill points at created/written/synced/replaced/returned (`durable.rs:233`, `:269`). All 13 selected tests reported pass, but three of those are SMB early-return passes. Local NTFS behavior and classification are exercised. Plan L1175/L2250/L2337, Q-30/Q-39 checked. Physical power-loss durability beyond OS contract is not inferred from process kills. |
| G2-50 | Read DELETE/FULL SQLite setup, lock-wait test, real killed-transaction/commit-order harness and WAL refusal. All eight selected tests reported pass; two are SMB early-return passes. `mem::forget` of a pool alone would be weak crash evidence, but separate killed-child tests supply the process-crash checks. Q-16 permits the rollback-journal design; Plan L2063/L2337 and Q-30/Q-31 checked. |
| G2-52 | Read the restore crash-point table traversal and startup/commit classification paths. Its one test iterates the table and passed. Per-case assertions are supplemented by G2-53..60. Plan L2250-L2269/L2339, D-1/Q-30/Q-33/Q-35 checked. |
| G2-55 | Read preparation at E, failed manifest/changed-DB/abort handling and preservation of authority bytes at `restore_epoch_harness.rs:1674`, plus production restore classification/commit and persisted audit failure counting. Sixteen selected tests reported pass, with the network-specific portion conditional. Plan L2262, D-1/Q-38 checked. It asserts writes stay off until commit or abort and that audit failure counts survive restart/episode changes. |
| G2-58 | Read ahead-without-evidence refusal and signed transition authorization over computed leaves. Two tests passed; malformed or wrong-custodian evidence leaves the authority/install state untouched. Plan L2265, D-1/Q-33/Q-36 checked. |
| G2-63 | Read the required repository security artifact, production profile-label derivation/AAD/padding/canonicality, and registry tests. Three registry plus five label tests passed. The registry pins 67 domains and 20 labels (87 distinct tagged entries), not an outdated count. The profile-label golden at `shared/src/keys.rs:578` is an actual fixed vector. Plan L2341/D-8/Q-41 checked. These crypto checks do not cover Q-18 lifecycle enforcement; B1 to B4 remain outside the packet's security evidence. |

## Verification boundaries

No author review reports, `.omc/`, `.omx/reports/`, or other scratch directories were consulted. The specified plan, ADRs and repository evidence artifacts were used. The only authored output is this report. Build/test intermediates and synthetic test fixtures were placed under the designated private target by setting CARGO_TARGET_DIR, TMP and TEMP. No real ShardX launcher data or Windows Credential Manager entry was intentionally accessed. The G2-48 command was withheld because its unignored `a_real_os_store_key_survives_into_a_fresh_process` at `src-tauri/src/credential.rs:263` writes the actual Windows store at `:268`. The unfiltered launcher `cargo test --lib` would include it, so that essential full-suite command was not run; the packet's other filtered launcher commands were run instead. Some credential tests also fall back to the default config path, so a blanket skip of just that one real-store test would not establish the requested no-touch guarantee.

The build scripts changed two tracked generated Tauri schemas. After all launcher builds/tests finished, I restored only `src-tauri/gen/schemas/desktop-schema.json` and `src-tauri/gen/schemas/windows-schema.json` to HEAD checkout-filtered bytes, and `git status --short` was clean. There were no implementation edits, commits, pushes, comments, issues or PR changes.

