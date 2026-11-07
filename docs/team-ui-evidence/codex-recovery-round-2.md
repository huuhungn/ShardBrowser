# Independent recovery verification, round 2

Verified HEAD: `3c38057a95e9cb272f048a22296a949d07bac007`.

Baseline: `git diff 6bb928d2..HEAD`. Verification date: 2026-11-07, Windows. Production code remained at this HEAD; the working-copy changes are verifier tests and this evidence. No commit, push, PR, or issue was made.

Three reproducible defects were found: Reset accepts an omitted account identity, Reset treats an unreadable pin database as an absent pin and deletes a working identity, and the Team page offers Reset for an interrupted root bootstrap that the backend protects. Goals **2, 7, and 9 are VIOLATED**. Goals **1, 3, 4, 5, 6, and 8 HOLD** within the documented shipped custody model and the tested paths.

## Scope and method

The normative sources were only ADR 0002's Q-12/Q-13 decision rows, D-5 including the plaintext-v3 amendment, D-9, ADR 0004's key-storage decisions, `docs/key-custody.md`, and the verbatim master-design excerpts supplied in the request. No author plan, previous review/evidence report, `.omc/`, `.omx/`, or scratch directory was consulted. The master design was not searched for. The required session-resume tool returned only this task's title, not earlier findings.

The test pattern used for additions is the repository's existing current-thread loopback mock, temporary config/data roots and mock credentials (`fleet_custody::tests::mock`, `custody_tests::joiner`, `recovery_import::tests::fixture`, and `custodian_it`); the UI addition follows the existing `teamDevicePage` and IPC interception tests in `tests/e2e/app.spec.ts`. These are verification additions to established patterns, with no new product feature or prior-art survey needed.

Cargo ran offline (`CARGO_NET_OFFLINE=true`), and npm was set offline. Feature-test traffic was confined to local loopback fixtures. The real server was built before `custodian_it`; those tests used `--test-threads=1`. Every launcher invocation used `--lib` and explicitly skipped `a_real_os_store_key_survives_into_a_fresh_process`. That real OS-store test was never run. Library tests select `keyring_core::mock::Store` (`src-tauri/src/credential.rs:68`); all state-mutating fixtures used temporary roots, not the user's `%APPDATA%\shardx-launcher`.

Tooling deviation: after a context-mode execution error, its required diagnostic reported a built-in npm package-version lookup. This was not feature/test traffic and was outside the requested loopback-only boundary. No feature data or credentials were submitted by this verification. No tool or dependency was upgraded.

## Confirmed defects

### D1 — Reset's account check accepts an absent account ID

**Location:** `src-tauri/src/lib.rs:3085`, with `src-tauri/src/fleet_client.rs:1059` and `:1091`.

`account_device_status` defaults a missing `/v2/me.account_id` to an empty string and discards the login ticket's account ID when constructing its result. Reset compares the saved owner only if both strings are nonempty. A login ticket can therefore name account B while `team.json` names account A, and a `/v2/me` response omitting `account_id` but listing A's device as pending gets past the ownership check. Reset then clears A's identity and forgets both readable credentials.

The new regression test uses exactly that ticket/listing discrepancy and asserts both refusal and preservation. It fails with `refused=false, identity_kept=false, credentials_kept=false`. This requires a manipulated/inconsistent server listing; it is not a claim that the honest server normally lists another account's device. The client already has the ticket account and should require a nonempty matching account, also checking listing/ticket consistency.

**Affected goals:** 2 and 7. **Impact:** destructive fail-open ownership validation; the pending path does not preserve a backup.

### D2 — An unreadable trust ledger turns an active pinned device into a resettable one

**Location:** `src-tauri/src/lib.rs:3092`, `:3373`, and `:3125`.

Reset asks `pinned_anchor(&c).is_some()`. The fallback in `pinned_anchor` turns `tenant_pin` errors into `None` with `.ok()??`. Consequently a damaged/unreadable `team-sync.db` is treated as proof that the device is unpinned. For a device that previously completed pinning and whose server row is still active, Reset is allowed. Since its seeds remain readable and its row is not revoked, `keep` is false, so Reset clears `team.json` and deletes both credentials without preserving the old identity.

The new test pins an enrolled device, proves the pin is readable, corrupts only the temporary ledger, confirms `Db::open()` fails, and calls Reset against an active listing. It fails with `refused=false, identity_kept=false, credentials_kept=false`. No false revocation is needed. Reset must distinguish an absent pin from a pin-read error before permitting destructive cleanup.

**Affected goals:** 2 and 7. **Impact:** loss of a working identity after local ledger corruption, bypassing the active-and-pinned guard.

### D3 — The lost-key UI offers Reset for an interrupted root bootstrap

**Location:** `src/features/manage-team/ui/TeamCard.tsx:579`; backend refusal at `src-tauri/src/lib.rs:3061`.

The lost-key branch distinguishes custodians using only `boot.activated`. An interrupted bootstrap can have `started=true`, `activated=false`, saved root identity and a saved create request; the server may already have accepted/activated that request. The UI renders the member Reset button in this state. The backend refuses Reset for any root state naming this tenant/device, even before activation, so the offered action cannot complete. The root identity itself remains protected.

The new Playwright test starts from the lost-root-keys fixture and changes only the bootstrap status to `started=true, activated=false`, remounts Team, and asserts zero Reset buttons. It fails with **Expected: 0; Received: 1**. The existing backend test `enroll_again_is_refused_for_an_active_pinned_or_custodian_device` proves refusal even with an unactivated root state; `connection_change_preserves_an_unfinished_root_identity` covers the saved-create case. The UI needs to represent this protected interrupted-root state explicitly.

**Affected goal:** 9. **Impact:** misleading recovery guidance and a guaranteed backend refusal, not key deletion through that button.

## Goal-by-goal evidence

### Goal 1 — Tenant, account, server instance and listed device binding: HOLDS

**Enforcement path:** `recovery_import::run` opens/authenticates the bundle (`src-tauri/src/recovery_import.rs:244`); `custodian_of` checks the saved tenant (`:131`); `check_pin` preserves the existing anchor (`:158`); `check_listing` requires the bundle's instance/account and an active row with both matching key IDs (`:169`). The session binding checks every expected identity/key field (`src-tauri/src/fleet_client.rs:165`, `:542`), and `check_root_grant` requires exact signed self-grant readback, ACTIVE generation, acknowledged grant and the same unwrapped TRK (`src-tauri/src/recovery_import.rs:202`). State writes occur only after these checks (`:340`).

**Tests:** recovery-import negative listing tests cover each key ID independently, other account, other instance, revoked row and no state/session side effects; the real-server negative import test covers another tenant and a second server. New pending/revoked-root-grant and malformed-v3 tests close the grant-state and full-entry-path gaps. See the goal output below and complete run output appendix. D1 concerns Reset's different ownership path, not import.

<!-- GOAL-1-OUTPUT -->

### Goal 2 — Preserve working device identity and root custody: VIOLATED

**Enforcement path:** import's `custodian_of` rejects a different device or readable different seeds (`src-tauri/src/recovery_import.rs:144`); its write phase rechecks the local identity and root/custody states (`:381`, `:393`, `:402`) and commits `team.json` last (`:479`). Reset rejects root state before and after the request (`src-tauri/src/lib.rs:3061`, `:3098`), and retains credentials plus an identity copy when a server merely says revoked (`:3108`).

**Tests:** existing working-identity, concurrent identity/root-state change, revoked-row credential preservation and lost-root import tests pass. Both new Reset regressions fail: D1 and D2 bypass guards and clear a working non-root identity. Root Reset refusal and preservation on a falsely revoked row still hold.

<!-- GOAL-2-OUTPUT -->

### Goal 3 — V3 custodian block consistency: HOLDS

**Enforcement path:** `RootCustodian::check` verifies the signing seed's anchor ID, signature, FirstRootSelfGrant variant, tenant/instance/root ID/generation/account/device/signing ID, and HPKE opening to the bundle TRK (`shared/src/recovery_bundle.rs:291`). The parser dispatches strictly on plaintext domain/version and closed fields (`:391`); root/FKEK IDs are re-derived (`:420`, `:430`, `:590`). `open` invokes the custodian check before returning (`:593`), and import enters through `open` (`src-tauri/src/recovery_import.rs:260`).

**Tests:** shared mutation cases cover wrong signing/HPKE seed, account/device/tenant/instance, TRK, root generation, grant variant, malformed grant and mismatched domain/block presence; the frozen v2 fixture remains accepted. The new full-entry import test seals an authenticated v3 with the wrong custodian HPKE seed, then proves refusal before any network request and byte-identical state files. Assertions inspect behavior, not just a successful seal.

<!-- GOAL-3-OUTPUT -->

### Goal 4 — 2.7 compatibility, bootstrap resume, and preserving a good older export: HOLDS

**Enforcement path:** `shared/src/recovery_bundle.rs:394` retains v2 decoding. `root_bootstrap::check_bundle` accepts the previously pinned v2 bytes (`src-tauri/src/root_bootstrap.rs:411`); `reusable_bundle` requires v3 with the exact saved custodian/self-grant before create (`:431`); step 3 applies this only while `create_request` is empty (`:783`). Export verifies the sealed candidate and synthetic-key probe before replacing the path, performs a durable write, then checks exact final-path readback (`:398`; `shared/src/recovery_bundle.rs:612`). Export again requires a live self-grant and the ACTIVE generation's retained key (`src-tauri/src/root_bootstrap.rs:998`). UI requires matching passphrases and the export fingerprint tick (`src/features/manage-team/ui/TeamCard.tsx:125`, `:184`, `:656`).

**Tests:** frozen 2.7 fixture round-trip, v2 reuse rejection, pinned-v2 acceptance, failed export preservation of a genuinely openable prior bundle, final-path readback and export-before-fleet-key refusal all pass. The existing two v2 bootstrap unit tests exercise helpers; the new real-server test additionally resumes the entire bootstrap twice: unpinned v2 becomes v3, while a v2 hash already filed in a generation-create request remains byte-identical and activates on replay. Both runs assert a single root generation. The existing integration assertion in `src-tauri/tests/fleet_enrollment_it.rs:859` was read, but that separate integration target was not invoked because launcher execution was constrained to `--lib`; the real-server library journeys and the new resume test provide executable coverage here.

<!-- GOAL-4-OUTPUT -->

### Goal 5 — Secret leakage to state, IPC, logs and errors: HOLDS within the documented custody model

**Enforcement path:** imported seeds go through credential-store readback (`src-tauri/src/recovery_import.rs:473`) and are removed from the saved config (`:487`). Bootstrap stores a TRK reference and releases the setup copy after activation (`src-tauri/src/root_bootstrap.rs:471`, `:638`); fleet key persistence protects file copies and moves them into the credential store (`src-tauri/src/fleet_keys.rs:283`, `:373`). Secret-bearing Debug implementations redact material (`shared/src/recovery_bundle.rs:245`, `:335`; `src-tauri/src/team_config.rs:69`; `src-tauri/src/fleet_keys.rs:138`; `src-tauri/src/fleet_client.rs:134`). IPC exposes counts/status, not unwrapped keys (`src-tauri/src/lib.rs:3638`). Import/export logs name only error codes (`src-tauri/src/recovery_import.rs:61`; `src-tauri/src/lib.rs:2566`).

The client retains login passwords only for redaction, hides passwords and bearer bodies on subsequent refusals, and keeps only a screened code for refused logins (`src-tauri/src/fleet_client.rs:257`, `:277`, `:358`, `:425`). Sync uses that same client redactor (`src-tauri/src/team/sync.rs:819`). The UI clears the account password before import/export/Reset calls (`src/features/manage-team/ui/TeamCard.tsx:191`, `:207`, `:222`).

**Tests:** the subprocess journey scan executes real import/export/collect/revocation and checks logged output, IPC replies and saved device state for the eight generated key/seed values, both passwords and session-token syntax. It asserts that the worker actually passed and required files/replies were present. Credential/file-state/Debug tests and token/password echo tests also pass, including sync after login. This is a Windows verification: DPAPI and the mock credential store are exercised. ADR 0004's documented fallback locations, same-user compromise, and `key-custody.md`'s explicit unrecognized server-encoding limitation are not asserted away by a passing scan. No secret material is included in this report.

<!-- GOAL-5-OUTPUT -->

### Goal 6 — Recollect after Reset/import and exclude unverified FKEKs: HOLDS

**Enforcement path:** Reset unindexes unreadable keys and removes old device acknowledgements (`src-tauri/src/lib.rs:3121`); import replaces member custody or retains only the custodian's own matching grant acknowledgement (`src-tauri/src/recovery_import.rs:429`, `:453`) and unindexes unreadable generations (`:469`). `forget_device_acks` persists the cleared acknowledgement map (`src-tauri/src/fleet_custody.rs:1209`); `ack_device_grant` binds the new request to the collected grant (`:589`). Collect verifies the pinned trust chain and the opened key before storage (`src-tauri/src/lib.rs:3263`, `:3423`); the store refuses key substitution (`src-tauri/src/fleet_keys.rs:234`). `verified_keys` exports only verified generations and fails on an unreadable verified key (`:264`).

**Tests:** real-server member Reset with missing keys and a transient unavailable fleet-key store both re-enroll, approve, collect generation 0, and verify the new device's acknowledgement in the database. Fresh and same-root recovery imports collect successfully. Unit tests cover stale acknowledgement removal, unopenable index entries, substitution refusal, rejection of untrusted evidence, export selection and retention of previous keys. A real conflicting readable key is deliberately still refused and surfaced; the goal's successful recovery path does not silently overwrite it. Legacy unverified keys already cached by 2.4.2 remain the documented compatibility exception and are excluded from recovery export.

<!-- GOAL-6-OUTPUT -->

### Goal 7 — Reset only an owned device that is eligible: VIOLATED

**Enforcement path:** `account_device_status` looks up the requested device in the signed-in account listing (`src-tauri/src/fleet_client.rs:1051`); Reset compares the saved owner (`src-tauri/src/lib.rs:3085`) and `enroll_again_allowed` permits pending/revoked or active-without-pin only (`:3178`).

**Tests:** unlisted-device refusal, nonempty different-owner refusal, active-pinned refusal and permitted pending/revoked cases pass. D1 shows the owner comparison fails open when `/v2/me.account_id` is omitted. D2 shows an unreadable persisted pin is treated as no pin. The new tests assert refusal, byte-preserved identity and preserved credentials and both fail on all three checks.

<!-- GOAL-7-OUTPUT -->

### Goal 8 — Root connection-change protection and stored fleet-key retention: HOLDS

**Enforcement path:** connection changes load the root state with error propagation, protect activated/saved-create root identities, and allow the documented lost-both-seeds case only with a saved config copy and no credential deletion (`src-tauri/src/lib.rs:2037`, `:2049`, `:2069`). Locked/unavailable stores do not count as lost (`src-tauri/src/team_config.rs:172`). `unindex_unopenable` copies the original fleet-key index before dropping only index entries, retains locked entries, and never calls credential deletion (`src-tauri/src/fleet_keys.rs:322`). Both Reset and import use this helper.

**Tests:** corrupt root state, live/locked/unavailable root seeds, both-lost root seeds, and saved-create unfinished bootstrap are covered for both URL and tenant changes. Index tests compare the exact backup bytes, verify other fleets and readable/locked generations are retained, and reload the credential after a transient read fault. The real-server Reset/rejoin unavailable-store test proves this through commands. D2 concerns the separate join-pin database on a non-root device, not bypass of root-state connection-change guards or deletion of a stored FKEK.

<!-- GOAL-8-OUTPUT -->

### Goal 9 — Honest recovery actions and visible fleet-key refusals: VIOLATED

**Enforcement path:** import passes its collect report to the shared renderer (`src/features/manage-team/ui/TeamCard.tsx:200`, `:231`); substitution is reported before general failure/waiting (`:252`); import's `finally` refreshes identity even if collect fails (`:215`). Activated roots and unreadable root state suppress Reset (`:64`, `:579`). Export needs a usable/blocked held fleet key and a readable recorded fingerprint (`:674`). Backend import reports a completed import followed by collect failure distinctly (`src-tauri/src/lib.rs:3165`).

**Tests:** existing Playwright cases for failed evidence, substitution, root lost keys, root unavailable store, unreadable root state, export prerequisite and fingerprint confirmation all pass. The full final suite has 96 passing tests and one failure, the added interrupted-root Reset regression D3. A prior teardown/trace-stream failure was reproduced as a passing original test on the final run; it is not reported as a product defect. The page's active-root and refusal rendering are protected, but its `started=true, activated=false` lost-key branch still offers a backend-forbidden Reset.

<!-- GOAL-9-OUTPUT -->

## Test integrity and execution notes

The relevant test bodies were checked for substantive assertions and exercised paths. The new regressions contain no `#[ignore]`, skipped assertions, conditional early success, or empty assertions. Their failure messages print only booleans or UI counts. Existing import negatives check state preservation and/or absence of session calls, shared crypto tests actually open modified bundles, and the real-server journeys assert collected generation and server records.

There are two explicit test-harness qualifications:

- `custodian_it::the_journey_leak_scan_worker` has `#[ignore]` by design, but the nonignored parent starts that exact test with `--ignored --nocapture`, checks subprocess success **and** `1 passed`, checks expected artifacts, and scans them. The parent passed in this run. The top-level `1 ignored` therefore represents a worker run by its parent, not missing leakage coverage. The machine's real OS-store test is unrelated and remained excluded.
- `server/tests/identity_authority.rs:230` still has a conditional early return if neither a symlink nor a junction can be created. I ran this target with `CI=true`, which turns that branch into an assertion failure. All 23 tests passed, including the link/reparse-point check; this run did not take its early-success branch. The separate launcher integration bootstrap test panics if its server binary is missing (`src-tauri/tests/fleet_enrollment_it.rs:647`), rather than passing silently.

Initial attempts are preserved in the log artifacts: the first e2e web-server startup exceeded 120 seconds; the next run passed 95 tests and failed during browser-context trace teardown at `app.spec.ts:808`; the final unchanged original test passed. Attempts to relink the launcher or rebuild the server while their test executables were running hit Windows sharing violations (`LNK1104` / access denied). After those processes finished, the corresponding targets were rerun successfully, apart from the intended assertion failures. No OS error 1455 occurred. These harness/build attempts do not count as passing tests.

<!-- RUN-OUTPUTS -->

## New test code

The exact working-copy additions are reproduced below. They use only established repository fixtures. No production fix has been applied; the failing regressions remain failing so a subsequent fix can be verified against them.

<!-- NEW-TEST-CODE -->

VERDICT: FAIL
