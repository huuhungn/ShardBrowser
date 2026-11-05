# Independent custodian verification, round 2

Verified HEAD: `6781e5656f9a27550b4cd020888a51276dda8fc5`.

Comparison: `git diff f5552844..HEAD`. Verification ran on Windows on 2026-11-05. Production references below are line numbers at that HEAD; new-test references are in the working copy. Production code was not changed. Five regression tests were added, using the repository's existing Rust fixtures, loopback servers, and Playwright fixtures. No separate prior-art survey was needed for these additions to established test patterns.

The verdict is **FAIL**. Goals **2, 5, 6 and 11 are VIOLATED** by the reproductions below. Goals **1, 3, 4, 7, 8, 9 and 10 HOLD** on the inspected paths and executed tests. These are bounded verification findings, not a claim that testing proves the absence of every possible vulnerability.

Only the requested contract sections were used as requirements: ADR 0002 Q-12, Q-13, C-1, Q-18, D-2, D-5 recovery wrap, D-9 and the initial Rule 6 pinned-head revocation rule; ADR 0004 key locations; and the shipped model in `docs/key-custody.md`. No author plan, review report, `.omc/`, `.omx/`, or scratch-directory evidence was consulted. References to plans inside source comments were not followed.

**Execution and test integrity**

The server was built before `custodian_it`. Launcher commands used `-j 4` and always included `--skip a_real_os_store_key_survives_into_a_fresh_process`. That test and its real-credential child were not run. Launcher fixtures use temporary config/data roots and the mock credential store; `%APPDATA%\shardx-launcher` was not accessed. There were no commits, pushes, PRs, issues, or production-server requests. Package installation for the UI used `npm ci --offline --ignore-scripts --no-audit --no-fund` in the root and `ui-kit`; UI tests used the local preview and mocked IPC.

The relevant assertion bodies were inspected, including negative assertions, request capture, exact-byte comparisons, response checks, and database checks. There are no empty or constant-success assertions or early-success returns in the feature tests cited below. The following existing test-harness exceptions must be distinguished from skipped coverage:

- `src-tauri/src/custodian_it.rs:1279` marks the leak-scan worker `#[ignore]`. Its ordinary parent test at line 1158 explicitly runs that exact worker with `--ignored --nocapture` and requires successful exit **and** `1 passed` before scanning its results. The parent passed, so the worker actually executed; this is not an unexecuted leak test.
- `src-tauri/src/credential.rs:273`, `:318`, `:355`, `:371` are ignored child entry points. They have environment guards with early returns. The no-store and encrypted-file parent tests require the child's completion marker, so a guard-only exit does not satisfy the parent. The real OS-store parent was explicitly excluded as required. None of the four ignored entries is counted as an independently passed test.
- `server/tests/v2_auth.rs:116` returns from the health-wait helper only after an HTTP success; exhaustion panics. It is not a test bypass. The unrelated symlink test in `identity_authority.rs` has a platform-dependent early return and was outside the `tenant_create` filter; it contributes no evidence here.
- The Playwright cases selected here have actual UI and request-state assertions, no `test.skip`, `test.fixme`, or early-success return. They verify UI behavior over mocked IPC, not cryptography. Cryptographic and actual HTTP claims below rely on Rust and real-server tests.

A combined context-mode test runner exceeded its 300-second tool-call limit without returning its results. Its unobserved runs are not counted. The relevant suites were rerun individually; the recorded results below are from observed completions.

**Commands and observed output**

For rows L1–L8 and N, the exact launcher command is:

```text
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib <filter> -- --skip a_real_os_store_key_survives_into_a_fresh_process
```

| Run | Command or filter | Observed result |
| --- | --- | --- |
| B | `cargo build -j 4 --manifest-path server/Cargo.toml` | exit 0; `Finished dev profile ... in 3m 08s` |
| S | `cargo test -j 4 --manifest-path server/Cargo.toml --test v2_auth` | `test result: ok. 82 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 70.12s` |
| I | `cargo test -j 4 --manifest-path server/Cargo.toml --test identity_authority tenant_create` | `test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 17 filtered out; finished in 2.04s` |
| L1 | `fleet_custody` (before new tests) | `test result: ok. 29 passed; 0 failed; 0 ignored; 0 measured; 684 filtered out; finished in 1.09s` |
| L1b | `fleet_custody` (final working copy) | `test result: FAILED. 29 passed; 2 failed; 0 ignored; 0 measured; 686 filtered out; finished in 1.07s`; only N1 and N2 failed |
| L2 | `custody_tests` | `test result: ok. 44 passed; 0 failed; 0 ignored; 0 measured; 673 filtered out; finished in 9.25s` |
| L3 | `fleet_client::tests` | `test result: FAILED. 15 passed; 1 failed; 0 ignored; 0 measured; 701 filtered out; finished in 0.01s`; the failure is new test N3 |
| L4 | `root_bootstrap::tests` | `test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 686 filtered out; finished in 16.14s` |
| L5 | `team_config::tests` | `test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 705 filtered out; finished in 0.04s` |
| L6 | `team::ledger::tests` | `test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 710 filtered out; finished in 0.55s` |
| L7 | `credential::tests` | `test result: ok. 6 passed; 0 failed; 4 ignored; 0 measured; 707 filtered out; finished in 10.71s` |
| L8 | `team::sync::tests` | `test result: FAILED. 199 passed; 1 failed; 0 ignored; 0 measured; 517 filtered out; finished in 395.85s`; the failure is new test N4 |
| R | `custodian_it` | `test result: ok. 6 passed; 0 failed; 1 ignored; 0 measured; 706 filtered out; finished in 135.70s` |
| H | `cargo test -j 4 --manifest-path shared/Cargo.toml join_sas` | `test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 303 filtered out; finished in 0.00s`; other integration binaries matched zero tests and are not counted |
| N | `verifier_` | `test result: FAILED. 0 passed; 4 failed; 0 ignored; 0 measured; 713 filtered out; finished in 0.66s` |
| U | Playwright command below | `11 passed (36.6s)`, `1 failed`; the failure is new test N5 |

```text
node_modules/.bin/playwright.cmd test tests/e2e/app.spec.ts --grep "two devices pass|custodian revokes|expired join|join code expired|first saw more|reason list|approval stays|refreshed keys|connecting needs|first device sets|interrupted custody|verifier:" --workers 4
```

UI prerequisites also completed: `npm --prefix ui-kit run build:lib`, and Playwright's `npm run build:e2e` (`tsc && vite build --mode e2e`). No remote browser installation was needed.

**1. Grant recipient substitution or mismatched listed key IDs — HOLDS**

Enforcement: `src-tauri/src/fleet_custody.rs:767` decodes both listed public keys and recomputes their key IDs; `:788` invokes this before a new approval; `:855` binds the grant to the recipient's account, device and key IDs; `:867` passes the **listed HPKE public key** to `seal_device_fkek`. The signed approval and profile capabilities use those same IDs. `server/src/routes/v2_approval.rs:998` independently derives the device-row key IDs and compares both row IDs and approval IDs before activating the device. `server/src/routes/v2_fleet.rs:893` checks the grant's active subject, account and both key IDs; `:914` requires a live approval for that scope. `shared/src/authz_record.rs:1060` exposes payload parsing, not signature acceptance; the collect path verifies evidence/signatures at `src-tauri/src/lib.rs:3244` before opening and retaining a grant.

Tests run: L1's `approval_is_refused_when_a_listed_key_does_not_hash_to_its_id` checks both key types, rejection and no requests; `the_member_grant_is_sealed_to_the_listed_hpke_key_and_opens_with_it` opens with the intended key, rejects a different private key and checks all subject fields and capabilities. S includes `a_custodian_approves_a_second_device_into_an_ordinary_session` and `every_approval_column_is_compared_with_its_container_on_each_request`. R's `two_devices_share_a_profile_through_a_real_server_after_approval` exercises actual encryption and collect across devices. Outputs: L1 29/29, S 82/82, R 6/6 passed. No additional test was needed for this goal.

**2. Ten-minute ceremony, comparison, and server-controlled extension — VIOLATED (D1)**

Enforcement that works: `fleet_custody.rs:696` durably records first sight; `:754` takes the earliest sight of the row or either key, preventing row-ID or key-swap resets; `:789` rejects an expired comparison; `:792` normalizes and compares the submitted SAS. `src-tauri/src/lib.rs:2776` uses the joining device's locally saved enrollment time, and `:2862` checks its deadline again at pin time. `TeamDevices.tsx:55` binds the comparison checkbox to the exact displayed code, and `:205` gates approval on that checkbox and expiry.

Defect D1: `src-tauri/src/fleet_custody.rs:935` checks the time **before** awaiting the server's active-generation response at `:936`; it then builds/signs with the same old `now` at `:941`. The caller captures that time at `src-tauri/src/lib.rs:2667`. A request begun just before the local deadline can therefore cause a **new** approval to be signed and sent after expiry by delaying the generation reply. The client allows up to 120 seconds for the request (`src-tauri/src/fleet_client.rs:209`). This is distinct from replaying an already signed approval. The server's ordinary approval validity check (`v2_approval.rs:968`) does not enforce this local ceremony deadline.

Existing tests run: L1's first-sight, mismatched-code, expiry, new-row-ID and key-swap tests; L2's `the_join_code_expires_ten_minutes_after_this_device_enrolled` and `a_late_join_confirm_is_refused_even_after_approval`; H's three independent SAS/hash tests; U's expiry and refreshed-key checkbox cases. All those existing cases passed.

New test N1: `fleet_custody::tests::verifier_approval_rechecks_time_after_the_generation_read` starts with 50 ms left and delays only the local generation reply by 150 ms. It verifies that the deadline has passed, then expects no approval POST. Actual output:

```text
test fleet_custody::tests::verifier_approval_rechecks_time_after_the_generation_read ... FAILED
a new approval was sent after its local deadline
```

**3. Pin another binding or replace a JOIN pin — HOLDS**

Enforcement: `shared/src/trust_chain.rs:675` hashes server instance, tenant, anchor and both local key IDs into the SAS. `src-tauri/src/lib.rs:2789` evaluates the self-signed root evidence; `:2853` compares the shown anchor and recomputes the SAS for the newly evaluated complete binding and local keys. `:2886` pins only after those checks. `src-tauri/src/team/ledger.rs:115` inserts with `ON CONFLICT DO NOTHING` and then compares the existing anchor, retaining the earlier source.

Tests run: H's `join_sas_matches_an_independent_sha256`, `join_sas_changes_with_every_input`, and `join_sas_displays_eight_groups_of_four` (3 passed); L2's instance-substitution, tenant-substitution, anchor-substitution, correct JOIN-pin readback and late-confirm tests (44 passed overall); L6's `a_join_pin_never_replaces_an_earlier_pin` checks unchanged anchor **and** source (7 passed overall). R's two-device journey performs the positive ceremony against the real server. No missing binding check was found; no new test was needed.

**4. Post-revocation access or an unrecoverable first-send failure — HOLDS**

Enforcement: `server/src/routes/v2_device_revoke.rs:554` acquires the write transaction, `:482` revokes device status, approvals, capabilities, root/fleet grants, sessions and leases, and the mutation/audit/receipt commit together. `server/src/routes/v2_auth.rs:389` requires the appropriate live device status when reloading sessions; `:421` rechecks under the mutation transaction. Session challenge/proof and refresh paths recheck live state. `v2_fleet.rs:893` rejects a new grant to a revoked subject. The supporting capability path at `server/src/routes/v2_capability.rs:107` / `:341` requires an active subject.

Launcher retry enforcement: `fleet_custody.rs:1088` saves before send; `:1093` sends the saved request; `:1120` rebuilds an old, refused, unfiled revocation rather than permanently stranding it. The inaccurate determination of when replacement is allowed is D2 under goal 5; it does not restore a revoked device's access.

Tests run: S's `a_revoked_device_cannot_sign_in_again`, `a_revocation_blocks_new_capabilities_and_inflight_session_proofs`, and atomic-revocation tests; L1's `a_resumed_revocation_resends_the_same_bytes` and `a_stale_unfiled_revocation_is_rebuilt`; R's `a_revoked_device_is_cut_off_but_keeps_the_key_it_already_holds_against_a_real_server`. Outputs: S 82 passed, L1 29 passed, R 6 passed. The real-server test checks that the fleet grant is marked revoked, new grants fail, collect/list fail on the revoked device, and the grant count does not grow.

The same real-server test deliberately opens leaked later ciphertext with the revoked device's retained generation-0 key. This is the documented C-1/key-custody limitation, not an authentication bypass: no rotation ships, copied keys cannot be recalled, and `retired` remains advisory. L8 separately exercises Q-18 compromise blocking and Rule 6 pinned-signer rejection. No additional test was needed for server cut-off or delayed-first-send recovery.

**5. Setup durability, one FKEK, and exact valid retry bytes — VIOLATED (D2)**

Enforcement that works at the tested failure points: `fleet_custody.rs:179` saves the nonce before generating/storing the key; `:184` reloads a held key and generates only on a missing credential with no saved key ID; `:195` saves the ID; `:382` durably saves all grant and lifecycle bytes together. `:493` never regenerates after the create request is saved. The D-9 sequence at `:498`, `:515`, `:536`, `:556` is create, both grants, both acknowledgements, activate. D-5 recovery wrapping uses the opened TRK at `:319` and commits its signed-container hash in the generation at `:336`. `src-tauri/src/lib.rs:2555` collects only after activation, and `:3218` verifies before retaining the FKEK. `root_bootstrap.rs:403` saves a cloned state before replacing the caller's state.

Defect D2: `src-tauri/src/fleet_custody.rs:1120` treats a bare 403 plus local age as sufficient to overwrite the saved revocation. The record's `issued_at_ms` is already backdated one minute by `src-tauri/src/root_bootstrap.rs:203`. At a retry 270 seconds after preparation, with the server one minute behind the client, the record is only 270 seconds old on the server (inside its 300-second allowance at `server/src/routes/v2_device_revoke.rs:633`), but 330 seconds old under the client comparison. A 403 from a proxy/server or another temporary authorization condition causes a different replay ID, signature, idempotency key and request bytes to be saved and sent. A generic 403 is not proof that the saved record's filing time has expired.

Tests run: L1's hold-before-request, crash-between-hold-and-save, missing/locked-key, failed-setup/no-verified-key, recovery unwrap, exact resumed setup, binding mismatch, collect/ack and revocation retry tests; L4's durable-save and root-key recovery tests; I's tenant/fleet/audit rollback tests; S's D-9 generation/grant/ack/activation tests and `every_custody_operation_replays_its_lost_response_after_a_restart`; R's real-server failed-save/replay test. Outputs: L1 29 passed, L4 31 passed, I 6 passed, S 82 passed, R 6 passed. The real-server run verifies one generation, the same key ID, removed setup reference, exact audit counts, and successful collect after retry.

New test N2: `fleet_custody::tests::verifier_a_403_does_not_replace_a_still_valid_revocation` supplies that clock relation and a loopback 403, verifies the saved issue time remains within the server allowance, and compares every posted body to the saved bytes. Actual output:

```text
test fleet_custody::tests::verifier_a_403_does_not_replace_a_still_valid_revocation ... FAILED
HTTP 403 replaced a request still valid on the server clock
```

The existing `a_retry_resends_a_saved_revocation_the_server_may_still_file` uses the same clock relation but a 503 response; it misses the 403-specific replacement branch. Setup resumption after the full one-year signed-grant validity interval was not simulated; `fleet_custody.rs:403` explicitly documents that expired saved setup requests have no rebuilding path. The one-FKEK/no-verified-key conclusions above are limited to the executed crash and retry cases, not arbitrary offline duration.

**6. Secrets in logs, files, IPC or error strings — VIOLATED (D3)**

Enforcement that works in ordinary flows: `src-tauri/src/credential.rs:99` stores and reads back a key through the OS store or open encrypted key file; `:68` selects the mock only for tests. `fleet_custody.rs:82` saves references, public IDs and sealed/signed records, not a raw FKEK; its Debug output is restricted at `:134`. `root_bootstrap.rs:403` and the credential migration tests cover durable references and deletion of plaintext copies. `src-tauri/src/fleet_client.rs:114` hides session tokens in Debug; `:234` redacts known secrets and token prefixes from ordinary errors; `:385` supplies password variants for a failed login. `src-tauri/src/lib.rs:3433` reports custody counts rather than root-key bytes.

Defect D3: `src-tauri/src/fleet_client.rs:379` / `:385` only removes a finite set of literal password spellings. Valid JSON can escape `/` as `\/`, whereas both generated escaped forms leave `/` unchanged (`:260`). A login error body containing the submitted password with an escaped slash survives redaction at `:320` and is included in the returned `detail`. `src-tauri/src/lib.rs:2593` returns that error string to IPC. This exposes the recoverable account password; it requires no FKEK/private-key access by the server.

Tests run: L3's existing raw-password, quote/control/non-ASCII escape, access-token, v1-token and Debug tests; L4's root state/Debug tests; L5's token/seed Debug, zeroization, credential migration and DPAPI tests; L7's mock-store and encrypted-file tests; R's `the_journey_leaks_no_secret_to_output_state_or_replies`. Outputs: 15 existing L3 tests passed; L4 31 passed; L5 12 passed; L7 6 passed with the explicit worker exclusions described above; R 6 passed. The leak parent checks eight captured secret/key forms plus password and token patterns, requires expected state/IPC files to exist, and separately checks displayed SAS values against stdout/stderr. Its successful journey does not cover hostile alternate JSON escaping.

New test N3: `fleet_client::tests::verifier_login_error_hides_a_json_escaped_slash_in_the_password` generates a random password suffix, proves the error JSON decodes to the exact submitted password, and asserts the suffix is absent from the error. It prints neither password nor suffix. Actual output:

```text
test fleet_client::tests::verifier_login_error_hides_a_json_escaped_slash_in_the_password ... FAILED
a recoverable password reached the error string
```

**7. Unsupported revocation reason or self-revocation from launcher — HOLDS**

Enforcement: `src-tauri/src/lib.rs:2716` parses the reason before opening a session; `fleet_custody.rs:1038` accepts only exact `retired` and `lost`; `:1061` rejects the custodian's own device ID case-insensitively. `TeamDevices.tsx:147` identifies self and `:214` omits its Revoke action; `:222` offers only Retired/Lost.

Tests run: L1's `only_retired_and_lost_are_accepted` and `a_custodian_does_not_revoke_itself` check error codes and absence of requests; U's `the reason list offers only Retired and Lost` checks the exact options and no self combobox; R exercises retired revocation. Outputs: L1 29 passed, U's reason case passed, R 6 passed. The backend's broader protocol enum does not bypass the launcher's command gate. No additional test was needed.

**8. Cross-tenant or non-custodian device listing — HOLDS**

Enforcement: `server/src/routes/v2_approval.rs:1073` requires a device session, `:1082` reloads it, `:1086` requires the same tenant, `:1093` checks ACTIVE root custody, and `:1101` scopes the SQL to that tenant. No account password ticket, ordinary session or pending session substitutes for custody.

Tests run: S's `a_custodian_lists_the_tenant_devices_with_their_public_keys` checks exact public fields and unchanged audit count; `only_an_active_custodian_session_lists_the_tenant_devices` tests ticket/pending/ordinary (403), foreign tenant (404 RESOURCE_NOT_FOUND), empty bearer (401) and custodian (200). Output: S 82 passed. L1's old-server listing-route error test also passed. No additional test was needed.

**9. Another device's root grants — HOLDS for device sessions**

Enforcement: `server/src/routes/v2.rs:750` accepts the dual caller, `:773` / `require_tenant_caller` at `:266` enforce that a v2 session's tenant and device equal the requested pair. Password tickets fail. The preserved v1 route at `:761` checks tenant membership and that the requested device belongs to the authenticated account. Thus v1 is account-scoped; it is not a device-session proof and is not represented here as one.

Tests run: S's `a_device_session_reads_the_active_fleet_generation_and_its_own_root_grants` reads an actual own grant, rejects another device of the same account, rejects foreign tenant and ticket callers, and tests the v1 account mapping. `a_v1_member_cannot_read_another_accounts_root_grants` rejects an actual other-account grant and checks that none was returned. Output: S 82 passed. This does not claim that a v1 account token is limited to one device; that route deliberately allows the account's own devices. No additional test was needed.

**10. Accidental opening of v1-guarded routes — HOLDS**

Enforcement: the only changed extractor sites are `server/src/routes/v2.rs:117` (identity), `:750` (own root grants), and `:880` (active fleet generation). `server/src/routes/v2_auth.rs:525` selects the v2 extractor only for ticket/access prefixes, otherwise retaining `AuthUser`; it does not treat an absent bearer as success. `server/src/routes/mod.rs:34` retains the old route handlers and adds the separately custodian-guarded device listing. Identity also accepts a live password ticket as explicitly implemented/tested; that is within the identity exception, not an opening of another legacy route.

Tests run: S's `the_legacy_guarded_routes_still_require_v1_auth` tests all 40 listed legacy method/path pairs both without a token and with a pending v2 session, requiring 401, then checks all three read exceptions still require authentication. `server_identity_answers_a_ticket_and_a_session_without_a_v1_token` checks positive identity callers and a dead token. The root/fleet read test checks their additional tenant/device restrictions. Output: S 82 passed. No additional test was needed.

**11. UI custody status and actions the backend always rejects — VIOLATED (D4, D5)**

Enforcement that works: `src-tauri/src/team_config.rs:328` calls `sync_cmd::holds_verified_fleet_key` (`src-tauri/src/sync_cmd.rs:468`), which uses `team::sync::holds_verified_key` (`src-tauri/src/team/sync.rs:1625`). It reverifies the stored grant under the pin and selected generation, so a legacy/unverified cached key is insufficient. `TeamCard.tsx:458` uses that flag to hide the join code. `TeamDevices.tsx:205` requires completed fleet setup for Approve.

Defect D4: `src-tauri/src/team/sync.rs:1630` considers only `verified_key`; it omits the Q-18 `commit_blocked` predicate used before sealing (`:3020`). With a counted compromised-device revocation exposing the generation, a push rejects with `sync.commitBlockedCompromised`, while the status predicate still returns true. The joining-device UI therefore takes the joined/key-held branch and hides the join code even though the generation cannot be used to seal a published-profile push under the contract's commit rule.

New test N4: `team::sync::tests::verifier_key_status_agrees_with_a_compromise_blocked_push` uses the existing signed compromise fixture, proves push rejects and sends no upload, then checks the UI's status predicate. Actual output:

```text
test team::sync::tests::verifier_key_status_agrees_with_a_compromise_blocked_push ... FAILED
the UI reports a usable fleet key while push is blocked
```

Defect D5: `src/features/manage-team/ui/TeamDevices.tsx:230` enables Revoke whenever the account is filled and no action is busy. It does not require a saved fleet create. `src-tauri/src/fleet_custody.rs:893`, reached from `revoke_member` at `:1064`, always rejects when `state.create_request` is empty. A root custodian before fleet setup can list another active device and is offered a Revoke action that always fails in that state. The existing E2E mock also implements that refusal (`src/e2e-mock.ts:433`), but the existing reason-options test never tries to establish action availability.

New test N5: `tests/e2e/app.spec.ts:946` loads an active peer while the Create fleet key action is still visible, signs in, and expects Revoke to be disabled. Actual output:

```text
verifier: revoke is unavailable before the fleet setup required by the backend
Error: expect(locator).toBeDisabled() failed
Expected: disabled
Received: enabled
1 failed
11 passed (36.6s)
```

Existing tests run: L5's `a_legacy_cached_fleet_key_alone_is_not_a_fleet_key`; L8's `key_status_and_push_agree_after_the_fleet_key_is_lost`, Q-18 and pinned-revoked-head cases; U's joined two-device flow, expired/unapproved re-enrollment, comparison checkbox, disabled Approve before setup, reason options and root bootstrap/resume cases. The existing UI cases passed. The new failures show two states absent from those existing tests.

**New test code**

The exact additions, with results above, follow. They contain no printed secret/key values, no ignored attributes, and no production fixes.

```diff
diff --git a/src-tauri/src/fleet_client.rs b/src-tauri/src/fleet_client.rs
index 722a9d54..d4367aca 100644
--- a/src-tauri/src/fleet_client.rs
+++ b/src-tauri/src/fleet_client.rs
@@ -2027,6 +2027,17 @@ mod tests {
         }
     }
 
+    #[test]
+    fn verifier_login_error_hides_a_json_escaped_slash_in_the_password() {
+        let suffix = random_id_hex();
+        let password = format!("verifier/{suffix}");
+        let echo = format!(r#"{{"password":"verifier\/{suffix}"}}"#);
+        let decoded: serde_json::Value = serde_json::from_str(&echo).unwrap();
+        assert!(decoded["password"].as_str() == Some(password.as_str()));
+        let error = login_error_echoing(&password, echo);
+        assert!(!error.contains(&suffix), "a recoverable password reached the error string");
+    }
+
     #[test]
     fn a_refusal_hides_the_v1_token_echoed_bare() {
         let rt = tokio::runtime::Builder::new_current_thread()
diff --git a/src-tauri/src/fleet_custody.rs b/src-tauri/src/fleet_custody.rs
index 7eae1981..47ee8d29 100644
--- a/src-tauri/src/fleet_custody.rs
+++ b/src-tauri/src/fleet_custody.rs
@@ -2654,4 +2654,49 @@ mod tests {
             "a still-valid saved revocation was replaced"
         );
     }
+
+    #[test]
+    fn verifier_approval_rechecks_time_after_the_generation_read() {
+        let f = fixture();
+        save(&f.prepared()).unwrap();
+        let (row, _) = joiner();
+        let rt = runtime();
+        let t0 = now_ms();
+        let first_seen = t0 - JOIN_WINDOW_MS + 50;
+        list(&f, std::slice::from_ref(&row), first_seen);
+        let (client, seen) = rt.block_on(mock(Arc::new(move |call, _| {
+            if call.ends_with("/key-generation") {
+                std::thread::sleep(std::time::Duration::from_millis(150));
+                (200, b"{\"generation\":0}".to_vec())
+            } else {
+                (503, Vec::new())
+            }
+        })));
+        let _ = approve(&rt, &f, &client, &row, &f.code(&row), t0);
+        assert!(now_ms() > first_seen + JOIN_WINDOW_MS);
+        assert!(sent(&seen).is_empty(), "a new approval was sent after its local deadline");
+    }
+
+    #[test]
+    fn verifier_a_403_does_not_replace_a_still_valid_revocation() {
+        let f = fixture();
+        save(&f.prepared()).unwrap();
+        let (mut row, _) = joiner();
+        row.status = "active".into();
+        let rt = runtime();
+        let (client, seen) = rt.block_on(mock(Arc::new(|_, _| (403, Vec::new()))));
+        let t0 = now_ms();
+        revoke(&rt, &f, &client, &row, DeviceRevocationReason::Retired, t0);
+        let saved = load().unwrap().revocations[&row.device_id].clone();
+        let retry = t0 + 270_000;
+        let server_now = retry - MINUTE;
+        assert!(server_now - issued_at(&saved, &f.signer).unwrap() < 300_000);
+        revoke(&rt, &f, &client, &row, DeviceRevocationReason::Retired, retry);
+        let posts = sent(&seen);
+        assert!(posts.len() >= 2, "both attempts must reach the loopback server");
+        assert!(
+            posts.iter().all(|(_, body)| body == &unhex_vec(&saved).unwrap()),
+            "HTTP 403 replaced a request still valid on the server clock"
+        );
+    }
 }
diff --git a/src-tauri/src/team/sync.rs b/src-tauri/src/team/sync.rs
index c03d6919..8479ffbb 100644
--- a/src-tauri/src/team/sync.rs
+++ b/src-tauri/src/team/sync.rs
@@ -5691,6 +5691,19 @@ mod tests {
         );
     }
 
+    #[test]
+    fn verifier_key_status_agrees_with_a_compromise_blocked_push() {
+        let w = world();
+        w.db().conn.execute_batch(&a_compromise(&w)).unwrap();
+        let error = w.push().unwrap_err();
+        assert!(has(&error, "sync.commitBlockedCompromised"));
+        assert!(w.sent("POST", "/uploads").is_empty());
+        assert!(
+            !holds_verified_key(&w.dev, &FLEET, NOW).unwrap(),
+            "the UI reports a usable fleet key while push is blocked"
+        );
+    }
+
     /// `world` with `extra` containers in its trust evidence.
     fn world_with(extra: Vec<Vec<u8>>) -> World {
         world_of(extra, true)
diff --git a/tests/e2e/app.spec.ts b/tests/e2e/app.spec.ts
index 0675d72c..1e7c0417 100644
--- a/tests/e2e/app.spec.ts
+++ b/tests/e2e/app.spec.ts
@@ -943,6 +943,15 @@ test("approval stays disabled until the custodian creates its fleet key", async
   await expect(row.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
 });
 
+test("verifier: revoke is unavailable before the fleet setup required by the backend", async ({ page: a }) => {
+  const server = fakeTeamServer([{ device_id: "c1".repeat(16), label: "Verifier Active", status: "active", granted: false }]);
+  await teamDevicePage(a, "a", server);
+  const row = await listDevices(a, "Verifier Active");
+  await cardSignIn(a);
+  await expect(a.getByRole("button", { name: "Create fleet key", exact: true })).toBeVisible();
+  await expect(row.getByRole("button", { name: "Revoke", exact: true })).toBeDisabled();
+});
+
 test("refreshed keys require a fresh join-code comparison", async ({ page: a }) => {
   const server = fakeTeamServer([{ device_id: "c1".repeat(16), label: "Verifier Pending", status: "pending", granted: false }]);
   await teamDevicePage(a, "a", server);
```

All 199 existing tests in the sync module passed, including the missing-key status check, Q-18 checks, and Rule 6 checks cited above. Its only failure was N4. A rebuild attempted while that Windows test executable was still running produced `LNK1104` (the output executable was locked); that failed build is not counted as a test result. The final fleet-custody run was started after the sync executable exited, to verify N2 with an explicitly active subject row.

The final fleet-custody rerun completed with tool-reported exit 1: `29 passed; 2 failed; 0 ignored; 0 measured; 686 filtered out; finished in 1.07s`. N1 failed at `src-tauri/src/fleet_custody.rs:2677`; N2, now using an active subject, failed at `:2697`. All 29 existing tests passed again. The final changes consist only of this report and the five test additions reproduced above; generated schema line-ending changes were restored.

VERDICT: FAIL
