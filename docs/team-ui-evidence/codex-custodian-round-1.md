# Independent custodian verification, round 1

Verified HEAD: `07260ecc2d6752c7ce824dc3024cd291b56528bc`.

Result: **FAIL**. Goals 2, 5, 6, 9 and 11 are VIOLATED. Goals 1, 3, 4, 7, 8 and 10 HOLD within the paths and cases exercised. Six defects are detailed below; the two credential-echo probes exercise one defect. HOLDS records the result of this bounded verification, not a proof against every possible implementation attack.

The implementation baseline was `git diff f5552844..HEAD` and the requested implementation files. The contract was the requested Q-12/Q-13/C-1/Q-18/D-2/D-5 recovery/D-9/Rule 6 material in ADR 0002, ADR 0004, and `docs/key-custody.md`. No author plan or review file, `.omc/`, `.omx/`, or scratch directory was opened. Independence qualification: the incoming environment had unsolicited memory context referring to previous reviews, and an initial ADR search exposed adjacent inline review-history text. Those were not treated as evidence or pursued. The conclusions below rely on repository code and executable probes.

All source references below use working-copy line numbers after adding the tests; production code is unchanged. The new tests follow the repository's existing Rust fixture/loopback-server and Playwright IPC-mock patterns. No feature implementation was built. All Cargo runs used `CARGO_NET_OFFLINE=true`. Dependencies needed for UI testing were installed from the offline npm cache, and `ui-kit` was built locally. No external service was contacted, no commit or remote write was made, and `%APPDATA%\shardx-launcher` was not used. Launcher fixtures use temporary roots and mock credentials. The forbidden real OS-store test was excluded throughout.

## Execution evidence

Every launcher command used this exact shape, with the filter from the table:

```text
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib FILTER -- --skip a_real_os_store_key_survives_into_a_fresh_process
```

The server was built before `custodian_it`:

```text
cargo build -j 4 --manifest-path server/Cargo.toml
Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 18s
exit code: 0
```

Captured test-summary outputs (counts are per invocation; repeated suites are not additive):

| ID | Command/filter | Output |
| --- | --- | --- |
| S1 | `cargo test -j 4 --manifest-path server/Cargo.toml --test v2_auth` (baseline tests) | `79 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 89.32s` |
| S2 | Same server command plus `verifier_ -- --nocapture` (first two probes) | `1 passed; 1 failed; 0 ignored; 0 measured; 79 filtered out; finished in 3.72s` |
| S3 | Same server command plus `verifier_revocation` | `1 passed; 0 failed; 0 ignored; 0 measured; 81 filtered out; finished in 4.59s` |
| S4 | `cargo test -j 4 --manifest-path server/Cargo.toml --test identity_authority tenant_create` | `6 passed; 0 failed; 0 ignored; 0 measured; 17 filtered out; finished in 1.60s` |
| C1 | `cargo test -j 4 --manifest-path shared/Cargo.toml join_sas` | `3 passed; 0 failed; 0 ignored; 0 measured; 303 filtered out; finished in 0.00s` |
| L1 | `fleet_custody` (baseline tests) | `25 passed; 0 failed; 0 ignored; 0 measured; 675 filtered out; finished in 0.69s` |
| L2 | `custody_tests` | `44 passed; 0 failed; 0 ignored; 0 measured; 662 filtered out; finished in 9.66s` |
| L3 | `custodian_it` (original leak scan) | `6 passed; 0 failed; 1 ignored; 0 measured; 699 filtered out; finished in 141.73s` |
| L4 | `root_bootstrap` | `31 passed; 0 failed; 0 ignored; 0 measured; 675 filtered out; finished in 28.87s` |
| L5 | `credential::tests` | `6 passed; 0 failed; 4 ignored; 0 measured; 696 filtered out; finished in 21.43s` |
| L6 | `team_config::tests` | `12 passed; 0 failed; 0 ignored; 0 measured; 694 filtered out; finished in 0.06s` |
| L7 | `fleet_client::tests` | `9 passed; 2 failed; 0 ignored; 0 measured; 695 filtered out; finished in 0.03s` (only the new echo probes fail) |
| L8 | `team::ledger::tests` | `7 passed; 0 failed; 0 ignored; 0 measured; 699 filtered out; finished in 0.52s` |
| L9 | `team::sync::tests` | `198 passed; 0 failed; 0 ignored; 0 measured; 508 filtered out; finished in 612.55s` |
| L10 | `custodian_it::the_journey_leaks_no_secret_to_output_state_or_replies` (strengthened scan) | `1 passed; 0 failed; 0 ignored; 0 measured; 705 filtered out; finished in 58.04s` |
| L11 | `verifier_` (all six final Rust launcher probes) | `2 passed; 4 failed; 0 ignored; 0 measured; 700 filtered out; finished in 0.65s` |
| U1 | Playwright command below | `2 failed`, `9 passed (50.4s)` |

```text
npm run test:e2e -- --grep 'two devices pass|a custodian revokes|expired join code|approved device whose join|custodian cannot approve|reason list|connecting needs no token|first device sets up root|interrupted custody|verifier' --workers=2
```

The initial launcher probe run also reproduced the same four failures (`0 passed; 4 failed; 700 filtered out; 0.09s`); L11 includes the subsequently added tenant and key-loss positive controls. S3's first draft expected HTTP 403; the server correctly returned HTTP 422 with the live-subject error. The assertion was corrected to require that specific status and error, then passed. This is a test-expectation correction, not a product defect.

Test-strength inspection: the cited behavioral tests have substantive equality, rejection, cryptographic-open, state, or outgoing-request assertions. The new tests contain no `#[ignore]`, test skip, empty assertion, or early success return. S1 has no ignored test; the `return` in its health helper exits only on a successful HTTP health response, otherwise it panics. The unselected identity-authority symlink test has a platform-dependent early return and is not cited as coverage. L3's ignored test is the leak worker: its parent explicitly launches it with `--exact ... --ignored`, requires successful exit and `1 passed`, then checks nonempty evidence. L5's four ignored functions are child-process workers. The unavailable-store and temporary encrypted-key-file parents invoke their workers and require a completion marker after assertions; missing-env early returns do not satisfy those parents. The real OS-store parent and its child were never run and are not evidence here. Thus the ignored counts are disclosed, not represented as executed standalone tests.

## Goal 1 — HOLDS

Enforcement: `src-tauri/src/fleet_custody.rs:744` derives both key IDs from the listed public keys and rejects either mismatch; `:758` gates new approvals; `:784` builds the approval and three capabilities, and `:844` seals the FKEK to that listed HPKE public key. `server/src/routes/v2_approval.rs:984` rederives IDs and compares the pending row; `server/src/routes/v2_fleet.rs:893` checks the live subject and scoped approval before filing a device grant. The shared `DeviceHpkeGrant` parsing visibility change at `shared/src/authz_record.rs:1059` does not bypass signature verification.

Tests/output: L1 passed `approval_is_refused_when_a_listed_key_does_not_hash_to_its_id` (`fleet_custody.rs:2044`), mutating all four listed ID/public-key fields and asserting no POST or saved approval. L1 also passed `the_member_grant_is_sealed_to_the_listed_hpke_key_and_opens_with_it` (`:2200`): verifies signed records, opens with the intended private key, checks the recovered FKEK and all subject/scope IDs, and asserts another private key fails to open it. S1 passed the server approval/grant checks; L3 passed the real two-device approval/profile journey. No additional test was needed for this goal.

## Goal 2 — VIOLATED (D1, D2)

Enforcement that works: `fleet_custody.rs:766` checks the custodian's local first-sight time and `:774` compares normalized SAS. `src-tauri/src/lib.rs:2157`, `:2776`, and `:2862` retain/check the joiner's local enrollment window. `shared/src/trust_chain.rs:675` binds server instance, tenant, anchor, signing ID and HPKE ID into the SAS.

Tests/output: L1 passed `the_custodian_window_starts_when_it_first_sees_the_row_and_never_resets`, `approval_is_refused_ten_minutes_after_first_sight`, `approval_is_refused_when_the_confirmed_code_differs`, and `a_saved_approval_is_resent_after_the_window_closes`. The last is replay of an already saved approval, not a new ceremony. L2 passed `the_join_code_expires_ten_minutes_after_this_device_enrolled` and `a_late_join_confirm_is_refused_even_after_approval`. C1 passed all three SAS vectors/input-binding/display tests. U1's original checkbox/expiry cases passed. The new Rust row-alias test and Playwright changed-code test fail.

**D1: changing a server row ID extends the same keys' approval window.** `fleet_custody.rs:698` indexes first sight only by server-provided `device_id`; `:675` computes SAS without that row ID; `:902` records a previously unseen row before checking its window. Concrete scenario: record a pending row at t0, wait eleven minutes, then list the identical public keys and key IDs under another device ID. The displayed SAS is unchanged, but the new map entry receives a fresh first-sight time and the custodian sends an approval POST. New test `verifier_server_row_alias_must_not_restart_the_same_keys_window` at `fleet_custody.rs:2472` fails with `a row alias extended the approval window without new keys`. It asserts the old/new SAS agree and that no mutation should be sent. This is a launcher test with a hostile loopback server response; it does not claim the honest server normally changes IDs.

**D2: comparison consent survives a changed join code.** `src/features/manage-team/ui/TeamDevices.tsx:43` stores checkbox state by device ID; `:77` replaces rows without resetting it; `:82` submits the refreshed row's SAS; `:196` and `:203` use only the retained ID membership to enable approval. Scenario: compare code A, check the box, refresh the same device ID with different keys and code B. Approval remains enabled and submits B without a new comparison. New Playwright test `verifier refreshed keys require a fresh join-code comparison` at `tests/e2e/app.spec.ts:946` fails: `Expected: not checked`, `Received: checked`. Its IPC mutation verifies the displayed code actually changed. Backend key/SAS validation does not establish that the user compared the replacement code.

## Goal 3 — HOLDS

Enforcement: `src-tauri/src/lib.rs:2789` validates generation-zero anchor evidence for the configured binding; `:2853` rechecks anchor, binding/SAS and local deadline before pinning. `src-tauri/src/team/ledger.rs:107` inserts the anchor with conflict-do-nothing semantics, preserving an earlier pin and its source.

Tests/output: L2 passed `a_join_confirm_is_refused_when_the_server_instance_changed` (`lib.rs:5941`), `a_join_pin_is_refused_for_another_anchor_than_the_one_shown` (`:5976`), and new `verifier_join_confirmation_binds_the_displayed_tenant` (`:5962`). The new test supplies the original displayed SAS with a different tenant and asserts error plus zero anchor rows; it passed again in L11. L8 passed `a_join_pin_never_replaces_an_earlier_pin` (`ledger.rs:1269`). C1 independently tests that every SAS input changes the digest. No anchor/instance/tenant substitution or JOIN overwrite was achieved.

## Goal 4 — HOLDS

Enforcement: `server/src/routes/v2_device_revoke.rs:482` invalidates approvals, capabilities, root/fleet grants, leases and sessions in the revocation transaction (`:554` begins the immediate transaction). `server/src/routes/v2_auth.rs:363` reloads live account/device/approval state; session proof and refresh paths also recheck revocation (`:1202`, `:1380`). `server/src/routes/v2_capability.rs:107` resolves a live subject and `:341` rejects grants to inactive subjects. `v2_fleet.rs:893` gates fleet grants on current subject/approval state. `fleet_custody.rs:1048` retains or rebuilds saved revocations, and `:1074` persists before sending. Local kept evidence is reverified (`lib.rs:3291`); revocation evidence is sticky in the ledger (`team/ledger.rs:907`).

Tests/output: S1 passed `a_revoked_device_cannot_sign_in_again` (`server/tests/v2_auth.rs:6215`), including pending/active devices, session invalidation, grant revocation and permanence. New S3 test `verifier_revocation_blocks_new_capabilities_and_inflight_session_proofs` (`:11052`) first issues a real capability, then files revocation: a fresh capability returns 422 with `the grant names no active subject under these keys`, a previously constructed session proof returns 409, and refresh returns 401. L1 passed saved-revocation exact replay (`:2363`) and stale-unfiled rebuild (`:2432`), demonstrating progress after a failed send. L2 passed sticky revocation/reverification cases. L3 passed `a_revoked_device_is_cut_off_but_keeps_the_key_it_already_holds_against_a_real_server` (`custodian_it.rs:855`). L9 exercises pinned revoked signers, advisory withdrawal and compromised-custodian blocks.

This does not promise erasure of a copied key. As `docs/key-custody.md` describes, a revoked device retaining an FKEK can decrypt ciphertext exposed to it; the real-server test deliberately demonstrates that limit. No new session, capability or grant after filing was obtained. The retry-byte violation under clock skew is separately recorded under goal 5; it did not make the revocation permanently unrecoverable.

## Goal 5 — VIOLATED (D3)

Enforcement that works: `fleet_custody.rs:170` persists a run nonce and holds the setup key in credential storage before saving its key ID; it does not regenerate after an established key reference becomes missing. `:262` prepares and saves the mutation bytes once, including the recovery grant (`:315`), then `:404` resumes the staged setup. `lib.rs:2555` collects a verified grant after activation and `:2563` releases the setup holding. This follows the PREPARING/ACTIVE lifecycle rather than treating a locally generated key as verified.

Tests/output: L1 passed crash between holding/saving (`:1409`), missing/locked setup-key failure (`:1430`), failed-setup leaves no verified key (`:1457`), create commitment (`:1476`), recovery grant opening/lifetime (`:1541`), and byte-for-byte resumed setup (`:1587`). L4 passed 31 root bootstrap/credential-reference/recovery tests. S4 passed tenant/default-fleet creation and audit-failure rollback. L3 passed `a_fleet_setup_resumes_after_a_failed_save_and_a_replayed_run_against_the_real_server` (`custodian_it.rs:433`). No second FKEK or permanently stranded PREPARING generation was reproduced in these setup crash cases.

**D3: a still-valid saved revocation is replaced before replay.** `fleet_custody.rs:1048` declares a request stale using only the launcher's clock (`issued_at + 300000 <= now`) and builds new signed/idempotency bytes. `root_bootstrap.rs:202` backdates issue time by one minute. The server accepts an issue time within five minutes of its own clock (`server/src/routes/v2_device_revoke.rs:633`). Scenario: save at local t0, fail the first send, retry at local t0+270 seconds while the server is 60 seconds behind. The saved record is only 270 seconds old at the server and remains within its validity interval, yet the launcher sends different bytes. New test `verifier_valid_revocation_retry_preserves_bytes_with_clock_skew` (`fleet_custody.rs:2487`) checks the server-side age precondition, captures both POSTs and fails with `a still-valid saved revocation was replaced`. This is a clock-injected launcher/loopback transport test backed by the server's time predicate, not an altered-clock real-server run. It violates the explicit goal's requirement for still-valid resumed request bytes.

## Goal 6 — VIOLATED (D4)

Enforcement that works: `src-tauri/src/credential.rs:32` selects the production credential store; test storage is isolated at `:77`; `:105` requires store/readback. `fleet_custody.rs:82` stores references and mutation containers, with redacted Debug at `:130`. `root_bootstrap.rs` migrates the legacy cleartext holding to credential storage and releases it after use; `team_config.rs:70` and `fleet_client.rs:118` redact Debug output. IPC intentionally returns the join SAS to render it; the secrecy requirement for a join code here is specifically log lines.

Tests/output: L1 passed state/Debug no-key tests, L4 the root holding/migration/redaction tests, L5 mock/store-unavailable/encrypted-file tests, and L6 configuration redaction/status tests. L3's existing journey scanner passed. Strengthened L10 also passed: scan eight key needles (FKEK, TRK, both HPKE private keys and both devices' four signing/HPKE seeds), password and v2 token patterns in stdout/stderr/state/IPC replies, and actual displayed SAS values in stdout/stderr. The scanner's separate temporary needle side channel is test-only and is excluded from scanned application state; no needle values were printed. A normal journey's clean scan does not cover arbitrary server error bodies.

**D4: untrusted error text propagates credentials.** `src-tauri/src/fleet_client.rs:249` reads any error response body and inserts its first 300 characters verbatim into an error string (`:254`–`:263`). Login sends the password at `:301`; IPC command paths such as `src-tauri/src/lib.rs:2074` convert the resulting error directly to a String. Scenario: a server/proxy returns HTTP 400 echoing the Authorization header or received login password. New tests `verifier_error_reply_must_not_echo_session_tokens` (`fleet_client.rs:1809`) and `verifier_login_error_must_not_echo_account_password` (`:1832`) fail in L7 and L11. The token probe exercises all three `v2t.`, `v2a.`, `v2r.` prefixes, aggregates the result and prints no token. Output is respectively `an echoed bearer reached the launcher error string` and `the account password reached the launcher error string`. The password is generated in the fixture and never printed. This proves error-string disclosure, with IPC propagation supported by code; it does not claim the normal server voluntarily echoes passwords or that a key was extracted from HPKE.

## Goal 7 — HOLDS

Enforcement: `src-tauri/src/lib.rs:2716` parses the reason before submitting; `fleet_custody.rs:1015` accepts only retired/lost; `:1038` rejects a case-insensitive match to the custodian's own device ID. `TeamDevices.tsx:212` omits the self revoke action and `:220` supplies the two reason choices.

Tests/output: L1 passed `only_retired_and_lost_are_accepted` (`:2308`) and `a_custodian_does_not_revoke_itself` (`:2334`), including no outgoing revocation for self. U1 passed `the reason list offers only Retired and Lost` and the custodian/self-device UI coverage. The backend allowlist is checked independently of the UI options. No new test was required.

## Goal 8 — HOLDS

Enforcement: `server/src/routes/v2_approval.rs:1066` requires a device session, reloads current state (`:1083`), compares tenant (`:1087`), requires an active custodian (`:1094`) and constrains the query by tenant (`:1100`).

Tests/output: S1 passed `a_custodian_lists_the_tenant_devices_with_their_public_keys` (`server/tests/v2_auth.rs:11082`) and `only_an_active_custodian_session_lists_the_tenant_devices` (`:11133`). The latter asserts ticket, pending and ordinary sessions all return 403; another tenant returns 404/RESOURCE_NOT_FOUND; no token returns 401; the valid custodian returns 200. These are real server tests, with positive control as well as denials. No cross-tenant or non-custodian listing was obtained.

## Goal 9 — VIOLATED (D5)

Enforcement for v2: `server/src/routes/v2.rs:266` resolves a live tenant session to its device ID; `:760` compares it to the requested root-grant recipient. S1 passed `a_device_session_reads_the_active_fleet_generation_and_its_own_root_grants` (`server/tests/v2_auth.rs:11166`), which asserts own read succeeds and another-device, ticket, and foreign-tenant reads are forbidden.

**D5: the legacy v1 branch omits recipient ownership.** `server/src/routes/v2.rs:272` returns `None` after checking tenant membership for a v1 caller; the `is_some_and` guard at `:763` consequently skips ownership. Scenario: a v1 login maps to tenant account OTHER, an ordinary member distinct from the OWNER custodian account. Request OWNER custodian's device root grants. New real-server test `verifier_v1_member_must_not_read_another_accounts_root_grant` (`server/tests/v2_auth.rs:10990`) first proves the custodian has one grant, then makes that unrelated member read: **HTTP 200, one grant**, where the test expects 403 and zero grants. S2 fails with `another account's root grant was readable (HTTP 200, 1 grants)`.

This returns sealed grant data, not a decrypted TRK. The v1 membership-only behavior already exists at the base revision; it is a residual violation of the unqualified attack goal, not a newly introduced regression in the diff. The new v2 branch itself enforces recipient equality.

## Goal 10 — HOLDS

Enforcement: `server/src/routes/v2_auth.rs:507` dispatches Caller to v2 authentication or the existing AuthUser extractor; `server/src/auth.rs:150` still validates v1 authentication/token version. The shared-read substitutions are `server/src/routes/v2.rs:117` (identity), `:751` (own root grants), and `:869` (active fleet generation). `server/src/routes/mod.rs` retains the remaining route/extractor guards. Identity can use the ticket principal; none of these reads becomes anonymous.

Tests/output: new S2 test `verifier_legacy_guarded_routes_require_v1_auth` (`server/tests/v2_auth.rs:11007`) passed. It enumerates 40 formerly v1-guarded method/path pairs, sends each without authentication and with a v2 session (80 HTTP 401 checks), and asserts the three shared read endpoints also return 401 without authentication. S1's shared-read test supplies the positive session-authenticated controls. No additional anonymous route was reached. Public health/login endpoints are not former guarded routes and were not misclassified as regressions.

## Goal 11 — VIOLATED (D6)

Key-status enforcement: `TeamCard.tsx:458` hides the join flow when `has_fleet_key` is true. `src-tauri/src/team_config.rs:328` uses `sync_cmd.rs:468`, which reaches `team/sync.rs:1625`: it requires a verified key of the highest observed generation. `team/sync.rs:1608` and `lib.rs:3291` reverify the kept grant; `team/sync.rs:3004`/`:3016` use that verified-key path to seal a published snapshot. This prevents treating a bare cache entry as usable custody.

Tests/output: L6 passed the legacy cached-key status rejection. L2 passed kept-grant revalidation. New `verifier_key_status_agrees_with_push_after_key_loss` at `team/sync.rs:5668` passed in L11: first a real fixture key reports held and pushes version 1; after removing the key cache, status is false and the next push returns `sync.noVerifiedFleetKey`. U1 passed the two-device setup/approve/collect/profile journey. No contradictory held-key status was reproduced by this probe.

**D6: the UI offers approval before fleet setup.** `src/features/manage-team/ui/TeamDevices.tsx:53` computes fleet readiness, but the Approve disabled predicate at `:203` does not use it. `fleet_custody.rs:867` requires a saved fleet create request and always reports `fleet.notCustodian` when it is missing. Scenario: the root custodian has completed root setup, lists a pending device and confirms its code, but has not created a fleet key. Approve is enabled even though the backend rejects that action in this state. New Playwright test `verifier approval stays disabled until the custodian creates its fleet key` (`tests/e2e/app.spec.ts:936`) fails: `Expected: disabled`, `Received: enabled`, while the Create fleet key button is visible. `src/e2e-mock.ts:374` only checks root activation for its custodian guard, so its model misses the production fleet prerequisite. The UI failure is observed in Playwright; the guaranteed backend rejection is established by its direct state guard.

## Added test code

The complete test-only working-copy diff follows, including the strengthened leak scanner. It is deliberately left uncommitted and includes failing assertions that reproduce the defects; production behavior was not patched. Generated schema-only churn is excluded.

```diff
diff --git a/server/tests/v2_auth.rs b/server/tests/v2_auth.rs
index bea306a7..e68b22b1 100644
--- a/server/tests/v2_auth.rs
+++ b/server/tests/v2_auth.rs
@@ -10986,6 +10986,98 @@ fn devices_path(tenant: &[u8; 16]) -> String {
     format!("/v2/tenants/{}/devices", hex(tenant))
 }
 
+#[tokio::test]
+async fn verifier_v1_member_must_not_read_another_accounts_root_grant() {
+    let mut server = start("verifier-root-reader", 28451).await;
+    let (custodian, access, _) = custodian(&mut server, 0x6c).await;
+    let path = format!("/v2/tenants/{}/devices/{}/root-key-grants", hex(&TENANT), hex(&custodian.id));
+    let (status, body) = server.call(&path, &access, None).await;
+    assert_eq!(status, 200);
+    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["grants"].as_array().unwrap().len(), 1);
+    let (_, login) = server.post("/auth/login", None, json!({"username":"admin", "password":"secret"})).await;
+    let v1 = login["token"].as_str().unwrap();
+    // This v1 user maps to OTHER, not the custodian's OWNER account.
+    server.sql("UPDATE v2_accounts SET legacy_user_id = (SELECT id FROM users WHERE username = 'admin') WHERE id = ?", &[&OTHER]).await;
+    let (status, body) = server.call(&path, v1, None).await;
+    let returned = serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["grants"].as_array().map(Vec::len)).unwrap_or(0);
+    assert!(status == 403 && returned == 0, "another account's root grant was readable (HTTP {status}, {returned} grants)");
+}
+
+#[tokio::test]
+async fn verifier_legacy_guarded_routes_require_v1_auth() {
+    let server = start("verifier-route-matrix", 28452).await;
+    let reader = device(&server, OWNER, 0x5b, "pending").await;
+    let s = session(&server, &reader).await;
+    let access = s["access_token"].as_str().unwrap();
+    let t = hex(&TENANT);
+    let id = hex(&reader.id);
+    let routes = [
+        ("GET", "/me".into()), ("POST", "/me/password".into()),
+        ("GET", "/users".into()), ("POST", "/users".into()),
+        ("DELETE", "/users/x".into()), ("PATCH", "/users/x/role".into()),
+        ("PATCH", "/users/x/password".into()), ("GET", "/audit".into()),
+        ("GET", "/folders".into()), ("POST", "/folders".into()),
+        ("PATCH", "/folders/x".into()), ("DELETE", "/folders/x".into()),
+        ("GET", "/envs".into()), ("POST", "/envs".into()),
+        ("GET", "/envs/x".into()), ("PATCH", "/envs/x".into()), ("DELETE", "/envs/x".into()),
+        ("POST", "/envs/x/checkout".into()), ("POST", "/envs/x/lease".into()),
+        ("POST", "/envs/x/release".into()), ("POST", "/envs/x/force-unlock".into()),
+        ("GET", "/envs/x/lock".into()), ("POST", "/envs/x/checkin".into()),
+        ("GET", "/envs/x/snapshot/1".into()), ("POST", "/acl".into()), ("DELETE", "/acl".into()),
+        ("GET", "/proxies".into()), ("POST", "/proxies".into()), ("DELETE", "/proxies/x".into()),
+        ("GET", format!("/v2/tenants/{t}/root-key-generation")),
+        ("POST", "/v2/operations".into()), ("POST", "/v2/operations/complete".into()),
+        ("POST", "/v2/fleet/leases".into()), ("POST", "/v2/fleet/leases/release".into()),
+        ("POST", "/v2/fleet/uploads".into()), ("POST", format!("/v2/fleet/uploads/{t}/{id}/chunk")),
+        ("POST", "/v2/fleet/uploads/commit".into()), ("POST", "/v2/fleet/uploads/abort".into()),
+        ("GET", format!("/v2/fleet/snapshots/{t}/{id}")),
+        ("GET", format!("/v2/fleet/snapshots/{t}/{id}/range")),
+    ];
+    let http = client();
+    for bearer in [None, Some(access)] {
+        for (method, path) in &routes {
+            let mut req = http.request(method.parse().unwrap(), format!("http://127.0.0.1:{}{path}", server.port));
+            if let Some(token) = bearer { req = req.bearer_auth(token); }
+            let res = req.header("content-type", "application/json").body("{}").send().await.unwrap();
+            assert_eq!(res.status().as_u16(), 401, "{method} {path}");
+        }
+    }
+    for path in ["/v2/server-identity".to_string(), format!("/v2/tenants/{t}/fleets/{t}/key-generation"), format!("/v2/tenants/{t}/devices/{id}/root-key-grants")] {
+        let res = http.get(format!("http://127.0.0.1:{}{path}", server.port)).send().await.unwrap();
+        assert_eq!(res.status().as_u16(), 401, "{path}");
+    }
+}
+
+#[tokio::test]
+async fn verifier_revocation_blocks_new_capabilities_and_inflight_session_proofs() {
+    let mut server = start("verifier-revoke-capability", 28453).await;
+    let (issuer, access, _) = custodian(&mut server, 0x6c).await;
+    let peer = device(&server, OWNER, 0x7d, "active").await;
+    file_approval(&server, &issuer, &peer, 0x7d).await;
+    let old_session = session(&server, &peer).await;
+    let ticket = server.login("owner").await;
+    let (status, pending_challenge) = challenge(&server, &ticket, &peer).await;
+    assert_eq!(status, 201);
+    let proof = answer(&ticket, &pending_challenge, &peer);
+    let duty = capability_grant(&issuer, &issuer.sk, |g| {
+        g.common.replay_id = [0xa8; 16];
+        g.capability = Capability::DeviceRevoke;
+    });
+    assert_eq!(server.call(GRANTS, &access, Some(&duty)).await.0, 201);
+    let initial_capability = capability_grant(&peer, &issuer.sk, |g| g.common.replay_id = [0xa9; 16]);
+    assert_eq!(server.call(GRANTS, &access, Some(&initial_capability)).await.0, 201);
+    let signed = revocation(&issuer.sk, &peer, 0x90, 30);
+    assert_eq!(server.call(&device_revoke_path(&peer.id), &access, Some(&revoke_request(0xa0, &signed))).await.0, 201);
+    let new_capability = capability_grant(&peer, &issuer.sk, |g| g.common.replay_id = [0xaa; 16]);
+    let (status, body) = server.call(GRANTS, &access, Some(&new_capability)).await;
+    assert_eq!(status, 422);
+    assert!(String::from_utf8_lossy(&body).contains("the grant names no active subject under these keys"));
+    let (status, _) = server.post("/v2/auth/device-session-proofs", Some(ticket["ticket"].as_str().unwrap()), proof).await;
+    assert_eq!(status, 409);
+    let (status, _) = server.post("/v2/auth/refresh", None, json!({"refresh_token": old_session["refresh_token"]})).await;
+    assert_eq!(status, 401);
+}
+
 #[tokio::test]
 async fn a_custodian_lists_the_tenant_devices_with_their_public_keys() {
     let mut server = start("s1-devices", 28235).await;
diff --git a/src-tauri/src/custodian_it.rs b/src-tauri/src/custodian_it.rs
index ba0096f5..08a3dc4b 100644
--- a/src-tauri/src/custodian_it.rs
+++ b/src-tauri/src/custodian_it.rs
@@ -1189,8 +1189,8 @@ fn the_journey_leaks_no_secret_to_output_state_or_replies() {
         .collect();
     assert_eq!(
         secrets.len(),
-        4,
-        "the FKEK, the TRK and two HPKE private keys"
+        8,
+        "the FKEK, the TRK, two HPKE private keys and both devices' four seeds"
     );
     secrets.push(PASSWORD.into());
     let mut scanned = vec![
@@ -1231,6 +1231,16 @@ fn the_journey_leaks_no_secret_to_output_state_or_replies() {
         }
     }
     assert!(hits.is_empty(), "{hits:?}");
+    // Join codes belong in the deliberate IPC reply, but never in log lines.
+    let replies = std::fs::read_to_string(scan.path().join("replies.jsonl")).unwrap();
+    let codes: Vec<String> = replies.lines().filter_map(|line| {
+        serde_json::from_str::<serde_json::Value>(line).ok()
+            .and_then(|value| value.get("sas").and_then(|v| v.as_str()).map(str::to_owned))
+    }).collect();
+    assert!(!codes.is_empty(), "the journey must exercise a displayed join code");
+    for (_, output) in scanned.iter().filter(|(name, _)| name == "stdout" || name == "stderr") {
+        assert!(!codes.iter().any(|sas| output.contains(sas)), "a join code reached a log line");
+    }
 }
 
 /// Copies this device's team state files that exist into `dir`, each named
@@ -1268,6 +1278,8 @@ fn the_journey_leak_scan_worker() {
     let fkek = crate::credential::load(&format!("fleet-key.{}.0", h.tenant)).unwrap();
     let c = crate::team_config::load().unwrap();
     let (a_sk, _) = shardx_core::grants::derive_keypair(&c.hpke_seed().unwrap());
+    let a_signing_seed = c.signing_key().unwrap().to_bytes();
+    let a_hpke_seed = c.hpke_seed().unwrap();
     let grants = with_session(&rt, &h, async |client, access| {
         client
             .root_key_grants(access, &h.tenant, &c.device_id)
@@ -1291,13 +1303,15 @@ fn the_journey_leak_scan_worker() {
         crate::team_collect_custody(OWNER.into(), PASSWORD.into()),
     )
     .unwrap_err();
-    let (b_sk, _) = shardx_core::grants::derive_keypair(
-        &crate::team_config::load().unwrap().hpke_seed().unwrap(),
-    );
+    let b_config = crate::team_config::load().unwrap();
+    let b_signing_seed = b_config.signing_key().unwrap().to_bytes();
+    let b_hpke_seed = b_config.hpke_seed().unwrap();
+    let (b_sk, _) = shardx_core::grants::derive_keypair(&b_hpke_seed);
     keep_state(&dir, "b");
     std::fs::write(
         secrets,
-        [hex(&*fkek), hex(&*trk), hex(&a_sk), hex(&b_sk)].join("\n"),
+        [hex(&*fkek), hex(&*trk), hex(&a_sk), hex(&b_sk),
+            hex(&a_signing_seed), hex(&a_hpke_seed), hex(&b_signing_seed), hex(&b_hpke_seed)].join("\n"),
     )
     .unwrap();
 }
diff --git a/src-tauri/src/fleet_client.rs b/src-tauri/src/fleet_client.rs
index 04b27d4e..1e4f9e83 100644
--- a/src-tauri/src/fleet_client.rs
+++ b/src-tauri/src/fleet_client.rs
@@ -1804,4 +1804,47 @@ mod tests {
     fn replay_ids_are_unique() {
         assert_ne!(random_id_hex(), random_id_hex());
     }
+
+    #[test]
+    fn verifier_error_reply_must_not_echo_session_tokens() {
+        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
+        rt.block_on(async {
+            let app = axum::Router::new().fallback(|headers: axum::http::HeaderMap| async move {
+                let echoed = headers.get("authorization").unwrap().to_str().unwrap().to_string();
+                (axum::http::StatusCode::BAD_REQUEST, echoed)
+            });
+            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
+            let url = format!("http://{}", listener.local_addr().unwrap());
+            let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
+            let client = FleetClient::new(&url, "").unwrap();
+            let mut leaked = false;
+            for prefix in ["v2t.", "v2a.", "v2r."] {
+                let token = format!("{prefix}{}", "7d".repeat(32));
+                let error = client.server_identity(&token).await.unwrap_err().to_string();
+                leaked |= error.contains(&token);
+            }
+            task.abort();
+            assert!(!leaked, "an echoed bearer reached the launcher error string");
+        });
+    }
+
+    #[test]
+    fn verifier_login_error_must_not_echo_account_password() {
+        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
+        rt.block_on(async {
+            let app = axum::Router::new().fallback(|axum::Json(body): axum::Json<serde_json::Value>| async move {
+                (axum::http::StatusCode::BAD_REQUEST, body["password"].as_str().unwrap().to_owned())
+            });
+            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
+            let url = format!("http://{}", listener.local_addr().unwrap());
+            let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
+            let client = FleetClient::new(&url, "").unwrap();
+            let password = format!("verifier-password-{}", random_id_hex());
+            let login = super::AccountLogin { tenant_id: "11", username: "owner", password: &password };
+            let result = client.login_ticket(&login).await;
+            let error = match result { Err(e) => e.to_string(), Ok(_) => panic!("expected error response") };
+            task.abort();
+            assert!(!error.contains(&password), "the account password reached the launcher error string");
+        });
+    }
 }
diff --git a/src-tauri/src/fleet_custody.rs b/src-tauri/src/fleet_custody.rs
index e961230c..35c05f33 100644
--- a/src-tauri/src/fleet_custody.rs
+++ b/src-tauri/src/fleet_custody.rs
@@ -2467,4 +2467,41 @@ mod tests {
         let (first, second) = (unhex_vec(&first).unwrap(), unhex_vec(&second).unwrap());
         assert_eq!(bodies, [first.clone(), first, second]);
     }
+
+    #[test]
+    fn verifier_server_row_alias_must_not_restart_the_same_keys_window() {
+        let f = fixture();
+        let mut state = f.prepared();
+        let (row, _) = joiner();
+        let t0 = now_ms();
+        see_devices(std::slice::from_ref(&row), &f.pin(), t0, &mut state, &mut |s| save(s)).unwrap();
+        let alias = TenantDevice { device_id: hex(&[0x6f; 16]), ..row.clone() };
+        assert!(f.code(&row) == f.code(&alias), "the ceremony inputs did not change");
+        let rt = runtime();
+        let (client, seen) = rt.block_on(mock(approve_server()));
+        let _error = approve(&rt, &f, &client, &alias, &f.code(&row), t0 + 11 * MINUTE);
+        assert!(sent(&seen).is_empty(), "a row alias extended the approval window without new keys");
+    }
+
+    #[test]
+    fn verifier_valid_revocation_retry_preserves_bytes_with_clock_skew() {
+        let f = fixture();
+        save(&f.prepared()).unwrap();
+        let (row, _) = joiner();
+        let row = TenantDevice { status: "active".into(), ..row };
+        let rt = runtime();
+        let (client, seen) = rt.block_on(mock(refuse_all()));
+        let t0 = now_ms();
+        revoke(&rt, &f, &client, &row, DeviceRevocationReason::Retired, t0);
+        let saved = load().unwrap().revocations[&row.device_id].clone();
+        // The server clock is one minute behind this custodian's. At retry,
+        // the saved issued_at is only 270 seconds old on that server.
+        let retry = t0 + 270_000;
+        let server_now = retry - MINUTE;
+        assert!(server_now - issued_at(&saved, &f.signer).unwrap() < 300_000);
+        revoke(&rt, &f, &client, &row, DeviceRevocationReason::Retired, retry);
+        let posts = sent(&seen);
+        assert_eq!(posts.len(), 2);
+        assert!(posts[0].1 == posts[1].1, "a still-valid saved revocation was replaced");
+    }
 }
diff --git a/src-tauri/src/lib.rs b/src-tauri/src/lib.rs
index b1994e10..ea862dec 100644
--- a/src-tauri/src/lib.rs
+++ b/src-tauri/src/lib.rs
@@ -5958,6 +5958,20 @@ mod custody_tests {
         assert_eq!(join_pin(), Some((BINDING_J, anchor, "JOIN".to_string())));
     }
 
+    #[test]
+    fn verifier_join_confirmation_binds_the_displayed_tenant() {
+        let now = root_bootstrap::now_ms();
+        let _j = joiner("http://127.0.0.1:9", now);
+        let c = team_config::load().unwrap();
+        let ledger = team::db::Db::open().unwrap();
+        let anchor = [0x0a; 32];
+        let shown = code_for(&c, &BINDING_J, &anchor);
+        let substituted = shardx_core::trust_chain::Binding { tenant_id: [0x6f; 16], ..BINDING_J };
+        let result = pin_join(&c, &ledger, &substituted, &anchor, &hex(&anchor), &shown, now);
+        assert!(result.is_err(), "a different tenant must not use the displayed code");
+        assert_eq!(ledger.conn.query_row("SELECT count(*) FROM trust_anchors", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
+    }
+
     #[test]
     fn a_join_pin_is_refused_for_another_anchor_than_the_one_shown() {
         let now = root_bootstrap::now_ms();
diff --git a/src-tauri/src/team/sync.rs b/src-tauri/src/team/sync.rs
index 772c0656..05889e98 100644
--- a/src-tauri/src/team/sync.rs
+++ b/src-tauri/src/team/sync.rs
@@ -5664,6 +5664,17 @@ mod tests {
         world_with(Vec::new())
     }
 
+    #[test]
+    fn verifier_key_status_agrees_with_push_after_key_loss() {
+        let w = world();
+        assert!(holds_verified_key(&w.dev, &FLEET, NOW).unwrap());
+        assert_eq!(w.push().unwrap().version, 1);
+        crate::fleet_keys::save(&crate::fleet_keys::FleetKeyStore::default()).unwrap();
+        assert!(!holds_verified_key(&w.dev, &FLEET, NOW).unwrap());
+        let error = w.push().unwrap_err();
+        assert!(has(&error, "sync.noVerifiedFleetKey"), "push must also reject the missing key");
+    }
+
     /// `world` with `extra` containers in its trust evidence.
     fn world_with(extra: Vec<Vec<u8>>) -> World {
         world_of(extra, true)
diff --git a/tests/e2e/app.spec.ts b/tests/e2e/app.spec.ts
index 9b235c81..2f6f48ec 100644
--- a/tests/e2e/app.spec.ts
+++ b/tests/e2e/app.spec.ts
@@ -933,6 +933,42 @@ test("the reason list offers only Retired and Lost", async ({ page: a }) => {
   await expect(reason).toContainText("Lost");
 });
 
+test("verifier approval stays disabled until the custodian creates its fleet key", async ({ page: a }) => {
+  const server = fakeTeamServer([{ device_id: "c1".repeat(16), label: "Verifier Pending", status: "pending", granted: false }]);
+  await teamDevicePage(a, "a", server);
+  const row = await listDevices(a, "Verifier Pending");
+  await row.getByLabel("The code on the other device matches").check();
+  await cardSignIn(a);
+  await expect(a.getByRole("button", { name: "Create fleet key", exact: true })).toBeVisible();
+  await expect(row.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
+});
+
+test("verifier refreshed keys require a fresh join-code comparison", async ({ page: a }) => {
+  const server = fakeTeamServer([{ device_id: "c1".repeat(16), label: "Verifier Pending", status: "pending", granted: false }]);
+  await teamDevicePage(a, "a", server);
+  await cardClick(a, "Create fleet key");
+  const row = await listDevices(a, "Verifier Pending");
+  await row.getByLabel("The code on the other device matches").check();
+  await a.evaluate(() => {
+    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
+    const original = ipc.invoke.bind(ipc);
+    ipc.invoke = async (...args) => {
+      const result = await original(...args);
+      if (args[0] === "team_devices") {
+        return (result as Record<string, unknown>[]).map((r) => r.label === "Verifier Pending"
+          ? { ...r, signing_key_id: "d2".repeat(32), hpke_key_id: "e3".repeat(32), sas: "1234 5678 90ab cdef 1234 5678 90ab cdef" }
+          : r);
+      }
+      return result;
+    };
+  });
+  await listDevices(a, "Verifier Pending");
+  await cardSignIn(a);
+  await expect(row.getByTestId("team-device-sas")).toHaveText("1234 5678 90ab cdef 1234 5678 90ab cdef");
+  await expect(row.getByLabel("The code on the other device matches")).not.toBeChecked();
+  await expect(row.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
+});
+
 test("connecting needs no token", async ({ page }) => {
   await gotoMocked(page);
   await page.getByRole("button", { name: "Team", exact: true }).click();
```

VERDICT: FAIL
