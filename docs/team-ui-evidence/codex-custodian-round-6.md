# Custodian fleet key, join ceremony and revocation — independent verification

HEAD verified: 4dddfdb6e9096b3a8a688df21221559875a75479.

Scope was the repository at that HEAD and git diff f5552844..HEAD. I used the contract rows and bullets named in the request from ADR 0002, the key locations in ADR 0004, and the shipped custody/revocation model in docs/key-custody.md. I did not inspect .omc/, .omx/, scratch directories, or review reports.

Test integrity check: the attack-path Rust tests contain real assertions; none was weakened with an empty assertion or an early return. The only early return found in the inspected server files is the intentional platform capability branch in server/tests/identity_authority.rs:213-221 (symlink creation is skipped only outside CI). The five ignored tests in the credential filter are explicitly child-process helpers, and the one ignored custodian_it entry is the intentional leak-scan worker. The required a_real_os_store_key_survives_into_a_fresh_process test was never run.

Common test outputs used below:

* cargo build -j 4 --manifest-path server/Cargo.toml — finished successfully.
* cargo test -j 4 --manifest-path server/Cargo.toml --test v2_auth — 83 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out.
* cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib fleet_custody -- --skip a_real_os_store_key_survives_into_a_fresh_process — 41 passed; 0 failed; 0 ignored; 0 measured; 694 filtered out.
* cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custodian_it -- --skip a_real_os_store_key_survives_into_a_fresh_process — 8 passed; 0 failed; 1 ignored; 0 measured; the ignored item is the_journey_leak_scan_worker.
* cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib root_bootstrap -- --skip a_real_os_store_key_survives_into_a_fresh_process — 31 passed; 0 failed; 0 ignored.
* cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib fleet_client -- --skip a_real_os_store_key_survives_into_a_fresh_process — 19 passed; 0 failed; 0 ignored.
* cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team_config -- --skip a_real_os_store_key_survives_into_a_fresh_process — 12 passed; 0 failed; 0 ignored.
* cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib credential -- --skip a_real_os_store_key_survives_into_a_fresh_process — 16 passed; 0 failed; 5 ignored; the five ignored entries are credential child-process helpers and the separate explicit OS-store check was skipped as required.
* cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib join -- --skip a_real_os_store_key_survives_into_a_fresh_process — 30 passed; 0 failed; 0 ignored.
* cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib a_join_pin_never_replaces_an_earlier_pin -- --skip a_real_os_store_key_survives_into_a_fresh_process — 1 passed; 0 failed.
* The requested Playwright command, npx playwright test tests/e2e/app.spec.ts -g "two devices|custodian|expired join|approval stays|revoke stays", stopped before collection with ERR_MODULE_NOT_FOUND: Cannot find package @playwright/test. No UI test executed and no repository file was created by that attempt.

## 1. Fleet grant recipient binding and listed-key identifiers — HOLDS

Enforcement:

* src-tauri/src/fleet_custody.rs:767-779 decodes the pending row's listed signing and HPKE public keys, recomputes signing_key_id and hpke_key_id, and rejects either mismatch before persistence.
* src-tauri/src/fleet_custody.rs:782-803 applies that check in check_member before the SAS and approval path.
* src-tauri/src/fleet_custody.rs:805-887 constructs the member grant by sealing the FKEK to the listed HPKE public key and saves the exact signed request bytes for replay.
* server/src/routes/v2_approval.rs:567-599 independently rederives the listed IDs from the stored public keys and compares the approval IDs.
* server/src/routes/v2_fleet.rs:792-909 verifies grant context, issuer signature, active subject, and the subject's exact signing/HPKE IDs before filing a DeviceHpkeGrant.

Tests and output:

* The fleet-custody run passed a_device_row_with_a_bad_key_id_is_refused_before_anything_is_saved and the_member_grant_is_sealed_to_the_listed_hpke_key_and_opens_with_it, as well as the exact-request and grant-integrity cases in that 41-test run.
* The 83-test v2_auth run passed the server approval, subject-key and fleet grant validation cases.

The server checks the recipient key identifier against the live device and the launcher test opens the ciphertext with the listed private key. A malicious custodian could deliberately create a signed denial grant with bad ciphertext, but that is an issuer-controlled denial and does not bypass the launcher sealing path or the server's signed-record/key-identity checks. No reachable path was found that gives a valid grant to a different listed device key.

New test written: none; existing coverage exercised the attack path.

## 2. Ten-minute first-sight approval window and SAS confirmation — HOLDS

Enforcement:

* src-tauri/src/fleet_custody.rs:645-648 defines JOIN_WINDOW_MS as ten minutes.
* src-tauri/src/fleet_custody.rs:695-750 records the first sighting of the pending row and each key ID with or_insert; later server data does not move the start time.
* src-tauri/src/fleet_custody.rs:753-764 uses the earliest recorded row/key time, and :782-803 rejects an expired window or a nonmatching typed SAS.
* src-tauri/src/fleet_custody.rs:910-954 checks the window before and after reading the active generation. :955-1021 replays a previously saved approval byte-for-byte, which is the documented retry exception after the original window closes.
* src/features/manage-team/ui/TeamDevices.tsx:161-224 computes the local expiry and disables approval after expiry.

Tests and output:

* The 41-test fleet-custody run passed approval_is_refused_ten_minutes_after_first_sight, a_saved_approval_is_resent_after_the_window_closes, approval_is_refused_when_the_confirmed_code_differs, a_new_row_id_for_the_same_keys_keeps_the_first_sight_window, and keys_moved_onto_a_row_seen_later_keep_their_first_sight_window.
* The 30-test join run passed a_late_join_confirm_is_refused_even_after_approval and the_join_code_expires_ten_minutes_after_this_device_enrolled.
* The UI cases were inspected at tests/e2e/app.spec.ts:1034-1057; collection was unavailable only because @playwright/test is absent, as recorded above.

The saved-request replay is intentional and sends the original request, so server-controlled data does not stretch a fresh approval window.

New test written: none.

## 3. Join pin binding and nonreplacement — HOLDS

Enforcement:

* shared/src/trust_chain.rs:671-700 computes the 128-bit join SAS over server instance, tenant, A0, signing-key ID and HPKE-key ID.
* src-tauri/src/lib.rs:2823-2877 obtains the live identity/evidence, evaluates A0, and returns the join code from those values.
* src-tauri/src/lib.rs:2880-2927 requires an unexpired code, checks the shown anchor against the evaluated anchor, recomputes SAS from the current binding, and calls the ledger pin only after the match.
* src-tauri/src/lib.rs:2930-2955 repeats evidence evaluation during confirm.
* src-tauri/src/team/ledger.rs:104-125 inserts the tenant pin with ON CONFLICT DO NOTHING, then compares an existing pin and rejects a different anchor; an accepted JOIN therefore never replaces an earlier pin.

Tests and output:

* The 30-test join run passed the server-instance, tenant, anchor, expiry and pin-read tests, including a_join_confirm_is_refused_when_the_server_instance_changed, a_join_confirm_is_refused_for_another_tenant_than_the_one_shown, a_join_pin_is_refused_for_another_anchor_than_the_one_shown, and a_joined_device_reads_its_anchor_from_the_join_pin.
* The dedicated ledger test passed with 1 passed; 0 failed: a_join_pin_never_replaces_an_earlier_pin.

New test written: none.

## 4. Revocation cutoff, self-revocation, and retry durability — HOLDS

Enforcement:

* server/src/routes/v2_auth.rs:359-445 makes a session live only while the device, keys and live approvals remain valid.
* server/src/routes/v2_device_revoke.rs:482-533 marks the device revoked, revokes approvals/capabilities/root/fleet grants, releases leases, and ends sessions in one transaction.
* server/src/routes/v2_device_revoke.rs:535-778 verifies active custodian, issuer signature and capability, exact subject keys, filing window, replay state and the last-custodian guard before applying the revocation.
* src-tauri/src/fleet_custody.rs:1041-1047 accepts only retired and lost. :1050-1130 refuses self-revocation, persists the exact revocation bytes before sending, and retries those bytes. It rebuilds only after the explicit top-level REVOCATION_OUTSIDE_WINDOW response while the subject is still live.

Tests and output:

* The 83-test v2_auth run passed session cutoff, revoked-device, capability, root/fleet grant and replay tests.
* The 41-test fleet-custody run passed a_custodian_does_not_revoke_itself, only_retired_and_lost_are_accepted, and a_resumed_revocation_resends_the_same_bytes.
* The 8-test custodian_it run passed the real-server revoke cutoff and audit row-count checks.

New test written: none.

## 5. FKEK generation lifecycle, crash/retry and saved-byte replay — HOLDS

Enforcement:

* src-tauri/src/fleet_custody.rs:167-201 saves the setup nonce first, reuses a saved setup key, and generates only when no saved key ID exists. Mismatched held/saved key IDs are refused.
* :203-215 forgets the setup key before clearing the reference and leaves the reference available for a retry if forgetting fails.
* :264-394 builds one FKEK, device grant, recovery grant and generation terms, then commits state atomically after the key is held.
* :400-576 resumes saved requests in fixed order, verifies server/epoch/device identity, acknowledges each grant and activates only after collection.
* src-tauri/src/lib.rs:2504-2573 releases the setup key before verified collection; a failure leaves the saved setup state resumable.
* docs/key-custody.md:116 documents the one-year expiry limitation for a PREPARING generation. That stated limitation is excluded by the request.

Tests and output:

* The 41-test fleet-custody run passed a_resumed_setup_resends_the_saved_bytes_and_never_makes_a_second_fleet_key, a_crash_between_holding_and_saving_the_fleet_key_reuses_the_held_key, a_failed_setup_leaves_no_verified_key, and the duplicate-ack, recovery, and exact-request tests.
* The 8-test custodian_it run passed setup resume, cleanup-failure/no-usable key, no-duplicate-ack, and real-server fleet-key creation/collection cases.

New test written: none.

## 6. Secret, seed, password, join-code and token leakage — HOLDS

Enforcement:

* src-tauri/src/fleet_client.rs:231-266 redacts secret values, bearer values, password fields and v2t., v2a., and v2r. token prefixes from errors; :113-122 hides session tokens in Debug.
* src-tauri/src/team_config.rs:71-88 uses a redacting Debug for tokens and seeds; its tests cover state serialization boundaries.
* src-tauri/src/root_bootstrap.rs:132-142 redacts the legacy TRK in debug output.
* src-tauri/src/fleet_custody.rs:134-142 omits keys and saved request bytes from debug output.
* src-tauri/src/custodian_it.rs includes a real-server secret-leak scan.

Tests and output:

* The credential run passed 16 passed; 0 failed; 5 ignored with the ignored entries limited to child-process helpers; the required OS-store test stayed skipped.
* The fleet-client, team-config, root-bootstrap and fleet-custody runs all passed their token/password/key redaction tests.
* The custodian_it run passed the integrated secret-leak scan.

The join-code IPC command at src-tauri/src/lib.rs:2823-2877 intentionally returns the current code to the join UI; that is the protocol's dedicated display output. No unintended log, persisted state, debug representation, error, or IPC reply was found to contain the FKEK, TRK, private/seed key, password, or v2 token values. The credential-store references and DPAPI-protected seed fields are the allowed custody locations described by ADR 0004:45-60 and docs/key-custody.md, not raw secret leakage.

New test written: none.

## 7. Launcher revocation reasons and custodian self-protection — HOLDS

Enforcement:

* src-tauri/src/fleet_custody.rs:1041-1047 parses only retired and lost.
* src-tauri/src/fleet_custody.rs:1065-1067 refuses the current custodian's own device ID.
* src/features/manage-team/ui/TeamDevices.tsx:229-249 offers the reason selector only with Retired/Lost and hides the current device row.

Tests and output:

* The 41-test fleet-custody run passed only_retired_and_lost_are_accepted and a_custodian_does_not_revoke_itself.
* The UI assertions at tests/e2e/app.spec.ts:1061-1071 were inspected and assert the exact two options. Playwright collection was unavailable because the package is missing.

New test written: none.

## 8. Tenant device listing scope and custodian requirement — HOLDS

Enforcement:

* server/src/routes/mod.rs:217-220 maps the device list route to v2_approval::list_tenant_devices.
* server/src/routes/v2_approval.rs:1063-1120 requires a live Principal::Session, requires the path tenant to equal the session tenant, checks is_active_custodian, and selects only that tenant's devices.

Tests and output:

* The 83-test v2_auth run passed a_custodian_lists_the_tenant_devices_with_their_public_keys and a_revoked_custodian_loses_the_shared_reads_and_listing, plus the cross-tenant and non-custodian authorization cases.

New test written: none.

## 9. Root-grant read isolation — HOLDS

Enforcement:

* server/src/routes/mod.rs:225-228 maps the root-grant read route to v2::list_tenant_root_key_grants.
* server/src/routes/v2.rs:744-785 uses require_tenant_caller, requires a v2 session for the same tenant and requires the path device ID to equal the caller device ID; otherwise it returns Forbidden. A v1 bearer does not pass this device-isolated read.
* The response contains sealed grants as intentional tenant trust evidence; docs/key-custody.md:116 and ADR 0002's trust-evidence rules document that tenant device sessions receive this evidence and only the recipient HPKE key opens its own grant.

Tests and output:

* The 83-test v2_auth run passed a_same_account_v1_token_does_not_bypass_device_root_grant_isolation and a_device_session_reads_the_active_fleet_generation_and_its_own_root_grants.

New test written: none.

## 10. v1-authenticated routes are not exposed anonymously — HOLDS

Enforcement:

* server/src/routes/mod.rs:48-240 shows the v2 route map. Mutating control, enrollment, approval, grant, revoke, sync and upload routes are mapped to extractors that require a v2 ticket/session or a signed record as their handler requires.
* server/src/routes/v2_auth.rs:447-487 reloads and validates a live v2 ticket/session; :510-533 is the explicit Caller bridge for routes that intentionally retain a v1 shared-read path.
* server/src/routes/v2.rs:114-143, :722-785, and :866-879 implement the intended authenticated reads: server identity, the caller's own root grants, and the active fleet generation. The tenant device list is separately session/custodian-gated at v2_approval.rs:1063-1120.

Tests and output:

* The 83-test v2_auth run passed the unauthenticated, stale-ticket, revoked session, v1-token isolation, and session-read tests. The 23-test identity_authority run also passed, including verified server-identity and v2-write gating. No route under review accepted an empty Authorization header.

New test written: none.

## 11. UI fleet-key state and action availability — HOLDS

Enforcement:

* src/features/manage-team/ui/TeamDevices.tsx:59-64 derives done from a committed fleet generation and no setup key being held, and ready from a verified usable fleet key.
* :74-86 refreshes custody status after setup failure; :131-150 renders blocked/no-usable/not-ready/ready states.
* :186-224 disables Approve unless the key is ready, the local ten-minute window is live, and the code-match checkbox is selected.
* :229-249 shows Revoke only for active non-self rows. It remains available after a fleet is created even if the local FKEK is lost, so loss of the key does not prevent device exclusion; before fleet creation the action is disabled.
* src/features/manage-team/ui/TeamCard.tsx:204-205 refreshes team state after collection, and :456-477 hides the join UI after a verified fleet key is held.

Tests and output:

* The UI cases inspected at tests/e2e/app.spec.ts:637-687, 799-839, 843-965, 969-1031, and 1034-1090 assert the two-device join, revoked pull cutoff, expired-code behavior, no-usable-key state, Q-18 notice, approval gating and revoke gating. They use nonempty visibility, text, count, value and enabled/disabled assertions.
* The requested Playwright command did not collect because the worktree lacks @playwright/test; no UI result is represented as a passing execution.

New test written: none.

## Defects

No defect with a reachable violation of the eleven stated goals was found. The documented custody limitation remains: docs/key-custody.md:116 says a PREPARING setup whose saved requests expire after one year has no completion route, and the request explicitly excludes that case. docs/key-custody.md:144-179 also says revocation does not recall an FKEK already held by a device and that rotation is a later operation; those are the shipped C-1/Q-13 semantics, not defects in this verification.

No new test was needed, so no test source file was added. The worktree was restored after test-generated schema-file changes; the only new file is this report.

VERDICT: PASS