# Independent verification: custodian fleet key, join ceremony and revocation

Verified HEAD: `97ee34c5e4aea772b75a9ba8730dc71693f4e938`.

Diff under examination: `git diff f5552844..HEAD`. Date: 2026-11-05. Platform: Windows. Production implementation was left unchanged. Four regression tests were added in the working copy; all four fail on the implementation at this HEAD. Goals 5, 6 and 11 are **VIOLATED**. The other eight goals **HOLD** on the paths and attacks exercised below.

Contract used for the conclusions: ADR 0002 Q-12, Q-13, C-1, Q-18, D-2, D-5 recovery grants, D-9 lifecycle maps and the pinned-head revocation rule; ADR 0004 credential storage; and the shipped model/limitations in `docs/key-custody.md`. No author plan or prior verification report was used. No `.omc/`, `.omx/` or scratch directory was inspected. New tests reuse this repository's existing loopback Axum fixtures, real-server harness and Playwright IPC fixtures.

The report distinguishes making a new signed approval from retransmitting one already confirmed and signed within the window. Saved, still-valid mutations must remain replayable. Revocation is assessed against the revoked device identity: registering a new pending identity with the shared account password, or decrypting previously obtained ciphertext with an already-copied key, is an explicitly documented limitation, not a revocation bypass.

## Reproduced defects

### D1 — A failed setup can leave a usable verified FKEK (goal 5)

**Enforcement gap:** `src-tauri/src/lib.rs:2557`, `src-tauri/src/lib.rs:2563`, `src-tauri/src/lib.rs:3117`, and `src-tauri/src/fleet_custody.rs:204`.

The verified collect saves the usable fleet key before setup deletes its temporary credential. If `credential::forget` fails, `team_fleet_key_setup` returns an error, but it does not undo or gate the already-collected key. `team_config::status().has_fleet_key` is true while `fleet_custody::status().setup_key_held` is also true.

Concrete scenario: finish generation activation, crash before collect, then resume while deletion of the setup credential fails. The new real-server test injects exactly that credential-store failure. It first proves there is no usable key before resumption, observes setup return an error, verifies the temporary key is still marked held, and fails because the key has become usable for sealing. This is an error/result consistency failure under the stated contract; the key itself was cryptographically verified. It does not demonstrate acceptance of an attacker-chosen FKEK.

New test: `src-tauri/src/custodian_it.rs:511`, `round3_failed_setup_cleanup_leaves_no_usable_verified_key`. Result: **FAILED**, `a failed setup left a verified key usable for sealing`.

### D2 — Successful device-list replies can echo an access token through IPC (goal 6)

**Enforcement gap:** `src-tauri/src/fleet_client.rs:681`, `src-tauri/src/fleet_custody.rs:739`, and `src-tauri/src/lib.rs:2618`.

Refusal text is scrubbed, but the successful device-list response is deserialized and its `label_hex` decoded directly into `ListedDevice.label`. That object is the Tauri command's serialized IPC reply.

Concrete scenario: the server receives the custodian's bearer token and puts its bytes in `label_hex` in an otherwise valid HTTP 200 device row. The launcher decodes the label and returns the complete token to the UI. The new loopback test passes a synthetic access token to `list_tenant_devices`, returns it in this documented field encoding, follows `see_devices`, and asserts that serialization excludes the token. It fails without printing the token. This is a recognized token prefix in decoded plaintext, not an unrecognized encoding left opaque in server error text. Normal best-effort logout reduces the token's useful lifetime, but does not satisfy the no-token-in-IPC contract; logout itself can fail.

New test: `src-tauri/src/fleet_custody.rs:2111`, `round3_a_successful_device_listing_does_not_echo_its_access_token_to_ipc`. Result: **FAILED**, `the device-list IPC reply leaked the access token`.

### D3 — Reopening Team offers reenrollment that an active pinned device always rejects (goal 11)

**Enforcement gap:** `src/features/manage-team/ui/TeamJoin.tsx:24`, `src/features/manage-team/ui/TeamJoin.tsx:102`, `src/features/manage-team/ui/TeamCard.tsx:456`; backend refusal at `src-tauri/src/lib.rs:2966`.

Concrete scenario: B is approved, confirms matching codes and pins the anchor, but has not collected its fleet key. Leave Team, wait beyond ten minutes, then reopen Team. `TeamJoin` initializes its component-local `pinned` flag to false. Show join code returns expiry, so the UI offers Enroll again. The backend always rejects this active-and-pinned state with `fleet.enrollAgainRefused`.

The new browser test performs this journey, confirms the IPC fixture rejects reenrollment, then fails because the forbidden action remains present. The fixture's refusal agrees with the real Rust command and its passing `enroll_again_is_refused_for_an_active_pinned_or_custodian_device` test. Collection remains an available way forward; this is a misleading offered action rather than destruction of the existing pin.

New test: `tests/e2e/app.spec.ts:896`, `round3 an active pinned device is not offered reenrollment after reopening Team`. Result: **FAILED**, expected 0 Enroll again buttons, received 1.

### D4 — The custodian's “Fleet key ready” ignores current key usability (goal 11)

**Enforcement gap:** `src/features/manage-team/ui/TeamDevices.tsx:53`, `src/features/manage-team/ui/TeamDevices.tsx:120`, `src/features/manage-team/ui/TeamDevices.tsx:205`, and `src/features/manage-team/ui/TeamCard.tsx:456`. The setup journal reported by `src-tauri/src/fleet_custody.rs:1178` is historical progress, not a live usability check.

Concrete scenario: a custodian completed setup, then its cached fleet key is lost, unavailable or no longer verifies. `team_status` correctly reports `has_fleet_key = false`; a published push refuses the key. The old setup journal still says `created = true, setup_key_held = false`. TeamCard selects the custodian branch and passes neither live key usability nor the Q-18 block state to TeamDevices. TeamDevices therefore says Fleet key ready and can enable approval based on that stale journal.

The existing Rust `key_status_and_push_agree_after_the_fleet_key_is_lost` test passes and establishes the real lost-key backend behavior. The new browser regression supplies that backend status while retaining completed setup progress, remounts Team, and fails on the ready message. It is a UI fixture test, not a second Rust cryptographic test.

New test: `tests/e2e/app.spec.ts:931`, `round3 a custodian with no usable key is not shown Fleet key ready`. Result: **FAILED**, expected 0 ready messages, received 1.

## Goal-by-goal evidence

Each test name below links to an executed suite in the output appendix. The appendix records exact commands, exit codes and test output, including the four new test bodies.

### 1. Substitute the recipient HPKE key or approve inconsistent public-key IDs — HOLDS

`src-tauri/src/fleet_custody.rs:767` recomputes both key IDs from the listed public keys; `:781` checks them before signing; `:855` binds the grant's recipient identifiers; `:867` seals to the exact decoded listed HPKE public key. `src-tauri/src/lib.rs:2671` supplies only a locally reverified fleet key. On the server, `server/src/routes/v2_approval.rs:976` checks pending/renewal eligibility and `:998` independently derives both IDs from stored public keys. `server/src/routes/v2_fleet.rs:893` binds a new grant to an active device and its keys.

Executed tests: `approval_is_refused_when_a_listed_key_does_not_hash_to_its_id`; `the_member_grant_is_sealed_to_the_listed_hpke_key_and_opens_with_it`; `a_custodian_lists_the_tenant_devices_with_their_public_keys`; `an_approval_needs_the_confirmation_the_session_and_the_exact_subject`; `a_custodian_approves_a_second_device_into_an_ordinary_session`. All passed. The HPKE test opens with the listed device's secret and explicitly rejects a different secret; it also inspects the signed approval and all three capability grants. The mismatch test edits each public key and each key ID and asserts nothing is sent or signed. No additional test was needed for this goal.

### 2. Bypass matching codes or extend either ten-minute comparison window — HOLDS

`src-tauri/src/fleet_custody.rs:696` saves first sight using the custodian's local clock. `:754` uses the earliest observation of the row or either key ID, so row renaming and key swapping do not reset the window. `:781` checks the code and time; `:944` checks time again after the network generation read. `src-tauri/src/lib.rs:2157` records enrollment time locally, `:2776` checks the joiner's window, and `:2911`/`:2924` enforce it before and after network work. `TeamDevices.tsx:55` binds a confirmation tick to both row ID and the displayed SAS, with the approve gate at `:205`.

Executed tests: `the_custodian_window_starts_when_it_first_sees_the_row_and_never_resets`; `approval_is_refused_ten_minutes_after_first_sight`; `approval_is_refused_when_the_confirmed_code_differs`; `a_new_row_id_for_the_same_keys_keeps_the_first_sight_window`; `keys_moved_onto_a_row_seen_later_keep_their_first_sight_window`; `keys_first_seen_after_a_swap_start_their_window_then`; `an_approval_is_not_signed_once_the_window_closes_during_the_generation_read`; `the_join_code_expires_ten_minutes_after_this_device_enrolled`; `a_late_join_confirm_is_refused_even_after_approval`. All passed. Browser tests for expiry, refreshed keys requiring a new comparison, and the custodian's disabled late approval also passed.

`a_saved_approval_is_resent_after_the_window_closes` passed: it deliberately allows exact retransmission of an already-confirmed signed request. This is recovery of the earlier decision, not a fresh signing window. No new test was needed.

### 3. Pin a different binding/anchor or replace a JOIN pin — HOLDS

`shared/src/trust_chain.rs:675` hashes the instance, tenant, anchor and both local key IDs into the 128-bit SAS. `src-tauri/src/lib.rs:2813` evaluates the evidence before showing the code. `:2853` compares the shown anchor and recomputes the whole SAS at pin time. `src-tauri/src/team/ledger.rs:107` uses insert-on-conflict-do-nothing and reads back the existing anchor; the earlier source is preserved.

Executed tests: the three `join_sas_*` tests; `a_join_confirm_is_refused_when_the_server_instance_changed`; `a_join_confirm_is_refused_for_another_tenant_than_the_one_shown`; `a_join_pin_is_refused_for_another_anchor_than_the_one_shown`; `a_joined_device_reads_its_anchor_from_the_join_pin`; `a_join_pin_never_replaces_an_earlier_pin`. All passed, with positive controls and assertions on the actual persisted pin/empty table. No new test was needed.

### 4. Give a revoked device new authority, or lose a saved revocation after send failure — HOLDS

`server/src/routes/v2_device_revoke.rs:554` takes the write transaction; `:732` files the signed revocation and `:733` revokes device status, sessions, approvals, capability grants, root grants, fleet grants and leases through `:482`. `server/src/routes/v2_auth.rs:363`/`:421` recheck live device/session state. New capability subjects must be active (`server/src/routes/v2_capability.rs:107`); new fleet grants have the active-subject predicate at `server/src/routes/v2_fleet.rs:893`.

The launcher saves exact bytes before sending at `src-tauri/src/fleet_custody.rs:1090` and reuses them at `:1095`. Only an explicit `REVOCATION_OUTSIDE_WINDOW` 403 for an unrevoked row permits one rebuild (`:1122`); generic refusals preserve the saved request. The server checks its filing window at `server/src/routes/v2_device_revoke.rs:632` and serves already-filed exact replays before that check.

Executed tests: `a_revoked_device_cannot_sign_in_again`; `a_revocation_blocks_new_capabilities_and_inflight_session_proofs`; `a_revoked_device_is_cut_off_but_keeps_the_key_it_already_holds_against_a_real_server`; `a_resumed_revocation_resends_the_same_bytes`; `a_stale_unfiled_revocation_is_rebuilt`; `a_retry_resends_a_saved_revocation_the_server_may_still_file`; `a_generic_403_does_not_replace_a_saved_revocation`. All passed. The real-server test attempts a fresh fleet grant after revocation and verifies rejection and no inserted grant.

Sticky client revocation, compromised-generation blocking, and rejection of a previously pinned head whose signer is subsequently revoked also passed in `custody_tests` and the targeted sync tests. Retired/lost revocations remain advisory for key rotation; copied keys are not recalled. No new test was needed.

### 5. Break setup crash/retry safety or retain a usable key after failure — VIOLATED

The positive protections are `src-tauri/src/fleet_custody.rs:174` (persist nonce, store/read back and reuse one FKEK), `:382` (save all exact requests before sending), `:494` (no rebuild once create is saved), `:498` through `:570` (create, file both grants, acknowledge and activate), and `:1151` (one active mutation run). `src-tauri/src/root_bootstrap.rs:403` saves a modified copy before replacing in-memory state. The recovery grant at `fleet_custody.rs:306` wraps under the self-grant's TRK and binds the generation's FKEK ID.

Executed passing tests include `a_crash_between_holding_and_saving_the_fleet_key_reuses_the_held_key`; `a_missing_or_locked_setup_key_after_its_id_is_saved_stops_and_never_regenerates`; `a_resumed_setup_resends_the_saved_bytes_and_never_makes_a_second_fleet_key`; `the_create_request_commits_to_the_one_device_grant_and_the_recovery_grant`; `the_recovery_grant_opens_to_the_fleet_key_and_runs_ten_years`; the real-server setup/resume tests; and `every_custody_operation_replays_its_lost_response_after_a_restart`.

The existing `a_failed_setup_leaves_no_verified_key` only fails generation creation, before collect. New test D1 covers the later cleanup failure and fails. Exact saved-byte retries and one-key behavior passed for still-valid records. The source explicitly documents no renewal/rebuild of setup grants after their year-long validity (`fleet_custody.rs:403`); these runs do not establish indefinite offline-resume liveness beyond the shipped validity/renewal limit.

### 6. Leak key material, password, join code in logs, or bearer tokens — VIOLATED

Positive protections: `src-tauri/src/credential.rs:99` stores raw keys with read-back, `:70` uses the mock backend in these tests; `fleet_custody.rs:82` persists references and signed/sealed requests, with restricted Debug at `:133`; `root_bootstrap.rs:157` onward returns fixed custody error codes; `fleet_client.rs:234` scrubs recognized secrets/tokens from error text and `:350` limits login failures to a constrained error code. Passwords are per-call inputs, not team state. Join codes are deliberately returned through their UI IPC response, but must not be logged.

Passing tests: `the_saved_state_and_its_debug_output_hold_no_key`; the root bootstrap secret/reference tests; the four selected mock-credential tests; all 17 fleet-client tests, including JSON/unicode/slash password echoes; team-config debug/storage tests; and `the_journey_leaks_no_secret_to_output_state_or_replies`.

The journey scans launcher stdout/stderr, serialized command replies and copied state against eight secret values plus the password, checks token-shaped strings, and separately checks displayed join codes against logs. It suppresses the real server's process output, so it is not a capture-based proof about every server log. It also did not cover hostile success-body echoes. New D2 does, and fails. No actual secret value is reproduced in this report or its test diagnostics.

### 7. Unsupported revocation reason or self-revocation from the launcher — HOLDS

`src-tauri/src/lib.rs:2716` calls `fleet_custody::revoke_reason` before any session work; the closed string match is at `fleet_custody.rs:1040`. `:1063` refuses the current device, case-insensitively. UI reason options are only retired/lost (`TeamDevices.tsx:222`); self rows have no revoke controls (`:147`, `:214`).

Executed tests: `only_retired_and_lost_are_accepted`; `a_custodian_does_not_revoke_itself`; browser `the reason list offers only Retired and Lost`; and `revoke stays disabled until the custodian creates its fleet key`. All passed. No new test was needed.

### 8. Cross-tenant or non-custodian device listing — HOLDS

`server/src/routes/v2_approval.rs:1067` requires a device session, reloads it in the transaction (`:1081`), compares its tenant to the path and requires an active root custodian. The SQL is tenant-filtered; tickets, pending setup and ordinary member sessions are rejected.

Executed tests: `a_custodian_lists_the_tenant_devices_with_their_public_keys` and `only_an_active_custodian_session_lists_the_tenant_devices`. Both passed. The latter checks a second tenant (404), tickets/pending/ordinary sessions (403), absence of a token (401), and a positive active-custodian control (200). No new test was needed.

### 9. Read another device's root grants through the device read endpoint — HOLDS

`server/src/routes/v2.rs:749` checks tenant membership and compares a v2 session's device to the path at `:772`. The legacy v1 caller is account-bound at `:761`: it may read grants for its mapped account's devices, not another account's devices. A v1 token has no device identity; that legacy account-level behavior is stated explicitly here rather than being confused with the new v2 device-session permission.

Executed tests: `a_device_session_reads_the_active_fleet_generation_and_its_own_root_grants` and `a_v1_member_cannot_read_another_accounts_root_grants`. Both passed, including same-account/different-device rejection for the v2 caller, foreign tenant and ticket rejection, actual nonempty own-grant controls, and rejection for a mapped foreign v1 account. This conclusion concerns the device grants endpoint, not signed sealed records intentionally included in trust evidence. No new test was needed.

### 10. Remove authentication from formerly v1-guarded routes — HOLDS

`server/src/routes/v2_auth.rs:520` dispatches recognized v2 ticket/access tokens through Principal validation, otherwise through the existing v1 AuthUser extractor. Only the three changed reads use Caller: `server/src/routes/v2.rs:114`, `:749`, `:879`; other legacy handlers still take AuthUser. The route registrations in `server/src/routes/mod.rs` were checked against this split.

Executed tests: `the_legacy_guarded_routes_still_require_v1_auth`; `server_identity_answers_a_ticket_and_a_session_without_a_v1_token`; and the active-generation/own-grants read test. All passed. The route matrix checks 40 legacy method/path combinations with both no bearer and a v2 device session and expects 401, and checks all three shared reads without a bearer (401). Server identity intentionally also accepts a live pre-device ticket; this is authenticated, not anonymous access. No new test was needed.

### 11. Misreport usable fleet custody or offer impossible backend actions — VIOLATED

The underlying usability predicate is sound in the exercised cases: `src-tauri/src/team_config.rs:320` reports `Some(false)` from `sync_cmd::verified_fleet_key_blocked` (`:469`), which uses `team::sync::verified_key_blocked` (`:1634`), the same reverified highest-generation key selection and compromise block used for sealing. `TeamCard.tsx:458` uses this for an ordinary joined device, and `:462` displays a separate Q-18 block state.

Executed passing tests: `a_legacy_cached_fleet_key_alone_is_not_a_fleet_key`; `key_status_and_push_agree_after_the_fleet_key_is_lost`; `key_status_agrees_with_a_compromise_blocked_push`; browser `a fleet key Q-18 blocks is reported instead of the join steps`; approval/revocation disabled before setup; the two-device profile journey. The UI still has separate stale-state paths: D3 and D4. Both new browser tests fail at their final visible-control/message assertions.

## Test integrity and execution limits

- No assertion was removed, weakened or converted to an expected failure. New regression assertions express the required behavior and remain failing in the working copy.
- The focused custody, client, join, key-status and server-auth tests contain no ignored security checks or early-return bypasses. Negative tests assert no outgoing mutation, no inserted/pinned state, exact request equality, or explicit denial, with positive controls where appropriate.
- The real-server leak worker has `#[ignore]` because its parent invokes that exact test in a fresh process with `--ignored --nocapture`. The parent requires successful exit and `1 passed`, requires the expected files and eight secrets, and checks both secrets and join-code logging. Its passing parent result therefore exercises the worker; the suite's one ignored line is not omitted coverage.
- A separate pre-existing weakness was found at `server/tests/identity_authority.rs:213`: the symlink subcheck returns early when Windows cannot create a symlink and `CI` is unset. The ordinary suite reported 23 passes. Re-running this test with `CI=1` failed at `:216`, exposing that this machine did not execute the symlink assertion. The directory-as-nonregular-file check still ran. No symlink coverage is claimed for the custody goals.
- Launcher commands used `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib <filter> -- --skip a_real_os_store_key_survives_into_a_fresh_process`. The excluded real OS credential-store test was never run. Test fixtures used temporary config/data roots and the in-memory credential backend; the real launcher profile under `%APPDATA%` was not used.
- The server build completed before `custodian_it`: `cargo build -j 4 --manifest-path server/Cargo.toml`, exit 0, `Finished dev profile ... in 12.65s`. An earlier redundant build collided with a running test server on Windows (os error 5); the successful build superseded it. No os error 1455 occurred.
- Two multi-command context-mode invocations exceeded the tool's 300-second response limit. Only completed, saved test outputs are counted. The uncompleted broad `team::sync::tests` invocation is not claimed as passing; the relevant sync tests were subsequently run with focused filters and completed. Cargo test failures below are the new regressions, plus the explicit CI symlink probe.
- UI dependencies were installed from the existing npm cache using `--offline --ignore-scripts --no-audit --no-fund`; ui-kit was built locally. Browser tests used the local Vite server at `127.0.0.1:4173`. Rust servers and mock servers listened on loopback. No commit, push, PR, issue or message was sent.
- Tooling-boundary note: after a context-mode tool error, its diagnostic command was invoked as the tool requested. It reported an npm version-availability check. That diagnostic was outside the requested test-only network boundary; no upgrade or issue command was run. This note prevents claiming an absolute network-isolation guarantee for the entire verifier session.

## Executed output and new regression source

The following output was captured from this worktree. Long secret-like hexadecimal values are redacted if encountered; no secret value is needed to understand any failure. Browser line numbers reflect each execution before later test insertions.

### `cargo test -j 4 --manifest-path server/Cargo.toml --test v2_auth`

Exit code: 0.

```text
running 82 tests
test a_device_that_changed_since_its_challenge_gets_no_session ... ok
test a_bootstrap_needs_a_first_self_grant_and_a_consumed_guard ... ok
test a_custodian_lists_the_tenant_devices_with_their_public_keys ... ok
test a_device_reads_back_only_its_own_fleet_grant_as_an_exact_descriptor ... ok
test a_custodian_approves_a_second_device_into_an_ordinary_session ... ok
test a_container_of_another_row_is_marked_without_a_hash ... ok
test a_custodian_creates_fleet_generations_and_files_their_grants ... ok
test a_corrupt_container_is_marked_without_a_hash_and_served_again_once_restored ... ok
test a_device_session_reads_the_active_fleet_generation_and_its_own_root_grants ... ok
test a_bootstrap_needs_d1_the_setup_session_and_an_exact_self_grant ... ok
test a_custodian_files_an_existing_root_grant_only_to_a_tenant_approved_device ... ok
test a_custodian_files_a_restore_epoch_transition_once_and_the_tenant_reads_it_back ... ok
test a_custodian_rotates_the_root_to_a_new_custodian_set ... ok
test a_custodian_acks_activates_rotates_and_revokes_fleet_grants ... ok
test a_custodian_revokes_a_root_grant_but_never_the_last_one ... ok
test a_proof_belongs_to_its_own_ticket ... ok
test a_closed_or_recovering_guard_never_approves ... ok
test a_mark_without_a_container_hash_is_served_again_once_the_row_verifies ... ok
test a_revocation_blocks_new_capabilities_and_inflight_session_proofs ... ok
test a_revocation_commits_its_root_activation ... ok
test a_revocation_quarantined_at_runtime_refuses_the_trust_evidence ... ok
test a_revocation_commits_its_fleet_activation_or_nothing ... ok
test a_quarantined_revocation_that_verifies_again_is_served_again_after_a_restart ... ok
test a_marked_row_swapped_for_another_genuine_revocation_is_not_served_again ... ok
test a_revocation_of_another_instance_turns_v2_off_until_it_is_put_back ... ok
test a_revocation_row_swapped_for_another_genuine_one_does_not_answer_a_retry ... ok
test a_revocation_row_the_startup_pass_cannot_read_turns_v2_off ... ok
test a_session_from_another_epoch_is_refused ... ok
test a_row_holding_another_rows_container_is_not_that_grant ... ok
test a_session_rotates_a_bounded_number_of_times ... ok
test a_signing_only_proof_burns_the_challenge ... ok
test a_first_device_confirmed_before_a_restore_is_approved_or_cancelled_after_it ... ok
test a_ticket_enrolls_a_device_and_then_proves_it_into_a_session ... ok
test a_ticket_becomes_a_device_session_only_through_both_proofs ... ok
test a_ticket_authorizes_nothing_but_its_own_proofs ... ok
test a_ticket_issues_five_challenges_in_its_life ... ok
test a_stored_receipt_that_disagrees_closes_the_approval_path ... ok
test a_v1_member_cannot_read_another_accounts_root_grants ... ok
test a_wrong_enrollment_signature_burns_the_challenge ... ok
test a_revoked_device_cannot_sign_in_again ... ok
test a_trust_evidence_page_stays_within_four_mebibytes ... ok
test after_a_restart_a_new_login_reaches_the_same_device ... ok
test concurrent_challenges_stop_at_the_cap ... ok
test an_approval_needs_the_confirmation_the_session_and_the_exact_subject ... ok
test a_root_rotation_rewraps_every_retained_fleet_key_before_it_activates ... ok
test approvals_and_root_grants_from_before_a_restore_still_work_after_it ... ok
test concurrent_identical_approvals_commit_once ... ok
test concurrent_identical_bootstraps_commit_once_and_a_bad_ledger_is_refused ... ok
test fleet_grants_from_before_a_restore_are_acknowledged_and_revoked_after_it ... ok
test live_state_ends_tickets_and_sessions ... ok
test every_approval_column_is_compared_with_its_container_on_each_request ... ok
test logout_ends_the_ticket_its_challenges_or_the_session ... ok
test login_failures_are_throttled_and_say_nothing ... ok
test an_expired_self_grant_is_neither_counted_nor_acknowledged ... ok
test only_an_acknowledged_unrevoked_custody_grant_issues ... ok
test only_a_live_custodian_files_an_issuable_grant_for_a_live_subject ... ok
test only_an_active_custodian_session_lists_the_tenant_devices ... ok
test only_the_accounts_own_pending_device_gets_a_challenge ... ok
test only_the_creator_files_its_own_grant_before_holding_the_generation ... ok
test refresh_rotates_once_and_respects_expiry ... ok
test server_identity_answers_a_ticket_and_a_session_without_a_v1_token ... ok
test readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant ... ok
test every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... ok
test the_legacy_guarded_routes_still_require_v1_auth ... ok
test the_active_custodian_files_capability_grants_once ... ok
test the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response ... ok
test every_fleet_grant_column_is_compared_with_its_container_on_each_request ... ok
test the_first_device_reads_back_acknowledges_and_activates_generation_zero ... ok
test the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt ... ok
test every_device_revocation_column_is_compared_with_its_container_on_each_request ... ok
test every_way_of_naming_the_tenant_shares_one_account_throttle ... ok
test the_startup_pass_quarantines_approvals_that_left_their_containers ... ok
test an_account_holds_a_bounded_number_of_tickets ... ok
test the_startup_pass_quarantines_device_revocations_that_left_their_containers ... ok
test the_trust_evidence_pages_past_a_thousand_containers_and_leaves_nothing_out ... ok
test the_trust_evidence_reports_a_revoked_device_from_its_record_not_its_column ... ok
test two_bootstraps_under_different_keys_commit_once_and_a_custodian_closes_it ... ok
test the_startup_pass_quarantines_fleet_grants_that_left_their_containers ... ok
test the_trust_evidence_is_the_full_ancestry_of_the_root_subjects ... ok
test the_startup_pass_quarantines_grants_that_left_their_containers ... ok
test every_custody_operation_replays_its_lost_response_after_a_restart ... ok
test every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... ok
test result: ok. 82 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 100.70s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 6.50s
```

### `cargo test -j 4 --manifest-path server/Cargo.toml --test identity_authority`

Exit code: 0.

```text
running 23 tests
test a_non_utf8_argument_is_a_usage_error ... ok
test init_requires_an_identity_directory ... ok
test init_refuses_an_identity_directory_inside_the_data_directory ... ok
test a_symlinked_record_is_refused ... ok
test init_writes_the_record_then_the_mirror_and_show_verifies_both ... ok
test tenant_create_refuses_before_identity_init ... ok
test unknown_commands_print_usage_and_fail ... ok
test tenant_create_refuses_a_weak_password ... ok
test show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest ... ok
test tenant_create_rolls_back_everything_when_the_audit_insert_fails ... ok
test tenant_create_takes_no_password_from_argv_or_env_and_never_blocks ... ok
test tenant_create_rolls_back_everything_when_the_fleet_audit_insert_fails ... ok
test init_refuses_existing_state_and_writes_nothing ... ok
test confirm_first_device_records_the_operator_match_once ... ok
test cancel_closes_the_attempt_for_good ... ok
test a_fingerprint_typo_writes_nothing_and_can_be_retried ... ok
test a_running_server_holds_the_lock_against_commands_and_a_second_server ... ok
test a_verified_identity_opens_v2_writes ... ok
test an_interrupted_init_is_reported_and_never_repaired ... ok
test tenant_create_writes_tenant_owner_membership_and_offline_audit_together ... ok
test cancel_refuses_what_is_not_an_open_reservation ... ok
test without_an_identity_directory_v2_writes_are_refused_and_v1_works ... ok
test confirm_refuses_a_device_that_is_not_a_clean_pending_first_device ... ok
test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.70s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 5.57s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib fleet_custody -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 101.

```text
running 32 tests
test fleet_custody::tests::a_setup_collect_that_keeps_no_key_reports_its_own_error ... ok
test fleet_custody::tests::a_crash_between_holding_and_saving_the_fleet_key_reuses_the_held_key ... ok
test fleet_custody::tests::an_old_server_without_the_listing_route_reports_server_too_old ... ok
test fleet_custody::tests::a_new_row_id_for_the_same_keys_keeps_the_first_sight_window ... ok
test fleet_custody::tests::a_setup_saved_for_another_tenant_device_or_server_is_refused ... ok
test fleet_custody::tests::a_failed_setup_leaves_no_verified_key ... ok
test fleet_custody::tests::a_resumed_revocation_resends_the_same_bytes ... ok
test fleet_custody::tests::a_custodian_does_not_revoke_itself ... ok
test fleet_custody::tests::only_retired_and_lost_are_accepted ... ok
test fleet_custody::tests::a_missing_or_locked_setup_key_after_its_id_is_saved_stops_and_never_regenerates ... ok
test fleet_custody::tests::a_resumed_setup_resends_the_saved_bytes_and_never_makes_a_second_fleet_key ... ok
test fleet_custody::tests::a_retry_resends_a_saved_revocation_the_server_may_still_file ... ok
test fleet_custody::tests::a_saved_approval_is_resent_after_the_window_closes ... ok
test fleet_custody::tests::a_generic_403_does_not_replace_a_saved_revocation ... ok
test fleet_custody::tests::a_setup_where_the_server_reports_pending_ack_keeps_the_saved_ack_after_release ... ok
test fleet_custody::tests::a_stale_unfiled_revocation_is_rebuilt ... ok
test fleet_custody::tests::an_approval_is_not_signed_once_the_window_closes_during_the_generation_read ... ok
test fleet_custody::tests::approval_is_refused_ten_minutes_after_first_sight ... ok
test fleet_custody::tests::approval_is_refused_when_a_listed_key_does_not_hash_to_its_id ... ok
test fleet_custody::tests::approval_is_refused_when_the_confirmed_code_differs ... ok
test fleet_custody::tests::collect_custody_uses_the_tenant_fleet_when_none_is_configured ... ok
test fleet_custody::tests::collect_skips_the_ack_of_an_acknowledged_grant ... ok
test fleet_custody::tests::keys_first_seen_after_a_swap_start_their_window_then ... ok
test fleet_custody::tests::keys_moved_onto_a_row_seen_later_keep_their_first_sight_window ... ok
test fleet_custody::tests::round3_a_successful_device_listing_does_not_echo_its_access_token_to_ipc ... FAILED
test fleet_custody::tests::team_commands_need_no_admin_token ... ok
test fleet_custody::tests::the_create_request_commits_to_the_one_device_grant_and_the_recovery_grant ... ok
test fleet_custody::tests::the_custodian_window_starts_when_it_first_sees_the_row_and_never_resets ... ok
test fleet_custody::tests::the_fleet_key_is_held_before_any_request_names_it ... ok
test fleet_custody::tests::the_member_grant_is_sealed_to_the_listed_hpke_key_and_opens_with_it ... ok
test fleet_custody::tests::the_recovery_grant_opens_to_the_fleet_key_and_runs_ten_years ... ok
test fleet_custody::tests::the_saved_state_and_its_debug_output_hold_no_key ... ok
failures:
thread 'fleet_custody::tests::round3_a_successful_device_listing_does_not_echo_its_access_token_to_ipc' (13476) panicked at src\fleet_custody.rs:2134:9:
the device-list IPC reply leaked the access token
failures:
test result: FAILED. 31 passed; 1 failed; 0 ignored; 0 measured; 688 filtered out; finished in 1.08s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 32.24s
error: test failed, to rerun pass `--lib`
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib fleet_client -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 17 tests
test fleet_client::tests::a_session_binding_must_name_every_expected_field ... ok
test fleet_client::tests::hex_from_the_server_never_panics_or_takes_signs ... ok
test fleet_client::tests::a_refusal_keeps_its_words_but_no_credential ... ok
test fleet_client::tests::a_password_goes_only_over_https_or_to_this_machine ... ok
test fleet_client::tests::replay_ids_are_unique ... ok
test fleet_client::tests::ids_must_be_16_bytes_of_hex ... ok
test fleet_client::tests::a_session_debug_print_hides_its_tokens ... ok
test fleet_client::tests::a_trailing_slash_does_not_double_up_in_paths ... ok
test fleet_client::tests::a_base_url_must_carry_a_scheme ... ok
test fleet_client::tests::the_client_token_zeroizes_on_drop ... ok
test fleet_client::tests::a_login_error_hides_a_password_echoed_with_an_escaped_slash ... ok
test fleet_client::tests::a_login_error_hides_a_password_echoed_with_json_escapes ... ok
test fleet_client::tests::a_login_error_hides_the_echoed_password ... ok
test fleet_client::tests::a_refusal_hides_the_v1_token_echoed_bare ... ok
test fleet_client::tests::an_error_reply_hides_echoed_session_tokens ... ok
test fleet_client::tests::a_login_error_hides_a_non_ascii_password_echoed_as_ascii_escapes ... ok
test fleet_client::tests::a_login_error_keeps_only_an_error_code_the_server_names ... ok
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 703 filtered out; finished in 0.01s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.06s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib root_bootstrap -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 31 tests
test root_bootstrap::tests::a_failed_save_leaves_the_callers_state_as_it_was ... ok
test root_bootstrap::tests::a_hex_secret_decodes_into_32_bytes_or_is_refused ... ok
test root_bootstrap::tests::a_receipt_counts_only_for_this_devices_own_approval ... ok
test root_bootstrap::tests::a_reference_for_another_tenant_or_with_a_malformed_nonce_is_refused ... ok
test root_bootstrap::tests::a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made ... ok
test root_bootstrap::tests::a_stored_response_counts_only_when_it_answers_this_exact_request ... ok
test root_bootstrap::tests::a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it ... ok
test root_bootstrap::tests::a_legacy_trk_is_refused_when_a_reference_is_already_set ... ok
test root_bootstrap::tests::a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key ... ok
test root_bootstrap::tests::the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written ... ok
test root_bootstrap::tests::a_legacy_trk_never_overwrites_a_different_stored_key ... ok
test root_bootstrap::tests::a_legacy_trk_with_a_malformed_nonce_is_refused_before_anything_is_stored ... ok
test root_bootstrap::tests::the_saved_state_never_prints_the_legacy_trk ... ok
test root_bootstrap::tests::a_new_run_never_reuses_a_key_an_abandoned_run_left ... ok
test root_bootstrap::tests::a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it ... ok
test root_bootstrap::tests::the_self_approval_names_this_device_tenant_wide_for_a_year ... ok
test root_bootstrap::tests::the_self_grant_seals_the_trk_to_this_device_and_links_the_approval ... ok
test root_bootstrap::tests::a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing ... ok
test root_bootstrap::tests::a_legacy_file_that_names_no_tenant_or_holds_no_key_is_refused ... ok
test root_bootstrap::tests::a_reference_to_another_credential_is_refused_and_that_credential_is_kept ... ok
test root_bootstrap::tests::a_legacy_trk_the_store_already_holds_is_only_dropped ... ok
test root_bootstrap::tests::a_resume_loads_the_stored_key_and_a_missing_one_is_not_made_up_again ... ok
test root_bootstrap::tests::a_store_that_refuses_a_new_key_leaves_no_reference_and_no_file ... ok
test root_bootstrap::tests::a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed ... ok
test root_bootstrap::tests::an_activated_run_forgets_a_key_that_an_earlier_run_left ... ok
test root_bootstrap::tests::an_activated_run_keeps_the_root_records_and_they_reload_exactly ... ok
test root_bootstrap::tests::releasing_forgets_the_key_and_drops_the_reference ... ok
test root_bootstrap::tests::the_activation_is_saved_before_the_key_is_forgotten ... ok
test root_bootstrap::tests::the_run_nonce_is_saved_before_the_key_is_stored ... ok
test root_bootstrap::tests::the_trk_is_stored_and_the_saved_state_holds_only_its_reference ... ok
test root_bootstrap::tests::the_recovery_export_is_read_back_and_its_pinned_hash_returned ... ok
test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 689 filtered out; finished in 17.63s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.59s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib join_ -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 29 tests
test team::ledger::tests::a_join_pin_never_replaces_an_earlier_pin ... ok
test custody_tests::a_join_confirm_is_refused_when_the_server_instance_changed ... ok
test custody_tests::a_joined_device_reads_its_anchor_from_the_join_pin ... ok
test custody_tests::a_join_confirm_is_refused_for_another_tenant_than_the_one_shown ... ok
test team::sync::tests::a_join_past_an_untrusted_child_keeps_data_and_can_unbind ... ok
test team::sync::tests::a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind ... ok
test custody_tests::a_join_pin_is_refused_for_another_anchor_than_the_one_shown ... ok
test team::sync::tests::join_after_a_restore_pins_the_transition_leaf_then_pulls ... ok
test team::sync::tests::a_join_whose_pin_fails_keeps_the_local_profile ... ok
test team::sync::tests::join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf ... ok
test team::sync::tests::join_binds_and_pulls_a_remote_profile_on_a_new_device ... ok
test team::sync::tests::join_lists_fleet_profiles_with_their_opened_labels_and_marks_bound_ones ... ok
test custody_tests::a_late_join_confirm_is_refused_even_after_approval ... ok
test custody_tests::the_join_code_expires_ten_minutes_after_this_device_enrolled ... ok
test custody_tests::an_approved_device_whose_join_code_expired_can_enroll_again ... ok
test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok
test team::sync::tests::join_never_pins_a_leaf_withdrawn_during_the_proof_fetch ... ok
test team::sync::tests::join_of_a_profile_created_after_a_restore_starts_at_that_epoch ... ok
test team::sync::tests::join_refuses_a_bound_or_running_local_profile ... ok
test team::sync::tests::join_refuses_a_local_profile_with_an_unfinished_publish ... ok
test team::sync::tests::join_refuses_a_remote_profile_already_bound_here ... ok
test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok
test team::sync::tests::join_refuses_a_remote_profile_bound_here_meanwhile ... ok
test team::sync::tests::join_refuses_the_rolled_back_child_of_the_leaf ... ok
test team::sync::tests::join_refuses_without_the_collected_fleet_key_and_creates_no_binding ... ok
test team::sync::tests::join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes ... ok
test team::sync::tests::join_then_check_in_then_pull_on_the_first_device ... ok
test team::sync::tests::join_then_a_push_before_the_first_pull_restores_is_refused ... ok
test team::sync::tests::join_with_a_lying_first_snapshot_pins_nothing ... ok
test result: ok. 29 passed; 0 failed; 0 ignored; 0 measured; 691 filtered out; finished in 54.10s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.63s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team_config -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 12 tests
test team_config::tests::a_device_without_an_identity_moves_nothing ... ok
test team_config::tests::team_config_golden_includes_enrolled_at_ms ... ok
test team_config::tests::debug_never_prints_the_token_or_a_seed ... ok
test team_config::tests::an_old_team_config_without_enrolled_at_ms_still_loads ... ok
test team_config::tests::secrets_zeroize_on_drop_and_the_file_format_is_unchanged ... ok
test team_config::tests::enrolled_seeds_move_to_the_credential_store_and_still_open ... ok
test team_config::tests::a_plaintext_file_still_loads_and_is_rewritten_protected ... ok
test team_config::tests::a_seed_the_store_refuses_stays_in_the_file ... ok
test team_config::tests::an_unopenable_dpapi_seed_is_named_kept_and_allows_re_enrollment ... ok
test team_config::tests::a_dpapi_protected_seed_moves_to_the_credential_store ... ok
test team_config::tests::saved_seeds_are_dpapi_protected_and_load_back ... ok
test team_config::tests::a_legacy_cached_fleet_key_alone_is_not_a_fleet_key ... ok
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 708 filtered out; finished in 0.05s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.87s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custodian_it -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 101.

```text
running 8 tests
test custodian_it::the_journey_leak_scan_worker ... ignored, a worker of the_journey_leaks_no_secret_to_output_state_or_replies
test custodian_it::a_fleet_setup_resumes_after_a_failed_save_and_a_replayed_run_against_the_real_server ... ok
test custodian_it::the_custodian_creates_and_collects_the_fleet_key_against_the_real_server ... ok
test custodian_it::the_journey_leaks_no_secret_to_output_state_or_replies ... ok
test custodian_it::round3_failed_setup_cleanup_leaves_no_usable_verified_key ... FAILED
test custodian_it::a_revoked_device_is_cut_off_but_keeps_the_key_it_already_holds_against_a_real_server has been running for over 60 seconds
test custodian_it::the_journey_writes_one_audit_row_per_mutation has been running for over 60 seconds
test custodian_it::two_devices_share_a_profile_through_a_real_server_after_approval has been running for over 60 seconds
test custodian_it::two_devices_share_a_profile_through_a_real_server_after_approval ... ok
test custodian_it::the_journey_writes_one_audit_row_per_mutation ... ok
test custodian_it::a_revoked_device_is_cut_off_but_keeps_the_key_it_already_holds_against_a_real_server ... ok
failures:
thread 'custodian_it::round3_failed_setup_cleanup_leaves_no_usable_verified_key' (33188) panicked at src\custodian_it.rs:540:5:
a failed setup left a verified key usable for sealing
failures:
test result: FAILED. 6 passed; 1 failed; 1 ignored; 0 measured; 712 filtered out; finished in 120.69s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.49s
error: test failed, to rerun pass `--lib`
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custody_tests -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 44 tests
test custody_tests::a_fleet_descriptor_counts_only_for_this_device_and_generation ... ok
test custody_tests::a_collected_fleet_key_is_never_replaced ... ok
test custody_tests::a_joined_device_reads_its_anchor_from_the_join_pin ... ok
test custody_tests::a_join_pin_is_refused_for_another_anchor_than_the_one_shown ... ok
test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok
test custody_tests::a_join_confirm_is_refused_when_the_server_instance_changed ... ok
test custody_tests::a_join_confirm_is_refused_for_another_tenant_than_the_one_shown ... ok
test custody_tests::a_key_is_used_only_while_its_kept_record_reloads_exactly ... ok
test custody_tests::a_late_join_confirm_is_refused_even_after_approval ... ok
test custody_tests::a_lapse_is_the_known_end_of_custody_clipped_at_the_key_age ... ok
test custody_tests::a_head_by_a_committer_a_sticky_revoked_key_appointed_is_refused ... ok
test custody_tests::a_server_delivered_fleet_key_is_counted_but_never_cached ... ok
test custody_tests::a_pinned_pending_device_can_enroll_again ... ok
test custody_tests::an_approved_device_whose_join_code_expired_can_enroll_again ... ok
test custody_tests::enroll_again_clears_a_pending_identity ... ok
test custody_tests::a_fleet_generation_never_goes_back ... ok
test custody_tests::a_lapsed_custodians_backdated_grant_is_refused_with_history ... ok
test custody_tests::a_kept_grant_is_reverified_before_its_key_is_used ... ok
test custody_tests::only_the_bootstrapped_device_has_a_pinned_anchor ... ok
test custody_tests::limit_a_new_device_counts_a_backdated_revocation_with_its_revoker ... ok
test custody_tests::limit_mutual_revocation_counts_both_on_a_new_device ... ok
test custody_tests::a_renewal_issued_before_the_count_is_sticky_and_alerts_once ... ok
test custody_tests::a_server_cannot_lapse_a_custodian_or_age_its_key_for_good ... ok
test custody_tests::an_omitted_first_root_grant_never_stretches_the_key_age_with_history ... ok
test custody_tests::a_counted_revocation_outlives_the_server_omitting_it ... ok
test custody_tests::limit_a_backdated_grant_from_a_never_counted_custodian_is_accepted ... ok
test custody_tests::local_distrust_ignores_what_is_first_seen_after_it ... ok
test custody_tests::reverifying_a_kept_key_records_the_lapse_history_shows ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok
test custody_tests::a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet ... ok
test custody_tests::revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok
test custody_tests::the_pinned_anchor_never_changes ... ok
test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_forged_container ... ok
test custody_tests::records_first_seen_before_a_count_keep_their_standing ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok
test custody_tests::pull_uses_a_verified_key_only_while_its_issuer_stands ... ok
test custody_tests::the_join_code_expires_ten_minutes_after_this_device_enrolled ... ok
test custody_tests::enroll_again_is_refused_for_an_active_pinned_or_custodian_device ... ok
test custody_tests::a_reported_revocation_outlives_the_server_omitting_it ... ok
test custody_tests::a_revocation_counts_only_from_a_custodian_allowed_to_revoke ... ok
test custody_tests::a_lapse_from_history_refuses_a_backdated_grant_with_no_evaluation_between ... ok
test custody_tests::a_verified_fleet_grant_opens_and_nothing_else_does ... ok
test result: ok. 44 passed; 0 failed; 0 ignored; 0 measured; 676 filtered out; finished in 8.94s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.41s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests::key_status -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 2 tests
test team::sync::tests::key_status_agrees_with_a_compromise_blocked_push ... ok
test team::sync::tests::key_status_and_push_agree_after_the_fleet_key_is_lost ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 718 filtered out; finished in 0.96s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.84s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests::a_pinned_head_of_a_since_revoked -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 1 test
test team::sync::tests::a_pinned_head_of_a_since_revoked_signer_is_not_restored ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 719 filtered out; finished in 2.62s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.76s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests::a_compromised_revocation_blocks -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 1 test
test team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 719 filtered out; finished in 2.07s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.72s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests::a_compromised_custodian_blocks -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 1 test
test team::sync::tests::a_compromised_custodian_blocks_every_fleet_through_the_root ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 719 filtered out; finished in 2.98s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.70s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib sync_cmd -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 8 tests
test sync_cmd::tests::profile_ref_is_stable_and_distinct ... ok
test sync_cmd::tests::profile_ref_is_sixteen_bytes_of_hex ... ok
test sync_cmd::tests::pull_refuses_another_profiles_snapshot ... ok
test sync_cmd::tests::push_seals_under_the_passphrase_even_with_a_cached_fleet_key ... ok
test sync_cmd::tests::pull_without_a_working_key_or_passphrase_asks_for_the_passphrase ... ok
test sync_cmd::tests::a_published_profile_never_takes_the_passphrase_path ... ok
test sync_cmd::tests::pull_does_not_try_a_key_from_a_grant_that_does_not_reverify ... ok
test sync_cmd::tests::push_refuses_an_empty_passphrase_even_with_a_cached_fleet_key ... ok
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 712 filtered out; finished in 5.15s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.03s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib credential::tests::a_key_round_trips_and_is_forgotten -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 1 test
test credential::tests::a_key_round_trips_and_is_forgotten ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 719 filtered out; finished in 0.02s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.07s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib credential::tests::references_are_separate_credentials -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 1 test
test credential::tests::references_are_separate_credentials ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 719 filtered out; finished in 0.00s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.56s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib credential::tests::a_namespace_keeps_one_devices_credentials_from_another -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 1 test
test credential::tests::a_namespace_keeps_one_devices_credentials_from_another ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 719 filtered out; finished in 0.00s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.60s
```

### `cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib credential::tests::a_failed_write_or_read_back_is_reported -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit code: 0.

```text
running 1 test
test credential::tests::a_failed_write_or_read_back_is_reported ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 719 filtered out; finished in 0.00s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.57s
```

### `CI=1 cargo test -j 4 --manifest-path server/Cargo.toml --test identity_authority a_symlinked_record_is_refused`

Exit code: 101.

```text
running 1 test
test a_symlinked_record_is_refused ... FAILED
thread 'a_symlinked_record_is_refused' (28020) panicked at tests\identity_authority.rs:216:9:
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 22 filtered out; finished in 0.58s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 39.30s
error: test failed, to rerun pass `--test identity_authority`
```

### `cargo test -j 4 --manifest-path shared/Cargo.toml --lib join_sas`

Exit code: 0.

```text
running 3 tests
test trust_chain::tests::join_sas_displays_eight_groups_of_four ... ok
test trust_chain::tests::join_sas_changes_with_every_input ... ok
test trust_chain::tests::join_sas_matches_an_independent_sha256 ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 303 filtered out; finished in 0.00s
    Finished `test` profile [unoptimized + debuginfo] target(s) in 32.38s
```

### Browser command

```text
node node_modules/@playwright/test/cli.js test tests/e2e/app.spec.ts --grep "custodian|fleet key|join code|join-code|revoke|reason list|connecting needs no token|first device|interrupted custody|round3|two devices" --workers 4 --reporter list
Exit code: 1
Running 15 tests using 4 workers
  ok  3 [chromium-desktop] › tests\e2e\app.spec.ts:254:1 › Team page warns about a custodian renewed after revocation (1.2s)
  ok  2 [chromium-desktop] › tests\e2e\app.spec.ts:843:1 › an expired join code offers Enroll again and a new code (2.1s)
  ok  5 [chromium-desktop] › tests\e2e\app.spec.ts:866:1 › an approved device whose join code expired can enroll again (3.6s)
  ok  1 [chromium-desktop] › tests\e2e\app.spec.ts:799:1 › a custodian revokes a device and the device can no longer pull (5.7s)
  ok  8 [chromium-desktop] › tests\e2e\app.spec.ts:958:1 › the reason list offers only Retired and Lost (837ms)
  ok  7 [chromium-desktop] › tests\e2e\app.spec.ts:931:1 › the custodian cannot approve a row it first saw more than ten minutes ago (2.1s)
  ok  9 [chromium-desktop] › tests\e2e\app.spec.ts:971:1 › approval stays disabled until the custodian creates its fleet key (720ms)
  ok 10 [chromium-desktop] › tests\e2e\app.spec.ts:981:1 › revoke stays disabled until the custodian creates its fleet key (600ms)
  ok 12 [chromium-desktop] › tests\e2e\app.spec.ts:1016:1 › connecting needs no token (609ms)
  ok 11 [chromium-desktop] › tests\e2e\app.spec.ts:990:1 › refreshed keys require a fresh join-code comparison (872ms)
  ok 14 [chromium-desktop] › tests\e2e\app.spec.ts:1057:1 › a fleet key Q-18 blocks is reported instead of the join steps (425ms)
  ok 13 [chromium-desktop] › tests\e2e\app.spec.ts:1033:1 › the first device sets up root custody once its passphrases agree (734ms)
  ok 15 [chromium-desktop] › tests\e2e\app.spec.ts:1064:1 › an interrupted custody setup resumes at its saved bundle without asking for a path (668ms)
  ok  4 [chromium-desktop] › tests\e2e\app.spec.ts:699:1 › two devices pass one team profile back and forth, then revert a revoked head to available (9.5s)
  x   6 [chromium-desktop] › tests\e2e\app.spec.ts:896:1 › round3 an active pinned device is not offered reenrollment after reopening Team (8.4s)
  1) [chromium-desktop] › tests\e2e\app.spec.ts:896:1 › round3 an active pinned device is not offered reenrollment after reopening Team 
    Error: expect(locator).toHaveCount(expected) failed
    Locator:  getByTestId('team-card').getByRole('button', { name: 'Enroll again', exact: true })
    Expected: 0
    Received: 1
        at C:\Users\User\dev\wt\shardbrowser-custodian-verify\tests\e2e\app.spec.ts:927:105
  1 failed
    [chromium-desktop] › tests\e2e\app.spec.ts:896:1 › round3 an active pinned device is not offered reenrollment after reopening Team 
  14 passed (30.1s)
```

### Browser command

```text
node node_modules/@playwright/test/cli.js test tests/e2e/app.spec.ts --grep "round3 a custodian with no usable key" --workers 1 --reporter list
Exit code: 1
Running 1 test using 1 worker
  x  1 [chromium-desktop] › tests\e2e\app.spec.ts:931:1 › round3 a custodian with no usable key is not shown Fleet key ready (6.3s)
  1) [chromium-desktop] › tests\e2e\app.spec.ts:931:1 › round3 a custodian with no usable key is not shown Fleet key ready 
    Error: expect(locator).toHaveCount(expected) failed
    Locator:  getByTestId('team-devices').getByText('Fleet key ready', { exact: true })
    Expected: 0
    Received: 1
        at C:\Users\User\dev\wt\shardbrowser-custodian-verify\tests\e2e\app.spec.ts:951:93
  1 failed
    [chromium-desktop] › tests\e2e\app.spec.ts:931:1 › round3 a custodian with no usable key is not shown Fleet key ready 
```

## New tests (complete bodies)

### `src-tauri/src/custodian_it.rs:511`

```rust
#[test]
fn round3_failed_setup_cleanup_leaves_no_usable_verified_key() {
    let rt = runtime();
    let h = custodian(15, "round3-cleanup", &rt);
    let c = crate::team_config::load().unwrap();
    let (signer, seed) = (c.signing_key().unwrap(), c.hpke_seed().unwrap());
    let device = crate::fleet_custody::FleetDevice {
        tenant_id: &c.tenant_id,
        device_id: &c.device_id,
        account_id: &c.account_id,
        signer: &signer,
        hpke_seed: &seed,
        vault: &crate::fleet_custody::CredentialFkekStore,
    };
    let root = crate::root_bootstrap::load().unwrap();
    // Model a crash after activation, before the first verified collect.
    with_session(&rt, &h, async |client, access| {
        let mut state = crate::fleet_custody::load().unwrap();
        crate::fleet_custody::bootstrap_fleet(
            client,
            access,
            &device,
            &root,
            &mut state,
            &mut |s| crate::fleet_custody::save(s),
        )
        .await
        .unwrap();
    });
    assert!(!crate::team_config::status().unwrap().has_fleet_key);
    let state = crate::fleet_custody::load().unwrap();
    let reference = format!(
        "fleet-setup.{}.{}",
        h.tenant.to_ascii_lowercase(),
        state.fkek_nonce
    );
    crate::credential::fail_next_call(&reference);
    let result = call(
        &rt,
        crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()),
    );
    assert!(result.is_err(), "the cleanup failure must reach the caller");
    assert!(crate::fleet_custody::status().unwrap().setup_key_held);
    assert!(
        !crate::team_config::status().unwrap().has_fleet_key,
        "a failed setup left a verified key usable for sealing"
    );
}
```

### `src-tauri/src/fleet_custody.rs:2111`

```rust
#[test]
    fn round3_a_successful_device_listing_does_not_echo_its_access_token_to_ipc() {
        let f = fixture();
        let rt = runtime();
        let access = format!("v2a.{}", "6f".repeat(32));
        let (mut row, _) = joiner();
        // A hostile server knows the bearer it just received. Return it in
        // the label encoding the client decodes before forming its IPC reply.
        row.label_hex = hex(access.as_bytes());
        let body = serde_json::to_vec(&serde_json::json!({ "devices": [{
            "device_id": row.device_id, "account_id": row.account_id,
            "status": row.status, "label_hex": row.label_hex,
            "signing_key_id": row.signing_key_id, "hpke_key_id": row.hpke_key_id,
            "signing_public_key": row.signing_public_key,
            "hpke_public_key": row.hpke_public_key,
        }] }))
        .unwrap();
        let (client, _) = rt.block_on(mock(Arc::new(move |call, _| {
            assert!(call.ends_with("/devices"));
            (200, body.clone())
        })));
        let rows = rt
            .block_on(client.list_tenant_devices(&access, &f.tenant))
            .unwrap();
        let mut state = f.state();
        let listed = see_devices(&rows, &f.pin(), now_ms(), &mut state, &mut |_| Ok(())).unwrap();
        let reply = serde_json::to_string(&listed).unwrap();
        assert!(
            !reply.contains(&access),
            "the device-list IPC reply leaked the access token"
        );
    }
```

### `tests/e2e/app.spec.ts:896`

```typescript
test("round3 an active pinned device is not offered reenrollment after reopening Team", async ({ page: a, browser, baseURL, viewport }) => {
  const server = fakeTeamServer();
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  try {
    await teamDevicePage(a, "a", server);
    await teamDevicePage(b, "b", server, true);
    await cardClick(a, "Create fleet key");
    await teamEnroll(b, "Round3 B");
    await cardClick(b, "Show join code");
    const row = await listDevices(a, "Round3 B");
    await row.getByLabel("The code on the other device matches").check();
    await cardSignIn(a);
    await row.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(row).toContainText("Active");
    await cardClick(b, "Codes match");
    await expect(b.getByTestId("team-join")).toContainText("Codes confirmed.");
    // No collect yet. Remounting loses component state but preserves the pin.
    await b.getByRole("button", { name: "Settings", exact: true }).click();
    await b.clock.fastForward("10:01");
    await b.getByRole("button", { name: "Team", exact: true }).click();
    await cardClick(b, "Show join code");
    await expect(b.getByTestId("team-join")).toContainText("This join code has expired.");
    // Prove the actual mock command models the backend's refusal for this state.
    const rejected = await b.evaluate(async () => {
      const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (cmd: string, args: object) => Promise<unknown> } }).__TAURI_INTERNALS__;
      try {
        await ipc.invoke("team_enroll_again", { username: "owner", password: "pw" });
        return false;
      } catch (e) { return String(e).includes("fleet.enrollAgainRefused"); }
    });
    expect(rejected).toBe(true);
    await expect(b.getByTestId("team-card").getByRole("button", { name: "Enroll again", exact: true })).toHaveCount(0);
  } finally { await b.context().close(); }
});
```

### `tests/e2e/app.spec.ts:931`

```typescript
test("round3 a custodian with no usable key is not shown Fleet key ready", async ({ page: a }) => {
  const server = fakeTeamServer();
  await teamDevicePage(a, "a", server);
  await cardClick(a, "Create fleet key");
  await expect(a.getByTestId("team-devices").getByText("Fleet key ready", { exact: true })).toBeVisible();
  // Model the real backend's tested lost-key state: the setup journal stays
  // created/released, while team_status reports no key usable for sealing.
  await a.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      const result = await original(...args);
      return args[0] === "team_status"
        ? { ...(result as object), has_fleet_key: false, fleet_key_blocked: false }
        : result;
    };
  });
  await a.getByRole("button", { name: "Settings", exact: true }).click();
  await a.getByRole("button", { name: "Team", exact: true }).click();
  await expect(a.getByTestId("team-devices")).toBeVisible();
  await expect(a.getByTestId("team-devices").getByText("Fleet key ready", { exact: true })).toHaveCount(0);
});
```

VERDICT: FAIL
