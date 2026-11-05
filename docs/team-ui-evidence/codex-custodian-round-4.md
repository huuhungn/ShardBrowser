# Independent custodian verification — round 4

Verified HEAD: `de6545dbb40eddfbfa6af117b18b8d1adf2f2a68`.

Base for implementation comparison: `f5552844`. Verification date: 2026-11-05 UTC (2026-11-06 Asia/Bangkok at completion). Platform: Windows, PowerShell. The worktree was clean at the start. Production implementation was not changed; the working copy now includes five independent regression tests and a local-only Playwright configuration.

The result is FAIL. Five regression tests fail for four distinct implementation problems: unstructured revocation-error matching (two failures), an access-token body exposed in an IPC error, account-scoped legacy access to a different device's root grants, and a reenrollment action offered to an active pinned device after local expiry.

## Scope and method

Authority was the requested portions of ADR 0002, ADR 0004's key-storage decision, and the shipped model and limitations in `docs/key-custody.md`. I did not open the prior verification reports, authors' plans, `.omc/`, `.omx/`, or scratch directories. A session-start memory digest was supplied automatically; I did not expand it or use it as verification evidence. The required context-resume call returned only the current task title.

The applicable evidence-gate-verification skill supplied the assertion-sensitivity check and the requirement to retain actual exit statuses. Existing repository fixtures were reused for every added probe; no feature was built and no prior-art/network survey was needed.

Contract elements checked:

- Q-12: SAS binds instance, tenant, anchor, signing-key ID and HPKE-key ID; 16 bytes; eight groups of four hex characters; local ten-minute comparison windows; pin only after comparison.
- D-2: root-custodian issuance and explicit device capabilities; approval and key-grant subjects name the exact device and key IDs.
- D-5: the recovery wrap binds fleet/generation/FKEK ID and recipient root ID/generation and unwraps to the same FKEK.
- D-9: create, device/recovery grant filing, both acknowledgements, activation, exact saved mutation requests and response matching. Bootstrap commits to one required device grant and the recovery-grant hash.
- Q-13/C-1: filed revocation is permanent, cuts sessions/leases/grants immediately, and does not recall copied keys. Retired/lost rotation is advisory. Q-18 blocks commits on counted compromise exposure. Rule 6 also quarantines a previously pinned head once its signer is proven revoked.
- ADR 0004: secret storage uses credentials with read-back verification, with the documented fallback behavior. Temporary fleet/root setup state contains credential references and sealed records, not clear keys.

All Cargo dependency resolution and npm dependency installation were offline. HTTP test servers bound to loopback. The browser test configuration routes non-loopback browser requests to a closed loopback proxy. No commit, push, PR, or issue was created. The real OS credential-store test was excluded from every launcher invocation; no application command was run against `%APPDATA%\shardx-launcher`.

Execution caveat: a long context-mode invocation timed out after 300 seconds before returning the `team::sync` result. I reran that suite with ordinary process capture and obtained its complete result. The mandated context-mode diagnostic reported an available npm release; this diagnostic is outside the intended repository/test-only workflow, so I do not claim independently proven network isolation for that diagnostic. No upgrade or issue command was run.

## Execution ledger

Every launcher command used this exact form, with the filter in the table:

```text
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib <filter> -- --skip a_real_os_store_key_survives_into_a_fresh_process
```

The server was built before `custodian_it`:

```text
cargo build -j 4 --manifest-path server/Cargo.toml
Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 53s
exit 0
```

| Run | Actual result | Exit |
| --- | --- | --- |
| Server `cargo test -j 4 --manifest-path server/Cargo.toml --test v2_auth`, HEAD tests | 82 passed; 0 failed; 0 ignored; first run 85.56s, captured repeat 68.29s | 0 |
| Server `--test identity_authority` | 23 passed; 0 failed; 0 ignored; 6.40s; symlink subcase caveat below | 0 |
| Launcher `fleet_custody`, original tests | 34 passed; 0 failed; 0 ignored; 1.20s | 0 |
| Launcher `fleet_custody`, after the first two probes | 34 passed; 2 failed; 0 ignored; 1.39s | 101 |
| Launcher `fleet_client` | 19 passed; 0 failed; 0 ignored; 0.04s | 0 |
| Launcher `root_bootstrap` | 31 passed; 0 failed; 0 ignored; 18.74s | 0 |
| Launcher `custody_tests` | 45 passed; 0 failed; 0 ignored; 8.48s | 0 |
| Launcher `team::ledger` | 7 passed; 0 failed; 0 ignored; 0.48s | 0 |
| Launcher `team::sync`, completed rerun | 200 passed; 0 failed; 0 ignored; 481.99s | 0 |
| Launcher `team_config` | 12 passed; 0 failed; 0 ignored; 0.04s | 0 |
| Launcher `credential::tests` | 6 passed; 0 failed; 4 ignored child helpers; 12.06s | 0 |
| Launcher `custodian_it` | 8 passed; 0 failed; 1 ignored child helper; 149.41s | 0 |
| Shared `cargo test -j 4 --manifest-path shared/Cargo.toml join_sas` | 3 passed; 0 failed; 0 ignored | 0 |
| Shared `cargo test -j 4 --manifest-path shared/Cargo.toml authz_record` | 24 passed; 0 failed; 0 ignored | 0 |
| Existing relevant Chromium E2E tests | 17 passed; 34.8s | 0 |
| Launcher `round4_`, all three new Rust probes | 0 passed; 3 failed; 0 ignored; 0.12s | 101 |
| Server `--test v2_auth round4_`, new root-read probe | 0 passed; 1 failed; 0 ignored; 3.21s | 101 |
| Chromium `--grep round4`, new UI probe | 1 failed; expected 0 reenrollment buttons, received 1 | 1 |

The completed launcher suite outputs are in `round-4-test-runs.json`, `round-4-sync.log`, `round-4-team_config.log`, `round-4-credential-tests.log`, and `round-4-custodian_it.log`, beside this report. Shared outputs are in `round-4-shared-runs.json`. Server outputs are in `round-4-server-auth.log` and `round-4-server-probe.log`. New negative results are in `round-4-round4_.log` and `round-4-ui-probe.log`. These logs contain test names, statuses and failure descriptions; no session-token value was found in the evidence-file scan.

Browser commands:

```text
npm ci --offline --ignore-scripts --no-audit --no-fund
npm ci --prefix ui-kit --offline --ignore-scripts --no-audit --no-fund
npm --prefix ui-kit run build:lib
npm run test:e2e -- --config playwright.round4.config.ts --grep 'two devices pass|custodian|join code|approved device|active pinned|reason list|approval stays|revoke stays|refreshed keys|connecting needs|first device sets|fleet key Q-18|interrupted custody'
npm run test:e2e -- --config playwright.round4.config.ts --grep round4
```

## Goal 1 — HOLDS

Enforcement: `src-tauri/src/fleet_custody.rs:768` derives both IDs from the listed public keys; `:782` checks those IDs before a new approval; `:856` constructs the grant subject; `:868` seals to the validated listed HPKE public key. The IPC path at `src-tauri/src/lib.rs:2664` rereads the device list, and `:2691` enters that path. Server `server/src/routes/v2_approval.rs:998` independently derives the device-row IDs and compares them to both the row and signed approval. `server/src/routes/v2_fleet.rs:893` checks the grant's exact live subject and key IDs.

Read and ran:

```text
fleet_custody::tests::approval_is_refused_when_a_listed_key_does_not_hash_to_its_id ... ok
fleet_custody::tests::the_member_grant_is_sealed_to_the_listed_hpke_key_and_opens_with_it ... ok
fleet_custody::tests::a_device_row_with_a_bad_key_id_is_refused_before_anything_is_saved ... ok
a_custodian_approves_a_second_device_into_an_ordinary_session ... ok
a_custodian_creates_fleet_generations_and_files_their_grants ... ok
```

The grant test at `fleet_custody.rs:2328` parses and verifies the signature, opens with the intended HPKE secret, rejects a different HPKE secret, and checks the account/device/key IDs, fleet/generation/FKEK commitment and all three capability subjects. The mismatch test at `:2083` checks the refusal and that no approval was posted. No additional gap requiring a new probe was found here.

## Goal 2 — HOLDS

Enforcement: `fleet_custody.rs:697` durably records the first sight of a pending device and each key ID; `:755` takes the earliest of row/key sightings. `:790` checks ten minutes, `:793` compares the supplied code, and `:943` checks time again after the active-generation read. A row-ID change or key swap therefore does not restart an already-seen key's window. `lib.rs:2157` records enrollment on the local clock; `:2781` bounds the joiner's window; `:2942` and `:2955` check before and after network reads. Shared `trust_chain.rs:675` binds all five SAS inputs.

Read and ran:

```text
the_custodian_window_starts_when_it_first_sees_the_row_and_never_resets ... ok
approval_is_refused_ten_minutes_after_first_sight ... ok
approval_is_refused_when_the_confirmed_code_differs ... ok
a_new_row_id_for_the_same_keys_keeps_the_first_sight_window ... ok
keys_moved_onto_a_row_seen_later_keep_their_first_sight_window ... ok
keys_first_seen_after_a_swap_start_their_window_then ... ok
an_approval_is_not_signed_once_the_window_closes_during_the_generation_read ... ok
the_join_code_expires_ten_minutes_after_this_device_enrolled ... ok
a_late_join_confirm_is_refused_even_after_approval ... ok
join_sas_matches_an_independent_sha256 ... ok
join_sas_changes_with_every_input ... ok
join_sas_displays_eight_groups_of_four ... ok
```

The Chromium ten-minute test and fresh-key-comparison test also passed. `TeamDevices.tsx:64` keys the comparison checkbox by device ID plus SAS, so refreshed keys require a new comparison.

Precision of this result: the comparison/signing window gates **new authorization**. `fleet_custody.rs:931` deliberately replays an already saved, previously confirmed approval after the window, without signing a fresh approval. The test `a_saved_approval_is_resent_after_the_window_closes` verifies byte identity. This is consistent with the saved-valid-request retry requirement in goal 5; it is not a claim that the server's eventual filing time must be within ten minutes. No proof of a human actually comparing two displays is possible from a boolean UI action; the enforced boundary is an explicit matching-code confirmation.

## Goal 3 — HOLDS

Enforcement: `lib.rs:2794` evaluates the evidence anchor; `:2884` compares the displayed anchor and recomputes SAS over the evaluated binding and local keys. `team/ledger.rs:107` inserts a pin with `ON CONFLICT DO NOTHING`, then checks the existing anchor; source and earlier pin are retained. `:127` returns a tenant pin only when the tenant has exactly one binding. `lib.rs:3200` uses that pinned state for later grant verification.

Read and ran:

```text
custody_tests::a_join_confirm_is_refused_when_the_server_instance_changed ... ok
custody_tests::a_join_confirm_is_refused_for_another_tenant_than_the_one_shown ... ok
custody_tests::a_join_pin_is_refused_for_another_anchor_than_the_one_shown ... ok
custody_tests::a_joined_device_reads_its_anchor_from_the_join_pin ... ok
team::ledger::tests::a_join_pin_never_replaces_an_earlier_pin ... ok
```

These are substantive negative pin assertions, not only SAS string comparisons. The ledger test checks the retained anchor and original `BOOTSTRAP` source after rejected replacement and repeated JOIN. The real-server two-device journey also passed.

## Goal 4 — VIOLATED

The server cutoff holds in the exercised paths. `v2_device_revoke.rs:554` takes a write transaction and reloads the issuer session; `:632` checks an unfiled record's filing window; `:732` inserts the revocation and calls `revoke_everything`. `:489` changes the device status, `:495` invalidates approvals/capabilities/root/fleet grants, `:515` removes profile leases and `:529` ends sessions. `v2_auth.rs:363` checks live device state, `:421` reloads that state, and `:1445` repeats it for refresh. `v2_fleet.rs:893` denies new fleet grants to revoked subjects. The filed response is replayed before the unfiled-window check at `v2_device_revoke.rs:559`.

Read and ran:

```text
a_revoked_device_cannot_sign_in_again ... ok
a_revocation_blocks_new_capabilities_and_inflight_session_proofs ... ok
a_revocation_commits_its_fleet_activation_or_nothing ... ok
a_revocation_commits_its_root_activation ... ok
fleet_custody::tests::a_resumed_revocation_resends_the_same_bytes ... ok
fleet_custody::tests::a_stale_unfiled_revocation_is_rebuilt ... ok
custodian_it::a_revoked_device_is_cut_off_but_keeps_the_key_it_already_holds_against_a_real_server ... ok
```

The real-server test proves cutoff and separately proves that copied generation-0 keys still decrypt leaked ciphertext, as the contract explicitly permits. Sticky withdrawal and the already-pinned-head rule also passed in `team::ledger`, `custody_tests` and `team::sync`, including `a_pinned_head_of_a_since_revoked_signer_is_not_restored` and `an_ordinary_push_refuses_over_a_pinned_head_whose_signer_is_proven_revoked`.

**Defect R4-1a, medium — stale revocation recovery depends on JSON whitespace.** At `fleet_custody.rs:1127`, retry classification searches the rendered error string for the literal substring `"code":"REVOCATION_OUTSIDE_WINDOW"`, rather than parsing the top-level code. After a first send fails, a later HTTP 403 containing the same legitimate code as formatted JSON (`"code": "REVOCATION_OUTSIDE_WINDOW"`) never rebuilds the stale unfiled request. Repeated retries keep sending the expired bytes; the launcher provides no recovery for this response shape. A proxy that reserializes the otherwise identical JSON is sufficient. The shipped server currently emits compact JSON, so the direct-server happy retry test does not expose this interoperability defect.

New probe: `fleet_custody.rs:2867`, `round4_formatted_window_error_recovers_a_stale_unfiled_revocation`.

```text
... FAILED
equivalent JSON whitespace stranded the expired unfiled revocation
exit 101
```

## Goal 5 — VIOLATED

The fleet setup crash/retry path itself held. `fleet_custody.rs:175` saves a nonce before storing the FKEK, reuses a held key, and refuses regeneration once an ID exists. `:267` constructs the device/recovery grants and the six lifecycle requests. `:383` saves them together before any lifecycle request is sent. `:494` reuses them; `:506`, `:526`, `:546` and `:565` validate the exact stored response and expected terms. `lib.rs:2559` releases the setup credential before verified collect, and `:3142` verifies before keeping the key. The status/config path never treats the temporary setup credential as a verified fleet key.

Read and ran:

```text
the_fleet_key_is_held_before_any_request_names_it ... ok
a_crash_between_holding_and_saving_the_fleet_key_reuses_the_held_key ... ok
a_missing_or_locked_setup_key_after_its_id_is_saved_stops_and_never_regenerates ... ok
a_resumed_setup_resends_the_saved_bytes_and_never_makes_a_second_fleet_key ... ok
the_create_request_commits_to_the_one_device_grant_and_the_recovery_grant ... ok
the_recovery_grant_opens_to_the_fleet_key_and_runs_ten_years ... ok
a_failed_setup_leaves_no_verified_key ... ok
custodian_it::a_fleet_setup_resumes_after_a_failed_save_and_a_replayed_run_against_the_real_server ... ok
custodian_it::a_setup_whose_cleanup_fails_leaves_no_usable_verified_key ... ok
custodian_it::a_setup_does_not_ack_again_after_its_acked_receipt ... ok
every_custody_operation_replays_its_lost_response_after_a_restart ... ok
```

The generation-create test checks the committed required set and recovery hash, and the recovery test opens the wrap to the same FKEK. The real-server crash test checks one generation, unchanged key commitment and no extra mutation audit rows after replay. The cleanup-failure test checks `has_fleet_key == false` before the successful retry.

**Defect R4-1b, medium — a nested diagnostic code replaces valid saved bytes.** The same substring classifier at `fleet_custody.rs:1127` treats this response as the window error:

```json
{"code":"FORBIDDEN","context":{"code":"REVOCATION_OUTSIDE_WINDOW"}}
```

One second after the first failed send, the saved revocation is still valid. A retry receiving this response rebuilds and saves a different signed record and idempotency request anyway. This violates the goal's final exact-retry requirement, although it does not generate a second FKEK. The existing generic-403 test uses an empty body and misses this case.

New probe: `fleet_custody.rs:2810`, `round4_nested_error_code_does_not_replace_a_valid_saved_revocation`.

```text
... FAILED
a nested context code replaced a still-valid saved revocation
exit 101
```

## Goal 6 — VIOLATED

Enforcement that held: `credential.rs:79` uses local credential persistence and `:106` reads the key back; `root_bootstrap.rs:485` stores the temporary TRK; `fleet_custody.rs:175` stores the temporary FKEK. `FleetCustodyState` at `:83` carries references and signed/sealed requests, and its Debug implementation at `:134` omits them. `fleet_client.rs:113` redacts session Debug output, `:234` scrubs tokens, and `:349` retains only a constrained code on login failure. `lib.rs:3470` returns root/fleet counts, never the unwrapped keys. A join code is intentionally returned to the UI, but must not appear in logs.

Read and ran:

```text
the_saved_state_and_its_debug_output_hold_no_key ... ok
a_session_debug_print_hides_its_tokens ... ok
a_login_error_hides_the_echoed_password ... ok
a_login_error_hides_a_password_echoed_with_json_escapes ... ok
a_login_error_hides_a_non_ascii_password_echoed_as_ascii_escapes ... ok
a_login_error_hides_a_password_echoed_with_an_escaped_slash ... ok
a_successful_device_listing_does_not_echo_its_access_token_to_ipc ... ok
a_device_label_holding_the_token_body_is_not_echoed_to_ipc ... ok
custodian_it::the_journey_leaks_no_secret_to_output_state_or_replies ... ok
```

The journey scan actually runs the ignored worker in a child process and requires `1 passed`; it requires eight secret values to be scanned, checks expected state files/replies exist, checks session-token forms, and separately checks displayed join codes against stdout/stderr. Its clean result is useful evidence for that journey, not a complete hostile-response proof.

**Defect R4-2, high — failed device listing leaks a usable access-token body through IPC.** `fleet_client.rs:698` calls `ok_or_err`, which at `:293` passes an empty secret list to the redactor. The success path at `:720` does pass the access token. A server/proxy can return HTTP 403 whose `error` is the exact 64-hex access-token body without the `v2a.` prefix. This is not an unusual encoding: it is the bearer body the existing success-path redactor explicitly recognizes. The marker-only refusal redactor leaves it intact, and `lib.rs:2621` returns that error string to IPC. Prepending `v2a.` reconstructs the usable credential. No actual credential is printed in this report or by the probe.

New probe: `fleet_custody.rs:2843`, `round4_refused_device_listing_hides_the_access_token_body`.

```text
... FAILED
the error returned to IPC contains the bearer token body
exit 101
```

The same empty-secret helper is also used by `fleet_client.rs:521` for custody POST refusals; the new executable proof covers device listing specifically. The documented limit for arbitrary server-selected encodings does not excuse omission of the already supported exact token-body redaction.

## Goal 7 — HOLDS

Enforcement: `lib.rs:2721` parses the reason before configuration/session work, through `fleet_custody.rs:1041`, which accepts only `retired` and `lost`. `fleet_custody.rs:1064` rejects the custodian's own ID case-insensitively before saving/sending. UI `TeamDevices.tsx:162` identifies self; its action controls and two-option reason list agree with these restrictions.

Read and ran:

```text
fleet_custody::tests::only_retired_and_lost_are_accepted ... ok
fleet_custody::tests::a_custodian_does_not_revoke_itself ... ok
the reason list offers only Retired and Lost ... passed
revoke stays disabled until the custodian creates its fleet key ... passed
```

The reason test checks six unsupported strings and the actual IPC command. The self-revocation test covers both offered reasons and uppercase self ID, verifies no request occurred and no revocation was saved. Shared parsing accepts additional protocol reasons, which does not widen the launcher's command boundary.

## Goal 8 — HOLDS

Enforcement: `server/src/routes/v2_approval.rs:1066` accepts only a device-session principal, reloads it at `:1081`, compares the requested tenant at `:1084`, and requires active root custody at `:1091`. The SELECT at `:1097` includes the tenant predicate. `v2_auth.rs:461` rejects missing/invalid bearers before the handler.

Read and ran:

```text
a_custodian_lists_the_tenant_devices_with_their_public_keys ... ok
only_an_active_custodian_session_lists_the_tenant_devices ... ok
```

Tests are at current working-copy `server/tests/v2_auth.rs:11222` and `:11273` (HEAD line numbers were 11171 and 11222). They verify row keys and tenant isolation; ticket, pending session, ordinary session, other tenant and absent-token failures; and a positive custodian read. All 82 original server tests passed. No extra probe was needed for this boundary.

## Goal 9 — VIOLATED under the stated device-isolation goal

V2 enforcement holds: `server/src/routes/v2.rs:774` compares the session device to the requested device, and `:264` checks its tenant. However, the v1 branch at `:761` only checks that the target device belongs to the v1 user's mapped account. It has no device identity or proof-of-possession requirement. Thus the absolute goal “read another device's root grants” is stronger than the implemented compatibility policy.

Read and ran:

```text
a_device_session_reads_the_active_fleet_generation_and_its_own_root_grants ... ok
a_v1_member_cannot_read_another_accounts_root_grants ... ok
```

**Defect R4-3, medium — legacy bearer bypasses device-level root-grant read isolation within one account.** A pending peer device under the same owner account gets HTTP 403 with its own v2 device session when requesting the custodian's root grants. A legacy v1 bearer mapped to that owner account requests the same URL and receives HTTP 200 with one grant, without proving possession of the custodian device's keys. This is disclosure of sealed root-grant records, not decryption or disclosure of the TRK. The explicit compatibility branch and its positive existing test suggest this behavior is intentional; it still violates goal 9 as written. Cross-account and cross-tenant reads remain denied.

New probe at `server/tests/v2_auth.rs:10989`, `round4_same_account_v1_token_does_not_bypass_device_root_grant_isolation`. It checks the own-device positive read and peer-session denial before the legacy-bearer assertion.

```text
... FAILED
an account-only v1 bearer bypassed device isolation: HTTP 200, 1 grants
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 82 filtered out
exit 101
```

If the intended contract explicitly permits account-wide v1 readback, that exception should be added to this goal; the stronger device-only assertion should not be reported as holding.

## Goal 10 — HOLDS

Enforcement: only server identity (`v2.rs:115`), active fleet generation (`:881`) and root-grant readback (`:751`) changed from `AuthUser` to `Caller`. `v2_auth.rs:522` dispatches valid ticket/access forms to the v2 principal extractor and all other cases to the original `AuthUser` extractor. `server/src/auth.rs:132` still demands and validates the v1 bearer. Other previously guarded handlers keep that extractor. The new device-list route at `routes/mod.rs:218` uses the separate custodian guard, and trust evidence was already device-session authenticated.

Read and ran:

```text
the_legacy_guarded_routes_still_require_v1_auth ... ok
server_identity_answers_a_ticket_and_a_session_without_a_v1_token ... ok
a_device_session_reads_the_active_fleet_generation_and_its_own_root_grants ... ok
```

The route matrix (`server/tests/v2_auth.rs:11079`, HEAD 11028) tests both no bearer and a pending v2 access bearer across the formerly v1-only route set and checks HTTP 401, then checks that the three shared reads also deny an absent bearer. The root-grant ownership exception in goal 9 requires a valid legacy token and does not open any route without authentication. A pre-device ticket is permitted for server identity only; this is authenticated identity discovery, not a tokenless route.

## Goal 11 — VIOLATED

The key-status half held for the tested key/trust conditions. `team_config.rs:320` calls `sync_cmd.rs:469`, which reaches `team/sync.rs:1633`; that reads the highest verified generation, calls the same `verified_key`/`readable_key` functions used for sealing and checks `ledger::commit_blocked`. `TeamCard.tsx:462` distinguishes usable key from Q-18 blocked key, and `TeamDevices.tsx:61` also requires live key status before declaring setup ready or approving a member.

Read and ran:

```text
team::sync::tests::key_status_and_push_agree_after_the_fleet_key_is_lost ... ok
team::sync::tests::key_status_agrees_with_a_compromise_blocked_push ... ok
team_config::tests::a_legacy_cached_fleet_key_alone_is_not_a_fleet_key ... ok
a custodian with no usable key is not shown Fleet key ready ... passed
a custodian whose fleet key is blocked is shown the Q-18 notice ... passed
a fleet key Q-18 blocks is reported instead of the join steps ... passed
an active pinned device is not offered reenrollment after reopening Team ... passed
```

These checks establish key usability under locally verified evidence, not a promise that every future network request succeeds.

**Defect R4-4, medium — local expiry offers reenrollment to an active pinned device.** `TeamJoin.tsx:29` initializes `pinned` to false on each mount. An approved device confirms its code, navigates away before collecting, returns before the deadline, and clicks Show join code while the window is still open. The backend returns a valid code but no persisted-pin flag. When the component's local timer later expires (`:36`), `refusal` is still null, so `:115` renders Enroll again. The real backend always rejects this state through `lib.rs:2997`/`:3010`. The old UI test waits until after expiry before asking for a code, so it exercises the backend's expired-code classification and misses this order of events.

New probe at `tests/e2e/app.spec.ts:931`, `round4 active pinned device is not offered reenrollment when a remounted code expires`. It proves the active/pinned state, verifies that the mock backend rejects reenrollment in that same state (consistent with the independently run backend tests), then checks the visible button count.

```text
Error: expect(locator).toHaveCount(expected) failed
Expected: 0
Received: 1
1 failed
exit 1
```

## Test-integrity findings

The original 82 `v2_auth` tests, 34 `fleet_custody` tests, 19 client tests, 31 root-bootstrap tests, 45 custody tests, 7 ledger tests, 200 sync tests, 12 team-config tests and three SAS tests contain active assertions and are not ignored. Tests that delegate to helpers were traced: the two-device integration journey asserts key equality and profile transfers in `shared_profile`; the four sync wrappers delegate to helpers that assert quarantine, no skip, retained local content and removed staging.

Exceptions are recorded explicitly:

- `custodian_it.rs:1467` marks the leak-scan worker ignored for ordinary discovery. Its non-ignored parent at `:1346` invokes it with `--exact ... --ignored --nocapture` and asserts both child exit success and `1 passed`. This worker actually ran; the parent passed. It is not missing leak coverage disguised by an ignored test.
- Four credential child workers are ignored at top-level discovery. The two key-file parent tests run their applicable child workers and passed. The real-credential-store child was not invoked. The explicitly forbidden `a_real_os_store_key_survives_into_a_fresh_process` was skipped throughout.
- `server/tests/identity_authority.rs:213` has an early return after a Windows symlink creation failure. A focused `--nocapture` rerun confirmed `os error 1314` and that this branch returned. The preceding non-regular-directory rejection assertions ran, but the true symlink rejection did not. This is a test-coverage limitation outside the eleven custodian attack boundaries, and the suite's 23-pass summary must not be read as proof of that symlink subcase. See `round-4-symlink.log`.
- No empty assertions, ignored new probes, or early-success exits were added. The new UI probe's `return false` is inside the backend-refusal observation and is followed by `expect(rejected).toBe(true)`.

A bounded assertion-sensitivity check changed only the expected `BadValue` field in `shared/src/authz_record.rs:2334`. The named test failed with exit 101; restoring the exact original bytes made it pass with exit 0. The restored file SHA-256 is `c166a2709a2db057522a383e444c21fc1bd517b53b6d0d4cd3894b2a433459a7`. See `round-4-mutation-check.json`. No production mutation remains.

## Added probe code

The following source is copied from the working-copy tests; it changes no production behavior. Fixtures and helpers are those already in the repository. Assertion messages deliberately omit credential and key bytes.

### round4_nested_error_code_does_not_replace_a_valid_saved_revocation

`src-tauri/src/fleet_custody.rs`

```rust
#[test]
    fn round4_nested_error_code_does_not_replace_a_valid_saved_revocation() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (mut row, _) = joiner();
        row.status = "active".into();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(Arc::new(|_, _| {
            (
                403,
                br#"{"code":"FORBIDDEN","context":{"code":"REVOCATION_OUTSIDE_WINDOW"}}"#.to_vec(),
            )
        })));
        let t0 = now_ms();
        revoke(&rt, &f, &client, &row, DeviceRevocationReason::Retired, t0);
        let saved = load().unwrap().revocations[&row.device_id].clone();
        assert_eq!(sent(&seen).len(), 1);
        revoke(
            &rt,
            &f,
            &client,
            &row,
            DeviceRevocationReason::Retired,
            t0 + 1_000,
        );
        assert!(
            sent(&seen)
                .iter()
                .all(|(_, body)| body == &unhex_vec(&saved).unwrap()),
            "a nested context code replaced a still-valid saved revocation"
        );
    }
```

### round4_refused_device_listing_hides_the_access_token_body

`src-tauri/src/fleet_custody.rs`

```rust
#[test]
    fn round4_refused_device_listing_hides_the_access_token_body() {
        let f = fixture();
        let rt = runtime();
        let token_body = "9c".repeat(32);
        let access = format!("v2a.{token_body}");
        let echoed = token_body.clone();
        let (client, _) = rt.block_on(mock(Arc::new(move |_, _| {
            (
                403,
                serde_json::to_vec(&serde_json::json!({"error": echoed})).unwrap(),
            )
        })));
        let error = rt
            .block_on(client.list_tenant_devices(&access, &f.tenant))
            .unwrap_err()
            .to_string();
        assert!(error.contains("fleet.refusedCustody|status=403|"));
        assert!(
            !error.to_ascii_lowercase().contains(&token_body),
            "the error returned to IPC contains the bearer token body"
        );
    }
```

### round4_formatted_window_error_recovers_a_stale_unfiled_revocation

`src-tauri/src/fleet_custody.rs`

```rust
#[test]
    fn round4_formatted_window_error_recovers_a_stale_unfiled_revocation() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (mut row, _) = joiner();
        row.status = "active".into();
        let rt = runtime();
        let (offline, _) = rt.block_on(mock(refuse_all()));
        let t0 = now_ms();
        revoke(&rt, &f, &offline, &row, DeviceRevocationReason::Retired, t0);
        let saved = load().unwrap().revocations[&row.device_id].clone();
        let body = serde_json::to_vec_pretty(&serde_json::json!({
            "code": "REVOCATION_OUTSIDE_WINDOW", "error": "window"
        }))
        .unwrap();
        let (client, seen) = rt.block_on(mock(Arc::new(move |_, _| (403, body.clone()))));
        let error = revoke(
            &rt,
            &f,
            &client,
            &row,
            DeviceRevocationReason::Retired,
            t0 + 10 * MINUTE,
        );
        assert!(error.contains("fleet.refusedCustody|status=403|"));
        assert!(
            load().unwrap().revocations[&row.device_id] != saved,
            "equivalent JSON whitespace stranded the expired unfiled revocation"
        );
        assert_eq!(
            sent(&seen).len(),
            2,
            "retry the saved bytes then the rebuilt request"
        );
    }
```

### round4_same_account_v1_token_does_not_bypass_device_root_grant_isolation

`server/tests/v2_auth.rs`

```rust
#[tokio::test]
async fn round4_same_account_v1_token_does_not_bypass_device_root_grant_isolation() {
    let mut server = start("round4-root-device", 28461).await;
    let (owner_device, owner_access, _) = custodian(&mut server, 0x6c).await;
    let peer = device(&server, OWNER, 0x7d, "pending").await;
    let peer_session = session(&server, &peer).await;
    let path = format!(
        "/v2/tenants/{}/devices/{}/root-key-grants",
        hex(&TENANT),
        hex(&owner_device.id)
    );
    let (status, body) = server.call(&path, &owner_access, None).await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["grants"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        server
            .call(&path, peer_session["access_token"].as_str().unwrap(), None)
            .await
            .0,
        403
    );
    let (_, login) = server
        .post(
            "/auth/login",
            None,
            json!({"username":"admin", "password":"secret"}),
        )
        .await;
    server.sql(
        "UPDATE v2_accounts SET legacy_user_id = (SELECT id FROM users WHERE username = 'admin') WHERE id = ?",
        &[&OWNER]
    ).await;
    let (status, body) = server
        .call(&path, login["token"].as_str().unwrap(), None)
        .await;
    let returned = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v["grants"].as_array().map(Vec::len))
        .unwrap_or(0);
    assert!(
        status == 403 && returned == 0,
        "an account-only v1 bearer bypassed device isolation: HTTP {status}, {returned} grants"
    );
}
```

### UI local-expiry probe

`tests/e2e/app.spec.ts`

```typescript
test("round4 active pinned device is not offered reenrollment when a remounted code expires", async ({ page: a, browser, baseURL, viewport }) => {
  const server = fakeTeamServer();
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  try {
    await teamDevicePage(a, "a", server);
    await teamDevicePage(b, "b", server, true);
    await cardClick(a, "Create fleet key");
    await teamEnroll(b, "Pinned B");
    await cardClick(b, "Show join code");
    const row = await listDevices(a, "Pinned B");
    await row.getByLabel("The code on the other device matches").check();
    await cardSignIn(a);
    await row.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(row).toContainText("Active");
    await cardClick(b, "Codes match");
    await expect(b.getByTestId("team-join")).toContainText("Codes confirmed.");
    await b.getByRole("button", { name: "Settings", exact: true }).click();
    await b.getByRole("button", { name: "Team", exact: true }).click();
    await cardClick(b, "Show join code");
    await expect(b.getByTestId("team-join-sas")).toBeVisible();
    await b.clock.fastForward("10:01");
    await expect(b.getByTestId("team-join")).toContainText("This join code has expired.");
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

## Outcome

| Goal | Result |
| --- | --- |
| 1. Grant recipient and listed key IDs | HOLDS |
| 2. Join confirmation and local windows for new authorization | HOLDS |
| 3. Compared tuple and immutable earlier pin | HOLDS |
| 4. Revocation cutoff and failed-send recovery | VIOLATED — R4-1a; server cutoff holds |
| 5. Fleet setup and exact saved-request retries | VIOLATED — R4-1b; fleet setup tests hold |
| 6. Secret/token/code leakage | VIOLATED — R4-2 |
| 7. Launcher revoke reasons and self-revoke | HOLDS |
| 8. Custodian-only tenant device listing | HOLDS |
| 9. Device-only root-grant reads | VIOLATED — R4-3; legacy account-wide exception |
| 10. Previously v1-guarded routes | HOLDS |
| 11. Honest key status and actionable UI | VIOLATED — R4-4; tested key-status predicates hold |

VERDICT: FAIL
