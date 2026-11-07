# Independent verification: recovery, export and device Reset — round 1

Verified HEAD: `e5e8b9e149bce70a2bcf2592280804174a0395a0`

Compared implementation: `git diff 6bb928d2..HEAD`. Verification date: 2026-11-07.

**Result: FAIL.** The existing recovery journeys pass, but the added adversarial tests demonstrate failures in identity preservation, password error handling and UI reporting. The account-ownership finding below requires an inconsistent server listing; it is not evidence of an honest server's RBAC being bypassed.

## Scope and execution boundaries

The normative inputs were ADR 0002's Q-12/Q-13 decision rows, D-5 including its plaintext-v3 amendment, D-9, ADR 0004, `docs/key-custody.md`, and the master-design excerpt supplied in the request. Repository implementation and test helpers were traced from these paths. No `.omc/`, `.omx/`, scratch-directory plans, author reports or external services were used as evidence. Generation rotation is outside this verification.

Production code was left unchanged. The working-copy additions are seven Rust tests and three Playwright tests, this report, and a structured test-output record, `docs/team-ui-evidence/codex-recovery-round-1-tests.json`. Tests reuse the repository's temporary-root, in-memory credential-store and loopback-server patterns. No commit, push, issue or PR was made. The real-OS-store test was excluded from every launcher invocation; the real launcher configuration directory was not used.

Code references for enforcing production paths are HEAD line numbers (the new tests are below those paths). References to added tests use the final working-copy line numbers. Test output below omits compiler progress and temporary directory names, not failed assertions or test outcomes. No generated key bytes, live tokens or captured passwords are reproduced.

## Goal results

| Goal | Result | Finding |
|---|---|---|
| 1. Wrong tenant/account/instance or revoked/mismatched device import | HOLDS | Import checks bundle context, local identity, account listing, session binding and exact live self-grant before state writes. |
| 2. Replace a working identity, destroy falsely-revoked credentials, or clear root identity through import/Reset | VIOLATED | D1: Reset writes a stale identity snapshot after its network wait. Ordinary false-revocation credential retention and import guards pass. |
| 3. Inconsistent v3 custodian/anchor/TRK/self-grant | HOLDS | Closed decoding, signature verification, context matching and HPKE/TRK equality checks reject the malformed bundles tested. |
| 4. 2.7 bundle opening/resume, step-3 upgrade, or replacement by an unopenable export | HOLDS | Compatibility and upgrade gates pass; an added test verifies that a genuinely openable older bundle survives a rejected export. See D7 for a separate export UX contract defect. |
| 5. Secret material in state/IPC/log/error | VIOLATED | D3: an unencoded account password echoed by `/v2/me` reaches the import error/IPC path. The normal-journey leak scan passes. |
| 6. Stale collect acknowledgements/substitution after Reset/import; unverified key retention/export | HOLDS | Tested lost/unavailable key and acknowledgement recovery paths succeed; failed verification does not cache a key, and export selects verified entries. |
| 7. Reset another account's device or an active pinned device | VIOLATED | D4: the client accepts a listed device despite an explicit account mismatch. Honest-server unlisted devices and active pinned devices are protected. |
| 8. Root connection changes, unreadable root state, or stored fleet-key deletion | VIOLATED | D2: an unfinished root bootstrap is excluded from the connection-change guard. Activated/unreadable-root and fleet-key preservation tests pass. |
| 9. Hide a refused key, offer root Reset, or offer a deterministically rejected action | VIOLATED | D5/D6: corrupt root status exposes Reset, and rejected fleet evidence becomes a generic waiting notice. |

### Goal 1 — HOLDS

Enforcing path: `src-tauri/src/recovery_import.rs:244` loads the configuration and opens the authenticated bundle; `:131` checks tenant and existing identity; `:158` checks the pinned anchor; `:169` checks server-instance ID, account ID, active status and both key IDs; `:271` orders these checks before the session and writes. `src-tauri/src/fleet_client.rs:476` verifies the session binding and proves possession of the imported keys. `recovery_import.rs:202` requires the exact signed self-grant, ACKNOWLEDGED grant state, ACTIVE root generation and the same unwrapped TRK. `:365` is reached only after these checks.

Tests run: `recovery_import`, shared `recovery_bundle`, and real-server `custodian_it` (commands/results below). Relevant output:

```text
test recovery_import::tests::another_server_is_refused_before_any_session_is_asked_for ... ok
test recovery_import::tests::a_revoked_row_keys_that_differ_and_another_account_are_refused ... ok
test recovery_import::tests::another_identity_in_team_json_is_refused ... ok
test recovery_import::tests::a_bundle_of_another_anchor_than_the_pinned_one_is_refused ... ok
test recovery_import::tests::a_self_grant_not_active_is_missing ... ok
test recovery_import::tests::codex_import_rejects_a_different_hpke_id_without_writing ... ok
test custodian_it::an_import_is_refused_for_a_v2_bundle_another_tenant_or_a_second_server_against_a_real_server ... ok
```

The new HPKE-ID test fills a gap in the original listing test, which changed only the signing key ID. It asserts the specific rejection code, absence of a session challenge, and unchanged state files. Its code is included below. The second-real-server test rejects at login because that server does not know the tenant; the separate mock test exercises an explicit instance mismatch after a successful login.

### Goal 2 — VIOLATED (D1)

Enforcing paths that work: `recovery_import.rs:144` prevents replacing another device or different readable seeds; `:381` rereads the identity before writing. `src-tauri/src/lib.rs:3056` blocks Reset of the locally recorded root custodian. `:3082` preserves a copy and keeps credentials when the listing says revoked or seeds do not read. Import writes credentials with readback at `recovery_import.rs:473` and commits `team.json` last at `:479`.

The Reset path itself loads at `lib.rs:3048`, awaits the listing at `:3064`, and clears/saves that earlier object at `:3097`, with no comparable reread or shared identity-operation lock. D1 demonstrates the resulting overwrite.

```text
test recovery_import::tests::another_identity_in_team_json_is_refused ... ok
test recovery_import::tests::a_team_json_that_changed_since_the_check_is_refused ... ok
test custody_tests::enroll_again_is_refused_for_an_active_pinned_or_custodian_device ... ok
test custody_tests::a_revoked_device_enrolls_again_and_keeps_its_old_credentials ... ok
test custodian_it::a_root_custodian_with_lost_keys_imports_its_bundle_on_its_own_roots ... ok
test custody_tests::codex_reset_preserves_an_identity_replaced_while_listing_is_in_flight ... FAILED
Reset overwrote the newer root identity
```

The added test uses a deterministic interleaving: while Reset is waiting for `/v2/me`, another local writer commits a working root identity; the reply then lists the old member as revoked. It observes the new identity being cleared from the active configuration. This is a concurrent-writer test, not a claim that a remote server can directly write local state. The old-credential preservation branch still operates, and the backup can contain the newer identity; that does not make replacing the active identity correct.

### Goal 3 — HOLDS

Enforcing path: `shared/src/recovery_bundle.rs:271` reads a closed custodian map; `:391` dispatches v2/v3 by domain and requires the corresponding version and custodian presence. `:291` verifies the grant's signature under the seed-derived public key, checks the FirstRootSelfGrant variant, tenant/instance, root generation/key ID, account/device/signing identity, and HPKE unwrap equality to the TRK. `:315` binds the seed-derived signing ID to the anchor. `:562` calls these checks after authenticated decryption and root-key-ID validation. Import uses this opener at `recovery_import.rs:260`.

```text
test recovery_bundle::tests::a_v3_bundle_round_trips_with_its_root_custodian ... ok
test recovery_bundle::tests::a_custodian_block_that_does_not_match_the_anchor_or_self_grant_is_refused ... ok
test recovery_bundle::tests::a_header_of_another_root_generation_than_the_self_grant_is_refused ... ok
test recovery_bundle::tests::a_v2_plaintext_with_a_custodian_block_and_a_v3_plaintext_without_one_are_refused ... ok
test recovery_bundle::tests::a_bundle_holds_only_keys_that_match_their_ids ... ok
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 298 filtered out; finished in 69.99s
```

The mismatch test seals each malformed plaintext and actually calls `open`; its cases include another seed, account, device, tenant, instance, root key, generation, HPKE seed, wrong grant variant, malformed record and wrong anchor. These are rejection assertions, not just parser construction tests. No additional test was needed for this goal.

### Goal 4 — HOLDS

Enforcing paths: the domain/version dispatch at `shared/src/recovery_bundle.rs:391` retains v2 reading. `src-tauri/src/root_bootstrap.rs:411` accepts an opening bundle with the pinned exact hash and TRK, including v2. `:431` requires v3 with the same device and self-grant to reuse an unpinned export. Bootstrap step 3 calls that gate at `:783`; a saved create request bypasses replacement and activation checks its pinned bundle at `:901`. Export verifies sealed bytes and a synthetic unwrap before replacement (`:400`), writes durably (`:402`), then compares the final-path readback byte-for-byte (`:403`). `src-tauri/src/durable.rs:17` writes/syncs a sibling before atomic replacement. `shared/src/recovery_bundle.rs:612` opens, validates the expected header, and performs the synthetic-key probe.

```text
test recovery_bundle::tests::a_v2_bundle_sealed_by_2_7_still_opens_without_a_custodian ... ok
test root_bootstrap::tests::a_v2_bundle_saved_before_the_create_is_replaced_by_a_v3_export ... ok
test root_bootstrap::tests::activation_accepts_the_v2_bundle_a_2_7_create_pinned ... ok
test root_bootstrap::tests::the_recovery_export_is_read_back_and_its_pinned_hash_returned ... ok
test root_bootstrap::tests::an_export_that_cannot_read_back_or_open_is_refused ... ok
test root_bootstrap::tests::codex_a_rejected_export_preserves_an_openable_older_bundle ... ok
test result: ok. 36 passed; 0 failed; 0 ignored; 0 measured; 741 filtered out; finished in 27.12s
```

The original replacement test used literal placeholder bytes as the older file. The added test instead exports a valid v3 bundle, opens it, attempts an export containing another device's self-grant, and verifies both unchanged bytes and successful reopening afterward. Compatibility evidence is the checked-in 2.7 fixture plus the pinned-v2 activation helper and the traced resume path; no old application binary was launched. D7 below concerns the separately specified owner fingerprint-confirmation ceremony, not a failed cryptographic compatibility or atomic-write test.

### Goal 5 — VIOLATED (D3)

Enforcement that passes: `shared/src/recovery_bundle.rs:245`/`:334` redact secret debug fields; `root_bootstrap.rs:135` redacts legacy TRK debug output. `team_config.rs:203`, `fleet_keys.rs:288`, and `credential.rs` store/readback keys through the credential boundary; Windows state copies use DPAPI (`team_config.rs:292`, `fleet_keys.rs:374`). `recovery_import.rs:61` logs error codes only. `lib.rs:3610` returns counts/status, not opened root keys. `fleet_client.rs:255` redacts recognized tokens and supplied secrets; `:389` handles login errors without returning arbitrary login-body text.

The gap is `fleet_client.rs:1022`: after login, `/v2/me` error handling supplies only the ticket, not the account password, to the redactor. Its response text is retained by `:343` and becomes the error returned through `recovery_import.rs:292` and `lib.rs:3130`.

```text
test fleet_client::tests::a_login_error_hides_the_echoed_password ... ok
test fleet_client::tests::a_login_error_hides_a_password_echoed_with_json_escapes ... ok
test fleet_client::tests::an_error_reply_hides_echoed_session_tokens ... ok
test custodian_it::the_journey_leaks_no_secret_to_output_state_or_replies ... ok
test recovery_import::tests::a_bundle_that_does_not_open_is_refused_with_its_own_code ... ok
test recovery_import::tests::codex_import_error_does_not_echo_the_login_password_after_login ... FAILED
account password reached the import error
```

The new test echoes the exact fixture login password, without encoding, from the next request's error body. It asserts no state mutation and checks the returned error without printing the password. This differs from the explicitly accepted limitation in `docs/key-custody.md:428` about encodings the launcher does not recognize. The passing journey leak scan covers successful import/export and ordinary errors; it does not exercise this hostile response.

### Goal 6 — HOLDS

Enforcing paths: `fleet_keys.rs:322` copies aside and unindexes unreadable keys, preserves locked entries, and never calls credential deletion. Reset calls it and clears old acks at `lib.rs:3093`; import does so at `recovery_import.rs:469` and replaces member custody/filters foreign acks at `:429`/`:453`. `fleet_custody.rs:1209` clears saved device acks. Collection checks grant context and signed evidence (`lib.rs:3235`, `:3395`, `:3563`), then stores through `fleet_keys.rs:234`; a different/read-failing key for an indexed generation is rejected. `fleet_custody.rs:589` skips an already acknowledged grant or builds a saved exact request. Export obtains only verified generations from `fleet_keys.rs:264`, fails on an unreadable verified entry, and requires the active generation in `root_bootstrap.rs:1011`.

```text
test fleet_keys::tests::unopenable_generations_leave_the_index_and_nothing_else_is_lost ... ok
test fleet_keys::tests::verified_keys_lists_only_verified_generations_and_refuses_an_unreadable_one ... ok
test fleet_custody::tests::collect_skips_the_ack_of_an_acknowledged_grant ... ok
test fleet_custody::tests::a_collected_ack_survives_a_later_release_of_the_setup_key ... ok
test custody_tests::a_verified_fleet_grant_opens_and_nothing_else_does ... ok
test custody_tests::a_collected_fleet_key_is_never_replaced ... ok
test recovery_import::tests::custody_states_are_replaced_kept_or_refused ... ok
test custodian_it::a_fresh_device_imports_the_recovery_bundle_and_keeps_the_team_against_a_real_server ... ok
test custodian_it::an_interrupted_import_resumes ... ok
test custodian_it::a_member_with_lost_keys_is_reset_after_revocation_and_rejoins_against_a_real_server ... ok
test custodian_it::a_member_whose_fleet_key_store_is_unavailable_rejoins_against_a_real_server ... ok
```

The real-server Reset tests assert a new device ID, a successful verified collect, an acknowledged grant belonging to that new device, and usable fleet-key status. The unavailable-store case also checks the old stored key still exists. The import journey goes on to approve a new device, exchange a profile and revoke a member. No added test was needed for these covered paths. This result does not promise that a genuinely different readable key is silently replaced, or that arbitrary local credential-store tampering is accepted.

### Goal 7 — VIOLATED at the client ownership check (D4)

Enforcing paths that work: `fleet_client.rs:996` uses a newly authenticated account ticket to list devices and selects the requested device ID from `/v2/me`. `lib.rs:3150` rejects active+pinned, missing and unsupported statuses. `:3056` protects the recorded root. The client then discards the returned account and instance fields at `:3075`, retaining only `device.status`.

```text
test custody_tests::enroll_again_is_refused_for_an_active_pinned_or_custodian_device ... ok
test custody_tests::codex_reset_of_an_unlisted_device_keeps_identity_and_credentials ... ok
test custodian_it::a_member_with_lost_keys_is_reset_after_revocation_and_rejoins_against_a_real_server ... ok
test custody_tests::codex_reset_checks_the_signed_in_account_against_the_saved_owner ... FAILED
a different signed-in account cleared the saved owner's device
```

The positive new test models the normal wrong-account outcome: the account's listing lacks the configured device, and Reset leaves both file and credentials intact. The failing probe returns a ticket and listing explicitly naming account B, while the saved identity belongs to account A, and includes A's device row as pending. Reset accepts it. **Qualification:** `docs/key-custody.md:349` trusts the server for RBAC. This is therefore a missing local consistency check under an inconsistent/malicious listing, not an end-to-end exploit against the honest server. The literal attack goal's account mismatch is achieved at the launcher boundary; the report does not claim the test defeats server membership enforcement.

### Goal 8 — VIOLATED (D2)

Enforcing paths that work: `lib.rs:2033` fails a connection change if root state does not load; for an activated matching root it requires both seeds to be genuinely lost (`:2038`), copies configuration (`:2045`), and avoids credential deletion (`:2066`). Reset also loads root state fail-closed (`:3056`). `fleet_keys.rs:322` removes only index entries after a durable copy; import and Reset do not delete stored FKEKs.

The root-identity guard includes `root.activated` at `lib.rs:2034`. A saved bootstrap with a first self-grant but `activated == false` is treated as a member: `clear_identity` at `:2056`, followed by credential deletion at `:2068`.

```text
test custody_tests::a_server_change_with_a_corrupt_root_state_is_refused ... ok
test custody_tests::a_root_custodian_whose_keys_are_not_lost_keeps_its_connection ... ok
test custody_tests::a_root_custodian_with_lost_keys_or_a_member_may_change_its_connection ... ok
test fleet_keys::tests::unopenable_generations_leave_the_index_and_nothing_else_is_lost ... ok
test custody_tests::codex_connection_change_preserves_an_unfinished_root_identity ... FAILED
connection change cleared the unfinished root identity
```

The new unit test constructs the matching root state with a valid first self-grant, leaves its local activation flag false, and changes the connection. It fails on identity preservation. The particularly serious reachable case is a completed server activation followed by a crash/error before the local flag is saved: server activation occurs at `root_bootstrap.rs:913`, trust-evidence readback at `:931`, and only then `finish_activation` at `:944`. Thus the false local flag is not proof that the device is not already the server's root custodian. The unit test verifies the local destructive branch; it does not claim to have injected a real process crash at that network boundary.

### Goal 9 — VIOLATED (D5, D6)

Enforcement that passes: `TeamCard.tsx:191` feeds the import collect report to the same reporting function as Collect; `:243` displays key substitution. `:557` hides Reset when `boot.activated` is known. `TeamDevices.tsx:61` combines setup state with live usable-key status before offering approval. The existing 92-test browser run passed the substitution, root-lost, unavailable-store, stale-code and early-export cases.

Two gaps remain. `TeamCard.tsx:78` swallows bootstrap-status errors, leaving `boot` null; `:557` interprets that as a non-root and renders Reset. Separately, `lib.rs:3637` represents rejected evidence as `fleet_failed = 1`, while `TeamCard.tsx:222` never reads `fleet_failed`: `:245` presents it as waiting because `fleet_refusal` identifies substitution only.

```text
an import whose collect is refused another fleet key says so ... passed
a root custodian whose keys are lost is offered import, not Reset ... passed
a root custodian whose key store is unavailable is told to try again, with no Reset or sign-in ... passed
codex: an import with rejected fleet evidence reports failure rather than waiting ... FAILED
Expected waiting-notice count: 0; Received: 1
codex: an unreadable root state never offers Reset ... FAILED
Expected Reset-button count: 0; Received: 1
```

The added browser tests inject the actual backend failure shapes at IPC while retaining the real React UI. The unreadable-state test first confirms the normal root UI hides Reset, then makes the status read fail and remounts Team. The rejected-evidence test uses exactly the report fields produced by `custody_report(..., FleetGrant::Failed)`. These are UI tests, not claims that Playwright drove the native Rust backend.

## Defect catalogue

### D1 — High: Reset can overwrite a newer working/root identity

Location: `src-tauri/src/lib.rs:3048`, `:3064`, `:3097`.

Scenario: start Reset for a member; while its account listing is in flight, a concurrent local connection/enrollment/import operation commits a different working identity. The old Reset reply arrives and the earlier `TeamConfig` is saved with its identity cleared, overwriting the newer state. The root check ran before that concurrent write. The new race test fails at the preserved-device assertion. An identity lock or a commit-time reread/compare covering both configuration and root state is needed; the existing import reread shows the established pattern.

### D2 — High: connection changes delete an unfinished root's identity

Location: `src-tauri/src/lib.rs:2034`, `:2056`, `:2068`; reachable ordering at `src-tauri/src/root_bootstrap.rs:913` through `:944`.

Scenario: root bootstrap has a durable self-grant and the server may already have activated generation 0, but local activation completion has not been saved. Changing URL or tenant classifies it as a member, clears identity and forgets its device credential references. Guard matching in-progress root ownership as well as completed bootstrap ownership. The added test fails on the changed file; credential deletion is also explicit on that branch in the traced code.

### D3 — High: a raw account password can enter an import error/IPC reply

Location: `src-tauri/src/fleet_client.rs:1022`, `:343`; propagation at `src-tauri/src/lib.rs:3130`.

Scenario: login succeeds, then `/v2/me` responds with an error body containing the exact password received during login. That request's redactor knows only the ticket. The original body text reaches the error returned by the command. The new test detects the password in the returned string without printing it. The code-only recovery log is not itself the leak. Retain only a bounded error code for this path or keep the operation's known sensitive values available to its error sanitizer.

### D4 — Medium, inconsistent-server condition: Reset ignores explicit account mismatch

Location: `src-tauri/src/lib.rs:3075`; account data is available at `src-tauri/src/fleet_client.rs:1036`.

Scenario: saved device belongs to A; the fresh ticket and `/v2/me` name B, but the listing includes the saved device as pending. Reset takes only the status, clears A's identity and takes the ordinary credential-deletion branch. This is reproduced by the new test. The honest-server wrong-account path passes. Because the shipped threat model trusts server RBAC, this is a client consistency/hardening defect under the literal attack goal, not proof of a server authorization vulnerability. Compare the returned account with the saved owner before destructive work, as recovery import already does.

### D5 — Medium: an unreadable root state exposes a Reset action that always errors

Location: `src/features/manage-team/ui/TeamCard.tsx:78`, `:557`; backend rejection at `src-tauri/src/lib.rs:3056`.

Scenario: root keys are lost and `custody-bootstrap.json` is unreadable. Team status still reports lost keys, but bootstrap status rejects. The UI swallows that error, treats null bootstrap state as a member, and offers Reset. The backend always fails its root-state load. The new browser test observes one Reset button where none should exist. Display the unknown/unreadable-root state explicitly and withhold destructive actions until identity classification succeeds.

### D6 — Medium: rejected fleet evidence is reduced to a waiting notice

Location: `src/features/manage-team/ui/TeamCard.tsx:222`, `:245`; report mapping at `src-tauri/src/lib.rs:3637`, `:3649`.

Scenario: recovery import succeeds, but the following fleet grant fails signature/trust evidence or unwrap validation. Backend reports `fleet_failed=1`, `fleet_grants_waiting=1`, `fleet_refusal=null`. UI ignores the failure count and shows an informational join/collect-again notice rather than the rejection. Root success toasts can accompany it. The added test reproduces the misleading waiting notice. Keep a distinct failed/unfetched result and present that failure alongside successful identity restoration.

### D7 — Medium: export has no owner fingerprint-confirmation step

Location: `src/features/manage-team/ui/TeamCard.tsx:176`–`:188`; backend command `src-tauri/src/lib.rs:2534`.

Scenario: a root with a fleet key supplies account credentials and matching recovery passphrases, chooses the path, and export completes immediately. No root-key fingerprint is presented for confirmation. The supplied Journey E explicitly requires owner fingerprint confirmation, and ADR 0002 D-5 `:1009`–`:1012` identifies that fingerprint as `root_key_id`; the displayed bootstrap anchor is a different identifier. The added browser test sees the successful export before any fingerprint confirmation (expected success-toast count zero, observed one). Passphrase confirmation, reauthentication, byte readback and synthetic unwrap do work; they do not satisfy this separate ceremony requirement.

## Commands and recorded output

Every launcher test command included `--skip a_real_os_store_key_survives_into_a_fresh_process`. No `-j 1` fallback was needed.

```text
git rev-parse HEAD
e5e8b9e149bce70a2bcf2592280804174a0395a0

cargo build -j 4 --manifest-path server/Cargo.toml
Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 09s

cargo test -j 4 --manifest-path shared/Cargo.toml recovery_bundle
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 298 filtered out; finished in 69.99s

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib recovery_import -- --skip a_real_os_store_key_survives_into_a_fresh_process
Before new tests: test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 758 filtered out; finished in 4.12s

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custodian_it -- --skip a_real_os_store_key_survives_into_a_fresh_process --test-threads=1
test result: ok. 16 passed; 0 failed; 1 ignored; 0 measured; 753 filtered out; finished in 351.85s

npx playwright test tests/e2e/app.spec.ts --retries=0
Before new tests: 92 passed (56.0s)

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib codex_ -- --skip a_real_os_store_key_survives_into_a_fresh_process --test-threads=1
test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 768 filtered out; finished in 14.48s
This filter also matched two pre-existing codex_mcp unit tests; the seven new Rust tests were 3 passed, 4 failed.

npx playwright test tests/e2e/app.spec.ts --retries=0 --grep codex:
At that point two new tests existed: 2 failed (D5 and D6; assertion details above).

npx playwright test tests/e2e/app.spec.ts --retries=0 --grep "codex: export"
1 failed (D7; successful export before fingerprint confirmation).

$env:CI = 'true'; cargo test -j 4 --manifest-path server/Cargo.toml --test identity_authority a_symlinked_record_is_refused -- --nocapture
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 0.65s
```

The first attempt to compile that server integration test overlapped the running real-server journey and failed replacing the in-use server executable (`os error 5`). No test ran in that attempt. The recorded passing retry ran after the journey exited, with `CI=true` to forbid the test's non-CI early-return fallback.

The seven full launcher filters below ran after the new Rust tests were added. The JSON evidence file records every test name and status, along with each command, exit status and result line.

| Filter | Result output |
|---|---|
| `root_bootstrap` | `test result: ok. 36 passed; 0 failed; 0 ignored; 0 measured; 741 filtered out; finished in 27.12s` |
| `fleet_keys` | `test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 767 filtered out; finished in 0.04s` |
| `fleet_custody` | `test result: ok. 42 passed; 0 failed; 0 ignored; 0 measured; 735 filtered out; finished in 1.35s` |
| `fleet_client` | `test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 758 filtered out; finished in 0.04s` |
| `team_config` | `test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 763 filtered out; finished in 0.07s` |
| `custody_tests` | `test result: FAILED. 53 passed; 3 failed; 0 ignored; 0 measured; 721 filtered out; finished in 8.52s` |
| `recovery_import` | `test result: FAILED. 13 passed; 1 failed; 0 ignored; 0 measured; 763 filtered out; finished in 5.13s` |

Each filter used:

```text
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib <filter> -- --skip a_real_os_store_key_survives_into_a_fresh_process
```

## Test-strength audit and limits

- No added test is ignored, empty, marked expected-failure, or allowed to return early. Failing regression assertions remain failing; production code was not changed to make them pass.
- The shared/import/root/fleet/client/team-config test modules contain meaningful positive and negative assertions. Relevant tests compare state bytes, credential presence, exact grant/request context, and observable outcomes. No silent skip was found in those selected tests.
- `custodian_it.rs:2115` does contain an `#[ignore]` worker. It is not missing coverage: the nonignored parent at `:1989` invokes that exact worker with `--ignored --nocapture`, requires a successful exit and `1 passed`, requires eight collected secret values and specific state/reply files, then scans them and child stdout/stderr. The passing parent establishes that the worker ran. The top-level summary still correctly says one ignored; it is not represented as zero ignored here. The exact worker selection does not run the prohibited OS-store test.
- `server/tests/identity_authority.rs:230`–`:237` contains a non-CI early return if neither a symlink nor a junction can be made. Its original structure is not unconditionally strong. Running it with `CI=true` turns that branch into an assertion failure; this run passed through the link/reparse-point rejection and regular-file recovery assertions.
- `src-tauri/tests/fleet_enrollment_it.rs` was inspected, including its strengthened missing-server panic and the root-bootstrap resume test. It is an integration target, not part of the user-specified `--lib` commands, and no execution result for it is claimed. Actual local-server coverage here comes from the executed `custodian_it` lib harness. The 2.7 compatibility result is limited to the current-HEAD golden fixture and current reader/resume checks, not a launched historical binary.
- Playwright uses the existing mocked IPC harness, not the native app or a real credential store. Backend behavior is independently exercised by the Rust suites and loopback real-server tests. Browser failure reports inject backend-shaped responses/errors, while UI code remains unmodified.
- The account-mismatch probe intentionally exceeds an honest RBAC listing: its precondition and the shipped RBAC trust assumption are stated in Goal 7/D4. It must not be cited as a demonstrated server authorization bypass.
- Rust formatting initially reported differences only in the added tests. `cargo fmt --manifest-path src-tauri/Cargo.toml` formatted those additions; no production behavior was changed. Build-generated schema line-ending changes were restored to HEAD.

## Added test code and results

The following source excerpts are the final working-copy tests. Fixture constants are synthetic; assertions deliberately avoid printing actual key or password values. The code uses existing helpers in the surrounding modules, whose real-loopback and temporary-root paths were inspected.

### `codex_reset_preserves_an_identity_replaced_while_listing_is_in_flight`

Source: `src-tauri/src/lib.rs:6354`. Result: **FAILED — Reset overwrote the newer root identity (D1).**

```rust
    #[test]
    fn codex_reset_preserves_an_identity_replaced_while_listing_is_in_flight() {
        use std::sync::Arc;
        let rt = runtime();
        let changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let changed_in_reply = changed.clone();
        let reply: Arc<fleet_custody::tests::Reply> = Arc::new(move |call, _| {
            let body = match call {
                "POST /v2/auth/login" => serde_json::json!({
                    "ticket": "v2t.fixture", "ticket_id": hex(&[1; 16]),
                    "account_id": hex(&[6; 16]), "server_instance_id": hex(&INSTANCE),
                    "restore_epoch": 0
                }),
                "GET /v2/me" => {
                    // A concurrent enrollment/import has committed another working identity.
                    let mut current = team_config::load().unwrap();
                    current.device_id = hex(&[0x6b; 16]);
                    current.signing_credential_ref = "codex-race-signing".into();
                    current.hpke_credential_ref = "codex-race-hpke".into();
                    credential::store(&current.signing_credential_ref, &[0x71; 32]).unwrap();
                    credential::store(&current.hpke_credential_ref, &[0x72; 32]).unwrap();
                    team_config::save(&current).unwrap();
                    root_bootstrap::save(&root_bootstrap::BootstrapState {
                        tenant_id: current.tenant_id,
                        device_id: current.device_id,
                        activated: true,
                        ..Default::default()
                    })
                    .unwrap();
                    changed_in_reply.store(true, std::sync::atomic::Ordering::SeqCst);
                    serde_json::json!({"devices": [{"device_id": hex(&JOINER), "status": "revoked"}]})
                }
                _ => serde_json::json!({}),
            };
            (200, serde_json::to_vec(&body).unwrap())
        });
        let (client, _) = rt.block_on(fleet_custody::tests::mock(reply));
        let _j = joiner(client.base_url(), root_bootstrap::now_ms());
        let result = rt.block_on(team_enroll_again("u".into(), "p".into()));
        assert!(changed.load(std::sync::atomic::Ordering::SeqCst));
        let after = team_config::load().unwrap();
        assert!(
            after.device_id == hex(&[0x6b; 16]),
            "Reset overwrote the newer root identity"
        );
        assert!(result.is_err(), "Reset accepted a stale identity snapshot");
    }
```

### `codex_reset_of_an_unlisted_device_keeps_identity_and_credentials`

Source: `src-tauri/src/lib.rs:6402`. Result: **PASSED — missing account-owned listing preserves the configuration and credentials (Goal 7 control).**

```rust
    #[test]
    fn codex_reset_of_an_unlisted_device_keeps_identity_and_credentials() {
        let rt = runtime();
        let (url, _) = me_server(&rt, "missing");
        let _j = joiner(&url, root_bootstrap::now_ms());
        let before = team_json();
        let refs = refs();
        let result = rt.block_on(team_enroll_again("other-account".into(), "p".into()));
        assert!(result.is_err());
        assert!(team_json() == before);
        assert!(credential::load(&refs[0]).is_ok() && credential::load(&refs[1]).is_ok());
    }
```

### `codex_reset_checks_the_signed_in_account_against_the_saved_owner`

Source: `src-tauri/src/lib.rs:6415`. Result: **FAILED — a different signed-in account cleared the saved owner's device (D4, inconsistent-listing precondition).**

```rust
    #[test]
    fn codex_reset_checks_the_signed_in_account_against_the_saved_owner() {
        let rt = runtime();
        let reply: std::sync::Arc<fleet_custody::tests::Reply> = std::sync::Arc::new(|call, _| {
            let body = match call {
                "POST /v2/auth/login" => serde_json::json!({
                    "ticket": "v2t.fixture", "ticket_id": hex(&[1; 16]),
                    "account_id": hex(&[0x6c; 16]), "server_instance_id": hex(&INSTANCE),
                    "restore_epoch": 0
                }),
                "GET /v2/me" => serde_json::json!({
                    "account_id": hex(&[0x6c; 16]), "server_instance_id": hex(&INSTANCE),
                    "devices": [{"device_id": hex(&JOINER), "status": "pending"}]
                }),
                _ => serde_json::json!({}),
            };
            (200, serde_json::to_vec(&body).unwrap())
        });
        let (client, _) = rt.block_on(fleet_custody::tests::mock(reply));
        let _j = joiner(client.base_url(), root_bootstrap::now_ms());
        let before = team_json();
        assert!(team_config::load().unwrap().account_id != hex(&[0x6c; 16]));
        let result = rt.block_on(team_enroll_again("other-account".into(), "p".into()));
        assert!(
            team_json() == before,
            "a different signed-in account cleared the saved owner's device"
        );
        assert!(result.is_err());
    }
```

### `codex_connection_change_preserves_an_unfinished_root_identity`

Source: `src-tauri/src/lib.rs:6445`. Result: **FAILED — connection change cleared the unfinished root identity (D2).**

```rust
    #[test]
    fn codex_connection_change_preserves_an_unfinished_root_identity() {
        for (url, tenant) in connection_changes() {
            let _j = joiner(URL_J, root_bootstrap::now_ms());
            root_here();
            let mut root = root_bootstrap::load().unwrap();
            let c = team_config::load().unwrap();
            let signer = c.signing_key().unwrap();
            let (_, hpke_public) = shardx_core::grants::derive_keypair(&c.hpke_seed().unwrap());
            let cx = root_bootstrap::Context16 {
                tenant: TENANT,
                instance: INSTANCE,
                epoch: 0,
                account: [6; 16],
                device: JOINER,
                signing_key_id: shardx_core::keys::signing_key_id(
                    signer.verifying_key().as_bytes(),
                ),
                hpke_key_id: shardx_core::keys::hpke_key_id(&hpke_public),
            };
            root.self_grant = hex(&root_bootstrap::self_grant(
                &cx,
                &signer,
                &hpke_public,
                &[9; 32],
                [8; 16],
                root_bootstrap::now_ms(),
            )
            .unwrap());
            // An interrupted bootstrap has saved its first self-grant but has
            // not yet persisted finish_activation's activated flag.
            root.activated = false;
            root_bootstrap::save(&root).unwrap();
            let before = team_json();
            let refs = refs();
            let result = team_set_connection(url, String::new(), tenant);
            assert!(
                team_json() == before,
                "connection change cleared the unfinished root identity"
            );
            assert!(credential::load(&refs[0]).is_ok() && credential::load(&refs[1]).is_ok());
            assert!(result.is_err());
        }
    }
```

### `codex_import_error_does_not_echo_the_login_password_after_login`

Source: `src-tauri/src/recovery_import.rs:695`. Result: **FAILED — account password reached the import error (D3).**

```rust
    #[test]
    fn codex_import_error_does_not_echo_the_login_password_after_login() {
        let f = fixture();
        let ordinary = server(me(INSTANCE, ACCOUNT, "active", key_ids()), (500, ""));
        let reply: Arc<Reply> = Arc::new(move |call, body| {
            if call == "GET /v2/me" {
                (500, br#"{"error":"pw"}"#.to_vec())
            } else {
                ordinary(call, body)
            }
        });
        let (err, calls, unchanged) = refused_by(&f, reply);
        assert!(calls.iter().any(|c| c == "GET /v2/me"));
        assert!(unchanged);
        assert!(
            !err.contains("pw"),
            "account password reached the import error"
        );
    }
```

### `codex_import_rejects_a_different_hpke_id_without_writing`

Source: `src-tauri/src/recovery_import.rs:715`. Result: **PASSED — wrong HPKE ID rejected before challenge/write (Goal 1).**

```rust
    #[test]
    fn codex_import_rejects_a_different_hpke_id_without_writing() {
        let f = fixture();
        let listing = me(INSTANCE, ACCOUNT, "active", (key_ids().0, hex(&[0xee; 32])));
        let (err, calls, unchanged) = refused_by(&f, server(listing, (500, "")));
        assert!(crate::errcode::has_code(&err, "recovery.deviceNotActive"));
        assert!(!calls.iter().any(|c| c == CHALLENGE));
        assert!(unchanged);
    }
```

### `codex_a_rejected_export_preserves_an_openable_older_bundle`

Source: `src-tauri/src/root_bootstrap.rs:1468`. Result: **PASSED — older bundle unchanged and still opens (Goal 4).**

```rust
    #[test]
    fn codex_a_rejected_export_preserves_an_openable_older_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.bundle");
        let recovery = RecoveryExport {
            path: &path,
            passphrase: "codex fixture passphrase",
        };
        let trk = [9; 32];
        let (cx, good) = custodian_cx([5; 16], &trk);
        export_v3(&cx, &trk, &good, &recovery);
        let before = std::fs::read(&path).unwrap();
        assert!(rb::open(&before, recovery.passphrase).is_ok());
        let (_, wrong) = custodian_cx([0x0e; 16], &trk);
        let result = export_recovery_bundle(
            &cx,
            &trk,
            &signer(),
            &HPKE_SEED,
            &wrong,
            Vec::new(),
            &recovery,
            1_800_000_000_000,
        );
        assert!(result.is_err());
        let after = std::fs::read(&path).unwrap();
        assert!(after == before, "the good bundle was replaced");
        assert!(rb::open(&after, recovery.passphrase).is_ok());
    }
```

### `codex: an import with rejected fleet evidence reports failure rather than waiting`

Source: `tests/e2e/app.spec.ts:1203`. Result: **FAILED — waiting-notice count expected 0, received 1 (D6).**

```typescript
test("codex: an import with rejected fleet evidence reports failure rather than waiting", async ({ page }) => {
  const card = await teamDevicePage(page, "b", fakeTeamServer());
  await page.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      const result = await original(...args);
      // Exact report shape of custody_report(..., FleetGrant::Failed).
      return args[0] === "team_import_recovery_bundle"
        ? { ...(result as object), fleet_opened: 0, fleet_failed: 1, newest_fleet_generation: null,
            fleet_grants_waiting: 1, fleet_refusal: null }
        : result;
    };
  });
  const form = card.getByTestId("team-import");
  await form.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await form.getByLabel(OLD_DEVICE_LOST).check();
  await cardClick(page, "Import recovery bundle");
  await expect(page.getByText("The recovery bundle was imported.")).toBeVisible();
  await expect(page.getByText("A fleet key grant is waiting but was not kept.", { exact: false })).toHaveCount(0);
  await expect(page.getByText(/fleet.*(failed|refused|does not verify)/i)).toBeVisible();
});
```

### `codex: export waits for the owner's recovery fingerprint confirmation`

Source: `tests/e2e/app.spec.ts:1244`. Result: **FAILED — export-success count expected 0, received 1 before fingerprint confirmation (D7).**

```typescript
test("codex: export waits for the owner's recovery fingerprint confirmation", async ({ page }) => {
  await teamDevicePage(page, "a", fakeTeamServer());
  await cardClick(page, "Create fleet key");
  const form = page.getByTestId("team-export");
  await cardSignIn(page);
  await form.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await form.getByLabel("Recovery passphrase again").fill("correct horse");
  await form.getByRole("button", { name: "Export recovery bundle" }).click();
  // Journey E requires owner fingerprint confirmation in addition to the
  // passphrase confirmation. No fingerprint has been confirmed in this flow.
  await expect(page.getByText("Recovery bundle exported to C:\\Users\\Example\\shardx-recovery.shxrecovery.")).toHaveCount(0);
  await expect(page.getByRole("dialog").filter({ hasText: /fingerprint/i })).toBeVisible();
});
```

### `codex: an unreadable root state never offers Reset`

Source: `tests/e2e/app.spec.ts:1320`. Result: **FAILED — Reset-button count expected 0, received 1 (D5).**

```typescript
test("codex: an unreadable root state never offers Reset", async ({ page }) => {
  const card = await teamDevicePage(page, "root-keys-lost", fakeTeamServer());
  await expect(card.getByRole("button", { name: "Reset this device" })).toHaveCount(0);
  await page.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      if (args[0] === "team_custody_bootstrap_status") {
        throw new Error("[[shardx:fleet.custodyStateCorrupt]]");
      }
      return original(...args);
    };
  });
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Team", exact: true }).click();
  await expect(card.getByTestId("team-keys-lost")).toBeVisible();
  await expect(card.getByRole("button", { name: "Reset this device" })).toHaveCount(0);
});
```

VERDICT: FAIL
