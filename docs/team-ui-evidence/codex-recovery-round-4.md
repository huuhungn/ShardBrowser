# Independent recovery verification, round 4

Verified HEAD: `06e48aa77fd8f7311024a3fe420410edb8815079` (PR #279, `fix/v281`). GitHub reports the same PR head and base `905246e7f0acb86f29f86d9d49926a315539ecae`.

This is a static, read-only verification of implementation and tests, with this report as the sole requested write. No build, test suite, application, browser automation or server was run. No source file was changed. The normative sources are the requested Q-12/Q-13 decision rows, D-5 including its v3 amendment, D-9, ADR 0004, `docs/key-custody.md`, and the master-design excerpts supplied in the request. The only previous verification report consulted was `docs/team-ui-evidence/codex-recovery-round-3.md`. No author plan, other review report, `.omc/`, `.omx/`, or scratch-directory content was used. Root/fleet rotation is outside this verdict.

The five specific round-3 defects are closed in the inspected code. Two additional defects remain: an error checking whether the root journal exists is treated as absence, and the readable-device UI still treats another device's root journal as its own. Neither finding depends on a failing local test run; the paths below establish them statically.

## CI evidence

Observed on 2026-11-07 at 12:31:07 UTC using `gh pr checks 279 --repo huuhungn/ShardBrowser`. [HEAD run 42372082306](https://github.com/huuhungn/ShardBrowser/actions/runs/42372082306):

| Check | Observed state |
| --- | --- |
| Launcher, server and shared MSRV | pass, 4m29s |
| Rust SDK stable and MSRV | pass, 2m49s |
| Rust compiles on macOS | pass, 1m10s |
| Rust tests on Windows | pending |
| frontend, Rust, and MCP checks | pending |

`gh run list --repo huuhungn/ShardBrowser --branch main --limit 5`, supplemented with the same read-only command's JSON fields to bind results to commits, showed:

| Main run | Commit | Result |
| --- | --- | --- |
| [Release, 42347821500](https://github.com/huuhungn/ShardBrowser/actions/runs/42347821500) | `905246e7f0acb86f29f86d9d49926a315539ecae` | success |
| [CI, Release v2.8.0 (#278), 42347816967](https://github.com/huuhungn/ShardBrowser/actions/runs/42347816967) | `905246e7f0acb86f29f86d9d49926a315539ecae` | success |
| [CI, #277, 42342926502](https://github.com/huuhungn/ShardBrowser/actions/runs/42342926502) | `7c5b37083e605c872d73ca3070c9f8c2f00a8c14` | success |
| [CI, #276, 42331556904](https://github.com/huuhungn/ShardBrowser/actions/runs/42331556904) | `3c38057a95e9cb272f048a22296a949d07bac007` | success |
| [CI, #275, 42309376818](https://github.com/huuhungn/ShardBrowser/actions/runs/42309376818) | `e5e8b9e149bce70a2bcf2592280804174a0395a0` | success |

Parent success is not HEAD test success. Pending checks are not counted as passed. The FAIL below is caused by the static defects, independently of those pending results.

## Round-3 D1-D5 closure

| Previous defect | Assessment | Code and regression evidence |
| --- | --- | --- |
| D1: import authentication context not bound to the bundle | **CLOSED** | `src-tauri/src/recovery_import.rs:177` checks both the listing and first ticket's instance/account against the bundle. The import at `:312` supplies the bundle's account/instance to `src-tauri/src/fleet_client.rs:519`; that method checks the second ticket before requesting a challenge, and still ends the ticket on rejection. `session_with_ticket` at `fleet_client.rs:571` binds the proof to that ticket, tenant, device and both public keys. `recovery_import.rs:808` independently changes account and instance in each of the two logins while keeping the listing consistent, and asserts the specific error, no challenge, and unchanged files. |
| D2: a false pending listing deletes working member credentials | **CLOSED** | `src-tauri/src/lib.rs:3116` now preserves credentials and a durable copy for both pending and revoked replies. `lib.rs:6968` checks a pinned device with readable seeds, a pending reply, a backup, and both original stored seeds after Reset. `lib.rs:6943` retains the revoked case; `:6759`, `:6903` and `:6626` retain genuine pending, pinned-pending and older-config positive controls. |
| D3: successful root-grant JSON causes a UTF-8 slice panic and secret echo | **CLOSED** | `src-tauri/src/lib.rs:3721` delegates to `fleet_client.rs:1820`, which rejects non-ASCII-hex bytes before slicing and uses checked ranges. All three fields in `custody_report` at `lib.rs:3674` use it. `lib.rs:6986` checks the multibyte/sentinel case, signed hex and another non-ASCII case, then injects the malformed string into each of the three grant fields; assertions require no panic and no sentinel in the error. This is a direct decoder/report regression, not a new HTTP/subprocess leak test. The ordinary collect still reaches `end_session` at `lib.rs:3253` after a structured report error. |
| D4: collect never promotes an equal legacy cached key to verified | **CLOSED** | `src-tauri/src/fleet_keys.rs:248` permits an equal existing key to reach `verified.insert` and the durable write at `:258`; a different or unreadable existing key still returns false. `fleet_keys.rs:612` starts with two unmarked generations, refuses the different key, promotes the equal key, reloads the marker, and checks the export selector contains only the promoted generation. The genuine export journey at `src-tauri/src/custodian_it.rs:1422` opens the exported bundle and checks its retained FKEK. There is still no single integration test combining legacy-cache promotion, import/collect and export. |
| D5: root Reset offered while status loads or after unfinished bootstrap expires | **CLOSED for both reported scenarios** | `src/features/manage-team/ui/TeamCard.tsx:565` and `:587` require a loaded root status and use `this_device` in the lost-key branch. `src-tauri/src/lib.rs:2915` classifies an expired join window with matching root state as `fleet.enrollAgainRefused` before the network step. `lib.rs:7028` tests pending/active listings and both present/absent passwords; `:7054` checks tenant/device ownership in status. `tests/e2e/app.spec.ts:1404` holds the status promise and checks no Reset/sign-in before and after release; `:1452` checks the readable unfinished-root expiry UI. The mock guard at `src/e2e-mock.ts:495` now checks `this_device`, including unfinished state. The separate readable-device/foreign-journal case remains R4-D2 below. |

Honest-flow checks: the bound-ticket change preserves the ordinary real-server import/export journey (`custodian_it.rs:1422`) and same-machine root recovery (`:1934`); preserving pending credentials still clears the current member identity as required (`lib.rs:6759`); valid hex keeps the real collect path; equal-key promotion preserves substitution rejection (`lib.rs:4106`); and the UI still provides real member recovery (`tests/e2e/app.spec.ts:1291`) and root import (`:1340`). These are inspected positive controls, not claims that the pending HEAD jobs have executed successfully.

## Attack-goal results

### Goal 1: wrong tenant/account/server/device import — HOLDS

Enforcement: `src-tauri/src/recovery_import.rs:131` requires a custodian block, the configured tenant and a compatible local identity. `:158` checks an existing tenant anchor before any request. `:170` requires the bundle account and instance in both the login ticket and listing, and an active row with both exact key IDs. The row is selected by device ID at `src-tauri/src/fleet_client.rs:1115`. The second login is independently bound at `recovery_import.rs:312` / `fleet_client.rs:531`; the session proof checks the complete binding at `fleet_client.rs:571`. `recovery_import.rs:202` then requires the exact signed self-grant, acknowledged under an active root, opening to the bundle TRK. Both ticket and session cleanup run on these errors. State writes start only at `recovery_import.rs:347`.

Tests read: `recovery_import.rs:782` (HPKE ID), `:792` (instance), `:808` (both login tickets), `:842` (revoked row, signing ID, listing account), `:977` (tenant and local identity), `:1197` (pre-existing anchor), `:910` and `:1225` (generation/grant liveness). `src-tauri/src/custodian_it.rs:1636` exercises v2 rejection, another tenant and another real server, with no imported credentials/state; `:1422` is the positive import journey.

Coverage qualification: the real second-server test is rejected at login because that server lacks the tenant; the matching-listing/wrong-instance cases are covered by the unit HTTP fixture. A useful additional full-import case would independently replace the grant descriptor's exact container, require `recovery.rootGrantMissing`, and assert logout and unchanged credentials. The implementation compares exact bytes already.

### Goal 2: destructive identity replacement through import/Reset — VIOLATED

Normal enforcement: `src-tauri/src/recovery_import.rs:144` rejects a different device or readable different seed; `:389` rechecks the current identity after network work; `:399` checks existing root/custody journals before writing. `src-tauri/src/lib.rs:3066` rejects the root custodian before listing, and `:3103` rechecks current identity and root state afterwards. `:3116` preserves the old config and credentials for unsigned pending/revoked claims or unreadable seeds. A Reset does not enroll a replacement device itself.

Tests read: `recovery_import.rs:977`, `:1030`, `:1060`, `:1177`; `lib.rs:6412`, `:6497`, `:6521`, `:6853`, `:6943`, `:6968`; and `custodian_it.rs:1934`, which rejects root Reset and successfully imports on the same roots. `custodian_it.rs:1695` injects an import failure at the final team-config write and verifies a later import resumes.

**R4-D1 bypasses the root guard when the journal's existence check itself errors.** A pending/revoked listing can then make Reset clear a root custodian's current identity, despite its intact device credentials. The backup/retention branch limits damage but does not make root Reset permissible. Existing tests use a root file that is absent, readable, or corrupt after a successful existence check; they do not inject a metadata-lookup error.

### Goal 3: inconsistent v3 custodian block opens/imports — HOLDS

Enforcement: `shared/src/recovery_bundle.rs:391` dispatches closed plaintext schemas by domain/version and requires the v3 block. `:405` and `:417` rederive TRK/FKEK IDs; `:562` authenticates the envelope and checks the header root ID. `RootCustodian::check` at `:291` verifies the first self-grant signature/variant, header tenant/instance/root/generation, subject account/device/signing ID, anchor derived from the signing seed, and HPKE unwrap equality to the plaintext TRK. `src-tauri/src/recovery_import.rs:260` calls that reader and maps rejection to a fixed error before import processing.

Tests read: `shared/src/recovery_bundle.rs:777` (positive round trip/readiness), `:827` (wrong seed, device, account, tenant, TRK, generation, HPKE seed, record, variant, instance and anchor), `:902` (header generation independently), and `:918` (forbidden/missing custodian and mismatched schema versions). `src-tauri/src/recovery_import.rs:1266` seals an invalid HPKE custodian, calls the full entry point, and asserts no request and no file changes.

Coverage qualification: the full import negative uses one custodian mutation; the broader cryptographic matrix is in the shared reader that import invokes. There is no need to claim the unit import helper revalidates arbitrary fabricated plaintext: it is an internal helper after `open`, and the production entry point performs that open.

### Goal 4: v2 compatibility/bootstrap resume/unsafe replacement — HOLDS

Enforcement: `shared/src/recovery_bundle.rs:394` still reads v2 without a custodian, using the original header/KDF/AEAD format. `src-tauri/src/root_bootstrap.rs:431` reuses an unpinned bundle only if it is v3 with the same device and exact self-grant. Step 3 applies that rule only before the create request at `:783`. Once create is saved, activation uses the pinned bytes and TRK at `:901`, through the v2-compatible `check_bundle` at `:411`. `:366` seals a v3 export, verifies opening and a synthetic unwrap **before** replacement at `:400`, durably writes it at `:402`, and requires final-path readback byte equality at `:403`. `src-tauri/src/durable.rs:17` writes/syncs a sibling and replaces the destination atomically. The export command reauthenticates at `src-tauri/src/lib.rs:2554`, reads back the root grant, requires the active FKEK, and ends the session. UI confirmation is at `TeamCard.tsx:125`, `:184`, `:664` and `:682`.

Tests read: `shared/src/recovery_bundle.rs:812` opens the checked-in 2.7 fixture and checks byte-identical v2 encoding; `root_bootstrap.rs:1457`, `:1497`, `:1530`, `:1591`, `:1653`, `:1695`; `src-tauri/src/custodian_it.rs:1971` resumes both before/after a v2 create, checks v3 replacement versus exact v2 preservation, and asserts one server root generation. `src-tauri/tests/fleet_enrollment_it.rs:642` exercises failed approval, store unavailability, failed ack/activation saves, pinned-bundle loss, full replay and the v3 contents. `custodian_it.rs:1402` rejects export before the fleet key; `:1422` verifies the exported retained key and unchanged state/audit. `tests/e2e/app.spec.ts:1226`, `:1245`, `:1267` check export gating/fingerprint.

Coverage gap: the missing-directory/directory-destination test fails during writing, not during final-path readback after replacement. Add an injected final read error or changed readback and assert export returns failure, never acknowledges readiness, and any installed bundle consists of the already validated bytes. The current prevalidation and byte-equality check establish the intended protection statically.

### Goal 5: secret material in state/IPC/logs/errors — HOLDS within the documented custody model

Enforcement: `src-tauri/src/recovery_import.rs:258` replaces file/decryption diagnostics with fixed codes; `:61` logs step/error codes, and `:479` stores only credential references in the committed identity. `src-tauri/src/credential.rs:99` requires store/readback equality and converts backend failures to fixed errors. Bootstrap state serialization/redacted Debug omits the legacy TRK; the running TRK lives behind a reference and is released after activation. `shared/src/recovery_bundle.rs:246` and `:335` redact Debug output. `src-tauri/src/team_config.rs:71` redacts seeds/token, while `:341` exposes public status only. `src-tauri/src/lib.rs:3665` returns counts/generations, not opened root material; the repaired hex error at `:3721` contains no server string.

`src-tauri/src/fleet_client.rs:429` remembers the operation's password only for redaction and suppresses login error text; `:362` redacts later errors, including access tokens and remembered passwords. The shared redactor at `:281` handles literal supplied secrets, token bodies and token markers. `src-tauri/src/team/sync.rs:819` applies the same client redactor to sync errors. `recovery_import.rs:343` and `lib.rs:3253`/`:2565` end sessions on normal success/error paths.

Tests read: `lib.rs:6986` (the old panic path and all three fields); `recovery_import.rs:703`, `:762`, `:1305` (later password echo and bundle errors); `shared/src/recovery_bundle.rs:777` (redacted custodian Debug); the refusal tests added around `src-tauri/src/team/sync.rs:5775`; and `src-tauri/src/custodian_it.rs:2138` with its worker at `:2265`. That parent requires successful subprocess exit and `1 passed`, checks eight collected key sentinels plus both passwords, verifies expected artifacts exist, and scans stdout/stderr, command replies and selected state files for secrets/tokens.

This classification follows ADR 0004 and the explicit shipped exceptions in `docs/key-custody.md:72`, `:387` and `:432`: existing file fallback/DPAPI storage is not itself an accidental leak, and arbitrary encodings of secrets echoed by a hostile server are explicitly outside the promise. No new raw seed/TRK export or literal remote-echo leak was found.

Coverage gaps: `custodian_it.rs:2245` does not collect `fleet-keys.json` or the Reset/import backup files into the leak scan. The new malformed-success decoder test is direct and uses a sentinel; it does not exercise HTTP, IPC, process stderr and logout together. Add those artifacts and a successful-JSON malicious-grant case for each field to the subprocess harness, asserting fixed errors, no sentinel in output/replies, and session cleanup. These are limits on test evidence, not demonstrated leaks at this HEAD.

### Goal 6: post-recovery collect mismatch or unverified key retention/export — HOLDS

Enforcement: `src-tauri/src/fleet_keys.rs:331` unindexes unreadable keys after a backup, preserves locked-file entries and never deletes stored credentials. Reset invokes it at `src-tauri/src/lib.rs:3128`, then clears old acknowledgements at `:3131`; import invokes it at `src-tauri/src/recovery_import.rs:476`. Import replaces a member custody journal at `:435`, preserves only acknowledgements for the custodian's own saved grant at `:459`, and refuses another custodian's journal at `:415`. `src-tauri/src/fleet_custody.rs:589` creates/saves the current grant's exact ack and validates the response; `:1209` propagates journal read failures when clearing acks.

`src-tauri/src/lib.rs:3280` reads the live generation/device grant, obtains trust evidence, evaluates the pinned chain and recipient at `:3450`, opens/checks the FKEK, and only then calls `keep_fleet_key` at `:3366`. `fleet_keys.rs:236` prevents substitution, including an unreadable indexed value, while promoting equal legacy bytes. `:273` exports only generations marked verified and errors if a marked key does not open; `root_bootstrap.rs:1014` requires the active generation among them. Import does not trust retained bundle FKEKs as a replacement for verified collect.

Tests read: `fleet_keys.rs:501`, `:576`, `:612`; `lib.rs:4013`, `:4106`; `recovery_import.rs:1060`; `custodian_it.rs:1422`, `:1695`, `:1856`, `:1863`, `:1934`. The shared member-rejoin helper at `custodian_it.rs:1755` exercises real revoke, Reset, fresh enrollment, approval, pin, collect, and the new device's acknowledged grant, including a transient fleet-store failure with the stored key retained. Wrong-byte substitution remains intentionally rejected; such a rejection is not a recovery regression.

Coverage gap: combine the D4 legacy-equal-key fixture with the real import/collect/export journey and assert the opened v3 bundle contains the promoted key. Also inject corrupt fleet-custody state at Reset/import boundaries and check config/credentials stay intact while accounting for Reset's documented, backed-up index cleanup before the custody read fails.

### Goal 7: Reset of another account's device or an active pinned device — HOLDS

Enforcement: `src-tauri/src/fleet_client.rs:1115` selects the requested row from the account listing. `src-tauri/src/lib.rs:3086` requires a nonempty login-ticket account equal to the listing account and, when recorded, the saved owner. `:3095` fallibly reads the pin for active devices; `:3195` rejects active pinned, missing and unrecognized states. `:3103` rechecks identity after the listing. Failure to read an active device's trust ledger is an error, not an absent pin.

Tests read: `lib.rs:6536`, `:6549`, `:6584`, `:6626`, `:6642`, `:6775`, `:6853`, `:7106`, `:7127`, `:7143`; `custodian_it.rs:1755` checks the real active pinned member before revocation. Positive controls cover genuine pending and active-unpinned devices. The two account fields are independently mismatched in `:7143`; neither changed listing identity nor an omitted account is accepted.

The root-journal problem in R4-D1 does not remove the account check or an independently readable active pin. Its Reset path uses an otherwise allowed pending/revoked listing and violates the additional root exclusion, reported under goal 2.

### Goal 8: root-key loss on connection changes, or stored FKEK deletion — VIOLATED

Normal enforcement: `src-tauri/src/lib.rs:2037` loads root state before changing anything, protects activated roots and unfinished roots with saved create requests, and requires **both** device seeds to be genuinely lost before allowing the exceptional move. `:2049` preserves the config and `:2071` suppresses credential deletion for that exceptional root case. `:2060` propagates errors clearing fleet acks before saving the changed identity. `src-tauri/src/fleet_keys.rs:365` copies the index before removing entries and never calls `credential::forget`; import/Reset preserve stored FKEKs.

Tests read: `lib.rs:6670`, `:6700`, `:7209`, `:7227`, `:7284`; `fleet_keys.rs:501`; `custodian_it.rs:1863`. These verify saved-create root protection, the pre-create exception, corrupt JSON, readable/unavailable/locked versus genuinely lost credentials, durable backups and retained FKEKs.

**R4-D1 remains:** `src-tauri/src/root_bootstrap.rs:1140` turns an error checking existence into a default root state. The connection-change guard then treats a working root as a member, clears its identity and calls `credential::forget` on its two references. The corrupt-JSON regression at `lib.rs:7209` does not cover this earlier failure point. No stored-FKEK deletion path was found in Reset/import.

### Goal 9: honest Team-page actions and visible collect failures — VIOLATED

Working enforcement: `src/features/manage-team/ui/TeamCard.tsx:210` passes the post-import report to `report`; `:252` explicitly reports substitution and `:254` reports failed evidence/opening. The `finally` at `:215` refreshes even when collect failed after import. `TeamDevices.tsx:61` combines saved setup progress with live key status, and `:138` displays blocked/unusable keys. The lost-key branch at `TeamCard.tsx:565` and `:587` excludes loading, unreadable and matching root states from Reset. Backend join-window classification at `src-tauri/src/lib.rs:2915` excludes unfinished roots from Enroll again.

Tests read: `tests/e2e/app.spec.ts:1141`, `:1181`, `:1203`, `:1226`, `:1245`, `:1267`, `:1291`, `:1317`, `:1340`, `:1353`, `:1373`, `:1395`, `:1404`, `:1429`, `:1452`. These have concrete visibility/disabled-state/error assertions. The mock preserves the imported report failure shape; it is UI evidence, not proof of cryptography or real server authorization.

**R4-D2 remains:** the readable-device branch at `TeamCard.tsx:623` checks `boot.activated` without `boot.this_device`. A preserved root journal belonging to the prior device/tenant still selects root controls and hides the new member's join flow. Show devices is enabled after password entry but the backend deterministically returns `fleet.notCustodian`. R4-D1 can also cause root status to be misclassified as absent when its metadata lookup fails.

## Defects

### R4-D1 — Medium — An error checking root-journal existence bypasses root preservation

Locations: `src-tauri/src/root_bootstrap.rs:1138` (especially `:1140`); destructive caller `src-tauri/src/lib.rs:2037`, `:2061`, `:2069`; Reset caller `:3066`, `:3109` and `:3186`.

Concrete scenario: keep a working root custodian's `team.json` and both credential entries readable, but make metadata lookup of `custody-bootstrap.json` fail. An ACL/filesystem error is one case; a deterministic Unix regression can leave a symlink loop at that pathname, so metadata lookup returns a loop error while the sibling `team.json` remains readable. This is a journal-read failure, not a genuinely absent journal. `Path::exists()` suppresses that error and returns false. `load()` returns `BootstrapState::default()` without ever reaching its fallible read/parse. Changing the saved URL or tenant consequently computes `root_custodian = false`, clears the working root identity, saves the new config, and forgets both device credentials with no root backup. The promised fail-closed behavior for unreadable root state is bypassed before the protected branch runs.

The same default state passes both `own_root_state` checks in Reset. With a pending/revoked account listing, Reset succeeds on the root device. That variant retains a config copy and credentials, but still clears a root identity that should be excluded from Reset. This finding is about handling local storage failure; it does not claim a remote server can modify the journal or that the product protects against a hostile local administrator.

Test that catches it: extend the connection-change/root-preservation tests with a root journal for which metadata lookup returns an error, separately from an absent file and corrupt JSON. On Unix, use an isolated symlink-loop fixture; on Windows, use deterministic metadata-failure injection or an ACL fixture. Assert that both URL and tenant changes fail, `team.json` is byte-identical and both credentials still load. Reuse the fixture for Reset with a valid owned pending/revoked listing and require rejection with the current root identity intact. A genuinely missing journal must remain a member positive control. The current `lib.rs:7209` test reaches `read_to_string`/JSON parsing and therefore misses this case. Propagate existence-check errors instead of treating every false result as absence.

### R4-D2 — Low — Another device's root journal still selects root actions for a readable member

Locations: `src/features/manage-team/ui/TeamCard.tsx:479`, `:486`, `:623`, `:645`; `src/features/manage-team/ui/TeamDevices.tsx:157`; backend comparison `src-tauri/src/root_bootstrap.rs:1104` and rejection `src-tauri/src/lib.rs:2692` / `:3419`.

Concrete scenario: use the explicitly supported connection change after both old root-device keys were lost (`lib.rs:7284` tests that allowance), and enroll a fresh member for another tenant on the same local roots. The old root journal is deliberately preserved. On reopening Team, bootstrap status correctly returns `started=true`, `activated=true`, `this_device=false`, and the new device has readable seeds. The lost-key branch is no longer involved. `TeamCard.tsx:623` nevertheless selects `TeamDevices` from `boot.activated`, displays the old anchor, and omits `TeamJoin`. Entering the account password enables Show devices, but `team_devices` always fails because `bootstrap_anchor` requires the journal to match the current tenant and device. Thus the UI offers a known-invalid action and hides the code comparison the honest new member needs. Export is also displayed for the wrong journal, although its missing fingerprint keeps its button disabled.

A related pre-create case uses an unfinished foreign journal retained by the allowed change at `lib.rs:6700`: the bootstrap form offers Resume custody setup even though `root_bootstrap.rs:646` always rejects the different tenant/device journal. This is the same missing ownership classification, not a second security bypass.

Test that catches it: extend the UI fixture with a readable enrolled member and bootstrap status `{started: true, this_device: false, activated: true}` from the old tenant. Assert no root anchor, root device-management controls or export form; assert that the member can show/confirm its own join code and collect normally. Repeat with a foreign unfinished journal and ensure no unusable Resume action is offered. Add a real-state regression that changes a lost root's connection, enrolls a new member, and checks that status reports the ownership mismatch without altering the preserved journal. The backend status unit test at `lib.rs:7054` already checks `this_device=false`; no inspected UI test feeds that state into the readable-device branches. The new field is consumed only in the lost-key branch, so the original D5 reproductions are fixed while this distinct case remains.

## Test-strength audit and limits

The cited rejection tests have concrete error, request-order, file, credential or visibility assertions. The real-server journeys assert key usability, exact bundle contents, grant acknowledgement, state continuity and/or audit counts. There is no empty assertion or silent success return in the cited feature tests. Two exceptions to a literal no-ignore/no-return claim must remain explicit:

- `src-tauri/src/custodian_it.rs:2264` marks the subprocess worker ignored for ordinary discovery. Its non-ignored parent at `:2138` launches it by exact name with `--ignored` and requires successful exit plus `1 passed`; it is not being cited as an unexecuted standalone test.
- `server/tests/identity_authority.rs:230` can return early outside CI when neither symlink nor junction creation succeeds. In CI it asserts failure before returning. The regular directory negative runs before that point, and the link/reparse rejection plus regular-file positive control are at `:239` and `:254`. `src-tauri/tests/fleet_enrollment_it.rs:157` is the readiness helper's successful return, not a skipped feature test; the cited bootstrap test panics if the required server executable is absent at `:647`.

No proposed regression in this report was written or run. Remaining coverage suggestions are identified under their corresponding goals; they are not counted as demonstrated product defects. The closed round-3 cases and successful parent CI do not discharge R4-D1/R4-D2 or the still-pending HEAD jobs.

VERDICT: FAIL
