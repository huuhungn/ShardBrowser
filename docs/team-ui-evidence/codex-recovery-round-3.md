**Independent static verification — recovery round 3**

Verified HEAD: `53246f4b549e0a42e4e8c15811b90450e978f314`.

Comparison: `6bb928d2..53246f4b549e0a42e4e8c15811b90450e978f314`. GitHub reports this SHA as the head of open PR #277, branch `fix/recovery-r2`. The worktree was clean before this report. This report is the only file written. No source was changed, no build or test was run, and no server was started.

The normative sources were ADR 0002's Q-12 and Q-13 decision-table rows (lines 134 and 135), D-5 (line 885, including the plaintext-v3 amendment at line 1022), D-9 (line 1370), ADR 0004, `docs/key-custody.md`, and the master-design excerpts supplied in the request. Implementation and test dependencies were followed where needed. No author plan, earlier verification report, `.omc/`, `.omx/`, or scratch directory was read. Automatically supplied historical review memories were not used as evidence. Rotation's absence is not a finding.

HOLDS below means the inspected implementation enforces the stated goal under the shipped custody model; it is a static conclusion, not a claim of a locally executed attack test. VIOLATED identifies a concrete reachable code path. The documented limits remain relevant: possessing a v3 bundle and its passphrase already gives the root-device identity; revocation does not retract copied keys; legacy plaintext/DPAPI storage and arbitrary re-encoding of secrets by a hostile server have the limits stated in `docs/key-custody.md:376` and `docs/key-custody.md:416`.

**CI evidence**

Observation at approximately `2026-11-07T04:44:54Z`, using the requested read-only commands:

- `gh pr checks 277 --repo huuhungn/ShardBrowser`: run [42339012483](https://github.com/huuhungn/ShardBrowser/actions/runs/42339012483), independently matched to the verified HEAD with `gh run view`. Launcher/server/shared MSRV **pass** (4m40s); Rust SDK stable/MSRV **pass** (4m9s); macOS compilation **pass** (1m4s); Windows Rust tests **pending**; frontend/Rust/MCP checks **pending**. The run was `in_progress`, with no overall conclusion.
- `gh run list --repo huuhungn/ShardBrowser --branch main --limit 5`: all five returned runs were completed successfully: [42331556904](https://github.com/huuhungn/ShardBrowser/actions/runs/42331556904), [42309376818](https://github.com/huuhungn/ShardBrowser/actions/runs/42309376818), [42302647566](https://github.com/huuhungn/ShardBrowser/actions/runs/42302647566), [42295080966](https://github.com/huuhungn/ShardBrowser/actions/runs/42295080966), and [42295067697](https://github.com/huuhungn/ShardBrowser/actions/runs/42295067697).
- The newest main run is for `3c38057a95e9cb272f048a22296a949d07bac007`; its success is parent evidence, not a successful run of HEAD. CI wiring includes shared/server/launcher tests at `.github/workflows/ci.yml:111`, `:114`, `:120`, `:331`, `:334`, and `:342`, and frontend E2E at `:236`.

**Goal 1 — tenant, account, instance, device status and key-ID isolation: VIOLATED**

Enforcement: `src-tauri/src/recovery_import.rs:131` rejects another saved tenant and a conflicting local device identity; `:158` checks the existing tenant anchor; `:169` checks the listing's instance, account, active status and both derived key IDs. `:309` opens a device session and `:202` requires the exact acknowledged self-grant under an active root generation, opened to the bundle TRK. The public entry point at `:244` calls the shared authenticated bundle reader before these steps. Session proof checks are in `src-tauri/src/fleet_client.rs:520`.

Tests read: `src-tauri/src/recovery_import.rs:776` (HPKE-ID mismatch), `:786` (other instance), `:799` (revoked row, signing-ID mismatch, other listed account), `:934` (other tenant/identity), `:1154` (other anchor), `:867` and `:1182` (generation/grant state). Full-command real-server negatives are at `src-tauri/src/custodian_it.rs:1636`; session-binding field mutations are at `src-tauri/src/fleet_client.rs:1941`.

Gap/defect: these import tests change the account in `/v2/me`, not the login ticket while leaving `/v2/me` consistent with the bundle. Import ignores `ticket_account_id`, and its second login/session is not bound back to the bundle's account or instance. Finding D1 describes the accepting path and test.

**Goal 2 — preserve a working identity and the root custodian: VIOLATED**

Enforcement: import's identity check is `src-tauri/src/recovery_import.rs:144`; its pre-write configuration comparison and root/custody-state checks are at `:383`, `:393`, and `:403`. Reset checks for a matching root state before networking and again after the response at `src-tauri/src/lib.rs:3061` and `:3108`; it re-reads the configuration at `:3102`. A row reported revoked or either unreadable seed triggers a configuration backup and retains credentials at `:3114`. Identity clearing and conditional credential deletion occur at `:3129` and `:3131`.

Tests read: `src-tauri/src/recovery_import.rs:934`, `:987`, `:1017`, and `:1134`; `src-tauri/src/lib.rs:6397`, `:6482`, `:6506`, `:6838`, and `:6928`; root-device recovery on its original roots at `src-tauri/src/custodian_it.rs:1934`. The race tests independently cover a changed team identity and a changed root state during the listing. The revoked-row test asserts both original credentials remain readable and a backup exists.

The specific false-**revoked** branch preserves the credentials, and the inspected root guard holds. However, a false **pending** listing clears an already working member identity and deletes both readable credentials without a backup. This satisfies the broader working-identity attack in this goal; see D2. Existing tests authorize a genuinely pending pinned joiner, but do not distinguish it from a previously working device downgraded by the server's reply.

**Goal 3 — internally inconsistent v3 custodian block: HOLDS**

Enforcement: `shared/src/recovery_bundle.rs:291` verifies the self-grant signature with the seed-derived signing key, the anchor ID, first-self-grant variant, tenant, instance, account, device, root generation and root key ID, and HPKE opening to the bundle TRK. Closed-map/domain/version handling is at `:391`; TRK/FKEK identifiers and ordering are checked at `:413`; the public opener invokes the custodian check at `:593`. Import always opens the file through that reader at `src-tauri/src/recovery_import.rs:260`.

Tests read: `shared/src/recovery_bundle.rs:777`, `:827`, `:902`, `:918`, `:1056`, and the self-grant size-bound cases at `:1265`; full import rejection before any request or state write at `src-tauri/src/recovery_import.rs:1223`. The mutation cases include another signing seed, account, device, tenant, instance, root key, root generation, wrong HPKE seed, wrong anchor, non-record data and the wrong grant variant. Assertions check the particular mismatch or format error, not merely successful parsing.

Additional useful coverage: a separately corrupted signature and an altered subject-signing-key ID through the full import entry point, asserting no requests and unchanged state. The inspected checks already reject them; this is coverage expansion, not a demonstrated defect.

**Goal 4 — 2.7.x opening/resume, step-3 upgrade and preserving an openable export: HOLDS**

Enforcement: shared opening dispatches v2/v3 at `shared/src/recovery_bundle.rs:394`, without imposing the new-export passphrase minimum on opening (`:457`, `:505`, `:562`). `src-tauri/src/root_bootstrap.rs:411` accepts the already pinned v2 file, while `:431` and `:783` require an unpinned reusable bundle to carry this device and its exact self-grant as v3. Export at `:366` verifies opening and the synthetic readiness probe before replacing the destination and then compares final-path readback bytes exactly (`:400`). `shared/src/recovery_bundle.rs:612` implements that verification/probe. The write uses the synced sibling/replace path in `src-tauri/src/durable.rs:17`.

Tests read: the fixed 2.7 encoder fixture is consumed and compared byte-for-byte in `shared/src/recovery_bundle.rs:812`; authentication mutations are at `:1009`. `src-tauri/src/root_bootstrap.rs:1488` starts with a genuinely openable older bundle and verifies it remains identical and openable after a rejected export; `:1448`, `:1582`, `:1644`, and `:1686` cover write/open failures, readback, v3 reuse and pinned v2 activation. `src-tauri/src/custodian_it.rs:1971` exercises both sides of server create with real command resumption and asserts exactly one root generation. `src-tauri/tests/fleet_enrollment_it.rs:642` exercises save failures, missing bundle, activation replay and the v3 device/account block.

Remaining coverage: no feature-specific injected final-path read failure after a successful replacement was found; the existing missing-directory/directory-destination test fails earlier. The implementation still returns failure on unequal or failed readback. D4 below is a separate export-availability/completeness defect, not acceptance of an unopenable replacement.

**Goal 5 — secrets in state, IPC, logs or errors: VIOLATED**

Enforcement: import stores seeds through readback-verified credentials at `src-tauri/src/recovery_import.rs:473` and writes only references at `:484`; bootstrap state skips serialization of the legacy TRK at `src-tauri/src/root_bootstrap.rs:110`. Credential readback is `src-tauri/src/credential.rs:99`; protected config serialization is `src-tauri/src/team_config.rs:331`. Redacted debug views include `shared/src/recovery_bundle.rs:245` and `:334`. Import logs use error codes at `src-tauri/src/recovery_import.rs:61`; IPC collect reports counts at `src-tauri/src/lib.rs:3652`. Client refusal sanitization is `src-tauri/src/fleet_client.rs:268`, `:279`, `:360`, and `:427`, with sync refusals routed through `src-tauri/src/team/sync.rs:819`.

Tests read: `src-tauri/src/custodian_it.rs:2138` and its worker at `:2265`; `src-tauri/src/recovery_import.rs:697`, `:756`, and `:1262`; `src-tauri/src/fleet_client.rs:2027`, `:2083`, `:2167`, `:2177`, `:2215`, `:2280`, `:2292`, `:2310`, and `:2324`; `src-tauri/src/team/sync.rs:5775`; `src-tauri/src/fleet_custody.rs:1751`. These test ordinary output/state and refusal echoes. They do not cover a successful JSON root-grant response that triggers the unsafe UTF-8 slicing in the separate `hex_bytes` decoder. That produces an unsanitized panic diagnostic containing literal server-supplied secret text; see D3.

Coverage qualification: `keep_state` at `src-tauri/src/custodian_it.rs:2245` copies team, root-bootstrap and fleet-custody JSON, but not `fleet-keys.json` or the trust database. The leak scan should explicitly include those artifacts, their backups created during Reset/import, and the Reset journey. This omission is not itself evidence that those files leak keys.

**Goal 6 — collect after Reset/import and verification of fleet keys: HOLDS**

Enforcement: Reset removes stale acknowledgement requests at `src-tauri/src/lib.rs:3128`; import replaces member custody or retains only matching own-grant acknowledgements at `src-tauri/src/recovery_import.rs:429` and `:453`. Both call `src-tauri/src/fleet_keys.rs:322` to back up and unindex unopenable entries, while preserving locked-file entries and stored credentials. Collection checks the pinned trust chain, recipient, fleet, generation and opened key at `src-tauri/src/lib.rs:3267` and `:3437`, then prevents replacement of a readable different key at `src-tauri/src/fleet_keys.rs:234`. Acknowledgements bind the exact grant and checked response at `src-tauri/src/fleet_custody.rs:589`. Export selects verified generations at `src-tauri/src/fleet_keys.rs:264` and requires the active generation at `src-tauri/src/root_bootstrap.rs:1011`.

Tests read: `src-tauri/src/custodian_it.rs:1422`, `:1695`, `:1755` (called by tests `:1856` and `:1863`), and `:1934`; `src-tauri/src/recovery_import.rs:1017`; `src-tauri/src/fleet_keys.rs:492` and `:567`; `src-tauri/src/lib.rs:4004` and `:4097`; `src-tauri/src/root_bootstrap.rs:1521`. They assert a kept key, successful own-grant acknowledgement and usable status, not just that the command returned.

No new unverified FKEK acceptance or erroneous stale-ack/substitution path was established for the documented missing/unavailable-key recovery cases. A deliberately different readable cached key must still produce substitution. The documented legacy 2.4.2 cache exception is not treated as new unverified acceptance. There is, however, a missing promotion of an equal legacy key after successful verification, which makes Export stay broken (D4). That is classified under goal 9 and the export contract rather than as an unverified-key export.

**Goal 7 — Reset ownership and an active pinned row: HOLDS**

Enforcement: `src-tauri/src/lib.rs:3087` requires a nonempty ticket account equal to the listing account and, when recorded, the saved owner. The device is selected by its exact ID from that account's listing at `src-tauri/src/fleet_client.rs:1089`. `src-tauri/src/lib.rs:3095` reads the pin fallibly; `:3182` rejects a server-listed active pinned row and an unlisted row. Unlike import, Reset uses the ticket's account identity.

Tests read: `src-tauri/src/lib.rs:6521`, `:6534`, `:6569`, `:6611`, `:6627`, and `:6838`; the real-server pre-revocation refusal at `src-tauri/src/custodian_it.rs:1767`; UI refusal at `tests/e2e/app.spec.ts:1317`. The missing-owner and unreadable-ledger cases assert refusal plus preserved credentials/configuration. A legacy config with no account is accepted only when ticket and listing agree. D2 changes the reported status to pending; it does not bypass this goal's active-row branch.

**Goal 8 — root keys across connection changes; stored fleet-key preservation: HOLDS**

Enforcement: `src-tauri/src/lib.rs:2037` loads root state fallibly and treats activation or a saved create request for this identity as root custody. A connection change is rejected unless both seeds are specifically lost (`:2043` and `src-tauri/src/team_config.rs:172`); the allowed lost-key case backs up `team.json` and excludes credential deletion (`src-tauri/src/lib.rs:2049`, `:2071`). Corrupt fleet-custody state also stops acknowledgement clearing before saving the new configuration (`src-tauri/src/fleet_custody.rs:1209`). Reset/import fleet unindexing at `src-tauri/src/fleet_keys.rs:322` copies the original index and removes references only; it never calls credential deletion.

Tests read: `src-tauri/src/lib.rs:6655`, `:6685`, `:6983`, `:7001`, and `:7058`; `src-tauri/src/fleet_keys.rs:492`; unavailable-store Reset journey at `src-tauri/src/custodian_it.rs:1863`. Tests cover URL and tenant changes, unfinished create state, corrupt root JSON, readable/missing/unavailable/locked/foreign-DPAPI seeds, backup creation and credential retention. The documented exception for both lost root seeds preserves their references in the backup and is not a violation.

Additional coverage needed: a corrupt `fleet-custody.json` on both Reset and connection-change paths, asserting unchanged team identity and no credential deletion even if fleet unindexing has already copied/changed its index. The current loaders fail closed, but a dedicated assertion for this ordering was not found in the reviewed feature tests.

**Goal 9 — honest recovery UI and executable actions: VIOLATED**

Enforcement: `src/features/manage-team/ui/TeamCard.tsx:200` forwards the import's collect report and refreshes status even on a post-import failure; `:230` reports substitution before failure before waiting. Root/lost/unreadable-state branching is at `:540` and `:582`; export requires a usable/blocked verified fleet key, root-key fingerprint acknowledgement and login inputs at `:677`. `src/features/manage-team/ui/TeamDevices.tsx:59` combines local custody progress with live key usability instead of claiming readiness from progress alone.

Tests read: `tests/e2e/app.spec.ts:1141`, `:1158`, `:1181`, `:1203`, `:1226`, `:1245`, `:1267`, `:1291`, `:1317`, `:1332`, `:1340`, `:1353`, `:1373`, and `:1395`. Substitution and failed-evidence reports remain visible. These are UI tests through `src/e2e-mock.ts:490`, not real backend cryptographic evidence.

Two remaining classes are uncovered: a verified legacy cached key makes Export enabled but permanently refused (D4), and root-device exclusions are incomplete while root status is loading or a readable bootstrap is unfinished (D5). The stable loaded lost-root and unreadable-root cases in the existing tests do not exercise those states.

**Defects**

**D1 — Medium — Import does not bind authentication context back to the bundle.**

Locations: `src-tauri/src/recovery_import.rs:182`, `:295`, `:312`; `src-tauri/src/fleet_client.rs:1088`, `:548`.

Concrete scenario: use a valid bundle for account A and instance S. Have the login reply name account B, while `/v2/me` names A and lists the bundle device active with its actual key IDs. `account_device_status` returns both account IDs, but `check_listing` checks only `me.account_id`. For the second login, return a valid session challenge naming B and the bundle's public keys; the session validator checks against that second ticket, not A. A responding server can return the exact original self-grant as acknowledged/active and an active-generation reply; import then writes the identity for A. The same split exists for the second session's instance. No seed, signature or bundle forgery is needed: the server has the public keys and the original grant, and the importing client supplies proof with the bundle keys.

This is acceptance of contradictory authentication/bundle bindings, not a claim that the account password adds a security factor or that the honest server grants B access. The honest-server case is rejected upstream. The client-side check promised by goal 1 is missing for an adversarial/inconsistent server response.

Test that catches it: extend the import mock fixture with independent login-ticket and `/v2/me` account/instance fields. Keep the bundle and listing valid, change only the ticket account, and assert `recovery.otherAccount`, no session challenge and no state/credential writes. Also vary only the second login's account or instance and require failure before a proof/import commit. Current tests at `recovery_import.rs:799` vary the listing account instead.

**D2 — Medium — A false pending listing deletes a working member's credentials.**

Locations: `src-tauri/src/lib.rs:3094`, `:3114`, `:3131`, `:3184`.

Concrete scenario: an active, pinned member has readable signing/HPKE credentials and has already collected its verified fleet key. During Reset, the server returns the correct account/device identifiers but reports `pending`. Pending is allowed even with a pin. Because both seeds read and status is not `revoked`, `keep` is false: no `team.json` backup is made, the identity is cleared and both credentials are forgotten. This is the same unsigned-status downgrade threat the revoked branch explicitly handles, with a different status value. A legitimate pending joiner can still be allowed to reset without making an untrusted status sufficient for permanent credential deletion.

Test that catches it: extend the real member fixture or Reset mock with an already approved/collected member and a pending-only listing override. Assert either refusal with byte-identical config/credentials, or a durable original-config backup with both credentials retained. Keep the genuine pending-joiner positive control. `src-tauri/src/lib.rs:6888` currently tests a genuinely pending pinned device; `:6928` checks retention only when the reply says revoked.

**D3 — Medium — Successful root-grant JSON can leak a literal token/password through a UTF-8 slicing panic.**

Locations: `src-tauri/src/lib.rs:3712` (fault), `:3661` (caller), `:3231` (collect path), `:3164` (post-import collect); `src-tauri/src/fleet_client.rs:1255`, `:1837`.

Concrete scenario: during the collect following import, the server returns HTTP 200 with a syntactically valid `RootKeyGrant` whose `hpke_info_hex` is an even-byte-length string beginning with the three-byte character U+20AC followed by one ASCII character, then the literal access token received in the request. With a normal 64-hex-digit token body the total byte length is even. The server can return no active fleet generation so collection reaches `custody_report` directly. `hex_bytes` checks only byte-length parity; its first `s[0..2]` slice ends inside U+20AC and panics. Rust's default string-slice panic diagnostic includes the offending string, hence the literal token. A suitably padded literal account-password echo has the same path. No custom production panic-redaction hook was found in the launcher sources.

The failure bypasses `FleetClient::hide`, because those checks handle refusal responses, not these successful JSON fields. This does not rely on an unknown encoding of the secret: the secret itself is literal, after the malformed prefix. The decoder predates the feature, but the newly shipped post-import collect reaches it and goal 5 explicitly covers its error paths.

Test that catches it: a subprocess leak test should drive `team_collect_custody` and post-import collect with each of the three root-grant hex fields containing a multibyte boundary plus a generated token/password sentinel. Require a normal structured error, no panic, no sentinel in stderr/stdout/IPC, and correct session cleanup. A direct decoder regression should cover all even-length non-ASCII inputs. `src-tauri/src/fleet_client.rs:2106` tests a different, hardened hex decoder; it does not protect `lib.rs:3707`.

**D4 — Medium — A legacy key successfully verified by collect is never marked verified for export.**

Locations: `src-tauri/src/fleet_keys.rs:243`, `:273`; `src-tauri/src/root_bootstrap.rs:1014`; `src/features/manage-team/ui/TeamCard.tsx:677`.

Concrete scenario: the local index has a readable generation-0 key from the legacy cache, with no entry in `verified`. It is the same FKEK that the valid current device grant opens. Import/Reset correctly preserves that readable key. The follow-up collect verifies the grant and records it in the trust ledger (`src-tauri/src/lib.rs:3468`), but `fleet_keys::collect` takes its equal-existing-key early return before `verified.insert`. It reports the key opened and acknowledges the grant. Live Team status can now report `has_fleet_key` because `src-tauri/src/team/sync.rs:1685` verifies the cached bytes against the ledger independently of the index marker. Export becomes enabled, yet `verified_keys` omits generation 0 and `export_again` always returns `fleet.recoveryExportNeedsFleetKey`. Repeated collect does not repair the marker. This also leaves legacy pull treating the now-verified key as exempt from re-verification (`fleet_keys.rs:105`).

Test that catches it: seed a legacy unmarked generation 0 with the exact key in a valid grant, then run import/collect through the real fixture. Assert that the marker is persisted, live status is usable, export succeeds, and the opened v3 bundle contains the key. Add an equal-key promotion unit case beside `fleet_keys.rs:567`, plus a different-key control that still refuses substitution. Its current test manually marks the keys verified and therefore misses the promotion path.

**D5 — Low — Root-device UI exclusions miss loading and readable unfinished-bootstrap states.**

Locations: `src/features/manage-team/ui/TeamCard.tsx:63`, `:80`, `:582`, `:633`; `src/features/manage-team/ui/TeamJoin.tsx:54`, `:126`; `src-tauri/src/lib.rs:2928`, `:3067`.

Concrete scenarios:

1. On page mount, let `team_status` resolve for a root device with missing credentials while `team_custody_bootstrap_status` is still pending. `boot` is null and `bootUnreadable` is false, so the lost-key branch treats it as a member and displays Reset. The username/password inputs are also displayed, so a delayed status response permits an enabled Reset. The backend root check rejects it. The UI must treat unknown root status as unknown, rather than as no root state.
2. An unfinished root bootstrap with readable credentials, no usable fleet key and an expired enrollment window renders `TeamJoin`. If the server reports pending, or active with no local pin, `team_join_code` returns ordinary `fleet.joinCodeExpired` because it checks status/pin but not root state. `TeamJoin` offers Enroll again, which calls the Reset backend. That backend always rejects a matching root state, including unfinished state. This path persists after all status requests finish.

Tests that catch them: delay the bootstrap-status promise in the lost-root UI fixture and assert no Reset at every intermediate render, then resolve/reject it and assert the appropriate import/error UI. Separately supply `started=true`, `activated=false`, readable keys and an expired window; exercise Show join code and assert no Enroll again. Add a backend classification test that a saved root setup never yields the reset-offering expiry code. Existing `tests/e2e/app.spec.ts:1373` uses lost keys, so it never enters the readable `TeamJoin` branch. The mock Reset guard at `src/e2e-mock.ts:485` checks only `activated`, whereas the real backend checks matching root state regardless of activation; that fixture also needs parity for the new test to be meaningful.

**Test-strength audit and remaining evidence limits**

The cited rejection tests have concrete error/state/credential assertions; the integration journeys assert key usability, identity continuity, grant acknowledgements and/or server audit counts. No empty assertion or silently skipped cited recovery test was found. UI tests assert rendered outcomes and use a mock; they do not establish cryptographic acceptance.

There are two explicit qualifications to a literal claim of “no ignore or early return”:

- `src-tauri/src/custodian_it.rs:2264` marks the leak worker ignored. This is not an unexecuted evidence claim: the ordinary test at `:2138` launches that exact worker with `--ignored`, requires successful termination and `1 passed`, checks the secret count and expected artifact names, and scans its output. The parent is not ignored.
- `server/tests/identity_authority.rs:230` still returns early if neither a symlink nor a junction can be created outside CI. Under CI it asserts failure before that return; successful symlink/junction setup must reach the actual rejection and regular-file positive-control assertions at `:239` and `:254`. `src-tauri/tests/fleet_enrollment_it.rs:157` is a successful readiness-helper return, not a skipped test; the bootstrap test explicitly panics if its server executable is absent at `:647`.

The existing leak harness omits fleet-key index/backups and malformed-success panic cases; the v3 full-import negative uses one custodian mutation while the shared reader covers the broader matrix; final-path read-failure injection and corrupt fleet-custody ordering deserve the additional cases noted above. None of the proposed regressions was written or executed in this read-only round. Pending HEAD CI is not represented as a pass. The verdict is FAIL because of the static defects, independently of the remaining CI outcomes.

VERDICT: FAIL
