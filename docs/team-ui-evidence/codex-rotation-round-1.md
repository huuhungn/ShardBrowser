# Independent verification — fleet key rotation, round 1

Verified HEAD: `48194687c58e3a7f730c05c5352ffde7b6eac3cf`

Comparison: `git diff 9616035a..HEAD`. Review date: 2026-11-08.

This is a static, read-only verification of implementation and test source. No builds, test commands, package managers, browsers, or servers were run. The only worktree write is this requested report. No author plans, earlier review reports, `.omc/`, `.omx/`, or scratch directories were consulted. The contract is the specified portions of ADR 0002, `docs/key-custody.md`, and the master-design quotations supplied in the request. Root rotation and moving root custody are excluded.

`HOLDS` below means no successful attack was found in the inspected paths; it is not a claim that tests were executed locally. Tests cited were read, including their assertions and relevant fixtures. Defects are established by source-level control/data flow; proposed regression tests were not executed.

## CI evidence

Read-only `gh pr list --repo huuhungn/ShardBrowser --state all --limit 8` returned PRs 283 through 276. PR 283 was OPEN; 282–276 were MERGED. `gh pr checks` was queried for 280, 281, 282, and 283.

| PR | Observed check state | Evidence |
| --- | --- | --- |
| 280 | All five reported checks passed | [Run 42473047849](https://github.com/huuhungn/ShardBrowser/actions/runs/42473047849) |
| 281 | All five reported checks passed | [Run 42474190546](https://github.com/huuhungn/ShardBrowser/actions/runs/42474190546) |
| 282 | All five reported checks passed | [Run 42480895161](https://github.com/huuhungn/ShardBrowser/actions/runs/42480895161) |
| 283 | Latest observation: SDK stable/MSRV, macOS compilation, launcher/server/shared MSRV, and frontend/Rust/MCP checks passed; Windows Rust tests pending | [Run 42485023089](https://github.com/huuhungn/ShardBrowser/actions/runs/42485023089) |

PR 283's `headRefOid` was `45bc0c8f3fc817228114d935e7f9958d609be628`, not the verified HEAD. These results are evidence for the named PR revisions, not a green exact-HEAD result for this six-story worktree. Initially the frontend/Rust/MCP check on 283 was also pending; it passed on the second query. No check failure was observed.

## Results by attack goal

### 1. N+1 only reaches an eligible, exactly approved recipient — VIOLATED

Normal enforcement is substantial:

- `src-tauri/src/fleet_custody.rs:932` derives signing/HPKE IDs from public keys; `:1933` verifies a saved approval's signature, exact account/device/key IDs, scope, and window.
- `src-tauri/src/fleet_custody.rs:2017` fetches fresh signer-specific evidence; `:2025` excludes local/reported revocations and withdrawn signers; `:2030` requires exact saved or chain approval. `shared/src/trust_chain.rs:521` implements `approves_keys`.
- `src-tauri/src/lib.rs:2959` requires the server's ACTIVE generation to match a locally verified key and ledger maximum at Start. Collection validates descriptors, recipient, chain, opening, and expected generation at `:3531`, `:3570`, `:3600`, and `:3716`.
- The unchanged server also checks exact active subject keys and approval at `server/src/routes/v2_fleet.rs:893` and `:914`. That does not protect a grant ciphertext already transmitted to a hostile server.

The approval-resume path bypasses recipient withdrawal checks once its rebuilt grant already names ACTIVE. See **F1 (High)**.

Tests: `src-tauri/src/fleet_custody.rs:4759`, `:4778`, `:4788`, `:4798` cover invalid Start prerequisites; `:5114` expired approval; `:5139` evidence batching; `:5179` revoked active listing; `:5198` substituted HPKE key; `:5228` approval from chain; `:5407` failed evidence; `:5573` approval resumed across rotation; `:5606` revoked approval before rebuilding; `:5629` existing member result; `:5645` substituted key during rebuild. `shared/src/trust_chain.rs:1064` tests exact identity/scope/window. `src-tauri/src/lib.rs:4284` tests collection identity and key validation. `src-tauri/src/custodian_it.rs:1369`, particularly `:1574`, exercises an honest real server granting B but excluding revoked C.

Missing coverage: revocation **after** a rebuilt N+1 filing is saved but before its first transmission; independently persisted recipient withdrawal with no saved rotation member result. F1 describes the catching tests.

### 2. Crash, replay, key custody, and completion/abandonment — VIOLATED

Core replay protections: `src-tauri/src/fleet_custody.rs:209` persists a nonce before credential storage, reuses an already stored key, and rejects replacement when a saved key ID names a missing key; `:241` retries credential deletion before clearing its reference. Preparation at `:467` and `:546` saves signed containers and mutation envelopes before sending. `:1638` restarts pre-step-4 state after an epoch change; `:1712` prevents rebuilding saved rotation requests. `:1772` and `:1819` validate exact replay replies. `:1872` demands a matching activation replay after alleged N+1 ACTIVE. `:1892`, `:1907`, and `:1919` handle release/phase transitions. The custody lock is `:2106`, held by `src-tauri/src/lib.rs:2941`; release and verified collection precede Activated at `:2993`.

Server response replay precedes normal mutation checks at `server/src/routes/v2_fleet.rs:351`, `:758`, and `:1475`. Required acknowledgements, activation, and retirement are in the transaction at `:1533` through `:1665`.

The backend permits Start after expired when N+1 never landed, but the UI disables that action unconditionally. See **F2 (Medium)**. This exceeds the accepted limitation of a generation actually still PREPARING on the server.

Tests: `src-tauri/src/fleet_custody.rs:4538` checks the distinct new key and all grant terms; `:4642` failed preparation saves and identical replay; `:4703` stored-key reuse after failed ID save; `:4831` expiry cleanup/approval resumption; `:4878` lost activation reply; `:4980` preparing across restore; `:4996` pre-step-4 restore restart; `:5035` Start after a create that never landed; `:5423` member replay; `:5444` unfinished resume; `:5482` approval phase gate. `src-tauri/src/custodian_it.rs:1369`, including `:1437`, tests the real-server saved-create interruption and completion with one N+1, N retired, setup key gone, and both generations retained. The UI test `tests/e2e/app.spec.ts:839` explicitly asserts the incorrect disabled state.

Coverage gaps: the failed-save loop covers preparation checkpoints, not every member/Done/credential-clear/collection save. Add lost replies after server commit for create, each filing, and each acknowledgement, plus failure between credential deletion and state save. Also test a same-epoch permanent refusal of the saved S0 before step 4: `:1707` returns before deadline-based expiry and that state has no deadline. The current restore test does not establish a way out of that case; it is an unresolved coverage question, not a separate confirmed defect here.

### 3. Server-based expiry and retryable refusals — VIOLATED

At invocation time, `src-tauri/src/fleet_custody.rs:1653` routes past-deadline or changed-epoch state through the server ACTIVE read. Filing/ack 403 handling is at `:1748`; incomplete activation stays retryable at `:1763`. `:1853` checks ACTIVE, requires matching activation replay for N+1, preserves unknown state, and preserves an early 403 before the clock-tolerance boundary. Setup release follows the resulting successful/terminal path, not local time alone.

However, the timestamp is captured once and remains stale over awaits. Crossing the deadline during the invocation permits mutations without the required intervening ACTIVE read. See **F3 (Medium)**.

Tests: `src-tauri/src/fleet_custody.rs:4855` already-past-deadline invocation; `:4878` lost activation response; `:4934` near-deadline 403; `:4949` early 403 preserves Preparing/key; `:4962` unexpected ACTIVE preserves bytes; `:4980` restore; `:5068` incomplete activation remains resumable. All use a fixed invocation time and miss F3's crossing-during-await scenario. The near-deadline 403 behavior itself follows ADR `docs/adr/0002-g2-contract-decisions.md:1516` and is not reported as a defect.

### 4. Transient member-grant failure remains resumable — HOLDS

`src-tauri/src/fleet_custody.rs:1458` parses the structured refusal marker; `:1473` excludes 401, 408, and 429 from permanent 4xx refusal classification. Evidence failure propagates at `:2017`. A member filing is saved before sending at `:2061`; only a permanent refusal records `refused` at `:2072`. Other errors return while Activated. Results and Done are committed after processing completes at `:2082`. Transport/evidence errors propagate through `src-tauri/src/fleet_client.rs:709` and `:891`.

Tests: `src-tauri/src/fleet_custody.rs:5259` records permanent refusal/counts; `:5407` evidence 503 leaves Activated and no filing/results; `:5423` filing 503 retains and replays the exact filing, then completes.

Missing tests: table-driven 401/408/429, an actual connection reset/timeout, malformed success reply, and failure on a second member after the first succeeds. Assert no premature Done/refused and byte-identical replay. The test named transport failure injects HTTP 503 rather than dropping the connection; its assertions are meaningful but its coverage is narrower than the name suggests.

### 5. Older-generation reads and newest-generation seals — HOLDS

`src-tauri/src/team/sync.rs:1727` selects the requested read key and re-verifies its grant. `src-tauri/src/lib.rs:3789` checks exact stored record bytes (`:3809`), issuer withdrawal (`:3817`), ledger evaluation and grant validity (`:3820`); `shared/src/trust_chain.rs:640` validates recipient, generation, window, and authority. Pull calls this read-only path at `src-tauri/src/team/sync.rs:4907` and `:4941`. Revert reads P at `:2297` but seals through `push_inner`/`seal_snapshot` at `:2310` and `:3113`. Sealing uses `verified_key` at `:1683`, rejecting a generation below the ledger maximum maintained at `src-tauri/src/team/ledger.rs:1051`. Server upload/commit ACTIVE checks remain at `server/src/routes/v2_uploads.rs:368` and `:1217`. IPC callers are `src-tauri/src/sync_cmd.rs:109`, `:205`, and `:359`.

Tests: `src-tauri/src/team/sync.rs:11515` older-head pull; `:11530` first joined pull; `:11760` tampered old grant refuses without pin/output; `:11784` expired old grant; `:11817` missing old key; `:11834` old-generation push refuses/releases without upload; `:11850` newest-generation push; `:11676` older P/newest R; `:13201` retired revert upload abandoned and next revert uses newest. `src-tauri/src/lib.rs:5548` verifies issuer revocation/distrust removes key usability.

Coverage additions: directly revoke/distrust the issuer of an old-generation published head, rather than relying on the shared verifier test; exercise an explicitly stale checkout in revert and assert no upload. No implementation failure was established in these paths.

### 6. Per-profile generation floor and exemptions — HOLDS

`src-tauri/src/team/sync.rs:4462` applies the floor only to Advance/Accept using the actual anchor manifest. The pinned-head branch at `:4324`, withdrawn-pin search at `:4365`, and Join at `:4473` are exempt; no anchor means no floor (`:4465`). Accepted heads replace the anchor at `:4474` and `:4482`. Walk completes before restore (`:4897`); `restore_then_pin` stages at `:4749` and the pin transaction conditionally checks the original binding at `:4676`.

Tests: `src-tauri/src/team/sync.rs:11588` rejects decreasing Advance without pin/output; `:11612` rejects decreasing accepted R; `:11638` demonstrates the accepted wedge until a lower-generation head is revoked and can Join; `:11676` searches below a withdrawn pin for older P; `:11708` takes the floor from the transition anchor manifest rather than a stale binding column; `:11530` covers no anchor.

Additional coverage: explicitly test a reported-only signer with a decreasing-generation head to demonstrate that floor exemption and the existing reported/proven distinction interact as specified. No defect was found.

### 7. Pull and push preserves local work, stops on pull failure, and lists the right profiles — VIOLATED

`src/features/manage-team/ui/TeamDevices.tsx:140` attempts push first and only falls back on `sync.remoteAhead`; an exception from pull prevents the subsequent push (`:147`). API mappings are `src/entities/team/model/api.ts:188` and `:192`; IPC guards are `src-tauri/src/sync_cmd.rs:109` and `:359`. Backend older-key enumeration at `src-tauri/src/team/sync.rs:255` filters tenant/server, excludes version-zero rows, and compares the recorded head generation with that fleet's ledger maximum.

The fallback does not distinguish a stale clean copy from a stale copy with unpushed changes. Pull rejects a held lease/pending operation, but not unpushed local contents. See **F4 (High)**. The rendered list also stays stale after an ordinary Check in or Unbind outside this component; see **F5 (Low)**.

Tests: `src-tauri/src/team/sync.rs:11544` checks older-key list inclusion/exclusion and version zero; `:11572` proves a clean push re-seals and removes the backend row. `tests/e2e/app.spec.ts:861` covers the two-device flow; `:898` asserts a refused pull leaves the row and does not push; `:907` covers a clean behind copy; `:935` covers avoiding pull when already current. These mock scenarios do not contain different unpushed local content when the remote is ahead, and refresh the list through its own repush/rotate actions rather than an ordinary Check in.

### 8. Locally justified banner and completed-export prompt — VIOLATED

The ordinary banner path is local: `src-tauri/src/lib.rs:2678` uses the pinned context, local ledger maximum and holdings; `src-tauri/src/fleet_custody.rs:1304` combines saved revocations with saved grants/results or ledger holdings and takes the most urgent tier. A malformed saved revocation for a known saved holder is urgent (`:1331`). The UI renders its tier at `src/features/manage-team/ui/TeamDevices.tsx:225` and refreshes after Revoke at `:188`.

Rotation completion sets `export_due` at `src-tauri/src/fleet_custody.rs:2083`. Successful export computes the highest generation actually included and invokes `exported` at `src-tauri/src/lib.rs:2631` and `:2650`. `src-tauri/src/fleet_custody.rs:1344` normally clears the prompt only if that export covers the rotation. However, an unrelated concurrent custody operation makes the notification disappear silently, leaving the prompt set despite a sufficient successful export. See **F6 (Low)**.

Tests: `src-tauri/src/fleet_custody.rs:5328` routine banner/clear; `:5352` urgent priority, ledger holder, malformed revocation; `:5381` no banner for a device without the current key; `:5391` old export keeps/new export clears. `tests/e2e/app.spec.ts:773`, including `:807`, covers revoke tiers, rotation, and successful export. No cited test holds the custody lock during the export completion callback. Banner command errors currently yield no banner at `src-tauri/src/lib.rs:2669`; a focused unavailable-ledger test would document that failure behavior, but no separate banner defect is asserted here.

### 9. Secrets stay out of state, IPC, logs, and errors — VIOLATED

Secret custody and public projections are generally explicit: setup keys use the credential store at `src-tauri/src/fleet_custody.rs:209`; rotation state at `:1510` stores references and encrypted/signed requests; Debug at `:150` and `:1560` omits contents; IPC status at `:2115`, `:2133`, and `:2150` exposes public status. Parse errors discard contents at `:2196`. Refusal/login redaction is in `src-tauri/src/fleet_client.rs:281`, `:362`, and `:453`; team config protection/Debug in `src-tauri/src/team_config.rs:71`, `:203`, and `:331`; protected fleet-key storage in `src-tauri/src/fleet_keys.rs:230` and `:255`. Export logs use static status or parsed codes at `src-tauri/src/lib.rs:2647` and `:2654`.

A hostile listing can put a literal hexadecimal account password in the device-ID field, which the new rotation path logs and persists. See **F7 (Medium)**. This is a direct echo, not the documented exception for unrecognized encodings.

Tests: `src-tauri/src/fleet_custody.rs:5661` checks actual saved rotation state and Debug against generated setup/new/old fleet keys, TRK, and seeds; `:3137`, `:3193`, `:3210`, and `:3228` cover token/invalid listing fields. `src-tauri/src/custodian_it.rs:2490` scans actual worker state, output and IPC against nine key/seed markers, account/bundle passwords and token prefixes. `src-tauri/src/fleet_client.rs:2055`, `:2111`, `:2195`, `:2205`, and `:2243` cover session/password/token error redaction. Debug tests also occur at `src-tauri/src/team_config.rs:549` and `src-tauri/src/fleet_keys.rs:632`. Hex/parser regressions are `src-tauri/src/lib.rs:7338`, `src-tauri/src/team_config.rs:823`, and `src-tauri/src/fleet_keys.rs:700`.

The leak worker at `src-tauri/src/custodian_it.rs:2616` is marked `#[ignore]`, intentionally: the unignored parent invokes exactly that worker with `--ignored` at `:2499`, and requires successful exit and `1 passed` at `:2512`. This is not skipped coverage. Its copied state set at `:2597` includes team, fleet-custody and bootstrap state, not `fleet-keys.json`; it uses a healthy mock credential store and does not establish every crash checkpoint or fallback case. The shipped non-Windows plaintext fallback in `docs/key-custody.md:72` and `:439` is a stated custody limit, not classified as a new rotation defect.

### 10. Orphan credential forget — HOLDS

`src-tauri/src/lib.rs:2212` persists new enrollment, `:2228` verifies the usable new keys, then `:2236` runs cleanup best-effort. Cleanup at `:2259` reads only unreadable-copy candidates; `:2269` logs fixed parse diagnostics/error kinds without copy contents. `:2283` excludes the current identity, other server/tenant and duplicate lookups. `:2291` requires the authenticated account's exact device row to be revoked. `:2299` only admits the two expected old-device credential references and explicitly excludes both current references. `:2306` continues after individual deletion failure. The account lookup is `src-tauri/src/fleet_client.rs:1080`/`:1119`; credential errors are fixed messages at `src-tauri/src/credential.rs:93` and `:151`.

Tests: `src-tauri/src/lib.rs:7480` checks revoked deletion, pending retention, malformed-copy tolerance and preserved backup copies; `:7511` checks failed credential deletion and failed account lookup without enrollment failure. Helper `:7468` asserts successful enrollment and the current new identity.

Missing focused tests: old copies referencing current credentials or another device's credentials; other-server/tenant and active/unlisted device cases; captured log scanning for a sentinel embedded in malformed JSON. The guards exist, but these branches deserve explicit regressions.

## Confirmed defects

### F1 — High — approval replay can transmit N+1 after recipient revocation

Location: `src-tauri/src/fleet_custody.rs:1210`, `:1221`, `:1235`, and `:1247`; caller `src-tauri/src/lib.rs:2862`.

An approval saved under N resumes after rotation, builds its N+1 grant, and saves it. Stop execution immediately after that save, before any N+1 ciphertext is transmitted. Revoke the recipient. On the next approval resume, ACTIVE equals the saved grant generation, so the `active > grant.generation` block containing the revocation check is skipped. The saved N+1 ciphertext is sent. A hostile server forwards it to the revoked recipient, who possesses the HPKE private key. This is delivery of a new key after revocation, not attempted recall of an already copied key.

There is a second eligibility gap in the same resume path: while rebuilding, it consults saved local revocations and the latest rotation's member results, but does not obtain/check the subject evidence and persisted withdrawal used by `grant_members`. A recipient omitted from that rotation's listing, whose withdrawal is recorded in the ledger rather than this custodian's saved revocations, can pass this path.

Catching tests: extend `fleet_custody.rs:5573` to persist the rebuilt N+1 grant and interrupt before POST, revoke, then resume with the same ACTIVE generation; assert zero fleet-grant transmissions. Separately omit the member result, persist recipient withdrawal in the ledger, and assert no newly built or transmitted N+1 grant. The present `:5606` test revokes while the saved grant is still N and therefore exercises only the guarded branch.

Correction direction: revalidate recipient eligibility before transmitting any saved grant as well as before rebuilding one; use the same exact-approval/withdrawal evidence requirements as the member-distribution path without changing saved request bytes.

### F2 — Medium — expired rotations that are restartable are blocked by the UI

Location: `src/features/manage-team/ui/TeamDevices.tsx:107` and `:252`.

The component equates every `expired` phase with a stuck server generation and disables Rotate. Let a saved create never reach the server, then resume after the deadline: server N ACTIVE permits terminal expiry and setup-key release. A later Start would succeed because N+1 does not exist, as the backend test at `src-tauri/src/fleet_custody.rs:5035` demonstrates. The Team page provides no way to send it. Reloading preserves the disabled state. The same applies when a restore removed N+1.

This contradicts amended Q-49 at `docs/adr/0002-g2-contract-decisions.md:135` and sequence K at `:1485`. The unconditional stuck statement in `docs/key-custody.md:366` is also stale; the ADR explicitly distinguishes an existing PREPARING generation from a create that never landed.

Catching test: replace/extend `tests/e2e/app.spec.ts:839` with expired states both with and without a server N+1. After sign-in, allow Start; the absent-generation case completes, while the existing-generation case surfaces `fleet.rotationStuck` and remains expired with its new setup credential released. The existing test at `:845` positively asserts the defect.

Correction direction: permit Start from expired and let the backend create response distinguish the accepted stuck limit. Align custody documentation with that distinction.

### F3 — Medium — crossing the deadline during network waits bypasses the expiry read

Location: `src-tauri/src/lib.rs:2955`; `src-tauri/src/fleet_custody.rs:1627`, `:1654`, `:1748`, and `:1759`.

The command captures `now` once. Resume Preparing just before its saved deadline, and delay the server-identity response until after the deadline. The check still compares the earlier timestamp, so S0/create/filing mutations are sent before reading ACTIVE. The pre-activation guard and 403 tolerance check also use that same earlier time. There is no elapsed-time update in this path.

Catching test: inject a clock and advance it past the saved deadline while identity is outstanding. After identity returns, assert that the next relevant request reads ACTIVE and no capability/create/grant/ack mutation precedes that read. Repeat the boundary during the grant loop before another send/activation. Existing tests pass an already-expired fixed timestamp and do not catch this.

Correction direction: evaluate effective current time before each deadline-sensitive send and before the expiry decision, accounting for elapsed time across awaits. The approval path at `src-tauri/src/fleet_custody.rs:1134` already uses elapsed time for its window.

### F4 — High — Pull and push can overwrite unpushed local changes

Location: `src/features/manage-team/ui/TeamDevices.tsx:146`; `src-tauri/src/team/sync.rs:2987`, `:4875`, and `:4950`.

A's pinned version is 1 and its local profile contains unpushed edits. It has no current lease or pending operation, for example after an expired/released lease. B has pushed version 2. After rotation, A selects Pull and push. Checkout returns `sync.remoteAhead` solely because the server version is greater; it has not saved A's content. The UI immediately calls Pull. Pull only blocks a lease or PENDING operation, then restores the server snapshot through staging and replaces A's profile. The subsequent push seals B's contents under the new key. A's unpushed data has been overwritten. A remote-ahead result does not prove the local copy is clean.

Catching test: use two different real profile contents, with A's unpushed sentinel and B's newer snapshot, no lease/pending operation on A, and an older-generation pin. Invoke the actual fallback sequence and assert A's sentinel is preserved and no replacement push occurs until the local-change conflict is resolved. Add an E2E assertion that this path reports the conflict. `tests/e2e/app.spec.ts:907` uses a clean stale copy; `:935` only protects a copy already at the server head.

Correction direction: explicitly detect/preserve unpushed local work before the automatic pull. A successful first push is safe, but `remoteAhead` alone is insufficient permission to replace the local profile.

### F5 — Low — older-key rows are not refreshed by ordinary profile actions

Location: `src/features/manage-team/ui/TeamDevices.tsx:56`, `:59`, and `:62`; `src/features/manage-team/ui/TeamProfiles.tsx:112` and `:133`.

After rotation, an older-key row is displayed. Use the normal profile Check in action to push that same profile under the newest generation. The backend list is now empty, and the shared profile status refreshes, but TeamDevices only subscribes to the store's refresh function and keeps its own `older` array. It reloads on mount or its own rotate/repush actions, not on the changed binding status. The obsolete older-generation row stays displayed. Ordinary Unbind can similarly leave a row for a profile no longer bound.

Catching test: rotate, observe the older-key row, Check in through the normal profile controls, and assert that row disappears without remounting or another rotation. Repeat with Unbind. Current E2E coverage removes rows through the component's own Pull and push callback, which explicitly refreshes its list.

Correction direction: invalidate/reload the older-key list when shared profile bindings/status change, including successful ordinary pushes and unbinds.

### F6 — Low — successful covered export loses its prompt-clear notification on lock contention

Location: `src-tauri/src/fleet_custody.rs:1339`; caller `src-tauri/src/lib.rs:2650`.

An export includes the newest generation and completes successfully while an unrelated custody command, such as listing/approving devices, holds `begin()`. `exported(newest)` returns `Ok(())` immediately when it fails to acquire the lock. No durable notification or retry is scheduled. Once that other operation ends, `export_due` remains true even though the recovery bundle covers the newest generation. The caller logs no error and the UI reloads the still-true flag. This concerns overlapping supported IPC commands; the normal single-action UI test does not exercise it.

Catching test: complete a rotation, hold a custody guard representing a non-rotation operation, finish an export containing that generation, release the guard, and assert eventual `export_due == false` without exporting again. Also verify that a genuinely newer concurrent rotation keeps its prompt.

Correction direction: preserve/retry the successful-export notification through custody-lock contention and apply its generation coverage check when it is consumed.

### F7 — Medium — a raw hexadecimal password is accepted as a device ID and logged/persisted

Location: `src-tauri/src/fleet_client.rs:820` and `:845`; new sinks `src-tauri/src/fleet_custody.rs:2080` and `:2085`.

Use a valid account password consisting of 32 lowercase hexadecimal characters. The hostile server already receives it during login and returns an active device row whose device ID is that exact password, with otherwise valid public keys/key IDs and ordinary evidence. ID validation only checks 16-byte hexadecimal syntax. The client retains the exact password for redaction at `src-tauri/src/fleet_client.rs:435`, but device-list redaction at `:852` only covers status and decoded label. Exact-approval checking correctly rejects the substituted identity as `skipped:no-approval`; nevertheless, the raw ID is printed in the rotation member log and stored as a `member_results` map key.

This is literal password echo, so the unusual-encoding exception at `docs/key-custody.md:483` does not apply. Attribution: identifier sanitization is a baseline hole; rotation adds the durable member-results and member-log sinks. The baseline device-list IPC also returns the identifier at `src-tauri/src/fleet_custody.rs:901`.

Catching test: log in with a generated 32-hex password, return an active row whose ID equals that password, complete member processing, and scan captured stderr and saved fleet-custody state for that exact marker. Test account-ID echo separately in device-list IPC. Existing token-shaped ID tests reject wrong lengths/prefixes and miss a password that is itself syntactically a valid ID.

Correction direction: reject identifiers matching retained credentials before they enter state, IPC, or logs; replacing identity bytes with a redaction placeholder would corrupt protocol identity and is not an appropriate validation result.

## Test-integrity and scope conclusions

The cited core and UI tests have substantive positive/negative assertions; no empty assertions or early-success bypasses were found in the inspected cases. The one ignored leak worker is explicitly executed by an unignored parent with exit/output assertions. The expired-UI test is a substantive test of the wrong contract behavior, rather than an empty or skipped test. Mock success journeys do not prove the absent dirty-data, concurrency, deadline-crossing, or hostile-password cases.

The accepted limits remain accepted: no server discard route for a truly stuck PREPARING generation; one-generation member pickup; lazy re-seal and eventual expiry of old grants; no retroactive removal of copied keys/data; no protection against a stolen root custodian through fleet rotation alone. None is reported as an implementation defect. Goals 4, 5, 6, and 10 hold on the reviewed paths. Goals 1, 2, 3, 7, 8, and 9 have the defects above.

VERDICT: FAIL
