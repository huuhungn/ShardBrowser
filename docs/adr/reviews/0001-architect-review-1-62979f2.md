# Independent Architect review: ADR 0001

- **Review date:** 2026-10-04
- **Reviewed commit:** `62979f297e44fc92e592e75ac1b3b3b903462f29`
- **Review worktree:** `C:/Users/Administrator/AppData/Local/hermes/cache/scratch/adr0001-arch-review-62979f2`
- **ADR:** `docs/adr/0001-server-identity-and-tenant-bootstrap.md`
- **ADR SHA-256:** `0193e580bedc83987fb47a75f812ef2dc42e7760c975f2787bfe4d5b304b4402`
- **Frozen plan SHA-256:** `a4a136c9ff0358fdce0967f7c09d7f7a744bbf33aac3db2ce8475972453eb813`
- **Independent G2 verdict SHA-256:** `392ad5b34a0ea5efd2b514f85fd57e2a92451e6e97434792b376c3179a03bd1f`
- **Overall verdict:** **REVISE**
- **Severity counts:** P0 = 0; P1 = 4; P2 = 3.

| Area | Architect verdict | Boundary |
|---|---|---|
| D1 | **REVISE** | Retain the accepted self-approval decision, but freeze its confirmation lifecycle, authentication/PoP bridge and retry contract before approval. Include the actual HPKE-ID persistence defect in its forward migration contract. |
| D2 | **APPROVE** | The issuer rule is sound as a design rule when combined with S5/S6/S7 and the existing instance-bound migration obligations. This is not implementation verification. P2-01 specifies the retained verification obligations. |
| D3-proposed | **APPROVE, proposal only** | NULL/NULL offline actor mapping is defensible in this trusted-operator model. It remains proposed, not user accepted. P2-02 must be an explicit schema/audit obligation. |
| Pin-at-create analysis | **APPROVE, analysis only** | Feasibility, sequencing, reservations, OOB trust, PoP, races and restore invalidation are fairly distinguished. The recommendation to keep D1 is sound, not a decision rejecting the alternative. |
| Overall consistency | **APPROVE, with P2 clarification** | No contradictory acceptance status or claim closing G2 was found. The outstanding implementation contracts prevent full ADR approval despite this consistency verdict. |

**Disposition:** No demonstrated P0 in the accepted decision text. Four contract-level P1s block Architect APPROVE. The current implementation has additional defects, but the ADR correctly disclaims implementation equivalence and keeps production closed. Do not mistake missing code for a newly introduced ADR vulnerability, or mistake a list of unresolved security contracts for closure of those contracts.

## Evidence conventions and scope

- **ADR `:<line>`** means the ADR path above; **plan L<n>** means `.omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md`.
- **V<n>** means line n of `C:/Users/Administrator/AppData/Local/hermes/cache/scratch/adr0001-arch-review-62979f2-out/g2-independent-verdict-2026-10-03.md`.
- **VERIFIED** means independently read from the indicated frozen source. **INFERRED** means a consequence or risk deduced from those reads, not a reproduced exploit.
- Exact artifact hashes and HEAD were checked. `git status --porcelain` initially returned no changes. Read-only diffs from both `8d07f0d` and `ff9de4f` to reviewed HEAD returned no paths under `server/`, `shared/`, or `src-tauri/`.
- All 885 ADR lines were read, including S1-S7, Q1-Q4, the Option A commands, D1-D3, alternative analysis, obligations, consequences and revision history. The frozen plan, open questions, Architect v1-v6, final Critic review and consensus record were read at the relevant source sections; prior approval was not treated as approval of this ADR.
- No server was run, no URL was opened, no profile was accessed, and neither repository/worktree was edited. No Rust build or runtime acceptance test is claimed.
- An offline Python calculation reproduced the two source-defined hash preimages on synthetic public bytes only. A disposable **in-memory** SQLite database applied all eight current migrations: no `v2_audit_events`, sessions require a non-NULL device ID, and `PRAGMA foreign_key_check` returned `[]`. These are source/schema probes, not G2 results or SQLx migration verification. Recorded output: `architect-offline-source-probes-62979f2.json` beside this review.
- The supplied fresh-server probe is earlier evidence, not a fresh execution by this reviewer: `fresh-server-probe.json:2,7-13` records source `8d07f0d`, HTTP 400 and `server identity is not initialised`. Source equality above supports using it for context, not claiming it ran at this HEAD.

## Findings, ordered by severity

| ID | Severity | Finding and consequence | Exact evidence and evidence class |
|---|---|---|---|
| P1-01 | P1 | **The accepted one-time boundary still lacks a frozen confirmation lifecycle and S6 linkage contract.** Binding fields and an atomic consume are stated, but the uniqueness/lifetime boundary, cancellation/tombstones, epoch invalidation and linkage of the consumed confirmation to the exact active approval are explicitly left undefined. An implementer must choose security semantics to decide whether revocation, an epoch change or restoration of earlier state can reopen bootstrap. | **VERIFIED:** `docs/adr/0001-server-identity-and-tenant-bootstrap.md:679-698,821-829`; plan L774, L812-L819, L1073, L373-L376. **INFERRED:** wrong uniqueness scope, deleting history or treating a new epoch as a new bootstrap opportunity can defeat the accepted one-time intent. No exploit is claimed. |
| P1-02 | P1 | **There is no specified login-to-pending-device authentication/possession bridge.** D1 requires login before enrollment and later a live session on that exact pending device, but does not define the authenticated promotion between those states. Both-key commitment is also not the same as HPKE private-key possession. This is a prerequisite of the accepted first-device path, not merely a later login feature. | **VERIFIED:** ADR `:674,688-690,725-727,783-784,821-823`; plan L368-L370, L1059, L1122-L1124; `server/migrations/0004_v2_team_fleet.sql:93-103`; `server/src/auth.rs:139-160`; `server/src/routes/mod.rs:20,31-38`; `server/src/enrollment.rs:213-222`; `shared/src/enrollment_proof.rs:17-43`. **INFERRED:** absent a frozen promotion/authentication rule, account-only login may be mistaken for device authentication, or the no-device login/device-FK cycle may be solved with an unsafe placeholder. |
| P1-03 | P1 | **Exact response-loss replay is promised but its approval contract and ordering are not defined.** After the first commit, the ordinary D1 emptiness predicates are necessarily false. A retry must be distinguished before attempting a second creation, with an exact persisted request/response identity and stated live-auth/epoch policy. The ADR expressly defers that distinction. The frozen common mutation enum does not already supply an approval operation. | **VERIFIED:** ADR `:684-694,824-826`; plan L1107, L1100, L910-L937 (operation enum L913 excludes approval/capability grant); `server/src/routes/v2.rs:192-205,218-226`; `server/src/idempotency.rs:20-26,35-41,121-138`. **INFERRED:** checking emptiness first rejects legitimate response-loss retries; bypassing it without exact identity risks treating a new signed approval as a retry. |
| P1-04 | P1 | **The analysis stops at correct shared hash helpers and omits the wrong HPKE ID actually persisted by enrollment.** D1 confirms stored device IDs, while the alternative proposes recomputing both role-specific IDs. Today enrollment uses the signing-key hash function for the HPKE public key. This must be included in the ADR's authoritative-ID and forward reconciliation requirements, or correct client/CLI HPKE fingerprints will not match existing enrolled rows. | **VERIFIED:** ADR `:677-681,741-748,778-780`; `shared/src/keys.rs:54-55,87-94`; `shared/src/canonical.rs:336-343`; `server/src/enrollment.rs:240-241,259-275`. **Observed offline calculation:** the two hash preimages on bytes `00..1f` give different IDs (`architect-offline-source-probes-62979f2.json`). **INFERRED:** copying the existing stored field either blocks confirmation or preserves the wrong role identity; silently rewriting signed references can violate exact claim/column equality (plan L370). |
| P2-01 | P2 | **D2 should consolidate its full issuer predicate and first-root setup authorization matrix.** Its core rule is correct and its source reference imports live device/session/capability/grant checks. Keep explicit obligations for exact issuer-key-to-device linkage, current-instance/current-epoch validity, ACTIVE pointer/row agreement, revocation races, grant acknowledgment/validity, and permission for gen-0 readback/ack/activation before operating capabilities exist. | **VERIFIED:** ADR `:160-177,185-187,373-395,403-424,702-716,730-732,830-832`; plan L370, L774, L812-L829, L943-L947, L1071-L1073, L1095, L1101, L1107. **INFERRED:** implementing a shorthand ACTIVE check outside the mutation transaction, or requiring an operating capability for the bootstrap acknowledgment, would respectively permit a TOCTOU bug or reintroduce a cycle. This is not a demonstrated defect in D2's accepted rule. |
| P2-02 | P2 | **D3 is a coherent proposed actor mapping, not yet a complete structured-audit contract.** Retain an explicit obligation to define target/outcome/action enums, actor-nullability constraints, request attribution and fail-closed transaction-local insertion. NULL/NULL must be restricted to the accepted offline action class, not accepted from network input. | **VERIFIED:** ADR `:525-534,667-669,718-723,833`; plan L1091, L1107, L1109; `server/src/audit.rs:15-31`; all eight current migrations contain no `v2_audit_events` (offline schema probe). **INFERRED:** merely reusing `audit::log` or making actor fields universally optional would not meet the intended attribution/rollback boundary. |
| P2-03 | P2 | **Some plan paraphrases overstate what their individual cited line proves.** L481 supplies the `Capability` field/type, not its value list; L1067 supplies an existing minimum list that the eventual enum must preserve. L220 explicitly withholds implied root custody, not literally every capability. L1107 names approval and root/fleet lifecycle mutations, not capability-grant issuance by name. The broader deny-by-default/atomicity interpretation may be adopted, but distinguish that interpretation from a literal quoted source clause. | **VERIFIED:** ADR `:632-639,714,830-832`; plan L220, L481, L1067, L1107. **INFERRED:** these are citation-precision issues, not grounds to authorize `tenant.manage` issuance or relax atomicity. No cited code line-number error was found. |

## Required changes for Architect APPROVE

### P1-01: Freeze the confirmation state machine, not just its field names

Retain D1. Add a normative schema/constraint and transition contract, either in this ADR or a specifically identified contract appendix reviewed with it. At minimum:

1. Fix the representation of instance/epoch/tenant/account/device/both key IDs, suites/encodings and current-state equality checks. Define the uniqueness boundary that enforces one first approval for the accepted tenant/instance lifetime; an epoch-scoped uniqueness constraint alone must not reset a consumed authorization. Define how historical confirmations are distinguished from a current unconsumed row without violating D1's “no other confirmation” guard.
2. State allowed pending, consumed, invalidated/cancelled and historical states; specify which actions are legal and which are permanent denials. Expiration is a **recommendation**, not an explicit frozen-plan requirement for confirmations. If no expiry is chosen, state that and the key-loss/typo/cancellation policy. Never leave delete/reinsert or a force reset as an implicit recovery mechanism.
3. Bind consumption to the **exact** approval replay ID and canonical/container hashes or another explicitly equivalent immutable linkage. S6 may read this as OOB evidence for the same approved subject, not as reusable permission to self-approve another device.
4. Specify current-epoch mismatch behavior, revocation before and after consumption, and the trusted-restore treatment of pending/consumed/history state. Old-epoch confirmation must not become valid simply by rewriting its epoch. A restore which cannot establish the relevant trusted bootstrap history must have a stated fail-closed/operator recovery outcome, not silently become “empty.” Do **not** invent an external transparency ledger: selective same-epoch malicious DB rollback remains outside the frozen guarantee (plan L376).
5. State that the offline CLI verifies external identity/mirror consistency while holding the Option A lock. Commit confirmation plus structured audit together; the online `BEGIN IMMEDIATE` consumes confirmation, approval, pending-to-active transition, response and audit together. Any insert failure rolls back the transaction.

Required design cases: concurrent requests for the confirmed device, a competing enrolled device, new approval replay ID, cancelled confirmation, revoked pending device, consumed approval later revoked, response loss, epoch change, earlier restored DB state, and audit/storage failure. Implementation/harness evidence belongs to the gated G2 work; the architecture contract must precede that work.

### P1-02: Freeze the no-device to pending-device authentication bridge

Specify the authority of tenant login before there is a device, the limited operations that principal may perform, the canonical enrollment/PoP binding and the authenticated session promotion/readback after the server assigns the device ID. On the D1 path the approving requester must prove it is the confirmed device, not merely supply that ID under owner credentials. Check current account, single-owner membership, pending-device status, session expiry/revocation and tuple/key equality in the same acceptance transaction.

The design must distinguish:

- A signing proof over both public-key commitments, which binds the pair but proves the signing private key only.
- HPKE private-key possession, required by plan L368's separate lifecycle/PoP statement. Freeze the selected proof/check and stage, or explicitly settle the interpretation of that plan prerequisite through review. Merely matching an HPKE public-key fingerprint is not proof of its private half. Existing S6 HPKE unwrap/readback remains mandatory regardless.
- A limited pending-device session needed for approval/root setup, versus an active ordinary mutation session. Neither login nor enrollment may create operating capabilities/root custody.

No particular new login wire format or HPKE protocol is imposed by this review. The **missing choice** is the blocker. Current `AuthUser` resolves a v1 `users` row; `v2_sessions.device_id` is NOT NULL/FK-bound; and `/v2/auth/login` is absent. Those are independently verified facts, not evidence of an already-working bridge. Account ID must not be used as a device-ID placeholder; `server/src/routes/v2.rs:446-458` currently passes account ID in both positions for another idempotency path and is not a safe pattern to copy.

### P1-03: Freeze approval replay/stored-response semantics

Define request identity, operation scope, exact request bytes/hash and exact response bytes/status/bounds/version/hash, storage keys and collision behavior for the approval endpoint. Decide whether to extend a common mutation wrapper or specify a separate approval request/response contract. The plan requires atomic exact response persistence (L1107), but its closed operation enum L913 does **not** already define `DEVICE_APPROVE`; extending that enum is new ADR design, not an existing plan requirement.

State the order explicitly: authenticated current-context exact-retry lookup; exact-match stored response under a defined live-auth policy; otherwise the first-creation signature/equality/confirmation/emptiness guards. A changed request under the same idempotency identity conflicts. A new identity must not bypass consumed confirmation/history. Define retry after session revocation/expiry, approval revocation and epoch change; returning a historical response must never perform or recreate authorization. The offline confirmation command also needs a stated response-loss/readback policy, even if its mutation retry deliberately refuses and the operator uses a separate read-only status command.

Current `consume_replay_id` only supplies fresh/already-used and the present-approval route conflicts on replay. That is not the stored-response behavior promised by D1. This is a contract repair before approval, not permission to implement while G2 fails.

### P1-04: Add the actual key-ID writer defect and forward reconciliation rule

Name `server/src/enrollment.rs:241` in the current-code consequences. Require authoritative recomputation of the signing ID with `signing_key_id` and HPKE ID with `hpke_key_id` from the corresponding validated public keys and pinned suites/encoding. Confirmation must not bless an opaque existing ID without this equality check.

Extend forward migration/reconciliation classification to existing wrong-domain HPKE rows and every affected approval/grant/reference. Distinguish legitimately unconfirmed pending setup from already signed or trusted records; do not silently relabel old signed claims. Inconsistent data needs explicit quarantine/re-enrollment/operator review according to the chosen contract. Preserve shipped migration checksums, child references, uniqueness and composite instance boundaries. This extends ADR `:400-433`'s already-correct forward migration principle; it does not request editing `0004` or fixing runtime code in this review.

## Verified-correct claims and security evaluation

### D1: Accepted shape is defensible, but not fully specified

**VERIFIED:** ADR `:671-698` binds a durable operator confirmation to instance, epoch, tenant, account, device and **both** key IDs; requires the owner/device live session; restricts approval to tenant scope and `team.device`; prohibits prior approval/capability/root rows; consumes it under `BEGIN IMMEDIATE` with approval/device transition/audit/response. The required confirmation is not mistakenly excluded by its own emptiness check. The creation code and schema are currently active-only (`server/src/enrollment.rs:264`; `0004:84`); ADR `:620-623,661-663` explicitly acknowledges and requires pending state.

**INFERRED:** With an immutable exact confirmation and all acceptance predicates in the same write transaction, a second device cannot win simply by enrolling sooner or racing an approval. Serializing the write prevents two approvals from observing the empty state. Signing one record twice is not permission to create two records. A pending device alone does not violate the stated no-prior-approval/root guard. Requiring no other pending devices would be an additional policy, **not** a frozen-plan requirement.

This is a narrow exception to the ordinary issuer-capability rule in S5/plan L427. ADR `:626,645-652,671` correctly labels it as new design rather than pretending the frozen plan already permits self-approval. It does not imply root custody or operating capability. Confirmation reuse for S6 can avoid a second OOB ceremony, but requires P1-01's immutable linkage.

### D2: Correctly closes pre-ACTIVE and tenant.manage-only capability issuance

**VERIFIED:** ADR `:702-716` permits `TenantCapabilityGrantV2` only from an ACTIVE-root `root.custody` holder with live session and non-revoked grant, referencing plan L820-L822. It explicitly excludes `tenant.manage`-only issuance, and reserves `root.custody` grant creation for S6's root endpoints, preserving plan L1130. The exact `Capability` value list is not frozen by L481; the minimum values already exist at L1067.

**INFERRED:** The intended sequence is acyclic:

`tenant login -> pending enrollment/PoP -> offline confirmation -> D1 exact active approval -> S6 generation-0 self-grant in PREPARING -> exact readback/HPKE/key-ID/recovery acknowledgments -> ACTIVE generation/pointer -> D2 operating capabilities -> later device approvals under device.approve`.

No pre-ACTIVE operating grant is needed to sign the S6 self-grant, which has its own issuer-equals-subject rule. This does not authorize ordinary work with a PREPARING root. The existing plan supplies gen-0 readback/ack/activation semantics (L812-L819, L943-L946); P2-01 should record the setup actor permissions so an implementer does not accidentally require a capability obtainable only after activation.

Instance composite PK/FK boundaries and runtime epoch checks are **different** protections. Root-generation keys at L1071 are instance/tenant/generation-bound, not keyed by epoch; grants and authorization records carry `restore_epoch`. Do not add epoch to a generation PK and claim that is required by these citations. D2 must check signed grant/current epoch and exact equality as well as the instance/generation linkage and ACTIVE pointer. Existing code does not prove this: `generations.rs:69-89` begins from a numeric pointer; `fleet_generations.rs:131-173` accepts a pointer without an ACTIVE row; `generations.rs:243-300` checks prerequisites partly before its update transaction. The ADR correctly calls these out as insufficient, not compliant implementations.

### D3: Proposed offline actor attribution is acceptable within the stated trust model

**VERIFIED:** Plan L1091 names the structured audit fields without specifying actor nullability or a synthetic operator account. Plan L1109 requires enum/reason codes, not free-form detail. D3 (`:718-723`) chooses NULL account/device, `offline_operator_cli`, a request ID and separate action names, and expressly requires a forward schema change. No synthetic tenant account is needed to pretend the operator is an enrolled device.

**INFERRED:** A trusted stopped-server CLI can write this attribution without changing the tenant signing trust anchor. It identifies an actor class, not a personally authenticated human operator. Per-operator identity is a possible operational **recommendation beyond this plan**, not a requirement introduced here. Nullable actors alone are insufficient; P2-02 should restrict valid offline action/null combinations and transaction-local insertion. Resolve the pre-device login audit classification consistently with P1-02 rather than interpreting “network actions always carry ... device” as a working login solution.

### Pinning at tenant creation: fair analysis and sound recommendation

**VERIFIED:** `shared/src/keys.rs:54-55,87-94` defines role-separated public-byte hashes with no server, epoch, tenant or device input. `fleet_client.rs:157-174` receives existing keys. `routes/v2.rs:613-626` mints the device ID at enrollment. This supports feasibility of precomputation, not a shipped offline key-preparation workflow. P1-04 concerns the different actual persistence writer, not these correct source citations.

Plan L256 orders HTTPS and instance pinning before key generation/challenge. L257 requires OOB confirmation before first root/TRK and approval/key grants for later devices; it does **not** say that tenant creation must precede local key generation. ADR `:751-759` correctly distinguishes a changed offline-first journey from a connection/pin-first preparation variant before stopped-server tenant creation. Architectural review of a changed journey remains necessary; the alternative is not cryptographically ruled out by L256.

ADR `:769-791` correctly requires one-use reservation creation with tenant/owner/audit, full instance/epoch/tenant/owner/both-ID binding, independent OOB comparison, no imported private keys, later exact pending-device binding after normal login/PoP, and atomic consume. A self-signed preparation file proves signing-key possession only; it is not operator trust. An HPKE public-ID match is not HPKE private PoP (`:774-784`). A mismatched or competing enrollment must not take the reservation. Signing an approval/root grant and satisfying activation/readback remain separate.

ADR `:792-797` explicitly identifies expiry, cancellation/replacement, key loss, response-loss retries, races, restore invalidation and historical tombstones as contracts to freeze **if adopted**, not completed design. It forbids old-epoch pins silently becoming current, deletion/reinsertion and force reset. This is sufficiently complete **alternative analysis**; it would not be sufficient as an adopted implementation contract. The same lifecycle/retry rigor is required for D1, so D1 is not “no durable state”; it avoids the *additional pre-enrollment binding* state. The comparison table acknowledges D1 recovery/retry cost and its extra stop/start.

**INFERRED:** There is no inherent cryptographic security upgrade from moving confirmation earlier. Operator-confirmed keys still need context, possession, exact device binding and one-use consumption. Keeping D1 for initial scope is reasonable because the confirmed enrolled tuple already exists, while avoiding the extra server-wide stop can justify reconsidering the alternative. The recommendation at `:808-814` is conditional, not an assertion of user rejection or an authorization to add a second parallel bootstrap path.

Current client persistence is not a proven baseline for either design: `src-tauri/src/lib.rs:1954-1974,1976-1987` generates keys, awaits enrollment, then saves seeds; `team_config.rs:20-45` declares storage fields but proves no crash-safe pre-enrollment ceremony. Key persistence/protection and enrollment response-loss must remain gated verification obligations. No actual secret values were read.

## Citation audit

### Plan citations supporting the reviewed sections

The following were independently read at source, not accepted from the ADR's recap.

| Citation | Actual source statement | Assessment |
|---|---|---|
| L198 | Architect, then Critic, then G2 spike, then independent verifier PASS before production staffing; operator drill remains release gate. | Correct at ADR `:24-26,848,885`. |
| L220, L1067 | Owner role does not imply root custody; coarse roles plus explicit sensitive-mutation capabilities, deny-by-default, minimum value list. | Substantively compatible; literal “owner implies none” and value-set citation precision are P2-03. |
| L256-L257 | HTTPS/pin -> separate key generation -> challenge; PoP and OOB first-root confirmation; later devices need approval/key grants. | Alternative's sequencing interpretation correct. |
| L364 | Public signing/HPKE keys/IDs and structured metadata are allowed; plaintext key material is not authorized by this public metadata boundary. | Correct for public preparation input. Confirmation/reservation metadata is new ADR design. |
| L368-L370 | Two separate keypairs/IDs with separate lifecycle/PoP; challenge instance/epoch/tenant/nonce/pair/expiry commitment; pending device; exact signed/indexed equality. | Correct pending-state statement. Actual code does not supply HPKE private PoP; P1-02 freezes the prerequisite. |
| L427 | Issuer key must be looked up in same tenant/epoch with suitable capability. | Correct gap identification. D1/D2 are explicit decisions resolving it, not pre-existing exceptions. |
| L481, L484-L485 | Capability field/type; device/account optionality; root.custody only device-scoped with HPKE subject. | L481 alone does not list values (P2-03). Root endpoints remain additionally controlling under D2/L1130. |
| L774, L812-L819 | Exact active approval linkage; one `BEGIN IMMEDIATE`, no prior root/gen/active custody; OOB/signing/HPKE checks; issuer=subject; gen 0 PREPARING + self-grant/audit/response; activation readback/recovery. | Correctly restated by S6 and trust-anchor section. |
| L820-L822 | ExistingRootGrant to ACTIVE root from active same-tenant custodian with live capability/session/device/non-revoked grant. | Accurate support for the D2 analogue; D2 applicability to capability issuance is new ADR design. |
| L943-L946 | Exact closed generation-create/grant-create/ack/activate request/response maps; bootstrap embeds self-grant; prerequisite evidence and lifecycle/pointer/audit/response atomicity. | Q3 correctly states current partial activation is not proof of this full contract. |
| L1071-L1073 | Instance/tenant-bound root generation/grant composite keys/FK; one first self-grant by partial unique index and emptiness transaction; gen 0. | Correct. Does not define the new confirmation schema or an epoch-keyed generation PK. |
| L1091 | Structured v2 audit field list. | Correct; D3 actor nullability is proposed design, not already specified nullability. |
| L1095, L1101 | Composite instance/tenant identity throughout coordination/root/fleet candidates and downstream references, max one ACTIVE generation per instance scope. | Correct in Q3 forward migration/readers contract. |
| L1100, L1107 | Scoped idempotency identity; exact response + audit + named security mutations in one transaction; audit/response failure rolls back. | Correct atomicity requirement; capability-grant naming caveat is P2-03; D1 exact retry is P1-03. |
| L1124-L1126, L1130 | Enrollment PoP; exact approval/revoke and capability signed-container endpoints; root custody cannot use generic admin/grant path. | Correct cited endpoint names/record types. Current router differs, which ADR does not conceal. |
| L373-L376, L2248-L2267 | External epoch authority, trusted control-plane limits and deterministic authorized restore/crash handling. | S1-S4/Q3 remain consistent. No same-epoch malicious-rollback guarantee should be added. |

### Code citations and descriptions

No incorrect cited code line number was found in D1/D2/D3/pin sections. The missing writer defect is P1-04, not an incorrect shared-helper citation.

| ADR reference | Independently read source and assessment |
|---|---|
| `:658-660` | `routes/v2.rs:77-79` selects non-revoked tenant issuers; `0004:356-363` defines table; `v2_e2e.rs:138-147` inserts it. Search of source/migrations/tests found no production INSERT writer. The trust set is not in the plan's listed schema. Correct. |
| `:661-663` | `enrollment.rs:264` inserts active; `0004:84` allows active/revoked, no pending. Correct. |
| `:664-669` | `routes/v2.rs:173-226,274-322` verify, consume replay and return accepted; no approval/capability table row/status/live-role/capability mutation. `idempotency.rs:35-98` writes the replay ledger rather than the enum-named target tables. `audit.rs:22-31` swallows v1 audit insert errors via pool, outside an encompassing mutation transaction. Correct. |
| `:741-749` | `keys.rs:54-55,87-94`, `fleet_client.rs:157-174`, `routes/v2.rs:613-626` match the hash/caller/server-assigned-ID claims. Correct. Actual enrollment HPKE-ID writer omission is P1-04. |
| `:400-424` | `0004:38` NOT NULL/range, `generations.rs:69-89` pointer-derived first number, `fleet_generations.rs:131-173` pointer-only anchoring, `generations.rs:268-300` joint lifecycle/pointer writes, `routes/v2.rs:1129-1145` lifecycle-row active read: all correct. No claim those paths implement full S6/L946 is justified or made. |
| `:331-350,497-538` | `0004:47-52` legacy bridge, `routes/mod.rs:17-49` lacks v2 login, `auth.rs:23-28` Argon2 hash, `main.rs:31-48` no subcommand parsing and normal startup migration/admin path, `db.rs:26` migrations: accurate distinctions between proposed commands and current behavior. |

## Consistency, acceptable retained obligations and gate boundary

**VERIFIED consistency:** ADR `:3,7-14,334-343,356-364,464-477,611-626,671-723,736-739,816-848,850-885` consistently distinguishes user acceptance from full Architect approval. Q1 format, Option A and NULL-before-activation are accepted; D1/D2 accepted; D3 proposed; pinning neither accepted nor rejected. S1-S7 remain a separately labeled frozen-plan baseline; historical revision-log statements are clearly historical. NULL remains throughout PREPARING, and gen 0 becomes current only with ACTIVE activation. The pointer decision does not claim to settle the issuer exception or all Q3. No statement claims this ADR clears G2-06/16/18/64 or authorizes production without PASS.

**Acceptable open obligations, if kept explicitly gated:** D2 adversarial current-context/issuer/revocation/rotation tests; D3 enum/nullability/transaction-local audit implementation after the actor mapping is settled; the remaining capability value/scope rules while preserving plan L1067's minimum; Q1 restore-preparation manifest format; Q4 separate STREAM/envelope ADR scope; SQLx/Windows migration preservation and durability harness; official Rust golden vectors and implementation verification. Open algorithm/provider or restore details are not automatically waived by ADR approval and still block the applicable G2 rows. The relevant P1 choices above, however, are necessary to know what the D1 implementation is supposed to enforce and cannot remain merely an unspecified “implementation contract.”

The supplied independent authority states **G2 FAIL overall** (V220-V222), **G2-06 FAIL** (V160), **G2-16 BLOCKED** (V170) and **G2-18 BLOCKED** (V172). Earlier plan-level Architect/Critic approvals authorized the bounded G2 spike only, not production (`consensus-shardx-v0.2-team-fleet-encrypted-backup.md:3-5,9-17`; plan L198).

**This Architect review does not change the independent G2 verdict or any G2 row.** Even closing every P1 in this review would only permit reconsideration of the ADR's Architect gate; production implementation remains blocked until the required independent verifier G2 PASS.
