# Independent third Architect review: ADR 0001

- **Review date:** 2026-10-04
- **Reviewed source:** isolated archive snapshot `C:/Users/Administrator/AppData/Local/hermes/cache/scratch/adr0001-rereview-a2d92d2d5510` of baseline commit `62979f297e44fc92e592e75ac1b3b3b903462f29`, with only `docs/adr/0001-server-identity-and-tenant-bootstrap.md` overlaid as the review candidate. The archive is not a Git checkout; this review does not claim its HEAD is a new commit.
- **ADR SHA-256:** `a2d92d2d5510b0fc1733e687d998870eb82abb97cf1d923cdc7678f28f4885f7` (**1,350 lines**).
- **Frozen plan SHA-256:** `a4a136c9ff0358fdce0967f7c09d7f7a744bbf33aac3db2ce8475972453eb813`.
- **Independent G2 verdict SHA-256:** `392ad5b34a0ea5efd2b514f85fd57e2a92451e6e97434792b376c3179a03bd1f`.
- **First review SHA-256:** `82ae5397ae7af4a1602bfc6fad37b729633a7ce6bedf07f4738f6c9845a9a4be`.
- **Second review SHA-256:** `f163d8a7cccb693ed15443ceae99e3f9091d8894caeb31ab8f9adbd52c5126cd`.
- **Scope:** independent design re-review of the four original P1 findings, principally the revised R3 against the second review's minimal required change. No ADR, runtime, shipped migration, or commit was changed. No product test, migration verification, G2 rerun, or production-readiness claim is made.

## Verdict summary

| Original finding | Third-review verdict | Reason |
|---|---|---|
| P1-01 — confirmation lifecycle, lifetime history, restore handling, exact S6 linkage | **APPROVE** | R1's permanent non-epoch-scoped guard and exact consumed approval linkage survive R3 receipt GC and restore reconciliation. |
| P1-02 — account login to device-bound session; signing and HPKE possession | **APPROVE** | R2 still requires both-key proof and live device-bound setup/ordinary predicates; R3 neither introduces an account-only shortcut nor a new bootstrap dependency. |
| P1-03 — exact approval replay, live-auth ordering, one authoritative durable ledger | **APPROVE** | R3 chooses `v2_idempotency`, specifies its storage-only representation and constrained approval extension, and supplies retention/GC, migration, atomicity, and restart/restore rules. The remaining ledger ambiguity is resolved. |
| P1-04 — role-separated key-ID derivation and forward reconciliation | **APPROVE** | R4's authoritative derivation, preservation, quarantine, and trusted-provenance rules remain applicable to R3 requests, receipts, sessions, and history. |

**Overall verdict: APPROVE for the revised P1-remediation design contracts.** There are **0 P0 and 0 remaining/new P1 blockers**; all four original P1 findings are closed at the design-review level. There is **1 new nonblocking P2 clarification** below, plus **3 retained P2/open-decision groups**. This is not acceptance of D3, resolution of Q1/Q4, evidence that the ADR has been implemented, or an instruction to silently change the ADR's draft status. The remaining decisions and verification obligations must remain recorded.

**G2 is unchanged: FAIL, 0 PASS / 4 FAIL / 60 BLOCKED across 64 rows.** Architect approval does not authorize production implementation (`G2:1-3`; `PLAN:198`; `ADR:24-26,1275-1279,1286-1292`).

## Citation convention and authorities

All citations below refer to exact line numbers in the frozen snapshot:

- `ADR` = `docs/adr/0001-server-identity-and-tenant-bootstrap.md`.
- `PLAN` = `.omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md`.
- `G2` = `.hermes/evidence/team-production/g2-independent-verdict-2026-10-03.md`.
- `REVIEW-2` = `.hermes/evidence/team-production/adr0001-rereview-6312978a1807/architect-review.md`.
- Code/migration citations use their full repository-relative paths.

The second review's actual requirement was to choose one replay authority and state operation representation, request/receipt fields, schema constraints, global reservation, retention/GC, migration relation, and crash/restart/restore behavior (`REVIEW-2:49-58`). Its original security ordering was already substantially accepted (`REVIEW-2:47`). The analysis below is based on those sources and the current ADR, not an assumption that the candidate must be approved.

## P1-03: why the revised contract now meets the requirement

### 1. One response authority, without silently extending the wire enum

R3 explicitly makes **`v2_idempotency` the sole approval replay-response authority** and rejects a separate approval operations/receipt table (`ADR:942-946`). The body remains the exact signed approval container on the planned route, not a new idempotent wrapper (`ADR:947-954`; `PLAN:1125`).

`DEVICE_APPROVE` is a **storage-only** kind and is forbidden in the closed common wire enum (`ADR:956-958`). This is a coherent, expressly proposed amendment, not a claim that it is already in the frozen plan. The actual common enum does not contain it (`PLAN:910-913`). The comparison with COMMIT is accurate: COMMIT also retains its exact request/receipt maps outside the common wrappers (`PLAN:955-960,1090`). Approval is now a second explicitly documented stored-response exception to the plan's common-map rule, not an undocumented re-encoding.

The common ledger PK is preserved (`ADR:965`; `PLAN:1090,1100`). The request digest binds instance, epoch, tenant, actor account/device, route subject, length, and exact signed body; it is a comparison value, not another key dimension (`ADR:988-995`). Consequently, a different body cannot create a second operation under the original identity.

### 2. Conditional columns, relational feasibility, and reservation scope

The extension requires all four approval-only fields iff the row is `DEVICE_APPROVE`, and all four NULL otherwise (`ADR:959-961`). Approval domain, epoch/ID bounds, exact body/hash, succeeded-only status, response type/bytes/hash, and retention are specified (`ADR:963-972`). The conditional FK references the **full unique** approval key `(tenant_id,payload_domain,replay_id)` (`ADR:973`; `PLAN:1062`). The partial unique index is on the **child ledger**, enforcing at most one actor/operation response per global approval reservation (`ADR:974-979`).

**SQLite feasibility is sound.** A NULL `approval_payload_domain` makes the child composite FK inapplicable to other operation kinds even though their tenant and idempotency key are not NULL. The explicit all-present/all-absent CHECK prevents an approval from taking that NULL escape. A partial child unique index is permissible; it is not being used as the FK parent key. The baseline parent already has the full composite PK at `server/migrations/0004_v2_team_fleet.sql:126-155`. An approval must be inserted before its receipt row, which is compatible with step 4's one transaction (`ADR:1058-1064`); no reciprocal receipt FK creates a new cycle.

A disposable in-memory SQL model, using all eight archived migrations to create the actual parent table and a modeled R3 child, observed these exact behaviors with SQLite **3.50.4**, `PRAGMA foreign_keys=1`: NULL-extension non-approval accepted; approval NULL extension rejected by CHECK; non-approval extension rejected by CHECK; missing approval rejected by FK; matching approval accepted; another actor or instance rejected by partial UNIQUE; parent deletion rejected by RESTRICT; child deletion allowed while the approval reservation remained. These are **design-feasibility observations**, not verification of an unimplemented forward migration or the Rust/SQLx runtime.

The global reservation without instance/epoch matches the plan's expressly unique authorization replay scope (`PLAN:409-411,1062`). The operation PK still stores instance, and R3 checks exact instance/epoch and receipt/approval equality rather than inferring the process's instance (`ADR:965,988-993,1027-1047,1068-1076`). Forward instance/tenant boundary obligations in R1/R4 are not removed (`ADR:754,763-767,1110-1124`; `PLAN:1095`). The narrower replay reservation is not permission to skip those checks or weaken other composite FKs.

### 3. Excluding `restore_epoch` from the PK is safe here

The PK follows the plan's epoch-independent identity (`PLAN:1090`). Epoch remains part of the request digest and approval extension, while the payload's noncurrent instance/epoch is rejected **before lookup** (`ADR:967,988-991,1031-1034`). An exact retained row can return success only after current session, actor/key binding, and live approval checks (`ADR:1027-1029,1038-1047`). Old-epoch retained rows can only produce `STALE_CONTEXT`; the ADR prohibits rewriting the epoch or returning historical success (`ADR:1075-1086`).

Including epoch in the PK would create another lookup namespace; the chosen contract instead refuses reuse through the persistent approval reservation and R1 lifetime guard. There is no stale-success path or new bootstrap opportunity caused by omitting epoch. This conclusion relies on the stated external identity authority and trusted live control plane, not protection against arbitrary same-epoch selective DB rollback (`PLAN:373-376`; `ADR:1076-1077`).

### 4. Retention and GC do not erase one-time history

R3 sets `retained_until` to `not_after_ms + authorization_replay_retention`, exactly the plan's authorization-tombstone floor (`ADR:1013-1015`; `PLAN:409-410`). Receipt GC runs under `BEGIN IMMEDIATE`, does not delete/rewrite the approval, tombstone, confirmation linkage, or audit, and rejects the reserved ID after receipt deletion rather than manufacturing another response or approval (`ADR:1016-1025`). RESTRICT prevents deleting the parent before a retained receipt (`ADR:973,1019`).

This is consistent with response expiry never granting fresh mutation permission (`PLAN:1422`). COMMIT's snapshot-linked retention remains a separate invariant; nothing in the approval-only GC rule reduces it (`PLAN:1106,1423`). The general signed-integer bounds remain binding on retention arithmetic and SQL storage (`PLAN:401,1096`); checked addition and fail-closed overflow handling belong in the later migration/runtime verification, not saturation, wrapping, or SQLite REAL coercion.

R1 retains the exact consumed approval link and hashes for tenant lifetime and forbids reset/replacement (`ADR:760-770,779-794`). R3 expressly makes D1 history independent of response retention (`ADR:1023-1025`). S6 revalidates the linked active approval, signature, context, and confirmation hashes, not the continued existence of receipt bytes (`ADR:810-817`; `PLAN:774,812-819`). Thus legitimate receipt GC cannot reopen D1 or silently erase its OOB evidence.

### 5. Replay ordering preserves both retry and live authorization

Authentication and current actor/key predicates precede lookup (`ADR:1027-1029`). Changed identity-bound bytes/path/subject/account conflict; another actor receives no stored response (`ADR:1031-1037`). An exact hit reparses and compares the receipt and approval, requires live authorization, and returns stored bytes **before** the pending/unconsumed/historical-emptiness creation guards (`ADR:1038-1051`). R3 explicitly excludes first-creation issuer discovery from rejecting a committed D1 retry simply because bootstrap ended (`ADR:1049-1051`).

On a miss, R1/R2 and signed-record/live-issuer predicates apply; a consumed/closed guard or different replay ID never creates another exception (`ADR:1052-1057`). The committing transaction persists reservation, receipt, audit, and all confirmation/guard/device/session transitions; any failure rolls back all effects (`ADR:1058-1064`). This directly supplies the plan's mutation/response/audit atomicity requirement for approvals (`PLAN:1107`) without relying on the frozen runtime's behavior.

### 6. Migration, crash, restart, and restore have one resolution path

The ADR calls for a forward plan-conformant table without changing `0004`. It assigns neither `v2_operations` nor `v2_replay_ledger` response authority; a retained baseline ledger must be transactionally consistent, and disagreement is an integrity failure, not a fallback response (`ADR:978-986`). This correctly distinguishes the actual shipped operation ledger (`server/migrations/0004_v2_team_fleet.sql:310-326`) from the consumed-replay ledger (`:376-387`).

The route really does verify and consume a replay ID without storing an exact approval receipt or approval mutation; it then emits a fresh JSON response (`server/src/routes/v2.rs:168-225`; `server/src/idempotency.rs:35-64`). These are **baseline deficiencies**, not regressions introduced by this ADR and not receipt bytes that can be safely synthesized during migration.

Step 4 commits the complete state or nothing. A pre-write startup/migration/recognized-restore integrity pass verifies each retained approval-response row's target, hashes, equality fields, and epoch. A corrupted row closes the affected approval path as `recovery_required`, with no regeneration, deletion, or creation fallback (`ADR:1066-1077`). An approval without a response row is history with **no replay**, not an invitation to reconstruct a receipt (`ADR:1020-1025,1073-1074`). R1/R4 still govern missing, contradictory, or unproven legacy/restore history and must quarantine rather than invent provenance (`ADR:799-808,1116-1137`). Migration must preserve this fail-closed treatment, including legacy consumed-replay evidence; copying rows with made-up responses is not authorized.

That is enough to close `REVIEW-2:53-56`: one replay-response authority, an exact constrained extension, durable global reservation, retention/GC, explicit relationship to baseline ledgers, and fail-closed crash/restore reconciliation are now chosen. R5 records the relevant constraint/GC/integrity cases as future obligations, not execution evidence (`ADR:1140,1159-1164`).

## Spot-check of the other three approved P1 contracts

### P1-01 — APPROVE

R1's guard and confirmation remain non-epoch-scoped and do not infer freshness from empty approval tables (`ADR:743-750`). Consumed link/hashes, no replacement/reset, historical terminal states, and restore unknown-history rejection remain explicit (`ADR:760-808`). R3's permanent reservation and receipt-independent history preserve those rules, while its exact-hit-before-creation-guards ordering permits response-loss retry after root rows exist (`ADR:1016-1025,1047-1051`). No regression of the one-time confirmation or exact S6 linkage was found.

### P1-02 — APPROVE

R2 still separates account-only pre-device tickets from device FK-bound sessions (`ADR:840-850,910-921`). Its challenge binds both validated keys and context; the secret recovered through HPKE plus Ed25519 signature proves both possession predicates before atomic session creation (`ADR:874-908`). D1 promotes only the exact proof-bound session to root setup; ordinary operations require live capabilities (`ADR:923-938`). R3 accepts reauthentication under a new session ID but not a different account/device/key tuple (`ADR:1042-1047`). No account-as-device shortcut or new signing-only proof was introduced.

The dependency chain remains acyclic: account ticket -> both-key device session -> offline confirmation + D1 approval -> exact S6 self-grant/activation -> D2 operating capabilities. Gen-0 setup does not demand an operating capability it can obtain only after activation (`ADR:929-936,704-718`); an exact D1 replay is not incorrectly routed through the ordinary `device.approve` issuer discovery (`ADR:1043-1051`).

### P1-04 — APPROVE

The archived writer really uses `signing_key_id` for HPKE at `server/src/enrollment.rs:240-241`. The key library has different signing/HPKE domain labels and functions (`shared/src/keys.rs:52-55,86-95`); the underlying preimage is domain label including NUL, big-endian length, raw bytes (`shared/src/canonical.rs:331-343`). R4 retains authoritative recomputation, whole-context checks, exclusive-lock inventory, byte preservation, and quarantine of signed/trusted/ambiguous data (`ADR:1092-1137`). R3 does not permit a stored receipt or corrected index to bypass those rules. No regression was found.

## New findings

### P2-04 — Narrow the generic 400 fallback to preserve the stable signed-record error contract

**Evidence:** `ADR:1084-1086` says invalid bytes or binding receive 400 while separately retaining `AUTH_CLAIM_COLUMN_MISMATCH`. The frozen contract explicitly maps noncanonical records, invalid signatures, signed-byte/container-hash/equality/key-substitution failures, and wire-integer failures to **422** (`PLAN:1233,1236`). R3 correctly maps changed idempotency requests to 409 and corrupted stored response to `422 MUTATION_RESPONSE_MISMATCH` (`ADR:1035,1040`; `PLAN:1229,1235`), and expressly proposes the new stale-context/closed-bootstrap codes (`ADR:1081-1084`).

**Impact/severity:** nonblocking **P2**. The broad fallback is ambiguous about which failures are malformed HTTP input versus canonical/signed-record failures with a frozen code. It is a client error-contract clarification, not a second replay authority, authorization bypass, or reason to reopen P1-03. No error status was exercised against the unimplemented route.

**Minimal required change:** state that 400 covers only malformed transport/request shape or unspecified request/path binding errors; retain the exact plan-defined 422 codes for their signed-record/canonicality/integer classes and the existing 409/401/403 distinctions. Specify precedence for a known signed-claim mismatch instead of letting the generic wording override it. Preserve fail-closed/no historical-success behavior. Do not change the frozen plan's error classes implicitly.

## Retained P2 and open decisions

These remain unresolved; they are not new P1 findings from R3:

1. **P2-01 — D2 capability value/scope and complete issuer predicate.** ACTIVE-root custody issuance is retained; `tenant.manage` is not a substitute and `root.custody` is not a generic capability grant. The exact capability set/scope and live role/session/key/grant/ACTIVE-pointer transaction and race proof remain obligations (`ADR:704-718,1263-1269`; `REVIEW-2:72`).
2. **P2-02 — D3 structured audit mapping.** D3 remains proposed. Offline-only actor nullability, action/target/outcome enums, request attribution, and forward migration must be decided. Network callers may not supply NULL actor identity, and audit insert failure must roll back the mutation (`ADR:720-725,1270-1274`; `PLAN:1091,1107,1109`; `REVIEW-2:73`).
3. **P2-03 — Q1/Q4 and evidence boundary.** The restore-preparation manifest and remaining Q4/envelope ownership contract are open. R1 constrains safe history, not a complete restore implementation. R5 and disposable design probes are not passed G2 cases; neither review approval nor design fixtures change the gate (`ADR:13-14,1254-1279,1286-1292`; `REVIEW-2:74`; `G2:1-3`).

## Evidence identity and limits

Additional reviewed source hashes:

| Source | SHA-256 |
|---|---|
| `server/migrations/0004_v2_team_fleet.sql` | `8c00c5b291e85684a0e20d1267240691102ec5886a93b60b6350c18dcff23d5f` |
| `server/src/routes/v2.rs` | `47226842a35f952aa6b940b968b662487daf4f0f9d518eee6ed6918f59195402` |
| `server/src/idempotency.rs` | `584d504b4298d1c72f36d683fb167c8cb1f52e9bad57a264288570ac41a28e9a` |
| `server/src/enrollment.rs` | `906ef2689da7a8445ef4aacd296f28b5542beec1bb5e5432d33a9e8340aebb19` |
| `shared/src/keys.rs` | `0809af292b2eecde6421b647dcf8c70e7829971aed2044c7ad93183d6b8a6279` |
| `shared/src/canonical.rs` | `b6a32e51b85793dca5faf47ffe82a00b35cb93b4a4b6453d8743c3103c301df2` |

The disposable probe lives only in the scratch snapshot:

- `review-probe-r3.py`, SHA-256 `b77ef6437d0582585fc378d899a45eeb6c8ac160a15a7d962dffcd11a2eef9c0`.
- `review-probe-r3-result.json`, SHA-256 `f276dbed6426b8888ff537a07e8ecc44983086fb0263630dc649f9f0000b42dd`; real execution returned ten SQL observations, exit 0.

The probe supplies relational feasibility evidence only. It does not prove exact CBOR/parser/signature behavior, migration preservation, Rust/SQLx FK configuration, concurrency/crash/restart behavior, receipt equality, or any G2 row. No secrets, cookies, or profile storage were accessed.

## Final disposition

**APPROVE** the revised R3 against the second review's remaining P1-03 requirement, and retain **APPROVE** for P1-01, P1-02, and P1-04. Address the nonblocking P2 error-contract clarification and preserve the three retained decision/verification groups. G2 remains **FAIL** and production implementation remains gated. This review artifact is the only file written to the parent working tree; no ADR/runtime/migration edit or commit was made.
