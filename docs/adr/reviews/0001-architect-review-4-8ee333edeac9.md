# ADR 0001 P2-04 Confirmation Review

- **Review date:** 2026-10-05
- **Review type:** Independent bounded design confirmation only
- **Scope:** P2-04 only; confirm whether the generic HTTP `400` fallback was narrowed while the plan-defined signed-record `422` classes remain authoritative.
- **Limits:** Read only the candidate ADR, frozen plan, and prior review identified below. No ADR, runtime, migration, or commit was changed. No product tests, migration verification, G2 rerun, or production-readiness verification was performed.

## Evidence identity and hashes

| Artifact | Identity | SHA-256 |
|---|---|---|
| Candidate ADR | `C:/Users/Administrator/AppData/Local/hermes/cache/scratch/adr0001-rereview-8ee333edeac9/docs/adr/0001-server-identity-and-tenant-bootstrap.md` | `8ee333edeac94378fe210258808248ad32f85b0261d0691220b48944973c5d68` |
| Frozen plan | `C:/Users/Administrator/AppData/Local/hermes/cache/scratch/adr0001-rereview-8ee333edeac9/.omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md` | `a4a136c9ff0358fdce0967f7c09d7f7a744bbf33aac3db2ce8475972453eb813` |
| Prior review | `C:/Users/Administrator/AppData/Local/hermes/cache/scratch/adr0001-rereview-8ee333edeac9/docs/adr/reviews/0001-architect-review-3-a2d92d2d5510.md` | `69bb2088c20954a48221efb695c33adafa5348fed945d008500224c606250feb` |
| Baseline approved commit | Provided review identity | `3f9f1573b99340474662720c19b0873adcc03ff7` |
| Baseline ADR | Provided review identity | `a2d92d2d5510b0fc1733e687d998870eb82abb97cf1d923cdc7678f28f4885f7` |

## Verdict summary

| Item | Verdict |
|---|---|
| P2-04 — generic HTTP `400` versus signed-record `422` classes | **CLOSED** |
| P1-01 | **Not reopened; prior APPROVE stands** |
| P1-02 | **Not reopened; prior APPROVE stands** |
| P1-03 | **Not reopened; prior APPROVE stands** |
| P1-04 | **Not reopened; prior APPROVE stands** |
| Overall design confirmation | **APPROVE** |

## P2-04 cited reasoning

The prior review identified P2-04 as a nonblocking ambiguity: the ADR's broad invalid-bytes/binding `400` wording could obscure the frozen plan's exact `422` classes. Its requested minimal change was to restrict `400` to malformed transport/request shape or unnamed request/path binding, while preserving the named `422` classes and the existing `409`/`401`/`403` distinctions (`PRIOR-REVIEW:105-111`).

The candidate ADR implements that change:

- HTTP `400` is limited to malformed transport/request shape or a request/path binding not otherwise named by the plan, and is explicitly not a fallback for a parsed signed record (`ADR:1084-1087`).
- The candidate preserves `422` for `NON_CANONICAL_RECORD`, `SIGNATURE_INVALID`, `SIGNED_BYTES_MISMATCH`, `SIGNED_CONTAINER_HASH_MISMATCH`, `AUTH_CLAIM_COLUMN_MISMATCH`, `KEY_SUBSTITUTION_DETECTED`, `HEAD_ROLLBACK_DETECTED`, `WIRE_INTEGER_OUT_OF_RANGE`, and `MUTATION_RESPONSE_MISMATCH` (`ADR:1087-1093`).
- The frozen plan independently defines the signed-record classes as HTTP `422`, including the canonical/signature/hash/claim/key/head classes (`PLAN:1233`), mutation and snapshot response mismatches (`PLAN:1235`), and out-of-range wire integers (`PLAN:1236`).
- The candidate preserves the plan's other distinctions: `409` for idempotency/context/bootstrap conflicts and `401`/`403` for session and authorization conditions (`ADR:1079-1097`; `PLAN:1224-1230`).
- Unknown codes or an HTTP/code mismatch fail closed, as required by the plan (`ADR:1095-1097`; `PLAN:1247`).
- The candidate's R5 restates the boundary operationally: parsed signed-record failures retain their plan-defined `422` code and never use generic `400`; `400` is only for unparseable transport/request shape or unnamed path binding (`ADR:1167-1175`).

**Finding:** None remains for P2-04. **Severity:** None after remediation; the prior issue was nonblocking P2. **Minimal change:** verified as present in the candidate ADR. P2-04 is therefore **CLOSED** at the design-review level.

## P1 regression check

No approved P1 finding was reopened by the P2-04 clarification:

- **P1-01 — not reopened.** The candidate retains the non-epoch-scoped bootstrap guard and confirmation history model (`ADR:743-750`). Receipt retention/GC does not delete or rewrite the approval, tombstone, confirmation linkage, or audit, and post-GC replay cannot produce historical success (`ADR:1013-1025`; `PRIOR-REVIEW:16-19,91`).
- **P1-02 — not reopened.** The candidate still separates account-only pre-device tickets from device-bound sessions and requires the enrollment binding to carry both key proofs and their context (`ADR:840-862`; `PRIOR-REVIEW:17,93-97`). Nothing in the narrowed `400` rule creates an account-only, signing-only, or alternate bootstrap path.
- **P1-03 — not reopened.** The candidate retains `v2_idempotency` as the sole approval replay-response authority (`ADR:940-946`), exact-hit validation and live authorization ordering before creation guards (`ADR:1027-1051`), and the receipt-retention/GC behavior above. The HTTP clarification does not add a second replay authority or alter replay precedence.
- **P1-04 — not reopened.** The candidate retains the R4 key-ID derivation and forward-reconciliation section and its preservation/quarantine requirements (`ADR:1101-1137`; `PRIOR-REVIEW:19,99-101`). The signed-record `422` mapping reinforces, rather than weakens, those integrity checks.

## Replay authority, retention, and order

These P1-03 invariants remain explicit in the candidate and are unaffected by P2-04:

1. **Authority:** `v2_idempotency` is the sole approval replay-response authority (`ADR:942-946`).
2. **Retention:** receipt GC deletes only eligible response rows; it does not delete or rewrite approval history, tombstones, confirmation linkage, or audit (`ADR:1013-1025`).
3. **Order:** current device-bound authentication and context checks precede response lookup; exact-hit integrity and live-authorization checks precede returning the stored response, while exact replay is handled before first-creation guards (`ADR:1027-1051`).

## Final status

**P2-04: CLOSED.** The candidate narrows HTTP `400` to malformed/unparseable transport or request shape and unnamed request/path binding, while preserving the frozen plan's exact signed-record `422` error classes and existing status distinctions. **Overall: APPROVE for this design confirmation only.** This is not a product-test result, does not claim G2 `PASS`, and does not authorize production implementation.
