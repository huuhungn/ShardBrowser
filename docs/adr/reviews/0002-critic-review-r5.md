# Critic review, round 5: ADR 0002 draft revision 5

**VERDICT: ACCEPT-WITH-RESERVATIONS.** 0 BLOCKING, 1 MAJOR, 4 MINOR.

The reservation: the **Trust chain / 2.4.3** row must not be approved until M21 is fixed (a one-sentence rule change). Every other approval-page row is decidable as written. The rows marked reinterprets/amends still need the Architect + Critic pass the page itself requires (plan L2566), and D-3 still needs the L2443 dependency review.

Draft = `scratchpad/adr0002-g2-decisions-draft.md` revision 5; revision 4 is kept as `.rev4.md`.

## Round-4 items

| Round 4 | Status | Evidence |
|---|---|---|
| B7 read-only breaks v1 | **Resolved.** Read-only only in K5a, K5b, K6, K7-K12. K1/K2/K4 turn off v2 writes and leave v1 unaffected (ADR1 L302-L303, L576-L578 re-read). Harness row added for an unset `SHARDX_IDENTITY_DIR` | rev5 D-1 classification text |
| M19 commit predicate | **Resolved.** `base_version == max(current_version, version_floor)` for commit and lease. L1412/L2608 marked as amended; L372/L1105 marked as reinterpreted | rev5 D-1 and approval row |
| M20 revert acceptance | **Resolved in shape:** exact walk-back rule, pin R directly, audit the skip, stated limits, vectors. Has a soundness gap: M21 | |
| Minors 1-4 | Resolved (see notes below). Minor 3's error-body field needs the allowlist step: minor 1 | |

Citations re-checked: L372, L517, L524, L526, L1105, L1106, L1220, L1228, L1412, L2258-L2265, L2608; ADR1 L302-L303, L576-L578.

## Focus checks

**Epoch jump rule.** The jump is allowed only when all of these hold:
- `M.restore_epoch > P.restore_epoch`;
- the binding accepted the new epoch through a custodian-signed transition;
- `M.base_version` is at least the highest version this client ever pinned;
- `M.base_version <= i64::MAX - 2^32`.

What this gives:
- It covers a device whose pin equals the restored head (the round-4 minor 1 case).
- A hostile server can at most make honest committers skip version numbers once per legitimate restore. The skip is cosmetic, and the bound leaves 2^32 commits.
- Fork and rollback acceptance are not possible: a forged transition or manifest is still required.

**Superseded definition and error body.** The definition is unchanged and sound.

Plan L1220: error JSON is `code`, `request_id`, `retryable`, `safe_message`, **optional allowlisted fields** and an optional `retry_after_seconds`; L1247 adds that an unknown code fails closed.
- So an additive field **is** permitted, but only as an allowlisted field.
- The draft does not cite L1220 or register `superseded_by_restore_epoch` in the allowlist (minor 1).
- A non-secret `U64` epoch is a safe allowlist entry, and clients that ignore it still reconcile through `BASE_VERSION_MISMATCH`.

## MAJOR

**M21. Unsigned, server-reported revocations now enable acceptance: a hostile server can make honest clients roll back profile content.**
- The revert rule skips heads whose signer is a key "the client holds as **revoked**". In rule 6 that state comes from "a revocation in the evidence, a `DeviceRevocationV2`, or local distrust".
- The evidence's `revocations` / `device_revocations` lists are unsigned server statements. Revision 3 kept them harmless by design: "Server-reported revocations only tighten ... never needs them to accept anything". The revert rule breaks that invariant.
- Attack:
  1. The latest legitimate head L is signed by honest device S. The hostile server reports S as revoked.
  2. Every client rejects L as revoked-signed.
  3. Per rule 6, the committer's revert flow commits "content decrypted from the newest earlier snapshot whose signer was valid and is not revoked", which is the content of L's predecessor P0, as R with `previous = L`.
  4. Every client then accepts R through the walk-back (L is "revoked", and the chain is exact) and pins it.
- Result: L's changes are silently undone, at a higher version, with a valid signature. Before revision 5 the same false report only caused a quarantine (denial of service).
- Fix: a head is "revoked" for the revert rule (and for the committer's choice of revert content) only through a **signed** `DeviceRevocationV2` (Q-13) that chains to `A0` like any other record, or through local distrust. Unsigned server reports may still quarantine, but never enable a skip. Add a vector: a server-reported revocation without a signed record must not allow the revert.
- Severity: integrity and data loss, so it is not downgraded. Realist: it needs a hostile server and a user taking the revert action, but the UI makes revert the default path.

## MINOR

1. Cite L1220 and add `superseded_by_restore_epoch` (and its type, `U64`) to the error-field allowlist for `BASE_VERSION_MISMATCH`.
2. The K2/K4 rule "v1 unaffected" reads the plan's L2263 "quarantine/disable writes" and L2264 "fail closed" as v2-scoped. That is reasonable, given ADR1 L576-L578, but it is an interpretation; note it in the D-1 Plan-lines cell.
3. The revert walk-back requires every manifest between R and P to be revoked-signed. If the server presents R before a valid intermediate head L1 that the client has not yet pinned, the walk-back fails at L1. State that the client first advances its pin through valid heads in order and then applies the rule; add the vector.
4. Revert vectors should include a head that was pinned and whose signer was revoked later, which then becomes skippable under the definition "last pinned non-revoked head".

## Approval page

| Row | Decidable? |
|---|---|
| Q-1, Q-2, Q-4, Q-5/D-9, Q-6, Q-7, Q-12, Q-13, Q-14, Q-15 | Yes |
| D-1 | Yes (minor 2 labelling) |
| D-2, D-3 (conditional), D-4, D-5, D-6, D-7, D-8 | Yes |
| Trust chain / 2.4.3 | **Hold** until M21 is fixed. I-1 alone is decidable |

## Remaining reservations after M21

- Architect + Critic pass for every row marked reinterprets/amends:
  - L427, L913, L1125;
  - L2243/L2251;
  - L299/L966-L970/L1105;
  - L1085/L1090/L1099/L1412/L2608;
  - L372, L375.
- The D-3 provider review (`aead-stream` unverified offline).
- Q-17 custodian-event UX.
- G2 still has to implement and harness all of this (G2-55..60 stay BLOCKED until then).