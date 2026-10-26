# Critic review, round 4: ADR 0002 draft revision 4

**VERDICT: REVISE** (1 BLOCKING, 2 MAJOR, 4 MINOR). All three items are textual fixes; with them this reviewer would move to ACCEPT-WITH-RESERVATIONS. Mode: THOROUGH (adversarial on the three focus areas).

Draft = `scratchpad/adr0002-g2-decisions-draft.md` revision 4 (cited `r4 Lnnn`); revision 3 is kept as `.rev3.md`.

## Round-3 items

| Round 3 | Status | Evidence |
|---|---|---|
| B6 uploads FK | **Resolved.** COMMITTED uploads referenced by kept snapshots travel with them; FK to live generations required; FK inventory; empty `foreign_key_check` after the merge | r4 L313, L319-L323, L335 |
| M16 stale receipts | **Resolved** in definition (live-only `v2_idempotency`, `superseded_by_restore_epoch`, per-kind table, r4 L345-L355); reinterpretations of L299/L966-L970 flagged. One plan line missed; see M19 | |
| M17 revoked signer | **Resolved.** Prepare refuses or drops a snapshot whose signer is revoked or unknown in live, together with every later version of that profile (r4 L331-L333). Rule 6 now splits revoked (reject, quarantine, L375) from lapsed (r4 L1606-L1613), and the reinterpretation is flagged on the page (r4 L31). New gap in the revert path; see M20 | |
| M18 recoverable cases | **Resolved** (r4 L24, L131-L132, L357-L365) | |
| Minors 1-8 | Resolved: profile invariants (r4 L325-L328); `renewed_after_revocation` on the first-seen clock (r4 L1266); new-device limitation stated; ADR1 tables and v1 tables assigned (r4 L316-L317; ADR1 L750, L754, L850, L986-L989 checked); Q-15 row. Minor 8 was "fixed" in a way that creates B7 | |

Citations checked: L299, L517, L521, L574, L949, L1087, L1089, L1099, L1159, L1226, L1228, L1412, L2258-L2265, L2608; ADR1 L302-L303, L576-L578, L750-L756, L850, L986-L989. All say what is claimed, except where the findings below show an omission.

## Focus 1: version_floor and the head-chain rule

**Can a hostile server use it to make a client accept a forked or rolled-back head?** No new path.
- The jump is allowed only for the first manifest after an accepted, custodian-signed transition.
- That manifest must chain from the transition leaf's new head, and its `base_version` must be at least the highest version this client ever pinned (r4 L342).
- The server can forge neither the transition nor the manifest. Serving two different "first manifests" to different clients is equivocation, which is outside the guarantee before and after this change (L2387).
- A rollback below the client's highest pinned version is refused as `HEAD_ROLLBACK_DETECTED`.

**Can it make a client skip or reject a legitimate head?**
- With an honest server, no for clients that accepted the transition: `version_floor = max(live current_version, live version_floor, backup current_version)` (r4 L307) is at least every version any client pinned, and it is monotone across repeated restores.
- Two edge cases (minor 1):
  - **Trigger.** A device whose pin already equals the restored head has no transition to "accept", so the rule as worded rejects its first legitimate post-restore manifest.
  - **No upper bound.** A hostile server can hand a committer a `base_version` near `i64::MAX` and exhaust the profile's version space. That is a denial of service, which a hostile server can cause anyway.

**Plan consistency: not complete (M19).**

## Focus 2: the superseded definition

The definition is sound:
- commits are superseded iff their `(profile, resulting_version, snapshot_id)` is not a kept snapshot;
- uploads iff the upload row is not kept; publishes iff the profile is not kept;
- every control-plane kind is never superseded;
- `IDEMPOTENCY_MISMATCH` is still checked first;
- keys stay reserved forever, and `version_floor` guarantees no future snapshot reuses a superseded `(profile, version)`.

A revoked-signer drop correctly supersedes the receipts of the dropped versions. Remaining nits are in minor 3.

## Focus 3: read-only outside K3 vs L2258-L2265

**It contradicts both the plan and accepted ADR 0001 (B7).**

## BLOCKING

**B7. "Outside K3 the server opens the DB read-only" puts every non-v2 server into a read-only state, breaking v1. That contradicts ADR 0001 Q2/P1 (accepted) and the plan's v2-only rows.**
- r4 L485: `Outside K3 it opens the DB read-only (SQLite mode=ro), so every write fails, including v1 writes and logins (round-3 minor 8; stricter than the v2-only rule of L2258-L2265)`.
- K1 is `X missing or corrupt` (r4 L471). ADR1 L302-L303: with `SHARDX_IDENTITY_DIR` unset, `v2 stays disabled (EPOCH_AUTHORITY_MISSING); v1 keeps working`. ADR1 L576-L578: `record missing → EPOCH_AUTHORITY_MISSING; v2 writes disabled; v1 unaffected`.
- So every deployment that has not run `identity init` (today, every shipped 2.4.x server) classifies as K1. It would open its DB read-only, and v1 login, profiles and locks would stop working.
- Plan L2258 says `disable v2 writes`, and the other rows say `writes off` / `disable writes` in the v2 context. They never make v1 read-only.
- The round-3 concern (live DB drift between prepare and commit) only exists while a restore is in progress.
- Fix:
  - Make the server read-only only in the restore-in-progress classes (K5a, K5b, K6, K7-K12).
  - Keep the plan semantics for K1 (v2 writes off, v1 unaffected), K2 (security incident, fail closed as the plan says) and K4.
  - Add a harness row: an unset identity directory still serves v1 writes.
- Confidence HIGH (direct text conflict). Realist: detected at the first test of a v1-only server, but it reverses an accepted decision and the plan row, so it must not be approved as written.

## MAJOR

**M19. `version_floor` amends the commit check L1412 (and L2608) without listing it, so a plan-literal server rejects the first commit after every restore.**
- L1412: the commit transaction checks `base_version == current_version`. L2608 says `exact base_version`.
- After restore `current_version = V_backup` while checkout returns `base_version = max(current_version, version_floor)` (r4 L341). The first commit carries `base_version = version_floor > current_version`, which L1412 rejects as `BASE_VERSION_MISMATCH`.
- The D-1 row lists amendments to L1085, L1090 and L1099 only (r4 L24).
- The new client chain rule also relaxes the client side of L372 ("only accept a chain continuing the pinned head") and L521 ("equals pinned/current head", which still holds) without listing L372.
- Fix: add L1412, L2608 and L372 to the Plan-lines column, and state the new commit predicate exactly (`base_version == max(current_version, version_floor)`). Alternatively, set the lease's `base_version` and check against it.

**M20. The revert path after a revoked-signer head has no acceptance rule for the other clients.**
- r4 L1610: `a current profile.commit holder checks out with the rejected head as previous_signed_head_hash, and commits content decrypted from the newest earlier snapshot whose signer was valid`.
- Every other client has rejected that head and quarantined. The revert manifest's `previous_signed_head_hash` is the rejected head, so under L372 and rule 6 they cannot chain onto it without first accepting the head they just rejected.
- The draft does not say whether a client may accept "pinned H_prev → rejected H_rej → revert H_rev" by skipping H_rej, or what H_rev must prove: that its content equals a verified older snapshot, or merely that its signer is valid. Two implementers will diverge: one accepts the revert, the other keeps the profile quarantined forever.
- Fix: define a revert rule. For example, a manifest whose previous head is a head this client rejected for a revoked signer is accepted iff its signer is valid now and it was committed after the revocation became known. The client pins H_rev directly and records H_rej as skipped. Add vectors.

## MINOR

1. **Jump trigger and bound** (r4 L342).
   - Define the trigger by epoch, not by "after an accepted transition": the first manifest whose `restore_epoch` exceeds its previous head manifest's, where that previous head is the client's current pin at the new epoch. This covers devices whose pin already equals the restored head.
   - Optionally cap the jump (refuse `base_version` above `i64::MAX - 2^32`) against version-space exhaustion.
2. L1105 ("replay returns the exact bytes; no reserialization") is also narrowed by the superseded rule; add it to the D-1 Plan lines next to L299 and L966-L970.
3. **Superseded nits.**
   - `BASE_VERSION_MISMATCH` for a superseded commit is indistinguishable from an ordinary stale base. Consider a reason detail (`restore_superseded`) so the client goes straight to transition reconcile.
   - State that `superseded_by_restore_epoch` is never cleared and does not change `retained_until`.
4. The D-1 approval row is long enough that the "Cannot recover" list is easy to miss. Consider splitting recover and cannot-recover into two cells. Editorial.

## Approval page: decidability per row

| Row | Decidable? |
|---|---|
| Q-1, Q-2, Q-4, Q-5/D-9, Q-6, Q-7, Q-12, Q-13, Q-14, Q-15 | Yes |
| D-1 | **No** until B7 and M19 are fixed (plan lines incomplete; read-only rule contradicts ADR 0001) |
| D-2, D-3 (conditional on L2443), D-4, D-5, D-6, D-7, D-8 | Yes |
| Trust chain / 2.4.3 | Yes after M20 (the revert rule is part of the decision) |

## What would upgrade the verdict

- **B7:** scope read-only to the restore-in-progress classes.
- **M19:** list L1412, L2608 and L372 with the exact commit predicate.
- **M20:** a revert-acceptance rule.

These are all small. After them, the remaining reservations are the already-flagged plan amendments and reinterpretations (L427, L913, L1125, L2243/L2251, L299/L966-L970/L1105, L1085/L1090/L1099/L1412, L375), which need the Architect + Critic pass the page itself requires, and the D-3 dependency review.