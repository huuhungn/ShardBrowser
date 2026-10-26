# Critic review, round 7: ADR 0002 revision 9 (Critic half of the plan L2566 amendment pass)

**VERDICT: REVISE.** 0 BLOCKING, 3 MAJOR, 6 MINOR.

**The approval page should not go to the user yet.** Two reasons:
- M22 and M23 are integrity holes in rows the user is asked to approve (Q-1 and the trust chain).
- M24 changes what decided C-1 actually delivers.

Each fix is a sentence or a short rule, and none of them reopens C-1, C-2 or C-3.

**Inputs:**
- Draft revision 9: `scratchpad/adr0002-g2-decisions-draft.md`, 2042 lines, SHA-256 `f13979c5...a42320`.
- Diffs read in full: rev6 to rev7, and rev7 to rev9.
- Architect review: `scratchpad/adr0002-architect-amendments-review.md`.
- Plan: SHA-256 `a4a136c9...` (prefix matches). Lines re-read: L34, L290, L364, L372, L375, L376, L495, L517, L524, L1067, L1089, L1099, L1102, L1108, L1112, L1127, L1220, L1355, L1383, L1385, L2243, L2251, L2263, L2264, L2466, L2513, L2618, L2676, L2764, plus every "six/sáu" site.
- Code: `server/src/auth.rs:186-234` and `server/src/audit.rs:15-32`, at `439e932` and on main.

Mode: started THOROUGH; escalated to ADVERSARIAL after the third MAJOR finding.

## (1) Architect findings

| Architect finding | Status in rev9 |
|---|---|
| Q-1 tenant without a covered profile | Resolved differently: clients compare epochs only for manifests (draft line 64-67, rule at 1599). Sound for authorization records. **But the manifest half is wrong: see M22** |
| L913 once, six kinds, `FLEET_GRANT_REVOKE`, L1127 ack | Resolved (lines 29, 90-98, 1466-1493) |
| Q-13 `device.revoke`, table, L406-L408 exception | Resolved (lines 33, 1810-1817, 669, 1238) |
| Q-13 count changes ("five/six") | Partly: the list is incomplete (minor 2) |
| L1108/L1383/L2618/L290 revoke vs rotate | Decided as C-1 and labelled. Three restatements of the same rule are not listed (minor 1) |
| D-1 merge relabelled as an amendment of L2243, L2251, L376 | Resolved (lines 36, 296, 375) |
| L1399/L1402, L2608, L372 version jump | Moot after C-2; correctly removed |
| L1220 extension | Resolved ("extends (additive)", line 36, 355) |
| K2 risk ordering | Decided as C-3 (line 24, 494). The harness row is factually wrong: minor 3 |
| D-3 fallback 3 | Resolved: XChaCha20 + `StreamBE32` under the L1353 equivalent-primitive clause; nothing pre-approved (line 46, 808-829) |
| L375 path (ii) | Resolved: dropped (line 1681-1687) |
| 30-day first-seen cliff | Replaced by "issuer still a custodian at first sight" (line 1645). **It does not block backdating by a revoked custodian: see M23** |

## (2) Labels

- **Honest and minimal:** D-1's amendments; Q-13's L1125 and L406-L408; the single L913 amendment; L1127 as a reinterpretation; D-3 C's L1348 reinterpretation; C-2 "none" (plan L1089 fixes no path formula; I re-checked that the plan states no blob-path formula anywhere).
- **Incomplete:** C-1 (minor 1) and the count sites (minor 2).
- **Silent amendment (part of M22):** the manifest epoch rule `<= Ebind` departs from L524 and L375 without a label.

## (3) `version_floor` and the removed alternatives

- Grep: `version_floor` and "jump" appear only in the history and in the round tables.
- Restore merge row (309), harness rows (589, 593-594), revert rule (1666-1667 now "+1" only) and superseded rule (355, matched by `snapshot_id`) are all consistent with C-2.
- The `snapshot_id` match keeps superseded receipts superseded after a version number is reused. I checked this case: rolled-back `(p, V+1, S_old)` against new `(p, V+1, S_new)`.
- With `version_floor` gone, nothing at the client separates a post-restore head from a rolled-back child of the restored head except the epoch. That check is wrong (M22).
- I missed this in rounds 1-6: the hole was also present under `version_floor`, because the rolled-back child chains exactly from the restored head either way.

## MAJOR

**M22. After a restore, a hostile server can resurrect a rolled-back head and fork clients. The manifest epoch rule `restore_epoch <= Ebind` contradicts L524 and L375.**

Evidence:
- Draft line 1599: "for a manifest only: `restore_epoch <= Ebind` (Q-1, L524)".
- Plan L524: manifest `restore_epoch` = "exact current accepted epoch".
- Plan L375: quarantine when `restore_epoch` "giảm/tăng mà chưa có valid transition".
- Draft line 348: "Clients re-pin through the transition ... the next manifest continues the restored head".

Attack:
1. The live DB had heads `V_b+1..V_live` at epoch `E`, and the restore rolls back to `V_b`.
2. The rolled-back manifest `M_old` (version `V_b+1`, epoch `E`, `previous` = the restored head) is honestly signed by a then-valid committer.
3. Its blob still exists: C-2 never deletes a promoted path, and the archived `pre-restore` DB holds its bytes.
4. A client that re-pinned to the restored leaf checks `M_old`: it chains exactly (+1), the signer is valid, and `E <= E+1`. The client accepts it.
5. The server shows `M_old` to some clients and the honest post-restore head (`V_b+1`, epoch `E+1`) to others. The restore is silently undone on chosen devices, and the profile forks at `V_b+1`.

No other rule blocks this:
- leaf and inclusion checks (lines 413, 550) bind only the leaf;
- the superseded rule acts only server-side.

Fix:
- At first acceptance, a new head must have `M.restore_epoch == Ebind`. The only exception is the exact leaf of the accepted transition for that profile, proven by inclusion (L2243). That exception also covers a new device that joins before the first post-restore commit.
- Already-pinned heads keep their epoch.
- Label it as literal L524. Q-1 then needs no change for manifests.
- Add a vector: rolled-back child of the restored leaf at the lower epoch → quarantine (`HEAD_ROLLBACK_DETECTED`).

Confidence HIGH. Integrity impact, so no downgrade. It is not BLOCKING, because the attacker cannot forge content: it must be content a valid committer signed.

**M23. Proven revocations never reach the custodian fixpoint, so a revoked compromised custodian key passes the new "still a custodian at first sight" check. Backdating is not blocked.**

Evidence:
- Line 1600: "usable" excludes only "reported revoked" and local distrust.
- Fixpoint 1603-1610: `Cust(K)` ignores `DeviceRevocationV2` entirely.
- Line 1645: the issuer "is still a custodian (rule 2)" at first sight.
- Line 1610: self-renewal is valid whenever the previous window covers the chosen `issued_at_ms`.

Attack (task (4)):
1. Custodian device D is stolen. A current custodian files a `DeviceRevocationV2` for D, and client P counts it as proven.
2. Later the hostile server omits the unsigned `device_revocations` tuple for D and the reported revocation of D's root grant (allowed: they are unsigned).
3. The thief uses D's key to sign a `DeviceRevocationV2` against honest device H, with `issued_at_ms` backdated into D's window.
4. P checks the new revocation:
   - D was a custodian holding `device.revoke` at `issued_at_ms`: yes;
   - `Cust(D)` at first sight: yes, because nothing removes D, and if D's window has lapsed, a backdated self-renewal (line 1610) extends it.
5. P counts H as proven revoked, and the honest committer's UI offers the revert of H's legitimate head by default. This is the M21 outcome, reached through a key P knows is revoked.
6. Variant: with the same key the thief can approve a fake committer F backdated into D's window, then sign arbitrary heads.

The draft's claim (line 1650) "It stops a revocation forged or backdated with a key whose custodianship has since ended" holds only while the client can see the end. Against a hostile server that is limited to D-6's sticky lapse and the 1095-day clip. It never holds for a key the client holds a signed revocation for.

Fix:
- Make proven revocations sticky in "usable". Once a client has counted a `DeviceRevocationV2` for device D, any record signed by D's keys that the client **first sees after** counting it is unusable, whatever its `issued_at_ms`, because issuers choose `issued_at_ms`.
- D also leaves `Cust` for every check made after that point, including the first-sight custodian check.
- Records first seen before the count stay as verified.
- State the residual limit: a new device has no history, so it cannot separate backdated records from legitimate ones (the D-6 limit).
- Add vectors: a revocation and an approval signed by a proven-revoked custodian key and first seen afterwards are refused; the same records first seen before stay accepted.

Confidence HIGH. Security impact, so no downgrade.

**M24. The `rotation_required` definition clears too early and misses grant revocation. Under decided C-1, the banner can disappear while a removed party can still read new keys.**

Evidence:
- Line 1812: a fleet is "`rotation_required` while its ACTIVE generation was granted to a now-revoked device ... until a newer generation is ACTIVE".
- Line 672: a fleet `RecoveryGrant` is wrapped under the ACTIVE root generation.
- Line 1060 and plan L495/L1355: the FKEK is wrapped under the TRK.
- Line 1519: "`FLEET_GRANT_REVOKE` ... the fleet becomes `rotation_required`".

Two holes:
- (a) **Revoked custodian, fleet rotated before the root.** The new generation's `RecoveryGrant` is wrapped under TRK `N`, which the revoked custodian device holds. That device can therefore unwrap the new FKEK from server-held grant ciphertext, yet the fleet's flag clears.
- (b) **Grant revoked without a device revocation** (a member leaves one fleet, L1126). The derived definition at 1812 covers only revoked devices, so an implementer following it shows no banner, contradicting line 1519.

Fix:
- A fleet is `rotation_required` while its ACTIVE generation was granted, in any device variant, to a device that is now revoked, or under a grant that is now revoked.
- A fleet is also `rotation_required` while its ACTIVE generation's `RecoveryGrant` is under a root generation that is itself `rotation_required`.
- The UI orders root rotation before fleet rotation.
- Add harness rows for both holes.

Confidence HIGH.

## (5) C-1 consequences (answers to the coordinator)

| Question | Answer |
|---|---|
| What the revoked device can still push | Nothing through an honest server: sessions, leases and grants are revoked in one transaction (1811), and in-flight commits fail on the lease. Through a hostile server, its manifests are refused by every client that holds the revocation; otherwise L376 applies |
| What it can still decrypt | Every snapshot committed under the unrotated generation, plus (M24) new fleet generations while the root is unrotated, whenever it obtains the ciphertext. The server holds all ciphertext and is untrusted in this design, so in practice "leaks" means "the server or its storage". The C-1 cell says this honestly |
| Enforced or advisory | **Advisory.** No commit is blocked, there is no deadline, and the flag is derived on the server and shown as a banner, so a hostile server can hide it. Minor 5 |

## MINOR

1. **C-1 Plan lines are incomplete.** L34 (P1.3 "revoke+activate logical op"), L2676 (drill) and L2764 (G2 checklist: "revoke+activate logical operation được khóa") restate L1108. Add them; otherwise the gate checklist fails as written.
2. **The count-site list is still incomplete.** Unlisted "six authorization/key-grant" sites: L364, L2333, L2336, L2421, L2478, L2484, L2510, L2563 (G2 independent-verifier row), L2632. L2032's "sixth" is an ordinal and needs no change. Better: amend by rule ("every count of authorization/key-grant records or grants in the plan rises by one").
3. **"Logins fail" in K2 and during a restore is false for shipped v1** (draft 493, 594).
   - A successful v1 login writes nothing: the JWT is stateless and the throttle is in memory (`server/src/auth.rs:203-233`).
   - The failed-login audit insert is swallowed (`audit.rs:22-31`, `let _ =`).
   - Under `mode=ro`, v1 logins and reads keep working, which matches the decided "read-only", and audit rows are silently lost.
   - Fix the harness row to "v1 writes fail; logins and reads succeed; audit is lost and flagged", or decide explicitly that logins are blocked.
4. **The harness row "no code path deletes a blob path" (593) contradicts retention GC** (L2548, L1106, and draft 369's "blobs the live store has already deleted"). Fix: "no upload or promote path deletes or overwrites a blob; only retention GC deletes, and only unreferenced paths".
5. **`rotation_required` advisory status is unstated.** Say "advisory, no deadline, no commit is blocked" on the C-1 row. Let clients derive it from the signed `DeviceRevocationV2` and grant evidence they already fetch, so a hostile server cannot hide the banner. No harness row covers the derivation.
6. **Re-filing has no trigger.** Line 1653 relies on "any current custodian files a fresh revocation", but nothing prompts one when the original issuer lapses. Add a custodian-side event, or accept the liveness cost on the page.

## Pre-commitment vs actual

| Predicted | Found |
|---|---|
| Stale `version_floor` references | None live |
| Holes in the first-seen rule | M23 |
| C-1 window under-specified | M24, minor 5 |
| Count-site gaps | Minor 2 |

Not predicted: M22, a pre-existing epoch hole that C-2 makes load-bearing.

## Verdict justification

REVISE: 3 MAJOR, escalated to ADVERSARIAL.

The decided choices themselves are sound, and their labels are honest except for minor 1. The architect's findings are all resolved, apart from the residual minor 2 and the M23 gap in the replacement first-seen rule.

What upgrades this to ACCEPT-WITH-RESERVATIONS:
- M22: `==` with the leaf exception, plus a vector.
- M23: sticky proven revocation in "usable" and `Cust`, plus vectors.
- M24: the `rotation_required` definition, root-first ordering, and harness rows.
- Minors 1 and 3, which change what the user approves.

Minors 2, 4, 5 and 6 can ride along.

## Open questions (unscored)

- Effective time of a `DeviceRevocationV2` against records already accepted (approvals and grants D issued before it). M23's rule is first-sight based and leaves them standing. Confirm that this is intended.
- Should `reason_code = compromised` gate commits under the unrotated generation (a client-side refusal)? That is a C-1 policy question for the user, not a defect.
- D-3 `aead-stream` (L2443) and Q-17 remain open from earlier rounds.