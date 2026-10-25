# Critic narrow diff check, round 9: ADR 0002 revision 13 (Q-18 and the recorded user decisions)

**VERDICT: REVISE (narrow).** 0 BLOCKING, 1 MAJOR, 5 MINOR.

None of the findings changes a user decision:
- M26 aligns the `exposed` definition with the approved C-1 wording ("every fleet whose ACTIVE key a removed device could hold"), so the user does not need to re-approve anything.
- Minors 1-5 correct claims and costs in the body.

A diff check of those passages is enough after the fix.

**Inputs:**
- Draft revision 13: 2206 lines, SHA-256 `e2924c673b40e29f...`.
- Full diffs read: rev11 to rev12 (44 lines) and rev12 to rev13 (154 lines).
- Draft re-read: 691, 1609-1612, 1644, 1750, 1865-1888, 1905-1913.
- Plan re-read: L812-L832 (root lifecycle), L1786-L1793 (local `sync_state` DDL), L1841 (local operation states), L2040-L2041 and L2377 (durable commit replay).

Mode: THOROUGH.

## Recorded decisions

| Decision | Recorded correctly? |
|---|---|
| C-3 relabel confirmed | Yes: rows 20 and 39 and the K2 text (507) |
| Q-17 design review before W6 | Yes: row and 1311 |
| Q-18 block | Yes: rows 17, 23 and 36, rule 1876-1883, revert 1708, vectors 1905-1912 |
| Q-19 (A) | Yes: row, rule 1 (1631), Q-19 entry; (B) and (C) kept as rejected |
| Q-20 split | Yes: row and 1884-1888 |

Revision 12 (r8b minors 1 and 2) is also correct: no upper bound on the root range, PREPARING roots included, and gen-0 without a cache starts at `g0`. Vectors for both were added.

## Q-18 under attack

**Can a hostile server lift the block?**

| Attack | Result |
|---|---|
| Report "not required", or drop the unsigned reports | Cannot lift it: the cause is the counted signed `DeviceRevocationV2` (1879, vector 1912) |
| Roll back to an older, unexposed generation | Cannot: "newer" in the release rule, plus the highest-generation-per-fleet rule (1750) |
| PREPARING generation passed off as ACTIVE | The client cannot verify generation state (1644), so "ACTIVE" in the release is server-asserted. Safe only because the client also verifies that the target generation is unexposed. A server can release onto a PREPARING but genuinely unexposed generation: confidentiality holds, availability may suffer. State that the release rests on the client's checks, not on ACTIVE (minor 1) |
| Fake rotation | Needs custodian signatures. On devices with history, the thief's records first seen after the count are refused (sticky rule). **Within the no-history limit**, a thief plus server can supply D's backdated grants in the same evaluation and release the block onto a thief-chosen key. That is a disclosure path, but no worse than having no Q-18. "A hostile server cannot lift the block" (1879) and "never a disclosure" (1882) must be qualified (minor 1) |
| Withhold the revocation | **Can stop the block from ever starting** on a client that has not fetched the signed revocation, or, on a no-history device, D's root grant. Line 1612 still says omission "only blocks a revert or keeps a sticky revocation from starting". It now also lets commits continue under the stolen key (minor 2) |
| Release onto a key the revoked device generated | **Possible: M26** |

**What a forged `compromised` revocation can do.**
- Inside the no-history limit: freeze commits on the affected devices (stated).
- Not stated: a stolen *current* custodian key, which D-6 admits has no time limit against a hostile server, can file `compromised` revocations of honest custodians on **every** device. Each one freezes the root and every fleet.
- If it revokes every other `key.rotate` holder, the sticky rule refuses those custodians' later rotation records, so the freeze never lifts and the tenant goes to Q-14.
- This is within custodian authority, but the stated cost (1882, row 23) understates it (minor 4).

**Is "no plan line changes" honest?** Mostly yes: no plan line obliges a client to commit. Two points need stating, or the label is incomplete (minor 3):
- **In-flight commits.** The plan requires durable, byte-identical resume of a persisted `CommitRequestV2` across close and reopen (L2040-L2041, L2377). The block applies "before checkout" (1879), so a commit whose upload is already READY when the revocation is counted would complete under the stolen key. Its ciphertext is already on the server, so refusing gains nothing; completing it keeps the plan intact. Say so explicitly.
- **Local state.** The plan's local `sync_state` is a closed CHECK enum (L1790-L1793: `LOCAL`, `AVAILABLE`, `CHECKED_OUT`, `LEASE_AT_RISK`, `OFFLINE_FORK`, `UPLOADING`, `RESTORE_REQUIRED`, `CONFLICT`, `QUARANTINED`). State how a blocked dirty profile is represented, for example "stays `AVAILABLE` with `dirty = 1` and a local `last_error_code`". A new enum value would be an amendment.

**Boundary choice (1887): `FLEET_GRANT_REVOKE` with `compromised` gets an urgent banner but no block.** Sound and consistent with the rule that unsigned server mutations never decide. Note the consequence: a member removed for compromise without a `DeviceRevocationV2` leaves commits open under a key that member holds. The UI should steer the admin to `DEVICE_REVOKE` for that case. This belongs to the Q-17 review; it is not a finding.

## MAJOR

**M26. `exposed` counts only grantees, not issuers, so a key that a revoked device generated can stay "clean". The advisory flag misses it, and Q-18 can release onto it.**

Evidence:
- Line 1865 (rev13): a generation is exposed "if it was granted to a device that is now revoked, or under a key-carrying grant that is now revoked".
- Plan L824-L826: a root `RotationGrant` "is signed by an active custodian of N". The rotating custodian creates TRK `N+1`, and no plan line or draft line requires it to grant `N+1` to itself.
- Draft 691: a `RecoveryGrant` issuer "holding an acknowledged `RotationGrant` to the PREPARING `N+1`".

Scenario:
1. Custodian D rotates the root to `N+1` and grants it only to E and F (for example, a hand-over before retiring).
2. D is then revoked as `compromised`.
3. `N` is exposed but RETIRED. `N+1` is ACTIVE and "not granted to D", so the root shows clear.
4. Every fleet generation whose bound `RecoveryGrant` is under `N+1` shows clear on the root clause. No banner, no Q-18 block.
5. Yet D generated TRK `N+1` and can unwrap every `RecoveryGrant` under it, which means every FKEK.

The approved C-1 row already promises the right semantics ("every fleet whose ACTIVE key a removed device could hold"); the definition falls short of it.

Fleets are mostly covered indirectly, because a fleet key's creator must hold a root TRK. The root case is the real hole, and through the root clause it reaches every fleet.

Fix:
- A generation is exposed if any key-carrying grant for it (root `RotationGrant`, `ExistingRootGrant`, `FirstRootSelfGrant`; fleet `DeviceHpkeGrant`), or any `RecoveryGrant` under it, was **issued by** or **granted to** a now-revoked device.
- Add a vector: the rotating custodian excluded itself from `N+1` and is then revoked as `compromised` → root and fleets flagged and blocked.

Confidence HIGH on the logic. The scenario is uncommon, but the impact is silent disclosure of every key, so no downgrade. This hole predates revision 13 (it has been in the definition since revision 10), and I missed it in r8 and r8b; Q-18 makes it load-bearing.

## MINOR

1. Qualify 1879 and 1882: the release relies on the client verifying an unexposed, higher generation, not on the server's ACTIVE pointer. Within the no-history limit, a thief plus server can fake a rotation and release onto a thief key: a disclosure no worse than without Q-18, but not "never".
2. Update 1612 and the Q-18 rule: withholding the signed revocation (or, on no-history devices, D's root grant) prevents the block from starting. Omission no longer "only blocks a revert".
3. Plan-label completeness: state the in-flight commit rule (READY uploads complete; only new checkouts are refused) and how a blocked profile maps onto the closed `sync_state` enum (L1790-L1793). Otherwise "no plan line changes" is not demonstrated.
4. Q-18 cost (1882 and row 23): add that a stolen current custodian key can freeze commits tenant-wide on every device, permanently if it revokes every other `key.rotate` holder (→ Q-14). Also add that a rotation stalls, keeping the freeze, while any required member cannot ack (plan L289, L2618); the operator path is to remove that member first.
5. The approval-page note (11-13) and the status (166) say the L2566 Critic pass is "rounds 1 to 8b", but the Q-18 rule post-dates 8b. Cite this round (r9), and its follow-up check, once it passes.

## Verdict justification

- The decisions are recorded faithfully, and revision 12 is correct.
- The Q-18 rule resists the stated server attacks for devices with history: hidden reports, rollback, and "not required".
- One MAJOR remains (M26): a definitional gap that predates Q-18 but now decides when a commit block releases.
- After M26 and the minors, a diff check of 1612, 1865-1883, the Q-18 row and the vectors is enough.

## Open questions (unscored)

- Should the UI make `DEVICE_REVOKE` the default when an admin chooses `compromised` on a `FLEET_GRANT_REVOKE` (Q-17 design review)?
- D-3 `aead-stream` (L2443) remains open.