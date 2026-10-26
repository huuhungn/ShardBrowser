# Critic review, round 8: ADR 0002 revision 10

**VERDICT: REVISE (narrow).** 0 BLOCKING, 1 MAJOR, 5 MINOR.

**Page readiness: not yet.** The "Decisions for user approval" page can go to the user after five edits:
- M25;
- minors 1 and 2, which change what the user is told about decided C-3 and Q-13;
- minor 3, the "new server work" label;
- minor 4, the RecoveryGrant evidence that M25 needs.

None of these reopens C-1, C-2 or C-3. A diff check of those passages is enough; a full round 9 is not needed.

**Inputs:**
- Draft revision 10: 2125 lines, SHA-256 `9578a2df678172e6...`.
- Full diff against `.rev9.md` (223 diff lines), every hunk read.
- Plan (SHA prefix `a4a136c9`): L18, L45, L289, L445, L463, L495, L496, L947, L1233, L1237, L2032, L2038, plus every "năm/five" site.
- Code: `server/src/auth.rs:186-234` and `server/src/audit.rs:15-32`.

Mode: THOROUGH. No escalation: one MAJOR, no CRITICAL.

## Round-7 items

| r7 | Status | Evidence (rev10 line) |
|---|---|---|
| **M22** epoch at first acceptance | **Resolved** | `== Ebind` with the leaf-by-inclusion exception (1667-1671); usable rule (1621); codes `HEAD_ROLLBACK_DETECTED` (plan L1233) and `RESTORE_EPOCH_TRANSITION_REQUIRED` (plan L1237) verified; vectors (1721-1725); harness (604-607); Q-1, D-1 and trust-chain rows. Correctly unlabelled: this is literal L524 and L375 |
| **M23** sticky proven revocation | **Resolved for devices with history** | In "usable" (1624), in `Cust` and in the first-sight check (1633-1635, 1676); stated limits (1681-1683); vectors (1714-1720); D-6 (e) (1322-1325). The no-history residual is stated and asserted by a vector. Addition (b) is a separate issue: minor 2 |
| **M24** `rotation_required` | **Resolved in definition** | Exposed generations (1857), the fleet clause with current or superseded `RecoveryGrant`s (1859), root first (1860), harness (1872-1873). The client-side derivation claim is not implementable as written: M25 |
| Minor 1 C-1 lines | Resolved | L34, L2676, L2764 on the C-1 row (18), the Q-13 row (33) and in Q-13 (1855) |
| Minor 2 counts | Resolved by rule | 33, 1867-1870. Nit on L2032: minor 5 |
| Minor 3 logins | Fact fixed (500-506, 603, 610). Labels: minors 1 and 3 |
| Minor 4 GC | Resolved | 19, 352, 609 |
| Minor 5 advisory | Advisory status stated (18, 1861) | Derivation: M25 |
| Minor 6 re-file | Resolved | 103, 1864, 1875; liveness cost stated |
| Open questions | Q-18 and Q-19 added and left open (1879-1880) | |

## Author addition (a): a superseded RecoveryGrant still exposes the fleet

**The rule is correct.**
- A revoked custodian holds TRK `N`, and the server keeps the old `RecoveryGrant` under `N` for the current fleet generation.
- A root rotation alone (D-5 rewrap) does not remove that old ciphertext, so only a fleet rotation clears the exposure.
- The order "root first, then each fleet" follows from this.
- "`RotationGrant` carries no key" is verified against plan L496 (fields only: previous key ID, counts, hashes, `activation_not_before_ms`).

**Costs:**
- Every custodian revocation, including `retired` and `rekeyed`, raises a banner on the root and every fleet. Revocations of honest devices will therefore produce the same banner as compromises. That is banner fatigue for an advisory signal; this is an open question, not a defect.
- A custodian whose window merely lapses exposes nothing, so the three-year re-key (D-6 (c)) causes no flood.

**Derivation:** see M25.

## Author addition (b): `issued_at_ms` at or after the revocation's `issued_at_ms` is refused on every device

Line 1624: "a container signed by `D`'s key that is not yet accepted when the revocation is counted is unusable if its `issued_at_ms` is at or after the earliest counted revocation's `issued_at_ms`."

Adversarial reading, scored as minor 2:
- **Security gain is close to zero.** A thief always backdates below the revocation's time; the draft's own text says "only a backdated record escapes".
- **The revoker chooses the time.** Its `issued_at_ms` comes from the revoker's clock. With an honest server it is bounded only by the 30-day filing window (1238); with a hostile server it is not bounded at all.
- **Consequence: a split view across devices from an honest operation.** Suppose the revoker's clock is days behind, or a custodian files a prepared revocation late:
  1. records D legitimately issued in that interval (a custodian appointment, a device approval) are refused on new devices and on any device that had not yet fetched them;
  2. devices that verified them earlier keep them;
  3. on new devices the cascade runs through `Cust`, so heads from devices approved by the affected subtree quarantine there, while older devices accept them.
- **It pre-decides open Q-19.** It withdraws records issued at or after the revocation's time, for not-yet-accepted records only, while Q-19 (1880) says the effective time is open.
- **Fix:** drop (b) and keep it as a Q-19 option, with this divergence stated. If it stays, it must be presented to the user as a decision that partly settles Q-19, with the clock-skew and late-filing divergence and a vector.

## MAJOR

**M25. A hostile server can hide the fleet half of `rotation_required` after a custodian revocation, although the page says clients derive the flag from signed evidence.**

Evidence:
- C-1 row (18): "Clients derive it from signed evidence and do not trust a server flag."
- Line 1862: the derivation uses "the `RecoveryGrant` and generation fields it verifies"; "It cannot hide a cause that rests on a signed `DeviceRevocationV2` the client holds."
- Trust evidence (1601-1606) carries root grants, approvals, capabilities, revocations and ACTIVE `DeviceHpkeGrant`s, but **no `RecoveryGrant` or `RotationGrant` containers**. An ordinary client never otherwise verifies the `RecoveryGrant`s of a fleet generation.

Scenario:
1. Custodian D is revoked, and every client holds the signed revocation and D's root grant for generation `N`.
2. The root banner shows; the custodian rotates the root.
3. The hostile server supplies no `RecoveryGrant` evidence, so no client can see that each fleet's ACTIVE generation is wrapped under `N`. Every fleet banner clears.
4. Fleets are never rotated, and D (with the server) reads every new fleet snapshot. This is the M24 (a) outcome, against the adversary the derivation claim was meant to address.

Fix, small and client-verifiable:
- Add to the trust evidence, for each fleet the requester belongs to, the ACTIVE generation's `RotationGrant` and the `RecoveryGrant` it binds (`recovery_grant_signed_container_hash`, plan L496). For generation 0, use its initial `RecoveryGrant`.
- Rule: the fleet is clear of the root clause iff that bound `RecoveryGrant`'s `recipient_root_generation` is not exposed.
- This rule is equivalent to the current-or-superseded clause, because a generation's activation `RecoveryGrant` is issued under the root ACTIVE at issuance (draft 688; plan L289). A generation activated under an unexposed root therefore never had a wrap under an earlier exposed root.
- Missing evidence means flagged, so omission can only add a banner.
- Add a vector: the server omits the RotationGrant or RecoveryGrant evidence → the fleet stays flagged.

Confidence HIGH. Confidentiality impact against an in-scope adversary, so no downgrade. The fix is short.

## MINOR

1. **C-3 row overstates "the literal fail closed".** The row (20, unchanged) says K2 "makes v1 read-only too, the literal 'fail closed' of L2264" and "K2 follows L2264 literally". Revision 10 (500-506) correctly says that v1 logins and reads keep working, on a DB whose integrity is in doubt in K2. That is write-closed, not fail-closed. Relabel K2 for v1 as "reinterprets L2264 (fail closed = writes closed for v1)", state on the row that logins and reads continue, and let the user confirm. Realist: an attacker able to swap the DB can read it from disk anyway, so the impact is low; the issue is honesty on a decided row.
2. **Drop or surface addition (b)** (above).
3. **Minor-3 audit reporting is labelled "New" only in the D-1 body (505).** The D-1 page row says "an audit write that fails is reported (logged and counted)" as if it already existed. It is new server work that changes the shipped v1 path (`server/src/audit.rs:22-31` discards errors with `let _ =`). Mark it on the row as "new server work, touches shipped v1 audit", and give it a work item.
4. **RecoveryGrant evidence and determinism.** This is the evidence half of M25: list the containers in 1601-1606 and state the clear condition. In the same section, add the mutual-revocation vector. A new device that sees, in one evaluation, D's revocation by E and D's backdated revocation of E counts both, because same-evaluation containers count as seen before (1634). It therefore treats honest custodian E as revoked. This sits inside the stated no-history limit, but it is its sharpest case and should be asserted like the other documented limit (1720).
5. **Count rule at L2032.** Plan L2032 counts "five approval/capability/fleet-grant schemas" persisted in `signed_authorization_records`. The draft stores `DeviceRevocationV2` in its own `v2_device_revocations` table (1866), so turning L2032's five into six would wrongly put it in that table. Either exempt L2032, or store the record in `signed_authorization_records` and drop the separate table.

## Verdict justification

- M22, M23 and M24 are fixed in substance, and the six r7 minors are fixed.
- One MAJOR remains (M25): the client-derivation claim on decided C-1 is false against a hostile server, and evidence plus one rule fixes it.
- Minors 1-3 change what the user is told on decided or approved rows.
- Recalibration: M25 was weighed against "the flag is advisory" and kept MAJOR, because the page sells client derivation as the defence against a hiding server.
- Prediction vs result: I predicted that additions (a) and (b) would be the weak spots. (a) turned out sound; (b) turned out risky. M25 was not predicted; it came from checking which evidence the derivation actually reads.

## Open questions (unscored)

- Banner tiering by `reason_code` (`compromised`/`lost` vs `retired`/`rekeyed`), so that routine retirements do not train users to ignore the banner.
- Q-18, Q-19, D-3 `aead-stream` (L2443) and Q-17 remain open, as stated in the draft.