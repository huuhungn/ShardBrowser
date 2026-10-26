# Critic narrow diff check, round 8b: ADR 0002 revision 11 vs revision 10

**VERDICT: ACCEPT-WITH-RESERVATIONS.** 0 BLOCKING, 0 MAJOR, 2 MINOR (one new, one optional).

**Page readiness: yes.** The "Decisions for user approval" page can now go to the user. Neither minor changes what a page row asks the user to approve, so both can be fixed in the body in parallel.

When showing the page, the coordinator must point out:
- the **C-3 relabel** that the row asks the user to re-confirm;
- the **open user questions** Q-17, Q-18, Q-19 and Q-20 (none decided).

**Inputs:**
- Draft revision 11: 2164 lines, SHA-256 `aa8488b2633be497...`.
- Full `diff` against `.rev10.md` (118 diff lines), every hunk read.
- Re-read: draft 684-691 (issuer matrix), 1000-1006 and 1519-1528 (generation-0 hash sources).
- Plan L496 and L2032 re-checked.

## Round-8 items

| r8 | Status | Evidence (rev11 line) |
|---|---|---|
| **M25** hidden fleet evidence | **Resolved** | Evidence (1609): ACTIVE generation's `RotationGrant` plus the bound `RecoveryGrant` (L496); for generation 0, every gen-0 `RecoveryGrant`. Client test (1863-1866), missing evidence = flagged (1868), limit (1869), C-1 row (18), derivation text (1872), vectors (1885-1886) |
| Minor 1 C-3 wording | Resolved | C-3 row (20) now "**reinterprets** L2264 ('writes closed' for v1; logins and reads continue)" with "Please re-confirm"; D-1 row (36); K2 text (503). No remaining "literally" claim |
| Minor 2 addition (b) | Resolved | Removed from "usable" (1627), ordering and limit (1637-1638), and vectors (1722). Now Q-19 option (C) (1896-1900) with gain, skew and divergence stated. Grep: the cutoff appears only in Q-19 and the history |
| Minor 3 audit labelling | Resolved | D-1 row (36) "New server work (touches the shipped v1 audit path ...)"; WI-AUDIT-RO (585) scoped to `mode=ro`, v1 unchanged otherwise; 506 |
| Minor 4 mutual revocation | Resolved | Asserted limit vector (1722); residual text names it (1638) |
| Minor 5 L2032 | Resolved | Exempt with the stated reason (33, 1877-1881); plan L2032 verified ("five approval/capability/fleet-grant schemas" in `signed_authorization_records`; "sixth root-grant schema" in dedicated tables) |
| Q-20 | Added and left undecided (1901) | |

## Addition (a): the fleet test also checks every later root

**Correct, and it fixes a gap in my own r8 rule.**
- My rule checked only the root that the bound `RecoveryGrant` names.
- Generation `g` is activated under root `N`. D-5 then rewraps `g` under `N+1`, `N+2`, and so on at each root rotation.
- So a custodian of `N+1` revoked later can unwrap `g`, while `N` stays clean.
- The vector at 1886 asserts exactly this case.

**New gap, minor 1: the upper bound "up to and including the ACTIVE root" (1866) misses a PREPARING root above ACTIVE.**
- During a root rotation to `N+k`, D-5 rewraps retained fleet generations under PREPARING `N+k` (issuer matrix, 691: "a custodian of the ACTIVE root `N` holding an acknowledged `RotationGrant` to the PREPARING `N+1` it wraps under").
- If the holder of that `RotationGrant` is revoked while `N+k` is still PREPARING, then `N+k` is exposed and `g` has a wrap under it.
- But `N+k` is above ACTIVE `N`, so the fleet test does not look at it. Root `N` itself may be clean (for example, a custodian appointed only through the rotation). Root and fleets then all show clear.
- The rotation may stall indefinitely, because the revoked device never acks.
- The gap closes once the rotation activates or is superseded, since `N+k` then falls inside the range. Until then it is silent.
- Fix: "no root generation numbered above the bound root, in any state, is exposed". Drop the upper bound and add a vector for the case.

## Addition (b): generation 0 limit

**Honest and correctly scoped.**
- For generation 0, `recovery_grant_signed_container_hash` comes from the D-9 create and activate payloads (1004-1006, 1526-1528). Those are mutation bodies, not records in the trust evidence.
- So nothing in the signed authorization family binds the first wrap, as the draft says (1864).
- Using the lowest `recipient_root_generation` ever verified (cached in W6) is sound for devices with history.
- For devices without history, the limit is no wider than the existing one at 1869: a hostile server can already hide exposure from such a device by omitting the revoked device's root grant.

**Optional, minor 2:** on a device with no cached gen-0 evidence, start the gen-0 range at the tenant's first root generation instead of the lowest one shown. Cost: a false banner for a gen-0 fleet created after an exposed root was rotated away, cleared by one fleet rotation. Benefit: this limit is gone. It is a trade-off, not a defect; take it or leave it.

## Verdict justification

- Every r8 finding is resolved.
- Addition (a) is right in substance, but its upper bound leaves the transient PREPARING-root gap (minor 1).
- Addition (b) is honest.
- No row of the approval page needs to change for either minor.
- Mode: THOROUGH; no escalation.

## Reservations carried forward

- C-3 relabel: the user must re-confirm it.
- Q-17, Q-18, Q-19, Q-20: user decisions.
- D-3 `aead-stream` dependency review (L2443): unverified offline.
- Every proposed row still needs the user's approval.