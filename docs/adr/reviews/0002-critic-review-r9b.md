# Critic narrow diff check, round 9b: ADR 0002 revision 14 vs revision 13

**VERDICT: ACCEPT-WITH-RESERVATIONS.** 0 BLOCKING, 0 MAJOR, 3 MINOR.

- M26 and the five r9 minors are fixed.
- Neither new passage that the author flagged as unreviewed (the release wording and the stolen-custodian freeze) introduces a defect beyond the minors below.
- No user decision changes.
- Minor 1 changes behaviour, so a glance at that one passage after the fix is enough. Minors 2 and 3 are wording only.

**Inputs:**
- Draft revision 14: 2249 lines, SHA-256 `4aa3fa53255e878a...`.
- Full `diff` against `.rev13.md` (97 diff lines), every hunk read.
- Plan re-read: L1159 (upload states), L1794-L1795 (`dirty`, `last_error_code TEXT`, unconstrained), L2040 (COMMIT operation persisted "before finalize").

Mode: THOROUGH.

## Round-9 items

| r9 | Status | Evidence (rev14 line) |
|---|---|---|
| **M26** issuer exposure | **Resolved** | Issuer-or-grantee clause (1867-1871), citing plan L824-L826; C-1 row detail lines (17) now match its approved "a removed device could hold"; vector (1930). Wording nit: minor 3 |
| Minor 1 release | Resolved in substance | Release needs a client-verified generation that is higher, unexposed and free of a `compromised` cause; ACTIVE is only reported (1891); PREPARING means availability only; no-history disclosure stated. Placement nit: minor 2 |
| Minor 2 omission | Resolved | 1614 and 1885 |
| Minor 3 in-flight / `sync_state` | `sync_state` resolved; in-flight partly | `AVAILABLE`/`CHECKED_OUT` with `dirty = 1` and a client-local `last_error_code` (plan L1795 is unconstrained `TEXT`, so no plan change); vectors (1931-1932). In-flight rule: minor 1 |
| Minor 4 costs | Resolved | Stalled rotation and the operator path (L289, L2618); stolen-key tenant-wide freeze falling back to Q-14 (1896-1898); Q-18 row (21) |
| Minor 5 citations | Resolved | 11, 166, 183-184, 223, with the follow-up check marked pending |
| Open note | Recorded, not decided | 1904, 1938 |

## Adversarial check of the two new passages

**Release wording (1891).** I re-ran the r9 attacks against the new text:
- server-reported ACTIVE pointing at a PREPARING generation;
- rollback to an older generation (blocked by "numbered higher" and 1750);
- hidden reports;
- fake rotation on a device with history (blocked by the sticky rule).

All hold. With the issuer clause, a generation that the revoked device created is now exposed, so the release can no longer land on it.

**Stolen-custodian freeze (1898).** Accurate and complete:
- every device counts the thief's revocations until the thief key is itself counted as revoked;
- if every other `key.rotate` holder is revoked, nobody can sign a rotation that the sticky rule accepts, so Q-14 is the only path;
- the text correctly calls it an availability cost within custodian authority.

## MINOR

1. **The in-flight rule completes commits whose upload is not yet on the server.**
   - Line 1886 completes "a commit whose `CommitRequestV2` and upload were already persisted ... (upload `READY`, **or a persisted COMMIT operation**)".
   - Plan L2040 persists the COMMIT operation "before finalize", so the upload may still be `OPEN` with chunks unsent.
   - The justification, "Its ciphertext is already on the server", is then false: completing it uploads more ciphertext under the stolen key to a possibly hostile server.
   - Fix: complete only when the upload is `READY`, or `FINALIZING` under recovery, because then the bytes are on the server. An upload still `OPEN` is aborted (plan L1159 `ABORTED`), and its operation ends with the local `ROTATION_REQUIRED_COMPROMISED`. Replay of already-sent request bytes stays byte-identical, so L2040-L2041 and L2377 still hold.
   - Add a vector: COMMIT operation persisted, upload `OPEN` → aborted, nothing more sent.
2. **Sentence misplacement in the release text (1891).** "For a fleet flagged through the root, that means the root first, then the fleet; ... Commits then use the new generation. A revert ... only after the rotation" was appended to the no-history disclosure bullet, so it reads as if it applied only in that case. Move it back to the release rule itself.
3. **The issuer clause wording does not match its own gloss (1868, 1871).**
   - The clause covers "any key-carrying grant for it, or any `RecoveryGrant` wrapped under it". For a fleet generation, its own `RecoveryGrant` is not "wrapped under" it, and a fleet `RotationGrant` is not key-carrying.
   - Yet 1871 says "Their issuers still count under the issuer clause".
   - In practice both issuers are root custodians whose root falls inside the checked range (D-2 issuer matrix), so the root clause covers them, and this is not a hole.
   - Fix: say "for a fleet, also the issuers of its `RecoveryGrant`s and `RotationGrant`", or drop the gloss and state the indirect coverage.

## Verdict justification

- All r9 findings are fixed.
- The release rule and the freeze cost survive the attacks.
- Only minor 1 has behavioural content: a narrow window, a single partial upload, and the same key that the advisory state would use anyway.
- Nothing here needs the user.

## Reservations carried forward

- The approval-page note still marks the r9 follow-up as pending; cite this check once minor 1 is fixed.
- D-3 `aead-stream` dependency review (L2443): unverified offline.
- The open `DEVICE_REVOKE` default question goes to the Q-17 design review before W6.