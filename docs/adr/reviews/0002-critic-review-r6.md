# Critic review, round 6: ADR 0002 draft revision 6

**VERDICT: ACCEPT-WITH-RESERVATIONS.** 0 BLOCKING, 0 MAJOR, 2 MINOR.

**The "Hold" on the Trust chain / 2.4.3 row is lifted.** M21 is fixed. The one new minor (minor 1, how the signed revocation reaches clients) fails safe: if it is never fixed, a revert is blocked, but nothing is wrongly accepted.

Draft: `scratchpad/adr0002-g2-decisions-draft.md`, revision 6 (1943 lines). Method: a full `diff` against `.rev5.md`; every changed hunk read.

## Round-5 items

| Round 5 | Status | Evidence (rev6 line) |
|---|---|---|
| **M21** unsigned reports enable revert | **Resolved** | See the list below |
| Minor 1: error allowlist | Resolved | 360: `superseded_by_restore_epoch: U64` added to the allowlisted fields of `BASE_VERSION_MISMATCH` (L1220). Plan L1220 permits allowlisted optional fields, so the change complies |
| Minor 2: K2/K4 "v1 unaffected" | Resolved | 24 (D-1 cell, reinterprets L2263, L2264) and 499 (class text) |
| Minor 3: advance the pin first | Resolved | 1631: "First, the client advances its pin through every valid head in chain order". Vector at 1647. Advancing stops at the first rejected head, because ordinary acceptance fails there, so it cannot advance past the revoked run |
| Minor 4: head pinned, then its signer revoked | Resolved | 1629 and the vector at 1648 |

How rev6 resolves M21:
- 1623-1625: two strengths of revocation. "Proven" means a signed `DeviceRevocationV2` that chains to `A0`, or local distrust. "Reported" means an unsigned evidence entry only.
- 1627: "Only a proven revocation enables the revert path". A false report causes at most a quarantine.
- 1629: the revert content and the committer's offer to revert both require a proven revocation.
- 1635: the skip condition is "proven revoked"; reported-only and lapsed do not count.
- 1646: new vector, unsigned report only → refused.
- 1570: the "only tighten" invariant is restated.
- 32: the approval row states the signed-revocation condition.

## Adversarial re-check of the fix

These cases all hold:
- **False report, hostile server:** the result is quarantine only (DoS). No acceptance is possible. This restores the L1570 invariant.
- **Forged `DeviceRevocationV2`:** to be "proven", it must chain to `A0` by rules 1-4. The issuer must be a custodian holding device-scoped `device.approve` over the device's approval scope (draft line 92). A server cannot forge one without a custodian key.
- **Malicious custodian revokes an honest device to roll back its head:** this is within the custodian trust model, which is equal to the authority already needed to approve devices. The revocation is audited and permanent (1779), so it is not a new capability.
- **R's own signer with only a reported revocation:** rule 1 ("not revoked or distrusted", 1632) refuses R. That is a correct tightening, since a report may refuse but never accept.
- **Server withholds the signed revocation:** the revert is blocked, which is DoS only. It is fail-safe, and the same class as the evidence-omission rule (1565).

## MINOR

1. **The signed revocation has no delivery path to clients.** Two parts of the draft leave it out:
   - The evidence set (1560-1563) lists root grants, approvals and capability grants, but no `DeviceRevocationV2` containers.
   - The page map (1557-1558) carries revocations only as unsigned tuples.

   Q-13 (1767-1768) defines how the record is *filed*, but no read path defines how other clients *obtain* it. As written, a proven revocation can only come from local distrust or from an implementation-specific fetch, so the revert path is unreachable for devices that did not file the revocation.

   Fail-safe, so MINOR. Fix: add "every filed `DeviceRevocationV2` of the tenant, as signed containers" to the evidence set; omission only blocks a revert. Add a vector for "device-revocation container fetched through trust-evidence".
2. Rule 6 (1624) says "chains to `A0` by rules 1-4" generically. Name the capability and time explicitly: the issuer holds device-scoped `device.approve` covering the subject device's approval scope at `issued_at_ms` (draft line 92), and the record's validity window contains its first-seen time (30-day filing window, 1235). Without this, two implementers could evaluate the window at different times.

## Remaining reservations (unchanged; not blockers for this draft)

- Architect + Critic pass for every row that reinterprets or amends the plan:
  - L427, L913, L1125;
  - L2243/L2251, L2263/L2264;
  - L299/L966-L970/L1105;
  - L1085/L1090/L1099/L1412/L2608;
  - L372, L375.
- The D-3 `aead-stream` dependency review (L2443), unverified offline.
- Q-17 custodian-event UX (owner decision).

## Verdict justification

- Mode: THOROUGH. No CRITICAL or MAJOR findings remain, so there was no escalation.
- Every claimed rev6 fix is present and correct in the diff.
- No new revision-6 text weakens any earlier fix: the diff touches only rule 6, the 1570 invariant, D-1 lines 24/360/499, the approval rows, the history and the status.
- Not ACCEPT outright, because of the external reservations above.