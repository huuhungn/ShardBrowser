# Critic review, round 2: ADR 0002 draft revision 2

**VERDICT: REVISE** (2 BLOCKING, 7 MAJOR, 11 MINOR). Mode: ADVERSARIAL (carried over; new BLOCKING findings in new material).

Draft = `scratchpad/adr0002-g2-decisions-draft.md` revision 2 (cited `r2 Lnnn`); revision 1 kept as `adr0002-g2-decisions-draft.rev1.md` (SHA-256 `d3277c7f...1901`). Plan, ADR1 and gap report hashes unchanged from round 1.

## Overall assessment

The revision is substantive, not cosmetic. Of the round-1 items, B1 (structure), B2 (ambiguity), M1, M2 (rule exists), M3, M6, M7 and M8 are closed. B3 is closed in D-5 but undermined by a contradiction in D-9.

The new material introduces two soundness problems:
1. The D-6 / trust-chain exposure bound shown to the user ("730 days instead of 10 years") is false. With self-renewal, a stolen custodian key plus a hostile server is valid against clients indefinitely.
2. The Q-1 restore design carries revocations forward but not key-generation retirement. A restore across an exclusion rotation resurrects an ACTIVE fleet/root generation whose keys the excluded device holds.

Several new mechanisms also have a contradiction or liveness bug: the WAL sidecars in D-1 step 4, the D-9 recovery-ack actor, the trust-evidence ancestry, and the manifest validity time.

## Round-1 findings: resolved or not

| Round 1 | Status | Evidence |
|---|---|---|
| B1 crash mapping | **Resolved in structure.** State byte (r2 L238), P1 write primitive for every write (r2 L308-L319), K1-K12 (r2 L332-L345), crash-point table (r2 L353-L367). K5 now maps an unparsable manifest with an unadvanced authority to L2260. One crash point still lands in K12 instead of its mapped row (new M9). | |
| B2 trust chain | **Ambiguity resolved:** exact fixpoint (r2 L1327-L1365), A0 pin, full-ID I-1 (r2 L1431), 128-bit SAS with value sources (r2 L1385-L1403), no re-anchoring (r2 L1407-L1411). New problems: B4, M12, M13. | |
| B3 recovery | **Resolved in D-5** (bundle carries TRK + all retained FKEKs + A0, r2 L937-L956; rewrap rule r2 L900-L909) **but unsatisfiable as written** because of the D-9 ack actor (M11). | |
| M1 issuer widening | Resolved: custodian-only reading stated (r2 L472-L479); subject eligibility (r2 L518-L523). | |
| M2 manifest signer | Rule added (r2 L516, L1362-L1365), but its time basis is `created_at_ms` (M12). | |
| M3 reader by magic | Resolved (r2 L704-L711, test r2 L778-L779). | |
| M4 TTL | Replaced by tiered TTL + renewal; the stated bound is wrong (B4). | |
| M5 Q-1 | Answered (r2 L32-L43), but carry-forward is incomplete (B5) and the L427 reinterpretation is not flagged (M14). | |
| M6 fleet lifecycle | Resolved by D-9 (plan amendment flagged, r2 L1220), except the ack actor (M11). | |
| M7 crate fallback | Resolved (r2 L656-L663; acceptance conditional, r2 L557-L558). | |
| M8 restore entry point | Resolved (r2 L376-L413), but it silently requires a readable live DB (M10). | |
| Minors | All addressed as listed in r2 L1494, except minor 10's new citation (minor 9 below). | |

## Citations checked in revision 2

New or changed plan citations opened: L289, L440, L1233 (`KEY_SUBSTITUTION_DETECTED`), L1240 (`ENVELOPE_UNSUPPORTED`), L1412 (commit checks role, capability, signature, lease owner), L1502 (`recovery_ready`), L1846-L1850, L2618; ADR1 L415-L425 (ACTIVE-pointer row check). All say what is claimed except L1846-L1850 (minor 9). The commit-identity correction (r2 L145-L160) matches round-1 evidence.

## BLOCKING

**B4. The exposure bound for a stolen custodian key is false; with renewal it is unbounded, and the user is asked to approve D-6 on that bound.**
- r2 L91-L92 (approval page): `a stolen custodian key stays usable against clients for at most 730 days instead of 10 years`. r2 L1374-L1378: `a stolen custodian key is usable against clients for at most about 2 x 730 days after its last legitimate window`.
- Fixpoint step (r2 L1333-L1336): a grant adds a window if the issuer's window contains `r.issued_at_ms`. The signer chooses `issued_at_ms`, and self-renewal is allowed (r2 L1339-L1340, D-6 step 1 at r2 L1059-L1063).
- Attack: a thief holding custodian key K (last window ends at T) signs an `ExistingRootGrant` to K itself dated T-1 ms, giving a new window to T+730d. Before that ends, the thief signs the next one, and so on. The approval and capability links needed by rule 1 and rule 3 are self-issued the same way (rule 3/4 only require the issuer to have been a custodian at `issued_at_ms`).
- A hostile server presents the chain and hides revocations (L376); the client accepts it indefinitely. The same holds for appointing fresh attacker-controlled custodians.
- Only non-custodian keys (which cannot renew themselves) get the 365-day bound.
- Why BLOCKING: the approval page presents a security trade-off that does not exist, and D-6 is chosen on it.
- Fix: state honestly that, without client-visible revocation, a stolen custodian key is unbounded against a hostile server, and keep TTL only as a bound for non-custodian keys and for a non-hostile server. Optionally add a detection mitigation: every client surfaces each newly accepted custodian key and each custodian renewal (UI event and audit), so an unknown custodian is noticeable. Rewrite r2 L82-L94 and r2 L1374-L1381 accordingly.
- Confidence HIGH (follows directly from rules 1, 3, 4 and D-6 step 1).

**B5. Restore resurrects retired key generations; revocation carry-forward does not cover them (Q-1 / D-1).**
- r2 L293-L295: the carry-forward lists only revoked authorization rows and devices. Generation state is not carried. If a root or fleet rotation happened between backup and E (typically to exclude a device, L829-L832, L1385), the candidate has generation N ACTIVE, while live had N+1 ACTIVE and N RETIRED. The excluded device holds FKEK N / TRK N.
- After step 5:
  - The server's ACTIVE fleet generation is N. New or re-granted devices receive FKEK N through `DeviceHpkeGrant`s (D-2 subject rules check only device state). Snapshots they push are readable by the excluded device. Server ciphertext is not trusted for confidentiality (L2551), so this is in scope. That breaks L1385 ("revoked device does not receive a new generation").
  - The next rotation reuses generation number N+1 with a new key, so every client that pinned the old N+1 `fkek_key_id` raises `KEY_SUBSTITUTION_DETECTED` (r2 L1358-L1360).
  - Clients that recorded N+1 refuse to push (r2 L1380-L1381), so the fleet stalls.
- The approval page (r2 L12, L41-L43) tells the user that carry-forward closes the resurrection problem; it closes only half.
- Fix (pick one and put it on the approval page): carry forward generation rows (state, key IDs, recovery and grant hashes) for every fleet and root generation in live whose number exceeds the candidate's; or refuse `restore prepare` when the live DB has a generation newer than the candidate's unless the operator accepts a mandatory post-restore rotation to a number above the live maximum, with the old ACTIVE generation marked RETIRED in step 5. Add harness rows for restore-across-rotation.
- Confidence HIGH.

## MAJOR

**M9. D-1 step 4 can leave a stale `-wal` beside the installed candidate; a crash point mapped to K8/K9 ends in K12.** r2 L316: `Rename the live DB (with any -wal/-shm) ... rename the candidate to the DB path`. Multi-file renames are not atomic, and the order is unspecified. If the crash falls after the main file moves but before `shardx.db-wal` moves:
- the table maps this to K8 (r2 L362, `M` absent);
- `restore commit` installs the candidate next to the old WAL;
- the K9 checkpoint (r2 L342) replays old frames into the candidate, so the hash mismatches and the restore ends in K12, where the operator has to recover by hand.

Plan L2267 requires each crash point to map to exactly one row deterministically. Fix: in `restore prepare`, under the lock, checkpoint the live DB with TRUNCATE and refuse if any `-wal`/`-shm` is non-empty. In step 4, move the sidecars before the main file. Before the install rename, assert that no sidecar exists at the DB path. Add this crash point to the table.

**M10. The restore design requires a readable live DB, so the `disaster_recovery` case (and DB loss) is impossible, and Q-1's safety depends on it.** `restore prepare` requires signers that are `a live root custodian ... in the live DB at E` (r2 L382). Coverage uses heads `in the live DB at E` (r2 L302-L306). Carry-forward is computed from the live DB (r2 L293-L295). If the live DB is lost or corrupt, which is the usual reason to restore, no procedure exists. If a later relaxation proceeds without it, Q-1 resurrects every post-backup revocation. Fix: state "live DB required; restore without it is out of scope and fails closed", and say what the operator does on DB loss (for example: new tenant, or a defined revoke-all-non-custodians policy). Put this consequence on the approval page under Q-1/D-1.

**M11. D-9's recovery-ack actor makes D-5's rotation rule unsatisfiable.** D-5 (r2 L900-L904) requires acknowledged `RecoveryGrant`s with `recipient_root_generation = N+1` before N+1 activates. D-9 (r2 L1235) says the ack actor is `a custodian of recipient_root_generation`. D-2 (r2 L503-L504) defines custodian as holding a grant `in the ACTIVE root generation`. While N+1 is PREPARING, nobody qualifies, so root rotation can never activate. D-2's issuer row already has the right rotation exception (r2 L512); D-9's ack actor needs the same one (a custodian of ACTIVE N holding an acknowledged `RotationGrant` to N+1). Confidence HIGH; trivial fix.

**M12. Manifest signer authority is evaluated at `created_at_ms`, which the plan says is not validity authority.** Rule 6 (r2 L1362-L1365) checks approval and `profile.commit` at the payload's `created_at_ms`. Plan L526: `created_at_ms ... informational, not lease/validity authority`. Any key that once held `profile.commit` can backdate `created_at_ms` into its old window and produce manifests clients accept forever, subject only to head chaining. That voids the 365-day bound for capability holders too. Fix: check the signer chain at verification time (`now`) when a head is first accepted, and pin the result; or document a different, plan-consistent time source.

**M13. The trust-evidence endpoint omits the expired ancestry the fixpoint needs; verification fails after about two years.** r2 L1310-L1312: evidence contains `the tenant's FirstRootSelfGrant, unexpired root grants, and the approvals and capability grants of custodians...`. The step rule (r2 L1333-L1336) needs the issuer's window at the child's `issued_at_ms`. After a self-renewal, the previous grant is the issuer; once it expires (about 730 days after bootstrap with renewal at 50%), it is no longer returned, and every current custodian becomes unprovable for new devices and for re-verification. The same applies to historical approvals and capability grants required by rules 3 and 4. Fix: evidence returns the full ancestry of every live custodian (all root grants, plus the approvals and capability grants that each edge relies on, expired or not), and the 4096 cap is sized against that history. Local caching (W6) alone does not help new devices.

**M14. The approval page is not decidable as written for Q-1 and D-6, and it omits decisions those rows depend on.**
- Q-1 (r2 L12, L36-L37) reads L427's "same tenant/epoch" as "issuer live in the current database". That reinterprets plan text. The page does not mark it as a plan reinterpretation needing the same Architect + Critic pass it requires for amendments (r2 L7-L8).
- D-6's trade-off rests on B4.
- Q-14 (r2 L1468-L1471) is the only path out of "every custodian lapsed" (r2 L1415-L1423, D-6 step 5 at r2 L1070-L1072), but it is not on the page.
- Q-13 (r2 L1465-L1467) owns the L1108 / L2618 requirement "revoke + new-generation activation is one logical audited transaction". D-9 defers it (r2 L1257-L1259), and it is not on the page either.

Fix: add Q-13 and Q-14 rows with recommendations, mark Q-1 as a reinterpretation of L427 (amendment-equivalent review), and correct D-6 per B4.

**M15. Q-7's `SHXBAK02` is not specified enough to decide.** r2 L17, L67-L71, L747-L748: `passphrase header + SHARDXBK suite-2 body`. A suite-2 body is defined by `EnvelopeIntentV2`/`DekSlotV2`, which require tenant, fleet, profile, lease and snapshot IDs, an FKEK key ID and generation, and a signed manifest (L643-L658, L607-L612). D-3's release order hinges on verifying that manifest before decryption (r2 L717-L720). For a local passphrase backup there is no tenant, fleet, FKEK, lease or manifest signer, and the draft does not say what fills those fields or what replaces step 2. Fix: either define a local profile of the envelope (placeholder rules, how the passphrase KEK replaces the FKEK wrap, what authenticates the object before decrypt) or keep Q-7 as "deferred, needs its own design".

## MINOR

1. Join SAS (r2 L1398-L1399), `second preimage, about 2^128 work`: if the server substitutes on both screens (fake joiner keys on B, fake A0' on D), it needs only a collision between two inputs it controls, about 2^64 work. That must be done online after D enrolls, so it is still impractical, but correct the claim.
2. The client fixpoint treats a `RotationGrant` to a PREPARING root as custodianship (r2 L1333). D-2's server definition requires the ACTIVE generation (r2 L503-L504). Align them, or state that the gap only matters with a hostile server.
3. Rule 4 accepts only device-scoped capability grants (r2 L1348). D-2's manifest signer and issuer rows say "holding" (r2 L516), which server-side could include account-scoped grants. Make both say device-scoped, or define account-scope matching.
4. `RecoveryGrant` TTL 3650 days (r2 L1052) is not in the renewal list (r2 L1064-L1065), so without a root rotation server-side recovery lapses at year 10. Add it or state the limit.
5. Fallback key file (r2 L974-L979) "same construction as the bundle" inherits header fields (`tenant_id`, `root_generation`, `root_key_id`) that mean nothing for a local multi-key file. Give it its own header map.
6. r2 L955-L957: `recovery_ready = 0` is local to the activating client, so "the UI blocks new snapshots for that fleet generation" does not stop other devices. Say it is advisory, or make it a server-side flag.
7. K5 (r2 L338) also matches `X = E+1, M = X` with a corrupt manifest. The row label L2260 and the abort text "authority still E" (r2 L384) are then wrong. Split it into K5a (pre) and K5b (post, retire only).
8. A tenant not needing a transition can end with zero live custodians after carry-forward (its custodian replaced after the backup). Detect it in `restore prepare` and list it in the summary.
9. r2 L1128-L1130 cites L1846-L1850 for "every `*_sha256` next to exact bytes is a plain SHA-256"; those lines only check length 32.
10. D-9 gives `RotationGrant` state `FILED` with no ack (r2 L1234-L1235), but the plan table `v2_fleet_rotation_grants` has `acked_at` (L1077) and L1382 says the client "ký ack" for the set. State this as a deviation, or allow the ack.
11. D-6 step 1 (r2 L1059-L1063) renews the approval before the capability grants, but issuing the approval needs a live `device.approve` (r2 L509). Reorder, or note that capability grants renew on their own cycle first.

## What's missing

- Harness rows for restore across a rotation (B5) and for the WAL-sidecar crash point (M9).
- A UI/audit event for "new custodian accepted" as the only practical detection for B4.
- On the approval page: Q-13, Q-14, and the live-DB precondition (M10).

## Approval page: decidability per row

| Row | Decidable as written? |
|---|---|
| Q-1 | No: reinterprets L427 unflagged; carry-forward incomplete (B5); needs the live DB (M10) |
| Q-2, Q-4, Q-6 | Yes |
| Q-5 / D-9 | Yes once the M11 ack actor is fixed; amendment correctly flagged |
| Q-7 | No (M15) |
| Q-12 | Yes (minor 1 wording) |
| D-1 | No until B5, M9, M10 are fixed |
| D-2 | Yes (minor 3) |
| D-3 | Yes, conditional on the L2443 review as stated |
| D-4, D-7, D-8 | Yes |
| D-5 | Yes once M11 is fixed |
| D-6 | No (B4; depends on the missing Q-14) |
| Trust chain / 2.4.3 | I-1 yes; full chain no until B4, M12, M13 are fixed |

## Self-audit and realist check

- B4: HIGH. Not refutable: the rules quoted permit it. Kept BLOCKING because it is a false security claim on the approval page, not merely an accepted limit.
- B5: HIGH. Security (confidentiality against an excluded device) plus liveness. Not downgraded: security-breach class.
- M9: HIGH, but a fail-closed outcome (K12), so MAJOR, not BLOCKING.
- M10: fail-closed today, so MAJOR. Mitigated by: prepare refuses without live custodians.
- M13: liveness only. Mitigated by: caching on existing devices; it fails closed.

## What would upgrade the verdict

- Correct B4's claim, with the detection mitigation or an honest statement.
- Close B5 by carrying generation state forward or forcing a rotation.
- Fix M9 and M11 (small textual fixes), M12, and M13.
- Add Q-13 and Q-14 to the page, flag the Q-1 reinterpretation, and either specify or defer Q-7.