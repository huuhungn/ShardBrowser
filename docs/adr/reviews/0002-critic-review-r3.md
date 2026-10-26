# Critic review, round 3: ADR 0002 draft revision 3

**VERDICT: REVISE** (1 BLOCKING, 3 MAJOR, 8 MINOR). Mode: THOROUGH. ADVERSARIAL was applied to the new restore scope, which carries the only BLOCKING finding.

Draft = `scratchpad/adr0002-g2-decisions-draft.md` revision 3 (cited `r3 Lnnn`); revision 2 is kept beside it. Plan, ADR1 and gap report are unchanged.

## Overall assessment

Round 2 is largely closed:
- B4 is now stated honestly (r3 L127-L131, L1185-L1221).
- M9 has checkpoint, sidecar ordering and an assertion (r3 L383, L388, L444).
- M10 now requires a live DB (r3L305-L308).
- M11 has the ack-actor exception (r3 L1391, L991-L992).
- M12 uses first acceptance at `now` (r3 L1529-L1535).
- M13 returns paginated full ancestry (r3 L1474-L1482).
- M14 adds the Plan-lines column and the Q-13/Q-14 rows.
- M15 is deferred.
- The minors are fixed. The D-7 citations L439, L558, L583, L921 and L934 check out.

B5 is solved in principle by the data-plane/control-plane split. The live control plane's generations, revocations and grants can no longer roll back. The merge table itself has one FK contradiction that makes every restore fail. It also leaves stale receipts and unchecked signers.

## Focus questions

**1. Does the merge keep every invariant, FK and fencing rule?**
- Fencing: **yes.** Leases are dropped (r3 L292), `last_fencing_token = max(live, backup)` (r3 L290), and the next checkout token exceeds both (L1098).
- Generation and revocation invariants: **yes**, for every table taken from live.
- FK: **no** (B6).
- Idempotency/receipt invariants: **no** (M16).

**2. Can it accept a blob whose key or signer the live control plane no longer trusts?**
- Key: **no.** `v2_snapshots` keeps its composite FK to the live `v2_fleet_key_generations(…, generation, fkek_key_id)` (L1089). Generation numbers and key IDs are never reused (L1101), so a restored snapshot always names a key generation the live plane still holds. A RETIRED generation is legitimate retained data and leaks nothing new.
- Signer: **yes** (M17). Nothing checks a restored head's manifest signer against live revocations, and trust-chain rule 6 lets a user accept or re-sign such a head.

**3. The `v2_idempotency` and `v2_profiles` rules.** See M16 and minor 1.

**4. The 180-day renewal-fork threshold.** It is a weak, noisy heuristic, not a soundness problem; see minor 2.

**5. Is every approval-page row decidable?** All rows except D-1 (B6, M16, M18). The trust-chain row also mislabels its plan lines (M17, minor 7).

## BLOCKING

**B6. The restore scope drops `v2_uploads`, but every `v2_snapshots` row has a composite FK to `v2_uploads`. Every restore therefore refuses, or `--drop-unreferenced` deletes every snapshot.**
- r3 L293: `v2_sessions, v2_enrollment_challenges, v2_uploads, v2_upload_chunks | none | unfinished uploads are dropped; finalized data lives in v2_snapshots`.
- Plan L1089: `v2_snapshots(...) FOREIGN KEY(server_instance_id,tenant_id,upload_id,fleet_id,snapshot_id,manifest_replay_id) REFERENCES v2_uploads(...)`. L1102 makes this FK the upload/snapshot equality lock.
- Step 2a runs `foreign_key_check` and applies the refusals (r3 L384, L300). With no upload rows, every backup snapshot fails. `--drop-unreferenced` (r3 L303) would then drop every snapshot, so every profile's head is lost.
- The restore-scope harness rows (r3 L507-L513) cannot pass as written.
- Fix: take from the backup every `v2_uploads` row referenced by a retained `v2_snapshots` row (terminal `COMMITTED` state, immutable path, exact request, manifest and receipt bytes). Require their FK to live `v2_fleet_key_generations`. Drop only non-terminal uploads and their chunks. Add a harness row asserting `foreign_key_check` is empty after the merge with no rows dropped.
- Confidence HIGH (a direct DDL contradiction).

## MAJOR

**M16. `v2_idempotency` "union, live row wins" keeps stored responses for rolled-back state, and nothing defines "superseded by the transition".**
- r3 L289: `a stored response of a commit that the restore rolls back is superseded by the transition`. No rule implements this. Live `COMMIT` rows keep `CommitReceiptBindingV2` bytes for versions `V_backup+1..V_live` that no longer exist after the merge.
- After restore, new commits reuse those version numbers with different heads.
- A client retrying a lost-response commit gets the old receipt byte-identically (L966-L970). Server-side that is a receipt/snapshot/head/epoch mismatch, `RECEIPT_MISMATCH` (L1105). Client-side, its pinned head is not the transition's previous head unless it was the latest, so it quarantines.
- The same applies to live `CREATE_UPLOAD` / `FINALIZE_UPLOAD` / `PROFILE_PUBLISH_CREATE` responses naming uploads or profiles the merge dropped.
- Fix: define it. For example: keep every live key as a reservation (keys are never reused), mark rows whose referenced resource is not in the candidate as `superseded_by_restore`, and have a replay of such a key return a defined error (`STALE_CONTEXT`, or a new `RESTORE_SUPERSEDED`) instead of the stored bytes. Add the matching harness rows.

**M17. Restored heads are not checked against the live control plane's signer trust, and rule 6 lets users accept or launder heads signed by revoked keys.**
- `restore prepare` checks FK, schema and blobs (r3 L298-L303), and the custodian checks only leaves it has pinned (r3 L476). No step verifies that each restored head's manifest signer is still an approved, unrevoked device with `profile.commit` in the live plane.
- Scenario: a device stolen before the backup pushed content, and it was revoked after the backup. Restore makes its head current again.
- Rule 6 (r3 L1536-L1540) treats any signer without authority at `now` as "lapsed" and offers (ii) explicit user acceptance or (i) re-sign by a current committer. For a **revoked** signer, (ii) is fail-open, and plan L375 says to quarantine when a signature or grant is invalid. Path (i) launders content authored by a compromised key into a fresh valid signature.
- The trust-chain row says `Plan lines: none` (r3 L31).
- Fix:
  - `restore prepare` lists, and refuses unless `--drop-unreferenced` is given, every restored head whose signer device or key is revoked in live.
  - Rule 6 distinguishes **revoked** (reject; no acceptance or re-sign path) from **lapsed** (expired; the paths stay).
  - Mark rule 6(ii) as a reinterpretation of L375 on the page.

**M18. D-1 is not decidable as written, because the page does not say what a restore can actually recover.**
- Blobs are not restored: `each row's blob must exist at immutable_blob_path` (r3 L291), with refusal otherwise (r3 L301). So a restore can only rewind heads to snapshots whose blobs are still in the live store (default retention 5, L2548), unless the operator first copies blobs back from a backup. That step is not defined (allowed? where? verified how?).
- `the backup and live schema versions differ` refuses (r3 L299). Every backup taken before a server migration becomes unrestorable.
- Together with the live-DB precondition, D-1 recovers only from logical damage within retention on an unmigrated schema. The user should approve that knowingly.
- Fix: state the recoverable cases on the approval row. Either define an operator blob-restore step (copy into the immutable store, verify against `ciphertext_sha256`, before prepare) or say there is none. Either migrate the candidate copy forward before the merge or state that a migration ends restorability of older backups.

## MINOR

1. **`v2_profiles` merge (r3 L290).** `current_key_generation` comes from live, while `current_version` and its snapshot come from the backup. Define what `current_key_generation` means (the head snapshot's generation, or the active generation for the next write) and assert the matching invariant. `fleet_id` comes from live but the snapshot rows carry the backup `fleet_id`: require equality or refuse. Say whether "a profile only in the backup is refused" can be overridden by `--drop-unreferenced`.
2. **180-day `custodian.renewal_fork` (r3 L1199).**
   - Legitimate false positives: a custodian's root `RotationGrant` to itself at any root rotation within 180 days of a renewal (common after an exclusion), and re-issue after lost client state.
   - The time basis is not stated; `issued_at_ms` is thief-chosen.
   - The detection value is low: a thief need not renew while the legitimate device keeps renewing, because it rides the legitimate windows.
   - Fix: count only `ExistingRootGrant`s for the same root generation; measure by local first-seen time; also raise an event for any renewal of a key whose device the client knows is revoked or re-keyed.
3. **Mitigations (a)-(c) protect only devices with history.** A new joiner baselines whatever the evidence shows, so a forged custodian raises no `appointed` event there. Server omission of a key's earliest root grant raises `first_not_before(K)` on that device and stretches the 1095-day clip. "Omission is safe" (r3 L1480) holds for the fixpoint, not for clipping. State both.
4. `DeviceRevocationV2` (r3 L1642-L1651) carries a validity window, but D-6 gives no TTL for it, and L406-L408 requires one. State that a filed revocation is permanent and the window bounds only its presentation.
5. The restore-scope table omits the ADR 0001 R1 first-device confirmation table and the v1 tables. The harness assertion (r3 L296) would catch this; assign them now.
6. Q-15 (baseline for G2 scoring, r3 L1665) is a user decision but is not on the approval page.
7. Trust-chain row "Plan lines: none" (r3 L31): see M17 (rule 6(ii) vs L375).
8. Between `restore prepare` and `restore commit`, a server started in K7 (v2 writes off, but logins and v1 writes possible) changes the live DB hash, which loops abort and prepare (r3 L387). Require the server to stay stopped, or block all DB writes in K7.

## What's missing

- A merge-completeness harness assertion: no backup row is dropped without being listed, and `foreign_key_check` is empty (B6).
- A replay-after-restore harness: retry of a rolled-back commit, create-upload and publish (M16).
- A restore harness for a head signed by a device revoked in live (M17).

## Approval page: decidability per row

| Row | Decidable? |
|---|---|
| Q-1 | Yes (reinterpretation of L427 marked) |
| Q-2, Q-4, Q-6, Q-12 | Yes |
| Q-5 / D-9 | Yes (amendment marked; M11 fixed) |
| Q-7 | Yes (deferral; `SHXBAK01` on provider BE32, byte-identical per `stream.rs:437-446`) |
| Q-13 | Yes (amendment marked; minor 4) |
| Q-14 | Yes |
| D-1 | **No:** B6, M16, M18 |
| D-2, D-3 (conditional), D-4, D-5, D-7, D-8 | Yes |
| D-6 | Yes (honest bound; minor 2, 3) |
| Trust chain / 2.4.3 | Yes after M17 (plan-lines label) |

## Self-audit and realist check

- B6: HIGH, a DDL fact. Not refutable. Fail-closed (refusal), but kept BLOCKING because the decided restore design cannot run at all and G2-55..60 cannot be harnessed.
- M16: HIGH. MAJOR, not BLOCKING. Mitigated by: outcomes are quarantine or mismatch (fail closed), not data loss.
- M17: MEDIUM-HIGH. Security (integrity). Kept MAJOR. Mitigated by: an honest server reports the revocation, and the user is prompted. Not downgraded further: path (i) launders content.
- M18: decidability, not soundness.

## What would upgrade the verdict

- Keep committed uploads in the merge (B6).
- Define replay semantics for superseded idempotency rows (M16).
- Add the revoked-signer check and the revoked/lapsed split in rule 6 (M17).
- State the recoverable cases and the blob and schema rules on the D-1 row (M18).

With those, the ADR would be ACCEPT-WITH-RESERVATIONS from this reviewer.