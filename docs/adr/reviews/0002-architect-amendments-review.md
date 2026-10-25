# Architect review: ADR 0002 rows that reinterpret or amend the frozen plan

- **Reviewed:** `adr0002-g2-decisions-draft.md` revision 7, SHA-256 `ec544f5f1e1a4801dc5350d7d39268160847d13e8e31d8893f63a51c99424e7d`.
- **Against:** frozen plan SHA-256 `a4a136c9ff0358fdce0967f7c09d7f7a744bbf33aac3db2ce8475972453eb813` (matches the draft's Sources table); ADR 0001 as on `main` (`scratchpad/adr0001-main.md`); code at `439e932` (`C:/Users/User/dev/tools/ShardBrowser-g2`).
- **Scope:** only the six rows the approval page marks as reinterpret/amend. Read-only; no repository file touched.
- **Test applied:** a "reinterpretation" that changes observable behaviour compared with the plan's literal reading is an amendment.

## Overall verdict: APPROVE-WITH-CHANGES

No row is unsound, and the six critic rounds closed the logic gaps they looked at. But the Plan-lines column is **not yet a complete or fully honest list**, which is what the user is asked to approve:

- two labels are too soft: D-1's merge, and the trust chain's L375 override;
- at least eight plan lines the rows change are not listed: L376, L1399/L1402, L1067, L445/L463 together with the "six records" counts, L406-L408, L1127, L1220 and L1348;
- two design gaps sit outside what the critics examined:
  - a tenant that gets no restore transition is never defined (Q-1/D-1);
  - the 30-day first-seen rule strands long-offline devices (trust chain).

D-3's conditional amendment should not be pre-approved.

| Row | Label honest? | Necessary? | Verdict |
|---|---|---|---|
| Q-1 (L427) | Yes | Yes | APPROVE-WITH-CHANGES |
| Q-5 / D-9 (L913) | Yes | Yes | APPROVE-WITH-CHANGES |
| Q-13 (L913, L1125) | Partly: hides L1108 and L1067 effects | Yes | APPROVE-WITH-CHANGES |
| D-1 (many) | Partly: the merge, L372 and L2263/L2264 are amendment-grade; L299 is honest | Merge: yes. `version_floor`: a choice, not forced | APPROVE-WITH-CHANGES |
| D-3 (L1352/L1353, fallback 3) | Yes | No: a plan-conformant fallback exists | REJECT the conditional amendment as specified |
| Trust chain (L375, L372) | L375: no (an override); L372: yes | L375 (ii): no; L372 revert: useful, not forced | APPROVE-WITH-CHANGES |

---

## Q-1: reinterpret L427

**What the plan says.** L427 (`issuer_signing_key_id`): "the key is looked up in the same tenant/epoch and has a suitable capability". L406-L411 require `restore_epoch` in every authorization payload. L375 quarantines a binding when `restore_epoch` rises without a valid transition.

**Is the label honest?** Yes. "Same tenant/epoch" does not say whose epoch. The strict reading (record epoch must equal the current epoch) defeats itself:

- after any restore, every approval and grant is dead at once, custodian grants included;
- so nobody can reissue them;
- yet L2243 and L310 clearly expect tenants to continue after a restore.

When the literal reading cannot work, choosing the one workable reading is a fair reinterpretation.

**Necessary, minimal, consistent?**
- Necessary: yes, for the reason above.
- Minimal: yes.
- Consistent with D-1: yes. D-1 keeps the live control plane, so no revoked record comes back.

**Knock-on the draft does not list.**
- The client rule `restore_epoch <= Ebind` (draft L1583) leans on `Ebind`, "the epoch the binding has accepted" (L1577), which is per binding. Tenant-level records (approvals, capability, root and fleet grants) are verified outside any binding: a new device, or a device with no binding.
- D-1's coverage rule (draft L450) gives a tenant a transition only if some profile has a head in **both** the live DB and the backup. Plan L1112 sets `mapping_count` to `1..1000000`, so a transition with no leaves is impossible.
- Result: a tenant whose profiles are all live-only (lost by the restore), or which has no profiles, gets no signed transition. Under the draft's rules its devices can then never accept a record issued at `E+1` (a new device approval, fleet grant or capability). The tenant is effectively bricked until it re-bootstraps.
- Neither Q-1 nor D-1 says how such a tenant moves to `E+1`.

**Verdict: APPROVE-WITH-CHANGES.**
- Define a tenant-level `Ebind`: per `(server_instance_id, tenant_id)`, advanced by any verified same-tenant transition.
- State what happens to a tenant with no covered profile. Either D-1 issues a transition for every tenant with an active device (this needs a zero-leaf form, so amend L1112 and L2243), or such a tenant explicitly recovers through Q-14.
- Either way it must appear on the page.

---

## Q-5 / D-9: amend L913

**What the plan says.**
- L910-L913: every remote non-COMMIT mutation uses `IdempotentMutationRequestV2`, with `operation_kind` a closed enum of 11 values and no fleet value.
- L924-L931: the stored response repeats `operation_kind`.
- L1107: "root/fleet grant/revoke/rotate/activate" must persist the mutation, the exact idempotency response and the audit in one transaction.
- L1127-L1129: fleet endpoints exist without payload maps.

**Is the label honest?** Yes, it is a real amendment of a closed wire enum.

**Necessary?** Yes. L1107 demands an exact stored idempotency response for fleet grant and activation. That response type carries `operation_kind` from the closed L913 enum. Any route therefore amends either L913 or the L924 response contract, as the draft says (draft L58).

**Minimal and consistent?** Mostly. The four maps mirror the root lifecycle (L943-L946). Three gaps:

1. **No `FLEET_GRANT_REVOKE`.**
   - L1107 names fleet revoke, and the root lifecycle has `ROOT_GRANT_REVOKE` (L947).
   - The draft revokes fleet grants only as a side effect of `DEVICE_REVOKE`, which revokes the whole device.
   - Removing a device from **one** fleet (the L1126 membership PATCH; L290, L335 "revoked device gets no new generation") has no idempotent revoke path. That means a third L913 amendment later.
2. **L1127 ack path.** L1127 defines a **generation**-level ack (`.../key-generations/{generation}/ack`). D-9 defines a per-**grant** ack keyed by `replay_id`. This reinterprets L1127 and is not listed.
3. **Batching.** Q-13 adds `DEVICE_REVOKE` to the same enum. Two separate amendments of one closed enum invite drift between vectors.

**Verdict: APPROVE-WITH-CHANGES.**
- Amend L913 once, for Q-5, Q-13 and `FLEET_GRANT_REVOKE`: six new kinds. `FLEET_GRANT_REVOKE` mirrors L947, with a reason code and an invalidation count.
- List L1127 (ack granularity) on the page.

---

## Q-13: amend L913, L1125

**What the plan says.**
- L1125 routes `POST /v2/devices/{id}/revoke` through `SignedAuthorizationRecordV2<DeviceApprovalV2>`.
- L913 has no device-revoke kind.
- L290, L1108, L1383 and L2618: "revoke device + activate the new generation is one logical operation". The transaction revokes device, sessions and grants and flips the generations. A missing ack or capability fails the whole operation.
- L1067: the minimum capability set includes **`device.revoke`**, separate from `device.approve`.

**Is the label honest?** Partly. Amending L913 and L1125 is honest. Two further effects are hidden:

1. **L1108, L1383, L2618, L290 weakened.** `activations` has length `0..65535` (draft L1779-L1780). Only a `compromised` reason "should" carry replacement activations, and the UI merely warns (draft L1787). So revoke-without-rotation is legal. Yet the draft says "L1108 is delivered literally" (draft L96). The plain reading of L1108 and L1383 is that a device revoke **is** a revoke-plus-activation. Making activation optional changes observable server behaviour.
   - Trade-off: requiring activations means a lost device cannot be revoked until every remaining device has acked the new generation, so revocation is not immediate.
   - Either choice is defensible, but the user must make it knowingly.
2. **Wrong capability.** The issuer must hold `device.approve` (draft L92, L1628, L1657). The plan names `device.revoke` for this purpose (L1067). D-2 keeps `device.revoke` in its closed 14-value set (draft L650) but gives it no use in the issuer matrix (draft L671-L680), so it becomes a dead value. That contradicts the plan's separation of duties.

**Knock-ons the draft does not list.**
- A new authorization payload kind changes counts the plan fixes:
  - "five payloads" (L445, L463);
  - "six authorization/key-grant records" or "six grants" in about 20 places, gate rows included (L230, L304, L370, L1081, L2038, L2354, L2375, L2383, L2423, L2450, L2534, L2563-L2566, L2595, L2650, L2669, L2757).
- The amendment must say whether `DeviceRevocationV2` joins those matrices. It should, being a signed record with indexed columns.
- No storage table exists in §7 (L1056-L1093), and the draft defines none. D-1 requires every table to have a restore-scope row (draft L323).
- "Window bounds only filing; a filed revocation is permanent" (draft L1788) departs from the common rule L406-L408 (`server_now` inside the window at use). That is a per-record-kind exception, not listed.

**Verdict: APPROVE-WITH-CHANGES.**
- Issuer = custodian holding a device-scoped **`device.revoke`** covering the device's approval scope. Update trust-chain rule 6 and the round-6 vector to match.
- Decide `activations >= 1` (literal L1108) or keep `0..` and list L1108, L1383, L2618 and L290 as reinterpreted.
- Add the table, the restore-scope row and the count changes (L445, L463, the "six" sites) to the page.
- List the L406-L408 exception.

---

## D-1: restore

### (a) Merge: reinterpret L2243 and L2251

**What the plan says.**
- L2251 (step 2): "create the restored SQLite candidate at an inactive path".
- L2243: an "authoritative server restore" raises the epoch.
- L376: the external record handles "authorized restore/**DB-image rollback**". If live control-plane trust is lost, "all v2 writes fail operationally and **must be restored from trusted operator evidence**".
- L333-L334: "backup tamper does not grant auth because the live control plane remains the authority".

**Is the label honest?** No; it is amendment-grade. "DB-image rollback" (L376) is a whole-image restore. The merge changes what a restore does in ways users will see:

- control-plane rows survive from the live DB;
- profiles that exist only in live are lost;
- the restore is impossible without a healthy live DB.

**Necessary and minimal?** The merge is the right design. L333-L334 already make the live control plane the authority over backups. The rejected whole-DB variants (draft L570-L571) provably resurrect revocations (L1385).

**Knock-on the draft does not list: L376.** The plan names restore as the remedy for exactly the case where live control-plane trust is lost. D-1 refuses that case ("live DB required", draft L382-L385) and sends it to Q-14 (new tenant). Removing the plan's stated remedy for that case is a change to L376. The page cites L376 only for "keep writes off".

### (b) L299, L966-L970, L1105: replays of rolled-back operations

**What the plan says.** A retry with the same key and request hash returns the same receipt or stored bytes.

**Is the label honest?** Yes, as a reinterpretation. Under the literal whole-image restore, a rolled-back operation's idempotency row would not exist either. The retry would then also end in an error: no lease, or `BASE_VERSION_MISMATCH`. So what the client observes matches the literal reading.

**Unlisted:** adding `superseded_by_restore_epoch` to the allowlisted fields of `BASE_VERSION_MISMATCH` extends the L1220 error contract. It is additive but should be listed.

### (c) `version_floor`: amend L1085, L1090, L1099, L1412, L2608; reinterpret L372

**What the plan says.**
- L1099: "version increases by exactly one per successful commit".
- L1412: the commit checks `base_version == current_version`.
- L2608: the commit checks "exact base_version".
- L372: the client accepts only a chain that continues its pinned head.

**Are the labels honest?**
- L1085, L1090, L1099 and L1412 are honest amendments.
- **L2608 needs no amendment.** It says only "exact base_version", which the new predicate still satisfies. Over-listing it is harmless.
- **L372 is amendment-grade.** A client now accepts a version gap that it would otherwise reject. The epoch gate (draft L350-L355) bounds it well: a custodian-signed transition, at most once, and a minimum based on the highest version ever pinned.

**Necessary?** Not forced by the text. Under the literal whole-image restore, versions are simply reused and every plan line holds; the draft's own "not recommended" option (draft L356) needs no plan change.

There is a stronger argument the draft does not make: shipped code builds blob paths from the version (`server/src/fleet.rs:754-758`) and deletes any existing file at the target before the promote rename (`fleet.rs:480-484`). If v2 keeps that scheme, version reuse would overwrite immutable blobs that the archived `pre-restore-<txn>.db` still references. `version_floor` prevents that, and so would keying v2 blob paths by `snapshot_id` (plan L1089 fixes no formula).

**Unlisted:** the lease state machine L1399 (`base=current_version`) and L1402 (`current_version+1`) states the same rule as L1412 and must be amended with it.

### (d) L2263, L2264: v2-scoped "disable writes" and "fail closed"

**What the plan says.** L2258 explicitly says "disable **v2** writes". L2263 ("quarantine/disable writes") and L2264 ("security incident, fail closed") do not say v2.

**Is the label honest?** It is a defensible reading. ADR 0001 L576-L578 decided "v1 unaffected" only for a **missing** record (K1); extending that to K2 and K4 is this ADR's own step.

**Consistency.** The draft blocks v1 writes during a normal restore (K5-K12, draft L500) but keeps v1 writable during a K2 security incident (draft L501). That is inverted risk ordering.

**Verdict for D-1: APPROVE-WITH-CHANGES.**
- Relabel the merge as an **amendment** of L2243, L2251 and L376.
- Add L1399/L1402 and L1220.
- Drop L2608, or mark it "no change".
- Mark L372 as amendment-grade.
- Ask the user to decide explicitly whether a K2 security incident freezes v1 too. My recommendation: yes for K2, v2-only for K4.
- State the blob-path argument for `version_floor`, or state that `version_floor` is optional if v2 keys blob paths by `snapshot_id`.
- The no-transition tenant gap from Q-1 also belongs here.

---

## D-3: amend L1352 and L1353 only if fallback 3 is used

**What the plan says.**
- L1352: payload AEAD is XChaCha20-Poly1305.
- L1353: "RustCrypto STREAM LE31 **or an equivalent primitive** confirmed by an official-doc spike and test vectors; no hand-written nonce counter".
- L1348: reject on counter "exhaust LE31".

**Is the label honest?** Yes. Fallback 3 (ChaCha20 with STREAM-BE32, draft L812-L815, L827-L828) contradicts L1352.

**Necessary?** No.
- Option B (draft L806-L811) uses crates already in, or close to, the graph and is very likely to pass L2443.
- If both A and B fail, a plan-conformant third fallback exists: **XChaCha20-Poly1305 with RustCrypto `StreamBE32`** (19-byte prefix).
  - It keeps L1352.
  - It fits L1353's "equivalent primitive" clause, given the spike and vectors L1353 already demands.
  - Only the L1348 wording ("exhaust LE31" read as "exhaust the chosen STREAM counter") needs a note.
- The draft's reason for plain ChaCha20 is byte-identity with the shipped frame code. That has little value for a new `SHARDXBK` suite, and it gives up XChaCha's protection against DEK reuse (draft L817-L819).

**Unlisted:** fallback 3 also touches L1348 (LE31 exhaustion).

**Verdict: REJECT the conditional amendment as specified.** Approve only the A/B order now. Replace fallback 3 with XChaCha20 + `StreamBE32`, and treat any real L1352 change as a fresh amendment decided only if A, B and that fallback all fail. The user should not pre-approve a plan amendment that will probably never be needed.

---

## Trust chain: reinterpret L375 and L372

### L375: a lapsed signer accepted by explicit user action

**What the plan says.** L375: the client quarantines a binding when a signature or grant is invalid, ... Detection is relative to pinned state.

**Is the label honest?** No. Path (ii) (draft L1658-L1662) lets a user click through a check that the draft's own rule 6 treats as failing. A binding that would be quarantined is not. That is an override of a fail-closed rule, which is an amendment.

**Necessary?** No.
- Path (i), re-sign, stays within the plan and is available whenever any current committer exists. Devices that already pinned the head can re-sign, because re-reading a pinned head does not re-evaluate its signer (draft L1625).
- Path (ii) adds no reachability over (i) except when no current committer exists, which is the Q-14 case anyway.
- It adds a social-engineering path: per L376, a server that hides a revocation makes a revoked signer look lapsed.

### L372: a revert commit chains over rejected heads

**Is the label honest?** Yes. Hash continuity from `P` through `J1..Jn` to `R` is preserved; only acceptance of the intermediate heads is skipped. Within the plan's alternatives (republish, or an operator restore that drops the head through D-1) it is not strictly necessary, but it is valuable and well bounded. Only proven revocations enable it, per the M21 fix.

**Knock-on the draft does not list: the 30-day cliff.** A `DeviceRevocationV2` counts only if its 30-day window contained the time **this client first saw it** (draft L1630, vector L1657).
- Scenario: a device pins `P`, goes offline for more than 30 days, and meanwhile the revocation is filed and a revert `R` committed.
- It can then never count the revocation, so it refuses `R` and stays quarantined on that profile for good. New devices are unaffected: they accept the latest head without walking its ancestry.
- The window does defend against something real: a revocation backdated by a key whose custodianship has since lapsed. A narrower rule keeps that defence without the cliff: the issuer must be a custodian at the client's first-seen time (rule 2), in addition to at `issued_at_ms`.
- I am not certain this covers every backdating case; the critic should check it.

**Also:** rule 6 uses `device.approve` for the revocation issuer; see Q-13.

**Verdict: APPROVE-WITH-CHANGES.**
- Either drop path (ii), leaving L375 untouched, or relabel it as an **amendment** of L375 that the user explicitly accepts. I recommend dropping it.
- Keep the L372 revert.
- Replace the first-seen window test, or at least list the offline-device consequence as an accepted cost.

---

## What the user must know before approving the page

1. **The Plan-lines column is incomplete.** Unlisted changes: L376 (D-1); L1399/L1402 (D-1); L1220 (D-1); L1067 `device.revoke` and the L1108/L1383/L2618/L290 "revoke = revoke + activate" rule (Q-13); L445/L463 and the ~20 "six records/grants" sites, including the G2 and v0.2.1 gates (Q-13); L406-L408 (Q-13 permanence); L1127 (D-9); L1348 (D-3).
2. **Three labels understate their effect:**
   - D-1's merge amends L2243, L2251 and L376;
   - the L372 version-gap rule is amendment-grade;
   - trust-chain path (ii) amends L375.
3. **`version_floor` is a choice, not a necessity.** It costs four amendments plus a wider client rule. The alternative, accepting version reuse, needs no plan change but requires v2 blob paths keyed by `snapshot_id`; shipped `fleet.rs:754` keys them by version.
4. **Restore no longer covers a lost or untrusted live DB.** That case becomes "recover each tenant into a new tenant" (Q-14), contrary to L376's stated remedy.
5. **A tenant with no covered profile is undefined after a restore** (Q-1/D-1). As written, its devices cannot accept anything issued at `E+1`.
6. **Do not pre-approve D-3 fallback 3.** A conformant alternative exists.
7. **Revocation without rotation.** Q-13 as written allows it; the plan text forbids it. Choose explicitly between immediate revoke and literal atomic revoke-plus-rotate.
8. Every change above still needs the Critic half of the pass that L2566 and the page itself require. This review is the Architect half only.

## References

- Plan: L290, L299, L333-L334, L372, L375, L376, L406-L411, L427, L445, L463, L517-L524, L910-L970, L1067, L1081, L1085-L1090, L1099, L1104-L1108, L1112, L1125-L1131, L1220-L1233, L1348, L1352-L1353, L1383, L1399-L1412, L2243-L2265, L2383, L2443, L2563-L2566, L2608, L2618; "six" count sites listed under Q-13.
- ADR 0001 (main): L226-L228 (P1 record fields), L301-L303 and L576-L578 ("v1 unaffected" only for a missing record), L315-L321 (manifest deferred).
- Draft rev7: L14-L32 (page), L36-L43 (Q-1), L86-L97 and L1762-L1788 (Q-13), L298-L371 and L499-L502 (D-1), L641-L680 (D-2), L799-L828 (D-3), L1448-L1504 (D-9), L1577-L1662 (trust chain).
- Code `439e932`: `server/src/fleet.rs:474-486` (promote deletes any existing target), `server/src/fleet.rs:754-758` (blob path keyed by version).