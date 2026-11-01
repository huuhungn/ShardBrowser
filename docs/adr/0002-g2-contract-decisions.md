# ADR 0002: G2 contract decisions (D-1 to D-9)

- **Status:** Accepted for development on 2026-10-25 (revision 15). The
  user decided C-1 to C-3 and Q-17 to Q-20 directly and approved every other
  row of the approval page. Releasing any v2 code built on it still requires an
  independent G2 `PASS` before v0.2.0 (L2341, L2345-L2347).
- **Split:** D-3 (envelope v2 and STREAM) is its own ADR,
  [0003](0003-envelope-v2-stream.md), as ADR 0001 Q4 requires for G2-27.
- **Date:** 2026-10-25
- **Scope:** close D-1..D-8 of the G2 gap report, add D-9 (fleet generation
  lifecycle), and specify the fleet-key trust chain the interim 2.4.3 patch is
  waiting for.
- **Deciders:** user (approved 2026-10-25). Reviewers: Architect, Critic (revision 1
  review: REVISE, `reviews/0002-critic-review-r1.md`; revision 2 review:
  REVISE, `reviews/0002-critic-review-r2.md`; revision 3 review:
  REVISE, `reviews/0002-critic-review-r3.md`; revision 4 review:
  REVISE, `reviews/0002-critic-review-r4.md`; revision 5 review:
  ACCEPT-WITH-RESERVATIONS, `reviews/0002-critic-review-r5.md`; revision 6 review:
  ACCEPT-WITH-RESERVATIONS, Hold on the trust-chain row lifted, `reviews/0002-critic-review-r6.md`;
  Architect review of the amend/reinterpret rows: APPROVE-WITH-CHANGES, D-3 fallback 3 rejected,
  `reviews/0002-architect-amendments-review.md`; revision 9 review (Critic half of the L2566 pass):
  REVISE, 3 MAJOR and 6 MINOR, `reviews/0002-critic-review-r7.md`; revision 10 review: REVISE (narrow),
  1 MAJOR and 5 MINOR, `reviews/0002-critic-review-r8.md`; revision 11 narrow diff check:
  ACCEPT-WITH-RESERVATIONS, 2 MINOR, `reviews/0002-critic-review-r8b.md`; revision 13 narrow diff check:
  REVISE (narrow), 1 MAJOR and 5 MINOR, `reviews/0002-critic-review-r9.md`; revision 14 narrow diff check:
  ACCEPT-WITH-RESERVATIONS, 3 MINOR, `reviews/0002-critic-review-r9b.md`).

## Decisions approved by the user

Every row on this page was **approved by the user on 2026-10-25**: the choices C-1 to C-3 and Q-17 to Q-20 were decided directly, and every row of the "Rows" table was approved with its recommended choice. Details and alternatives are in the section named in the first column. The
"Plan lines" column lists every plan line the row changes (the decided choices list theirs in their own table):
- **amends**: changes observable behaviour compared with the plan's literal reading;
- **reinterprets**: picks one reading where the plan text admits more than one, with no change in observable behaviour;
- **extends (additive)**: adds a field or column the plan's closed lists do not have.

Every amends, reinterprets or extends entry still needs the Architect + Critic pass of plan L2566. That pass is provided by the Architect review of the amend/reinterpret rows (`reviews/0002-architect-amendments-review.md`) and Critic rounds 1 to 9b (`reviews/0002-critic-review-r1.md`, `-r2.md` to `-r8.md`, `-r8b.md`, `-r9.md`, `-r9b.md`). Round 8b accepted with reservations. Round 9 reviewed the Q-18 rule of revision 13 and asked for revision 14 (REVISE, narrow). Its follow-up, round 9b (`-r9b.md`), accepted revision 14 with reservations; revision 15 fixes its three minors. Q-18 changes no plan line. "None" means the row stays inside the plan text.

### Decided by the user on 2026-10-25

| Choice | Decision | Plan lines |
|---|---|---|
| **C-1 Device revocation and rotation** (Q-13) | **Immediate revoke, rotate later.** `DEVICE_REVOKE` revokes the device, its sessions, leases and grants at once. Activations are optional; any that are included commit in the same transaction. The root and every fleet whose ACTIVE key a removed device could hold are `rotation_required`, and the UI keeps a rotation banner until a newer generation clears it:<br>- the root, while its ACTIVE generation was granted to, or had a grant issued by, a now-revoked device, or was granted under a now-revoked root grant;<br>- a fleet, while its ACTIVE generation was granted to, or had a grant issued by, a now-revoked device, or was granted under a now-revoked grant (including `FLEET_GRANT_REVOKE`), or while any `RecoveryGrant` of it is wrapped under a root generation that meets the root condition. Revoking a custodian therefore flags the root and every fleet; the root is rotated first, then the fleets.<br>`rotation_required` is **advisory, with one exception (Q-18)**: it has no deadline and blocks no commit, except that a client refuses to commit under a generation flagged because of a counted `DeviceRevocationV2` with `reason_code = compromised`, until a newer, unexposed generation is ACTIVE. Cost: commits there stop until a custodian rotates. The banner is urgent for `compromised`/`lost` and routine for `retired`/`rekeyed` (Q-20). Clients derive it from signed evidence and do not trust a server flag. For a fleet, that evidence includes the ACTIVE generation's `RotationGrant` and the `RecoveryGrant` it binds, and missing evidence counts as flagged (revision 11, critic r8 M25).<br>Until rotation, new snapshots use a generation whose key the removed device holds: it cannot fetch them through the server, but it can read any ciphertext that leaks (L290 and L1385 already say copied keys cannot be recalled).<br>Revision 10 makes the trigger exact, states the advisory status and completes the plan lines (critic r7 M24, minors 1 and 5); revision 13 adds the user's Q-18 commit block and Q-20 banner split; revision 14 adds grant issuers to the trigger, which aligns it with "a removed device could hold" (critic r9 M26); the choice itself is unchanged | **amends** L290, L1108, L1383, L2618, and the restatements L34 (P1.3 "revoke+activate logical op"), L2676 (drill) and L2764 (G2 checklist) (revocation no longer waits for activation). The Q-18 block is a client-local refusal to start a commit. No plan line requires a client to commit or forbids this, so it adds no label. For `compromised`, it keeps new snapshots off the stolen key, which is closer to the plan's atomic rotate than the advisory flag |
| **C-2 Blob paths** (D-1) | **v2 blob paths are keyed by `snapshot_id`.** An existing blob path is never deleted or overwritten by an upload or promote (retention GC still deletes paths that no live head or retained snapshot references, L2548, L1106; revision 10 clarification, decision unchanged): a path that already exists must hold byte-identical content, otherwise the upload quarantines. Version numbers may repeat across a restore; identity across a restore is `(restore_epoch, version)`, and head hashes are unique. No `version_floor` | none (L1089 fixes no path formula). Code: the `439e932` prototype's version-keyed paths and delete-before-rename (`server/src/fleet.rs:474-484`, `:754-758`) must not carry into v2 |
| **C-3 v1 during a K2 security incident** (D-1) | **K2 makes v1 read-only too**, like a restore in progress. K4 stays v2-only.<br>**What read-only means for v1:** v1 writes are closed, but v1 logins and reads keep working, on a DB whose integrity is in doubt in K2. That is "writes closed", not a full "fail closed".<br>**Relabel confirmed by the user on 2026-10-25:** K2 **reinterprets** L2264 as "writes closed" (revision 11, critic r8 minor 1). The decision itself is unchanged | K4 **reinterprets** L2263 (v2-scoped). K2 **reinterprets** L2264 ("fail closed" read as "writes closed" for v1; logins and reads continue; confirmed) |
| **Q-17 Custodian event UX** (D-6 (a)) | **A design review of the custodian-event UX is held before W6 starts.** It covers the product wording and an acknowledgement flow that users will not train themselves to dismiss, for `custodian.appointed`, `custodian.renewed_after_revocation`, `revocation.refile_needed` and the rotation banners | none |
| **Q-18 Commit block for `compromised`** (Q-13, C-1) | **Block.** A client refuses locally to commit under any root or fleet generation that is `rotation_required` because of a counted `DeviceRevocationV2` with `reason_code = compromised`. The refusal lasts until a newer, unexposed generation is ACTIVE (for a fleet flagged through the root: the root, then the fleet). Other reason codes stay advisory, and unsigned server reports never block.<br>**Cost:** commits on the affected fleets stop until a custodian rotates. A revert or re-sign commit waits for the rotation too. A rotation that waits on a member who cannot acknowledge keeps the freeze until that member is removed. A forged `compromised` revocation inside the D-6 no-history limit can stop commits on the affected devices. A stolen current custodian key can freeze the whole tenant on every device, and if it revokes every other `key.rotate` holder, the tenant recovers through Q-14 (critic r9 minor 4).<br>**Limits:** commits already persisted complete. Withholding the signed revocation keeps the block from starting. Within the no-history limit, a faked rotation can release the block onto a thief's key, which is no worse than without Q-18 | none (client-local refusal; in-flight commits complete as L2040-L2041 and L2377 require; no new `sync_state` value, L1790-L1793) |
| **Q-19 Effective time of a revocation** (trust chain, rule 1) | **(A) First sight only, as written.** A record verified before the client counted the revocation stays verified. Rejected: (B) withdraw every record by the revoked device on counting; (C) an `issued_at_ms` cutoff | none |
| **Q-20 Banner tiering** (Q-13) | **Split by reason code.** The banner is urgent for `compromised`/`lost` and routine for `retired`/`rekeyed`. Only wording and urgency change; the flag is unchanged. For `compromised`, the urgent banner also says that commits are blocked (Q-18) and names the rotation to run | none |

### Decided by the user on 2026-10-26

| Choice | Decision | Plan lines |
|---|---|---|
| **Q-21 Recovery passphrase bytes** (D-5) | **The exact UTF-8 bytes as entered, with no Unicode normalization.** The KDF of the recovery bundle and of the fallback key file takes the passphrase as typed. Rejected: NFC before the KDF, which needs a normalization library on every client and changes nothing for keyboard input, which is NFC on every supported OS. Cost: a passphrase pasted in another normalization form derives another key; the export UI asks for the passphrase twice, so the user types it in the form they will type again | L1386, L2448 |

### Decided on 2026-10-27 (choice delegated by the user)

| Choice | Decision | Plan lines |
|---|---|---|
| **Q-22 Approval scope of a root custodian** (trust chain, rule 1) | **Tenant scope only.** An `ExistingRootGrant` or `RotationGrant` counts toward custody only when its linked approval has `approval_scope_kind = tenant`. A fleet-scoped approval admits a device to that fleet and never carries root custody: the TRK opens every fleet's `RecoveryGrant`, and custodians issue tenant-wide grants. The base `g0` is unaffected, because D1 approvals are tenant-scoped (ADR 0001). The server applies the same rule when it files a root grant other than the S6 self-grant. **Cost:** an admin approves a device at tenant scope before appointing it custodian. Rejected: any scope, the reading rule 3 alone gave | none (narrows rule 1 of this ADR) |

### Decided on 2026-10-28 (strict defaults chosen by the user)

| Choice | Decision | Plan lines |
|---|---|---|
| **Q-23 Issuer of `ROOT_GRANT_REVOKE`** (L947) | **An ACTIVE root custodian only**, the D-2 issuer rule as implemented: a custodian of the tenant's ACTIVE root generation, signing in with its session, may revoke any root grant of that tenant, including its own. The server refuses a revoke that would leave the ACTIVE root with no other custodian (`LAST_ROOT_CUSTODIAN`). No separate capability is added. Rejected: a dedicated `root.revoke` capability (more records for no new guarantee, since custodians already hold the TRK) | none (confirms L947) |
| **Q-24 A generation stuck before activation** (L949, S6) | **Never re-filed.** If the creator's `FirstRootSelfGrant` or `FirstFleetSelfGrant` is revoked before it is acknowledged, that generation can never activate: no second self-grant is accepted for it, and the creator does not regain the right to file one. Recovery is a new generation (a root rotation, or the next fleet generation). Rejected: allowing a re-filed self-grant, which would let a revoked device regain a key the revoke meant to withhold | none (narrows S6) |

### Decided on 2026-10-29 (strict defaults chosen by the user)

| Choice | Decision | Plan lines |
|---|---|---|
| **Q-25 When a lapse is observed** (D-6 (b)) | **From history, before new evidence.** At each evaluation the client first evaluates the containers it has already sighted, records `observed_lapsed_at_ms` for every ledger key whose known window has ended, and only then accepts the new containers. A lapse is never taken from the evidence that is being accepted, so for a key this device has already counted, a server cannot slip a backdated grant from the lapsed key into the evaluation that would record the lapse, or keep the key alive by sending a self-extension first. **Limit:** a key the device never counted (the server withheld its root grant for its whole window, or the device was offline throughout) has no history to lapse from, so a backdated grant arriving together with that root grant is accepted; this is the D-6 no-history bound, and the D-6 (a) custodian events (Q-17) are what reveal it. A key that is merely absent from the evidence is not lapsed; only a key whose window from counted evidence has ended is. **Cost:** a valid renewal that this device first sees after the key's window ended is refused like a forged one; the custodian must be re-appointed by another custodian (D-6 (b)). Rejected: recording the lapse in the accepting evaluation (an independent security review showed the backdating attack above) | none (sharpens D-6 (b)) |
| **Q-26 Local distrust and collected fleet keys** (D-6 (d), Q-19) | **Distrust also withdraws keys.** When a fleet key is about to be used, the client re-evaluates the grant that delivered it (G2-35) and drops the key if that grant's issuer is now locally distrusted or proven revoked (rule 6), even though the grant was first seen before. This is a narrow exception to Q-19 (A) for key material only: every other record first seen before the distrust or the revocation keeps its standing. It withdraws keys from the delivering grant's direct issuer only: a key appointed by the distrusted key before the distrust keeps its standing (Q-19 (A)) and can still deliver keys until it is itself distrusted or revoked. Rejected: keeping Q-19 (A) for keys, which leaves local distrust, the only mitigation for a device with no history, unable to remove a key already collected | none (narrows Q-19 (A) for keys) |
| **Q-27 A device offline across several fleet rotations** | **Fail closed.** A device accepts a fleet generation only one step above the highest it has verified (or any generation on first sighting). A device that missed two or more rotations refuses the newer generation and must be enrolled again. Rejected: walking the `RotationGrant` chain to catch up (more design for a rare case) | none |
| **Q-28 A generation left PREPARING across a restore** (D-1, Q-1) | **Fail closed.** A root or fleet generation still PREPARING at restore epoch `E` does not activate at `E+1`, and no new grant can be filed into it, because new grants carry the generation's epoch. The custodian creates a new generation after the restore. Rejected: letting an older-epoch generation activate after a restore | none |

### Decided on 2026-10-29 (G2 evidence scope chosen by the user)

| Choice | Decision | Plan lines |
|---|---|---|
| **Q-29 Windows credential store evidence** (G2-48) | **A scripted manual run on a real Windows machine.** The repository ships a script that checks the credential store across a machine restart, a locked session and an unavailable store; the user runs it by hand and its log is the evidence. Rejected: CI-only evidence, which cannot restart or lock a session | G2-48 |
| **Q-30 Supported filesystems and crash evidence** (G2-49, G2-50, G2-52) | **Local NTFS only.** A data directory on a network share (SMB), exFAT or FAT32 is refused at startup (fail closed, tested). Crash evidence is a process kill or an injected crash point at every write, rename and fsync; no power-loss run is required. Rejected: ReFS (no CI support) and a power-pull requirement | G2-49, G2-50, G2-52 |
| **Q-31 Network-share probe** (G2-50) | **A temporary SMB share on the test machine**, pointing at an empty scratch directory and deleted after the test, proves the network-share refusal | G2-50 |
| **Q-32 Independent verifier** (G2-64) | **Hermes or Codex**, in its own worktree, reading the plan and the code but not the implementer's reports, runs the checks and gives the verdict. The release waits for its PASS | G2-64, L2341, L2510 |

### Implementation choices recorded on 2026-10-29 (WP-6 offline restore)

These narrow D-1 toward fail-closed behaviour; each was reviewed independently.

| Choice | Decision | D-1 text it narrows |
|---|---|---|
| **Q-33 Transition source and withdrawal** | `restore prepare` takes the transitions already submitted online (`POST` restore-epoch route) instead of `--transitions <dir>`, considers only the step being prepared (E to E+1), and re-checks at prepare that each signer is a live, unrevoked device that is an ACTIVE root custodian at E. Because a signed transition carries no restore transaction id, a submitted row cannot be bound to one restore; an audited offline `restore withdraw-transitions --tenant` (allowed only before a restore is prepared) removes a tenant's submitted rows so one custodian cannot block every later restore | step 1', the `prepare` row of the command table |
| **Q-34 Rolled-back outcomes and replay order** | A restore marks the ledger rows of rolled-back COMMIT, CREATE_UPLOAD, FINALIZE_UPLOAD and PROFILE_PUBLISH_CREATE with `superseded_by_restore_epoch = E+1` (set once, by trigger). The idempotency ledger is consulted before the restore-epoch check on publish, checkout, release, create-upload and finalize, so a replay of a superseded commit answers 409 `BASE_VERSION_MISMATCH` with `superseded_by_restore_epoch`, a superseded create or finalize answers `RESOURCE_NOT_FOUND`, and a kept outcome replays its stored bytes | L377-L389 |
| **Q-35 Not in this cut** | No `--drop-unreferenced`: a profile or head present on one side only refuses the restore. Candidate = a copy of the live DB with the backup's data plane attached (equivalent to the D-1 merge). `abort --orphans` keeps `pre-restore-*` archives unless `--delete-archives` is given. Release builds refuse `export-heads` and `prepare` (as D-1 requires before v0.2.2); crash points exist only in debug builds | the `--drop-unreferenced` paragraph, K3, L584 |

### Implementation choices recorded on 2026-10-29 (WP-4 launcher restore-epoch client)

Found by the independent review of WP-4; both fail closed.

| Choice | Decision | Plan text it narrows or corrects |
|---|---|---|
| **Q-36 Transition signer and leaf head** | The launcher accepts a restore-epoch transition only when its signer is an ACTIVE root custodian at `issued_at_ms`, is still one when the launcher first sees the transition, and was not observed lapsed at or before `issued_at_ms` (the revocation rule of D-6 (b), since `issued_at_ms` is chosen by the signer). A head named by a proof leaf is accepted only after its manifest verifies as a first acceptance under rule 6 (signature, tenant, fleet, profile, instance, version, signer authority now), exempt only from the epoch check, so a restored head whose signer no longer holds an approval keeps the binding quarantined; refused transitions are not retried automatically and no operator command clears them in this cut. A device offline past a custodian's lapse therefore cannot accept that custodian's transitions, the same cost Q-25 accepts | rule 6, D-1 launcher acceptance |
| **Q-37 Binding proofs outlive unbind** | `restore_epoch_binding_proofs` keeps its foreign key to `restore_epoch_transitions` but replaces the `ON DELETE RESTRICT` key to `profile_bindings` with an insert-only trigger (a proof is filed only for a bound profile), and filed transitions and proofs are append-only (update triggers abort). The plan DDL's key made every binding with a filed proof impossible to unbind, contradicting the requirement that receipts and tombstones survive the binding delete. Launcher schema v5 | DDL at L2002-L2028 against L1422 and L2239 |

### Implementation choices recorded on 2026-10-29 (server closure, launcher downgrade and publish-create)

Found by independent reviews; each fails closed.

| Choice | Decision | Plan or ADR text it narrows |
|---|---|---|
| **Q-38 A revocation that is not served turns v2 off** | Hiding a revocation is the unsafe direction, unlike hiding a grant. The startup pass reads every `v2_device_revocations` row. The v2 control plane is off (`CONTROL_PLANE_INTEGRITY_UNTRUSTED`, 423) and the trust page and `restore prepare` refuse while any revocation is not served correctly now: a row fails to load and verify, a row belongs to another server instance, or a quarantine mark names a row that is gone. A mark keeps the SHA-256 of the row's container only when that container alone verifies as the revocation of that same row (server instance, tenant and replay ID); such a row is served again after a restart only while it holds that container. A mark without a hash (the container was corrupt or belonged to another row) is served again once the row verifies. Marks stay as history. Accepted limit, as in Q-13: a database writer who can place another genuine revocation under the same replay ID before the mark is written can still have it served. The refusal names the tenant and replay ID and says that restoring the row and restarting clears it. The scope stays server-wide. The D-1 WI-AUDIT-RO failure count is kept per episode; a non-zero count of an earlier episode is kept beside the new one, printed by `restore status` in every class, and cleared only by its own `restore commit` or `restore abort` or by `restore clear-audit-count --episode <key>`; a count file with a line that cannot be read is set aside as `.corrupt-<ms>` and its valid lines kept | Q-13, Q-14, D-1 WI-AUDIT-RO |
| **Q-39 A configured identity directory that fails preflight** | When `SHARDX_IDENTITY_DIR` is set, also to an empty value, and is refused (empty, missing, not local NTFS, a link, or another volume), the server refuses to start, v1 included, and the restore commands report that refusal. It is never treated as unset (K1). Identity records, manifests and restore artifacts must be plain files on the same volume | Q-30, D-1 startup classes |
| **Q-40 Downgrade clone safety** | A downgrade clone is refused while the data root differs from the config root (v0.1.28 reads only the config root). A rolled-back clone is retired into the journal's `clone-retired` folder and never deleted, and a data-root move is refused while any downgrade journal or retired clone exists. A profile inside an open downgrade or restore flow gets no user-data folder | L2238-L2241 |
| **Q-41 Profile label format** | `label_ciphertext` is `nonce(12) \|\| ChaCha20-Poly1305 ciphertext \|\| tag(16)` under a label subkey, never under the FKEK itself. Subkey: HKDF-SHA256, no salt, IKM the FKEK, info `"SHARDX-PROFILE-LABEL-KEY-V2\0" \|\| tenant(16) \|\| fleet(16) \|\| profile(16) \|\| u64be(generation)`. AAD: `"SHARDX-PROFILE-LABEL-V2\0"` with the same IDs and generation. Plaintext: `u16be(len) \|\| label \|\| zero padding` to the smallest bucket of 64, 256 or 1024 bytes; a label is 1 to 1022 bytes. Opening refuses a non-minimal bucket, non-zero padding or a zero length even under a valid tag. Pinned by a golden vector in `shared` | L300, L1143 (label sealing) |
| **Q-42 Publish-create on the launcher** | The stored request is resent only after the key is verified again and is not blocked by a counted compromise; a blocked request stays unsent and can be cancelled locally (`profile_sync_cancel_publish`), which sends nothing. A reply that matches the request on every identity field always binds the profile at version 0, whatever its lease says: an expired lease binds with no lease and is released, an expiry beyond `now + TTL + 60 s` binds as `LEASE_AT_RISK` clamped to `now + TTL`. A reply that does not match quarantines the operation instead of replaying it. An unbound release is retried at the next sync and dropped once TTL + 60 s have passed. The publish completion must change exactly one operation row. A lease carried over from schema v5 has no stored expiry and becomes `LEASE_AT_RISK`, still a held lease. Credential references are unique per server origin. A second origin of one instance cannot yet store fleet key state for a grant record another origin already stored; that fails closed | L954, L1422, L1440-L2030 |

### Decided on 2026-11-01 (G2-64 finding B6, chosen by the user)

| Choice | Decision | Plan lines |
|---|---|---|
| **Q-43 Which REAL and TEXT coercions probe 10 refuses** (G2-42) | **The ones that would store a value other than the exact wire integer.** A REAL with a fraction (`0.5`), a REAL or TEXT outside `0..=9223372036854775807` (`2^63`, `2^64 - 1`, `'9223372036854775808'`, `'-1'`), TEXT that names no integer (`'zero'`) and a BLOB are refused before mutation by the column's `CHECK` or by `STRICT`, and the row keeps its value. A TEXT in integer form within that range (`'9223372036854775807'`) is stored as that exact `INTEGER`, and so is a REAL that holds an integer (`1.0`). A TEXT in decimal or exponent form goes through a double first, so above 2^53 it can round (`'9007199254740993.0'` is stored as 9007199254740992; probed on SQLite 3.49.1). SQLite converts all of these before any `CHECK` or trigger can see the original type, so no DDL refuses it short of retyping every column as `ANY`, and the server's integer columns (G2-45, migration 0030) behave the same. The launcher only binds `i64` values, never REAL or TEXT, so no stored integer can differ from what was written. **Rejected:** rebuilding every local table with `ANY` columns and a `typeof` check, a schema migration of live user data that would change no stored value | L2047 (probe 10) |

### Rows (approved by the user on 2026-10-25)

| Item | Approved choice | Plan lines | Depends on |
|---|---|---|---|
| Q-1 Records across a restore epoch | A record's `restore_epoch` is its issuance epoch and stays valid while its row is live and unrevoked. Clients compare epochs only for manifests (a new head must carry exactly the binding's accepted epoch, except the transition's own leaf; L375/L524), never for authorization records, so a tenant without a covered profile is not locked out at `E+1` | **reinterprets** L427 ("same tenant/epoch" read as "issuer live in the current DB") | D-1 |
| Q-2 `root.custody` in `TenantCapabilityGrantV2` | Parser keeps the L484 shape; issuance is rejected; custody comes only from root grants | none | D-2 |
| Q-4 Custodian count range | `1..65535` in wire, server and local DDL | none | D-4 |
| Q-5 / D-9 + Q-13 Operation kinds | **One** amendment of the closed L913 enum, adding six kinds: `FLEET_GENERATION_CREATE`, `FLEET_GRANT_CREATE`, `FLEET_GRANT_ACK`, `FLEET_GENERATION_ACTIVATE`, `FLEET_GRANT_REVOKE`, `DEVICE_REVOKE`. Every fleet grant variant is acknowledged one grant at a time, on L1127's generation ack route | **amends** L913. **reinterprets** L1127 (per-grant ack on the per-generation route) | unblocks W4 |
| Q-6 Shipped `SHXFLT01` fleet blobs | Read-only, only through an explicit legacy import; never auto re-published | none | D-3 |
| Q-7 Local backup writer | **Deferred** to its own design. `SHXBAK01` stays the writer; its frame code moves to the chosen provider's STREAM-BE32, which is byte-identical | none (`p = 1` stays the recorded G2-46 deviation) | D-3, D-8 |
| Q-12 Join ceremony | Mandatory 128-bit SAS over instance, tenant, anchor and the joiner's two key IDs; the comparison expires after 10 minutes | none | trust chain |
| Q-13 Device revocation | New signed `DeviceRevocationV2` record. Issuer: a custodian holding device-scoped `device.revoke` (L1067). Stored in a new `v2_device_revocations` table. Permanent once filed.<br>**Sticky at clients:** once a client counts a revocation, every record signed by the revoked key that it first sees afterwards is refused, whatever its `issued_at_ms`, and the key stops being a custodian for that client. A device with no history cannot apply this (the D-6 limit).<br>**Rotation:** revocation is immediate and rotation follows later (C-1, decided). `rotation_required` covers revoked devices and revoked grants, waits for the root before the fleets, and is derived by clients. It is advisory, except that clients refuse to commit under a generation flagged by a `compromised` revocation until it is rotated (Q-18). The banner is urgent or routine by reason code (Q-20).<br>**Re-filing:** when a revocation's issuer loses custody, every current custodian's client prompts a re-file | **amends** L1125 (revoke takes `DeviceRevocationV2`).<br>**Count rule (amends every count site):** every plan statement that counts the authorization/key-grant record family including `TenantRootKeyGrantV2` ("six"/"sáu") becomes seven, and every one that counts the 5.6.1 payloads without the root grant ("five"/"năm") becomes six. The rule governs any site this list misses, except a count of what one storage table holds. Sites found: five becomes six at L45, L445, L463, L2038; six becomes seven at L230, L304, L364, L370, L1081, L2333, L2336, L2354, L2375, L2383, L2421, L2423, L2450, L2466, L2478, L2484, L2510, L2513, L2534, L2563, L2566, L2595, L2632, L2650, L2669, L2757. Exempt (critic r8 minor 5): L2032, both its "five" and its ordinal "sixth". It counts the schemas that the client's `signed_authorization_records` table persists, and `DeviceRevocationV2` is kept in its own store (server `v2_device_revocations`; on clients, the W6 trust-evidence cache). Unchanged: the L18 history line.<br>**Also amends** L406-L408 (window checked only at filing; the revocation then stays in force); L1056-L1093 (new table); L34, L290, L1108, L1383, L2618, L2676, L2764 through decided C-1. L913 is covered by the single amendment above. Uses L1067's `device.revoke` with no change | C-1, D-9 |
| Q-14 Recovery after custody or DB loss | Offline `tenant export-snapshots` CLI gives a rebuilt device ciphertext and signed records; the device recovers into a new tenant from its recovery bundle | none (new offline command) | D-5, D-6, D-1 |
| Q-15 G2 scoring baseline | Score G2 at the exact commit proposed for release, which must be on `main`; the server work on `team-custody-production` (`439e932`) counts only once merged | none | every row |
| D-1 Restore | `SHARDXRP` manifest, complete crash mapping, offline `restore` CLI. **Only the data plane is restored:** heads, snapshots and their committed uploads come from the backup; every control-plane table comes from the live DB.<br>**Recovers only:** logical damage to heads and snapshot rows, with a readable live DB, on the same schema version, for snapshots whose blobs are still in the live store (default retention 5, L2548).<br>**Cannot recover:** a lost, corrupt or untrusted live DB (use Q-14); blobs already deleted (blobs are never restored); any backup taken before a schema migration (refused).<br>**Integrity:** snapshots signed by a key revoked in live are refused or dropped; retries of rolled-back operations get an error, never a stored receipt; the DB is read-only while a restore is in progress and in K2 (C-3): v1 writes fail, and v1 logins and reads keep working.<br>**New server work (touches the shipped v1 audit path, `server/src/audit.rs:22-31`, which discards errors today):** an audit write that fails while read-only is logged and counted, never silently dropped (work item WI-AUDIT-RO, workstream W8).<br>Blob paths are keyed by `snapshot_id` and never overwritten, and only retention GC deletes a blob, and only one that no live head or retained snapshot references, so version numbers may repeat across a restore without touching any blob (C-2). After a restore, clients accept a new head only at the new epoch, so a rolled-back head cannot be replayed (trust chain).<br>Production restore is refused until v0.2.2 (L2396) | **amends** L2243, L2251 (the candidate is a merge, not a DB image) and L376 (restore no longer remedies an untrusted live control plane; that case goes to Q-14); L1090 (additive column `superseded_by_restore_epoch`). **reinterprets** L299, L966-L970, L1105 (a rolled-back operation's replay returns an error, not its stored bytes; what the client sees matches a whole-image restore). **extends (additive)** L1220 (`superseded_by_restore_epoch: U64` allowlisted on `BASE_VERSION_MISMATCH`). Through decided C-3, K4 **reinterprets** L2263 (v2-scoped) and K2 **reinterprets** L2264 (writes closed for v1; relabel confirmed by the user on 2026-10-25) | C-2, C-3, Q-1, Q-14 |
| D-2 Capabilities and issuers | Closed 14-value set. Issuers are root custodians holding a device-scoped `device.approve`, `device.revoke`, `fleet.manage` or `key.rotate`; a manifest signer needs a device-scoped `profile.commit` | none (states the L257/L258 reading; uses L1067) | Q-2 |
| D-3 Envelope v2 | `SHARDXBK` suite 2 = XChaCha20-Poly1305 + STREAM-LE31. Approval covers **only the order of plan-conformant sources**: (A) `aead-stream` LE31; (B) `aead 0.5.2` LE31 + `chacha20poly1305 0.10`; (C) XChaCha20-Poly1305 + RustCrypto `StreamBE32` under L1353's "equivalent primitive" clause, with the spike and vectors L1353 requires. Any change to L1352 would be a fresh amendment, decided only if A, B and C all fail. The reader is chosen by binding state, never by magic | none for A and B. For C: **reinterprets** L1348 ("exhaust LE31" read as "exhaust the chosen STREAM counter") | G2 dependency review (L2443): done 2026-10-25 in [ADR 0003](0003-envelope-v2-stream.md), provider A passes |
| D-4 Set hashes | Flat sorted `signed_container_hash` lists with per-kind labels; counts `>= 1` | none | D-9 |
| D-5 Recovery | The bundle carries the TRK, every retained FKEK and the bootstrap anchor. Root rotation cannot activate until every retained fleet generation has an acknowledged `RecoveryGrant` under the new root | none (defines the L946 "recovery evidence") | Q-1 |
| D-6 TTL and stolen-key exposure | Tiered TTLs with renewal at 50%. **Honest bound:** against a hostile server, a stolen custodian key has **no time limit**. Mitigations: custodian change events on devices with history, sticky lapse, sticky proven revocation, a 1095-day maximum custodian key age, and local distrust | none (new rules within L406-L408; extends ADR 0001 R3 to renewal approvals) | Q-13, Q-14 |
| D-7 Unbind tombstone | Canonical tombstone map built from request and response fields, stored as the `UNBIND` receipt | none | none |
| D-8 Registry | One table; `verify_strict`; FKEK HPKE info and AAD aligned with the root grant | none | D-3 |
| Trust chain / 2.4.3 | Every device pins the bootstrap anchor `A0`. Exact fixpoint verifier over paginated full-ancestry evidence. The manifest signer is checked when a head is first accepted:<br>- a **revoked** signer is rejected with no override; the profile continues only through a revert commit that every client accepts by one fixed rule, and only after a proven revocation (a signed `DeviceRevocationV2` whose issuer is still a custodian, and not proven revoked, when the client first sees it; or local distrust);<br>- a **lapsed** signer is never accepted directly; a current committer re-signs, and with no current committer the tenant uses Q-14.<br>**Head epoch:** a new head must carry exactly the binding's accepted epoch. The only exception is the accepted transition's own leaf, proven by inclusion. A rolled-back head replayed after a restore therefore quarantines (`HEAD_ROLLBACK_DETECTED`).<br>**Sticky proven revocation:** once a client counts a revocation of device D, D's key stops being a custodian for that client, and every record signed by D's key that the client first sees afterwards is refused, whatever its `issued_at_ms`. A device with no history cannot apply this (the D-6 limit).<br>Interim fix: I-1, falling back to I-3 | **reinterprets** L372 (a revert commit chains over rejected heads; hash continuity is kept, only acceptance of the skipped heads is withheld). The head-epoch rule is the literal L524 ("exact current accepted epoch") and L375, so it needs no label | D-2, D-6, Q-13 |

### Approved answers, one paragraph each

**C-1 / C-2 / C-3 and Q-17 to Q-20 (decided by the user on 2026-10-25).** The designs are in Q-13 and "Open questions" (C-1, Q-18, Q-20), in D-1 (C-2, C-3), in D-6 (a) (Q-17) and in trust-chain rule 1 (Q-19). The rejected alternatives (atomic revoke + rotate; `version_floor`; v1 writable in K2) are kept only in revision 8 (`adr0002-g2-decisions-draft.rev8.md`).

**Q-1. Records across a restore epoch (reinterprets L427).**
- **Recommendation.** A record's `restore_epoch` is its issuance epoch, and it must equal the current epoch when the record is issued. After that, the record stays valid at any later epoch while its exact row exists, unrevoked, in the database.
- **Client side.**
  - Clients compare `restore_epoch` only for manifests and heads, against the epoch the binding has accepted through a valid transition (L375, L524). A new head must carry exactly that epoch; the only exception is the transition's own leaf, proven by inclusion (trust chain, rule 6).
  - Authorization and key-grant records are not compared with any binding epoch, because the server already checked their epoch at issuance (L406-L411).
- **Tenants without a covered profile.** A tenant gets no restore transition when none of its profiles has a head in both the live DB and the backup, because a transition needs at least one leaf (L1112). Its devices still accept records issued at `E+1`. Its lost profiles quarantine on their bindings (L2243), and their owners republish. A tenant with no profiles needs nothing.
- **The reinterpretation.** L427 looks the issuer up "in the same tenant/epoch". This answer reads that as "issuer live in the current database".
- **Benefit.** Without this reading, every record fails at the same moment after a restore, and reissuing them needs a custodian whose own grant is also stale (round-1 M5).
- **Cost.** The epoch field no longer shows whether a record predates the latest restore.

**Q-2. `root.custody` in `TenantCapabilityGrantV2`.**
- **Recommendation.** Keep the L484 parser rule, reject issuance at `POST /v2/capability-grants`, and derive live custody only from non-revoked, acknowledged `TenantRootKeyGrantV2` rows of the ACTIVE generation.
- **Benefit.** One source of truth. Nobody can hold custody authority without the TRK, which matches ADR 0001 D2 (ADR1 L719).
- **Cost.** L484 describes a record that v0.2.x never issues.

**Q-5 / D-9 + Q-13. One L913 amendment (six kinds).**
- **Recommendation.** Amend the closed L913 enum once for D-9 and Q-13:
  - `FLEET_GENERATION_CREATE`, `FLEET_GRANT_CREATE`, `FLEET_GRANT_ACK`, `FLEET_GENERATION_ACTIVATE`;
  - `FLEET_GRANT_REVOKE`, mirroring `ROOT_GRANT_REVOKE` (L947), so a device can lose one fleet without being revoked everywhere;
  - `DEVICE_REVOKE`.

  Per-grant acks travel on L1127's generation route (`.../key-generations/{generation}/ack`), one request per grant.
- **Benefit.** W4 can start; the closed enum changes once, with one vector set; fleet generation `0` gets defined sources for `recovery_grant_hash` and `required_grant_set_hash`.
- **Cost.** A plan amendment, because L913 is a closed wire enum; no option avoids it (L924 repeats the kind in every stored response).

**Q-6. Shipped `SHXFLT01` blobs.**
- **Recommendation.** Never read these blobs through the Team pull path. Open them only through an explicit "import legacy snapshot" action that creates a new local profile, which the user may publish as a new v2 profile.
- **Benefit.** Closes the rollback path from round-1 M3 and needs no server migration.
- **Cost.** One manual step per legacy profile.

**Q-7. Local backup writer (deferred).**
- **Why not now.** A `SHARDXBK` suite-2 body needs tenant, fleet, lease and snapshot IDs, an FKEK wrap and a signed manifest (L607-L612, L643-L658), none of which a local passphrase backup has.
- **Recommendation.**
  - Defer `SHXBAK02` to its own ADR.
  - Until then, `SHXBAK01` stays the writer, with its frame code on the chosen provider's STREAM-BE32. That layout is byte-identical to the shipped nonce (`envelope.rs:252-263`, `aead-0.5.2/src/stream.rs:437-446`).
- **Benefit.** No new format; 2.4.x keeps reading new local backups; the hand-written nonce goes away.
- **Cost.** Local backups keep `p = 1` (G2-46) and the 12-byte nonce until the separate design lands.

**Q-12. Join ceremony.**
- **Recommendation.** Mandatory for every joining device.
  - Both screens show `join_sas` (128 bits, 8 groups of 4 hex digits) over `server_instance_id`, `tenant_id`, the anchor key ID, and the joiner's signing and HPKE key IDs.
  - The full values are one click away, and the comparison expires 10 minutes after the pending device row appears.
- **Benefit.** One comparison covers both directions.
- **Attack cost.** 2^128 for a one-screen substitution, and 2^64 online, inside the 10-minute window, for a two-screen one.
- **Cost.** Users can click through, so the UI must not make that the default.

**Q-13. Device revocation.**
- **Recommendation.**
  - **Record.** A signed `DeviceRevocationV2`. Its issuer is a custodian holding a device-scoped `device.revoke` (L1067) that covers the device's approval scope. D-2 previously named `device.approve`; that is corrected.
  - **Route and table.** It is filed through `DEVICE_REVOKE` at `POST /v2/devices/{id}/revoke` (amends L1125) and stored in `v2_device_revocations`. Several revocations of one device are allowed, so a current custodian can re-file one if the original issuer later loses custody.
  - **Lifetime.** A revocation joins the authorization-record family, so the plan's counts change by one rule (every count of the family becomes seven, every count of the 5.6.1 payloads becomes six). Its 30-day window is checked only when it is filed (amends L406-L408 for this kind); after that it stays in force permanently.
  - **Sticky at clients.** Once a client counts a revocation, it refuses every record signed by the revoked key that it first sees afterwards, and that key stops being a custodian for it (trust chain, rule 1).
  - **Rotation (C-1, decided).** Revocation is immediate; rotation follows later. The root and the affected fleets stay `rotation_required` until a newer, unexposed generation is ACTIVE, with the root rotated first. Each client derives the flag from signed evidence. The flag is advisory, with one exception: a generation flagged by a counted `compromised` revocation blocks commits until it is rotated (Q-18). The banner is urgent for `compromised`/`lost` and routine for `retired`/`rekeyed` (Q-20).
  - **Re-filing.** When the issuer of every counted revocation of a device stops being a custodian, each current custodian's client prompts a re-file.
- **Benefit.** The plan's separate `device.revoke` duty is used. Clients get a signed revocation that they can verify, though the server can still hide it.
- **Cost.** One more record kind across every count and matrix of the plan.

**Q-14. Recovery after custody loss or live-DB loss.**
- **Recommendation.** An offline `shardx-team-server tenant export-snapshots --tenant <id> --db <path> --out <dir>` command, run under `shardx.lock`.
  - It exports every retained snapshot object with its signed manifest, plus every signed record of the tenant.
  - `--db` may point at a verified backup copy, because clients verify everything against `A0`.
  - A rebuilt device opens the recovery bundle, verifies the export, decrypts it, and publishes into a fresh tenant (ADR 0001 D1).
- **Benefit.** No online path bypasses custody. It covers custody lapse, total device loss, and the live-DB loss that D-1 no longer handles (L376).
- **Cost.** Operator host access, and history continues only as imported snapshots.

**Q-15. G2 scoring baseline.**
- **Recommendation.** Score G2 at the exact commit proposed for release, on `main`. The server work at `439e932` (16 files, +1889/-42) counts once merged.
- **Benefit.** A G2 `PASS` is tied to code that ships (L2341).
- **Cost.** The gap report must be re-run on `main` after the merge.

**D-1. Restore scope (amends L2243, L2251, L376).**
- **Recommendation.** `restore prepare` merges the backup's data plane (heads, snapshots and the `COMMITTED` uploads they reference) with the live DB's control plane.
- **Live-DB precondition.** A readable, integrity-checked live DB is required. This removes L376's remedy of restoring from operator evidence when the live control plane is untrusted; that case goes to Q-14.
- **Benefit.** Revoked devices and retired key generations cannot come back, and post-backup records are kept.
- **What it recovers.** Logical damage to heads and snapshot rows, on the current schema version, for snapshots whose blobs are still in the live store; with retention 5 (L2548), that is usually the last few versions.
- **What it cannot recover.** A lost, corrupt or untrusted live DB (Q-14); deleted blobs (never restored); any backup older than a schema migration (refused).
- **Integrity.**
  - Committed uploads travel with their snapshots.
  - Retries of rolled-back operations get `BASE_VERSION_MISMATCH` or `RESOURCE_NOT_FOUND`.
  - Revoked-signer snapshots are refused or dropped.
  - Blob paths are keyed by `snapshot_id` and never overwritten; only retention GC deletes a blob, and only an unreferenced one (C-2).
  - K2 freezes v1 writes too (C-3); v1 logins and reads keep working, and a failed audit write is reported.
  - Clients refuse a rolled-back head replayed after the restore, because a new head must carry the new epoch (trust chain, rule 6).

**D-6. TTL and stolen-key exposure.**
- **Recommendation: Option D.**
  - 730 days for approvals and root grants;
  - 365 days for capability and device FKEK grants;
  - 3650 days for recovery grants;
  - 30 days for rotation grants.

  Renewal is at 50% through existing endpoints.
- **The honest bound.** Against a server that hides revocations (L376), a stolen custodian key is valid **with no time limit**: it can renew itself (L820-L822) and appoint custodians, and the thief chooses `issued_at_ms`. TTL bounds only keys that cannot renew themselves (365 days), and servers that report revocations.
- **Mitigations (detection, not prevention).**
  - (a) A custodian ledger with events for new custodians, and for renewals of keys known to be revoked or re-keyed. This works on devices with history only.
  - (b) Sticky lapse.
  - (c) A 1095-day maximum custodian key age.
  - (d) Local distrust.
- **Rejected.** A renewal cap tied to root-generation events: a thief holding the TRK can sign those too.
- **Trade-off.**
  - Visible detection instead of a false bound.
  - Custodian devices re-key every three years.
  - A tenant whose custodians are all offline for more than half a lifetime recovers through Q-14.

**D-3 provider order (round-1 M7; fallback 3 replaced per the architect review).**
1. `aead-stream` with `StreamLE31`, if it passes the L2443 review with `aead 0.6` / `chacha20poly1305 0.11`.
2. The `aead 0.5.2` `stream` feature with `chacha20poly1305 0.10.x`.
3. XChaCha20-Poly1305 with RustCrypto `StreamBE32` (19-byte prefix), as L1353's "equivalent primitive", confirmed by the official-doc spike and vectors that L1353 already demands.

No plan amendment is pre-approved.

## How to read this draft

Like ADR 0001, each item separates three things:

1. **Plan facts**: text the frozen plan already fixes, cited as `Lnnnn`.
   Where the plan already decides something the gap report listed as open, the
   item says so.
2. **Options**: concrete designs with byte-level detail and trade-offs,
   including compatibility with shipped code.
3. **Proposed decision**: a recommendation. New design that is not plan text
   is labelled **new**.

Notation: `domain_hash(L, x) = SHA-256(ASCII L || u32be(len(x)) || x)`, the
construction the plan uses everywhere (e.g. L436, L615) and that
`shared/src/canonical.rs:336-343` implements. Labels end in `\0`. All maps are
`CanonicalCborV2` closed maps (L387-L391). Field order in tables is for
reading; encoding order is the canonical key order. Types are as defined at
L392-L397; every integer persisted in SQLite is bounded to `0..i64::MAX`
(L401).

### Sources

| Source | Identity |
|---|---|
| Frozen plan `.omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md` | SHA-256 `a4a136c9ff0358fdce0967f7c09d7f7a744bbf33aac3db2ce8475972453eb813` |
| ADR 0001, newest status on `main` (`0e0a792`) | blob SHA-256 `72f113a0410bb8f1834f7e91ca293c432a0ad78edb37bf673b692b94798e7b52`; cited as `ADR1 Lnnn` |
| G2 gap report | `reviews/0002-g2-gap-439e932.md`, SHA-256 `6bc896e2c84d1cf21e0da6ec2aa5110f90ff4fbf698570b4093f281125baa9dc` |
| Critic review of revision 1 | `reviews/0002-critic-review-r1.md` |
| Critic review of revision 2 | `reviews/0002-critic-review-r2.md` |
| Critic review of revision 3 | `reviews/0002-critic-review-r3.md` |
| Critic review of revision 4 | `reviews/0002-critic-review-r4.md` |
| Critic review of revision 5 | `reviews/0002-critic-review-r5.md` |
| Critic review of revision 6 | `reviews/0002-critic-review-r6.md` |
| Architect review of the amend/reinterpret rows (revision 7) | `reviews/0002-architect-amendments-review.md` |
| Critic review of revision 9 (round 7) | `reviews/0002-critic-review-r7.md` |
| Critic review of revision 10 (round 8) | `reviews/0002-critic-review-r8.md` |
| Critic narrow diff check of revision 11 (round 8b) | `reviews/0002-critic-review-r8b.md` |
| Critic narrow diff check of revision 13 (round 9) | `reviews/0002-critic-review-r9.md` |
| Critic narrow diff check of revision 14 (round 9b) | `reviews/0002-critic-review-r9b.md` |
| Note on the reviews | They are copied verbatim. Their `scratchpad/adr0002-…` paths name the files now in `reviews/0002-…`, and their line numbers cite the draft revision they reviewed |
| Code at `439e932` | `git worktree add --detach <dir> 439e932` |

**Commit identity (corrected).** `439e932` (#104) is on
`team-custody-production` (whose tip `1d7a0c3` differs from it only in
`server/README.md`), **not** on `main`; neither commit is an ancestor of the
other (`git merge-base --is-ancestor`, both directions false). Between
`439e932` and `main` (`0e0a792`):

- `shared/src` and `src-tauri/src` are byte-identical (`git diff` is empty),
  so every shared and client citation below also holds on `main`, and on the
  shipped 2.4.2 client.
- `server/src` differs in 16 files: `439e932` adds 1889 lines and removes 42
  (`identity.rs`, `identity_record.rs`, `cli.rs`, `idempotency.rs`,
  `generations.rs`, `fleet_generations.rs`, `routes/*`, and smaller edits).
  Server citations below give the `main` line where it differs:
  `server/src/fleet_generations.rs:27` at `439e932` is `:24` on `main`;
  `server/src/grants.rs:19`, `server/src/fleet_grants.rs:171-183` (INSERT) and
  `server/src/routes/v2.rs:78` (`v2_tenant_issuers`) read the same on both.

### Shipped facts that constrain every option

These are in released builds (2.4.x) built from `main`.

- **Containers on disk.** Local backups are `SHXBAK01` files and fleet
  snapshots are `SHXFLT01` objects (`shared/src/backup_file.rs:36,42`), each
  wrapping the `SHRDXBK2` container (`shared/src/backup.rs:62`); the outer file
  carries a 16-byte salt and a 32-byte verifying key (`backup_file.rs:290`).
  Released since 0.2.0 (`CHANGELOG.md` L718, L750).
- **Frame AEAD.** ChaCha20-Poly1305 with nonce
  `prefix[7] || u32be(counter) || final_flag[1]` (`shared/src/envelope.rs:252-263`,
  `keys.rs:46-48`), byte-for-byte the RustCrypto `StreamBE32` layout
  (`aead-0.5.2/src/stream.rs:437-446`) but hand-written, which L1353 forbids.
- **Registry constants** (`shared/src/keys.rs:31-50`, `signing.rs:31-35`,
  `grants.rs:43-53`): envelope suite `1`, wrap suite `1` (ChaCha20-Poly1305,
  12-byte nonce), signature suite `1` version `1`, HPKE suite `1`, stream prefix
  length `7`.
- **Key IDs.** `signing_key_id`, `hpke_key_id`, `root_key_id` use
  `domain_hash` (`keys.rs:54-56`). `fkek_key_id` hashes a canonical map with no
  label prefix (`fleet_grants.rs:201-211`); deployed 2.4.x servers store IDs in
  that form.
- **Argon2id** for local backups: 64 MiB, `t=3`, `p=1`, salt input
  `"SHARDX-LOCAL-BACKUP-FKEK-V1\0" || salt16` (`passphrase.rs:20-34,81-90`).
- **Crates** (`shared/Cargo.lock`): `chacha20poly1305 0.11.0` on `aead 0.6.1`,
  which has no `stream` module and points to `aead-stream`
  (`aead-0.6.1/src/lib.rs:98-102`), not in the lockfile or the local registry.
  `aead 0.5.2` is present through `aes-gcm 0.10.3`, a direct dependency.

---

## D-1. Restore-preparation manifest, restore scope, entry point and crash mapping

### Plan facts

- **Step 2 manifest.** Step 2 creates "an external restore-preparation manifest" (L2251). The manifest binds:
  - the candidate DB SHA-256;
  - the transition-set SHA-256;
  - the instance;
  - the previous and new epoch;
  - the restore transaction ID.

  It is written with a file fsync and a parent-directory fsync. Steps 3-5 resume or retire from it (L2252-L2254).
- **Crash table.** The table at L2256-L2265 has rows keyed on "non-terminal" and "terminal" preparation. L2267 requires **every** crash point, explicitly including "preparation-manifest fsync", to map to exactly one row.
- **What ADR 0001 P1 already fixes.**
  - The record fields that point back to the preparation: `restore_txn_id`, `restored_db_sha256`, `transition_set_sha256` (ADR1 L226-L228).
  - The record write procedure: tmp, fsync, replace, directory fsync (ADR1 L309-L311).
- **What ADR 0001 defers.** It defers the manifest to this decision, and requires the CLI and server to refuse a restore until the manifest exists (ADR1 L315-L321). Offline CLI commands run under the exclusive `shardx.lock` (ADR1 L546-L556).
- **Audit.** L2316 requires an audit event for every restore-epoch transition.
- **Rollback limitation.** The external record does not detect a selective rollback of role, session, revocation, lease or generation rows. If the integrity or freshness of the live control-plane DB is no longer trusted, v2 writes fail operationally (L376). L2243 and L2251 speak of a "restored SQLite candidate" without saying which tables it restores.

### Does the plan allow keeping restore out of v0.2.0?

**No, not without a plan amendment.** Nothing in the plan permits deferral:
- the restore crash harness is a G2 deliverable (L2337);
- uncertainty about crash reconciliation fails G2 (L2341);
- the evidence must cover every crash row (L2673);
- v0.2.0's gate requires the whole prepare/fsync/replace/install/open/reconcile table (L2363).

L2396 puts the tenant-scoped signed transition **workflow itself**, not just a UI, in v0.2.2. Consequences:
- The G2/v0.2.0 harness runs with **fixture-signed** transitions (test custodian keys).
- Production restore stays refused until v0.2.2 delivers L2396, so ADR 0001's refusal remains the production posture.
- That refusal does not exempt G2-55, 56, 57 or 60. They stay `BLOCKED` until this design is implemented and harnessed.

### Proposed decision (Option A)

#### Restore scope: data plane from the backup, control plane from the live DB (new; resolves round-2 B5, M10)

Amendment of L2243, L2251 and L376 (architect review: a merge changes what users see compared with the DB-image restore those lines describe): the "restored candidate" is a merge of two sources.
- The backup supplies the **data plane**.
- The live DB at `E` supplies the **control plane**.

This keeps every revocation, key generation and authorization record that exists in the live DB. A restore across a rotation therefore leaves the live ACTIVE generation ACTIVE. An excluded device gets no new key, and generation numbers never repeat.

| Table (L1056-L1093) | Source in the candidate | Rule |
|---|---|---|
| `v2_tenants`, `v2_accounts`, `v2_tenant_memberships`, `v2_devices`, `v2_device_approvals`, `v2_capability_grants`, `v2_device_revocations` (Q-13), `v2_fleets`, `v2_fleet_memberships` | live | exact rows |
| `v2_root_key_generations`, `v2_tenant_root_key_grants`, `v2_fleet_key_generations`, `v2_fleet_device_hpke_grants`, `v2_fleet_recovery_grants`, `v2_fleet_rotation_grants` | live | exact rows; generation states and pointers are the live ones |
| `v2_restore_epoch_transitions`, `v2_restore_epoch_transition_proofs` | live | step 5 adds the `E -> E+1` rows |
| `v2_audit_events` | live | audit is never rolled back; step 5 appends the restore audit |
| `v2_idempotency` | live rows only (backup-only rows were garbage-collected in live and stay gone) | every key stays reserved; rows whose result the restore rolls back are marked superseded (below) |
| `v2_profiles` | per column: `current_version` = version of the restored head snapshot (the backup's, or lower after a revoked-signer drop); `fleet_id`, `label_ciphertext`, `status`, `current_key_generation`, `created_at` from live; `last_fencing_token = max(live, backup)`; `updated_at` = prepare time | profile invariants below; a profile only in live is lost (coverage below); a profile only in the backup is refused, or dropped with its snapshots and uploads under `--drop-unreferenced` |
| `v2_snapshots` | backup | each row's blob must already exist in the live store at `immutable_blob_path` with `ciphertext_size` and `ciphertext_sha256` (blobs are never restored); each row's signer must not be revoked in live (refusals below) |
| `v2_profile_leases` | none (every lease released) | the next checkout uses a fencing token above `last_fencing_token`, so no token repeats (L1098) |
| `v2_uploads` | backup rows in state `COMMITTED` that a kept `v2_snapshots` row references through its composite FK (L1089, L1102) | exact rows (request, manifest and receipt bytes, `immutable_path`). Every other state (`OPEN`, `FINALIZING`, `READY`, `ABORTED`, `QUARANTINED`, L1159) and every unreferenced row is dropped. Each kept row's FK to the live `v2_fleet_key_generations` (L1087) must hold |
| `v2_upload_chunks` | none | chunks belong only to unfinished uploads |
| `v2_sessions`, `v2_enrollment_challenges`, `v2_pre_device_sessions` (ADR1 L850) | none | step 5 invalidates sessions anyway |
| `v2_server_state` | rebuilt in step 5 | mirror of record `E+1` |
| `v2_bootstrap_guards`, `v2_first_device_confirmations` (ADR1 L750-L756), `v2_replay_ledger` if kept (ADR1 L986-L989), `v2_operations`, `v2_tenant_issuers` | live | one-time bootstrap state and replay tombstones never roll back (round-3 minor 5) |
| v1 tables `users`, `folders`, `proxies`, `environments`, `acl`, `locks`, `snapshots`, `audit_log` (`server/migrations/0001_init.sql`) | live | v1 data is outside this restore; v1 rollback is the separate L2245 flow |

Any other table added later must be assigned a row in this table before it ships. The harness asserts that the assignment covers every table in the schema.

**Foreign keys the merge touches (round-3 B6).** Every FK the plan defines across the two sources:
- `v2_snapshots` -> `v2_uploads` (L1089): both from the backup, kept together by the `COMMITTED`-upload rule.
- `v2_snapshots` and `v2_uploads` -> `v2_fleet_key_generations` (L1087, L1089): backup rows against live generations. Generation numbers and key IDs are never reused (L1101), so a match always names the same key; a miss means the live DB garbage-collected that generation.
- Root and fleet grants -> generations, and proofs -> transitions: both sides come from live, unchanged.
- Any tenant-scoped FK that W2 adds under L1097 is caught by `foreign_key_check`.

**Profile invariants (round-3 minor 1).** For every kept profile:
- the live `fleet_id` equals the backup's, and that of every kept snapshot and upload of the profile;
- `current_key_generation` means the generation for the **next** write (it moves at activation, L1108), and it equals the fleet's live ACTIVE generation;
- the head snapshot (version `current_version`) may use an older retained generation, and its FK to the live `v2_fleet_key_generations` must hold.

**Refusals.** Each of these lists the offending rows and refuses:
- the backup and live schema versions differ (the backup is never migrated forward);
- a backup row has no parent after the merge (`foreign_key_check`), for example a snapshot under a generation the live DB has garbage-collected;
- a profile invariant fails;
- a snapshot blob is missing from the live store or differs;
- a kept snapshot's manifest signer key belongs to a device revoked in live, or is unknown to live (round-3 M17).

`--drop-unreferenced` drops exactly the listed data-plane rows. For a revoked signer it drops that snapshot **and every later version of the same profile**, because they descend from it; the profile's head becomes its newest remaining snapshot, and the profile is lost if none remains. Dropped rows are recorded as lost in the audit and the summary. After the merge, `foreign_key_check` must be empty.

**Blob paths and versions after a restore (C-2, decided by the user on 2026-10-25).** After a restore, the next commit has `target_version = V_backup + 1` (L517), a number that existed in live with a different head.

**Blob paths by `snapshot_id`.**
- v2 stores each object at `<blob_root>/<tenant_hex>/blobs/<profile_hex>/<snapshot_id_hex>.bin`. L1089 fixes no formula, and `snapshot_id` is unique and immutable (L1102).
- A promote never deletes an existing path: a path that already exists must hold byte-identical content (same `ciphertext_sha256`), otherwise the upload quarantines. This replaces the `439e932` prototype's delete-then-rename (`server/src/fleet.rs:480-484`).
- Retention GC (default 5 snapshots, L2548; idempotency floor, L1106) is the only code path that deletes a blob. It deletes only a path that no live head or retained snapshot references, and never rewrites one. No upload or promote path deletes or overwrites a blob.
- Version numbers may repeat across a restore. Identity across a restore is `(restore_epoch, version)`, and the head hash is unique. `(server_instance_id, tenant_id, profile_id, version)` stays unique in the DB (L1099), because rows of rolled-back versions are not in the candidate.
- Superseded receipts are matched by `snapshot_id` (below), so a reused number never revives an old receipt.
- Clients re-pin through the transition (L375), and the next manifest continues the restored head with `base_version` equal to its version and `restore_epoch = E+1`, so L372 and L1412 hold literally. A rolled-back child of the restored head (same version, epoch `E`) still chains exactly, so the client refuses it by its epoch (trust chain, rule 6; critic r7 M22).
- Plan lines: none.

**Replays after a restore (round-3 M16; reinterprets L299 and L966-L970).** The merge keeps every live `v2_idempotency` key, so no key is ever reused (L1100). It sets a new additive column, `superseded_by_restore_epoch = E+1` (NULL otherwise), on exactly these rows:

| Row kind | Superseded iff | Replay with the same request hash returns |
|---|---|---|
| commit (`CommitReceiptBindingV2` response, L1105) | the receipt's `(profile_id, resulting_version, snapshot_id)` is not a kept `v2_snapshots` row | `BASE_VERSION_MISMATCH` (409, no commit, reconcile; L1228), with `superseded_by_restore_epoch: U64` added to the allowlisted error fields of `BASE_VERSION_MISMATCH` (L1220), so the client goes straight to transition reconcile; a client that ignores the field still reconciles |
| `CREATE_UPLOAD`, `FINALIZE_UPLOAD` | the upload ID is not a kept `v2_uploads` row | `RESOURCE_NOT_FOUND` (L1226) |
| `PROFILE_PUBLISH_CREATE` | the profile is not a kept `v2_profiles` row | `RESOURCE_NOT_FOUND` |
| every other kind | never | the stored bytes, as L966-L970 define (a checkout or release replay may name a lease that no longer exists, which L966-L969 already allow) |

- A replay with a different request hash still fails with `IDEMPOTENCY_MISMATCH` first.
- A superseded row never returns its stored bytes, so no response names a version or upload that no longer exists.
- `superseded_by_restore_epoch` is never cleared and does not change `retained_until`; the row is garbage-collected on the usual schedule (L1106).
- Reinterpretation: L299, L966-L970 and L1105 promise the exact stored bytes on every retry; this ADR limits that promise to rows that no restore has superseded.

**What a restore can and cannot recover (round-3 M18).**
- **Can:** heads and snapshot rows that were damaged or wrongly advanced (logical damage), rolled back to a backup taken on the current schema version, for every snapshot whose blob is still in the live immutable store. With the default retention of 5 snapshots (L2548), that is usually the last few versions of each profile.
- **Cannot:**
  - a lost or corrupt live DB (use Q-14);
  - snapshots whose blobs the live store has already deleted: blobs are never restored, and no blob-staging step exists (such snapshots can only be dropped, with `--drop-unreferenced`);
  - any backup taken before a schema migration: prepare refuses, so each migration ends the restorability of older backups;
  - content signed by a key revoked in live (refused or dropped);
  - control-plane state of any kind (by design).
- **Possible later, as additive features:** an audited blob-staging step (copy into the immutable store only where absent, verified against `ciphertext_sha256`), and forward migration of the backup copy with the server's own migrations. Neither is proposed now.

**Live DB required (round-2 M10; amends L376).** L376 names restore from trusted operator evidence as the remedy when trust in the live control plane is lost. This design refuses exactly that case and sends it to Q-14.
- **Preconditions for `restore prepare`.** A live DB at the DB path whose mirror equals `X`, with `integrity_check` = `ok` and an empty `foreign_key_check`.
- **When the live DB is missing or corrupt.** The command exits non-zero with "live DB required". No relaxation exists, because the backup's control plane alone would resurrect every later revocation.
- **Operator path on DB loss.** Keep the external record and leave v2 writes off (L376). Each tenant recovers into a new tenant: `tenant export-snapshots --db <verified backup>` (Q-14) plus its recovery bundle.

#### Manifest format

File `<SHARDX_IDENTITY_DIR>/restore-preparation-v2.bin`, 200 bytes,
big-endian:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | `magic` | ASCII `"SHARDXRP"` |
| 8 | 2 | `version: u16` | `2` |
| 10 | 2 | `record_length: u16` | `200`, equals file size |
| 12 | 1 | `state: u8` | **new**: `1` = PREPARED, `2` = TERMINAL; any other value is unparsable |
| 13 | 3 | `reserved` | `0` |
| 16 | 16 | `server_instance_id` | equals record `E` |
| 32 | 8 | `previous_epoch: u64` | `E` |
| 40 | 8 | `new_epoch: u64` | `E+1 <= i64::MAX` |
| 48 | 16 | `restore_txn_id` | random, non-zero; becomes the `E+1` record's `restore_txn_id` |
| 64 | 32 | `candidate_db_sha256` | SHA-256 of the fsynced candidate file; becomes `restored_db_sha256` |
| 96 | 32 | `transition_set_sha256` | defined below; becomes the `E+1` record's field |
| 128 | 32 | `previous_record_sha256` | **new**: `external_record_sha256` of record `E` (ADR1 L232) |
| 160 | 8 | `prepared_at_ms: u64` | informational |
| 168 | 32 | `checksum` | `domain_hash("SHARDX-RESTORE-PREPARATION-V2\0", bytes[0..168])` |

The parser checks:
- exact size, magic, version and length;
- `state` in `{1,2}` and reserved bytes zero;
- the checksum;
- non-zero IDs and hashes;
- `new_epoch = previous_epoch + 1`.

#### Transition set and hash

Artifacts live in `<SHARDX_IDENTITY_DIR>/restore-<txn_hex>/`, outside the DB rollback scope (L2248). Each artifact is one file named by the lowercase hex of its SHA-256:
- each tenant's exact `SignedRestoreEpochTransitionV2` outer bytes;
- each exact `RestoreEpochInclusionProofV2`;
- the index.

Revision 2's revocation carry-forward artifact is removed, because the live control plane is already in the candidate.

```text
RestoreTransitionSetIndexV2 (closed map)
  domain                 tstr  "shardx.restore-epoch.transition-set-index.v2"
  version                U16   2
  server_instance_id     Uuid16
  previous_epoch         U64   E
  new_epoch              U64   E+1
  restore_txn_id         Bytes(16,16)
  backup_db_sha256       Hash32   SHA-256 of the backup file as read
  live_db_sha256         Hash32   SHA-256 of the live DB file after the prepare checkpoint (new)
  entries                array sorted by tenant_id bytes, no duplicate, length 0..65535 (new limit)
    entry: { tenant_id Uuid16,
             exact_signed_transition_bytes_sha256 Hash32 (L749),
             mapping_count U64 (equals the signed payload),
             proof_set_sha256 Hash32 }

proof_set_sha256      = domain_hash("SHARDX-RESTORE-PROOF-SET-V2\0",
                          proof_sha256[leaf_index 0] || ... || proof_sha256[mapping_count-1])   (L713)
transition_set_sha256 = domain_hash("SHARDX-RESTORE-TRANSITION-SET-V2\0", exact index bytes)
```

Refinement of ADR 0001 P1: ADR1 L228 says "SHA-256 of the transition/proof set". This ADR makes that value the labelled `domain_hash` of the index above.
- The index also commits to the live DB image the merge used.
- An empty `entries` array is valid (no tenant needed a transition, L2243). Its hash is non-zero, as ADR1 L242-L244 requires.

**Coverage.** A tenant needs a transition iff at least one of its profiles has a current head both in the live DB at `E` and in the backup. The leaves are exactly those profiles (L672-L674). Profiles with a live head but no head in the backup are lost by the restore and listed in the audit; their clients quarantine (L2243).

`restore prepare` also lists every tenant that has zero live custodians (round-2 minor 8):
- if such a tenant needs coverage, prepare refuses, because nobody can sign the transition;
- otherwise it appears in the summary and the audit.

#### Write procedure (new; every write uses the P1 primitive: write `.tmp`, flush, fsync, replace, fsync parent directory)

| Step | Action |
|---|---|
| 1' | **Preconditions** (under `shardx.lock`):<br>- class K3 with no orphan file (no manifest, candidate or `restore-*` directory);<br>- the live-DB checks above;<br>- open the live DB, run `PRAGMA wal_checkpoint(TRUNCATE)`, close every connection;<br>- require that no `-journal` exists and that `-wal` is absent or zero-length, then delete a `-shm` if present;<br>- compute `live_db_sha256`. |
| 2a | **Build the candidate:**<br>1. Copy the backup to `<SHARDX_DATA_DIR>/restore-candidate-<txn_hex>.db.tmp` and run `integrity_check` on the copy.<br>2. Open the copy with `journal_mode=DELETE` and attach the live DB read-only.<br>3. In one transaction, apply the restore-scope table.<br>4. Run `integrity_check` and `foreign_key_check`, then apply the refusals.<br>5. Check the blobs.<br>6. Close the copy and require that it has no sidecar (`-journal`, `-wal`, `-shm`).<br>7. fsync, rename to `restore-candidate-<txn_hex>.db`, fsync the data directory.<br>8. Compute `candidate_db_sha256`. |
| 2b | Create the artifact directory, then fsync the identity directory. Write each artifact into it with the P1 primitive, then fsync the artifact directory. |
| 2c | Write the manifest with `state = PREPARED` with the P1 primitive. **Preparation is durable only after the identity-directory fsync of 2c.** |
| 3 | Write record `E+1` with the P1 primitive (L2252, the authority commit point). `restore commit` from K7 first repeats the checkpoint of 1' and requires `SHA-256(live DB) = live_db_sha256`. If the live DB changed after prepare, it refuses: abort, then prepare again. |
| 4 | **Install** (round-2 M9; each sub-step is idempotent):<br>(i) If a live DB file is at the DB path, open it, run `wal_checkpoint(TRUNCATE)`, and close it.<br>(ii) Rename each existing live sidecar (`-wal`, `-shm`, `-journal`) to `pre-restore-<txn_hex>.db-wal` / `-shm` / `-journal`, sidecars first.<br>(iii) Rename the live main file to `<SHARDX_DATA_DIR>/pre-restore-<txn_hex>.db`. It is kept for the operator and is never evidence.<br>(iv) Assert that neither the DB path nor any of its sidecar paths exists. On failure, stop (K12).<br>(v) Rename the candidate to the DB path.<br>(vi) fsync the data directory (L2253).<br>An archive target that already exists is accepted only if it is zero-length or byte-identical; otherwise K12. |
| 5 | Open the installed DB. Verify the record, manifest, artifacts, and the leaves against the DB heads. Then, in one SQLite transaction:<br>- persist transitions and proofs (L2254);<br>- invalidate every session and challenge;<br>- rebuild `v2_server_state` to record `E+1`;<br>- write the audit (below).<br>Commit, then read back. |
| 6 | Rewrite the manifest with `state = TERMINAL` (P1 primitive). |
| 7 | Delete the artifact files, then the manifest, then the artifact directory, with an identity-directory fsync after each removal. The manifest goes before the directory so that a manifest never exists without its directory (K5b relies on this). |

#### Classification (evaluated before any SQLite write, at server startup and by `restore status`)

**Observables.**
- `X`: the external record.
- `M`: the mirror `(instance, epoch, external_record_sha256)`, read with `mode=ro` from the DB at the DB path. It is `absent` if no file is there; a file is never created.
- `P`: the manifest: `absent`, `unparsable`, PREPARED or TERMINAL.
- `C`: whether the candidate file is present at its path.
- `Dx`: whether the artifact directory `restore-<hex(X.restore_txn_id)>` exists.

**Derived conditions.**
- `pre`: `X.epoch = P.previous_epoch` and `SHA-256(X) = P.previous_record_sha256`.
- `post`: `X.epoch = P.new_epoch`, and `X.restore_txn_id`, `X.restored_db_sha256`, `X.transition_set_sha256` equal the manifest's `restore_txn_id`, `candidate_db_sha256`, `transition_set_sha256`.

| # | Condition (first match wins) | Row | Action |
|---|---|---|---|
| K1 | `X` missing or corrupt | L2258 | v2 writes off |
| K2 | `M` present and (instance differs or `X.epoch < M.epoch`) | L2264 | security incident |
| K3 | `P` absent, `M = X` | L2259 | normal read-only verification; stray `.tmp`, candidate, archive or artifact files are listed, never read as evidence, and removed by `restore abort --orphans` |
| K4 | `P` absent, otherwise | L2263 | operator recovery only |
| K5a | `P` unparsable, `M = X`, `Dx` false (authority not advanced: prepare refuses to start while any `restore-*` directory exists, so `Dx` is false before step 3) | L2260 | writes off; only audited `restore abort` (no resume) |
| K5b | `P` unparsable, `M = X`, `C` absent, `Dx` true (restore already committed in step 5) | L2265 | `restore commit --retire`: audit, then step 7; abort not allowed |
| K6 | `P` unparsable, otherwise | L2263 | operator recovery only |
| K7 | `pre`, `M = X`, PREPARED | L2260 | writes off; `restore commit` (re-verify including `live_db_sha256`, then step 3) or `restore abort` |
| K8 | `post`, PREPARED, `C` present, `M` = `E` or `absent` | L2261 | `restore commit` resumes step 4 from (i) |
| K9 | `post`, PREPARED, `C` absent, `M.epoch < P.new_epoch` | L2262 | `restore commit`: let SQLite roll back any uncommitted step-5 transaction, checkpoint, require file SHA-256 = `candidate_db_sha256` (else K12), then step 5 |
| K10 | `post`, `M = X`, PREPARED | L2265 | `restore commit` re-runs the step-5 readback, then steps 6-7 |
| K11 | `post`, `M = X`, TERMINAL | L2265 | `restore commit` continues step 7; missing artifacts are expected |
| K12 | anything else (for example `pre` with TERMINAL, `post` with `M` ahead or mismatched, a K9 hash mismatch, a failed step-4 assertion) | L2263 | operator recovery only |

The server never resumes a restore itself; it only classifies. Write behaviour per class (round-4 B7):
- **Restore in progress (K5a, K5b, K6, K7-K12).** The server opens the DB read-only (SQLite `mode=ro`), so every write fails, including v1 writes. The live DB hash therefore cannot change between prepare and commit (round-3 minor 8).
- **K2 (C-3, decided by the user on 2026-10-25).** The server raises the security incident of L2264 and opens the DB read-only like a restore in progress, so v1 writes are frozen too. Because v1 logins and reads continue (below), this **reinterprets** L2264's "fail closed" as "writes closed" for v1 (critic r8 minor 1). The user confirmed the relabel on 2026-10-25; the decision itself is unchanged.
- **v1 logins and reads while read-only (critic r7 minor 3).** Read-only means v1 writes fail; v1 logins and reads keep working, which matches the decided "read-only":
  - a successful v1 login writes nothing: the JWT is stateless and the throttle is in memory (`server/src/auth.rs:203-233`, same at `439e932` and on `main`);
  - a failed v1 login tries to insert a `login_failed` audit row, and v1 discards that error (`server/src/audit.rs:22-31`, `let _ =`).

  So read-only mode would silently lose failed-login audit rows. **New:** the read-only server must report every audit write that fails. It logs each one at error level with its action and actor, and `restore status` and the K2 incident output print the count since the server opened read-only. Nothing in this design blocks logins. This is new server work that changes the shipped v1 audit path (work item WI-AUDIT-RO below).
- **K1, K4.** v2 writes are off and v1 is unaffected (L2258; ADR1 L302-L303, L576-L578). For K4 this reads L2263 "quarantine/disable writes" as v2-scoped, a reinterpretation listed on the approval page. Every 2.4.x server without an identity record is K1 and keeps serving v1.
- **K3.** Normal operation. Round-2 minor 7 is fixed by the K5a/K5b split: an unparsable manifest maps to "abort" only while the authority is still `E`, and to "retire" after the commit.

#### Crash points (L2267) mapped to rows

| Crash point | Observables after restart | Class, row |
|---|---|---|
| Anywhere in 1', 2a or 2b | `P` absent, `M = X = E` | K3, L2259 |
| 2c after `.tmp` fsync, before replace | `P` absent | K3, L2259 |
| 2c after replace, before directory fsync | `P` absent or PREPARED, whichever the filesystem kept | K3 L2259 or K7 L2260 |
| After 2c directory fsync (preparation durable) | PREPARED, `pre` | K7, L2260 |
| Step 3 before replace (record `.tmp` written) | PREPARED, `pre`, stale record `.tmp` | K7, L2260 (resume deletes the stale `.tmp`) |
| Step 3 after replace, before directory fsync | `pre` or `post` | K7 L2260 or K8 L2261 |
| After step 3 directory fsync (authority commit) | `post`, `C` present, `M = E` | K8, L2261 |
| Step 4 (i) during or after the checkpoint | `post`, `C` present, `M = E` | K8, L2261 |
| Step 4 (ii) after moving some or all sidecars | `post`, `C` present, `M = E` (the WAL was empty after (i)) | K8, L2261 |
| Step 4 (iii) after archiving the main file | `post`, `C` present, `M` absent | K8, L2261 |
| Step 4 (v) after the install rename, before (vi) | K8 or K9, whichever the filesystem kept | L2261 or L2262 |
| After step 4 (vi), before or during step 5 | `post`, `C` absent, `M.epoch < E+1` | K9, L2262 |
| After step 5 commit, before step 6 completes | `post`, `M = X`, PREPARED | K10, L2265 |
| Step 6 any point | `post`, `M = X`, PREPARED or TERMINAL | K10 or K11, L2265 |
| Step 7 any point | TERMINAL; or `P` absent with `M = X` and possibly an empty artifact directory | K11 L2265 or K3 L2259 |

**Why a stale WAL cannot reach the candidate.** Step 1' and step 4 (i) leave the live `-wal` empty. Step 4 (ii) moves the sidecars before the main file. Step 4 (iv) proves that nothing is left at the DB path before the install. The candidate itself has no sidecar (2a).

**Remaining dependency.** K9 relies on SQLite restoring the candidate's bytes after a crash inside the step-5 transaction. That holds for a rollback journal, and for WAL without a checkpoint of uncommitted frames. The G2 harness must prove it under the WAL policy chosen for G2-50.

#### Entry point and transition flow (new; resolves round-1 M8)

Offline commands of `shardx-team-server`, each under the exclusive
`shardx.lock` of ADR 0001 Option A (ADR1 L546-L556):

| Command | Effect |
|---|---|
| `restore export-heads --backup <db> --out <dir>` | Requires the step-1' preconditions. Verifies record `E` and the backup's integrity; draws `restore_txn_id`; writes one `RestoreEpochTransitionRequestV2` per tenant needing coverage for custodians, plus a summary of lost profiles and zero-custodian tenants. |
| `restore prepare --backup <db> --txn <hex> --transitions <dir> [--drop-unreferenced]` | Steps 1'-2c. Each signed transition must match its request and be signed by a key that is a live root custodian of that tenant in the live DB at `E`. Its reason code must be `operator_restore`, `disaster_recovery` or `verified_backup_rollback` (L731). Every tenant needing coverage must have exactly one. |
| `restore commit [--retire]` | From K7, K8, K9, K10 or K11: performs the remaining steps. `--retire` only from K5b. |
| `restore abort [--orphans]` | Only from K5a or K7 (authority still `E`). Writes audit, then deletes the candidate, every `restore-*` directory, and the manifest last. `--orphans` cleans K3 leftovers. |
| `restore status` | Read-only; prints the class and row. |

```text
RestoreEpochTransitionRequestV2 (closed map; file handed to a custodian)
  domain              tstr  "shardx.restore-epoch.transition-request.v2"
  version             U16   2
  server_instance_id  Uuid16
  tenant_id           Uuid16
  previous_epoch      U64   E
  new_epoch           U64   E+1
  restore_txn_id      Bytes(16,16)
  backup_db_sha256    Hash32
  mapping_codec       tstr  "PROFILE_HEAD_SET_MERKLE_V2"
  leaves              array of exact RestoreEpochLeafV2 bytes, sorted per L678, length 1..1000000
```

**Signing the transition.**
- The custodian's client (the v0.2.2 workflow, L2396) checks every leaf whose profile it has pinned against its own pinned head.
- It then builds the `RestoreEpochTransitionV2` payload over the same leaves (L719-L735), signs it, and exports the exact signed container file.
- In the G2/v0.2.0 harness, test custodian keys sign.
- Release builds before v0.2.2 refuse `restore export-heads` and `restore prepare` with a non-zero exit.

**Audit.** This extends ADR 0001 D3 (ADR1 L726-L731). Actor columns are NULL and `reason_code = offline_operator_cli`.
- `server.restore_prepare` and `server.restore_abort` are written in the live DB.
- Inside the step-5 transaction, `server.restore_commit` and one `tenant.restore_epoch_transition` per tenant (L2316) are appended to the candidate's copy of the live audit.
- The prepare audit therefore survives both in the installed DB, which carries the live audit, and in the archived `pre-restore-<txn_hex>.db`.

### Alternatives

- **Option B (canonical CBOR manifest).** Self-describing, but it needs the CBOR decoder before the authority is trusted, which is the reason ADR 0001 chose a fixed layout (ADR1 L210-L215). It is also not fixed-size.
- **Option C (plan amendment: restore out of v0.2.0).** Amend L2337, L2341, L2363 and L2673, and score G2-55/56/57/60 "deferred by amendment". v0.2.0 is internal-only (L2368), so the real cost is not production risk: the restore path reaches v0.2.2 unharnessed, and the amendment needs a fresh Architect + Critic pass.
- **Whole-DB restore with carry-forward (revision 2).** Carry forward revoked rows and every newer generation row. Rejected: it must enumerate every kind of control-plane change and still loses post-backup records. The round-2 review showed one missed kind (generations) already breaks L1385.
- **Whole-DB restore plus a forced rotation above the live maximum.** Rejected for the same reason: revocations, approvals and grants issued after the backup would still be lost or resurrected.
- **Terminal state by rename** (`restore-preparation-v2.done`) instead of a state byte. Equivalent; rejected only because the state byte reuses the accepted P1 write primitive and keeps one file name.

### Unblocks and tests

- **Rows:** G2-55, 56, 57, 60, and the preparation parts of G2-52, 54 and 58. Workstream W8. Conditional on the Q-1 answer and the restore-scope reinterpretation.
- **Work item WI-AUDIT-RO (new server work, W8; critic r8 minor 3).** It changes the shipped v1 audit path. `server/src/audit.rs:22-31` today discards the result of the `audit_log` insert (`let _ =`). Under `mode=ro` (K2 and restore in progress), each failed audit write must be logged at error level with its action and actor and added to a counter. `restore status` and the K2 incident output print that count. Outside read-only mode, the behaviour of v1 is unchanged. Covered by the harness rows "Server in K7" and "v1 in K2".
- **Golden vectors:**
  - PREPARED and TERMINAL manifests for `0->1`, with an empty index and a two-tenant index;
  - index and request bytes with their hashes;
  - `proof_set_sha256` for `mapping_count = 1, 2, 3`, reusing L753-L756.
- **Negative vectors:**
  - size 199/201, magic `SHARDXID`, version 1, `state` 0 and 3, reserved non-zero, checksum flip;
  - `new_epoch != previous_epoch + 1`, a zero txn ID or zero hashes, a `previous_record_sha256` mismatch;
  - unsorted or duplicate index entries;
  - an artifact whose hash differs from its name.
- **Crash harness:** one injected crash at every row of the crash-point table, including the three step-4 sub-steps, each asserting the expected class K and plan row. K5a, K5b and K12 by corruption injection.
- **Restore-scope harness (round-2 B5, M10):**
  - **Across a fleet rotation that excluded a device.** After restore, the ACTIVE generation and its grants are the live ones, the excluded device receives nothing, and the next rotation number is the live maximum + 1.
  - **Across a root rotation.** Same assertions for root generations.
  - **Revocations.** A device or grant revoked after the backup stays revoked.
  - **Fencing.** The first fencing token after restore exceeds the live `last_fencing_token`.
  - **Refusals.** A backup snapshot under a generation the live DB has garbage-collected refuses, and `--drop-unreferenced` records it as lost. A schema-version mismatch refuses. A missing or corrupt live DB refuses. A non-empty live `-wal` after the checkpoint refuses. A live DB changed between prepare and commit refuses at K7.
  - **Zero custodians.** A tenant with zero live custodians that needs coverage refuses.
  - **Merge completeness (round-3 B6).** For a normal backup, `foreign_key_check` is empty after the merge with no row dropped, and every kept snapshot has its `COMMITTED` upload. Every dropped backup row is listed.
  - **Replays after restore (round-3 M16).** A retry of a rolled-back commit returns `BASE_VERSION_MISMATCH`. A retry of a dropped create-upload, finalize or publish returns `RESOURCE_NOT_FOUND`. The first commit after the restore reuses `V_backup + 1` at a new `snapshot_id` path, and no archived blob is touched.
  - **Revoked signer (round-3 M17).** A backup head signed by a device revoked in live refuses. With `--drop-unreferenced`, that snapshot and its later versions are dropped, and the head moves down.
  - **Server in K7 (round-3 minor 8).** A server started between prepare and commit cannot write, and `live_db_sha256` still matches at commit. v1 logins and reads still work there, as in K2.
  - **Rolled-back head replayed after a restore (critic r7 M22).**
    - Setup: live heads `V_b+1..V_live` at epoch `E`; restore to `V_b`; the archived `pre-restore` DB still holds the old `V_b+1` manifest `M_old` (epoch `E`, `previous_signed_head_hash` = the restored head, honestly signed).
    - The server shows `M_old` to client A and the honest post-restore head (`V_b+1`, epoch `E+1`) to client B.
    - Expected: A, which has re-pinned to the transition leaf, quarantines with `HEAD_ROLLBACK_DETECTED` and does not pin `M_old`; B accepts the honest head; no profile forks at `V_b+1`.
  - **v1 outside a restore (round-4 B7).** With `SHARDX_IDENTITY_DIR` unset (K1), v1 login and writes still work and v2 writes are refused.
  - **Blob paths (C-2).** A promote onto an existing path with different bytes quarantines the upload and leaves the path unchanged; a promote with identical bytes succeeds. No code path deletes or overwrites a blob path that a live head or retained snapshot references. Retention GC deletes only unreferenced paths and never rewrites one.
  - **v1 in K2 (C-3; critic r7 minor 3).** In K2, v1 writes fail, and v1 logins and reads succeed. A failed login's audit write fails, and the server logs it at error level and counts it in the incident output, instead of dropping it silently.

---

## D-2. `Capability` value set, issuer rules and subject rules

### Plan facts

- `Capability` syntax: `[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+` (L396-L397).
- L1067 lists a **minimum** set: `tenant.manage`, `membership.manage`,
  `fleet.manage`, `device.approve`, `device.revoke`, `key.rotate`,
  `recovery.manage`, `lease.force_expire`, `profile.publish`,
  `profile.checkout`, `profile.commit`, `root.custody`.
- Fixed `grant_capability` values: `fleet.key.receive` (L494),
  `fleet.key.recover` (L495), `key.rotate` (L496), `root.custody` (L771).
- `root.custody` in a capability grant only device-scoped (L484-L485).
- Issuers need a "suitable" capability (L427), never mapped per record kind
  (ADR1 L655-L656).
- **Who signs, per the plan text:** later devices need an "owner/root-signed
  approval và key grant" (L257); ordinary fleet devices receive a "root/owner-
  signed HPKE FKEK grant" (L258). Commit requires role, explicit capability and
  a valid signature (L1412).
- ADR 0001 D2: only an ACTIVE root custodian issues capability grants
  (ADR1 L710-L724).

Production mismatch: the server checks `"root-custody"`
(`server/src/grants.rs:19`, same on `main`), not a valid `Capability`; shared
and plan use `root.custody` (`shared/src/grants.rs:47`). The server accepts a
non-plan fleet variant `FirstFleetSelfGrant`
(`server/src/fleet_generations.rs:24` on `main`).

### Interpretation of L257/L258 (stated, critic M1)

"Owner" in L257/L258 cannot mean the role, because no role implies any
capability (L1067, ADR1 L640-L641). This ADR reads "owner/root-signed" as
**signed by a root custodian**. Revision 1 let any `device.approve` or
`fleet.manage` holder sign; that widened the plan and is withdrawn. Delegation
to non-custodian admins is listed below as a rejected alternative that would
need a plan amendment.

### Proposed decision

**Value set (closed, 14 values).** Anything else rejects as
`NON_CANONICAL_RECORD`.

| Value | Where it may appear | Scope kinds in `TenantCapabilityGrantV2` |
|---|---|---|
| `tenant.manage` | capability grant | `tenant` |
| `membership.manage` | capability grant | `tenant` |
| `fleet.manage` | capability grant | `tenant`, `fleet` |
| `device.approve` | capability grant | `tenant`, `fleet` |
| `device.revoke` | capability grant | `tenant`, `fleet` |
| `key.rotate` | capability grant; `RotationGrant.grant_capability` | `tenant`, `fleet` |
| `recovery.manage` | capability grant | `tenant` |
| `lease.force_expire` | capability grant | `tenant`, `fleet`, `profile` |
| `profile.publish` | capability grant | `tenant`, `fleet` |
| `profile.checkout` | capability grant | `tenant`, `fleet`, `profile` |
| `profile.commit` | capability grant | `tenant`, `fleet`, `profile` |
| `root.custody` | `TenantRootKeyGrantV2.grant_capability`; capability-grant issuance rejected (Q-2) | none |
| `fleet.key.receive` | `DeviceHpkeGrant.grant_capability` only | none |
| `fleet.key.recover` | `RecoveryGrant.grant_capability` only | none |

**Issuer matrix.** "Custodian" means a device holding a live, acknowledged,
non-revoked `TenantRootKeyGrantV2` in the ACTIVE root generation. All checks
are against live state in the mutation transaction (L1107). "Holding" a capability means a live,
**device-scoped** `TenantCapabilityGrantV2` (subject device = the acting
device) covering the scope; account-scoped grants serve server RBAC only and
never satisfy an issuer or signer rule (round-2 minor 3). Clients use a
superset of this custodian definition (trust-chain rule 1 also counts a root
`RotationGrant` before its generation activates); the difference matters only
with a hostile server, which still needs a custodian's signature.

| Record | Issuer must be |
|---|---|
| `DeviceApprovalV2` | D1 one-time self-issue (ADR1 L677-L702); otherwise a custodian holding `device.approve` covering `approval_scope_kind/id`. Renewal self-approval (same device, same keys, while its current approval is live) is allowed under this rule (**new**, needed by D-6) |
| `DeviceRevocationV2` (Q-13) | a custodian holding a device-scoped `device.revoke` (L1067) covering the subject device's approval scope |
| `TenantCapabilityGrantV2` | a custodian (D2) |
| `DeviceHpkeGrant` | a custodian holding `fleet.manage` covering the fleet and holding that FKEK generation. Issuer may equal subject; this replaces `FirstFleetSelfGrant` |
| `RecoveryGrant` | a custodian of `recipient_root_generation`, which is ACTIVE at issuance; or, during a root rotation (D-5), a custodian of the ACTIVE root `N` holding an acknowledged `RotationGrant` to the PREPARING `N+1` it wraps under |
| `RotationGrant` | a custodian holding `key.rotate` covering the fleet and holding the previous generation |
| `TenantRootKeyGrantV2` | fixed by L812-L828 |
| `RestoreEpochTransitionV2` | a same-tenant custodian (L733, L1131) |
| `SignedSnapshotManifestV2` (critic M2) | a device with a live `DeviceApprovalV2` whose scope covers the fleet or tenant, holding a device-scoped `profile.commit` covering the profile or its fleet, and (server side) the current lease holder (L1412); clients check it when a head is first accepted (trust-chain rule 6) |

**Subject eligibility for `DeviceHpkeGrant`** (server side, at filing and at
release; critic M1): the subject device is `active` and not revoked
(L1385); it has a live `DeviceApprovalV2` with scope `tenant` or this fleet;
`subject_signing_key_id` and `recipient_hpke_key_id` equal the device row's
`signing_key_id` and `hpke_key_id`; the subject account is a member of the
fleet; and the generation is PREPARING (required set) or ACTIVE.

### Alternatives

- **Delegated issuers.** Any `device.approve` / `fleet.manage` holder signs.
  Lets admins without custody hand out FKEKs; wider than L257/L258 and doubles
  the client chain depth. Needs a plan amendment.
- **Open set, regex only.** Unknown values would be stored and shown as
  meaningful; conflicts with closed records (L391).
- **Extra `fleet.key.grant` capability.** A value the plan never names.

### Unblocks and tests

- Rows: G2-02, issuer checks in G2-01, 03, 04, 05, 06, G2-07 (manifest
  signer), G2-17, 19, 20, 30. Workstreams W1, W4.
- Vectors: one valid grant per (value, allowed scope); negatives per value
  with a disallowed scope, `root-custody`, uppercase, trailing dot,
  `fleet.key.receive` as a capability, `fleet.key.grant`, account-scoped
  `root.custody`, any `root.custody` capability-grant filing.
- Integration: each record kind signed by a non-custodian holder of the
  capability, a custodian lacking the capability, a revoked custodian, a
  PREPARING or RETIRED custodian, cross-tenant; `DeviceHpkeGrant` to a revoked,
  unapproved or non-member device, or with an HPKE key ID differing from the
  device row; manifest signed by a device without `profile.commit`.

---

## D-3. Envelope v2 and STREAM (G2-27)

Moved to [ADR 0003](0003-envelope-v2-stream.md), which also records the
G2 dependency review (plan L2443) that selects provider A. The approved
row on the approval page above is unchanged.

## D-4. Set-hash preimages

### Plan facts

- `RotationGrant` carries `required_device_grant_count:U32`,
  `required_device_grant_set_hash` and `recovery_grant_signed_container_hash`
  (L496). Root create/activate carry `required_custodian_grant_count:U32` in
  `1..65535` and `required_custodian_grant_set_hash` (L860-L861, L885, L943,
  L946). Fleet generation rows carry `recovery_grant_hash` and
  `required_grant_set_hash` (L1074). Rotation activation needs the exact
  recovery grant and required device grant set (L1128, L1382, L2618).
- No preimage is defined.
- Derived from plan rules: at root bootstrap the only grant that can target
  generation `0` is the single `FirstRootSelfGrant` (L812-L818, L1073), because
  `ExistingRootGrant` targets the ACTIVE generation (L820). So the bootstrap
  custodian set has exactly one member.
- Precedent: L496 binds a grant by its internal `signed_container_hash`.

### Proposed decision (Option A)

```text
required_custodian_grant_set_hash =
    domain_hash("SHARDX-ROOT-CUSTODIAN-GRANT-SET-V2\0", h_1 || ... || h_n)
required_device_grant_set_hash =
    domain_hash("SHARDX-FLEET-DEVICE-GRANT-SET-V2\0", h_1 || ... || h_n)
```

`h_i` is the internal `signed_container_hash` (L436) of each required grant,
sorted ascending as unsigned bytes, no duplicates, `n` equal to the payload
count, and `n >= 1` for both sets (a fleet generation with no device able to
open it is invalid; answers critic minor 9). Root members are the
`FirstRootSelfGrant` (bootstrap, `n = 1`) or `RotationGrant`s for the target
generation and key ID; fleet members are `DeviceHpkeGrant`s for the same fleet,
generation and `fkek_key_id`. Members' `subject_device_id` values are pairwise
distinct. Fleet rows store `required_grant_set_hash =
required_device_grant_set_hash` and `recovery_grant_hash =
recovery_grant_signed_container_hash`; for generation `0` both come from the
D-9 create payload, for rotations they must also equal the `RotationGrant`.
Count range: `1..65535` in the wire payload, the server and the local DDL
(Q-4; tightening the local `1..4294967295` at L1664 is allowed by L1442).

Activation predicate: for every `h_i` a grant row with that hash exists, is
non-revoked, acknowledged, valid at `server_now`, and passes all-column
equality; extra grants outside the set are allowed. The client builds every
required grant before create (grants need only the generation number and key
ID). Replacing a required grant after create needs a new generation.

### Alternatives

- **Canonical CBOR set map** with context fields: repeats context the members
  already bind and needs array support in every verifier.
- **Recipient tuples** (`device_id || hpke_key_id`): allows reissue without a
  new generation but stops pinning exact grants.

### Unblocks and tests

- Rows: G2-05, G2-16, G2-19, fleet activation (D-9), G2-44 columns.
  Workstream W4.
- Vectors: root set `n = 1, 2, 3`; fleet set `n = 1, 2, 3`.
- Negatives: unsorted, duplicate, count mismatch, `n = 0`, member for another
  generation or key, two members for one device, member revoked or not
  acknowledged, bootstrap with `n = 2`, count 65536.

---

## D-5. Root wrap, recovery bundle, recovery evidence and fallback key file

### Plan facts

- `RecoveryGrant` fields and bounds (L495, L1630);
  `grant_capability = fleet.key.recover`.
- FKEK AEAD-wrapped under the TRK (L1294, L1355); DEK-wrap precedent: AAD is
  the exact context bytes (L616).
- **Recovery bundle contains the TRK and retained FKEKs**, encrypted under a
  passphrase-derived key, with version, suite, KDF params, fingerprint and
  integrity authentication (L1386); export needs re-auth, passphrase
  confirmation, write-readback and a synthetic-key test unwrap (L1387).
- Old generations are kept until no retained snapshot references them and the
  recovery drill passes (L1384); v0.2.2 gates: lost-device + recovery-bundle
  drill, restore of every retained generation before key GC (L2403-L2404).
- Excluding a device needs a new root generation and **rewrapped fleet
  recovery grants** (L831-L832).
- Activation validates "all acknowledgements/recovery evidence" (L946) and
  waits for recovery-bundle readiness (L819).
- `recovery_bundle_sha256` in root create/activate and rows (L862, L885,
  L943, L946, L1071; local nullable L1663). Argon2id fallback profile 64 MiB,
  `t=3`, `p=4`, salt >= 16, only raise cost (L1375); recovery-KDF separate from
  password hashing (L2448). Fallback encrypted key file when the OS store is
  unavailable (L1374).

### Proposed decision

**Root wrap (Option A, unchanged from revision 1).**

```text
FleetRecoveryWrapContextV2 (closed map)
  domain                     tstr  "shardx.keys.fleet-key-grant.recovery.wrap-context.v2"
  version                    U16   2
  replay_id                  ReplayId16
  tenant_id                  Uuid16
  server_instance_id         Uuid16
  restore_epoch              U64   issuance epoch (Q-1)
  fleet_id                   Uuid16
  fkek_key_id                KeyId32
  generation                 U64
  recipient_root_key_id      KeyId32
  recipient_root_generation  U64
  root_wrap_suite_id         U16   1
  grant_capability           tstr  "fleet.key.recover"

wrapped_fleet_key_bytes = ChaCha20-Poly1305.Seal(key = TRK, nonce = root_wrap_nonce_bytes[12] random,
                            aad = exact root_wrap_context_bytes, plaintext = FKEK[32])   -> 48 bytes
```

Every context field equals the payload field of the same name before unwrap;
after unwrap the plaintext is 32 bytes and `fkek_key_id(plaintext)` equals
`fkek_key_id`, else fail closed and zeroize.

**Recovery evidence at root rotation (critic B3, new).** `ROOT_GENERATION_ACTIVATE`
for generation `N+1` additionally requires, inside its transaction, that every
retained fleet generation of the tenant (state ACTIVE, or RETIRED and not yet
GC'd per L1384) has an acknowledged, non-revoked `RecoveryGrant` with
`recipient_root_generation = N+1`. This is how this ADR defines L946's
"recovery evidence"; it needs no new wire field. So no retained FKEK is left
reachable only through a RETIRED root. The rotating custodian produces these
grants by unwrapping the existing grants under `N` and rewrapping under `N+1`
(L831-L832). A fleet generation activated while root `N` is ACTIVE gets its
`RecoveryGrant` under `N` (D-9) and is carried into `N+1` by this rule. The
rewrapped grants are acknowledged by a custodian of ACTIVE `N` that holds an
acknowledged root `RotationGrant` to `N+1`, and therefore TRK `N+1` (D-9 ack
actor; round-2 M11).

**Recovery bundle (critic B3: now carries what L1386 requires).**

```text
RecoveryBundleHeaderV2 (closed map; also the AEAD associated data)
  domain             tstr   "shardx.recovery.bundle.v2"
  version            U16    2
  tenant_id          Uuid16
  server_instance_id Uuid16
  root_generation    U64
  root_key_id        KeyId32
  kdf_id             U16    1 = Argon2id, version 0x13
  kdf_memory_kib     U32    65536..1048576
  kdf_iterations     U32    3..64
  kdf_parallelism    U32    exactly 4
  kdf_salt           Bytes(16,16)
  aead_suite_id      U16    1 = ChaCha20-Poly1305
  aead_nonce         Bytes(12,12)
  created_at_ms      UnixMs

RecoveryBundleV2 (file bytes) = the header map's fields plus
  ciphertext         Bytes(48,16777216)
encoded as one closed canonical map; AAD = exact canonical bytes of RecoveryBundleHeaderV2.

KEK = Argon2id(passphrase UTF-8, salt = "SHARDX-RECOVERY-BUNDLE-KDF-V2\0" || kdf_salt,
               m, t, p from the header, out = 32)

RecoveryBundlePlaintextV2 (closed map)
  domain                           tstr  "shardx.recovery.bundle-plaintext.v2"
  version                          U16   2
  root_key_id                      KeyId32
  trk                              Bytes(32,32)
  bootstrap_anchor_signing_key_id  KeyId32   (trust chain; new)
  retained_fkeks                   array sorted by (fleet_id, generation), unique, length 0..65535
    item: { fleet_id Uuid16, generation U64, fkek_key_id KeyId32, fkek Bytes(32,32) }

recovery_bundle_sha256 = domain_hash("SHARDX-RECOVERY-BUNDLE-V2\0", exact file bytes)
```

**Passphrase bytes (Q-21, decided by the user on 2026-10-26).** The
passphrase enters the KDF as the exact UTF-8 bytes typed, without Unicode
normalization. A minimum length binds only a new export, never the opening
of an existing bundle, so a later build that raises it still opens older
bundles.

Content rule: `retained_fkeks` holds **every** retained FKEK of the tenant at
export time (L1386). At bootstrap there are none. The bundle pinned by a
rotation `N+1` holds TRK `N+1` and every retained FKEK, which the rotating
custodian already unwraps to produce the rewrapped `RecoveryGrant`s above.
FKEKs created after the pinned export are recoverable through their
`RecoveryGrant` under the ACTIVE root. The activating client then sets its
local `device_state.recovery_ready = 0` (L1502) and shows a warning until the
user re-exports a bundle that includes the new FKEK. This is advisory and local
to that device (round-2 minor 6): other devices are not blocked, and until the
re-export the new FKEK is recoverable only through the server-held
`RecoveryGrant`. Re-exported bundles use the same format and are not referenced
by any server row.

After decrypt: `root_key_id(trk)` equals both `root_key_id` fields, every
`fkek_key_id` re-derives, all buffers zeroize. The L1386 fingerprint is
`root_key_id`; the UI shows the full value on request and a truncated form
otherwise, and logs never contain it (L2642).

**Readiness (L819, L1387).** The client re-reads the file from its final path,
recomputes `recovery_bundle_sha256`, decrypts, checks the IDs, then seals a
fresh random 32-byte key under the recovered TRK with ChaCha20-Poly1305, a
random 12-byte nonce and AAD = canonical `RecoveryReadinessProbeV2`
`{domain:"shardx.recovery.readiness-probe.v2", version:2, root_key_id,
probe_nonce:Nonce16}`, and opens it again (critic minor 8). Only the hash
travels, in the activate payload.

**Fallback encrypted key file (new; for W7/G2-48; own header per round-2 minor 5).**
`<config_root>/team-sync/keys-fallback.bin` is one closed canonical map with the
fields of `FallbackKeyFileHeaderV2` plus `ciphertext Bytes(48,16777216)`;
AAD = exact canonical bytes of the header.

```text
FallbackKeyFileHeaderV2 (closed map)
  domain           tstr   "shardx.local.fallback-key-file.v2"
  version          U16    2
  kdf_id           U16    1 = Argon2id, version 0x13
  kdf_memory_kib   U32    65536..1048576
  kdf_iterations   U32    3..64
  kdf_parallelism  U32    exactly 4
  kdf_salt         Bytes(16,16)
  aead_suite_id    U16    1 = ChaCha20-Poly1305
  aead_nonce       Bytes(12,12)
  created_at_ms    UnixMs

KEK = Argon2id(passphrase UTF-8, salt = "SHARDX-FALLBACK-KEY-FILE-KDF-V2\0" || kdf_salt,
               m, t, p from the header, out = 32)

FallbackKeyFilePlaintextV2 (closed map)
  domain   tstr  "shardx.local.fallback-key-file-plaintext.v2"
  version  U16   2
  entries  array sorted by credential_ref, unique, length 0..4096
    item: { credential_ref Text(1,255), key_kind enum signing|hpke|trk|fkek, key_bytes Bytes(32,32) }
```

The header has no tenant, root or instance field; each entry is bound to its
use by `credential_ref`. `team-sync.db` keeps only `credential_ref` (L1373).

### Alternatives

- Root wrap AAD with a label prefix (L801-L803 pattern), or an HKDF subkey
  with XChaCha: equally sound, more constructions to test.
- Bundle with all retained TRKs instead of rewrapped grants: keeps old roots
  alive in every bundle and still needs RecoveryGrants for server-side
  recovery; rejected.
- Bundle with TRK only (revision 1): contradicts L1386 and, combined with no
  rewrap rule, loses pre-rotation FKEKs (critic B3); withdrawn.
- Reuse `SHXBAK01`: profile-archive format, hand-written nonce, `p = 1`.

### Unblocks and tests

- Rows: G2-04, G2-16, G2-19, G2-46, G2-48 (fallback file), `P-OP` drill
  (L2564). Workstreams W4, W7.
- Vectors: wrap context and wrapped FKEK; bundle file and hash for a fixed
  passphrase/salt/nonce with two retained FKEKs; RFC 9106 Argon2id KAT;
  readiness probe bytes.
- Negatives: context field mismatches, nonce 11/24, wrapped 47/49, wrong TRK,
  `fkek_key_id` mismatch; wrong passphrase, each header field mutated,
  `kdf_parallelism = 1`, `kdf_memory_kib = 65535`, TRK ID mismatch, unsorted
  FKEKs; root activation with one retained fleet generation lacking a
  `RecoveryGrant` under `N+1`.
- Drill: rotate root twice, lose every device, recover from the latest bundle
  alone, restore one snapshot of every retained fleet generation (L2404).

---

## D-6. TTL policy, renewal, stolen-key exposure and `authorization_replay_retention`

### Plan facts

- **Window rules.** `issued_at_ms <= not_before_ms < not_after_ms`, `server_now` in the window, and a TTL within tenant policy (L406-L408). The tombstone lasts at least `not_after_ms + authorization_replay_retention`, and nothing is reused after a revoke (L409-L410).
- **When validity is checked.** At every authorization or key release (L370, L1081). This settles revision 1's Q-3: the window is not just an issuance window.
- **Root-grant rules.**
  - Root grants bind an exact active approval (L774).
  - An `ExistingRootGrant` may be signed by a "different-or-same" live custodian (L820-L822).
  - The first self-grant and the D1 approval are one-time (L1073, ADR1 L688-L699).
- **Replay ledger.** ADR 0001 R3 sets `retained_until = not_after_ms + authorization_replay_retention` (ADR1 L1019-L1031).
- **What the plan leaves undefined.** No TTL value, storage location or renewal flow.
- **Hidden revocations.** Clients cannot see revocations that a hostile server hides; that case is outside the guarantee (L376).

### Options

- **A. 3650-day constants, no renewal (revision 1).** Ten-year exposure for a non-custodian key, then a deadlock cliff. Withdrawn.
- **B. Uniform 365 days with renewal.** Shortest window for non-custodian keys. The cost: custodians must be online at least every six months, or the tenant deadlocks.
- **C. Per-tenant policy columns.** The literal reading of "tenant policy". The cost: mutable state, a CLI command, and a policy read before each issuance. It can be added later by additive migration.
- **D. Tiered constants with mandatory renewal (recommended).**

### Proposed decision (Option D)

Constants in `shared`, the one policy every tenant has:

| Record kind | Max `not_after_ms - not_before_ms` | Why |
|---|---|---|
| `DeviceApprovalV2` | 730 days = `63072000000` ms | custody backbone; a lapse deadlocks the tenant |
| `TenantRootKeyGrantV2` (all variants) | 730 days | same |
| `TenantCapabilityGrantV2` | 365 days = `31536000000` ms | bounds client-side exposure of delegated authority; any custodian can renew |
| `FleetKeyGrantV2::DeviceHpkeGrant` | 365 days | same |
| `FleetKeyGrantV2::RecoveryGrant` | 3650 days = `315360000000` ms | self-authenticating under the TRK (a forgery yields nothing); must outlive retained snapshots; rewrapped at every root rotation (D-5) and renewed by step 2 below |
| `FleetKeyGrantV2::RotationGrant` | 30 days = `2592000000` ms | activation window only; not renewed |
| `DeviceRevocationV2` (Q-13) | 30 days | `server_now` must be inside the window when the record is filed; afterwards the revocation is permanent (round-3 minor 4). This exception to the use-time check of L406-L408 is listed as an amendment on the approval page |
| `MAX_CUSTODIAN_KEY_AGE` (new) | 1095 days = `94608000000` ms from the key's first custodian window | mitigation (c) below |
| `authorization_replay_retention` | 90 days = `7776000000` ms | authorization rows are never deleted in v0.2.x; this only sets `retained_until` of derived ledgers |

**Renewal flow (new; existing endpoints only).** A record is due for renewal
once `now >= not_before_ms + (not_after_ms - not_before_ms) / 2`.

1. **A custodian renews itself in this order** (round-2 minor 11). Each step runs while the records it relies on are still live:
   1. a new set of its own capability grants (D2), which needs only its live custodianship;
   2. a new `DeviceApprovalV2` for itself (a renewal self-approval, D-2), which needs the live `device.approve`;
   3. a new `ExistingRootGrant` to itself for the ACTIVE generation, linking the new approval (L821 allows the same custodian), followed by `ROOT_GRANT_ACK`.

   The order matters only when an old record is close to lapsing; in normal operation, all three are renewed at 50%.
2. **A custodian's client, whenever online, renews due records of the tenant's other active devices:**
   - approvals, capability grants and `DeviceHpkeGrant`s;
   - every due `RecoveryGrant`. It holds the TRK, so it unwraps and rewraps under the ACTIVE root (round-2 minor 4).
3. **Old records are not revoked; they lapse.** The approval endpoint must accept a renewal approval for an already active device with unchanged keys. That is a server change: ADR 0001 R3 handles only pending devices.
4. **Warnings.** The UI warns at 75% of any custodian's lifetime and at 75% of its key age, and names the date.
5. **Re-key.** Before `MAX_CUSTODIAN_KEY_AGE`, a custodian device re-keys through existing flows:
   1. it enrolls a fresh key pair as a new device (ADR 0001 enrollment);
   2. it is approved and root-granted by a custodian, which may be its own old key;
   3. the old device row is revoked (Q-13).
6. **Total lapse.** If every custodian lapses, custody is lost, and the tenant recovers into a new tenant through Q-14. This is a residual risk, to be documented in the runbook.

**Clocks.**
- Acceptance needs no extra rule: `not_before_ms <= server_now` is already L408.
- Clients take `issued_at_ms` and `not_before_ms` from the server clock, through an additive `server_now_ms` field in `GET /v2/me` (new; L1123 lists the endpoint without a body).
- Client-side window checks use the local clock with a 300 s tolerance (new).

### Exposure of a stolen key (honest bound; round-2 B4)

**With a server that reports revocations:**
- the server rejects a revoked key immediately;
- clients reject it from the reported `revoked_at_ms`.

**With a hostile server that hides revocations** (outside the guarantee, L376):

| Stolen key | Client-side bound |
|---|---|
| Non-custodian (capability holder, FKEK recipient, manifest signer) | It cannot issue records to itself. Clients accept its signatures for at most 365 days (+300 s) after the last legitimate capability grant to it. This needs the first-acceptance rule for manifests (trust chain, rule 6). |
| Custodian | **No time limit.** The thief signs a renewal to the key itself, choosing `issued_at_ms` inside the key's current window, and repeats before each window ends. It can also appoint new custodians and issue their approvals and capability grants. The fixpoint accepts all of this, because each step only needs the issuer to be a custodian at the chosen `issued_at_ms`. |

**Mitigations (proposed).** They detect misuse; they do not prevent it.

- **(a) Custodian ledger and change events.**
  - Each client stores, in its W6 signed-claim store, one row per custodian key: first local sighting, first window `not_before_ms`, latest `not_after_ms`, and the appointing key.
  - On every trust-evidence evaluation, it raises a UI event and a local audit entry for:
    - `custodian.appointed`: a key not in the ledger becomes a custodian;
    - `custodian.renewed_after_revocation`: a window is extended for a key whose device this client knows is revoked (reported, or a `DeviceRevocationV2`, Q-13) or re-keyed (step 5 above). The time is the local first-seen time of the extending record, never its `issued_at_ms`.
  - Revision 3's 180-day `custodian.renewal_fork` detector is dropped (round-3 minor 2). Root `RotationGrant`s and re-issue after lost client state made it noisy, the thief chooses `issued_at_ms`, and a thief riding the legitimate windows never needs to renew.
  - The event shows the issuing and subject keys, truncated, with the full values one click away. It stays badged in Team settings until a user acknowledges it. The final wording and acknowledgement flow come from the custodian-event UX design review held before W6 starts (Q-17, decided by the user on 2026-10-25).
  - Every device with history that accepts a forged custodian therefore shows it. A device that is never shown the forged chain does not trust it.
  - **Limit (round-3 minor 3).** A new device baselines whatever the evidence shows, so a forged custodian already present when it joins raises no `appointed` event there.
- **(b) Sticky lapse.**
  - When a client first computes that a ledger key has no window containing `now`, it records `observed_lapsed_at_ms` (local clock).
  - From then on, a record that would extend that key counts only if its issuer is another custodian and its `issued_at_ms` is greater than `observed_lapsed_at_ms`, which is a re-appointment.
  - This defeats backdated extensions of a key taken from a device after its custody ended, such as a disposed device.
- **(c) Maximum custodian key age.**
  - Every window of key `K` is clipped at `first_not_before(K) + MAX_CUSTODIAN_KEY_AGE`. `first_not_before(K)` is the smallest `not_before_ms` of any usable root grant with subject `K` the client has ever seen. It is cached in the ledger and never increases.
  - The server also rejects filing a root grant whose `not_after_ms` exceeds that limit.
  - A forged chain therefore cannot keep one stolen key alive for more than 1095 days after that key's first window. A longer attack must introduce a new custodian key, which (a) shows on every device with history that accepts it.
  - **Limit (round-3 minor 3).** A server that omits a key's earliest root grant from a new device's evidence raises `first_not_before(K)` on that device and stretches its clip. Omission is safe for the fixpoint (it can only refuse), but not for the clip. Devices with history keep their cached minimum.
- **(d) Local distrust.**
  - Team settings offers "Distrust custodian key K".
  - The device then ignores every record issued by `K` that it first saw locally after the distrust moment. Local first-seen times cannot be forged by the thief.
  - A device with no history of `K` ignores `K` entirely.
  - Custodians whose only path ran through a distrusted key must be re-appointed by another custodian. If `A0`'s path is the only one, the tenant recovers through Q-14.
  - On a non-hostile server, the custodian also revokes the key (Q-13).
- **(e) Sticky proven revocation (new; critic r7 M23).**
  - Once a client counts a signed `DeviceRevocationV2` of device `D` (trust-chain rule 6), `D`'s signing key has no custodian window for any record the client first sees afterwards, and every such record signed by that key is unusable, whatever its `issued_at_ms` (trust-chain rule 1).
  - It works like (d), but a signed revocation triggers it instead of a user action, so a hostile server cannot undo it by omitting the unsigned revocation reports.
  - **Limit.** A device with no history first sees `D`'s revocation and `D`'s other records in the same evaluation, so it cannot separate backdated records from legitimate ones (the history limit of (a) and (c)).

**Resulting bound, stated exactly.** Against a hostile server:
- a stolen custodian key stays usable without a time limit until a device counts a signed revocation of it; from then on, that device refuses every record by the key that it first sees later;
- every device **with history** that accepts a forged custodian key shows a `custodian.appointed` event;
- a single stolen key's own custodianship ends within 1095 days of its first window;
- nothing here prevents misuse before a user reads the event.

The trust-chain section implements (a)-(e).

**Rejected mitigation: a cap on renewals without a fresh root-generation event.** A thief holding a custodian key also holds the TRK, so it can sign a root `RotationGrant` and the new generation's grants. The cap bounds nothing against the thief, and it costs every tenant a full root rotation and rewrap.

### Unblocks and tests

- **Rows:** validity checks in G2-01..06; `retained_until` in G2-15/G2-31 and the ADR 0001 R3 ledger; G2-45 bounds. Workstreams W1, W3, W4, W6.
- **Tests per record kind:**
  - the maximum window accepts, +1 ms rejects;
  - a future `not_before_ms` rejects;
  - use after expiry rejects before authorization and before HPKE open;
  - the renewal chain for a single-custodian tenant crosses the old expiry with no gap;
  - a renewal approval for an active device with changed keys rejects;
  - GC deletes only ledger rows.
- **Tests per mitigation:**
  - `RecoveryGrant` renewal rewraps under the ACTIVE root;
  - a root grant past `MAX_CUSTODIAN_KEY_AGE` is rejected by the server and clipped by the client;
  - a backdated extension after an observed lapse is ignored;
  - a forged appointment raises `custodian.appointed`;
  - a renewal of a key whose device is known to be revoked raises `custodian.renewed_after_revocation`, measured by local first-seen time;
  - after distrust, a record first seen later is ignored;
  - after a signed revocation of a custodian is counted, a record by its key first seen later is ignored (vectors in trust-chain rule 6).

---

## D-7. `binding_tombstone_sha256` preimage

### Plan facts

- `LOCAL_UNBIND` request and response fields (L953); mutation, tombstone and
  exact response commit together (L934-L936); retry after deletion returns the
  tombstone response (L969-L970); probe 1 requires tombstone context, request
  hash and exact receipt bytes to survive the deletion (L2036); a completed
  `UNBIND` must carry `exact_receipt_bytes` (L1863). No preimage is defined.

Constraint: the preimage must be recomputable from bytes that survive the
deletion, never from the deleted row.

### Proposed decision (Option A)

```text
LocalBindingTombstoneV2 (closed map)
  domain                     tstr         "shardx.local.binding-tombstone.v2"
  version                    U16          2
  server_id                  Text(1,512)
  server_instance_id         Uuid16
  restore_epoch              U64
  tenant_id                  Uuid16
  fleet_id                   Uuid16
  remote_profile_id          Uuid16
  local_profile_id           Text(1,255)
  remote_version             U64
  expected_signed_head_hash  Hash32       omitted iff remote_version = 0
  unbind_idempotency_key     ReplayId16
  completed_at_ms            UnixMs

binding_tombstone_sha256 = domain_hash("SHARDX-LOCAL-BINDING-TOMBSTONE-V2\0", exact tombstone bytes)
```

For `UNBIND`, `operations.exact_receipt_bytes` holds the exact tombstone bytes
and `receipt_sha256 = SHA-256(exact tombstone bytes)`. The two digests of the
same bytes are deliberate (critic minor 10): `receipt_sha256` follows the
plan's convention that an `exact_*_sha256` value is a plain SHA-256 of
the exact bytes (L439, L558, L583, L921, L934), so one generic integrity check
covers every receipt kind; `binding_tombstone_sha256` is a protocol value that
must not collide with any other record's digest, hence the label.

Related (recommended answer to revision 1's Q-8): the `RELEASE` receipt is the
exact canonical response payload `shardx.sync.release-lease-response.v2`
carried inside its stored response; the `COMMIT` receipt is the exact
`CommitReceiptBindingV2` (L1105).

### Alternatives

- Reuse `canonical_request_hash`: adds nothing, does not commit to completion.
- Hash the deleted row: non-canonical TEXT renderings, not recomputable after
  deletion.

### Unblocks and tests

- Rows: G2-26, G2-32 (`UNBIND` receipt rule), G2-33, G2-43. Workstream W6.
- Vectors: `remote_version = 0` (head omitted) and `7`.
- Negatives: head present at 0 or absent at 7, `local_profile_id` 256 bytes,
  empty `server_id`; recomputed hash after delete + close/reopen differing
  from the stored response fails closed.

---

## D-8. Registry pins (single table)

The plan delegates these values to G2 (L425-L426, L610, L628, L648, L650,
L1356, L1357) and requires a reviewed record (G2-63, L2339). **Plan** = fixed
by the plan; **Shipped** = in released code; **Proposed** = this ADR. G2-63
signs off this table.

| Registry item | Value | Exact lengths | Status and evidence |
|---|---|---|---|
| `signature_suite_id` | `1` = Ed25519, RFC 8032 pure, `verify_strict` | pk 32, sig 64 | Shipped value `signing.rs:31`; Proposed: replace `Verifier::verify` (`signing.rs:92`) with `verify_strict` |
| `signature_version` | `1` | | Plan L426; Shipped `signing.rs:33` |
| `signing_key_id` | `domain_hash("SHARDX-SIGNING-KEY-ID-V2\0", pk[32])` | 32 | Shipped `keys.rs:54,87`; ADR1 R4 |
| `hpke_key_id` | `domain_hash("SHARDX-HPKE-KEY-ID-V2\0", pk[32])` | 32 | Shipped `keys.rs:55,93`; ADR1 R4 |
| `root_key_id` | `domain_hash("SHARDX-TENANT-ROOT-KEY-ID-V2\0", trk[32])` | 32 | Plan L798 |
| `fkek_key_id` | `SHA-256(canonical {domain:"shardx.keys.fleet-key-id.v2", version:2, key_bytes:fkek[32]})` | 32 | Shipped `fleet_grants.rs:201-211`; plan silent. Proposed: keep (deployed 2.4.x IDs; key IDs immutable, L1101) |
| `hpke_suite_id`, TRK grants | `1` = base `0x00`, KEM `0x0020`, KDF `0x0001`, AEAD `0x0003` | enc 32, wrapped TRK 48 | Plan L775-L782 |
| `hpke_suite_id`, FKEK grants | same tuple, value `1` | enc exactly 32 (plan bound 1..2048), wrapped FKEK exactly 48 (plan bound 1..4096) | Proposed; L1356 only suggests the suite and leaves the ID to G2 (critic minor 11) |
| FKEK HPKE `info` | closed map: `domain="shardx.keys.fleet-key-grant.device-hpke.hpke-info.v2"`, `version=2`, `replay_id`, `tenant_id`, `server_instance_id`, `restore_epoch`, `fleet_id`, `fkek_key_id`, `generation`, `subject_account_id`, `subject_device_id`, `recipient_hpke_key_id`, `hpke_suite_id=1`, plus `hpke_mode_id=0`, `hpke_kem_id=0x0020`, `hpke_kdf_id=0x0001`, `hpke_aead_id=0x0003`, `grant_capability="fleet.key.receive"` | 1..1024 | Shipped map lacks the last five fields (`fleet_grants.rs:52-75`). Proposed: align with the root info map (L786-L792); every 2.4.x grant must be reissued for the plan payload domain anyway (gap G2-03) |
| FKEK HPKE AAD | `"SHARDX-FLEET-KEY-GRANT-AAD-V2\0"` \|\| `u32be(len(info))` \|\| `info` | | Shipped: canonical map (`fleet_grants.rs:81-91`). Proposed: root pattern (L801-L803) |
| `envelope_suite_id` | `2` = XChaCha20-Poly1305 STREAM-LE31; `1` = legacy `SHRDXBK2` only; `3` reserved for D-3 Option C (XChaCha20-Poly1305 STREAM-BE32, 19-byte prefix) | tag 16 | Proposed (D-3); `1` Shipped `keys.rs:31` |
| `stream_nonce_prefix` | random per snapshot | suite 2: exactly 20; suite 3 (Option C): 19; suite 1: 7 | Proposed (D-3); Shipped `keys.rs:48` |
| `wrap_suite_id` (DEK under FKEK) | `1` = ChaCha20-Poly1305, AAD = exact context bytes (L616) | nonce exactly 12, wrapped DEK 48 | Shipped `keys.rs:33,46,111-127`; Proposed: keep |
| `root_wrap_suite_id` (FKEK under TRK) | `1`, same construction | nonce 12, wrapped 48 | Proposed (D-5) |
| `archive_format_id` | `1` = tar, v2 writer grammar (L1366) | | Proposed; inside legacy suite-1 bodies the value is not interpreted |
| `compression_id` | `1` = gzip (RFC 1952) over the tar stream, before encryption (L1364) | | Proposed |
| `archive_policy_id` | `1` = v2 strict Windows path policy (L1367) | | Proposed |
| `PreambleV2.flags` | none defined; `0x0000` | | Proposed (D-3) |
| `frame_plaintext_size` | writer `1048576`; reader `65536..4194304` | | Plan L649, L1354 |
| KDF, recovery bundle and fallback key file | Argon2id `0x13`, `m` 65536..1048576 KiB, `t` 3..64, `p = 4`, out 32, salt 16; salt labels `SHARDX-RECOVERY-BUNDLE-KDF-V2\0`, `SHARDX-FALLBACK-KEY-FILE-KDF-V2\0` | | Plan L1375; Proposed bounds and labels (D-5) |
| KDF, legacy `SHXBAK01` | Argon2id `m = 65536`, `t = 3`, `p = 1`, salt input `"SHARDX-LOCAL-BACKUP-FKEK-V1\0"` \|\| `salt16` | | Shipped `passphrase.rs:20-34`; recorded deviation for G2-46; stays the local writer until the deferred Q-7 design lands (frame code on the provider STREAM-BE32) |
| `Capability` values | D-2 table | | Proposed |
| TTL and retention | D-6 table | | Proposed |

New labels in this ADR (all proposed): `SHARDX-RESTORE-PREPARATION-V2\0`,
`SHARDX-RESTORE-PROOF-SET-V2\0`, `SHARDX-RESTORE-TRANSITION-SET-V2\0`,
`SHARDX-ENVELOPE-PREAMBLE-V2\0`, `SHARDX-ROOT-CUSTODIAN-GRANT-SET-V2\0`,
`SHARDX-FLEET-DEVICE-GRANT-SET-V2\0`, `SHARDX-RECOVERY-BUNDLE-KDF-V2\0`,
`SHARDX-RECOVERY-BUNDLE-V2\0`, `SHARDX-FALLBACK-KEY-FILE-KDF-V2\0`,
`SHARDX-LOCAL-BINDING-TOMBSTONE-V2\0`, `SHARDX-FLEET-KEY-GRANT-AAD-V2\0`,
`SHARDX-JOIN-ANCHOR-SAS-V2\0`. New map domains are listed where defined. A
test asserts that no two labels or map domains in `shared` are equal.

- Rows: G2-28, G2-29, G2-63, pins in G2-03, 10, 11, 46.
- Tests: RFC 8032 vectors plus the small-order / non-canonical `R`/`S` matrix
  under `verify_strict`; RFC 9180 known-answer vectors for suite 1; info/AAD
  golden bytes for TRK and FKEK grants; label-uniqueness test.

---

## D-9. Fleet key-generation lifecycle (new; answers Q-5 and critic M6)

### Plan facts

- Endpoints exist without payload maps: create generation, generation ack,
  activate (L1127); grant filing for the three `FleetKeyGrantV2` variants and
  device readback (L1128-L1129).
- Activation needs the exact recovery grant plus every required device grant
  readback/ack (L289, L1128, L1382, L2618); revoke + activation is one logical
  operation (L1108); PREPARING generations are never used for snapshots
  (L1081, L1380).
- Root lifecycle maps are the template (L856-L899); all non-COMMIT mutations
  use `IdempotentMutationRequestV2`/`IdempotentStoredResponseV2` with a closed
  `operation_kind` enum (L910-L936) that has no fleet value.

### Proposed decision

**Plan amendment (one for the whole ADR; architect review).** Append six kinds to the closed L913 enum, with these scopes:

| Kind | Scope |
|---|---|
| `FLEET_GENERATION_CREATE` | `fleet.key-generation-create.v2` |
| `FLEET_GRANT_CREATE` | `fleet.key-grant-create.v2` |
| `FLEET_GRANT_ACK` | `fleet.key-grant-ack.v2` |
| `FLEET_GENERATION_ACTIVATE` | `fleet.key-generation-activate.v2` |
| `FLEET_GRANT_REVOKE` | `fleet.key-grant-revoke.v2` |
| `DEVICE_REVOKE` | `device.revoke.v2` (Q-13) |

Each transaction writes the mutation, the audit and the exact stored response together (L1107).

`FLEET_GRANT_ACK` is sent on L1127's generation route, `POST /v2/fleets/{id}/key-generations/{generation}/ack`, one request per grant, naming the grant by `replay_id`. This reinterprets L1127's per-generation ack as per-grant. Common to every map below: `domain`, `version=2`, `tenant_id`,
`server_instance_id`, `restore_epoch`, `fleet_id`, `generation:U64`,
`fkek_key_id:KeyId32`; all fields required unless stated.

| Map (request / response domain) | Additional fields |
|---|---|
| `FleetKeyGenerationCreateV2` / `shardx.keys.fleet-key-generation-create.v2` | `mode` enum `bootstrap`\|`rotation`; `previous_generation:U64` and `previous_fkek_key_id:KeyId32` required iff rotation (`generation = previous + 1`, key IDs differ); `root_generation:U64` (the ACTIVE root that the recovery grant targets); `required_device_grant_count:U32` `1..65535`; `required_device_grant_set_hash:Hash32` (D-4); `recovery_grant_signed_container_hash:Hash32`; `rotation_grant_signed_container_hash:Hash32` required iff rotation |
| `FleetKeyGenerationCreatedV2` / `shardx.keys.fleet-key-generation-created.v2` | the request's fields after the common ones, plus `generation_state="PREPARING"`, `created_at_ms:UnixMs` |
| `FleetKeyGrantCreateV2` / `shardx.keys.fleet-key-grant-create.v2` | `grant_variant` enum `DeviceHpkeGrant`\|`RecoveryGrant`\|`RotationGrant`; `replay_id:ReplayId16`; `exact_signed_grant_container_bytes:Bytes(1,131072)`; `signed_container_hash:Hash32`; `exact_signed_grant_container_bytes_sha256:Hash32`. The embedded record must be exactly that variant with equal common and replay fields |
| `FleetKeyGrantCreatedV2` / `shardx.keys.fleet-key-grant-created.v2` | `grant_variant`, `replay_id`, both container hashes, `subject_device_id` iff `DeviceHpkeGrant`, `recipient_root_generation` iff `RecoveryGrant`, `grant_state` = `"PENDING_ACK"` (every variant), `created_at_ms` |
| `FleetKeyGrantAckV2` / `shardx.keys.fleet-key-grant-ack.v2` | `replay_id`; `grant_variant` enum `DeviceHpkeGrant`\|`RecoveryGrant`\|`RotationGrant`; both container hashes; `locally_unwrapped_fkek_key_id:KeyId32` equal to `fkek_key_id` (for `RotationGrant`: the ID of the new FKEK the actor holds locally). Actor: the subject device (device grant); a custodian of `recipient_root_generation`, or, while that root generation is PREPARING, a custodian of the ACTIVE root `N` holding an acknowledged root `RotationGrant` to it (recovery grant; round-2 M11); a custodian holding a device-scoped `key.rotate` for the fleet (rotation grant; matches L1077 `acked_at` and L1382; round-2 minor 10) |
| `FleetKeyGrantAckedV2` / `shardx.keys.fleet-key-grant-acked.v2` | `replay_id`, `grant_variant`, both container hashes, `ack_outcome="acknowledged"`, `acked_at_ms` |
| `FleetKeyGenerationActivateV2` / `shardx.keys.fleet-key-generation-activate.v2` | `required_device_grant_count`, `required_device_grant_set_hash`, `recovery_grant_signed_container_hash`; previous pair omitted iff `generation = 0`; `rotation_grant_signed_container_hash` iff rotation |
| `FleetGrantRevokeV2` / `shardx.keys.fleet-key-grant-revoke.v2` | `grant_variant` enum `DeviceHpkeGrant`\|`RecoveryGrant`\|`RotationGrant`; `replay_id`; `signed_container_hash:Hash32`; `reason_code` enum `member_removed`\|`device_revoked`\|`superseded`\|`compromised`. Actor: a custodian holding a device-scoped `fleet.manage` for the fleet. Mirrors `ROOT_GRANT_REVOKE` (L947); the grant is marked revoked, never deleted (L409-L410) |
| `FleetGrantRevokedV2` / `shardx.keys.fleet-key-grant-revoked.v2` | the request's fields after the common ones, `revoked_at_ms`, `invalidation_count:U32` as in L947 |
| `FleetKeyGenerationActivatedV2` / `shardx.keys.fleet-key-generation-activated.v2` | the request's fields after the common ones, `target_state="ACTIVE"`, `previous_state="RETIRED"` iff previous pair, `activated_at_ms` |

Rules:

- **Create.** Bootstrap iff `generation = 0` and the fleet has no generation;
  the actor is a custodian holding `fleet.manage` (bootstrap) or `key.rotate`
  (rotation) for the fleet; `root_generation` equals the tenant's ACTIVE
  pointer with a matching ACTIVE row (ADR1 L419-L423). The row stores
  `recovery_grant_hash = recovery_grant_signed_container_hash` and
  `required_grant_set_hash = required_device_grant_set_hash`, which is where
  generation `0` gets both values.
- **Grant create.** `DeviceHpkeGrant` for a PREPARING or ACTIVE generation
  (adding a device later does not change the set hash); `RecoveryGrant` for
  any retained generation (including rewraps at root rotation, D-5);
  `RotationGrant` only for the PREPARING target, with fields equal to the
  create row. Issuer and subject rules per D-2.
- **Activate.** Inside one transaction: the D-4 predicate over the required
  set; the recovery grant acknowledged; for rotation, the `RotationGrant`
  matches, is acknowledged, and `activation_not_before_ms <= server_now`; then PREPARING ->
  ACTIVE and previous ACTIVE -> RETIRED, audit, stored response. Device
  revocation goes through `DEVICE_REVOKE`, which may carry these activation
  requests; they are optional (C-1, decided), and missing ones leave the
  fleet `rotation_required` (Q-13).
- **Revoke.** `FLEET_GRANT_REVOKE` removes one grant, for example when a
  device leaves one fleet (L1126 membership PATCH). It does not rotate; the
  fleet becomes `rotation_required` (unless `reason_code = superseded`) and is
  rotated later, as after a device revoke (C-1; definition in Q-13).

- Rows: fleet parts of G2-03, G2-04, G2-05, G2-14, G2-15, G2-44.
  Workstreams W3, W4.
- Vectors: one golden request/response pair per map, bootstrap and rotation.
- Negatives: bootstrap with an existing generation, rotation with a gap,
  PREPARING root, `RotationGrant` field mismatch, ack by a non-subject, recovery ack for a PREPARING root by a custodian
  without a root `RotationGrant` to it, rotation activation with an
  unacknowledged `RotationGrant`, ack
  with a wrong unwrapped key ID, activation before `activation_not_before_ms`,
  activation with one unacknowledged member, replay with changed bytes.

---

## Trust chain for fleet key grants and snapshot manifests

### The shipped gap (what 2.4.3 waits for)

`team_collect_custody` opens every fleet grant the server returns and caches the FKEK (`src-tauri/src/lib.rs:2356-2385`, identical on `main`).
- It gets only hex fields (`src-tauri/src/fleet_client.rs:687-695`).
- It indexes the cache by the server's JSON `fleet_generation` (`lib.rs:2373`).
- It does no container, signature, issuer, subject or post-open key-ID check.

Push then prefers the cached FKEK, so a hostile server can substitute its own FKEK and read later pushes.

On the server side:
- it stores `exact_signed_container_bytes` (`server/src/fleet_grants.rs:171-183`) but does not return it;
- its issuer trust is `v2_tenant_issuers`, a non-plan table with no production writer (ADR1 L664-L666).

### Plan facts

- **What is trusted.** The coordinator and the live RBAC DB are the trusted control plane. Server-held ciphertext and signed artifacts are not trusted for confidentiality or integrity (L2551).
- **What clients detect.** Clients detect substitution relative to pinned state, with no global guarantee (L375, L2387). Hidden revocations are outside the guarantee (L376).
- **Bootstrap and joining.**
  - First-root bootstrap confirms fingerprints out of band (L257, L370, L815).
  - The first owner pins `server_instance_id` (L256).
  - Later devices need a root/owner-signed approval and key grant (L257, L258).
- **Root grants form a tree.** The tenant has exactly one `FirstRootSelfGrant`, self-signed by its subject (L815-L816, L1073). Every later root grant is signed by a live custodian (L820-L828). The tree is rooted at that one key.

### Definitions (new)

- **Bootstrap anchor `A0`.** The `subject_signing_key_id` of the tenant's `FirstRootSelfGrant`. Every device of the tenant pins `(server_instance_id, tenant_id, A0)`. `A0` never changes for a tenant.
- **Evidence (round-2 M13: full ancestry, paginated).** A new read-only endpoint, `GET /v2/tenants/{tenant_id}/trust-evidence?cursor=<opaque>&signer=<KeyId32>...`, returns pages of the closed map:

  ```text
  TenantTrustEvidencePageV2
    domain              "shardx.trust.tenant-evidence-page.v2"
    version             2
    server_instance_id
    tenant_id
    server_now_ms
    page_index          U32
    next_cursor         Bytes(0,64); empty on the last page
    signing_public_keys [Bytes(32,32)]
    containers          [Bytes(1,131072)]
    revocations         [{payload_domain, replay_id, revoked_at_ms}]
    device_revocations  [{device_id, revoked_at_ms}]
  ```

  - **Page limits.** At most 1024 containers and 4 MiB per page.
  - **The evidence set is the full ancestry, expired records included:**
    - every `TenantRootKeyGrantV2` of the tenant;
    - every `DeviceApprovalV2` and `TenantCapabilityGrantV2` whose subject key is the subject of any root grant;
    - the approval and capability grants of every `signer` the client asks about;
    - every filed `DeviceRevocationV2` of the tenant, as exact signed containers in `containers`, paged like every other container (round-6 minor 1). This is the read path through which a device that did not file a revocation obtains it. Omitting one never causes an acceptance of a record. It can block a revert (rule 6), keep a sticky revocation from starting (rule 1), and keep the `rotation_required` flag and the Q-18 commit block from starting, so that commits continue under the revoked device's key as they would without Q-18 (critic r9 minor 2);
    - for every fleet the requesting device belongs to, so that clients derive `rotation_required` themselves (Q-13): the `DeviceHpkeGrant` containers of the ACTIVE generation (new in revision 10); and that generation's activation evidence (new in revision 11, critic r8 M25). The activation evidence is its `RotationGrant` and the `RecoveryGrant` the `RotationGrant` binds through `recovery_grant_signed_container_hash` (L496). Generation `0` has no `RotationGrant`, so its evidence is every `RecoveryGrant` of generation `0`. A client that lacks this evidence for a fleet treats that fleet as `rotation_required`, so omission can only add a banner.
  - **Client cap and sizing.** The client stops at 65536 containers in total and then fails closed (quarantine). Sizing: renewal at 50% produces about 12 containers per custodian per year, so the cap covers about 5000 custodian-years.
  - **Omission is safe for the fixpoint.** The fixpoint is monotone, so a page the server leaves out can only cause a refusal, never an acceptance. This does not hold for the D-6 (c) clip, which an omitted earliest root grant can stretch on a device without history.
  - **Public keys** are accepted only when `signing_key_id(pk)` equals the ID they are used for.
  - **Caching.** Existing devices cache verified containers in W6 and fetch only what is new. New devices fetch everything.
- **Server-reported revocations only tighten.** The client applies them: a record whose `revoked_at_ms` is reported is rejected from that time on. It never needs them to accept anything, and they never enable a revert skip; only a signed `DeviceRevocationV2` or local distrust does (round-5 M21).

### Verification algorithm (client side; resolves round-1 B2)

Let `now` be the local clock with a 300 s tolerance, and `Ebind` the epoch the binding has accepted.

A container is **usable** if all of the following hold:
- it parses exactly (L440) and all its hashes recompute;
- its signature verifies under the public key of `issuer_signing_key_id`;
- its tenant and instance equal the binding;
- for a manifest only: the epoch condition of rule 6 (a new head carries exactly `Ebind`; Q-1, L524, L375). Authorization and key-grant records carry no client-side epoch condition; the server checked their epoch at issuance (L406-L411);
- it is not reported revoked at the time in question;
- it is not ignored by local distrust (D-6 (d));
- **sticky proven revocation (new; critic r7 M23; D-6 (e)).** It is not signed by the signing key of a device `D` that this client holds as proven revoked (rule 6), unless the client first saw the container before it counted that revocation. The issuer chooses `issued_at_ms`, so `issued_at_ms` plays no part in this test. Containers first seen before the count stay as verified: the user chose first sight only on 2026-10-25 (Q-19 (A)), and rejected both withdrawing them and an `issued_at_ms` cutoff.

1. **Custodian windows.** For each key `K`, `Cust(K)` is the set of `[not_before_ms, not_after_ms)` windows of usable `TenantRootKeyGrantV2` records with subject signing key `K`. It is computed as a least fixpoint:
   - **Base.** The `FirstRootSelfGrant` `g0`, whose issuer and subject are both `A0`, together with its linked approval (`subject_device_approval_replay_id`). That approval must be `A0`'s D1 self-issued `DeviceApprovalV2`.
   - **Step.** An `ExistingRootGrant` or `RotationGrant` `r` adds its window to `Cust(subject)` when both hold:
     - the issuer `X` has a window in `Cust(X)` containing `r.issued_at_ms`;
     - `r`'s linked approval is valid at `r.issued_at_ms` (rule 3) and is tenant-scoped (Q-22).
   - **Clipping.** Every window of `K` is clipped at `first_not_before(K) + MAX_CUSTODIAN_KEY_AGE` (D-6 (c)).
   - **Sticky lapse.** An extension of a ledger key with an observed lapse counts only under D-6 (b).
   - **Sticky proven revocation (critic r7 M23).** Once the client counts a `DeviceRevocationV2` of device `D` (rule 6), `D`'s signing key leaves `Cust` for every check about a container the client first sees afterwards: the issuer condition of the step above, rules 2-4, and the first-sight custodian check of rule 6. A backdated self-renewal therefore cannot restore it. For containers first seen before the count, `D`'s windows still count as before, so earlier-verified approvals and grants that `D` issued keep their standing. A refused renewal of `D` first seen afterwards still raises `custodian.renewed_after_revocation` (D-6 (a)).
     - **Order.** A revocation counted during one evaluation applies to containers first seen in later evaluations. Containers first seen in the same evaluation count as first seen before it, so each evaluation stays a monotone least fixpoint. This is where the no-history limit below comes from.
     - **Residual limit (D-6 limit).** A new device, or one that fetches `D`'s revocation and `D`'s later records in a single evaluation (for example after a long offline period), has no first-seen order between them. It cannot separate a record backdated into `D`'s window from a legitimate one, and it accepts the backdated record if the windows allow. Against this, the device has only local distrust, and the ledger events on other devices with history. Its sharpest case is a mutual revocation: such a device counts both a revocation of D by an honest custodian E and a backdated revocation of E signed by D, so it treats E as revoked too (vector below).
   - **Termination.** The fixpoint is monotone over at most 65536 containers, so it terminates; no separate hop limit is needed. Self-renewal (`X = subject`) works because the previous window covers the new grant's `issued_at_ms`.
   - **Root `RotationGrant` before activation (round-2 minor 2).** The client counts a root `RotationGrant` as custodianship even while its generation is PREPARING, because it cannot verify generation state. The server is stricter (D-2: ACTIVE generation only). The gap matters only with a hostile server, and even then a custodian's signature is still required.
   - **Ledger update.** After each evaluation, the client updates the D-6 (a) ledger and raises its events.
2. **Custodian now.** `K` has a window in `Cust(K)` containing `now`.
3. **Approval valid at time `t`** for key `K`. A usable `DeviceApprovalV2` with `subject_signing_key_id = K` and a window containing `t`. Its issuer is either:
   - `A0` itself, for the D1 approval linked by `g0`; or
   - a key that, at the approval's `issued_at_ms`, was a custodian holding `device.approve` covering the approval scope (rule 4).
4. **Capability `c` over scope `s` at time `t`** for key `K`. A usable, **device-scoped** `TenantCapabilityGrantV2` with:
   - subject signing key `K`;
   - capability `c`;
   - a scope covering `s`;
   - a window containing `t`;
   - an issuer that was a custodian at the grant's `issued_at_ms`.

   Account-scoped grants never satisfy this rule (D-2).
5. **Accept a `DeviceHpkeGrant` `G` for device `D`** iff all of the following hold:
   - `G` is usable and its window contains `now`;
   - `subject_account_id`, `subject_device_id`, `subject_signing_key_id` and `recipient_hpke_key_id` equal `D`'s own;
   - `grant_capability = fleet.key.receive` and `hpke_suite_id = 1`;
   - `hpke_info_bytes` equals the D-8 info map rebuilt from `G`'s fields;
   - the issuer `I` was, at `G.issued_at_ms`, a custodian with a valid approval and `fleet.manage` covering `G.fleet_id`;
   - after HPKE open, `fkek_key_id(FKEK) = G.fkek_key_id`;
   - `D` has not pinned a different `fkek_key_id` for `(fleet_id, generation)`. Otherwise the result is `KEY_SUBSTITUTION_DETECTED` (L1233).

   `D` caches by the verified fields, never by server JSON.
6. **Accept a `SignedSnapshotManifestV2`** (D-3 step 2; round-2 M12).
   - **First acceptance.** When a client first accepts a manifest as a new head, the signer must have, **at `now`**:
     - a valid approval covering the fleet or tenant;
     - a device-scoped `profile.commit` covering the profile or its fleet.

     The pinned head-chain checks also apply (L528-L539). `created_at_ms` is never used for this, because it is informational (L526).
   - **Epoch at first acceptance (critic r7 M22; literal L524 and L375, no amendment).** A manifest accepted as a new head must have `restore_epoch == Ebind`.
     - **The only exception** is the exact leaf of the accepted restore transition for this profile, proven by its inclusion proof (L2243). That head was committed at an earlier epoch, and the transition binds it. The exception also covers a new device that joins before the first post-restore commit.
     - A head the client already pinned keeps its epoch; re-reading it does not re-check the epoch.
     - A lower epoch on any other head is a rollback: the binding quarantines with `HEAD_ROLLBACK_DETECTED` (L1233). That includes a rolled-back child of the restored leaf, which chains exactly and has a valid signer. A higher epoch without a valid transition quarantines with `RESTORE_EPOCH_TRANSITION_REQUIRED` (L375, L1237).
     - Why: after a restore, nothing else separates the honest post-restore head (`V_b+1`, epoch `E+1`) from the rolled-back manifest (`V_b+1`, epoch `E`), whose blob may still exist. The leaf and inclusion checks bind only the leaf, and the superseded rule acts only on the server.
   - **Pinning.** The client pins the accepted head together with the verification result. Re-reading an already pinned head does not re-evaluate the signer, so a head stays readable after its signer's grants expire.
   - **Revoked signer (round-3 M17; round-5 M21).** A revocation comes in two strengths:
     - **Proven revoked:** a usable signed `DeviceRevocationV2` (Q-13), or the client's own local distrust (D-6 (d)). A `DeviceRevocationV2` counts only if all of these hold (round-6 minor 2):
       - its issuer was, at the record's `issued_at_ms`, a custodian (rule 1) holding a device-scoped `device.revoke` (L1067) that covered the subject device's approval scope (rule 4; D-2 issuer rule for Q-13);
       - its issuer **is still a custodian** (rule 2) at the time this client first sees the record (local clock, 300 s tolerance). This replaces revision 7's 30-day first-seen window, which would have locked out devices that were offline for more than 30 days. Under the sticky rule of rule 1, an issuer that this client already holds as proven revoked is not a custodian here, whatever window a backdated renewal claims (critic r7 M23);
       - its subject device and signing key equal the signer of the rejected head;
       - once counted, it stays counted: a filed revocation is permanent (Q-13).

       **What this stops and does not stop.**
       - It stops a revocation forged or backdated with a key whose custodianship has visibly ended on this client: the client has observed the key's lapse (sticky lapse, D-6 (b)), or the client already holds a signed revocation of the key's device (sticky rule, rule 1). The second case holds even when a hostile server omits the unsigned reports and the thief backdates a self-renewal.
       - It does not stop a revocation by a stolen *current* custodian key that no counted revocation covers yet. Every custodian may revoke, which is the same trust the custodian already has for approving devices.
       - It does not help a device without history, which first sees the stolen key's revocation and its backdated records together (rule 1, residual limit).
       - It does not stop a server from withholding the record, which only blocks the revert.
       - If the issuer loses custody before a long-offline device returns, that device cannot count the record. A current custodian then files a fresh revocation for the same device; the table allows several per device, and the re-filing reminder of Q-13 prompts it.
     - **Reported revoked:** only an unsigned revocation entry in the server's evidence.

     In both cases the head is rejected and the profile binding quarantines (L375). There is no acceptance path and no re-sign path, because re-signing would launder content authored by a compromised key. **Only a proven revocation enables the revert path below.** A reported-only revocation never lets a client skip a head, so a false report from a hostile server causes at most a quarantine (denial of service).

     The only way forward is a **revert commit**: a current `profile.commit` holder checks out with the rejected head as `previous_signed_head_hash`, and commits content decrypted from the newest earlier snapshot whose signer was valid and is not proven revoked. The committer's client offers the revert only when the rejected head's signer is proven revoked. A head this client already pinned is treated the same way if its signer is later proven revoked; a reported-only revocation of a pinned head quarantines without enabling a skip.

     **Revert acceptance rule (round-4 M20, round-5 M21; reinterprets L372).** First, the client advances its pin through every valid head in chain order, by ordinary acceptance (round-5 minor 3). Then let `P` be its last pinned head whose signer is not proven revoked (none for a new device). The client accepts a manifest `R` iff all of these hold:
     1. `R` passes rule 6 as a first acceptance, and its signer is not revoked or distrusted.
     2. Following `previous_signed_head_hash` back from `R` reaches `P` (or the profile's first manifest, if there is no `P`) through a run of one or more manifests, `J1..Jn`, that the server supplies. Every one of them:
        - is usable;
        - is signed by a key the client holds as **proven revoked**: a signed `DeviceRevocationV2` chaining to `A0`, or local distrust. A reported-only revocation or a lapsed grant does not count.
        - chains exactly: versions increase by one.
     3. `R.base_version = Jn.target_version`.

     On acceptance the client pins `R` directly, never pins any `J`, records `J1..Jn` as skipped in the local audit, and lifts the quarantine.
     - **Committer side.** The committer's client also checks out on `Jn` only through this flow. If the revocation's `reason_code` is `compromised`, the revert waits until the affected generations are rotated (Q-18), so its content is encrypted under the new generation.
     - **What the client cannot verify.** That `R`'s content really comes from an earlier valid snapshot: re-encryption hides that. Trust in `R`'s content rests on its signer being a valid committer, exactly as for any other commit.
     - **No timing condition.** The rule deliberately does not require `R` to be committed after the revocation, because `created_at_ms` is informational (L526) and no other field orders the two.
     - **Vectors:**
       - accepted: one proven-revoked head; two stacked proven-revoked heads; a new device without a pin;
       - refused: a run containing a lapsed, unrevoked head; a gap below the pin;
       - **refused (round-5 M21): an unsigned server report only.** The revert is refused and the quarantine stays;
       - accepted after advancing (round-5 minor 3): a valid head `L1` the client has not yet pinned sits before the revoked run, so the pin first advances to `L1`, then `R` is accepted;
       - accepted (round-5 minor 4): a head the client pinned before its signer was proven revoked becomes skippable, `P` moves to the last earlier head, and `R` is accepted.
       - accepted (round-6 minor 1): a device that did not file the revocation obtains the `DeviceRevocationV2` container through the trust evidence, counts it as proven, and accepts `R`.
       - refused (round-6 minor 2, revised): a `DeviceRevocationV2` whose issuer lacked `device.revoke` for the device at `issued_at_ms`, or whose issuer was no longer a custodian when this client first saw it;
       - accepted (revision 8): a device offline for 40 days returns, its issuer is still a custodian, and it counts the revocation and accepts `R`;
       - accepted after re-filing (revision 8): the original issuer has lapsed, a current custodian files a second revocation of the same device, and the returning device counts that one.
       - **Sticky proven revocation (critic r7 M23).** Setup: client P counts a `DeviceRevocationV2` of custodian device D. Then the server omits D's `device_revocations` entry and the reported revocation of D's root grant.
         - refused: a `DeviceRevocationV2` against honest device H, signed by D's key with `issued_at_ms` backdated into D's window and first seen by P afterwards. It is not counted, H's head stays accepted, and no revert is offered;
         - refused: the same, with D's window lapsed and a backdated self-renewal of D supplied alongside. The renewal does not count, and it raises `custodian.renewed_after_revocation`;
         - refused: a `DeviceApprovalV2` and a `profile.commit` grant for a fake committer F, signed by D's key, backdated into D's window and first seen afterwards. F's next head is refused;
         - accepted: an approval or root grant that D issued and P first saw before the count stays verified, and the device it names keeps its standing;
         - documented limit, mutual revocation (critic r8 minor 4; asserted, so that any change is deliberate): a new device sees, in one evaluation, honest custodian E's revocation of D and a revocation of E signed by D's key and backdated into D's window. It counts both, so it treats both D and E as revoked: E's later records and approvals are refused there, and heads signed by E quarantine on that device. Devices with history that counted D's revocation earlier refuse the backdated one and keep E;
         - documented limit (asserted, so that any change is deliberate): a new device that fetches D's revocation and D's backdated revocation of H in one evaluation counts the backdated one.
       - **Head epoch (critic r7 M22).** Setup: a restore from `V_live` to `V_b` at transition `E -> E+1`.
         - refused: a client re-pinned to the transition leaf is shown the rolled-back child `M_old` (version `V_b+1`, epoch `E`, `previous_signed_head_hash` = the leaf, signer valid). Result: `HEAD_ROLLBACK_DETECTED`, quarantine, nothing pinned;
         - accepted: the honest post-restore head (`V_b+1`, epoch `E+1`);
         - accepted: the transition leaf itself at its older epoch, proven by inclusion, on a new device that joins before the first post-restore commit;
         - refused: a head at epoch `E+2` with no transition (`RESTORE_EPOCH_TRANSITION_REQUIRED`).
   - **Lapsed signer.** The signer's authority merely expired, unrevoked, before this client first saw the head; for example, a new device joins long after the last commit.
     - The head is not accepted. The UI says "latest version was signed by a device whose authority has lapsed".
     - The only path is a **re-sign**: any current `profile.commit` holder checks out and commits the same content, producing a manifest signed now. A device that already pinned the head can do this, because re-reading a pinned head does not re-evaluate its signer.
     - With no current committer, the tenant uses Q-14.
     - Revision 7's "explicit user acceptance" path is dropped (architect review). It overrode L375's fail-closed rule, and it was a social-engineering path, because a hidden revocation makes a revoked signer look lapsed (L376).
   - **Hostile server.** A server that hides a revocation makes a revoked signer look lapsed; that is the hidden-revocation limit of L376.

**Exact signer of each link.**
- A grant is signed by issuer `I`, a custodian (rules 1-2).
- `I`'s capability grant (rule 4) and approval (rule 3) are each signed by a key that was a custodian at their `issued_at_ms`.
- That custodian's windows come, in turn, from root grants, back to `g0`, which `A0` self-signed.

Because every legitimate custodian descends from `g0`, a device anchored on `A0` accepts grants from custodians appointed by **any** custodian. This is the bridging case round 1 raised.

**Exposure (round-2 B4; replaces revision 2's "bounded exposure").**
- **What the chain proves.** That every link was signed by a key that was a custodian at the time the link claims. It cannot prove that the key was in legitimate hands, and the signer chooses that time.
- **The consequence.** A stolen custodian key, combined with a server that hides revocations, is accepted with no time limit. D-6 states the exact bound and the mitigations (a)-(d) that this algorithm implements.
- **Fleet generation freshness.** "The newest generation" is likewise outside the guarantee. As a cheap tightening, `D` records the highest generation it has verified per fleet and refuses to push under a lower one. Restore no longer lowers generations (D-1), so this rule needs no restore exception.

### Join ceremony (Q-12; replaces revision 1's truncated confirmation)

```text
join_sas = first 16 bytes of domain_hash("SHARDX-JOIN-ANCHOR-SAS-V2\0",
             server_instance_id[16] || tenant_id[16] || A0[32]
             || joiner_signing_key_id[32] || joiner_hpke_key_id[32])
display  = 32 lowercase hex digits in 8 groups of 4
```

**Where each value comes from.**
- **On the approving custodian `B`.** `server_instance_id`, `tenant_id` and `A0` come from `B`'s own pinned binding. The joiner's key IDs come from the pending device row the server reports.
- **On the joiner `D`.** `server_instance_id`, `tenant_id` and `A0` come from the trust evidence, after `D` has verified that `g0` is self-signed by `A0`. Its key IDs come from its own keys.

**Attack cost (round-2 minor 1).**
- A substitution on one screen needs a second preimage of the 128-bit value, about 2^128 work.
- A substitution on both screens (fake joiner keys on `B`, a fake `A0'` on `D`) needs a collision between two inputs the server controls, about 2^64 work. The server can start only after `D` has enrolled, because it needs `D`'s key IDs.
- `B`'s comparison screen expires 10 minutes after the pending device row appears (new), and the server cannot extend that window without a new enrollment, which changes the inputs.

**Procedure.**
- The full 64-hex values of `A0` and both key IDs are one click away on both screens.
- Only on a match does `B` sign `D`'s approval and `D` pin `(server_instance_id, tenant_id, A0)`.
- This also defines how a joining device pins `server_instance_id`; L256 covers only the first owner.

### Anchor loss, revocation, rotation and recovery

- **Custodian lost, revoked, rotated out or re-keyed (including `A0`'s device).** No re-anchoring is needed, and none is offered:
  - the tree's past edges stay valid inside their windows;
  - the lost key stops being renewed, and its windows expire, at the latest at its maximum key age;
  - reported revocations cut it off sooner.

  A server-supplied "new anchor" is never accepted.
- **Suspected stolen custodian key, server trusted.** Revoke the device (Q-13), rotate the root and the affected fleets (D-5, D-9), and distrust the key on every device (D-6 (d)).
- **Suspected stolen custodian key, server distrusted.** Distrust the key on every device. If the server cannot be trusted afterwards, abandon the tenant and recover through Q-14.
- **Every device lost, or every custodian lapsed.** The plan offers no way back into the old tenant:
  - `FirstRootSelfGrant` is one-time (L1073);
  - every other root grant needs a live custodian (L820-L828).

  Recommended path: **recover into a new tenant through Q-14.**
  1. A rebuilt device opens the latest recovery bundle (D-5), which carries the TRK, every retained FKEK and `A0`.
  2. It pins `A0` from the authenticated bundle.
  3. It verifies the offline export of the old tenant against `A0` and decrypts the retained snapshots.
  4. It publishes them into a fresh tenant bootstrapped with ADR 0001 D1.
- **Server reinstall (new `server_instance_id`).** Bindings quarantine (L375). For trust purposes it is a new tenant.

### Interim options for 2.4.3 (stopgaps, not plan-conformant)

| Option | Change | Protects against | Cost |
|---|---|---|---|
| I-1 Pinned issuer | **Server:** the 2.4.3 server adds the stored exact container bytes to the fleet-grant GET (an additive field).<br>**Client verification:** the client verifies the shipped flat container and its signature, and requires `issuer_signing_key_id` to equal a locally pinned key:<br>- its own key, if this device created the fleet;<br>- otherwise, the **full 64-hex** signing key ID the user copies from the issuing device's Team settings screen, where that device computes it from its own private key. The joining client never pre-fills this value from the server.<br>**Field use:** the client takes `fleet_id`, `generation`, `fkek_key_id`, subject, recipient and `hpke_info` from the verified container. It requires subject and recipient to equal this device and the info bytes to equal the signed field, and it checks `fkek_key_id` after open. | A server-substituted FKEK, from the first collection on | Additive response field, client verification, one settings field |
| I-2 Trust on first use | Pin the first issuer key seen | Substitution after first contact only | Useless if the server is hostile at join |
| I-3 Stop adopting server FKEKs | Push uses only a locally created FKEK or the passphrase path | Removes the hole | Loses multi-device push |

**Proposed:** I-1, falling back to I-3 when no key is pinned or the server is older than 2.4.3. Also correct `docs/key-custody.md`, which claims the server cannot read contents.

### Rows and workstreams that deliver the full chain

- **W1:** exact containers, closed parsers, `verify_strict` (G2-01, 02, 03, 29).
- **D-2 issuer matrix and ADR 0001 D1/D2 flows** (G2-01, G2-02).
- **W2:** persistence of approvals and capability grants (G2-01, 02, 44).
- **W3/W4** (G2-03..06, G2-30):
  - the paginated trust-evidence endpoint;
  - the D-9 lifecycle;
  - issuer and subject rules;
  - client reparse and all-column equality;
  - post-open key-ID checks.
- **W6** (G2-32, G2-35):
  - local signed-claim storage (`signed_authorization_records`, probe 3);
  - the pinned anchor;
  - the custodian ledger;
  - pinned manifest verification results.
- **W7:** anchors and keys out of plaintext `team.json` (G2-47, G2-48).

---

## Open questions the sources do not resolve

**Already answered** (see "Decisions approved by the user"):
- Q-1, Q-2, Q-4, Q-5 (D-9), Q-6, Q-12, Q-13, Q-14 and Q-15 have answers approved by the user on 2026-10-25.
- Q-7 is approved as deferred.
- Q-17 to Q-20 were decided by the user on 2026-10-25; their entries below record the decisions.
- Revision 1's Q-3 is settled by L370/L1081 (D-6), Q-8 by D-7, and Q-9 by the D-3 provider order.

**Remaining questions** (Q-17 to Q-20 are decided and kept here as the record of each decision):

- **Q-10 `intent_sha256` naming.** D-3 sets it to the domain-separated `intent_hash`; a reviewer may prefer plain SHA-256 to match the name. Recommended: keep `intent_hash`.
- **Q-11 Total server loss.** The bundle restores every key, but the blobs live on the server. Recommended: the `P-OP` drill (L2564) includes a verified backup of the server DB and blob directory alongside the bundle. That backup is what Q-14's `--db` and the blob export read when the live server is gone.
- **Q-13 fields (proposed; vectors come with the amendment).**

  ```text
  DeviceRevocationV2 (payload inside SignedAuthorizationRecordV2)
    domain                  "shardx.authz.device-revocation.v2"
    version                 2
    common fields           the common authorization fields of L406-L411 (tenant, instance,
                            restore_epoch, replay_id, issued_at_ms, not_before_ms, not_after_ms)
    subject_account_id      Uuid16
    subject_device_id       Uuid16
    subject_signing_key_id  KeyId32
    subject_hpke_key_id     KeyId32
    reason_code             enum lost | compromised | retired | rekeyed

  DeviceRevokeRequestV2 (IdempotentMutationRequestV2 body, operation_kind DEVICE_REVOKE)
    exact_signed_revocation_container_bytes  Bytes(1,131072)
    signed_container_hash                    Hash32
    activations                              array, sorted by (kind, fleet_id, generation), unique,
                                             length 0..65535
      item: exact FleetKeyGenerationActivateV2 or root-generation activate request bytes
  ```

  **Rules.**
  - **Issuer.** A custodian holding a device-scoped `device.revoke` (L1067) that covers the subject device's approval scope.
  - **Activations.** Each one is validated as if it were sent alone. The revocation, the session and grant revocations, every included activation and the audit commit in one transaction (L1107). In practice the route's request body cap, not the codec's 65535, bounds how many activations one `DEVICE_REVOKE` carries: `POST /v2/devices/{device_id}/revoke` shares the 262144-byte `MAX_ROOT_REQUEST_BODY` (`server/src/routes/v2_root.rs`) with the other root and fleet generation routes, and one fleet rotation activation adds about 545 encoded bytes to a request of about 1424 bytes without any, so about 478 fit.
  - **Rotation (C-1, decided by the user on 2026-10-25).** Activations are optional. This amends L290, L1108, L1383 and L2618, and their restatements L34, L2676 and L2764.
  - **`rotation_required` (derived, not stored; made exact in revision 10, critic r7 M24).**
    - A root or fleet generation is **exposed** if either of these holds (issuer clause added in revision 14, critic r9 M26):
      - any key-carrying grant for it, or any `RecoveryGrant` wrapped under it (for a root generation), was **issued by** or **granted to** a device that is now revoked. For a fleet generation, the issuers of its own `RecoveryGrant`s and of its `RotationGrant` count as well (revision 15, critic r9b minor 3). Whoever issues such a grant holds the key: the custodian that signs a root `RotationGrant` to `N+1` creates TRK `N+1` (L824-L826), whether or not it grants `N+1` to itself;
      - it was granted under a key-carrying grant that is now revoked.

      Key-carrying grants are any `TenantRootKeyGrantV2` variant (`FirstRootSelfGrant`, `ExistingRootGrant`, `RotationGrant`) for the root (revoked by `ROOT_GRANT_REVOKE`, L947) and `DeviceHpkeGrant` for a fleet (revoked by `FLEET_GRANT_REVOKE` for any reason except `superseded`). This matches the approved C-1 wording, "every fleet whose ACTIVE key a removed device could hold". Exposure is a fact about the generation and never clears. Revoking a fleet `RecoveryGrant` or a fleet `RotationGrant` exposes nothing by itself: a fleet `RotationGrant` carries no key (L496), and a `RecoveryGrant` is reached only through the root. Their issuers still count, through the fleet sentence of the issuer clause. Those issuers are root custodians whose root generation falls inside the checked range (D-2 issuer matrix), so the root clause covers them too; the explicit fleet sentence only makes that visible.
    - The **root** is `rotation_required` while its ACTIVE generation is exposed.
    - A **fleet** is `rotation_required` while its ACTIVE generation is exposed, or while any `RecoveryGrant` of that generation, current or superseded, is wrapped under an exposed root generation. A custodian holds the TRK, so it can unwrap every such `RecoveryGrant` from server-held ciphertext. Revoking a custodian therefore flags the root and every fleet of the tenant.
    - **Client test for the root clause (critic r8 M25).** A fleet is clear of the root clause only if all of these hold:
      - the client holds and verifies the ACTIVE generation's activation evidence from the trust evidence: its `RotationGrant` (signed by a custodian holding `key.rotate`, with `generation` and `fkek_key_id` equal to the ACTIVE generation), and the `RecoveryGrant` whose `signed_container_hash` equals the `RotationGrant`'s `recovery_grant_signed_container_hash` (L496). For generation `0`, which has no `RotationGrant`, the client uses the `RecoveryGrant` of generation `0` with the lowest `recipient_root_generation` it has ever verified (cached in W6). Nothing signed binds the initial wrap of generation `0`. A device with no cached generation-`0` evidence therefore starts the range at the tenant's first root generation (the generation of `g0`), not at the lowest one the server shows (revision 12, critic r8b minor 2). Cost: a fleet created at generation `0` after an exposed root was rotated away shows a banner it does not need on such a device. One fleet rotation clears it, because generation `1` has a `RotationGrant` that binds its `RecoveryGrant`;
      - that `RecoveryGrant`'s `recipient_root_generation` is not exposed;
      - no root generation numbered above that one, in any state (PREPARING included), is exposed (revision 12, critic r8b minor 1). There is no upper bound at the ACTIVE root.
    - **Why this test covers "current or superseded".** A generation's activation `RecoveryGrant` is wrapped under the root ACTIVE at issuance (D-2 issuer matrix; L289), so the generation never had a wrap under an earlier root. Every later root rotation rewraps it under the new root (D-5), so it has a wrap under every later root. That includes a root that is still PREPARING above the ACTIVE one: a custodian of ACTIVE `N` holding a `RotationGrant` to PREPARING `N+k` wraps under it (D-2 issuer matrix). The round-8 review's rule checks only the bound root. This test also checks every higher root, which a custodian revoked after a root rotation, or during one, would otherwise slip past.
    - **Missing evidence means flagged.** If the activation evidence is missing, does not verify, or does not match the ACTIVE generation, the fleet is `rotation_required`. Omission therefore only adds a banner.
    - **Limit.** Whether a root generation is exposed rests on the root grants in the trust evidence. A server that omits a revoked device's root grant hides that exposure from a device that never cached the grant (the no-history limit). Devices with history keep the cached grant (W6).
    - **Order.** The root is rotated first (D-5 rewraps the retained `RecoveryGrant`s under the new root), then each flagged fleet. A fleet rotated before the root stays flagged, because its new generation's `RecoveryGrant` is wrapped under the exposed root. A root rotation alone leaves every fleet flagged, because each fleet generation still has a `RecoveryGrant` under the exposed root. The UI lists root rotation before fleet rotation.
    - **Advisory, with one exception (critic r7 minor 5; Q-18 decided by the user on 2026-10-25).** `rotation_required` has no deadline, and the banner stays until the condition clears. It blocks no commit, except as follows.
    - **Commit block for `compromised` (Q-18, decided).**
      - **Cause.** A generation's flag has a `compromised` cause if its exposure comes from a `DeviceRevocationV2` with `reason_code = compromised` that this client has counted (rule 6). That covers a fleet generation flagged through its own grants, and one flagged through an exposed root whose cause is `compromised`. Unsigned server reports, `FLEET_GRANT_REVOKE` and `ROOT_GRANT_REVOKE` never create this cause, whatever their reason code.
      - **Refusal.** The client refuses locally, before checkout, to commit under any root or fleet generation whose flag has a `compromised` cause. The refusal covers ordinary commits, revert commits and re-sign commits. The UI explains that a rotation is needed, and no override is offered. On a device with history, a hostile server cannot lift the block: the cause rests on a signed record the client holds, and the sticky rule refuses the revoked key's later records. A server that withholds the signed revocation (or, on a device without history, the revoked device's root grant) can keep the block from starting; then commits continue under the stolen key, as they would without Q-18 (critic r9 minor 2).
      - **In-flight commits (critic r9 minor 3).** The block refuses only new checkouts and new commit requests. An in-flight commit completes only if its upload is already `READY`, or `FINALIZING` during recovery (L1159), when the revocation is counted. Then its ciphertext is already on the server, so refusing it would protect nothing, and its replay stays byte-identical as L2040-L2041 and L2377 require. A COMMIT operation persisted before finalize (L2040) whose upload is still `OPEN` is aborted instead (upload state `ABORTED`, L1159). Nothing more is sent, and the operation ends with the local `ROTATION_REQUIRED_COMPROMISED`. Replays of request bytes already sent stay byte-identical, so L2040-L2041 and L2377 still hold (critic r9b minor 1).
      - **Local state, no new enum value (critic r9 minor 3).** The closed `sync_state` enum (L1790-L1793) is unchanged.
        - A blocked profile that is not checked out stays `AVAILABLE`, with `dirty = 1` if it has local changes.
        - A profile already `CHECKED_OUT` stays so until its lease is released (no commit is sent), then becomes `AVAILABLE` with `dirty = 1`.
        - In both cases `last_error_code` (L1795) holds the local value `ROTATION_REQUIRED_COMPROMISED`. That value is client-local, never sent on the wire, and cleared on release.
      - **Release.** The release rests on the client's own checks, not on the server's ACTIVE pointer (critic r9 minor 1). The refusal lasts until the client verifies, from signed evidence, a generation numbered higher than the blocked one that is not exposed and has no `compromised` cause; the server reports which generation is ACTIVE. For a fleet flagged through the root, that means the root first, then the fleet; a fleet rotated before the root stays blocked. Commits then use the new generation. A revert of the revoked device's heads (rule 6) therefore happens only after the rotation, so its content is never encrypted under the stolen key (moved here in revision 15, critic r9b minor 2).
        - A server can point at a PREPARING but genuinely unexposed generation. That affects availability, never confidentiality.
        - Within the D-6 no-history limit, a thief plus a hostile server can supply the revoked key's backdated grants in the same evaluation and release the block onto a key the thief chose. That is a disclosure, but no worse than without Q-18.
      - **Other reason codes.** `lost`, `retired` and `rekeyed` stay advisory: commits succeed under the flagged generation.
      - **Cost.** Commits on every affected fleet stop until a custodian with `key.rotate` rotates, root first. After a custodian revocation for `compromised`, that is every fleet of the tenant.
        - **Stalled rotation.** A rotation, and with it the freeze, stalls while any required member cannot acknowledge its grant (L289, L2618). The operator path is to remove that member first (`FLEET_GRANT_REVOKE` or `DEVICE_REVOKE`), then rotate with a required set that leaves it out. If the PREPARING generation was created with the member in its required set, that means a new rotation.
        - **Forged revocation within the no-history limit.** A forged `compromised` revocation inside the D-6 limit (for example the mutual-revocation case of rule 6) can stop commits on the affected devices.
        - **Stolen current custodian key (critic r9 minor 4).** Such a key has no time limit against a hostile server (D-6), and it can file `compromised` revocations of honest custodians that every device counts. Each one freezes the root and every fleet. If it revokes every other `key.rotate` holder, the sticky rule refuses their later rotation records, so the freeze never lifts, and the tenant recovers into a new tenant through Q-14. This is within custodian authority, which can already revoke anyone, but Q-18 turns it into a tenant-wide stop.
        - These are availability costs. The disclosure case under the no-history limit is stated under "Release".
      - **Plan lines.** None. This is a client-local refusal to start a commit, and no plan line requires a client to commit. In-flight commits complete as L2040-L2041 and L2377 require, and the closed `sync_state` enum (L1790-L1793) is not extended (see above).
    - **Banner tiers (Q-20, decided by the user on 2026-10-25).** The banner is split by the `reason_code` of the counted revocations behind it. Only wording and urgency change; the flag is unchanged.
      - **Urgent:** `compromised` or `lost`. For `compromised`, the banner also says that commits are blocked (Q-18) and names the rotation to run, root first. When several causes apply, the most urgent one wins.
      - **Routine:** `retired` or `rekeyed`.
      - **Causes without a device revocation:** a `FLEET_GRANT_REVOKE` with `compromised` is urgent but does not block commits, because it is an unsigned server mutation; other grant revocations are routine. Consequence: a member removed for compromise without a `DeviceRevocationV2` leaves commits open under a key that member holds. Whether the UI should default to `DEVICE_REVOKE` when an admin picks `compromised` on a `FLEET_GRANT_REVOKE` is an open note for the Q-17 review (critic r9).
      - The wording and acknowledgement flow are part of the Q-17 design review.
    - **Derived by clients.** Each client derives the flag itself from signed evidence it already fetches: `DeviceRevocationV2` containers and every root grant (trust evidence), the `DeviceHpkeGrant` containers of each ACTIVE fleet generation (trust evidence), and each ACTIVE fleet generation's `RotationGrant` and bound `RecoveryGrant` (trust evidence, revision 11). It never trusts a server flag. A server-reported grant revocation can add the flag but never clear it. A `FLEET_GRANT_REVOKE` or `ROOT_GRANT_REVOKE` is a server mutation, not a signed record, so a hostile server can hide that cause. It cannot hide a cause that rests on a signed `DeviceRevocationV2` the client holds. The server derives the same flag for its own UI and audit.
  - **Re-filing reminder (new; critic r7 minor 6).** Every current custodian holding `device.revoke` over a revoked device's scope tracks that device's revocations. When its client computes that the issuer of **every** counted revocation of that device is no longer a custodian (lapse, revocation or re-key; rule 2), it raises a `revocation.refile_needed` event. The event offers a one-click re-file: a fresh `DeviceRevocationV2` for the same device with the same `reason_code`. The event stays badged in Team settings until a re-file is filed or a user dismisses it. Liveness cost: until some custodian's client is online and acts, a device returning from a long absence cannot count the old revocation, so it cannot revert the revoked device's heads. It only quarantines them.
  - **Lifetime.** `server_now` must be inside the 30-day window at filing (L406-L408, checked at filing only). After that the revocation is permanent and never lapses.
  - **Storage.** `v2_device_revocations(server_instance_id, tenant_id, replay_id, payload_domain, payload_version, subject_account_id, subject_device_id, subject_signing_key_id, subject_hpke_key_id, reason_code, issuer_signing_key_id, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version, signature_bytes, signed_container_hash, exact_signed_container_bytes, exact_signed_container_bytes_sha256, filed_at_ms, PRIMARY KEY(server_instance_id,tenant_id,replay_id))`, with an index on `(server_instance_id, tenant_id, subject_device_id)` and no uniqueness on the device, because a current custodian may re-file. Restore scope: live (D-1).
  - **Counts (amended by rule; critic r7 minor 2).** The record joins the authorization family. **Rule:** every plan statement that counts the authorization/key-grant record family including `TenantRootKeyGrantV2` (written "six" or "sáu") becomes seven, and every one that counts the 5.6.1 payloads without the root grant (written "five" or "năm") becomes six. This covers the common-field, equality and all-column matrices, and it governs any site the list below misses. It does not apply to a count of what one storage table holds.
    - Five becomes six at: L45, L445, L463, L2038.
    - Six becomes seven at: L230, L304, L364, L370, L1081, L2333, L2336, L2354, L2375, L2383, L2421, L2423, L2450, L2466, L2478, L2484, L2510, L2513, L2534, L2563, L2566, L2595, L2632, L2650, L2669, L2757. L2563 is the G2 independent-verifier row.
    - **Exempt (critic r8 minor 5):** L2032, both its "five" and its ordinal "sixth". Verified: L2032 says the client's `signed_authorization_records` table persists "five approval/capability/fleet-grant schemas", and dedicated tables persist the "sixth root-grant schema". `DeviceRevocationV2` is not stored in `signed_authorization_records`: the server keeps it in `v2_device_revocations`, and clients keep it in the W6 trust-evidence cache.
    - Unchanged: L18, a history line.
  - **Tests (harness rows; revision 10).**
    - **Revoked custodian, fleet rotated first (M24 (a)).** Revoke custodian D, which is not a fleet member. Expect the root and every fleet to be flagged. Rotate a fleet first: it stays flagged, because its new `RecoveryGrant` is under the exposed root. Rotate the root alone: every fleet stays flagged. Rotate the root, then the fleet: both clear.
    - **Grant revoked without a device revocation (M24 (b)).** `FLEET_GRANT_REVOKE` of a member's `DeviceHpkeGrant` with `member_removed` flags that fleet only, and rotating it clears the flag. The same revoke with `superseded` flags nothing.
    - **Hidden fleet evidence (critic r8 M25).** Revoke custodian D, then rotate the root only. A hostile server serves no `RotationGrant` or `RecoveryGrant` evidence for the fleets, or serves a `RecoveryGrant` whose hash differs from the `RotationGrant`'s `recovery_grant_signed_container_hash`. Expected: every fleet stays flagged on every client. With the correct evidence served, every fleet also stays flagged, because the bound `RecoveryGrant` is under the exposed root; after the fleets rotate, they clear.
    - **Exposure through a later root (revision 11).** A fleet generation is activated under root `N`, the root rotates to `N+1`, and then a custodian of `N+1` is revoked. Expected: the fleet is flagged, although its bound `RecoveryGrant` is under the unexposed root `N`, because D-5 rewrapped it under `N+1`.
    - **Exposure through a PREPARING root (revision 12, critic r8b minor 1).** A fleet generation is activated under root `N`, which stays clean. A root rotation to `N+k` starts, and the custodian holding the root `RotationGrant` to PREPARING `N+k` rewraps the fleet's `RecoveryGrant` under `N+k`. That custodian is then revoked while `N+k` is still PREPARING, so the rotation stalls. Expected: the fleet is flagged on every client, although `N+k` is above the ACTIVE root. The root itself may show clear.
    - **Generation 0 without a cache (revision 12, critic r8b minor 2).** A new device sees a generation-`0` fleet whose only shown `RecoveryGrant` is a rewrap under an unexposed root `N+1`, while the tenant's first root `N` is exposed. Expected: the fleet is flagged. After one fleet rotation, it clears.
    - **Commit block for `compromised` (Q-18; revision 13).**
      - refused: custodian D is revoked with `reason_code = compromised`. Every client refuses to commit, revert or re-sign under every fleet's ACTIVE generation, before taking a lease, and shows the urgent banner saying commits are blocked;
      - still refused: a fleet is rotated before the root, because its new generation's `RecoveryGrant` is under the exposed root;
      - released: the root is rotated, then the fleet. Commits under the new fleet generation succeed, and the banner clears;
      - released per fleet: member device M is revoked for `compromised`. Only M's fleets are blocked, and rotating one releases it;
      - not blocked: the same revocations with `lost` (urgent banner, commits succeed) or `retired`/`rekeyed` (routine banner, commits succeed);
      - not blocked: a server report alone, or a `FLEET_GRANT_REVOKE` with `compromised` (urgent banner, commits succeed);
      - not lifted: the server reports "not required" or omits the revocation report, but the client holds the signed revocation, so the block stays.
      - **issuer exposure (critic r9 M26; revision 14):** custodian D rotates the root to `N+1` and grants `N+1` only to E and F. D is then revoked with `compromised`. Expected: `N+1` is exposed (D issued its `RotationGrant`s), so the root and every fleet whose `RecoveryGrant` is under `N+1` are flagged and Q-18-blocked. Rotating the root to `N+2` without D's involvement, then the fleets, releases them;
      - in-flight commit completes (revision 14): a commit whose upload is `READY` and whose `CommitRequestV2` is persisted when the revocation is counted completes, and its replay after close and reopen is byte-identical. A new checkout on the same profile is refused;
      - in-flight upload aborted (revision 15, critic r9b minor 1): a COMMIT operation is persisted, but its upload is still `OPEN` with chunks unsent when the revocation is counted. Expected: the upload goes to `ABORTED`, no further chunk, finalize or commit is sent, the operation ends with `ROTATION_REQUIRED_COMPROMISED`, and a replay of any request already sent is byte-identical;
      - local state (revision 14): a blocked dirty profile stays `AVAILABLE` with `dirty = 1` and `last_error_code = ROTATION_REQUIRED_COMPROMISED`. A `CHECKED_OUT` profile releases its lease without committing and then shows the same state. No `sync_state` value outside L1790-L1793 is written.
    - **Advisory and client-derived (minor 5).** While a banner without a `compromised` cause shows, commits under the flagged generation succeed, and no deadline is enforced. The server reports no flag and omits the grant-revocation report, but the client holds the signed `DeviceRevocationV2`: the client still shows the banner. A server report of a grant revocation adds the banner, and a server report of "not required" does not clear one the client derived.
    - **Re-filing reminder (minor 6).** The original issuer's custody lapses. Every current custodian with `device.revoke` over the device raises `revocation.refile_needed`; after one re-files, the event clears on all of them, and a device returning after 40 days counts the new record.

- **Q-16 WAL policy.** K9 in D-1 depends on the G2-50 WAL decision (W7). Steps 1' and 4 of D-1 assume only that `wal_checkpoint(TRUNCATE)` is available.
- **Q-17 Custodian event UX (decided by the user on 2026-10-25).** D-6 (a) needs product wording and an acknowledgement flow that users will not train themselves to dismiss. **Decision:** a design review of the custodian-event UX is held before W6 starts. It covers `custodian.appointed`, `custodian.renewed_after_revocation`, `revocation.refile_needed`, and the urgent and routine rotation banners (Q-20), including the commit-blocked wording (Q-18).
  - **Review held on 2026-10-25:** [reviews/0002-q17-custodian-event-ux-review.md](reviews/0002-q17-custodian-event-ux-review.md) (independent review REVISE, all 15 findings addressed in revision 2). It decides the open note below: choosing `compromised` makes `DEVICE_REVOKE` the primary action, and removing only the grant stays available. It raises one W6 item for this ADR: revoking a custodian key that has no enrolled device.
  - **Open note for the review (critic r9; decided by the review above):** should choosing `compromised` on a `FLEET_GRANT_REVOKE` default the admin to `DEVICE_REVOKE`? Only a signed `DeviceRevocationV2` starts the Q-18 block, so a grant revocation alone leaves commits open under a key the member holds.
- **Q-18 Commit block for a compromised device (decided by the user on 2026-10-25; raised by critic r7).** **Decision: block.** A client refuses locally to commit under any root or fleet generation that is `rotation_required` because of a counted revocation with `reason_code = compromised`, until a newer generation is ACTIVE. Other reason codes stay advisory. The rule, its cost (commits stop until a custodian rotates) and its tests are in Q-13 above.
- **Q-19 Effective time of a revocation for records accepted before it (decided by the user on 2026-10-25; raised by critic r7).** **Decision: (A) first sight only, as written.** A record signed by device D that a client verified before it counted D's revocation stays verified, for example an approval, a grant or a custodian appointment that D issued. That is simple and the same on every device with the same history, but forgeries the thief made before the revocation reached the client stay.
  - Rejected (B), withdraw every record by D on counting: it would orphan legitimate devices whose only path ran through D.
  - Rejected (C), an `issued_at_ms` cutoff: it gains almost nothing against a backdating thief, and revoker clock skew or late filing gives devices divergent views.
- **Q-20 Banner tiering by `reason_code` (decided by the user on 2026-10-25; raised by critic r8).** **Decision: split the banner by reason code.** It is urgent for `compromised`/`lost` and routine for `retired`/`rekeyed`. Only the wording and urgency change; the flag is unchanged. For `compromised`, the urgent banner also says that commits are blocked (Q-18). The rule is in Q-13 above.

---

## Disposition of the critic reviews

### Round 1 (revision 1)

| Finding | Disposition |
|---|---|
| B1 crash mapping, manifest writes | Fixed: state byte, write procedure, classification K1-K12, crash-point table (D-1) |
| B2 trust chain | Fixed:<br>- anchor `A0`;<br>- fixpoint algorithm with exact signers and time rules;<br>- bridging;<br>- 128-bit SAS with stated value sources;<br>- anchor loss, rotation and recovery;<br>- I-1 key source (trust-chain section) |
| B3 recovery bundle and rotation | Fixed: the bundle carries the TRK, all retained FKEKs and `A0`; root activation requires rewrapped `RecoveryGrant`s (D-5) |
| M1 issuer widening, subject checks | Fixed: custodian-only issuers stated as the reading of L257/L258; subject eligibility (D-2) |
| M2 manifest signer | Fixed: D-2 matrix, D-3 step 2, trust-chain rule 6 (time basis corrected in round 2) |
| M3 legacy reader by magic | Fixed: reader chosen by binding state; legacy only via explicit import (D-3) |
| M4 TTL | Fixed: tiered TTLs and renewal flow (D-6); exposure statement corrected in round 2 |
| M5 Q-1 implicit | Fixed: Q-1 answered; restore scope corrected in round 2 |
| M6 fleet lifecycle | Fixed: new D-9 (plan amendment flagged) |
| M7 crate fallback | Fixed: provider order; acceptance conditional on L2443 (D-3) |
| M8 restore entry point | Fixed: `restore` CLI, transition request/sign flow, audit actions, production refusal until v0.2.2 (D-1) |
| Minors 1-11, 13, 14 | Fixed in place in revision 2 |
| Minor 12 split D-3 | Kept as a precondition of acceptance; D-3 is self-contained |

### Round 2 (revision 2)

| Finding | Disposition |
|---|---|
| B4 false exposure bound | Fixed: D-6 and the trust chain now state that a stolen custodian key has no time limit against a hostile server. Added mitigations: (a) custodian ledger and events, (b) sticky lapse, (c) `MAX_CUSTODIAN_KEY_AGE` 1095 days, enforced by the server and clipped by clients, (d) local distrust. Rejected the renewal cap, with the reason given. The approval page was rewritten to match |
| B5 restore resurrects retired generations | Fixed by changing the restore scope rather than extending carry-forward:<br>- the candidate takes the whole control plane from the live DB, so generations, revocations and post-backup records are never rolled back;<br>- per-table rules, fencing-token maximum, FK and blob refusals;<br>- harness rows for restore across fleet and root rotations (D-1).<br>The carry-forward artifact is removed |
| M9 stale WAL sidecar | Fixed: TRUNCATE checkpoint and sidecar checks in prepare (step 1'); step 4 split into idempotent sub-steps, sidecars moved first, assertion before install; candidate built without sidecars; new crash points |
| M10 live DB required | Fixed: stated as a precondition; fails closed; DB-loss path via Q-14; on the approval page |
| M11 recovery-ack actor | Fixed: D-9 ack actor includes a custodian of ACTIVE `N` holding an acknowledged root `RotationGrant` to `N+1`; D-5 states it |
| M12 manifest signer time | Fixed: checked at `now` when a head is first accepted, then pinned; lapsed signer → re-sign or explicit acceptance (rule 6) |
| M13 expired ancestry | Fixed: paginated evidence returns the full ancestry, expired included; client cap 65536 with sizing |
| M14 page not decidable | Fixed: "Plan lines" column marks Q-1 and D-1 as reinterpretations and Q-5/D-9 and Q-13 as amendments; Q-13 and Q-14 rows added; D-6 corrected |
| M15 `SHXBAK02` underspecified | Fixed by deferral: own ADR; interim `SHXBAK01` writer on the provider STREAM-BE32 (byte-identical) |
| Minor 1 SAS bound | Fixed: 2^64 collision when both screens are substituted; 10-minute expiry |
| Minor 2 PREPARING root custodianship | Stated: client superset, server stricter; matters only with a hostile server |
| Minor 3 account-scoped grants | Fixed: device-scoped only, for issuers and manifest signers, server and client (D-2, rule 4) |
| Minor 4 `RecoveryGrant` renewal | Fixed: D-6 renewal step 2 |
| Minor 5 fallback key file header | Fixed: own header map (D-5) |
| Minor 6 `recovery_ready` scope | Fixed: stated as advisory and local (D-5) |
| Minor 7 K5 ambiguity | Fixed: K5a/K5b split by the artifact directory of `X.restore_txn_id`; step 7 deletes the manifest before the directory |
| Minor 8 zero custodians | Fixed: listed by prepare; refused if the tenant needs coverage |
| Minor 9 L1846-L1850 citation | Fixed: cites the plan's `exact_*_sha256` definitions (D-7) |
| Minor 10 `RotationGrant` ack | Fixed: the ack is allowed and required before activation (D-9), matching L1077 and L1382 |
| Minor 11 renewal order | Fixed: capability grants, then approval, then root grant (D-6) |

### Round 3 (revision 3)

| Finding | Disposition |
|---|---|
| B6 restore drops `v2_uploads` | Fixed: `COMMITTED` upload rows referenced by kept snapshots come from the backup with their FK to live generations checked; other uploads and all chunks are dropped. Every FK the merge touches is listed. Harness: `foreign_key_check` empty, no row dropped for a normal backup (D-1) |
| M16 stale receipts, version reuse | Fixed: live keys only; additive `superseded_by_restore_epoch`; a superseded replay returns `BASE_VERSION_MISMATCH` or `RESOURCE_NOT_FOUND`, never stored bytes (reinterprets L299, L966-L970). Additive `version_floor` stops version reuse (amends L1085, L1099), with a client chain rule. Harness rows added |
| M17 restored heads, revoked signers | Fixed: prepare refuses, or with `--drop-unreferenced` drops, snapshots whose signer is revoked or unknown in live, together with their later versions. Rule 6 splits revoked (reject, quarantine, revert commit only) from lapsed (re-sign or explicit acceptance; marked as reinterpreting L375 on the page) |
| M18 recoverable cases | Fixed: recoverable and unrecoverable cases are on the D-1 row and paragraph and in D-1. No blob staging and no forward migration are proposed; both are named as possible later features |
| Minor 1 `v2_profiles` merge | Fixed: `current_key_generation` = next-write generation equal to live ACTIVE; `fleet_id` equality; head FK; the backup-only profile override stated |
| Minor 2 renewal-fork detector | Dropped; replaced by `custodian.renewed_after_revocation`, timed by local first-seen time |
| Minor 3 history-only protection | Stated in D-6 (a), D-6 (c) and the evidence "omission" note |
| Minor 4 revocation TTL | Fixed: 30-day filing window; a filed revocation is permanent (D-6, Q-13) |
| Minor 5 unassigned tables | Fixed: ADR 0001 tables and v1 tables assigned (live) |
| Minor 6 Q-15 not on page | Fixed: Q-15 row and paragraph |
| Minor 7 trust-chain plan lines | Fixed: marks the L375 reinterpretation |

### Round 4 (revision 4)

| Finding | Disposition |
|---|---|
| B7 read-only outside K3 breaks v1 | Fixed: read-only only in K5a, K5b, K6 and K7-K12. K1, K2 and K4 keep plan semantics (v2 writes off, v1 unaffected; K2 security incident). Harness row for v1 with an unset identity directory |
| M19 commit check not amended | Fixed: commit predicate `base_version == max(current_version, version_floor)` stated; L1412, L2608 (amend) and L372 (reinterpret) added to the D-1 Plan-lines cell |
| M20 revert acceptance | Fixed: an exact revert acceptance rule (skip a chained run of revoked-signer heads, pin `R` directly, audit the skip), its limits, and vectors |
| Minor 1 jump trigger and bound | Fixed: the trigger is by epoch and covers a device pinned at the restored head; `i64::MAX - 2^32` bound on the server and the client |
| Minor 2 L1105 | Fixed: added to the reinterpretations |
| Minor 3 superseded nits | Fixed: additive `superseded_by_restore_epoch` field in the error body; the column is never cleared and does not change `retained_until` |
| Minor 4 long D-1 row | Fixed: the cell is split into recover, cannot-recover and integrity lines |

### Round 5 (revision 5): ACCEPT-WITH-RESERVATIONS

| Finding | Disposition |
|---|---|
| M21 unsigned reports enable revert | Fixed: "proven revoked" = signed `DeviceRevocationV2` chaining to `A0`, or local distrust. Only proven revocations enable the revert skip and revert content choice; reported-only revocations quarantine. Vector "unsigned report only -> revert refused" added |
| Minor 1 error allowlist | Fixed: L1220 cited; `superseded_by_restore_epoch: U64` added to the allowlisted fields of `BASE_VERSION_MISMATCH` |
| Minor 2 K2/K4 "v1 unaffected" | Fixed: marked as a reinterpretation of L2263 and L2264 in the D-1 Plan-lines cell and the class text |
| Minor 3 advance pin first | Fixed: the rule first advances the pin through valid heads; vector added |
| Minor 4 pinned-then-revoked head | Fixed: vector added |

### Round 6 (revision 6): ACCEPT-WITH-RESERVATIONS; the Hold on the trust-chain row is lifted

| Finding | Disposition |
|---|---|
| Minor 1 no delivery path for the signed revocation | Fixed: every filed `DeviceRevocationV2` of the tenant is part of the trust-evidence set as signed containers, paged like the others; vector for a device that did not file the revocation |
| Minor 2 issuer and window not explicit | Fixed: rule 6 names the issuer condition (custodian with device-scoped `device.approve` over the device's scope at `issued_at_ms`), subject equality, and a filing window that must contain the client's first-seen time; refusal vector added |
| Minor 8 server in K7 | Fixed: the server opens the DB read-only while a restore is in progress (narrowed in round 4, B7) |

### Architect review of the plan-amendment rows (revision 7)

| Finding | Disposition |
|---|---|
| Plan-lines column incomplete | Fixed: added L376, L1399/L1402, L1220 (extends), L1067 (used, no change), L290/L1108/L1383/L2618 (under C-1 (b)), L445/L463/L2038 and the seventeen "six" sites, L406-L408, L1127, L1348 (D-3 Option C), L1056-L1093 (new table); dropped L2608 (unchanged) |
| Labels too soft | Fixed: D-1 merge **amends** L2243, L2251, L376; the L372 version jump is an amendment (C-2 (a) only); trust-chain path (ii) is dropped, so L375 is untouched |
| D-3 fallback 3 rejected | Fixed: replaced with XChaCha20-Poly1305 + `StreamBE32` under L1353's equivalent-primitive clause; the row approves only the order of plan-conformant sources |
| Tenant without a covered profile | Fixed: clients compare epochs only for manifests, so authorization records issued at `E+1` are accepted; lost profiles quarantine and are republished (Q-1) |
| L913, L1127, `FLEET_GRANT_REVOKE`, `device.revoke`, revoke vs rotate | Fixed: one L913 amendment with six kinds; per-grant ack on the generation route (reinterprets L1127); `FleetGrantRevokeV2` maps; Q-13 issuer `device.revoke`, D-2 updated; revoke-vs-rotate is user choice C-1; storage table; L406-L408 exception listed |
| 30-day first-seen cliff | Fixed: the issuer must still be a custodian at first sight; several revocations per device allow re-filing; what it stops and does not stop is stated |
| `version_floor` not forced | Presented as user choice C-2; recommended (b), blob paths by `snapshot_id`, which needs no plan amendment |
| K2 risk ordering | Presented as user choice C-3; recommended (a), K2 freezes v1 too |

### Round 7 (revision 9): REVISE, 3 MAJOR, 6 MINOR (Critic half of the L2566 pass)

| Finding | Disposition |
|---|---|
| M22 rolled-back head replayed after a restore | Fixed: a new head must have `restore_epoch == Ebind` at first acceptance. The only exception is the accepted transition's own leaf, proven by inclusion; pinned heads keep their epoch. This is the literal L524 and L375, so no label is needed. Vectors in rule 6 and a D-1 harness row cover the rolled-back child (`HEAD_ROLLBACK_DETECTED`). The approval page's trust-chain, Q-1 and D-1 rows state it |
| M23 proven revocations outside the fixpoint | Fixed: a sticky proven revocation in "usable" and in `Cust`. Records signed by a proven-revoked key and first seen after the count are refused whatever their `issued_at_ms`, and the key fails the first-sight custodian check. Records first seen before stay verified (their effective time is Q-19). On every device, a record issued at or after the revocation's `issued_at_ms` is refused. The no-history residual is stated (D-6 limit), vectors are added, and D-6 gains mitigation (e) |
| M24 `rotation_required` incomplete | Fixed: the exposed-generation definition covers revoked devices and revoked key-carrying grants (`FLEET_GRANT_REVOKE`, `ROOT_GRANT_REVOKE`), plus fleets whose `RecoveryGrant`, current or superseded, is under an exposed root. The root rotates before the fleets. Harness rows cover both holes. The review's rule is tightened for superseded `RecoveryGrant`s: after a root-only rotation, the old wrap under the exposed root still exposes the fleet key |
| Minor 1 C-1 plan lines | Fixed: L34, L2676 and L2764 added, each verified in the plan, on the C-1 row, the Q-13 row and the Q-13 rules |
| Minor 2 count sites | Fixed by rule: "six" counts of the family become seven and "five" counts of the 5.6.1 payloads become six. The review's sites L364, L2333, L2336, L2421, L2478, L2484, L2510, L2563 and L2632 are verified and listed. Verification also found "năm" (five) at L45 and L2032, now listed. L2032's ordinal and the L18 history line are unchanged |
| Minor 3 "logins fail" | Fixed: v1 logins and reads keep working while read-only (`server/src/auth.rs:203-233`), and v1 writes fail. Failed-login audit writes, which v1 swallows (`server/src/audit.rs:22-31`), must be logged and counted (new). The harness rows are corrected |
| Minor 4 blob-deletion row vs retention GC | Fixed: no code path deletes or overwrites a referenced blob path. Retention GC (L2548, L1106) deletes only unreferenced paths and never rewrites one. The C-2 design text and the D-1 row match |
| Minor 5 advisory status | Fixed: stated on the C-1 row and in Q-13. Clients derive the flag from signed evidence, and the trust evidence adds the ACTIVE `DeviceHpkeGrant` containers. Harness row added. A hidden `FLEET_GRANT_REVOKE` stays a stated limit, because it is not a signed record |
| Minor 6 re-filing trigger | Fixed: a `revocation.refile_needed` event on every current custodian once every counted revocation's issuer has lost custody. The liveness cost is stated, and a harness row is added |
| Open questions (unscored) | Added as Q-18 (commit block for `compromised`) and Q-19 (effective time for records accepted before the revocation), not decided. D-3 `aead-stream` (L2443) and Q-17 stay open |

### Round 8 (revision 10): REVISE (narrow), 1 MAJOR, 5 MINOR

| Finding | Disposition |
|---|---|
| M25 the fleet half of `rotation_required` can be hidden | Fixed: the trust evidence carries each ACTIVE fleet generation's `RotationGrant` and the `RecoveryGrant` it binds (L496). A fleet is clear of the root clause only if that evidence verifies, the bound `RecoveryGrant`'s `recipient_root_generation` is not exposed, and no later root up to the ACTIVE root is exposed. Missing evidence counts as flagged. The review's rule checks only the bound root; this one adds the later roots, because D-5 rewraps under every new root and a custodian revoked after a root rotation would otherwise escape. Generation `0` has no `RotationGrant`, which is a stated no-history limit. Vectors cover dropped or mismatched evidence and exposure through a later root |
| Minor 1 C-3 "literal fail closed" | Fixed: K2 for v1 is relabelled **reinterprets** L2264 ("writes closed"; logins and reads continue) on the C-3 row, the D-1 row and the K2 class text. The C-3 row asks the user to re-confirm the relabel; the decision itself is unchanged |
| Minor 2 author addition (b) | Fixed: the `issued_at_ms` cutoff is dropped from "usable", from the ordering and limit text, and from the vectors. It is now option (C) of Q-19, with its near-zero gain, the clock-skew and late-filing problem, and the divergent views it causes |
| Minor 3 audit reporting not marked new | Fixed: the D-1 row marks it as new server work that touches the shipped v1 audit path (`server/src/audit.rs:22-31`). New work item WI-AUDIT-RO under W8 |
| Minor 4 mutual-revocation determinism | Fixed: a documented-limit vector, asserted. A new device counts both E's revocation of D and D's backdated revocation of E. The residual-limit text names this case. The `RecoveryGrant` evidence half is handled under M25 |
| Minor 5 L2032 count | Fixed: L2032 is verified (client `signed_authorization_records`, "five ... schemas" plus the "sixth root-grant schema") and exempted, both its five and its ordinal. The count rule excludes counts of what one storage table holds |
| Open question: banner tiering | Added as Q-20, not decided |

### Round 8b (revision 11, narrow diff check): ACCEPT-WITH-RESERVATIONS, 2 MINOR

| Finding | Disposition |
|---|---|
| Minor 1 upper bound misses a PREPARING root | Fixed: the fleet test has no upper bound. No root generation numbered above the bound root, in any state (PREPARING included), may be exposed. Vector added: the holder of a `RotationGrant` to PREPARING `N+k` is revoked midway |
| Minor 2 (optional) generation-0 range on a device without a cache | Adopted: such a device starts the generation-0 range at the tenant's first root generation. The cost is stated (an extra banner, cleared by one fleet rotation), and the generation-0 no-history limit is removed. Vector added |
| Reservations carried forward | Unchanged: the user re-confirms the C-3 relabel; Q-17 to Q-20 are user decisions; D-3 `aead-stream` (L2443) is unverified offline; every proposed row needs the user's approval. No approval-page row changes in revision 12 |

### Round 9 (revision 13, narrow diff check of Q-18 and the recorded decisions): REVISE (narrow), 1 MAJOR, 5 MINOR

| Finding | Disposition |
|---|---|
| M26 `exposed` counts grantees only | Fixed: a generation is exposed if any key-carrying grant for it, or any `RecoveryGrant` under it, was issued by or granted to a now-revoked device (L824-L826). The C-1 row's detail lines now say "granted to, or had a grant issued by", which matches its approved "a removed device could hold". Vector added: D rotates the root to `N+1`, grants only E and F, and is revoked as `compromised`, so the root and fleets are flagged and blocked |
| Minor 1 release rests on the client | Fixed: the release needs the client's own verification of a higher, unexposed generation, not the server's ACTIVE pointer. "Cannot lift" is limited to devices with history, and the no-history disclosure case (no worse than without Q-18) is stated |
| Minor 2 omission line | Fixed: withholding the signed revocation, or on a no-history device the root grant, keeps the flag and the block from starting (trust evidence and the Q-18 rule) |
| Minor 3 in-flight commits and `sync_state` | Fixed: persisted commits (upload `READY`, persisted COMMIT operation) complete with byte-identical replay (L2040-L2041, L2377). A blocked profile stays `AVAILABLE` (or `CHECKED_OUT` until release) with `dirty = 1` and the local `last_error_code` `ROTATION_REQUIRED_COMPROMISED` (L1794-L1795). No new enum value (L1790-L1793). Vectors added |
| Minor 4 cost understated | Fixed: a stolen current custodian key can freeze the tenant on every device, and permanently if it revokes every other `key.rotate` holder (falls back to Q-14). A rotation stalls while a required member cannot ack (L289, L2618); the operator removes that member first. On the Q-18 row and in the rule |
| Minor 5 citations | Fixed: r9 is cited in the approval-page note, the status line, the reviewers list and the sources. Its follow-up diff check is recorded as pending |
| Open question: `DEVICE_REVOKE` default | Added as an open note for the Q-17 review, not decided |

### Round 9b (revision 14, narrow diff check): ACCEPT-WITH-RESERVATIONS, 3 MINOR

| Finding | Disposition |
|---|---|
| Minor 1 in-flight commits with unsent bytes | Fixed: an in-flight commit completes only with its upload `READY`, or `FINALIZING` during recovery. A persisted COMMIT whose upload is still `OPEN` is aborted (`ABORTED`, L1159), sends nothing more, and ends with `ROTATION_REQUIRED_COMPROMISED`. Vector added |
| Minor 2 misplaced release sentence | Fixed: "root first, then the fleet; revert only after the rotation" moved into the release rule |
| Minor 3 issuer clause wording | Fixed: the clause names the issuers of a fleet generation's `RecoveryGrant`s and `RotationGrant`, and the gloss states that the root clause covers them as well |
| Reservations carried forward | The pending citation is replaced by r9b in the approval-page note and the status line. D-3 `aead-stream` (L2443) stays unverified offline; the `DEVICE_REVOKE` default goes to the Q-17 review before W6 |

---

## Revision log

- **2026-10-25, revision 1.** First draft closing D-1..D-8 with options and proposed decisions, a trust-chain section for the 2.4.3 patch, and open questions.
- **2026-10-25, revision 2.** Addresses the round-1 critic review (REVISE: 3 BLOCKING, 8 MAJOR, 14 MINOR).
  - Added the "Decisions for user approval" page, with one recommended answer per user decision.
  - Corrected the commit identity: `439e932` is on `team-custody-production`; shared and client code equal `main`; server code differs in 16 files.
  - D-1: PREPARED/TERMINAL state, write procedure, full crash classification, revocation carry-forward, offline restore CLI and transition flow, production refusal until v0.2.2.
  - D-2: custodian-only issuers as the stated reading of L257/L258, subject eligibility, manifest signer.
  - D-3: provider fallback order, reader selection by binding state, pass 2 on the local spool file.
  - D-4: counts `>= 1`, fleet generation `0` sources.
  - D-5: the bundle carries what L1386 requires plus `A0`; root rotation requires rewrapped recovery grants; header type; readiness probe AAD; fallback key file.
  - D-6: tiered TTLs with a renewal flow, replacing the 3650-day constants.
  - D-7: digest rationale; `RELEASE` receipt.
  - D-8: corrected FKEK suite status.
  - New D-9: fleet lifecycle maps (plan amendment).
  - Trust chain rewritten as an exact algorithm with a 128-bit join SAS.
  - Why: the review showed unmapped crash states, an ambiguous and grindable trust chain, and data loss after root rotation, each of which would fail G2 or lose keys.
- **2026-10-25, revision 3.** Addresses the round-2 critic review (REVISE: 2 BLOCKING, 7 MAJOR, 11 MINOR). Revision 2 is kept as `adr0002-g2-decisions-draft.rev2.md`.
  - **Approval page:** added a "Plan lines" column marking every reinterpretation (Q-1 for L427; D-1 for L2243 and L2251) and amendment (Q-5/D-9 and Q-13 for L913; Q-13 for L1125; D-3 conditionally for L1352/L1353); added Q-13 and Q-14; Q-7 is now deferred.
  - **D-1:** restore now takes the control plane from the live DB (data-plane-only restore); a readable live DB is required; carry-forward is removed; the index commits to `live_db_sha256`; checkpoint and sidecar rules; idempotent install sub-steps; K5a/K5b; new crash points and restore-across-rotation harness rows.
  - **D-6:** honest exposure statement and mitigations (a)-(d); `RecoveryGrant` renewal; renewal order.
  - **Trust chain:** paginated full-ancestry evidence; first-acceptance manifest rule; ledger, clipping, sticky lapse and distrust in the fixpoint; corrected SAS bound with an expiry.
  - **D-2:** device-scoped holding.
  - **D-5:** advisory `recovery_ready`; own fallback header; rotation ack actor.
  - **D-7:** citation fix.
  - **D-9:** recovery-ack exception; `RotationGrant` ack; `DEVICE_REVOKE` for the L1108 coupling.
  - **Why:** the round-2 review showed:
    - a false security bound on the approval page;
    - a restore that resurrected retired key generations;
    - a stale-WAL crash path;
    - an unsatisfiable rotation rule;
    - manifest validity based on a field the plan calls informational;
    - evidence that stopped verifying after about two years.
- **2026-10-25, revision 4.** Addresses the round-3 critic review (REVISE: 1 BLOCKING, 3 MAJOR, 8 MINOR). Revision 3 is kept as `adr0002-g2-decisions-draft.rev3.md`.
  - **D-1:**
    - committed uploads travel with their snapshots;
    - FK list and profile invariants;
    - revoked-signer refusal and drop;
    - `version_floor` and superseded idempotency rows with defined replay errors;
    - a "can and cannot recover" statement;
    - ADR 0001 and v1 tables assigned;
    - the server is read-only outside K3;
    - new harness rows.
  - **Approval page:** D-1 row states the recovery limits and the new reinterpretations and amendments; the trust-chain row marks the L375 reinterpretation; Q-15 added.
  - **D-6:** renewal-fork detector replaced; history-only limits stated; `DeviceRevocationV2` filing window.
  - **Trust chain:** rule 6 splits revoked from lapsed, with a revert-commit path.
  - **Why:** the round-3 review showed:
    - a merge that failed every restore on the snapshot-to-upload FK;
    - receipts for rolled-back versions;
    - restored or re-signed heads from revoked keys;
    - an approval row that hid what restore can recover.
- **2026-10-25, revision 5.** Addresses the round-4 critic review (REVISE: 1 BLOCKING, 2 MAJOR, 4 MINOR). Revision 4 is kept as `adr0002-g2-decisions-draft.rev4.md`.
  - **D-1:**
    - the DB is read-only only while a restore is in progress, and K1, K2, K4 keep plan semantics;
    - exact commit predicate, amending L1412 and L2608;
    - epoch-based jump trigger with an `i64::MAX - 2^32` bound;
    - superseded error-body field and retention note;
    - new harness rows.
  - **Approval page:** the D-1 row is split into recover, cannot-recover and integrity lines, and adds L1105 and L372 (reinterpret) and L1412 and L2608 (amend); the trust-chain row adds L372 for the revert rule.
  - **Trust chain:** exact revert acceptance rule with vectors.
  - **Why:** revision 4:
    - would have made every server without an identity record read-only for v1;
    - changed the commit check without listing it;
    - left revert acceptance up to each implementation.
- **2026-10-25, revision 6.** Addresses the round-5 critic review (ACCEPT-WITH-RESERVATIONS: 1 MAJOR, 4 MINOR). Revision 5 is kept as `adr0002-g2-decisions-draft.rev5.md`.
  - **Trust chain:**
    - rule 6 separates proven revocations (a signed `DeviceRevocationV2` chaining to `A0`, or local distrust) from unsigned server reports;
    - only proven revocations enable the revert skip and the choice of revert content;
    - the pin advances through valid heads first;
    - three new vectors.
  - **D-1:** `superseded_by_restore_epoch: U64` is allowlisted per L1220; the K2/K4 "v1 unaffected" reading is marked as a reinterpretation of L2263/L2264.
  - **Approval page:** the trust-chain row states the signed-revocation condition.
  - **Why:** revision 5 let an unsigned server report make honest clients undo a legitimate head.
- **2026-10-25, revision 7.** Addresses the round-6 critic review (ACCEPT-WITH-RESERVATIONS: 2 MINOR; the Hold on the trust-chain row is lifted). Revision 6 is kept as `adr0002-g2-decisions-draft.rev6.md`.
  - **Trust evidence:** now carries every filed `DeviceRevocationV2` as a signed container.
  - **Rule 6:** names the revocation issuer's capability and time, and the first-seen filing-window check.
  - **Vectors:** two new ones.
  - **Plan lines:** no change; these minors add no new reinterpretation or amendment beyond Q-13's (L913, L1125).
- **2026-10-25, revision 8.** Addresses the independent Architect review of the amend/reinterpret rows (APPROVE-WITH-CHANGES; D-3 fallback 3 rejected). Revision 7 is kept as `adr0002-g2-decisions-draft.rev7.md`.
  - **Approval page:** opens with three user choices:
    - C-1, revoke + rotate atomically vs immediate revoke (recommended);
    - C-2, `version_floor` vs blob paths by `snapshot_id` (recommended);
    - C-3, K2 freezes v1 (recommended) vs plan-literal v2-only.
  - **Plan lines:** completed and relabelled honestly; new "extends (additive)" label.
  - **Q-1:** client epoch check limited to manifests; tenants without a covered profile are defined.
  - **D-9 / Q-13:**
    - one six-kind L913 amendment with `FLEET_GRANT_REVOKE`;
    - per-grant ack on the L1127 route;
    - `device.revoke` issuer and storage table;
    - count changes;
    - L406-L408 exception.
  - **D-1:** L376 amendment stated; C-2 and C-3 designs; L2608 dropped.
  - **D-3:** Option C is now XChaCha20 + `StreamBE32`, with no pre-approved amendment.
  - **Trust chain:** revocation counts if its issuer is still a custodian at first sight, replacing the 30-day cliff; re-filing; the "explicit acceptance" path is dropped.
- **2026-10-25, revision 9.** Records the user's decisions on the three choices, all as recommended:
  - C-1, immediate revoke and rotate later;
  - C-2, blob paths by `snapshot_id`, never deleted or overwritten;
  - C-3, K2 freezes v1.

  Revision 8 is kept as `adr0002-g2-decisions-draft.rev8.md`. Every other row stays proposed.
  - **Removed (rejected alternatives):**
    - the option columns of the choice table;
    - the `version_floor` design: column, checkout rule, commit and lease predicate, bound, and the epoch-triggered client jump rule;
    - its plan lines: L1085, L1099, L1399, L1402, L1412, L372;
    - the `version_floor` clause of the `v2_profiles` merge row;
    - the "version jump" harness row;
    - the jump allowance in the revert rule;
    - C-1 option (a) in Q-13;
    - C-3 option (b) in D-1.
  - **Added:**
    - a decided-choices table;
    - harness rows for never-overwritten blob paths and for v1 frozen in K2;
    - a derived definition of `rotation_required`.
  - **Re-checked:** no live passage depends on `version_floor` any more; the only mentions left are in the history above.
- **2026-10-25, revision 10.** Addresses the round-7 critic review (REVISE: 3 MAJOR, 6 MINOR). Revision 9 is kept as `adr0002-g2-decisions-draft.rev9.md`. C-1, C-2 and C-3 are not reopened, and every other row stays proposed.
  - **Trust chain:** head epoch `== Ebind` at first acceptance, with the transition-leaf exception (M22); sticky proven revocation in "usable" and `Cust`, with the no-history residual stated (M23); vectors for both.
  - **Q-13 / C-1:** exact `rotation_required` (exposed generations, revoked grants, `RecoveryGrant` under an exposed root, root first), advisory and client-derived (M24, minor 5); re-filing reminder (minor 6); count amendment by rule (minor 2); L34, L2676, L2764 added (minor 1); harness rows.
  - **D-1:** v1 logins and reads work while read-only, and failed audit writes are reported (minor 3); retention GC is the only blob deletion, and only for unreferenced paths (minor 4); harness row for the rolled-back head replay (M22).
  - **D-6:** mitigation (e) sticky proven revocation.
  - **Trust evidence:** adds the ACTIVE `DeviceHpkeGrant` containers of the requester's fleets.
  - **Open questions:** Q-18 and Q-19 added, not decided.
  - **Approval page:** the C-1, Q-1, Q-13, D-1, D-6 and trust-chain rows are updated to match.
- **2026-10-25, revision 11.** Addresses the round-8 critic review (REVISE, narrow: 1 MAJOR, 5 MINOR). Revision 10 is kept as `adr0002-g2-decisions-draft.rev10.md`. C-1, C-2 and C-3 are not reopened, and every other row stays proposed.
  - **Trust evidence and Q-13:** each ACTIVE fleet generation's `RotationGrant` and bound `RecoveryGrant`, a client test for the fleet root clause (bound root and every later root not exposed), and missing evidence counts as flagged (M25). Vectors added.
  - **C-3 / D-1:** K2 for v1 is relabelled **reinterprets** L2264, and the user is asked to re-confirm (minor 1). The audit reporting is marked as new server work on the shipped v1 path, with work item WI-AUDIT-RO (minor 3).
  - **Trust chain:** the `issued_at_ms` cutoff is removed and moved into Q-19 as option (C) (minor 2). A mutual-revocation limit vector is added (minor 4).
  - **Counts:** L2032 is exempt (minor 5).
  - **Open questions:** Q-20, banner tiering by `reason_code`, added and not decided.
- **2026-10-25, revision 12.** Addresses the round-8b narrow diff check (ACCEPT-WITH-RESERVATIONS: 2 MINOR). Revision 11 is kept as `adr0002-g2-decisions-draft.rev11.md`.
  - **Q-13 fleet test:** no upper bound; any higher root generation, PREPARING included, counts (minor 1).
  - **Generation 0:** a device without a cache starts at the tenant's first root generation; the cost is stated and the limit removed (minor 2).
  - **Vectors:** two added.
  - **Unchanged:** no approval-page row changes. C-1, C-2 and C-3 are unchanged, and every other row stays proposed.
- **2026-10-25, revision 13.** Records the user's decisions of 2026-10-25. Revision 12 is kept as `adr0002-g2-decisions-draft.rev12.md`.
  - **Approval page:** retitled "Decisions approved by the user". Every row is approved by the user on 2026-10-25. The L2566 note cites the Architect review and Critic rounds 1 to 8b. Q-17 to Q-20 are added to the decided table.
  - **C-3:** the relabel is confirmed. K2 **reinterprets** L2264 as "writes closed"; v1 logins and reads continue. The re-confirm note is removed.
  - **Q-17:** a custodian-event UX design review is held before W6 starts (D-6 (a), Q-13 banners).
  - **Q-18:** a client-local commit block for generations flagged by a counted `compromised` revocation, until rotation, root first. It is the one exception to "advisory", recorded on the C-1, Q-13 and decided rows, in the Q-13 rules and in seven new vectors. The cost is stated (commits stop until a custodian rotates). Plan lines: none.
  - **Q-19:** (A) first sight only. (B) and (C) are kept as one-line rejected alternatives, and trust-chain rule 1 now states the decision.
  - **Q-20:** the banner is split, urgent for `compromised`/`lost` and routine for `retired`/`rekeyed`; the urgent `compromised` banner says commits are blocked.
  - **Status:** "Revision 13, decisions approved by the user on 2026-10-25".
- **2026-10-25, revision 14.** Addresses the round-9 narrow diff check (REVISE, narrow: 1 MAJOR, 5 MINOR). Revision 13 is kept as `adr0002-g2-decisions-draft.rev13.md`. The user's decisions are unchanged.
  - **M26:** `exposed` now counts grant issuers as well as recipients, with a vector.
  - **Q-18 rule:**
    - the release rests on the client's own checks, and "cannot lift" is qualified for the no-history limit (minor 1);
    - withholding the revocation keeps the block from starting (minor 2);
    - in-flight commits complete, and a blocked profile maps onto the closed `sync_state` enum, with vectors (minor 3);
    - the freeze by a stolen custodian key (falling back to Q-14) and stalled rotations are stated (minor 4).
  - **Citations and status:** r9 is cited (minor 5).
  - **Q-17:** the `DEVICE_REVOKE`-default note is added as open.
  - **Status:** "Revision 14, decisions approved by the user on 2026-10-25".
- **2026-10-25, revision 15.** Addresses the round-9b narrow diff check (ACCEPT-WITH-RESERVATIONS: 3 MINOR). Revision 14 is kept as `adr0002-g2-decisions-draft.rev14.md`. The user's decisions are unchanged.
  - **In-flight rule:** only `READY` (or `FINALIZING` during recovery) uploads complete; an `OPEN` upload is aborted. Vector added (minor 1).
  - **Release rule:** the root-first and revert-after-rotation sentence is moved into it (minor 2).
  - **Issuer clause:** fleet `RecoveryGrant` and `RotationGrant` issuers are named (minor 3).
  - **Citations:** r9b is cited in the L2566 note, the status line, the reviewers list and the sources.
  - **Status:** "Revision 15, decisions approved by the user on 2026-10-25".- **2026-10-25, revision 16 (moved into `docs/adr`).** No decision changes.
  - **Split:** D-3 moves to [ADR 0003](0003-envelope-v2-stream.md), as ADR 0001 Q4 requires; a pointer stays in its place.
  - **D-3 dependency review (L2443):** done in ADR 0003. Provider A (`aead-stream 0.6.0`) passes, so the reservation "unverified offline" in the revision 12 and 15 entries is closed.
  - **Reviews:** copied verbatim into `reviews/0002-*`; citations point there.
  - **Status:** "Accepted for development on 2026-10-25".
