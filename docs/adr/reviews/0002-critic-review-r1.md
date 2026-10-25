# Critic review: ADR 0002 draft (G2 contract decisions D-1..D-8)

**VERDICT: REVISE** (3 BLOCKING, 8 MAJOR, 14 MINOR). Mode: escalated to ADVERSARIAL after the first BLOCKING finding.

Draft = `scratchpad/adr0002-g2-decisions-draft.md` (cited `draft Lnnn`). Plan = frozen plan, SHA-256 `a4a136c9...eb813` (verified). ADR1 = `scratchpad/adr0001-main.md`, SHA-256 `72f113a0...7b52` (verified). Gap = `g2-gap-439e932.md`, SHA-256 `6bc896e2...a9dc` (verified).

## Overall assessment

Citation discipline is good: about 150 plan and ADR1 line references were opened and, with one embellishment, say what the draft claims. D-1's reading of the plan is correct, and the D-3 crate facts check out against the local registry. The draft fails as a contract in three places. The D-1 manifest state machine leaves crash points that map to no crash-table row. The fleet-grant trust chain is ambiguous and has bootstrap and anchor-loss holes, so two implementers would build different verifiers. The D-5 recovery design contradicts plan L1386 and loses fleet keys after a root rotation. Several decisions also lean on open questions (Q-1, Q-5) that they implicitly decide.

## Pre-commitment predictions vs actual

| Prediction | Result |
|---|---|
| Line citations drift or misquote | Mostly wrong: 1 embellishment (L2396 "UI"), 1 provenance mislabel (439e932 is not main) |
| Trust chain has a first-contact or rotation hole | Confirmed (B2) |
| Long TTL trades away the client-side revocation backstop | Confirmed (M4) |
| Restore manifest crash states incomplete | Confirmed (B1) |
| D-3 rests on an unverified crate | Confirmed (M7), acknowledged as Q-9 |

## Verification of the specific asks

### 1. Plan facts and citations

Opened: L255-L258, L365-L411, L415-L507, L511-L760, L760-L970, L1060-L1112, L1116-L1132, L1284-L1389, L1409, L1442, L1630, L1663-L1664, L1863, L2036, L2236-L2405, L2443, L2448, L2544-L2566, L2614-L2620, L2640-L2644, L2668-L2676; ADR1 L1-L30, L150-L330, L480-L580, L615-L750, L1012-L1034, L1090-L1150, L1317-L1350. All match except:
- draft L105-L106 "Only the tenant-scoped signed transition workflow **and its UI** are a v0.2.2 deliverable (L2396)". L2396 says no "UI" (the UI line is L2395, for rotation/revocation/recovery). Minor, but see M8: L2396 puts the transition itself, not only its UI, in v0.2.2.
- draft L40/L42-L44: "Production code ... detached `439e932`" and "Shipped facts ... are on `main` today". `439e932` (#104) is on `team-custody-production`, not main; `git merge-base` shows neither is an ancestor of the other. `shared/src` and `src-tauri/src` are byte-identical between the two, so every shared and client citation holds on main. `server/src` differs in 16 files (-1889 lines: identity, cli, generations, fleet_generations). `server/src/fleet_generations.rs:27` is `:24` on main. Minor.
- New design is labelled as such where it is new (D-1 `previous_record_sha256`, join-device reverse confirmation, D-6 `server_now_ms`). Not labelled: D-1 index `entries` cap `0..65535` (draft L150), a new tenant limit. Minor.

### 3. D-1 "plan does not allow keeping restore out of v0.2.0": CORRECT

L2337 (G2 deliverable: preparation fsync and every row of the 12.4 crash table; the 12.4 heading at L2235 contains the table at L2256-L2265), L2341 (uncertainty about "external epoch crash reconciliation" makes G2 FAIL/BLOCKED), L2363 (v0.2.0 gate: the whole prepare/fsync/replace/install/open/reconcile table), L2673 (evidence: record/preparation/candidate/transition SHA-256 and every row), L2566 (only G2 and `P-OP` open). Nothing found that permits deferral. Caveat: L2396 defers the transition workflow itself to v0.2.2, so the v0.2.0 harness can only run with fixture-signed transitions. The draft should say this explicitly; it does not change the conclusion.

### 4. D-3 crate/API claims

| Claim | Status | Evidence |
|---|---|---|
| `aead 0.6` has no `stream` module | VERIFIED | `aead-0.6.1/src/` contains only `lib.rs`, `dev.rs`; `lib.rs:98,102` point to `aead-stream` |
| `aead 0.5.2` `StreamLE31::COUNTER_MAX = 0x0fff_ffff` | VERIFIED | `aead-0.5.2/src/stream.rs:493`; nonce = prefix, then `u32le(position OR last<<31)`; rejects `position > COUNTER_MAX` (`:526-538`) |
| Shipped nonce equals `StreamBE32` byte for byte | VERIFIED | `StreamBE32::aead_nonce` `stream.rs:437-446` (prefix, u32be, flag byte; prefix = 12-5 = 7) vs `shared/src/envelope.rs:252-263` and `keys.rs:48` |
| `chacha20poly1305 0.11.0` on `aead 0.6.1`; `aead 0.5.2` only via `aes-gcm 0.10.3` | VERIFIED | `shared/Cargo.lock`; `aes-gcm` is a direct dep of `shardx-core` |
| `XChaCha20Poly1305` available | VERIFIED | `chacha20poly1305-0.11.0/src/lib.rs:191`, default features |
| 62-byte frame AAD = shipped order | VERIFIED | `envelope.rs:38` label (25 B incl. NUL), `:270-277` label, intent_hash, u32be(counter), u8(final) |
| `aead-stream` exists, works with `aead 0.6.1`/`chacha20poly1305 0.11`, same LE31 layout and limit | UNVERIFIED | not in lockfile, not in `~/.cargo/registry/{src,cache}`; no network |
| draft-irtf-cfrg-xchacha A.3.1 vector | UNVERIFIED | no network |

### 5. D-6 3650-day TTL: see M4.
### 6. Trust chain: see B2 (does not reliably stop FKEK or signer substitution).
### 7. Missing items: see M6, M8 and "What's missing".

## BLOCKING

**B1. D-1 manifest state machine leaves crash points with no crash-table row (violates L2267, so G2 FAILs per L2341).**
- draft L165-L167: `"Non-terminal preparation" (L2259) means the manifest file exists. Retirement (L2254, L2265) deletes the manifest`. Plan row L2265 requires a state "preparation journal **terminal**" with external = mirror = E+1. Under the draft definition a terminal manifest cannot exist, so the crash after step 5 commit/readback and before deletion (external E+1, mirror E+1, manifest present) matches neither L2259 (requires no non-terminal preparation), L2262 (mirror < E+1) nor L2265.
- The draft never says how the manifest itself is written (tmp, fsync, rename, directory fsync). A torn manifest with external still E hits draft L131-L133 `Any failure maps to EPOCH_RECONCILIATION_REQUIRED (L2263)`, but L2263 is the row for "External **ahead** DB". With external = E the plan intends L2259/L2260 (abort allowed). L2267 lists "preparation-manifest fsync" as a crash point that must map to exactly one row.
- Fix: add an explicit state (for example a `state:u8` PREPARED/RETIRING byte under the checksum, or a terminal rename such as `restore-preparation-v2.done`). Specify tmp+fsync+rename+dir-fsync for the manifest and the artifact directory. Add a table that maps every crash point of L2250-L2254 plus each manifest/artifact write to exactly one L2256-L2265 row, with external-E parse failures mapped to L2259/L2260, not L2263.
- Confidence HIGH. Not refutable without new text.

**B2. Fleet-grant trust chain is ambiguous and does not close bootstrap or anchor-loss holes (draft L1012-L1041, L1047).**
- Chain shape. Draft L1026-L1031 says `a chain of at most two links`, then describes up to three signatures: grant signed by issuer I; I's `TenantCapabilityGrantV2` signed by custodian C; C's `ExistingRootGrant`/`RotationGrant` signed by the anchor. The required signer of the `DeviceApprovalV2` "for the issuer device" is unspecified. The chain is also not transitive: a device anchored on custodian B rejects a legitimate admin whose capability grant came from custodian A (A holds a self-signed `FirstRootSelfGrant`, not one signed by B). Two implementers will build different verifiers.
- First contact. Draft L1019-L1021: `the user confirms on D the approving custodian's signing key ID`. Comparison length is not specified, and D-5 draft L731 says fingerprints are `shown truncated in the UI`. A 32-64-bit truncated key ID can be ground by a hostile server: it generates a signing key whose truncated ID collides and then signs its own FKEK grant chain to that anchor. ADR1 D1 (L683-L685) compares **full** key IDs; the reverse ceremony must do the same and must say what D displays and where the value comes from.
- Anchor loss or rotation. There is no procedure for when the anchor custodian is revoked, lost or rotated out (L829-L832), or for a device rebuilt from a recovery bundle after all devices are lost (D1 is one-time per tenant, ADR1 L688-L689). Either devices are locked out permanently, or implementers add a server-supplied re-anchor, which reopens the hole the section exists to close.
- Revocation. A revoked but unexpired custodian or admin key still verifies on the client, because the client cannot see revocation (draft L1040, plan L376). With D-6's 10-year TTL this is a 10-year window for a hostile server plus one stolen key (M4).
- Interim I-1 (draft L1047): `a key ID the user confirms in Team settings` with no stated source. If the UI pre-fills it from the server, I-1 degenerates into I-2 (TOFU). I-1 must also take `fleet_id`/`generation`/`fkek_key_id` from the verified container, because today's cache index comes from server JSON (`src-tauri/src/lib.rs:2369-2370` uses `g.fleet_generation`).
- Fix: specify the exact verification algorithm (recursive chain to any custodian whose root grant chains to the anchor, with a hop limit, the `DeviceApprovalV2` signer rule, and the generation each link must belong to). Require full-length key-ID (or at least 128-bit SAS) comparison. Define re-anchoring (who signs, what the user confirms) and recovered-device anchoring. State the I-1 key-ID source.
- Confidence HIGH on ambiguity and missing procedures; MEDIUM on grindability (depends on the unspecified display length).

**B3. D-5 recovery bundle excludes FKEKs, contradicting L1386, and nothing rewraps recovery grants at root rotation, so fleet keys can be lost (data loss, not downgraded).**
- Plan L1386: `Recovery bundle chứa TRK và retained FKEKs`. Draft L735-L739: the generation pins a bundle `with retained_fkeks empty ... FKEKs are recovered from server-held RecoveryGrants. Bundles exported later with FKEKs included are allowed but are not referenced`.
- After root rotation N to N+1, existing `RecoveryGrant`s still name `recipient_root_generation = N` (D-2 requires the recipient generation to be ACTIVE only at issuance, draft L274). The N+1 bundle holds only TRK N+1 (`RecoveryBundlePlaintextV2.trk` is a single key, draft L720). Nothing in D-2, D-4 or D-5 requires fleet recovery grants to be rewrapped under N+1 before N retires, although plan L831-L832 mentions rewrapped recovery grants for exclusion. If every device is then lost, every pre-rotation fleet generation is unrecoverable unless the user kept bundle N. That contradicts the v0.2.2 gates L2403-L2404 (recovery-bundle drill, restore every retained generation before key GC).
- Q-11 (draft L1105-L1108) raises only the server-loss case, not this one.
- Fix: either include retained FKEKs (or all retained TRKs) in each pinned bundle, or make root activation require rewrapped `RecoveryGrant`s for every retained fleet generation under N+1 (and define "recovery evidence" at L946 accordingly). Then state how L1386 is met.
- Confidence HIGH.

## MAJOR

**M1. D-2 issuer rules widen plan L257/L258 without saying so.** L257: later devices need an `owner/root-signed approval và key grant`. L258: ordinary devices receive a `root/owner-signed HPKE FKEK grant`. Draft L271-L273 lets any live `device.approve` / `fleet.manage` holder sign. Draft L291 claims Option A `stays within the plan's names`. Delegation by a root custodian (D2) may be an acceptable reading, but it must be stated as an interpretation (or a Q-item) because it changes who can hand out FKEKs. Also missing: subject eligibility for `DeviceHpkeGrant` (subject device active, approved for that fleet, HPKE key ID equals the device row, not revoked; L1385). Fix: add an explicit interpretation note plus the subject checks.

**M2. D-3 manifest signer authorization is undefined.** Draft L467-L469, step 2: `signer trusted per the trust chain below`. The trust chain covers only `DeviceHpkeGrant` issuers (draft L1012). There is no rule for which keys may sign `SignedSnapshotManifestV2` (a `profile.commit` holder? chain to the anchor? device approved for the fleet?). Without one, any fleet member holding the FKEK can push an accepted snapshot. Fix: add a manifest-signer rule to the chain and to the D-2 matrix.

**M3. D-3 legacy reader selected by outer magic is a downgrade/rollback path.** Draft L494-L500: shipped containers `are recognized by their outer magic and opened only by the legacy SHRDXBK2 reader`. Nothing forbids a binding with a pinned v2 head from accepting an `SHXFLT01` object served by the server (legacy path: no v2 manifest, head check after output, `backup.rs:531` vs `:590`, mitigated only by buffering). Fix: choose the reader from local binding state or the verified v2 manifest, never from magic. A binding with any v2 head accepts only `SHARDXBK` suite 2. Legacy objects only through an explicit import path.

**M4. D-6: 3650-day TTL removes the only revocation control a client can check, and only moves the outage it claims to avoid.**
- Draft L821: `Revocation (revoked_at) stays the primary control; TTL is a backstop.` For server-side checks, yes. For client-side verification against a hostile server (the trust-chain threat), revocation is invisible (L376, draft L1040), so TTL is the only control. 3650 days makes a stolen custodian/admin key usable against clients for 10 years.
- Draft L796-L798 argues that a short TTL means a scheduled outage. With no renewal flow, 3650 days is the same outage deferred: the D1 approval (one-time, ADR1 L688-L699), the custodian's capability grants and the root grants (which bind `subject_device_approval_replay_id`, L774) expire together, and `ExistingRootGrant` needs a live custodian (L820-L822). That is a custody deadlock at year 10, and a fresh bootstrap is refused because the tenant already has approvals.
- Fix: either specify a renewal/reissue flow (and then choose a shorter TTL for capability and FKEK grants), or record the 10-year client-side revocation window and the year-10 cliff as accepted risks with a required rotation before expiry. Also: draft L815 `additionally requires not_before_ms <= server_now` is already in L408 (minor).

**M5. Q-1 is left open, but the draft implicitly decides it, and the D-1 restore depends on it.** Draft L1071-L1075 leaves epoch validity open. Trust-chain step 2 (draft L1024-L1025) requires `the current instance and epoch`; L427 requires the issuer key lookup in the same tenant/epoch; the D-5 context binds `restore_epoch` (draft L660). So after any D-1 restore, every approval and grant fails client verification until it is reissued. Reissue needs a live custodian whose own grant is also epoch-E, the same deadlock as M4. Fix: decide Q-1 before accepting D-1, D-5 and the chain, or make each conditional on it.

**M6. Fleet generation lifecycle (Q-5) is not decided, so W4 cannot start.** Draft L1086-L1090 defers it. D-4 draft L585-L587 maps fleet rows from the `RotationGrant`, but fleet generation 0 has no `RotationGrant`. The plan's closed enum L913 has no fleet operation, and L1127 lists endpoints without maps. The gap report puts D-1..D-8 first "so W1-W8 can start" (gap L93); W4 still needs fleet create/ack/activate maps. Fix: add D-9 with closed request/response maps and the gen-0 sources of `recovery_grant_hash` and `required_grant_set_hash` (or an explicit plan amendment for the enum).

**M7. D-3 Option A depends on an unverified crate with no fallback.** Draft L389-L394, L504-L506; `aead-stream` is absent from the lockfile and from the local registry. Whether a non-prerelease version supports `aead 0.6.1` and `chacha20poly1305 0.11`, and keeps the 0.5.2 LE31 layout and limit, is unverified (Q-9). If it fails L2443, the ADR has no ordered fallback. Fix: state the fallback order (for example Option B on aead 0.5.2, which is already in the graph, then Option C with a plan amendment) and make the D-3 acceptance conditional on the G2 dependency review.

**M8. D-1 has no restore entry point or transition-signing flow.** ADR1 L317-L321 makes the CLI and server refuse a restore "until that ADR defines the manifest", so the restore ADR must also define the entry point. Steps L2251-L2252 need every tenant's root-signed transition **before** the authority commit, and leaves bind `new_signed_head_hash` from the candidate DB. Custodians submit transitions through the HTTP endpoint L1131, but writes are quiesced and, under ADR1 Option A, the server is stopped. D3 (ADR1 L726-L731) defines no restore audit actions, although L2316 requires a restore-epoch audit. Fix: define the command (lock, flags), how custodians receive candidate heads and return signed transitions offline, and the D3 action names. State that production restore stays refused until v0.2.2 delivers L2396.

## MINOR

1. draft L105-L106 adds "UI" to L2396.
2. draft L181-L183, Option C risk `v0.2.0 would ship a team server`: v0.2.0 is internal-only, `không production release` (L2368).
3. draft L159 defines `transition_set_sha256` as a labelled `domain_hash`, while accepted ADR1 P1 L228 says "SHA-256 of the transition/proof set". Record this as a refinement of P1.
4. draft L150 `entries` length `0..65535` is a new limit; label it.
5. draft L396-L399 Option B objection `two majors of the same AEAD stack in one graph`: the graph already has `aead 0.5.2` and `0.6.1`; the real cost is adding `chacha20poly1305 0.10`.
6. D-3 two-pass reader (draft L470-L483): require pass 2 to read the same local, already-hashed file, otherwise the step-3 claim does not hold. Frame AEAD still limits the damage.
7. draft L815 duplicates L408 (see M4).
8. D-5 readiness test (draft L743) does not give the AAD of the synthetic wrap. The bundle AAD (draft L715) is "the map without ciphertext", which is not a closed type; name it, for example `RecoveryBundleHeaderV2`.
9. D-4 (draft L578-L583): say whether fleet `required_device_grant_count = 0` is valid.
10. D-7 (draft L894-L898): the same tombstone bytes get two different hashes (domain-hashed `binding_tombstone_sha256`, plain `receipt_sha256`). Document why.
11. D-8 row `hpke_suite_id` (draft L941) is marked `Plan L775-L779` for both grants; the plan pins it only for TRK grants. FKEK is Proposed (L1356).
12. D-3 sits inside ADR 0002 although ADR1 Q4 (L488-L490) decided on a separate ADR. Split it before acceptance, as draft L310-L311 promises.
13. Provenance mislabel 439e932 vs main (see section 1).
14. I-1 table entry (draft L1047) does not require checking that subject and recipient equal this device, or that HPKE info matches the signed payload.

## What's missing

- Fallback encrypted key-file format and KDF salt label (L1374-L1375). W7/G2-48 need it; D-8's KDF row covers parameters only.
- SQLite WAL policy decision (gap W7, G2-50).
- Freshness of the "newest generation" (a server can steer pushes to an older FKEK generation that a revoked device knows). Even if it is outside the guarantee, say so.
- How a joining device pins `server_instance_id` (L256 covers only the first owner).
- Restore audit actions (M8) and RUSTSEC-2023-0071 disposition (W10; not a design item, but G2-62).

## Ambiguity risks

- draft L1026 `chain of at most two links` -> A: two certificates above the grant; B: two signatures in total. Wrong choice: false rejects, or acceptance of an unanchored issuer.
- draft L1019 `confirms ... signing key ID` -> A: full 64 hex; B: truncated fingerprint (draft L731). Wrong choice: a grindable anchor.
- draft L737 `a rotation writes a new bundle` -> A: TRK-only; B: includes retained FKEKs. Wrong choice: B3 data loss.
- draft L165 "manifest exists" = non-terminal -> see B1.

## Multi-perspective notes

- Executor: W4 is blocked by Q-5 (M6); W8 cannot write the crash table (B1, M8); W5 cannot pin a crate (M7).
- Stakeholder: D-1's honest "no deferral without amendment" is useful. Option C is mispriced as a production risk (minor 2).
- Skeptic: the trust chain is the security core of the 2.4.3 patch and the least specified part of the draft.

## Self-audit and realist check

- B1: HIGH; not refutable from the text. Realist: caught at G2 at the latest, but G2 is the gate, and the fix is a small amount of text.
- B2: HIGH (ambiguity), MEDIUM (grind). Kept BLOCKING because the section's stated purpose is to stop server substitution.
- B3: HIGH; data-loss class, not downgraded.
- M3 was considered for BLOCKING and kept MAJOR. Mitigated by: v2 pulls verify a v2 manifest and the legacy path buffers before unpack, so the exposure is rollback to a legacy object, not plaintext forgery.
- M4 kept MAJOR. Mitigated by: the cliff is 10 years away; the revocation window requires a hostile server plus a stolen key.

## Open questions (unscored)

- Does the published `aead-stream` LE31 keep `COUNTER_MAX = 0x0fff_ffff`? (Irrelevant at 8192 frames or fewer, but the negative vector "counter at provider maximum" depends on it.)
- Is `team-custody-production` at 439e932 the intended "production" baseline, or main?
- L1125 routes device revoke through a `DeviceApprovalV2` record, which looks like a plan typo; no D-item covers the revoke record.

## What would upgrade the verdict

Fix B1-B3 with exact text, decide Q-1 and Q-5 (or make the dependent decisions conditional), add the manifest-signer rule and reader selection by binding state (M2, M3), and add a D-3 fallback order.