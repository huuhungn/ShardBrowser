# Independent verification: ADR 0002 rule 6 revert and Team join

Verified HEAD: `33e431ae59cce3443ab49f658a417252f21957d1`.

Worktree: `C:\Users\User\dev\wt\shardbrowser-team-ui-verify`.

The initial working tree was clean. Production code is unchanged. Seven new unit tests and one test helper were added at the end of `src-tauri/src/team/sync.rs`; five tests fail on the implementation at this HEAD. They remain as failing regression tests, without `#[ignore]` or `#[should_panic]`.

The contract examined is ADR 0002:1493–1495 and :1529–1596, specifically the requested joining, revoked/lapsed signer, and sticky proven revocation rules. No author review reports, `.omc/`, `.omx/reports/`, or scratch directories were read. No remote service was contacted, and no commit, push, issue, PR, or message was created. Cargo used `CARGO_NET_OFFLINE=true`. Network fixtures bind `127.0.0.1:0` (`sync.rs:5343`); profile and database fixtures use temporary directories and the config-root test lock (`sync.rs:5322`, :5381). The excluded real credential-store test was never run. No command accessed `%APPDATA%\shardx-launcher` or printed secret material.

Test pattern: the repository's existing `team::sync::tests::World`, loopback server, restore fixtures, and SQLite fault-injection pattern (`sync.rs:5321`, :10989, :11516, :12105). No new feature or external prior-art survey was needed.

## Results and commands

All commands used the requested invocation and skip argument:

```powershell
$env:CARGO_NET_OFFLINE='true'
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib codex_verifier_ -- --skip a_real_os_store_key_survives_into_a_fresh_process
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custody_tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::db::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
```

| Run | Scope | Actual result |
|---|---|---|
| S | Original sync suite, executable built before adding verifier tests | `159 passed; 0 failed; 0 ignored; 0 measured; 452 filtered out; finished in 465.04s` |
| V | Seven added verifier tests | `2 passed; 5 failed; 0 ignored; 0 measured; 611 filtered out; finished in 19.22s` |
| C | Custody/ledger integration tests | `33 passed; 0 failed; 0 ignored; 0 measured; 585 filtered out; finished in 14.71s` |
| D | Database schema and persistence tests | `19 passed; 0 failed; 0 ignored; 0 measured; 599 filtered out; finished in 5.39s` |

Thus 211 distinct existing tests passed; the new tests add two passes and five reproducible failures. The command for V exited 1 because of assertions. An earlier attempt to build V while S still held the Windows executable failed with linker `LNK1104` (the executable was in use). After S exited, the identical command rebuilt successfully and ran V. This was not a test failure or error 1455. No `-j 1` fallback was needed. D was repeated because the first tool orchestration discarded its completed output; the recorded result above is the second invocation.

The output excerpts under each property are from these runs. Each named existing test's assertions and relevant helpers were read. Searches found no `#[ignore]` or literal empty/always-true assertions in the four examined implementation/test files. A supplemental body scan covered 79 tests in the sync revert/join section, 11 sticky-revocation tests in `lib.rs`, and four schema-9 tests, with no early `return` in those bodies. Helpers such as `World::enroll` have intentional setup branches for an unbound fixture; they do not skip the test body. Existing tests were not edited. A meaningful weakness in an existing test's expected behavior, rather than an empty assertion, is identified under property 9.

| Property | Result |
|---|---|
| 1. Only proven-revoked runs are skipped | HOLDS |
| 2. Proven-revoked signers are never newly pinned | VIOLATED |
| 3. The committer seals P's content | HOLDS |
| 4. Failed/refused operations preserve local data | VIOLATED |
| 5. Quarantine clears only on valid R acceptance | VIOLATED |
| 6. A completed revert installs P locally | HOLDS |
| 7. Sticky revocation rejects renewal and alerts once | HOLDS |
| 8. Renewal alert requires the revoked key's signature | HOLDS |
| 9. Abandonment/refusal removes decrypted staging | VIOLATED |
| 10. Restore-leaf proof, checkout gate, and join recovery | HOLDS, with the signer defect in property 2 still applying |

## 1. Proven-revoked run membership — HOLDS

Enforcement: `team/ledger.rs:134` records local distrust; :233 reads proven revocation by key; :865 and :1106 count signed revocations only after signature, tenant/instance, historical custody/capability, and first-sight custody checks. `team/sync.rs:4106` evaluates and records evidence before an ordinary walk. The walk verifies signatures, binding identifiers, epochs, and linkage at :4020; classification at :4056 puts only withdrawn keys in `Standing::Withdrawn`. `revert_rule` at :3868 checks version/base/hash continuity and allows only that standing into the skipped run. Reported and untrusted/lapsed heads refuse at :3878–3879. :4088 and `refused_in_walk` at :384 preserve/set the revoked quarantine. `revert_inner` at :2010 requires an open run and an earlier P before any checkout.

S output, selected:

```text
test team::sync::tests::revert_rule_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
test team::sync::tests::revert_rule_refuses_a_reported_only_revocation ... ok
test team::sync::tests::revert_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
test team::sync::tests::revert_refuses_a_reported_only_revocation ... ok
test team::sync::tests::revert_refuses_a_reported_only_head_below_a_revoked_pin ... ok
test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lacked_device_revoke ... ok
test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight ... ok
test team::sync::tests::revert_accepts_one_proven_revoked_head ... ok
test team::sync::tests::revert_accepts_two_stacked_proven_revoked_heads ... ok
test team::sync::tests::revert_accepts_on_a_new_device_without_a_pin ... ok
test team::sync::tests::revert_accepts_a_revocation_another_device_filed ... ok
test team::sync::tests::revert_accepts_after_forty_days_offline ... ok
test team::sync::tests::revert_accepts_after_a_current_custodian_refiles ... ok
```

C additionally passed `a_revocation_counts_only_from_a_custodian_allowed_to_revoke` (`lib.rs:3555`) and `a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet` (:3593). The refusal tests assert quarantine, pin version, and empty audit/output, not just an error. Positive tests assert the accepted head and exact skipped-head audit rows.

Added V test `codex_verifier_local_distrust_enables_revert` (`sync.rs:12607`) fills the end-to-end local-distrust acceptance gap: no signed/server-reported revocation is supplied, local distrust alone enables the revert, R is pinned, J is audited, and the installed marker is P's `v1`. Result: `... ok`. Full code is below.

This result concerns membership of J1..Jn. Validation of R's own signer on replay has the separate defect D2 below.

## 2. No newly pinned proven-revoked signer — VIOLATED

Ordinary enforcement: `sync.rs:3942`, :3975, :4005 and :4057 keep withdrawn heads out of the anchor; :4077 appends them to the skipped run instead of pinning them. `pin_withdrawn` at :1668 protects an ordinary push. Restore leaves have a withdrawn check at :1383. A previously valid pin that later becomes revoked is retained as a rejected starting point until a revert; this is expressly allowed by the ADR and is not itself the defect.

S output:

```text
test team::sync::tests::a_pinned_head_of_a_since_revoked_signer_is_not_restored ... ok
test team::sync::tests::a_new_head_of_a_signer_revoked_in_this_pulls_evidence_is_refused ... ok
test team::sync::tests::revert_skips_a_head_pinned_before_its_signer_was_proven_revoked ... ok
test team::sync::tests::an_ordinary_push_refuses_over_a_pinned_head_whose_signer_is_proven_revoked ... ok
```

Missing cases were added and both fail:

* `codex_verifier_join_never_pins_a_leaf_revoked_in_its_evidence` (`sync.rs:12491`): expected version 0; actual version 1, after verifying that the leaf signer's signed revocation was newly counted. **D1:** `accept_transitions` evaluates at :1144, checks the leaf against the old database at :1249/:1383, then `store_transitions` writes the pin at :1567 before recording the evaluation at :1588. A valid custodian transition points to A's leaf; A's signed revocation is in the same fetched evidence, with no unsigned report. The join persists A's leaf, then the following walk detects the counted revocation and returns an error with that revoked leaf still pinned. The existing leaf test at :9405 does not supply this newly counted revocation case.
* `codex_verifier_replayed_revert_never_pins_its_now_revoked_signer` (:12507): R lands remotely with its reply lost; before local acceptance its signer is locally distrusted. **D2:** `revert_inner` resumes an uploaded lease at :2008 without another walk. `finish` at :3433 checks receipt/readback but does not check R's current signer standing, then pins it at :3480. Actual state is `("AVAILABLE", None, 3, "v1")`, versus expected `("QUARANTINED", Some("SIGNER_REVOKED"), 1, "local")`.

These are distinct acceptance paths; ordinary pull rejection coverage does not cover either. Full failing output and test code are below.

## 3. Committed revert contains P, not J or local edits — HOLDS

Enforcement: `sync.rs:2010` walks to the last valid anchor; :2044 obtains P's own generation's read key; :2055 restores P into the sibling staging directory; :2059 passes **that directory** to `push_inner`. `seal_snapshot` packs its supplied directory at :2871–2872 and seals under the checkout's verified generation at :2860. The live profile directory is never the source of a new revert seal. The resumed-upload path uses its already stored request/object.

S output:

```text
test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
test team::sync::tests::revert_commits_over_a_head_pinned_before_its_signer_was_proven_revoked ... ok
test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok
test team::sync::tests::revert_waits_for_rotation_after_a_compromised_revocation ... ok
test team::sync::tests::revert_resumes_after_a_lost_commit_reply ... ok
```

The fixture at :10989 creates distinct markers for P (`v1`), J (`v2`), and local edits (`local`). Tests at :11047 and :11161 assert `v1` both in the committer's directory and after another device actually downloads/decrypts R. The rotation test at :11198 verifies generation 2 on R while reading P from generation 1. The local-distrust verifier test also passes this content check. No additional content test was needed.

As ADR :1565 states, a receiver cannot cryptographically prove that another committer chose P's plaintext; this holds for the implemented committer path, not for arbitrary signed content produced by a different client.

## 4. Failed/refused revert, join, or pull preserves local data — VIOLATED

Existing guards: `sync.rs:1948`/ :1955 stage and clean up a refused revert; join refuses conflicting bindings before insertion at :2274 and :2330; pull validates the chain before restoration at :4412. `restore` authenticates the complete envelope before unpacking at :4328–4351. `shared/src/snapshot.rs:178` stages extraction and swaps only after successful unpacking, protecting against corrupt snapshot content.

S output:

```text
test team::sync::tests::a_refused_revert_checkout_keeps_the_local_profile ... ok
test team::sync::tests::revert_is_refused_for_a_reported_only_revocation ... ok
test team::sync::tests::an_abandoned_revert_lease_discards_its_staging ... ok
test team::sync::tests::join_refuses_the_rolled_back_child_of_the_leaf ... ok
test team::sync::tests::join_with_a_lying_first_snapshot_pins_nothing ... ok
```

The revert refusal tests compare actual file trees. Several join refusal tests only use a nonexistent output directory; those checks do not establish preservation of preexisting local edits after the restore succeeds and the DB pin fails.

**D3:** At `sync.rs:4457` the restore has already replaced the real directory before the fallible `pin` transaction at :4459/:4269. A failed update or transaction commit returns an error after destroying the previous local files, without rollback. The same ordering exists for P advancement at :4430–4431. `join` delegates to this path at :2353.

Two added V tests inject an abort on the `base_version` update, using the repository's existing SQLite-trigger fault-injection pattern. Both confirm the intended DB failure before checking data:

```text
test team::sync::tests::codex_verifier_failed_pull_pin_preserves_local_files ... FAILED
  left: "v1"
 right: "local"
test team::sync::tests::codex_verifier_failed_join_pin_preserves_local_files ... FAILED
a refused join must preserve local data
```

Locations: :12532 and :12547; helper :12523. In the pull case the pin remains at 0 while the directory contains remote `v1`. In the post-restore join case `base_version` remains 0 and the unsynced `local-only` file has disappeared. This models a storage failure at acceptance; no production implementation was changed to create it.

The added recovery test (:12579) separately verifies that a corrupt blob is rejected without changing an **existing** local tree, and later pull/push or unbind succeeds. It passes.

Contract nuance: ADR :1553 explicitly allows advancing/restoring a valid P while an open revoked run still returns `sync.signerRevoked`. That intentional partial-acceptance behavior already makes the user's absolute property 4 stronger than the ADR. D3 above is independent of that nuance: even an ordinary valid pull/full join that fails its pin write replaces the local data.

## 5. SIGNER_REVOKED clears only when valid R is accepted — VIOLATED

Enforcement on the intended paths: `sync.rs:3625–3634` preserves quarantine and error code on release; :4436 refuses to clear it without an accepted run; :4259 atomically pins R and closes audit rows, with `lift` allowed only when the completed walk accepted a run. Revert completion records the audit and pending swap in its pin transaction at :3494–3515.

S output:

```text
test team::sync::tests::an_abandoned_revert_keeps_the_binding_quarantined ... ok
test team::sync::tests::revert_resumes_after_a_lost_release_of_an_abandoned_lease ... ok
test team::sync::tests::a_revert_lease_whose_run_was_closed_elsewhere_is_released ... ok
test team::sync::tests::a_reported_only_quarantine_stays_once_the_approval_is_hidden ... ok
test team::sync::tests::only_a_signer_revoked_quarantine_lets_a_pull_through ... ok
```

The release tests exercise blocked seal, missing generation key, aborted upload, replayed checkout, and lost release responses; their assertions retain the reason and block ordinary pushes. A successful replay that actually accepts a still-valid R is distinct from merely receiving/replaying a release reply.

**D2 also violates this property:** `finish` clears `last_error_code` unconditionally at :3484 on replayed commit completion without establishing that R's signer is still valid. V's test at :12507 proves the lost-reply scenario with a signer locally distrusted before acceptance: quarantine becomes `AVAILABLE`, error becomes `None`, and the directory changes to `v1`. A valid receipt is being treated as sufficient for local acceptance of an invalid R.

## 6. Completed revert installs P locally — HOLDS

Enforcement: `sync.rs:3509` adds `revert_swaps` in the same transaction as the accepted R and closed audit. `revert` calls `settle_revert_swap` after completion at :1951. The resumable rename sequence is at :1868–1905. Push, pull, and revert settle before further work (:1661, :4377, :1948). The actual launch entry point settles at `launch.rs:150`, under the launch claim. `sync_cmd.rs:205` and :536 hold mutation claims for revert/join; delete (`lib.rs:860`) and unbind (`team/downgrade.rs:1238`) do likewise.

S output:

```text
test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok
test team::sync::tests::a_crash_after_finish_completes_the_staging_swap ... ok
test team::sync::tests::a_crash_inside_the_staging_swap_resumes ... ok
test team::sync::tests::a_staging_dir_without_a_swap_row_is_never_swapped_in ... ok
test team::sync::tests::the_launch_settle_needs_a_team_database_only_when_one_exists ... ok
```

Tests at :11298 and :11325 assert `v1`, absence of staging/old directories, and absence of the swap row after each recovery state. The launch branch in the unit test calls the same settle function; the actual launch caller was inspected separately. These are injected crash-state tests, not an OS process-kill exercise.

This is the ADR's recoverable guarantee: after the public revert completes, or the pending swap is resumed, P is installed. The ADR deliberately permits a crash interval between the DB acceptance and directory swap. No additional test was needed.

## 7. Backdated self-renewal stays refused; exactly one alert — HOLDS

Enforcement: `team/ledger.rs:267` loads permanent per-key count cutoffs. :319 compares first-seen evaluation; :326–334 drops newly seen records from the revoked key regardless of their claimed issue time. :287 distinguishes counted device revocation from local distrust for alert eligibility. :379 verifies/recognizes the self-renewal and :398 inserts only the first alert for that key. Schema 9's primary key at `team/db.rs:1331` and immutable/insert-once triggers at :1375–1383 prevent duplication, replacement, and deletion.

C/D output:

```text
test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok
test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok
test custody_tests::revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok
test custody_tests::a_head_by_a_committer_a_sticky_revoked_key_appointed_is_refused ... ok
test custody_tests::records_first_seen_before_a_count_keep_their_standing ... ok
test team::db::tests::renewed_after_revocation_alerts_refuse_delete_and_replace ... ok
test team::db::tests::a_version_8_file_migrates_to_version_9_and_reopens ... ok
```

`lib.rs:4798` compares custody before/after and the exact alert tuple. :4874 supplies multiple distinct genuine renewals across evaluations and repeats evidence, asserting one row with the first container/time. :4912 and :4958 test the cutoff and distrust distinction. Database tests at :2270 exercise duplicate/replace/update/delete refusal and reopen. No missing coverage requiring a new test was found for this property.

## 8. Alert requires a renewal verified under the revoked key — HOLDS

Enforcement: `team/ledger.rs:388` resolves the public key by the named issuer and verifies the signed container before any alert insertion. :391 requires a root-key grant; :394 excludes bootstrap grants and requires subject signing key equal issuer. Merely naming a revoked key is insufficient.

C output:

```text
test custody_tests::renewed_after_revocation_is_not_raised_for_a_forged_container ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok
test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok
```

`lib.rs:4824` constructs a container naming D but signed by another key, confirms the named issuer, and separately omits D's public key for a genuine renewal. It asserts no alert and unchanged custody. :4931 covers another custodian renewing D and D issuing a grant to someone else. The positive case asserts the exact signed container hash. No new test was needed.

## 9. No decrypted P staging after abandonment/refusal/delete/unbind — VIOLATED

Cleanup paths: `sync.rs:1955` calls `discard_revert_staging` after a revert error; :1928 removes the sibling directory when no pending lease/swap needs it. `lib.rs:870–875` settles the swap and deletes staging even for profile deletion under a held lease. `team/downgrade.rs:1248–1250` settles/cleans before the unbind. Successful local unbind refuses held leases/pending operations at `sync.rs:3662` and :3671, so those refusals are not falsely treated as completed unbinds.

S output:

```text
test team::sync::tests::a_refused_revert_discards_its_staging ... ok
test team::sync::tests::a_refused_revert_checkout_keeps_the_local_profile ... ok
test team::sync::tests::an_abandoned_revert_lease_discards_its_staging ... ok
test team::sync::tests::deleting_or_unbinding_a_profile_discards_its_revert_staging ... ok
```

**D4:** `discard_revert_staging` at :1917–1925 preserves plaintext whenever the local binding still has a lease. After abandonment is processed by the server but its release reply is lost, the client's pending release retains that lease reference; the public revert returns an error and leaves the full decrypted P on disk indefinitely unless a later operation completes cleanup. No swap is pending and no R was accepted.

The existing test at :11430 is not empty or skipped, but its assertion at :11445 explicitly expects the staging directory to remain when the release reply is lost (`exists() == lost`). Thus its passing name overstates the requested no-plaintext guarantee.

Added V test `codex_verifier_abandoned_revert_lost_release_removes_plaintext` at :12560 checks a compromise discovered at checkout, a server-processed release whose reply is lost, unchanged local data, no server lease, and a pending local release. Its final assertion fails:

```text
test team::sync::tests::codex_verifier_abandoned_revert_lost_release_removes_plaintext ... FAILED
[sync] release: [[shardx:fleet.refusedSync|status=503|detail=]]
abandonment must remove decrypted P even when its reply is lost
```

The implementation intentionally treats this as resumable while the requested property gives no retained-plaintext exception for a lost release. The new test preserves the stricter requested assertion instead of adopting the existing test's exception.

## 10. Team joining: proven restore leaf, checkout gate, recovery — HOLDS for these checks

Enforcement: `sync.rs:2315` selects the start epoch; :1102 verifies transitions; :1296 verifies the custodian's signature, identity, epoch, historical/current authority and local withdrawal; :1434 verifies the inclusion proof. :1224 walks from the listed head to the exact proof leaf; :1395 verifies each intervening signature, binding identity and current epoch. The leaf is verified at :1346 and pinned with its evidence at :1461. Post-restore profiles created at the current epoch follow ordinary acceptance and need no older transition, as the ADR specifies.

The checkout gate compares `base_version < remote_version` at :1759. Fresh checkout refuses at :2737, while a replayed checkout over unpulled data is closed/released at :2781–2797. `join` creates no lease or mutation operation of its own before delegating to pull (:2331, :2353), so a failed new join remains locally unbindable unless a later push is already in flight. `unbind`'s no-lease/no-pending transaction is at :3649.

S output:

```text
test team::sync::tests::join_after_a_restore_pins_the_transition_leaf_then_pulls ... ok
test team::sync::tests::join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf ... ok
test team::sync::tests::join_refuses_the_rolled_back_child_of_the_leaf ... ok
test team::sync::tests::join_with_a_lying_first_snapshot_pins_nothing ... ok
test team::sync::tests::join_then_a_push_before_the_first_pull_restores_is_refused ... ok
test team::sync::tests::join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes ... ok
test team::sync::tests::a_leaf_head_is_accepted_only_as_a_new_head_is ... ok
test team::sync::tests::a_lapsed_or_former_custodian_signs_no_transition ... ok
test team::sync::tests::a_custodian_distrusted_here_signs_no_transition ... ok
test team::sync::tests::a_transition_that_does_not_verify_keeps_the_binding_quarantined ... ok
```

Tests :12354 and :12385 assert no checkout/commit of unpulled data, closure of pending checkout, and successful subsequent pull then push. Added V test `codex_verifier_failed_join_has_pull_push_and_unbind_recovery` (:12579) uses existing local files, rejects a corrupt snapshot, confirms byte-for-byte preservation and checkout denial, and verifies both recovery choices: corrected pull followed by push, or local unbind with data preserved. Result: `... ok`.

This HOLDS is limited to the stated proof, checkout, and recovery checks. It is not an overall approval of joining: D1 proves that a genuinely proven leaf can still be wrongly pinned when its signer is revoked in the same evidence. That violates property 2 and rule 6's signer requirement; it does not forge or bypass the custodian transition/inclusion proof. D3 separately violates local-data preservation on failed join pinning.

## Defects to address

| ID | Severity | Location | Concrete scenario / consequence |
|---|---|---|---|
| D1 | High | `src-tauri/src/team/sync.rs:1249`, :1383, :1567, :1588 | Join sees a valid restore proof and the leaf signer's signed revocation together. Leaf validation reads the ledger before the count is recorded; transaction persists the revoked leaf, and later pull refusal leaves it pinned. |
| D2 | High | `src-tauri/src/team/sync.rs:2008`, :3433, :3480 | Revert commit reply is lost; R's signer becomes locally distrusted before local acceptance. Replayed completion pins R, clears SIGNER_REVOKED, and swaps data without checking the signer again. |
| D3 | High | `src-tauri/src/team/sync.rs:4457`, :4459, :4269; also :4430 | Pull/join replaces the live profile, then the pin write fails. Operation reports failure with unsynced local files already lost and base/pin not reflecting the restored bytes. |
| D4 | Medium | `src-tauri/src/team/sync.rs:1917`, :1924, :1955 | Revert is abandoned after checkout and release is processed remotely; reply is lost. Local held-lease flag prevents removal of decrypted P staging after the error. |

No production fixes were applied: this is independent verification, with executable counterexamples left for the implementer. The seven new tests, their shared helper, and exact V/C/D output follow.

## Added test code

File: `src-tauri/src/team/sync.rs:12489`. The code below is copied from the working tree; all production code and preexisting tests remain unchanged.

```rust
    // Independent ADR 0002 verification: reuse the local World fixture.
    #[test]
    fn codex_verifier_join_never_pins_a_leaf_revoked_in_its_evidence() {
        let (w, d, _, old) = joinable_after_restore(0);
        let revoked_leaf = forge(&w, &author(), |_| {});
        let previous = SignedSnapshotManifestV2::parse(&old).unwrap().head_hash();
        let leaves = [leaf(PROFILE, previous, revoked_leaf)];
        w.file(&w.me.sk, &transition(&w.me, 0, &leaves), &leaves, &[PROFILE], 0);
        w.fake().head = Some(revoked_leaf);
        serve(&w, &author_pages_for(&w, T0 + 300 * DAY,
            Some(DeviceRevocationReason::Retired), false));
        assert!(!ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap());
        w.join(LOCAL, PROFILE, &d.path().join("joined")).unwrap_err();
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap());
        assert_eq!(w.state(LOCAL).3, 0, "a newly counted revoked leaf must never be pinned");
    }

    #[test]
    fn codex_verifier_replayed_revert_never_pins_its_now_revoked_signer() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        w.fake().lose.push("commit");
        w.revert(&udd).unwrap_err();
        assert_eq!(w.fake().version, 3);
        assert_eq!(w.state(LOCAL).3, 1, "R not yet locally accepted");
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id, NOW).unwrap();
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id).unwrap());
        let _replayed = w.revert(&udd);
        let (state, reason, _, version, _) = w.state(LOCAL);
        assert_eq!((state.as_str(), reason.as_deref(), version, marker(&udd)),
            ("QUARANTINED", Some("SIGNER_REVOKED"), 1, "local".into()),
            "replay must not accept a proven-revoked R or lift quarantine");
    }

    fn codex_verifier_inject_pin_failure(w: &World) {
        w.db().conn.execute_batch(
            "CREATE TRIGGER codex_pin_failure BEFORE UPDATE OF base_version ON profile_bindings
             WHEN NEW.base_version > OLD.base_version
             BEGIN SELECT RAISE(ABORT, 'codex injected pin write failure'); END;"
        ).unwrap();
    }

    #[test]
    fn codex_verifier_failed_pull_pin_preserves_local_files() {
        let w = world();
        chain_of(&w, &[&w.me.sk]);
        let d = second(&w);
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        codex_verifier_inject_pin_failure(&w);
        let err = w.pull(&out).unwrap_err();
        assert!(format!("{err:#}").contains("codex injected pin write failure"));
        assert_eq!(w.state(LOCAL).3, 0);
        assert_eq!(marker(&out), "local", "a refused pull must preserve local data");
    }

    #[test]
    fn codex_verifier_failed_join_pin_preserves_local_files() {
        let (w, d, _, _) = joinable_after_restore(0);
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("local-only"), b"unsynced local edit").unwrap();
        codex_verifier_inject_pin_failure(&w);
        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(format!("{err:#}").contains("codex injected pin write failure"));
        assert_eq!(w.count("SELECT base_version FROM profile_bindings"), 0);
        assert!(out.join("local-only").exists(), "a refused join must preserve local data");
    }

    #[test]
    fn codex_verifier_abandoned_revert_lost_release_removes_plaintext() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        let before = tree(&udd);
        let compromise = a_compromise(&w);
        {
            let mut f = w.fake();
            f.on_checkout = Some(compromise);
            f.lose.push("release");
        }
        let err = w.revert(&udd).unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"));
        assert_eq!(tree(&udd), before);
        assert!(w.fake().lease.is_none(), "server has processed abandonment");
        assert_eq!(w.count("SELECT count(*) FROM operations WHERE kind = 'RELEASE' AND state = 'PENDING'"), 1);
        assert!(!beside(&udd, ".revert-staging").exists(), "abandonment must remove decrypted P even when its reply is lost");
    }

    #[test]
    fn codex_verifier_failed_join_has_pull_push_and_unbind_recovery() {
        for recovery in ["pull-push", "unbind"] {
            let (w, d, _, _) = joinable_after_restore(0);
            let good = w.fake().objects[&1].clone();
            *w.fake().objects.get_mut(&1).unwrap().last_mut().unwrap() ^= 1;
            let out = d.path().join("profile");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(out.join("local-only"), b"unsynced local edit").unwrap();
            let before = tree(&out);
            w.join(LOCAL, PROFILE, &out).unwrap_err();
            assert_eq!(tree(&out), before);
            let err = w.push_from(&out).unwrap_err();
            assert!(has(&err, "sync.remoteAhead"));
            assert!(w.sent("POST", "/checkout").is_empty());
            if recovery == "pull-push" {
                w.fake().objects.insert(1, good);
                w.pull(&out).unwrap();
                assert_eq!(noise(&out), noise(&w.udd));
                assert_eq!(w.push_from(&out).unwrap().version, 2);
            } else {
                unbind(LOCAL, SERVER, NOW).unwrap();
                assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
                assert_eq!(tree(&out), before);
            }
        }
    }

    #[test]
    fn codex_verifier_local_distrust_enables_revert() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&author()), NOW).unwrap();
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        assert_eq!(w.revert(&out).unwrap().version, 3);
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        assert_eq!(skipped(&w), [accepted_by(2, r, 1)]);
        assert_eq!(marker(&out), "v1");
        settled(&w, &out);
    }
```

## New-test output (V)

```text
Compiling shardx-launcher v2.5.0 (C:\Users\User\dev\wt\shardbrowser-team-ui-verify\src-tauri)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 30.10s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-d5f26ba2bf22f859.exe)

running 7 tests
test team::sync::tests::codex_verifier_abandoned_revert_lost_release_removes_plaintext ... FAILED
test team::sync::tests::codex_verifier_failed_join_pin_preserves_local_files ... FAILED
test team::sync::tests::codex_verifier_failed_pull_pin_preserves_local_files ... FAILED
test team::sync::tests::codex_verifier_join_never_pins_a_leaf_revoked_in_its_evidence ... FAILED
test team::sync::tests::codex_verifier_local_distrust_enables_revert ... ok
test team::sync::tests::codex_verifier_replayed_revert_never_pins_its_now_revoked_signer ... FAILED
test team::sync::tests::codex_verifier_failed_join_has_pull_push_and_unbind_recovery ... ok

failures:

---- team::sync::tests::codex_verifier_abandoned_revert_lost_release_removes_plaintext stdout ----
[sync] release: [[shardx:fleet.refusedSync|status=503|detail=]]

thread 'team::sync::tests::codex_verifier_abandoned_revert_lost_release_removes_plaintext' (34812) panicked at src\team\sync.rs:12575:9:
abandonment must remove decrypted P even when its reply is lost
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

---- team::sync::tests::codex_verifier_failed_join_pin_preserves_local_files stdout ----

thread 'team::sync::tests::codex_verifier_failed_join_pin_preserves_local_files' (33296) panicked at src\team\sync.rs:12556:9:
a refused join must preserve local data

---- team::sync::tests::codex_verifier_failed_pull_pin_preserves_local_files stdout ----

thread 'team::sync::tests::codex_verifier_failed_pull_pin_preserves_local_files' (8880) panicked at src\team\sync.rs:12543:9:
assertion `left == right` failed: a refused pull must preserve local data
  left: "v1"
 right: "local"

---- team::sync::tests::codex_verifier_join_never_pins_a_leaf_revoked_in_its_evidence stdout ----

thread 'team::sync::tests::codex_verifier_join_never_pins_a_leaf_revoked_in_its_evidence' (35040) panicked at src\team\sync.rs:12503:9:
assertion `left == right` failed: a newly counted revoked leaf must never be pinned
  left: 1
 right: 0

---- team::sync::tests::codex_verifier_replayed_revert_never_pins_its_now_revoked_signer stdout ----

thread 'team::sync::tests::codex_verifier_replayed_revert_never_pins_its_now_revoked_signer' (12536) panicked at src\team\sync.rs:12518:9:
assertion `left == right` failed: replay must not accept a proven-revoked R or lift quarantine
  left: ("AVAILABLE", None, 3, "v1")
 right: ("QUARANTINED", Some("SIGNER_REVOKED"), 1, "local")


failures:
    team::sync::tests::codex_verifier_abandoned_revert_lost_release_removes_plaintext
    team::sync::tests::codex_verifier_failed_join_pin_preserves_local_files
    team::sync::tests::codex_verifier_failed_pull_pin_preserves_local_files
    team::sync::tests::codex_verifier_join_never_pins_a_leaf_revoked_in_its_evidence
    team::sync::tests::codex_verifier_replayed_revert_never_pins_its_now_revoked_signer

test result: FAILED. 2 passed; 5 failed; 0 ignored; 0 measured; 611 filtered out; finished in 19.22s

error: test failed, to rerun pass `--lib`
```

## Custody output (C)

```text
Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.81s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-d5f26ba2bf22f859.exe)

running 33 tests
test custody_tests::a_collected_fleet_key_is_never_replaced ... ok
test custody_tests::a_server_delivered_fleet_key_is_counted_but_never_cached ... ok
test custody_tests::a_fleet_descriptor_counts_only_for_this_device_and_generation ... ok
test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok
test custody_tests::a_key_is_used_only_while_its_kept_record_reloads_exactly ... ok
test custody_tests::a_server_cannot_lapse_a_custodian_or_age_its_key_for_good ... ok
test custody_tests::a_head_by_a_committer_a_sticky_revoked_key_appointed_is_refused ... ok
test custody_tests::only_the_bootstrapped_device_has_a_pinned_anchor ... ok
test custody_tests::a_lapse_is_the_known_end_of_custody_clipped_at_the_key_age ... ok
test custody_tests::limit_a_new_device_counts_a_backdated_revocation_with_its_revoker ... ok
test custody_tests::limit_a_backdated_grant_from_a_never_counted_custodian_is_accepted ... ok
test custody_tests::limit_mutual_revocation_counts_both_on_a_new_device ... ok
test custody_tests::a_kept_grant_is_reverified_before_its_key_is_used ... ok
test custody_tests::a_fleet_generation_never_goes_back ... ok
test custody_tests::an_omitted_first_root_grant_never_stretches_the_key_age_with_history ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok
test custody_tests::local_distrust_ignores_what_is_first_seen_after_it ... ok
test custody_tests::reverifying_a_kept_key_records_the_lapse_history_shows ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_forged_container ... ok
test custody_tests::a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok
test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok
test custody_tests::a_counted_revocation_outlives_the_server_omitting_it ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok
test custody_tests::a_lapsed_custodians_backdated_grant_is_refused_with_history ... ok
test custody_tests::pull_uses_a_verified_key_only_while_its_issuer_stands ... ok
test custody_tests::records_first_seen_before_a_count_keep_their_standing ... ok
test custody_tests::a_verified_fleet_grant_opens_and_nothing_else_does ... ok
test custody_tests::the_pinned_anchor_never_changes ... ok
test custody_tests::a_revocation_counts_only_from_a_custodian_allowed_to_revoke ... ok
test custody_tests::a_reported_revocation_outlives_the_server_omitting_it ... ok
test custody_tests::revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok
test custody_tests::a_lapse_from_history_refuses_a_backdated_grant_with_no_evaluation_between ... ok

test result: ok. 33 passed; 0 failed; 0 ignored; 0 measured; 585 filtered out; finished in 14.71s
```

## Database output (D)

```text
Finished `test` profile [unoptimized + debuginfo] target(s) in 0.53s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-d5f26ba2bf22f859.exe)

running 19 tests
test team::db::tests::an_unexpected_version_1_file_is_not_migrated ... ok
test team::db::tests::a_version_5_upload_session_without_its_commit_operation_refuses_the_file ... ok
test team::db::tests::renewed_after_revocation_alerts_refuse_delete_and_replace ... ok
test team::db::tests::a_database_held_in_wal_mode_is_refused ... ok
test team::db::tests::journals_and_epoch_proofs_keep_their_constraints_across_a_reopen ... ok
test team::db::tests::a_new_database_reopens_with_its_schema_and_settings ... ok
test team::db::tests::every_sync_integer_class_keeps_its_range_across_a_reopen ... ok
test team::db::tests::an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key ... ok
test team::db::tests::a_version_1_file_migrates_to_version_5_and_reopens ... ok
test team::db::tests::a_version_8_file_migrates_to_version_9_and_reopens ... ok
test team::db::tests::skipped_heads_refuse_delete_replace_and_a_second_resolution ... ok
test team::db::tests::the_triggers_and_indexes_of_a_version_5_file_survive_version_6 ... ok
test team::db::tests::a_version_2_file_migrates_to_version_5_or_is_left_as_it_was ... ok
test team::db::tests::a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding ... ok
test team::db::tests::the_ledger_never_takes_back_what_it_learned ... ok
test team::db::tests::a_version_3_file_migrates_to_version_6_or_is_left_as_it_was ... ok
test team::db::tests::an_unknown_schema_fails_closed_and_is_left_as_it_was ... ok
test team::db::tests::a_version_8_file_with_another_min_reader_is_not_migrated ... ok
test team::db::tests::a_version_5_file_with_data_moves_to_version_6_keeping_every_row ... ok

test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 599 filtered out; finished in 5.39s
```

VERDICT: FAIL
