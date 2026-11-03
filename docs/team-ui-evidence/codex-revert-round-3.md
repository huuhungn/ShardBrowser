# Independent verification: ADR 0002 rule 6 and Team join — round 3

Verified HEAD: `8be4e6a6db1e78fd130902bf68490d317454f49e`.

Worktree: `<verify-worktree>`.

Result: **FAIL**. One defect, reproduced in two scenarios, violates properties **3 and 6**: a revert can commit and install the content of a source snapshot whose signer has since been proven revoked. Properties 1, 2, 4, 5, 7, 8, 9 and 10 hold within the specified ADR contract and its express exceptions.

Only repository source, the requested ADR passages, and locally started tests were used. No author review reports, `.omc/`, `.omx/reports/`, scratch directories, or OpenViking memories were read. No production implementation was changed; four unit tests were added. There were no commits, pushes, PRs, issues, or external application/server interactions. The test server binds `127.0.0.1:0` (`sync.rs:5496`); profile/config/database fixtures use temporary directories. The prohibited OS credential-store test was explicitly skipped in every Cargo command. The real application-data directory was not accessed.

**Contract interpretation**

The governing text is `docs/adr/0002-g2-contract-decisions.md:1493` and `:1529`, `:1534` through the end of the lapsed-signer bullet at `:1593`. Property 2 is assessed with the ADR's explicit ordinary-push exception: an ordinary push pins its own committed head and checks withdrawal on a later pull/push. The reader, restore-leaf and revert pins are checked here. Existing historical pins may subsequently have their signer revoked; that is handled by the rejected-pin/revert path.

For property 4, the open-run pull's restore of a newer P followed by `sync.signerRevoked` is required behavior. Replacing unsynced edits through that restore is assessed against an ordinary successful pull, not treated as a defect by itself. For property 9, a resumable upload with no release pending, or a committed pending swap, is the ADR's express staging-retention exception. For property 10, the transition-proof requirement concerns accepting a restore leaf at an older epoch; a profile first committed at the current epoch uses ordinary rule-6 acceptance.

**Commands and observed results**

Every command used this exact shape:

```text
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib <filter> -- --skip a_real_os_store_key_survives_into_a_fresh_process
```

| ID | Filter | Observed output |
|---|---|---|
| S | `team::sync::tests` | `test result: FAILED. 177 passed; 3 failed; 0 ignored; 0 measured; 452 filtered out; finished in 580.49s` |
| N | `independent_r3` | `test result: FAILED. 2 passed; 2 failed; 0 ignored; 0 measured; 629 filtered out; finished in 9.72s` |
| C | `custody_tests` | `test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 599 filtered out; finished in 8.15s` |
| D | `team::db::tests` | `test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 614 filtered out; finished in 4.47s` |
| L | `team::ledger::tests` | `test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 627 filtered out; finished in 0.55s` |

All 177 pre-existing sync tests passed. S also included three new sync probes. Its third failure was in the initial differential fixture: two independently initialized Windows Local State files generated different os_crypt keys. The fixture was corrected to start both restores with the same complete Local State, without removing the full-tree equality assertion. N reran all four final probes: that comparison and the genuinely backdated-renewal probe passed; both source-withdrawal probes still failed. C includes the new renewal probe. No production code changed between S and N.

Two preliminary attempts at C and D while S's executable was still running ended at the Windows linker with `LNK1104` for the running test executable. No tests ran in those attempts. Both commands were rerun successfully after S and N exited. No OS error 1455 occurred, so the -j 1 fallback was not needed. The initial full build took 6m 10s; the test execution times are shown above. Tauri regenerated two schema files without semantic differences; those build side effects were restored to HEAD.

**Assertion and coverage audit**

The tests cited below were read through their fixtures and assertions. They have no `#[ignore]`, empty/vacuous assertions, or early returns bypassing the checked behavior. Fake-server handlers do return injected failures; those are fault injection, not test bypasses. The helper `World::enroll` intentionally returns for an unbound fixture after collecting its fleet key; the calling tests continue and assert the join/publish behavior. Assertions inspect committed versions/hashes, error codes, quarantine states, audit rows, actual profile contents, staging removal, and/or recorded requests. Existing tests were left intact.

One coverage gap was identified without a product defect: the existing `a_backdated_self_renewal_after_a_count_is_refused` uses issuance T0+10 days while the revocation count is at T0+1 day. The added renewal probe tests issuance before the count and after-history rejection, with a fresh-history positive control. Two additional probes cover source-snapshot withdrawal at download and before resuming a stored upload. The fourth compares the entire restored file tree of the open-run exception with ordinary pull.

**D1 — High: a revoked source snapshot can be republished by a trusted revert signer**

Enforcing-code gap: `src-tauri/src/team/sync.rs:2069` resumes an upload solely from the held base and existing staging directory, skipping a new walk. On the fresh path, `:2120` downloads the chosen source and `:2124` passes its staging directory into `push_inner` without rechecking the source signer. `:2915` seals that directory. `:3496` and `:3572` recheck R's signer, but not the signer of the snapshot that supplied R's content.

Concrete chain: v1 is signed by trusted device A and contains marker `v1`; v2 is signed by B and contains `v2`; v3 is signed by C. The local pin is v1, C is locally distrusted, and A remains a valid committer. Initially the revert selects v2 as P.

1. **Withdrawal during source download:** the fake server's snapshot-download hook records local distrust of B in the real temporary trust ledger before returning the downloaded source. The revert continues, commits v4 signed by A, accepts it, and swaps in `v2`. At that point both v2 and v3 have proven-revoked signers and v1 is the newest valid earlier snapshot. The operation should refuse without modifying the live profile, or recompute/restage from v1.
2. **Withdrawal before retry:** the first revert stages/seals v2, but its CREATE_UPLOAD is dropped before processing, so no R exists. B is then locally distrusted before the next revert call. The retry takes the shortcut at `:2069`, publishes v4 with v2's content, and installs it. A subsequent ordinary pull of v4 independently confirms the committed payload is `v2`, not `v1`.

This is a committer-side defect. A reader cannot detect the content mismatch after re-encryption, as the ADR explicitly acknowledges; R has a trusted signer. The failure therefore propagates rejected content through an apparently valid R and affects properties 3 and 6, without requiring a revoked R signer to be pinned.

Final focused reproduction output:

```text
Finished `test` profile [unoptimized + debuginfo] target(s) in 1m 09s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-5846a8c03bdfcc30.exe)

running 4 tests
test custody_tests::independent_r3_a_truly_backdated_renewal_is_sticky_and_alerts_once ... ok
test team::sync::tests::independent_r3_open_run_restore_matches_an_ordinary_pull ... ok
test team::sync::tests::independent_r3_revert_rechecks_its_source_after_download ... FAILED
test team::sync::tests::independent_r3_resumed_revert_rechecks_its_source ... FAILED

failures:

---- team::sync::tests::independent_r3_revert_rechecks_its_source_after_download stdout ----

thread 'team::sync::tests::independent_r3_revert_rechecks_its_source_after_download' (43032) panicked at src\team\sync.rs:13102:17:
assertion `left == right` failed: only v1 remains valid after the v2 source signer is withdrawn
  left: "v2"
 right: "v1"
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

---- team::sync::tests::independent_r3_resumed_revert_rechecks_its_source stdout ----

thread 'team::sync::tests::independent_r3_resumed_revert_rechecks_its_source' (43724) panicked at src\team\sync.rs:13139:17:
assertion `left == right` failed: a resumed R must not publish a source already proven revoked before retry
  left: "v2"
 right: "v1"


failures:
    team::sync::tests::independent_r3_resumed_revert_rechecks_its_source
    team::sync::tests::independent_r3_revert_rechecks_its_source_after_download

test result: FAILED. 2 passed; 2 failed; 0 ignored; 0 measured; 629 filtered out; finished in 9.72s

error: test failed, to rerun pass `--lib`
```

**Property 1 — Only proven-revoked runs admit R: HOLDS**

Code path read: src-tauri/src/team/sync.rs:3964 (`revert_rule`), :4021 (`walk`), :4202 (`walked`); src-tauri/src/team/ledger.rs:134, :239, :830, :1112.

The walk files the evidence first, distinguishes withdrawn/reported/untrusted in that order, verifies signatures, profile identity, epoch and exact chain continuity, and only joins Withdrawn heads. A reported-only or lapsed member stops the walk; a run already encountered preserves SIGNER_REVOKED. `counted` requires a valid signature, custody and device.revoke at issuance and custody at first sight. Local distrust enters the same permanent withdrawal table.

Tests inspected and executed: `revert_rule_accepts_one_proven_revoked_head` (src-tauri/src/team/sync.rs:10457); `revert_rule_accepts_two_stacked_proven_revoked_heads` (src-tauri/src/team/sync.rs:10466); `revert_rule_accepts_on_a_new_device_without_a_pin` (src-tauri/src/team/sync.rs:10476); `revert_rule_refuses_a_run_with_a_lapsed_unrevoked_head` (src-tauri/src/team/sync.rs:10484); `revert_rule_refuses_a_reported_only_revocation` (src-tauri/src/team/sync.rs:10491); `revert_rule_refuses_a_gap_below_the_pin` (src-tauri/src/team/sync.rs:10501); `revert_accepts_one_proven_revoked_head` (src-tauri/src/team/sync.rs:10553); `revert_accepts_two_stacked_proven_revoked_heads` (src-tauri/src/team/sync.rs:10567); `revert_accepts_on_a_new_device_without_a_pin` (src-tauri/src/team/sync.rs:10582); `revert_refuses_a_run_with_a_lapsed_unrevoked_head` (src-tauri/src/team/sync.rs:10593); `revert_refuses_a_reported_only_revocation` (src-tauri/src/team/sync.rs:10754); `revert_refuses_a_reported_only_head_below_a_revoked_pin` (src-tauri/src/team/sync.rs:10782); `revert_refuses_a_revocation_whose_issuer_lacked_device_revoke` (src-tauri/src/team/sync.rs:10862); `revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight` (src-tauri/src/team/sync.rs:10874); `local_distrust_alone_enables_a_revert` (src-tauri/src/team/sync.rs:12819).

Observed test-output excerpts (S for sync, C for custody, D for schema; final new probes use N):

```text
test team::sync::tests::revert_rule_accepts_one_proven_revoked_head ... ok
test team::sync::tests::revert_rule_accepts_two_stacked_proven_revoked_heads ... ok
test team::sync::tests::revert_rule_accepts_on_a_new_device_without_a_pin ... ok
test team::sync::tests::revert_rule_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
test team::sync::tests::revert_rule_refuses_a_reported_only_revocation ... ok
test team::sync::tests::revert_rule_refuses_a_gap_below_the_pin ... ok
test team::sync::tests::revert_accepts_one_proven_revoked_head ... ok
test team::sync::tests::revert_accepts_two_stacked_proven_revoked_heads ... ok
test team::sync::tests::revert_accepts_on_a_new_device_without_a_pin ... ok
test team::sync::tests::revert_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
test team::sync::tests::revert_refuses_a_reported_only_revocation ... ok
test team::sync::tests::revert_refuses_a_reported_only_head_below_a_revoked_pin ... ok
test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lacked_device_revoke ... ok
test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight ... ok
test team::sync::tests::local_distrust_alone_enables_a_revert ... ok
```

No additional test was necessary for this property beyond the cited coverage and code-path inspection.

**Property 2 — No newly accepted head has a proven-revoked signer: HOLDS**

Code path read: src-tauri/src/team/sync.rs:1265 (leaf record/recheck closure), :1474 (`store_transitions`), :3496 (`dropped_withdrawn_r`), :3568 (finish transaction), :4357 (`pin`); src-tauri/src/team/ledger.rs:239.

Leaf acceptance records newly counted revocations and checks its signer in the same immediate transaction. Pull/P acceptance rechecks the chosen head's signer under the pin transaction after downloading. Revert finish rechecks R after readback; a withdrawn R loses its used lease without a pin or swap. Already-pinned historical heads and the ADR's explicit ordinary-push exception are not classified as new reader-side acceptance violations.

Tests inspected and executed: `join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes` (src-tauri/src/team/sync.rs:12667); `a_new_head_of_a_signer_revoked_in_this_pulls_evidence_is_refused` (src-tauri/src/team/sync.rs:8097); `a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download` (src-tauri/src/team/sync.rs:12976); `a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked` (src-tauri/src/team/sync.rs:12701); `a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned` (src-tauri/src/team/sync.rs:13000); `revert_skips_a_head_pinned_before_its_signer_was_proven_revoked` (src-tauri/src/team/sync.rs:10821).

Observed test-output excerpts (S for sync, C for custody, D for schema; final new probes use N):

```text
test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok
test team::sync::tests::a_new_head_of_a_signer_revoked_in_this_pulls_evidence_is_refused ... ok
test team::sync::tests::a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok
test team::sync::tests::a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok
test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
test team::sync::tests::revert_skips_a_head_pinned_before_its_signer_was_proven_revoked ... ok
```

No additional test was necessary for this property beyond the cited coverage and code-path inspection.

**Property 3 — R contains the last valid earlier snapshot P: VIOLATED**

Code path read: src-tauri/src/team/sync.rs:2065–2128 (`revert_inner` source selection/resume), :2915 (`seal_snapshot`), :3521 (`finish`).

The normal path restores P into staging and seals that directory, which excludes the user's unsynced edits. However, P's signer is not retained/rechecked after its download or when a retained upload resumes. The new probes demonstrate D1 below: revoked v2 content is committed as v4 although v1 is the last valid earlier snapshot.

Tests inspected and executed: `revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head` (src-tauri/src/team/sync.rs:11222); `revert_commits_over_a_head_pinned_before_its_signer_was_proven_revoked` (src-tauri/src/team/sync.rs:11237); `revert_committed_here_is_accepted_by_a_second_device` (src-tauri/src/team/sync.rs:11336); `revert_waits_for_rotation_after_a_compromised_revocation` (src-tauri/src/team/sync.rs:11373); `independent_r3_revert_rechecks_its_source_after_download` (src-tauri/src/team/sync.rs:13082); `independent_r3_resumed_revert_rechecks_its_source` (src-tauri/src/team/sync.rs:13115).

Observed test-output excerpts (S for sync, C for custody, D for schema; final new probes use N):

```text
test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
test team::sync::tests::revert_commits_over_a_head_pinned_before_its_signer_was_proven_revoked ... ok
test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok
test team::sync::tests::revert_waits_for_rotation_after_a_compromised_revocation ... ok
test team::sync::tests::independent_r3_revert_rechecks_its_source_after_download ... FAILED
test team::sync::tests::independent_r3_resumed_revert_rechecks_its_source ... FAILED
```

The new test source is reproduced below; the failing probes are intentionally retained as failures.

**Property 4 — Refusal preserves local data; pin-time withdrawal and open-run exception: HOLDS**

Code path read: src-tauri/src/team/sync.rs:1968, :2327, :4357, :4414, :4430, :4531; src-tauri/src/sync_cmd.rs:205, :359, :536.

Revert and pull restore into a sibling directory. A failed restore/pin deletes dispensable staging and leaves the profile untouched. The pin and pending swap are committed together before swapping. The open-run branch intentionally pins/restores a newer P and then reports sync.signerRevoked. The new differential test compares all relative paths and file bytes against an ordinary pull of the same P, including Local State, and tests this exception explicitly. The transaction-time withdrawal probes assert both no pin and unchanged profile bytes.

Tests inspected and executed: `a_refused_revert_checkout_keeps_the_local_profile` (src-tauri/src/team/sync.rs:11456); `an_abandoned_revert_lease_discards_its_staging` (src-tauri/src/team/sync.rs:11606); `a_pull_whose_pin_fails_keeps_the_local_profile` (src-tauri/src/team/sync.rs:12731); `a_join_whose_pin_fails_keeps_the_local_profile` (src-tauri/src/team/sync.rs:12750); `a_failed_join_recovers_by_pull_then_push_or_by_unbind` (src-tauri/src/team/sync.rs:12791); `a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download` (src-tauri/src/team/sync.rs:12976); `a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned` (src-tauri/src/team/sync.rs:13000); `a_pull_keeps_the_devices_local_state` (src-tauri/src/team/sync.rs:12847); `a_revert_keeps_the_devices_local_state` (src-tauri/src/team/sync.rs:12863); `a_failed_anchor_restore_keeps_the_quarantine_and_unresolved_rows` (src-tauri/src/team/sync.rs:10951); `independent_r3_open_run_restore_matches_an_ordinary_pull` (src-tauri/src/team/sync.rs:13036).

Observed test-output excerpts (S for sync, C for custody, D for schema; final new probes use N):

```text
test team::sync::tests::a_refused_revert_checkout_keeps_the_local_profile ... ok
test team::sync::tests::an_abandoned_revert_lease_discards_its_staging ... ok
test team::sync::tests::a_pull_whose_pin_fails_keeps_the_local_profile ... ok
test team::sync::tests::a_join_whose_pin_fails_keeps_the_local_profile ... ok
test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok
test team::sync::tests::a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok
test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
test team::sync::tests::a_pull_keeps_the_devices_local_state ... ok
test team::sync::tests::a_revert_keeps_the_devices_local_state ... ok
test team::sync::tests::a_failed_anchor_restore_keeps_the_quarantine_and_unresolved_rows ... ok
test team::sync::tests::independent_r3_open_run_restore_matches_an_ordinary_pull ... ok
```

The new test source is reproduced below; the failing probes are intentionally retained as failures.

**Property 5 — Only accepting R lifts SIGNER_REVOKED: HOLDS**

Code path read: src-tauri/src/team/sync.rs:3679 (`release_reply`), :4357 (`pin` lift flag), :4601 (quarantine without an accepted run), :3496, :3521.

Release clears lease fields but preserves quarantine and its reason. Pull only lifts when the walk has an accepted run and finishes on an accepted head; an open later run stays quarantined. Lost COMMIT replies may lift quarantine only through validated acceptance of R. A withdrawn replayed R drops the consumed lease and keeps the quarantine. Valid restore transitions supersede the old epoch/audit under the ADR's separate restore rules.

Tests inspected and executed: `an_abandoned_revert_keeps_the_binding_quarantined` (src-tauri/src/team/sync.rs:11294); `revert_resumes_after_a_lost_release_of_an_abandoned_lease` (src-tauri/src/team/sync.rs:11570); `a_revert_lease_whose_run_was_closed_elsewhere_is_released` (src-tauri/src/team/sync.rs:11688); `a_reported_only_quarantine_stays_once_the_approval_is_hidden` (src-tauri/src/team/sync.rs:10711); `a_pull_crossing_an_accepted_run_into_another_keeps_the_quarantine` (src-tauri/src/team/sync.rs:10992); `a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked` (src-tauri/src/team/sync.rs:12701); `a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned` (src-tauri/src/team/sync.rs:13000); `revert_resumes_after_a_lost_commit_reply` (src-tauri/src/team/sync.rs:11426).

Observed test-output excerpts (S for sync, C for custody, D for schema; final new probes use N):

```text
test team::sync::tests::an_abandoned_revert_keeps_the_binding_quarantined ... ok
test team::sync::tests::revert_resumes_after_a_lost_release_of_an_abandoned_lease ... ok
test team::sync::tests::a_revert_lease_whose_run_was_closed_elsewhere_is_released ... ok
test team::sync::tests::a_reported_only_quarantine_stays_once_the_approval_is_hidden ... ok
test team::sync::tests::a_pull_crossing_an_accepted_run_into_another_keeps_the_quarantine ... ok
test team::sync::tests::a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok
test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
test team::sync::tests::revert_resumes_after_a_lost_commit_reply ... ok
```

No additional test was necessary for this property beyond the cited coverage and code-path inspection.

**Property 6 — After R acceptance the directory holds P: VIOLATED**

Code path read: src-tauri/src/team/sync.rs:1891 (`settle_revert_swap`), :1968, :2065–2128, :3576–3612 (`finish` pin/audit/swap transaction); src-tauri/src/launch.rs:150.

Normal completion and crash recovery install staged P and retain device Local State. D1 means the directory can instead receive the former P whose signer is now proven revoked. The download probe observes v2 locally after successful R acceptance, and the retry probe independently pulls the committed R and observes v2 where v1 is required.

Tests inspected and executed: `revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head` (src-tauri/src/team/sync.rs:11222); `revert_committed_here_is_accepted_by_a_second_device` (src-tauri/src/team/sync.rs:11336); `a_crash_after_finish_completes_the_staging_swap` (src-tauri/src/team/sync.rs:11473); `a_crash_inside_the_staging_swap_resumes` (src-tauri/src/team/sync.rs:11500); `a_resumed_revert_whose_staging_is_gone_restores_p_again` (src-tauri/src/team/sync.rs:12879); `a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull` (src-tauri/src/team/sync.rs:13199); `independent_r3_revert_rechecks_its_source_after_download` (src-tauri/src/team/sync.rs:13082); `independent_r3_resumed_revert_rechecks_its_source` (src-tauri/src/team/sync.rs:13115).

Observed test-output excerpts (S for sync, C for custody, D for schema; final new probes use N):

```text
test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok
test team::sync::tests::a_crash_after_finish_completes_the_staging_swap ... ok
test team::sync::tests::a_crash_inside_the_staging_swap_resumes ... ok
test team::sync::tests::a_resumed_revert_whose_staging_is_gone_restores_p_again ... ok
test team::sync::tests::a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull ... ok
test team::sync::tests::independent_r3_revert_rechecks_its_source_after_download ... FAILED
test team::sync::tests::independent_r3_resumed_revert_rechecks_its_source ... FAILED
```

The new test source is reproduced below; the failing probes are intentionally retained as failures.

**Property 7 — Sticky revocation rejects backdated renewal and alerts once: HOLDS**

Code path read: src-tauri/src/team/ledger.rs:273 (`prepare` first-sighting cutoffs), :385 (`renewed_after_revocation`); src-tauri/src/team/db.rs:1324, :1374.

Containers first seen after the counted revocation are dropped regardless of issued_at_ms. An eligible self-renewal records the first alert only; schema 9's primary key and immutable/insert-once triggers prevent a second row or replacement. The existing test named backdated uses an issuance at T0+10 days while counting at T0+1 day; the added test closes that chronology gap with issuance T0+0.5 days, count T0+1 day, and sightings at days 20 and 21, plus a fresh-history positive control.

Tests inspected and executed: `a_backdated_self_renewal_after_a_count_is_refused` (src-tauri/src/lib.rs:4798); `renewed_after_revocation_is_bounded_per_key` (src-tauri/src/lib.rs:4897); `renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count` (src-tauri/src/lib.rs:4935); `independent_r3_a_truly_backdated_renewal_is_sticky_and_alerts_once` (src-tauri/src/lib.rs:4823); `renewed_after_revocation_alerts_refuse_delete_and_replace` (src-tauri/src/team/db.rs:2270); `a_version_8_file_migrates_to_version_9_and_reopens` (src-tauri/src/team/db.rs:2115); `records_first_seen_before_a_count_keep_their_standing` (src-tauri/src/lib.rs:4696); `revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key` (src-tauri/src/lib.rs:4610).

Observed test-output excerpts (S for sync, C for custody, D for schema; final new probes use N):

```text
test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok
test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok
test custody_tests::independent_r3_a_truly_backdated_renewal_is_sticky_and_alerts_once ... ok
test team::db::tests::renewed_after_revocation_alerts_refuse_delete_and_replace ... ok
test team::db::tests::a_version_8_file_migrates_to_version_9_and_reopens ... ok
test custody_tests::records_first_seen_before_a_count_keep_their_standing ... ok
test custody_tests::revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok
```

The new test source is reproduced below; the failing probes are intentionally retained as failures.

**Property 8 — Only a renewal verified under the revoked key raises the alert: HOLDS**

Code path read: src-tauri/src/team/ledger.rs:69 (`keys_of`), :328–341, :385–413.

The evidence-key map is indexed by the hash of each actual public key. The claimed issuer must select that key and strict signature verification must succeed. The verified payload must be a non-bootstrap root grant whose subject key equals its issuer. Missing keys, forged signatures, another issuer, another subject, and local distrust without a counted revocation do not raise the alert.

Tests inspected and executed: `renewed_after_revocation_is_not_raised_for_a_forged_container` (src-tauri/src/lib.rs:4847); `renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian` (src-tauri/src/lib.rs:4954); `renewed_after_revocation_is_not_raised_for_a_distrusted_key` (src-tauri/src/lib.rs:4981); `renewed_after_revocation_is_bounded_per_key` (src-tauri/src/lib.rs:4897).

Observed test-output excerpts (S for sync, C for custody, D for schema; final new probes use N):

```text
test custody_tests::renewed_after_revocation_is_not_raised_for_a_forged_container ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok
test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok
```

No additional test was necessary for this property beyond the cited coverage and code-path inspection.

**Property 9 — Abandonment, refusal, delete and unbind remove decrypted revert staging: HOLDS**

Code path read: src-tauri/src/team/sync.rs:1936, :1983, :4430; src-tauri/src/lib.rs:859–879; src-tauri/src/team/downgrade.rs:1238–1250.

Cleanup preserves staging only for the ADR's pending swap or resumable upload under the held lease with no matching pending release. A lost release is still abandonment and removes staging. Delete removes staging even with a held lease. The public unbind flow settles a pending swap, discards orphan staging, then performs the transactional unbind. A still-resumable upload is the express contract exception, not a completed abandonment.

Tests inspected and executed: `a_refused_revert_discards_its_staging` (src-tauri/src/team/sync.rs:11463); `an_abandoned_revert_lease_discards_its_staging` (src-tauri/src/team/sync.rs:11606); `an_abandoned_revert_with_a_lost_release_keeps_no_plaintext` (src-tauri/src/team/sync.rs:12766); `deleting_or_unbinding_a_profile_discards_its_revert_staging` (src-tauri/src/team/sync.rs:11628); `a_release_pending_for_another_lease_keeps_the_staging` (src-tauri/src/team/sync.rs:12927); `a_withdrawn_device_releases_its_revert_lease_on_the_server` (src-tauri/src/team/sync.rs:13160); `a_revert_lease_whose_walk_fails_is_released_on_the_server` (src-tauri/src/team/sync.rs:13179).

Observed test-output excerpts (S for sync, C for custody, D for schema; final new probes use N):

```text
test team::sync::tests::a_refused_revert_discards_its_staging ... ok
test team::sync::tests::an_abandoned_revert_lease_discards_its_staging ... ok
test team::sync::tests::an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok
test team::sync::tests::deleting_or_unbinding_a_profile_discards_its_revert_staging ... ok
test team::sync::tests::a_release_pending_for_another_lease_keeps_the_staging ... ok
test team::sync::tests::a_withdrawn_device_releases_its_revert_lease_on_the_server ... ok
test team::sync::tests::a_revert_lease_whose_walk_fails_is_released_on_the_server ... ok
```

No additional test was necessary for this property beyond the cited coverage and code-path inspection.

**Property 10 — Join proves restore leaf, blocks premature check-in, and retains recovery paths: HOLDS**

Code path read: src-tauri/src/team/sync.rs:2327 (`join`), :1102 (`accept_transitions`), :1305, :1358, :1407, :1446, :1474, :1774 (base/remote check), :2784 (`checkout`), :3745 (`unbind`); src-tauri/src/sync_cmd.rs:536.

Join creates a version-0 binding at E or E-1 and delegates to pull. Across a restore, the transition must have a trusted custodian signature and inclusion proof, above-leaf links must verify with exact IDs/epoch/continuity, and the leaf signer is checked again within its pin transaction. A base below the pinned remote version blocks fresh checkout; a replayed checkout is released. Transient download failures recover by pull then push; invalid transitions and rollback quarantines retain unbind. Profiles created at the current epoch use ordinary rule-6 acceptance and do not invent a restore proof.

Tests inspected and executed: `join_after_a_restore_pins_the_transition_leaf_then_pulls` (src-tauri/src/team/sync.rs:12311); `join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf` (src-tauri/src/team/sync.rs:12327); `join_refuses_the_rolled_back_child_of_the_leaf` (src-tauri/src/team/sync.rs:12341); `join_with_a_lying_first_snapshot_pins_nothing` (src-tauri/src/team/sync.rs:12404); `join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes` (src-tauri/src/team/sync.rs:12667); `join_then_a_push_before_the_first_pull_restores_is_refused` (src-tauri/src/team/sync.rs:12530); `join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes` (src-tauri/src/team/sync.rs:12561); `a_failed_join_recovers_by_pull_then_push_or_by_unbind` (src-tauri/src/team/sync.rs:12791); `a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind` (src-tauri/src/team/sync.rs:12951); `join_then_check_in_then_pull_on_the_first_device` (src-tauri/src/team/sync.rs:12649); `a_transition_that_does_not_verify_keeps_the_binding_quarantined` (src-tauri/src/team/sync.rs:9149); `a_leaf_head_is_accepted_only_as_a_new_head_is` (src-tauri/src/team/sync.rs:9580).

Observed test-output excerpts (S for sync, C for custody, D for schema; final new probes use N):

```text
test team::sync::tests::join_after_a_restore_pins_the_transition_leaf_then_pulls ... ok
test team::sync::tests::join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf ... ok
test team::sync::tests::join_refuses_the_rolled_back_child_of_the_leaf ... ok
test team::sync::tests::join_with_a_lying_first_snapshot_pins_nothing ... ok
test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok
test team::sync::tests::join_then_a_push_before_the_first_pull_restores_is_refused ... ok
test team::sync::tests::join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes ... ok
test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok
test team::sync::tests::a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind ... ok
test team::sync::tests::join_then_check_in_then_pull_on_the_first_device ... ok
test team::sync::tests::a_transition_that_does_not_verify_keeps_the_binding_quarantined ... ok
test team::sync::tests::a_leaf_head_is_accepted_only_as_a_new_head_is ... ok
```

No additional test was necessary for this property beyond the cited coverage and code-path inspection.

**New unit tests retained in the working copy**

The existing local `World`/fake-server, trust-ledger, `tree`, `marker`, and `counted_d` helpers are reused. These are verification additions to established test patterns, not a new feature implementation. The failing tests accept either a clean refusal or a successful recomputation from the remaining valid P; they reject any commit of the withdrawn source. No assertion was changed to match the defect.

`src-tauri/src/team/sync.rs:13036`

```rust
    #[test]
    fn independent_r3_open_run_restore_matches_an_ordinary_pull() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        let ordinary = d.path().join("ordinary");
        let open_run = d.path().join("open-run");
        for out in [&ordinary, &open_run] {
            std::fs::create_dir_all(out.join("Default")).unwrap();
            std::fs::write(out.join("Local State"), LOCAL_STATE).unwrap();
            std::fs::write(out.join("marker"), b"unsynced").unwrap();
            std::fs::write(out.join("Default/local-only"), b"unsynced edit").unwrap();
        }
        // Start both restores with the same complete device state. Windows
        // otherwise generates independent random os_crypt keys on first use.
        shardx_core::LocalCrypt::open(&ordinary).unwrap();
        std::fs::copy(ordinary.join("Local State"), open_run.join("Local State")).unwrap();
        w.fake().listed = Some((1, Some(heads[0])));
        w.pull(&ordinary).unwrap();
        w.db().conn.execute_batch(
            "UPDATE profile_bindings SET remote_version = 0, base_version = 0,
             last_observed_head_hash = NULL"
        ).unwrap();
        w.fake().listed = None;
        serve(&w, &author_pages_for(
            &w, T0 + 300 * DAY, Some(DeviceRevocationReason::Retired), false,
        ));
        let err = w.pull(&open_run).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"));
        revoked_at(&w, 1);
        assert_eq!(w.state(LOCAL).4, Some(heads[0].to_vec()));
        let relative = |root: &Path| {
            tree(root).into_iter().map(|(p, bytes)| {
                (p.strip_prefix(root).unwrap().to_path_buf(), bytes)
            }).collect::<Vec<_>>()
        };
        assert!(relative(&ordinary) == relative(&open_run),
            "the open-run exception must keep exactly what an ordinary pull keeps");
        assert_eq!(marker(&open_run), "v1");
        assert!(local_state_kept(&open_run));
        settled(&w, &open_run);
    }
```

`src-tauri/src/team/sync.rs:13082`

```rust
    #[test]
    fn independent_r3_revert_rechecks_its_source_after_download() {
        let w = world();
        let mut evidence = author_pages(&w, T0 + 300 * DAY, false, false);
        let rejected = committer(&w, &mut evidence, 0x20, T0 + 300 * DAY);
        let heads = chain_of(&w, &[&w.me.sk, &author(), &rejected]);
        serve(&w, &evidence);
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&rejected), NOW).unwrap();
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        w.fake().on_snapshot = Some(distrust_author());
        let result = w.revert(&out);
        assert!(w.fake().on_snapshot.is_none(), "source download hook executed");
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap());
        match result {
            Ok(pushed) => {
                assert_eq!(pushed.version, 4);
                assert_eq!(marker(&out), "v1",
                    "only v1 remains valid after the v2 source signer is withdrawn");
            }
            Err(_) => {
                assert_eq!(w.fake().version, 3, "a refusal commits nothing");
                assert!(tree(&out) == before, "a refusal preserves the local profile");
                assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
            }
        }
        settled(&w, &out);
    }
```

`src-tauri/src/team/sync.rs:13115`

```rust
    #[test]
    fn independent_r3_resumed_revert_rechecks_its_source() {
        let w = world();
        let mut evidence = author_pages(&w, T0 + 300 * DAY, false, false);
        let rejected = committer(&w, &mut evidence, 0x20, T0 + 300 * DAY);
        let heads = chain_of(&w, &[&w.me.sk, &author(), &rejected]);
        serve(&w, &evidence);
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&rejected), NOW).unwrap();
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        w.fake().skip.push("upload");
        w.revert(&out).unwrap_err();
        assert_eq!(w.fake().version, 3, "no R has landed");
        assert_eq!(marker(&beside(&out, ".revert-staging")), "v2");
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&author()), NOW).unwrap();
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap());
        match w.revert(&out) {
            Ok(pushed) => {
                assert_eq!(pushed.version, 4);
                let readback = d.path().join("readback");
                w.pull(&readback).unwrap();
                assert_eq!(marker(&readback), "v1",
                    "a resumed R must not publish a source already proven revoked before retry");
                assert_eq!(marker(&out), "v1");
            }
            Err(_) => {
                assert_eq!(w.fake().version, 3, "a refusal commits nothing");
                assert!(tree(&out) == before);
                assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
            }
        }
    }
```

`src-tauri/src/lib.rs:4823`

```rust
    #[test]
    fn independent_r3_a_truly_backdated_renewal_is_sticky_and_alerts_once() {
        let me = me();
        let (_dir, path) = counted_d(&me);
        let before = custodian(&path, &d_id());
        let renewal = d_root(&d_key(), 0x93, T0 + DAY / 2, LONG);
        let later = omitting(&me, vec![renewal.clone()]);
        let (_fresh_dir, fresh) = ledger_at();
        collect_at(&fresh, &later, &[], 1, T0 + 20 * DAY);
        assert!(custodian(&fresh, &d_id()).1 > before.1,
            "without revocation history this renewal extends the window");
        for day in [20, 21] {
            collect_at(&path, &later, &[], 1, T0 + day * DAY);
            assert_eq!(custodian(&path, &d_id()), before);
            assert_eq!(alerts(&path), [(
                "custodian.renewed_after_revocation".to_string(),
                hex(&d_id()), hash_of(&renewal), (T0 + 20 * DAY) as i64,
            )]);
        }
    }
```

**Verification limits and retained state**

This is source and unit-test verification on Windows against HEAD, including cryptographic fixtures, a loopback HTTP server, actual temporary SQLite transactions and filesystem swaps. It is not a packaged desktop GUI or deployed-server end-to-end run. Crash/swap and failure cases cited here use the repository's explicit injection points. The scoped conclusion is based on the observed paths and tests, not an exhaustive proof of all possible filesystem failures or thread interleavings.

The only intended working-copy changes are the four unit tests in `src-tauri/src/team/sync.rs` and `src-tauri/src/lib.rs`, plus this report. The implementation remains at the verified HEAD. D1 is unfixed so its reproductions remain reviewable.

VERDICT: FAIL

