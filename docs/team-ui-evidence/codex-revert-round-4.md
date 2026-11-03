**Independent verification: ADR 0002 rule-6 revert and Team join — round 4**

Verified HEAD: `5ac2fd15de1939f990728e1de0b244c35b03d6eb`.

Scope: `docs/adr/0002-g2-contract-decisions.md:1529` (Joining), `:1534` through `:1593` (revoked and lapsed signers, including Client status), and `:1493` (Sticky proven revocation). Evidence came from this worktree's implementation, test bodies and newly executed local tests. No authors' review reports, `.omc/`, `.omx/reports/`, or existing scratch directories were read. No commits, pushes, PRs, issues or external service calls were made. Cargo used offline dependency resolution; test network traffic used the tests' loopback servers. The API probe used the actual router in process, without a network listener. Tests used temporary configuration roots; the real launcher data directory and the real OS-credential-store test were not used.

**Result: FAIL.** Property 9 is violated through folder deletion and the local API's individual profile deletion. A second defect violates the in-scope Client status rule that a device with a withdrawn own key commits no R: a prepared but unprocessed COMMIT is sent after withdrawal. The other nine numbered properties hold in the inspected paths and executed cases, with the ADR's expressly stated exceptions below.

No production implementation was changed. Five new regression tests remain in the working copy: two pass and three fail. The three failing assertions expose two defects, because two tests cover separate deletion entry points with the same omitted cleanup. All 180 pre-existing sync tests passed; all 34 custody, 19 database and 6 ledger tests also passed.

**Contract interpretation**

- The open-run pull exception is required: a newer P may replace local unsynced edits and remain pinned while the call reports `sync.signerRevoked`. The existing comparison test checks the complete relative file trees against an ordinary successful pull of the same P, including Local State.
- The ADR at line 1553 expressly excepts an ordinary push's own committed head from the transactional signer recheck. Properties 2 and 4 below concern revert, pull and join; that documented ordinary-push exception is not misclassified as a defect.
- An older-epoch join leaf needs the signed restore transition. A profile created after the restore, or a profile at the initial epoch, uses ordinary first acceptance; it does not need a nonexistent restore transition.
- The ADR explicitly permits staging retention for an upload sealed under a still-held lease with no matching release pending, and for a committed pending swap. A merely retryable upload is not treated as an abandoned lease. Once a pin has committed, swap recovery is a committed operation, not a refused acceptance.
- A reader cannot prove that a different committer encrypted P's plaintext into R (`ADR:1565`). Property 3 verifies this client's committer path; the new test additionally decrypts the committed result through a separate enrolled configuration root.

**Test commands and outcomes**

Every invocation used the requested skip, including retries. No OS error 1455 occurred, so all runs used `-j 4`.

```powershell
$env:CARGO_NET_OFFLINE='true'
# C1
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync:: -- --skip a_real_os_store_key_survives_into_a_fresh_process
# C2
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib verifier_round4 -- --skip a_real_os_store_key_survives_into_a_fresh_process
# C3
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custody_tests:: -- --skip a_real_os_store_key_survives_into_a_fresh_process
# C4
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::db:: -- --skip a_real_os_store_key_survives_into_a_fresh_process
# C5
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::ledger:: -- --skip a_real_os_store_key_survives_into_a_fresh_process
```

- C1: `test result: FAILED. 180 passed; 1 failed; 0 ignored; 0 measured; 453 filtered out; finished in 879.66s` (exit 1).
- C2: `test result: FAILED. 2 passed; 3 failed; 0 ignored; 0 measured; 633 filtered out; finished in 7.12s` (exit 1).
- C3: `test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 604 filtered out; finished in 13.82s` (exit 0).
- C4: `test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 619 filtered out; finished in 5.94s` (exit 0).
- C5: `test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 632 filtered out; finished in 0.54s` (exit 0).

C1 contains the 180 existing sync tests plus the first added folder-deletion regression. C2 runs all five final added regressions. A first C2 attempt made while C1 was running failed before executing tests with `LINK : fatal error LNK1104`: Windows held the running test executable open. C2 was rerun after C1 exited; its actual test failures are shown above and below. This was an execution-order issue, not a product failure. Build-generated schema files were restored after testing; only the report and test additions remain.

**Test integrity**

I inspected the cited tests and their relevant fixture helpers, including the independent code/spec and architecture checks. There are no ignored tests, unconditional-success assertions or test-body early returns in the property coverage. The bare return in `sync.rs:5615` belongs to the fixture's deliberate unbound-enrollment branch, not to an assertion-skipping test. All executed runs report zero ignored tests. Existing tests were not modified or weakened.

The tests assert concrete pins, version numbers, hashes/audit resolution, quarantine reason, lease state, remote commit counts, file-tree equality, marker contents and staging absence. The backdated-renewal test at `lib.rs:4823` includes a fresh-ledger positive control proving the same renewal really extends custody without revocation history. The forged-renewal test covers both a wrong signature and an omitted public key. The source-withdrawal tests' success/error branches both assert the required outcome: a successful replacement must contain the remaining valid P; an error must commit nothing and preserve local files. They are not unconditional passes.

**Property 1. Revert acceptance requires an entirely proven-revoked run — HOLDS.**

`src-tauri/src/team/ledger.rs:1112` verifies the revocation signature, issuer custody and device.revoke scope at issuance, and custody at first sight; `ledger.rs:898` persists the count, and `ledger.rs:134` records local distrust in the same permanent key ledger. `src-tauri/src/team/sync.rs:4246` records evaluation before walking. `sync.rs:4073`, `4136`, and `4188` distinguish withdrawn, reported-only and untrusted/lapsed signers. `sync.rs:3999` permits only Withdrawn links in the run, checks hash/version continuity, and accepts a valid next head. `sync.rs:4219` refuses reported/lapsed interruptions and preserves the revoked quarantine.

Tests run and actual completion output (command IDs above):

```text
[C1] test team::sync::tests::revert_rule_accepts_one_proven_revoked_head ... ok
[C1] test team::sync::tests::revert_rule_accepts_two_stacked_proven_revoked_heads ... ok
[C1] test team::sync::tests::revert_rule_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
[C1] test team::sync::tests::revert_rule_refuses_a_reported_only_revocation ... ok
[C1] test team::sync::tests::revert_accepts_one_proven_revoked_head ... ok
[C1] test team::sync::tests::revert_accepts_two_stacked_proven_revoked_heads ... ok
[C1] test team::sync::tests::revert_accepts_on_a_new_device_without_a_pin ... ok
[C1] test team::sync::tests::revert_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
[C1] test team::sync::tests::revert_refuses_a_reported_only_revocation ... ok
[C1] test team::sync::tests::revert_refuses_a_reported_only_head_below_a_revoked_pin ... ok
[C1] test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lacked_device_revoke ... ok
[C1] test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight ... ok
[C1] test team::sync::tests::revert_accepts_after_forty_days_offline ... ok
[C1] test team::sync::tests::revert_accepts_after_a_current_custodian_refiles ... ok
[C1] test team::sync::tests::local_distrust_alone_enables_a_revert ... ok
```

New test: none needed for this property; the cited existing cases contain substantive assertions and passed.

**Property 2. No proven-revoked signer is newly pinned by revert, pull or join — HOLDS.**

`src-tauri/src/team/sync.rs:4208` adds revoked links to the skip run without pinning them. `sync.rs:4403` acquires an IMMEDIATE transaction and `4408` rechecks withdrawal before pinning a pulled head or P. Restore-leaf acceptance records the evaluation and rechecks the signer in the same transaction at `sync.rs:1265` / `1601`. A reverted R is checked on replay at `1844` and again after network readback inside the pin transaction at `3603` / `3607`. `ledger.rs:239` covers counted revocation and local distrust. The ADR expressly excepts an ordinary push's own already-committed head; that exception is not a revert/pull/join acceptance.

Tests run and actual completion output (command IDs above):

```text
[C1] test team::sync::tests::a_new_head_of_a_signer_revoked_in_this_pulls_evidence_is_refused ... ok
[C1] test team::sync::tests::a_pinned_head_of_a_since_revoked_signer_is_not_restored ... ok
[C1] test team::sync::tests::revert_skips_a_head_pinned_before_its_signer_was_proven_revoked ... ok
[C1] test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok
[C1] test team::sync::tests::a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok
[C1] test team::sync::tests::a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok
[C1] test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
[C2] test team::sync::tests::verifier_round4_open_run_anchor_withdrawn_during_download_is_not_pinned ... ok
```

New coverage: `verifier_round4_open_run_anchor_withdrawn_during_download_is_not_pinned` (`src-tauri/src/team/sync.rs:13278`). Full test code appears below.

**Property 3. A locally authored R carries the newest valid P — HOLDS.**

`src-tauri/src/team/sync.rs:4209` advances the anchor through valid heads. `sync.rs:2106` walks and requires both an open revoked run and P; `2146` reads P under its own generation; `2154` restores P into sibling staging; `2159` passes staging, not the live profile, to push_inner. `sync.rs:2972` packs that supplied directory. `sync.rs:1714` resolves the recorded source from the lowest open audit row; `1892` rechecks its withdrawal before COMMIT, including resumed uploads. Remote readers cannot prove plaintext provenance after re-encryption, as the ADR explicitly states at line 1565; this property is the committer-side guarantee.

Tests run and actual completion output (command IDs above):

```text
[C1] test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
[C1] test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok
[C1] test team::sync::tests::revert_commits_over_a_head_pinned_before_its_signer_was_proven_revoked ... ok
[C1] test team::sync::tests::revert_waits_for_rotation_after_a_compromised_revocation ... ok
[C1] test team::sync::tests::a_revert_audits_the_accepted_runs_it_crosses ... ok
[C1] test team::sync::tests::a_revert_never_commits_a_source_withdrawn_during_its_download ... ok
[C1] test team::sync::tests::a_resumed_revert_never_commits_a_source_withdrawn_before_its_retry ... ok
[C2] test team::sync::tests::verifier_round4_revert_uses_newest_valid_content_and_remote_readback ... ok
```

New coverage: `verifier_round4_revert_uses_newest_valid_content_and_remote_readback` (`src-tauri/src/team/sync.rs:13243`). Full test code appears below.

**Property 4. Refusal preserves the local profile; the specified open-run exception is equivalent to ordinary pull — HOLDS.**

`src-tauri/src/team/sync.rs:4465` restores only into staging and runs the pin callback before swapping. A restore/pin failure cleans staging at `4490`; the live profile remains untouched. `sync.rs:2013` / `2019` does the same for revert failure. `sync.rs:4610` files the open run, restores and pins a newer P via that same staged path, keeps quarantine and returns signerRevoked at `4634`. `sync.rs:4449` copies the device's Local State into staging. Withdrawal is judged inside the transaction at `4408` (pull/P), `1270` (leaf), and `3607` (R after readback). The open-run comparison test checks complete relative file trees against an ordinary successful pull, including unsynced files and Local State.

Tests run and actual completion output (command IDs above):

```text
[C1] test team::sync::tests::revert_is_refused_for_a_reported_only_revocation ... ok
[C1] test team::sync::tests::a_refused_revert_checkout_keeps_the_local_profile ... ok
[C1] test team::sync::tests::a_pull_whose_pin_fails_keeps_the_local_profile ... ok
[C1] test team::sync::tests::a_join_whose_pin_fails_keeps_the_local_profile ... ok
[C1] test team::sync::tests::an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok
[C1] test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok
[C1] test team::sync::tests::a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind ... ok
[C1] test team::sync::tests::a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok
[C1] test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
[C1] test team::sync::tests::an_open_run_restore_keeps_what_an_ordinary_pull_keeps ... ok
[C1] test team::sync::tests::a_pull_keeps_the_devices_local_state ... ok
[C2] test team::sync::tests::verifier_round4_open_run_anchor_withdrawn_during_download_is_not_pinned ... ok
```

New coverage: `verifier_round4_open_run_anchor_withdrawn_during_download_is_not_pinned` (`src-tauri/src/team/sync.rs:13278`). Full test code appears below.

**Property 5. Releasing or replaying a lease does not lift SIGNER_REVOKED — HOLDS.**

`src-tauri/src/team/sync.rs:3756` preserves quarantine while clearing the released lease. `sync.rs:4636` refuses to lift a revoked quarantine without an accepted R. `sync.rs:4415` clears it only when the caller supplies a nonempty accepted run (`4657`). Revert finish accepts audit rows and pin atomically at `3603` / `3625`, with withdrawal checked first; `1844` rejects an invalid replay. The lost-release path at `2074` replays release, then walks and restores P again. The success in a lost-COMMIT-reply replay is acceptance of a still-valid R, not release alone.

Tests run and actual completion output (command IDs above):

```text
[C1] test team::sync::tests::an_abandoned_revert_keeps_the_binding_quarantined ... ok
[C1] test team::sync::tests::an_ordinary_push_refuses_a_revert_lease_on_the_pinned_head ... ok
[C1] test team::sync::tests::revert_resumes_after_a_lost_release_of_an_abandoned_lease ... ok
[C1] test team::sync::tests::a_revert_lease_whose_run_was_closed_elsewhere_is_released ... ok
[C1] test team::sync::tests::a_reported_only_quarantine_stays_once_the_approval_is_hidden ... ok
[C1] test team::sync::tests::a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok
[C1] test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
[C1] test team::sync::tests::revert_resumes_after_a_lost_commit_reply ... ok
```

New test: none needed for this property; the cited existing cases contain substantive assertions and passed.

**Property 6. An accepted R installs P in the profile directory — HOLDS.**

`src-tauri/src/team/sync.rs:3640` writes the pending swap in the same transaction that pins R and resolves the skipped audit. The revert wrapper calls `settle_revert_swap` at `2015`, whose rename/recovery sequence is `1926`. Pulls stage and swap through `4465`. Pending swaps settle before later push (`1676`), pull (`4574`), revert (`2012`) or launch (`src-tauri/src/launch.rs:150`). Missing staging on a resumable upload triggers the walk and restore at `sync.rs:2103`.

Tests run and actual completion output (command IDs above):

```text
[C1] test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
[C1] test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok
[C1] test team::sync::tests::revert_resumes_after_a_lost_commit_reply ... ok
[C1] test team::sync::tests::a_crash_after_finish_completes_the_staging_swap ... ok
[C1] test team::sync::tests::a_crash_inside_the_staging_swap_resumes ... ok
[C1] test team::sync::tests::a_staging_dir_without_a_swap_row_is_never_swapped_in ... ok
[C1] test team::sync::tests::a_resumed_revert_whose_staging_is_gone_restores_p_again ... ok
[C1] test team::sync::tests::a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull ... ok
[C1] test team::sync::tests::a_revert_keeps_the_devices_local_state ... ok
[C2] test team::sync::tests::verifier_round4_revert_uses_newest_valid_content_and_remote_readback ... ok
```

New coverage: `verifier_round4_revert_uses_newest_valid_content_and_remote_readback` (`src-tauri/src/team/sync.rs:13243`). Full test code appears below.

**Property 7. Backdated self-renewal remains refused and produces one persistent alert per revoked key — HOLDS.**

`src-tauri/src/team/ledger.rs:159` prepares evidence before the trust-chain evaluation. `ledger.rs:283` loads permanent counted-evaluation cutoffs; `325` compares first-sighting evaluation, not issued_at; `338` raises the alert and `340` discards the newly seen record. `ledger.rs:296` restricts this alert to DEVICE_REVOCATION, not local distrust alone. `ledger.rs:405` inserts only if the per-key alert does not already exist. Schema 9 defines the composite primary key at `src-tauri/src/team/db.rs:1324` and prevents replace/delete/update at `1375`.

Tests run and actual completion output (command IDs above):

```text
[C3] test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok
[C3] test custody_tests::a_renewal_issued_before_the_count_is_sticky_and_alerts_once ... ok
[C3] test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok
[C3] test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok
[C3] test custody_tests::renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok
[C4] test team::db::tests::renewed_after_revocation_alerts_refuse_delete_and_replace ... ok
[C4] test team::db::tests::a_version_8_file_migrates_to_version_9_and_reopens ... ok
[C3] test custody_tests::a_counted_revocation_outlives_the_server_omitting_it ... ok
[C3] test custody_tests::revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok
[C3] test custody_tests::a_head_by_a_committer_a_sticky_revoked_key_appointed_is_refused ... ok
[C3] test custody_tests::records_first_seen_before_a_count_keep_their_standing ... ok
[C3] test custody_tests::limit_mutual_revocation_counts_both_on_a_new_device ... ok
[C3] test custody_tests::limit_a_new_device_counts_a_backdated_revocation_with_its_revoker ... ok
```

New test: none needed for this property; the cited existing cases contain substantive assertions and passed.

**Property 8. The alert requires a self-renewal verifying under the revoked key — HOLDS.**

`src-tauri/src/team/ledger.rs:73` maps public keys by their computed signing-key IDs. `ledger.rs:394` verifies the container under the revoked issuer's exact public key; a missing key or bad signature returns without an alert. `397` requires a root-key-grant payload; `400` requires a renewal of the issuer's own key and excludes FirstRootSelfGrant.

Tests run and actual completion output (command IDs above):

```text
[C3] test custody_tests::renewed_after_revocation_is_not_raised_for_a_forged_container ... ok
[C3] test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok
[C3] test custody_tests::a_renewal_issued_before_the_count_is_sticky_and_alerts_once ... ok
```

New test: none needed for this property; the cited existing cases contain substantive assertions and passed.

**Property 9. Decrypted P cleanup on refusal, abandonment, profile deletion and unbind — VIOLATED.**

Normal refusal/abandonment cleanup is `src-tauri/src/team/sync.rs:1971` / `2019`; a pending release for the held lease disables retention at `1981`, even if its reply was lost. The ADR's resumable-upload/pending-swap exceptions are preserved. Individual profile deletion cleans staging at `src-tauri/src/lib.rs:870` / `875`; production unbind settles and discards at `src-tauri/src/team/downgrade.rs:1248`. However folder deletion at `lib.rs:1145` calls `profile.rs:941`, which goes directly through `trash::move_to_trash` at `profile.rs:969` and `profile::delete` at `trash.rs:108`. The underlying delete at `profile.rs:769` removes only udd, leaving its sibling .revert-staging. See defect D1 and the new failing test. The local API also bypasses cleanup at `src-tauri/src/api.rs:698`; its folder endpoint shares the same folder-delete path at `api.rs:848`.

Tests run and actual completion output (command IDs above):

```text
[C1] test team::sync::tests::a_refused_revert_discards_its_staging ... ok
[C1] test team::sync::tests::an_abandoned_revert_lease_discards_its_staging ... ok
[C1] test team::sync::tests::an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok
[C1] test team::sync::tests::deleting_or_unbinding_a_profile_discards_its_revert_staging ... ok
[C1] test team::sync::tests::a_release_pending_for_another_lease_keeps_the_staging ... ok
[C1] test team::sync::tests::a_withdrawn_device_releases_its_revert_lease_on_the_server ... ok
[C2] test team::sync::tests::verifier_round4_folder_delete_discards_decrypted_revert_staging ... FAILED
[C2] test api::automation_endpoint_tests::verifier_round4_api_delete_discards_decrypted_revert_staging ... FAILED
```

New coverage: `verifier_round4_folder_delete_discards_decrypted_revert_staging` (`src-tauri/src/team/sync.rs:11718`); `verifier_round4_api_delete_discards_decrypted_revert_staging` (`src-tauri/src/api.rs:1693`). Full test code appears below.

**Property 10. Join proves a restore leaf, blocks premature check-in and retains recovery paths — HOLDS.**

`src-tauri/src/team/sync.rs:2415` chooses only the initial epoch; the unverified manifest never supplies an accepted pin. `2453` calls pull. `verify_transition` (`1305`) checks the custodian signature, identity, epoch and authority; `verify_proof` (`1446`) checks inclusion. A version-zero binding walks backward from the listed head at `1224`; `above_leaf` (`1407`) checks signatures, IDs, version links and epoch. The leaf receives first-acceptance authority checks at `1358` and transactional withdrawal checks at `1265`. `sync.rs:1807` detects base_version < remote_version; `2837` refuses fresh checkout, and `2881` releases a replayed one. `src-tauri/src/sync_cmd.rs:542` claims the profile through join, as push/revert/pull also do. Failed joins retain a binding that pull can resume or local unbind can remove. Profiles created after a restore use ordinary current-epoch acceptance; the restore-leaf requirement applies to the ADR's older-epoch exception.

Tests run and actual completion output (command IDs above):

```text
[C1] test team::sync::tests::join_binds_and_pulls_a_remote_profile_on_a_new_device ... ok
[C1] test team::sync::tests::join_after_a_restore_pins_the_transition_leaf_then_pulls ... ok
[C1] test team::sync::tests::join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf ... ok
[C1] test team::sync::tests::join_refuses_the_rolled_back_child_of_the_leaf ... ok
[C1] test team::sync::tests::join_of_a_profile_created_after_a_restore_starts_at_that_epoch ... ok
[C1] test team::sync::tests::join_with_a_lying_first_snapshot_pins_nothing ... ok
[C1] test team::sync::tests::join_then_a_push_before_the_first_pull_restores_is_refused ... ok
[C1] test team::sync::tests::join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes ... ok
[C1] test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok
[C1] test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok
[C1] test team::sync::tests::a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind ... ok
```

New test: none needed for this property; the cited existing cases contain substantive assertions and passed.

**Defect D1 — HIGH: deletion paths leave decrypted P in a sibling directory (property 9).**

Enforcing cleanup exists only in the individual UI command at `src-tauri/src/lib.rs:870` and `:875`. The following production routes bypass it:

- UI folder deletion: `src-tauri/src/lib.rs:1145` calls `src-tauri/src/profile.rs:941`; at `profile.rs:969` it goes directly to `trash::move_to_trash`, with `profile::delete` as the fallback at `:971`.
- API individual deletion: `src-tauri/src/api.rs:692`, specifically the direct trash call at `:698`.
- API folder deletion: `src-tauri/src/api.rs:848` uses the same affected folder implementation.

The common lower-level path is `src-tauri/src/trash.rs:108` → `src-tauri/src/profile.rs:762`. The latter deletes only the normal user-data directory at `:769`; it never removes the sibling `<user-data-dir>.revert-staging` or settles a pending revert swap.

Concrete scenario: a revert has staged decrypted P and is interrupted with a resumable upload, or otherwise leaves staging. The user deletes the containing folder with its profiles, or deletes the profile using the local API. The profile record and ordinary data directory are successfully deleted, but P remains as plaintext in the sibling staging directory. The new tests create the same on-disk staging condition with a sentinel, exercise the actual deletion entry points, first assert that deletion really succeeded, and then fail because staging still exists. They do not depend on a failed delete or on an artificial implementation bypass.

Observed output:

```text
folder deletion must remove the deleted profile's decrypted revert staging
API deletion must remove the deleted profile's decrypted revert staging
```

The existing `deleting_or_unbinding_a_profile_discards_its_revert_staging` passes because it exercises the UI's individual delete and the unbind wrapper, both of which have the cleanup. It does not cover these two bypasses. The repair should put pending-swap settlement and unconditional deletion-time staging cleanup in a shared deletion path used by all three routes; this verification leaves production code unchanged.

**Defect D2 — HIGH: a withdrawn device can send a prepared COMMIT that never landed.**

Locations: `src-tauri/src/team/sync.rs:2047` / `:2051` in `withdrawn_device`, and the READY branch at `:1892` / `:1904` in `push_inner`. The first allows continuation whenever a COMMIT row exists, even a pending one which the server never processed. The latter checks P's signer via `source_withdrawn`, but does not check the signing device's own withdrawal before sending that COMMIT. `finish` rejects the resulting R at `:3607` only after the server has committed it.

Concrete scenario exercised by `verifier_round4_withdrawn_committer_sends_no_prepared_revert`:

1. P is signed by a different, still-valid device; J is locally distrusted.
2. A revert seals R and prepares its COMMIT. The loopback fixture rejects the first request before routing/processing it (`sync.rs:5475`), leaving one pending COMMIT and the server at version 2.
3. This device locally distrusts its own signing key and retries the revert.
4. The retry sends the pending COMMIT; the fixture's count of actually applied commits changes from 2 to 3. Its commit handler advances the version and increments that counter only on a new commit (`sync.rs:5360` / `:5366`).
5. The client then returns an error, keeps its local pin at P and keeps local profile bytes unchanged. Those assertions pass before the test fails on the newly applied remote commit.

Observed output:

```text
assertion `left == right` failed: a withdrawn device must commit no new R
  left: 3
 right: 2
```

This violates the explicit Client status sentence at `docs/adr/0002-g2-contract-decisions.md:1553`: a device with its own signing key proven revoked or locally distrusted refuses the revert and commits nothing. It is an additional defect in the requested contract, separate from the ten numbered pin/content/cleanup assertions. It does not falsely imply that the withdrawn R was locally pinned: the test verifies that it was not. A pending request must be distinguished from an already-landed result when handling own-key withdrawal; replaying a genuinely lost committed reply must remain supported.

**New unit test code**

The following is the exact test code left in the working copy. It uses the repository's established temporary-store, loopback-server, fault-injection and in-process-router fixtures. No production paths were changed to make a probe fail or pass.

`src-tauri/src/team/sync.rs:11718` — FAILED (C2).

```rust
    #[test]
    fn verifier_round4_folder_delete_discards_decrypted_revert_staging() {
        let w = world();
        let _lifecycle = crate::profile::lifecycle_test_guard();
        let mut profile = crate::profile::StoredProfile::default();
        profile.meta.folder = "verifier-round4".into();
        crate::profile::save_raw(&mut profile).unwrap();
        let id = profile.meta.id;
        w.bind(&id, [0xc4; 16], 1, [9; 32]);
        let udd = crate::store::user_data_root().unwrap().join(&id);
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(udd.join("marker"), b"local").unwrap();
        let staging = beside(&udd, ".revert-staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("marker"), b"decrypted P").unwrap();

        assert_eq!(
            crate::folder_delete("verifier-round4".into(), true).unwrap(),
            1
        );
        assert!(!udd.exists(), "the profile data was deleted");
        assert!(
            crate::profile::load_raw(&id).is_err(),
            "the profile record was deleted"
        );
        assert!(
            !staging.exists(),
            "folder deletion must remove the deleted profile's decrypted revert staging"
        );
    }
```

`src-tauri/src/team/sync.rs:13243` — ok (C2).

```rust
    #[test]
    fn verifier_round4_revert_uses_newest_valid_content_and_remote_readback() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &w.me.sk, &author()]);
        serve(
            &w,
            &author_pages_for(
                &w,
                T0 + 300 * DAY,
                Some(DeviceRevocationReason::Retired),
                false,
            ),
        );
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"unsynced local").unwrap();
        assert_eq!(w.revert(&out).unwrap().version, 4);
        assert_eq!(
            marker(&out),
            "v2",
            "P must be the newest valid earlier snapshot"
        );
        let other = second(&w);
        let readback = other.path().join("readback");
        w.pull(&readback).unwrap();
        assert_eq!(
            marker(&readback),
            "v2",
            "the encrypted committed R also carries P"
        );
        settled(&w, &readback);
    }
```

`src-tauri/src/team/sync.rs:13278` — ok (C2).

```rust
    #[test]
    fn verifier_round4_open_run_anchor_withdrawn_during_download_is_not_pinned() {
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
        let err = w.pull(&out).unwrap_err();
        assert!(
            w.fake().on_snapshot.is_none(),
            "anchor download hook executed"
        );
        assert!(has(&err, "sync.signerRevoked"));
        revoked_at(&w, 1);
        assert_eq!(w.state(LOCAL).4, Some(heads[0].to_vec()));
        assert_eq!(tree(&out), before);
        settled(&w, &out);
    }
```

`src-tauri/src/team/sync.rs:13305` — FAILED (C2).

```rust
    #[test]
    fn verifier_round4_withdrawn_committer_sends_no_prepared_revert() {
        let w = world();
        let mut evidence = author_pages(&w, T0 + 300 * DAY, false, false);
        let rejected = committer(&w, &mut evidence, 0x20, T0 + 300 * DAY);
        let heads = chain_of(&w, &[&author(), &rejected]);
        serve(&w, &evidence);
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&rejected), NOW).unwrap();
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        w.fake().skip.push("commit");
        w.revert(&out).unwrap_err();
        assert_eq!(w.fake().version, 2, "R has not landed");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'COMMIT' AND state = 'PENDING'"),
            1
        );
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id, NOW).unwrap();
        let commits = w.fake().commits;
        let result = w.revert(&out);
        assert!(result.is_err(), "the withdrawn committer's revert is refused");
        assert_eq!(tree(&out), before);
        revoked_at(&w, 1);
        assert_eq!(
            w.fake().commits,
            commits,
            "a withdrawn device must commit no new R"
        );
        assert_eq!(w.fake().version, 2);
    }
```

`src-tauri/src/api.rs:1693` — FAILED (C2).

```rust
    #[tokio::test]
    async fn verifier_round4_api_delete_discards_decrypted_revert_staging() {
        let (_store, token, _lock) = scratch_store();
        let mut profile = crate::profile::StoredProfile::default();
        crate::profile::save_raw(&mut profile).unwrap();
        let id = profile.meta.id;
        let udd = crate::store::user_data_root().unwrap().join(&id);
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(udd.join("marker"), b"local").unwrap();
        let staging = crate::team::sync::beside(&udd, ".revert-staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("marker"), b"decrypted P").unwrap();
        let (status, body) = send(authed(
            "DELETE",
            &format!("/profiles/{id}"),
            &token,
            Value::Null,
        ))
        .await;
        let record_deleted = crate::profile::load_raw(&id).is_err();
        crate::store::set_config_root(None);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["deleted"], json!(true));
        assert!(record_deleted && !udd.exists(), "the profile was deleted");
        assert!(
            !staging.exists(),
            "API deletion must remove the deleted profile's decrypted revert staging"
        );
    }
```

**Execution transcript excerpts**

The completion lines and summaries below are verbatim. Repeated “running for over 60 seconds” notices (tests waiting on the shared configuration lock), dependency compilation chatter and package-lock waits are omitted. The assertion failure messages are quoted in defects D1 and D2 above.

**C1: `team::sync::`**

```text
running 181 tests
test team::sync::tests::a_blocked_publish_is_cancelled_by_its_command_and_stops_blocking_a_downgrade ... ok
test team::sync::tests::a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks ... ok
test team::sync::tests::a_compromise_counted_mid_transfer_aborts_the_upload ... ok
test team::sync::tests::a_crash_inside_the_staging_swap_resumes ... ok
test team::sync::tests::a_custodian_not_yet_appointed_signs_no_transition ... ok
test team::sync::tests::a_custodian_reappointed_after_its_lapse_signs_again ... ok
test team::sync::tests::a_binding_and_its_rows_name_the_servers_account_and_key ... ok
test team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key ... ok
test team::sync::tests::a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen ... ok
test team::sync::tests::a_device_clock_behind_the_server_still_binds_one_profile ... ok
test team::sync::tests::a_compromised_custodian_blocks_every_fleet_through_the_root ... ok
test team::sync::tests::a_failed_anchor_restore_keeps_the_quarantine_and_unresolved_rows ... ok
test team::sync::tests::a_custodian_distrusted_here_signs_no_transition ... ok
test team::sync::tests::a_failed_record_leaves_no_evaluation_and_keeps_the_refusal ... ok
test team::sync::tests::a_failed_release_of_an_old_lease_is_retried_as_stored ... ok
test team::sync::tests::a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code ... ok
test team::sync::tests::a_head_committed_on_top_does_not_strand_the_push ... ok
test team::sync::tests::a_head_met_again_after_an_unbind_reopens_its_row ... ok
test team::sync::tests::a_device_whose_own_key_is_withdrawn_sends_no_revert ... ok
test team::sync::tests::a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind ... ok
test team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte ... ok
test team::sync::tests::a_join_whose_pin_fails_keeps_the_local_profile ... ok
test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok
test team::sync::tests::a_binding_changed_during_acceptance_is_not_moved ... ok
test team::sync::tests::a_key_without_its_kept_record_asks_to_be_collected_again ... ok
test team::sync::tests::a_known_custodian_with_no_root_holding_blocks ... ok
test team::sync::tests::a_landed_commit_whose_reply_was_lost_replays_after_its_pin_signer_is_revoked ... ok
test team::sync::tests::a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept ... ok
test team::sync::tests::a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull ... ok
test team::sync::tests::a_crash_after_finish_completes_the_staging_swap ... ok
test team::sync::tests::a_lapse_seen_while_accepting_refuses_a_backdated_transition ... ok
test team::sync::tests::a_new_head_of_a_signer_revoked_in_this_pulls_evidence_is_refused ... ok
test team::sync::tests::a_head_whose_signer_may_not_commit_is_not_restored ... ok
test team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation ... ok
test team::sync::tests::a_new_head_from_an_earlier_epoch_is_a_rollback ... ok
test team::sync::tests::a_lease_from_before_the_restore_is_released_before_the_binding_moves ... ok
test team::sync::tests::a_key_the_checkout_does_not_name_is_never_used ... ok
test team::sync::tests::a_lease_at_risk_is_still_a_held_lease ... ok
test team::sync::tests::a_pinned_head_is_read_back_only_as_the_bindings_own ... ok
test team::sync::tests::a_lost_session_or_rate_limit_keeps_the_stored_request ... ok
test team::sync::tests::a_normal_push_still_refuses_a_quarantined_binding ... ok
test team::sync::tests::a_pinned_head_stays_readable_after_its_signers_grants_expire ... ok
test team::sync::tests::a_profile_is_published_with_its_first_lease_and_then_pushed ... ok
test team::sync::tests::a_profile_published_after_a_restore_starts_at_the_servers_epoch ... ok
test team::sync::tests::a_missing_or_withdrawn_fleet_key_is_refused ... ok
test team::sync::tests::a_failure_inside_a_run_writes_no_unresolved_rows ... ok
test team::sync::tests::a_publish_replayed_after_its_lease_ended_binds_the_one_profile ... ok
test team::sync::tests::a_lapsed_or_former_custodian_signs_no_transition ... ok
test team::sync::tests::a_publish_whose_operation_was_cancelled_meanwhile_binds_nothing ... ok
test team::sync::tests::a_pinned_head_of_a_since_revoked_signer_is_not_restored ... ok
test team::sync::tests::a_published_profile_pushes_and_another_device_pulls_it ... ok
test team::sync::tests::a_receipt_or_readback_that_does_not_match_is_never_kept ... ok
test team::sync::tests::a_push_behind_the_listed_head_is_refused ... ok
test team::sync::tests::a_pull_whose_pin_fails_keeps_the_local_profile ... ok
test team::sync::tests::a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok
test team::sync::tests::a_pull_keeps_the_devices_local_state ... ok
test team::sync::tests::a_refused_or_mismatched_reply_is_never_kept ... ok
test team::sync::tests::a_refused_publish_is_not_replayed_and_the_next_one_starts_afresh ... ok
test team::sync::tests::a_refused_revert_checkout_keeps_the_local_profile ... ok
test team::sync::tests::a_refused_revert_discards_its_staging ... ok
test team::sync::tests::a_release_pending_for_another_lease_keeps_the_staging ... ok
test team::sync::tests::a_lease_expiry_outside_the_ttl_is_refused_by_name ... ok
test team::sync::tests::a_kept_revocation_reloads_with_every_column_equal ... ok
test team::sync::tests::a_report_of_a_revoked_signer_a_pull_saw_is_kept ... ok
test team::sync::tests::a_reply_too_large_to_hold_is_refused ... ok
test team::sync::tests::a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok
test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
test team::sync::tests::a_pull_crossing_an_accepted_run_into_another_keeps_the_quarantine ... ok
test team::sync::tests::a_renewed_lease_moves_the_bindings_expiry_forward ... ok
test team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte ... ok
test team::sync::tests::a_pull_waits_for_a_push_in_flight ... ok
test team::sync::tests::a_reported_only_quarantine_stays_once_the_approval_is_hidden ... ok
test team::sync::tests::a_restore_epoch_that_goes_back_is_a_rollback ... ok
test team::sync::tests::a_resumed_revert_never_commits_a_source_withdrawn_before_its_retry ... ok
test team::sync::tests::a_resumed_revert_whose_staging_is_gone_restores_p_again ... ok
test team::sync::tests::a_retried_revert_files_each_accepted_run_once ... ok
test team::sync::tests::a_revert_audits_the_accepted_runs_it_crosses ... ok
test team::sync::tests::a_replayed_checkout_on_an_old_head_is_released_and_taken_again ... ok
test team::sync::tests::a_revert_keeps_the_devices_local_state ... ok
test team::sync::tests::a_revert_lease_held_over_a_rollback_is_released ... ok
test team::sync::tests::a_revert_lease_whose_walk_fails_is_released_on_the_server ... ok
test team::sync::tests::a_revert_never_commits_a_source_withdrawn_during_its_download ... ok
test team::sync::tests::a_publish_is_bound_whatever_its_lease_expiry_says ... ok
test team::sync::tests::a_staging_dir_without_a_swap_row_is_never_swapped_in ... ok
test team::sync::tests::a_stored_finalize_is_not_sent_once_a_compromise_is_counted ... ok
test team::sync::tests::a_stored_publish_goes_out_while_its_key_holds ... ok
test team::sync::tests::a_revert_lease_whose_run_was_closed_elsewhere_is_released ... ok
test team::sync::tests::a_publish_at_a_restore_epoch_never_waits_on_its_acceptance ... ok
test team::sync::tests::a_swap_row_for_a_deleted_profile_is_cleared ... ok
test team::sync::tests::a_revocation_recorded_after_checkout_abandons_an_ordinary_push ... ok
test team::sync::tests::a_leaf_head_is_accepted_only_as_a_new_head_is ... ok
test team::sync::tests::a_server_integer_past_the_signed_range_is_refused_before_any_row ... ok
test team::sync::tests::a_verified_transition_moves_only_the_bindings_it_covers ... ok
test team::sync::tests::a_stored_publish_is_not_sent_once_its_key_is_blocked_or_withdrawn ... ok
test team::sync::tests::a_withdrawn_device_releases_its_revert_lease_on_the_server ... ok
test team::sync::tests::an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok
test team::sync::tests::an_exposure_survives_a_recollection_that_omits_its_grant ... ok
test team::sync::tests::an_interrupted_upload_resumes_at_the_offset_head_reports ... ok
test team::sync::tests::an_open_run_restore_keeps_what_an_ordinary_pull_keeps ... ok
test team::sync::tests::an_open_upload_is_aborted_once_a_compromise_is_counted ... ok
test team::sync::tests::an_ordinary_push_refuses_a_revert_lease_on_the_pinned_head ... ok
test team::sync::tests::a_publish_reply_that_does_not_name_the_request_is_never_kept ... ok
test team::sync::tests::a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh ... ok
test team::sync::tests::an_ordinary_push_refuses_over_a_pinned_head_whose_signer_is_proven_revoked ... ok
test team::sync::tests::an_abandoned_revert_lease_discards_its_staging ... ok
test team::sync::tests::a_rolled_back_head_or_epoch_quarantines_the_binding ... ok
test team::sync::tests::an_unbind_after_an_accepted_transition_keeps_its_evidence ... ok
test team::sync::tests::an_unbind_at_version_zero_omits_the_head ... ok
test team::sync::tests::an_unbind_is_refused_while_a_lease_request_or_journal_is_open ... ok
test team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly ... ok
test team::sync::tests::an_unreadable_release_reply_is_reported_and_replayed ... ok
test team::sync::tests::deleting_or_unbinding_a_profile_discards_its_revert_staging ... ok
test team::sync::tests::a_publish_that_cannot_be_trusted_stores_and_sends_nothing ... ok
test team::sync::tests::an_abandoned_revert_keeps_the_binding_quarantined ... ok
test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok
test team::sync::tests::join_lists_fleet_profiles_with_their_opened_labels_and_marks_bound_ones ... ok
test team::sync::tests::join_binds_and_pulls_a_remote_profile_on_a_new_device ... ok
test team::sync::tests::join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf ... ok
test team::sync::tests::join_after_a_restore_pins_the_transition_leaf_then_pulls ... ok
test team::sync::tests::join_of_a_profile_created_after_a_restore_starts_at_that_epoch ... ok
test team::sync::tests::join_refuses_a_bound_or_running_local_profile ... ok
test team::sync::tests::join_refuses_a_local_profile_with_an_unfinished_publish ... ok
test team::sync::tests::join_refuses_a_remote_profile_already_bound_here ... ok
test team::sync::tests::join_refuses_a_remote_profile_bound_here_meanwhile ... ok
test team::sync::tests::a_stored_publish_that_drifts_from_its_bytes_is_never_sent ... ok
test team::sync::tests::join_refuses_the_rolled_back_child_of_the_leaf ... ok
test team::sync::tests::join_refuses_without_the_collected_fleet_key_and_creates_no_binding ... ok
test team::sync::tests::join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes ... ok
test team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes ... ok
test team::sync::tests::join_then_check_in_then_pull_on_the_first_device ... ok
test team::sync::tests::an_unsent_cancel_release_is_retried_and_then_given_up ... ok
test team::sync::tests::local_distrust_alone_enables_a_revert ... ok
test team::sync::tests::revert_accepts_after_a_current_custodian_refiles ... ok
test team::sync::tests::join_then_a_push_before_the_first_pull_restores_is_refused ... ok
test team::sync::tests::revert_accepts_after_forty_days_offline ... ok
test team::sync::tests::revert_accepts_a_revocation_another_device_filed ... ok
test team::sync::tests::only_a_signer_revoked_quarantine_lets_a_pull_through ... ok
test team::sync::tests::revert_accepts_a_head_both_proven_and_reported ... ok
test team::sync::tests::join_with_a_lying_first_snapshot_pins_nothing ... ok
test team::sync::tests::revert_accepts_one_proven_revoked_head ... ok
test team::sync::tests::revert_accepts_on_a_new_device_without_a_pin ... ok
test team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes ... ok
test team::sync::tests::an_unbind_cut_off_at_any_write_leaves_the_binding_whole ... ok
test team::sync::tests::revert_accepts_two_stacked_proven_revoked_heads ... ok
test team::sync::tests::revert_advances_the_pin_over_a_valid_head_first ... ok
test team::sync::tests::revert_commits_over_a_head_pinned_before_its_signer_was_proven_revoked ... ok
test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
test team::sync::tests::revert_rule_accepts_a_head_both_proven_and_reported ... ok
test team::sync::tests::revert_rule_accepts_on_a_new_device_without_a_pin ... ok
test team::sync::tests::revert_rule_accepts_one_proven_revoked_head ... ok
test team::sync::tests::revert_rule_accepts_two_stacked_proven_revoked_heads ... ok
test team::sync::tests::revert_rule_advances_the_pin_over_a_valid_head_first ... ok
test team::sync::tests::revert_rule_refuses_a_gap_below_the_pin ... ok
test team::sync::tests::revert_rule_refuses_a_reported_only_revocation ... ok
test team::sync::tests::revert_rule_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok
test team::sync::tests::revert_is_refused_for_a_reported_only_revocation ... ok
test team::sync::tests::revert_refuses_a_gap_below_the_pin ... ok
test team::sync::tests::revert_refuses_a_reported_only_head_below_a_revoked_pin ... ok
test team::sync::tests::revert_refuses_a_reported_only_revocation ... ok
test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lacked_device_revoke ... ok
test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight ... ok
test team::sync::tests::revert_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
test team::sync::tests::revert_refuses_without_a_valid_earlier_snapshot ... ok
test team::sync::tests::revert_restores_an_anchor_of_an_older_generation_after_rotation ... ok
test team::sync::tests::revert_resumes_after_a_lost_commit_reply ... ok
test team::sync::tests::revert_resumes_after_a_lost_release_of_an_abandoned_lease ... ok
test team::sync::tests::revert_skips_a_head_pinned_before_its_signer_was_proven_revoked ... ok
test team::sync::tests::revert_waits_for_rotation_after_a_compromised_revocation ... ok
test team::sync::tests::statuses_without_a_database_are_empty_and_create_nothing ... ok
test team::sync::tests::statuses_report_renewed_after_revocation_alerts ... ok
test team::sync::tests::the_launch_settle_needs_a_team_database_only_when_one_exists ... ok
test team::sync::tests::verifier_round4_folder_delete_discards_decrypted_revert_staging ... FAILED
test team::sync::tests::a_tombstone_that_no_longer_recomputes_is_never_returned ... ok
test team::sync::tests::stale_unresolved_rows_are_superseded_once_by_a_transition_or_unbind ... ok
test team::sync::tests::statuses_flag_a_revert_in_progress ... ok
test team::sync::tests::statuses_offer_revert_for_any_unresolved_proven_run ... ok
test team::sync::tests::the_leaf_head_search_is_bounded_and_skipped_for_an_unchanged_pin ... ok
test team::sync::tests::a_transition_that_does_not_verify_keeps_the_binding_quarantined ... ok
test team::sync::tests::statuses_map_each_binding_state ... ok
test team::sync::tests::a_stored_column_that_drifts_from_its_bytes_is_never_sent ... ok
test result: FAILED. 180 passed; 1 failed; 0 ignored; 0 measured; 453 filtered out; finished in 879.66s
```

**C2: `verifier_round4`**

```text
running 5 tests
test team::sync::tests::verifier_round4_folder_delete_discards_decrypted_revert_staging ... FAILED
test team::sync::tests::verifier_round4_open_run_anchor_withdrawn_during_download_is_not_pinned ... ok
test team::sync::tests::verifier_round4_revert_uses_newest_valid_content_and_remote_readback ... ok
test team::sync::tests::verifier_round4_withdrawn_committer_sends_no_prepared_revert ... FAILED
test api::automation_endpoint_tests::verifier_round4_api_delete_discards_decrypted_revert_staging ... FAILED
test result: FAILED. 2 passed; 3 failed; 0 ignored; 0 measured; 633 filtered out; finished in 7.12s
```

**C3: `custody_tests::`**

```text
running 34 tests
test custody_tests::a_fleet_descriptor_counts_only_for_this_device_and_generation ... ok
test custody_tests::a_collected_fleet_key_is_never_replaced ... ok
test custody_tests::a_server_delivered_fleet_key_is_counted_but_never_cached ... ok
test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok
test custody_tests::a_key_is_used_only_while_its_kept_record_reloads_exactly ... ok
test custody_tests::a_head_by_a_committer_a_sticky_revoked_key_appointed_is_refused ... ok
test custody_tests::a_server_cannot_lapse_a_custodian_or_age_its_key_for_good ... ok
test custody_tests::a_renewal_issued_before_the_count_is_sticky_and_alerts_once ... ok
test custody_tests::only_the_bootstrapped_device_has_a_pinned_anchor ... ok
test custody_tests::limit_a_new_device_counts_a_backdated_revocation_with_its_revoker ... ok
test custody_tests::limit_a_backdated_grant_from_a_never_counted_custodian_is_accepted ... ok
test custody_tests::a_fleet_generation_never_goes_back ... ok
test custody_tests::limit_mutual_revocation_counts_both_on_a_new_device ... ok
test custody_tests::a_kept_grant_is_reverified_before_its_key_is_used ... ok
test custody_tests::a_lapse_is_the_known_end_of_custody_clipped_at_the_key_age ... ok
test custody_tests::an_omitted_first_root_grant_never_stretches_the_key_age_with_history ... ok
test custody_tests::a_counted_revocation_outlives_the_server_omitting_it ... ok
test custody_tests::reverifying_a_kept_key_records_the_lapse_history_shows ... ok
test custody_tests::a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok
test custody_tests::local_distrust_ignores_what_is_first_seen_after_it ... ok
test custody_tests::a_lapsed_custodians_backdated_grant_is_refused_with_history ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_forged_container ... ok
test custody_tests::the_pinned_anchor_never_changes ... ok
test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok
test custody_tests::revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok
test custody_tests::records_first_seen_before_a_count_keep_their_standing ... ok
test custody_tests::a_verified_fleet_grant_opens_and_nothing_else_does ... ok
test custody_tests::pull_uses_a_verified_key_only_while_its_issuer_stands ... ok
test custody_tests::a_reported_revocation_outlives_the_server_omitting_it ... ok
test custody_tests::a_revocation_counts_only_from_a_custodian_allowed_to_revoke ... ok
test custody_tests::a_lapse_from_history_refuses_a_backdated_grant_with_no_evaluation_between ... ok
test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 604 filtered out; finished in 13.82s
```

**C4: `team::db::`**

```text
running 19 tests
test team::db::tests::an_unexpected_version_1_file_is_not_migrated ... ok
test team::db::tests::a_version_5_upload_session_without_its_commit_operation_refuses_the_file ... ok
test team::db::tests::a_database_held_in_wal_mode_is_refused ... ok
test team::db::tests::renewed_after_revocation_alerts_refuse_delete_and_replace ... ok
test team::db::tests::skipped_heads_refuse_delete_replace_and_a_second_resolution ... ok
test team::db::tests::a_new_database_reopens_with_its_schema_and_settings ... ok
test team::db::tests::journals_and_epoch_proofs_keep_their_constraints_across_a_reopen ... ok
test team::db::tests::an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key ... ok
test team::db::tests::a_version_1_file_migrates_to_version_5_and_reopens ... ok
test team::db::tests::every_sync_integer_class_keeps_its_range_across_a_reopen ... ok
test team::db::tests::a_version_8_file_migrates_to_version_9_and_reopens ... ok
test team::db::tests::a_version_2_file_migrates_to_version_5_or_is_left_as_it_was ... ok
test team::db::tests::the_triggers_and_indexes_of_a_version_5_file_survive_version_6 ... ok
test team::db::tests::an_unknown_schema_fails_closed_and_is_left_as_it_was ... ok
test team::db::tests::a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding ... ok
test team::db::tests::the_ledger_never_takes_back_what_it_learned ... ok
test team::db::tests::a_version_3_file_migrates_to_version_6_or_is_left_as_it_was ... ok
test team::db::tests::a_version_8_file_with_another_min_reader_is_not_migrated ... ok
test team::db::tests::a_version_5_file_with_data_moves_to_version_6_keeping_every_row ... ok
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 619 filtered out; finished in 5.94s
```

**C5: `team::ledger::`**

```text
running 6 tests
test team::ledger::tests::holdings_name_every_issuer_and_subject_of_a_key_carrying_grant ... ok
test team::ledger::tests::a_version_6_file_files_the_holdings_of_its_kept_evidence ... ok
test team::ledger::tests::a_second_origin_of_the_instance_files_a_new_generation ... ok
test team::ledger::tests::a_lapsed_key_counts_only_after_its_observed_lapse ... ok
test team::ledger::tests::a_version_6_file_with_unreadable_kept_pages_still_opens ... ok
test team::ledger::tests::a_filed_grant_files_the_key_state_it_names ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 632 filtered out; finished in 0.54s
```

The implementation defects were reproduced without modifying production code. The failing tests remain enabled for the authors to fix against.

VERDICT: FAIL
