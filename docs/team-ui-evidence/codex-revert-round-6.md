**Independent verification — ADR 0002 rule 6 and Team join, round 6**

Verified HEAD: `a4332d7654d07086fdf7ee2e283d632542a8343b`.

Worktree: `<verify-worktree>`. The initial worktree was clean. Production code remains at that HEAD; the only source changes are the two additional unit tests reproduced below.

Contract read: `docs/adr/0002-g2-contract-decisions.md:1493` (sticky proven revocation), `:1529` (Joining), and `:1534` through the end of the Lapsed signer bullet. Findings are based on repository source, the contract and locally executed tests. No authors' review reports, `.omc/`, `.omx/reports/`, or scratch directories were consulted. No commit, push, PR or issue was created. No external service was contacted; sync tests start their own loopback server. Test fixtures use temporary config/data roots; the real launcher AppData directory and the real-OS-credential-store test were not used.

**Execution evidence**

All commands used the required form, including the explicit credential-store exclusion:

```text
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
test result: ok. 188 passed; 0 failed; 0 ignored; 0 measured; 455 filtered out; finished in 325.00s

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib round6_ -- --skip a_real_os_store_key_survives_into_a_fresh_process
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 643 filtered out; finished in 4.19s

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custody_tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 611 filtered out; finished in 8.84s

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::db::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 626 filtered out; finished in 4.03s

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib api_delete_discards_decrypted_revert_staging -- --skip a_real_os_store_key_survives_into_a_fresh_process
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 644 filtered out; finished in 0.01s
```

244 tests passed across these five successful runs. The first run executed the 188 existing sync tests before the two new probes were compiled; the second run compiled and executed both added probes against unchanged production code.

One earlier attempt at the custody command failed at linking while the first sync test executable was still running on Windows:

```text
error: linking with `link.exe` failed: exit code: 1104
LINK : fatal error LNK1104: cannot open file '...\src-tauri\target\debug\deps\shardx_launcher_lib-75db4031ddb60a97.exe'
error: could not compile `shardx-launcher` (lib test) due to 1 previous error
```

That attempt ran no custody tests. After the running suite exited, compilation and the custody rerun succeeded as recorded above. No OS error 1455 occurred, so no -j 1 fallback was needed. Build-generated schema files had only line-ending changes and were restored; `git diff --check` passed.

**Assertion review**

I read the cited test bodies and their fixture helpers, including the actual binding/audit queries, tree comparisons, fake-server hooks and failure injections. No cited test has an ignore attribute, empty assertion or early success return. A source scan of all test functions in sync.rs, ledger.rs, db.rs and lib.rs found no explicit ignore attributes and no test-body early-return/constant-true candidates; the API deletion test was checked separately. The fixture's early return for an intentionally unbound world is setup, not a skipped test assertion.

The source-withdrawal tests allow either a refusal preserving local data or a successful rebuild from the still-valid earlier P; both branches contain assertions and both are permitted outcomes. The older replay test ignores the returned Result but asserts the relevant quarantine, pin and content invariants; the newer readback tests additionally assert the exact failure code and that the withdrawal hook ran. The added probes extend coverage without changing any existing assertion.

**Property 1 — Only proven-revoked runs enable R: HOLDS**

Enforcing code: `src-tauri/src/team/ledger.rs:273`, `src-tauri/src/team/ledger.rs:830`, `src-tauri/src/team/ledger.rs:1115`; `src-tauri/src/team/sync.rs:4037`, `src-tauri/src/team/sync.rs:4094`, `src-tauri/src/team/sync.rs:4225`, `src-tauri/src/team/sync.rs:4275`, `src-tauri/src/team/sync.rs:2144`.

The ledger counts a signed revocation only after signature, binding, subject-device approval, issuer custody, scoped device.revoke and first-sight custody checks. Local distrust uses the same withdrawn-key lookup. The walk verifies signatures, identifiers, epochs, exact previous hashes and consecutive versions. Only Standing::Withdrawn enters a run; Reported and Untrusted refuse. A refusal inside a run retains SIGNER_REVOKED. The committer requires an open run plus P before checkout.

| Test definition | Captured output |
| --- | --- |
| `src-tauri/src/team/sync.rs:10646` | `test team::sync::tests::revert_accepts_one_proven_revoked_head ... ok` |
| `src-tauri/src/team/sync.rs:10660` | `test team::sync::tests::revert_accepts_two_stacked_proven_revoked_heads ... ok` |
| `src-tauri/src/team/sync.rs:10675` | `test team::sync::tests::revert_accepts_on_a_new_device_without_a_pin ... ok` |
| `src-tauri/src/team/sync.rs:10686` | `test team::sync::tests::revert_refuses_a_run_with_a_lapsed_unrevoked_head ... ok` |
| `src-tauri/src/team/sync.rs:10847` | `test team::sync::tests::revert_refuses_a_reported_only_revocation ... ok` |
| `src-tauri/src/team/sync.rs:10705` | `test team::sync::tests::a_failure_inside_a_run_writes_no_unresolved_rows ... ok` |
| `src-tauri/src/team/sync.rs:10875` | `test team::sync::tests::revert_refuses_a_reported_only_head_below_a_revoked_pin ... ok` |
| `src-tauri/src/team/sync.rs:10955` | `test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lacked_device_revoke ... ok` |
| `src-tauri/src/team/sync.rs:10967` | `test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight ... ok` |
| `src-tauri/src/team/sync.rs:13531` | `test team::sync::tests::a_revocation_naming_another_device_never_enables_a_skip ... ok` |
| `src-tauri/src/team/sync.rs:12998` | `test team::sync::tests::local_distrust_alone_enables_a_revert ... ok` |

**Property 2 — Rejected heads are never newly pinned: HOLDS**

Enforcing code: `src-tauri/src/team/sync.rs:4245`, `src-tauri/src/team/sync.rs:4430`, `src-tauri/src/team/sync.rs:1262`, `src-tauri/src/team/sync.rs:1474`, `src-tauri/src/team/sync.rs:3640`; `src-tauri/src/team/ledger.rs:239`.

The walk keeps rejected links in memory/audit and passes only an accepted anchor to pin. Pull pinning and R completion acquire an IMMEDIATE transaction and re-read withdrawal state. Restore-transition acceptance records its evidence inside the transaction, then checks the leaf signer; a failing check rolls the tentative UPDATE back. This follows the ADR's explicit scope: ordinary push pins its own committed head and detects withdrawal at the next operation. An already pinned head can also become revoked later; that historical pin is not a new acceptance. The new probe observes every committed remote_version change across two rejected heads, closing the gap in tests that inspected only the final pin.

| Test definition | Captured output |
| --- | --- |
| `src-tauri/src/team/sync.rs:10660` | `test team::sync::tests::revert_accepts_two_stacked_proven_revoked_heads ... ok` |
| `src-tauri/src/team/sync.rs:12846` | `test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok` |
| `src-tauri/src/team/sync.rs:13155` | `test team::sync::tests::a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok` |
| `src-tauri/src/team/sync.rs:13391` | `test team::sync::tests::an_open_run_anchor_withdrawn_during_download_is_not_pinned ... ok` |
| `src-tauri/src/team/sync.rs:13597` | `test team::sync::tests::join_never_pins_a_leaf_withdrawn_during_the_proof_fetch ... ok` |
| `src-tauri/src/team/sync.rs:13620` | `test team::sync::tests::revert_never_pins_an_r_withdrawn_during_the_readback ... ok` |
| `src-tauri/src/team/sync.rs:13648` | `test team::sync::tests::round6_a_stacked_run_never_temporarily_pins_a_rejected_head ... ok` |

**Property 3 — The committer seals P, never J or unsynced local content: HOLDS**

Enforcing code: `src-tauri/src/team/sync.rs:4094`, `src-tauri/src/team/sync.rs:2144`, `src-tauri/src/team/sync.rs:2184`, `src-tauri/src/team/sync.rs:2192`, `src-tauri/src/team/sync.rs:2197`, `src-tauri/src/team/sync.rs:1714`, `src-tauri/src/team/sync.rs:1895`, `src-tauri/src/team/sync.rs:2988`.

The forward/backward walk selects the newest valid earlier anchor. Revert restores that anchor through its own generation's readable key into a sibling staging directory and passes that directory to push_inner/seal_snapshot. Before COMMIT, source_withdrawn re-reads the audit's original P and checks its signer; a withdrawn source abandons the prepared upload while Jn remains listed. Resumed uploads whose staging is missing walk and restore again. The second-device readback test checks encrypted R actually contains v2 when P=v2, J=v3, and local data differs. As the ADR states, readers cannot prove another committer used P because re-encryption hides content provenance; this verdict concerns the implemented committer.

| Test definition | Captured output |
| --- | --- |
| `src-tauri/src/team/sync.rs:11315` | `test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok` |
| `src-tauri/src/team/sync.rs:13356` | `test team::sync::tests::a_revert_uses_the_newest_valid_content_and_reads_back_remotely ... ok` |
| `src-tauri/src/team/sync.rs:13273` | `test team::sync::tests::a_revert_never_commits_a_source_withdrawn_during_its_download ... ok` |
| `src-tauri/src/team/sync.rs:13315` | `test team::sync::tests::a_resumed_revert_never_commits_a_source_withdrawn_before_its_retry ... ok` |
| `src-tauri/src/team/sync.rs:13058` | `test team::sync::tests::a_resumed_revert_whose_staging_is_gone_restores_p_again ... ok` |
| `src-tauri/src/team/sync.rs:11064` | `test team::sync::tests::revert_restores_an_anchor_of_an_older_generation_after_rotation ... ok` |

**Property 4 — Failures preserve local data; the open-run restore has ordinary-pull semantics: HOLDS**

Enforcing code: `src-tauri/src/team/sync.rs:4487`, `src-tauri/src/team/sync.rs:4503`, `src-tauri/src/team/sync.rs:4430`, `src-tauri/src/team/sync.rs:3640`, `src-tauri/src/team/sync.rs:4647`, `src-tauri/src/team/sync.rs:1262`, `src-tauri/src/team/sync.rs:2040`.

Download/unpack targets staging. The profile swap follows a successful pin plus revert_swaps transaction, so download failures, pin-write failures and signer withdrawal during network awaits preserve the original tree. IMMEDIATE transactions serialize other ledger writers through pin commit. The intentional open-run path records quarantine, restores/pins a newer P, keeps the audit open, and returns sync.signerRevoked. Its tree is compared byte-for-byte with an ordinary pull from identical local state, including Local State/os_crypt preservation. The new R pin-write-failure probe covers server COMMIT success followed by local transaction failure, then a successful retry without a second server version.

| Test definition | Captured output |
| --- | --- |
| `src-tauri/src/team/sync.rs:11549` | `test team::sync::tests::a_refused_revert_checkout_keeps_the_local_profile ... ok` |
| `src-tauri/src/team/sync.rs:12910` | `test team::sync::tests::a_pull_whose_pin_fails_keeps_the_local_profile ... ok` |
| `src-tauri/src/team/sync.rs:12929` | `test team::sync::tests::a_join_whose_pin_fails_keeps_the_local_profile ... ok` |
| `src-tauri/src/team/sync.rs:12970` | `test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok` |
| `src-tauri/src/team/sync.rs:13155` | `test team::sync::tests::a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok` |
| `src-tauri/src/team/sync.rs:13391` | `test team::sync::tests::an_open_run_anchor_withdrawn_during_download_is_not_pinned ... ok` |
| `src-tauri/src/team/sync.rs:13179` | `test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok` |
| `src-tauri/src/team/sync.rs:13215` | `test team::sync::tests::an_open_run_restore_keeps_what_an_ordinary_pull_keeps ... ok` |
| `src-tauri/src/team/sync.rs:13026` | `test team::sync::tests::a_pull_keeps_the_devices_local_state ... ok` |
| `src-tauri/src/team/sync.rs:13685` | `test team::sync::tests::round6_a_revert_pin_failure_preserves_local_data_and_retries ... ok` |

**Property 5 — Lease abandonment and replay do not clear SIGNER_REVOKED: HOLDS**

Enforcing code: `src-tauri/src/team/sync.rs:3796`, `src-tauri/src/team/sync.rs:1764`, `src-tauri/src/team/sync.rs:1844`, `src-tauri/src/team/sync.rs:3570`, `src-tauri/src/team/sync.rs:3644`, `src-tauri/src/team/sync.rs:4453`, `src-tauri/src/team/sync.rs:4674`.

Release drops the lease and pending operations while explicitly retaining quarantine. An ordinary push refuses a held revert lease. A pull only clears SIGNER_REVOKED when its walk accepted R; a still-open later run retains quarantine. Replayed R must pass the withdrawn-signer check before and inside finish. A valid replayed COMMIT can clear quarantine only by actually accepting valid R, not merely because a stored reply exists. During a resumable upload the sync_state is UPLOADING, but SIGNER_REVOKED and the ordinary-push gate remain in force.

| Test definition | Captured output |
| --- | --- |
| `src-tauri/src/team/sync.rs:11387` | `test team::sync::tests::an_abandoned_revert_keeps_the_binding_quarantined ... ok` |
| `src-tauri/src/team/sync.rs:11663` | `test team::sync::tests::revert_resumes_after_a_lost_release_of_an_abandoned_lease ... ok` |
| `src-tauri/src/team/sync.rs:11867` | `test team::sync::tests::a_revert_lease_whose_run_was_closed_elsewhere_is_released ... ok` |
| `src-tauri/src/team/sync.rs:10804` | `test team::sync::tests::a_reported_only_quarantine_stays_once_the_approval_is_hidden ... ok` |
| `src-tauri/src/team/sync.rs:11085` | `test team::sync::tests::a_pull_crossing_an_accepted_run_into_another_keeps_the_quarantine ... ok` |
| `src-tauri/src/team/sync.rs:12880` | `test team::sync::tests::a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok` |
| `src-tauri/src/team/sync.rs:13179` | `test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok` |
| `src-tauri/src/team/sync.rs:13685` | `test team::sync::tests::round6_a_revert_pin_failure_preserves_local_data_and_retries ... ok` |

**Property 6 — Accepted R installs P in the profile directory: HOLDS**

Enforcing code: `src-tauri/src/team/sync.rs:3650`, `src-tauri/src/team/sync.rs:3663`, `src-tauri/src/team/sync.rs:3678`, `src-tauri/src/team/sync.rs:2050`, `src-tauri/src/team/sync.rs:1936`, `src-tauri/src/team/sync.rs:1676`, `src-tauri/src/team/sync.rs:4612`; `src-tauri/src/launch.rs:150`.

R's pin, accepted skip rows and pending-swap row commit together. The wrapper then swaps staged P into the profile. If interrupted after the DB commit, revert, pull, push and launch settle the swap before accessing the profile. Rename stages are restartable. The tests cover actual local content, independent remote readback, lost COMMIT replies, missing staging and each interrupted rename state. The 'launch' test calls the settling helper rather than starting a real browser; the production launch call site was read separately.

| Test definition | Captured output |
| --- | --- |
| `src-tauri/src/team/sync.rs:11315` | `test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok` |
| `src-tauri/src/team/sync.rs:11429` | `test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok` |
| `src-tauri/src/team/sync.rs:11519` | `test team::sync::tests::revert_resumes_after_a_lost_commit_reply ... ok` |
| `src-tauri/src/team/sync.rs:11566` | `test team::sync::tests::a_crash_after_finish_completes_the_staging_swap ... ok` |
| `src-tauri/src/team/sync.rs:11593` | `test team::sync::tests::a_crash_inside_the_staging_swap_resumes ... ok` |
| `src-tauri/src/team/sync.rs:13042` | `test team::sync::tests::a_revert_keeps_the_devices_local_state ... ok` |
| `src-tauri/src/team/sync.rs:13507` | `test team::sync::tests::a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull ... ok` |
| `src-tauri/src/team/sync.rs:13685` | `test team::sync::tests::round6_a_revert_pin_failure_preserves_local_data_and_retries ... ok` |

**Property 7 — Sticky self-renewal refusal and exactly one alert per revoked key: HOLDS**

Enforcing code: `src-tauri/src/team/ledger.rs:273`, `src-tauri/src/team/ledger.rs:321`, `src-tauri/src/team/ledger.rs:385`, `src-tauri/src/team/ledger.rs:404`, `src-tauri/src/team/ledger.rs:830`; `src-tauri/src/team/db.rs:1324`, `src-tauri/src/team/db.rs:1375`.

prepare compares each container's first-seen evaluation with the earliest counted revocation and removes later containers regardless of issued_at_ms. A refused self-renewal triggers the alert path only for DEVICE_REVOCATION history, not distrust alone. INSERT ... WHERE NOT EXISTS preserves the first alert; the schema's per-key primary key and insert/update/delete triggers prevent duplication or replacement. Tests include a genuinely backdated issuance before the count, with a no-history control demonstrating the same renewal otherwise extends custody, repeat evaluations, multiple renewal containers, reopened DB persistence and earlier-seen records retaining standing.

| Test definition | Captured output |
| --- | --- |
| `src-tauri/src/lib.rs:4785` | `test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok` |
| `src-tauri/src/lib.rs:4810` | `test custody_tests::a_renewal_issued_before_the_count_is_sticky_and_alerts_once ... ok` |
| `src-tauri/src/lib.rs:4891` | `test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok` |
| `src-tauri/src/lib.rs:4929` | `test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok` |
| `src-tauri/src/lib.rs:4975` | `test custody_tests::renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok` |
| `src-tauri/src/lib.rs:4683` | `test custody_tests::records_first_seen_before_a_count_keep_their_standing ... ok` |
| `src-tauri/src/lib.rs:4597` | `test custody_tests::revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok` |
| `src-tauri/src/team/db.rs:2270` | `test team::db::tests::renewed_after_revocation_alerts_refuse_delete_and_replace ... ok` |
| `src-tauri/src/team/db.rs:2115` | `test team::db::tests::a_version_8_file_migrates_to_version_9_and_reopens ... ok` |

**Property 8 — Only a self-renewal verified under the revoked key raises the alert: HOLDS**

Enforcing code: `src-tauri/src/team/ledger.rs:69`, `src-tauri/src/team/ledger.rs:392`, `src-tauri/src/team/ledger.rs:394`, `src-tauri/src/team/ledger.rs:397`, `src-tauri/src/team/ledger.rs:400`.

Public keys are indexed by their derived signing-key IDs. The alert function verifies the record using the key corresponding to its named issuer before parsing a renewing root grant; it then requires subject == issuer and excludes FirstRootSelfGrant. The forged-container test deliberately names D but signs with another key and also exercises missing D public-key evidence; neither raises an alert. Renewals signed by a different custodian and D's grants to another subject are negative controls.

| Test definition | Captured output |
| --- | --- |
| `src-tauri/src/lib.rs:4841` | `test custody_tests::renewed_after_revocation_is_not_raised_for_a_forged_container ... ok` |
| `src-tauri/src/lib.rs:4948` | `test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok` |
| `src-tauri/src/lib.rs:4785` | `test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok` |

**Property 9 — Abandonment, deletion and unbind remove plaintext staging: HOLDS**

Enforcing code: `src-tauri/src/team/sync.rs:1983`, `src-tauri/src/team/sync.rs:2014`, `src-tauri/src/team/sync.rs:2027`, `src-tauri/src/team/sync.rs:2055`; `src-tauri/src/profile.rs:762`; `src-tauri/src/trash.rs:65`; `src-tauri/src/team/downgrade.rs:548`, `src-tauri/src/team/downgrade.rs:1241`; `src-tauri/src/api.rs:692`, `src-tauri/src/api.rs:844`; `src-tauri/src/lib.rs:860`, `src-tauri/src/lib.rs:1132`.

Cleanup removes .revert-staging, .revert-old and unpack's .incoming/.backup siblings. A pending release for the held lease disqualifies staging retention even if its reply was lost. Only an actual pending swap or a resumable sealed upload under the held lease retains P, as explicitly allowed by Client status. Every deletion path reaches discard_revert_for_deletion before trash/archive deletion and forces removal even under a held lease. Unbind and downgrade settle swaps and discard staging before detaching/archiving. Tests exercise UI deletion, folder deletion, local API deletion, unbind, lost-release abandonment and unpack leftovers.

| Test definition | Captured output |
| --- | --- |
| `src-tauri/src/team/sync.rs:11556` | `test team::sync::tests::a_refused_revert_discards_its_staging ... ok` |
| `src-tauri/src/team/sync.rs:11699` | `test team::sync::tests::an_abandoned_revert_lease_discards_its_staging ... ok` |
| `src-tauri/src/team/sync.rs:12945` | `test team::sync::tests::an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok` |
| `src-tauri/src/team/sync.rs:11721` | `test team::sync::tests::deleting_or_unbinding_a_profile_discards_its_revert_staging ... ok` |
| `src-tauri/src/team/sync.rs:11776` | `test team::sync::tests::folder_delete_discards_decrypted_revert_staging ... ok` |
| `src-tauri/src/team/sync.rs:11807` | `test team::sync::tests::deletion_unbind_and_discard_remove_the_unpack_leftovers_beside_the_staging ... ok` |
| `src-tauri/src/api.rs:1693` | `test api::automation_endpoint_tests::api_delete_discards_decrypted_revert_staging ... ok` |
| `src-tauri/src/team/sync.rs:13106` | `test team::sync::tests::a_release_pending_for_another_lease_keeps_the_staging ... ok` |

**Property 10 — Join proves the restored leaf, blocks premature push and remains recoverable: HOLDS**

Enforcing code: `src-tauri/src/team/sync.rs:2400`, `src-tauri/src/team/sync.rs:2455`, `src-tauri/src/team/sync.rs:1102`, `src-tauri/src/team/sync.rs:1221`, `src-tauri/src/team/sync.rs:1305`, `src-tauri/src/team/sync.rs:1358`, `src-tauri/src/team/sync.rs:1407`, `src-tauri/src/team/sync.rs:1446`, `src-tauri/src/team/sync.rs:1474`, `src-tauri/src/team/sync.rs:1803`, `src-tauri/src/team/sync.rs:2856`; `src-tauri/src/sync_cmd.rs:536`.

For a profile predating the current restore epoch, the version-zero binding starts at E-1 and its first pin is the leaf included in a custodian-signed transition. The search follows the listed chain backwards, verifying each child's signature, IDs and exact epoch. The leaf gets first-acceptance authority checks and a transaction-time withdrawal check. A profile created after restore (or at epoch zero) follows ordinary chain acceptance; it does not invent a restore transition. Transition acceptance advances remote_version without claiming the data is restored. base_version < remote_version blocks fresh checkout and releases replayed checkout until pull restores the head. Failed proof, download and pin cases preserve local files; retry pull followed by push or unbind remains possible. Entry commands claim the stopped profile before joining.

| Test definition | Captured output |
| --- | --- |
| `src-tauri/src/team/sync.rs:12490` | `test team::sync::tests::join_after_a_restore_pins_the_transition_leaf_then_pulls ... ok` |
| `src-tauri/src/team/sync.rs:12506` | `test team::sync::tests::join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf ... ok` |
| `src-tauri/src/team/sync.rs:12520` | `test team::sync::tests::join_refuses_the_rolled_back_child_of_the_leaf ... ok` |
| `src-tauri/src/team/sync.rs:12583` | `test team::sync::tests::join_with_a_lying_first_snapshot_pins_nothing ... ok` |
| `src-tauri/src/team/sync.rs:12547` | `test team::sync::tests::join_of_a_profile_created_after_a_restore_starts_at_that_epoch ... ok` |
| `src-tauri/src/team/sync.rs:12709` | `test team::sync::tests::join_then_a_push_before_the_first_pull_restores_is_refused ... ok` |
| `src-tauri/src/team/sync.rs:12740` | `test team::sync::tests::join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes ... ok` |
| `src-tauri/src/team/sync.rs:13130` | `test team::sync::tests::a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind ... ok` |
| `src-tauri/src/team/sync.rs:12970` | `test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok` |
| `src-tauri/src/team/sync.rs:12846` | `test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok` |
| `src-tauri/src/team/sync.rs:13597` | `test team::sync::tests::join_never_pins_a_leaf_withdrawn_during_the_proof_fetch ... ok` |
| `src-tauri/src/team/sync.rs:12828` | `test team::sync::tests::join_then_check_in_then_pull_on_the_first_device ... ok` |

**New unit tests**

The existing test pattern chosen was the loopback `World` fixture, file-tree comparison and SQLite failure injection already present in `src-tauri/src/team/sync.rs:5569`, `:11278` and `:12898`. This is test coverage of an established implementation, so no new-feature prior-art survey or external contact was needed.

Added at `src-tauri/src/team/sync.rs:13648` and `:13685`. Both passed, with exact output:

```text
test team::sync::tests::round6_a_stacked_run_never_temporarily_pins_a_rejected_head ... ok
test team::sync::tests::round6_a_revert_pin_failure_preserves_local_data_and_retries ... ok
```

The first test records every committed pin change across a stacked run instead of observing only the final head. The second injects a local pin-transaction failure after the server has committed R, checks the complete local tree and open audit, proves ordinary push stays blocked, and then proves retry installs P without another server commit. Its retained staging is an explicitly permitted resumable upload, not an abandoned lease.

```rust
    // Independent round-6 probe: inspect every committed pin update, not
    // just the final binding, while accepting a stacked revoked run.
    #[test]
    fn round6_a_stacked_run_never_temporarily_pins_a_rejected_head() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        w.db()
            .conn
            .execute_batch(
                "CREATE TABLE round6_pin_log(version INTEGER NOT NULL);
             CREATE TRIGGER round6_pin_observer AFTER UPDATE OF remote_version ON profile_bindings
             WHEN NEW.remote_version != OLD.remote_version
             BEGIN INSERT INTO round6_pin_log VALUES (NEW.remote_version); END;",
            )
            .unwrap();

        w.pull(&d.path().join("profile")).unwrap();
        let db = w.db();
        let pins: Vec<i64> = db
            .conn
            .prepare("SELECT version FROM round6_pin_log ORDER BY rowid")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(pins, [4], "neither rejected version may ever become a pin");
        available_at(&w, 4, heads[3]);
        assert_eq!(
            skipped(&w),
            [accepted_by(2, heads[3], 1), accepted_by(3, heads[3], 1)]
        );
    }

    // Independent round-6 probe: a server-side commit is not permission to
    // replace local data before the pin and swap-marker transaction commits.
    #[test]
    fn round6_a_revert_pin_failure_preserves_local_data_and_retries() {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        std::fs::create_dir_all(udd.join("Default")).unwrap();
        std::fs::write(udd.join("Default/local-only"), b"unsynced edit").unwrap();
        let before = tree(&udd);
        fail_the_pin_write(&w);

        let err = w.revert(&udd).unwrap_err();
        assert!(format!("{err:#}").contains("injected pin write failure"));
        assert_eq!(w.fake().version, 3, "R committed on the server");
        assert!(
            tree(&udd) == before,
            "the failed pin must preserve every local file"
        );
        let (state, reason, _, version, head) = w.state(LOCAL);
        assert_eq!(
            (state.as_str(), reason.as_deref(), version, head),
            (
                "UPLOADING",
                Some("SIGNER_REVOKED"),
                1,
                Some(heads[0].to_vec())
            )
        );
        assert!(has(
            &w.push_from(&udd).unwrap_err(),
            "sync.revertInProgress"
        ));
        assert_eq!(w.count("SELECT count(*) FROM revert_swaps"), 0);
        assert_eq!(skipped(&w), [(2, None, None, 1)]);
        assert_eq!(marker(&beside(&udd, ".revert-staging")), "v1");

        w.db()
            .conn
            .execute_batch("DROP TRIGGER pin_failure")
            .unwrap();
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        assert_eq!(w.fake().version, 3, "retry does not create another commit");
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        assert_eq!(skipped(&w), [accepted_by(2, r, 1)]);
        assert_eq!(marker(&udd), "v1");
        assert!(!udd.join("Default/local-only").exists());
        settled(&w, &udd);
    }
```

**Defects and limits**

No in-scope implementation defect was found at the verified HEAD. All ten properties hold under the specified ADR contract.

The verdict includes the contract's stated exceptions and limits: open-run pull may replace unsynced edits exactly as an ordinary successful pull does; ordinary push pins its own committed head; an accepted DB pin may await its durable directory swap after a crash; resumable sealed uploads and pending swaps retain staging; readers trust a valid R committer for content provenance; and a device with no first-seen history cannot distinguish records delivered in the same evaluation. These are not reported as defects. Restore transitions supersede obsolete open audit rows under their separately verified transition path.

Verification used unit tests with local HTTP fixtures and real local filesystem/SQLite operations. It did not start a production server, a real browser, or a live fleet. The launch entry point was inspected and its swap helper exercised without launching the desktop application.

VERDICT: PASS
