# Independent verification: ADR 0002 rule-6 revert and Team join — round 8

Verified HEAD: `8592d06d3fae6dea9409b38fe9f8d674ea79b30e`.

Worktree: `<verify-worktree>`. Verification date: 2026-11-04.

The worktree started clean. Review used the repository's current ADR and implementation, the complete `c60a64fc..HEAD` diff, and executable tests. No prior author/verifier report, `.omc/`, `.omx/reports/`, or scratch directory was read. Two fresh review lanes independently checked ledger/alert enforcement and join/cleanup architecture; both found no defect, and the architecture lane returned CLEAR. No commit, push, PR, issue, external service contact, or production-profile access was performed. Test fixtures use temporary directories and loopback servers. The OS credential-store test was explicitly excluded from every Cargo invocation.

The only intentional working-copy source change is the new round-8 unit test reproduced below. It reuses the existing `World` loopback fixture, `tree`, `revoked_at` and `settled` helpers in `sync.rs`; this is an extension of the established test pattern, not a new feature. Production code remains HEAD's code. Build-generated schema changes are restored before completion.

## Contract interpretation

The reviewed contract is `docs/adr/0002-g2-contract-decisions.md:1529`, `:1534` through the end of the lapsed-signer bullet at `:1593`, and the sticky-proven-revocation bullet at `:1493`.

Three explicit contract details qualify the shorter wording of the property list:

- ADR `:1553` names `sync.signerRevokedAtP` after a pull advances/restores P, and `sync.signerRevoked` when it does not advance. The implemented distinction is required by the current contract.
- ADR `:1553` expressly exempts an ordinary push's own committed head from the pre-pin withdrawal check: it pins as committed and quarantines on the next pull/push. Properties 2 and 4 below verify the requested revert/pull/join pin paths, including their races, with that documented exception. They do not claim the stronger unconditional property for ordinary push.
- The custodian-proven leaf requirement in property 10 governs the earlier-epoch restore exception. Current-epoch profiles can join by ordinary manifest acceptance. Similarly, a successful pin with a pending crash-recovery swap and a still-resumable sealed upload are the ADR's explicit staging-retention exceptions.

ADR `:1565` also states the reader cannot prove that a remote valid committer re-encrypted P. Property 3 verifies this client's committer implementation and a second device's decryption of the resulting R; it does not claim a ciphertext-level proof unavailable to the protocol.

## Commands and results

All test commands used the required form:

```text
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team:: -- --skip a_real_os_store_key_survives_into_a_fresh_process
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custody_tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib a_delete_for_good_removes_revert_staging_without_the_team_database -- --skip a_real_os_store_key_survives_into_a_fresh_process
```

The first clean build took 8m 26s. Two supplemental invocations were initially attempted while the team test executable was still running; both failed before executing tests with linker LNK1104 because Windows held that executable open. They were retried serially after it exited. This was a verification-run scheduling error, not a product assertion failure. No OS error 1455 occurred. A review lane's earlier queued custody invocation was cancelled before compilation/tests, and is not counted as coverage.

The single ignored entry in the broad team suite is `team::downgrade::tests::child_clone` (`downgrade.rs:1868`), an explicitly marked subprocess entry for the separate crash harness. Its absent-environment return is part of that helper, not any evidence test cited below. The parent crash tests exercise it in child processes. None of the property-evidence tests is ignored or exits early to bypass assertions.

Final completed runs (exit code 0 for each):

```text
running 304 tests
test result: ok. 303 passed; 0 failed; 1 ignored; 0 measured; 350 filtered out; finished in 847.97s
running 34 tests
test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 620 filtered out; finished in 10.79s
running 1 test
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 653 filtered out; finished in 0.03s
```

**338 tests passed; 0 failed.** The one ignored broad-suite entry is the crash-harness helper described above. All 87 distinct evidence tests cited below completed with `ok`. Their bodies and relevant helpers were inspected; none has an ignored attribute, early test return, empty assertion or conditional bypass. A source scan independently found no return token in those test bodies. Helper-only tests call helpers that assert real state/file invariants. `rustfmt --check --edition 2021 src-tauri/src/team/sync.rs` and both diff whitespace checks passed.

## 1. Only proven-revoked runs permit R — HOLDS

Enforcing code: `src-tauri/src/team/ledger.rs:134`, `:239`, `:830`, `:1115`; `src-tauri/src/team/sync.rs:4112`, `:4186`, `:4300`, `:4350`, `:2145`.

The ledger stores counted signed revocations and local distrust by key. The walk records evidence before classifying heads; Withdrawn is checked before Reported and Untrusted. Only Withdrawn joins a run. Signatures, identifiers, epoch, consecutive versions and previous hashes are checked before first acceptance. Reported-only and lapsed members refuse; a refusal after meeting a withdrawn head sets SIGNER_REVOKED. The committer requires both an open run and an anchor before staging or checkout.

Assertion review: Existing tests assert exact error codes, versions, hashes, skip-audit rows and quarantine state. The new round-8 test fills the committer-side mixed-run coverage gap: both lapsed and reported-only tails, two attempts each, full local tree equality, unchanged pin, no checkout/commit, no lease or staging.

New unit test: `round8_revert_refuses_mixed_runs_without_touching_local_data`; exact code appears in the appendix. Existing assertions were left intact.

Tests run and their actual output (source coordinates refer to the final working copy):

| Test source | Output |
|---|---|
| `src-tauri/src/team/sync.rs:10723` | `test team::sync::tests::revert_accepts_one_proven_revoked_head ... ok` |
| `src-tauri/src/team/sync.rs:10737` | `test team::sync::tests::revert_accepts_two_stacked_proven_revoked_heads ... ok` |
| `src-tauri/src/team/sync.rs:10752` | `test team::sync::tests::revert_accepts_on_a_new_device_without_a_pin ... ok` |
| `src-tauri/src/team/sync.rs:10763` | `test team::sync::tests::revert_refuses_a_run_with_a_lapsed_unrevoked_head ... ok` |
| `src-tauri/src/team/sync.rs:10924` | `test team::sync::tests::revert_refuses_a_reported_only_revocation ... ok` |
| `src-tauri/src/team/sync.rs:10952` | `test team::sync::tests::revert_refuses_a_reported_only_head_below_a_revoked_pin ... ok` |
| `src-tauri/src/team/sync.rs:10904` | `test team::sync::tests::revert_refuses_a_gap_below_the_pin ... ok` |
| `src-tauri/src/team/sync.rs:11032` | `test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lacked_device_revoke ... ok` |
| `src-tauri/src/team/sync.rs:11044` | `test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight ... ok` |
| `src-tauri/src/team/sync.rs:11056` | `test team::sync::tests::revert_accepts_after_forty_days_offline ... ok` |
| `src-tauri/src/team/sync.rs:11074` | `test team::sync::tests::revert_accepts_after_a_current_custodian_refiles ... ok` |
| `src-tauri/src/team/sync.rs:13823` | `test team::sync::tests::a_revocation_naming_another_device_never_enables_a_skip ... ok` |
| `src-tauri/src/team/sync.rs:13258` | `test team::sync::tests::local_distrust_alone_enables_a_revert ... ok` |
| `src-tauri/src/team/sync.rs:14024` | `test team::sync::tests::round8_revert_refuses_mixed_runs_without_touching_local_data ... ok` |

## 2. No rejected head is pinned — HOLDS

Enforcing code: `src-tauri/src/team/sync.rs:4320`, `:4505`, `:1254`, `:1478`, `:1593`, `:3570`, `:3642`; `src-tauri/src/team/ledger.rs:239`.

Run members only enter the in-memory run and skipped_heads audit. The pull pin transaction rechecks the final signer's withdrawal under an immediate transaction. A restore-leaf transaction records newly counted revocations before its final withdrawal check; false rolls back even its tentative UPDATE. Revert readback rechecks under the pin transaction and drops the lease on withdrawal. This finding uses the ADR's expressly documented ordinary-push exception described above.

Assertion review: The stacked-run test uses a SQLite trigger to record every committed remote_version update and requires exactly [4], rather than only checking the final version. Race tests assert that the withdrawal hook actually ran, the signer is withdrawn, the pin stayed put, and the entire local file tree stayed equal.

No additional unit test was needed for this property; existing tests exercise the relevant path and failure cases.

Tests run and their actual output (source coordinates refer to the final working copy):

| Test source | Output |
|---|---|
| `src-tauri/src/team/sync.rs:14079` | `test team::sync::tests::a_stacked_run_never_temporarily_pins_a_rejected_head ... ok` |
| `src-tauri/src/team/sync.rs:13106` | `test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok` |
| `src-tauri/src/team/sync.rs:13889` | `test team::sync::tests::join_never_pins_a_leaf_withdrawn_during_the_proof_fetch ... ok` |
| `src-tauri/src/team/sync.rs:13415` | `test team::sync::tests::a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok` |
| `src-tauri/src/team/sync.rs:13634` | `test team::sync::tests::an_open_run_anchor_withdrawn_during_download_is_not_pinned ... ok` |
| `src-tauri/src/team/sync.rs:13439` | `test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok` |
| `src-tauri/src/team/sync.rs:13912` | `test team::sync::tests::revert_never_pins_an_r_withdrawn_during_the_readback ... ok` |

## 3. A locally committed R carries the latest valid P — HOLDS

Enforcing code: `src-tauri/src/team/sync.rs:4169`, `:2145`, `:2185`, `:2198`, `:1706`, `:1888`, `:2989`, `:4613`.

The walk selects the newest valid earlier anchor, including moving backward below a newly withdrawn pin. Revert opens that snapshot with its own generation's readable key into a fresh sibling staging directory, then passes that directory to push_inner and snapshot::pack. Local unsynced files and rejected J content are never the sealing source. Before sending a prepared COMMIT, source_withdrawn rereads the anchor named by the lowest unresolved audit row and checks its signer. The ADR explicitly trusts an otherwise valid remote committer for the content of its R; re-encryption prevents a reader from proving equality with P.

Assertion review: The newest-content test distinguishes v1, v2=P, v3=J and unsynced local content, then opens the committed ciphertext on a second device and requires v2 there too. Withdrawal tests require no new server commit and unchanged local files.

No additional unit test was needed for this property; existing tests exercise the relevant path and failure cases.

Tests run and their actual output (source coordinates refer to the final working copy):

| Test source | Output |
|---|---|
| `src-tauri/src/team/sync.rs:11392` | `test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok` |
| `src-tauri/src/team/sync.rs:11407` | `test team::sync::tests::revert_commits_over_a_head_pinned_before_its_signer_was_proven_revoked ... ok` |
| `src-tauri/src/team/sync.rs:13599` | `test team::sync::tests::a_revert_uses_the_newest_valid_content_and_reads_back_remotely ... ok` |
| `src-tauri/src/team/sync.rs:11543` | `test team::sync::tests::revert_waits_for_rotation_after_a_compromised_revocation ... ok` |
| `src-tauri/src/team/sync.rs:11141` | `test team::sync::tests::revert_restores_an_anchor_of_an_older_generation_after_rotation ... ok` |
| `src-tauri/src/team/sync.rs:13533` | `test team::sync::tests::a_revert_never_commits_a_source_withdrawn_during_its_download ... ok` |
| `src-tauri/src/team/sync.rs:13568` | `test team::sync::tests::a_resumed_revert_never_commits_a_source_withdrawn_before_its_retry ... ok` |

## 4. Failure preserves local data; pin-time withdrawal is rechecked — HOLDS

Enforcing code: `src-tauri/src/team/sync.rs:2041`, `:4505`, `:4562`, `:4578`, `:4723`, `:1254`, `:3642`; `src-tauri/src/sync_cmd.rs:205`, `:359`, `:535`.

Download/unpack targets staging. The live profile is swapped only after pin and swap-marker commit; restore/pin failure cleans staging and leaves the live profile unchanged. The open-run branch deliberately restores and pins newer P while preserving quarantine, then reports sync.signerRevokedAtP. It shares the same restore path as a successful ordinary pull, including seeding Local State. Immediate pin transactions prevent a concurrently recorded withdrawal from being overlooked. Pending successful swaps are resumed at subsequent entry points as required by the ADR.

Assertion review: Failure tests inject actual SQLite aborts or damaged range objects and compare files/content, pin and audit state. The ordinary/open-run comparison seeds identical Local State, performs both restores of the same P and compares every relative path and byte; it does not misclassify ordinary pull replacement of unsynced edits as a defect.

No additional unit test was needed for this property; existing tests exercise the relevant path and failure cases.

Tests run and their actual output (source coordinates refer to the final working copy):

| Test source | Output |
|---|---|
| `src-tauri/src/team/sync.rs:11626` | `test team::sync::tests::a_refused_revert_checkout_keeps_the_local_profile ... ok` |
| `src-tauri/src/team/sync.rs:13170` | `test team::sync::tests::a_pull_whose_pin_fails_keeps_the_local_profile ... ok` |
| `src-tauri/src/team/sync.rs:13189` | `test team::sync::tests::a_join_whose_pin_fails_keeps_the_local_profile ... ok` |
| `src-tauri/src/team/sync.rs:14116` | `test team::sync::tests::a_revert_pin_failure_preserves_local_data_and_retries ... ok` |
| `src-tauri/src/team/sync.rs:13940` | `test team::sync::tests::a_corrupt_revert_source_preserves_data_and_retries ... ok` |
| `src-tauri/src/team/sync.rs:13475` | `test team::sync::tests::an_open_run_restore_keeps_what_an_ordinary_pull_keeps ... ok` |
| `src-tauri/src/team/sync.rs:11121` | `test team::sync::tests::a_failed_anchor_restore_keeps_the_quarantine_and_unresolved_rows ... ok` |
| `src-tauri/src/team/sync.rs:13415` | `test team::sync::tests::a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok` |
| `src-tauri/src/team/sync.rs:13634` | `test team::sync::tests::an_open_run_anchor_withdrawn_during_download_is_not_pinned ... ok` |
| `src-tauri/src/team/sync.rs:13889` | `test team::sync::tests::join_never_pins_a_leaf_withdrawn_during_the_proof_fetch ... ok` |
| `src-tauri/src/team/sync.rs:13912` | `test team::sync::tests::revert_never_pins_an_r_withdrawn_during_the_readback ... ok` |
| `src-tauri/src/team/sync.rs:13439` | `test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok` |

## 5. Abandonment and reply replay do not independently lift quarantine — HOLDS

Enforcing code: `src-tauri/src/team/sync.rs:3696`, `:3753`, `:3795`, `:2110`, `:1831`, `:3644`, `:4525`, `:4751`.

Lease release changes the lease fields while preserving SIGNER_REVOKED and quarantined state. A held revert lease is continued only by revert. Pull lifts this reason only with an accepted run; a now-hidden reported-only revocation with no accepted R leaves it intact. A replayed committed R still passes withdrawal and readback checks before finish records acceptance and lifts quarantine. Replay alone is not an acceptance bypass.

Assertion review: Assertions cover delivered/lost releases, exact quarantine reason, no ordinary-push checkout, server and client lease removal, no plaintext staging, and successful later pull only when a valid R is accepted.

No additional unit test was needed for this property; existing tests exercise the relevant path and failure cases.

Tests run and their actual output (source coordinates refer to the final working copy):

| Test source | Output |
|---|---|
| `src-tauri/src/team/sync.rs:11464` | `test team::sync::tests::an_abandoned_revert_keeps_the_binding_quarantined ... ok` |
| `src-tauri/src/team/sync.rs:10881` | `test team::sync::tests::a_reported_only_quarantine_stays_once_the_approval_is_hidden ... ok` |
| `src-tauri/src/team/sync.rs:11740` | `test team::sync::tests::revert_resumes_after_a_lost_release_of_an_abandoned_lease ... ok` |
| `src-tauri/src/team/sync.rs:12127` | `test team::sync::tests::a_revert_lease_whose_run_was_closed_elsewhere_is_released ... ok` |
| `src-tauri/src/team/sync.rs:13140` | `test team::sync::tests::a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok` |
| `src-tauri/src/team/sync.rs:13439` | `test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok` |
| `src-tauri/src/team/sync.rs:13711` | `test team::sync::tests::a_withdrawn_device_releases_its_revert_lease_on_the_server ... ok` |
| `src-tauri/src/team/sync.rs:13779` | `test team::sync::tests::a_revert_lease_whose_walk_fails_is_released_on_the_server ... ok` |

## 6. Accepted R installs P in the profile directory — HOLDS

Enforcing code: `src-tauri/src/team/sync.rs:3650`, `:3664`, `:3680`, `:1928`, `:2052`, `:4578`; `src-tauri/src/launch.rs:150`; `src-tauri/src/team/db.rs:1339`.

Revert finish pins R, accepts the run and inserts revert_swaps atomically. The outer revert settles the sibling-directory swap after that transaction. Pull follows the same pin/swap design. A crash or file lock after the pin leaves a recoverable swap, and push/pull/revert/launch settle it before using profile data.

Assertion review: Tests assert P's marker on both devices, unchanged local content before acceptance, one server version on replay, all intermediate rename crash states, preserved Local State, and no pending swap/staging after completion.

No additional unit test was needed for this property; existing tests exercise the relevant path and failure cases.

Tests run and their actual output (source coordinates refer to the final working copy):

| Test source | Output |
|---|---|
| `src-tauri/src/team/sync.rs:11506` | `test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok` |
| `src-tauri/src/team/sync.rs:11596` | `test team::sync::tests::revert_resumes_after_a_lost_commit_reply ... ok` |
| `src-tauri/src/team/sync.rs:11643` | `test team::sync::tests::a_crash_after_finish_completes_the_staging_swap ... ok` |
| `src-tauri/src/team/sync.rs:11670` | `test team::sync::tests::a_crash_inside_the_staging_swap_resumes ... ok` |
| `src-tauri/src/team/sync.rs:13302` | `test team::sync::tests::a_revert_keeps_the_devices_local_state ... ok` |
| `src-tauri/src/team/sync.rs:13318` | `test team::sync::tests::a_resumed_revert_whose_staging_is_gone_restores_p_again ... ok` |
| `src-tauri/src/team/sync.rs:13799` | `test team::sync::tests::a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull ... ok` |

## 7. Sticky revocation rejects backdated self-renewal and raises one alert — HOLDS

Enforcing code: `src-tauri/src/team/ledger.rs:151`, `:273`, `:324`, `:385`, `:830`; `src-tauri/src/team/db.rs:1324`, `:1375`; `src-tauri/src/lib.rs:2685`.

prepare filters by local first-seen evaluation versus the earliest counted revocation, not issued_at_ms. Filtered grants cannot restore custody. Genuine self-renewals first seen after a signed revocation raise one durable alert per tenant/server/key. The table key plus insert-once/delete/update triggers preserve its first hash and timestamp. Earlier/same-evaluation sightings retain their standing, matching the ADR history limit.

Assertion review: Tests compare exact custody windows and complete alert tuples over fresh DB opens, distinct renewals and repeated evaluations. A positive no-history control proves the same renewal really extends custody without prior revocation. Schema tests attempt duplicate insert, REPLACE, delete and update, then reopen and verify the original row.

No additional unit test was needed for this property; existing tests exercise the relevant path and failure cases.

Tests run and their actual output (source coordinates refer to the final working copy):

| Test source | Output |
|---|---|
| `src-tauri/src/lib.rs:4790` | `test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok` |
| `src-tauri/src/lib.rs:4815` | `test custody_tests::a_renewal_issued_before_the_count_is_sticky_and_alerts_once ... ok` |
| `src-tauri/src/lib.rs:4896` | `test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok` |
| `src-tauri/src/lib.rs:4934` | `test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok` |
| `src-tauri/src/lib.rs:4980` | `test custody_tests::renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok` |
| `src-tauri/src/lib.rs:4602` | `test custody_tests::revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok` |
| `src-tauri/src/lib.rs:4667` | `test custody_tests::a_head_by_a_committer_a_sticky_revoked_key_appointed_is_refused ... ok` |
| `src-tauri/src/lib.rs:4688` | `test custody_tests::records_first_seen_before_a_count_keep_their_standing ... ok` |
| `src-tauri/src/lib.rs:4705` | `test custody_tests::limit_mutual_revocation_counts_both_on_a_new_device ... ok` |
| `src-tauri/src/lib.rs:4725` | `test custody_tests::limit_a_new_device_counts_a_backdated_revocation_with_its_revoker ... ok` |
| `src-tauri/src/team/db.rs:2270` | `test team::db::tests::renewed_after_revocation_alerts_refuse_delete_and_replace ... ok` |
| `src-tauri/src/team/db.rs:2115` | `test team::db::tests::a_version_8_file_migrates_to_version_9_and_reopens ... ok` |

## 8. Only a renewal verifying under the revoked key raises its alert — HOLDS

Enforcing code: `src-tauri/src/team/ledger.rs:69`, `:385`, `:394`, `:397`, `:400`.

Public-key IDs are derived from the supplied public keys. The alert helper requires a successful signature verification under the record issuer's key, a root grant, a non-bootstrap variant and subject key equal to issuer. Missing keys, forged signatures and grants about another subject do not raise an alert.

Assertion review: The forged-container test explicitly declares the revoked key as issuer while signing with another key and supplies both keys; it also tests a genuine renewal with the issuer public key omitted. Assertions require no alert and unchanged custody. The positive genuine-renewal test requires one exact alert.

No additional unit test was needed for this property; existing tests exercise the relevant path and failure cases.

Tests run and their actual output (source coordinates refer to the final working copy):

| Test source | Output |
|---|---|
| `src-tauri/src/lib.rs:4846` | `test custody_tests::renewed_after_revocation_is_not_raised_for_a_forged_container ... ok` |
| `src-tauri/src/lib.rs:4953` | `test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok` |
| `src-tauri/src/lib.rs:4815` | `test custody_tests::a_renewal_issued_before_the_count_is_sticky_and_alerts_once ... ok` |

## 9. Abandoned/refused/deleted/unbound staging is cleaned — HOLDS

Enforcing code: `src-tauri/src/team/sync.rs:1975`, `:2018`, `:2027`, `:2041`; `src-tauri/src/team/downgrade.rs:548`, `:1242`; `src-tauri/src/profile.rs:777`, `:954`; `src-tauri/src/trash.rs:65`; `src-tauri/src/lib.rs:860`.

Cleanup removes staging, moved-aside data and unpack crash siblings. The only retained staging is the ADR's pending-swap or resumable sealed-upload exception; a pending release disqualifies an abandoned lease, even with a lost reply. Trash deletion settles first and fails closed; permanent deletion removes siblings without requiring a valid team DB. Successful unbind and downgrade clone settle/discard before removing or archiving the binding/profile.

Assertion review: These tests exercise the production UI/folder/delete/unbind entry points, all four sibling suffixes, held leases, lost releases, a broken team DB, and swap failure. A refused trash operation retaining the original and pending swap is intentional fail-closed behavior, not a completed deletion.

No additional unit test was needed for this property; existing tests exercise the relevant path and failure cases.

Tests run and their actual output (source coordinates refer to the final working copy):

| Test source | Output |
|---|---|
| `src-tauri/src/team/sync.rs:11633` | `test team::sync::tests::a_refused_revert_discards_its_staging ... ok` |
| `src-tauri/src/team/sync.rs:11776` | `test team::sync::tests::an_abandoned_revert_lease_discards_its_staging ... ok` |
| `src-tauri/src/team/sync.rs:13205` | `test team::sync::tests::an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok` |
| `src-tauri/src/team/sync.rs:11798` | `test team::sync::tests::deleting_or_unbinding_a_profile_discards_its_revert_staging ... ok` |
| `src-tauri/src/team/sync.rs:11890` | `test team::sync::tests::folder_delete_discards_decrypted_revert_staging ... ok` |
| `src-tauri/src/team/sync.rs:11921` | `test team::sync::tests::deletion_unbind_and_discard_remove_the_unpack_leftovers_beside_the_staging ... ok` |
| `src-tauri/src/team/sync.rs:11855` | `test team::sync::tests::a_folder_delete_keeps_a_profile_whose_pending_swap_cannot_land ... ok` |
| `src-tauri/src/profile.rs:1741` | `test profile::tests::a_delete_for_good_removes_revert_staging_without_the_team_database ... ok` |
| `src-tauri/src/team/downgrade.rs:1689` | `test team::downgrade::tests::a_clone_lands_a_pending_revert_swap_and_leaves_no_staging ... ok` |
| `src-tauri/src/team/sync.rs:13940` | `test team::sync::tests::a_corrupt_revert_source_preserves_data_and_retries ... ok` |

## 10. Join proves its restore leaf, gates check-in and retains recovery paths — HOLDS

Enforcing code: `src-tauri/src/sync_cmd.rs:535`; `src-tauri/src/team/sync.rs:2401`, `:1094`, `:1297`, `:1350`, `:1399`, `:1438`, `:1254`, `:1478`, `:1795`, `:2858`, `:3819`.

A version-zero binding is inserted at the server's start epoch, or E-1 when required. The earlier-epoch leaf exception requires a custodian-signed transition and exact profile inclusion proof; every child traversed toward the leaf must verify linkage, identity, signature and epoch. The subsequent pull decides child authority. base_version stays behind remote_version until restoration, so fresh checkout refuses and replayed checkout releases. Failed joins can retry pull and then push, or unbind when trust remains refused. Ordinary current-epoch profiles use ordinary manifest acceptance rather than the earlier-epoch exception.

Assertion review: Tests assert actual restored bytes and exact leaf hash/epoch/proof rows, no checkout or premature commit, base_version zero after failure, repeated refusal of untrusted children, and both pull-then-push and unbind recovery routes.

No additional unit test was needed for this property; existing tests exercise the relevant path and failure cases.

Tests run and their actual output (source coordinates refer to the final working copy):

| Test source | Output |
|---|---|
| `src-tauri/src/team/sync.rs:12750` | `test team::sync::tests::join_after_a_restore_pins_the_transition_leaf_then_pulls ... ok` |
| `src-tauri/src/team/sync.rs:12766` | `test team::sync::tests::join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf ... ok` |
| `src-tauri/src/team/sync.rs:12780` | `test team::sync::tests::join_refuses_the_rolled_back_child_of_the_leaf ... ok` |
| `src-tauri/src/team/sync.rs:12843` | `test team::sync::tests::join_with_a_lying_first_snapshot_pins_nothing ... ok` |
| `src-tauri/src/team/sync.rs:12807` | `test team::sync::tests::join_of_a_profile_created_after_a_restore_starts_at_that_epoch ... ok` |
| `src-tauri/src/team/sync.rs:12969` | `test team::sync::tests::join_then_a_push_before_the_first_pull_restores_is_refused ... ok` |
| `src-tauri/src/team/sync.rs:13000` | `test team::sync::tests::join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes ... ok` |
| `src-tauri/src/team/sync.rs:13106` | `test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok` |
| `src-tauri/src/team/sync.rs:13230` | `test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok` |
| `src-tauri/src/team/sync.rs:13390` | `test team::sync::tests::a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind ... ok` |
| `src-tauri/src/team/sync.rs:13889` | `test team::sync::tests::join_never_pins_a_leaf_withdrawn_during_the_proof_fetch ... ok` |
| `src-tauri/src/team/sync.rs:13982` | `test team::sync::tests::a_join_past_an_untrusted_child_keeps_data_and_can_unbind ... ok` |

## 11. Every post-c60a64fc hunk preserves behavior — HOLDS

Enforcing code: Only `src-tauri/src/team/sync.rs` changes in `git diff c60a64fc..HEAD` (29 insertions, 40 deletions). Detailed hunk inventory follows.

All five commits were read through their combined complete diff and all 27 zero-context hunks. The helper keeps the same connection/transaction and bound parameter. SQL EXISTS and the former optional SELECT 1 return the same bool for absent/present rows and both propagate database errors. All four old anchor assignments supplied Some(p); the removed inner None state was unreachable. Constant replacements preserve literal bytes; the closure rename preserves its one call and error propagation. The same parsed p is carried through each constructor/consumer. No error code/message, ordering, reachable branch or test assertion changes.

Assertion review: A direct Git-blob comparison returned `HEAD test module identical to c60a64fc: True`. All other files, including all other tests, are absent from the diff. The working-copy addition is one new test only; the production portion still equals HEAD byte-for-byte after newline normalization.

New unit test: `round8_revert_refuses_mixed_runs_without_touching_local_data`; exact code appears in the appendix. Existing assertions were left intact.

Tests run and their actual output (source coordinates refer to the final working copy):

| Test source | Output |
|---|---|
| `src-tauri/src/team/sync.rs:5825` | `test team::sync::tests::a_published_profile_pushes_and_another_device_pulls_it ... ok` |
| `src-tauri/src/team/sync.rs:12928` | `test team::sync::tests::join_refuses_a_bound_or_running_local_profile ... ok` |
| `src-tauri/src/team/sync.rs:12879` | `test team::sync::tests::join_refuses_a_local_profile_with_an_unfinished_publish ... ok` |
| `src-tauri/src/team/sync.rs:8685` | `test team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly ... ok` |
| `src-tauri/src/team/sync.rs:8769` | `test team::sync::tests::an_unbind_at_version_zero_omits_the_head ... ok` |
| `src-tauri/src/team/sync.rs:14024` | `test team::sync::tests::round8_revert_refuses_mixed_runs_without_touching_local_data ... ok` |

## Property 11: complete hunk inventory

`git log c60a64fc..HEAD` returned exactly these five commits:

```text
8592d06d3fae6dea9409b38fe9f8d674ea79b30e Rename the restore_then_pin closure parameter so it no longer shadows pin.
c64a402f389005f9bea6de87cd0ffdcb8006f65e Share one binding-exists query across publish, bind and unbind checks.
cf485edea1f9ec8c9b17a289db29e2aacd9fdd07 Name the SIGNER_REVOKED quarantine code once in Rust.
dba4045452801f373182396035e31028a222e2fb Name the revert staging and swap directory suffixes once.
c211e07d80e2089091e740126ff7c36c3dd560ff Type the walk anchor's snapshot manifest as always present.
```

The complete diff has 27 hunks with `--unified=0`, all in `src-tauri/src/team/sync.rs`. Each row below accounts for every listed hunk at its HEAD line:

| HEAD line(s) | Review of change and behavioral equivalence |
|---|---|
| 81 | New constant equals the former exact quarantine string. |
| 204 | `is_published` retains the missing-DB early result, opens the same DB, binds the same local ID and asks whether a row exists. Optional `SELECT 1` and `SELECT EXISTS` have identical present/absent semantics; database errors still propagate. |
| 370, 1756 | Quarantine and push comparison use the identical string constant; error construction and control flow stay the same. |
| 1941 | Swap sibling paths use constants with identical bytes. |
| 1999, 2002 | Two suffix definitions and SWAP_DIRS preserve values and order. |
| 2106, 2139 | Revert's quarantine comparison and staging path preserve values. |
| 2151, 2167 | Inner Option removed from the anchor check/destructure. All four prior constructors always supplied Some(p); no reachable failure/success branch changes. |
| 2260, 2275, 2413 | Publish/join call the same helper against the original connection. Helper's SQL, parameter and bool conversion stay unchanged. Join's short-circuit order stays unchanged. |
| 3823 | Unbind delegates the identical EXISTS query through the existing immediate transaction's dereference; no new connection or transaction boundary. The unbound reply branch stays identical. |
| 4143 | Walked's anchor type loses only the never-constructed inner None state. Default remains no anchor. |
| 4220, 4255, 4322, 4330 | All four constructors carry the same already-parsed p into the anchor, removing only Some wrapping. Linkage, authority and epoch checks stay before the same branches. |
| 4586, 4593 | Closure parameter renamed from pin to pin_to; same type, same single invocation, same position after restore and same ? propagation. |
| 4588 | Pull staging path uses the identical suffix constant. |
| 4697, 4751 | Pull's quarantine comparisons use the identical string; branch operators and conditions are unchanged. |
| 4730, 4761 | Pull destructures the narrower anchor; the former inner None was unreachable. Restore/pin/error paths remain identical. |

The baseline's four anchor assignments were at 4231, 4266, 4333 and 4341, all `Some((link, Some(p)))`. There is no additional hidden parsed-value change in this commit range: the retained p values are the same already-parsed values in those constructors.

Verification output:

```text
29  40  src-tauri/src/team/sync.rs
Diff hunk count: 27
HEAD test module identical to c60a64fc: True
Production portion equals HEAD: True
```

The `HEAD` test-module comparison used Git blobs, so the new working-copy probe is excluded from that assertion. All other test files are unchanged by the commit range. `git diff --check c60a64fc..HEAD` produced no errors.

## New unit test: exact working-copy code

Location: `src-tauri/src/team/sync.rs:14024`. The existing pull tests covered mixed runs; this probe directly exercises the committer refusing both a lapsed tail and a reported-only tail after a proven-revoked head. It checks every local file, pin/hash/quarantine, absence of checkout/commit, lease cleanup and staging across repeated attempts. It passed in the completed `team::` run:

```text
test team::sync::tests::round8_revert_refuses_mixed_runs_without_touching_local_data ... ok
```

```rust
    // Independent round-8 probe: the committer must refuse a mixed run,
    // preserve every local file, and keep the quarantine without a checkout.
    #[test]
    fn round8_revert_refuses_mixed_runs_without_touching_local_data() {
        for reported in [false, true] {
            let w = world();
            let mut evidence = author_pages_for(
                &w,
                T0 + 300 * DAY,
                Some(DeviceRevocationReason::Retired),
                false,
            );
            let end = if reported {
                T0 + 300 * DAY
            } else {
                T0 + DAY / 2
            };
            let other = committer(&w, &mut evidence, 0x20, end);
            if reported {
                evidence[0].device_revocations.push(RevokedDevice {
                    device_id: [0x21; 16],
                    revoked_at_ms: T0 + DAY / 2,
                });
            }
            let heads = chain_of(&w, &[&w.me.sk, &author(), &other]);
            serve(&w, &evidence);
            let d = second(&w);
            pin_at(&w, &d, &heads, 1);
            let out = d.path().join("profile");
            std::fs::create_dir_all(out.join("Default")).unwrap();
            std::fs::write(out.join("marker"), b"unsynced local").unwrap();
            std::fs::write(out.join("Default/local-only"), b"keep every byte").unwrap();
            std::fs::write(out.join("Local State"), LOCAL_STATE).unwrap();
            let before = tree(&out);
            let checkouts = w.sent("POST", "/checkout").len();
            let commits = w.fake().commits;

            for _ in 0..2 {
                let err = w.revert(&out).unwrap_err();
                assert!(
                    has(&err, "sync.signerRevoked"),
                    "reported={reported}: {err:#}"
                );
                revoked_at(&w, 1);
                assert_eq!(w.state(LOCAL).4, Some(heads[0].to_vec()));
                assert!(tree(&out) == before, "reported={reported}");
                assert_eq!(w.sent("POST", "/checkout").len(), checkouts);
                assert_eq!(w.fake().commits, commits);
                assert!(skipped(&w).is_empty());
                assert_eq!(local_leases(&w), 0);
                settled(&w, &out);
            }
        }
    }
```

## Defects and final assessment

No defect was found in the eleven properties under the current ADR contract and the explicit exceptions recorded above. No behavior change was found in any of the 27 refactor hunks, and no baseline test assertion was removed or weakened. The Windows linker-lock failures were resolved by serial retries; they did not execute or fail any product test.

Remaining working-copy changes are this evidence report and the single added unit test. Production implementation, generated schemas, HEAD and branch remain unchanged. No commit or external publication was made.

VERDICT: PASS
