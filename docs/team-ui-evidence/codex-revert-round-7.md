# Independent verification: ADR 0002 rule 6 and Team join — round 7

Verified HEAD: `3e98af0c127692cf76c42af201c3f4e81f75c00d`

Worktree: `<verify-worktree>`. Verification date: 2026-11-04.

The production implementation is unchanged from this HEAD. The working-copy change is two additional unit tests in `src-tauri/src/team/sync.rs`, reproduced below, plus this report. The initial worktree was clean. Line references are to the final working copy; production line numbers are unchanged.

The contract used for the verdict is `docs/adr/0002-g2-contract-decisions.md:1493` (sticky proven revocation), `:1529` (Joining), and `:1534` through `:1593` (revoked signer, client status, revert acceptance and lapsed signer). No author review report files, `.omc/`, `.omx/reports/`, or scratch directories were opened. No historical review verdict was used as evidence.

## Execution and test integrity

All six successful runs below exited 0: **256 tests passed, zero failed, zero ignored**. The original sync suite ran 194 tests; the two newly added probes ran separately against the unchanged production implementation. The other modules ran after those tests were added.

Every Rust invocation used the requested command form, including the real-credential-store exclusion. Each shell set `$env:CARGO_NET_OFFLINE='true'` first. Only the tests' local fixtures were contacted. Sync fixtures bind `127.0.0.1:0` (`sync.rs:5680`) and serialize a temporary config-root override (`sync.rs:5657`, `:5716`); database/custody tests use temporary database paths. The excluded real OS credential-store test was never run, and the real AppData launcher directory was not accessed. No commit, push, PR, issue, or external contact was made.

| Run | Filter | Observed summary |
|---|---|---|
| S | `team::sync::tests` | test result: ok. 194 passed; 0 failed; 0 ignored; 0 measured; 457 filtered out; finished in 350.80s |
| N | `round7_` | test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 651 filtered out; finished in 4.52s |
| C | `custody_tests` | test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 619 filtered out; finished in 8.68s |
| D | `team::db::tests` | test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 634 filtered out; finished in 3.98s |
| L | `team::ledger::tests` | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 647 filtered out; finished in 0.43s |
| B | `profile_mutation_boundary_tests` | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 652 filtered out; finished in 0.01s |

Exact commands (the environment assignment above applies to each):

```powershell
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib round7_ -- --skip a_real_os_store_key_survives_into_a_fresh_process
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custody_tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::db::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::ledger::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib profile_mutation_boundary_tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
```

I read the enforcing paths and the cited tests, including their setup, helper assertions, fault injection and recovery assertions. There are no ignored tests, empty assertions, literal `assert!(true)` assertions, or early-success exits in the cited test bodies. Two short tests delegate assertions to `refused_as_reported` or `refused_checkout`; those helpers assert the error/state/pin/audit or full-tree preservation. The fixture's `World::enroll` early return at `sync.rs:5741` deliberately creates an unbound device; it does not exit a test. Schema tests temporarily disable CHECK constraints to isolate trigger enforcement and then assert refusal; that is an adversarial database test, not a removed check. Existing tests and production code were not edited.

The new tests use the repository's established pattern: `World` with its localhost server, temporary roots, full-tree comparison and real SQLite state (`sync.rs:5657`, `:11366`). No new feature implementation or prior-art survey was needed.

### Execution issues, retained for transparency

1. While the original sync executable was still running, the first custody and database attempts tried to relink it after the new tests were added. Windows returned `LINK : fatal error LNK1104` for the running `shardx_launcher_lib-02d27abf0cb60a91.exe`; both cargo invocations exited 1 before executing tests. After the original run completed, the same commands succeeded. This was a running-executable file lock, not a test failure or os error 1455; no `-j 1` fallback was required.
2. The first new-probe run reported `1 passed; 1 failed`: the damaged-source test expected `field=envelope`, but the implementation returned `[[shardx:sync.badReplySync|field=range]]`. Reading the fixture at `sync.rs:5538` showed that it recomputes ETag from the damaged object; `sync.rs:4640` correctly rejects that mismatch before envelope authentication. I corrected only this new test to assert the exact actual error code and `field=range`, preserving all state, no-checkout, no-commit, full-tree, cleanup and successful-retry assertions. Its final run passed. No production change or existing expectation was made.

## Findings by property

### 1. Only proven-revoked heads enable a revert

**HOLDS.**

Enforcement: `src-tauri/src/team/ledger.rs:1115` verifies the signed revocation, tenant/instance, subject device/key approval, issuer custody and scoped `device.revoke`, including custody at first sight. `ledger.rs:134` records local distrust; `ledger.rs:239` tests the durable proven-revocation table. `src-tauri/src/team/sync.rs:4361` records the evaluation before walking. `sync.rs:4180` checks signatures, identities, epoch and chain linkage, classifies proven withdrawal before reports/lapse, and calls `sync.rs:4123` (`revert_rule`). Only `Withdrawn` joins a run; `Reported` and `Untrusted` refuse. `sync.rs:384` preserves the revoked quarantine on a failure inside a run. `sync.rs:2101` requires an open run and P before a committer can proceed.

The tests assert the actual pin, quarantine, audit membership and/or no checkout, not just an error. No additional test was needed for this property.

Tests read and run (each `ok` is present in the captured output in the run appendix):

- `revert_rule_accepts_two_stacked_proven_revoked_heads` — `src-tauri/src/team/sync.rs:10647` — **ok**, run S.
- `revert_rule_refuses_a_run_with_a_lapsed_unrevoked_head` — `src-tauri/src/team/sync.rs:10665` — **ok**, run S.
- `revert_rule_refuses_a_reported_only_revocation` — `src-tauri/src/team/sync.rs:10672` — **ok**, run S.
- `revert_rule_refuses_a_gap_below_the_pin` — `src-tauri/src/team/sync.rs:10682` — **ok**, run S.
- `revert_accepts_two_stacked_proven_revoked_heads` — `src-tauri/src/team/sync.rs:10748` — **ok**, run S.
- `revert_refuses_a_run_with_a_lapsed_unrevoked_head` — `src-tauri/src/team/sync.rs:10774` — **ok**, run S.
- `revert_refuses_a_reported_only_revocation` — `src-tauri/src/team/sync.rs:10935` — **ok**, run S.
- `a_failure_inside_a_run_writes_no_unresolved_rows` — `src-tauri/src/team/sync.rs:10793` — **ok**, run S.
- `revert_refuses_a_revocation_whose_issuer_lacked_device_revoke` — `src-tauri/src/team/sync.rs:11043` — **ok**, run S.
- `revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight` — `src-tauri/src/team/sync.rs:11055` — **ok**, run S.
- `a_revocation_naming_another_device_never_enables_a_skip` — `src-tauri/src/team/sync.rs:13834` — **ok**, run S.
- `local_distrust_alone_enables_a_revert` — `src-tauri/src/team/sync.rs:13269` — **ok**, run S.
- `a_revocation_counts_only_from_a_custodian_allowed_to_revoke` — `src-tauri/src/lib.rs:3547` — **ok**, run C.
- `a_lapsed_key_counts_only_after_its_observed_lapse` — `src-tauri/src/team/ledger.rs:1229` — **ok**, run L.

### 2. Proven-revoked heads are never newly pinned by pull, join or revert

**HOLDS.**

Enforcement: `src-tauri/src/team/sync.rs:4180` accumulates withdrawn heads without pinning them. `sync.rs:4516` acquires an IMMEDIATE transaction and calls `ledger::withdrawn_in` before the pull/P pin. `sync.rs:1261` records the transition's evidence and rechecks the leaf signer inside `store_transitions` (`sync.rs:1474`), rolling the transaction back if withdrawn. `sync.rs:3601` rechecks R inside the final IMMEDIATE transaction through `dropped_withdrawn_r` (`sync.rs:3576`), after all readback awaits.

The stacked-run test installs a database trigger that records every committed pin update and asserts exactly [4], so a transient J pin would fail. Network hooks persist real local distrust during download, proof fetch and readback. Scope follows the ADR's explicit ordinary-push exception: an ordinary committed head pins as committed; this verdict does not silently extend the prohibition beyond that contract. A head pinned before revocation may remain the existing pin until a valid replacement is accepted.

Tests read and run (each `ok` is present in the captured output in the run appendix):

- `a_stacked_run_never_temporarily_pins_a_rejected_head` — `src-tauri/src/team/sync.rs:14030` — **ok**, run S.
- `join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes` — `src-tauri/src/team/sync.rs:13117` — **ok**, run S.
- `join_never_pins_a_leaf_withdrawn_during_the_proof_fetch` — `src-tauri/src/team/sync.rs:13900` — **ok**, run S.
- `a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download` — `src-tauri/src/team/sync.rs:13426` — **ok**, run S.
- `an_open_run_anchor_withdrawn_during_download_is_not_pinned` — `src-tauri/src/team/sync.rs:13645` — **ok**, run S.
- `a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned` — `src-tauri/src/team/sync.rs:13450` — **ok**, run S.
- `revert_never_pins_an_r_withdrawn_during_the_readback` — `src-tauri/src/team/sync.rs:13923` — **ok**, run S.

### 3. A locally committed revert contains the newest valid earlier P

**HOLDS.**

Enforcement: `src-tauri/src/team/sync.rs:4180` moves the walk's anchor through valid heads and backtracks from a withdrawn pin. `sync.rs:2101` reads that anchor under its own generation via `readable_key` (`sync.rs:1633`), restores it into sibling staging and passes staging, not the live profile, to `push_inner`. `sync.rs:2995` packs the supplied staging directory. `sync.rs:1714` re-reads the open audit row's P before sending/replaying a prepared revert commit; the READY guard at `sync.rs:1897` abandons an unsent upload if its source has been withdrawn.

The remote-readback test starts with P=v2, rejected content=v3 and distinct unsynced local content; both the committer's directory and a second device pulling encrypted R contain v2. The new corruption probe additionally checks that unauthenticated P commits nothing and a retry restores v1. As the ADR states, a receiving client cannot establish the plaintext provenance of an arbitrary other committer's re-encryption; provenance here is enforced on the local committer.

Tests read and run (each `ok` is present in the captured output in the run appendix):

- `revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head` — `src-tauri/src/team/sync.rs:11403` — **ok**, run S.
- `revert_commits_over_a_head_pinned_before_its_signer_was_proven_revoked` — `src-tauri/src/team/sync.rs:11418` — **ok**, run S.
- `a_revert_uses_the_newest_valid_content_and_reads_back_remotely` — `src-tauri/src/team/sync.rs:13610` — **ok**, run S.
- `revert_waits_for_rotation_after_a_compromised_revocation` — `src-tauri/src/team/sync.rs:11554` — **ok**, run S.
- `a_revert_never_commits_a_source_withdrawn_during_its_download` — `src-tauri/src/team/sync.rs:13544` — **ok**, run S.
- `a_resumed_revert_never_commits_a_source_withdrawn_before_its_retry` — `src-tauri/src/team/sync.rs:13579` — **ok**, run S.
- `round7_corrupt_revert_source_preserves_data_and_retries` — `src-tauri/src/team/sync.rs:13951` — **ok**, run N (new test; code below).

### 4. Refusal preserves local data; the open-run P restore follows ordinary pull semantics

**HOLDS.**

Enforcement: `src-tauri/src/team/sync.rs:4589` restores into staging and invokes the pin before swapping; errors discard staging. `sync.rs:4573` seeds staging with the device's Local State. `sync.rs:4690` holds the open-run quarantine, restores/pins P only when P advances the pin, and reports `sync.signerRevokedAtP`; otherwise it reports `sync.signerRevoked`. `sync.rs:1936` swaps only with a committed `revert_swaps` row. The withdrawal checks listed in property 2 run after network I/O, inside the pin transaction. `src-tauri/src/sync_cmd.rs:205`, `:359`, `:536` acquire profile mutation claims before revert/pull/join; `src-tauri/src/launch.rs:150` settles a committed swap before launch.

The open-run comparison initializes identical device state, pulls the exact same snapshot normally and through the exception, then compares every relative file path and byte. Both replace unsynced local edits and preserve Local State. This required replacement is not classified as data loss. A committed pin with a pending filesystem swap is already accepted and is resumed before later operations; it is distinct from a refusal before pin commit. The new tests compare the complete local file tree on failure.

Tests read and run (each `ok` is present in the captured output in the run appendix):

- `a_refused_revert_checkout_keeps_the_local_profile` — `src-tauri/src/team/sync.rs:11637` — **ok**, run S.
- `an_abandoned_revert_with_a_lost_release_keeps_no_plaintext` — `src-tauri/src/team/sync.rs:13216` — **ok**, run S.
- `a_pull_whose_pin_fails_keeps_the_local_profile` — `src-tauri/src/team/sync.rs:13181` — **ok**, run S.
- `a_join_whose_pin_fails_keeps_the_local_profile` — `src-tauri/src/team/sync.rs:13200` — **ok**, run S.
- `a_revert_pin_failure_preserves_local_data_and_retries` — `src-tauri/src/team/sync.rs:14067` — **ok**, run S.
- `an_open_run_restore_keeps_what_an_ordinary_pull_keeps` — `src-tauri/src/team/sync.rs:13486` — **ok**, run S.
- `a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download` — `src-tauri/src/team/sync.rs:13426` — **ok**, run S.
- `round7_corrupt_revert_source_preserves_data_and_retries` — `src-tauri/src/team/sync.rs:13951` — **ok**, run N (new test; code below).
- `round7_join_untrusted_child_keeps_data_and_can_unbind` — `src-tauri/src/team/sync.rs:13990` — **ok**, run N (new test; code below).
- `every_tauri_profile_mutation_entry_point_checks_running_state_first` — `src-tauri/src/lib.rs:5211` — **ok**, run B.

### 5. Release, abandonment and lost replies do not lift SIGNER_REVOKED

**HOLDS.**

Enforcement: `src-tauri/src/team/sync.rs:3759` releases the lease and fails pending operations while preserving the revoked reason and QUARANTINED state. `sync.rs:4690` explicitly rejects lifting a SIGNER_REVOKED quarantine when no run was accepted. `sync.rs:4516` lifts only with an accepted run ending in a valid head; `sync.rs:3601` accepts R and resolves its audit in the same pin transaction. `sync.rs:2101` replays a pending release before attempting a fresh revert. `sync.rs:3576` drops the lease of a replayed withdrawn R without pinning it.

Tests check quarantine and dirty/pin state, number and exact replay bytes where applicable, and refusal of ordinary check-in. The ADR separately permits restore-epoch transitions and explicit unbind to supersede audit rows; those are not mistaken for revert-lease release.

Tests read and run (each `ok` is present in the captured output in the run appendix):

- `an_abandoned_revert_keeps_the_binding_quarantined` — `src-tauri/src/team/sync.rs:11475` — **ok**, run S.
- `revert_resumes_after_a_lost_release_of_an_abandoned_lease` — `src-tauri/src/team/sync.rs:11751` — **ok**, run S.
- `revert_resumes_after_a_lost_commit_reply` — `src-tauri/src/team/sync.rs:11607` — **ok**, run S.
- `a_reported_only_quarantine_stays_once_the_approval_is_hidden` — `src-tauri/src/team/sync.rs:10892` — **ok**, run S.
- `a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked` — `src-tauri/src/team/sync.rs:13151` — **ok**, run S.
- `a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned` — `src-tauri/src/team/sync.rs:13450` — **ok**, run S.
- `a_pull_crossing_an_accepted_run_into_another_keeps_the_quarantine` — `src-tauri/src/team/sync.rs:11173` — **ok**, run S.

### 6. Acceptance of R installs P in the profile directory

**HOLDS.**

Enforcement: `src-tauri/src/team/sync.rs:3601` pins R, marks the skipped run ACCEPTED, and inserts `revert_swaps` atomically. `sync.rs:2047` settles that swap after success; `sync.rs:1936` resumes each directory-rename state. Pull of another device's R goes through `sync.rs:4589`. Later push, pull, revert and launch settle a previously committed swap first.

Assertions verify v1/v2 file contents, resolved audit, removed staging/old directories and no pending swap. Recovery tests cover lost replies, each interrupted rename state and missing staging.

Tests read and run (each `ok` is present in the captured output in the run appendix):

- `revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head` — `src-tauri/src/team/sync.rs:11403` — **ok**, run S.
- `revert_committed_here_is_accepted_by_a_second_device` — `src-tauri/src/team/sync.rs:11517` — **ok**, run S.
- `a_revert_uses_the_newest_valid_content_and_reads_back_remotely` — `src-tauri/src/team/sync.rs:13610` — **ok**, run S.
- `a_crash_after_finish_completes_the_staging_swap` — `src-tauri/src/team/sync.rs:11654` — **ok**, run S.
- `a_crash_inside_the_staging_swap_resumes` — `src-tauri/src/team/sync.rs:11681` — **ok**, run S.
- `a_resumed_revert_whose_staging_is_gone_restores_p_again` — `src-tauri/src/team/sync.rs:13329` — **ok**, run S.
- `a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull` — `src-tauri/src/team/sync.rs:13810` — **ok**, run S.
- `round7_corrupt_revert_source_preserves_data_and_retries` — `src-tauri/src/team/sync.rs:13951` — **ok**, run N (new test; code below).

### 7. Backdated self-renewal is refused and alerts once per counted revoked key

**HOLDS.**

Enforcement: `src-tauri/src/team/ledger.rs:273` loads the earliest counted evaluation per revoked key, preserves only containers sighted by that evaluation, and drops later containers regardless of their claimed issue time. It calls `renewed_after_revocation` (`ledger.rs:385`) only for a counted DEVICE_REVOCATION. `src-tauri/src/team/db.rs:1324` keys the alert by instance/tenant/kind/signing key; `db.rs:1375` prevents replacement, deletion and mutation. Earlier-verified records and same-evaluation records retain their ADR-defined standing.

The decisive backdating test uses issued_at=T0+DAY/2, before the count at T0+DAY, then evaluates at T0+20DAY and T0+21DAY. A fresh ledger accepts and extends custody (positive control); the historical ledger does not extend, and exactly one alert retains the original container hash and time. Multiple different renewals and database reopen are exercised.

Tests read and run (each `ok` is present in the captured output in the run appendix):

- `a_backdated_self_renewal_after_a_count_is_refused` — `src-tauri/src/lib.rs:4790` — **ok**, run C.
- `a_renewal_issued_before_the_count_is_sticky_and_alerts_once` — `src-tauri/src/lib.rs:4815` — **ok**, run C.
- `renewed_after_revocation_is_bounded_per_key` — `src-tauri/src/lib.rs:4896` — **ok**, run C.
- `renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count` — `src-tauri/src/lib.rs:4934` — **ok**, run C.
- `renewed_after_revocation_is_not_raised_for_a_distrusted_key` — `src-tauri/src/lib.rs:4980` — **ok**, run C.
- `revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key` — `src-tauri/src/lib.rs:4602` — **ok**, run C.
- `records_first_seen_before_a_count_keep_their_standing` — `src-tauri/src/lib.rs:4688` — **ok**, run C.
- `renewed_after_revocation_alerts_refuse_delete_and_replace` — `src-tauri/src/team/db.rs:2270` — **ok**, run D.
- `a_version_8_file_migrates_to_version_9_and_reopens` — `src-tauri/src/team/db.rs:2115` — **ok**, run D.
- `the_ledger_never_takes_back_what_it_learned` — `src-tauri/src/team/db.rs:2347` — **ok**, run D.

### 8. The renewal alert requires a signature under the revoked custodian's own key

**HOLDS.**

Enforcement: `src-tauri/src/team/ledger.rs:385` looks up the named issuer's public key and calls `verify_signature` before considering an alert. The verified payload must be a non-bootstrap TenantRootKeyGrant with subject signing key equal to issuer. A missing key, forged signature, other subject, other issuer or other payload exits without inserting an alert.

The forgery test constructs a container naming D but signed by a different key, supplies that other public key, and separately tries a genuine renewal while omitting D's key. Both leave the alert table empty and custody unchanged. Genuine signed renewals provide the positive control; assertions are not vacuous.

Tests read and run (each `ok` is present in the captured output in the run appendix):

- `renewed_after_revocation_is_not_raised_for_a_forged_container` — `src-tauri/src/lib.rs:4846` — **ok**, run C.
- `renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian` — `src-tauri/src/lib.rs:4953` — **ok**, run C.
- `renewed_after_revocation_is_bounded_per_key` — `src-tauri/src/lib.rs:4896` — **ok**, run C.

### 9. Refused or abandoned reverts and removal paths clean plaintext staging

**HOLDS.**

Enforcement: `src-tauri/src/team/sync.rs:2047` invokes cleanup on revert error. `sync.rs:1983` always removes unpack leftovers, retaining staging only for a committed pending swap or a resumable upload under the still-held lease with no matching pending release. `sync.rs:2027` settles before trash deletion and removes all staging siblings; `sync.rs:2035` removes them for permanent deletion. Call paths: `src-tauri/src/trash.rs:68`, `src-tauri/src/profile.rs:766`, `:777`, `:988`; explicit unbind at `src-tauri/src/team/downgrade.rs:1252` and clone at `:548` settle/clean before detaching or archiving. `sync.rs:3825` refuses unbind with a lease/pending operation, preventing an active upload from being orphaned.

Checked .revert-staging, .revert-old, .revert-staging.incoming and .revert-staging.backup. The contract explicitly permits retaining P for a resumable held upload or committed pending swap; a lost RELEASE reply is not that exception. The new damaged-source test checks every sibling is absent after refusal, before retry.

Tests read and run (each `ok` is present in the captured output in the run appendix):

- `a_refused_revert_discards_its_staging` — `src-tauri/src/team/sync.rs:11644` — **ok**, run S.
- `an_abandoned_revert_lease_discards_its_staging` — `src-tauri/src/team/sync.rs:11787` — **ok**, run S.
- `an_abandoned_revert_with_a_lost_release_keeps_no_plaintext` — `src-tauri/src/team/sync.rs:13216` — **ok**, run S.
- `deleting_or_unbinding_a_profile_discards_its_revert_staging` — `src-tauri/src/team/sync.rs:11809` — **ok**, run S.
- `folder_delete_discards_decrypted_revert_staging` — `src-tauri/src/team/sync.rs:11901` — **ok**, run S.
- `deletion_unbind_and_discard_remove_the_unpack_leftovers_beside_the_staging` — `src-tauri/src/team/sync.rs:11932` — **ok**, run S.
- `a_folder_delete_keeps_a_profile_whose_pending_swap_cannot_land` — `src-tauri/src/team/sync.rs:11866` — **ok**, run S.
- `round7_corrupt_revert_source_preserves_data_and_retries` — `src-tauri/src/team/sync.rs:13951` — **ok**, run N (new test; code below).
- `a_profile_removed_for_good_drops_its_binding` — `src-tauri/src/team/sync.rs:11990` — **ok**, run S.

### 10. Join proves its restore leaf, gates local check-in and retains recovery paths

**HOLDS.**

Enforcement: `src-tauri/src/team/sync.rs:2407` binds at the listed epoch or E-1 based on v1's epoch, then calls pull. `sync.rs:1102` follows the listed chain back to the proven leaf for an unpinned binding; `sync.rs:1407` verifies above-leaf signature/identity/linkage/epoch without trusting server-listed keys' authority. `sync.rs:1305` verifies custodian authority over the signed transition, `sync.rs:1446` verifies inclusion, and `sync.rs:1358` checks the leaf as a first acceptance. `sync.rs:1474` atomically persists/readbacks proofs and pin after recording evidence and rechecking the signer. `sync.rs:1808` computes base_version < remote_version; `sync.rs:2864` rejects fresh checkout when behind and releases replayed checkout as stored. Pull and explicit unbind provide recovery.

The new test fills the specific combination not asserted by the existing join tests: the leaf is valid and proven, but a current-epoch descendant verifies only under a server-listed key with no approval/capability. Join must leave local data untouched, pin only the leaf, keep base_version=0, block checkout, and allow unbind. For a profile created after the restore, the ordinary current-epoch first-acceptance path applies, as the ADR specifies; it does not need a nonexistent prior restore leaf.

Tests read and run (each `ok` is present in the captured output in the run appendix):

- `join_after_a_restore_pins_the_transition_leaf_then_pulls` — `src-tauri/src/team/sync.rs:12761` — **ok**, run S.
- `join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf` — `src-tauri/src/team/sync.rs:12777` — **ok**, run S.
- `join_refuses_the_rolled_back_child_of_the_leaf` — `src-tauri/src/team/sync.rs:12791` — **ok**, run S.
- `join_with_a_lying_first_snapshot_pins_nothing` — `src-tauri/src/team/sync.rs:12854` — **ok**, run S.
- `join_then_a_push_before_the_first_pull_restores_is_refused` — `src-tauri/src/team/sync.rs:12980` — **ok**, run S.
- `join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes` — `src-tauri/src/team/sync.rs:13011` — **ok**, run S.
- `a_failed_join_recovers_by_pull_then_push_or_by_unbind` — `src-tauri/src/team/sync.rs:13241` — **ok**, run S.
- `a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind` — `src-tauri/src/team/sync.rs:13401` — **ok**, run S.
- `join_never_pins_a_leaf_withdrawn_during_the_proof_fetch` — `src-tauri/src/team/sync.rs:13900` — **ok**, run S.
- `round7_join_untrusted_child_keeps_data_and_can_unbind` — `src-tauri/src/team/sync.rs:13990` — **ok**, run N (new test; code below).

## Defects

No implementation defect was established in the requested contract scope. Both new probes pass on the unchanged production implementation. The two execution issues above are recorded separately and are not hidden as successful first attempts.

This is a source-and-unit-test verification using local protocol fixtures, not a live fleet or packaged-desktop exercise. The verdict observes the contract's explicit boundaries: already-pinned historical heads, ordinary-push committed-head pinning, pending committed swaps/resumable uploads, and the receiver's inability to inspect another committer's plaintext provenance. The required open-run restore of P is tested against ordinary successful pull, including replacement of unsynced edits, and is not reported as a defect.

## New unit tests retained in the working copy

`src-tauri/src/team/sync.rs:13951` and `src-tauri/src/team/sync.rs:13990`. These fill two specific coverage combinations: a damaged revert source with full local-tree/cleanup/retry assertions, and a proven restore leaf followed by a server-listed but unauthorized child with check-in and recovery assertions.

```rust
    // Independent round-7 probe: a damaged P must leave the complete local
    // tree intact, remove plaintext staging, and permit a clean retry.
    #[test]
    fn round7_corrupt_revert_source_preserves_data_and_retries() {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        std::fs::create_dir_all(udd.join("Default")).unwrap();
        std::fs::write(udd.join("Default/local-only"), b"unsynced edit").unwrap();
        std::fs::write(udd.join("Local State"), LOCAL_STATE).unwrap();
        let before = tree(&udd);
        let good = w.fake().objects[&1].clone();
        *w.fake().objects.get_mut(&1).unwrap().last_mut().unwrap() ^= 1;
        let commits = w.fake().commits;
        let checkouts = w.sent("POST", "/checkout").len();

        let err = w.revert(&udd).unwrap_err();
        // The fixture derives ETag from the damaged object, so the response
        // is rejected at the range check before envelope authentication.
        assert!(has(&err, "sync.badReplySync"), "{err:#}");
        assert!(format!("{err:#}").contains("field=range"), "{err:#}");
        assert!(tree(&udd) == before, "every local file remains unchanged");
        assert_eq!(w.fake().commits, commits);
        assert_eq!(w.sent("POST", "/checkout").len(), checkouts);
        revoked_at(&w, 1);
        assert_eq!(w.state(LOCAL).4, Some(heads[0].to_vec()));
        for suffix in SWAP_DIRS.iter().chain(UNPACK_LEFTOVERS.iter()) {
            assert!(!beside(&udd, suffix).exists(), "plaintext leftover: {suffix}");
        }
        assert_eq!(local_leases(&w), 0);

        w.fake().objects.insert(1, good);
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        assert_eq!(marker(&udd), "v1");
        assert!(local_state_kept(&udd));
        assert!(!udd.join("Default/local-only").exists());
        settled(&w, &udd);
    }

    // Independent round-7 probe: the leaf search may follow a child signed
    // by a server-listed key, but that key's missing authority must stop the
    // subsequent pull and any check-in of the untouched local profile.
    #[test]
    fn round7_join_untrusted_child_keeps_data_and_can_unbind() {
        let (w, d, leaf_head, _) = joinable_after_restore(1);
        let key = author();
        {
            let mut f = w.fake();
            let m = SignedSnapshotManifestV2::parse(&f.manifests[&2]).unwrap();
            let mut p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
            p.signer_signing_key_id = key_id_of(&key);
            let child = SignedSnapshotManifestV2::sign(&key, &p).unwrap();
            f.manifests.insert(2, child.exact_bytes().to_vec());
            f.head = Some(child.head_hash());
        }
        let mut evidence = pages(&w.me, &w.grant, &Ev::default());
        evidence[0].signing_public_keys.push(key.verifying_key().to_bytes());
        serve(&w, &evidence);
        let out = d.path().join("profile");
        std::fs::create_dir_all(out.join("Default")).unwrap();
        std::fs::write(out.join("Default/local-only"), b"unsynced edit").unwrap();
        std::fs::write(out.join("Local State"), LOCAL_STATE).unwrap();
        let before = tree(&out);

        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(has(&err, "sync.signerUntrusted"), "{err:#}");
        assert_eq!(w.state(LOCAL).4, Some(leaf_head.to_vec()));
        assert_eq!(w.state(LOCAL).3, 1, "only the proven leaf was pinned");
        assert_eq!(w.count("SELECT base_version FROM profile_bindings"), 0);
        assert!(tree(&out) == before);
        assert!(has(&w.push_from(&out).unwrap_err(), "sync.remoteAhead"));
        assert!(w.sent("POST", "/checkout").is_empty());
        assert!(has(&w.pull(&out).unwrap_err(), "sync.signerUntrusted"));
        assert!(tree(&out) == before);
        settled(&w, &out);
        unbind(LOCAL, SERVER, NOW).unwrap();
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert!(tree(&out) == before);
    }
```

Final new-test output:

```text
running 2 tests
test team::sync::tests::round7_join_untrusted_child_keeps_data_and_can_unbind ... ok
test team::sync::tests::round7_corrupt_revert_source_preserves_data_and_retries ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 651 filtered out; finished in 4.52s
```

## Run output appendix

The following are captured libtest output lines from the successful runs, with compiler/linker boilerplate and temporary executable paths omitted. The “running for over 60 seconds” notices are retained; they are not ignored tests or suppressed failures.

### Run S: team::sync::tests

```text
running 194 tests
test team::sync::tests::a_compromise_counted_mid_transfer_aborts_the_upload ... ok
test team::sync::tests::a_custodian_reappointed_after_its_lapse_signs_again ... ok
test team::sync::tests::a_blocked_publish_is_cancelled_by_its_command_and_stops_blocking_a_downgrade ... ok
test team::sync::tests::a_crash_inside_the_staging_swap_resumes ... ok
test team::sync::tests::a_custodian_not_yet_appointed_signs_no_transition ... ok
test team::sync::tests::a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks ... ok
test team::sync::tests::a_binding_and_its_rows_name_the_servers_account_and_key ... ok
test team::sync::tests::a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen ... ok
test team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key ... ok
test team::sync::tests::a_device_clock_behind_the_server_still_binds_one_profile ... ok
test team::sync::tests::a_device_withdrawn_in_the_walks_evidence_sends_no_revert ... ok
test team::sync::tests::a_custodian_distrusted_here_signs_no_transition ... ok
test team::sync::tests::a_failed_anchor_restore_keeps_the_quarantine_and_unresolved_rows ... ok
test team::sync::tests::a_compromised_custodian_blocks_every_fleet_through_the_root ... ok
test team::sync::tests::a_failed_record_leaves_no_evaluation_and_keeps_the_refusal ... ok
test team::sync::tests::a_failed_release_of_an_old_lease_is_retried_as_stored ... ok
test team::sync::tests::a_binding_changed_during_acceptance_is_not_moved ... ok
test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok
test team::sync::tests::a_join_whose_pin_fails_keeps_the_local_profile ... ok
test team::sync::tests::a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind ... ok
test team::sync::tests::a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code ... ok
test team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte ... ok
test team::sync::tests::a_head_committed_on_top_does_not_strand_the_push ... ok
test team::sync::tests::a_head_met_again_after_an_unbind_reopens_its_row ... ok
test team::sync::tests::a_device_whose_own_key_is_withdrawn_sends_no_revert ... ok
test team::sync::tests::a_folder_delete_keeps_a_profile_whose_pending_swap_cannot_land ... ok
test team::sync::tests::a_crash_after_finish_completes_the_staging_swap ... ok
test team::sync::tests::a_key_without_its_kept_record_asks_to_be_collected_again ... ok
test team::sync::tests::a_known_custodian_with_no_root_holding_blocks ... ok
test team::sync::tests::a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept has been running for over 60 seconds
test team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation has been running for over 60 seconds
test team::sync::tests::a_landed_commit_whose_reply_was_lost_replays_after_its_pin_signer_is_revoked ... ok
test team::sync::tests::a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull ... ok
test team::sync::tests::a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept ... ok
test team::sync::tests::a_lapse_seen_while_accepting_refuses_a_backdated_transition ... ok
test team::sync::tests::a_lease_at_risk_is_still_a_held_lease ... ok
test team::sync::tests::a_lease_from_before_the_restore_is_released_before_the_binding_moves ... ok
test team::sync::tests::a_key_the_checkout_does_not_name_is_never_used ... ok
test team::sync::tests::a_head_whose_signer_may_not_commit_is_not_restored ... ok
test team::sync::tests::a_new_head_from_an_earlier_epoch_is_a_rollback ... ok
test team::sync::tests::a_new_head_of_a_signer_revoked_in_this_pulls_evidence_is_refused ... ok
test team::sync::tests::a_pinned_head_is_read_back_only_as_the_bindings_own ... ok
test team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation ... ok
test team::sync::tests::a_lapsed_or_former_custodian_signs_no_transition ... ok
test team::sync::tests::a_pinned_head_stays_readable_after_its_signers_grants_expire ... ok
test team::sync::tests::a_failure_inside_a_run_writes_no_unresolved_rows has been running for over 60 seconds
test team::sync::tests::a_failure_inside_a_run_writes_no_unresolved_rows ... ok
test team::sync::tests::a_profile_is_published_with_its_first_lease_and_then_pushed ... ok
test team::sync::tests::a_pinned_head_of_a_since_revoked_signer_is_not_restored ... ok
test team::sync::tests::a_publish_replayed_after_its_lease_ended_binds_the_one_profile ... ok
test team::sync::tests::a_normal_push_still_refuses_a_quarantined_binding ... ok
test team::sync::tests::a_profile_removed_for_good_drops_its_binding ... ok
test team::sync::tests::a_missing_or_withdrawn_fleet_key_is_refused ... ok
test team::sync::tests::a_lost_session_or_rate_limit_keeps_the_stored_request ... ok
test team::sync::tests::a_profile_published_after_a_restore_starts_at_the_servers_epoch ... ok
test team::sync::tests::a_publish_whose_operation_was_cancelled_meanwhile_binds_nothing ... ok
test team::sync::tests::a_kept_revocation_reloads_with_every_column_equal has been running for over 60 seconds
test team::sync::tests::a_published_profile_pushes_and_another_device_pulls_it ... ok
test team::sync::tests::a_pull_keeps_the_devices_local_state ... ok
test team::sync::tests::a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok
test team::sync::tests::a_profile_removed_for_good_releases_its_lease_unless_work_is_pending ... ok
test team::sync::tests::a_pull_whose_pin_fails_keeps_the_local_profile ... ok
test team::sync::tests::a_push_behind_the_listed_head_is_refused ... ok
test team::sync::tests::a_receipt_or_readback_that_does_not_match_is_never_kept ... ok
test team::sync::tests::a_kept_revocation_reloads_with_every_column_equal ... ok
test team::sync::tests::a_lease_expiry_outside_the_ttl_is_refused_by_name ... ok
test team::sync::tests::a_refused_or_mismatched_reply_is_never_kept ... ok
test team::sync::tests::a_leaf_head_is_accepted_only_as_a_new_head_is has been running for over 60 seconds
test team::sync::tests::a_pull_crossing_an_accepted_run_into_another_keeps_the_quarantine ... ok
test team::sync::tests::a_refused_publish_is_not_replayed_and_the_next_one_starts_afresh ... ok
test team::sync::tests::a_refused_revert_checkout_keeps_the_local_profile ... ok
test team::sync::tests::a_refused_revert_discards_its_staging ... ok
test team::sync::tests::a_pull_waits_for_a_push_in_flight ... ok
test team::sync::tests::a_release_pending_for_another_lease_keeps_the_staging ... ok
test team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte ... ok
test team::sync::tests::a_renewed_lease_moves_the_bindings_expiry_forward ... ok
test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
test team::sync::tests::a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok
test team::sync::tests::a_reply_too_large_to_hold_is_refused ... ok
test team::sync::tests::a_report_of_a_revoked_signer_a_pull_saw_is_kept ... ok
test team::sync::tests::a_reported_only_quarantine_stays_once_the_approval_is_hidden ... ok
test team::sync::tests::a_restore_epoch_that_goes_back_is_a_rollback ... ok
test team::sync::tests::a_resumed_revert_never_commits_a_source_withdrawn_before_its_retry ... ok
test team::sync::tests::a_revert_never_commits_a_source_withdrawn_during_its_download ... ok
test team::sync::tests::a_revert_lease_whose_walk_fails_is_released_on_the_server ... ok
test team::sync::tests::a_publish_at_a_restore_epoch_never_waits_on_its_acceptance has been running for over 60 seconds
test team::sync::tests::a_publish_is_bound_whatever_its_lease_expiry_says has been running for over 60 seconds
test team::sync::tests::a_revert_keeps_the_devices_local_state ... ok
test team::sync::tests::a_publish_reply_that_does_not_name_the_request_is_never_kept has been running for over 60 seconds
test team::sync::tests::a_replayed_checkout_on_an_old_head_is_released_and_taken_again ... ok
test team::sync::tests::a_publish_that_cannot_be_trusted_stores_and_sends_nothing has been running for over 60 seconds
test team::sync::tests::a_revert_audits_the_accepted_runs_it_crosses ... ok
test team::sync::tests::a_retried_revert_files_each_accepted_run_once ... ok
test team::sync::tests::a_leaf_head_is_accepted_only_as_a_new_head_is ... ok
test team::sync::tests::a_revert_lease_whose_run_was_closed_elsewhere_is_released ... ok
test team::sync::tests::a_publish_at_a_restore_epoch_never_waits_on_its_acceptance ... ok
test team::sync::tests::a_revert_uses_the_newest_valid_content_and_reads_back_remotely ... ok
test team::sync::tests::a_revocation_naming_another_device_never_enables_a_skip ... ok
test team::sync::tests::a_revert_pin_failure_preserves_local_data_and_retries ... ok
test team::sync::tests::a_revert_lease_held_over_a_rollback_is_released ... ok
test team::sync::tests::a_resumed_revert_whose_staging_is_gone_restores_p_again ... ok
test team::sync::tests::a_stacked_run_never_temporarily_pins_a_rejected_head ... ok
test team::sync::tests::a_staging_dir_without_a_swap_row_is_never_swapped_in ... ok
test team::sync::tests::a_server_integer_past_the_signed_range_is_refused_before_any_row ... ok
test team::sync::tests::a_stored_finalize_is_not_sent_once_a_compromise_is_counted ... ok
test team::sync::tests::a_stored_publish_goes_out_while_its_key_holds ... ok
test team::sync::tests::a_revocation_recorded_after_checkout_abandons_an_ordinary_push ... ok
test team::sync::tests::a_swap_row_for_a_deleted_profile_is_cleared ... ok
test team::sync::tests::a_publish_is_bound_whatever_its_lease_expiry_says ... ok
test team::sync::tests::a_verified_transition_moves_only_the_bindings_it_covers ... ok
test team::sync::tests::a_withdrawn_committer_sends_no_prepared_revert_commit ... ok
test team::sync::tests::a_withdrawn_device_releases_its_revert_lease_on_the_server ... ok
test team::sync::tests::a_stored_publish_is_not_sent_once_its_key_is_blocked_or_withdrawn ... ok
test team::sync::tests::an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok
test team::sync::tests::an_exposure_survives_a_recollection_that_omits_its_grant ... ok
test team::sync::tests::an_interrupted_upload_resumes_at_the_offset_head_reports ... ok
test team::sync::tests::an_open_run_anchor_withdrawn_during_download_is_not_pinned ... ok
test team::sync::tests::a_publish_reply_that_does_not_name_the_request_is_never_kept ... ok
test team::sync::tests::a_rolled_back_head_or_epoch_quarantines_the_binding has been running for over 60 seconds
test team::sync::tests::a_rolled_back_head_or_epoch_quarantines_the_binding ... ok
test team::sync::tests::an_open_run_restore_keeps_what_an_ordinary_pull_keeps ... ok
test team::sync::tests::an_open_upload_is_aborted_once_a_compromise_is_counted ... ok
test team::sync::tests::an_abandoned_revert_lease_discards_its_staging ... ok
test team::sync::tests::a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh ... ok
test team::sync::tests::a_stored_column_that_drifts_from_its_bytes_is_never_sent has been running for over 60 seconds
test team::sync::tests::an_ordinary_push_refuses_a_revert_lease_on_the_pinned_head ... ok
test team::sync::tests::an_ordinary_push_refuses_over_a_pinned_head_whose_signer_is_proven_revoked ... ok
test team::sync::tests::an_unbind_after_an_accepted_transition_keeps_its_evidence ... ok
test team::sync::tests::an_unbind_at_version_zero_omits_the_head ... ok
test team::sync::tests::an_unbind_is_refused_while_a_lease_request_or_journal_is_open ... ok
test team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly ... ok
test team::sync::tests::an_unreadable_release_reply_is_reported_and_replayed ... ok
test team::sync::tests::deleting_or_unbinding_a_profile_discards_its_revert_staging ... ok
test team::sync::tests::deletion_unbind_and_discard_remove_the_unpack_leftovers_beside_the_staging ... ok
test team::sync::tests::a_stored_publish_that_drifts_from_its_bytes_is_never_sent has been running for over 60 seconds
test team::sync::tests::folder_delete_discards_decrypted_revert_staging ... ok
test team::sync::tests::a_publish_that_cannot_be_trusted_stores_and_sends_nothing ... ok
test team::sync::tests::join_after_a_restore_pins_the_transition_leaf_then_pulls ... ok
test team::sync::tests::a_tombstone_that_no_longer_recomputes_is_never_returned has been running for over 60 seconds
test team::sync::tests::a_transition_that_does_not_verify_keeps_the_binding_quarantined has been running for over 60 seconds
test team::sync::tests::an_abandoned_revert_keeps_the_binding_quarantined has been running for over 60 seconds
test team::sync::tests::join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf ... ok
test team::sync::tests::an_abandoned_revert_keeps_the_binding_quarantined ... ok
test team::sync::tests::join_binds_and_pulls_a_remote_profile_on_a_new_device ... ok
test team::sync::tests::join_lists_fleet_profiles_with_their_opened_labels_and_marks_bound_ones ... ok
test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok
test team::sync::tests::join_never_pins_a_leaf_withdrawn_during_the_proof_fetch ... ok
test team::sync::tests::join_of_a_profile_created_after_a_restore_starts_at_that_epoch ... ok
test team::sync::tests::join_refuses_a_bound_or_running_local_profile ... ok
test team::sync::tests::join_refuses_a_local_profile_with_an_unfinished_publish ... ok
test team::sync::tests::join_refuses_a_remote_profile_already_bound_here ... ok
test team::sync::tests::join_refuses_a_remote_profile_bound_here_meanwhile ... ok
test team::sync::tests::a_stored_publish_that_drifts_from_its_bytes_is_never_sent ... ok
test team::sync::tests::join_refuses_the_rolled_back_child_of_the_leaf ... ok
test team::sync::tests::join_refuses_without_the_collected_fleet_key_and_creates_no_binding ... ok
test team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes ... ok
test team::sync::tests::an_unbind_cut_off_at_any_write_leaves_the_binding_whole has been running for over 60 seconds
test team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes ... ok
test team::sync::tests::join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes ... ok
test team::sync::tests::an_unbind_cut_off_at_any_write_leaves_the_binding_whole ... ok
test team::sync::tests::an_unsent_cancel_release_is_retried_and_then_given_up has been running for over 60 seconds
test team::sync::tests::revert_accepts_one_proven_revoked_head ... ok
test team::sync::tests::revert_accepts_on_a_new_device_without_a_pin ... ok
test team::sync::tests::revert_accepts_after_forty_days_offline ... ok
test team::sync::tests::revert_accepts_after_a_current_custodian_refiles ... ok
test team::sync::tests::revert_accepts_a_head_both_proven_and_reported ... ok
test team::sync::tests::revert_accepts_a_revocation_another_device_filed ... ok
test team::sync::tests::only_a_signer_revoked_quarantine_lets_a_pull_through ... ok
test team::sync::tests::an_unsent_cancel_release_is_retried_and_then_given_up ... ok
test team::sync::tests::local_distrust_alone_enables_a_revert ... ok
test team::sync::tests::join_then_check_in_then_pull_on_the_first_device ... ok
test team::sync::tests::revert_accepts_two_stacked_proven_revoked_heads ... ok
test team::sync::tests::join_then_a_push_before_the_first_pull_restores_is_refused ... ok
test team::sync::tests::revert_advances_the_pin_over_a_valid_head_first ... ok
test team::sync::tests::revert_commits_over_a_head_pinned_before_its_signer_was_proven_revoked ... ok
test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok
test team::sync::tests::revert_is_refused_for_a_reported_only_revocation ... ok
test team::sync::tests::revert_rule_accepts_a_head_both_proven_and_reported ... ok
test team::sync::tests::revert_rule_accepts_on_a_new_device_without_a_pin ... ok
test team::sync::tests::revert_rule_accepts_one_proven_revoked_head ... ok
test team::sync::tests::revert_rule_accepts_two_stacked_proven_revoked_heads ... ok
test team::sync::tests::revert_rule_advances_the_pin_over_a_valid_head_first ... ok
test team::sync::tests::revert_rule_refuses_a_gap_below_the_pin ... ok
test team::sync::tests::revert_rule_refuses_a_reported_only_revocation ... ok
test team::sync::tests::revert_rule_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
test team::sync::tests::revert_never_pins_an_r_withdrawn_during_the_readback ... ok
test team::sync::tests::revert_refuses_a_gap_below_the_pin ... ok
test team::sync::tests::revert_refuses_a_reported_only_head_below_a_revoked_pin ... ok
test team::sync::tests::join_with_a_lying_first_snapshot_pins_nothing ... ok
test team::sync::tests::revert_refuses_a_reported_only_revocation ... ok
test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lacked_device_revoke ... ok
test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight ... ok
test team::sync::tests::revert_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
test team::sync::tests::statuses_report_renewed_after_revocation_alerts ... ok
test team::sync::tests::revert_waits_for_rotation_after_a_compromised_revocation ... ok
test team::sync::tests::revert_resumes_after_a_lost_release_of_an_abandoned_lease ... ok
test team::sync::tests::revert_resumes_after_a_lost_commit_reply ... ok
test team::sync::tests::revert_skips_a_head_pinned_before_its_signer_was_proven_revoked ... ok
test team::sync::tests::statuses_without_a_database_are_empty_and_create_nothing ... ok
test team::sync::tests::revert_restores_an_anchor_of_an_older_generation_after_rotation ... ok
test team::sync::tests::revert_refuses_without_a_valid_earlier_snapshot ... ok
test team::sync::tests::the_launch_settle_needs_a_team_database_only_when_one_exists ... ok
test team::sync::tests::a_tombstone_that_no_longer_recomputes_is_never_returned ... ok
test team::sync::tests::statuses_offer_revert_for_any_unresolved_proven_run ... ok
test team::sync::tests::stale_unresolved_rows_are_superseded_once_by_a_transition_or_unbind ... ok
test team::sync::tests::statuses_flag_a_revert_in_progress ... ok
test team::sync::tests::the_leaf_head_search_is_bounded_and_skipped_for_an_unchanged_pin ... ok
test team::sync::tests::a_transition_that_does_not_verify_keeps_the_binding_quarantined ... ok
test team::sync::tests::statuses_map_each_binding_state ... ok
test team::sync::tests::a_stored_column_that_drifts_from_its_bytes_is_never_sent ... ok
test result: ok. 194 passed; 0 failed; 0 ignored; 0 measured; 457 filtered out; finished in 350.80s
```

### Run N: round7_

```text
running 2 tests
test team::sync::tests::round7_join_untrusted_child_keeps_data_and_can_unbind ... ok
test team::sync::tests::round7_corrupt_revert_source_preserves_data_and_retries ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 651 filtered out; finished in 4.52s
```

### Run C: custody_tests

```text
running 34 tests
test custody_tests::a_fleet_descriptor_counts_only_for_this_device_and_generation ... ok
test custody_tests::a_collected_fleet_key_is_never_replaced ... ok
test custody_tests::a_server_delivered_fleet_key_is_counted_but_never_cached ... ok
test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok
test custody_tests::a_key_is_used_only_while_its_kept_record_reloads_exactly ... ok
test custody_tests::a_server_cannot_lapse_a_custodian_or_age_its_key_for_good ... ok
test custody_tests::a_head_by_a_committer_a_sticky_revoked_key_appointed_is_refused ... ok
test custody_tests::a_renewal_issued_before_the_count_is_sticky_and_alerts_once ... ok
test custody_tests::only_the_bootstrapped_device_has_a_pinned_anchor ... ok
test custody_tests::a_lapse_is_the_known_end_of_custody_clipped_at_the_key_age ... ok
test custody_tests::limit_mutual_revocation_counts_both_on_a_new_device ... ok
test custody_tests::a_kept_grant_is_reverified_before_its_key_is_used ... ok
test custody_tests::limit_a_backdated_grant_from_a_never_counted_custodian_is_accepted ... ok
test custody_tests::limit_a_new_device_counts_a_backdated_revocation_with_its_revoker ... ok
test custody_tests::a_lapsed_custodians_backdated_grant_is_refused_with_history ... ok
test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok
test custody_tests::a_fleet_generation_never_goes_back ... ok
test custody_tests::records_first_seen_before_a_count_keep_their_standing ... ok
test custody_tests::local_distrust_ignores_what_is_first_seen_after_it ... ok
test custody_tests::a_lapse_from_history_refuses_a_backdated_grant_with_no_evaluation_between ... ok
test custody_tests::an_omitted_first_root_grant_never_stretches_the_key_age_with_history ... ok
test custody_tests::a_revocation_counts_only_from_a_custodian_allowed_to_revoke ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok
test custody_tests::pull_uses_a_verified_key_only_while_its_issuer_stands ... ok
test custody_tests::reverifying_a_kept_key_records_the_lapse_history_shows ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_forged_container ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok
test custody_tests::a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet ... ok
test custody_tests::the_pinned_anchor_never_changes ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok
test custody_tests::a_counted_revocation_outlives_the_server_omitting_it ... ok
test custody_tests::a_reported_revocation_outlives_the_server_omitting_it ... ok
test custody_tests::revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok
test custody_tests::a_verified_fleet_grant_opens_and_nothing_else_does ... ok
test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 619 filtered out; finished in 8.68s
```

### Run D: team::db::tests

```text
running 19 tests
test team::db::tests::an_unexpected_version_1_file_is_not_migrated ... ok
test team::db::tests::a_version_5_upload_session_without_its_commit_operation_refuses_the_file ... ok
test team::db::tests::every_sync_integer_class_keeps_its_range_across_a_reopen ... ok
test team::db::tests::an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key ... ok
test team::db::tests::renewed_after_revocation_alerts_refuse_delete_and_replace ... ok
test team::db::tests::journals_and_epoch_proofs_keep_their_constraints_across_a_reopen ... ok
test team::db::tests::a_database_held_in_wal_mode_is_refused ... ok
test team::db::tests::a_version_8_file_migrates_to_version_9_and_reopens ... ok
test team::db::tests::skipped_heads_refuse_delete_replace_and_a_second_resolution ... ok
test team::db::tests::a_new_database_reopens_with_its_schema_and_settings ... ok
test team::db::tests::a_version_1_file_migrates_to_version_5_and_reopens ... ok
test team::db::tests::a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding ... ok
test team::db::tests::the_triggers_and_indexes_of_a_version_5_file_survive_version_6 ... ok
test team::db::tests::a_version_2_file_migrates_to_version_5_or_is_left_as_it_was ... ok
test team::db::tests::the_ledger_never_takes_back_what_it_learned ... ok
test team::db::tests::a_version_3_file_migrates_to_version_6_or_is_left_as_it_was ... ok
test team::db::tests::an_unknown_schema_fails_closed_and_is_left_as_it_was ... ok
test team::db::tests::a_version_8_file_with_another_min_reader_is_not_migrated ... ok
test team::db::tests::a_version_5_file_with_data_moves_to_version_6_keeping_every_row ... ok
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 634 filtered out; finished in 3.98s
```

### Run L: team::ledger::tests

```text
running 6 tests
test team::ledger::tests::holdings_name_every_issuer_and_subject_of_a_key_carrying_grant ... ok
test team::ledger::tests::a_lapsed_key_counts_only_after_its_observed_lapse ... ok
test team::ledger::tests::a_version_6_file_files_the_holdings_of_its_kept_evidence ... ok
test team::ledger::tests::a_second_origin_of_the_instance_files_a_new_generation ... ok
test team::ledger::tests::a_version_6_file_with_unreadable_kept_pages_still_opens ... ok
test team::ledger::tests::a_filed_grant_files_the_key_state_it_names ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 647 filtered out; finished in 0.43s
```

### Run B: profile_mutation_boundary_tests

```text
running 1 test
test profile_mutation_boundary_tests::every_tauri_profile_mutation_entry_point_checks_running_state_first ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 652 filtered out; finished in 0.01s
```

VERDICT: PASS
