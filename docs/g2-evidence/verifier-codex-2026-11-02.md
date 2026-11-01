# Independent G2 verification - Codex

Revision: `9e29a2c6a1ae39378b3fe269e3f1ee82a530b9e3`. Date: 2026-11-02. Repository initially clean and clean again at completion. No intentional source edits; two Tauri-generated schema side effects were restored to checkout-filtered HEAD bytes. Build target: `C:/Users/User/AppData/Local/Temp/g264-target-codex`; cargo compilation uses `-j 2`. Test processes have APPDATA/LOCALAPPDATA/TEMP/TMP redirected to that private directory and RUST_TEST_THREADS=2. G2-48 real Credential Manager test is excluded under the explicit prohibition. Owner exceptions: G2-48 PENDING-MANUAL and Team UI deferred.

## Result and command summary

**The rest of G2 does not hold, even with G2-48 PENDING-MANUAL and the deferred Team UI accepted.** There are two blocking findings: **N1**, a later counted compromised revocation is discarded when an earlier benign revocation exists for the same key; and **N2**, a persisted but unprocessed FINALIZE request bypasses the required OPEN-upload compromise check. Detailed file:line references, failure scenarios, evidence strength and related B3 state discrepancies appear below. These defects are independent of the environment limits that also prevented full test reproduction.

The verifier checked all 64 row mappings and located all 265 distinct cited file/test pairs (317 row/test pairs). Twenty rows received detailed semantic review, including every mandatory sample: G2-30, G2-31, G2-35, G2-41, G2-42, G2-43, G2-49, G2-55 and G2-63. The complete citation inventory, plan/ADR readback, test execution ledger and per-row counts follow. No directly cited test is marked ignored; helper-based assertions and intentional crash children were distinguished from vacuous tests. Conditional filesystem early returns are explicitly not credited as reproduced branches.

| Command family | Outcome |
| --- | --- |
| `python scripts/g2-evidence.py --check` | Run initially and after cleanup: both exit 0, **118 files checked, 0 problems**. |
| `cargo +stable fmt --check --manifest-path <crate>/Cargo.toml` | **4/4 pass**: shared, server, src-tauri, sdks/rust. |
| `cargo +stable clippy --locked -j 2 --manifest-path <crate>/Cargo.toml --all-targets -- -D warnings` | **3/3 pass**: shared, server, src-tauri. |
| `cargo +stable test --locked -j 2 --manifest-path shared/Cargo.toml` | Exit 101: library **282 passed, 18 failed, 0 ignored**. Failures report DPAPI protect errors. |
| Shared remaining targets: `cargo +stable test --locked -j 2 --manifest-path shared/Cargo.toml --test '*' --no-fail-fast`; then `--doc` | Integration targets **5 passed, 9 failed, 1 ignored**; nine failures report DPAPI fixture errors. Doc tests: 0 tests, exit 0. Across the full shared target set: **287 passed, 27 failed, 1 ignored**. |
| `cargo +stable test --locked -j 2 --manifest-path server/Cargo.toml` | Exit 0: **347 passed, 0 failed, 3 ignored**, across all targets/doc tests. Includes conditional filesystem tests whose skipped branches are excluded from the semantic verdict. |
| `cargo +stable build --locked -j 2 --manifest-path server/Cargo.toml` | Exit 0; server built before launcher tests. |
| `cargo +stable test --locked -j 2 --manifest-path src-tauri/Cargo.toml --lib -- --skip a_real_os_store_key_survives_into_a_fresh_process` | Exit 101: **405 passed, 91 failed, 11 ignored, 1 filtered out**. The explicit exclusion prevents real Credential Manager access. The failures include DPAPI/protection-dependent fixture setup; this is not an unfiltered full-suite pass. |
| Installed MSRV checks: `cargo +<version> check --locked -j 2 --all-targets --manifest-path <crate>/Cargo.toml` | **3/3 pass**: shared 1.87.0, server 1.89.0, src-tauri 1.88.0. Exact compiler versions are recorded below. |
| README section 6 row commands, with `+stable -j 2` and the G2-48 exclusion | **96 invocations: 75 exit 0, 21 nonzero; 252 passing and 67 failing test executions; 0 ignored.** Repeated citations count again. These totals overlap the full suites and are not additional unique tests. G2-62 is covered by the gates; G2-64 is this report. |
| `npm.cmd run test:i18n`, `test:rust-strings`, `test:backend-locale`, `test:raw-error-toast` | **4/4 pass**, respectively **16, 3, 7, 2 tests** (28 total). Initial compact log extraction omitted Node's Unicode summary lines; the count readback established these totals. |
| Three packet `cargo +stable audit ...` commands, exact flags below | All exit 1 before advisory evaluation: exclusive lock on read-only advisory database path. **No current RustSec result verified.** |
| Additional B1/B2/B4 helper execution | **3/3 pass**: holdings enumeration, v6-to-v7 holdings backfill, fleet-scoped revocation scenario. |
| Four targeted conditional-branch diagnostic invocations with `--nocapture` | All exit 0 but explicitly report **five SMB-dependent branches and one identity-record symlink branch skipped**. Their passing statuses are not credited as evidence for those branches. |

All cargo compilation used the private target and `-j 2`. Test fixtures used private APPDATA/LOCALAPPDATA/TEMP/TMP and two Rust test threads. Commands, exact names, exit codes and captured summaries are retained below. Some report sections interleave because independent command runners appended upon completion; headings identify each command unambiguously.

## Final B1-B7 closure decisions

| Prior finding | Independent decision on this tree |
| --- | --- |
| B1 | **Source fix addresses the original defect; full runtime closure remains unverified.** The holdings helper passes, but `a_compromised_custodian_blocks_every_fleet_through_the_root` fails at protection-dependent world construction before its assertions. The production path now follows root exposure, issuers, bound recovery evidence and higher PREPARING roots. |
| B2 | **Source fix addresses the original defect; full runtime closure remains unverified.** The append-only holdings/backfill helper passes; the recollection regression fails in the same fixture setup. N1 is a separate evidence-retention defect. |
| B3 | **Not closed.** N2 reaches the omitted pending-FINALIZE branch. The server upload ABORTED state and required persisted local error also remain unproven by the fix and disagree with the reviewed paths. The named regression itself fails during fixture setup here. |
| B4 | **Closed for the original scope defect.** Its four-case fleet/tenant scenario passed independently, and the implementation matches server scope selection. |
| B5 | **Closed for the original empty-activations limitation.** The shared activation boundary/parser test and both server activation/rollback tests passed. Source confirms one atomic transaction. |
| B6 | **Closed by Q-43 at the typed-i64 wire boundary**, consistent with the server. Both local range/reopen tests and the cited server integer probes passed. Arbitrary SQL numeric TEXT has an additional rounding case; the ADR's broad wording and test coverage need the precision qualification documented below. No wire bypass was demonstrated. |
| B7 | **Server replay matrix gap closed; complete local runtime reproduction remains unverified.** Both exhaustive server matrices and restore replay test passed. Source now covers LocalUnbind and the local replay combinations, but their DPAPI-dependent fixtures fail before those assertions. |

The B1/B2/B7 runtime qualifications are verification limits, not an assertion that their original code bugs persist. They do not diminish the independently identified N1/N2 blockers. No author's assertion of closure substitutes for a reproduced scenario.

## Executed commands

### `python scripts/g2-evidence.py --check`

Exit 0; elapsed 0.1 s.

```text
118 files checked, 0 problems
```

### `rustc +stable --version`

Exit 0; elapsed 0.0 s.

```text
rustc 1.99.1 (58cf8f9c3 2026-10-13)
```

### `cargo +stable --version`

Exit 0; elapsed 0.0 s.

```text
cargo 1.99.1 (5f94df478 2026-08-27)
```

### `cargo +stable fmt --check --manifest-path shared/Cargo.toml`

Exit 0; elapsed 0.4 s.

```text

```

### `cargo +stable fmt --check --manifest-path server/Cargo.toml`

Exit 0; elapsed 0.5 s.

```text

```

### `cargo +stable fmt --check --manifest-path src-tauri/Cargo.toml`

Exit 0; elapsed 0.6 s.

```text

```

### `cargo +stable fmt --check --manifest-path sdks/rust/Cargo.toml`

Exit 0; elapsed 0.1 s.

```text

```

### `cargo +stable clippy --locked -j 2 --manifest-path shared/Cargo.toml --all-targets -- -D warnings`

Exit 0; elapsed 20.7 s.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 20.63s
```

### `cargo +stable clippy --locked -j 2 --manifest-path server/Cargo.toml --all-targets -- -D warnings`

Exit 0; elapsed 67.9 s.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 07s
```


### Independent in-memory SQL reproduction

Extracted the exact `trust_proven_revocations` CREATE TABLE and the `record_in` INSERT from production sources; executed with Python SQLite 3.49.1 in `:memory:`. Inserted two fixture containers for the same instance/tenant/key/source, first `retired`, then `compromised`, evaluations 1 and 2. Result: **one row; evaluation 1 and the first container retained**. The second container was silently discarded. This directly exercises the storage failure; it does not claim to execute Rust signature validation or a live launcher. No filesystem fixture created.

### `cargo +stable clippy --locked -j 2 --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings`

Exit 0; elapsed 135.2 s.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 15s
```

### `cargo +stable test --locked -j 2 --manifest-path shared/Cargo.toml`

Exit 101; elapsed 114.9 s.

```text
thread 'backup_file::tests::the_two_container_kinds_are_told_apart' (32700) panicked at src\backup_file.rs:428:71:
seal: pack profile for backup

Caused by:
    DPAPI protect failed

---- cookies::tests::cookie_db_roundtrip stdout ----

thread 'cookies::tests::cookie_db_roundtrip' (27296) panicked at src\cookies.rs:218:44:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- cookies::tests::partitioned_cookies_keep_distinct_scope stdout ----

thread 'cookies::tests::partitioned_cookies_keep_distinct_scope' (31276) panicked at src\cookies.rs:245:44:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- oscrypt::tests::local_cookie_roundtrip stdout ----

thread 'oscrypt::tests::local_cookie_roundtrip' (21948) panicked at src\oscrypt.rs:347:40:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- snapshot::tests::a_junction_is_neither_packed_through_nor_followed_on_replace stdout ----

thread 'snapshot::tests::a_junction_is_neither_packed_through_nor_followed_on_replace' (22872) panicked at src\snapshot.rs:1407:32:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- snapshot::tests::long_paths_unpack_and_an_overlong_one_is_refused stdout ----

thread 'snapshot::tests::long_paths_unpack_and_an_overlong_one_is_refused' (29872) panicked at src\snapshot.rs:1365:51:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- snapshot::tests::ntfs_case_fold_collisions_are_refused_and_distinct_names_kept stdout ----

thread 'snapshot::tests::ntfs_case_fold_collisions_are_refused_and_distinct_names_kept' (18944) panicked at src\snapshot.rs:1343:67:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- snapshot::tests::pack_unpack_carries_password_from_wal stdout ----

thread 'snapshot::tests::pack_unpack_carries_password_from_wal' (28616) panicked at src\snapshot.rs:974:45:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- snapshot::tests::pack_unpack_excludes_cache_and_keeps_cookies stdout ----

thread 'snapshot::tests::pack_unpack_excludes_cache_and_keeps_cookies' (20596) panicked at src\snapshot.rs:584:45:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- snapshot::tests::pack_unpack_normalizes_saved_passwords stdout ----

thread 'snapshot::tests::pack_unpack_normalizes_saved_passwords' (24192) panicked at src\snapshot.rs:927:45:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- snapshot::tests::pack_unpack_normalizes_web_data_secrets stdout ----

thread 'snapshot::tests::pack_unpack_normalizes_web_data_secrets' (16024) panicked at src\snapshot.rs:889:45:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- snapshot::tests::unpack_canonicalizes_paths_before_matching stdout ----

thread 'snapshot::tests::unpack_canonicalizes_paths_before_matching' (25644) panicked at src\snapshot.rs:714:30:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- snapshot::tests::unpack_rejects_symlink_entries stdout ----

thread 'snapshot::tests::unpack_rejects_symlink_entries' (26696) panicked at src\snapshot.rs:1113:30:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- snapshot::tests::unpack_rejects_two_entries_for_one_path stdout ----

thread 'snapshot::tests::unpack_rejects_two_entries_for_one_path' (27888) panicked at src\snapshot.rs:1188:10:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed

---- snapshot::tests::unpack_swap_drops_stale_files_and_is_atomic stdout ----

thread 'snapshot::tests::unpack_swap_drops_stale_files_and_is_atomic' (27916) panicked at src\snapshot.rs:1019:45:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed


failures:
    backup_file::tests::a_fleet_snapshot_round_trips
    backup_file::tests::a_snapshot_sealed_for_another_profile_is_refused
    backup_file::tests::another_fleet_key_cannot_open_it
    backup_file::tests::the_two_container_kinds_are_told_apart
    cookies::tests::cookie_db_roundtrip
    cookies::tests::partitioned_cookies_keep_distinct_scope
    oscrypt::tests::local_cookie_roundtrip
    snapshot::tests::a_junction_is_neither_packed_through_nor_followed_on_replace
    snapshot::tests::long_paths_unpack_and_an_overlong_one_is_refused
    snapshot::tests::ntfs_case_fold_collisions_are_refused_and_distinct_names_kept
    snapshot::tests::pack_unpack_carries_password_from_wal
    snapshot::tests::pack_unpack_excludes_cache_and_keeps_cookies
    snapshot::tests::pack_unpack_normalizes_saved_passwords
    snapshot::tests::pack_unpack_normalizes_web_data_secrets
    snapshot::tests::unpack_canonicalizes_paths_before_matching
    snapshot::tests::unpack_rejects_symlink_entries
    snapshot::tests::unpack_rejects_two_entries_for_one_path
    snapshot::tests::unpack_swap_drops_stale_files_and_is_atomic

test result: FAILED. 282 passed; 18 failed; 0 ignored; 0 measured; 0 filtered out; finished in 85.97s

error: test failed, to rerun pass `--lib`
```

`npm.cmd run test:i18n` -> exit 0

```text

```

`npm.cmd run test:rust-strings` -> exit 0

```text

```

`npm.cmd run test:backend-locale` -> exit 0

```text

```

`npm.cmd run test:raw-error-toast` -> exit 0

```text

```

`cargo +stable audit --version` -> exit 0

```text
cargo-audit-audit 0.22.2
```

`cargo +stable audit --deny unsound --deny yanked --file shared/Cargo.lock` -> exit 1

```text
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
error: couldn't fetch advisory database: I/O operation failed: failed to obtain lock file 'C:\Users\User\.cargo\advisory-db..lock'
Caused by:
  -> failed to obtain lock file 'C:\Users\User\.cargo\advisory-db..lock'
  -> attempted to take an exclusive lock on a read-only path
```

`cargo +stable audit --deny unsound --deny yanked --file server/Cargo.lock --ignore RUSTSEC-2023-0071` -> exit 1

```text
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
error: couldn't fetch advisory database: I/O operation failed: failed to obtain lock file 'C:\Users\User\.cargo\advisory-db..lock'
Caused by:
  -> failed to obtain lock file 'C:\Users\User\.cargo\advisory-db..lock'
  -> attempted to take an exclusive lock on a read-only path
```

`cargo +stable audit --deny unsound --deny yanked --file src-tauri/Cargo.lock --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195 --ignore RUSTSEC-2026-0367 --ignore RUSTSEC-2026-0368 --ignore RUSTSEC-2026-0369 --ignore RUSTSEC-2024-0429` -> exit 1

```text
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
error: couldn't fetch advisory database: I/O operation failed: failed to obtain lock file 'C:\Users\User\.cargo\advisory-db..lock'
Caused by:
  -> failed to obtain lock file 'C:\Users\User\.cargo\advisory-db..lock'
  -> attempted to take an exclusive lock on a read-only path
```

Exact-SHA CI readback: unauthenticated GitHub Actions REST GET for head_sha=9e29a2c6a1ae39378b3fe269e3f1ee82a530b9e3 failed with WinError 10013 (socket access forbidden). No CI success is inferred from earlier commits.


## Citation inventory (repository source)

All 64 row IDs are present. 265 distinct (file,test) pairs, 317 row/test pairs. Missing named functions: []. Type names and prose in notes excluded. Existence alone is not a semantic verdict; detailed samples and execution results follow.

- G2-01: `server/tests/v2_auth.rs:1583` `the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt`; `server/tests/v2_auth.rs:8686` `every_approval_column_is_compared_with_its_container_on_each_request`; `server/tests/v2_auth.rs:8792` `the_startup_pass_quarantines_approvals_that_left_their_containers`; `shared/src/authz_record.rs:1940` `golden_vectors`
- G2-02: `server/tests/v2_auth.rs:9469` `every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup`; `shared/src/authz_record.rs:1940` `golden_vectors`
- G2-03: `server/tests/v2_auth.rs:8444` `every_fleet_grant_column_is_compared_with_its_container_on_each_request`; `server/tests/v2_auth.rs:8589` `the_startup_pass_quarantines_fleet_grants_that_left_their_containers`; `shared/src/authz_record.rs:1940` `golden_vectors`
- G2-04: `shared/src/authz_record.rs:2508` `recovery_grant_binds_context_suite_and_lengths`; `shared/src/authz_record.rs:2550` `recovery_grant_opens_only_under_its_root_and_to_its_fkek`; `shared/src/authz_record.rs:1940` `golden_vectors`; `server/tests/v2_auth.rs:8444` `every_fleet_grant_column_is_compared_with_its_container_on_each_request`
- G2-05: `shared/src/authz_record.rs:2600` `rotation_grant_follows_its_generation_window_and_count_rules`; `shared/src/authz_record.rs:1940` `golden_vectors`; `server/tests/v2_auth.rs:8444` `every_fleet_grant_column_is_compared_with_its_container_on_each_request`
- G2-06: `server/tests/v2_auth.rs:9166` `every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup`; `shared/src/authz_record.rs:1940` `golden_vectors`
- G2-07: `shared/src/snapshot_v2.rs:1054` `golden_vectors`; `shared/src/snapshot_v2.rs:1167` `payload_rejects_every_field_level_defect`; `shared/src/snapshot_v2.rs:1268` `container_rejects_every_field_level_defect`; `shared/src/snapshot_v2.rs:1374` `signing_binds_the_signer_key`; `shared/src/snapshot_v2.rs:1666` `manifest_binds_a_sealed_envelope_v2_object`
- G2-08: `server/tests/v2_profiles.rs:2646` `every_upload_refusal_has_its_status_and_code`
- G2-09: `server/tests/v2_profiles.rs:2294` `an_upload_commits_once_and_the_next_checkout_starts_at_its_head`
- G2-10: `shared/src/envelope_v2.rs:1897` `the_closed_maps_parse_what_the_builders_write`; `shared/src/envelope_v2.rs:1970` `every_dek_slot_context_rule_is_enforced`; `shared/src/envelope_v2.rs:2037` `every_dek_slot_rule_is_enforced`; `shared/src/envelope_v2.rs:2330` `a_slot_that_differs_from_the_intent_is_refused`; `shared/src/envelope_v2.rs:2380` `the_reader_refuses_an_open_map`; `shared/src/envelope.rs:769` `g2_golden_vector_dek_slot`; `shared/src/canonical.rs:666` `g2_golden_vector_dek_slot_context_hash`
- G2-11: `shared/src/envelope_v2.rs:1688` `the_intent_bounds_are_the_plans`; `shared/src/envelope_v2.rs:2121` `every_envelope_intent_rule_is_enforced`; `shared/src/envelope_v2.rs:1665` `the_intent_and_slot_must_be_the_ones_the_manifest_names`; `shared/src/snapshot_v2.rs:1666` `manifest_binds_a_sealed_envelope_v2_object`; `shared/src/envelope.rs:780` `g2_golden_vector_intent`; `shared/src/envelope.rs:792` `g2_golden_vector_intent_genesis`
- G2-12: `shared/src/restore_epoch.rs:815` `golden_vectors`; `shared/src/restore_epoch.rs:1088` `leaf_roundtrips_and_refuses_contract_violations`; `shared/src/restore_epoch.rs:1136` `leaf_sets_must_be_non_empty_sorted_and_unique`; `shared/src/restore_epoch.rs:1194` `every_leaf_proves_and_every_tampering_fails`; `shared/src/restore_epoch.rs:1253` `a_proof_binds_tenant_profile_instance_epochs_count_and_root`; `shared/src/restore_epoch.rs:1291` `proof_parser_refuses_every_contract_violation`; `shared/src/envelope.rs:819` `g2_golden_vectors_merkle_roots`
- G2-13: `shared/src/restore_epoch.rs:873` `transition_roundtrips_and_verifies`; `shared/src/restore_epoch.rs:895` `transition_payload_refuses_every_contract_violation`; `shared/src/restore_epoch.rs:961` `signed_transition_refuses_every_container_defect`; `shared/src/restore_epoch.rs:1044` `transition_signature_binds_key_bytes_and_label`
- G2-14: `shared/src/mutation.rs:1855` `golden_vectors`; `shared/src/mutation.rs:1738` `every_map_roundtrips_byte_for_byte`; `shared/src/mutation.rs:1762` `every_map_refuses_another_domain_or_version`; `shared/src/mutation.rs:1924` `every_kind_has_one_scope_and_the_scope_must_match`; `shared/src/mutation.rs:1954` `hashes_and_closed_fields_are_checked`; `shared/src/mutation.rs:2358` `device_revoke_maps_carry_one_container_and_roundtrip`; `server/tests/v2_auth.rs:5949` `a_revocation_commits_its_fleet_activation_or_nothing`; `server/tests/v2_auth.rs:6141` `a_revocation_commits_its_root_activation`; `shared/src/fleet_lifecycle.rs:1142` `golden_vectors`
- G2-15: `shared/src/mutation.rs:1855` `golden_vectors`; `shared/src/mutation.rs:1738` `every_map_roundtrips_byte_for_byte`; `shared/src/mutation.rs:1762` `every_map_refuses_another_domain_or_version`
- G2-16: `server/tests/v2_auth.rs:2089` `the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response`
- G2-17: `server/tests/v2_auth.rs:9166` `every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup`
- G2-18: `server/tests/v2_auth.rs:2939` `readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant`
- G2-19: `server/tests/v2_auth.rs:2939` `readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant`
- G2-20: `shared/src/mutation.rs:2653` `a_revocation_names_a_known_reason_and_its_outcome`; `server/tests/v2_auth.rs:5257` `a_custodian_revokes_a_root_grant_but_never_the_last_one`
- G2-21: `server/tests/v2_profiles.rs:798` `one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes`; `src-tauri/src/team/sync.rs:4441` `a_profile_is_published_with_its_first_lease_and_then_pushed`; `src-tauri/src/team/sync.rs:4538` `every_publish_crash_point_resumes_with_the_exact_stored_bytes`
- G2-22: `server/tests/v2_profiles.rs:798` `one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes`; `server/tests/v2_profiles.rs:1845` `a_stored_response_naming_another_profile_or_lease_is_never_replayed`; `src-tauri/src/team/sync.rs:5181` `a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept`; `src-tauri/src/team/sync.rs:7587` `a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key`
- G2-23: `server/tests/v2_profiles.rs:2294` `an_upload_commits_once_and_the_next_checkout_starts_at_its_head`; `server/tests/v2_profiles.rs:2646` `every_upload_refusal_has_its_status_and_code`; `src-tauri/src/team/sync.rs:5474` `a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte`
- G2-24: `server/tests/v2_profiles.rs:2294` `an_upload_commits_once_and_the_next_checkout_starts_at_its_head`; `server/tests/v2_profiles.rs:3258` `a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot`; `src-tauri/src/team/sync.rs:4293` `every_crash_point_resumes_with_the_exact_stored_bytes`
- G2-25: `server/tests/v2_profiles.rs:798` `one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes`; `server/tests/v2_profiles.rs:1845` `a_stored_response_naming_another_profile_or_lease_is_never_replayed`; `src-tauri/src/team/sync.rs:4401` `a_release_whose_reply_was_lost_is_replayed_byte_for_byte`
- G2-26: `shared/src/profile_lease.rs:1076` `the_unbind_maps_round_trip_and_pin_the_tombstone`; `shared/src/profile_lease.rs:1126` `the_unbind_maps_refuse_what_l953_does_not_allow`; `src-tauri/src/team/sync.rs:6596` `an_unbind_tombstone_outlives_its_binding_and_replays_exactly`; `src-tauri/src/team/sync.rs:6680` `an_unbind_at_version_zero_omits_the_head`; `src-tauri/src/team/sync.rs:6698` `an_unbind_cut_off_at_any_write_leaves_the_binding_whole`; `src-tauri/src/team/sync.rs:6734` `an_unbind_is_refused_while_a_lease_request_or_journal_is_open`
- G2-27: `shared/src/envelope_v2.rs:1111` `xchacha20poly1305_matches_the_draft_vector`; `shared/src/envelope_v2.rs:1273` `golden_objects`; `shared/src/envelope_v2.rs:1308` `every_preamble_rule_is_enforced`; `shared/src/envelope_v2.rs:1461` `every_frame_rule_is_enforced`; `shared/src/envelope_v2.rs:1223` `the_stream_counter_stops_at_the_provider_maximum`
- G2-28: `shared/src/grants.rs:503` `the_pinned_suite_matches_the_rfc_9180_vectors`; `shared/src/grants.rs:619` `info_bytes_match_g2_vector`; `shared/src/grants.rs:645` `only_the_granted_device_can_open`; `shared/src/grants.rs:684` `grant_cannot_be_replayed_into_another_tenant_or_epoch`; `shared/src/grants.rs:920` `the_fleet_grant_aad_is_the_label_the_length_and_the_info`; `shared/src/grants.rs:930` `a_device_fleet_grant_opens_only_to_the_key_it_names`; `shared/src/fleet_grants.rs:236` `a_sealed_fleet_key_opens_to_the_exact_same_bytes`
- G2-29: `shared/src/authz_record.rs:2099` `signature_binds_issuer_and_bytes`; `shared/src/authz_record.rs:2134` `small_order_issuer_key_never_verifies`; `shared/src/signing.rs:225` `rfc8032_vectors_sign_and_verify_strictly`; `shared/src/signing.rs:264` `speccheck_matrix_accepts_only_the_unambiguous_case`; `shared/src/signing.rs:436` `g2_golden_vector_signed_container_hash`
- G2-30: `server/tests/v2_auth.rs:9609` `every_device_revocation_column_is_compared_with_its_container_on_each_request`; `server/tests/v2_auth.rs:9832` `the_startup_pass_quarantines_device_revocations_that_left_their_containers`; `server/tests/v2_auth.rs:9940` `a_revocation_of_another_instance_turns_v2_off_until_it_is_put_back`; `server/tests/v2_auth.rs:10000` `a_revocation_quarantined_at_runtime_refuses_the_trust_evidence`; `server/tests/v2_auth.rs:10061` `a_quarantined_revocation_that_verifies_again_is_served_again_after_a_restart`; `server/tests/v2_auth.rs:10132` `a_marked_row_swapped_for_another_genuine_revocation_is_not_served_again`; `server/tests/v2_auth.rs:10280` `a_corrupt_container_is_marked_without_a_hash_and_served_again_once_restored`; `server/tests/v2_auth.rs:10393` `the_trust_evidence_reports_a_revoked_device_from_its_record_not_its_column`; `server/tests/v2_auth.rs:10447` `a_revocation_row_swapped_for_another_genuine_one_does_not_answer_a_retry`; `server/tests/v2_auth.rs:10503` `a_revocation_row_the_startup_pass_cannot_read_turns_v2_off`; `src-tauri/src/team/sync.rs:6092` `a_kept_revocation_reloads_with_every_column_equal`
- G2-31: `server/tests/v2_auth.rs:1583` `the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt`; `server/tests/v2_auth.rs:2089` `the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response`; `server/tests/v2_auth.rs:10642` `every_custody_operation_replays_its_lost_response_after_a_restart`; `server/tests/v2_e2e.rs:251` `v2_operations_replay_the_stored_response`; `server/tests/v2_profiles.rs:798` `one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes`; `server/tests/v2_profiles.rs:1845` `a_stored_response_naming_another_profile_or_lease_is_never_replayed`; `server/tests/v2_profiles.rs:3258` `a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot`; `server/tests/v2_profiles.rs:3971` `every_profile_operation_replays_its_lost_response_after_a_restart`; `server/tests/restore_epoch_harness.rs:2203` `d1_replays_of_rolled_back_results_answer_as_superseded_and_kept_ones_replay`; `src-tauri/src/team/sync.rs:4538` `every_publish_crash_point_resumes_with_the_exact_stored_bytes`; `src-tauri/src/team/sync.rs:7587` `a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key`; `src-tauri/src/team/sync.rs:5474` `a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte`; `src-tauri/src/team/sync.rs:4293` `every_crash_point_resumes_with_the_exact_stored_bytes`; `src-tauri/src/team/sync.rs:4401` `a_release_whose_reply_was_lost_is_replayed_byte_for_byte`; `src-tauri/src/team/sync.rs:6596` `an_unbind_tombstone_outlives_its_binding_and_replays_exactly`
- G2-32: `src-tauri/src/team/db.rs:1488` `a_new_database_reopens_with_its_schema_and_settings`; `src-tauri/src/team/db.rs:2155` `a_version_5_file_with_data_moves_to_version_6_keeping_every_row`; `src-tauri/src/team/db.rs:2117` `the_triggers_and_indexes_of_a_version_5_file_survive_version_6`
- G2-33: `src-tauri/src/team/sync.rs:6596` `an_unbind_tombstone_outlives_its_binding_and_replays_exactly`; `src-tauri/src/team/sync.rs:6698` `an_unbind_cut_off_at_any_write_leaves_the_binding_whole`; `src-tauri/src/team/sync.rs:6804` `a_tombstone_that_no_longer_recomputes_is_never_returned`; `src-tauri/src/team/sync.rs:7821` `an_unbind_after_an_accepted_transition_keeps_its_evidence`; `src-tauri/src/team/db.rs:1843` `a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding`
- G2-34: `src-tauri/src/team/sync.rs:4401` `a_release_whose_reply_was_lost_is_replayed_byte_for_byte`; `src-tauri/src/team/sync.rs:5052` `an_unsent_cancel_release_is_retried_and_then_given_up`; `src-tauri/src/team/sync.rs:6525` `an_unreadable_release_reply_is_reported_and_replayed`
- G2-35: `src-tauri/src/team/records.rs:487` `six_records_reopen_exactly_and_refuse_every_changed_column`; `src-tauri/src/team/records.rs:559` `a_second_self_grant_and_a_cross_instance_generation_are_refused`; `src-tauri/src/team/records.rs:627` `only_a_self_grant_files_a_generation_and_a_duplicate_row_refuses`; `src-tauri/src/team/ledger.rs:1380` `a_filed_grant_files_the_key_state_it_names`; `src-tauri/src/team/sync.rs:4626` `a_binding_and_its_rows_name_the_servers_account_and_key`; `src-tauri/src/team/sync.rs:6092` `a_kept_revocation_reloads_with_every_column_equal`
- G2-36: `src-tauri/src/team/db.rs:2491` `an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key`; `src-tauri/src/team/sync.rs:5548` `an_interrupted_upload_resumes_at_the_offset_head_reports`
- G2-37: `src-tauri/src/team/sync.rs:4293` `every_crash_point_resumes_with_the_exact_stored_bytes`; `src-tauri/src/team/sync.rs:4328` `a_stored_column_that_drifts_from_its_bytes_is_never_sent`; `src-tauri/src/team/sync.rs:5437` `a_stored_publish_that_drifts_from_its_bytes_is_never_sent`
- G2-38: `src-tauri/src/team/sync.rs:5572` `a_receipt_or_readback_that_does_not_match_is_never_kept`; `src-tauri/src/team/sync.rs:4209` `a_published_profile_pushes_and_another_device_pulls_it`; `src-tauri/src/team/db.rs:2491` `an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key`; `server/tests/v2_profiles.rs:2294` `an_upload_commits_once_and_the_next_checkout_starts_at_its_head`; `server/tests/v2_profiles.rs:2646` `every_upload_refusal_has_its_status_and_code`
- G2-39: `src-tauri/src/team/sync.rs:7050` `a_verified_transition_moves_only_the_bindings_it_covers`; `src-tauri/src/team/sync.rs:7230` `a_transition_that_does_not_verify_keeps_the_binding_quarantined`; `src-tauri/src/team/sync.rs:7413` `a_restore_epoch_that_goes_back_is_a_rollback`; `src-tauri/src/team/sync.rs:7437` `a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen`; `src-tauri/src/team/sync.rs:7661` `a_leaf_head_is_accepted_only_as_a_new_head_is`; `src-tauri/src/team/sync.rs:7742` `a_pinned_head_is_read_back_only_as_the_bindings_own`; `src-tauri/src/team/sync.rs:7770` `a_lapsed_or_former_custodian_signs_no_transition`; `src-tauri/src/team/sync.rs:7821` `an_unbind_after_an_accepted_transition_keeps_its_evidence`; `src-tauri/src/team/sync.rs:7862` `a_binding_changed_during_acceptance_is_not_moved`; `src-tauri/src/team/sync.rs:7991` `a_lease_from_before_the_restore_is_released_before_the_binding_moves`; `src-tauri/src/team/sync.rs:8133` `a_custodian_not_yet_appointed_signs_no_transition`; `src-tauri/src/team/sync.rs:8249` `a_failed_release_of_an_old_lease_is_retried_as_stored`
- G2-40: `src-tauri/src/team/db.rs:1517` `an_unknown_schema_fails_closed_and_is_left_as_it_was`; `src-tauri/src/team/db.rs:1967` `a_database_held_in_wal_mode_is_refused`
- G2-41: `src-tauri/src/team/journal.rs:701` `every_restore_phase_survives_close_and_reopen_in_order`; `src-tauri/src/team/journal.rs:724` `a_restore_phase_cannot_skip_repeat_or_leave_a_terminal_one`; `src-tauri/src/team/journal.rs:745` `a_restore_journal_retires_only_when_settled`; `src-tauri/src/team/journal.rs:757` `the_restore_resume_table_is_fixed_per_crash_point`; `src-tauri/src/team/journal.rs:834` `a_clone_journal_walks_its_chain_with_every_phase_surviving_reopen`; `src-tauri/src/team/journal.rs:906` `a_downgrade_phase_cannot_skip_and_a_rollback_is_always_open`; `src-tauri/src/team/journal.rs:1157` `the_resume_table_for_a_downgrade_journal_continues_every_open_phase`; `src-tauri/src/team/journal.rs:1171` `the_digests_survive_reopen_byte_for_byte`; `src-tauri/src/team/downgrade.rs:1778` `a_cut_off_at_every_step_resumes_to_the_same_finished_clone`; `src-tauri/src/team/downgrade.rs:1828` `a_process_killed_at_every_step_resumes_to_the_same_finished_clone`; `src-tauri/src/team/downgrade.rs:1843` `a_rollback_from_every_step_puts_the_original_back_and_frees_the_profile`; `src-tauri/src/team/downgrade.rs:3029` `a_readback_that_v0_1_28_would_not_agree_with_fails_the_flow`; `src-tauri/src/team/downgrade.rs:1597` `discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive`; `src-tauri/src/team/sync.rs:6734` `an_unbind_is_refused_while_a_lease_request_or_journal_is_open`
- G2-42: `src-tauri/src/team/db.rs:2800` `every_sync_integer_class_keeps_its_range_across_a_reopen`; `src-tauri/src/team/records.rs:675` `every_integer_class_keeps_its_range_across_a_reopen`
- G2-43: `src-tauri/src/team/sync.rs:4538` `every_publish_crash_point_resumes_with_the_exact_stored_bytes`; `src-tauri/src/team/sync.rs:7587` `a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key`; `src-tauri/src/team/sync.rs:5474` `a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte`; `src-tauri/src/team/sync.rs:4293` `every_crash_point_resumes_with_the_exact_stored_bytes`; `src-tauri/src/team/sync.rs:6596` `an_unbind_tombstone_outlives_its_binding_and_replays_exactly`; `src-tauri/src/team/sync.rs:4401` `a_release_whose_reply_was_lost_is_replayed_byte_for_byte`; `src-tauri/src/team/sync.rs:7526` `a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh`
- G2-44: `server/tests/v2_upgrade_chain.rs:1307` `the_plan_assertions_hold_on_a_reopened_fresh_file`; `server/tests/v2_upgrade_chain.rs:1318` `the_plan_assertions_hold_on_a_reopened_v0_1_28_file_and_its_backup_restores`; `server/tests/v2_upgrade_chain.rs:1355` `fixtures_1_to_4_hold_on_a_fresh_file`; `server/tests/v2_upgrade_chain.rs:1364` `fixtures_1_to_4_hold_on_a_v0_1_28_file_after_its_upgrade`; `server/tests/v2_upgrade_chain.rs:1376` `fixtures_1_to_4_hold_on_a_populated_0016_file_after_its_upgrade`; `server/tests/v2_upgrade_chain.rs:366` `m0017_root_generations_only_move_forward_on_upgraded_rows`; `server/tests/v2_upgrade_chain.rs:1438` `m0033_the_quarantine_gains_a_container_hash_and_stays_append_only`
- G2-45: `server/tests/v2_upgrade_chain.rs:489` `m0030_upgraded_integer_columns_refuse_values_that_are_no_integers`; `server/tests/v2_integer_domain.rs:209` `every_class_decodes_its_domain_ends_and_refuses_everything_else`; `server/tests/v2_integer_domain.rs:370` `every_class_column_stores_its_domain_ends_and_its_check_refuses_the_rest`; `server/tests/v2_integer_domain.rs:492` `every_integer_column_of_every_v2_table_has_an_upper_bound_check`; `server/tests/v2_integer_domain.rs:526` `every_integer_column_of_every_v2_table_refuses_a_value_that_is_no_integer`; `server/tests/v2_integer_domain.rs:586` `the_bound_scan_tells_bounded_from_unbounded_columns`
- G2-46: `shared/src/recovery_bundle.rs:741` `argon2id_matches_the_rfc_9106_vector`; `shared/src/recovery_bundle.rs:767` `the_kek_is_argon2id_over_the_labelled_salt`
- G2-47: `src-tauri/src/team_config.rs:427` `debug_never_prints_the_token_or_a_seed`; `src-tauri/src/fleet_keys.rs:410` `debug_never_prints_a_key`; `src-tauri/src/fleet_client.rs:1496` `a_session_debug_print_hides_its_tokens`; `src-tauri/src/root_bootstrap.rs:1447` `the_trk_is_stored_and_the_saved_state_holds_only_its_reference`; `src-tauri/src/root_bootstrap.rs:1494` `a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing`; `src-tauri/src/root_bootstrap.rs:1591` `a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it`; `src-tauri/src/root_bootstrap.rs:1326` `the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written`; `src-tauri/src/root_bootstrap.rs:1315` `the_saved_state_never_prints_the_legacy_trk`; `src-tauri/src/root_bootstrap.rs:1467` `a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key`; `src-tauri/src/root_bootstrap.rs:1539` `a_reference_to_another_credential_is_refused_and_that_credential_is_kept`; `src-tauri/src/root_bootstrap.rs:1686` `the_activation_is_saved_before_the_key_is_forgotten`; `src-tauri/src/root_bootstrap.rs:1748` `the_run_nonce_is_saved_before_the_key_is_stored`; `src-tauri/src/root_bootstrap.rs:1723` `a_new_run_never_reuses_a_key_an_abandoned_run_left`; `src-tauri/src/root_bootstrap.rs:1620` `a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed`; `src-tauri/src/root_bootstrap.rs:1858` `a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made`; `src-tauri/src/root_bootstrap.rs:1898` `a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it`; `src-tauri/src/key_file.rs:319` `a_forget_succeeds_only_once_the_key_is_confirmed_gone`
- G2-48: `src-tauri/src/credential.rs:172` `a_key_round_trips_and_is_forgotten`; `src-tauri/src/credential.rs:185` `references_are_separate_credentials`; `src-tauri/src/credential.rs:193` `a_failed_write_or_read_back_is_reported`; `src-tauri/src/credential.rs:263` `a_real_os_store_key_survives_into_a_fresh_process`; `src-tauri/src/credential.rs:305` `an_unavailable_store_fails_closed_in_a_fresh_process`; `src-tauri/src/credential.rs:359` `a_key_file_key_is_locked_then_served_in_a_fresh_process`
- G2-49: `src-tauri/src/durable.rs:151` `a_durable_write_replaces_the_file_and_leaves_no_temporary`; `src-tauri/src/durable.rs:190` `a_failed_replace_keeps_the_old_file_and_removes_the_temporary`; `src-tauri/src/durable.rs:233` `a_write_killed_at_any_step_leaves_the_old_or_the_new_file`; `src-tauri/src/durable.rs:269` `a_kill_during_back_to_back_writes_never_tears_or_loses_a_returned_write`; `src-tauri/src/durable.rs:290` `creating_a_file_that_exists_never_overwrites_it`; `shared/src/volume.rs:126` `only_a_local_ntfs_disk_is_accepted`; `shared/src/volume.rs:160` `a_local_ntfs_directory_is_accepted_and_a_missing_one_is_not`; `shared/src/volume.rs:179` `an_smb_share_is_refused`; `server/src/db.rs:348` `storage_that_cannot_be_resolved_is_refused`; `server/src/db.rs:371` `storage_on_an_smb_share_is_refused`; `server/src/identity.rs:697` `preflight_refuses_an_identity_directory_on_an_smb_share`; `server/tests/restore_epoch_harness.rs:2519` `an_identity_directory_the_preflight_refuses_never_falls_to_k1`; `server/tests/restore_epoch_harness.rs:2829` `an_empty_identity_directory_setting_refuses_to_start`
- G2-50: `server/src/db.rs:293` `the_database_runs_a_synced_rollback_journal_and_survives_an_unclosed_pool`; `server/src/db.rs:526` `a_killed_transaction_reopens_old_or_new_never_half`; `server/src/db.rs:595` `a_kill_between_commits_keeps_every_returned_commit`; `server/src/db.rs:617` `a_second_writer_waits_for_the_write_lock`; `server/src/db.rs:371` `storage_on_an_smb_share_is_refused`; `src-tauri/src/crash_harness.rs:141` `a_killed_transaction_reopens_old_or_new_never_half`; `src-tauri/src/team/db.rs:1967` `a_database_held_in_wal_mode_is_refused`; `shared/src/volume.rs:179` `an_smb_share_is_refused`
- G2-51: `shared/src/snapshot.rs:1265` `the_windows_path_corpus_is_refused_in_every_position`; `shared/src/snapshot.rs:1287` `every_name_windows_rewrites_is_refused`; `shared/src/snapshot.rs:1308` `ntfs_case_fold_collisions_are_refused_and_distinct_names_kept`; `shared/src/snapshot.rs:1359` `long_paths_unpack_and_an_overlong_one_is_refused`; `shared/src/snapshot.rs:1394` `a_junction_is_neither_packed_through_nor_followed_on_replace`; `src-tauri/src/team/downgrade.rs:1597` `discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive`; `src-tauri/src/team/downgrade.rs:1979` `a_trace_of_the_old_id_after_the_move_fails_the_discovery_scan`
- G2-52: `server/tests/restore_epoch_harness.rs:1260` `g2_52_every_crash_point_maps_to_one_row_and_resumes_to_the_restored_state`
- G2-53: `server/tests/identity_authority.rs:194` `a_symlinked_record_is_refused`; `server/tests/identity_authority.rs:456` `show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest`; `server/tests/restore_epoch_harness.rs:2596` `an_identity_directory_that_is_not_there_is_missing_and_stops_the_server`
- G2-54: `server/tests/restore_epoch_harness.rs:1635` `l2259_g2_54_a_record_equal_to_its_mirror_without_a_manifest_opens_normally`
- G2-55: `server/tests/restore_epoch_harness.rs:1674` `l2260_g2_55_a_durable_preparation_at_e_keeps_writes_off_until_commit_or_abort`; `server/tests/restore_epoch_harness.rs:1471` `g2_55_a_failed_read_only_audit_write_is_counted_in_restore_status`; `server/tests/restore_epoch_harness.rs:1543` `g2_55_the_k2_incident_output_prints_the_audit_failure_count`; `server/tests/restore_epoch_harness.rs:1587` `g2_55_a_directory_at_the_count_path_stops_a_read_only_start_by_name`; `server/tests/restore_epoch_harness.rs:2636` `g2_55_restore_commit_prints_the_final_audit_failure_count_and_clears_it`; `server/tests/restore_epoch_harness.rs:2677` `g2_55_a_read_only_start_logs_the_failed_audit_writes_counted_so_far`; `server/tests/restore_epoch_harness.rs:2728` `g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count`; `server/tests/restore_epoch_harness.rs:2754` `g2_55_a_count_under_a_changed_episode_key_is_kept_and_cleared_by_name`; `server/tests/restore_epoch_harness.rs:2909` `g2_55_a_count_file_with_a_bad_line_is_set_aside_and_its_valid_lines_kept`; `server/src/audit.rs:532` `a_failed_read_only_audit_write_is_logged_and_counted`; `server/src/audit.rs:573` `the_count_continues_across_read_only_restarts_of_one_episode`; `server/src/audit.rs:597` `a_changed_episode_key_keeps_the_old_count_until_it_is_cleared_by_name`; `server/src/audit.rs:641` `one_bad_line_in_the_count_file_loses_only_itself`; `server/src/audit.rs:709` `a_crash_while_setting_a_file_aside_never_loses_the_valid_lines`; `server/src/audit.rs:762` `the_count_is_written_atomically_and_an_unreadable_one_is_reported`; `server/src/audit.rs:792` `a_directory_or_link_at_the_count_path_is_refused_by_name`
- G2-56: `server/tests/restore_epoch_harness.rs:1756` `l2261_g2_56_an_authority_ahead_of_the_live_mirror_resumes_only_the_install`
- G2-57: `server/tests/restore_epoch_harness.rs:1823` `l2262_g2_57_an_installed_db_behind_the_record_is_verified_then_rebuilt`
- G2-58: `server/tests/restore_epoch_harness.rs:1918` `l2263_g2_58_an_authority_ahead_without_exact_evidence_fails_closed`; `server/tests/restore_epoch_harness.rs:1962` `l2263_g2_58_only_a_live_custodian_transition_over_the_computed_leaves_prepares`
- G2-59: `server/tests/restore_epoch_harness.rs:1543` `g2_55_the_k2_incident_output_prints_the_audit_failure_count`
- G2-60: `server/tests/restore_epoch_harness.rs:2031` `l2265_g2_60_a_reconciled_epoch_retires_its_bundle_and_the_next_start_is_normal`
- G2-61: `shared/src/backup_file.rs:448` `a_snapshot_sealed_for_another_profile_is_refused`; `shared/src/backup_file.rs:402` `another_fleet_key_cannot_open_it`; `shared/tests/backup_file_roundtrip.rs:133` `the_ciphertext_does_not_contain_the_plaintext`; `shared/tests/backup_file_roundtrip.rs:219` `a_tampered_backup_body_is_refused`; `shared/tests/backup_file_roundtrip.rs:185` `a_truncated_backup_is_refused_and_leaves_the_destination_untouched`; `shared/src/backup.rs:826` `every_single_byte_mutation_is_detected`; `shared/src/backup.rs:844` `truncation_at_any_length_is_detected`; `shared/src/backup.rs:869` `cross_envelope_frame_splice_is_rejected`; `src-tauri/src/sync_cmd.rs:662` `pull_refuses_another_profiles_snapshot`; `src-tauri/src/sync_cmd.rs:598` `push_seals_under_the_passphrase_even_with_a_cached_fleet_key`; `shared/src/grants.rs:684` `grant_cannot_be_replayed_into_another_tenant_or_epoch`; `shared/src/fleet_grants.rs:276` `tampering_with_the_stored_info_fails_the_open`; `server/tests/identity_authority.rs:406` `an_interrupted_init_is_reported_and_never_repaired`; `server/src/integrity.rs:559` `wrong_domain_hpke_ids_are_quarantined_once`; `src-tauri/src/lib.rs:2990` `a_server_delivered_fleet_key_is_counted_but_never_cached`; `src-tauri/src/lib.rs:3580` `a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet`; `src-tauri/src/team/sync.rs:5709` `a_compromised_revocation_blocks_commits_under_an_exposed_generation`; `src-tauri/src/team/sync.rs:5923` `a_compromised_custodian_blocks_every_fleet_through_the_root`; `src-tauri/src/team/sync.rs:6026` `an_exposure_survives_a_recollection_that_omits_its_grant`; `src-tauri/src/team/sync.rs:5985` `an_open_upload_is_aborted_once_a_compromise_is_counted`
- G2-62: document/manual/independent-verdict evidence
- G2-63: `shared/tests/registry_pins.rs:120` `every_signing_domain_is_distinct_and_versioned`; `shared/tests/registry_pins.rs:137` `every_hash_label_is_distinct_and_nul_terminated`; `shared/tests/registry_pins.rs:159` `the_numeric_registry_holds_the_reviewed_values`; `shared/src/keys.rs:578` `g2_golden_vector_profile_label`; `shared/src/keys.rs:427` `a_profile_label_opens_only_where_it_was_sealed`; `shared/src/keys.rs:470` `a_profile_label_has_a_length_bound_both_ways`; `shared/src/keys.rs:495` `a_profile_label_is_padded_to_a_bucket`; `shared/src/keys.rs:524` `a_profile_label_that_is_not_canonical_is_refused`
- G2-64: document/manual/independent-verdict evidence

### Additional Q-43 precision probe

Python SQLite 3.49.1 in-memory table using the verbatim local column `remote_version          INTEGER NOT NULL CHECK (remote_version BETWEEN 0 AND 9223372036854775807)` in STRICT mode: bound TEXT `9007199254740993.0` and `9007199254740993e0` each store INTEGER **9007199254740992**; TEXT `9007199254740993` and i64 9007199254740993 store **9007199254740993**. This is a lossy TEXT-to-REAL-to-INTEGER conversion accepted within range. It probes SQL input, not the CBOR wire codec. The existing test pairs cover fractional 0.5, out-of-range values and lossless end values, not this precision case.


## Independent semantic findings

These findings come from the fixed tree, not an adoption of an author's review. The requested prior independent report was read only to identify B1-B7 and their scenarios. No `.omc/`, `.omx/reports/`, author scratch reports or ADR review files were opened. The explicit plan path under `.omx/plans/` was read. The evidence-gate-verification skill supplied the verification method; its mutation suggestion was not applied because the user prohibits source edits.

### N1 - HIGH: a later compromised revocation is silently discarded

Locations: `src-tauri/src/team/db.rs:108` (table), `:116` (primary key); `src-tauri/src/team/ledger.rs:792` (counting), `:794` (INSERT ... ON CONFLICT DO NOTHING), `:669` (scan), `:695` (non-compromised reason skipped). Server permits re-filing with a fresh replay ID: `server/src/routes/v2_device_revoke.rs:644` reads the subject without requiring active status, `:671` scopes replay uniqueness to the record replay ID. Contract: ADR 0002 Q-13/Q-18, `docs/adr/0002-g2-contract-decisions.md:1734` (cause), `:1736` (refusal), `:1742` (release).

Failure scenario: this client first counts a valid `lost`, `retired` or `rekeyed` revocation for member M. M still holds fleet generation G. A current authorized custodian later files another genuine revocation of M with a new replay ID and reason `compromised`. The ledger evaluates the new record, but its primary key is only (instance, tenant, signing key, source). The insert keeps the first container. `commit_blocked` reads only that retained container, sees the earlier non-compromised reason and continues. With an honest unrevoked issuer delivering the client's fleet grant and available verification keys, new commits under G remain allowed although a counted compromised revocation now exposes G. This is not the accepted no-history omission limit: the client received both signed records.

An in-memory reproduction using the exact production CREATE TABLE and INSERT confirms the second container is discarded (details above). Signature verification and the full push path were source-traced, not dynamically bypassed. Existing tests exercise each reason in separate fresh worlds; none supplies two valid reasons for one key. This blocks G2-61 and qualifies the trust claims of G2-30/35/63. Retaining append-only exposure holdings fixes B2's original scenario but does not fix loss of the later compromise cause.

### N2 - MEDIUM: a persisted FINALIZE request bypasses the OPEN-upload compromise check

Locations: `src-tauri/src/team/sync.rs:1486` (guard only if no pending FINALIZE), `:1514` (unconditional finalize after that branch), `:2549` and `:2563` (reuse/store FINALIZE before network send), `:2569` (send). Contract: ADR Q-18 in-flight rule permits completion only for server READY/FINALIZING, and requires OPEN to abort.

Failure scenario: all ciphertext chunks reach an upload that remains OPEN. The client durably inserts FINALIZE, then crashes before the first request reaches the server (or transport drops it unprocessed). A compromise is counted before resumption. Local upload state is OPEN, but FINALIZE is PENDING, so the new guard is skipped; the client sends finalize and then commit without checking whether the server had ever reached FINALIZING/READY. The existing `every_crash_point_resumes_with_the_exact_stored_bytes` explicitly creates the dropped-unprocessed-finalize state (`src-tauri/src/team/sync.rs:4295`), but never counts a compromise there. The new B3 regression (`:5985`) stops at HEAD before a FINALIZE operation exists, so it covers only the other branch.

This is a source-proven state-machine counterexample, not a claim of an additional ciphertext disclosure after all chunks were already transferred. It nevertheless contradicts the frozen amended OPEN/READY boundary and leaves B3 only partially closed. A pending local intent does not establish the server state. No source mutation or added Rust test was performed.

Related B3 outcome discrepancies: `fail_upload` at `src-tauri/src/team/sync.rs:2418` marks only the local upload ABORTED and calls `abandon`; `abandon` at `:2722` sends RELEASE. The server release route (`server/src/routes/v2_profiles.rs:802`, `:859`) deletes the lease and does not transition the upload to ABORTED. The server has a separate abort endpoint (`server/src/routes/v2_uploads.rs:749`). The regression asserts only local rows. Also no production assignment of `ROTATION_REQUIRED_COMPROMISED` exists in the local `last_error_code`; the before-checkout branch returns an error without persisting it. These are backend state gaps, separate from the accepted UI deferral. They are not counted as extra independent security vulnerabilities here.

## B1-B7 closure assessment

- **B1: source-level fix present; dynamic regression result is recorded in the command ledger.** `ledger::holdings` at `src-tauri/src/team/ledger.rs:452` includes root/fleet issuer and recipient holdings, RecoveryGrant root holdings and RotationGrant issuers. `activations` binds the rotation's recovery hash and fleet/key/generation. `commit_blocked` searches the bound root and every higher root, including PREPARING, and fails closed when activation evidence is missing. The regression checks root-first/fleet-first order, later PREPARING roots, missing and mismatched evidence. No old shortcut remains. Runtime closure is qualified where fixture setup fails.
- **B2: original replacement-page failure is fixed in source.** `trust_key_holdings` is append-only, and replacing the retained fleet evidence does not delete its holdings. Schema v7 backfills retained evidence and raises min_reader_version. The named recollection regression retains the old exposure. Previously discarded pre-v7 history cannot be reconstructed; missing activation evidence initially fails closed. N1 is a different retained-evidence loss not addressed by this fix.
- **B3: PARTIAL, not closed.** Before-checkout refusal and the OPEN branch without FINALIZE are fixed. N2 and the related state discrepancies above remain. The regression checks no subsequent PATCH/finalize/commit and local lease release, but misses the pending-FINALIZE branch and server upload state.
- **B4: fixed in source.** `shared/src/trust_chain.rs:520` derives fleet scope only when every usable approval names that same fleet, otherwise tenant scope. `ledger::counted` uses that scope for device.revoke. The regression tests matching fleet, another fleet, mixed tenant approval and tenant capability. This matches the server's scope selection. Its execution result is recorded below; a setup failure is not a successful scenario reproduction.
- **B5: fixed in source and covered by substantive tests.** `DeviceRevokeRequestV2` parses 0..65535 sorted unique root/fleet activations, including max and max+1 cases. `server/src/routes/v2_device_revoke.rs:554` begins one write transaction; activations at `:689` and revocation at `:726` commit together. Tests assert incomplete recovery ACK rolls back activation and revocation, successful fleet activation commits both once, and root activation works. Results below determine runtime confidence.
- **B6: original blanket-coercion requirement is closed by the explicit Q-43 decision, with a precision caveat.** Keeping typed INTEGER columns and binding checked i64 values is sound at the stated wire boundary and consistent with server migration 0030. Fractional/out-of-range/nonnumeric/BLOB cases fail and leave prior values intact; endpoints survive reopen. The wording should not claim every arbitrary numeric TEXT conversion is exact: the independent 2^53+1 decimal/exponent probe above rounds before CHECK/STRICT, equally on the server's post-affinity strategy. This does not demonstrate a CBOR-to-i64 exploit; no wire code binding numeric TEXT was found. The new precision case is not covered by either cited local test.
- **B7: original matrix gap is fixed in source.** The custody matrix covers all 11 custody OperationKind variants, the profile matrix covers five profile variants, and LocalUnbind has its local reopen/tombstone test. Exhaustive matches reject an unhandled new enum variant at compile time. Helpers restart the real binary on the same DB, compare exact status/body, reject changed nonce under the same key, and compare every table's sorted rows before/after replay. COMMIT is a separate request type and is covered by the commit and restore replay tests. Results below qualify whether these scenarios were reproduced in this environment.

### `cargo +stable test --locked -j 2 --manifest-path server/Cargo.toml`

Exit 0; elapsed 554.4 s.

```text
    Finished `test` profile [unoptimized + debuginfo] target(s) in 2m 48s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.63s
test result: ok. 106 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 15.91s
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.67s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 13.03s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.76s
test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 63.00s
test result: ok. 75 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 206.84s
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.76s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 15.44s
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.68s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.60s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.42s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 38.52s
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.65s
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.89s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.28s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.24s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.60s
test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.15s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```


## Detailed samples (20 rows)

Execution outcomes are reported separately; a source-level satisfactory test design does not turn a setup failure into a pass.

| Row | Plan / ADR spot-check and independent source assessment |
| --- | --- |
| G2-01 | Plan 443-508; D-2/Q-1/Q-13/Q-22. Approval fields and identity/instance binding correspond to the closed maps. `v2_auth.rs:8686` mutates denormalized columns and checks refusal/quarantine; startup test at :8792 checks the restart path. `authz_record.rs:1940` pins signed-container hashes. The generic all-column helper at `v2_auth.rs:8993` first checks an intact positive control and restores each changed row. DDL-pinned versus request-compared columns are accounted for, rather than silently ignored. |
| G2-14 | Plan 910-1054; Q-5/Q-13. Shared mutation map tests enforce domains, version, unique operation scopes, hashes and closed fields. `shared/src/mutation.rs:2358` tests root/fleet activation ordering, duplicate rejection and 65535/65536 limits. Server revoke route uses a single transaction for activation and revocation; B5 tests inspect resulting rows and rollback. |
| G2-27 | Plan 1352-1371; ADR 0003/D-3. `envelope_v2.rs:1111` compares the published XChaCha vector; :1273 pins preamble/intent/slot/object hashes at multiple frame sizes; :1461 rejects counter gaps, repeated counters, empty/missing/following FINAL and oversized frames. Production :820 uses the provider DecryptorLE31 and authenticates AAD; frame parsing and bounded head parsing precede allocations. Counter test checks 0x7fffffff versus 0x80000000. No hand-written STREAM nonce replaces the provider. |
| G2-28 | Plan 1358; D-5/D-8. RFC 9180 test at `grants.rs:503` pins receiver key, ciphertext opens and exported secret. Recipient/context replay tests are substantive. `info_bytes_match_g2_vector` at :619 is mislabeled: it only asserts canonical roundtrip, despite claiming a pinned hash. However `authz_record.rs:2006` and :2019 actually pin fleet and root info lengths and SHA-256, and the root payload calls the same `grants::root_grant_info` builder. Therefore there is a citation/comment defect, not a demonstrated missing root-info golden value across the gate. |
| G2-30 | Plan 2338/2058 and probe 3; Q-13/Q-38. Revocation matrices at `v2_auth.rs:9609` and :9832 cover runtime/startup equality; `v2_device_revoke::load_revocation` re-verifies signature and exact row columns. Quarantine binds SHA-256 when the original container independently verifies; a swapped genuine container is refused after the mark. The ADR explicitly accepts the pre-mark two-step swap, which is not re-raised here. The cited Plan 2034 is startup compatibility, not the equality paragraph; 2040/2058 carry the latter. N1 is an independent client revocation-history gap. |
| G2-31 | Plan 1424/2048; Q-34/Q-42. `v2_auth.rs:10592` and `v2_profiles.rs:3920` helpers compare exact reply status/body across a real server restart and compare every table's rows; changed request nonce under the old idempotency key gets 409. Matrices exhaustively match OperationKind. Local unbind is covered separately. This is substantially stronger than the old B7 evidence. New compromise timing remains outside those replay-only matrices (N2). |
| G2-35 | Plan 2040/2058; Q-13/Q-26/Q-42. `team/records.rs:487` changes every column of six record shapes with CHECK/FK disabled, then demands the ledger-unreadable code for authoritative columns and an exact positive readback after rollback. It checks 326 refused changes (5*57+41); local credential/verification/ack metadata are explicitly excluded. :559 rejects a second self grant and wrong-instance generation by UNIQUE/FK. Production `records::load` at :287 reconstructs expected columns and verifies origin/instance; cryptographic signature and issuer trust are rechecked in the key-use chain, rather than being supplied by the SQL row alone. Revocation coverage is a separate seventh-family test. |
| G2-39 | Plan 2044; Q-1/Q-36/Q-37. `team/sync.rs:7050` verifies an n=3 restore proof, persists exact transition/proof bytes, advances only covered bindings and leaves the uncovered profile quarantined; reads the reopened DB and attempts a subsequent push. Negative tests vary tenant/instance/head/signing custody/lapse and old lease release. Shared proof tests cover n=1/2/3 and unary/binary direction/tamper cases. DPAPI-dependent setup limits runtime verification here. |
| G2-41 | Plan 2046; Q-35/Q-40. `team/journal.rs:701` closes/reopens each restore phase; :724 rejects skipping/repeating/terminal escape; :757 pins the phase-to-resume table. Downgrade :1778 injects every cut point and :1828 kills the child process; both check file placement, cloned content and repeat completion. Ignored child tests are intentionally invoked by the parent with crash environment, not missing parent assertions. Restore has no production writer, honestly disclosed; probe 9 requires durable phases/resume classification, so the broader restore workflow deferral alone is not a blocker. |
| G2-42 | Plan 2047 as amended by Q-43. Both local tests bind integer endpoints, reject fractional/out-of-range/nonnumeric/BLOB values while checking the old value stays, then reopen and verify max and typeof INTEGER. They deliberately accept lossless examples. The tests have substantial assertions despite long fixture construction. See B6 for the separate numeric TEXT precision caveat and the typed-i64 boundary. |
| G2-43 | Plan 2048; D-7/Q-42. Replay tests inspect byte-identical stored requests/responses for publish, checkout, upload, finalize, release and unbind, plus expired/superseded outcomes requiring a new key. `sync.rs:4293` has both a finalize dropped before processing and a lost response after processing. That is good response-loss coverage, but it is not a compromise-crossing matrix; N2 is the missing combination. |
| G2-44 | Plan 2080-2222; Q-34/Q-38. Fresh, v0.1.28 and populated 0016 tests call substantive assertion helpers. `v2_upgrade_chain.rs:1190` onward checks exact UNIQUE/FK error classes with valid controls, instance/generation/key components, reopened integrity and foreign_key_check; the upgrade backup is hashed, restored and migrated again. Zero inline assert macros in small wrappers are not vacuous tests. Mutation scripts were inspected as cited artifacts but not executed because they edit source. |
| G2-45 | Plan 2338/2343; integer contract/D-6. `v2_integer_domain.rs:370` tests decoded/storage ends, malformed values and specific CHECK versus trigger errors, then all v2 integer columns are scanned for upper bounds/type checks. Migration 0030 adds BEFORE INSERT/UPDATE type predicates after affinity. This agrees with Q-43 for typed wire integers; it does not inspect original arbitrary numeric TEXT spelling. |
| G2-49 | Plan 2337/1175/2250; Q-30/Q-39. `durable.rs:19` writes sibling temp, sync_all, replace and parent equivalent; Windows :82 uses MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH). Parent kill tests check old-or-new whole bytes and previously returned writes. `volume.rs:46` classifies only local NTFS; :65 resolves junction/mapped paths before checking. Real SMB tests return early without reachable shares. They must not be counted as proof merely because libtest prints ok. The harness is process-kill evidence, not a power-pull guarantee, as Q-30 permits. |
| G2-50 | Plan 2337/2063; Q-16/Q-30/Q-31. Server DB opens DELETE journal + FULL synchronous + busy timeout, not WAL. Tests kill open and between-commit transactions, verify old-or-new consistency and last returned commits, and exercise lock waiting. Launcher refuses existing WAL. This is a deliberate supported-mode decision, not missing WAL enablement. Actual network-share refusal remains conditional. |
| G2-52 | Plan 2339/2250-2269; D-1/Q-30/Q-33/Q-35. `restore_epoch_harness.rs:1260` enumerates six prepare and fourteen commit cuts, checks exit 86, exact K classification, external epoch monotonicity, hot-journal behavior and final restored state. `server/src/restore.rs:197` maps observations to K classes, :343 writes/syncs/replaces artifacts, and commit installs/reconciles before normal writes. Tests retain pre-restore archives unless deletion is explicitly requested. |
| G2-55 | Plan 2262; D-1/Q-38. Prepared-at-E test checks writes stay closed until commit/abort. HTTP login failure tests inspect durable audit count across restarts, episode changes and corrupted-line salvage, and explicit clearing. `audit.rs:112` refuses symlink/non-file count paths; restore status prints counts. The network-data-directory subcase at `restore_epoch_harness.rs:2728` has a loopback-share early return, independently of the SHARDX_TEST_SMB_DIR setup. |
| G2-59 | Plan 2266; D-1/Q-39. The row's single command is the K2 audit test, whose fixture sets another server instance; it does not itself prove every behind-epoch case. The broader restore class/harness tests cover behind and different-instance classifications. This is weaker row-specific citation than the full-suite coverage, not evidence that the production comparator is absent. |
| G2-61 | Plan 2340; Q-13/Q-14/Q-18. Tamper/recipient/profile isolation assertions are meaningful, but several fail in DPAPI fixture creation here before reaching their assertions. New holdings and scope code address B1/B2/B4. N1 and N2 prevent the broad DONE trust-enforcement claim from holding. G2-48/UI exceptions do not remove these backend obligations. |
| G2-63 | Plan 2341; D-8/Q-41. Registry numeric pins match suite IDs and sizes; label sealing uses a separate HKDF-SHA256 subkey, typed IDs/generation AAD, nonce(12), tag(16), u16 length and minimal 64/256/1024 buckets. `keys.rs:578` pins subkey and ciphertext hashes; malformed padding/minimal-bucket and cross-context opens are tested. The aggregate registry contains 67 domains and 20 labels, not every shared label (see discrepancy list). Independent scanning of 105 constant declarations found 105 distinct values. The security artifact exists and its hash was checked; author review conclusions were not used as verifier evidence. |

## Exact structure cross-checks

The plan-side common authorization fields are domain/version/replay_id/tenant_id/issued_at_ms/not_before_ms/not_after_ms/server_instance_id/restore_epoch. Device approval adds subject account/device/signing/HPKE IDs, approval scope kind/ID and approved_use. These map one-for-one to the parser and persisted equality columns; the seven-family amendment adds DeviceRevocation with subject identity and reason. Fleet HPKE info also binds fleet/key/generation, recipient and the fixed mode/KEM/KDF/AEAD tuple (0,32,1,3), suite 1 and capability; root info binds root key/generation in the corresponding closed map. Relevant known hashes: fleet HPKE info `2a4877e5df7b46a2c00c6809e334f58cdffdeefe063b36d78c7611c593f8e518`, root info `83cf05a9e2a487fa64210dfa9fdc2486e9e84615f1a4842d920c8190a42f1493`.

ADR 0003's 64-byte preamble is magic[8], version u16, preamble length u16, suite u16, flags u16, intent length u32, slot length u32, frame plaintext size u32, reserved u32=0, intent SHA-256[32], all fixed integers big-endian. Runtime values are SHARDXBK/version 2/length 64/suite 2/flags 0; STREAM uses LE31 internally with a 20-byte prefix. Frame header is kind u8/counter u32/ciphertext length u32 and the final frame is non-empty. These are pinned by the golden and malformed tests.

Q-41 label derivation was compared field-by-field: HKDF info label + tenant(16) + fleet(16) + profile(16) + u64be(generation); separate AAD label with the same identity tuple; plaintext u16be(length), bytes, zero padding to smallest bucket. The pinned generation-7 subkey is `1b9252810d436b045965d1105ea45a008a6e9735b98acaa6466d352747e505dd`; this is public deterministic fixture output, not a real key.

### `cargo +stable build --locked -j 2 --manifest-path server/Cargo.toml`

Exit 0; elapsed 122.8 s.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 02s
```

### G2-01 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt every_approval_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_approvals_that_left_their_containers`

Exit 0; elapsed 46.1 s.

```text
test every_approval_column_is_compared_with_its_container_on_each_request ... ok
test the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt ... ok
test the_startup_pass_quarantines_approvals_that_left_their_containers ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 72 filtered out; finished in 12.04s
```


## All-row plan and ADR citation readback

These are actual current plan text snippets at the first cited line, plus ADR identifiers checked for presence. Blank headings or broad section anchors are not treated as exact criteria. Full cited ranges were used in detailed samples.

| Row | Packet plan citation | Current first cited line | ADR decision(s) |
|---|---|---|---|
| G2-01 | L443-L508 | #### 5.6.1. Authorization payload schemas | D-2, Q-1, Q-13, Q-22 |
| G2-02 | L443-L508 | #### 5.6.1. Authorization payload schemas | Q-2, D-2, Q-13 |
| G2-03 | L443-L508, L1358 | #### 5.6.1. Authorization payload schemas | D-8, D-9, Q-5, Q-13, Q-26 |
| G2-04 | L443-L508 | #### 5.6.1. Authorization payload schemas | D-5, D-9 |
| G2-05 | L443-L508 | #### 5.6.1. Authorization payload schemas | D-5, D-9, Q-5 |
| G2-06 | L760-L909 | #### 5.6.4. Exact `TenantRootKeyGrantV2` contract | Q-1, D-4, Q-23, Q-24 |
| G2-07 | L509-L589 | #### 5.6.2. Exact snapshot manifest, commit request và receipt schemas | Q-1, Q-36 |
| G2-08 | L509-L589 | #### 5.6.2. Exact snapshot manifest, commit request và receipt schemas | Q-34 |
| G2-09 | L509-L589 | #### 5.6.2. Exact snapshot manifest, commit request và receipt schemas | none |
| G2-10 | L590-L759 | #### 5.6.3. Exact envelope-intent, restore-transition và Merkle-proof contracts | D-3, ADR 0003, D-8 |
| G2-11 | L590-L759 | #### 5.6.3. Exact envelope-intent, restore-transition và Merkle-proof contracts | D-3, ADR 0003 |
| G2-12 | L590-L759 | #### 5.6.3. Exact envelope-intent, restore-transition và Merkle-proof contracts | D-1, Q-1, Q-36 |
| G2-13 | L590-L759 | #### 5.6.3. Exact envelope-intent, restore-transition và Merkle-proof contracts | D-1, Q-33, Q-36 |
| G2-14 | L910-L1054 | #### 5.6.5. Exact mutation request/stored-response/idempotency contracts | Q-5, Q-13 |
| G2-15 | L910-L1054 | #### 5.6.5. Exact mutation request/stored-response/idempotency contracts | D-6, Q-34 |
| G2-16 | L915 | `PROFILE_PUBLISH_CREATE / PROFILE_CHECKOUT / CREATE_UPLOAD / FINALIZE_UPLOAD / RELEASE_LEASE / LOCAL_UNBIND / ROOT_GENERATION_CREATE / ROOT_GRANT_CREATE / ROOT_GRANT_ACK / ROOT_G | Q-5, D-4, D-9, Q-28 |
| G2-17 | L915 | `PROFILE_PUBLISH_CREATE / PROFILE_CHECKOUT / CREATE_UPLOAD / FINALIZE_UPLOAD / RELEASE_LEASE / LOCAL_UNBIND / ROOT_GENERATION_CREATE / ROOT_GRANT_CREATE / ROOT_GRANT_ACK / ROOT_G | Q-5, D-4, D-9 |
| G2-18 | L915 | `PROFILE_PUBLISH_CREATE / PROFILE_CHECKOUT / CREATE_UPLOAD / FINALIZE_UPLOAD / RELEASE_LEASE / LOCAL_UNBIND / ROOT_GENERATION_CREATE / ROOT_GRANT_CREATE / ROOT_GRANT_ACK / ROOT_G | Q-5, D-9 |
| G2-19 | L915 | `PROFILE_PUBLISH_CREATE / PROFILE_CHECKOUT / CREATE_UPLOAD / FINALIZE_UPLOAD / RELEASE_LEASE / LOCAL_UNBIND / ROOT_GENERATION_CREATE / ROOT_GRANT_CREATE / ROOT_GRANT_ACK / ROOT_G | Q-5, D-9, Q-24, Q-28 |
| G2-20 | L915 | `PROFILE_PUBLISH_CREATE / PROFILE_CHECKOUT / CREATE_UPLOAD / FINALIZE_UPLOAD / RELEASE_LEASE / LOCAL_UNBIND / ROOT_GENERATION_CREATE / ROOT_GRANT_CREATE / ROOT_GRANT_ACK / ROOT_G | Q-5, Q-23 |
| G2-21 | L915, L1137 | `PROFILE_PUBLISH_CREATE / PROFILE_CHECKOUT / CREATE_UPLOAD / FINALIZE_UPLOAD / RELEASE_LEASE / LOCAL_UNBIND / ROOT_GENERATION_CREATE / ROOT_GRANT_CREATE / ROOT_GRANT_ACK / ROOT_G | Q-41, Q-42 |
| G2-22 | L915, L1138 | `PROFILE_PUBLISH_CREATE / PROFILE_CHECKOUT / CREATE_UPLOAD / FINALIZE_UPLOAD / RELEASE_LEASE / LOCAL_UNBIND / ROOT_GENERATION_CREATE / ROOT_GRANT_CREATE / ROOT_GRANT_ACK / ROOT_G | Q-34, Q-42 |
| G2-23 | L915, L1147-L1158 | `PROFILE_PUBLISH_CREATE / PROFILE_CHECKOUT / CREATE_UPLOAD / FINALIZE_UPLOAD / RELEASE_LEASE / LOCAL_UNBIND / ROOT_GENERATION_CREATE / ROOT_GRANT_CREATE / ROOT_GRANT_ACK / ROOT_G | Q-34 |
| G2-24 | L915, L1159-L1219 | `PROFILE_PUBLISH_CREATE / PROFILE_CHECKOUT / CREATE_UPLOAD / FINALIZE_UPLOAD / RELEASE_LEASE / LOCAL_UNBIND / ROOT_GENERATION_CREATE / ROOT_GRANT_CREATE / ROOT_GRANT_ACK / ROOT_G | Q-34 |
| G2-25 | L915, L1140 | `PROFILE_PUBLISH_CREATE / PROFILE_CHECKOUT / CREATE_UPLOAD / FINALIZE_UPLOAD / RELEASE_LEASE / LOCAL_UNBIND / ROOT_GENERATION_CREATE / ROOT_GRANT_CREATE / ROOT_GRANT_ACK / ROOT_G | Q-34, Q-42 |
| G2-26 | L915, L2038, ADR D-7 | `PROFILE_PUBLISH_CREATE / PROFILE_CHECKOUT / CREATE_UPLOAD / FINALIZE_UPLOAD / RELEASE_LEASE / LOCAL_UNBIND / ROOT_GENERATION_CREATE / ROOT_GRANT_CREATE / ROOT_GRANT_ACK / ROOT_G | D-7, Q-37, Q-40 |
| G2-27 | L1352-L1371 | ### 9.3. Algorithms và framing | D-3, ADR 0003 |
| G2-28 | L1358 | - Device distribution: HPKE RFC 9180, suite mặc định đề xuất X25519 + HKDF-SHA256 + ChaCha20-Poly1305; exact `DeviceHpkeGrant` signed payload bind suite, info,  | D-8, D-5 |
| G2-29 | L2335 | - Reproducible spike matrix cho STREAM/final-frame AAD, HPKE out-of-envelope TRK/FKEK grants, signing suite và every exact `CanonicalCborV2` contract named in 5 | D-8 |
| G2-30 | L2338, L2034, L2058 | - Strict Windows path/case-fold/discovery corpus và current SQLite support cho local DDL + eleven probes, plus fresh/upgrade server migration probes for snapsho | Q-13, Q-38 |
| G2-31 | L2338, L1424, L2048 | - Strict Windows path/case-fold/discovery corpus và current SQLite support cho local DDL + eleven probes, plus fresh/upgrade server migration probes for snapsho | Q-34, Q-42 |
| G2-32 | L1450-L2034, L2036 | -- Every INTEGER below that mirrors an unsigned wire value repeats this bound. | Q-1, Q-37, Q-42 |
| G2-33 | L2038 | 1. **UNBIND delete:** insert completed `UNBIND` với exact response/receipt bytes, delete `profile_bindings` row, assert `operations.local_profile_id IS NULL` nh | D-7, Q-37 |
| G2-34 | L2039 | 2. **RELEASE response loss:** insert completed `RELEASE`, close/reopen, replay cùng scope/key/hash/full bytes và assert exact `IdempotentStoredResponseV2` + rel | Q-34 |
| G2-35 | L2040, L2034, L2058 | 3. **Canonical authorization/root grants + equality:** cho năm records ở 5.6.1 và `TenantRootKeyGrantV2`, encode→decode→re-encode byte-identical; reject every n | Q-13, Q-26, Q-42 |
| G2-36 | L2041 | 4. **Upload resume/digest + identity/replay FK:** persist upload `snapshot_id`, `manifest_replay_id`, offset/digest/size, intent/preamble/slot hashes, instance/ | none |
| G2-37 | L2042 | 5. **Manifest/request byte-identical replay + equality mismatch:** before finalize persist COMMIT operation + upload with exact manifest/request bytes/hashes an | none |
| G2-38 | L2043 | 6. **Receipt replay/mismatch:** server commit persists exact `CommitReceiptBindingV2` bytes/hash atomically; local verifies request/snapshot/version/head/lease- | none |
| G2-39 | L2044 | 7. **Tenant/profile epoch transition:** exact 5.6.3 vectors for `n=1/2/3`, binary/unary nodes and directions; create colliding profile IDs across tenants and mu | Q-1, Q-36, Q-37 |
| G2-40 | L2045 | 8. **Unknown schema:** mutate test DB thành `schema_version = reader_max + 1`, `min_reader_version = binary_version + 1`, non-singleton hoặc `migration_state != | none |
| G2-41 | L2046 | 9. **Recovery journal:** advance durable restore journal qua phase, close/reopen tại từng crash point và assert replay chọn đúng next/rollback phase; completed  | Q-35, Q-40 |
| G2-42 | L2047 | 10. **SQLite unsigned wire range:** boundary vectors `0` và `9223372036854775807` pass cho mỗi wire-integer class; `-1`, `9223372036854775808`, `184467440737095 | D-6, Q-43 |
| G2-43 | L2048 | 11. **Exact mutation replay:** for publish-create, checkout, create-upload, finalize and local unbind, simulate response loss before client receipt persistence  | D-7, Q-42 |
| G2-44 | L2080-L2222 | **Executable server migration probes — fresh và upgrade-from-v0.1.28** | Q-34, Q-38 |
| G2-45 | L2343, L2338 | **Gate:** mọi row có reproducible evidence, rồi independent verifier readback commands/fixtures/versions/SHA-256 và phát verdict `PASS`. Bất kỳ uncertainty về e | D-6 |
| G2-46 | L1377 | - Default fallback: salt random >=16 bytes; Argon2id profile khởi điểm 64 MiB, `t=3`, `p=4`, output 32 bytes theo profile memory-constrained RFC 9106; benchmark | D-5, Q-7, Q-21 |
| G2-47 | L2335 | - Reproducible spike matrix cho STREAM/final-frame AAD, HPKE out-of-envelope TRK/FKEK grants, signing suite và every exact `CanonicalCborV2` contract named in 5 | D-5 |
| G2-48 | L1374-L1376, L2335, ADR Q-29 | - Ưu tiên backend OS credential store explicit theo platform; dependency spike phải chọn `keyring-core` + platform backend thay vì ngầm tin behavior cross-platf | Q-29, D-5 |
| G2-49 | L2337, L1175, L2250 | - Windows durability harness prove file `sync_data`, immutable rename, parent-directory fsync/durable equivalent và SQLite WAL/busy/crash ordering trên supporte | Q-30, Q-39 |
| G2-50 | L2337, L2063 | - Windows durability harness prove file `sync_data`, immutable rename, parent-directory fsync/durable equivalent và SQLite WAL/busy/crash ordering trên supporte | Q-16, Q-30, Q-31 |
| G2-51 | L2338 | - Strict Windows path/case-fold/discovery corpus và current SQLite support cho local DDL + eleven probes, plus fresh/upgrade server migration probes for snapsho | Q-30 |
| G2-52 | L2339, L2250-L2269 | - Filesystem restore-epoch harness prove external checksummed record nằm ngoài SQLite rollback scope; candidate/transition/preparation fsync; external replace+p | D-1, Q-30, Q-33, Q-35 |
| G2-53 | L2260 |  /  External record missing/corrupt  /  Bất kỳ DB/mirror  /  `EPOCH_AUTHORITY_MISSING/CORRUPT`; disable v2 writes, không rebuild authority từ DB/backup  /  | D-1, Q-39 |
| G2-54 | L2261 |  /  External instance/epoch = DB mirror  /  Không có non-terminal restore preparation  /  Normal read-only verification rồi open; checksum/hash mismatch vẫn fail clos | D-1 |
| G2-55 | L2262 |  /  Preparation durable, external vẫn `E`, DB mirror `E`  /  Candidate + transition set valid, authority commit point chưa qua  /  Giữ writes off; resume validation/s | D-1, Q-38 |
| G2-56 | L2263 |  /  External `E+1`, live DB vẫn mirror `E`  /  Exact preparation manifest/candidate/transition hashes valid  /  Resume atomic DB install rồi read-only reconcile; khôn | D-1, Q-33 |
| G2-57 | L2264 |  /  External `E+1`, installed restored DB mirror `< E+1`  /  Same-instance preparation manifest và complete tenant transition/proof set valid  /  Verify candidate/int | D-1, Q-33 |
| G2-58 | L2265 |  /  External ahead DB nhưng preparation/transition/proof thiếu, corrupt, uncovered hoặc cross-tenant  /  Không đủ exact recovery evidence  /  `EPOCH_RECONCILIATION_RE | D-1, Q-33, Q-36 |
| G2-59 | L2266 |  /  External epoch hoặc instance **behind/different from DB mirror**  /  Bất kỳ  /  `EPOCH_AUTHORITY_BEHIND_DB`; security incident, fail closed; không copy/lower/rewr | D-1, Q-39 |
| G2-60 | L2267 |  /  External = reconciled DB mirror `E+1`, preparation journal terminal  /  Hash/readback/fsync pass  /  Retire preparation bundle; subsequent startup normal  /  | D-1, Q-28 |
| G2-61 | L2340 | - Trust-boundary tests distinguish guarantees: artifact/blob/backup tamper is client-detected and confidentiality-preserving; live coordination/RBAC DB rollback | Q-13, Q-14, Q-18 |
| G2-62 | L2336, L2343 | - Official vectors + malformed/counter/final/trailing-byte tests; prove exact API semantics, algorithm IDs, license, maintenance, MSRV, feature graph và advisor | D-3, ADR 0003 |
| G2-63 | L2341 | - Security review artifact chốt suite/provider hoặc ghi blocker; không được “tạm implement” primitive chưa pass. | D-8, Q-41 |
| G2-64 | L2343, L2512, L2565 | **Gate:** mọi row có reproducible evidence, rồi independent verifier readback commands/fixtures/versions/SHA-256 và phát verdict `PASS`. Bất kỳ uncertainty về e | Q-15, Q-32 |

ADR exact pointers: Q-43 at :122; Q-18 cause/refusal/in-flight/local-state/release at :1734-1742; PREPARING-root scenario :1771; Q-32 at :85 permits Hermes **or** Codex. The packet section 8 instead says both verifiers must PASS, which is stricter than the cited Q-32. This report does not manufacture a second verifier.


## Discrepancies and evidence limits

1. N1 and N2 above materially contradict the G2-61 trust-enforcement DONE claim. B3's named regression misses a persisted-but-unsent FINALIZE, and checks local ABORTED state rather than server ABORTED state. The ADR-required local last_error_code is also not persisted.
2. `shared/src/grants.rs:619` is not the pinned golden-info test its name/comment and G2-28 annotation claim. The actual root/fleet info hashes are pinned in `authz_record::tests::golden_vectors`, so this is a misleading citation with compensating coverage.
3. `shared/tests/registry_pins.rs:19`/`:89` has 67 domains and 20 labels, not the all-shared namespace comparison D-8 promises at `docs/adr/0002-g2-contract-decisions.md:1321`. Missing constants include root/fleet HPKE AAD labels (`grants.rs:52`, `:343`), mutation request/response and root/fleet set labels (`mutation.rs:48`, `:49`, `:55`, `:56`), tombstone (`profile_lease.rs:586`), recovery bundle/KDF/readiness and fallback plaintext/KDF domains. Golden vectors pin several individually, but do not assert pairwise distinction across this omitted set. An independent scan of 105 actual string/byte domain-label constant declarations found 105 unique values; no present collision is alleged. The aggregate test's coverage claim is weaker than stated. Inline domain literals are a further limit of that constant-only scan.
4. Q-43's production typed-i64 decision is consistent with the server; its universal description of lossless numeric TEXT is overbroad. `9007199254740993.0` is an accepted lossy SQL input (see reproduction), while integer TEXT/i64 forms stay exact. Current tests omit that precision boundary. This is a SQL-contract wording/coverage issue, not demonstrated unvalidated wire input.
5. G2-21 plan L1137 is blank; publish is L1139. G2-22 L1138 is the listing route; checkout is L1140. G2-25 L1140 is checkout; release is L1142. Broad L915 still enumerates their operation kinds, and their tests exercise the intended routes. G2-30 L2034 is schema compatibility; equality is L2040/2058. Restore test names retain old plan line numbers, two below current, as the packet acknowledges.
6. G2-59's single named test demonstrates a different-instance K2 incident and audit count, not all behind-epoch cases by itself. Broader harness/classification tests supply the other coverage. Its row command is weaker than the row title if read alone.
7. SMB probes return early yet libtest counts them as passed. Some restore tests use the administrative loopback share instead of the explicit temporary share variable; the CI setup of SHARDX_TEST_SMB_DIR alone does not guarantee these branches execute. The symlink test separately checks a directory and returns if symlink creation lacks privilege (error 1314). No test marked DONE is credited with an unexecuted conditional branch here.
8. Cited tests have no direct #[ignore] attributes. Ignored crash-child entrypoints are deliberately run by nonignored parent tests with exact filters/environment; they are not silently dropped coverage. Standalone manual/recovery drills remain ignored and are listed in gate counts. G2-48's real-store parent is explicitly excluded by this verifier's no-Credential-Manager constraint.
9. README section 11's old 255 distinct/307 pairs and historical counts are not current-tree counts. The fixed packet now names 265 distinct file/test pairs and 317 row/test pairs. Prior run outcomes, prior commit CI and authors' closure assertions are not substitutes for this run.
10. The manifest is a fixed evidence-file list, not a hash of every executed production source. In particular, `shared/src/trust_chain.rs` and `server/src/routes/v2_fleet.rs` are relevant closure paths outside the fixed packet artifact list. The ledger and root-grant route are already included. The exact repository commit binds those source paths; additional hashes are recorded below. The README and SHA256SUMS intentionally exclude themselves from their own list.
11. Packet Q-32 wording says both verifiers must PASS, whereas the actual ADR says Hermes or Codex. This report is one independent verdict. Neither the absent second report nor the two owner exceptions is being used as a standalone blocking finding.
12. The restore journal production writer, Team UI/event presentation, local-backup Argon2 p=1 deviation, type-level zeroization evidence and credential persistence limit are explicitly distinguished from the covered backend probes. No freed-memory or physical power-loss test was claimed. User-approved G2-48 and UI deferral remain accepted.

The requested gate commands caused the Tauri build script to regenerate two tracked schema JSON files. Those were generated side effects, not intentional verifier changes; exact HEAD restoration and clean final status are recorded at the end. No source mutations, worktree/branch operations, commits, pushes, comments, issues, PRs, production hosts or real credential-store operations are part of this verification.

## Hash readback

The packet checker returned `118 files checked, 0 problems`, exit 0. Hash convention: SHA-256 after CRLF-to-LF normalization, not necessarily raw checkout bytes. The following is the checked manifest, reproduced for auditability:

```text
8b9ef41a21e93d19b4e4fe4641aff06d96a123256cb00c0e8580f0fa70a5523e  .omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md
7f537e2ad776b15feef977a6b38c96abf2e341deab0ff1a230aa4de12f0d8b54  docs/adr/0002-g2-contract-decisions.md
6f5f4a2b622004641b4e14e3491d0b2d2f2ad94516d47ae20277a2e0a7715894  docs/adr/0003-envelope-v2-stream.md
b57bcac69f46d18a252cd735be09571efac6eb13990474decd084feac9f3cae0  docs/adr/0004-credential-store.md
35d6caaefc0bf5d8019256ed96ef1dba8ef64a320c1049e6aa47d26f0cdec3b3  docs/dependency-review.md
1411a14b5533bcd8e22963480a5c2f60a058571d413fcdb7fbe678cd60dd2b30  docs/g2-48-manual-check.md
e77ffd79b91b4973e93fdf85e30cd3867e92948ee1f98c0d3c0dee803874fc61  docs/g2-evidence/verifier-codex-2026-11-01.md
d94741ac1d41c74e2ec12f63468ee880c787d247556252aa71d074169431d6fd  docs/key-custody.md
0c7356078ea3992a01f2520fef753c0571cfb8b37c9ecef52f7bd3c326b52fbc  docs/security-review-g2.md
f2d5a11f5258c112b1e1d2928ddcff622796d12b779a612c591561e73b10ca81  docs/trust-boundaries.md
df7a8ef919035e0ea622fa2585130d6e7a376de0e1398f3c699e64f9596dbfd1  package.json
2e6f3583e175fe8ee8cd5c07a05e4c3bbd9d4022a0d7231e453a372590576ad3  scripts/backend-error-locale.test.mjs
5626e47ebb99bff53bbbc0368f3559dbe614701a23f8a0b2a1a072b493241cac  scripts/g2-44-migration-mutants.py
d746b3388b5c22619e83364d2ac30be5a6ca0fd34f02f6470ede7aea41ef9ef9  scripts/g2-48-credential-check.ps1
7f30ac478e06f61405e45e9e6e401b5fa3a620ff42a7ca5534dfde7a000f2fa7  scripts/g2-evidence.py
f5c785e19f147a03c0cbf72b035a07b5f84e6abb996b05738fe9851d1c4fdb57  scripts/g2-wp5-mutants.py
73134016054c07db46b45601ac00296582094e4acb2102e77314629dbeedd0da  scripts/i18n-locale-parity.test.mjs
ca33c963924704db3918f6bb4e10cc5437f54e4a4bdd9832f3b3334f0587aacd  scripts/rust-user-strings.baseline.json
7a0000221b2d4012c2931073a908f73cd248464626e9ab3c473eb88f0edf3339  scripts/rust-user-strings.test.mjs
8abb55bd3abd995cd973823c78f5f70cc36d2afa9c9514238f993265fe1ad717  server/Cargo.lock
62856599b5732dfe91e2b9a02821845eb1eda136a3232b3b8493735083373cb6  server/Cargo.toml
154f82267c2523e7d98dc9bf8a60df9662376d03dd524367da59f7e42d619524  server/migrations/0001_init.sql
5e2bf8c5ab8522b71f8e6b9b0fedf0bfefc6753fdc1a41142691c152aa57fe03  server/migrations/0002_lock_token_and_token_version.sql
2c9b27a9072938b07a56fb60b696ea01f34e5ff3e97e97d4dbea1a5a9ec55136  server/migrations/0003_clear_empty_lock_tokens.sql
64e8a39f005acb4697caed1bd0079502d77aac32a80af4995ea70c4c223f653b  server/migrations/0004_v2_team_fleet.sql
043c25e1b8ee785b7b1ff4cf0dc979b268fcaedfdb143d5e87ccf76c9255b298  server/migrations/0005_replay_ledger_root_key_grants.sql
c5e433bb9138a4420f69ade7d390e7e2c5f20595682f5e68b2739b72371c8dac  server/migrations/0006_root_key_generations.sql
6b0c4187659eaa3fc57de2a0c61b402aced31fcc99bd5bd7793195d2cae42b30  server/migrations/0007_fleet_key_generations.sql
5a7fc52ad934b31c94e6c055829cd2a9d35ffaadb827f778bad95c7cdab848c4  server/migrations/0008_replay_ledger_fleet_key_grants.sql
a15e857919265a7db0a19e1bde059a0c0cb7fae24618f3e38637983643c29bf8  server/migrations/0009_make_active_root_generation_nullable.sql
41ade8dc1791bc5a4727fbd6bb23293e7c97baf87236a0b09e5f69ca3e909682  server/migrations/0010_v2_audit_events.sql
16519b06f4e014ed44cfeb5104a36bff359440e9e2be5e4c5da427e78a62d9b0  server/migrations/0011_instance_bound_key_generations.sql
f3e0477301a92d9158b657b4f6b258dc08c611a4c23d7bb8134d8546ec97ed05  server/migrations/0012_v2_device_states_and_bootstrap_guards.sql
f4b7f884277ef39713fd2d89db99c9242fbed19a96a589e368a36c11c798d5e8  server/migrations/0013_v2_pre_device_and_device_sessions.sql
d8eaecacd5ee7587a824d19a06d98237d4fa07a0c275060b9b99b96b4b2f73a8  server/migrations/0014_v2_ticket_enrollment.sql
80a1c44cd20a4b52a50e253d5f6c0077b786096cb7a1c860c2520cf22afc7022  server/migrations/0015_v2_idempotency_and_device_approval.sql
bb1911c482b5a11a70baefb35c5759d21d4f206735b4a0f17f07dea821cb20ee  server/migrations/0016_v2_root_bootstrap.sql
8960f81ae20f24071275e786c7699498a908d65234673735571a367948241ec7  server/migrations/0017_v2_root_ack_activate.sql
f812c0029be011855148816853f7dff46e4cf224c4d7935c44b73e7b8ef362a5  server/migrations/0018_v2_capability_grants.sql
d786bdc2b5233705d716ccd78a1c7422e8caaab2ef2691e8a9513bf33aa99f2c  server/migrations/0019_v2_grant_quarantine.sql
8ef51b4c4287044b5fc0072044be4e842d8a7354c11869c551af93161b2cea0c  server/migrations/0020_v2_fleet_generation_lifecycle.sql
617ec8b40ab70e7e8d2997ea8bc1f9b25900b1b50e77dac40acf956665da13b6  server/migrations/0021_v2_fleet_generation_guards.sql
d6433001edea4f1a1865b276576a9f1dda4f4db9d7d34fab68a28ecd4a1363f4  server/migrations/0022_v2_guard_followups.sql
e56c2728fc078d169a83fc7131fb2a41beca83108ae519731d0ddb38ecf57a11  server/migrations/0023_v2_device_revocations.sql
cb5638832803cfad7d22bf207364f6e863834e59b686dbdf1d080a35b8be3ec7  server/migrations/0024_v2_restore_epoch_transitions.sql
a1d310c6c24abf17e3adc65b0e05f1c082820d044ccec6d2079c7cd8dda08cb0  server/migrations/0025_v2_profile_leases.sql
00ffdba8d997e24a16866c041aa5a2e576d236856afbed4ad3c32dbf992825e3  server/migrations/0026_v2_uploads_snapshots.sql
63a23859dc550ee75928ab07a23d167e8293d98afec8a7c137681bee435d5b58  server/migrations/0027_v2_upload_reconciler.sql
afc671618d53bd6f0fe6855b3a2bb4caf1825a0755451eccbc2b5dbc2b6edd06  server/migrations/0028_v2_fleet_grant_quarantine.sql
aeffc1f4e7531ae68f81277fb5297d4b9edd531c612b70ecb4d115510ed5b301  server/migrations/0029_v2_device_approval_quarantine.sql
aa9fbea67c53037225fc82a2f1fc62ed4da4d616231a7ef972edc7fcb4ec55e1  server/migrations/0030_v2_integer_columns_hold_integers.sql
98a523d0559ec2a1849b1ad5e769c3a1dae9ff84b97ff5519fe191307e694a4d  server/migrations/0031_v2_idempotency_superseded.sql
ef3675e61aae8c79891160fd5b0354ecff12dd0f3772db07ff80a69f5a281bfc  server/migrations/0032_v2_device_revocation_quarantine.sql
602d815bd8d0acdd107c8e2fbee3ec68077af84d42f4d1a7632cdf5d87ef2ce7  server/migrations/0033_v2_revocation_quarantine_hash.sql
f2643a8297236ae1930bcf94046aa837f7947efe8e787fa8895a66b8cce5ef9e  server/src/audit.rs
c38874f3f57bb2caca052738753600d0dad1661925cabba6882ecad901b099e9  server/src/db.rs
dfbd5addb74bddac25e60966e2973722f3f845ce600ebf8426951f4203c8add6  server/src/identity.rs
ef74d770e2aa79d8e768c52725f6118e7852327f9e84ff01d556381fea343c4f  server/src/integrity.rs
7b76e4b4caaa74e39dfa4c8df553d19ffc6a5439a830a7d633a5b206f246bd27  server/src/restore.rs
0d00d23b131efcf35bb326fbde2dc92ebae2104a3b5c61261e392c0dd0542628  server/src/routes/v2_device_revoke.rs
e6b5e97562624d4fb6eb2c0d51957de81e2cadbb679711543edba6a2b27e5012  server/src/routes/v2_profiles.rs
79793116f93288197d60b3bdc4e8f41516747a3f2b55c9fb2d97dc77c8a2a832  server/src/routes/v2_root.rs
4ce36a8e58416fc587413fa32ac94bce44a9c9368aa98d56b6f3dad722868359  server/src/routes/v2_root_grants.rs
17c78440f33166091549ac57cd721f3d9b9d3c796b9b8958605358390b5bfd9d  server/src/routes/v2_uploads.rs
9a4e3af8bdb570fd8161bc65ce15cefccb5611f766e05ae0db08cdc059555acd  server/tests/fixtures/plan_assert.sql
154f82267c2523e7d98dc9bf8a60df9662376d03dd524367da59f7e42d619524  server/tests/fixtures/v0.1.28/0001_init.sql
5e2bf8c5ab8522b71f8e6b9b0fedf0bfefc6753fdc1a41142691c152aa57fe03  server/tests/fixtures/v0.1.28/0002_lock_token_and_token_version.sql
2c9b27a9072938b07a56fb60b696ea01f34e5ff3e97e97d4dbea1a5a9ec55136  server/tests/fixtures/v0.1.28/0003_clear_empty_lock_tokens.sql
1f92d52a0c87508adedf3ae10b9cd0e71464039f4a68020efe1469da5610aaa4  server/tests/identity_authority.rs
8bb6752450636fbc69617500309c75eb0dccb79da505a2135ac0bff7ed67aac7  server/tests/migration_line_endings.rs
7f35e2faacbdcf07124f0146f2af5320b4d26c8d9bde8212c52ab12c0c5141fb  server/tests/restore_epoch_harness.rs
4c2cb8616f660f2c015dd28ded153390ad5ee1a5f0623cd8d4eaeb19ed3d1d3e  server/tests/v2_auth.rs
ee433df3564de6bc83353229cb121b3fb0697c2a1670bbfd80427b0eafefe23e  server/tests/v2_e2e.rs
e0cb1af61cea523c027be1b62e5748f2d07d6c1ae4db2d15970bfb97e3d40665  server/tests/v2_integer_domain.rs
55d771dee17d1626b0132bfca7f1d09d5fa1758658f35bb3a3d1acda12b01ac8  server/tests/v2_profiles.rs
0cbef6a46682244a3fd0ff0e8fdffebb74c333d8854592c3bd9952bc5524f11b  server/tests/v2_upgrade_chain.rs
6551ab70c24483019ba6d7b1f2fd0a83319fbe5db102cdc031033bc5b9f444c5  shared/Cargo.lock
48df95a206b860681be0d880cc5fda9b53ffbb691464e130834824bf09e6b7e2  shared/Cargo.toml
6a5e6c9b30710a4c84deff24e1254a6795f9b94a83e27983313e6de6220c3fa4  shared/src/authz_record.rs
02f28d9cdf5c195ca26afd11bc191f51fdaa67aa5a808570e74dc79c039c8bfd  shared/src/backup.rs
14fbcfdc0a524c0605dffe300171b4d3af79b0f16f0e6b8b6cd82f6e8f4855fe  shared/src/backup_file.rs
1c0a5c290c7b8fbfa6081d4bb04a649b0b8bd426a0378685b4d6ee0f5a5052c5  shared/src/canonical.rs
5275da8fbc5c7de9aa40a709560be12751c54360cdc67886ce064b9c4bfa466c  shared/src/envelope.rs
8665d7a8eaf200bb9cd0adeb2f37a6f2d3fb7297000de8f571df7c5b55c0b4e3  shared/src/envelope_v2.rs
b248174bb81d01b45c36601f7abbc88b5e1f5a49a2a5e375c5440c0be3769e7d  shared/src/fleet_grants.rs
ce867fa6466bc96d3802a98c8a62707fa435f72cd526a5f98e1ab53a44e70763  shared/src/fleet_lifecycle.rs
aabfff686412e883193e3712dabc124007428d06b818a5effc8e94eb7c7d73d9  shared/src/grants.rs
20bc0670aac39bcac43df7a9396d7bc9027100357ff5001ffae164dc640f5f74  shared/src/keys.rs
3e2d622cb9dc8fb50bf1f1d0c125544011b091b9e67f94da56e3f65c5627386d  shared/src/mutation.rs
df5cc90741047d028b3a4c0b5c49171e98c80e9378c1c99fbc63c3532469cdc0  shared/src/profile_lease.rs
6792c6013a50db228f343d1cdee6f6022581e5ebe2be4ceb911a66a2bfd13e3f  shared/src/recovery_bundle.rs
c786234b4fd05a12818f3b49ba3c019ca06961c1d2088dc33c3e8424fcd43cdf  shared/src/restore_epoch.rs
a3b8db8546f4e5bd892af614b210d0c8e0e4a771a673f681d8de852006928335  shared/src/signing.rs
06824a6663586e5fa371381d9fae2a743853b930d86ef7d759e4f8d4f9200d7a  shared/src/snapshot.rs
ba4c9aecccf35c941d34ae5a16151a1c4bf64e6d44349095673d72c87731f230  shared/src/snapshot_v2.rs
5ca8e012a5416d6490d8825ae9d719f9b08336bd1a51a027252f9870da939b5a  shared/src/volume.rs
406011b39668daeb801cd7a01e03daf6114665116e797deba577047559349489  shared/tests/backup_file_roundtrip.rs
bf2620b350a859fdf823a740766fdc058ea0ec0eacc777234388804a3741f5b6  shared/tests/registry_pins.rs
4e43b4bef124ad1bec0c6fa729ce7f9aba76e343d08de41fba911185c1f7389f  src-tauri/Cargo.lock
5e71e8b88da16a2d92d8361232f5399c608142a775a96d96a3f1efbdbd4c848a  src-tauri/Cargo.toml
561abb0de4086ec088ff9238ac11857b0858ab2686785c9b5ea290d17ad03cd7  src-tauri/src/crash_harness.rs
48a04523bfd5982676bb8509cfe4e29bf99ce84b231f5d9730863d468c437863  src-tauri/src/credential.rs
daf772f36eae8f74a16584aca0a39cae9ee0772ed8117bbbea9b28b05377300d  src-tauri/src/durable.rs
295233cf8e9ff6c56a936136ef4175c26c6e7eb16c2503ab80cfb529ae1fcd87  src-tauri/src/fleet_client.rs
79740ed5bc965f3b7ec7ad95fddca737d585c88d9fa229a992a810547f4d7033  src-tauri/src/fleet_keys.rs
055ce8fd245f54dc3b958210322a99822437356a4579260d8327440f2854a78b  src-tauri/src/key_file.rs
6f4974cd2416e5462852b111e462bdcd9fd0bd0b4d6233624fe71586dca3bcf5  src-tauri/src/lib.rs
1b37bab1ec439aa3b02130dd769ec79028e1da0d612b637a8187605e1ee6574c  src-tauri/src/migrate.rs
ef3b50ee72dcdc9a8ea2d30870a0f6da28ba7793d7da21e7f4686cde9b004bcd  src-tauri/src/root_bootstrap.rs
60005cfd7c072799be4aeb0459cf3cadc7483bd17104755be700b42e02e687a9  src-tauri/src/store.rs
7b8de75c4fe3a2b5f46deef61bb67a67814c79f2271d8d909fb3f1926d498000  src-tauri/src/sync_cmd.rs
ff3505dd6b062408e2f2bfb5d7d9ec5dc1a8d931f4cb2f3f3e295783d376e6cc  src-tauri/src/team/db.rs
ec0b156292043de6798b29e736486e9c3a18d53e11e7467bcfe9b5e633accbed  src-tauri/src/team/downgrade.rs
aaea3d2c1013628a22ff2d0c827cb4d3a316883fa7402e5aaa2fbae286e01145  src-tauri/src/team/journal.rs
8cd84b6d7997fc180bcfcedba74214a760d44afb3c9233c87c1b993f3a0c9050  src-tauri/src/team/ledger.rs
ff05989a0f1dac9655ee4a12afb6b1fad18fa963f7df45e92ee0a29facc29f17  src-tauri/src/team/records.rs
5d07d00effa4a09f5b64a6c6cdb5e876a82445d4fb2eb864b809df598a8d42a9  src-tauri/src/team/sync.rs
e086eae874ba763f246672f1d5225dd0b6ac8711d0e0b44c6a8322ef26e4daa3  src-tauri/src/team_config.rs
```

Additional normalized source/document hashes (all from this revision):

```text
0489f218a993c86e378d36fecdf02bc81f18b8b8b46c3d4bd91e6f810a314888  docs/g2-evidence/README.md
806116b2f8ba0bd32968e374de128f460ab935f842619d694640757f374de3c8  docs/g2-evidence/SHA256SUMS
8cd84b6d7997fc180bcfcedba74214a760d44afb3c9233c87c1b993f3a0c9050  src-tauri/src/team/ledger.rs
2070eca62a8d86471842f8ea75d95990102c1a8ffb7814ec4e284bf9ccd22b72  shared/src/trust_chain.rs
4ce36a8e58416fc587413fa32ac94bce44a9c9368aa98d56b6f3dad722868359  server/src/routes/v2_root_grants.rs
dd9e03b5c19eaa588c7ab5e03d65bf93222c826fafe371f350829325389038c0  server/src/routes/v2_fleet.rs
135913d769ff951ddcb09ca080d2415333e4429321e885860881a03a06b2d699  src-tauri/build.rs
```

### G2-01 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors`

Exit 0; elapsed 526.2 s.

```text
test authz_record::tests::golden_vectors ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.02s
```

### G2-02 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup`

Exit 0; elapsed 14.9 s.

```text
test every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 14.22s
```

### G2-02 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors`

Exit 0; elapsed 0.1 s.

```text
test authz_record::tests::golden_vectors ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.01s
```

### G2-03 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_fleet_grants_that_left_their_containers`

Exit 0; elapsed 8.9 s.

```text
test the_startup_pass_quarantines_fleet_grants_that_left_their_containers ... ok
test every_fleet_grant_column_is_compared_with_its_container_on_each_request ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 73 filtered out; finished in 8.61s
```

### G2-03 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors`

Exit 0; elapsed 0.3 s.

```text
test authz_record::tests::golden_vectors ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.02s
```

### G2-04 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- recovery_grant_binds_context_suite_and_lengths recovery_grant_opens_only_under_its_root_and_to_its_fkek authz_record::tests::golden_vectors`

Exit 0; elapsed 0.2 s.

```text
test authz_record::tests::recovery_grant_binds_context_suite_and_lengths ... ok
test authz_record::tests::golden_vectors ... ok
test authz_record::tests::recovery_grant_opens_only_under_its_root_and_to_its_fkek ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 297 filtered out; finished in 0.03s
```

### G2-04 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request`

Exit 0; elapsed 9.5 s.

```text
test every_fleet_grant_column_is_compared_with_its_container_on_each_request ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 9.07s
```

### G2-05 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- rotation_grant_follows_its_generation_window_and_count_rules authz_record::tests::golden_vectors`

Exit 0; elapsed 0.1 s.

```text
test authz_record::tests::rotation_grant_follows_its_generation_window_and_count_rules ... ok
test authz_record::tests::golden_vectors ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 298 filtered out; finished in 0.01s
```

### G2-05 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request`

Exit 0; elapsed 12.1 s.

```text
test every_fleet_grant_column_is_compared_with_its_container_on_each_request ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 11.76s
```

### G2-06 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup`

Exit 0; elapsed 36.2 s.

```text
test every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 35.91s
```

### G2-06 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors`

Exit 0; elapsed 0.2 s.

```text
test authz_record::tests::golden_vectors ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.01s
```

### G2-07 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- snapshot_v2::tests::golden_vectors payload_rejects_every_field_level_defect container_rejects_every_field_level_defect signing_binds_the_signer_key manifest_binds_a_sealed_envelope_v2_object`

Exit 0; elapsed 0.2 s.

```text
test authz_record::tests::container_rejects_every_field_level_defect ... ok
test snapshot_v2::tests::container_rejects_every_field_level_defect ... ok
test snapshot_v2::tests::golden_vectors ... ok
test snapshot_v2::tests::payload_rejects_every_field_level_defect ... ok
test snapshot_v2::tests::manifest_binds_a_sealed_envelope_v2_object ... ok
test snapshot_v2::tests::signing_binds_the_signer_key ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 294 filtered out; finished in 0.02s
```

### G2-08 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- every_upload_refusal_has_its_status_and_code`

Exit 0; elapsed 9.1 s.

```text
test every_upload_refusal_has_its_status_and_code ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 8.71s
```

### G2-09 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head`

Exit 0; elapsed 6.3 s.

```text
test an_upload_commits_once_and_the_next_checkout_starts_at_its_head ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 5.50s
```

### G2-10 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_closed_maps_parse_what_the_builders_write every_dek_slot_context_rule_is_enforced every_dek_slot_rule_is_enforced a_slot_that_differs_from_the_intent_is_refused the_reader_refuses_an_open_map g2_golden_vector_dek_slot g2_golden_vector_dek_slot_context_hash`

Exit 0; elapsed 0.2 s.

```text
test canonical::tests::g2_golden_vector_dek_slot_context_hash ... ok
test envelope::tests::g2_golden_vector_dek_slot ... ok
test envelope_v2::tests::every_dek_slot_context_rule_is_enforced ... ok
test envelope_v2::tests::every_dek_slot_rule_is_enforced ... ok
test envelope_v2::tests::a_slot_that_differs_from_the_intent_is_refused ... ok
test envelope_v2::tests::the_closed_maps_parse_what_the_builders_write ... ok
test envelope_v2::tests::the_reader_refuses_an_open_map ... ok
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 293 filtered out; finished in 0.02s
```

### G2-11 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_intent_bounds_are_the_plans every_envelope_intent_rule_is_enforced the_intent_and_slot_must_be_the_ones_the_manifest_names manifest_binds_a_sealed_envelope_v2_object g2_golden_vector_intent g2_golden_vector_intent_genesis`

Exit 0; elapsed 0.2 s.

```text
test envelope::tests::g2_golden_vector_intent ... ok
test envelope::tests::g2_golden_vector_intent_genesis ... ok
test envelope_v2::tests::the_intent_and_slot_must_be_the_ones_the_manifest_names ... ok
test envelope_v2::tests::the_intent_bounds_are_the_plans ... ok
test envelope_v2::tests::every_envelope_intent_rule_is_enforced ... ok
test snapshot_v2::tests::manifest_binds_a_sealed_envelope_v2_object ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 294 filtered out; finished in 0.02s
```

### G2-12 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- restore_epoch::tests::golden_vectors leaf_roundtrips_and_refuses_contract_violations leaf_sets_must_be_non_empty_sorted_and_unique every_leaf_proves_and_every_tampering_fails a_proof_binds_tenant_profile_instance_epochs_count_and_root proof_parser_refuses_every_contract_violation g2_golden_vectors_merkle_roots`

Exit 0; elapsed 0.2 s.

```text
test envelope::tests::g2_golden_vectors_merkle_roots ... ok
test restore_epoch::tests::a_proof_binds_tenant_profile_instance_epochs_count_and_root ... ok
test restore_epoch::tests::golden_vectors ... ok
test restore_epoch::tests::leaf_roundtrips_and_refuses_contract_violations ... ok
test restore_epoch::tests::leaf_sets_must_be_non_empty_sorted_and_unique ... ok
test restore_epoch::tests::proof_parser_refuses_every_contract_violation ... ok
test restore_epoch::tests::every_leaf_proves_and_every_tampering_fails ... ok
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 293 filtered out; finished in 0.09s
```

### G2-13 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- transition_roundtrips_and_verifies transition_payload_refuses_every_contract_violation signed_transition_refuses_every_container_defect transition_signature_binds_key_bytes_and_label`

Exit 0; elapsed 0.2 s.

```text
test restore_epoch::tests::transition_payload_refuses_every_contract_violation ... ok
test restore_epoch::tests::signed_transition_refuses_every_container_defect ... ok
test restore_epoch::tests::transition_roundtrips_and_verifies ... ok
test restore_epoch::tests::transition_signature_binds_key_bytes_and_label ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 296 filtered out; finished in 0.02s
```

### G2-14 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- mutation::tests::golden_vectors every_map_roundtrips_byte_for_byte every_map_refuses_another_domain_or_version every_kind_has_one_scope_and_the_scope_must_match hashes_and_closed_fields_are_checked device_revoke_maps_carry_one_container_and_roundtrip fleet_lifecycle::tests::golden_vectors`

Exit 0; elapsed 4.1 s.

```text
test fleet_lifecycle::tests::golden_vectors ... ok
test fleet_lifecycle::tests::every_map_roundtrips_byte_for_byte ... ok
test mutation::tests::every_kind_has_one_scope_and_the_scope_must_match ... ok
test mutation::tests::every_map_refuses_another_domain_or_version ... ok
test mutation::tests::every_map_roundtrips_byte_for_byte ... ok
test mutation::tests::golden_vectors ... ok
test mutation::tests::hashes_and_closed_fields_are_checked ... ok
test mutation::tests::device_revoke_maps_carry_one_container_and_roundtrip ... ok
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 292 filtered out; finished in 3.99s
```

### G2-14 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- a_revocation_commits_its_fleet_activation_or_nothing a_revocation_commits_its_root_activation`

Exit 0; elapsed 5.2 s.

```text
test a_revocation_commits_its_root_activation ... ok
test a_revocation_commits_its_fleet_activation_or_nothing ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 73 filtered out; finished in 4.80s
```

### G2-15 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- mutation::tests::golden_vectors every_map_roundtrips_byte_for_byte every_map_refuses_another_domain_or_version`

Exit 0; elapsed 0.2 s.

```text
test mutation::tests::every_map_refuses_another_domain_or_version ... ok
test fleet_lifecycle::tests::every_map_roundtrips_byte_for_byte ... ok
test mutation::tests::golden_vectors ... ok
test mutation::tests::every_map_roundtrips_byte_for_byte ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 296 filtered out; finished in 0.01s
```

### G2-16 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response`

Exit 0; elapsed 4.6 s.

```text
test the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 4.04s
```

### G2-17 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup`

Exit 0; elapsed 36.8 s.

```text
test every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 35.96s
```

### G2-18 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant`

Exit 0; elapsed 4.5 s.

```text
test readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 4.07s
```

### `cargo +stable test --locked -j 2 --manifest-path src-tauri/Cargo.toml --lib -- --skip a_real_os_store_key_survives_into_a_fresh_process`

Exit 101; elapsed 701.3 s.

```text
thread 'team_config::tests::saved_seeds_are_dpapi_protected_and_load_back' (27716) panicked at src\team_config.rs:557:27:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]


failures:
    custody_tests::a_collected_fleet_key_is_never_replaced
    custody_tests::pull_uses_a_verified_key_only_while_its_issuer_stands
    dpapi::tests::a_secret_round_trips_and_is_not_stored_in_the_clear
    dpapi::tests::an_empty_secret_round_trips_through_dpapi
    dpapi::tests::an_unreadable_blob_is_kept_rather_than_dropped
    fleet_keys::tests::a_key_left_in_the_file_is_dpapi_protected_and_moves_later
    fleet_keys::tests::saved_keys_move_to_the_credential_store_and_still_open
    key_file::tests::keys_the_os_store_refuses_go_to_the_key_file_once_it_is_open
    sync_cmd::tests::a_published_profile_never_takes_the_passphrase_path
    sync_cmd::tests::pull_does_not_try_a_key_from_a_grant_that_does_not_reverify
    sync_cmd::tests::pull_refuses_another_profiles_snapshot
    sync_cmd::tests::pull_without_a_working_key_or_passphrase_asks_for_the_passphrase
    sync_cmd::tests::push_refuses_an_empty_passphrase_even_with_a_cached_fleet_key
    sync_cmd::tests::push_seals_under_the_passphrase_even_with_a_cached_fleet_key
    team::sync::tests::a_binding_and_its_rows_name_the_servers_account_and_key
    team::sync::tests::a_binding_changed_during_acceptance_is_not_moved
    team::sync::tests::a_blocked_publish_is_cancelled_by_its_command_and_stops_blocking_a_downgrade
    team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key
    team::sync::tests::a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept
    team::sync::tests::a_compromised_custodian_blocks_every_fleet_through_the_root
    team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation
    team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte
    team::sync::tests::a_custodian_distrusted_here_signs_no_transition
    team::sync::tests::a_custodian_not_yet_appointed_signs_no_transition
    team::sync::tests::a_custodian_reappointed_after_its_lapse_signs_again
    team::sync::tests::a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen
    team::sync::tests::a_device_clock_behind_the_server_still_binds_one_profile
    team::sync::tests::a_failed_record_leaves_no_evaluation_and_keeps_the_refusal
    team::sync::tests::a_failed_release_of_an_old_lease_is_retried_as_stored
    team::sync::tests::a_head_committed_on_top_does_not_strand_the_push
    team::sync::tests::a_head_whose_signer_may_not_commit_is_not_restored
    team::sync::tests::a_kept_revocation_reloads_with_every_column_equal
    team::sync::tests::a_key_the_checkout_does_not_name_is_never_used
    team::sync::tests::a_key_without_its_kept_record_asks_to_be_collected_again
    team::sync::tests::a_lapse_seen_while_accepting_refuses_a_backdated_transition
    team::sync::tests::a_lapsed_or_former_custodian_signs_no_transition
    team::sync::tests::a_leaf_head_is_accepted_only_as_a_new_head_is
    team::sync::tests::a_lease_at_risk_is_still_a_held_lease
    team::sync::tests::a_lease_expiry_outside_the_ttl_is_refused_by_name
    team::sync::tests::a_lease_from_before_the_restore_is_released_before_the_binding_moves
    team::sync::tests::a_lost_session_or_rate_limit_keeps_the_stored_request
    team::sync::tests::a_missing_or_withdrawn_fleet_key_is_refused
    team::sync::tests::a_new_head_from_an_earlier_epoch_is_a_rollback
    team::sync::tests::a_pinned_head_is_read_back_only_as_the_bindings_own
    team::sync::tests::a_profile_is_published_with_its_first_lease_and_then_pushed
    team::sync::tests::a_profile_published_after_a_restore_starts_at_the_servers_epoch
    team::sync::tests::a_publish_at_a_restore_epoch_never_waits_on_its_acceptance
    team::sync::tests::a_publish_is_bound_whatever_its_lease_expiry_says
    team::sync::tests::a_publish_replayed_after_its_lease_ended_binds_the_one_profile
    team::sync::tests::a_publish_reply_that_does_not_name_the_request_is_never_kept
    team::sync::tests::a_publish_that_cannot_be_trusted_stores_and_sends_nothing
    team::sync::tests::a_publish_whose_operation_was_cancelled_meanwhile_binds_nothing
    team::sync::tests::a_published_profile_pushes_and_another_device_pulls_it
    team::sync::tests::a_pull_waits_for_a_push_in_flight
    team::sync::tests::a_push_behind_the_listed_head_is_refused
    team::sync::tests::a_receipt_or_readback_that_does_not_match_is_never_kept
    team::sync::tests::a_refused_or_mismatched_reply_is_never_kept
    team::sync::tests::a_refused_publish_is_not_replayed_and_the_next_one_starts_afresh
    team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte
    team::sync::tests::a_renewed_lease_moves_the_bindings_expiry_forward
    team::sync::tests::a_replayed_checkout_on_an_old_head_is_released_and_taken_again
    team::sync::tests::a_reply_too_large_to_hold_is_refused
    team::sync::tests::a_restore_epoch_that_goes_back_is_a_rollback
    team::sync::tests::a_rolled_back_head_or_epoch_quarantines_the_binding
    team::sync::tests::a_server_integer_past_the_signed_range_is_refused_before_any_row
    team::sync::tests::a_stored_column_that_drifts_from_its_bytes_is_never_sent
    team::sync::tests::a_stored_publish_goes_out_while_its_key_holds
    team::sync::tests::a_stored_publish_is_not_sent_once_its_key_is_blocked_or_withdrawn
    team::sync::tests::a_stored_publish_that_drifts_from_its_bytes_is_never_sent
    team::sync::tests::a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh
    team::sync::tests::a_tombstone_that_no_longer_recomputes_is_never_returned
    team::sync::tests::a_transition_that_does_not_verify_keeps_the_binding_quarantined
    team::sync::tests::a_verified_transition_moves_only_the_bindings_it_covers
    team::sync::tests::an_exposure_survives_a_recollection_that_omits_its_grant
    team::sync::tests::an_interrupted_upload_resumes_at_the_offset_head_reports
    team::sync::tests::an_open_upload_is_aborted_once_a_compromise_is_counted
    team::sync::tests::an_unbind_after_an_accepted_transition_keeps_its_evidence
    team::sync::tests::an_unbind_at_version_zero_omits_the_head
    team::sync::tests::an_unbind_cut_off_at_any_write_leaves_the_binding_whole
    team::sync::tests::an_unbind_is_refused_while_a_lease_request_or_journal_is_open
    team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly
    team::sync::tests::an_unreadable_release_reply_is_reported_and_replayed
    team::sync::tests::an_unsent_cancel_release_is_retried_and_then_given_up
    team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes
    team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes
    team::sync::tests::the_leaf_head_search_is_bounded_and_skipped_for_an_unchanged_pin
    team_config::tests::a_dpapi_protected_seed_moves_to_the_credential_store
    team_config::tests::a_plaintext_file_still_loads_and_is_rewritten_protected
    team_config::tests::a_seed_the_store_refuses_stays_in_the_file
    team_config::tests::enrolled_seeds_move_to_the_credential_store_and_still_open
    team_config::tests::saved_seeds_are_dpapi_protected_and_load_back

test result: FAILED. 405 passed; 91 failed; 11 ignored; 0 measured; 1 filtered out; finished in 156.96s

error: test failed, to rerun pass `--lib`
```

### G2-19 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant`

Exit 0; elapsed 3.8 s.

```text
test readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 3.49s
```

### `cargo +1.87.0 check --locked -j 2 --all-targets --manifest-path shared/Cargo.toml`

Exit 0; elapsed 34.0 s.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 33.96s
```

### G2-20 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- a_revocation_names_a_known_reason_and_its_outcome`

Exit 0; elapsed 32.7 s.

```text
test mutation::tests::a_revocation_names_a_known_reason_and_its_outcome ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.00s
```

### G2-20 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- a_custodian_revokes_a_root_grant_but_never_the_last_one`

Exit 0; elapsed 7.1 s.

```text
test a_custodian_revokes_a_root_grant_but_never_the_last_one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 6.69s
```


## Supplemental B1/B2/B4 helper execution

Command (already-built stable launcher test executable, isolated environment above):

```text
C:\Users\User\AppData\Local\Temp\g264-target-codex\debug\deps\shardx_launcher_lib-44eec91b66e81cf5.exe holdings_name_every_issuer_and_subject_of_a_key_carrying_grant a_version_6_file_files_the_holdings_of_its_kept_evidence a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet --nocapture
```

Exit 0.

```text

running 3 tests
test team::ledger::tests::a_version_6_file_files_the_holdings_of_its_kept_evidence ... ok
test team::ledger::tests::holdings_name_every_issuer_and_subject_of_a_key_carrying_grant ... ok
test custody_tests::a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 505 filtered out; finished in 1.21s


```
### `cargo +1.89.0 check --locked -j 2 --all-targets --manifest-path server/Cargo.toml`

Exit 0; elapsed 117.3 s.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 57s
```

### G2-21 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes`

Exit 0; elapsed 116.7 s.

```text
test one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 6.29s
```


## Reproducible N1 storage probe with foreign keys enabled

Run this Python from the repository root; it creates only an in-memory database. The target DDL and INSERT are extracted verbatim. The parent fixture table supplies the foreign-key prerequisite. Container bodies are marked fixture bytes; this isolates retention rather than claiming a cryptographic end-to-end test.

```python
from pathlib import Path
import re, sqlite3
schema = Path("src-tauri/src/team/db.rs").read_text(encoding="utf-8")
source = Path("src-tauri/src/team/ledger.rs").read_text(encoding="utf-8")
ddl = re.search(r"CREATE TABLE trust_proven_revocations \(.*?\) STRICT;", schema, re.S).group(0)
insert = re.search(r'"(INSERT INTO trust_proven_revocations\s+VALUES .*?ON CONFLICT DO NOTHING)"', source, re.S).group(1)
c = sqlite3.connect(":memory:")
c.execute("PRAGMA foreign_keys=ON")
c.execute("CREATE TABLE trust_anchors(server_instance_id TEXT, tenant_id TEXT, PRIMARY KEY(server_instance_id, tenant_id)) STRICT")
c.execute("INSERT INTO trust_anchors VALUES ('fixture-instance','fixture-tenant')")
c.execute(ddl)
for evaluation, reason in [(1, b"fixture:retired"), (2, b"fixture:compromised")]:
    c.execute(insert, ("fixture-instance", "fixture-tenant", "11"*32, evaluation, evaluation, reason))
print("SQLite", sqlite3.sqlite_version, "foreign_keys", c.execute("PRAGMA foreign_keys").fetchone()[0])
print(c.execute("SELECT counted_evaluation, exact_signed_container_bytes FROM trust_proven_revocations").fetchall())
```

Observed: SQLite 3.49.1, foreign_keys 1; `[(1, b'fixture:retired')]`. The second, compromised fixture is discarded.
### `cargo +1.88.0 check --locked -j 2 --all-targets --manifest-path src-tauri/Cargo.toml`

Exit 0; elapsed 271.6 s.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4m 31s
```

### G2-21 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_profile_is_published_with_its_first_lease_and_then_pushed every_publish_crash_point_resumes_with_the_exact_stored_bytes`

Exit 101; elapsed 283.5 s.

```text
test team::sync::tests::a_profile_is_published_with_its_first_lease_and_then_pushed ... FAILED
test team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes ... FAILED
---- team::sync::tests::a_profile_is_published_with_its_first_lease_and_then_pushed stdout ----
thread 'team::sync::tests::a_profile_is_published_with_its_first_lease_and_then_pushed' (33008) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes stdout ----
thread 'team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes' (33128) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 506 filtered out; finished in 0.75s
error: test failed, to rerun pass `--lib`
```

### G2-22 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed`

Exit 0; elapsed 6.5 s.

```text
test a_stored_response_naming_another_profile_or_lease_is_never_replayed ... ok
test one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 5.73s
```


### Supplemental `cargo +stable test --locked -j 2 --manifest-path shared/Cargo.toml --test * --no-fail-fast`

Covers targets skipped after the initial shared library failure. Exit 101; elapsed 244.7 s.

```text
test a_non_backup_file_is_rejected_before_the_passphrase_is_used ... ok
test a_short_passphrase_is_refused_at_backup_time ... ok
test a_profile_survives_backup_and_restore_byte_for_byte ... FAILED
test a_tampered_backup_body_is_refused ... FAILED
test a_truncated_backup_is_refused_and_leaves_the_destination_untouched ... FAILED
test a_wrong_passphrase_is_refused_and_leaves_the_destination_untouched ... FAILED
test the_ciphertext_does_not_contain_the_plaintext ... FAILED
test two_backups_of_the_same_profile_differ ... FAILED
failures:
    DPAPI protect failed
    DPAPI protect failed
    DPAPI protect failed
    DPAPI protect failed
    DPAPI protect failed
    DPAPI protect failed
failures:
test result: FAILED. 2 passed; 6 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.68s
error: test failed, to rerun pass `--test backup_file_roundtrip`
test v1_reader_rejects_a_v2_container ... FAILED
test v1_snapshot_still_round_trips_after_v2_landed ... FAILED
test v2_container_wraps_a_v1_snapshot_losslessly ... FAILED
failures:
v1 pack: DPAPI protect failed
v1 pack: DPAPI protect failed
v1 pack: DPAPI protect failed
failures:
test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
error: test failed, to rerun pass `--test g3_v1_v2_compatibility`
test operator_can_recover_a_backup_on_a_fresh_machine_and_forgeries_are_refused ... ignored, operator drill; run explicitly on a disposable machine
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test every_hash_label_is_distinct_and_nul_terminated ... ok
test every_signing_domain_is_distinct_and_versioned ... ok
test the_numeric_registry_holds_the_reviewed_values ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
error: 2 targets failed:
```
### G2-22 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key`

Exit 101; elapsed 1.1 s.

```text
test team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key ... FAILED
test team::sync::tests::a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept ... FAILED
---- team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key stdout ----
thread 'team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key' (33688) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept stdout ----
thread 'team::sync::tests::a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept' (26984) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 506 filtered out; finished in 0.41s
error: test failed, to rerun pass `--lib`
```


### Supplemental `cargo +stable test --locked -j 2 --manifest-path shared/Cargo.toml --doc`

Covers targets skipped after the initial shared library failure. Exit 0; elapsed 0.7 s.

```text
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```
### G2-23 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head every_upload_refusal_has_its_status_and_code`

Exit 0; elapsed 8.8 s.

```text
test an_upload_commits_once_and_the_next_checkout_starts_at_its_head ... ok
test every_upload_refusal_has_its_status_and_code ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 8.46s
```

### G2-23 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte`

Exit 101; elapsed 0.8 s.

```text
test team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte ... FAILED
---- team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte stdout ----
thread 'team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte' (23080) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 507 filtered out; finished in 0.23s
error: test failed, to rerun pass `--lib`
```

### G2-24 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot`

Exit 0; elapsed 6.6 s.

```text
test a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot ... ok
test an_upload_commits_once_and_the_next_checkout_starts_at_its_head ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 6.26s
```

### G2-24 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_crash_point_resumes_with_the_exact_stored_bytes`

Exit 101; elapsed 1.1 s.

```text
test team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes ... FAILED
---- team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes stdout ----
thread 'team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes' (33248) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 507 filtered out; finished in 0.28s
error: test failed, to rerun pass `--lib`
```

### G2-25 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed`

Exit 0; elapsed 6.2 s.

```text
test a_stored_response_naming_another_profile_or_lease_is_never_replayed ... ok
test one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 5.63s
```

### G2-25 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_release_whose_reply_was_lost_is_replayed_byte_for_byte`

Exit 101; elapsed 0.9 s.

```text
test team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte ... FAILED
---- team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte stdout ----
thread 'team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte' (32720) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 507 filtered out; finished in 0.26s
error: test failed, to rerun pass `--lib`
```

### G2-26 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_unbind_maps_round_trip_and_pin_the_tombstone the_unbind_maps_refuse_what_l953_does_not_allow`

Exit 0; elapsed 0.2 s.

```text
test profile_lease::tests::the_unbind_maps_round_trip_and_pin_the_tombstone ... ok
test profile_lease::tests::the_unbind_maps_refuse_what_l953_does_not_allow ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 298 filtered out; finished in 0.04s
```

### G2-26 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unbind_tombstone_outlives_its_binding_and_replays_exactly an_unbind_at_version_zero_omits_the_head an_unbind_cut_off_at_any_write_leaves_the_binding_whole an_unbind_is_refused_while_a_lease_request_or_journal_is_open`

Exit 101; elapsed 1.6 s.

```text
test team::sync::tests::an_unbind_at_version_zero_omits_the_head ... FAILED
test team::sync::tests::an_unbind_cut_off_at_any_write_leaves_the_binding_whole ... FAILED
test team::sync::tests::an_unbind_is_refused_while_a_lease_request_or_journal_is_open ... FAILED
test team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly ... FAILED
---- team::sync::tests::an_unbind_at_version_zero_omits_the_head stdout ----
thread 'team::sync::tests::an_unbind_at_version_zero_omits_the_head' (27360) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_unbind_cut_off_at_any_write_leaves_the_binding_whole stdout ----
thread 'team::sync::tests::an_unbind_cut_off_at_any_write_leaves_the_binding_whole' (21604) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_unbind_is_refused_while_a_lease_request_or_journal_is_open stdout ----
thread 'team::sync::tests::an_unbind_is_refused_while_a_lease_request_or_journal_is_open' (16176) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly stdout ----
thread 'team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly' (24720) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 4 failed; 0 ignored; 0 measured; 504 filtered out; finished in 0.99s
error: test failed, to rerun pass `--lib`
```

### G2-27 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- xchacha20poly1305_matches_the_draft_vector golden_objects every_preamble_rule_is_enforced every_frame_rule_is_enforced the_stream_counter_stops_at_the_provider_maximum`

Exit 0; elapsed 0.3 s.

```text
test envelope_v2::tests::every_preamble_rule_is_enforced ... ok
test envelope_v2::tests::golden_objects ... ok
test envelope_v2::tests::the_stream_counter_stops_at_the_provider_maximum ... ok
test envelope_v2::tests::xchacha20poly1305_matches_the_draft_vector ... ok
test envelope_v2::tests::every_frame_rule_is_enforced ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 295 filtered out; finished in 0.18s
```

### G2-28 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_pinned_suite_matches_the_rfc_9180_vectors info_bytes_match_g2_vector only_the_granted_device_can_open grant_cannot_be_replayed_into_another_tenant_or_epoch the_fleet_grant_aad_is_the_label_the_length_and_the_info a_device_fleet_grant_opens_only_to_the_key_it_names a_sealed_fleet_key_opens_to_the_exact_same_bytes`

Exit 0; elapsed 0.2 s.

```text
test fleet_grants::tests::a_sealed_fleet_key_opens_to_the_exact_same_bytes ... ok
test grants::tests::a_device_fleet_grant_opens_only_to_the_key_it_names ... ok
test grants::tests::info_bytes_match_g2_vector ... ok
test grants::tests::grant_cannot_be_replayed_into_another_tenant_or_epoch ... ok
test grants::tests::the_fleet_grant_aad_is_the_label_the_length_and_the_info ... ok
test grants::tests::the_pinned_suite_matches_the_rfc_9180_vectors ... ok
test grants::tests::only_the_granted_device_can_open ... ok
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 293 filtered out; finished in 0.01s
```

### G2-29 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- signature_binds_issuer_and_bytes small_order_issuer_key_never_verifies rfc8032_vectors_sign_and_verify_strictly speccheck_matrix_accepts_only_the_unambiguous_case g2_golden_vector_signed_container_hash`

Exit 0; elapsed 0.2 s.

```text
test authz_record::tests::small_order_issuer_key_never_verifies ... ok
test authz_record::tests::signature_binds_issuer_and_bytes ... ok
test signing::tests::g2_golden_vector_signed_container_hash ... ok
test signing::tests::speccheck_matrix_accepts_only_the_unambiguous_case ... ok
test signing::tests::rfc8032_vectors_sign_and_verify_strictly ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 295 filtered out; finished in 0.05s
```


### Conditional-branch diagnostic `cargo +stable test --locked -j 2 --manifest-path shared/Cargo.toml --lib -- an_smb_share_is_refused --nocapture`

Exit 0. Passing libtest status does not credit a skipped branch.

```text
SKIPPED an_smb_share_is_refused: set SHARDX_TEST_SMB_DIR to a reachable \\host\share directory (needs an SMB share; CI creates one)
test volume::tests::an_smb_share_is_refused ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.00s
```

### Conditional-branch diagnostic `cargo +stable test --locked -j 2 --manifest-path server/Cargo.toml -- smb_share --nocapture`

Exit 0. Passing libtest status does not credit a skipped branch.

```text
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
SKIPPED storage_on_an_smb_share_is_refused: no reachable SMB share
SKIPPED preflight_refuses_an_identity_directory_on_an_smb_share: no reachable SMB share
test db::tests::storage_on_an_smb_share_is_refused ... ok
test identity::tests::preflight_refuses_an_identity_directory_on_an_smb_share ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 106 filtered out; finished in 0.01s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 24 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 75 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 15 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Conditional-branch diagnostic `cargo +stable test --locked -j 2 --manifest-path server/Cargo.toml --test restore_epoch_harness -- an_identity_directory_the_preflight_refuses_never_falls_to_k1 g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count --nocapture`

Exit 0. Passing libtest status does not credit a skipped branch.

```text
no loopback administrative share on this machine; not checked
test an_identity_directory_the_preflight_refuses_never_falls_to_k1 ... ok
no loopback administrative share on this machine; not checked
test g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 2.31s
```

### Conditional-branch diagnostic `cargo +stable test --locked -j 2 --manifest-path server/Cargo.toml --test identity_authority -- a_symlinked_record_is_refused --nocapture`

Exit 0. Passing libtest status does not credit a skipped branch.

```text
skipping: cannot create a symlink here: A required privilege is not held by the client. (os error 1314)
test a_symlinked_record_is_refused ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 21 filtered out; finished in 0.94s
```
### G2-30 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_device_revocation_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_device_revocations_that_left_their_containers a_revocation_of_another_instance_turns_v2_off_until_it_is_put_back a_revocation_quarantined_at_runtime_refuses_the_trust_evidence a_quarantined_revocation_that_verifies_again_is_served_again_after_a_restart a_marked_row_swapped_for_another_genuine_revocation_is_not_served_again a_corrupt_container_is_marked_without_a_hash_and_served_again_once_restored the_trust_evidence_reports_a_revoked_device_from_its_record_not_its_column a_revocation_row_swapped_for_another_genuine_one_does_not_answer_a_retry a_revocation_row_the_startup_pass_cannot_read_turns_v2_off`

Exit 0; elapsed 32.9 s.

```text
test a_corrupt_container_is_marked_without_a_hash_and_served_again_once_restored ... ok
test a_marked_row_swapped_for_another_genuine_revocation_is_not_served_again ... ok
test a_revocation_of_another_instance_turns_v2_off_until_it_is_put_back ... ok
test a_quarantined_revocation_that_verifies_again_is_served_again_after_a_restart ... ok
test a_revocation_quarantined_at_runtime_refuses_the_trust_evidence ... ok
test a_revocation_row_swapped_for_another_genuine_one_does_not_answer_a_retry ... ok
test a_revocation_row_the_startup_pass_cannot_read_turns_v2_off ... ok
test the_startup_pass_quarantines_device_revocations_that_left_their_containers ... ok
test the_trust_evidence_reports_a_revoked_device_from_its_record_not_its_column ... ok
test every_device_revocation_column_is_compared_with_its_container_on_each_request ... ok
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 65 filtered out; finished in 32.42s
```

### G2-30 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_kept_revocation_reloads_with_every_column_equal`

Exit 101; elapsed 0.8 s.

```text
test team::sync::tests::a_kept_revocation_reloads_with_every_column_equal ... FAILED
---- team::sync::tests::a_kept_revocation_reloads_with_every_column_equal stdout ----
thread 'team::sync::tests::a_kept_revocation_reloads_with_every_column_equal' (32916) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 507 filtered out; finished in 0.22s
error: test failed, to rerun pass `--lib`
```

### G2-31 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response every_custody_operation_replays_its_lost_response_after_a_restart`

Exit 0; elapsed 13.5 s.

```text
test the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt ... ok
test the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response ... ok
test every_custody_operation_replays_its_lost_response_after_a_restart ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 72 filtered out; finished in 13.15s
```

### G2-31 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_e2e -- v2_operations_replay_the_stored_response`

Exit 0; elapsed 2.8 s.

```text
test v2_operations_replay_the_stored_response ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 2.41s
```

### G2-31 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot every_profile_operation_replays_its_lost_response_after_a_restart`

Exit 0; elapsed 11.6 s.

```text
test a_stored_response_naming_another_profile_or_lease_is_never_replayed ... ok
test a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot ... ok
test one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes ... ok
test every_profile_operation_replays_its_lost_response_after_a_restart ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 11.10s
```

### G2-31 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- d1_replays_of_rolled_back_results_answer_as_superseded_and_kept_ones_replay`

Exit 0; elapsed 9.1 s.

```text
test d1_replays_of_rolled_back_results_answer_as_superseded_and_kept_ones_replay ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 8.78s
```

### G2-31 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_publish_crash_point_resumes_with_the_exact_stored_bytes a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte every_crash_point_resumes_with_the_exact_stored_bytes a_release_whose_reply_was_lost_is_replayed_byte_for_byte an_unbind_tombstone_outlives_its_binding_and_replays_exactly`

Exit 101; elapsed 1.8 s.

```text
test team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key ... FAILED
test team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte ... FAILED
test team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte ... FAILED
test team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly ... FAILED
test team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes ... FAILED
test team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes ... FAILED
---- team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key stdout ----
thread 'team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key' (19712) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte stdout ----
thread 'team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte' (16908) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte stdout ----
thread 'team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte' (21004) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly stdout ----
thread 'team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly' (26060) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes stdout ----
thread 'team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes' (4276) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes stdout ----
thread 'team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes' (9912) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 6 failed; 0 ignored; 0 measured; 502 filtered out; finished in 1.18s
error: test failed, to rerun pass `--lib`
```

### G2-32 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_new_database_reopens_with_its_schema_and_settings a_version_5_file_with_data_moves_to_version_6_keeping_every_row the_triggers_and_indexes_of_a_version_5_file_survive_version_6`

Exit 0; elapsed 2.4 s.

```text
test team::db::tests::a_new_database_reopens_with_its_schema_and_settings ... ok
test team::db::tests::the_triggers_and_indexes_of_a_version_5_file_survive_version_6 ... ok
test team::db::tests::a_version_5_file_with_data_moves_to_version_6_keeping_every_row ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 505 filtered out; finished in 1.80s
```

### G2-33 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unbind_tombstone_outlives_its_binding_and_replays_exactly an_unbind_cut_off_at_any_write_leaves_the_binding_whole a_tombstone_that_no_longer_recomputes_is_never_returned an_unbind_after_an_accepted_transition_keeps_its_evidence a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding`

Exit 101; elapsed 1.5 s.

```text
test team::sync::tests::a_tombstone_that_no_longer_recomputes_is_never_returned ... FAILED
test team::sync::tests::an_unbind_after_an_accepted_transition_keeps_its_evidence ... FAILED
test team::db::tests::a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding ... ok
test team::sync::tests::an_unbind_cut_off_at_any_write_leaves_the_binding_whole ... FAILED
test team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly ... FAILED
---- team::sync::tests::a_tombstone_that_no_longer_recomputes_is_never_returned stdout ----
thread 'team::sync::tests::a_tombstone_that_no_longer_recomputes_is_never_returned' (5864) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_unbind_after_an_accepted_transition_keeps_its_evidence stdout ----
thread 'team::sync::tests::an_unbind_after_an_accepted_transition_keeps_its_evidence' (33216) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_unbind_cut_off_at_any_write_leaves_the_binding_whole stdout ----
thread 'team::sync::tests::an_unbind_cut_off_at_any_write_leaves_the_binding_whole' (15888) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly stdout ----
thread 'team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly' (23148) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 1 passed; 4 failed; 0 ignored; 0 measured; 503 filtered out; finished in 0.91s
error: test failed, to rerun pass `--lib`
```

### G2-34 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_release_whose_reply_was_lost_is_replayed_byte_for_byte an_unsent_cancel_release_is_retried_and_then_given_up an_unreadable_release_reply_is_reported_and_replayed`

Exit 101; elapsed 1.3 s.

```text
test team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte ... FAILED
test team::sync::tests::an_unreadable_release_reply_is_reported_and_replayed ... FAILED
test team::sync::tests::an_unsent_cancel_release_is_retried_and_then_given_up ... FAILED
---- team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte stdout ----
thread 'team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte' (29492) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_unreadable_release_reply_is_reported_and_replayed stdout ----
thread 'team::sync::tests::an_unreadable_release_reply_is_reported_and_replayed' (29172) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_unsent_cancel_release_is_retried_and_then_given_up stdout ----
thread 'team::sync::tests::an_unsent_cancel_release_is_retried_and_then_given_up' (31524) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 505 filtered out; finished in 0.57s
error: test failed, to rerun pass `--lib`
```

### G2-35 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- six_records_reopen_exactly_and_refuse_every_changed_column a_second_self_grant_and_a_cross_instance_generation_are_refused only_a_self_grant_files_a_generation_and_a_duplicate_row_refuses a_filed_grant_files_the_key_state_it_names a_binding_and_its_rows_name_the_servers_account_and_key a_kept_revocation_reloads_with_every_column_equal`

Exit 101; elapsed 2.7 s.

```text
test team::ledger::tests::a_filed_grant_files_the_key_state_it_names ... ok
test team::records::tests::a_second_self_grant_and_a_cross_instance_generation_are_refused ... ok
test team::records::tests::only_a_self_grant_files_a_generation_and_a_duplicate_row_refuses ... ok
test team::sync::tests::a_binding_and_its_rows_name_the_servers_account_and_key ... FAILED
test team::sync::tests::a_kept_revocation_reloads_with_every_column_equal ... FAILED
test team::records::tests::six_records_reopen_exactly_and_refuse_every_changed_column ... ok
---- team::sync::tests::a_binding_and_its_rows_name_the_servers_account_and_key stdout ----
thread 'team::sync::tests::a_binding_and_its_rows_name_the_servers_account_and_key' (13148) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_kept_revocation_reloads_with_every_column_equal stdout ----
thread 'team::sync::tests::a_kept_revocation_reloads_with_every_column_equal' (30456) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 4 passed; 2 failed; 0 ignored; 0 measured; 502 filtered out; finished in 2.20s
error: test failed, to rerun pass `--lib`
```

### G2-36 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key an_interrupted_upload_resumes_at_the_offset_head_reports`

Exit 101; elapsed 1.0 s.

```text
test team::db::tests::an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key ... ok
test team::sync::tests::an_interrupted_upload_resumes_at_the_offset_head_reports ... FAILED
---- team::sync::tests::an_interrupted_upload_resumes_at_the_offset_head_reports stdout ----
thread 'team::sync::tests::an_interrupted_upload_resumes_at_the_offset_head_reports' (31892) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 506 filtered out; finished in 0.40s
error: test failed, to rerun pass `--lib`
```

### G2-37 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_crash_point_resumes_with_the_exact_stored_bytes a_stored_column_that_drifts_from_its_bytes_is_never_sent a_stored_publish_that_drifts_from_its_bytes_is_never_sent`

Exit 101; elapsed 1.7 s.

```text
test team::sync::tests::a_stored_column_that_drifts_from_its_bytes_is_never_sent ... FAILED
test team::sync::tests::a_stored_publish_that_drifts_from_its_bytes_is_never_sent ... FAILED
test team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes ... FAILED
---- team::sync::tests::a_stored_column_that_drifts_from_its_bytes_is_never_sent stdout ----
thread 'team::sync::tests::a_stored_column_that_drifts_from_its_bytes_is_never_sent' (31852) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_stored_publish_that_drifts_from_its_bytes_is_never_sent stdout ----
thread 'team::sync::tests::a_stored_publish_that_drifts_from_its_bytes_is_never_sent' (32308) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes stdout ----
thread 'team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes' (32232) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 505 filtered out; finished in 0.81s
error: test failed, to rerun pass `--lib`
```


## Additional verifier version readback

```text
Python 3.12.10 (tags/v3.12.10:0cc8128, Apr  8 2025, 12:21:36) [MSC v.1943 64 bit (AMD64)]
SQLite 3.49.1
OS Windows-11-10.0.26300-SP0
rustc +1.87.0 --version -> exit 0: rustc 1.87.0 (17067e9ac 2025-05-09)
rustc +1.88.0 --version -> exit 0: rustc 1.88.0 (6b00bc388 2025-06-23)
rustc +1.89.0 --version -> exit 0: rustc 1.89.0 (29483883e 2025-08-04)
node --version -> exit 0: v24.22.2
npm.cmd --version -> exit 0: 12.2.1
git --version -> exit 0: git version 2.56.0.windows.3
```
### G2-38 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_receipt_or_readback_that_does_not_match_is_never_kept a_published_profile_pushes_and_another_device_pulls_it an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key`

Exit 101; elapsed 1.4 s.

```text
test team::db::tests::an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key ... ok
test team::sync::tests::a_published_profile_pushes_and_another_device_pulls_it ... FAILED
test team::sync::tests::a_receipt_or_readback_that_does_not_match_is_never_kept ... FAILED
---- team::sync::tests::a_published_profile_pushes_and_another_device_pulls_it stdout ----
thread 'team::sync::tests::a_published_profile_pushes_and_another_device_pulls_it' (33652) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_receipt_or_readback_that_does_not_match_is_never_kept stdout ----
thread 'team::sync::tests::a_receipt_or_readback_that_does_not_match_is_never_kept' (30644) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 505 filtered out; finished in 0.51s
error: test failed, to rerun pass `--lib`
```

### G2-38 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head every_upload_refusal_has_its_status_and_code`

Exit 0; elapsed 10.0 s.

```text
test an_upload_commits_once_and_the_next_checkout_starts_at_its_head ... ok
test every_upload_refusal_has_its_status_and_code ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 9.43s
```

### G2-39 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_verified_transition_moves_only_the_bindings_it_covers a_transition_that_does_not_verify_keeps_the_binding_quarantined a_restore_epoch_that_goes_back_is_a_rollback a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen a_leaf_head_is_accepted_only_as_a_new_head_is a_pinned_head_is_read_back_only_as_the_bindings_own a_lapsed_or_former_custodian_signs_no_transition an_unbind_after_an_accepted_transition_keeps_its_evidence a_binding_changed_during_acceptance_is_not_moved a_lease_from_before_the_restore_is_released_before_the_binding_moves a_custodian_not_yet_appointed_signs_no_transition a_failed_release_of_an_old_lease_is_retried_as_stored`

Exit 101; elapsed 4.3 s.

```text
test team::sync::tests::a_custodian_not_yet_appointed_signs_no_transition ... FAILED
test team::sync::tests::a_binding_changed_during_acceptance_is_not_moved ... FAILED
test team::sync::tests::a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen ... FAILED
test team::sync::tests::a_failed_release_of_an_old_lease_is_retried_as_stored ... FAILED
test team::sync::tests::a_lapsed_or_former_custodian_signs_no_transition ... FAILED
test team::sync::tests::a_leaf_head_is_accepted_only_as_a_new_head_is ... FAILED
test team::sync::tests::a_lease_from_before_the_restore_is_released_before_the_binding_moves ... FAILED
test team::sync::tests::a_pinned_head_is_read_back_only_as_the_bindings_own ... FAILED
test team::sync::tests::a_restore_epoch_that_goes_back_is_a_rollback ... FAILED
test team::sync::tests::a_transition_that_does_not_verify_keeps_the_binding_quarantined ... FAILED
test team::sync::tests::a_verified_transition_moves_only_the_bindings_it_covers ... FAILED
test team::sync::tests::an_unbind_after_an_accepted_transition_keeps_its_evidence ... FAILED
---- team::sync::tests::a_custodian_not_yet_appointed_signs_no_transition stdout ----
thread 'team::sync::tests::a_custodian_not_yet_appointed_signs_no_transition' (19760) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_binding_changed_during_acceptance_is_not_moved stdout ----
thread 'team::sync::tests::a_binding_changed_during_acceptance_is_not_moved' (32424) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen stdout ----
thread 'team::sync::tests::a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen' (240) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_failed_release_of_an_old_lease_is_retried_as_stored stdout ----
thread 'team::sync::tests::a_failed_release_of_an_old_lease_is_retried_as_stored' (11536) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_lapsed_or_former_custodian_signs_no_transition stdout ----
thread 'team::sync::tests::a_lapsed_or_former_custodian_signs_no_transition' (22620) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_leaf_head_is_accepted_only_as_a_new_head_is stdout ----
thread 'team::sync::tests::a_leaf_head_is_accepted_only_as_a_new_head_is' (26984) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_lease_from_before_the_restore_is_released_before_the_binding_moves stdout ----
thread 'team::sync::tests::a_lease_from_before_the_restore_is_released_before_the_binding_moves' (616) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_pinned_head_is_read_back_only_as_the_bindings_own stdout ----
thread 'team::sync::tests::a_pinned_head_is_read_back_only_as_the_bindings_own' (33656) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_restore_epoch_that_goes_back_is_a_rollback stdout ----
thread 'team::sync::tests::a_restore_epoch_that_goes_back_is_a_rollback' (31712) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_transition_that_does_not_verify_keeps_the_binding_quarantined stdout ----
thread 'team::sync::tests::a_transition_that_does_not_verify_keeps_the_binding_quarantined' (30824) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_verified_transition_moves_only_the_bindings_it_covers stdout ----
thread 'team::sync::tests::a_verified_transition_moves_only_the_bindings_it_covers' (27888) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_unbind_after_an_accepted_transition_keeps_its_evidence stdout ----
thread 'team::sync::tests::an_unbind_after_an_accepted_transition_keeps_its_evidence' (29528) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 12 failed; 0 ignored; 0 measured; 496 filtered out; finished in 2.90s
error: test failed, to rerun pass `--lib`
```

### G2-40 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unknown_schema_fails_closed_and_is_left_as_it_was a_database_held_in_wal_mode_is_refused`

Exit 0; elapsed 1.4 s.

```text
test team::db::tests::a_database_held_in_wal_mode_is_refused ... ok
test team::db::tests::an_unknown_schema_fails_closed_and_is_left_as_it_was ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 506 filtered out; finished in 0.60s
```

### G2-41 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_restore_phase_survives_close_and_reopen_in_order a_restore_phase_cannot_skip_repeat_or_leave_a_terminal_one a_restore_journal_retires_only_when_settled the_restore_resume_table_is_fixed_per_crash_point a_clone_journal_walks_its_chain_with_every_phase_surviving_reopen a_downgrade_phase_cannot_skip_and_a_rollback_is_always_open the_resume_table_for_a_downgrade_journal_continues_every_open_phase the_digests_survive_reopen_byte_for_byte a_cut_off_at_every_step_resumes_to_the_same_finished_clone a_process_killed_at_every_step_resumes_to_the_same_finished_clone a_rollback_from_every_step_puts_the_original_back_and_frees_the_profile a_readback_that_v0_1_28_would_not_agree_with_fails_the_flow discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive an_unbind_is_refused_while_a_lease_request_or_journal_is_open`

Exit 101; elapsed 18.7 s.

```text
test team::downgrade::tests::a_cut_off_at_every_step_resumes_to_the_same_finished_clone ... ok
test team::downgrade::tests::a_process_killed_at_every_step_resumes_to_the_same_finished_clone ... ok
test team::downgrade::tests::a_readback_that_v0_1_28_would_not_agree_with_fails_the_flow ... ok
test team::downgrade::tests::discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive ... ok
test team::journal::tests::a_clone_journal_walks_its_chain_with_every_phase_surviving_reopen ... ok
test team::journal::tests::a_downgrade_phase_cannot_skip_and_a_rollback_is_always_open ... ok
test team::journal::tests::a_restore_journal_retires_only_when_settled ... ok
test team::journal::tests::a_restore_phase_cannot_skip_repeat_or_leave_a_terminal_one ... ok
test team::journal::tests::every_restore_phase_survives_close_and_reopen_in_order ... ok
test team::journal::tests::the_digests_survive_reopen_byte_for_byte ... ok
test team::journal::tests::the_restore_resume_table_is_fixed_per_crash_point ... ok
test team::journal::tests::the_resume_table_for_a_downgrade_journal_continues_every_open_phase ... ok
test team::sync::tests::an_unbind_is_refused_while_a_lease_request_or_journal_is_open ... FAILED
test team::downgrade::tests::a_rollback_from_every_step_puts_the_original_back_and_frees_the_profile ... ok
---- team::sync::tests::an_unbind_is_refused_while_a_lease_request_or_journal_is_open stdout ----
thread 'team::sync::tests::an_unbind_is_refused_while_a_lease_request_or_journal_is_open' (28684) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 13 passed; 1 failed; 0 ignored; 0 measured; 494 filtered out; finished in 18.03s
error: test failed, to rerun pass `--lib`
```

### G2-42 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_sync_integer_class_keeps_its_range_across_a_reopen every_integer_class_keeps_its_range_across_a_reopen`

Exit 0; elapsed 1.2 s.

```text
test team::db::tests::every_sync_integer_class_keeps_its_range_across_a_reopen ... ok
test team::records::tests::every_integer_class_keeps_its_range_across_a_reopen ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 506 filtered out; finished in 0.52s
```

### G2-43 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_publish_crash_point_resumes_with_the_exact_stored_bytes a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte every_crash_point_resumes_with_the_exact_stored_bytes an_unbind_tombstone_outlives_its_binding_and_replays_exactly a_release_whose_reply_was_lost_is_replayed_byte_for_byte a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh`

Exit 101; elapsed 2.2 s.

```text
test team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key ... FAILED
test team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte ... FAILED
test team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte ... FAILED
test team::sync::tests::a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh ... FAILED
test team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly ... FAILED
test team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes ... FAILED
test team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes ... FAILED
---- team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key stdout ----
thread 'team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key' (2592) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte stdout ----
thread 'team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte' (32488) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte stdout ----
thread 'team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte' (31104) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh stdout ----
thread 'team::sync::tests::a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh' (25952) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly stdout ----
thread 'team::sync::tests::an_unbind_tombstone_outlives_its_binding_and_replays_exactly' (33148) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes stdout ----
thread 'team::sync::tests::every_crash_point_resumes_with_the_exact_stored_bytes' (25352) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes stdout ----
thread 'team::sync::tests::every_publish_crash_point_resumes_with_the_exact_stored_bytes' (32308) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 0 passed; 7 failed; 0 ignored; 0 measured; 501 filtered out; finished in 1.52s
error: test failed, to rerun pass `--lib`
```

### G2-44 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_upgrade_chain -- the_plan_assertions_hold_on_a_reopened_fresh_file the_plan_assertions_hold_on_a_reopened_v0_1_28_file_and_its_backup_restores fixtures_1_to_4_hold_on_a_fresh_file fixtures_1_to_4_hold_on_a_v0_1_28_file_after_its_upgrade fixtures_1_to_4_hold_on_a_populated_0016_file_after_its_upgrade m0017_root_generations_only_move_forward_on_upgraded_rows m0033_the_quarantine_gains_a_container_hash_and_stays_append_only`

Exit 0; elapsed 2.9 s.

```text
test fixtures_1_to_4_hold_on_a_fresh_file ... ok
test fixtures_1_to_4_hold_on_a_populated_0016_file_after_its_upgrade ... ok
test m0017_root_generations_only_move_forward_on_upgraded_rows ... ok
test fixtures_1_to_4_hold_on_a_v0_1_28_file_after_its_upgrade ... ok
test m0033_the_quarantine_gains_a_container_hash_and_stays_append_only ... ok
test the_plan_assertions_hold_on_a_reopened_fresh_file ... ok
test the_plan_assertions_hold_on_a_reopened_v0_1_28_file_and_its_backup_restores ... ok
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 16 filtered out; finished in 2.60s
```

### G2-45 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_upgrade_chain -- m0030_upgraded_integer_columns_refuse_values_that_are_no_integers`

Exit 0; elapsed 0.6 s.

```text
test m0030_upgraded_integer_columns_refuse_values_that_are_no_integers ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 0.23s
```

### G2-45 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_integer_domain -- every_class_decodes_its_domain_ends_and_refuses_everything_else every_class_column_stores_its_domain_ends_and_its_check_refuses_the_rest every_integer_column_of_every_v2_table_has_an_upper_bound_check every_integer_column_of_every_v2_table_refuses_a_value_that_is_no_integer the_bound_scan_tells_bounded_from_unbounded_columns`

Exit 0; elapsed 0.9 s.

```text
test every_class_decodes_its_domain_ends_and_refuses_everything_else ... ok
test every_integer_column_of_every_v2_table_has_an_upper_bound_check ... ok
test every_class_column_stores_its_domain_ends_and_its_check_refuses_the_rest ... ok
test the_bound_scan_tells_bounded_from_unbounded_columns ... ok
test every_integer_column_of_every_v2_table_refuses_a_value_that_is_no_integer ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.65s
```

### G2-46 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- argon2id_matches_the_rfc_9106_vector the_kek_is_argon2id_over_the_labelled_salt`

Exit 0; elapsed 4.3 s.

```text
test recovery_bundle::tests::argon2id_matches_the_rfc_9106_vector ... ok
test recovery_bundle::tests::the_kek_is_argon2id_over_the_labelled_salt ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 298 filtered out; finished in 4.15s
```

### G2-47 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- debug_never_prints_the_token_or_a_seed debug_never_prints_a_key a_session_debug_print_hides_its_tokens the_trk_is_stored_and_the_saved_state_holds_only_its_reference a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written the_saved_state_never_prints_the_legacy_trk a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key a_reference_to_another_credential_is_refused_and_that_credential_is_kept the_activation_is_saved_before_the_key_is_forgotten the_run_nonce_is_saved_before_the_key_is_stored a_new_run_never_reuses_a_key_an_abandoned_run_left a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it a_forget_succeeds_only_once_the_key_is_confirmed_gone`

Exit 0; elapsed 31.1 s.

```text
test fleet_client::tests::a_session_debug_print_hides_its_tokens ... ok
test fleet_keys::tests::debug_never_prints_a_key ... ok
test key_file::tests::a_forget_succeeds_only_once_the_key_is_confirmed_gone ... ok
test root_bootstrap::tests::a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key ... ok
test root_bootstrap::tests::a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it ... ok
test root_bootstrap::tests::a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made ... ok
test root_bootstrap::tests::a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing ... ok
test root_bootstrap::tests::a_new_run_never_reuses_a_key_an_abandoned_run_left ... ok
test root_bootstrap::tests::a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it ... ok
test root_bootstrap::tests::a_reference_to_another_credential_is_refused_and_that_credential_is_kept ... ok
test root_bootstrap::tests::a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed ... ok
test root_bootstrap::tests::the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written ... ok
test root_bootstrap::tests::the_activation_is_saved_before_the_key_is_forgotten ... ok
test root_bootstrap::tests::the_saved_state_never_prints_the_legacy_trk ... ok
test root_bootstrap::tests::the_run_nonce_is_saved_before_the_key_is_stored ... ok
test team_config::tests::debug_never_prints_the_token_or_a_seed ... ok
test root_bootstrap::tests::the_trk_is_stored_and_the_saved_state_holds_only_its_reference ... ok
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 491 filtered out; finished in 30.54s
```

### G2-48 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_key_round_trips_and_is_forgotten references_are_separate_credentials a_failed_write_or_read_back_is_reported an_unavailable_store_fails_closed_in_a_fresh_process a_key_file_key_is_locked_then_served_in_a_fresh_process`

Exit 0; elapsed 9.6 s.

```text
test credential::tests::a_failed_write_or_read_back_is_reported ... ok
test credential::tests::a_key_round_trips_and_is_forgotten ... ok
test credential::tests::an_unavailable_store_fails_closed_in_a_fresh_process ... ok
test credential::tests::references_are_separate_credentials ... ok
test credential::tests::a_key_file_key_is_locked_then_served_in_a_fresh_process ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 503 filtered out; finished in 9.09s
```

### G2-49 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_durable_write_replaces_the_file_and_leaves_no_temporary a_failed_replace_keeps_the_old_file_and_removes_the_temporary a_write_killed_at_any_step_leaves_the_old_or_the_new_file a_kill_during_back_to_back_writes_never_tears_or_loses_a_returned_write creating_a_file_that_exists_never_overwrites_it`

Exit 0; elapsed 0.7 s.

```text
test durable::tests::a_failed_replace_keeps_the_old_file_and_removes_the_temporary ... ok
test durable::tests::a_durable_write_replaces_the_file_and_leaves_no_temporary ... ok
test durable::tests::a_write_killed_at_any_step_leaves_the_old_or_the_new_file ... ok
test durable::tests::creating_a_file_that_exists_never_overwrites_it ... ok
test durable::tests::a_kill_during_back_to_back_writes_never_tears_or_loses_a_returned_write ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 503 filtered out; finished in 0.15s
```

### G2-49 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- only_a_local_ntfs_disk_is_accepted a_local_ntfs_directory_is_accepted_and_a_missing_one_is_not an_smb_share_is_refused`

Exit 0; elapsed 0.1 s.

```text
test volume::tests::an_smb_share_is_refused ... ok
test volume::tests::only_a_local_ntfs_disk_is_accepted ... ok
test volume::tests::a_local_ntfs_directory_is_accepted_and_a_missing_one_is_not ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 297 filtered out; finished in 0.00s
```

### G2-49 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- storage_that_cannot_be_resolved_is_refused storage_on_an_smb_share_is_refused preflight_refuses_an_identity_directory_on_an_smb_share`

Exit 0; elapsed 0.4 s.

```text
test db::tests::storage_on_an_smb_share_is_refused ... ok
test identity::tests::preflight_refuses_an_identity_directory_on_an_smb_share ... ok
test db::tests::storage_that_cannot_be_resolved_is_refused ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 105 filtered out; finished in 0.02s
```

### G2-49 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- an_identity_directory_the_preflight_refuses_never_falls_to_k1 an_empty_identity_directory_setting_refuses_to_start`

Exit 0; elapsed 2.7 s.

```text
test an_identity_directory_the_preflight_refuses_never_falls_to_k1 ... ok
test an_empty_identity_directory_setting_refuses_to_start ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 2.36s
```

### G2-50 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- the_database_runs_a_synced_rollback_journal_and_survives_an_unclosed_pool a_killed_transaction_reopens_old_or_new_never_half a_kill_between_commits_keeps_every_returned_commit a_second_writer_waits_for_the_write_lock storage_on_an_smb_share_is_refused`

Exit 0; elapsed 1.3 s.

```text
test db::tests::a_killed_transaction_reopens_old_or_new_never_half ... ok
test db::tests::a_kill_between_commits_keeps_every_returned_commit ... ok
test db::tests::storage_on_an_smb_share_is_refused ... ok
test db::tests::the_database_runs_a_synced_rollback_journal_and_survives_an_unclosed_pool ... ok
test db::tests::a_second_writer_waits_for_the_write_lock ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 103 filtered out; finished in 0.80s
```

### G2-50 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_killed_transaction_reopens_old_or_new_never_half a_database_held_in_wal_mode_is_refused`

Exit 0; elapsed 1.5 s.

```text
test team::db::tests::a_database_held_in_wal_mode_is_refused ... ok
test crash_harness::team_sync_db::a_killed_transaction_reopens_old_or_new_never_half ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 506 filtered out; finished in 0.59s
```

### G2-50 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- an_smb_share_is_refused`

Exit 0; elapsed 0.3 s.

```text
test volume::tests::an_smb_share_is_refused ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.00s
```

### G2-51 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_windows_path_corpus_is_refused_in_every_position every_name_windows_rewrites_is_refused ntfs_case_fold_collisions_are_refused_and_distinct_names_kept long_paths_unpack_and_an_overlong_one_is_refused a_junction_is_neither_packed_through_nor_followed_on_replace`

Exit 101; elapsed 0.3 s.

```text
test snapshot::tests::every_name_windows_rewrites_is_refused ... ok
test snapshot::tests::long_paths_unpack_and_an_overlong_one_is_refused ... FAILED
test snapshot::tests::a_junction_is_neither_packed_through_nor_followed_on_replace ... FAILED
test snapshot::tests::the_windows_path_corpus_is_refused_in_every_position ... ok
test snapshot::tests::ntfs_case_fold_collisions_are_refused_and_distinct_names_kept ... FAILED
---- snapshot::tests::long_paths_unpack_and_an_overlong_one_is_refused stdout ----
thread 'snapshot::tests::long_paths_unpack_and_an_overlong_one_is_refused' (31080) panicked at src\snapshot.rs:1365:51:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed
---- snapshot::tests::a_junction_is_neither_packed_through_nor_followed_on_replace stdout ----
thread 'snapshot::tests::a_junction_is_neither_packed_through_nor_followed_on_replace' (32916) panicked at src\snapshot.rs:1407:32:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed
---- snapshot::tests::ntfs_case_fold_collisions_are_refused_and_distinct_names_kept stdout ----
thread 'snapshot::tests::ntfs_case_fold_collisions_are_refused_and_distinct_names_kept' (23032) panicked at src\snapshot.rs:1343:67:
called `Result::unwrap()` on an `Err` value: DPAPI protect failed
test result: FAILED. 2 passed; 3 failed; 0 ignored; 0 measured; 295 filtered out; finished in 0.04s
error: test failed, to rerun pass `--lib`
```

### G2-51 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive a_trace_of_the_old_id_after_the_move_fails_the_discovery_scan`

Exit 0; elapsed 1.3 s.

```text
test team::downgrade::tests::discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive ... ok
test team::downgrade::tests::a_trace_of_the_old_id_after_the_move_fails_the_discovery_scan ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 506 filtered out; finished in 0.50s
```

### G2-52 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- g2_52_every_crash_point_maps_to_one_row_and_resumes_to_the_restored_state`

Exit 0; elapsed 20.5 s.

```text
test g2_52_every_crash_point_maps_to_one_row_and_resumes_to_the_restored_state ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 20.07s
```

### G2-53 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test identity_authority -- a_symlinked_record_is_refused show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest`

Exit 0; elapsed 1.4 s.

```text
test a_symlinked_record_is_refused ... ok
test show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 20 filtered out; finished in 0.86s
```

### G2-53 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- an_identity_directory_that_is_not_there_is_missing_and_stops_the_server`

Exit 0; elapsed 1.0 s.

```text
test an_identity_directory_that_is_not_there_is_missing_and_stops_the_server ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 0.58s
```

### G2-54 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2259_g2_54_a_record_equal_to_its_mirror_without_a_manifest_opens_normally`

Exit 0; elapsed 2.9 s.

```text
test l2259_g2_54_a_record_equal_to_its_mirror_without_a_manifest_opens_normally ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 2.59s
```

### G2-55 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2260_g2_55_a_durable_preparation_at_e_keeps_writes_off_until_commit_or_abort g2_55_a_failed_read_only_audit_write_is_counted_in_restore_status g2_55_the_k2_incident_output_prints_the_audit_failure_count g2_55_a_directory_at_the_count_path_stops_a_read_only_start_by_name g2_55_restore_commit_prints_the_final_audit_failure_count_and_clears_it g2_55_a_read_only_start_logs_the_failed_audit_writes_counted_so_far g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count g2_55_a_count_under_a_changed_episode_key_is_kept_and_cleared_by_name g2_55_a_count_file_with_a_bad_line_is_set_aside_and_its_valid_lines_kept`

Exit 0; elapsed 19.3 s.

```text
test g2_55_a_count_file_with_a_bad_line_is_set_aside_and_its_valid_lines_kept ... ok
test g2_55_a_directory_at_the_count_path_stops_a_read_only_start_by_name ... ok
test g2_55_a_count_under_a_changed_episode_key_is_kept_and_cleared_by_name ... ok
test g2_55_a_read_only_start_logs_the_failed_audit_writes_counted_so_far ... ok
test g2_55_a_failed_read_only_audit_write_is_counted_in_restore_status ... ok
test g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count ... ok
test g2_55_restore_commit_prints_the_final_audit_failure_count_and_clears_it ... ok
test g2_55_the_k2_incident_output_prints_the_audit_failure_count ... ok
test l2260_g2_55_a_durable_preparation_at_e_keeps_writes_off_until_commit_or_abort ... ok
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 15 filtered out; finished in 19.02s
```

### G2-55 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- a_failed_read_only_audit_write_is_logged_and_counted the_count_continues_across_read_only_restarts_of_one_episode a_changed_episode_key_keeps_the_old_count_until_it_is_cleared_by_name one_bad_line_in_the_count_file_loses_only_itself a_crash_while_setting_a_file_aside_never_loses_the_valid_lines the_count_is_written_atomically_and_an_unreadable_one_is_reported a_directory_or_link_at_the_count_path_is_refused_by_name`

Exit 0; elapsed 0.5 s.

```text
test audit::tests::a_changed_episode_key_keeps_the_old_count_until_it_is_cleared_by_name ... ok
test audit::tests::a_crash_while_setting_a_file_aside_never_loses_the_valid_lines ... ok
test audit::tests::a_directory_or_link_at_the_count_path_is_refused_by_name ... ok
test audit::tests::a_failed_read_only_audit_write_is_logged_and_counted ... ok
test audit::tests::one_bad_line_in_the_count_file_loses_only_itself ... ok
test audit::tests::the_count_continues_across_read_only_restarts_of_one_episode ... ok
test audit::tests::the_count_is_written_atomically_and_an_unreadable_one_is_reported ... ok
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 101 filtered out; finished in 0.13s
```

### G2-56 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2261_g2_56_an_authority_ahead_of_the_live_mirror_resumes_only_the_install`

Exit 0; elapsed 5.4 s.

```text
test l2261_g2_56_an_authority_ahead_of_the_live_mirror_resumes_only_the_install ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 5.06s
```

### G2-57 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2262_g2_57_an_installed_db_behind_the_record_is_verified_then_rebuilt`

Exit 0; elapsed 9.7 s.

```text
test l2262_g2_57_an_installed_db_behind_the_record_is_verified_then_rebuilt ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 9.40s
```

### G2-58 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2263_g2_58_an_authority_ahead_without_exact_evidence_fails_closed l2263_g2_58_only_a_live_custodian_transition_over_the_computed_leaves_prepares`

Exit 0; elapsed 11.4 s.

```text
test l2263_g2_58_an_authority_ahead_without_exact_evidence_fails_closed ... ok
test l2263_g2_58_only_a_live_custodian_transition_over_the_computed_leaves_prepares ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 10.65s
```

### G2-59 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- g2_55_the_k2_incident_output_prints_the_audit_failure_count`

Exit 0; elapsed 4.7 s.

```text
test g2_55_the_k2_incident_output_prints_the_audit_failure_count ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 4.33s
```

### G2-60 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2265_g2_60_a_reconciled_epoch_retires_its_bundle_and_the_next_start_is_normal`

Exit 0; elapsed 9.8 s.

```text
test l2265_g2_60_a_reconciled_epoch_retires_its_bundle_and_the_next_start_is_normal ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 9.34s
```

### G2-61 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- a_snapshot_sealed_for_another_profile_is_refused every_single_byte_mutation_is_detected truncation_at_any_length_is_detected cross_envelope_frame_splice_is_rejected another_fleet_key_cannot_open_it grant_cannot_be_replayed_into_another_tenant_or_epoch tampering_with_the_stored_info_fails_the_open`

Exit 101; elapsed 33.6 s.

```text
test backup::tests::cross_envelope_frame_splice_is_rejected ... ok
test backup::tests::every_single_byte_mutation_is_detected ... ok
test backup_file::tests::a_snapshot_sealed_for_another_profile_is_refused ... FAILED
test backup_file::tests::another_fleet_key_cannot_open_it ... FAILED
test fleet_grants::tests::tampering_with_the_stored_info_fails_the_open ... ok
test grants::tests::grant_cannot_be_replayed_into_another_tenant_or_epoch ... ok
test backup::tests::truncation_at_any_length_is_detected ... ok
---- backup_file::tests::a_snapshot_sealed_for_another_profile_is_refused stdout ----
thread 'backup_file::tests::a_snapshot_sealed_for_another_profile_is_refused' (9228) panicked at src\backup_file.rs:456:63:
    DPAPI protect failed
---- backup_file::tests::another_fleet_key_cannot_open_it stdout ----
thread 'backup_file::tests::another_fleet_key_cannot_open_it' (25748) panicked at src\backup_file.rs:409:72:
    DPAPI protect failed
test result: FAILED. 5 passed; 2 failed; 0 ignored; 0 measured; 293 filtered out; finished in 33.22s
error: test failed, to rerun pass `--lib`
```

### G2-61 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --test backup_file_roundtrip -- the_ciphertext_does_not_contain_the_plaintext a_tampered_backup_body_is_refused a_truncated_backup_is_refused_and_leaves_the_destination_untouched`

Exit 101; elapsed 9.3 s.

```text
test a_truncated_backup_is_refused_and_leaves_the_destination_untouched ... FAILED
test a_tampered_backup_body_is_refused ... FAILED
test the_ciphertext_does_not_contain_the_plaintext ... FAILED
---- a_truncated_backup_is_refused_and_leaves_the_destination_untouched stdout ----
thread 'a_truncated_backup_is_refused_and_leaves_the_destination_untouched' (16184) panicked at tests\backup_file_roundtrip.rs:199:63:
    DPAPI protect failed
---- a_tampered_backup_body_is_refused stdout ----
thread 'a_tampered_backup_body_is_refused' (12772) panicked at tests\backup_file_roundtrip.rs:228:63:
    DPAPI protect failed
---- the_ciphertext_does_not_contain_the_plaintext stdout ----
thread 'the_ciphertext_does_not_contain_the_plaintext' (26416) panicked at tests\backup_file_roundtrip.rs:146:63:
    DPAPI protect failed
test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 5 filtered out; finished in 8.76s
error: test failed, to rerun pass `--test backup_file_roundtrip`
```

### G2-61 `cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- pull_refuses_another_profiles_snapshot push_seals_under_the_passphrase_even_with_a_cached_fleet_key a_server_delivered_fleet_key_is_counted_but_never_cached a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet a_compromised_revocation_blocks_commits_under_an_exposed_generation a_compromised_custodian_blocks_every_fleet_through_the_root an_exposure_survives_a_recollection_that_omits_its_grant an_open_upload_is_aborted_once_a_compromise_is_counted`

Exit 101; elapsed 5.1 s.

```text
test custody_tests::a_server_delivered_fleet_key_is_counted_but_never_cached ... ok
test sync_cmd::tests::pull_refuses_another_profiles_snapshot ... FAILED
test sync_cmd::tests::push_seals_under_the_passphrase_even_with_a_cached_fleet_key ... FAILED
test team::sync::tests::a_compromised_custodian_blocks_every_fleet_through_the_root ... FAILED
test team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation ... FAILED
test team::sync::tests::an_exposure_survives_a_recollection_that_omits_its_grant ... FAILED
test custody_tests::a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet ... ok
test team::sync::tests::an_open_upload_is_aborted_once_a_compromise_is_counted ... FAILED
---- sync_cmd::tests::pull_refuses_another_profiles_snapshot stdout ----
thread 'sync_cmd::tests::pull_refuses_another_profiles_snapshot' (1580) panicked at src\sync_cmd.rs:669:14:
called `Result::unwrap()` on an `Err` value: pack profile for backup
    DPAPI protect failed
---- sync_cmd::tests::push_seals_under_the_passphrase_even_with_a_cached_fleet_key stdout ----
thread 'sync_cmd::tests::push_seals_under_the_passphrase_even_with_a_cached_fleet_key' (4692) panicked at src\sync_cmd.rs:613:33:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_compromised_custodian_blocks_every_fleet_through_the_root stdout ----
thread 'team::sync::tests::a_compromised_custodian_blocks_every_fleet_through_the_root' (13476) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation stdout ----
thread 'team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation' (7636) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_exposure_survives_a_recollection_that_omits_its_grant stdout ----
thread 'team::sync::tests::an_exposure_survives_a_recollection_that_omits_its_grant' (2156) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
---- team::sync::tests::an_open_upload_is_aborted_once_a_compromise_is_counted stdout ----
thread 'team::sync::tests::an_open_upload_is_aborted_once_a_compromise_is_counted' (33192) panicked at src\team\sync.rs:4112:74:
called `Result::unwrap()` on an `Err` value: [[shardx:keyStore.protectFailed]]
test result: FAILED. 2 passed; 6 failed; 0 ignored; 0 measured; 500 filtered out; finished in 3.12s
error: test failed, to rerun pass `--lib`
```

### G2-61 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test identity_authority -- an_interrupted_init_is_reported_and_never_repaired`

Exit 0; elapsed 4.4 s.

```text
test an_interrupted_init_is_reported_and_never_repaired ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 21 filtered out; finished in 3.24s
```

### G2-61 `cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- wrong_domain_hpke_ids_are_quarantined_once`

Exit 0; elapsed 1.0 s.

```text
test integrity::tests::wrong_domain_hpke_ids_are_quarantined_once ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 107 filtered out; finished in 0.39s
```

### G2-63 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --test registry_pins -- every_signing_domain_is_distinct_and_versioned every_hash_label_is_distinct_and_nul_terminated the_numeric_registry_holds_the_reviewed_values`

Exit 0; elapsed 0.2 s.

```text
test every_hash_label_is_distinct_and_nul_terminated ... ok
test every_signing_domain_is_distinct_and_versioned ... ok
test the_numeric_registry_holds_the_reviewed_values ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### G2-63 `cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- g2_golden_vector_profile_label a_profile_label_opens_only_where_it_was_sealed a_profile_label_has_a_length_bound_both_ways a_profile_label_is_padded_to_a_bucket a_profile_label_that_is_not_canonical_is_refused`

Exit 0; elapsed 0.2 s.

```text
test keys::tests::a_profile_label_has_a_length_bound_both_ways ... ok
test keys::tests::a_profile_label_is_padded_to_a_bucket ... ok
test keys::tests::a_profile_label_that_is_not_canonical_is_refused ... ok
test keys::tests::g2_golden_vector_profile_label ... ok
test keys::tests::a_profile_label_opens_only_where_it_was_sealed ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 295 filtered out; finished in 0.02s
```


## Per-row invocation totals

{'invocations': 96, 'exit_0': 75, 'nonzero': 21, 'passed': 252, 'failed': 67, 'ignored': 0}

Repeated test names count again on each cited row. G2-48 real Credential Manager test omitted explicitly; G2-62 uses the gate commands, G2-64 is this independent verdict.

| Row | Invocations | Exit 0 | Nonzero | Passing executions | Failing executions | Ignored |
|---|---:|---:|---:|---:|---:|---:|
| G2-01 | 2 | 2 | 0 | 4 | 0 | 0 |
| G2-02 | 2 | 2 | 0 | 2 | 0 | 0 |
| G2-03 | 2 | 2 | 0 | 3 | 0 | 0 |
| G2-04 | 2 | 2 | 0 | 4 | 0 | 0 |
| G2-05 | 2 | 2 | 0 | 3 | 0 | 0 |
| G2-06 | 2 | 2 | 0 | 2 | 0 | 0 |
| G2-07 | 1 | 1 | 0 | 6 | 0 | 0 |
| G2-08 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-09 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-10 | 1 | 1 | 0 | 7 | 0 | 0 |
| G2-11 | 1 | 1 | 0 | 6 | 0 | 0 |
| G2-12 | 1 | 1 | 0 | 7 | 0 | 0 |
| G2-13 | 1 | 1 | 0 | 4 | 0 | 0 |
| G2-14 | 2 | 2 | 0 | 10 | 0 | 0 |
| G2-15 | 1 | 1 | 0 | 4 | 0 | 0 |
| G2-16 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-17 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-18 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-19 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-20 | 2 | 2 | 0 | 2 | 0 | 0 |
| G2-21 | 2 | 1 | 1 | 1 | 2 | 0 |
| G2-22 | 2 | 1 | 1 | 2 | 2 | 0 |
| G2-23 | 2 | 1 | 1 | 2 | 1 | 0 |
| G2-24 | 2 | 1 | 1 | 2 | 1 | 0 |
| G2-25 | 2 | 1 | 1 | 2 | 1 | 0 |
| G2-26 | 2 | 1 | 1 | 2 | 4 | 0 |
| G2-27 | 1 | 1 | 0 | 5 | 0 | 0 |
| G2-28 | 1 | 1 | 0 | 7 | 0 | 0 |
| G2-29 | 1 | 1 | 0 | 5 | 0 | 0 |
| G2-30 | 2 | 1 | 1 | 10 | 1 | 0 |
| G2-31 | 5 | 4 | 1 | 9 | 6 | 0 |
| G2-32 | 1 | 1 | 0 | 3 | 0 | 0 |
| G2-33 | 1 | 0 | 1 | 1 | 4 | 0 |
| G2-34 | 1 | 0 | 1 | 0 | 3 | 0 |
| G2-35 | 1 | 0 | 1 | 4 | 2 | 0 |
| G2-36 | 1 | 0 | 1 | 1 | 1 | 0 |
| G2-37 | 1 | 0 | 1 | 0 | 3 | 0 |
| G2-38 | 2 | 1 | 1 | 3 | 2 | 0 |
| G2-39 | 1 | 0 | 1 | 0 | 12 | 0 |
| G2-40 | 1 | 1 | 0 | 2 | 0 | 0 |
| G2-41 | 1 | 0 | 1 | 13 | 1 | 0 |
| G2-42 | 1 | 1 | 0 | 2 | 0 | 0 |
| G2-43 | 1 | 0 | 1 | 0 | 7 | 0 |
| G2-44 | 1 | 1 | 0 | 7 | 0 | 0 |
| G2-45 | 2 | 2 | 0 | 6 | 0 | 0 |
| G2-46 | 1 | 1 | 0 | 2 | 0 | 0 |
| G2-47 | 1 | 1 | 0 | 17 | 0 | 0 |
| G2-48 | 1 | 1 | 0 | 5 | 0 | 0 |
| G2-49 | 4 | 4 | 0 | 13 | 0 | 0 |
| G2-50 | 3 | 3 | 0 | 8 | 0 | 0 |
| G2-51 | 2 | 1 | 1 | 4 | 3 | 0 |
| G2-52 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-53 | 2 | 2 | 0 | 3 | 0 | 0 |
| G2-54 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-55 | 2 | 2 | 0 | 16 | 0 | 0 |
| G2-56 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-57 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-58 | 1 | 1 | 0 | 2 | 0 | 0 |
| G2-59 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-60 | 1 | 1 | 0 | 1 | 0 | 0 |
| G2-61 | 5 | 2 | 3 | 9 | 11 | 0 |
| G2-63 | 2 | 2 | 0 | 8 | 0 | 0 |

## Final integrity and cleanup readback

The only repository writes were Tauri-generated schema side effects, now undone using `git cat-file --filters HEAD:<path>` bytes. No git index, branch, worktree configuration, commit or remote mutation was performed. No test sources were edited.

```text
src-tauri/gen/schemas/desktop-schema.json: restored checkout-filtered HEAD bytes; SHA-256 c68c778972e75f0da1f598f6c20efba9a5292d52de8b8314ed336944bd4d80e9
src-tauri/gen/schemas/windows-schema.json: restored checkout-filtered HEAD bytes; SHA-256 c68c778972e75f0da1f598f6c20efba9a5292d52de8b8314ed336944bd4d80e9
git diff --exit-code -> exit 0
(empty output)
git status --short -> exit 0
(empty output)
git rev-parse HEAD -> exit 0
9e29a2c6a1ae39378b3fe269e3f1ee82a530b9e3
python scripts/g2-evidence.py --check -> exit 0
118 files checked, 0 problems
```

## Remaining verification limits and final decision

- The original B1/B2/B3 end-to-end scenarios and many local publish/push/replay/backup assertions were attempted but stopped in DPAPI/protection-dependent fixture setup. Source review and the passing isolated ledger helpers are narrower evidence. The report does not claim those failed fixtures reproduced their intended scenarios.
- N1 was reproduced dynamically at the production SQL retention boundary, including a foreign-key-enabled probe. Its signed-record acceptance and eventual commit path were traced in source. N2 is a source-established state-machine counterexample using an interruption point already present in the repository test harness. Neither is represented as a newly executed end-to-end Rust regression; source edits and injected test files were outside the permitted scope.
- Five network-share branches and the identity-record symlink branch were observed skipping. No SMB share or machine privilege was created. Other platform-specific behavior, physical power-loss durability, real credential persistence, current remote CI status and current RustSec advisories were not verified here. The existing ignored operator drill was not run. Mutation scripts that edit source were inspected where cited but not executed.
- Q-43's arbitrary numeric TEXT rounding boundary and D-8's incomplete aggregate domain/label registry remain coverage/documentation discrepancies. The detailed list also records the misleading HPKE-info golden citation, stale plan-line citations, stale packet counts and narrower G2-59 citation. No present domain collision or validated-i64 wire corruption was demonstrated.
- G2-48 remains **PENDING-MANUAL under the owner's accepted exception**. Team UI deferral is also accepted. Neither is a reason for this FAIL. The remaining backend gate fails because of N1/N2; the execution limits independently prevent claiming every other row was reproduced.

At completion the exact requested HEAD is unchanged, `git diff --exit-code` passes, `git status --short` is empty, and the manifest checker again reports 118 files checked with zero problems. The report is the sole authored deliverable. No production data, real ShardX app-data directory or real credential-store test was used.

VERDICT: FAIL
