# G2 evidence packet

This is the evidence the independent verifier reads back for G2 (WP-10, row
G2-64). It lists all 64 G2 rows with their plan line, status, evidence and the
ADR decision that narrows them; the commands, toolchains and gates to
reproduce the evidence; and a SHA-256 for every artifact it cites.

- **Packet date:** 2026-11-01. **Code under review:** `main` at fe8c8e36, which
  carries the fixes for verifier findings B1 to B7 (section 8), plus this
  refresh (branch `g2/evidence-b1-b7`). The first packet reviewed the head of
  PR #212 (`g2/trk-at-rest`, 5c1cd7b8).
- **Plan:** `.omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md`.
  The G2 rows are cited by plan line; lines after about L900 are 2 lower in
  older citations (test names such as `l2259_g2_54_...` keep the old numbers).
  The G2 gate paragraph is at L2343: every row needs reproducible evidence, then
  an independent verifier reads back commands, fixtures, versions and SHA-256
  and gives the verdict `PASS`.
- **ADR:** `docs/adr/0002-g2-contract-decisions.md` as on `main` (Q-1 to Q-43).
  ADRs 0003 (envelope v2 and STREAM) and 0004 (credential store) are cited
  where a row depends on them.
- **Row IDs** G2-01 to G2-64 are the numbering of the G2 gap analyses; the
  plan itself does not number them.

## Verdict of this packet

Status counts: DONE 62, PENDING-MANUAL 1, FAIL 1.

**G2 is FAIL.** The independent verifier returned FAIL on 2026-11-01
(section 8). The owner decided to release v2.5.0 with G2 recorded as FAIL,
because the paths the findings affect are not reachable from the launcher UI
or the Automation API in that release. The Team UI that exposes publish must
not ship until findings B1 to B7 are fixed and both verifiers return PASS.
B1 to B7 are now fixed on `main` (section 8). Both verifiers reran on
9e29a2c6 on 2026-11-02 and returned FAIL again, Codex for two new findings
(N1, N2) and Hermes for the skipped SMB branches; those are fixed here too.
G2 stays FAIL until both verifiers return PASS on the fixed tree.

- **G2-48 is PENDING-MANUAL.** The plan's gate paragraph (L2343) lists
  "credential-store persistence" among the uncertainties that make G2
  `FAIL/BLOCKED`. The evidence for it is a log from a real Windows machine
  (ADR Q-29), and nobody has run it yet. Under the gate paragraph, unresolved
  credential-store-persistence evidence means G2 is not a full PASS. The owner
  chose to release without waiting for it, so the release proceeds on an owner
  decision, not on a verifier-confirmed full PASS.
- **G2-64 is FAIL.** Codex found seven blocking findings (B1 to B7); Hermes
  produced no report. All seven are fixed and G2-14, G2-31, G2-42 and G2-61
  are DONE again. The 2026-11-02 rerun found N1 and N2 (Codex) and the
  skipped SMB branches (Hermes); they are fixed as well (section 8).
- Every other row is DONE in the sense the gap analyses use: a test or a
  recorded run exercises the row's PASS criterion. DONE is not a G2 gate PASS.
  Rows with a weaker form of evidence say so in their **Note**.

## 1. Toolchains

Print them with:

```
rustc +stable --version && cargo +stable --version
for v in 1.87.0 1.88.0 1.89.0; do rustc +$v --version; done
grep -H '^rust-version' shared/Cargo.toml server/Cargo.toml src-tauri/Cargo.toml
```

Values on the machine that ran this packet (Windows 11, `x86_64-pc-windows-msvc`):

| Role | Version |
| --- | --- |
| stable rustc | 1.99.1 (58cf8f9c3 2026-10-13); cargo 1.99.1 (5f94df478 2026-08-27) |
| MSRV of `shared` (`shardx-core`) | rust-version 1.87; rustc 1.87.0 (17067e9ac 2025-05-09) |
| MSRV of the launcher (`src-tauri`) | rust-version 1.88; rustc 1.88.0 (6b00bc388 2025-06-23) |
| MSRV of `server` | rust-version 1.89; rustc 1.89.0 (29483883e 2025-08-04) |

CI installs `stable` fresh on each run, so its version floats; the MSRV job
reads each crate's `rust-version` from its manifest, so the three cannot drift.
Node 20 runs the npm checks in CI (this machine ran them on Node v24.22.2).

## 2. Reproduce the gates

Run everything from the repository root. On a small machine add `-j 1` and set
`CARGO_TARGET_DIR` to a scratch directory; a full parallel `cargo test` can
fail with Windows error 1455 (paging file).

**Formatting** (all four crates):

```
for c in shared server src-tauri sdks/rust; do cargo +stable fmt --check --manifest-path $c/Cargo.toml; done
```

**Clippy**, warnings denied:

```
for c in src-tauri shared server; do cargo +stable clippy --locked --manifest-path $c/Cargo.toml --all-targets -- -D warnings; done
```

**Tests, per crate.** The launcher's enrollment test starts a real server, so
build the server first:

```
cargo test --locked --manifest-path shared/Cargo.toml
cargo test --locked --manifest-path server/Cargo.toml
cargo build --locked --manifest-path server/Cargo.toml
cargo test --locked --manifest-path src-tauri/Cargo.toml
```

The SMB refusal tests (G2-49, G2-50) skip unless `SHARDX_TEST_SMB_DIR` names a
share on this machine. CI creates one in the step `Create a temporary SMB
share` of the job `Rust tests on Windows` (elevated `New-SmbShare` on an empty
scratch directory, removed afterwards). Without the variable those tests pass
by skipping.

**MSRV with `--locked`**, each crate on its declared `rust-version`:

```
for crate in shared server src-tauri; do
  msrv=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' "$crate/Cargo.toml")
  rustup toolchain install "$msrv" --profile minimal
  cargo "+$msrv" check --locked --all-targets --manifest-path "$crate/Cargo.toml"
done
```

**Advisories** (the ignores are the reviewed ones in `docs/dependency-review.md`):

```
cargo +stable install cargo-audit --locked --version 0.22.2
cargo +stable audit --deny unsound --deny yanked --file shared/Cargo.lock
cargo +stable audit --deny unsound --deny yanked --file server/Cargo.lock --ignore RUSTSEC-2023-0071
cargo +stable audit --deny unsound --deny yanked --file src-tauri/Cargo.lock \
  --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195 \
  --ignore RUSTSEC-2026-0367 --ignore RUSTSEC-2026-0368 --ignore RUSTSEC-2026-0369 \
  --ignore RUSTSEC-2024-0429
```

**Interface language checks** (npm; they read files and need no `npm ci`):

```
npm run test:i18n
npm run test:rust-strings
npm run test:backend-locale
```

CI also runs `npm run test:raw-error-toast` in the same step.

**Mutation scripts** (optional; they edit and restore source files, so run
them in a scratch worktree): `scripts/g2-44-migration-mutants.py` for the
migrations (G2-44) and `scripts/g2-wp5-mutants.py` for the journals and the
downgrade flow (G2-41).

## 3. CI workflows that must be green

Workflow `CI` (file `ci.yml`), all five jobs, on the exact commit proposed for
release on `main` (ADR Q-15):

1. `Rust SDK stable and MSRV` (also runs the RustSec audit steps above)
2. `Rust tests on Windows` (shared, server and launcher tests with the SMB share)
3. `Rust compiles on macOS`
4. `frontend, Rust, and MCP checks` (fmt, clippy, interface language tests, build, tests)
5. `Launcher, server and shared MSRV`

The `Release` workflow publishes artifacts and is not a gate.

State read with `gh run list` on 2026-11-01, which the verifier must read again:

| Commit | Branch | Run | Result |
| --- | --- | --- | --- |
| da400ea0 | `team-custody-production` (PR #209 head) | 41247149446 | success |
| 0387f3a1 | `main` | 41248535227 | success |
| 5c1cd7b8 | `g2/trk-at-rest` (PR #212 head, the code the first packet reviewed) | 41254563480 | in progress when read |
| fe8c8e36 | `main` (B1 to B7 fixed, the code this refresh reviews) | 41328861443 | in progress when read |

The commit that carries this packet has not been pushed, so it has no run yet. The release commit needs its own green run (Q-15).

## 4. Hashes and line endings

`docs/g2-evidence/SHA256SUMS` holds `sha256  path` for every artifact this
packet cites, with paths relative to the repository root: test files, fixtures
and golden-vector sources, docs, the ADRs, the migration SQL, the plan, the
manifests and lockfiles, and the scripts. It excludes this README and
SHA256SUMS themselves.

```
python scripts/g2-evidence.py --check       # exit 0 only if every listed file matches
python scripts/g2-evidence.py --write       # regenerate SHA256SUMS from the list in the script
python scripts/g2-evidence.py --self-test   # check passes after --write, fails after one byte changes
```

The list of artifacts is fixed in the script. `--check` also fails when this
README names an existing repository file in backticks that the list does not
cover.

**Line endings.** The repository stores LF; a Windows checkout with
`core.autocrlf=true` holds CRLF (this one does). The script replaces CRLF by LF
before hashing, so the same sums hold on both. A plain `sha256sum` on a CRLF
checkout will not match; use `tr -d '\r' < file | sha256sum` for one file.

## 5. The rows

Status words: **DONE** a test or recorded run exercises the row's PASS
criterion; **PENDING-MANUAL** the evidence needs a run only the owner can do;
**PENDING** the row's work has not happened yet; **PARTIAL** the cited
tests pass but a verifier finding shows the row's criterion is not fully met;
**FAIL** the row's check was run and failed. A test name followed by
`(vector)` pins golden bytes or an official vector. Paths are relative to the
repository root. Section 6 gives the exact command of each row.

| Row | Name | Plan | Status | Evidence | ADR 0002 |
| --- | --- | --- | --- | --- | --- |
| G2-01 | DeviceApprovalV2 + container | L443-L508 | DONE | `server/tests/v2_auth.rs`: `the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt`, `every_approval_column_is_compared_with_its_container_on_each_request`, `the_startup_pass_quarantines_approvals_that_left_their_containers`; `shared/src/authz_record.rs`: `golden_vectors` (vector) | D-2, Q-1, Q-13, Q-22 |
| G2-02 | TenantCapabilityGrantV2 | L443-L508 | DONE | `server/tests/v2_auth.rs`: `every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup`; `shared/src/authz_record.rs`: `golden_vectors` (vector) | Q-2, D-2, Q-13 |
| G2-03 | FleetKeyGrantV2::DeviceHpkeGrant | L443-L508, L1358 | DONE | `server/tests/v2_auth.rs`: `every_fleet_grant_column_is_compared_with_its_container_on_each_request`, `the_startup_pass_quarantines_fleet_grants_that_left_their_containers`; `shared/src/authz_record.rs`: `golden_vectors` (vector); code: `src-tauri/src/lib.rs` | D-8, D-9, Q-5, Q-13, Q-26 |
| G2-04 | FleetKeyGrantV2::RecoveryGrant | L443-L508 | DONE | `shared/src/authz_record.rs`: `recovery_grant_binds_context_suite_and_lengths`, `recovery_grant_opens_only_under_its_root_and_to_its_fkek`, `golden_vectors` (vector); `server/tests/v2_auth.rs`: `every_fleet_grant_column_is_compared_with_its_container_on_each_request` | D-5, D-9 |
| G2-05 | FleetKeyGrantV2::RotationGrant | L443-L508 | DONE | `shared/src/authz_record.rs`: `rotation_grant_follows_its_generation_window_and_count_rules`, `golden_vectors` (vector); `server/tests/v2_auth.rs`: `every_fleet_grant_column_is_compared_with_its_container_on_each_request` | D-5, D-9, Q-5 |
| G2-06 | TenantRootKeyGrantV2 (3 variants, lifecycle) | L760-L909 | DONE | `server/tests/v2_auth.rs`: `every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup`; `shared/src/authz_record.rs`: `golden_vectors` (vector) **Note:** The launcher product path files only FirstRootSelfGrant; RotationGrant is exercised by the server tests. | Q-1, D-4, Q-23, Q-24 |
| G2-07 | SnapshotManifestV2 / signed / head hash | L509-L589 | DONE | `shared/src/snapshot_v2.rs`: `golden_vectors` (vector), `payload_rejects_every_field_level_defect`, `container_rejects_every_field_level_defect`, `signing_binds_the_signer_key`, `manifest_binds_a_sealed_envelope_v2_object` | Q-1, Q-36 |
| G2-08 | CommitRequestV2 | L509-L589 | DONE | `server/tests/v2_profiles.rs`: `every_upload_refusal_has_its_status_and_code`; code: `shared/src/snapshot_v2.rs` | Q-34 |
| G2-09 | CommitReceiptBindingV2 | L509-L589 | DONE | `server/tests/v2_profiles.rs`: `an_upload_commits_once_and_the_next_checkout_starts_at_its_head`; code: `shared/src/snapshot_v2.rs` | none |
| G2-10 | DekSlotContextV2 / DekSlotV2 | L590-L759 | DONE | `shared/src/envelope_v2.rs`: `the_closed_maps_parse_what_the_builders_write`, `every_dek_slot_context_rule_is_enforced`, `every_dek_slot_rule_is_enforced`, `a_slot_that_differs_from_the_intent_is_refused`, `the_reader_refuses_an_open_map`; `shared/src/envelope.rs`: `g2_golden_vector_dek_slot` (vector); `shared/src/canonical.rs`: `g2_golden_vector_dek_slot_context_hash` (vector) | D-3, ADR 0003, D-8 |
| G2-11 | EnvelopeIntentV2 | L590-L759 | DONE | `shared/src/envelope_v2.rs`: `the_intent_bounds_are_the_plans`, `every_envelope_intent_rule_is_enforced`, `the_intent_and_slot_must_be_the_ones_the_manifest_names`; `shared/src/snapshot_v2.rs`: `manifest_binds_a_sealed_envelope_v2_object`; `shared/src/envelope.rs`: `g2_golden_vector_intent` (vector), `g2_golden_vector_intent_genesis` (vector) | D-3, ADR 0003 |
| G2-12 | RestoreEpochLeafV2 / inclusion proof | L590-L759 | DONE | `shared/src/restore_epoch.rs`: `golden_vectors` (vector), `leaf_roundtrips_and_refuses_contract_violations`, `leaf_sets_must_be_non_empty_sorted_and_unique`, `every_leaf_proves_and_every_tampering_fails`, `a_proof_binds_tenant_profile_instance_epochs_count_and_root`, `proof_parser_refuses_every_contract_violation`; `shared/src/envelope.rs`: `g2_golden_vectors_merkle_roots` (vector) | D-1, Q-1, Q-36 |
| G2-13 | RestoreEpochTransitionV2 / signed | L590-L759 | DONE | `shared/src/restore_epoch.rs`: `transition_roundtrips_and_verifies`, `transition_payload_refuses_every_contract_violation`, `signed_transition_refuses_every_container_defect`, `transition_signature_binds_key_bytes_and_label` | D-1, Q-33, Q-36 |
| G2-14 | IdempotentMutationRequestV2 | L910-L1054 | DONE | `shared/src/mutation.rs`: `golden_vectors` (vector), `every_map_roundtrips_byte_for_byte`, `every_map_refuses_another_domain_or_version`, `every_kind_has_one_scope_and_the_scope_must_match`, `hashes_and_closed_fields_are_checked`, `device_revoke_maps_carry_one_container_and_roundtrip`; `server/tests/v2_auth.rs`: `a_revocation_commits_its_fleet_activation_or_nothing`, `a_revocation_commits_its_root_activation`; `shared/src/fleet_lifecycle.rs`: `golden_vectors` (vector) **Note:** verifier finding B5 is fixed (PR #219): the DEVICE_REVOKE map takes 0 to 65535 sorted, unique activations, and the server commits them with the revocation or not at all. | Q-5, Q-13 |
| G2-15 | IdempotentStoredResponseV2 | L910-L1054 | DONE | `shared/src/mutation.rs`: `golden_vectors` (vector), `every_map_roundtrips_byte_for_byte`, `every_map_refuses_another_domain_or_version` | D-6, Q-34 |
| G2-16 | ROOT_GENERATION_CREATE | L915 | DONE | `server/tests/v2_auth.rs`: `the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response`; code: `shared/src/mutation.rs`, `server/src/routes/v2_root.rs` | Q-5, D-4, D-9, Q-28 |
| G2-17 | ROOT_GRANT_CREATE | L915 | DONE | `server/tests/v2_auth.rs`: `every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup`; code: `shared/src/mutation.rs`, `server/src/routes/v2_root_grants.rs` | Q-5, D-4, D-9 |
| G2-18 | ROOT_GRANT_ACK | L915 | DONE | `server/tests/v2_auth.rs`: `readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant`; code: `shared/src/mutation.rs`, `server/src/routes/v2_root_grants.rs` | Q-5, D-9 |
| G2-19 | ROOT_GENERATION_ACTIVATE | L915 | DONE | `server/tests/v2_auth.rs`: `readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant`; code: `shared/src/mutation.rs`, `server/src/routes/v2_root_grants.rs` | Q-5, D-9, Q-24, Q-28 |
| G2-20 | ROOT_GRANT_REVOKE | L915 | DONE | `shared/src/mutation.rs`: `a_revocation_names_a_known_reason_and_its_outcome`; `server/tests/v2_auth.rs`: `a_custodian_revokes_a_root_grant_but_never_the_last_one`; code: `server/src/routes/v2_root_grants.rs` | Q-5, Q-23 |
| G2-21 | PROFILE_PUBLISH_CREATE | L915, L1139 | DONE | `server/tests/v2_profiles.rs`: `one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes`; `src-tauri/src/team/sync.rs`: `a_profile_is_published_with_its_first_lease_and_then_pushed`, `every_publish_crash_point_resumes_with_the_exact_stored_bytes`; code: `shared/src/profile_lease.rs`, `server/src/routes/v2_profiles.rs`, `src-tauri/src/fleet_client.rs`, `src-tauri/src/sync_cmd.rs`, `src-tauri/src/lib.rs` | Q-41, Q-42 |
| G2-22 | PROFILE_CHECKOUT | L915, L1140 | DONE | `server/tests/v2_profiles.rs`: `one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes`, `a_stored_response_naming_another_profile_or_lease_is_never_replayed`; `src-tauri/src/team/sync.rs`: `a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept`, `a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key`; code: `shared/src/profile_lease.rs`, `server/src/routes/v2_profiles.rs` | Q-34, Q-42 |
| G2-23 | CREATE_UPLOAD | L915, L1147-L1158 | DONE | `server/tests/v2_profiles.rs`: `an_upload_commits_once_and_the_next_checkout_starts_at_its_head`, `every_upload_refusal_has_its_status_and_code`; `src-tauri/src/team/sync.rs`: `a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte`; code: `shared/src/profile_lease.rs`, `server/src/routes/v2_uploads.rs` | Q-34 |
| G2-24 | FINALIZE_UPLOAD | L915, L1159-L1219 | DONE | `server/tests/v2_profiles.rs`: `an_upload_commits_once_and_the_next_checkout_starts_at_its_head`, `a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot`; `src-tauri/src/team/sync.rs`: `every_crash_point_resumes_with_the_exact_stored_bytes`; code: `shared/src/profile_lease.rs`, `server/src/routes/v2_uploads.rs` | Q-34 |
| G2-25 | RELEASE_LEASE | L915, L1142 | DONE | `server/tests/v2_profiles.rs`: `one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes`, `a_stored_response_naming_another_profile_or_lease_is_never_replayed`; `src-tauri/src/team/sync.rs`: `a_release_whose_reply_was_lost_is_replayed_byte_for_byte`; code: `shared/src/profile_lease.rs`, `server/src/routes/v2_profiles.rs` | Q-34, Q-42 |
| G2-26 | LOCAL_UNBIND | L915, L2038, ADR D-7 | DONE | `shared/src/profile_lease.rs`: `the_unbind_maps_round_trip_and_pin_the_tombstone`, `the_unbind_maps_refuse_what_l953_does_not_allow`; `src-tauri/src/team/sync.rs`: `an_unbind_tombstone_outlives_its_binding_and_replays_exactly`, `an_unbind_at_version_zero_omits_the_head`, `an_unbind_cut_off_at_any_write_leaves_the_binding_whole`, `an_unbind_is_refused_while_a_lease_request_or_journal_is_open`; code: `src-tauri/src/sync_cmd.rs`, `src-tauri/src/lib.rs` | D-7, Q-37, Q-40 |
| G2-27 | STREAM / preamble / final frame | L1352-L1371 | DONE | `shared/src/envelope_v2.rs`: `xchacha20poly1305_matches_the_draft_vector` (vector), `golden_objects` (vector), `every_preamble_rule_is_enforced`, `every_frame_rule_is_enforced`, `the_stream_counter_stops_at_the_provider_maximum`; files: `docs/adr/0003-envelope-v2-stream.md` | D-3, ADR 0003 |
| G2-28 | HPKE TRK/FKEK grants | L1358 | DONE | `shared/src/grants.rs`: `the_pinned_suite_matches_the_rfc_9180_vectors` (vector), `info_bytes_match_g2_vector` (vector), `only_the_granted_device_can_open`, `grant_cannot_be_replayed_into_another_tenant_or_epoch`, `the_fleet_grant_aad_is_the_label_the_length_and_the_info`, `a_device_fleet_grant_opens_only_to_the_key_it_names`; `shared/src/fleet_grants.rs`: `a_sealed_fleet_key_opens_to_the_exact_same_bytes` | D-8, D-5 |
| G2-29 | Signing suite | L2335 | DONE | `shared/src/authz_record.rs`: `signature_binds_issuer_and_bytes`, `small_order_issuer_key_never_verifies`; `shared/src/signing.rs`: `rfc8032_vectors_sign_and_verify_strictly` (vector), `speccheck_matrix_accepts_only_the_unambiguous_case` (vector), `g2_golden_vector_signed_container_hash` (vector) | D-8 |
| G2-30 | Grant ALL-column + HPKE equality (seven under Q-13) | L2338, L2040, L2058 | DONE | `server/tests/v2_auth.rs`: `every_device_revocation_column_is_compared_with_its_container_on_each_request`, `the_startup_pass_quarantines_device_revocations_that_left_their_containers`, `a_revocation_of_another_instance_turns_v2_off_until_it_is_put_back`, `a_revocation_quarantined_at_runtime_refuses_the_trust_evidence`, `a_quarantined_revocation_that_verifies_again_is_served_again_after_a_restart`, `a_marked_row_swapped_for_another_genuine_revocation_is_not_served_again`, `a_corrupt_container_is_marked_without_a_hash_and_served_again_once_restored`, `the_trust_evidence_reports_a_revoked_device_from_its_record_not_its_column`, `a_revocation_row_swapped_for_another_genuine_one_does_not_answer_a_retry`, `a_revocation_row_the_startup_pass_cannot_read_turns_v2_off`; `src-tauri/src/team/sync.rs`: `a_kept_revocation_reloads_with_every_column_equal`; code: `shared/src/authz_record.rs`, `server/src/routes/v2_device_revoke.rs`, `server/src/integrity.rs`, `src-tauri/src/lib.rs` | Q-13, Q-38 |
| G2-31 | Durable response-loss replay, every operation | L2338, L1424, L2048 | DONE | `server/tests/v2_auth.rs`: `the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt`, `the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response`, `every_custody_operation_replays_its_lost_response_after_a_restart`; `server/tests/v2_e2e.rs`: `v2_operations_replay_the_stored_response`; `server/tests/v2_profiles.rs`: `one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes`, `a_stored_response_naming_another_profile_or_lease_is_never_replayed`, `a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot`, `every_profile_operation_replays_its_lost_response_after_a_restart`; `server/tests/restore_epoch_harness.rs`: `d1_replays_of_rolled_back_results_answer_as_superseded_and_kept_ones_replay`; `src-tauri/src/team/sync.rs`: `every_publish_crash_point_resumes_with_the_exact_stored_bytes`, `a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key`, `a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte`, `every_crash_point_resumes_with_the_exact_stored_bytes`, `a_release_whose_reply_was_lost_is_replayed_byte_for_byte`, `an_unbind_tombstone_outlives_its_binding_and_replays_exactly` **Note:** verifier finding B7 is fixed (PR #221): the two `every_..._operation_replays_...` tests match on every `OperationKind`, so a new kind without a case does not compile; each case performs the real mutation, restarts the server on the same database, replays, and asserts the same bytes and no second resource. `LocalUnbind` never reaches the server and is covered by `an_unbind_tombstone_outlives_its_binding_and_replays_exactly`. | Q-34, Q-42 |
| G2-32 | Local plan DDL + 11 probes | L1450-L2034, L2036 | DONE | `src-tauri/src/team/db.rs`: `a_new_database_reopens_with_its_schema_and_settings`, `a_version_5_file_with_data_moves_to_version_6_keeping_every_row`, `the_triggers_and_indexes_of_a_version_5_file_survive_version_6`; files: `.omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md` | Q-1, Q-37, Q-42 |
| G2-33 | Probe 1 UNBIND tombstone | L2038 | DONE | `src-tauri/src/team/sync.rs`: `an_unbind_tombstone_outlives_its_binding_and_replays_exactly`, `an_unbind_cut_off_at_any_write_leaves_the_binding_whole`, `a_tombstone_that_no_longer_recomputes_is_never_returned`, `an_unbind_after_an_accepted_transition_keeps_its_evidence`; `src-tauri/src/team/db.rs`: `a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding` | D-7, Q-37 |
| G2-34 | Probe 2 RELEASE replay after lease gone | L2039 | DONE | `src-tauri/src/team/sync.rs`: `a_release_whose_reply_was_lost_is_replayed_byte_for_byte`, `an_unsent_cancel_release_is_retried_and_then_given_up`, `an_unreadable_release_reply_is_reported_and_replayed` | Q-34 |
| G2-35 | Probe 3 grant equality + second self-grant + cross-instance FK | L2040, L2034, L2058 | DONE | `src-tauri/src/team/records.rs`: `six_records_reopen_exactly_and_refuse_every_changed_column`, `a_second_self_grant_and_a_cross_instance_generation_are_refused`, `only_a_self_grant_files_a_generation_and_a_duplicate_row_refuses`; `src-tauri/src/team/ledger.rs`: `a_filed_grant_files_the_key_state_it_names`; `src-tauri/src/team/sync.rs`: `a_binding_and_its_rows_name_the_servers_account_and_key`, `a_kept_revocation_reloads_with_every_column_equal`; code: `src-tauri/src/lib.rs` | Q-13, Q-26, Q-42 |
| G2-36 | Probe 4 upload resume + UNIQUE/FK | L2041 | DONE | `src-tauri/src/team/db.rs`: `an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key`; `src-tauri/src/team/sync.rs`: `an_interrupted_upload_resumes_at_the_offset_head_reports` | none |
| G2-37 | Probe 5 manifest/request replay, 3 crash points | L2042 | DONE | `src-tauri/src/team/sync.rs`: `every_crash_point_resumes_with_the_exact_stored_bytes`, `a_stored_column_that_drifts_from_its_bytes_is_never_sent`, `a_stored_publish_that_drifts_from_its_bytes_is_never_sent` | none |
| G2-38 | Probe 6 receipt equality/readback | L2043 | DONE | `src-tauri/src/team/sync.rs`: `a_receipt_or_readback_that_does_not_match_is_never_kept`, `a_published_profile_pushes_and_another_device_pulls_it`; `src-tauri/src/team/db.rs`: `an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key`; `server/tests/v2_profiles.rs`: `an_upload_commits_once_and_the_next_checkout_starts_at_its_head`, `every_upload_refusal_has_its_status_and_code` | none |
| G2-39 | Probe 7 local epoch transition/proof | L2044 | DONE | `src-tauri/src/team/sync.rs`: `a_verified_transition_moves_only_the_bindings_it_covers`, `a_transition_that_does_not_verify_keeps_the_binding_quarantined`, `a_restore_epoch_that_goes_back_is_a_rollback`, `a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen`, `a_leaf_head_is_accepted_only_as_a_new_head_is`, `a_pinned_head_is_read_back_only_as_the_bindings_own`, `a_lapsed_or_former_custodian_signs_no_transition`, `an_unbind_after_an_accepted_transition_keeps_its_evidence`, `a_binding_changed_during_acceptance_is_not_moved`, `a_lease_from_before_the_restore_is_released_before_the_binding_moves`, `a_custodian_not_yet_appointed_signs_no_transition`, `a_failed_release_of_an_old_lease_is_retried_as_stored` | Q-1, Q-36, Q-37 |
| G2-40 | Probe 8 unknown/newer schema | L2045 | DONE | `src-tauri/src/team/db.rs`: `an_unknown_schema_fails_closed_and_is_left_as_it_was`, `a_database_held_in_wal_mode_is_refused` | none |
| G2-41 | Probe 9 recovery/downgrade journals | L2046 | DONE | `src-tauri/src/team/journal.rs`: `every_restore_phase_survives_close_and_reopen_in_order`, `a_restore_phase_cannot_skip_repeat_or_leave_a_terminal_one`, `a_restore_journal_retires_only_when_settled`, `the_restore_resume_table_is_fixed_per_crash_point`, `a_clone_journal_walks_its_chain_with_every_phase_surviving_reopen`, `a_downgrade_phase_cannot_skip_and_a_rollback_is_always_open`, `the_resume_table_for_a_downgrade_journal_continues_every_open_phase`, `the_digests_survive_reopen_byte_for_byte`; `src-tauri/src/team/downgrade.rs`: `a_cut_off_at_every_step_resumes_to_the_same_finished_clone`, `a_process_killed_at_every_step_resumes_to_the_same_finished_clone`, `a_rollback_from_every_step_puts_the_original_back_and_frees_the_profile`, `a_readback_that_v0_1_28_would_not_agree_with_fails_the_flow`, `discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive`; `src-tauri/src/team/sync.rs`: `an_unbind_is_refused_while_a_lease_request_or_journal_is_open`; code: `src-tauri/src/lib.rs`; files: `scripts/g2-wp5-mutants.py` **Note:** The restore journal has no production writer (only the downgrade flow and tests write it); the full pre-v2 restore is journal and refusal states only. That is v0.2.x scope, not a probe 9 criterion. | Q-35, Q-40 |
| G2-42 | Probe 10 local integer range | L2047 | DONE | `src-tauri/src/team/db.rs`: `every_sync_integer_class_keeps_its_range_across_a_reopen`; `src-tauri/src/team/records.rs`: `every_integer_class_keeps_its_range_across_a_reopen` **Note:** verifier finding B6 is resolved by a contract decision, ADR Q-43 (PR #220): probe 10 refuses the coercions that would change a value; a lossless TEXT or REAL is stored as the exact INTEGER, which is what both tests assert. | D-6, Q-43 |
| G2-43 | Probe 11 local mutation replay | L2048 | DONE | `src-tauri/src/team/sync.rs`: `every_publish_crash_point_resumes_with_the_exact_stored_bytes`, `a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key`, `a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte`, `every_crash_point_resumes_with_the_exact_stored_bytes`, `an_unbind_tombstone_outlives_its_binding_and_replays_exactly`, `a_release_whose_reply_was_lost_is_replayed_byte_for_byte`, `a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh` | D-7, Q-42 |
| G2-44 | Server migrations fresh + upgrade | L2080-L2222 | DONE | `server/tests/v2_upgrade_chain.rs`: `the_plan_assertions_hold_on_a_reopened_fresh_file`, `the_plan_assertions_hold_on_a_reopened_v0_1_28_file_and_its_backup_restores`, `fixtures_1_to_4_hold_on_a_fresh_file`, `fixtures_1_to_4_hold_on_a_v0_1_28_file_after_its_upgrade`, `fixtures_1_to_4_hold_on_a_populated_0016_file_after_its_upgrade`, `m0017_root_generations_only_move_forward_on_upgraded_rows`, `m0033_the_quarantine_gains_a_container_hash_and_stays_append_only`; files: `server/tests/fixtures/plan_assert.sql`, `server/tests/fixtures/v0.1.28/0001_init.sql`, `server/tests/fixtures/v0.1.28/0002_lock_token_and_token_version.sql`, `server/tests/fixtures/v0.1.28/0003_clear_empty_lock_tokens.sql`, `scripts/g2-44-migration-mutants.py` | Q-34, Q-38 |
| G2-45 | Unsigned i64 domain (server) | L2343, L2338 | DONE | `server/tests/v2_upgrade_chain.rs`: `m0030_upgraded_integer_columns_refuse_values_that_are_no_integers`; `server/tests/v2_integer_domain.rs`: `every_class_decodes_its_domain_ends_and_refuses_everything_else`, `every_class_column_stores_its_domain_ends_and_its_check_refuses_the_rest`, `every_integer_column_of_every_v2_table_has_an_upper_bound_check`, `every_integer_column_of_every_v2_table_refuses_a_value_that_is_no_integer`, `the_bound_scan_tells_bounded_from_unbounded_columns`; files: `server/migrations/0030_v2_integer_columns_hold_integers.sql` **Note:** The gap table cited lines 861-1238 of v2_integer_domain.rs, which has 622 lines; the tests are cited here by name. | D-6 |
| G2-46 | Argon2id | L1377 | DONE | `shared/src/recovery_bundle.rs`: `argon2id_matches_the_rfc_9106_vector` (vector), `the_kek_is_argon2id_over_the_labelled_salt` **Note:** Local SHXBAK01 backups keep p=1 (recorded deviation, ADR Q-7); the recovery bundle uses p=4. | D-5, Q-7, Q-21 |
| G2-47 | Secrecy/zeroization | L2335 | DONE | `src-tauri/src/team_config.rs`: `debug_never_prints_the_token_or_a_seed`; `src-tauri/src/fleet_keys.rs`: `debug_never_prints_a_key`; `src-tauri/src/fleet_client.rs`: `a_session_debug_print_hides_its_tokens`; `src-tauri/src/root_bootstrap.rs`: `the_trk_is_stored_and_the_saved_state_holds_only_its_reference`, `a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing`, `a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it`, `the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written`, `the_saved_state_never_prints_the_legacy_trk`, `a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key`, `a_reference_to_another_credential_is_refused_and_that_credential_is_kept`, `the_activation_is_saved_before_the_key_is_forgotten`, `the_run_nonce_is_saved_before_the_key_is_stored`, `a_new_run_never_reuses_a_key_an_abandoned_run_left`, `a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed`, `a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made`, `a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it`; `src-tauri/src/key_file.rs`: `a_forget_succeeds_only_once_the_key_is_confirmed_gone`; files: `docs/key-custody.md` **Note:** Type-level evidence: Zeroizing fields, ZeroizeOnDrop and Debug redaction; no test observes freed memory. Since #212 the TRK is in the credential store, not the state file. | D-5 |
| G2-48 | Windows credential store | L1374-L1376, L2335, ADR Q-29 | PENDING-MANUAL | `src-tauri/src/credential.rs`: `a_key_round_trips_and_is_forgotten`, `references_are_separate_credentials`, `a_failed_write_or_read_back_is_reported`, `a_real_os_store_key_survives_into_a_fresh_process`, `an_unavailable_store_fails_closed_in_a_fresh_process`, `a_key_file_key_is_locked_then_served_in_a_fresh_process`; files: `scripts/g2-48-credential-check.ps1`, `docs/g2-48-manual-check.md`, `docs/adr/0004-credential-store.md` **Note:** PENDING-MANUAL. The automated half (rows below) runs in `cargo test --lib`; the restart, locked-session and no-store half needs the owner to run the script. See "G2-48 is pending" below. | Q-29, D-5 |
| G2-49 | Windows file durability (local NTFS, Q-30) | L2337, L1175, L2250 | DONE | `src-tauri/src/durable.rs`: `a_durable_write_replaces_the_file_and_leaves_no_temporary`, `a_failed_replace_keeps_the_old_file_and_removes_the_temporary`, `a_write_killed_at_any_step_leaves_the_old_or_the_new_file`, `a_kill_during_back_to_back_writes_never_tears_or_loses_a_returned_write`, `creating_a_file_that_exists_never_overwrites_it`; `shared/src/volume.rs`: `only_a_local_ntfs_disk_is_accepted`, `a_local_ntfs_directory_is_accepted_and_a_missing_one_is_not`, `an_smb_share_is_refused`; `server/src/db.rs`: `storage_that_cannot_be_resolved_is_refused`, `storage_on_an_smb_share_is_refused`; `server/src/identity.rs`: `preflight_refuses_an_identity_directory_on_an_smb_share`; `server/tests/restore_epoch_harness.rs`: `an_identity_directory_the_preflight_refuses_never_falls_to_k1`, `an_empty_identity_directory_setting_refuses_to_start`; code: `src-tauri/src/store.rs`, `src-tauri/src/lib.rs`, `src-tauri/src/migrate.rs` **Note:** The SMB refusal tests skip unless `SHARDX_TEST_SMB_DIR` names a reachable share. Only the CI job `Rust tests on Windows` sets it. FAT32 or exFAT at the identity directory is refused by the same `require_local_ntfs` classification (volume tests); there is no identity-directory-specific FAT32 test. | Q-30, Q-39 |
| G2-50 | SQLite WAL/busy/crash ordering | L2337, L2063 | DONE | `server/src/db.rs`: `the_database_runs_a_synced_rollback_journal_and_survives_an_unclosed_pool`, `a_killed_transaction_reopens_old_or_new_never_half`, `a_kill_between_commits_keeps_every_returned_commit`, `a_second_writer_waits_for_the_write_lock`, `storage_on_an_smb_share_is_refused`; `src-tauri/src/crash_harness.rs`: `a_killed_transaction_reopens_old_or_new_never_half`; `src-tauri/src/team/db.rs`: `a_database_held_in_wal_mode_is_refused`; `shared/src/volume.rs`: `an_smb_share_is_refused`; code: `src-tauri/src/store.rs` **Note:** The SMB refusal part needs `SHARDX_TEST_SMB_DIR` (CI only, Q-31); the kill and ordering tests run locally. | Q-16, Q-30, Q-31 |
| G2-51 | Windows path corpus | L2338 | DONE | `shared/src/snapshot.rs`: `the_windows_path_corpus_is_refused_in_every_position`, `every_name_windows_rewrites_is_refused`, `ntfs_case_fold_collisions_are_refused_and_distinct_names_kept`, `long_paths_unpack_and_an_overlong_one_is_refused`, `a_junction_is_neither_packed_through_nor_followed_on_replace`; `src-tauri/src/team/downgrade.rs`: `discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive`, `a_trace_of_the_old_id_after_the_move_fails_the_discovery_scan` | Q-30 |
| G2-52 | Restore-epoch FS harness | L2339, L2250-L2269 | DONE | `server/tests/restore_epoch_harness.rs`: `g2_52_every_crash_point_maps_to_one_row_and_resumes_to_the_restored_state` **Note:** One test walks the whole crash table; G2-53 to G2-60 pin each row. | D-1, Q-30, Q-33, Q-35 |
| G2-53 | Missing/corrupt record | L2260 | DONE | `server/tests/identity_authority.rs`: `a_symlinked_record_is_refused`, `show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest`; `server/tests/restore_epoch_harness.rs`: `an_identity_directory_that_is_not_there_is_missing_and_stops_the_server`; code: `server/src/identity.rs` | D-1, Q-39 |
| G2-54 | External = mirror, no preparation | L2261 | DONE | `server/tests/restore_epoch_harness.rs`: `l2259_g2_54_a_record_equal_to_its_mirror_without_a_manifest_opens_normally` **Note:** Test names carry plan line numbers 2 below the current plan file. | D-1 |
| G2-55 | Preparation durable, authority E | L2262 | DONE | `server/tests/restore_epoch_harness.rs`: `l2260_g2_55_a_durable_preparation_at_e_keeps_writes_off_until_commit_or_abort`, `g2_55_a_failed_read_only_audit_write_is_counted_in_restore_status`, `g2_55_the_k2_incident_output_prints_the_audit_failure_count`, `g2_55_a_directory_at_the_count_path_stops_a_read_only_start_by_name`, `g2_55_restore_commit_prints_the_final_audit_failure_count_and_clears_it`, `g2_55_a_read_only_start_logs_the_failed_audit_writes_counted_so_far`, `g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count`, `g2_55_a_count_under_a_changed_episode_key_is_kept_and_cleared_by_name`, `g2_55_a_count_file_with_a_bad_line_is_set_aside_and_its_valid_lines_kept`; `server/src/audit.rs`: `a_failed_read_only_audit_write_is_logged_and_counted`, `the_count_continues_across_read_only_restarts_of_one_episode`, `a_changed_episode_key_keeps_the_old_count_until_it_is_cleared_by_name`, `one_bad_line_in_the_count_file_loses_only_itself`, `a_crash_while_setting_a_file_aside_never_loses_the_valid_lines`, `the_count_is_written_atomically_and_an_unreadable_one_is_reported`, `a_directory_or_link_at_the_count_path_is_refused_by_name`; code: `server/src/restore.rs` | D-1, Q-38 |
| G2-56 | External E+1, live mirror E | L2263 | DONE | `server/tests/restore_epoch_harness.rs`: `l2261_g2_56_an_authority_ahead_of_the_live_mirror_resumes_only_the_install` | D-1, Q-33 |
| G2-57 | E+1, restored mirror behind | L2264 | DONE | `server/tests/restore_epoch_harness.rs`: `l2262_g2_57_an_installed_db_behind_the_record_is_verified_then_rebuilt` | D-1, Q-33 |
| G2-58 | Ahead without evidence | L2265 | DONE | `server/tests/restore_epoch_harness.rs`: `l2263_g2_58_an_authority_ahead_without_exact_evidence_fails_closed`, `l2263_g2_58_only_a_live_custodian_transition_over_the_computed_leaves_prepares` | D-1, Q-33, Q-36 |
| G2-59 | Behind/different instance | L2266 | DONE | `server/tests/restore_epoch_harness.rs`: `g2_55_the_k2_incident_output_prints_the_audit_failure_count`; code: `server/src/identity.rs` **Note:** The K2 incident output is asserted in the same test as G2-55; the other-instance and record-behind cases are asserted in `restore_epoch_harness.rs`. | D-1, Q-39 |
| G2-60 | Reconciled E+1, retire bundle | L2267 | DONE | `server/tests/restore_epoch_harness.rs`: `l2265_g2_60_a_reconciled_epoch_retires_its_bundle_and_the_next_start_is_normal` | D-1, Q-28 |
| G2-61 | Trust-boundary tests/docs | L2340 | DONE | `shared/src/backup_file.rs`: `a_snapshot_sealed_for_another_profile_is_refused`, `another_fleet_key_cannot_open_it`; `shared/tests/backup_file_roundtrip.rs`: `the_ciphertext_does_not_contain_the_plaintext`, `a_tampered_backup_body_is_refused`, `a_truncated_backup_is_refused_and_leaves_the_destination_untouched`; `shared/src/backup.rs`: `every_single_byte_mutation_is_detected`, `truncation_at_any_length_is_detected`, `cross_envelope_frame_splice_is_rejected`; `src-tauri/src/sync_cmd.rs`: `pull_refuses_another_profiles_snapshot`, `push_seals_under_the_passphrase_even_with_a_cached_fleet_key`; `shared/src/grants.rs`: `grant_cannot_be_replayed_into_another_tenant_or_epoch`; `shared/src/fleet_grants.rs`: `tampering_with_the_stored_info_fails_the_open`; `server/tests/identity_authority.rs`: `an_interrupted_init_is_reported_and_never_repaired`; `server/src/integrity.rs`: `wrong_domain_hpke_ids_are_quarantined_once`; `src-tauri/src/lib.rs`: `a_server_delivered_fleet_key_is_counted_but_never_cached`, `a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet`; `src-tauri/src/team/sync.rs`: `a_compromised_revocation_blocks_commits_under_an_exposed_generation`, `a_compromised_custodian_blocks_every_fleet_through_the_root`, `an_exposure_survives_a_recollection_that_omits_its_grant`, `an_open_upload_is_aborted_once_a_compromise_is_counted`, `a_compromise_counted_mid_transfer_aborts_the_upload`, `a_known_custodian_with_no_root_holding_blocks`, `a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks`, `a_stored_finalize_is_not_sent_once_a_compromise_is_counted`, `a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code`; `src-tauri/src/team/ledger.rs`: `a_version_6_file_with_unreadable_kept_pages_still_opens`; files: `docs/trust-boundaries.md` **Note:** verifier findings B1 to B4 are fixed (PRs #216, #217, #218, #223); N1 and N2 of the rerun are fixed too (section 8): the Q-18 commit block derives exposure through the root from every verified grant and never forgets one, push refuses before checkout and an OPEN upload is aborted, and a fleet-scoped `device.revoke` is counted. | Q-13, Q-14, Q-18 |
| G2-62 | Dependencies (license, advisories, MSRV, feature graph) | L2336, L2343 | DONE | files: `docs/dependency-review.md`, `shared/Cargo.toml`, `server/Cargo.toml`, `src-tauri/Cargo.toml`, `shared/Cargo.lock`, `server/Cargo.lock`, `src-tauri/Cargo.lock` **Note:** Evidence is CI plus the manifests: rust-version 1.87 (shared), 1.89 (server), 1.88 (launcher), `cargo audit`, and the feature graph in docs/dependency-review.md. There is no unit test. | D-3, ADR 0003 |
| G2-63 | Security review artifact | L2341 | DONE | `shared/tests/registry_pins.rs`: `every_signing_domain_is_distinct_and_versioned`, `every_hash_label_is_distinct_and_nul_terminated`, `the_numeric_registry_holds_the_reviewed_values`; `shared/src/keys.rs`: `g2_golden_vector_profile_label` (vector), `a_profile_label_opens_only_where_it_was_sealed`, `a_profile_label_has_a_length_bound_both_ways`, `a_profile_label_is_padded_to_a_bucket`, `a_profile_label_that_is_not_canonical_is_refused`; files: `docs/security-review-g2.md`, `docs/key-custody.md`, `docs/dependency-review.md` **Note:** Closed by this packet. `registry_pins.rs` also holds the sixteen request and response domains of the lease, upload, publish, unbind and fleet-profile-page maps. | D-8, Q-41 |
| G2-64 | Independent verifier PASS | L2343, L2512, L2565 | FAIL | `docs/g2-evidence/verifier-codex-2026-11-01.md`, `docs/g2-evidence/verifier-codex-2026-11-02.md`, `docs/g2-evidence/verifier-hermes-2026-11-02.md` **Note:** FAIL. Codex returned FAIL with findings B1 to B7 on the head of PR #213 (2b35d84f); Hermes produced no report. B1 to B7 are fixed. The rerun on 9e29a2c6 returned FAIL from both verifiers; its findings are fixed; see section 8. | Q-15, Q-32 |

## 6. Commands per row

Every command runs the cited tests of one cargo target. The filters are test
names (a substring match, so a command may run a few extra tests); names that
exist in more than one module carry their module path. Add `-j 1` where the
machine needs it. Rows G2-48, G2-62, G2-63 and G2-64 also use the commands of
sections 2, 3 and 7.

#### G2-01

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt every_approval_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_approvals_that_left_their_containers
cargo test --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors
```

#### G2-02

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup
cargo test --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors
```

#### G2-03

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_fleet_grants_that_left_their_containers
cargo test --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors
```

#### G2-04

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- recovery_grant_binds_context_suite_and_lengths recovery_grant_opens_only_under_its_root_and_to_its_fkek authz_record::tests::golden_vectors
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request
```

#### G2-05

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- rotation_grant_follows_its_generation_window_and_count_rules authz_record::tests::golden_vectors
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request
```

#### G2-06

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup
cargo test --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors
```

#### G2-07

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- snapshot_v2::tests::golden_vectors payload_rejects_every_field_level_defect container_rejects_every_field_level_defect signing_binds_the_signer_key manifest_binds_a_sealed_envelope_v2_object
```

#### G2-08

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_profiles -- every_upload_refusal_has_its_status_and_code
```

#### G2-09

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head
```

#### G2-10

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- the_closed_maps_parse_what_the_builders_write every_dek_slot_context_rule_is_enforced every_dek_slot_rule_is_enforced a_slot_that_differs_from_the_intent_is_refused the_reader_refuses_an_open_map g2_golden_vector_dek_slot g2_golden_vector_dek_slot_context_hash
```

#### G2-11

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- the_intent_bounds_are_the_plans every_envelope_intent_rule_is_enforced the_intent_and_slot_must_be_the_ones_the_manifest_names manifest_binds_a_sealed_envelope_v2_object g2_golden_vector_intent g2_golden_vector_intent_genesis
```

#### G2-12

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- restore_epoch::tests::golden_vectors leaf_roundtrips_and_refuses_contract_violations leaf_sets_must_be_non_empty_sorted_and_unique every_leaf_proves_and_every_tampering_fails a_proof_binds_tenant_profile_instance_epochs_count_and_root proof_parser_refuses_every_contract_violation g2_golden_vectors_merkle_roots
```

#### G2-13

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- transition_roundtrips_and_verifies transition_payload_refuses_every_contract_violation signed_transition_refuses_every_container_defect transition_signature_binds_key_bytes_and_label
```

#### G2-14

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- mutation::tests::golden_vectors every_map_roundtrips_byte_for_byte every_map_refuses_another_domain_or_version every_kind_has_one_scope_and_the_scope_must_match hashes_and_closed_fields_are_checked device_revoke_maps_carry_one_container_and_roundtrip fleet_lifecycle::tests::golden_vectors
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- a_revocation_commits_its_fleet_activation_or_nothing a_revocation_commits_its_root_activation
```

#### G2-15

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- mutation::tests::golden_vectors every_map_roundtrips_byte_for_byte every_map_refuses_another_domain_or_version
```

#### G2-16

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response
```

#### G2-17

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup
```

#### G2-18

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant
```

#### G2-19

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant
```

#### G2-20

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- a_revocation_names_a_known_reason_and_its_outcome
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- a_custodian_revokes_a_root_grant_but_never_the_last_one
```

#### G2-21

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_profile_is_published_with_its_first_lease_and_then_pushed every_publish_crash_point_resumes_with_the_exact_stored_bytes
```

#### G2-22

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key
```

#### G2-23

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head every_upload_refusal_has_its_status_and_code
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte
```

#### G2-24

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- every_crash_point_resumes_with_the_exact_stored_bytes
```

#### G2-25

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_release_whose_reply_was_lost_is_replayed_byte_for_byte
```

#### G2-26

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- the_unbind_maps_round_trip_and_pin_the_tombstone the_unbind_maps_refuse_what_l953_does_not_allow
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unbind_tombstone_outlives_its_binding_and_replays_exactly an_unbind_at_version_zero_omits_the_head an_unbind_cut_off_at_any_write_leaves_the_binding_whole an_unbind_is_refused_while_a_lease_request_or_journal_is_open
```

#### G2-27

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- xchacha20poly1305_matches_the_draft_vector golden_objects every_preamble_rule_is_enforced every_frame_rule_is_enforced the_stream_counter_stops_at_the_provider_maximum
```

#### G2-28

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- the_pinned_suite_matches_the_rfc_9180_vectors info_bytes_match_g2_vector only_the_granted_device_can_open grant_cannot_be_replayed_into_another_tenant_or_epoch the_fleet_grant_aad_is_the_label_the_length_and_the_info a_device_fleet_grant_opens_only_to_the_key_it_names a_sealed_fleet_key_opens_to_the_exact_same_bytes
```

#### G2-29

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- signature_binds_issuer_and_bytes small_order_issuer_key_never_verifies rfc8032_vectors_sign_and_verify_strictly speccheck_matrix_accepts_only_the_unambiguous_case g2_golden_vector_signed_container_hash
```

#### G2-30

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- every_device_revocation_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_device_revocations_that_left_their_containers a_revocation_of_another_instance_turns_v2_off_until_it_is_put_back a_revocation_quarantined_at_runtime_refuses_the_trust_evidence a_quarantined_revocation_that_verifies_again_is_served_again_after_a_restart a_marked_row_swapped_for_another_genuine_revocation_is_not_served_again a_corrupt_container_is_marked_without_a_hash_and_served_again_once_restored the_trust_evidence_reports_a_revoked_device_from_its_record_not_its_column a_revocation_row_swapped_for_another_genuine_one_does_not_answer_a_retry a_revocation_row_the_startup_pass_cannot_read_turns_v2_off
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_kept_revocation_reloads_with_every_column_equal
```

#### G2-31

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response every_custody_operation_replays_its_lost_response_after_a_restart
cargo test --locked --manifest-path server/Cargo.toml --test v2_e2e -- v2_operations_replay_the_stored_response
cargo test --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot every_profile_operation_replays_its_lost_response_after_a_restart
cargo test --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- d1_replays_of_rolled_back_results_answer_as_superseded_and_kept_ones_replay
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- every_publish_crash_point_resumes_with_the_exact_stored_bytes a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte every_crash_point_resumes_with_the_exact_stored_bytes a_release_whose_reply_was_lost_is_replayed_byte_for_byte an_unbind_tombstone_outlives_its_binding_and_replays_exactly
```

#### G2-32

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_new_database_reopens_with_its_schema_and_settings a_version_5_file_with_data_moves_to_version_6_keeping_every_row the_triggers_and_indexes_of_a_version_5_file_survive_version_6
```

#### G2-33

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unbind_tombstone_outlives_its_binding_and_replays_exactly an_unbind_cut_off_at_any_write_leaves_the_binding_whole a_tombstone_that_no_longer_recomputes_is_never_returned an_unbind_after_an_accepted_transition_keeps_its_evidence a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding
```

#### G2-34

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_release_whose_reply_was_lost_is_replayed_byte_for_byte an_unsent_cancel_release_is_retried_and_then_given_up an_unreadable_release_reply_is_reported_and_replayed
```

#### G2-35

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- six_records_reopen_exactly_and_refuse_every_changed_column a_second_self_grant_and_a_cross_instance_generation_are_refused only_a_self_grant_files_a_generation_and_a_duplicate_row_refuses a_filed_grant_files_the_key_state_it_names a_binding_and_its_rows_name_the_servers_account_and_key a_kept_revocation_reloads_with_every_column_equal
```

#### G2-36

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key an_interrupted_upload_resumes_at_the_offset_head_reports
```

#### G2-37

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- every_crash_point_resumes_with_the_exact_stored_bytes a_stored_column_that_drifts_from_its_bytes_is_never_sent a_stored_publish_that_drifts_from_its_bytes_is_never_sent
```

#### G2-38

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_receipt_or_readback_that_does_not_match_is_never_kept a_published_profile_pushes_and_another_device_pulls_it an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key
cargo test --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head every_upload_refusal_has_its_status_and_code
```

#### G2-39

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_verified_transition_moves_only_the_bindings_it_covers a_transition_that_does_not_verify_keeps_the_binding_quarantined a_restore_epoch_that_goes_back_is_a_rollback a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen a_leaf_head_is_accepted_only_as_a_new_head_is a_pinned_head_is_read_back_only_as_the_bindings_own a_lapsed_or_former_custodian_signs_no_transition an_unbind_after_an_accepted_transition_keeps_its_evidence a_binding_changed_during_acceptance_is_not_moved a_lease_from_before_the_restore_is_released_before_the_binding_moves a_custodian_not_yet_appointed_signs_no_transition a_failed_release_of_an_old_lease_is_retried_as_stored
```

#### G2-40

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unknown_schema_fails_closed_and_is_left_as_it_was a_database_held_in_wal_mode_is_refused
```

#### G2-41

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- every_restore_phase_survives_close_and_reopen_in_order a_restore_phase_cannot_skip_repeat_or_leave_a_terminal_one a_restore_journal_retires_only_when_settled the_restore_resume_table_is_fixed_per_crash_point a_clone_journal_walks_its_chain_with_every_phase_surviving_reopen a_downgrade_phase_cannot_skip_and_a_rollback_is_always_open the_resume_table_for_a_downgrade_journal_continues_every_open_phase the_digests_survive_reopen_byte_for_byte a_cut_off_at_every_step_resumes_to_the_same_finished_clone a_process_killed_at_every_step_resumes_to_the_same_finished_clone a_rollback_from_every_step_puts_the_original_back_and_frees_the_profile a_readback_that_v0_1_28_would_not_agree_with_fails_the_flow discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive an_unbind_is_refused_while_a_lease_request_or_journal_is_open
```

#### G2-42

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- every_sync_integer_class_keeps_its_range_across_a_reopen every_integer_class_keeps_its_range_across_a_reopen
```

#### G2-43

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- every_publish_crash_point_resumes_with_the_exact_stored_bytes a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte every_crash_point_resumes_with_the_exact_stored_bytes an_unbind_tombstone_outlives_its_binding_and_replays_exactly a_release_whose_reply_was_lost_is_replayed_byte_for_byte a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh
```

#### G2-44

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_upgrade_chain -- the_plan_assertions_hold_on_a_reopened_fresh_file the_plan_assertions_hold_on_a_reopened_v0_1_28_file_and_its_backup_restores fixtures_1_to_4_hold_on_a_fresh_file fixtures_1_to_4_hold_on_a_v0_1_28_file_after_its_upgrade fixtures_1_to_4_hold_on_a_populated_0016_file_after_its_upgrade m0017_root_generations_only_move_forward_on_upgraded_rows m0033_the_quarantine_gains_a_container_hash_and_stays_append_only
```

#### G2-45

```
cargo test --locked --manifest-path server/Cargo.toml --test v2_upgrade_chain -- m0030_upgraded_integer_columns_refuse_values_that_are_no_integers
cargo test --locked --manifest-path server/Cargo.toml --test v2_integer_domain -- every_class_decodes_its_domain_ends_and_refuses_everything_else every_class_column_stores_its_domain_ends_and_its_check_refuses_the_rest every_integer_column_of_every_v2_table_has_an_upper_bound_check every_integer_column_of_every_v2_table_refuses_a_value_that_is_no_integer the_bound_scan_tells_bounded_from_unbounded_columns
```

#### G2-46

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- argon2id_matches_the_rfc_9106_vector the_kek_is_argon2id_over_the_labelled_salt
```

#### G2-47

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- debug_never_prints_the_token_or_a_seed debug_never_prints_a_key a_session_debug_print_hides_its_tokens the_trk_is_stored_and_the_saved_state_holds_only_its_reference a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written the_saved_state_never_prints_the_legacy_trk a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key a_reference_to_another_credential_is_refused_and_that_credential_is_kept the_activation_is_saved_before_the_key_is_forgotten the_run_nonce_is_saved_before_the_key_is_stored a_new_run_never_reuses_a_key_an_abandoned_run_left a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it a_forget_succeeds_only_once_the_key_is_confirmed_gone
```

#### G2-48

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_key_round_trips_and_is_forgotten references_are_separate_credentials a_failed_write_or_read_back_is_reported a_real_os_store_key_survives_into_a_fresh_process an_unavailable_store_fails_closed_in_a_fresh_process a_key_file_key_is_locked_then_served_in_a_fresh_process
```

#### G2-49

```
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_durable_write_replaces_the_file_and_leaves_no_temporary a_failed_replace_keeps_the_old_file_and_removes_the_temporary a_write_killed_at_any_step_leaves_the_old_or_the_new_file a_kill_during_back_to_back_writes_never_tears_or_loses_a_returned_write creating_a_file_that_exists_never_overwrites_it
cargo test --locked --manifest-path shared/Cargo.toml --lib -- only_a_local_ntfs_disk_is_accepted a_local_ntfs_directory_is_accepted_and_a_missing_one_is_not an_smb_share_is_refused
cargo test --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- storage_that_cannot_be_resolved_is_refused storage_on_an_smb_share_is_refused preflight_refuses_an_identity_directory_on_an_smb_share
cargo test --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- an_identity_directory_the_preflight_refuses_never_falls_to_k1 an_empty_identity_directory_setting_refuses_to_start
```

#### G2-50

```
cargo test --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- the_database_runs_a_synced_rollback_journal_and_survives_an_unclosed_pool a_killed_transaction_reopens_old_or_new_never_half a_kill_between_commits_keeps_every_returned_commit a_second_writer_waits_for_the_write_lock storage_on_an_smb_share_is_refused
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- a_killed_transaction_reopens_old_or_new_never_half a_database_held_in_wal_mode_is_refused
cargo test --locked --manifest-path shared/Cargo.toml --lib -- an_smb_share_is_refused
```

#### G2-51

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- the_windows_path_corpus_is_refused_in_every_position every_name_windows_rewrites_is_refused ntfs_case_fold_collisions_are_refused_and_distinct_names_kept long_paths_unpack_and_an_overlong_one_is_refused a_junction_is_neither_packed_through_nor_followed_on_replace
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive a_trace_of_the_old_id_after_the_move_fails_the_discovery_scan
```

#### G2-52

```
cargo test --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- g2_52_every_crash_point_maps_to_one_row_and_resumes_to_the_restored_state
```

#### G2-53

```
cargo test --locked --manifest-path server/Cargo.toml --test identity_authority -- a_symlinked_record_is_refused show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest
cargo test --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- an_identity_directory_that_is_not_there_is_missing_and_stops_the_server
```

#### G2-54

```
cargo test --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2259_g2_54_a_record_equal_to_its_mirror_without_a_manifest_opens_normally
```

#### G2-55

```
cargo test --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2260_g2_55_a_durable_preparation_at_e_keeps_writes_off_until_commit_or_abort g2_55_a_failed_read_only_audit_write_is_counted_in_restore_status g2_55_the_k2_incident_output_prints_the_audit_failure_count g2_55_a_directory_at_the_count_path_stops_a_read_only_start_by_name g2_55_restore_commit_prints_the_final_audit_failure_count_and_clears_it g2_55_a_read_only_start_logs_the_failed_audit_writes_counted_so_far g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count g2_55_a_count_under_a_changed_episode_key_is_kept_and_cleared_by_name g2_55_a_count_file_with_a_bad_line_is_set_aside_and_its_valid_lines_kept
cargo test --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- a_failed_read_only_audit_write_is_logged_and_counted the_count_continues_across_read_only_restarts_of_one_episode a_changed_episode_key_keeps_the_old_count_until_it_is_cleared_by_name one_bad_line_in_the_count_file_loses_only_itself a_crash_while_setting_a_file_aside_never_loses_the_valid_lines the_count_is_written_atomically_and_an_unreadable_one_is_reported a_directory_or_link_at_the_count_path_is_refused_by_name
```

#### G2-56

```
cargo test --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2261_g2_56_an_authority_ahead_of_the_live_mirror_resumes_only_the_install
```

#### G2-57

```
cargo test --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2262_g2_57_an_installed_db_behind_the_record_is_verified_then_rebuilt
```

#### G2-58

```
cargo test --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2263_g2_58_an_authority_ahead_without_exact_evidence_fails_closed l2263_g2_58_only_a_live_custodian_transition_over_the_computed_leaves_prepares
```

#### G2-59

```
cargo test --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- g2_55_the_k2_incident_output_prints_the_audit_failure_count
```

#### G2-60

```
cargo test --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2265_g2_60_a_reconciled_epoch_retires_its_bundle_and_the_next_start_is_normal
```

#### G2-61

```
cargo test --locked --manifest-path shared/Cargo.toml --lib -- a_snapshot_sealed_for_another_profile_is_refused every_single_byte_mutation_is_detected truncation_at_any_length_is_detected cross_envelope_frame_splice_is_rejected another_fleet_key_cannot_open_it grant_cannot_be_replayed_into_another_tenant_or_epoch tampering_with_the_stored_info_fails_the_open
cargo test --locked --manifest-path shared/Cargo.toml --test backup_file_roundtrip -- the_ciphertext_does_not_contain_the_plaintext a_tampered_backup_body_is_refused a_truncated_backup_is_refused_and_leaves_the_destination_untouched
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- pull_refuses_another_profiles_snapshot push_seals_under_the_passphrase_even_with_a_cached_fleet_key a_server_delivered_fleet_key_is_counted_but_never_cached a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet a_compromised_revocation_blocks_commits_under_an_exposed_generation a_compromised_custodian_blocks_every_fleet_through_the_root an_exposure_survives_a_recollection_that_omits_its_grant an_open_upload_is_aborted_once_a_compromise_is_counted a_compromise_counted_mid_transfer_aborts_the_upload a_known_custodian_with_no_root_holding_blocks a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks a_stored_finalize_is_not_sent_once_a_compromise_is_counted a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code a_version_6_file_with_unreadable_kept_pages_still_opens
cargo test --locked --manifest-path server/Cargo.toml --test identity_authority -- an_interrupted_init_is_reported_and_never_repaired
cargo test --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- wrong_domain_hpke_ids_are_quarantined_once
```

#### G2-63

```
cargo test --locked --manifest-path shared/Cargo.toml --test registry_pins -- every_signing_domain_is_distinct_and_versioned every_hash_label_is_distinct_and_nul_terminated the_numeric_registry_holds_the_reviewed_values
cargo test --locked --manifest-path shared/Cargo.toml --lib -- g2_golden_vector_profile_label a_profile_label_opens_only_where_it_was_sealed a_profile_label_has_a_length_bound_both_ways a_profile_label_is_padded_to_a_bucket a_profile_label_that_is_not_canonical_is_refused
```

## 7. G2-48 is pending

Status: **PENDING-MANUAL**. Under the plan's gate paragraph (L2343), unresolved
credential-store-persistence evidence means G2 is not a full PASS. The owner
chose to release without waiting for it; the release proceeds on that owner
decision.

What exists:

- `scripts/g2-48-credential-check.ps1` and `docs/g2-48-manual-check.md` are
  ready. The run has five phases (Store, a Windows restart then Verify,
  Locked, Unavailable from an elevated prompt, Cleanup). G2-48 passes when the
  log holds a `PASS` line for each phase from one run id (ADR Q-29). The script
  touches one test credential it creates and logs only its name, Win32 error
  codes and a SHA-256, never the value.
- The automated half runs in `cargo test --lib` and is in the row above: a key
  survives into a fresh process through the real Windows store (filed
  `persistence = Local`), an unavailable store fails closed, and the key file
  locks and unlocks.

What is not proven: that the stored credential survives a machine restart, is
readable while the session is locked, and is withheld from a logon session
with no credential store.

## 8. G2-64 is FAIL

The independent verifier is Codex and Hermes (ADR Q-32): each in its own
worktree, with the plan and the code but not the implementer's reports. On
2026-11-01 both started blind on the head of PR #213 (2b35d84f), whose tree is
what `main` received in PR #95 plus one review file under `docs/adr/reviews/`.

- **Codex: FAIL.** Its findings are in `verifier-codex-2026-11-01.md` beside
  this file. The implementer read each one against the code and the ADR and
  confirmed all seven:
  - **B1.** The Q-18 commit block does not derive exposure through the root
    (C-1 root clause, RecoveryGrant and RotationGrant issuers, PREPARING
    roots); `src-tauri/src/team/ledger.rs` says so in a `shortcut:` comment.
  - **B2.** Collecting the same generation again replaces its kept evidence,
    so an exposure seen only in the replaced pages stops counting.
  - **B3.** A COMMIT operation whose upload is still `OPEN` resumes after a
    `compromised` revocation is counted, instead of aborting; push also takes
    the lease before the check, where the ADR refuses before checkout.
  - **B4.** Only tenant-scoped `device.revoke` revocations are counted, so a
    fleet-scoped revocation of a fleet member never blocks commits.
  - **B5.** DEVICE_REVOKE accepts only an empty `activations` array.
  - **B6.** G2-42's tests expect lossless TEXT and REAL coercions to succeed,
    where probe 10 says they are rejected.
  - **B7.** G2-31 has no per-operation durable response-loss matrix.

  It also noted weaker spots that it did not count as blocking: the G2-28
  info "golden" is a roundtrip, stale plan lines in G2-21, G2-22 and G2-25, and
  SMB and symlink branches that skip without a share or privilege. Its test
  failures came from its sandbox, which refuses DPAPI; the implementer reran
  `cargo test` for `shared` outside the sandbox: 300 passed, 0 failed.
- **Hermes: no report.** Three runs stopped before a verdict: the default
  provider's safety filter refused, a Claude model hit an HTTP 400 on modified
  thinking blocks, and a Grok model fell into a repetition loop.
- **Owner decision (2026-11-01).** Release v2.5.0 with G2 recorded as FAIL. In
  that release the launcher UI does not call `profile_sync_publish` and the
  Automation API does not expose it, and push takes the v2 path only for a
  published profile, so the paths B1 to B4 affect are not reachable. The Team
  UI that exposes publish must not ship until B1 to B7 are fixed and both
  verifiers return PASS on the fixed tree.

### The fixes

One PR per finding. B1 to B5 each add a regression test that failed on the
code before the fix; B6 is a contract decision; B7 adds tests only, and
forcing one replay to run its operation again makes them fail:

- **B1 and B2, PR #216.** Every verified grant files who holds which root or
  fleet generation in `trust_key_holdings`, and every fleet activation its
  root generation in `trust_fleet_activations` (local schema 7); rows are
  never updated or deleted, and existing databases are backfilled. The block
  holds while a counted compromised key holds the fleet generation, or holds
  the generation's root or any higher one, or the evidence is missing.
  Tests: `a_compromised_custodian_blocks_every_fleet_through_the_root`,
  `an_exposure_survives_a_recollection_that_omits_its_grant`.
- **B4, PR #217.** A revocation counts when it is filed under the subject's
  revocation scope: the fleet when every usable approval of the key names that
  fleet, else the tenant. Test:
  `a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet`.
- **B3, PR #218.** Push refuses with `sync.commitBlockedCompromised` before
  checkout, and a COMMIT whose upload is still OPEN aborts it and releases the
  lease. Test: `an_open_upload_is_aborted_once_a_compromise_is_counted`.
- **B5, PR #219.** DEVICE_REVOKE carries 0 to 65535 activations, and the server
  applies them in the revocation's transaction.
- **B6, PR #220.** The owner chose to clarify the contract instead of
  rebuilding the tables: ADR Q-43.
- **B7, PR #221.** A durable response-loss matrix over every operation kind.
- **Review follow-ups, PR #223.** An unreadable kept evidence page no longer
  fails the version 7 migration; a known custodian with no root holding
  counts as holding every root; a compromise counted during the transfer
  stops the upload before the next chunk or the finalize.

### The rerun on 9e29a2c6 (2026-11-02)

Both verifiers ran blind again, each in its own worktree with its own build
directory, on `main` at 9e29a2c6. Hermes used `cx/gpt-6-astra`.

- **Codex: FAIL** (`verifier-codex-2026-11-02.md`). It judged B4, B5 and B6
  closed and B1, B2 and B7 fixed in source, but could not run their launcher
  tests because its sandbox refuses DPAPI. It found two new defects, both
  confirmed against the code:
  - **N1 (high).** `trust_proven_revocations` kept the first counted
    revocation of a key, so a later `compromised` revocation after a `lost`
    one was dropped and never blocked commits. Fixed: local schema 8 lets a
    counted compromised revocation replace a kept non-compromised container
    by an explicit `UPDATE`; its trigger refuses any other change, and the
    earliest count stays. Test:
    `a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks`.
  - **N2 (medium).** With a FINALIZE stored but never processed, a resumed
    push skipped the OPEN-upload check and sent finalize and commit. Fixed:
    an OPEN upload is aborted whether or not a FINALIZE is pending. Test:
    `a_stored_finalize_is_not_sent_once_a_compromise_is_counted`.
  - Also fixed from its B3 notes: the abort now sends
    `DELETE /v2/uploads/{id}` so the server upload is `ABORTED` too, and the
    launcher keeps `last_error_code = ROTATION_REQUIRED_COMPROMISED` on the
    blocked binding until the block is released (ADR Q-18). Test:
    `a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code`.
  - Its coverage notes are addressed: `shared/tests/registry_pins.rs` now
    holds every domain and label `shared` declares (D-8);
    `info_bytes_match_g2_vector` now pins the hash it names; Q-43 states the
    rounding of decimal or exponent TEXT above 2^53; the plan lines of G2-21,
    G2-22, G2-25 and G2-30 are corrected.
- **Hermes: FAIL** (`verifier-hermes-2026-11-02.md`). It judged B1 to B7
  closed and ran every suite (shared 314, server 347, launcher 496 passed,
  0 failed). It failed the gate only because the SMB branches of G2-49, G2-50
  and G2-55 skipped on its machine. The owner chose CI as the SMB evidence:
  the Windows job creates a share and sets `SHARDX_TEST_SMB_DIR`, and every
  SMB test panics instead of skipping when that variable names an unreachable
  share. The one test that used only the loopback administrative share,
  `g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count`, now
  panics when `CI` is set and that share is unreachable.
- ADR Q-32 asks for Hermes or Codex; the owner asked for both.

## 9. Accepted limits

These are decisions or deferrals, not open defects. The verifier should
confirm each is stated where claimed.

- **A revocation row can still be swapped in two steps** (ADR Q-38 as accepted
  in Q-13). A database writer who can place another genuine revocation under
  the same replay ID before the quarantine mark is written can still have it
  served. A revocation that is not served at all turns v2 off instead.
- **A second origin cannot store fleet key state for an already-stored grant
  record** (Q-42). Two origins of one instance cannot yet share a grant
  record's key state; the second one fails closed.
- **A fast device clock never holds a lease.** By Q-42's rule an expired lease
  binds the profile with no lease and releases it, so a device whose clock runs
  ahead of the server's treats a fresh lease as expired.
- **No Team UI for the G2 commands yet.** The launcher commands
  (`profile_sync_publish`, `team_unbind_profile`, the downgrade commands) and
  the server CLI exist; the owner deferred the screens.
- **Orphaned keys.** A key orphaned by an abandoned bootstrap run stays in the
  credential store (a new run never reuses it and nothing deletes it), and so
  does one left in a locked key file (`docs/security-review-g2.md`, Key storage).
- Also recorded in the rows: outside CI the SMB tests run only where
  `SHARDX_TEST_SMB_DIR` is set or the loopback administrative share is
  reachable, and skip otherwise; in CI they cannot skip (G2-49, G2-50, G2-55); the restore journal has no
  production writer (G2-41); local backups keep p=1 (G2-46); zeroization is
  type-level evidence (G2-47).

## 10. Rows that are not DONE, and what this packet found

- **G2-48** PENDING-MANUAL, see section 7.
- **G2-64** FAIL, see section 8. **G2-14**, **G2-31**, **G2-42** and
  **G2-61** were PARTIAL because of findings B1 to B7 and are DONE again.
- **G2-63** was PARTIAL in the last gap table. It is DONE here: the provider
  and profile-label rows are in `docs/security-review-g2.md`; the two label
  constants are in `shared/tests/registry_pins.rs`; this packet is the
  assembled evidence. The sixteen request and response domains of the lease,
  upload, publish, unbind and fleet-profile-page maps were added to the
  registry test's `DOMAINS` as well.
- **G2-62** gained a paragraph in `docs/dependency-review.md` for the
  `hkdf` 0.13.0 and `sha2` 0.11.0 direct dependencies.
- The gap table cited lines 861 to 1238 of `server/tests/v2_integer_domain.rs`
  for G2-45; that file has 622 lines. The row is cited by test name here.
- The gap table's note on the bootstrap TRK sitting in a state file in the
  clear is resolved by PR #212; see G2-47.

## 11. Test run behind this packet

On 2026-11-01, on a Windows 11 machine with stable rustc 1.99.1, the commands of section 6 were run, one invocation per cargo target with all of that target's filters, against 5c1cd7b8 plus this packet, with `cargo test --locked -j 1` and one scratch target directory. The twelve cargo targets they use ran the 255 distinct tests cited by the rows (307 row-to-test pairs; shared lib 81 run for 75 cited names, server `v2_auth` 20, `v2_profiles` 5, `v2_e2e` 1, `restore_epoch_harness` 20, `v2_upgrade_chain` 8, `v2_integer_domain` 5, `identity_authority` 3, server binary 15, shared `backup_file_roundtrip` 3 and `registry_pins` 3, launcher lib 93). All twelve exited 0 with 0 failed and 0 ignored. A script then matched every cited (file, test) pair to a `... ok` line: 306 of the 307 pairs matched; the remaining one, `custody_tests::a_server_delivered_fleet_key_is_counted_but_never_cached` (G2-61), lives in a module that the matcher does not map to `src-tauri/src/lib.rs`, and a separate run of it printed `ok`. The runs include a few extra tests that share a name filter.

Also run: `cargo +stable fmt --check` on `shared`; `cargo +1.87.0 check --locked --all-targets` on `shared` (finished, no errors); `npm run test:i18n` (16 passed), `test:rust-strings` (3 passed) and `test:backend-locale` (7 passed); `python scripts/g2-evidence.py --write`, `--check` and `--self-test`.

Not run here: clippy, the full `cargo test` of each crate, the MSRV checks of `server` (1.89) and the launcher (1.88), `cargo audit`, the macOS compile, the Playwright and MCP checks, and the SMB tests (no share was set up, so they skipped). Those rest on the CI runs in section 3 and the verifier.

**Refresh for B1 to B7.** On 2026-11-01 the section 6 commands of G2-14, G2-31, G2-42 and G2-61 were run with `cargo test --locked -j 4` against the tree `main` received in PR #221 (the head of that PR): 13 invocations, all `ok`, 0 failed, 0 ignored. Each fix PR also ran the feedback gate (clippy `-D warnings` and the tests of `shared`, `server` and the launcher's `team` module) clean against a baseline taken on `main` before the first fix, except PR #220, which changed only the ADR and two test comments, and passed the five CI jobs of section 3 on its exact head before merge.
