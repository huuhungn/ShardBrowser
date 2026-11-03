# Independent verification: ADR 0002 rule 6 and Team join

Verified HEAD: `bf09f51237bdc0cbe30634b67496e79afd0d1df8`.

The worktree was clean at the start. This review used the requested ADR passages and repository implementation/tests at that HEAD. No author reports, `.omc/`, `.omx/reports/`, or scratch directories were read. Production code was not changed. Three unit tests were appended to `src-tauri/src/team/sync.rs`; their complete source appears below. Existing source line numbers were preserved by appending the tests at the end of the module.

**Result: one confirmed defect, D1.** A custodian-signed revocation with the correct signing key but the wrong subject device is counted. It can turn a reported-only quarantine into an accepted skip, clear the quarantine, and replace the local profile. The new regression fails on the verified implementation. The two new timing regressions pass.

**Scope and interpretation.** The ADR is the contract, including its explicit ordinary-push exception, the first-sight/no-history limit, the open-run pull restore of P, and its statement that a reader trusts R's valid committer for R's plaintext provenance. Property 2 below concerns the pull/join/revert acceptance paths; the ADR expressly permits an ordinary push to pin its own committed head and quarantine on a later operation. Property 6 tests R produced by this client's revert; arbitrary remote R plaintext cannot be proven by a reader. For property 10, an earlier-epoch head requires the proven restore leaf; a profile originally created at the current epoch follows normal first acceptance, as the Joining bullet specifies.

**Execution and test integrity.** Cargo was put in offline mode with `$env:CARGO_NET_OFFLINE='true'`. Tests use temporary config roots/databases; the sync fixture binds its fake server to `127.0.0.1:0` (`src-tauri/src/team/sync.rs:5569`). The test root lock and root override are in `src-tauri/src/store.rs:35` and `src-tauri/src/store.rs:45`. No live service or `%APPDATA%\shardx-launcher` was accessed, and the real credential-store test was never run. No commits, pushes, PRs, issues, or messages to others were made.

I read the relevant assertions and fixture paths, and checked the reviewed modules for ignored tests, trivial always-true assertions, and early returns. The tests cited below have substantive assertions on errors, pins, audit rows, content, leases, or staging. None is ignored or bypasses its assertions. The return in the `World::enroll` helper is the deliberate unbound-fixture branch; it does not skip a test. The source-withdrawal tests that allow either a refusal or a successful rewalk assert content/state in both branches. No existing test or assertion was modified. The new tests assert that their injected mutation actually ran.

The existing loopback-server/temporary-ledger fixture was reused for the new tests (`src-tauri/src/team/sync.rs:4704`, `src-tauri/src/team/sync.rs:5569`); no new feature or external prior-art survey was needed.

**Commands and complete result summaries.** Every executed test command used this form, with the exact filters listed below:

```powershell
$env:CARGO_NET_OFFLINE='true'
cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib <filter> -- --skip a_real_os_store_key_survives_into_a_fresh_process
```

| Run | Exact filter | Observed output summary | Exit |
| --- | --- | --- | --- |
| S | `team::sync::tests` | `185 passed; 0 failed; 0 ignored; 0 measured; 455 filtered out; finished in 326.35s` | 0 |
| N | `verifier_round5_` | `2 passed; 1 failed; 0 ignored; 0 measured; 640 filtered out; finished in 4.77s` | 1 |
| C | `custody_tests` | `34 passed; 0 failed; 0 ignored; 0 measured; 609 filtered out; finished in 8.17s` | 0 |
| D | `team::db::tests` | `19 passed; 0 failed; 0 ignored; 0 measured; 624 filtered out; finished in 4.48s` | 0 |
| L | `team::ledger::tests` | `6 passed; 0 failed; 0 ignored; 0 measured; 637 filtered out; finished in 0.73s` | 0 |
| G | `a_clone_lands_a_pending_revert_swap_and_leaves_no_staging` | `1 passed; 0 failed; 0 ignored; 0 measured; 642 filtered out; finished in 0.26s` | 0 |

Run S used the original HEAD test binary, before the added tests. The later binary includes exactly the three additions. Total executed test cases: **248; 247 passed, 1 failed, 0 ignored**. Output excerpts below retain the test names and results, with the common module prefix omitted where identified.

An initial attempt at N while S still held the executable failed during linking with `LINK : fatal error LNK1104: cannot open file ...shardx_launcher_lib-7eb62a6e382ee148.exe`. No test ran in that attempt. After S exited, the same N command rebuilt and ran, producing the assertion failure below. This was a Windows executable lock, not a product failure. No OS error 1455 occurred, so no `-j 1` retry was needed. Build-generated schema line-ending changes were restored; only the added tests and this report remain changed.

**Property 1 — VIOLATED. Proven-revoked runs only.**

The chain path is `walked` (`src-tauri/src/team/sync.rs:4275`) -> ledger evaluation/record -> `walk` (`src-tauri/src/team/sync.rs:4094`) -> `revert_rule` (`src-tauri/src/team/sync.rs:4037`). The rule checks version/base/hash continuity and admits only `Standing::Withdrawn` into a run; reported and untrusted/lapsed heads refuse. The walk prefers proven withdrawal over an unsigned report at `src-tauri/src/team/sync.rs:4226`. `ledger::withdrawn_in` (`src-tauri/src/team/ledger.rs:239`) consults the permanent revocation table, which also contains local distrust (`src-tauri/src/team/ledger.rs:134`). The gap is before that rule: `counted` (`src-tauri/src/team/ledger.rs:1112`) does not validate the revocation's subject device against the signer's approved device. See D1.

Run S output, module `team::sync::tests` (assertions read at `src-tauri/src/team/sync.rs:10530`, `:10626`, `:10666`, `:10827`, `:10855`, `:10935`, `:10947`, and `:12978`):

```text
revert_rule_accepts_one_proven_revoked_head ... ok
revert_rule_accepts_two_stacked_proven_revoked_heads ... ok
revert_rule_accepts_on_a_new_device_without_a_pin ... ok
revert_rule_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
revert_rule_refuses_a_reported_only_revocation ... ok
revert_rule_refuses_a_gap_below_the_pin ... ok
revert_accepts_one_proven_revoked_head ... ok
revert_accepts_two_stacked_proven_revoked_heads ... ok
revert_accepts_on_a_new_device_without_a_pin ... ok
revert_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
revert_refuses_a_reported_only_revocation ... ok
revert_refuses_a_reported_only_head_below_a_revoked_pin ... ok
revert_refuses_a_revocation_whose_issuer_lacked_device_revoke ... ok
revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight ... ok
revert_accepts_a_revocation_another_device_filed ... ok
local_distrust_alone_enables_a_revert ... ok
```

Run C also passed `a_revocation_counts_only_from_a_custodian_allowed_to_revoke` and `a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet` (`src-tauri/src/lib.rs:3542`, `:3580`). Neither covers a wrong subject device. New test `verifier_round5_mismatched_revocation_device_never_enables_a_skip` (`src-tauri/src/team/sync.rs:13511`) covers that missing case and **FAILED** in run N. Full output and source are below.

**Property 2 — HOLDS within the ADR's acceptance scope. No proven-revoked head is pinned by pull/join/revert.**

Pull's `pin` checks the signer under an immediate transaction at `src-tauri/src/team/sync.rs:4446`. Revert's `finish` repeats the check after network readback, under its pin transaction, at `src-tauri/src/team/sync.rs:3645`; `dropped_withdrawn_r` at `:3569` drops the used lease. The leaf acceptance callback records the same evidence before checking the signer (`src-tauri/src/team/sync.rs:1265`, `:1270`); `store_transitions` at `:1474` rolls back its provisional updates when that callback refuses. Skipped J heads become audit rows, not pins. The ordinary-push exception is explicitly selected by `if revert` in `finish`, matching the ADR rather than an unconditional claim about all push pins.

Run S output (`team::sync::tests`; tests at `src-tauri/src/team/sync.rs:12826`, `:12860`, `:13135`, `:13161`, `:13371`):

```text
join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok
a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok
a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok
a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
an_open_run_anchor_withdrawn_during_download_is_not_pinned ... ok
```

Run N adds the missing fresh-R readback and join proof-fetch timing cases (`src-tauri/src/team/sync.rs:13573`, `:13596`):

```text
verifier_round5_join_leaf_withdrawn_during_proof_fetch_is_not_pinned ... ok
verifier_round5_fresh_r_withdrawn_during_readback_is_not_pinned ... ok
```

**Property 3 — HOLDS. The committer seals R from the newest valid P.**

The walk keeps the latest accepted anchor and walks below a withdrawn pin (`src-tauri/src/team/sync.rs:4094`). `revert_inner` (`:2094`) requires an open run and a concrete P, reads P using its own generation, and restores it into staging. It passes that staging directory to `push_inner`, which seals through `seal_snapshot` (`:2988`), so neither J's data nor local unsynced data supplies the snapshot. `source_withdrawn` (`:1714`) reloads the anchor named by the lowest open audit row; the READY branch rechecks that anchor before a new COMMIT (`:1897`). A missing or withdrawn source abandons the upload while the server is still at Jn. The read-only old-generation key path is `readable_key` (`:1633`).

Run S output (`team::sync::tests`; assertions at `src-tauri/src/team/sync.rs:11295`, `:11310`, `:11446`, `:13253`, `:13295`, `:13336`):

```text
revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
revert_commits_over_a_head_pinned_before_its_signer_was_proven_revoked ... ok
revert_waits_for_rotation_after_a_compromised_revocation ... ok
revert_restores_an_anchor_of_an_older_generation_after_rotation ... ok
a_revert_never_commits_a_source_withdrawn_during_its_download ... ok
a_resumed_revert_never_commits_a_source_withdrawn_before_its_retry ... ok
a_revert_uses_the_newest_valid_content_and_reads_back_remotely ... ok
```

The last test distinguishes newest P (`v2`) from the older pin (`v1`), rejected content (`v3`), and unsynced local content, then decrypts R on another device. No additional provenance test was needed.

**Property 4 — HOLDS for refusal/abandonment and withdrawal timing.**

`restore_then_pin` (`src-tauri/src/team/sync.rs:4503`) restores into staging, invokes the pin transaction, and only then settles the swap. Its failure branch discards staging. `revert` (`:2040`) follows the same cleanup rule; `fresh_staging` (`:4487`) copies the device's Local State before unpacking. The open-run exception (`:4649`) files the quarantine/run, restores and pins a newer P, and reports `sync.signerRevoked`; it uses the same restore path as an ordinary pull. The transaction-time withdrawal checks cited for property 2 protect both P and R. D1 is an erroneous successful acceptance, not a failure of the rollback mechanism; its local-data consequence is explicitly recorded below.

Run S output (`team::sync::tests`; assertions at `src-tauri/src/team/sync.rs:11519`, `:12890`, `:12909`, `:12925`, `:13135`, `:13161`, `:13195`, `:13371`):

```text
a_refused_revert_checkout_keeps_the_local_profile ... ok
a_pull_whose_pin_fails_keeps_the_local_profile ... ok
a_join_whose_pin_fails_keeps_the_local_profile ... ok
an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok
a_pull_keeps_the_devices_local_state ... ok
a_revert_keeps_the_devices_local_state ... ok
an_open_run_restore_keeps_what_an_ordinary_pull_keeps ... ok
a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok
a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
an_open_run_anchor_withdrawn_during_download_is_not_pinned ... ok
```

The open-run comparison initializes identical Local State and compares the complete relative file/byte trees from the ordinary pull and the exception. It does not treat replacement of ordinary unsynced edits as a defect. Both added timing tests in N also assert that the local file tree remains unchanged and staging is gone; both passed.

**Property 5 — VIOLATED through D1; release and replay paths themselves preserve quarantine.**

`release_reply` (`src-tauri/src/team/sync.rs:3752`, state update at `:3798`) retains `SIGNER_REVOKED` and returns the binding to QUARANTINED. Revert resumes a pending release before doing anything else (`:2109`). Pull refuses to clear the quarantine without an accepted run (`:4674`), and `pin` only clears it when `lift` is true (`:4451`). Revert's finish resolves the audit and clears quarantine with its accepted pin in one transaction (`:3650`). These gates depend on correct proof classification: D1 causes a nonconforming revocation to produce an accepted run and therefore clears the quarantine without a contract-valid R.

Run S output (`team::sync::tests`; assertions at `src-tauri/src/team/sync.rs:11367`, `:11499`, `:11643`, `:12860`, `:13161`, `:13448`, `:13467`):

```text
an_abandoned_revert_keeps_the_binding_quarantined ... ok
revert_resumes_after_a_lost_release_of_an_abandoned_lease ... ok
revert_resumes_after_a_lost_commit_reply ... ok
a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok
a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
a_withdrawn_device_releases_its_revert_lease_on_the_server ... ok
a_revert_lease_whose_walk_fails_is_released_on_the_server ... ok
```

New test N's wrong-device proof case **FAILED**, observing `AVAILABLE`, no error code, and version 3 instead of the existing `SIGNER_REVOKED` quarantine at version 0. The fresh-R withdrawal test passed with the quarantine and unresolved audit retained. No release or lost-reply replay alone was observed lifting the quarantine.

**Property 6 — HOLDS. Accepted locally produced R installs P.**

`finish` writes the pin, accepted audit rows, and `revert_swaps` row in the same transaction (`src-tauri/src/team/sync.rs:3594`). `revert` settles that row after success (`:2052`). `settle_revert_swap` (`:1936`) moves staged P into the profile and resumes interrupted rename states. Pull, push, revert, and launch settle a pending swap before further data use (`:4604`, `:1667`, `:2040`, `src-tauri/src/launch.rs:150`). A failed filesystem swap reports `sync.revertSwapPending` and keeps the durable row; the crash-resume behavior is tested, not described as immediate filesystem atomicity.

Run S output (`team::sync::tests`; tests at `src-tauri/src/team/sync.rs:11295`, `:11409`, `:11546`, `:11573`, `:13038`, `:13487`):

```text
revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
revert_committed_here_is_accepted_by_a_second_device ... ok
a_crash_after_finish_completes_the_staging_swap ... ok
a_crash_inside_the_staging_swap_resumes ... ok
a_resumed_revert_whose_staging_is_gone_restores_p_again ... ok
a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull ... ok
```

These tests inspect installed content (`v1`/`v2`), pending-row removal, and recovery at each rename state. No new test was needed beyond the fresh-R refusal check in N.

**Property 7 — HOLDS. Sticky self-renewal rejection and exactly one alert per revoked key.**

`prepare` (`src-tauri/src/team/ledger.rs:273`) loads the earliest counted evaluation, preserves records seen at or before it, and drops later records signed by the revoked key regardless of their issuance time. It distinguishes DEVICE_REVOCATION from local distrust for alert emission. `renewed_after_revocation` (`:385`) inserts only when there is no existing alert for that key. Schema 9's primary key and immutable/insert-once triggers enforce persistence (`src-tauri/src/team/db.rs:1324`, `:1375`). `record_in` stores sightings/counts (`src-tauri/src/team/ledger.rs:830`).

Run C output (`custody_tests`; assertions at `src-tauri/src/lib.rs:4597`, `:4785`, `:4810`, `:4891`, `:4929`, `:4975`):

```text
revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok
a_backdated_self_renewal_after_a_count_is_refused ... ok
a_renewal_issued_before_the_count_is_sticky_and_alerts_once ... ok
renewed_after_revocation_is_bounded_per_key ... ok
renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok
renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok
records_first_seen_before_a_count_keep_their_standing ... ok
```

Run D output (`team::db::tests`; `src-tauri/src/team/db.rs:2115`, `:2270`):

```text
a_version_8_file_migrates_to_version_9_and_reopens ... ok
renewed_after_revocation_alerts_refuse_delete_and_replace ... ok
```

The backdated-renewal test includes a no-history positive control; the deduplication test sends multiple genuine renewals across repeated evaluations and checks the original alert's identity and timestamp. Existing coverage was sufficient.

**Property 8 — HOLDS. Alert only for a renewal verified under the revoked key itself.**

`keys_of` derives key IDs from public keys (`src-tauri/src/team/ledger.rs:69`). `renewed_after_revocation` looks up the issuer by that ID, verifies the signature, requires a root-grant renewal, excludes FirstRootSelfGrant, and requires subject key == issuer (`src-tauri/src/team/ledger.rs:385`). A valid signature by another key is insufficient, even if the container names D.

Run C output (`custody_tests`; `src-tauri/src/lib.rs:4841`, `:4948`, `:4975`):

```text
renewed_after_revocation_is_not_raised_for_a_forged_container ... ok
renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok
renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok
```

The forged-container test actually signs the named-D container with a different key and separately removes D's public key from a genuine renewal's evidence; both leave the alert table empty. Existing coverage was sufficient.

**Property 9 — HOLDS. Decrypted staging is removed on abandonment, deletion, and unbind.**

`discard_revert_staging` (`src-tauri/src/team/sync.rs:1983`) removes staging and rename leftovers unless a pending swap or genuinely resumable upload needs them; a pending release for the held lease disables retention. `revert` invokes cleanup on refusal (`:2057`). `discard_revert_for_deletion` (`:2027`) first settles a swap and then unconditionally removes staging and crash leftovers. All deletion routes converge on it: UI single deletion (`src-tauri/src/lib.rs:860` -> `src-tauri/src/trash.rs:65`), local API (`src-tauri/src/api.rs:698`), folder deletion (`src-tauri/src/lib.rs:1132` / `src-tauri/src/api.rs:848` -> `src-tauri/src/profile.rs:943`), and direct/fallback deletion (`src-tauri/src/profile.rs:762`). Staging siblings are removed before trash creation and are not archive inputs. Unbind settles/discards first (`src-tauri/src/team/downgrade.rs:1252`); downgrade clone does so before archive (`:548`).

Run S output (`team::sync::tests`; `src-tauri/src/team/sync.rs:11536`, `:11679`, `:11701`, `:11756`, `:11787`, `:12925`):

```text
a_refused_revert_discards_its_staging ... ok
an_abandoned_revert_lease_discards_its_staging ... ok
an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok
deleting_or_unbinding_a_profile_discards_its_revert_staging ... ok
folder_delete_discards_decrypted_revert_staging ... ok
deletion_unbind_and_discard_remove_the_unpack_leftovers_beside_the_staging ... ok
```

Run G output (`src-tauri/src/team/downgrade.rs:1689`):

```text
test team::downgrade::tests::a_clone_lands_a_pending_revert_swap_and_leaves_no_staging ... ok
```

The deletion tests cover a held lease and all four sibling directories; the abandonment tests include a lost release reply. N's two passing timing tests additionally check no stale staging. The ADR's resumable-upload/pending-swap exceptions are not counted as abandonment.

**Property 10 — HOLDS. Proven restore leaf, pull before checkout, and recovery after failed join.**

`join` (`src-tauri/src/team/sync.rs:2400`) checks bindings/pending publish/key availability, chooses the initial epoch, inserts a version-0 binding, then calls pull. `accept_transitions` (`:1102`) follows each signed transition and inclusion proof; `verify_transition` (`:1305`), `verify_proof` (`:1446`), `above_leaf` (`:1407`), and `verify_leaf_head` (`:1358`) enforce custody, IDs, chain, epoch, signature, and authority. The leaf's signer is checked again after recording the same evidence under the pin transaction (`:1265`). `push_inner` computes base_version < remote_version (`:1807`) and `checkout` (`:2857`) refuses a fresh checkout or releases a replay when local data is behind. The command holds the profile mutation claim (`src-tauri/src/sync_cmd.rs:536`). A failed restore can retry pull; terminal quarantine leaves local unbind available (`src-tauri/src/team/downgrade.rs:1242`).

Run S output (`team::sync::tests`; tests at `src-tauri/src/team/sync.rs:12470`, `:12486`, `:12500`, `:12563`, `:12689`, `:12720`, `:12826`, `:12950`, `:13110`):

```text
join_after_a_restore_pins_the_transition_leaf_then_pulls ... ok
join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf ... ok
join_refuses_the_rolled_back_child_of_the_leaf ... ok
join_with_a_lying_first_snapshot_pins_nothing ... ok
join_then_a_push_before_the_first_pull_restores_is_refused ... ok
join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes ... ok
join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok
a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok
a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind ... ok
```

Run N's `verifier_round5_join_leaf_withdrawn_during_proof_fetch_is_not_pinned` also passed, including an actual successful unbind after rejection. The recovery tests perform the later pull/push or unbind; they do not merely assert the initial failure. The ADR's explicit pending-first-COMMIT-across-restore limitation is retained as a contract limitation, not a new defect in this join feature.

**Defect D1 — a wrong-device revocation is counted and enables a skip.**

Location: `src-tauri/src/team/ledger.rs:1125` checks tenant, instance, issuer custody, issuer capability, and current custody, but never compares `subject_device_id` to the subject signing key's approved device identity. `src-tauri/src/team/ledger.rs:874` then indexes the count solely by `subject_signing_key_id`. The head walk sees that row as proven withdrawal at `src-tauri/src/team/sync.rs:4111` / `:4226`; the accepted-run path reaches `pin`, where `lift` clears quarantine at `src-tauri/src/team/sync.rs:4451`.

The scoped ADR expressly requires that a counted revocation's **“subject device and signing key equal the signer of the rejected head”** (`docs/adr/0002-g2-contract-decisions.md:1538`). Only the key side is enforced. This is a validation defect requiring a correctly custodian-signed but internally inconsistent record; it is not a claim that an unsigned server can manufacture the signature or gain a custodian's permissions.

Concrete reproduction, implemented in `src-tauri/src/team/sync.rs:13511`:

1. Serve P at v1, a head J at v2 signed by the fixture author approved as device `0x71…`, and a currently authorized head R at v3.
2. Give the client only the unsigned report for that author's device. Its first pull correctly refuses, retains the local `unsynced local` marker, and quarantines at version 0.
3. Supply the current custodian's signed DeviceRevocationV2 with the author's signing key but subject device `0x99…`, keeping the unsigned report. The test verifies the original record's signature, changes only the device ID, and re-signs with the same permitted issuer. It asserts that this mutation occurred.
4. Pull again. Expected: no counted revocation, no skip, the same quarantine/version/content. Actual: the revocation is counted; pull succeeds, pins v3, files one skip, clears quarantine, and replaces the local profile.

This violates properties 1 and 5. It also shows the user-data effect of the invalid acceptance; the successful restore is not the ADR's open-run-P exception. No separate transactional rollback defect was found in property 4.

Run N's exact failure output:

```text
test team::sync::tests::verifier_round5_join_leaf_withdrawn_during_proof_fetch_is_not_pinned ... ok
test team::sync::tests::verifier_round5_fresh_r_withdrawn_during_readback_is_not_pinned ... ok
test team::sync::tests::verifier_round5_mismatched_revocation_device_never_enables_a_skip ... FAILED

---- team::sync::tests::verifier_round5_mismatched_revocation_device_never_enables_a_skip stdout ----

thread 'team::sync::tests::verifier_round5_mismatched_revocation_device_never_enables_a_skip' (1388) panicked at src\team\sync.rs:13555:9:
assertion `left == right` failed: a signed revocation for a different device is not proof against this signer
  left: (false, true, "AVAILABLE", None, 3, 1, false)
 right: (true, false, "QUARANTINED", Some("SIGNER_REVOKED"), 0, 0, true)

test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 640 filtered out; finished in 4.77s
```

Tuple fields are `(pull_is_error, signer_counted_withdrawn, state, error_code, pinned_version, skipped_row_count, local_tree_unchanged)`. The assertion compares actual post-operation state, not an implementation detail or an empty result. No production fix was made in this verifier worktree.

**New unit test source.** The following tests are appended inside the existing `team::sync::tests` module and use its local fake server and temporary configuration fixture.

```rust
#[test]
fn verifier_round5_mismatched_revocation_device_never_enables_a_skip() {
    let w = world();
    chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
    let mut evidence = author_pages_for(
        &w,
        T0 + 300 * DAY,
        Some(DeviceRevocationReason::Retired),
        true,
    );
    let mut changed = false;
    for container in &mut evidence[0].containers {
        let record = AuthorizationRecord::parse(container).unwrap();
        if record.payload_domain() != DOMAIN_DEVICE_REVOCATION {
            continue;
        }
        let verified = record
            .verify_signature(&w.me.sk.verifying_key().to_bytes())
            .unwrap();
        let Payload::DeviceRevocation(revocation) = verified.payload() else {
            panic!("expected a device revocation");
        };
        let mut wrong_device = revocation.clone();
        assert_eq!(wrong_device.subject_device_id, [0x71; 16]);
        wrong_device.subject_device_id = [0x99; 16];
        *container = build_record(
            &w.me.sk,
            DOMAIN_DEVICE_REVOCATION,
            &wrong_device.encode(),
        );
        changed = true;
    }
    assert!(changed, "the mismatched record was actually installed");
    let d = second(&w);
    // Establish the reported-only quarantine before supplying the bad proof.
    serve(&w, &author_pages(&w, T0 + 300 * DAY, false, true));
    let out = d.path().join("profile");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("marker"), b"unsynced local").unwrap();
    let before = tree(&out);
    assert!(has(&w.pull(&out).unwrap_err(), "sync.signerRevoked"));
    revoked_at(&w, 0);
    serve(&w, &evidence);
    let result = w.pull(&out);
    let (state, reason, _, version, _) = w.state(LOCAL);
    assert_eq!(
        (
            result.is_err(),
            ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap(),
            state,
            reason,
            version,
            skipped(&w).len(),
            tree(&out) == before,
        ),
        (true, false, "QUARANTINED".into(), Some("SIGNER_REVOKED".into()), 0, 0, true),
        "a signed revocation for a different device is not proof against this signer"
    );
    assert!(has(&result.unwrap_err(), "sync.signerRevoked"));
    settled(&w, &out);
}

#[test]
fn verifier_round5_join_leaf_withdrawn_during_proof_fetch_is_not_pinned() {
    let (w, d, _, _) = joinable_after_restore(0);
    let out = d.path().join("profile");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("marker"), b"unsynced local").unwrap();
    let before = tree(&out);
    w.fake().on_proof = Some(
        distrust_author().replace(&hex(&key_id_of(&author())), &hex(&w.me.to.signing_key_id)),
    );
    let result = w.join(LOCAL, PROFILE, &out);
    assert!(w.fake().on_proof.is_none(), "withdrawal hook ran");
    assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id).unwrap());
    assert!(has(&result.unwrap_err(), "sync.epochTransitionInvalid"));
    assert_eq!(w.state(LOCAL).3, 0);
    assert!(tree(&out) == before);
    assert!(w.sent("POST", "/checkout").is_empty());
    settled(&w, &out);
    unbind(LOCAL, SERVER, NOW).unwrap();
    assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
    assert!(tree(&out) == before);
}

#[test]
fn verifier_round5_fresh_r_withdrawn_during_readback_is_not_pinned() {
    let w = world();
    let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
    w.fake().skip.push("commit");
    w.revert(&udd).unwrap_err();
    assert_eq!(w.fake().version, 2, "no R has landed yet");
    let before = tree(&udd);
    w.fake().on_snapshot = Some(
        distrust_author().replace(&hex(&key_id_of(&author())), &hex(&w.me.to.signing_key_id)),
    );
    let result = w.revert(&udd);
    assert!(w.fake().on_snapshot.is_none(), "readback withdrawal hook ran");
    assert_eq!(w.fake().version, 3, "R landed before the readback");
    assert!(has(&result.unwrap_err(), "sync.signerRevoked"));
    revoked_at(&w, 1);
    assert!(tree(&udd) == before);
    assert_eq!(local_leases(&w), 0);
    assert_eq!(skipped(&w).len(), 1);
    assert!(skipped(&w)[0].1.is_none(), "the run is still open");
    settled(&w, &udd);
}
```

VERDICT: FAIL
