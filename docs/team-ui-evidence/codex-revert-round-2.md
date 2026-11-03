**Independent verification — ADR 0002 rule 6 revert and Team join, round 2**

Verified HEAD: `a1d90593941b9571cf28cbb826d64b9d7cae5d8f`.

Worktree: `<verify-worktree>`. The initial worktree was clean. Production implementation was left unchanged. The working-copy additions are four unit tests and one optional test-server callback in `src-tauri/src/team/sync.rs`, plus this report.

The review used the requested portions of `docs/adr/0002-g2-contract-decisions.md` (Joining at line 1529, Revoked/Lapsed signer at lines 1534–1593, sticky proven revocation at line 1493), implementation, and repository tests. No author review reports, `.omc/`, `.omx/reports/`, scratch directories, or external research were read. No commits, pushes, PRs, issues, or external service calls were made.

**Result**

Two implementation defects were reproduced: withdrawal can arrive after the walk/readback check and before the pin transaction in both pull and revert completion. A third failing probe exposes a conflict between property 4's unconditional preservation requirement and the ADR's explicit advance-to-P behavior. Properties 2, 4 and 5 are VIOLATED; properties 1, 3, 6, 7, 8, 9 and 10 HOLDS under the contract interpretations stated below. The two implementation defects independently require FAIL even if property 4 is reconciled with the ADR.

**Execution and isolation**

All runs used the requested library test invocation and skipped `a_real_os_store_key_survives_into_a_fresh_process`. The initial build used `--offline`; later invocations set process-local `CARGO_NET_OFFLINE=true`. Tests use the loopback Axum server in `sync.rs:5473`, temporary config roots (`sync.rs:5456`, `sync.rs:5517`), and the test-only in-memory credential backend (`src-tauri/src/credential.rs:56`). The real OS credential-store test was never run, and no operation targeted `%APPDATA%\shardx-launcher`.

Commands and aggregate output:

```text
cargo test -j 4 --offline --manifest-path src-tauri/Cargo.toml --lib team::sync::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
test result: FAILED. 174 passed; 2 failed; 0 ignored; 0 measured; 452 filtered out; finished in 502.11s

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib verifier_round2 -- --skip a_real_os_store_key_survives_into_a_fresh_process
test result: FAILED. 1 passed; 3 failed; 0 ignored; 0 measured; 626 filtered out; finished in 12.99s

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib verifier_round2 -- --skip a_real_os_store_key_survives_into_a_fresh_process
test result: FAILED. 1 passed; 3 failed; 0 ignored; 0 measured; 626 filtered out; finished in 8.05s

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custody_tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
test result: ok. 33 passed; 0 failed; 0 ignored; 0 measured; 597 filtered out; finished in 16.50s

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::db::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 611 filtered out; finished in 4.33s

cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::ledger::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 624 filtered out; finished in 0.58s
```

The broad sync run compiled after the first two new probes were added and before the final two additions. Thus all 174 original sync tests passed; its two failures were new probes. The final four-probe binary was run twice with identical outcomes. All 232 existing tests across the four modules passed; of the four new tests, one passed and three failed.

Two premature attempts to rebuild while the earlier Windows test executable was still running failed at linking with `LNK1104` on that executable; neither ran tests. They were retried after the running executable exited. One attempted filter `a_backdated_self_renewal_after_a_count_is_refused|renewed_after_revocation` matched zero tests (Rust filters are substrings); that run is not counted as evidence and was replaced by the full `custody_tests` run above. No os error 1455 occurred. Build-generated schema files had only line-ending churn and were restored; the final diff contains only the test additions and this report.

The cited tests and their assertion helpers were read. There are no `#[ignore]`, `#[should_panic]`, empty assertions or unconditional true assertions in the reviewed files, and no early-return bypass in the cited tests. The early return in `World::enroll` intentionally sets up an unbound fixture; it does not skip a test. The existing replay test assigns its result to `_replayed`, but still asserts the exact quarantine/version/data tuple, so it is not a vacuous test. New failures remain ordinary failing tests; their expectations were not weakened.

Unless marked working-copy, code references below refer to verified HEAD. Production line numbers are unchanged. The stdout excerpts below are actual matching result lines from the command runs above; unrelated passing test lines and long-running notices are omitted.

**D1 — Pull pins a key withdrawn during snapshot download (property 2)**

Enforcement gap: `src-tauri/src/team/sync.rs:4017` / `src-tauri/src/team/sync.rs:4132` check the signer while walking. `restore_then_pin` then awaits the object download and unpack (`src-tauri/src/team/sync.rs:4415`), and `pin` updates the binding in a new transaction without checking the signer (`src-tauri/src/team/sync.rs:4348`).

Concrete scenario: the client walks valid v1 and v2, with v2 signed by A. Another local ledger writer records local distrust of A while the snapshot GET is being served, before the pin transaction. Pull returns success, pins v2 and replaces the profile although A is now proven withdrawn. The new callback performs the same ledger insertion as the existing concurrent-writer fixture; it does not alter the manifest, pin or production logic.

New test: `src-tauri/src/team/sync.rs:12939`, `verifier_round2_pull_rechecks_revocation_after_snapshot_download`.

```text
assertion `left == right` failed: a signer withdrawn before the pin transaction must not be pinned
  left: (false, 2, false)
 right: (true, 0, true)
```

Tuple: (operation returned an error, pinned version, local tree unchanged). Both the callback execution and persisted withdrawal assertions passed before this failure. The withdrawal check must be performed under the pin transaction, against the actual head's signer.

**D2 — Lost COMMIT replay clears quarantine after R's signer is withdrawn during readback (properties 2 and 5)**

Enforcement gap: `src-tauri/src/team/sync.rs:1815` checks withdrawal before calling `finish`. The manifest GET, object readback and final listing in `finish` occur afterwards (`src-tauri/src/team/sync.rs:3531`, `src-tauri/src/team/sync.rs:3543`). Its transaction at `src-tauri/src/team/sync.rs:3554` unconditionally pins R, sets AVAILABLE and clears the error without a fresh withdrawal check.

Concrete scenario: P is v1, revoked J is v2, and R=v3 lands on the server with its COMMIT reply lost. On retry, the client passes its initial signer check. A concurrent ledger writer distrusts R's signer during the final readback listing. The client then pins v3, clears SIGNER_REVOKED and swaps P into the local directory. No valid R was accepted under the trust state at the pin.

New test: `src-tauri/src/team/sync.rs:12960`, `verifier_round2_replay_rechecks_revocation_at_the_pin_transaction`.

```text
assertion `left == right` failed: withdrawn R must not pin, lift quarantine, or replace local data
  left: (false, "AVAILABLE", None, 3, false)
 right: (true, "QUARANTINED", Some("SIGNER_REVOKED"), 1, true)
```

Tuple: (operation returned an error, state, reason, pinned version, local tree unchanged). The existing pre-retry-revocation test passes because it withdraws the key before the initial check; this new test targets the unchecked interval after that check. Revalidation and the pin/quarantine mutation need one transaction.

**D3 — A refused pull overwrites local edits while advancing to P (property 4 / contract discrepancy)**

Location: `src-tauri/src/team/sync.rs:4546` enters the open-run branch, `src-tauri/src/team/sync.rs:4563` restores and pins P, then `src-tauri/src/team/sync.rs:4569` returns `sync.signerRevoked`.

Concrete scenario: a version-0 local binding has an existing profile containing an unsynced marker. The server has valid P=v1 followed by proven-revoked J=v2. Pull returns SIGNER_REVOKED, but the profile tree is replaced by P. Join delegates to the same pull path, so its binding/first-pull sequence has the same branch.

New test: `src-tauri/src/team/sync.rs:12992`, `verifier_round2_refused_pull_preserves_existing_profile`.

```text
a refused pull replaced the local profile with P
```

The error and quarantine assertions pass before the tree-preservation assertion fails. This behavior is explicitly required by the ADR's Client status paragraph at `docs/adr/0002-g2-contract-decisions.md:1553` and already asserted by `a_new_head_of_a_signer_revoked_in_this_pulls_evidence_is_refused`. It contradicts the user's unconditional property 4. It is recorded separately from the two implementation regressions; changing it requires resolving that contract conflict rather than treating the existing positive test as weakened.

**Property 1 — Only proven-revoked runs enable R: HOLDS**

src-tauri/src/team/ledger.rs:1112 verifies the revocation signature, tenant/instance, custodian-at-issue, device.revoke scope and custodian-at-first-sight; src-tauri/src/team/ledger.rs:830 records permanent counted revocations. src-tauri/src/team/sync.rs:4194 records the evaluation before walking. src-tauri/src/team/sync.rs:4130 classifies withdrawn before reported/untrusted, and src-tauri/src/team/sync.rs:3943 permits only Withdrawn links in the skipped run, with exact version/base/hash continuity. src-tauri/src/team/sync.rs:384 keeps SIGNER_REVOKED after a failed walk inside a run.

The positive and negative vectors exercise actual signed evidence as well as the pure rule. Local distrust independently enables a revert. Reported-only and lapsed links do not acquire a skip audit or lift quarantine. The timing defects below concern the accepted head's signer, rather than promotion of a reported/lapsed J into a proven run.

```text
test team::sync::tests::revert_accepts_one_proven_revoked_head ... ok
test team::sync::tests::revert_accepts_two_stacked_proven_revoked_heads ... ok
test team::sync::tests::revert_accepts_on_a_new_device_without_a_pin ... ok
test team::sync::tests::revert_refuses_a_run_with_a_lapsed_unrevoked_head ... ok
test team::sync::tests::revert_refuses_a_reported_only_revocation ... ok
test team::sync::tests::revert_refuses_a_gap_below_the_pin ... ok
test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lacked_device_revoke ... ok
test team::sync::tests::revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight ... ok
test team::sync::tests::local_distrust_alone_enables_a_revert ... ok
```

**Property 2 — Never pin a proven-revoked signer: VIOLATED**

src-tauri/src/team/sync.rs:4017 checks withdrawal during walk; src-tauri/src/team/sync.rs:1265 rechecks a restore leaf after recording its evaluation inside store_transitions' transaction (src-tauri/src/team/sync.rs:1601). The revert completion check at src-tauri/src/team/sync.rs:1815 precedes finish's network awaits. Ordinary pull pinning at src-tauri/src/team/sync.rs:4345 and revert pinning at src-tauri/src/team/sync.rs:3554 do not recheck withdrawal in their transactions.

D1 and D2 reproduce the two missing checks. Existing same-evaluation leaf and pre-replay revocation tests pass, but do not cover revocation recorded during download/readback. Both new race tests assert that the local ledger really contains the withdrawal before inspecting the resulting pin; their failures are not setup failures.

```text
test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok
test team::sync::tests::a_new_head_of_a_signer_revoked_in_this_pulls_evidence_is_refused ... ok
test team::sync::tests::a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok
test team::sync::tests::verifier_round2_pull_rechecks_revocation_after_snapshot_download ... FAILED
test team::sync::tests::verifier_round2_replay_rechecks_revocation_at_the_pin_transaction ... FAILED
```

**Property 3 — Committed R contains the newest valid P, not J or local edits: HOLDS**

src-tauri/src/team/sync.rs:2081 requires an open run and an earlier anchor payload; src-tauri/src/team/sync.rs:2113 records the run and checks the compromise/rotation block; src-tauri/src/team/sync.rs:2125 reads P using P's generation. src-tauri/src/team/sync.rs:2129 restores P into staging and src-tauri/src/team/sync.rs:2134 passes that staging path to push_inner. src-tauri/src/team/sync.rs:2946 packs the provided directory for sealing.

The marker fixtures distinguish v1/v2/v3 and unsynced 'local' content. A second device decrypts the resulting committed R and sees v1, and the multi-run case chooses v3 rather than the older v1. Local State is intentionally retained from this device under the ADR and is excluded from snapshot content. This finding is about the committer implementation: as the ADR explicitly states, a receiving client cannot establish that another valid committer's re-encrypted R originated in P.

```text
test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok
test team::sync::tests::a_revert_audits_the_accepted_runs_it_crosses ... ok
test team::sync::tests::revert_waits_for_rotation_after_a_compromised_revocation ... ok
test team::sync::tests::a_revert_keeps_the_devices_local_state ... ok
```

**Property 4 — A refused/abandoned operation preserves local profile data: VIOLATED**

src-tauri/src/team/sync.rs:1978 stages reverts and discards on refusal. src-tauri/src/team/sync.rs:4390 seeds staging with Local State; src-tauri/src/team/sync.rs:4412 restores before pinning and swaps only after a successful pin. join at src-tauri/src/team/sync.rs:2428 delegates to pull. However, src-tauri/src/team/sync.rs:4548 restores and pins an earlier valid P on an open revoked run, then src-tauri/src/team/sync.rs:4569 returns sync.signerRevoked.

The injected pin-write failures and refused checkout/abandonment tests preserve local data. D3 shows the unconditional requested property is false: an existing local marker is replaced by P even though pull returns an error and remains quarantined. This is a specification conflict, not a concealed deviation from ADR 0002: its 'Client status' paragraph explicitly requires advancement to P on an open run. The report grades the user's property literally and does not silently waive this exception.

```text
test team::sync::tests::a_pull_whose_pin_fails_keeps_the_local_profile ... ok
test team::sync::tests::a_join_whose_pin_fails_keeps_the_local_profile ... ok
test team::sync::tests::a_refused_revert_checkout_keeps_the_local_profile ... ok
test team::sync::tests::an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok
test team::sync::tests::verifier_round2_refused_pull_preserves_existing_profile ... FAILED
```

**Property 5 — Only accepting a valid R lifts SIGNER_REVOKED: VIOLATED**

src-tauri/src/team/sync.rs:3704 preserves quarantine when a lease is released. src-tauri/src/team/sync.rs:2047 replays an abandoned lease's pending release first. src-tauri/src/team/sync.rs:4571 refuses to clear a quarantine without an accepted run; src-tauri/src/team/sync.rs:4351 clears it only when lift is true. In contrast, finish at src-tauri/src/team/sync.rs:3555 unconditionally writes AVAILABLE and clears last_error_code after the out-of-transaction signer check at src-tauri/src/team/sync.rs:1815.

Abandonment and lost release alone do not clear the quarantine in the tested paths. D2 demonstrates a lost COMMIT replay clearing it after R's signer has become locally distrusted. Replaying a reply that leads to proper acceptance of a still-valid R is allowed by the ADR; the defect is acceptance after the key was withdrawn, not replay itself.

```text
test team::sync::tests::an_abandoned_revert_keeps_the_binding_quarantined ... ok
test team::sync::tests::revert_resumes_after_a_lost_release_of_an_abandoned_lease ... ok
test team::sync::tests::only_a_signer_revoked_quarantine_lets_a_pull_through ... ok
test team::sync::tests::a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok
test team::sync::tests::verifier_round2_replay_rechecks_revocation_at_the_pin_transaction ... FAILED
```

**Property 6 — After accepted R, the profile receives P: HOLDS**

src-tauri/src/team/sync.rs:3569 records accepted skip rows and a revert_swaps row in the pin transaction. src-tauri/src/team/sync.rs:1989 settles the swap after success. src-tauri/src/team/sync.rs:1901 renames staging into the profile and clears the marker after completion. Later push/pull/revert calls settle first (src-tauri/src/team/sync.rs:1676, 4510, 1987); src-tauri/src/launch.rs:150 does so before browser startup.

Successful local reverts, second-device pulls, lost COMMIT replies, missing staging before upload resume and interrupted swap states restore P. This is the recoverable filesystem protocol stated in the ADR: a crash or filesystem error can temporarily leave a committed swap pending; the next entry point settles it. It is not a claim that SQLite and filesystem renames form a single atomic transaction.

```text
test team::sync::tests::revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head ... ok
test team::sync::tests::revert_committed_here_is_accepted_by_a_second_device ... ok
test team::sync::tests::revert_resumes_after_a_lost_commit_reply ... ok
test team::sync::tests::a_crash_after_finish_completes_the_staging_swap ... ok
test team::sync::tests::a_crash_inside_the_staging_swap_resumes ... ok
test team::sync::tests::a_resumed_revert_whose_staging_is_gone_restores_p_again ... ok
test team::sync::tests::a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull ... ok
```

**Property 7 — Sticky revocation rejects backdated self-renewal and alerts once: HOLDS**

src-tauri/src/team/ledger.rs:273 loads counted-evaluation cutoffs; src-tauri/src/team/ledger.rs:330 drops later-first-seen containers from a withdrawn issuer regardless of issued_at_ms. Only DEVICE_REVOCATION cutoffs trigger the alert (src-tauri/src/team/ledger.rs:292). src-tauri/src/team/ledger.rs:405 inserts the first alert only. src-tauri/src/team/db.rs:1324 defines the schema-9 per-instance/tenant/kind/key primary key, with immutable/retained-row triggers at src-tauri/src/team/db.rs:1375.

The tests inspect the persisted custody record before and after renewal, exact alert identity/container/time, repeated distinct renewals and reopening. Earlier-first-seen records remain valid as required. No additional test was necessary for the observed implementation path.

```text
test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok
test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok
test custody_tests::revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok
test custody_tests::records_first_seen_before_a_count_keep_their_standing ... ok
test team::db::tests::renewed_after_revocation_alerts_refuse_delete_and_replace ... ok
test team::db::tests::a_version_8_file_migrates_to_version_9_and_reopens ... ok
```

**Property 8 — Only a renewal verified under the revoked key raises that alert: HOLDS**

src-tauri/src/team/ledger.rs:67 derives the evidence key map by each public key's identifier. src-tauri/src/team/ledger.rs:394 verifies the container under the named issuer key before reading the verified payload. src-tauri/src/team/ledger.rs:400 requires a non-bootstrap root grant whose subject signing key equals that issuer.

Coverage includes a container claiming D as issuer but signed by another key, a genuine container without D's public key in evidence, renewal by another custodian, a grant by D for another subject, and local distrust without a counted signed revocation. The genuine bounded-renewal test provides the positive control.

```text
test custody_tests::renewed_after_revocation_is_not_raised_for_a_forged_container ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok
test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok
```

**Property 9 — Discard decrypted revert staging on refusal, abandonment, delete and unbind: HOLDS**

src-tauri/src/team/sync.rs:1994 invokes discard_revert_staging on error. src-tauri/src/team/sync.rs:1946 retains staging only for a pending swap or an upload under the held lease without a matching pending RELEASE. src-tauri/src/team/downgrade.rs:1248 settles and discards staging before unbind. src-tauri/src/lib.rs:870 settles first and src-tauri/src/lib.rs:873 unconditionally removes the staging sibling on profile delete, including with a held lease.

Tests inspect the staging path, local tree, pending RELEASE and server lease after a lost release. Delete/unbind tests invoke the actual command/helper with fixture profiles. As expressly allowed by the ADR, interrupted resumable uploads and committed-but-unsettled swaps can retain staging; these are not abandoned leases. The absent-staging resume path reconstructs P.

```text
test team::sync::tests::a_refused_revert_discards_its_staging ... ok
test team::sync::tests::an_abandoned_revert_lease_discards_its_staging ... ok
test team::sync::tests::an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok
test team::sync::tests::deleting_or_unbinding_a_profile_discards_its_revert_staging ... ok
test team::sync::tests::a_resumed_revert_whose_staging_is_gone_restores_p_again ... ok
```

**Property 10 — Team join proves the restore leaf, gates checkout and retains recovery: HOLDS**

src-tauri/src/sync_cmd.rs:542 takes the local mutation claim and calls join. src-tauri/src/team/sync.rs:2392 derives E or E-1 from the listing/v1 and inserts a version-0 binding; pull then verifies it. src-tauri/src/team/sync.rs:1224 follows the signed chain to the leaf; src-tauri/src/team/sync.rs:1407 checks intervening signatures/IDs/epoch. src-tauri/src/team/sync.rs:1305 verifies the custodian-signed transition, src-tauri/src/team/sync.rs:1446 checks inclusion, and src-tauri/src/team/sync.rs:1265 rechecks the leaf after ledger recording in the transaction. src-tauri/src/team/sync.rs:1774 computes base_version < remote_version; src-tauri/src/team/sync.rs:2812 refuses a fresh checkout and src-tauri/src/team/sync.rs:2859 releases a replay when behind. src-tauri/src/team/sync.rs:3724 allows unbind independently of quarantine reason.

This is the ADR's restore-leaf exception: profiles created after a restore, and epoch-0 profiles with no restore, still use ordinary first-head verification. Existing tests cover a revoked leaf, rolled-back child, lying initial epoch, post-restore commits, failed first restore, lost checkout and recovery by pull/push or unbind. The new invalid-transition join test adds explicit unbind recovery after cryptographic transition refusal. D1 remains an independent ordinary pull pinning defect under property 2; the transition-leaf transaction itself has the required in-transaction guard.

```text
test team::sync::tests::join_after_a_restore_pins_the_transition_leaf_then_pulls ... ok
test team::sync::tests::join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf ... ok
test team::sync::tests::join_refuses_the_rolled_back_child_of_the_leaf ... ok
test team::sync::tests::join_with_a_lying_first_snapshot_pins_nothing ... ok
test team::sync::tests::join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes ... ok
test team::sync::tests::join_then_a_push_before_the_first_pull_restores_is_refused ... ok
test team::sync::tests::join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes ... ok
test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok
test team::sync::tests::verifier_round2_invalid_transition_join_can_unbind ... ok
```

**New test code retained in the working copy**

All four tests are in `src-tauri/src/team/sync.rs:12917` and reuse the existing `World`, signed-manifest/evidence builders, tree comparison and SQL distrust helper. The positive test extends join recovery coverage after an invalid signed transition. The other three preserve the requested invariant as their assertion and fail at this HEAD.

```rust
    // Independent verification probes, round 2. Assert the requested invariants.
    #[test]
    fn verifier_round2_invalid_transition_join_can_unbind() {
        let (w, d, _, _) = joinable_after_restore(0);
        *w.fake().epoch_files.get_mut(&epoch_path(0)).unwrap().last_mut().unwrap() ^= 1;
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(has(&err, "sync.epochTransitionInvalid"));
        assert_eq!(w.state(LOCAL).3, 0, "no unproven leaf pinned");
        assert!(tree(&out) == before);
        assert!(w.push_from(&out).is_err());
        assert!(w.sent("POST", "/checkout").is_empty());
        unbind(LOCAL, SERVER, NOW).unwrap();
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert!(tree(&out) == before, "unbind remains a way forward");
        assert!(!beside(&out, ".revert-staging").exists());
    }

    #[test]
    fn verifier_round2_pull_rechecks_revocation_after_snapshot_download() {
        let w = world();
        chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        w.fake().on_snapshot = Some(distrust_author());
        let result = w.pull(&out);
        assert!(w.fake().on_snapshot.is_none(), "download hook executed");
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap());
        assert_eq!(
            (result.is_err(), w.state(LOCAL).3, tree(&out) == before),
            (true, 0, true),
            "a signer withdrawn before the pin transaction must not be pinned"
        );
    }

    #[test]
    fn verifier_round2_replay_rechecks_revocation_at_the_pin_transaction() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        w.fake().lose.push("commit");
        w.revert(&udd).unwrap_err();
        assert_eq!(w.fake().version, 3);
        assert_eq!(w.state(LOCAL).3, 1);
        let before = tree(&udd);
        // Another local ledger writer withdraws R's signer while finish awaits
        // its final readback. Reuse the fixture's existing concurrent-writer hook.
        w.fake().on_list = Some(distrust_author().replace(
            &hex(&key_id_of(&author())),
            &hex(&w.me.to.signing_key_id),
        ));
        let result = w.revert(&udd);
        assert!(w.fake().on_list.is_none(), "readback hook executed");
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id).unwrap());
        let (state, reason, _, version, _) = w.state(LOCAL);
        assert_eq!(
            (
                result.is_err(),
                state.as_str(),
                reason.as_deref(),
                version,
                tree(&udd) == before,
            ),
            (true, "QUARANTINED", Some("SIGNER_REVOKED"), 1, true),
            "withdrawn R must not pin, lift quarantine, or replace local data"
        );
    }

    #[test]
    fn verifier_round2_refused_pull_preserves_existing_profile() {
        let w = world();
        chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"unsynced local edit").unwrap();
        let before = tree(&out);
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"));
        assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
        assert!(
            tree(&out) == before,
            "a refused pull replaced the local profile with P"
        );
    }
```

The only test-fixture extension is the optional callback field at `src-tauri/src/team/sync.rs:4877` and its execution in the local server handler at line 5403. Its default is None, leaving existing tests unchanged:

```rust
// Added to Fake:
/// Independent verifier: another ledger writer during snapshot download.
on_snapshot: Option<String>,

// Added to handle, before serving the response:
if method == Method::GET && parts.len() == 5 && parts[3] == "snapshots" {
    if let Some(sql) = f.on_snapshot.take() {
        let c = rusqlite::Connection::open(Db::path().unwrap()).unwrap();
        assert_eq!(c.execute(&sql, []).unwrap(), 1);
    }
}
```

**Final new-probe output**

```text
running 4 tests
test team::sync::tests::verifier_round2_invalid_transition_join_can_unbind ... ok
test team::sync::tests::verifier_round2_pull_rechecks_revocation_after_snapshot_download ... FAILED
test team::sync::tests::verifier_round2_refused_pull_preserves_existing_profile ... FAILED
test team::sync::tests::verifier_round2_replay_rechecks_revocation_at_the_pin_transaction ... FAILED

failures:

---- team::sync::tests::verifier_round2_pull_rechecks_revocation_after_snapshot_download stdout ----

thread 'team::sync::tests::verifier_round2_pull_rechecks_revocation_after_snapshot_download' (21968) panicked at src\team\sync.rs:12952:9:
assertion `left == right` failed: a signer withdrawn before the pin transaction must not be pinned
  left: (false, 2, false)
 right: (true, 0, true)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

---- team::sync::tests::verifier_round2_refused_pull_preserves_existing_profile stdout ----

thread 'team::sync::tests::verifier_round2_refused_pull_preserves_existing_profile' (39732) panicked at src\team\sync.rs:13004:9:
a refused pull replaced the local profile with P

---- team::sync::tests::verifier_round2_replay_rechecks_revocation_at_the_pin_transaction stdout ----

thread 'team::sync::tests::verifier_round2_replay_rechecks_revocation_at_the_pin_transaction' (11596) panicked at src\team\sync.rs:12978:9:
assertion `left == right` failed: withdrawn R must not pin, lift quarantine, or replace local data
  left: (false, "AVAILABLE", None, 3, false)
 right: (true, "QUARANTINED", Some("SIGNER_REVOKED"), 1, true)


failures:
    team::sync::tests::verifier_round2_pull_rechecks_revocation_after_snapshot_download
    team::sync::tests::verifier_round2_refused_pull_preserves_existing_profile
    team::sync::tests::verifier_round2_replay_rechecks_revocation_at_the_pin_transaction

test result: FAILED. 1 passed; 3 failed; 0 ignored; 0 measured; 626 filtered out; finished in 12.99s

error: test failed, to rerun pass `--lib`
```

`git diff --check` passed. No production fix was applied as part of this independent verification.

VERDICT: FAIL
