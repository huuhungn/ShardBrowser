#!/usr/bin/env python3
"""Mutation check for the WP-5 journals and the launcher downgrade flow.

Applies ONE mutation at a time to `src-tauri/src/team/journal.rs` or
`downgrade.rs`, runs the module's tests, and reverts. A mutant is killed when
the tests fail, survives when they pass, and is invalid when the mutated file
does not compile (those are not counted). Before the first mutation the SHA-256
of both files is recorded; after every revert it is checked again, and the run
stops on a mismatch.

    CARGO_TARGET_DIR=<dir> python scripts/g2-wp5-mutants.py [--list] [--dry-run] [--only ID ...]

`--dry-run` only checks that every pattern matches exactly once.

Not mutated, because no test can observe the difference:
- the directory and file flushes (`durable::sync_parent`, `sync_all`): they only
  matter across a power cut, and the tests kill the process, not the machine;
- `store::require_local_ntfs(archive)`: it passes on every local NTFS test dir;
- `volume_serial` itself: a test run has one volume.
- `migrate.rs` and `runtime.rs`: this script only mutates the two files in
  `team/`. Their checks (`migrate::guarded`, the lock in
  `runtime::migrate_all_to`) are mutated by hand against their own tests.

Some mutants survive by design; each removes a check that a second check
repeats, so no behaviour changes (EQUIVALENT below).
"""
import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src-tauri" / "src" / "team"
J, D = "journal.rs", "downgrade.rs"

# (id, file, old, new). `old` must occur exactly once in `file`.
MUTANTS = [
    # --- journals: restore chain ---------------------------------------------
    ("J01-restore-skip", J, "RESTORE_FORWARD.get(i + 1)", "RESTORE_FORWARD.get(i + 2)"),
    ("J02-restore-rollback-closed", J,
     "(_, Self::RollbackRequired) => true,\n            _ => {\n                let at = RESTORE_FORWARD",
     "(_, Self::RollbackRequired) => false,\n            _ => {\n                let at = RESTORE_FORWARD"),
    ("J03-restore-swap-resume", J,
     "Self::SwapStarted | Self::RollbackRequired => Resume::Rollback,",
     "Self::SwapStarted | Self::RollbackRequired => Resume::Continue,"),
    ("J04-restore-second-flow", J,
     "let tx = txn(db)?;\n    refuse_second_flow(&tx, &journal.local_profile_id)?;",
     "let tx = txn(db)?;"),
    ("J05-restore-integer-range", J,
     "let version = i64::try_from(journal.target_version).map_err(|_| {\n        anyhow!(code_with(\n            \"journal.outOfRange\",\n            &[(\"field\", \"target_version\")]\n        ))\n    })?;",
     "let version = journal.target_version as i64;"),
    ("J06-restore-retire-open", J,
     "if !current.phase.is_terminal() {\n        bail!(code_with(\n            \"journal.notSettled\",",
     "if false && !current.phase.is_terminal() {\n        bail!(code_with(\n            \"journal.notSettled\","),
    ("J07-restore-any-transition", J, "if !current.phase.allows(to) {", "if false {"),
    ("J08-restore-open-lists-all", J,
     "if !journal.phase.is_terminal() {\n            open.push(journal);\n        }\n    }\n    Ok(open)\n}\n\n/// Writes a new journal at `CREATED`",
     "if true {\n            open.push(journal);\n        }\n    }\n    Ok(open)\n}\n\n/// Writes a new journal at `CREATED`"),
    ("J09-restore-readback", J,
     "if &stored != journal {\n        bail!(mismatch(\"journal\"));\n    }\n    tx.commit()?;\n    Ok(())\n}\n\n/// Moves the journal of `local`",
     "tx.commit()?;\n    Ok(())\n}\n\n/// Moves the journal of `local`"),
    ("J10-restore-advance-readback", J,
     "if stored.phase != to\n        || stored\n",
     "if stored.phase != to\n        && false\n        && stored\n"),
    ("J11-restore-retire-readback", J,
     "if restore_in(&tx, local)?.is_some() {\n        bail!(mismatch(\"row\"));",
     "if false && restore_in(&tx, local)?.is_some() {\n        bail!(mismatch(\"row\"));"),
    # --- journals: downgrade chain -------------------------------------------
    ("J12-down-rollback-closed", J,
     "(_, Self::RollbackRequired) => true,\n            _ => {\n                let chain",
     "(_, Self::RollbackRequired) => false,\n            _ => {\n                let chain"),
    ("J13-down-mixed-chains", J, "Mode::Clone => &CLONE_CHAIN,", "Mode::Clone => &PRE_V2_CHAIN,"),
    ("J14-down-needs-metadata", J,
     "(_, P::OriginalMetadataMoved) => metadata,", "(_, P::OriginalMetadataMoved) => true,"),
    ("J15-down-needs-readback", J,
     "journal.new_local_profile_id.is_some() && journal.discovery_readback_sha256.is_some()\n        }",
     "journal.new_local_profile_id.is_some()\n        }"),
    ("J16-down-needs-manifest", J,
     "journal.pre_v2_manifest_sha256.is_some()\n        }\n        (Mode::PreV2Restore",
     "true\n        }\n        (Mode::PreV2Restore"),
    ("J17-down-needs-binding", J,
     "if !bound {\n        bail!(code(\"journal.notBound\"));",
     "if false && !bound {\n        bail!(code(\"journal.notBound\"));"),
    ("J18-flow-taken-sql", J,
     "WHERE original_local_profile_id = ?1 AND phase <> 'ROLLED_BACK')",
     "WHERE original_local_profile_id = ?1 AND phase <> 'COMPLETED')"),
    ("J19-down-readback", J,
     "if &stored != journal {\n        bail!(mismatch(\"journal\"));\n    }\n    tx.commit()?;\n    Ok(())\n}\n\n/// Moves the journal `id`",
     "tx.commit()?;\n    Ok(())\n}\n\n/// Moves the journal `id`"),
    ("J20-down-advance-readback", J, "if stored != next {", "if false {"),
    ("J21-down-resume-rollback", J,
     "Self::RollbackRequired => Resume::Rollback,\n            Self::Completed | Self::RolledBack => Resume::Settled,\n            _ => Resume::Continue,",
     "Self::RollbackRequired => Resume::Continue,\n            Self::Completed | Self::RolledBack => Resume::Settled,\n            _ => Resume::Continue,"),
    ("J22-down-open-lists-all", J,
     "if !journal.phase.is_terminal() {\n            open.push(journal);\n        }\n    }\n    Ok(open)\n}\n\n/// What each phase needs",
     "if true {\n            open.push(journal);\n        }\n    }\n    Ok(open)\n}\n\n/// What each phase needs"),
    ("J23-down-any-transition", J,
     "if !current.phase.allows(current.mode, to) {", "if false {"),
    # --- downgrade: moves ----------------------------------------------------
    ("D01-overwrite-archive", D,
     "(true, true) => bail!(code(\"downgrade.archiveConflict\")),\n        (false, false)",
     "(true, true) => Ok(()),\n        (false, false)"),
    ("D02-prove-archived", D,
     "if !exists(&w.metadata_dst) || !exists(&w.data_dst) {\n        bail!(code(\"downgrade.originalGone\"));\n    }\n    outside_discovery",
     "if false {\n        bail!(code(\"downgrade.originalGone\"));\n    }\n    outside_discovery"),
    ("D03-prove-not-discoverable", D,
     "if discover()?.mentions(&j.original_local_profile_id) {\n        bail!(code(\"downgrade.stillDiscoverable\"));",
     "if false && discover()?.mentions(&j.original_local_profile_id) {\n        bail!(code(\"downgrade.stillDiscoverable\"));"),
    ("D04-archive-outside-discovery", D,
     "if inside.starts_with(root) {",
     "if false && inside.starts_with(root) {"),
    ("D04b-archive-outside-data-roots", D,
     "roots.extend([profiles, data, trash]);", "roots.extend([profiles]);"),
    ("D05-archive-paths-metadata", D,
     "if *metadata != metadata_dst.display().to_string() || *data != data_dst.display().to_string() {",
     "if *data != data_dst.display().to_string() {"),
    ("D06-archive-paths-data", D,
     "if *metadata != metadata_dst.display().to_string() || *data != data_dst.display().to_string() {",
     "if *metadata != metadata_dst.display().to_string() {"),
    ("D06b-archive-paths-any", D,
     "if *metadata != metadata_dst.display().to_string() || *data != data_dst.display().to_string() {",
     "if false {"),
    ("D07-journal-id-length", D, "if id.len() != 32 ||", "if false ||"),
    ("D07b-journal-id-hex", D,
     "|| !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {", "|| false {"),
    ("D08-original-id-path", D, "valid_id(original)?;\n    valid_id(new)?;", "valid_id(new)?;"),
    ("D09-new-id-path", D, "valid_id(original)?;\n    valid_id(new)?;", "valid_id(original)?;"),
    ("D09b-id-canonical", D,
     ".is_ok_and(|u| u.hyphenated().to_string() == id)", ".is_ok()"),
    ("D10-empty-user-data", D, "return make_dir(&w.data_dst);", "return Ok(());"),
    # --- downgrade: start ----------------------------------------------------
    ("D11-start-binding", D,
     "let db = Db::open()?;\n    binding_facts(&db, local)?;\n    if pending_work",
     "let db = Db::open()?;\n    if pending_work"),
    ("D12-start-pending", D, "if pending_work(&db, local)? > 0 {", "if false {"),
    ("D13-start-temporary", D, "p.meta.id == local && !p.meta.temporary", "p.meta.id == local"),
    ("D14-start-record-id", D, "p.meta.id == local && !p.meta.temporary", "!p.meta.temporary"),
    ("D15-constant-id", D,
     "    Ok(uuid::Builder::from_random_bytes(bytes)\n        .into_uuid()\n        .to_string())",
     "    let _ = bytes;\n    Ok(\"00000000-0000-4000-8000-000000000000\".to_string())"),
    ("D16-lease", D, "if lease.is_some() {", "if false {"),
    # --- downgrade: the clone ------------------------------------------------
    ("D17-marker-keys", D, "if keys.iter().any(|k| MARKER_KEYS.contains(&k.as_str()))", "if false"),
    ("D18-marker-values", D, "!bad.is_empty() && v.contains(bad.as_str())", "false"),
    ("D19-strip-markers", D,
     "for key in MARKER_KEYS {\n        stored.config.remove(key);\n    }",
     "for key in MARKER_KEYS {\n        let _ = key;\n    }"),
    ("D20-copy-skips-team-sync", D, "if top && name.starts_with(\"team-sync\") {", "if false && name.starts_with(\"team-sync\") {"),
    ("D21-listing-skips-team-sync", D,
     "if skip_team && dir == root && name.starts_with(\"team-sync\") {", "if false {"),
    ("D22-existing-copy-compared", D, "} else if listing(&w.clone_data, false)? != archived {", "} else if false {"),
    ("D23-existing-record-id", D,
     "if require_clean(&body, &forbidden)?.meta.id != new {", "if false {"),
    ("D24-readback-lists", D, "if !found.lists(new) ||", "if false ||"),
    ("D25-readback-user-data", D, "|| !found.has_data(new)", "|| false"),
    ("D26-readback-old-id", D,
     "|| found.mentions(&j.original_local_profile_id) {",
     "|| false {"),
    ("D27-readback-listing", D, "if !listed.iter().any(|p| p.id == new)", "if false"),
    # --- downgrade: rollback and resume -------------------------------------
    ("D28-rollback-overwrite", D,
     "if exists(dst) {\n            if exists(src) {\n                bail!(code(\"downgrade.rollbackConflict\"));",
     "if exists(dst) {\n            if false && exists(src) {\n                bail!(code(\"downgrade.rollbackConflict\"));"),
    ("D29-rollback-foreign-clone", D,
     ".is_ok_and(|p| Some(p.meta.id) == j.new_local_profile_id);", ".is_ok_and(|_| true);"),
    ("D31-conflict-keeps-going", D,
     "let _ = journal::downgrade_advance(\n                    &db,\n                    &j.journal_id,\n                    Phase::RollbackRequired,\n                    Patch::default(),\n                );",
     ""),
    ("D32-rollback-completed", D,
     "    if j.phase == Phase::Completed {\n        bail!(code_with(", "    if false {\n        bail!(code_with("),
    ("D33-pre-v2-as-clone", D,
     "Mode::PreV2Restore => Err(anyhow!(code(\"downgrade.preV2Unsupported\"))),",
     "Mode::PreV2Restore => run_clone(&j.journal_id),"),
    ("D34-clone-mode", D, "if peek.mode != Mode::Clone {\n        bail!(code(\"downgrade.notClone\"));", "if false {\n        bail!(code(\"downgrade.notClone\"));"),
    ("D35-unbind-flow", D,
     "if Db::path()?.exists() && journal::flow_taken(&Db::open()?, local)? {", "if false {"),
    # --- downgrade: readiness -----------------------------------------------
    ("D36-ready-running", D, "crate::process::Tracker::shared().running().len() as u64,", "0,"),
    ("D37-ready-needs-db", D, "    if Db::path()?.exists() {\n        let db = Db::open()?;\n        let count", "    if true {\n        let db = Db::open()?;\n        let count"),
    ("D38-ready-lease", D, "WHERE lease_id IS NOT NULL", "WHERE lease_id IS NULL"),
    ("D39-ready-operations", D,
     "WHERE state IN ('PENDING', 'RUNNING', 'AWAITING_RETRY'))\n                      +",
     "WHERE state IN ('PENDING'))\n                      +"),
    ("D40-ready-uploads", D,
     "WHERE state IN ('OPEN', 'FINALIZING', 'READY'))\",\n            )?,",
     "WHERE state IN ('OPEN'))\",\n            )?,"),
    ("D41-ready-spool", D, "entries.count() as u64", "0"),
    ("D42-ready-restore-journal", D,
     "count(\"SELECT count(*) FROM restore_journals\")", "count(\"SELECT count(*) FROM restore_journals WHERE 0\")"),
    ("D43-ready-open-downgrade", D,
     "WHERE phase NOT IN ('COMPLETED', 'ROLLED_BACK')\",",
     "WHERE phase NOT IN ('COMPLETED', 'ROLLED_BACK', 'CLAIMED')\","),
    ("D44-ready-unfinished", D, "AND d.phase = 'COMPLETED')", "AND d.phase = 'CLAIMED')"),
    ("D45-ready-two-clones", D, "HAVING count(*) > 1))", "HAVING count(*) > 2))"),
    ("D46-ready-unbind-on-clone", D,
     "WHERE o.kind = 'UNBIND' AND o.state = 'COMPLETED'\n                               AND o.local_profile_id_at_request = d.original_local_profile_id))",
     "WHERE o.kind = 'RELEASE' AND o.state = 'COMPLETED'\n                               AND o.local_profile_id_at_request = d.original_local_profile_id))"),
    ("D47-ready-evidence", D,
     "if j.mode == Mode::Clone && !clone_holds(&j, &found) {", "if j.mode == Mode::Clone && clone_holds(&j, &found) {"),
    ("D48-evidence-digest", D,
     "j.discovery_readback_sha256 == Some(readback_digest(j))\n        &&", "true\n        &&"),
    ("D49-evidence-archive", D,
     "places(j).is_ok_and(|w| exists(&w.metadata_dst) && exists(&w.data_dst))", "places(j).is_ok()"),
    ("D50-evidence-clone-listed", D, "        && found.lists(new)\n        && !found", "        && true\n        && !found"),
    ("D51-evidence-old-id", D,
     "&& !found.mentions(&j.original_local_profile_id)\n}", "&& true\n}"),
    # --- review fixes: layout, claims, rollback, guards --------------------------
    ("D52-legacy-roots", D,
     "config.join(\"profiles\"),\n        config.join(\"user-data\"),",
     "store::profiles_dir()?,\n        store::user_data_root()?,"),
    ("D53-data-root-scan", D,
     "if !same_dir(&store::data_root()?, &config) {", "if false {"),
    ("D54-data-root-moved", D,
     "if !same_dir(&store::data_root()?, &store::config_root()?) {", "if false {"),
    ("D55-start-layout", D, "    require_legacy_layout()?;\n    let new = random_id()?;", "    let new = random_id()?;"),
    ("D56-restorable-two-places", D,
     "if (in_place && archived) || (clone_present && !in_place && !archived) {",
     "if clone_present && !in_place && !archived {"),
    ("D57-restorable-nowhere", D,
     "if (in_place && archived) || (clone_present && !in_place && !archived) {",
     "if in_place && archived {"),
    ("D58-restorable-clone-record", D, "        if !ours {\n            return Err(conflict());", "        if false {\n            return Err(conflict());"),
    ("D60-rollback-unchecked", D, "    check_restorable(&j, w)?;\n", ""),
    ("D61-original-gone-after-clone", D,
     "&& !(clone_exists && *key == \"downgrade.originalGone\"))", ")"),
    ("D62-clone-exists-phase", D,
     "let clone_exists = matches!(phase, Phase::CloneWritten | Phase::ReadbackPassed);",
     "let clone_exists = false;"),
    ("D62b-clone-exists-readback", D,
     "matches!(phase, Phase::CloneWritten | Phase::ReadbackPassed)", "matches!(phase, Phase::CloneWritten)"),
    ("D63-reread-after-claim", D,
     "    let j = find(&db)?;\n    if j.original_local_profile_id", "    let j = peek.clone();\n    if j.original_local_profile_id"),
    ("D64-claim-covers-clone", D,
     "let _claim = claim(local, Some(&new))?;", "let _claim = claim(local, None)?;"),
    ("D65-resume-claims-clone", D,
     "peek.new_local_profile_id.as_deref(),\n    )?;", "None,\n    )?;"),
    ("D66-start-idle", D, "        listing(&data, false)?;\n        prove_idle(&data)?;", "        listing(&data, false)?;"),
    ("D67-start-links", D, "        listing(&data, false)?;\n        prove_idle(&data)?;", "        prove_idle(&data)?;"),
    ("D68-start-volume", D, "    same_volume(&data, &archive)?;\n", ""),
    ("D69-claimed-idle", D, "                    prove_idle(&w.data_src)?;\n                    prove_unlocked(&w)?;", "                    prove_unlocked(&w)?;"),
    ("D70-metadata-moved-idle", D,
     "                    prove_idle(&w.data_src)?;\n                    move_data(&w)?;", "                    move_data(&w)?;"),
    ("D71-claimed-volume", D, "                    same_volume(&w.data_src, &w.dir)?;\n", ""),
    ("D72-one-volume", D, "if !serials.windows(2).all(|pair| pair[0] == pair[1]) {", "if false {"),
    ("D73-idle-lock", D, "if exists(&lock) && free.is_err() {", "if false {"),
    ("D74-move-replaces", D,
     "durable::move_new(src, dst).with_context(", "durable::replace_file(src, dst).with_context("),
    ("D75-journals-exist-restore", D,
     "              + (SELECT count(*) FROM restore_journals)\",", "              + 0\","),
    ("D76-journals-exist-rolled-back", D,
     "WHERE phase <> 'ROLLED_BACK')", "WHERE phase <> 'COMPLETED')"),
    ("D77-journals-exist-none", D, "    Ok(count > 0)\n}\n\n/// What a resume", "    Ok(false)\n}\n\n/// What a resume"),
    # --- second review: retire, trial move, migration ---------------------------
    ("D78-retire-record-deleted", D,
     "    retire(&w.clone_metadata, &w.retired_metadata)?;\n",
     "    if exists(&w.clone_metadata) {\n        std::fs::remove_file(&w.clone_metadata)?;\n    }\n"),
    ("D79-retire-data-deleted", D,
     "    retire(&w.clone_data, &w.retired_data)?;\n",
     "    if exists(&w.clone_data) {\n        std::fs::remove_dir_all(&w.clone_data)?;\n    }\n"),
    ("D80-retire-record-skipped", D, "    retire(&w.clone_metadata, &w.retired_metadata)?;\n", ""),
    ("D81-retired-twice-data", D,
     "\n        || (exists(&w.clone_data) && exists(&w.retired_data))\n", "\n"),
    ("D82-settle-in-rollback", D, "    settle_probe(w)?;\n    check_restorable", "    check_restorable"),
    ("D83-settle-in-drive", D, "    settle_probe(&w)?;\n    point(\"claim_held\")?;", "    point(\"claim_held\")?;"),
    ("D84-unlocked-step", D, "                    prove_unlocked(&w)?;\n", ""),
    ("D85-unlocked-code", D, ".map_err(|_| anyhow!(code(\"downgrade.dataInUse\")))?;", "?;"),
    ("D86-unlocked-back", D, "    move_new(&w.probe, &w.data_src)\n}", "    Ok(())\n}"),
    ("D87-settle-moves-back", D, "(true, false) => move_new(&w.probe, &w.data_src),", "(true, false) => Ok(()),"),
    ("D88-settle-both", D,
     "(true, true) => bail!(code(\"downgrade.archiveConflict\")),\n        _ => Ok(()),",
     "(true, true) => Ok(()),\n        _ => Ok(()),"),
    ("D89-staging-kept", D,
     "if exists(&w.clone_staging) && exists(&w.data_dst) {", "if false {"),
    ("D90-migrating-flag", D, "    if crate::migrate::in_progress() {\n        bail!(code(\"downgrade.migrating\"));",
     "    if false {\n        bail!(code(\"downgrade.migrating\"));"),
    ("D91-unbind-migrating", D, "    valid_id(local)?;\n    refuse_while_migrating()?;", "    valid_id(local)?;"),
    ("D92-start-begin", D,
     "    valid_id(local)?;\n    let _flow = begin()?;", "    valid_id(local)?;\n    let _flow = exclusive();"),
    ("D93-run-begin", D,
     "pub(crate) fn run_clone(journal_id: &str) -> Result<CloneDone> {\n    let _flow = begin()?;",
     "pub(crate) fn run_clone(journal_id: &str) -> Result<CloneDone> {\n    let _flow = exclusive();"),
    ("D94-rollback-begin", D,
     "pub(crate) fn roll_back_clone(journal_id: &str) -> Result<CloneDone> {\n    let _flow = begin()?;",
     "pub(crate) fn roll_back_clone(journal_id: &str) -> Result<CloneDone> {\n    let _flow = exclusive();"),
]


EQUIVALENT = {
    # `profile::list_all` (D27) refuses the same state a line later.
    "D24-readback-lists",
    # `journal::downgrade_advance` refuses a rollback from COMPLETED anyway.
    "D32-rollback-completed",
    # `check_restorable` refuses a state with the original in two places before
    # the loop runs, and `move_new` refuses to replace it a step later.
    "D28-rollback-overwrite",
    # The volume check of the start repeats in `drive` (D71), and a test run
    # has one volume: only `one_volume` and `same_volume` are observable.
    "D68-start-volume",
    "D71-claimed-volume",
    # On Windows the trial move of `prove_unlocked` refuses a held lockfile too;
    # `prove_idle` is the check that matters elsewhere.
    "D69-claimed-idle",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_tests(mod):
    filt = "team::journal" if mod == J else "team::downgrade"
    return subprocess.run(
        ["cargo", "test", "-j", "1", "--lib", "--", filt, "--skip", "a_process_killed"],
        cwd=ROOT / "src-tauri", capture_output=True, text=True, env=os.environ.copy(),
    )


def main(argv):
    if "--list" in argv:
        for m in MUTANTS:
            print(m[0], m[1])
        return 0
    only = argv[argv.index("--only") + 1:] if "--only" in argv else None
    chosen = [m for m in MUTANTS if only is None or m[0] in only]
    bad = 0
    originals = {f: (SRC / f).read_bytes() for f in (J, D)}
    digests = {f: hashlib.sha256(b).hexdigest() for f, b in originals.items()}
    for mid, f, old, new in chosen:
        text = originals[f].decode("utf-8")
        nl = "\r\n" if "\r\n" in text else "\n"
        o, n = old.replace("\n", nl), new.replace("\n", nl)
        if text.count(o) != 1:
            print(f"BAD-PATTERN {mid}: {text.count(o)} matches")
            bad += 1
    if bad:
        return 2
    if "--dry-run" in argv:
        print(f"{len(chosen)} patterns match exactly once")
        return 0
    if "CARGO_TARGET_DIR" not in os.environ:
        print("set CARGO_TARGET_DIR")
        return 2
    killed = survived = invalid = 0
    results = []
    try:
        for mid, f, old, new in chosen:
            path = SRC / f
            text = originals[f].decode("utf-8")
            nl = "\r\n" if "\r\n" in text else "\n"
            path.write_bytes(text.replace(old.replace("\n", nl), new.replace("\n", nl), 1).encode("utf-8"))
            try:
                out = run_tests(f)
            finally:
                path.write_bytes(originals[f])
            if sha(path) != digests[f]:
                print(f"RESTORE FAILED for {f}")
                return 3
            body = out.stdout + out.stderr
            if out.returncode != 0 and "could not compile" in body:
                status = "invalid"
                invalid += 1
            elif out.returncode != 0:
                status = "killed"
                killed += 1
            else:
                status = "SURVIVED"
                survived += 1
            results.append((mid, status))
            print(f"{status:9} {mid}", flush=True)
    finally:
        for f, b in originals.items():
            (SRC / f).write_bytes(b)
        for f in (J, D):
            assert sha(SRC / f) == digests[f], f"{f} not restored"
    counted = killed + survived
    print(f"killed {killed}/{counted} (invalid, not counted: {invalid}); sha256 of both files restored")
    open_ones = [m for m, status in results if status == "SURVIVED" and m not in EQUIVALENT]
    return 1 if open_ones else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
