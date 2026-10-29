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
- the symlink guard in `move_data` (unix-only test).
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
     "let version = i64::try_from(journal.target_version)\n        .map_err(|_| anyhow!(code_with(\"journal.outOfRange\", &[(\"field\", \"target_version\")])))?;",
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
     "if stored.phase != to || stored != (RestoreJournal { phase: to, ..current }) {",
     "if false {"),
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
     "(true, true) => bail!(code(\"downgrade.archiveConflict\")),", "(true, true) => Ok(()),"),
    ("D02-prove-archived", D,
     "if !exists(&w.metadata_dst) || !exists(&w.data_dst) {\n        bail!(code(\"downgrade.originalGone\"));\n    }\n    outside_discovery",
     "if false {\n        bail!(code(\"downgrade.originalGone\"));\n    }\n    outside_discovery"),
    ("D03-prove-not-discoverable", D,
     "if discover()?.mentions(&j.original_local_profile_id) {\n        bail!(code(\"downgrade.stillDiscoverable\"));",
     "if false && discover()?.mentions(&j.original_local_profile_id) {\n        bail!(code(\"downgrade.stillDiscoverable\"));"),
    ("D04-archive-outside-discovery", D,
     "if inside.starts_with(std::fs::canonicalize(root)?) {",
     "if false && inside.starts_with(std::fs::canonicalize(root)?) {"),
    ("D05-archive-prefix", D, "let tidy = |p: &Path| p.starts_with(&dir) &&", "let tidy = |p: &Path| true &&"),
    ("D06-archive-dotdot", D,
     "!p.components().any(|c| c.as_os_str() == \"..\")", "true"),
    ("D07-journal-id-path", D, "|| j.journal_id.contains(['/', '\\\\', '.'])", "|| false"),
    ("D08-original-id-path", D, "valid_id(&j.original_local_profile_id)?;\n    valid_id(new)?;", "valid_id(new)?;"),
    ("D09-new-id-path", D, "valid_id(&j.original_local_profile_id)?;\n    valid_id(new)?;", "valid_id(&j.original_local_profile_id)?;"),
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
    ("D25-readback-user-data", D, "|| !found.data.contains(new)", "|| false"),
    ("D26-readback-old-id", D,
     "|| found.mentions(&j.original_local_profile_id)\n    {\n        bail!(code(\"downgrade.readbackFailed\"));",
     "|| false\n    {\n        bail!(code(\"downgrade.readbackFailed\"));"),
    ("D27-readback-listing", D, "if !listed.iter().any(|p| p.id == new)", "if false"),
    # --- downgrade: rollback and resume -------------------------------------
    ("D28-rollback-overwrite", D,
     "if exists(dst) {\n            if exists(src) {\n                bail!(code(\"downgrade.rollbackConflict\"));",
     "if exists(dst) {\n            if false && exists(src) {\n                bail!(code(\"downgrade.rollbackConflict\"));"),
    ("D29-rollback-foreign-clone", D,
     ".is_ok_and(|p| Some(p.meta.id) == j.new_local_profile_id);", ".is_ok_and(|_| true);"),
    ("D30-rollback-keeps-clone", D,
     "for dir in [&w.clone_data, &w.clone_staging] {\n        if exists(dir) {",
     "for dir in [&w.clone_data, &w.clone_staging] {\n        if false && exists(dir) {"),
    ("D31-conflict-keeps-going", D,
     "let _ = journal::downgrade_advance(\n                    &db,\n                    &j.journal_id,\n                    Phase::RollbackRequired,\n                    Patch::default(),\n                );",
     ""),
    ("D32-rollback-completed", D,
     "if j.mode != Mode::Clone || j.phase == Phase::Completed {", "if j.mode != Mode::Clone {"),
    ("D33-pre-v2-as-clone", D,
     "Mode::PreV2Restore => Err(anyhow!(code(\"downgrade.preV2Unsupported\"))),",
     "Mode::PreV2Restore => run_clone(&j.journal_id),"),
    ("D34-clone-mode", D, "if j.mode != Mode::Clone {\n        bail!(code(\"downgrade.notClone\"));", "if false {\n        bail!(code(\"downgrade.notClone\"));"),
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
]


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
    originals = {f: (SRC / f).read_bytes() for f in (J, D)}
    digests = {f: hashlib.sha256(b).hexdigest() for f, b in originals.items()}
    for mid, f, old, new in chosen:
        text = originals[f].decode("utf-8")
        nl = "\r\n" if "\r\n" in text else "\n"
        o, n = old.replace("\n", nl), new.replace("\n", nl)
        if text.count(o) != 1:
            print(f"BAD-PATTERN {mid}: {text.count(o)} matches")
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
    return 0 if survived == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
