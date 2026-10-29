#!/usr/bin/env python3
"""Mutation check for the G2-44 migration shape probes.

Applies one mutation at a time to a shipped server migration, runs the probes
in server/tests/v2_upgrade_chain.rs that read the migrated schema (the plan's
`_assert` script and fixtures 1 to 4), restores the file, and checks that its
SHA-256 is back. A mutant is KILLED when a probe fails, SURVIVED when all pass,
and ERROR when the build or a migration broke without a probe failing.

Usage (from anywhere):
    CARGO_TARGET_DIR=<dir> python scripts/g2-44-migration-mutants.py [--list] [--only NAME ...]

Never run it while another process reads or builds this worktree: each mutant
rewrites a migration in place for the length of one cargo run.
"""
import hashlib
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "server"
MIGRATIONS = SERVER / "migrations"
PROBES = ["the_plan_assertions", "fixtures_1_to_4"]

# The foreign key from a fleet-generation child to its generation, as 0020
# writes it three times (device, recovery, rotation grants).
GRANT_FK = (
    "    FOREIGN KEY (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id)\n"
    "        REFERENCES v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id),"
)
GRANT_FK_NO_KEY = (
    "    FOREIGN KEY (server_instance_id, tenant_id, fleet_id, generation)\n"
    "        REFERENCES v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation),"
)
# 0026 writes this one for v2_uploads, then for v2_snapshots.
GEN_FK = (
    "    FOREIGN KEY (server_instance_id, tenant_id, fleet_id, key_generation, fkek_key_id)\n"
    "        REFERENCES v2_fleet_key_generations(server_instance_id, tenant_id, fleet_id, generation,\n"
    "                                            fkek_key_id),"
)
GEN_FK_NO_KEY = (
    "    FOREIGN KEY (server_instance_id, tenant_id, fleet_id, key_generation)\n"
    "        REFERENCES v2_fleet_key_generations(server_instance_id, tenant_id, fleet_id, generation),"
)
UPLOAD_FK = (
    "    FOREIGN KEY (server_instance_id, tenant_id, upload_id, fleet_id, snapshot_id,\n"
    "                 manifest_replay_id)\n"
    "        REFERENCES v2_uploads(server_instance_id, tenant_id, upload_id, fleet_id, snapshot_id,\n"
    "                              manifest_replay_id),"
)
UPLOAD_FK_NO_REPLAY = (
    "    FOREIGN KEY (server_instance_id, tenant_id, upload_id, fleet_id, snapshot_id)\n"
    "        REFERENCES v2_uploads(server_instance_id, tenant_id, upload_id, fleet_id, snapshot_id),"
)

M26 = "0026_v2_uploads_snapshots.sql"
M20 = "0020_v2_fleet_generation_lifecycle.sql"
M11 = "0011_instance_bound_key_generations.sql"


def line(text, **kw):
    return text + "\n"


# (name, assertion group, file, old text, new text, nth occurrence of old)
MUTANTS = [
    # --- column NOT NULL and type (plan: pragma_table_info) ---
    ("uploads-snapshot_id-nullable", "types", M26,
     "    snapshot_id         BLOB    NOT NULL CHECK (length(snapshot_id) = 16),",
     "    snapshot_id         BLOB    CHECK (length(snapshot_id) = 16),", 0),
    ("uploads-manifest_replay_id-text", "types", M26,
     "    manifest_replay_id  BLOB    NOT NULL CHECK (length(manifest_replay_id) = 16),",
     "    manifest_replay_id  TEXT    NOT NULL CHECK (length(manifest_replay_id) = 16),", 0),
    ("uploads-fleet_id-nullable", "types", M26,
     "    fleet_id            BLOB    NOT NULL CHECK (length(fleet_id) = 16),",
     "    fleet_id            BLOB    CHECK (length(fleet_id) = 16),", 0),
    ("snapshots-upload_id-nullable", "types", M26,
     "    upload_id           BLOB    NOT NULL CHECK (length(upload_id) = 16),",
     "    upload_id           BLOB    CHECK (length(upload_id) = 16),", 1),
    ("snapshots-snapshot_id-nullable", "types", M26,
     "    snapshot_id         BLOB    NOT NULL CHECK (length(snapshot_id) = 16),",
     "    snapshot_id         BLOB    CHECK (length(snapshot_id) = 16),", 1),
    ("snapshots-manifest_replay_id-nullable", "types", M26,
     "    manifest_replay_id  BLOB    NOT NULL CHECK (length(manifest_replay_id) = 16),",
     "    manifest_replay_id  BLOB    CHECK (length(manifest_replay_id) = 16),", 1),
    ("snapshots-fleet_id-nullable", "types", M26,
     "    fleet_id            BLOB    NOT NULL CHECK (length(fleet_id) = 16),",
     "    fleet_id            BLOB    CHECK (length(fleet_id) = 16),", 1),
    ("root-generations-instance-nullable", "types", M11,
     "    server_instance_id BLOB    NOT NULL CHECK (length(server_instance_id) = 16),",
     "    server_instance_id BLOB    CHECK (length(server_instance_id) = 16),", 0),
    ("fleet-generations-instance-nullable", "types", M11,
     "    server_instance_id BLOB    NOT NULL CHECK (length(server_instance_id) = 16),",
     "    server_instance_id BLOB    CHECK (length(server_instance_id) = 16),", 1),
    # --- the five-column key of a fleet generation (plan: pragma_index_list) ---
    ("fleet-generations-key-reordered", "generation key", M11,
     "    UNIQUE (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id),",
     "    UNIQUE (server_instance_id, tenant_id, generation, fleet_id, fkek_key_id),", 0),
    ("fleet-generations-key-without-fkek", "generation key", M11,
     "    UNIQUE (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id),",
     "    UNIQUE (server_instance_id, tenant_id, fleet_id, generation),", 0),
    # --- foreign keys to the generation (plan: pragma_foreign_key_list, fixture 3) ---
    ("device-grants-fk-without-fkek", "generation FK", M20, GRANT_FK, GRANT_FK_NO_KEY, 0),
    ("recovery-grants-fk-without-fkek", "generation FK", M20, GRANT_FK, GRANT_FK_NO_KEY, 1),
    ("rotation-grants-fk-without-fkek", "generation FK", M20, GRANT_FK, GRANT_FK_NO_KEY, 2),
    ("uploads-fk-without-fkek", "generation FK", M26, GEN_FK, GEN_FK_NO_KEY, 0),
    ("snapshots-fk-without-fkek", "generation FK", M26, GEN_FK, GEN_FK_NO_KEY, 1),
    # --- the snapshot to upload key (plan: six-column FK, fixture 1) ---
    ("snapshots-upload-fk-without-replay", "upload FK", M26, UPLOAD_FK, UPLOAD_FK_NO_REPLAY, 0),
    # --- duplicate refusals (fixture 2) ---
    ("uploads-snapshot-id-unique-dropped", "unique", M26,
     "    UNIQUE (server_instance_id, tenant_id, profile_id, snapshot_id),\n", "", 0),
    ("uploads-replay-id-unique-dropped", "unique", M26,
     "    UNIQUE (server_instance_id, tenant_id, profile_id, manifest_replay_id),\n", "", 0),
    ("snapshots-snapshot-id-unique-dropped", "unique", M26,
     "    UNIQUE (server_instance_id, tenant_id, profile_id, snapshot_id),\n", "", 1),
    ("snapshots-replay-id-unique-dropped", "unique", M26,
     "    UNIQUE (server_instance_id, tenant_id, profile_id, manifest_replay_id),\n", "", 1),
    ("uploads-snapshot-id-unique-global", "unique", M26,
     "    UNIQUE (server_instance_id, tenant_id, profile_id, snapshot_id),",
     "    UNIQUE (snapshot_id),", 0),
    # --- close and reopen: state that lives only on the migrating connection ---
    ("snapshots-table-is-temp", "reopen", M26,
     "CREATE TABLE v2_snapshots (", "CREATE TEMP TABLE v2_snapshots (", 0),
    # --- integrity_check / foreign_key_check on an upgraded, populated file ---
    ("0020-leaves-a-dangling-ledger-row", "foreign_key_check", M20,
     "ALTER TABLE v2_idempotency_new RENAME TO v2_idempotency;",
     "ALTER TABLE v2_idempotency_new RENAME TO v2_idempotency;\n"
     "UPDATE v2_idempotency SET tenant_id = x'ffffffffffffffffffffffffffffffff';", 0),
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_nth(text, old, new, nth):
    at = -1
    for _ in range(nth + 1):
        at = text.find(old, at + 1)
        if at < 0:
            return None
    return text[:at] + new + text[at + len(old):]


def touch_sources():
    now = time.time()
    for p in (SERVER / "src" / "lib.rs", SERVER / "tests" / "v2_upgrade_chain.rs"):
        os.utime(p, (now, now))


def run_probes():
    touch_sources()
    proc = subprocess.run(
        ["cargo", "test", "-j", "1", "--test", "v2_upgrade_chain", "--"] + PROBES,
        cwd=SERVER, capture_output=True, text=True, timeout=1800,
    )
    out = proc.stdout + proc.stderr
    failed = re.findall(r"^test (\S+) \.\.\. FAILED", out, re.M)
    first = ""
    m = re.search(r"panicked at [^\n]*\n(.*?)\n(?:\s*left|\s*right|note:|\n)", out, re.S)
    if m:
        first = " ".join(m.group(1).split())[:230]
    if not failed:
        m = re.search(r"(plan's assertion failed:[^\n]*)", out)
        first = first or (m.group(1) if m else "")
    built = "could not compile" not in out
    return proc.returncode, failed, first, built, out


def main(argv):
    if "CARGO_TARGET_DIR" not in os.environ:
        sys.exit("set CARGO_TARGET_DIR to a scratch build directory")
    if "--list" in argv:
        for name, group, *_ in MUTANTS:
            print(f"{group:18} {name}")
        return 0
    only = argv[argv.index("--only") + 1:] if "--only" in argv else None
    chosen = [m for m in MUTANTS if only is None or m[0] in only]

    code, failed, first, built, out = run_probes()
    if code != 0:
        print(out[-3000:])
        sys.exit("the unmutated probes do not pass; fix that first")
    print(f"baseline: probes pass ({len(PROBES)} filters)")

    results = []
    for name, group, fname, old, new, nth in chosen:
        path = MIGRATIONS / fname
        original = path.read_bytes()
        before = hashlib.sha256(original).hexdigest()
        text = original.decode("utf-8")
        if "\r" in text:
            sys.exit(f"{fname} holds CR bytes; migrations are LF")
        mutated = replace_nth(text, old, new, nth)
        if mutated is None:
            sys.exit(f"{name}: occurrence {nth} of the text is not in {fname}")
        try:
            path.write_bytes(mutated.encode("utf-8"))
            code, failed, first, built, out = run_probes()
        finally:
            path.write_bytes(original)
        restored = sha(path) == before
        if not restored:
            sys.exit(f"{name}: {fname} did not restore (sha mismatch)")
        if not built:
            status = "ERROR"
        elif failed:
            status = "KILLED"
        elif code != 0:
            status = "ERROR"
        else:
            status = "SURVIVED"
        results.append((name, group, status, failed, first))
        print(f"{status:9} {group:18} {name}: {', '.join(failed) or '-'} | {first}", flush=True)

    killed = sum(1 for r in results if r[2] == "KILLED")
    print(f"\nkilled {killed}/{len(results)}; every migration file restored to its SHA-256")
    for name, group, status, *_ in results:
        if status != "KILLED":
            print(f"  not killed: {status} {name}")
    return 0 if killed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
