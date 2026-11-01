#!/usr/bin/env python3
"""Hashes of the artifacts the G2 evidence packet cites.

    python scripts/g2-evidence.py --write      regenerate docs/g2-evidence/SHA256SUMS
    python scripts/g2-evidence.py --check      verify every listed file against it
    python scripts/g2-evidence.py --self-test  prove --check passes, then fails

Line endings are normalised (CRLF to LF) before hashing: the repository stores
LF, and a Windows checkout with autocrlf may hold CRLF. Python 3 standard
library only. Exit status is 1 on any mismatch, missing file or unlisted line.
"""
import argparse
import hashlib
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUMS = "docs/g2-evidence/SHA256SUMS"
README = "docs/g2-evidence/README.md"

# Every file the packet cites. The packet's own README and SHA256SUMS are
# excluded: the sums cannot hash themselves.
ARTIFACTS = [
    ".omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md",
    "docs/adr/0002-g2-contract-decisions.md",
    "docs/adr/0003-envelope-v2-stream.md",
    "docs/adr/0004-credential-store.md",
    "docs/dependency-review.md",
    "docs/g2-48-manual-check.md",
    "docs/g2-evidence/verifier-codex-2026-11-01.md",
    "docs/key-custody.md",
    "docs/security-review-g2.md",
    "docs/trust-boundaries.md",
    "package.json",
    "scripts/backend-error-locale.test.mjs",
    "scripts/g2-44-migration-mutants.py",
    "scripts/g2-48-credential-check.ps1",
    "scripts/g2-evidence.py",
    "scripts/g2-wp5-mutants.py",
    "scripts/i18n-locale-parity.test.mjs",
    "scripts/rust-user-strings.baseline.json",
    "scripts/rust-user-strings.test.mjs",
    "server/Cargo.lock",
    "server/Cargo.toml",
    "server/migrations/0001_init.sql",
    "server/migrations/0002_lock_token_and_token_version.sql",
    "server/migrations/0003_clear_empty_lock_tokens.sql",
    "server/migrations/0004_v2_team_fleet.sql",
    "server/migrations/0005_replay_ledger_root_key_grants.sql",
    "server/migrations/0006_root_key_generations.sql",
    "server/migrations/0007_fleet_key_generations.sql",
    "server/migrations/0008_replay_ledger_fleet_key_grants.sql",
    "server/migrations/0009_make_active_root_generation_nullable.sql",
    "server/migrations/0010_v2_audit_events.sql",
    "server/migrations/0011_instance_bound_key_generations.sql",
    "server/migrations/0012_v2_device_states_and_bootstrap_guards.sql",
    "server/migrations/0013_v2_pre_device_and_device_sessions.sql",
    "server/migrations/0014_v2_ticket_enrollment.sql",
    "server/migrations/0015_v2_idempotency_and_device_approval.sql",
    "server/migrations/0016_v2_root_bootstrap.sql",
    "server/migrations/0017_v2_root_ack_activate.sql",
    "server/migrations/0018_v2_capability_grants.sql",
    "server/migrations/0019_v2_grant_quarantine.sql",
    "server/migrations/0020_v2_fleet_generation_lifecycle.sql",
    "server/migrations/0021_v2_fleet_generation_guards.sql",
    "server/migrations/0022_v2_guard_followups.sql",
    "server/migrations/0023_v2_device_revocations.sql",
    "server/migrations/0024_v2_restore_epoch_transitions.sql",
    "server/migrations/0025_v2_profile_leases.sql",
    "server/migrations/0026_v2_uploads_snapshots.sql",
    "server/migrations/0027_v2_upload_reconciler.sql",
    "server/migrations/0028_v2_fleet_grant_quarantine.sql",
    "server/migrations/0029_v2_device_approval_quarantine.sql",
    "server/migrations/0030_v2_integer_columns_hold_integers.sql",
    "server/migrations/0031_v2_idempotency_superseded.sql",
    "server/migrations/0032_v2_device_revocation_quarantine.sql",
    "server/migrations/0033_v2_revocation_quarantine_hash.sql",
    "server/src/audit.rs",
    "server/src/db.rs",
    "server/src/identity.rs",
    "server/src/integrity.rs",
    "server/src/restore.rs",
    "server/src/routes/v2_device_revoke.rs",
    "server/src/routes/v2_profiles.rs",
    "server/src/routes/v2_root.rs",
    "server/src/routes/v2_root_grants.rs",
    "server/src/routes/v2_uploads.rs",
    "server/tests/fixtures/plan_assert.sql",
    "server/tests/fixtures/v0.1.28/0001_init.sql",
    "server/tests/fixtures/v0.1.28/0002_lock_token_and_token_version.sql",
    "server/tests/fixtures/v0.1.28/0003_clear_empty_lock_tokens.sql",
    "server/tests/identity_authority.rs",
    "server/tests/migration_line_endings.rs",
    "server/tests/restore_epoch_harness.rs",
    "server/tests/v2_auth.rs",
    "server/tests/v2_e2e.rs",
    "server/tests/v2_integer_domain.rs",
    "server/tests/v2_profiles.rs",
    "server/tests/v2_upgrade_chain.rs",
    "shared/Cargo.lock",
    "shared/Cargo.toml",
    "shared/src/authz_record.rs",
    "shared/src/backup.rs",
    "shared/src/backup_file.rs",
    "shared/src/canonical.rs",
    "shared/src/envelope.rs",
    "shared/src/envelope_v2.rs",
    "shared/src/fleet_grants.rs",
    "shared/src/fleet_lifecycle.rs",
    "shared/src/grants.rs",
    "shared/src/keys.rs",
    "shared/src/mutation.rs",
    "shared/src/profile_lease.rs",
    "shared/src/recovery_bundle.rs",
    "shared/src/restore_epoch.rs",
    "shared/src/signing.rs",
    "shared/src/snapshot.rs",
    "shared/src/snapshot_v2.rs",
    "shared/src/volume.rs",
    "shared/tests/backup_file_roundtrip.rs",
    "shared/tests/registry_pins.rs",
    "src-tauri/Cargo.lock",
    "src-tauri/Cargo.toml",
    "src-tauri/src/crash_harness.rs",
    "src-tauri/src/credential.rs",
    "src-tauri/src/durable.rs",
    "src-tauri/src/fleet_client.rs",
    "src-tauri/src/fleet_keys.rs",
    "src-tauri/src/key_file.rs",
    "src-tauri/src/lib.rs",
    "src-tauri/src/migrate.rs",
    "src-tauri/src/root_bootstrap.rs",
    "src-tauri/src/store.rs",
    "src-tauri/src/sync_cmd.rs",
    "src-tauri/src/team/db.rs",
    "src-tauri/src/team/downgrade.rs",
    "src-tauri/src/team/journal.rs",
    "src-tauri/src/team/ledger.rs",
    "src-tauri/src/team/records.rs",
    "src-tauri/src/team/sync.rs",
    "src-tauri/src/team_config.rs",
]


def digest(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read().replace(b"\r\n", b"\n")).hexdigest()


def write(root):
    lines = []
    for rel in ARTIFACTS:
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            print("MISSING  " + rel)
            return 1
        lines.append(digest(full) + "  " + rel + "\n")
    with open(os.path.join(root, SUMS), "w", encoding="utf-8", newline="\n") as f:
        f.writelines(lines)
    print("wrote %d lines to %s" % (len(lines), SUMS))
    return 0


def cited_but_unlisted(root):
    """Repo files the README names in backticks that no line of SHA256SUMS covers."""
    readme = os.path.join(root, README)
    if not os.path.isfile(readme):
        return []
    with open(readme, encoding="utf-8") as f:
        text = f.read()
    own = {README, SUMS}
    found = set()
    for tok in re.findall(r"`([^`\s]+)`", text):
        if "/" in tok and tok not in own and tok not in ARTIFACTS and os.path.isfile(os.path.join(root, tok)):
            found.add(tok)
    return sorted(found)


def check(root):
    sums_path = os.path.join(root, SUMS)
    if not os.path.isfile(sums_path):
        print("MISSING  " + SUMS)
        return 1
    with open(sums_path, encoding="utf-8") as f:
        recorded = {}
        for n, line in enumerate(f, 1):
            m = re.fullmatch(r"([0-9a-f]{64})  (\S+)\n?", line)
            if not m or m.group(2) in recorded:
                print("BAD LINE %s:%d" % (SUMS, n))
                return 1
            recorded[m.group(2)] = m.group(1)
    bad = 0
    for rel in ARTIFACTS:
        full = os.path.join(root, rel)
        if rel not in recorded:
            print("UNLISTED " + rel + " (not in " + SUMS + ")")
            bad += 1
        elif not os.path.isfile(full):
            print("MISSING  " + rel)
            bad += 1
        elif digest(full) != recorded[rel]:
            print("MISMATCH " + rel)
            bad += 1
    for rel in sorted(set(recorded) - set(ARTIFACTS)):
        print("EXTRA    " + rel + " (in " + SUMS + " but not in ARTIFACTS)")
        bad += 1
    for rel in cited_but_unlisted(root):
        print("CITED    " + rel + " (named in the README, not hashed)")
        bad += 1
    print("%d files checked, %d problems" % (len(ARTIFACTS), bad))
    return 1 if bad else 0


def flip_byte(path):
    with open(path, "rb") as f:
        data = bytearray(f.read())
    data[len(data) // 2] ^= 0x01
    with open(path, "wb") as f:
        f.write(data)


def self_test():
    tmp = tempfile.mkdtemp(prefix="g2-evidence-")
    try:
        for rel in ARTIFACTS + [README]:
            src = os.path.join(ROOT, rel)
            if os.path.isfile(src):
                dst = os.path.join(tmp, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(src, dst)
        os.makedirs(os.path.join(tmp, os.path.dirname(SUMS)), exist_ok=True)
        steps = []

        def step(name, got, want):
            steps.append(got == want)
            print("%-4s %s (exit %d, expected %d)" % ("ok" if got == want else "FAIL", name, got, want))

        step("write on a temp copy", write(tmp), 0)
        step("check right after write passes", check(tmp), 0)
        first = os.path.join(tmp, ARTIFACTS[0])
        with open(first, "rb") as f:
            keep = f.read()
        flip_byte(first)
        step("check after one byte of %s changed fails" % ARTIFACTS[0], check(tmp), 1)
        with open(first, "wb") as f:
            f.write(keep)
        step("check after the byte is restored passes", check(tmp), 0)
        crlf = os.path.join(tmp, ARTIFACTS[1])
        with open(crlf, "rb") as f:
            data = f.read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        with open(crlf, "wb") as f:
            f.write(data)
        step("check with %s in CRLF passes" % ARTIFACTS[1], check(tmp), 0)
        os.remove(os.path.join(tmp, ARTIFACTS[2]))
        step("check with %s deleted fails" % ARTIFACTS[2], check(tmp), 1)
        return 0 if all(steps) else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true", help="regenerate " + SUMS)
    g.add_argument("--check", action="store_true", help="verify every listed file")
    g.add_argument("--self-test", action="store_true", help="prove --check passes, then fails")
    a = ap.parse_args()
    if a.write:
        return write(ROOT)
    if a.check:
        return check(ROOT)
    return self_test()


if __name__ == "__main__":
    sys.exit(main())
