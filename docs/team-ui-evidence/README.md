# Team UI evidence

Evidence for the Team UI phase's last story (S6): a team profile published on
one machine, restored, used and checked in on a second, and checked out again
on the first, plus the blind verifier round.

- [two-machine-run.md](two-machine-run.md): checklist for the operator's real
  two-machine run of the gate. Status: PENDING-MANUAL.
- [codex-revert-round-1.md](codex-revert-round-1.md): the Codex blind verifier,
  round 1, at 33e431ae. VERDICT: FAIL with four defects (D1 to D4), fixed with
  regression tests in the same change; round 2 runs on the fixed main.
- [codex-revert-round-2.md](codex-revert-round-2.md): the Codex blind verifier,
  round 2, at a1d90593. VERDICT: FAIL with two race defects (a signer withdrawn
  between the walk and the pin, for pull and for a replayed revert), fixed with
  regression tests in the same change. Its third probe, a refused pull keeping
  the local profile, contradicts the ADR's advance-to-P rule; an ordinary pull
  replaces unsynced local edits the same way, so the behavior stays and the
  probe was dropped. Round 3 runs on the fixed main.
- [codex-revert-round-3.md](codex-revert-round-3.md): the Codex blind verifier,
  round 3, at 8be4e6a6. VERDICT: FAIL with one defect: a revert could commit the
  content of a source snapshot whose signer was withdrawn during its download
  or before a retry. Fixed with regression tests in the same change; round 4
  runs on the fixed main.
