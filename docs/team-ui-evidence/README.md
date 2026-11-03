# Team UI evidence

Evidence for the Team UI phase's last story (S6): a team profile published on
one machine, restored, used and checked in on a second, and checked out again
on the first, plus the blind verifier round.

- [two-machine-run.md](two-machine-run.md): checklist for the operator's real
  two-machine run of the gate. Status: PENDING-MANUAL.
- [codex-revert-round-1.md](codex-revert-round-1.md): the Codex blind verifier,
  round 1, at 33e431ae. VERDICT: FAIL with four defects (D1 to D4), fixed with
  regression tests in the same change; round 2 runs on the fixed main.
