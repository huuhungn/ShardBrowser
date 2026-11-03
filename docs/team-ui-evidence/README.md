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
- [codex-revert-round-4.md](codex-revert-round-4.md): the Codex blind verifier,
  round 4, at 5ac2fd15. VERDICT: FAIL with two defects: folder and API deletion
  left the decrypted revert staging behind, and a device whose own key was
  withdrawn still sent a prepared revert commit that had not landed. Fixed with
  regression tests in the same change; round 5 runs on the fixed main.
- [codex-revert-round-5.md](codex-revert-round-5.md): the Codex blind verifier,
  round 5, at bf09f512. VERDICT: FAIL with one defect: a custodian-signed
  revocation naming the right signing key but another device was counted.
  Fixed with regression tests in the same change; round 6 runs on the fixed main.
- [codex-revert-round-6.md](codex-revert-round-6.md): the Codex blind verifier,
  round 6, at a4332d76. VERDICT: PASS: all ten properties hold. Its two new
  probes (a stacked run never pins a rejected head, even for a moment; a failed
  revert pin keeps local data and can be retried) are kept as regression tests.
