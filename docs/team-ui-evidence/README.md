# Team UI evidence

Evidence for the Team UI phase's last story (S6): a team profile published on
one machine, restored, used and checked in on a second, and checked out again
on the first, plus the blind verifier round.

- [two-machine-run.md](two-machine-run.md): checklist for the operator's real
  two-machine run of the gate. Status: BLOCKED until v0.2.2: v2.6.1 cannot
  create a fleet key or approve a second device, so a real server cannot get
  to the first publish (details in the file).
- [sandbox-reachability.md](sandbox-reachability.md): spike S0, 2026-11-05.
  Windows Sandbox reaches a team server on the host through a `portproxy` to
  its loopback (health 200, login 201), so step M.0b uses that method, with
  disposable credentials only.
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
- [codex-revert-round-7.md](codex-revert-round-7.md): the Codex blind verifier,
  round 7, at 3e98af0c (after the v2.6.1 fixes in #245). VERDICT: PASS: all ten
  properties hold. Its two new probes (a damaged revert source keeps local data
  and can be retried; a join past an untrusted child keeps local data and can be
  unbound) are kept as regression tests without the `round7_` prefix.
- [codex-revert-round-8.md](codex-revert-round-8.md): the Codex blind verifier,
  round 8, at 8592d06d (the mechanical cleanup of five anti-slop review items).
  VERDICT: PASS: all ten properties hold and every refactor hunk preserves
  behavior. Its new probe (a revert refuses a mixed run without touching local
  data) is kept as a regression test without the `round8_` prefix.
- [codex-custodian-round-1.md](codex-custodian-round-1.md): the Codex blind
  verifier of the custodian flow, round 1, at 07260ecc. VERDICT: FAIL with six
  defects (D1 to D6), fixed with regression tests in the same change; its tests
  are kept without the `verifier_` prefix. Round 2 runs on the fixed main.
- [codex-custodian-round-2.md](codex-custodian-round-2.md): the Codex blind
  verifier of the custodian flow, round 2, at 6781e565. VERDICT: FAIL with five
  defects (D1 to D5), fixed with regression tests in the same change; its tests
  are kept without the `verifier_` prefix. Round 3 runs on the fixed main.
- [codex-custodian-round-3.md](codex-custodian-round-3.md): the Codex blind
  verifier of the custodian flow, round 3, at 97ee34c5. VERDICT: FAIL with four
  defects (D1 to D4), fixed with regression tests in the same change; its tests
  are kept without the `round3` prefix. Round 4 runs on the fixed main.
- [codex-custodian-round-4.md](codex-custodian-round-4.md): the Codex blind
  verifier of the custodian flow, round 4, at de6545db. VERDICT: FAIL with four
  defects (R4-1 to R4-4), fixed with regression tests in the same change; its
  tests are kept without the `round4` prefix, and its `round-4-*` logs beside
  it. Round 5 runs on the fixed main.
- [codex-custodian-round-5.md](codex-custodian-round-5.md): the Codex blind
  verifier of the custodian flow, round 5, at 2d444375. VERDICT: FAIL on goals
  5, 6 and 9. Goal 6 (a listed key ID could carry a session-token body) is
  fixed in the same change: listed key IDs must hash from their listed keys.
  Goal 9's finding is the trust evidence, which serves every sealed root grant
  by design (ADR 0002), and goal 5's is a setup resumed after its requests
  expired; both are documented in `docs/key-custody.md` and the round-6 brief
  scopes them. Its revoked-custodian probe is kept as a regression test.
  Round 6 runs on the fixed main.
- [codex-custodian-round-6.md](codex-custodian-round-6.md): the Codex blind
  verifier of the custodian flow, round 6, at 4dddfdb6. VERDICT: PASS: all
  eleven goals hold and no new probe was needed. Its worktree had no
  `node_modules`, so it read the Playwright custody cases instead of running
  them; they run in CI and in the gate on the same main.
