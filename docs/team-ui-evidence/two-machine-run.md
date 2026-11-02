# Team UI two-machine run

**Status:** PENDING-MANUAL (owner decision 2026-11-03: the real two-machine run is done by the operator after release, like G2-48)

The gate: one team profile is published on machine A, restored and used on
machine B, checked in from B, and checked out again on A, with both machines
ending on the same pinned version. The operator runs it on two real,
disposable machines enrolled in one fleet, both on the same app build, and
fills in every field below. The automated counterpart is the e2e test "two
devices pass one team profile back and forth, then revert a revoked head to
available" in `tests/e2e/app.spec.ts`.

Do not paste tokens, hostnames, URLs or credentials; attach logs only after redaction.

## Machines

| | Machine A | Machine B |
|---|---|---|
| Machine label (A/B, no hostname) | | |
| OS and version | | |
| Device ID (first 8) | | |
| App version | | |
| App build SHA | | |

Both machines must run the same build: the app version and build SHA above match.

- **Tenant (first 8 characters at most):**
- **Operator:**
- **Date:**

## Gate steps

Record the time (local, with time zone) and the result (`PASS` or `FAIL` with
what was seen). "Badge" and "pin" are what the Team page and
`team_profiles_status` show on the machine that ran the step.

| # | Gate step | Path | Machine | Time | Badge, pin | Result |
|---|---|---|---|---|---|---|
| 1 | publish | S5 publish | A | | | |
| 2 | checkout/restore on B | S3b join + pull | B | | | |
| 3 | use | an ordinary launch (`launch_profile_synced`) | B | | | |
| 4 | check-in on B | S5 check-in (checkout inside push) | B | | | |
| 5 | checkout on A | A pull + check-in | A | | | |

## Final pins

| | Machine A | Machine B |
|---|---|---|
| Badge | | |
| Pinned version | | |
| Server head version | | |

Read the server head version on the Team page: "Show fleet profiles" in the
"Join from fleet" list shows "Version N" for the profile. Both machines must
end on the same pinned version as the server head.

## Notes

Anything unexpected: errors and their toasts, retries, timings. Attach logs
only after removing tokens, hostnames, URLs and credentials.
