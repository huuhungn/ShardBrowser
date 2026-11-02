# Team UI two-machine run

**Status:** PENDING-MANUAL (owner decision 2026-11-03: the real two-machine run is done by the operator after release, like G2-48)

The operator runs the two-machine gate (Plan:2388) on two real, disposable
machines enrolled in one fleet, and fills in every field below. The automated
counterpart is the e2e test "two devices pass one team profile back and forth,
then revert a revoked head to available" in `tests/e2e/app.spec.ts`.

## Machines

| | Machine A | Machine B |
|---|---|---|
| Hostname | | |
| OS and version | | |
| Device ID (first 8) | | |
| App version | | |
| App build SHA | | |

- **Team server URL and tenant (first 8):**
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

Both machines must end on the same pinned version as the server head.

## Notes

Anything unexpected: errors and their toasts, retries, timings, logs attached.
