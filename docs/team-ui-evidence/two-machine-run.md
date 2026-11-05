# Team UI two-machine run

**Status:** PENDING-MANUAL: the operator runs it after v2.7.0 is released, with the steps below (plan v0.2.2a section 6 M). It was BLOCKED from 2026-11-04 until the custodian work (Create fleet key, the device list with Approve and Revoke, the join code) shipped; the reason is kept below. Before that it was PENDING-MANUAL (owner decision 2026-11-03: the real two-machine run is done by the operator after release, like G2-48).

## Setup steps (M.0a-0g)

Use disposable credentials only, and record no hostnames, URLs or passwords.

1. **0a.** Host: `identity init`, `tenant create`, then start the server.
   Paste the printed 32-hex `tenant_id` exactly; the Team card's Generate
   button makes a UUID and does not apply here.
2. **0b.** Sandbox reachability, by the method the S0 spike proved: a
   `portproxy` to loopback, or the HTTPS fallback. Plaintext `portproxy` is for
   this test run only.
3. **0c.** A (a temporary local Windows user): connect (server URL and tenant
   ID, no token), enroll. The operator runs `tenant confirm-first-device`. A
   runs Set up root custody.
4. **0d.** A: Create fleet key.
5. **0e.** B (Windows Sandbox): connect, enroll, Show join code.
6. **0f.** A: Show devices. Compare the codes (and the full key IDs), tick
   "The code on the other device matches", Approve. B: Codes match, then
   Collect key custody.
7. **0g.** Gate steps 1-5 below.
8. **Optional.** A revokes B; record the refusal B gets on its next pull.

Record the results in a separate "Record the two-machine run" PR, redacted.

## Why it was blocked

Found on 2026-11-04 while preparing the run (machine A as a separate local
Windows user, machine B as Windows Sandbox, a fresh team server with a
verified identity and one tenant). Before any profile can be published, the
fleet needs custodian steps that v2.6.1 has no client for:

- **No fleet key is ever created.** Publish needs a fleet key this device
  verified (`sync.noVerifiedFleetKey`). The launcher only reads the active fleet
  key generation and its own grant (`fleet_client.rs`
  `active_fleet_generation`, `read_fleet_device_grant`); nothing calls the
  server's create routes (`POST /v2/fleets/:fleet_id/key-generations` and
  `.../grants`). So even machine A alone cannot publish.
- **A second device cannot be approved.** The launcher calls
  `approve_device` only for its own first-device bootstrap
  (`root_bootstrap.rs`); there is no approve action for another device, and
  `tenant confirm-first-device` works once per tenant. Machine B stays
  pending, so it cannot open a device session to list or join fleet profiles.
- `docs/key-custody.md` already says grants "must be filed by an external
  custodian"; no such tool ships.

The e2e test "two devices pass one team profile back and forth" then passed
because its mock server handed both devices a fleet key. Its mock now hands out
none: B is refused until A creates the fleet key, approves B and B collects.

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
