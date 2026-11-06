# Team UI two-machine run

**Status:** PASS on 2026-11-06 with v2.7.0 (build a8d512d1), on the second attempt; see Notes for the first. It was BLOCKED from 2026-11-04 until the custodian work (Create fleet key, the device list with Approve and Revoke, the join code) shipped; the reason is kept below.

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
| Machine label (A/B, no hostname) | A: a temporary local Windows user | B: Windows Sandbox |
| OS and version | Windows 11 Pro 10.0.26300 | Windows Sandbox, 10.0.26100 |
| Device ID (first 8) | bab9a5d4 | 3717ede4 |
| App version | 2.7.0 | 2.7.0 |
| App build SHA | a8d512d1 | a8d512d1 |

Both machines must run the same build: the app version and build SHA above match.

- **Tenant (first 8 characters at most):** ada0465f
- **Operator:** the repository owner, with the agent preparing the server, firewall rule, temporary user and Sandbox
- **Date:** 2026-11-06

Both machines installed `ShardX.Launcher_2.7.0_x64-setup.exe` from the v2.7.0
release, and the server was that release's `shardx-team-server-win-x64.exe`,
on a throwaway data directory, identity and tenant. Machine B reached it
through the loopback `portproxy` of step M.0b.

## Gate steps

Record the time (local, with time zone) and the result (`PASS` or `FAIL` with
what was seen). "Badge" and "pin" are what the Team page and
`team_profiles_status` show on the machine that ran the step.

| # | Gate step | Path | Machine | Time | Badge, pin | Result |
|---|---|---|---|---|---|---|
| 1 | publish | S5 publish | A | 09:20 +07 (version 1 filed 09:20:08) | Available, version 1 | PASS |
| 2 | checkout/restore on B | S3b join + pull | B | between 09:20 and 09:23 +07 | Available, version 1 | PASS |
| 3 | use | an ordinary launch (`launch_profile_synced`) | B | between 09:20 and 09:23 +07 | browser opened, page loaded, closed | PASS |
| 4 | check-in on B | S5 check-in (checkout inside push) | B | 09:23 +07 (version 2 filed 09:23:56) | Available, version 2 | PASS |
| 5 | checkout on A | A pull + check-in | A | 09:26-09:27 +07 (versions 3 and 4 filed 09:26:39 and 09:27:05) | Available, version 4 | PASS |

Times for steps 2 and 3 were not written down during the run; the window comes
from the server's snapshot times. Every filed version names the device that
signed it (`created_by_device`): versions 1, 3 and 4 by A, version 2 by B. A
checked in twice in step 5, so the head ended on version 4, not 3. The
optional revoke step was not run.

## Final pins

| | Machine A | Machine B |
|---|---|---|
| Badge | Available | Available |
| Pinned version | 4 | 4 (after a final Pull) |
| Server head version | 4 | 4 |

Read the server head version on the Team page: "Show fleet profiles" in the
"Join from fleet" list shows "Version N" for the profile. Both machines must
end on the same pinned version as the server head.

## Notes

Anything unexpected: errors and their toasts, retries, timings. Attach logs
only after removing tokens, hostnames, URLs and credentials.

Run on 2026-11-06:

- **Attempt 1 was lost to the run setup, not to the app.** After A set up root
  custody, the agent cleared the temporary user's Windows password with an
  administrator reset. That makes the user's DPAPI-protected Credential
  Manager entries unreadable, and A then refused Create fleet key with "A
  device key is missing from the OS credential store; this device must
  re-enroll". A was the root custodian and v2.7.0 cannot import a recovery
  bundle, so the tenant was abandoned. Attempt 2 used a new user created with
  no password, a new server data directory, identity and tenant, and a new
  Sandbox.
- **Defect: the first device never shows its key IDs.** `tenant
  confirm-first-device` asks for both key IDs "as shown on the client" (ADR
  0001 D1), but the Team page of an enrolled, pending first device shows only
  its Device ID. The operator typed the IDs the CLI printed, so the D1 cross
  check was not performed. Fix planned for v2.7.1.
- **UX: Approve is disabled with no reason given.** It needs the password
  field filled (the field is cleared after every action) and a usable fleet
  key. In attempt 1 the operator had set up root custody but not yet run
  Create fleet key, and nothing said why Approve stayed disabled. Fix planned
  for v2.7.1.
- Saving the recovery bundle into a folder the user cannot write failed with
  "Could not write the recovery bundle, read it back and open it; custody
  setup stopped before anything was filed", as designed. Saving to
  Documents worked.
- Windows Sandbox has no Notepad; the setup script was changed to start the
  launcher directly.
