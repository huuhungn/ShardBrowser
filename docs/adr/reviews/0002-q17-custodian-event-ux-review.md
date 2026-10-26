# ADR 0002 Q-17: custodian event and rotation banner UX review

- **Status:** design for W6, accepted on 2026-10-25 after the review that
  ADR 0002 Q-17 requires before W6 starts. Revision 2 answers every finding of
  the review; the record is at the end.
- **Inputs:** ADR 0002 D-6 (a) (custodian ledger and change events), D-6 (d)
  (local distrust), Q-13 (re-filing reminder, banner tiers, flag rules),
  Q-18 (commit block for `compromised`), Q-19 (first sight only), Q-20 (banner
  split by reason code), and the open note on defaulting to `DEVICE_REVOKE`.
- **Scope:** three events (`custodian.appointed`,
  `custodian.renewed_after_revocation`, `revocation.refile_needed`), the urgent
  and routine rotation banners, the commit-blocked state, and the revoke dialog.
  ADR 0002 fixes when each item is raised and cleared and what blocks commits.
  This document decides only what the user sees and how they respond. Where it
  needs a behaviour ADR 0002 does not define, it says so and names the W6 item.

## Principles

The failure to design against is habituation: a prompt that appears often and
can be cleared with one click teaches people to clear it without reading. The
opposite failure is friction so high that people route around it. Each rule
below removes one of those paths.

1. **Rare by construction.** Nothing here fires on a routine operation.
   Approving a device, a planned rotation, or a renewal by a custodian that is
   still trusted raises nothing. Only the three ADR 0002 events and the two
   banner tiers exist.
2. **No modal pop-ups.** Events never interrupt work. They appear as a counted
   badge (see "Where things appear") and, when urgent, as a line in the urgent
   strip.
3. **Acknowledging means choosing.** An event has no "OK" or "Dismiss all". The
   user picks an answer that says what they believe. Each answer has a stated
   consequence, and the answer, the subject key and the local time go into the
   local audit log. Answers are per device: each of a user's devices answers on
   its own, and the wording says "on this device".
4. **Banners clear by condition, not by click.** A rotation flag clears only
   when the client's own checks clear it (ADR 0002 Q-13). The urgent strip cannot
   be hidden. The routine notice lives only inside Settings → Team and has no
   strip to collapse.
5. **Answers bind to evidence, not to people.** An answer covers exactly the
   signed records it was given for, by `signed_container_hash`. A new record of
   the same kind about the same key raises the event again (see each event).
6. **Nothing the server says is presented as fact.** ADR 0002 signs no device
   label. Keys lead; labels are shown as "named {label} by the server". Lists of
   custodians come from this device's own ledger, without revoked or distrusted
   keys.
7. **Same words everywhere.** Each item has one title and one explanation, used
   in the badge, the card, the strip and the audit entry, as the GPU mismatch
   texts already do (`IncompatibleExplainer`).
8. **Keys are shown short, with the full value one click away** (ADR 0002 D-6
   (a)): the first 8 and last 4 hex digits, and "Show full key", which reveals
   and copies all 64.
9. **Times are what this device knows.** Event times are "This device first saw
   this on {time}" (the local first-seen time ADR 0002 uses), never presented as
   when it happened. Times are local and absolute ("25 Oct 2026, 19:42").

## Where things appear

| Surface | Shows |
|---|---|
| App-wide strip under the top bar | The urgent rotation banner, and one line per unanswered urgent event |
| Sidebar, Settings entry | A red count of unanswered events plus urgent causes. Nothing for the routine notice alone, so a long-standing routine notice never masks a new event |
| Settings → Team, "Security events" | One card per unanswered event, then the answered history (newest first, last 90 days), and the "baseline" entry below |
| Settings → Team, "Key rotation" | The routine notice, and the rotation checklist while anything is flagged |
| Browsers page, profile row | The commit-blocked state for profiles in a blocked fleet |

**Baseline entry (device with no history).** A device that joins, or loses its
local state, baselines whatever the evidence shows and raises no `appointed`
event for it (ADR 0002 D-6 (a), limit). It records one history entry instead:
"Custodians trusted as of {time}. Changes made before this device joined were
not checked." It lists the custodian keys it baselined.

## Distrust (shared by every event)

Distrust is ADR 0002 D-6 (d): this device ignores records signed by the key that
it **first sees after** the distrust moment. Records it already accepted stay
accepted (Q-19). ADR 0002 defines no undo, so this design offers none.

Before applying, a confirmation panel (inside the card, not a modal) shows:

- "On this device, anything new this key signs is ignored. What this device
  already accepted from it stays. This cannot be undone."
- Whether the key is a current custodian here, and, if so, whether it is this
  device's **only** custodian path (every other custodian revoked or distrusted)
  or the only `key.rotate` holder. If it is: "This device may then be unable to
  follow key rotations. If no custodian remains, the team has to be rebuilt
  from a recovery bundle (ADR 0002 Q-14)."
- Buttons "Distrust on this device" and "Cancel".

When a custodian key is revoked (counted `DeviceRevocationV2`) or distrusted on
this device, every **answered** `custodian.appointed` event that key issued
reopens with the note "The custodian who appointed this key is no longer
trusted". Q-19 keeps those appointments accepted, so this is where they get a
second look.

## Events

### `custodian.appointed` (routine unless the issuer is no longer trusted)

Raised when a key not in this device's custodian ledger becomes a custodian.

- **Title:** "New custodian key {subject key}"
- **Body:** "This device first saw this on {time}. The custodian key {issuer key}
  made {subject key} a custodian (named {label} by the server). Custodians can
  approve devices and hand out team keys. If nobody on your team did this, the
  key that appointed it may be stolen."
- **Answers:**
  - "I know about this": records the answer for this record.
  - "I don't recognise this": opens the distrust panel with **two** choices,
    "Distrust the new key" and "Distrust the new key and the key that appointed
    it". The panel names the issuer and shows its consequences (above). In a
    forged appointment the stolen key is the issuer, so the panel says: "If you
    did not expect this, the key that appointed it is the one to worry about."
    Then:
    - on a device holding `device.revoke`: "Revoke the device behind this key",
      shown only when the subject key belongs to a device the server lists for
      this tenant. If it does not, the card says "This key has no device in the
      team, so it can only be distrusted on each device", and the W6 item
      "revocation of a key without an enrolled device" is raised to the ADR,
      because `DeviceRevocationV2` names a subject device;
    - otherwise "Ask a custodian to revoke it", listing custodian keys from the
      local ledger (Principle 6).
- **Urgency:** routine; urgent when the issuer is revoked or distrusted on this
  device.
- **Re-raise:** each new appointment record of the same subject is a new event.

### `custodian.renewed_after_revocation` (always urgent)

Raised when a custodian window is extended for a key whose device this client
knows is revoked or re-keyed.

- **Title:** "A key that should be retired was renewed"
- **Body, revoked:** "{subject key} (named {label} by the server) belongs to a
  device that was revoked for '{reason}'. This device first saw its custodian
  window extended by {issuer key} on {time}. A team normally never does this;
  it usually means a key was stolen."
- **Body, re-keyed:** "{subject key} was replaced by a new key for the same
  device, but this device first saw the old key renewed by {issuer key} on
  {time}. A team normally never does this; it usually means the old key was
  stolen."
- **Answers:**
  - "Distrust both keys on this device" (primary): the distrust panel with both
    keys and their consequences. On a device holding `device.revoke`, the next
    step offers "Revoke the device behind {issuer key}"; otherwise "Ask a
    custodian" comes first.
  - "I have checked; this is expected": enabled only after typing the **last 4
    hex digits of the subject key**. A label could be chosen by the server; the
    key digits cannot.
- **Re-raise:** the answered state is keyed on the extending record's
  `signed_container_hash`. Every later extension (the thief "repeats before each
  window ends", D-6) is a new event, whatever was answered before.

### `revocation.refile_needed` (routine)

Raised on a custodian holding `device.revoke` when every issuer of a revoked
device's revocations is no longer a custodian (lapse, revocation or re-key).

- **Title:** "Re-file the revocation of {device key}"
- **Body:** "{device key} (named {label} by the server) was revoked for
  '{reason}'. Every custodian who signed that revocation is no longer a
  custodian. A team device that comes back after a long time offline can still
  refuse the revoked device's changes, but it cannot undo them until the
  revocation is signed again by a current custodian."
- **Answers:**
  - "Re-file now" (primary): files a fresh `DeviceRevocationV2` for the same
    device with the same reason code. The card closes on every custodian once
    one re-file is counted.
  - "Not needed", with a required reason: "Another custodian will re-file" or
    "No team device stays offline for long". The reasons are about the honest
    devices that re-filing protects.

### Several items at once

The strip shows one headline for the most urgent cause, then "and {k} more",
which expands to one line per cause and per urgent event. Causes are grouped:
`compromised` (commits paused), `lost` and grant-only `compromised` (rotation
needed), then urgent events. No cause is dropped from the expanded list.

## Rotation banners

The text and the checklist are built from the **set of flagged items**
(the root, and each fleet), each with its own cause (ADR 0002 Q-13). The root is
flagged only while its ACTIVE generation is exposed. A member device's
revocation flags only that device's fleets, and a `FLEET_GRANT_REVOKE` flags
only its fleet.

| Tier | Cause | Strip text | Blocks commits |
|---|---|---|---|
| Urgent | `compromised` device revocation | "A device was revoked as compromised. Saving to the server is paused for {list of fleets} until their keys are rotated." Then, only when the root is flagged: "Rotate the root key first, then each fleet." Button "Start rotation" | Yes (Q-18) |
| Urgent | `lost` device revocation | "A lost device may still hold keys for {list of fleets}. Rotate them so new snapshots use keys it never had." Root-first sentence only when the root is flagged | No |
| Urgent | `FLEET_GRANT_REVOKE` with `compromised` | "{member key} was removed from {fleet} as compromised, but saving is not paused. Rotate {fleet}." On a device holding `device.revoke`, a button "Revoke the device" | No |
| Routine | `retired`, `rekeyed`, other grant revocations | Not in the strip. Settings → Team: "Key rotation recommended: {n} fleet(s) still use keys a removed device had." | No |

The strip never names a person. Fleets are named by the names this device
already shows.

### Key rotation checklist

1. **Root key**: one of "Not needed", "Needs rotation", "Preparing", "Waiting
   for {n} acknowledgements", "Done".
2. **Each flagged fleet**: when the root is flagged, a fleet step is disabled
   until the root step is done, with "A fleet rotated before the root stays
   flagged." When the root is "Not needed", fleet steps start enabled.

A step waiting on a member who cannot acknowledge shows that member's key and
the way out: "Remove this member from {fleet}, then start the rotation again
without it" (ADR 0002 Q-18, stalled rotation). Devices without `key.rotate` see
"Ask a custodian to rotate", with custodian keys from the local ledger.

## Commit-blocked state (Q-18)

For a profile in a fleet blocked by a `compromised` cause:

- The profile row shows a lock badge "Saving paused" with the tooltip "This
  fleet's keys must be rotated before changes can be saved to the server.
  Changes stay on this device. When saving resumes, you may need to resolve a
  conflict with changes saved from other devices."
- Sync is refused before checkout (ADR 0002 Q-18), so no lease is taken and no
  commit is sent. Whether the browser profile may still be **opened locally**
  without a lease is not defined by ADR 0002. This design does not invent it:
  W6 implements whatever the existing checkout rules allow, and the tooltip
  above is accurate either way.
- When the block starts while a profile is open, the ADR 0002 in-flight rules
  apply: an upload already `READY` (or `FINALIZING` during recovery) completes;
  an `OPEN` upload is aborted, the row shows "Saving paused", and the profile
  stays `AVAILABLE` with `dirty = 1` after its lease is released.
- When the block lifts, the badge disappears and the next sync runs the normal
  version check. A conflict goes through the existing conflict path; no special
  path is added.
- `ROTATION_REQUIRED_COMPROMISED` maps to this text and is never shown raw.

## Revoke dialog: the `DEVICE_REVOKE` default (open note, decided here)

**Decision.** When an admin removing a member from a fleet picks the reason
"compromised", the dialog makes "Revoke the whole device (recommended)" the
primary action. It says:

- "Only revoking the device pauses saving until the keys are rotated. Removing it
  from this fleet alone leaves keys it already has usable for new snapshots
  until a rotation."
- The cost: "This pauses saving to the server for {n} fleet(s) until their keys
  are rotated." When the device is a custodian: "This device is a custodian, so
  saving pauses for every fleet in the team, and the root key must be rotated
  first."
- An option "Start the rotations in the same step", which includes the
  activations in the revoke request, as C-1 allows.

Removing the grant only stays available as the secondary action, because the
admin may not hold `device.revoke`. If the admin lacks it, the dialog says "A
custodian must revoke this device", and the grant revocation's urgent strip on
custodian devices that hold `device.revoke` carries a "Revoke the device"
button, so the follow-up is in front of the person who can do it.

**Why.** Only a signed `DeviceRevocationV2` starts the Q-18 block. A grant
revocation with `compromised` gives an urgent banner but leaves commits open
under a key the member holds (ADR 0002 Q-20).

## Wording and translation

All strings go into `src/shared/i18n/locales/en.json` and `vi.json` together,
under a `teamSecurity.` prefix, and are covered by `npm run test:i18n`.

## Acceptance tests for W6

The rules that raise and clear each item are proven by the Rust harness rows
ADR 0002 already lists (Q-13 "Tests", Q-18 "Commit block", D-6 (a)). The UI
tests below are e2e scenarios on the mocked IPC, in the style of
`tests/e2e/app.spec.ts`, and check only what is shown and what each answer
sends.

1. `custodian.appointed`: "I don't recognise this" offers both distrust
   choices and names the issuer; revoke appears only with `device.revoke` and a
   listed device; the answer appears in history with the local time.
2. Reopening: revoking the issuer of an answered appointment reopens it.
3. `custodian.renewed_after_revocation`: the strip gains a line; "expected"
   stays disabled until the last 4 hex digits of the subject key are typed; a
   second extension after an answer raises a new event.
4. Distrust panel: shows "cannot be undone" and the only-path warning when the
   key is the only custodian path; Cancel changes nothing.
5. `revocation.refile_needed`: "Re-file now" sends one revocation with the same
   reason code; "Not needed" requires one of the two reasons.
6. Urgent `compromised`, custodian revoked: the strip cannot be closed; rows show
   "Saving paused"; fleet steps stay disabled until the root step is done.
7. Urgent `compromised`, member revoked with the root clear: the strip names only
   that member's fleets; the root step shows "Not needed"; fleet steps are
   enabled.
8. Grant-only `compromised`: the urgent strip says saving is not paused, and
   shows "Revoke the device" only on a device holding `device.revoke`.
9. Several causes: one headline plus "and {k} more", and every cause in the
   expanded list.
10. Routine notice: nothing in the strip, no sidebar count; with a routine notice
    present, a new `appointed` event still raises the count.
11. Revoke dialog: "compromised" makes device revocation primary, states the
    fleet count, and the custodian wording when the device is a custodian.
12. Nothing raised: a device approval, a planned rotation and a renewal by a
    trusted custodian raise no event and no count.
13. Baseline: a device with no history records the baseline entry and raises no
    `appointed` event for keys present at join.
14. No item opens a modal on its own.

## Review record

| Date | Reviewer | Verdict | Changes made |
|---|---|---|---|
| 2026-10-25 | Independent design critic (fresh context; given ADR 0002, this document, `TeamCard.tsx`, `IncompatibleNotice.tsx` and the `team.` strings) | REVISE: 8 MAJOR, 7 MINOR | Revision 2, all 15 addressed (below) |

Disposition of the findings:

| # | Finding | Change |
|---|---|---|
| M1 | "Root first" stated in every case | Text and checklist built from the flagged set; root "Not needed"; grant-only text; test 7 |
| M2 | One dot masks new events behind a routine notice | Sidebar count only for events and urgent causes; test 10 |
| M3 | Distrust overstated, cost hidden, no undo | "Distrust" section: new records only, consequences, only-path warning, Cancel, "cannot be undone"; test 4 |
| M4 | `appointed` distrusts the wrong key | Issuer offered too; answered appointments reopen when the issuer loses trust; tests 1, 2 |
| M5 | Merge and re-raise undefined | Answers keyed on `signed_container_hash`; every new extension or appointment re-raises; test 3 |
| M6 | Device labels come from the server | Keys lead, labels "named by the server", confirmation by key digits, custodian lists from the local ledger |
| M7 | `DEVICE_REVOKE` default hides cost and follow-up | Fleet count and custodian wording, rotations in the same step, "Revoke the device" on the grant strip; tests 8, 11 |
| M8 | Commit-blocked state over-promised | No new open-without-lease mode invented; conflict wording; in-flight rules; normal conflict path |
| m9 | "Only a stolen key" too strong; re-keyed case | "Normally never… usually means"; separate re-keyed body |
| m10 | First-seen time shown as event time | Principle 9 and "This device first saw this on" |
| m11 | Re-file wording and reasons | Custody ends by lapse, revocation or re-key; returning devices refuse but cannot undo; reasons about honest devices |
| m12 | Several urgent causes | Headline plus "and {k} more", nothing dropped; test 9 |
| m13 | Principle 4 contradicted the table | Routine notice has no strip |
| m14 | No-history baseline silent | Baseline history entry; test 13 |
| m15 | Tests | Rust harness cited for clearing logic; tests 3, 7, 9, 12 added; "on this device" wording |

Open item carried to W6: the reviewer could not confirm whether a
`DeviceRevocationV2` can name a forged custodian key with no enrolled device.
ADR 0002 defines the record with a subject device, so this design offers revoke
only when the server lists a device for the key, and records the gap as a W6
item ("revocation of a key without an enrolled device") to bring back to the
ADR.
