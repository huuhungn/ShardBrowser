# Key custody and recovery

How profile encryption keys are held today: the verified fleet key that team
profiles sync under, the passphrase that remains for local backups and legacy
passphrase sync, and what the frozen v2 design still calls for.

Updated for the v0.2.2a custodian slice. Every claim here was checked against
the code, not the plan: where the plan describes something that does not exist
yet, this document says so.

## What exists today

### Local backup

`shared/src/backup_file.rs` derives the file key from a passphrase:

```
FKEK = Argon2id(passphrase, salt)     salt: 16 random bytes, stored in the file
DEK  = random 32 bytes                wrapped under FKEK
```

The DEK encrypts the profile; the FKEK only wraps the DEK. The salt travels in
the file header, so any machine can open a backup given the passphrase.

**There is no recovery path.** The passphrase is not stored, not escrowed, and
not derivable. A forgotten passphrase means the backup is unreadable — stated
plainly in `backup_cmd.rs` and in the UI before the user commits to it. This is
a deliberate trade, not an oversight: escrow that the Launcher could use
unattended is escrow an attacker with the same machine could also use.

### Fleet sync

A team profile, one published to the fleet, syncs over the G2 wire
(`src-tauri/src/team/sync.rs`). Each snapshot is sealed under the fleet's
`ACTIVE` fleet key (FKEK), and only under a key whose grant still verifies now
against the anchor this device pinned (`seal_snapshot`, `verified_key`); never
under the passphrase. Without such a key, publish, push, pull and join refuse
with `sync.noVerifiedFleetKey`, and a push releases the lease it took. The team
server stores ciphertext, hashes and versions; it holds no key and cannot open
what it stores. How the key reaches a device is in "What ships" below; what
revoking a device does and does not protect is in "Revocation: what it does and
does not protect".

Legacy passphrase sync remains for a profile that is not published. Its push
(`src-tauri/src/sync_cmd.rs`, `seal_for_push`) uploads exactly the container
`backup_file` produces, sealed under the shared team passphrase, and refuses an
empty one. Its pull tries the cached fleet keys newest first, then the
passphrase: a key collected from a verified grant only while that grant still
verifies, and a key cached by 2.4.2, which no grant ever verified, without a
check. On this path the passphrase is a shared
secret between devices, communicated out of band:

- Excluding a device means changing the passphrase and re-pushing.
- A leaked passphrase compromises every snapshot sealed under it.
- Nothing binds such a container to the tenant that stored it.

### Device keys

Enrollment (`server/src/enrollment.rs`) registers two keys per device:

| Key | Purpose | Stored |
| --- | --- | --- |
| Ed25519 signing | Proof of possession; signs snapshot manifests | OS credential store; else the key file or `team.json` |
| X25519 HPKE recipient | Opens root key grants sealed to this device | OS credential store; else the key file or `team.json` |

`team_collect_custody` uses the HPKE key to open root key grants and this
device's fleet key grant. The fleet key is kept only when its grant verifies
against the anchor this device pinned: the root custodian's bootstrap anchor,
or the anchor A0 a joining device confirmed with its join code (see "What
ships" and the threat model below).

Both seeds move into Windows Credential Manager (ADR 0004, `credential.rs`),
and `team.json` keeps only their references. Without a usable store they go
to the passphrase-protected key file (ADR 0002 D-5, `key_file.rs`) once the
operator creates one. A seed still in `team.json` is DPAPI-protected for the
current Windows user (`dpapi.rs`); elsewhere it is plaintext hex, protected by
file permissions alone. Keychain and kernel keyring are not wired up.

> **Warning: an administrator password reset loses the device keys.** Windows
> Credential Manager and DPAPI protect them with the Windows user's password.
> The user changing that password keeps them readable; an administrator
> resetting it (from another account or with `net user`) makes them
> unreadable for good on a local Windows account. A domain-joined account may
> recover them through the domain's DPAPI backup key; that was not checked.
> The Team page then says the keys are lost (`keys_lost`), or that the key
> store did not answer (`key_store_unavailable`: try again before resetting).
> A member device is reset: a custodian revokes it, then **Reset this device**
> (`team_enroll_again`, which accepts a pending, an unpinned active or a
> revoked row) copies `team.json` aside as `team.json.unreadable-<ms>`, keeps
> the old credentials, and the device enrolls again as a new row. The root
> custodian is never reset: it imports its recovery bundle (see "Recovery").
> For a member whose keys are lost and that the server **no longer lists**,
> Reset is refused; with the launcher closed, move `team.json` out of
> `%APPDATA%\shardx-launcher`, reopen the launcher, save the server URL and
> tenant ID again, and enroll it as a new device.

## What the design calls for

`.omx/plans/…-team-fleet-encrypted-backup.md` §5.6.4 defines a tenant root key
(TRK) that never leaves a device in the clear:

```
TRK ──HPKE seal to device HPKE public key──▶ v2_tenant_root_key_grants
```

Each device gets its own sealed copy. `shared/src/grants.rs` implements the
sealing (`seal_trk`, `open_trk`, 32-byte encapsulation, 48-byte wrapped key,
AAD bound to the grant fields) and the schema in `0004_v2_team_fleet.sql` has
every column needed to store one.

The lifecycle is three grant variants:

- `FirstRootSelfGrant` — the bootstrap device creates the TRK and seals it to
  itself, once per tenant, inside one `BEGIN IMMEDIATE` transaction.
- `ExistingRootGrant` — an active custodian seals the current TRK to a newly
  enrolled device.
- `RotationGrant` — a custodian seals a new generation, after which the old one
  is retired.

Revocation is deliberately narrow: revoking a grant blocks *future* unwraps but
cannot retract a TRK a device already copied. Excluding a device means rotating
to a new generation and re-wrapping — the design says this explicitly, and it is
the right model to keep.

### What ships

| Piece | State |
| --- | --- |
| `seal_trk` / `open_trk` | Implemented in `shared`; exercised end to end by the grant tests |
| `v2_tenant_root_key_grants` table | The exact plan 7.2 shape since migration 0016; spike rows stay read-only in `v2_legacy_tenant_root_key_grants` |
| `POST /v2/tenants/:tenant/root-key-generations` | S6 bootstrap: the D1 device's setup session files its signed `FirstRootSelfGrant` and generation 0 in `PREPARING`, as one exact idempotent mutation |
| `GET /v2/tenants/:tenant/devices/:device/root-key-grants` | Returns a device's sealed grants of an `ACTIVE` generation only, and only to that device's own v2 session; a v1 token gets 403. The tenant trust evidence still serves every sealed root grant to the tenant's device sessions, because clients derive `rotation_required` from them (ADR 0002); a grant opens only with its recipient's HPKE key |
| Root custody setup | "Set up root custody" on the tenant's first device: root generation 0 and its self grant, acknowledged and activated, and the recovery bundle written locally. Root key rotation is not implemented |
| Fleet key | "Create fleet key" on the root custodian: fleet generation 0, its device and recovery grants, acknowledged and activated. The key is kept only once a verified collect opens it. A setup left unfinished until its saved requests expire (one year) leaves the generation `PREPARING` with no route to finish or discard it; no server route discards it yet |
| Approving a device | The custodian's device list shows each pending device's code, computed from the custodian's pin and the listed key IDs, with both full key IDs and the anchor one click away. Approve needs the "code matches" box ticked and is refused more than ten minutes after this computer first saw the row. It files the device's fleet-scoped approval, its three profile capability grants and its fleet key grant |
| Joining | The new device's "Show join code" works for ten minutes after its own enrollment, by its own clock. "Codes match" pins the anchor (A0), and "Collect key custody" keeps the fleet key once its grant verifies against that pin. An expired code offers "Enroll again"; the old row stays on the server until a custodian revokes it |
| Revocation | Revoke on the device list, as retired or lost. `compromised` is not offered |
| Fleet key rotation | "Rotate fleet key" on the root custodian (2.9.0): see "Fleet key rotation" below. Root key rotation is not implemented |
| Recovery bundle | A v3 bundle (2.8.0) holds the root custodian's device identity, the root key and, when exported again after the fleet key exists, the team's verified fleet keys; a bundle from 2.7.x holds only the root key and cannot restore the team |
| Approvals and grants | Run one year, with no renewal |

The table describes 2.9.0. v2.10 (ADR 0002 Q-52 to Q-58) changes it, with no
server change:

- **Revocation** also offers `compromised` for member rows; custodian rows
  keep `retired` and `lost` (Q-57).
- **Recovery bundle:** v3 while the root custodian's current root grant is its
  first self-grant, v4 once a renewal or a hand-over replaced it (Q-53).
- **Approvals and grants:** the root custodian renews its own records at
  half-life, approval and root grant for two years, the rest for one (Q-55).
  Members' records still run one year with no renewal until v2.11.
- **Re-seal all profiles** on the root custodian (Q-54).
- **Root custody hand-over** to a new device (Q-56, Q-58): see "Root custody
  hand-over" below. Root key rotation still is not implemented (v2.11).

A grant has to name a generation that exists, and wrap the key that generation
committed to. Before this, the generation number in a grant was decoration: a
grant could name any number and seal any key, and the mismatch would only
surface later as a backup nobody could open.

Each key is generated on the device and never transmitted: a create request
names only the key's identifier, which is what keeps the server unable to read
anything sealed under it. A generation becomes `ACTIVE` only after its holder
acknowledges that it can unwrap what it filed.

Activation is deliberately separate from filing. Filing proves a grant was
written; it does not prove anyone can open it. A tenant that activated on filing
could seal itself under a key it had already lost, and that failure is
unrecoverable by construction — the server cannot help, because it never sees a
key.

Team profiles sync under the fleet key. The team passphrase and the v1 API
token remain only for legacy passphrase sync; connecting and every device
session work without a token.

### Revocation: what it does and does not protect

Revoking a device:

- In one transaction, revokes the device, ends its sessions, releases its
  leases, and revokes every approval, capability grant, root grant and fleet
  device grant naming it (`server/src/routes/v2_device_revoke.rs`).
- Stops new sign-ins as that device and new fleet grants to it.
- Puts out a signed revocation that clients count. From then on they refuse
  records signed by its key that they had not already seen.
- Quarantines heads it signs afterwards (`SIGNER_REVOKED`).
- Also quarantines, as `SIGNER_REVOKED`, a head it signed **before** the
  revoke, if a device already pinned that head. The custodian (or another
  device that can commit the profile) then has to run Revert on it to continue
  (ADR 0002 rule 6).

It does not:

- **Recall the fleet key the device holds.** Its generation stays `ACTIVE`
  until the custodian rotates the fleet key. Until then the device can decrypt
  every snapshot it downloaded and any later snapshot ciphertext that leaks to
  it, because new snapshots still use its key. It cannot fetch them through
  the server. After a rotation it still reads whatever was sealed under the
  keys it held.
- Delete profiles already pulled to its disk.
- Rotate keys. The custodian's Team page shows a banner when a revoked device
  held the current fleet key: urgent for `lost` (or a saved revocation that
  does not verify), routine for `retired`. It is advisory and clears once the
  fleet key is rotated.
- Survive a server that hides the revocation.
- Change anything else that is still shared. Both machines use the one tenant
  account, and its password is unchanged. The revoked machine can still sign
  in and enroll a *new* pending device, which gets nothing without a fresh
  approval. A shared legacy v1 token, if one was configured, also stays valid.

The launcher saves a revocation request before sending it and resends those
exact bytes on a retry. It builds a new one only when the server refuses the
saved one with `REVOCATION_OUTSIDE_WINDOW` and the device is not yet revoked;
any other refusal leaves the saved request as it is. An older server never
sends that code, so the launcher and the server are released together.

From v2.10 (ADR 0002 Q-57, Q-58):

- **`compromised`** is offered for a member row. A counted `compromised`
  revocation blocks commits under the generations that device held until the
  custodian rotates and the members collect (Q-18). It is refused for this
  device, for an outgoing custodian, and for any row whose key fresh evidence
  counts as a custodian; custodian rows get it in v2.11.
- **Revoking a custodian** (the old root after a hand-over) makes every device
  that counts the revocation refuse records by that key it first sees
  afterwards, member approvals the old root issued included. So the evaluation
  that would first count it is a *closure evaluation*: one evidence request
  that names every known device signer, at most 64, so that every member
  approval is first seen together with the revocation and keeps its standing.
  Every device ever named as the subject of a fleet key grant
  (`DeviceHpkeGrant`) counts toward the 64, revoked and retired ones included,
  not only today's members. A device that would need more than 64 fails
  closed (`fleet.trustClosureTooLarge`) and stays blocked until v2.11 brings a
  helper that evaluates several listings. A member the server leaves out is
  distrusted and enrolls again. A member still on 2.9.x when the old root is
  revoked distrusts peers it has not seen and must enroll again.

### A failure worth remembering

`record_table` in `v2_replay_ledger` had a CHECK constraint listing only the
device-approval and capability-grant tables. Root key grants claim their replay
id from the same ledger, so every attempt violated it.

The claim runs as `INSERT OR IGNORE ... changes()`, and OR IGNORE swallows a
CHECK violation exactly like a duplicate primary key — zero rows affected. The
endpoint read that as "already used" and answered `409`, so filing any grant
looked like a replay of a record that had never been stored. Grants were both
impossible to file and entirely unprotected against real replay.

Migration `0005` widens the constraint, and `consume_replay_id` now confirms the
row actually exists before reporting a replay, so a future constraint gap
surfaces as an error instead of a false accusation.

## Device custody collection

Enrollment generates an HPKE keypair, registers the public half with the
server, and now keeps the private half in `team.json` as `hpke_key_seed`.
Before this, the private half was discarded at the end of enrollment, so a
grant sealed to a device could never be opened by it: the custody chain broke
at the last step.

`team_collect_custody` fetches the grants issued to this device and opens each
one with that key. It reports counts, never the key itself -- where a recovered
root key should live is the storage question below, and handing it to the UI
would answer it badly.

Devices enrolled before the seed was persisted report
`can_receive_custody: false` and are told to re-enroll, rather than silently
failing to decrypt.

## Recovery

Root custody setup writes a *recovery bundle*: the TRK sealed under the
recovery passphrase. The bundle is re-read and checked to open before root
generation 0 is filed, and that generation pins the bundle's hash
(`root_bootstrap.rs`).

Create fleet key also files a *recovery grant*: the fleet key wrapped under the
TRK, kept on the team server.

### Recovery bundle v3 (2.8.0) and v4 (2.10)

From 2.8.0 the bundle's plaintext is v3: besides the TRK, the anchor ID and
the fleet keys it retains, it carries the root custodian's account and device
IDs, its signing and HPKE seeds and its exact first root self-grant. **A v3
bundle plus its passphrase is the root custodian device.** The team account
password adds no factor (every team device signs in as the one owner
account), so keep the bundle offline. A bundle exported before 2.8.0 holds no
root custodian and cannot restore the team (`recovery.bundleWithoutCustodian`):
the root custodian exports a new one with **Export recovery bundle** on the
Team page, once it holds the fleet key (`team_export_recovery_bundle`; it
files nothing and changes no state file). The page shows the root key ID, the
bundle's fingerprint (ADR 0002 D-5), and Export stays off until the owner
ticks that it was recorded. A bundle works only while the root
custodian's approval and grants run: 365 days from bootstrap. 2.7.x cannot
read the v3 state an import writes, so do not downgrade after an import.

From v2.10 a root custodian whose current root grant is no longer its first
self-grant (after renewing itself, or after receiving custody in a hand-over)
writes a **v4** bundle (ADR 0002 Q-53, D-5). Instead of the first self-grant
it carries the current root grant and the public key of the custodian that
signed it, so the bundle's device need not be the anchor. Import checks the
grant offline, then fetches trust evidence and requires the chain from the
pinned anchor to count the bundle's device as a custodian now
(`recovery.rootGrantIssuerNotCustodian`). A v4 bundle plus its passphrase is
that custodian device, exactly as for v3. A renewal replaces the records a
bundle names, so export again after one (the page asks); the new bundle works
for as long as the renewed records run. 2.9.x and older
cannot open a v4 bundle, and a bundle of a revoked device no longer imports
(`recovery.deviceNotActive`).

**Import** (`team_import_recovery_bundle`, under "Restore root custodian from a
recovery bundle" on the Team page) runs on a fresh device, or on the root
custodian's own machine after its keys were lost. The user ticks that the old
root custodian device is lost or its keys were reset. The import refuses to
run over another device's identity (`recovery.deviceHasIdentity`: reset a
member first), checks the bundle against the saved tenant and against the
anchor this device already trusts for that tenant before any request
(`recovery.otherAnchor`), then against the server's live row of the bundle's
device (`recovery.otherServer`, `recovery.otherAccount`,
`recovery.deviceNotActive`), opens a session with the bundle's keys, reads the
root self-grant back, writes the state files and `team.json` last, then
collects the fleet key. A member's `fleet-custody.json` found on the device is
moved aside as `fleet-custody.json.replaced-<ms>` and written again for the
root custodian; another custodian's is refused (`fleet.custodyOtherDevice`). A failed collect leaves the
import done (`recovery.importedCollectFailed`); run Collect key custody again.
When the session challenge answers 409 for a row the server listed as active
with the bundle's keys, the import reports `recovery.approvalExpired`; the
challenge's rare other 409s ("keys need reconciliation", "cannot hold a
session") read the same way.

What an import does not carry:

- `key_first_seen` starts empty, so a device that was pending when the root
  was lost gets a new ten-minute approval window on the importing machine.
  The code comparison still gates it.
- An approval the lost root filed whose fleet grant was not filed cannot be
  finished: approvals start empty. Revoke that device and have it enroll
  again.
- Saved revocations start empty; a revocation the lost root saved but never
  filed is rebuilt when the user revokes again.

Import and Reset remove from the `fleet-keys.json` index every fleet key that
does not open (any reason but a key file not opened yet), after copying the
file aside as `fleet-keys.json.unopenable-<ms>`. Stored keys are never deleted;
the next collect writes the key again from its verified grant. A 2.4.2 key
that left the index during a passing store fault has no verified grant and is
not collected again: restore it from the copy, which helps only while a later
collect has not rewritten the credential `fleet-key.{fleet}.{generation}`.

The root custodian keeps its connection, and so does a device whose root
custody setup has saved its create request, since the server may have
activated it before the setup finished: changing its server URL or tenant is
refused (`fleet.rootCustodianKeepsConnection`) unless both its device keys
are lost; then `team.json` is copied aside, nothing is forgotten, and import
is the way back. Any change of the URL string counts, so a root
custodian whose server moved to a new LAN address or port cannot change it on
the Team page: with the launcher closed, edit `server_url` in `team.json`.

A corrupt `fleet-custody.json` blocks a server or tenant change and a member
Reset: both clear the saved acknowledgements in that file, and when it does
not parse they fail closed before `team.json` changes. Reset has by then
already removed the unopenable fleet keys from the `fleet-keys.json` index
only. That is harmless: the file was copied aside first, the stored keys are
kept, and a later collect writes a verified key again.

The recovery passphrase is not stored anywhere: losing it and every device
that holds the keys loses the team profiles. Backups of `team.json` preserve
device identity, not profile contents.

For local backups and legacy passphrase sync, recovery is still exactly one
thing: **someone remembers the passphrase.** Operators should treat both
passphrases as credentials to be recorded in whatever the team already uses
for shared secrets, and should not assume the server can help. It cannot; it
never sees a key.

## Ordering the remaining work

Roughly the sequence the constraints force:

1. ~~**Persist TRK grants.**~~ Done: grants are stored and collectable, and a
   device can open its own grant.
2. ~~**Root generation lifecycle.**~~ Done for generation 0: root custody setup
   creates, acknowledges and activates it, with the `FirstRootSelfGrant`
   uniqueness the plan specifies. Root key rotation is not implemented.
3. ~~**Grant keys at enrollment.**~~ Done as approval: the root custodian
   approves a new device after comparing its join code, which files the
   device's fleet key grant. The device receives the fleet key, not the TRK.
4. ~~**Seal containers under a tenant key.**~~ Done for team profiles: they
   seal under the verified fleet key. Local `.shxbak` files keep the
   passphrase, since they have no tenant and should stay openable on a machine
   that has never enrolled, and so does legacy passphrase sync.
5. ~~**Recovery bundle plus readback.**~~ Done. From 2.8.0 the v3 bundle
   carries the root custodian itself, and import restores it (see "Recovery").
6. **Move device keys into the OS credential store.** Done on Windows
   (ADR 0004): seeds and cached fleet keys go to Credential Manager, with the
   key file as the fallback. Keychain and kernel keyring are not wired up.

7. **Fleet key rotation.** Done in 2.9.0 (see below).

v2.10, with no server change (ADR 0002 Q-52 to Q-58): moving root custody to
a new device row, the root custodian renewing its own approval and grants,
and re-sealing every profile under the newest fleet key at once. Once the old
row is revoked, a lost machine or an old bundle stops being a root custodian.

Still to come in v2.11, with one batched server update: root key rotation,
renewal of members' approvals and grants (which run one year), discarding a
stuck PREPARING generation, `compromised` for custodian rows, closures over
more than 64 signers, and Reset of a handed-over old root.

### Fleet key rotation

From 2.9.0 the root custodian rotates the fleet key with "Rotate fleet key" on
the Team page. The run creates generation N+1 with this device as its only
required holder, files its device, recovery and rotation grants, acknowledges
and activates them (the server retires N in the same step), collects N+1
verified, then grants N+1 to every member a signed approval names, minus
revoked or withdrawn devices. Every request is saved before it is sent, so an
interrupted run resumes with "Resume fleet key rotation". Approvals wait while
a rotation is unfinished. An approval interrupted before a rotation resumes
under the new generation, and every resume sends its saved fleet grant only
to a device the rotation did not skip, this custodian did not revoke and whose
key the trust ledger does not hold withdrawn. The new generation must activate within 30 days; a
rotation that runs out of time, or is caught by a server restore before it
activated, expires: the team keeps generation N and approvals work again.
Rotate stays available: when N+1 never reached the server, or a restore
removed it, the next rotation starts over; when the server still holds N+1
as PREPARING, that rotation ends expired again as stuck until a later version
can discard that generation on the server.

Re-sealing is lazy. Old snapshots stay under the key they were sealed with;
a pull reads them while this device holds that key with a grant still in
force, and the next push seals under the newest key. Generations never go
down along a profile's chain: a head under an older key than its profile
already uses is refused. Two costs follow:

- A device approved after a rotation, or restored from a recovery bundle,
  cannot read a profile that was not pushed again under the new key. It is
  told to ask a member who still holds the old key to push it once.
- A profile left under a retired key becomes unreadable for every device once
  the old key's device grants end (one year from each grant), since a retired
  generation's grants are never renewed.

The custodian's Team page lists "Profiles still under an older key" (those
bound on its own device whose last pinned or pushed head is below the newest
generation it verified), each with "Push": a push that seals under the newest
key. It never pulls: when the server says the local copy is behind its head,
nothing is pushed and the row asks to pull the profile from the profile list
first, since a pull replaces local changes this device has not pushed. The
list reloads after a Check in, Pull or Unbind there. After a server restore a row
keeps the previous head's generation until the next pull. A finished rotation
also asks for the recovery bundle to be exported again, since an earlier
bundle does not open the new key. Known limitation: an export that finishes
while another custody action (listing, approving or revoking devices) holds
the custody lock leaves that prompt up; exporting again clears it.

Members pick up the new key with "Collect key custody"; a push or pull refused
under the old key says so. A member offline across two rotations cannot take
the newest key and must be revoked and enroll again. A member the server
refused, or one without a valid signed approval, is skipped and enrolls again
the same way. Rotation does not cut off a stolen root machine or a leaked
recovery bundle: both open the new key's recovery grant. That needs root key
rotation.

From v2.10 the root custodian also has **Re-seal all profiles** (ADR 0002
Q-54). It moves every profile head under an older key, and during a hand-over
every head the outgoing custodian signed, to the active key in one run,
re-signed by this custodian, without a profile folder. It skips and lists
profiles in use (running, leased, with local changes or behind), in error,
quarantined or under a key this device does not hold, and resumes where it
stopped. Each re-sealed profile moves up one version, so a member with
unpushed changes must Pull first, which replaces those changes. Snapshots
below the heads keep their keys. Pushing a single profile from "Profiles
still under an older key" stays available.

In a hand-over, the new custodian's rotation grants the new key to every
member but not to the outgoing custodian (`skipped:outgoing-custodian`).

## Root custody hand-over

Since v2.10 (ADR 0002 Q-56, Q-58, D-5 sequence H), on the Team page. It moves
root custody from the current root machine A to a new device B, which is how a
custodian re-keys before its key age (1095 days). Once the old row is revoked,
a lost machine or an old bundle stops being a root custodian. No server change
is needed.

1. B enrolls and joins like any member, comparing the join code.
2. On A, **Approve as root custodian**. It is refused
   (`fleet.handoverNeedsReseal`) until A's own Re-seal all profiles finished
   with every head under the active key. A files B's tenant approval and root
   grant (two years each) and B's grant of the current fleet key N. From then
   on A refuses every custody action (`fleet.custodyHandedOver`). A can cancel
   by revoking B only until B rotates (`fleet.handoverPastRotation`).
3. On B, **Accept root custody**. B keeps the root grant only if its own trust
   chain, from the anchor it pinned, counts it
   (`fleet.handoverIssuerNotCustodian`). It then files its own capability
   grants and its own grant of N, after collecting A's.
4. B's checklist, each step enabled only after the previous one:
   0. **Export recovery bundle** (v4). Rotate needs it, so a lost B can be
      restored from it.
   1. **Rotate fleet key** to N+1, with no grant to A.
   2. **Re-seal all profiles**, including every head A signed.
   3. **Export recovery bundle** again, holding N+1.
   4. **Revoke the old root** as retired or lost (`compromised` is refused).
      Every send re-checks steps 0 to 3 and every profile head live
      (`fleet.handoverNotReady`). `retired` needs no blocker. `lost` may go
      ahead when the only blockers are heads A pushed after the re-seal, which
      are listed and reverted right after the revoke once the user confirms
      that exact list; each listed profile must be joined on B first (step
      `bind`), and a revert that fails is retried by the next Revoke. Before
      confirming, every member must run 2.10 and have
      synced once since the hand-over began: a member still on 2.9.x distrusts
      peers it has not seen and must enroll again.
5. A stays registered but inert: it cannot push, and every custody command
   refuses. Its Team page says it handed over and can be switched off. Switch
   it off. A revoked device cannot open a session to read its own signed
   revocation, so A stays inert, still holding its seeds and root state, until
   v2.11 brings Reset and the wipe of its seeds. A cancelled appointee stays
   inert the same way.

Step 4.4 relies on the closure evaluation in "Revocation", which keeps every
member trusted after a custodian is revoked, within its limits: at most 64
signers, fleet key grant subjects of the past included; a member the server
omits enrolls again; a member still on 2.9.x enrolls again.

What the hand-over does not do:

- **Cut A off cryptographically.** The root key is unchanged until v2.11 root
  rotation, and the server hands every fleet key's recovery grant to any
  device session. Until its row is revoked, A can open every fleet key, N+1
  included. Afterwards, anyone with A's root key and the server's data (a
  hostile server, a copy of its database) still can.
- **Keep history readable.** Once A is revoked, the fleet keys A's grants
  delivered stop opening on every device that counts the revocation. Re-sealed
  heads, later pushes and B's own key of N stay readable; older snapshots
  below the heads do not.
- **Run two at once.** One hand-over at a time.
- **Survive a restore from before the rotation.** A new custodian restored
  from its first v4 bundle (written before its rotation) has lost its
  hand-over state, so its Revoke of the old root takes the plain path,
  without the checklist or the live check of step 4.4.

## Root key rotation

In development for v2.11 (ADR 0002 Q-59, sequence RR). The root custodian
replaces the tenant root key (TRK) N with a fresh N+1 from the Team page
("Rotate root key"). It needs the 2.11 team server only when a stuck
generation has to be discarded (Q-60).

1. It is refused before anything is sent when this device is not the root
   custodian, handed custody over, or has another custody action unfinished
   (fleet rotation, re-seal, renewal, hand-over), a compromised-revocation
   block, or a fleet rotation still PREPARING on the server.
2. Every fleet key the team ever used is opened from its recovery grant under
   root N, verified against the pinned anchor, with TRK N. A key that does not
   open stops the rotation (`fleet.rootRotationMissingFleetKey`).
3. TRK N+1 is created in the credential store. A new recovery bundle (v4,
   holding TRK N+1, every fleet key and the rotation grant) is written to the
   path you choose, and its hash is pinned on the server, before root N+1 is
   created. Keep that file: older bundles stop working once N+1 is active.
4. The launcher files N+1, its rotation grant, a recovery grant of every fleet
   key under N+1, and activates N+1. Every step is saved before it is sent, so
   a crash or a lost reply resumes with the same bytes.
5. Then rotate the fleet key: the Team page asks for it until a fleet
   generation activates under N+1. Members are not interrupted by the root
   rotation itself.

If the activation waits for a stuck fleet rotation
(`fleet.rootRotationWaitsForFleetDiscard`) or the create finds a stuck root
rotation (`fleet.rootRotationStuck`), the server operator discards it with the
server stopped (see `docs/team-server.md`), and the rotation resumes.

What root rotation does not do:

- **Cut off an old TRK backwards.** Recovery grants under N stay on the
  server, so whoever holds TRK N (an old bundle, a handed-over root) still
  opens every fleet key up to that point. Only fleet keys activated after the
  following fleet rotation are out of its reach.
- **Cut off the current custodian.** Its own leaked bundle or stolen machine
  receives TRK N+1 like the rest of its keys. Hand custody over to a new
  device first (see "Root custody hand-over"), then rotate.

## Threat model, stated plainly

The team server is trusted for RBAC and coordination (who belongs to a
tenant, leases, version fencing). It is **not** trusted for key distribution:
a fleet key grant is accepted only when it verifies against the anchor this
device pinned, so a key the server sealed of its own choosing is refused.

- **Pinning.** The root custodian pins its bootstrap anchor at root custody
  setup. A joining device pins the anchor A0 by confirming its join code, a
  code over the server instance id, the tenant id, A0 and its own key IDs. The
  code is shown, and can be confirmed, only within ten minutes of that
  device's own enrollment, by its own clock.
- **Approving.** The custodian computes the same code from its pin and the
  key IDs the server lists, recomputing each listed key ID from its key.
  Approve needs the user to tick that the codes match, and is refused more than
  ten minutes after this custodian first saw the pending device, by its own
  clock; that first sight is never reset.
- **Collecting.** `team_collect_custody` keeps a fleet key only once its grant
  verifies against the pin, and refuses a different key for a generation it
  already holds (`KEY_SUBSTITUTION_DETECTED`).
- **Sealing.** A team profile's push seals under the verified `ACTIVE` fleet
  key and never the passphrase; its pull opens with a key whose grant still
  verifies. A legacy push seals under the shared passphrase and refuses an
  empty one.

What holds today:

- The server cannot read what a device pushes: a team profile is sealed under
  a fleet key the server never sees, a legacy push under the passphrase, which
  never leaves the devices. The server stores sealed containers only.
- A stolen container is useless without that key or passphrase.
- Tenant boundaries are enforced on every `/v2/` route (`require_tenant_member`).
  Root key generations are created, acknowledged and activated through signed
  requests (`v2_root`, `v2_root_grants`), not by membership alone.
- A stale push is refused: version fencing stops one device silently
  overwriting another.
- Key material at rest is in Windows Credential Manager (`persistence =
  Local`, so it never roams). What has to stay in `team.json` or
  `fleet-keys.json` is DPAPI-protected for the current Windows user. A file
  from an earlier version is rewritten protected the first time it is read,
  and its keys move to the store on the next protection pass. Elsewhere they
  stay plaintext hex, protected by file permissions alone (0600 on Unix).
- The TRK of a running root bootstrap is in the credential store (OS store, or
  else the open key file) under `tenant-root.{tenant}`. `custody-bootstrap.json`
  keeps only that reference, never the key, and the key is forgotten once the
  generation is active. With no store and no open key file the bootstrap stops
  with a `credential.*` error instead of writing the key to disk. A file from
  an earlier version that still carries the key is moved into the store the
  next time the bootstrap runs; if the store refuses, the file is left as it
  was and the run fails. If that file had no self-grant yet, nobody else saw
  the key and it is dropped for a fresh one. A launcher that held a cleartext
  TRK should rotate to the next root generation after activation.

DPAPI recovery caveat. A protected `team.json` or `fleet-keys.json` opens only
under the same Windows account with the same DPAPI master key. An
administrator resetting the account password, reinstalling Windows and copying
`%APPDATA%` back, or moving the files to another account or machine leaves
them unreadable. A backup of these files therefore no longer carries a device
identity across machines: a member device must enroll again, and the Launcher
says so (`keyStore.otherWindowsAccount`) instead of reporting a corrupt key.
The fleet keys in `fleet-keys.json` are lost the same way: the device enrolls
again, is approved again and collects the fleet key again. The root
custodian's identity survives through its v3 recovery bundle instead: import
it on the new machine or account (see "Recovery").

What does not hold:

- Recalling keys from a revoked device. Revocation cuts the device off the
  server, but it keeps the fleet key it already holds; see "Revocation: what
  it does and does not protect".
- From v2.10, a cryptographic cut-off of an old root after a hand-over. Its
  cut-off is server-enforced until v2.11 rotates the root key; see "Root
  custody hand-over".
- From v2.11, a cut-off of the current custodian's own leaked bundle by a
  root rotation: root rotation cuts off a handed-over root's TRK going
  forward; it does not cut off the current custodian's own leaked bundle:
  hand over first. See "Root key rotation".
- From v2.10, trust in a member the server leaves out of the evidence when a
  custodian is revoked: that member is distrusted and enrolls again. A server
  can deny service this way, not forge trust.
- From v2.10, renewal of a root custodian nobody uses. Renewal runs on custody
  and sync actions, so an unused custodian renews only on its next use, with a
  warning from 75% of its records' lifetime. One left unused until its records
  end lapses, and the team then recovers into a new tenant (ADR 0002 Q-14).
- Forward secrecy across rotations. A fleet key rotation protects only what is
  pushed afterwards; old snapshots stay under the keys a revoked device held.
- Device key confidentiality against code running as the same Windows user,
  which can ask Credential Manager and DPAPI too, or against local disk access
  on other platforms.
- Integrity of a legacy passphrase snapshot: anyone with the passphrase can
  seal one that opens.
- Integrity of a legacy snapshot pulled under a fleet key cached by 2.4.2:
  that key was never verified, so a server that chose it can substitute a
  snapshot that opens.
- Recovery of local backups and legacy passphrase snapshots, if the passphrase
  is lost.
- Secrecy of the account password or a session token against a hostile team
  server. The launcher keeps them out of its own logs, state and error
  strings, and removes the forms of them it recognizes from a server's refusal
  text; a refused login keeps only the server's error code, and a device list
  naming a device or account ID equal to the password is refused. A server that
  received the password or a token can still return it in an encoding the
  launcher does not recognize. The account password protects that account at
  that server only, so use a password unique to it.

`P-OP` remains blocked, and this is one of the reasons.
