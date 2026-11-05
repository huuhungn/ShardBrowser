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
| Root custody setup | "Set up root custody" on the tenant's first device: root generation 0 and its self grant, acknowledged and activated, and the recovery bundle written locally. Rotation is not implemented |
| Fleet key | "Create fleet key" on the root custodian: fleet generation 0, its device and recovery grants, acknowledged and activated. The key is kept only once a verified collect opens it. A setup left unfinished until its saved requests expire (one year) leaves the generation `PREPARING` with no route to finish or discard it; that waits for fleet key rotation |
| Approving a device | The custodian's device list shows each pending device's code, computed from the custodian's pin and the listed key IDs, with both full key IDs and the anchor one click away. Approve needs the "code matches" box ticked and is refused more than ten minutes after this computer first saw the row. It files the device's fleet-scoped approval, its three profile capability grants and its fleet key grant |
| Joining | The new device's "Show join code" works for ten minutes after its own enrollment, by its own clock. "Codes match" pins the anchor (A0), and "Collect key custody" keeps the fleet key once its grant verifies against that pin. An expired code offers "Enroll again"; the old row stays on the server until a custodian revokes it |
| Revocation | Revoke on the device list, as retired or lost. `compromised` is not offered |
| Fleet key rotation | Not implemented: a revoked device keeps generation 0 (see below) |
| Recovery bundle | Holds the root key. It does not include the fleet key yet, which stays recoverable through the server's recovery grant |
| Approvals and grants | Run one year, with no renewal |

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

- **Recall the fleet key the device holds.** Until rotation ships, generation 0
  stays `ACTIVE`. The device can decrypt every snapshot it downloaded and any
  later snapshot ciphertext that leaks to it, because new snapshots still use
  its key. It cannot fetch them through the server.
- Delete profiles already pulled to its disk.
- Rotate keys. The fleet becomes `rotation_required`, which is advisory for
  `retired` and `lost`.
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
TRK, kept on the team server. The bundle does not yet hold the fleet key; the
fleet key stays recoverable through that server recovery grant (the bundle's
TRK opens it). No restore command ships yet, so this path is not automated.

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
   uniqueness the plan specifies. Rotation is not implemented.
3. ~~**Grant keys at enrollment.**~~ Done as approval: the root custodian
   approves a new device after comparing its join code, which files the
   device's fleet key grant. The device receives the fleet key, not the TRK.
4. ~~**Seal containers under a tenant key.**~~ Done for team profiles: they
   seal under the verified fleet key. Local `.shxbak` files keep the
   passphrase, since they have no tenant and should stay openable on a machine
   that has never enrolled, and so does legacy passphrase sync.
5. ~~**Recovery bundle plus readback.**~~ Done for the TRK. The fleet key is
   recoverable through the server recovery grant; no restore command ships.
6. **Move device keys into the OS credential store.** Done on Windows
   (ADR 0004): seeds and cached fleet keys go to Credential Manager, with the
   key file as the fallback. Keychain and kernel keyring are not wired up.

Still to come: root and fleet key rotation (a revoked device keeps generation
0), a restore command for the recovery bundle, and renewal of approvals and
grants, which run one year.

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
identity across machines: the device must enroll again, and the Launcher says
so (`keyStore.otherWindowsAccount`) instead of reporting a corrupt key. The
fleet keys in `fleet-keys.json` are lost the same way: the device enrolls
again, is approved again and collects the fleet key again.

What does not hold:

- Recalling keys from a revoked device. Revocation cuts the device off the
  server, but it keeps the fleet key it already holds; see "Revocation: what
  it does and does not protect".
- Forward secrecy across rotations. There are no rotations.
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
  text; a refused login keeps only the server's error code. A server that
  received the password or a token can still return it in an encoding the
  launcher does not recognize. The account password protects that account at
  that server only, so use a password unique to it.

`P-OP` remains blocked, and this is one of the reasons.
