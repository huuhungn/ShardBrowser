# Key custody and recovery

How profile encryption keys are held today, why fleet sync currently needs a
shared passphrase, and what the frozen v2 design says should replace it.

Written against `main` at the commit that added profile sync. Every claim here
was checked against the code, not the plan: where the plan describes something
that does not exist yet, this document says so.

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

Profile sync (`src-tauri/src/sync_cmd.rs`) uploads exactly the container
`backup_file` produces. The team server stores ciphertext, a SHA-256 and a
version; it holds no key and cannot open what it stores.

The consequence is honest but limited: **the passphrase is a shared secret
between devices.** Whoever pulls a profile must know the passphrase used to
push it, communicated out of band. There is no per-device key wrapping, so:

- Revoking one device's access means changing the passphrase and re-pushing.
- A leaked passphrase compromises every snapshot sealed under it.
- Nothing binds a container to the tenant that stored it.

That is the current state. It is usable for a small team that already shares
credentials, and it is not what the v2 design calls for.

### Device keys

Enrollment (`server/src/enrollment.rs`) registers two keys per device:

| Key | Purpose | Stored |
| --- | --- | --- |
| Ed25519 signing | Proof of possession; signs snapshot manifests | OS credential store; else the key file or `team.json` |
| X25519 HPKE recipient | Opens root key grants sealed to this device | OS credential store; else the key file or `team.json` |

`team_collect_custody` uses the HPKE key to open root key grants. Fleet key
grants are sealed to it too, but are not opened until verified key
distribution ships (see the threat model below).

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
| `GET /v2/tenants/:tenant/devices/:device/root-key-grants` | Returns a device's sealed grants of an `ACTIVE` generation only |
| Root custody setup | "Set up root custody" on the tenant's first device: root generation 0 and its self grant, acknowledged and activated, and the recovery bundle written locally. Rotation is not implemented |
| Fleet key | "Create fleet key" on the root custodian: fleet generation 0, its device and recovery grants, acknowledged and activated. The key is kept only once a verified collect opens it |
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
`can_receive_custody: false` and are told to re-enrol, rather than silently
failing to decrypt.

## Recovery

The design's recovery path is a *recovery bundle*: the TRK wrapped under a
root-held key, produced at bootstrap, verified by readback before a generation
activates. It is not implemented.

Until it is, recovery is exactly one thing: **someone remembers the
passphrase.** Losing it loses the snapshots sealed under it. Backups of
`team.json` preserve device identity — they do not preserve profile contents,
because the device key never encrypted them.

Operators should therefore treat the sync passphrase as a credential to be
recorded in whatever the team already uses for shared secrets, and should not
assume the server can help. It cannot; it never sees a key.

## Ordering the remaining work

Roughly the sequence the constraints force:

1. ~~**Persist TRK grants.**~~ Done: grants are stored and collectable, and a
   device can open its own grant. Issuance is still manual.
2. **Root generation lifecycle.** Table plus create/activate/revoke, with the
   `FirstRootSelfGrant` uniqueness constraint the plan specifies.
3. **Grant TRK at enrollment.** A custodian device seals the TRK to the new
   device's HPKE key — the key enrollment already registers.
4. **Seal containers under the TRK.** Replace the passphrase-derived FKEK for
   fleet containers, keeping it for local `.shxbak` files, which have no tenant
   and should stay openable on a machine that has never enrolled.
5. **Recovery bundle plus readback**, before any of this is called
   production-ready.
6. **Move device keys into the OS credential store.** Done on Windows
   (ADR 0004): seeds and cached fleet keys go to Credential Manager, with the
   key file as the fallback. Keychain and kernel keyring are not wired up.

Steps 1–3 are prerequisites for 4; shipping 4 first would mean inventing a
distribution mechanism that the frozen design already specifies.

## Threat model, stated plainly

The team server is trusted for RBAC and coordination (who belongs to a
tenant, leases, version fencing). It is **not** trusted for key distribution.
Fleet key grants are not yet signed by an issuer the device can verify, so a
compromised server could seal a key of its own choosing to a device. Earlier
versions cached such keys and pushed under them; that let the server read
every later push and forge snapshots that pull would accept. Until verified
key distribution ships:

- The Launcher does not accept fleet keys from the server.
  `team_collect_custody` opens root key grants only; fleet key grants are
  counted (`fleet_grants_waiting`) and never opened or cached.
- Push always seals under the shared team passphrase, and refuses an empty
  one. Pull still tries fleet keys cached by earlier versions, newest first,
  then the passphrase, so snapshots already pushed under a fleet key restore.

What holds today:

- The server cannot read what a device pushes: push seals under the shared
  passphrase, which never leaves the devices. The server stores sealed
  containers only.
- A stolen container is useless without the passphrase.
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
so (`keyStore.otherWindowsAccount`) instead of reporting a corrupt key. Fleet
keys cached by an earlier version are lost the same way, so profiles pushed
under a fleet key should be pushed again now: the new push is sealed under the
passphrase and no longer depends on that cached key.

What does not hold:

- Per-device revocation. Everyone shares one passphrase.
- Forward secrecy across rotations. There are no rotations.
- Device key confidentiality against code running as the same Windows user,
  which can ask Credential Manager and DPAPI too, or against local disk access
  on other platforms.
- Integrity of snapshots pulled under a fleet key cached by an earlier
  version: if the server chose that key, it can forge a snapshot that opens.
- Recovery of anything, if the passphrase is lost.

`P-OP` remains blocked, and this is one of the reasons.
