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
| Ed25519 signing | Proof of possession; signs snapshot manifests | `team.json`, hex seed |
| X25519 HPKE recipient | Receives wrapped keys — **unused today** | `team.json`, hex seed |

The HPKE key is registered and never used. It exists because the design below
needs it, and enrollment is the only moment a device can introduce a key.

`team.json` sits beside the profile store in plaintext, protected by filesystem
permissions alone. For a prototype whose profiles are already on that disk this
adds no meaningful exposure, but it is not production key storage: an OS
credential store (DPAPI, Keychain, kernel keyring) is the intended home and is
not wired up.

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

### What is missing

| Piece | State |
| --- | --- |
| `seal_trk` / `open_trk` | Implemented in `shared`; exercised end to end by the grant tests |
| `v2_tenant_root_key_grants` table | The exact plan 7.2 shape since migration 0016; spike rows stay read-only in `v2_legacy_tenant_root_key_grants` |
| `POST /v2/tenants/:tenant/root-key-generations` | S6 bootstrap: the D1 device's setup session files its signed `FirstRootSelfGrant` and generation 0 in `PREPARING`, as one exact idempotent mutation |
| `GET /v2/tenants/:tenant/devices/:device/root-key-grants` | Returns a device's sealed grants of an `ACTIVE` generation only |
| Root generation lifecycle | Bootstrap create only. Readback, acknowledgement, activation and rotation are not implemented; the spike `POST /v2/tenant-root-key-grants` and begin/activate routes were removed |
| Grant issuance at enrollment | Not implemented — grants must be filed by an external custodian |
| Recovery bundle | Not implemented |

Storage and collection now exist: a grant sealed to a device's HPKE key can be
filed, read back, and opened by that device, and `v2_e2e.rs` proves the round
trip by recovering the key from what the server returned. The server stores
ciphertext it cannot read.

A grant now has to name a generation that exists, and wrap the key that
generation committed to. Before this, the generation number in a grant was
decoration: a grant could name any number and seal any key, and the mismatch
would only surface later as a backup nobody could open.

The bootstrap creates generation 0 in `PREPARING` together with the first
device's `FirstRootSelfGrant`, in one request that names only the root key's
identifier — the key itself is generated on the device and never transmitted,
which is what keeps the server unable to read anything sealed under it. It is
accepted once per tenant, only on the setup session that D1 approved. The
generation is to become `ACTIVE` only after the holder acknowledges that it can
unwrap what it filed; that step is not built yet.

Activation is deliberately separate from filing. Filing proves a grant was
written; it does not prove anyone can open it. A tenant that activated on filing
could seal itself under a key it had already lost, and that failure is
unrecoverable by construction — the server cannot help, because it never sees a
key.

What is still missing is everything that would *produce* grants automatically.
Nothing seals a TRK to a newly enrolled device, and no rotation or recovery
ceremony exists. So sync still falls back to a shared passphrase: the transport
and the bootstrap for a root key exist, the issuance ceremony does not.

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
6. **Move device keys into the OS credential store.**

Steps 1–3 are prerequisites for 4; shipping 4 first would mean inventing a
distribution mechanism that the frozen design already specifies.

## Threat model, stated plainly

What holds today:

- The server cannot read profile contents. It stores sealed containers only.
- A stolen container is useless without the passphrase.
- Tenant boundaries are enforced on every `/v2/` route (`require_tenant_member`).
- A stale push is refused: version fencing stops one device silently
  overwriting another.

What does not hold:

- Per-device revocation. Everyone shares one passphrase.
- Forward secrecy across rotations. There are no rotations.
- Device key confidentiality against local disk access. `team.json` is plaintext.
- Recovery of anything, if the passphrase is lost.

`P-OP` remains blocked, and this is one of the reasons.
