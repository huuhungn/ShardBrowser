# ADR 0001: Server identity authority and first-tenant bootstrap

- **Status:** Draft with partial decisions accepted; the full ADR is not approved.
- **Date:** 2026-10-03
- **Source commit:** `8d07f0d` (v2.2.10), branch `team-custody-production`
- **Deciders:** user + Architect review (pending)
- **User decisions so far:** Q1 P1 (record format, parser rules, identity-root
  config and write procedure) accepted 2026-10-03. Q2 entry point = Option A
  (offline operator CLI, server stopped), chosen 2026-10-03. Q3 nullable
  active pointer until generation `0` activation accepted 2026-10-03. Q3 D1
  (one-time first-device approval) and D2 (ACTIVE root custodian issues
  capability grants) accepted 2026-10-04; D3 (offline audit actor mapping)
  remains proposed. The Q1 restore manifest, remaining Q3 sub-questions and
  Q4 stay open.

## How to read this draft

This draft first records **only what the frozen v0.2.x plan already
settles** ("Settled by the plan", S1–S7). Gaps the plan leaves open are
listed as questions. Where the user has decided a question, or where a
concrete design is proposed, the text labels it "Decided" or "proposed", so
plan text and new design are never mixed.

Approving this ADR does not open production implementation. The plan staffs
production work only after a verifier confirms G2 `PASS` (plan L198), and the
current independent G2 verdict is FAIL.

### Sources

Both sources are local-only (excluded from Git). Reviewers need the exact
copies identified by these hashes.

| Source | Path | SHA-256 |
|---|---|---|
| Plan | `.omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md` | `a4a136c9ff0358fdce0967f7c09d7f7a744bbf33aac3db2ce8475972453eb813` |
| G2 verdict | `.hermes/evidence/team-production/g2-independent-verdict-2026-10-03.md` | `392ad5b34a0ea5efd2b514f85fd57e2a92451e6e97434792b376c3179a03bd1f` |

Citations use `L<n>` for plan lines and `V<n>` for verdict lines.

## Context

A fresh server cannot reach any v2 flow. An isolated server with a new data
directory returned `200` for health and v1 admin login, then `400 server
identity is not initialised` for `GET /v2/server-identity`
(`.hermes/evidence/team-production/fresh-server-probe.json`, source `8d07f0d`).

The code explains why:

- `verification_context` and `server_identity` read the singleton
  `v2_server_state` row and fail when it is absent
  (`server/src/routes/v2.rs:56`, `:69`, `:120`; route at
  `server/src/routes/mod.rs:31`).
- Nothing in production code writes `v2_server_state`, `v2_tenants`,
  `v2_accounts`, `v2_tenant_memberships` or `v2_tenant_issuers`. The only
  inserts are inside test modules (`server/src/fleet.rs:828`,
  `server/src/idempotency.rs:284`, `:351`, `:389`) and
  `server/tests/v2_schema.rs`.
- Startup only loads config and creates the v1 admin user
  (`server/src/main.rs:40`, `:48`; `server/src/db.rs:31`, `:55`). There is no
  CLI argument parsing and no external identity record handling.

The G2 verdict has 64 rows: 4 FAIL and 60 BLOCKED. The rows this ADR touches:

| Row | Verdict | What failed (verbatim scope) |
|---|---|---|
| G2-01 (V155) | FAIL | Spike signs `shardx.authorization.device-enrollment.v2` instead of `shardx.auth.device-approval.v2`; lacks approval and common validity/replay fields. |
| G2-06 (V160) | FAIL | Spike uses `shardx.authorization.tenant-root-key-grant.v2` instead of `shardx.keys.tenant-root-key-grant.v2`; omits `issued_at_ms`/`not_before_ms`/`not_after_ms`; `FirstRootSelfGrant` uses generation 1, not 0; issuer signing key differs from the subject key; no other variants, lifecycle, OOB or readback. |
| G2-27 (V181) | FAIL | Envelope STREAM: hand-rolled big-endian u32 counter, counter `2^31` accepted (plan L1348 requires LE31 exhaustion rejection), no preamble parser or official vectors. |
| G2-64 (V218) | FAIL | Roll-up row: the independent readback emits FAIL, so G2 stops. |
| G2-16, G2-17, G2-18 (V170–V172) | BLOCKED | No `ROOT_GENERATION_CREATE` / `ROOT_GRANT_CREATE` / `ROOT_GRANT_ACK` contracts in the spike. |
| G2-52 to G2-59 (V206–) | BLOCKED | No external restore-epoch record, checksum, preparation manifest, write order or crash-row handling. |

## Settled by the plan

Each item below is plan text, restated in English. Nothing here is new design.

### S1. The external identity record is the epoch authority

- The authority for the monotonic pair `server_instance_id + restore_epoch` is
  a checksummed, fsync'd **external identity record** in an operator-owned
  identity root, **outside** the SQLite DB/blob backup and rollback scope
  (L373, L2248).
- The record binds: magic/version, instance ID, previous/current epoch,
  restore transaction ID, restored-DB SHA-256, transition-set SHA-256, write
  timestamp, and a checksum over the canonical bytes that exclude the checksum
  (L373).
- The record path is an operator-configured identity root, not under the
  server DB/blob directory, and never part of the DB restore set (L2248).
- It is **not** a signed authorization record. It is a checksummed file.
  (The plan names no `ExternalIdentityRecordV2` type and no signature over it.)

### S2. `v2_server_state` is a mirror, never the authority

- `v2_server_state(singleton CHECK singleton=1, server_instance_id,
  restore_epoch, external_record_sha256, updated_at)` is a transactional
  mirror/cache only (L1055). It mirrors exactly
  `(server_instance_id, restore_epoch, external_record_sha256)` (L2248).
- Startup must not open v2 writes until the external record's checksum,
  instance and epoch pass and mirror reconciliation passes (L1055).
- Epoch range is `0..i64::MAX` (L2250); the migration enforces the same range
  (`server/migrations/0004_v2_team_fleet.sql:26-32`).

### S3. Write order and crash handling

- Record writes go temp → flush → atomic replace → parent-directory fsync
  (L1055, L2252).
- Restore order is fixed (L2250–L2254): verify current record `E`; build and
  fsync the restored DB candidate, transition/proof set and preparation
  manifest; atomically replace the record with `E+1` (the authority commit
  point); install the DB candidate; open read-only, verify, rebuild the mirror
  in one transaction, read it back, then enable writes.
- Crash table (L2256–L2265). In particular:
  - Record missing or corrupt → `EPOCH_AUTHORITY_MISSING/CORRUPT`, v2 writes
    disabled, authority is **never rebuilt from the DB or a backup** (L2258).
  - Record epoch or instance behind/different from the DB mirror →
    `EPOCH_AUTHORITY_BEHIND_DB`, fail closed, never copied/lowered/rewritten
    from SQLite (L2264).
- The record is never rolled back, deleted or lowered by a DB restore (L2267).
- Stated limit: the record does not detect selective same-epoch rollback of
  role/session/revocation/lease/generation rows (L376).

### S4. Client pinning

- The first owner's client pins `server_instance_id` on first connect (L256).
- Clients quarantine a binding when `server_instance_id` changes or
  `restore_epoch` moves without a valid transition (L375).

### S5. Authorization payloads (resolves the *target* for G2-01)

- Common required fields in all five authorization payloads: `domain:tstr`,
  `version:U16=2`, `replay_id:ReplayId16`, `tenant_id:Uuid16`,
  `issued_at_ms:UnixMs`, `not_before_ms:UnixMs`, `not_after_ms:UnixMs`,
  `server_instance_id:Uuid16`, `restore_epoch:U64` (L445–L448).
- Validity: `issued_at_ms <= not_before_ms < not_after_ms`, server time inside
  `[not_before_ms, not_after_ms)`, TTL within tenant policy (L406–L408).
- `DeviceApprovalV2`: domain exactly `shardx.auth.device-approval.v2`, no
  optional fields; own fields `subject_account_id`, `subject_device_id`,
  `subject_signing_key_id`, `subject_hpke_key_id`, `approval_scope_kind`
  (`tenant`|`fleet`), `approval_scope_id`, `approved_use` (`team.device`)
  (L450–L461). `replay_id` is the approval identity; signing and HPKE key IDs
  must differ (L466–L467).
- The container's `issuer_signing_key_id` must be a key found in the same
  tenant/epoch with a suitable capability (L427).

G2-01 needs no new design: the spike must be rewritten to this contract. This
ADR does not change the G2-01 verdict.

### S6. First root bootstrap (resolves the *target* for G2-06, G2-16)

- `TenantRootKeyGrantV2`: payload domain `shardx.keys.tenant-root-key-grant.v2`,
  version `2`, common fields from S5, plus `grant_variant`
  (`FirstRootSelfGrant`|`ExistingRootGrant`|`RotationGrant`), `root_key_id`,
  `root_generation`, `grant_capability = root.custody`, subject account/device,
  distinct subject signing and recipient HPKE key IDs,
  `subject_device_approval_replay_id` (L760–L774). The HPKE suite is RFC 9180
  base mode `0x00`, KEM `0x0020`, KDF `0x0001`, AEAD `0x0003` (L776–L779).
- `FirstRootSelfGrant` is accepted only inside one `BEGIN IMMEDIATE`
  tenant-root bootstrap transaction when the tenant has no root generation, no
  root grant and no active `root.custody` (L812–L814).
- Preconditions: subject enrollment proof-of-possession, an exact active
  device approval, and operator-confirmed out-of-band signing **and** HPKE
  fingerprints (L814–L815; also L257, L370).
- The issuer key in the container **equals the subject signing key**
  (L815–L816). No sentinel issuer/subject IDs exist in the plan.
- The same transaction inserts generation `0` as `PREPARING`, the exact
  self-grant, the bootstrap audit row and the idempotency response; a second
  self-grant or bootstrap always rejects (L816–L818). A partial UNIQUE index on
  `(server_instance_id, tenant_id) WHERE grant_variant='FirstRootSelfGrant'`
  plus the emptiness check enforce this (L1073).
- Activation waits for client readback, HPKE unwrap and key-ID check, and
  recovery-bundle readiness acknowledgement (L818–L819).
- Entry point: `POST /v2/tenants/{tenant_id}/root-key-generations` creates
  generation `0` with the embedded first self-grant container (L837–L839). The
  `/grants` endpoint rejects `FirstRootSelfGrant` (L840–L843). Request payload
  `TenantRootGenerationCreateV2` carries the bootstrap-only
  `first_self_grant_*` fields (L856–L865). The bootstrap must not go through
  any generic admin/grant path (L1130).
- The first approved owner/root device creates the TRK; the server never
  generates or sees plaintext KEK material (L1296).

### S7. RBAC rules that constrain bootstrap

- Roles are `owner`, `admin`, `member`; `root.custody` is a separate
  capability and is **not** implied by `owner` or `admin` (L1058, L1067).
- Approval and root grant/activate mutations check live role/session/
  capability state and persist the mutation, idempotency response and audit in
  one transaction (L1107).

## Open questions

### Q1. Byte format of the external identity record

The plan lists the record's fields (S1) but not their encoding. The open
points were: magic value (the only pinned magic, `"SHARDXBK"`, belongs to the
envelope `PreambleV2`, L1305); fixed layout vs `CanonicalCborV2`; checksum
algorithm; field widths; epoch-0 values for the restore-only fields; the
identity-root config; the restore-preparation manifest format (L2251).

**Status: P1 accepted by the user on 2026-10-03.** Acceptance covers the
byte layout, parser rules, config/file placement and write procedure below.
These are ADR decisions where the plan leaves encoding or provisioning open,
not newly discovered plan requirements. The restore-preparation manifest
remains open. Acceptance is not G2 verification or production authorization.

#### P1. `IdentityRecordV2` — fixed 168-byte big-endian layout (accepted)

Why fixed layout rather than CBOR: the record has a fixed set of
fixed-width fields and no optional or variable-length parts, so a fixed
layout leaves exactly one valid encoding for any field values without a
canonical-CBOR decoder at startup. It follows the precedent of `PreambleV2`
(L1301–L1314: "big-endian và immutable", ASCII magic, `u16` version and
length, `reserved:u32 = 0`).

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | `magic` | ASCII `"SHARDXID"` (`53 48 41 52 44 58 49 44`). Accepted; distinct from `"SHARDXBK"`. |
| 8 | 2 | `version: u16` | `2`. |
| 10 | 2 | `record_length: u16` | `168`. Must equal the file size. |
| 12 | 4 | `reserved: u32` | `0`. |
| 16 | 16 | `server_instance_id` | 16 random bytes from the OS CSPRNG at `identity init` (UUID v4 network byte order, same as `Uuid16`, L392). All-zero rejected. |
| 32 | 8 | `previous_epoch: u64` | Epoch `0`: `0`. Otherwise `restore_epoch - 1`. |
| 40 | 8 | `restore_epoch: u64` | `0..i64::MAX` (L2250). |
| 48 | 16 | `restore_txn_id` | Epoch `0`: all zero. Otherwise 16 random bytes, non-zero, equal to the preparation manifest's restore transaction ID (L2251). |
| 64 | 32 | `restored_db_sha256` | Epoch `0`: all zero. Otherwise SHA-256 of the installed DB candidate (L2251), non-zero. |
| 96 | 32 | `transition_set_sha256` | Epoch `0`: all zero. Otherwise SHA-256 of the transition/proof set for `E -> E+1` (L2251), non-zero. |
| 128 | 8 | `written_at_ms: u64` | Unix ms, `0..i64::MAX` (same range as `UnixMs`, L394). Informational; never used to order epochs. |
| 136 | 32 | `checksum` | `domain_hash("SHARDX-IDENTITY-RECORD-V2\0", bytes[0..136])`, i.e. SHA-256 over label, `u32be(136)` and bytes `0..136` (`shared/src/canonical.rs:336-343`). |

Derived value: `external_record_sha256 = SHA-256(all 168 bytes)`. This is
what `v2_server_state.external_record_sha256` mirrors (L2248).

Parser rules (accepted). Any failure is `EPOCH_AUTHORITY_CORRUPT` (L1238,
L2258); a missing file is `EPOCH_AUTHORITY_MISSING`. Nothing is repaired.

1. File size is exactly 168 bytes.
2. `magic`, `version`, `record_length`, `reserved` match exactly.
3. `checksum` matches. Then: `server_instance_id` is not all zero; both
   epochs and `written_at_ms` are `<= i64::MAX`.
4. Epoch `0`: `previous_epoch = 0` and the three restore fields are all zero.
   Epoch `> 0`: `previous_epoch = restore_epoch - 1` and none of the three
   restore fields is all zero.

Why the checksum is SHA-256, not CRC: the plan already pins SHA-256 for
`domain_hash`, and the server already depends on `sha2 = "0.10"`
(`server/Cargo.toml`). No new crate. The checksum detects corruption only;
it is not a signature, consistent with S1.

Why `restore_txn_id` is 16 random bytes: same width as `ReplayId16`
(L393). Not plan text.

**Verification of P1.** A reference encoder/parser
(`.hermes/evidence/team-production/adr0001-identity-record-v2/idrec.py`,
SHA-256 `ed751f6e0d73bcc131063695a59e0e5d73087ede25455c15eb61cdbe199ebc7b`)
produced two records. A separate Rust program that recomputes the checksum
with `shared::canonical::domain_hash`
(`parity-main.rs`, SHA-256
`58103685dcb2cdab22f70c7d0f7d5b2d71c6ed4ca2608cae669f50e9ef29da7b`, built
against `shared/` at `8d07f0d`) printed `checksum_match=true` for both and the
same `external_record_sha256`. The parser rejected all 14 negative cases
with the expected reason (length 167/169, wrong magic `SHARDXBK`, version 1,
length field 167, reserved 1, checksum bit-flip, body bit-flip, nil
instance, epoch over `i64::MAX`, two malformed epoch-0 records, wrong
`previous_epoch`, zero DB hash on a restore record). Results:
`vectors.json`, SHA-256
`f4dcbbe09bca3e660f87cacc9d04ab2c2e6dac45dfd9a4c36392248bd422bfbf`. These are
design fixtures for the accepted format, **not** official G2 golden vectors.
G2 must regenerate them from the eventual Rust implementation. The reference
encoder/parser was rerun on 2026-10-03: both positive records and all 14
negative outcomes matched `vectors.json`; Rust checksum parity passed for
both positive records again.

Design fixture 1 — epoch 0, instance `5f1c2b7a-3d4e-4f60-8a9b-0c1d2e3f4a5b`,
`written_at_ms = 1790985600000`:

```text
0000: 53 48 41 52 44 58 49 44 00 02 00 a8 00 00 00 00
0010: 5f 1c 2b 7a 3d 4e 4f 60 8a 9b 0c 1d 2e 3f 4a 5b
0020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0030..007f: 00 (restore fields, all zero at epoch 0)
0080: 00 00 01 a0 ff 0f 7c 00 66 fb 4c b7 90 60 d6 4d
0090: bd ef f8 b3 a0 f2 33 30 a0 f6 5a d8 dc 2b bd 52
00a0: cb 58 f8 37 db 3c 29 8e
checksum               = 66fb4cb79060d64dbdeff8b3a0f23330a0f65ad8dc2bbd52cb58f837db3c298e
external_record_sha256 = 9309a920a7bd36386b15988ba8c39d8cf07351e2b75065ea130d811130f1160b
```

Design fixture 2 — restore `0 -> 1`, same instance,
`restore_txn_id = 0f0e0d0c0b0a09080706050403020100`, DB and transition
hashes are SHA-256 of the ASCII strings `fixture-restored-db` and
`fixture-transition-set`, `written_at_ms = 1790989200000`:

```text
checksum               = a949806f69918996d1be6cf327a401d6c137ac2970c1760908717a4c8d320a27
external_record_sha256 = 828ad5d4dedb26d228160aad1d9118be1495cb975730c3324e3ae0be7e5a3bf4
```

#### P1 file placement and write procedure (accepted)

- Config: `SHARDX_IDENTITY_DIR`, no default. If unset, v2 stays disabled
  (`EPOCH_AUTHORITY_MISSING`); v1 keeps working.
- Preflight: the canonicalized identity directory must not equal, contain or
  sit inside the canonicalized `SHARDX_DATA_DIR` (which holds `shardx.db` and
  `blobs/`, `server/src/config.rs:34-37`). Network shares fail closed, as for
  other durability paths (L2335).
- Authority file: `<SHARDX_IDENTITY_DIR>/identity-record-v2.bin`.
- Write (L1055, L2252): write `identity-record-v2.bin.tmp`, flush, fsync,
  atomic replace, fsync the identity directory, using the Windows durability
  adapter G2 must prove (L1173, L2335).
- The preparation manifest (L2251) is a separate restore-time artifact. Its
  format is **not** part of P1 and stays open under Q1.

#### Still open under Q1

- Restore-preparation manifest format (L2251). P1 acceptance does not
  define it or close the restore crash-recovery proof obligations.

### Q2. Who creates epoch 0, and through which entry point

**Decided 2026-10-03: Option A** (offline operator CLI, server stopped). See
"Decision for Q2" below.

The plan says the first owner pins `server_instance_id` (L256) but not who
generates it or the epoch-0 record. A missing record must fail closed and must
never be rebuilt from the DB (L2258). So creating epoch 0 has to be an explicit
operator action that a fresh install can tell apart from a lost authority.

### Q3. First tenant, first owner, first device approval

- The API surface (L1120–L1131) has login by tenant slug (L1122) but **no
  tenant-creation endpoint** and no first-owner account creation.
- Plan `v2_accounts` (L1057) has no `legacy_user_id`; the migration adds one
  to bridge v1 users (`server/migrations/0004_v2_team_fleet.sql:47-52`).
  Option A settles the first owner as a fresh v2 account, not a bridged admin.
- **First device approval issuer.** The self-grant needs an exact active
  `DeviceApprovalV2` (L814), and every approval's issuer key must come from
  the same tenant with a suitable capability (L427). For the first device of a
  new tenant no such issuer exists. A plan search for an approval bootstrap
  rule found none. The code reads a `v2_tenant_issuers` trust set
  (`server/src/routes/v2.rs:78`; table at
  `server/migrations/0004_v2_team_fleet.sql:356`) that is not in the plan and
  has no production writer. D1/D2 under "First-device trust anchor" below
  were accepted by the user on 2026-10-04; D3 and Architect review remain
  open. User acceptance does not close the independent G2 gate.
- `v2_tenants.active_root_generation` is `NOT NULL`
  (`server/migrations/0004_v2_team_fleet.sql:38`) but generation `0` does not
  exist until the root bootstrap runs. The plan does not specify the pointer
  before activation. The decision below, accepted 2026-10-03, answers this
  for `tenant create` (Option A, command 3); implementation remains gated.
- The plan's login endpoint `POST /v2/auth/login` (L1122) is not in the
  router at `8d07f0d` (`server/src/routes/mod.rs`). Option A, step 4,
  depends on it.

Settled by choosing Option A: the first owner is a **fresh v2 account**
(`legacy_user_id` NULL), not a bridged v1 admin.

#### Q3 decision: nullable active pointer until activation (accepted)

**Status: accepted by the user on 2026-10-03.** Acceptance covers keeping
`active_root_generation = NULL` before generation `0` is successfully
activated, including while it is `PREPARING`, and setting the pointer to `0`
atomically with activation. Generation `0` is a valid active generation,
not an unset sentinel. This settles only this Q3 sub-question; it does not
approve a first-device issuer exception, the full ADR, implementation of the
CLI or migration, or clear G2.

**Plan boundary.** Plan L1056 (section 7.1) lists the column but specifies
neither nullability nor an initial value. Plan L812–L819 requires creation of
generation `0` as `PREPARING`, not `ACTIVE`, together with the exact
self-grant, audit and idempotency response. Activation waits for readback,
HPKE unwrap/key-ID verification and recovery readiness. L824–L828 also
forbids using a PREPARING root for snapshots/fleet rotation. Choosing NULL
is new ADR design; those ceremony requirements are already settled by S6.
The pointer must still participate in the plan's instance boundary: root rows,
grants and lookups are keyed by `server_instance_id` + `tenant_id` (L1071–L1073,
L1095, L1101). A nullable generation number alone is not that boundary.

**Decision (accepted).** Make the column nullable with no numeric default. Keep
its non-negative `i64` range check for non-NULL values. NULL means **no
ACTIVE root generation**, not necessarily that bootstrap has never started.
Do not use `0` or `-1` as an unset sentinel, pre-create an empty generation,
or add a second pending-pointer column.

| Durable stage | `active_root_generation` | Root lifecycle rows | Rule |
|---|---|---|---|
| Offline `tenant create` committed | NULL | None | Create the tenant/owner/membership and required audit together; create no root key, grant or custody capability. |
| First-root bootstrap committed | NULL | Generation `0`, `PREPARING` | Under `BEGIN IMMEDIATE`, verify S6 and atomically persist generation `0`, the exact self-grant, bootstrap audit and exact idempotency response (L812–L819, L943). |
| Readback/recovery acknowledgment pending | NULL | Generation `0`, `PREPARING` | The tenant may continue setup, but cannot use this root for ordinary custody/snapshot/fleet-key work. Do not rerun first-root bootstrap. |
| First-root activation committed | `0` | Generation `0`, `ACTIVE` | Recheck the exact activation prerequisites in the mutation transaction; atomically change lifecycle state and pointer with audit/idempotent response (L946). |
| Any failed bootstrap/activation transaction | Unchanged | Unchanged | Roll back all writes. A successful bootstrap followed by a failed activation leaves NULL plus `0/PREPARING`, not a fabricated ACTIVE root. |

First-generation numbering is explicitly `0`, never read from an unset
pointer and never `COALESCE(pointer, 0)` as authorization. After activation,
rotation keeps pointer `N` while `N+1` is PREPARING; its activation switches
`N+1` to ACTIVE, `N` to RETIRED and updates the pointer atomically, as already
required by L824–L828. A missing or mismatched ACTIVE row is an integrity
failure, not permission to repair the pointer silently.

**Current-code consequences (design only, source `8d07f0d`).**

- `server/migrations/0004_v2_team_fleet.sql:38` rejects NULL and negative
  values. This decision requires a forward migration; do not edit a shipped
  migration or instruct an operator to insert NULL into today's schema.
- The frozen plan also requires `server_instance_id` in root-generation and
  grant keys/FKs (L1071–L1073, L1095, L1101). The forward migration must add or
  reconcile that composite boundary before this pointer can authorize any
  root. It must cover the root rows, grants, activation lookup and every
  downstream fleet/upload/snapshot reference; tenant-only compatibility is
  not acceptable.
- `server/src/generations.rs:69-89` reads the pointer as `i64` and uses it
  as the first generation number. The eventual bootstrap path must instead
  create exact generation `0` within the S6 transaction and distinguish a
  missing tenant from an existing tenant with a NULL pointer.
- `server/src/fleet_generations.rs:131-173` treats a non-NULL pointer as
  sufficient to anchor a new fleet generation; it does not check for the
  matching ACTIVE root row. Require a same-tenant, same-instance ACTIVE
  generation matching the pointer in the eventual mutation transaction.
  NULL, PREPARING, RETIRED, missing-row and mismatch cases must fail closed.
- `server/src/generations.rs:268-300` already updates state and pointer in
  one transaction, but that is not proof of the full L946 activation
  contract. Preserve atomicity and add all plan-required validation,
  idempotency and audit; do not promote the root during `tenant create`.
- `server/src/routes/v2.rs:1129-1150` reports active generation from the
  lifecycle table, not this column. Both read paths must agree; no path may
  infer activation from the numeric pointer alone. Setup/login/enrollment
  remain separate from active-root authorization.

**Migration safety.** The schema was already released (`0004` in v0.2.0;
`0006` in v0.2.4), so historical migration checksums must remain unchanged.
Before converting an existing tenant, reconcile its pointer with its root
rows: preserve a matching ACTIVE generation; classify genuinely empty or
PREPARING-only setup as NULL; block inconsistent data for explicit review.
Never erase a mismatch or activate a generation merely to finish migration.
Prove preservation of every referencing table, indexes and foreign keys.

An in-memory SQLite probe applying all eight current migrations confirmed:
NULL is rejected by NOT NULL; `-1` is rejected by CHECK; `0` inserts even
with **zero** ACTIVE root rows. A separate disposable probe confirmed that
`PRAGMA foreign_keys=OFF` inside a transaction leaves enforcement enabled;
then dropping `v2_tenants` cascades to its child account. Rollback restored
the row. There are 12 current tables referencing `v2_tenants`, all with
`ON DELETE CASCADE`. Therefore a naive table rebuild is unsafe. Migration
mechanics need a dedicated preservation test on the server's SQLx/SQLite
stack, with foreign-key revalidation before normal traffic resumes. These
Python/SQLite probes explain the risk; they do not validate a migration.

**Alternatives not recommended.** Keeping NOT NULL and initializing `0`
avoids a migration, but advertises a real generation before it is ACTIVE;
current pointer-only consumers cannot distinguish those states. A separate
bootstrap flag can disambiguate it but creates another state to reconcile.
A `-1` sentinel conflicts with today's CHECK and the unsigned generation
domain. Inserting generation `0` as ACTIVE at tenant creation bypasses S6's
self-grant/readback/recovery prerequisites and is not an acceptable option.

**Required verification before adoption in implementation.** Test fresh
tenant -> NULL/no generation; successful bootstrap -> NULL/`0/PREPARING`;
activation with missing/wrong readback or recovery proof -> no changes;
successful activation -> `0`/`0/ACTIVE`; concurrent second bootstrap rejects
and exact idempotent retry returns the stored response without reinserting;
crash/rollback leaves no mixed state; all active-root consumers reject unset
or mismatched pointers; migration preserves child rows and legitimate ACTIVE
tenants while refusing inconsistent ones. Add rotation coverage proving the
pointer remains `N` until the atomic `N+1` activation (L824–L828, L943, L946).

**Scope conclusion.** This accepted decision resolves only the pre-activation pointer
semantics needed by the G2-06 bootstrap-generation target and G2-16/G2-18
lifecycle targets; it does **not** resolve those verifier rows or change their
statuses (S6; plan L812–L819, L943, L946, L1056). The exact payloads,
composite instance-bound schema, self-grant, readback, recovery, idempotency
and audit evidence remain required by the plan and are absent from the current
G2 verdict (G2-06 FAIL; G2-16 BLOCKED, V160, V170). The current
`begin_first_generation` and activation code therefore cannot be treated as
implementation of the full contract.
Plan L1091 already specifies the `v2_audit_events` fields: the remaining
question is how the offline operator maps to its actor/action fields and
how to migrate/write it, not whether to invent a new audit schema. The
first-device approval issuer, missing login implementation, Q1 restore
manifest and Q4 scope remain outside this pointer decision.

### Q4. Where G2-27 belongs

G2-27 is about the envelope STREAM framing (L1299–L1348, L2333–L2334, L2445,
L2464), not about server identity or bootstrap. Proposal: move it to a
separate ADR for envelope v2 / STREAM, and keep this ADR limited to identity
and bootstrap.

## Decision for Q2: Option A — offline operator CLI

Decided by the user on 2026-10-03. Option B is kept below as the rejected
alternative.

Invariants (S1–S3): the record lives outside the data directory; it is
written temp → fsync → replace → parent fsync before the mirror row; the
server process never creates a record on its own; a second init refuses.

### Commands (proposed names and flags)

The binary is `shardx-team-server` (`server/Cargo.toml:7-9`). It has no
argument parsing today (`server/src/main.rs`), so with no subcommand it keeps
running the server as now. New subcommands:

1. `shardx-team-server identity init`
   - Requires `SHARDX_IDENTITY_DIR` and passes the P1 preflight.
   - Takes the exclusive server lock (below), so it refuses while the server
     runs.
   - Refuses if `identity-record-v2.bin` or its `.tmp` exists, if
     `v2_server_state` has a row, or if any `v2_tenants` row exists. Exit code
     non-zero, nothing written.
   - Runs DB migrations, as the server does at startup (`server/src/db.rs`).
   - Generates `server_instance_id`, writes the epoch-0 record (P1), then
     inserts the `v2_server_state` mirror row in one SQLite transaction and
     reads it back (L2248, L2252 order: record first, mirror second).
   - Prints the instance ID and the full `external_record_sha256` so the
     operator can compare them out of band with what the first client pins
     (L256).
2. `shardx-team-server identity show` — read-only. Parses the record (P1
   rules), compares with the mirror, prints the result and the reason code.
   Never repairs.
3. `shardx-team-server tenant create --slug <slug> --owner-username <name>`
   - Takes the same exclusive lock; refuses unless the record and mirror
     already verify as in `identity show`.
   - Reads the owner password from an interactive prompt, or from stdin when
     `--password-stdin` is given. Never from argv or an environment variable.
     Rejects passwords that the existing weak-password rule rejects
     (`server/src/db.rs:118-121`).
   - In one transaction: insert `v2_tenants` (`status='active'`), the
     `v2_accounts` row (`legacy_user_id` NULL, Argon2 hash as in
     `server/src/auth.rs:23-25`) and the `owner` membership in
     `v2_tenant_memberships`, plus an audit row.
   - Q3 accepts `active_root_generation = NULL` until generation `0`
     activation. A forward migration and implementation verification remain
     required; do not insert NULL into today's NOT NULL schema. Offline audit
     actor/action mapping also remains open (proposal D3 below):
     the plan specifies `v2_audit_events` (L1091), but only v1 `audit_log`
     exists in the current migrations.
   - Prints the tenant ID.
4. The owner logs in through `POST /v2/auth/login` (L1122, not implemented
   yet; see Q3), enrolls the first device and runs the root bootstrap in S6.
   The owner role does **not** imply `root.custody` (S7).

### Server-stopped guarantee (proposed)

Both the server and every CLI subcommand take an exclusive lock on
`<SHARDX_DATA_DIR>/shardx.lock` with `std::fs::File::try_lock` (stable
Rust std, no new crate) and hold it for the whole run. A second holder gets
`WouldBlock` and exits with a clear "server is running" message. Probe on
this machine (rustc 1.98.1, Windows 11): a second handle got `WouldBlock`
while the first held the lock, and acquired it after `unlock`
(`.hermes/evidence/team-production/adr0001-identity-record-v2/lock-probe.rs`
and `lock-probe.out.txt`). This only orders processes on the same host and
filesystem; network shares already fail closed (L2335).

### Container use

The image runs as user `app` with `VOLUME ["/data"]` and
`ENTRYPOINT ["shardx-team-server"]` (`server/Dockerfile`). The identity
directory must be a **second** volume, not under `/data`, for example
`/identity`. Because the entrypoint is the binary, the operator runs the CLI
in a one-off container with the server container stopped:

```text
docker run --rm -it -v <data-vol>:/data -v <identity-vol>:/identity \
  -e SHARDX_IDENTITY_DIR=/identity <image> identity init
```

Placeholders in angle brackets are deployment-specific. `docker exec` into a
running server is not enough, because the lock refuses while it runs.

### Effects on startup

- `SHARDX_IDENTITY_DIR` unset, or record missing → `EPOCH_AUTHORITY_MISSING`;
  v2 writes disabled; v1 unaffected. The server never runs `identity init`
  itself (L2258).
- Record present → parse (P1), compare with the mirror, then follow the crash
  table (L2256–L2265).

### Consequences of choosing A

- No new network-reachable privileged endpoint.
- A fresh install is an explicit operator command, so a missing record at
  startup can always fail closed (L2258).
- Server operator and tenant owner stay separate identities.
- Cost: needs shell or `docker run` access on the host, and two operator
  steps before the first client can connect.
- Cost: adds argument parsing to the server binary.

## Rejected alternative

### Option B — One-time setup endpoint for the v1 admin

Rejected by the user on 2026-10-03 in favour of Option A. Kept for the
record.

1. Same identity-root config as A.
2. `POST /v2/admin/setup`, accepted only for a v1 user with `role='admin'`,
   and only when there is no record, no `v2_server_state` row and no v2
   tenant. It generates the instance ID, writes the epoch-0 record, inserts the
   mirror, then creates the first tenant and an owner account bridged to the
   calling v1 admin through `legacy_user_id`.
3. To lower the risk of the built-in default v1 credentials
   (`server/src/config.rs:51-52`), require a one-time setup token printed to
   the server log at startup.

| Pros | Cons |
|---|---|
| No shell needed; the launcher UI can drive setup. | Adds a privileged, network-reachable endpoint. |
| Reuses the existing v1 login and the `legacy_user_id` bridge already in the schema. | "Empty DB" becomes the signal that minting a new authority is allowed. After losing both the identity root and the DB, the server silently mints a new identity. Clients would see the instance change (L375), but the server side does not fail closed as L2258 intends. |
| One step from login to a usable tenant. | Merges the server operator (v1 admin) into the tenant owner. |

## First-device trust anchor (part of Q3)

**Status: D1 and D2 accepted by the user on 2026-10-04; D3 proposed.**
D1 accepts the one-time self-issued first approval only after the durable
offline confirmation and
emptiness/session/device guards described below. D2 accepts the ACTIVE
`root.custody` issuer rule for `TenantCapabilityGrantV2`; it does not allow
operating capability issuance before root activation. The PREPARING root
self-grant still follows S6 (L812–L819). D3 remains proposed, and Architect
review plus G2 `PASS` remain required before implementation.

**Accepted consequences.** The forward design must add a pending device state
and a durable first-device confirmation record; enforce the one-time D1
transaction and its exact idempotency/audit behavior; and enforce D2 only for
an ACTIVE, non-revoked root custodian with the live session/device checks.
Pinning key IDs at `tenant create` is analyzed below at the user's request;
it has not been accepted as a replacement for D1 or rejected by the user.
D1–D3 are ADR design choices, not pre-existing plan text.

**Plan facts.**

- After the PoP, enrollment stores a **pending** device (L369). Later devices
  need an owner- or root-signed approval and key grant (L257).
- Every `DeviceApprovalV2` / `TenantCapabilityGrantV2` issuer key must be
  found in the same tenant/epoch with a "suitable" capability (L427).
  `device.approve` is an explicit capability. Capabilities are deny-by-default,
  and `owner` implies none of them (L220, L1067).
- Approval and capability mutations check live role/session/capability state
  and persist the mutation, idempotency response and audit in one transaction
  (L1107). Endpoints: `POST /v2/devices/{id}/approve` (L1125) and
  `POST /v2/capability-grants` (L1126).
- `FirstRootSelfGrant` needs an exact active `DeviceApprovalV2` for its subject
  (L774, L814) and operator-confirmed OOB signing+HPKE fingerprints (L257,
  L370, L815). Its issuer key is the subject's own signing key (L815–L816).
  Bootstrap must not go through any generic admin/grant path (L1130).

**Gap.** In a new tenant no device holds `device.approve` or any other
capability, so neither the first `DeviceApprovalV2` nor the first
`TenantCapabilityGrantV2` has a valid issuer. The plan allows self-issuing
only for the root self-grant. Root custody does not imply `device.approve`,
so the same loop blocks approving the second device. The plan also maps no
record type to the capability that may issue it ("suitable", L427). Finally,
L815 requires an operator confirmation that the server can check, but the
plan does not say how that confirmation becomes durable state.

**Current code (source `8d07f0d`; `server/` and `shared/` unchanged at
`ff9de4f`).** Evidence for the design, not fixes. Implementation stays closed
until G2 `PASS`.

- Issuer trust comes from `v2_tenant_issuers` (`server/src/routes/v2.rs:77-78`;
  `server/migrations/0004_v2_team_fleet.sql:356`). That table is not in the
  plan, and its only writer is a test fixture (`server/tests/v2_e2e.rs:138`).
- Enrollment inserts the device as `active` (`server/src/enrollment.rs:264`).
  `v2_devices.status` allows only `active`/`revoked` (`0004:84`). The pending
  state from L369 does not exist.
- `present_device_approval` (`server/src/routes/v2.rs:173-226`) verifies the
  record and consumes its replay ID. It writes no `v2_device_approvals` row,
  changes no device status and checks neither `device.approve` nor live role.
  It logs to v1 `audit_log` outside any transaction and ignores write errors
  (`server/src/audit.rs:22`). `present_capability_grant` (`v2.rs:274-322`)
  has the same shape. None of this meets L1107.

**D1 (accepted 2026-10-04). One-time self-issued first approval, gated by
an offline confirmation.**

1. The owner logs in and enrolls the first device; it stays **pending**.
2. The operator stops the server and runs
   `shardx-team-server tenant confirm-first-device --tenant <slug> --device <id>`
   under the Option A lock. The CLI shows the pending device's full signing
   and HPKE key IDs. The operator enters both values as read from the client
   screen, and they must match exactly. In one transaction the CLI writes a
   confirmation row bound to `server_instance_id`, `restore_epoch`, tenant,
   account, device and both key IDs, plus audit. It refuses if the tenant
   already has any approval, capability grant, root generation, root grant or
   confirmation row.
3. After restart, `POST /v2/devices/{id}/approve` accepts a `DeviceApprovalV2`
   whose `issuer_signing_key_id` equals the subject signing key only if,
   inside `BEGIN IMMEDIATE`: the unconsumed confirmation matches the subject
   exactly; no approval, capability grant, root generation or root grant
   exists, and there is no other confirmation row; the live session is
   the tenant's single owner on that same device; and scope is
   `tenant`/`tenant_id` with `approved_use = team.device`. That transaction
   persists the approval, moves the device from pending to active, consumes
   the confirmation, and writes audit and the exact idempotency response. A
   later attempt to create another self-issued approval is rejected. The
   exact-response retry contract remains a review obligation below.

The S6 root bootstrap can then require this exact approval (L814) and reuse
the same confirmed fingerprints (L815) instead of a second confirmation.
Pinning at `tenant create` would move this confirmation before enrollment.
The alternative analysis below distinguishes the operational ordering from
the cryptographic requirements; it does not supersede accepted D1.

**D2 (accepted 2026-10-04). Who may issue `TenantCapabilityGrantV2`.** Only a
device holding `root.custody` in the tenant's **ACTIVE** root generation may
issue these grants, with a live session and a non-revoked grant (the same
checks as L820–L822).
After activation, the first device signs its own operating capabilities
(`device.approve` and so on) as the root custodian. This creates no second
bootstrap exception for capability issuance: the device signs for itself
under the normal D2 issuer rule. Operating capability grants wait until
readback and recovery readiness have activated the root. `root.custody`
itself is still granted only through the S6 root endpoints (L1130). Not recommended: a closed set of
self-issued capabilities during bootstrap. That adds a mutable bootstrap
window that must be tracked and closed. Still open under either option: the
exact `Capability` value set (L481). Grant issuance by `tenant.manage`
holders without ACTIVE root custody is not authorized by accepted D2; it
would require a separate proposed amendment.

**D3 (proposed). Offline audit actor.** CLI actions write `v2_audit_events`
(L1091) with `actor_account_id` and `actor_device_id` NULL,
`reason_code = offline_operator_cli`, a CLI-generated `request_id` and the
specific action (`tenant.create`, `tenant.first_device_confirm`). Create no
synthetic operator account. This needs both actor columns nullable in the
forward migration. Network actions always carry the live account and device.

**Verification before full ADR approval.** Self-issued approval is rejected
without a confirmation, with mismatched key IDs, under a different
session/account/device, on a second creation attempt, or once any
approval/grant/root row exists. After a crash, the device is either pending
with an unconsumed confirmation, or active with that confirmation consumed
and its approval committed; never half-applied. Root-issued capability grants
are rejected before activation and from PREPARING/RETIRED generations or
revoked custodians.

### Alternative analysis: pin both key IDs at `tenant create`

**Analysis requested 2026-10-04; not a replacement decision.** D1 remains
accepted. The alternative is feasible in principle, but changes when the
operator confirms the first device and requires an explicit pre-enrollment
reservation contract. It is not a way to skip approval, PoP, or root bootstrap.

**What the sources establish.** `signing_key_id` and `hpke_key_id` are
role-separated hashes of public-key bytes; their functions take no instance,
epoch, tenant or device ID (`shared/src/keys.rs:54-55,87-94`). The client
already passes its signer and HPKE public key into enrollment
(`src-tauri/src/fleet_client.rs:157-174`). This shows that computing the two
IDs before enrollment is possible, not that an offline key-preparation UI or
safe persistent bootstrap workflow has been implemented. The current route
mints `device_id` only during enrollment (`server/src/routes/v2.rs:613-626`).
These source references are unchanged between `8d07f0d` and `ff9de4f`.

Plan L256 orders HTTPS connection and instance pinning before key generation
and challenge issuance. An offline-preparation variant would change that
journey, but the key-ID functions do not impose that order. Nor must all
variants create keys before the first HTTPS connection: the client could pin
the initialized server and prepare its keys before the operator stops it for
`tenant create`. That requires splitting identity discovery/key preparation
from tenant login. The earlier statement that early pinning necessarily
precedes the first connection, and should be rejected for that reason alone,
was too strong. Any changed journey still needs Architect review.

**Required contract if this alternative is adopted (not frozen design).**

1. Initialize and verify the instance through Option A. The client prepares
   its separate signing and HPKE keys, keeps both private keys locally, and
   exposes only public IDs/keys for OOB confirmation. Independently compare
   the instance identity with `identity show`; bare key IDs identify keys,
   not the intended server. Public-key-only input is consistent with the
   metadata boundary in L364.
2. While stopped and under the Option A lock, `tenant create` would create
   tenant, owner, audit and a one-use reservation atomically. Bind it to the
   verified `server_instance_id`, `restore_epoch`, new tenant ID, new owner
   account ID, and both full key IDs with fixed suite/encoding rules. Compare
   both IDs with the intended client's OOB display, not merely with another
   copy of the same imported file. A self-signed preparation file can prove
   possession of its signing key; it cannot establish operator trust in that
   key by itself. Import no private keys.
3. Do not invent a device ID or create an already-approved device at tenant
   creation. After normal live owner login and enrollment PoP, recompute both
   IDs from the submitted public keys, compare them with the reservation,
   and atomically bind it to that exact pending device. A concurrent device,
   wrong account/tenant/instance/epoch, or a mismatch in either key must not
   win the reservation. It cannot be first-device-wins or a general issuer
   allowlist. Challenge/PoP requirements in L369/L1124 still apply; matching
   a public HPKE key ID is not proof of possession of its private key.
4. Permit the same narrowly scoped first self-issued `DeviceApprovalV2`
   only for the bound device, consuming the reservation with approval,
   activation of the device, exact stored response and audit. Preserve D1's
   no-prior-approval/capability/root guards. No root generation, root grant,
   operating capability or trusted-issuer row is created by `tenant create`.
   Root self-grant, HPKE readback and recovery readiness remain separate
   requirements (L774, L812–L819); D2 is unchanged.
5. Specify expiration, cancellation/replacement after a typo or lost keys,
   response-loss retries, race handling and restore invalidation before
   implementation. Old pins must not silently become valid in a new epoch
   or reopen after consumption. Retain auditable tombstones; do not use
   delete/reinsert or an unrestricted force option to reset bootstrap. D3's
   offline actor representation still needs approval under either design.

| Consideration | Accepted D1: confirm after enrollment | Pin at tenant creation |
|---|---|---|
| Additional downtime | Requires an extra server stop/start after the device becomes pending. | Can avoid that extra cycle if keys are ready during the already-offline tenant creation. Option A itself still requires a stopped server. |
| Binding at operator confirmation | Exact pending account/device, current epoch and both key IDs already exist. | Tenant/owner IDs become known in the creation transaction; the future device ID needs a later one-time binding. |
| Client preparation | Follows the L256–L257 connection/enrollment sequence. | Needs a supported pre-enrollment key-preparation/persistence workflow and OOB exchange. |
| Trust established | Operator confirms both keys for the enrolled subject; live checks still apply. | Operator pre-authorizes both keys for one future subject; possession and live checks still apply. No inherent cryptographic upgrade. |
| Failure handling | Must define confirmation recovery and exact retries. | Also needs reservation expiry, key-loss/typo replacement and atomic binding under competing enrollments. |
| Root/capability boundary | No root activation or operating grant merely from approval. | Identical boundary; pre-pinning does not permit early root/capability issuance. |

**Recommendation.** Keep D1 for the first implementation: it binds the trust
ceremony to an actual enrolled subject and avoids adding pre-enrollment
reservation states while G2 is still open. Reconsider early pinning if the
additional server-wide stop for each new tenant is an unacceptable operational
cost and the client can safely prepare/store keys before enrollment. If
adopted, replace D1 explicitly rather than quietly adding a second bootstrap
path; freeze and verify its reservation lifecycle first.

### Review obligations retained after D1/D2 acceptance

These are unresolved implementation contracts, not permission to weaken the
accepted one-time trust boundary:

- Define D1's confirmation schema/constraints and the login-to-pending-device
  session binding. The required confirmation must be present, while prior
  approvals/grants/root rows and any other confirmation must be absent.
- Distinguish an exact retry after response loss from a second creation
  attempt. The former needs a specified stored-response lookup and live-auth
  policy; the latter must never create another approval or reopen bootstrap.
- Define how the consumed confirmation remains linked to the exact active
  approval for S6 OOB verification without becoming reusable authorization;
  specify cancellation, revocation, epoch change and crash/recovery behavior.
- Freeze the remaining capability value/scope rules and prove D2's ACTIVE
  issuer checks. Acceptance does not expand `tenant.manage` into an issuer
  privilege or let a generic capability grant create `root.custody`.
- Resolve D3, login, forward migration/reconciliation and the remaining
  Q1/Q4 contracts. Neither this analysis nor user acceptance changes the
  independent G2-06 FAIL / G2-16 and G2-18 BLOCKED verdicts.

## Consequences once approved

- Plans for the G2 spike rewrite: G2-01 and G2-06 target S5 and S6 exactly;
  G2-16 to G2-18 target the S6 endpoints; G2-52 to G2-59 target S1 to S3 plus
  the P1 format and the Option A startup rules.
- The P1 format is accepted; its design fixtures are not G2 completion. G2
  needs official golden vectors generated from the Rust implementation, plus
  the negative cases listed under P1. The Q3 pointer decision is accepted,
  but neither that acceptance nor these fixtures establish G2 PASS.
- G2-64 clears only when an independent rerun reports PASS for every row. This
  ADR cannot clear it.
- Production v2 code stays closed until G2 `PASS` (L198).

## Revision log

- 2026-10-03: first draft. Settled points only; Q1–Q4 open; options A/B
  proposed for Q2/Q3.
- 2026-10-03: user chose Option A for Q2. Added the CLI commands, lock,
  container use and startup rules; marked Option B rejected; Q3 now records
  that the first owner is a fresh v2 account. Added proposal P1 for the Q1
  record format with verified proposal fixtures. At that revision, Q1
  (P1 acceptance and the preparation manifest), the rest of Q3, and Q4 were open.
- 2026-10-03: user accepted P1, including parser rules and file placement/write
  procedure; the restore manifest remains open. Rechecked the reference
  vectors and Rust checksum parity. Proposed a nullable active-root pointer
  until activation, with explicit PREPARING generation `0`, migration safety,
  caller obligations and required tests. Q3 proposal not yet accepted; full
  ADR approval and independent G2 PASS remain outstanding. First Git snapshot
  of this draft is limited to this ADR; no runtime or migration changes.
- 2026-10-03: independent review found and this draft corrected the plan
  section citation (L1056 is section 7.1), added the required composite
  `server_instance_id` boundary to the migration contract, and narrowed the
  Q3 conclusion so it does not claim to resolve G2-06/G2-16/G2-18.
- 2026-10-03: user accepted the Q3 nullable-pointer decision: NULL until
  generation `0` activation, including during PREPARING; activation sets
  pointer `0` and state ACTIVE atomically. Earlier pending-acceptance entries
  above are historical. Remaining Q3 questions, full ADR approval, migration
  design/verification and the independent G2 gate stay open. No runtime or
  migration changes accompany this acceptance.
- 2026-10-04: user accepted D1 (one-time self-issued first approval after
  durable offline key/fingerprint confirmation and emptiness/session/device
  guards) and D2 (only an ACTIVE, non-revoked `root.custody` holder issues
  `TenantCapabilityGrantV2`). D3 remains proposed. Clarified that D1's
  emptiness check excludes its own required confirmation, and that D2
  gates operating grants, not the PREPARING root self-grant. Analyzed
  tenant-create pinning without accepting or rejecting it on the user's
  behalf; corrected the earlier claim that the key-creation order alone
  rules it out. Acceptance changes only this ADR; implementation remains
  gated by Architect review and G2 `PASS`.
