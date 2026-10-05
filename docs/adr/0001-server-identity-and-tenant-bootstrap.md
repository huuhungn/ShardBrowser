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
   exact-response retry contract is specified in R3 below. R1-R4 are the
   proposed normative refinements submitted for a second Architect review;
   they retain D1/D2 and do not claim user acceptance of a new decision.

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

### R1. Confirmation lifetime and exact S6 evidence (P1-01)

**Proposed contract refinement for re-review, not an implemented migration.**
D1 fixes the one-time intent; the following storage/state choices are new ADR
policy. Plan L373-L376 supplies the restore/trusted-control-plane boundary;
L774 and L812-L819 require the exact approval and OOB evidence for S6.

**Representation and constraints.** Introduce forward-only
`v2_bootstrap_guards` with primary key `(server_instance_id, tenant_id)` and
state `unused|reserved|consumed|closed|recovery_required`. `tenant create`
creates `unused` together with the fresh tenant, owner and structured audit.
It is never inferred from an empty approval table. Introduce
`v2_first_device_confirmations` with primary key `(server_instance_id,
tenant_id)` (deliberately **not** epoch-scoped), unique `confirmation_id`
within the instance, and these required fields:

| Fields | Representation / invariant |
|---|---|
| `confirmation_id`, `server_instance_id`, `tenant_id`, `account_id`, `device_id`, `request_id` | 16-byte IDs; instance/tenant/account/device composite FKs, no cascading deletion of confirmation/history |
| `restore_epoch`, `confirmed_at_ms` | Nonnegative integers, bounded to SQLite signed-64 range; time is Unix milliseconds |
| `signing_key_id`, `hpke_key_id` | 32-byte, role-separated IDs, rederived under R4; unequal |
| `signing_public_key`, `hpke_public_key` | Immutable validated raw 32-byte Ed25519 and X25519 encodings, respectively |
| `signing_suite`, `hpke_suite` | Pinned suite `1` for Ed25519 and HPKE base X25519/HKDF-SHA256/ChaCha20-Poly1305; unknown suites fail closed |
| `state` | `pending`, `consumed`, `cancelled` or `invalidated`; immutable subject/context/key tuple |
| `consumed_at_ms`, `approval_replay_id`, `approval_payload_sha256`, `approval_signed_container_hash`, `approval_outer_sha256` | All absent until consumption, all required on `consumed`; hashes 32 bytes, replay ID 16 bytes; immutable afterwards |
| `terminal_at_ms`, `terminal_reason` | Required only on cancelled/invalidated; closed reasons `operator_cancelled`, `device_revoked`, `epoch_changed`, `integrity_failure` |

The consumed linkage has a restrictive composite FK to the exact approval
(instance, tenant, payload domain `shardx.auth.device-approval.v2`, replay ID).
`approval_replay_id` names the plan's `DeviceApprovalV2.replay_id`; there is
**no separate mutable approval ID** (plan L463-L467). All three stored hashes
must match re-parsed approval bytes, not just an FK or indexed columns.
`historical` is a read-only classification of a terminal row or a row from
an earlier epoch, not a state which permits replacement. Retain tombstones,
bytes and structured audit for the lifetime of the tenant/instance. No API,
CLI force flag, tenant re-enable, deletion/reinsertion or epoch transition
may set a used/closed guard back to `unused`.

**Transitions.** Both CLI and online checks reject guard/confirmation state
inconsistency rather than repairing it from apparent table emptiness.

| Before | Operation and complete result |
|---|---|
| `unused`, no confirmation | Offline confirm checks the external identity/mirror under the Option A exclusive lock, fresh-tenant provenance, one current active owner, exact pending device and both R4 key derivations. In one transaction insert pending confirmation + audit and change guard to `reserved`. All approval/capability/root-generation/root-grant rows, including revoked/history rows, must be absent. |
| `reserved` + `pending` | R2/R3 approval transaction requires exact current instance/epoch/owner/device/keys, the sole confirmation and no prior approval/grant/root rows. Insert exact approval, consume confirmation/linkage, set guard `consumed`, set device active, persist exact response and structured audit together under `BEGIN IMMEDIATE`. |
| `reserved` + `pending` | Offline `tenant cancel-first-device` under the same lock and identity checks sets cancelled + guard `closed` and audit atomically. Revocation of the pending device sets invalidated/device_revoked + `closed` with the revocation transaction. No replacement confirmation, including for the same fingerprints. |
| `consumed` | Later approval/device revocation closes live authority, not history. Keep the consumed link and guard; S6 must reject revoked/expired authority. Repeated confirmation or a new self-approval is permanently denied. |
| Any inconsistent/unproven state | Enter operational `recovery_required`; no bootstrap writes or key release. Preserve original rows and diagnosis; do not invent missing confirmation or approval history. |

There is **no time expiry for an offline confirmation** in this refinement.
It remains usable only while every live R2/R3 predicate and epoch/key equality
holds; signed approval validity and short-lived sessions/challenges still
expire. A mistyped fingerprint comparison writes nothing and can be retried.
After successful confirmation, key loss, cancellation or revocation closes
this bootstrap opportunity. Recovery requires trusted operator investigation;
if no valid history/key can be recovered, explicitly create a different tenant
ID and perform the full OOB ceremony again. This never transfers old authority
or data automatically and never resets this tenant. Expiring/replacing a
confirmation would require a separate reviewed policy, not an implicit retry.

**Restore and S6.** A recognized epoch increase invalidates pending
confirmations (guard becomes `closed`); consumed/cancelled/invalidated rows
remain historical and cannot reopen bootstrap. Do not rewrite their epoch,
keys, hashes or signed claims. Before enabling restored v2 writes, reconcile
guards, confirmations, approval bytes, mutation receipts and audit from trusted
operator restore evidence. Missing evidence, a pre-confirmation backup whose
later history is unknown, or contradictory guard/linkage means
`recovery_required`, never `unused`. An empty restored DB is not fresh setup.
Existing consumed/root state follows the reviewed restore-transition rules;
this refinement authorizes no new gen-0 bootstrap in a different epoch. The
Q1 manifest implementation remains open; this is its mandatory fail-closed
bootstrap-history invariant, not a new external transparency ledger. Selective
same-epoch malicious rollback is still outside plan L376's guarantee.

On first S6 creation, reverify the exact linked active approval, its signature,
all equality columns, validity/revocation, same subject and current context;
require the consumed confirmation's tuple and three hashes to match it.
The link is evidence that these same two keys were confirmed, **not** another
consumable permission. S6 still enforces empty root state, exact gen-0,
`FirstRootSelfGrant`, HPKE readback/recovery readiness and atomic generation
creation. No second device, approval or replacement grant can borrow this OOB
record. Later generation/restore actions use their normal plan predicates.

Offline success is reported only after commit. If the CLI loses its response,
re-running confirm refuses (no insert/update); a new read-only
`tenant first-device-status` under the Option A lock reports the existing
confirmation ID, tuple, state and consumed replay/hash linkage after identity
and R4 verification. It prints no token/private key. The operator compares it
with the intended client tuple. It never repairs or reissues confirmation.
Audit/storage failure aborts the entire CLI or online mutation. A crash leaves
either the complete pre-state or complete committed post-state, not half of
an approval. Offline actor-column mapping is still conditional on D3; neither
NULL network actors nor best-effort `audit::log` are allowed as a shortcut.

### R2. Account login to proof-bound pending-device session (P1-02)

**Proposed bridge, not current runtime behavior.** Plan L368-L370 requires
separate signing and HPKE PoP; L1122-L1124 supplies login/enrollment endpoints.
At source `62979f2`, `AuthUser` loads v1 users (`server/src/auth.rs:139-160`),
`/v2/auth/login` is absent (`server/src/routes/mod.rs:18-38`), and
`v2_sessions.device_id` is NOT NULL/FK-bound (`0004_v2_team_fleet.sql:93-103`).
Account IDs must never stand in for device IDs; do not copy the account-as-
device placeholder in `server/src/routes/v2.rs:446-458`.

**Principal classes and promotion.** `/v2/auth/login` authenticates the fresh
v2 account in the named tenant, verifies current active account/membership and
issues an account-only pre-device ticket, not a `v2_sessions` row. Store its
random 32-byte opaque token only as SHA-256 in a separate
`v2_pre_device_sessions` table with random 16-byte ID, instance/epoch/tenant/
account, account token-version, created/expiry/revocation/consumption times.
TTL is 10 minutes, non-refreshable. It may only use `/v2/me`, logout, enrollment
challenge/proof, and the two device-session proof endpoints below. It grants
no approval, root action, ordinary mutation or operating capability. Login
and challenge creation are rate-limited by tenant/account and source; tickets,
nonces and proof secrets never enter audit/logs.

Enrollment requires this ticket and fresh `CanonicalCborV2` signing proof
binding server instance, epoch, tenant, account, ticket ID, challenge ID,
nonce, both suite IDs, raw public keys, both correctly derived key IDs and
expiry. The server owns challenge fields; proof submission must equal the
stored challenge. Define the new closed `EnrollmentBindingV2` map with exactly
`domain="shardx.auth.enrollment-binding.v2"`, `version=2`,
`server_instance_id`, `restore_epoch`, `tenant_id`, `account_id`,
`pre_device_session_id`, `challenge_id`, `nonce`, `signing_suite`,
`signing_public_key`, `signing_key_id`, `hpke_suite`, `hpke_public_key`,
`hpke_key_id`, `expires_at_ms`. IDs/nonce are 16 bytes, keys/IDs are 32 bytes,
suites U16, epoch/time U64 in storage range; canonical map cap is 4096 bytes.
Sign
`ASCII("SHARDX-ENROLLMENT-BINDING-V2\0") || u32be(len(map_bytes)) || map_bytes`
with the candidate Ed25519 key. This replaces, not silently reinterprets, the
current proof that only signs tenant/account and public keys
(`shared/src/enrollment_proof.rs:17-43`). Challenge TTL is 120 seconds and
consumption, server-generated device ID, pending device and audit are atomic.
A collision never overwrites an existing device. Re-fetch owned enrollment
status via `/v2/me` after response loss; do not create an active session or
retry enrollment as a duplicate insert. Proof over both commitments proves
only the signing private key; it does **not** prove the HPKE private key.

**Selected separate HPKE PoP.** Add
`POST /v2/auth/device-session-challenges` and
`POST /v2/auth/device-session-proofs`, authenticated only by the pre-device
ticket. The supplied device ID must resolve to the ticket's own tenant/account
and revalidated keys; D1 requires pending status. After restart or session
loss, credentials produce a new ticket and these endpoints bind a new session
to the same enrolled device without re-enrollment. For an already active
device they require its still-valid, non-revoked approval before promotion.

The challenge is a closed `DeviceSessionBindingV2` map containing exactly
`domain="shardx.auth.device-session-binding.v2"`, `version=2`,
`server_instance_id`, `restore_epoch`, `tenant_id`, `account_id`,
`pre_device_session_id`, `device_id`, `challenge_id`, `nonce`,
`signing_suite`, `signing_public_key`, `signing_key_id`, `hpke_suite`,
`hpke_public_key`, `hpke_key_id`, `expires_at_ms`; types/bounds match the
enrollment map. Canonical bytes are capped at 4096 bytes. The server generates
a fresh random 32-byte secret `s`, stores only `SHA256(s)` alongside that exact
binding, ticket ID and unused/expiry state, and HPKE-seals `s` to the candidate
HPKE public key. Use RFC 9180 base mode, DHKEM(X25519,HKDF-SHA256), HKDF-SHA256,
ChaCha20-Poly1305 (mode 0, KEM 0x0020, KDF 0x0001, AEAD 0x0003), with
`info=ASCII("SHARDX-DEVICE-SESSION-HPKE-POP-V2\0")` and
`aad=exact_binding_bytes`. Return exact binding, encapsulated key (32 bytes)
and ciphertext (48 bytes). Reject invalid/low-order X25519 keys and failed
encapsulation; never fall back to plaintext. The client verifies the pinned
instance/epoch, complete binding and suite before decrypting.

The client returns challenge ID, decrypted `s` and a 64-byte Ed25519 signature
over
`ASCII("SHARDX-DEVICE-SESSION-POP-V2\0") || u32be(len(binding)) || binding || s`.
The proof endpoint compares `SHA256(s)` in constant time, verifies the
signature with the stored signing key and rechecks current context, ticket,
account/token-version/membership, device status and both key derivations in
one `BEGIN IMMEDIATE`. Challenge TTL is 120 seconds; revoke/expire it on use,
logout, key/status change or epoch change. A proof bound to a different ticket,
device, account or epoch fails; a replay cannot mint another session.

Success atomically consumes challenge **and ticket**, records both-PoP time,
and inserts the actual-device FK-bound session plus structured audit. Use
random opaque 32-byte access and refresh tokens, storing only hashes. Access
TTL is 5 minutes; pending/setup refresh has an absolute 30-minute bound from
PoP, rotates single-use refresh tokens and rechecks all live predicates.
Neither refresh nor credentials alone can change the bound device/keys. All
sessions store immutable instance/epoch/tenant/account/device/key IDs,
account token-version and PoP evidence, expiry/revocation and class
`pending_setup|root_setup|ordinary`. `/v2/me` returns that binding/class from
current rows; no success token is returned before commit. If promotion's
response is lost, acquire a new ticket and redo both proofs; any orphan
session remains limited and expires, never an account-only fallback.

**Same-transaction permissions.** D1 approval requires an unexpired,
unrevoked `pending_setup` session with both PoPs, current active account and
exactly one active owner membership (that account), the R1 confirmed pending
device and exact instance/epoch/keys. D1 approval makes the device active and
moves that session to `root_setup` atomically. Other pending sessions are not
silently promoted; refresh/proof may derive setup class only from that same
valid approval. Gen-0 create/self-grant/readback/ack/activate are allowed for
this exact approved subject via S6, without first requiring an operating
capability. They still validate S6/R1 and live session/approval in each
transaction. Setup never allows generic grants, profile/fleet writes or
`tenant.manage` privilege escalation. After root activation, the normal D2
ACTIVE, acknowledged, valid, non-revoked custody-grant checks authorize
capability issuance; ordinary operations additionally require their exact
live capabilities/roles. Session class alone is never an authorization.
Approval/device revocation, account disablement, membership change, credential
version change or epoch mismatch immediately prevents session use/refresh.

### R3. Approval request identity and exact response replay (P1-03)

**Single replay authority.** Plan L1107 requires the approval mutation, exact
response and structured audit to commit together; plan L1090 makes
`v2_idempotency` the common durable request/response ledger. R3 therefore
uses **`v2_idempotency` as the sole approval replay-response authority**.
There is no separate approval operations or receipt table. The approval route
in plan L1125 continues to receive **exact
`SignedAuthorizationRecordV2<DeviceApprovalV2>` outer bytes**, not a new
wrapper or mutable approval ID: content type `application/cbor`, no content
encoding, canonical bounded parsing and a 262144-byte body cap. Like `COMMIT`
(plan L955-L956, L1090), approval is a stored operation that is **not**
wrapped in `IdempotentMutationRequestV2`/`IdempotentStoredResponseV2`; the
closed wire enum at plan L913 stays unchanged. This is a proposed amendment
to plan §5.6.5, §7.3 and §10.2, effective only if this ADR is approved:

- The stored `v2_idempotency.operation_kind` domain is the L913 wire values,
  `COMMIT`, and storage-only `DEVICE_APPROVE`. No common wire request may
  carry `DEVICE_APPROVE`.
- `v2_idempotency` gains `approval_payload_domain`, `restore_epoch`,
  `actor_account_id` and `subject_device_id`. A table `CHECK` requires all
  four iff `operation_kind='DEVICE_APPROVE'` and all four NULL otherwise.

| `DEVICE_APPROVE` column(s) | Value / constraint |
|---|---|
| PK `(server_instance_id, tenant_id, actor_device_id, operation_scope, idempotency_key)` | Plan L1090 key; scope fixed `tenant.device-approve.v2`; key is the approval payload `replay_id` |
| `approval_payload_domain` | Fixed `shardx.auth.device-approval.v2` |
| `restore_epoch`, `actor_account_id`, `subject_device_id` | Epoch U64 in storage range; 16-byte IDs; subject equals the approval subject and route path |
| `canonical_request_hash` | Request digest defined below |
| `exact_request_bytes`, `exact_request_bytes_sha256` | Exact signed-container body, 1..262144 bytes, and its SHA-256; both equal the approval row's exact container bytes/hash |
| `status` | `succeeded` only; inserted solely by the committing transaction, never `in_flight` or `failed` |
| `response_record_type`, `exact_response_bytes`, `exact_response_bytes_sha256` | `DeviceApprovalReceiptV2`; exact receipt bytes (at most 4096) and SHA-256, all NOT NULL |
| `retained_until` | Retention floor below |
| Composite FK `(tenant_id, approval_payload_domain, idempotency_key)` | References plan L1062's unique `v2_device_approvals(tenant_id, payload_domain, replay_id)` with `ON DELETE RESTRICT`; NULL for other kinds, so they are unaffected |
| Partial UNIQUE `(tenant_id, approval_payload_domain, idempotency_key)` for `DEVICE_APPROVE` | At most one actor/operation row per approval replay ID |

The global replay reservation is the plan's approval key itself
(`(tenant_id,payload_domain,replay_id)`, plan L409-L410, L1062) plus its
retained tombstone. Another actor presenting the same replay ID hits that
reservation and cannot create a second row. Today's `v2_operations`
(`server/migrations/0004_v2_team_fleet.sql:309-326`) and `v2_replay_ledger`
(`:376-387`) are baseline runtime storage, not approval replay authorities.
A forward migration, never an edit of `0004`, creates the plan-conformant
table. If `v2_replay_ledger` is kept, it is written in the same transaction
and checked equal; any disagreement is an integrity failure, never a source
of a response. No receipt is migrated from `v2_operations`, because the
current route stores none (`server/src/routes/v2.rs:168-199`).

Define the request digest as
`SHA256(ASCII("SHARDX-DEVICE-APPROVE-REQUEST-V2\0") || instance16 ||
u64be(epoch) || tenant16 || actor_account16 || actor_device16 ||
subject_device16 || u32be(len(body)) || body)`.
Route, actor, payload subject, domain/version and stored equality columns
must agree. The fixed operation scope is part of lookup; the digest is a
comparison value, **not** part of the key, so a changed request cannot create
an additional operation under the same identity.

Success returns HTTP `201` (implied by `DEVICE_APPROVE` + `succeeded`; no
other status is stored), content type `application/cbor`, and a closed
canonical `DeviceApprovalReceiptV2` map with exactly
`domain="shardx.auth.device-approval-receipt.v2"`, `version=2`,
`server_instance_id`, `restore_epoch`, `tenant_id`, `actor_account_id`,
`actor_device_id`, `subject_device_id`, `approval_replay_id`, `request_hash`,
`approval_payload_sha256`, `approval_signed_container_hash`,
`approval_outer_sha256`, `confirmation_id`, `committed_at_ms`,
`outcome="succeeded"`. `confirmation_id` is required for D1 and omitted for
ordinary approvals; no other optional/unknown fields. IDs are 16 bytes,
hashes 32 bytes, epoch/time U64 in storage range. Replay reparses the stored
receipt and compares every field/hash with the row and approval. Never
regenerate a receipt, timestamp or serialized body. These bytes acknowledge
a past transaction, not current authorization; clients must query current
state before operating.

**Retention and GC.** At commit set
`retained_until = approval.not_after_ms + authorization_replay_retention`,
the plan L409-L410 tombstone floor; after `not_after_ms` the approval cannot
pass step 2's live checks anyway. GC runs under `BEGIN IMMEDIATE`, deletes
only `DEVICE_APPROVE` rows with `retained_until <= server_now`, and never
deletes or rewrites the approval row, its tombstone, R1 confirmation linkage
or audit; the RESTRICT FK prevents deleting the approval first. After GC, or
for a legacy approval without a stored receipt, the same replay ID hits the
approval reservation and is rejected (`409 IDEMPOTENCY_MISMATCH`, no response
bytes); the client re-reads current state. Response expiry never turns the
key into permission to create anything (plan L1422). D1 history lives in the
R1 confirmation and approval rows for the tenant lifetime and does not depend
on receipt retention.

**Order under `BEGIN IMMEDIATE`.** Before response lookup, authenticate the
current device-bound session in the current instance/epoch; recheck active
account/membership, role, expiry/revocation and exact actor/key binding. Then:

1. Bound/canonical-parse the request and compute exact digests. A payload
   instance or epoch different from the current context is rejected first
   (step-independent errors below). Find the `v2_idempotency` row by the
   unique identity above. Same identity with changed bytes, path, subject,
   actor-account or digest is `409 IDEMPOTENCY_MISMATCH` (plan §8.2) without
   mutation. A reserved approval replay ID under another actor also
   conflicts; no response is disclosed to that actor.
2. For an exact hit, verify the row against its FK approval: request
   bytes/hashes, receipt reparse and every receipt field/hash. Any mismatch
   is `422 MUTATION_RESPONSE_MISMATCH`, closes the tenant approval path as
   `recovery_required`, writes nothing and returns no success. Then require a
   live non-revoked/unexpired approval/device and current actor
   authorization. D1 retry needs the same account/device still the sole
   owner with setup or stronger device session; ordinary approval retry needs
   its normal live role and `device.approve` authority. The session ID may
   differ after R2 re-authentication; the authenticated actor/key tuple may
   not. Return the stored type/bytes without any write, **before**
   first-creation emptiness/pending/unconsumed guards. Later root/grant rows
   therefore do not break a valid response-loss retry. Do not reuse
   first-creation issuer discovery to reject the exact committed
   self-approval merely because bootstrap has ended.
3. For a miss, check the approval reservation and verify the signed record,
   validity/all-column equality, live issuer authority and path subject. For
   D1 also apply all R1/R2 sole-owner, confirmed pending device, unconsumed
   tuple and historical-emptiness guards. A consumed/closed guard or another
   replay ID never opens a new exception. For ordinary approval apply normal
   capability/role checks; self-signing is not an exception after D1.
4. In one transaction insert the approval row (the reservation), the
   `DEVICE_APPROVE` `v2_idempotency` row with exact receipt, structured audit,
   any retained baseline ledger row, and all R1/R2 confirmation/guard/device/
   session transitions. Any failure rolls back all effects. No provisional
   success response or best-effort audit. Concurrent identical requests
   serialize to one commit and exact replay; conflicting bytes or a competing
   device cannot win a second approval.

**Crash, restart and restore.** Step 4 is the only write, so a crash leaves
either no approval and no row, or both with their audit and transitions.
Before v2 writes open (startup, after the forward migration, after a
recognized restore), an integrity pass under the exclusive lock verifies
every `DEVICE_APPROVE` row: FK target present, every equality/hash/receipt
field matching, receipt epoch equal to row epoch. A failure marks the
affected tenant's approval path `recovery_required` (as in R1/R4) with no
deletion, regeneration or fallback creation. An approval without a row
(legacy, GC'd or restored without it) is valid history with no replay. A
retained row from an earlier epoch can only yield `STALE_CONTEXT`. R1 governs
D1 guard/confirmation reconciliation; same-epoch selective rollback remains
outside plan L376's guarantee.

Expired/revoked sessions receive `401` and must reauthenticate with both PoPs;
revoked/expired approval, device, owner membership or issuer authority receives
`403`. Epoch mismatch receives `409 STALE_CONTEXT`, no historical success
or epoch rewrite; instance mismatch is denied. New identity after consumed
confirmation receives `409 FIRST_DEVICE_ALREADY_CLOSED`. `STALE_CONTEXT` and
`FIRST_DEVICE_ALREADY_CLOSED` are proposed additions to plan §8.2. Invalid
bytes or binding receive `400`; signed-claim equality failures keep plan
`AUTH_CLAIM_COLUMN_MISMATCH`. Errors never return an old success or recreate
authorization. R1 defines CLI lost-response handling; it is readback, not
another confirmation mutation.

### R4. Key-ID derivation and forward reconciliation (P1-04)

**Verified defect and authority.** At source `62979f2`,
`server/src/enrollment.rs:241` stores `signing_key_id(req.hpke_public_key)`
in the HPKE-ID column; `shared/src/keys.rs:54-55,87-94` defines distinct
signing and HPKE domains. The local uncommitted compatibility fix is not
migration evidence. For validated raw 32-byte keys and the pinned suites,
authoritative IDs are respectively `signing_key_id(signing_public_key)` and
`hpke_key_id(hpke_public_key)`, i.e. SHA-256 of the appropriate ASCII domain
including NUL, `u32be(32)` and raw public-key bytes. Stored IDs are indexed
claims to compare with that derivation, never independent authority.

Enrollment, device-session PoP, offline display/confirmation, approval, S6,
activation, restore reconciliation and key-release paths must check both
IDs, raw key encodings/suites and complete context equality. A mismatch is
not a valid fingerprint for an operator to bless. CLI display fails closed
with reconciliation required instead of asking the operator to confirm an
opaque wrong ID. Existing signed-container equality checks remain necessary;
correcting an index does not correct bytes already signed with a wrong ID.

Extend the Q3 forward-migration obligations (above) as follows. Do not edit
shipped migration `0004` or its checksum. First inventory rows under exclusive
maintenance/Option A lock; classify by recomputed IDs and traverse every
instance/tenant/device/key reference, including sessions, enrollment/PoP
challenges, confirmations, approvals, capability/root/fleet grants, root and
fleet generations, recovery metadata and downstream snapshot/upload refs.
Preserve exact old bytes, IDs, hashes and audit in a reconciliation report
before any permitted repair. The migration cannot infer a legacy instance
from a convenient tenant-only join; use trusted provenance or quarantine.

| Cohort | Permitted result |
|---|---|
| Valid encodings/suites, both IDs correct, exact referenced signed claims consistent | Keep bytes/IDs; preserve all child references, uniqueness and instance/tenant composite FKs. This alone does not prove enrollment PoP or active status. |
| Legitimately pending, never confirmed/approved/trusted setup; wrong-domain HPKE ID only; no signed or trusted references | Under one audited forward repair transaction, recompute the ID, verify new ID/raw-key uniqueness, invalidate old challenges/pre-device/device sessions, and require both PoPs anew. No device-ID change or automatic active promotion. Then a fresh OOB ceremony may proceed only if R1 guard/provenance still says unused. |
| Any confirmation, consumed history, signed approval/grant, trusted/active use, or ambiguous legacy active row | Quarantine device and every affected authorization/key-release path; revoke sessions atomically, preserve original signed bytes and IDs. No in-place relabeling of signed claims, no blessing by operator confirmation. Recovery needs trusted operator review and ordinary re-enrollment/reissuance by a valid issuer; if no such authority exists, a distinct new tenant/full bootstrap, not a reset of D1. |
| Invalid/unknown key encoding/suite, collision, missing instance provenance, incomplete reference inventory or contradictory history | Fail closed as recovery required; do not auto-fix, drop conflicting children or manufacture a new ID. |

Today's writer inserts `active` without the planned pending/PoP contract;
therefore an old `active` row cannot be automatically downgraded to the safe
pending cohort merely because approval tables are empty. Legacy equality
`stored_hpke_id == signing_key_id(hpke_public_key)` identifies the bug, not
proof that the row was never trusted. Forward repair is restartable: a crash
commits the complete audited per-cohort transition or none; a second run
checks the recorded result rather than rewriting signed history. Run FK,
uniqueness and full-reference checks before opening v2 writes. Recognized
epoch change invalidates old sessions/challenges and invokes R1 history
reconciliation, but never changes key IDs (which are not epoch-derived).

### R5. Required design cases for R1-R4 re-review

These are test obligations for the gated G2 rewrite, **not passed tests**:

- Same-device concurrent identical approval yields one commit and exact
  receipt; different bytes at that identity conflict; another device, owner,
  account, path, replay ID or confirmation cannot win another D1 approval.
- Fingerprint typo writes nothing; confirmed key loss/cancel/revoked pending
  device closes the attempt; later approval revocation preserves consumed
  history and denies S6/retry, never reopening bootstrap.
- Account-only ticket, guessed device ID, signing-only PoP, wrong HPKE key,
  altered binding, stale epoch, consumed challenge/ticket and expired session
  cannot authorize approval. Correct proof survives restart/re-login through
  new challenge, not placeholder identity or account-only promotion.
- Approval response loss permits byte-identical same-actor replay after root
  rows exist. Expired session needs fresh both-key PoP; revoked approval,
  altered actor keys, missing live authority or epoch change never receives
  historical success. CLI response loss is verified via read-only status.
- Audit, receipt, FK or storage failure rolls back every transition; crash
  before/after commit exposes complete pre/post-state. Truncated/corrupt
  receipt or confirmation-to-approval hash mismatch fails closed.
- `DEVICE_APPROVE` rows: NULL/non-NULL extension-column `CHECK`, RESTRICT FK
  and partial uniqueness reject inconsistent rows; no common wire request
  can carry `DEVICE_APPROVE`; a disagreeing baseline ledger row yields no
  response. GC before/after `retained_until` and legacy approvals without a
  row reject the replay ID without a receipt; the startup/restore integrity
  pass marks a corrupted row `recovery_required` without deletion.
- Restored pre-confirmation/consumed/terminal snapshots and missing history
  exercise R1 recovery-required/closed outcomes; no epoch rewrite or
  empty-table reset. Same-epoch malicious rollback is not claimed detected.
- Wrong-domain legacy IDs cover pure pending and signed/active cohorts,
  collisions, every child-reference class, ambiguous instance provenance,
  re-run/crash safety and activation/restore/key-release quarantine.

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

R1-R4 propose the four missing P1 contracts; R5 enumerates their required
negative/race/recovery cases. They await independent re-review, not silent
promotion to accepted or implemented status. Remaining obligations are:

- Independently review R1 confirmation lifetime/S6 linkage, R2 both-key
  authentication bridge, R3 exact retry ordering, and R4 reconciliation.
  Runtime/migration behavior must later prove these contracts under G2.
- Freeze the remaining capability value/scope rules and prove D2's complete
  issuer predicate in the mutation transaction: exact issuer key/device,
  current instance/epoch, valid acknowledged non-revoked custody grant,
  ACTIVE pointer/row agreement, live role/session and revocation races.
  R2 separates gen-0 setup from ordinary operating capabilities; acceptance
  does not make `tenant.manage` an issuer privilege or let generic grants
  create `root.custody` (retained Architect P2-01).
- Resolve D3 and the structured-audit schema: target/outcome/action enums,
  request attribution, offline-only actor nullability and transaction-local
  fail-closed insertions. Network callers cannot supply NULL actor identity;
  R1/R3 require rollback on audit failure, not today's best-effort logger
  (retained Architect P2-02).
- Resolve remaining Q1 restore-manifest and Q4 contracts. R1 supplies mandatory
  fail-closed history invariants, not a complete restore implementation.
- Distinguish design fixtures/contract review from implementation evidence
  (retained Architect P2-03). Independent G2-06 FAIL / G2-16 and G2-18 BLOCKED
  remain unchanged. Architect approval alone cannot authorize production.

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

- 2026-10-04 (second-review candidate): added R1-R4 in response to Architect
  P1-01 through P1-04 at `62979f2`, plus R5 required design cases. These are
  proposed refinements of accepted D1/D2, not changes to user decisions or
  runtime/migrations. R1 chooses a permanent per-instance/tenant guard with
  no confirmation expiry/reset; R2 separates account tickets from both-key
  proof-bound sessions; R3 chooses a separate exact signed-body approval
  receipt ledger rather than extending the frozen common operation enum;
  R4 treats rederived key IDs as authoritative and quarantines signed/ambiguous
  historical data. Retained P2, D3, Q1/Q4 and independent G2 obligations remain
  open. This entry records submission scope, not a second review verdict.
- 2026-10-04 (third-review candidate): second review
  (`.hermes/evidence/team-production/adr0001-rereview-6312978a1807/architect-review.md`)
  approved R1, R2 and R4 and returned REVISE for R3: the separate approval
  ledger was not reconciled with plan `v2_idempotency`, retention/GC,
  recovery and authoritative replay. R3 now makes `v2_idempotency` the sole
  replay authority with a storage-only `DEVICE_APPROVE` kind, constrained
  approval columns, RESTRICT FK to the approval reservation, retention floor
  `not_after_ms + authorization_replay_retention`, GC, crash/restart/restore
  integrity rules and plan §8.2 error codes; R5 gains matching cases. These
  are proposed plan amendments pending the third review, not accepted policy.

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
