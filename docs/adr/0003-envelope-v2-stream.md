# ADR 0003: Envelope v2 and STREAM (G2-27)

- **Status:** Accepted for development on 2026-10-25. Releasing any code built
  on it still requires an independent G2 `PASS` before v0.2.0 (L2341).
- **Date:** 2026-10-25
- **Split from:** [ADR 0002](0002-g2-contract-decisions.md) item D-3, as
  ADR 0001 Q4 requires for G2-27.
- **Deciders:** user (approved 2026-10-25 with ADR 0002). Reviewers: the
  ADR 0002 Architect review and Critic rounds 1 to 9b, which reviewed this item
  inside ADR 0002 (`reviews/0002-*`).

This ADR is item D-3 of ADR 0002, split out as ADR 0001 Q4 decided (ADR1
L485-L490). It keeps the D-3 label, so ADR 0002 rows that say "D-3" point
here. "Plan" means the frozen plan
`.omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md`, cited as
`Lnnnn`.

## Status

Accepted for development on 2026-10-25. The user approved the provider order
with ADR 0002 (approval page, row D-3). The G2 dependency review (L2443) below
selects **provider A**. Releasing code built on it still requires an
independent G2 `PASS` (L2341).

## Context

The plan pins the envelope wire format and the algorithms and delegates only
the provider, numeric registry values and suite-specific lengths to G2
(L648, L650, L757-L758, L1353, L1356). Production ships a different container
(`SHRDXBK2`, hand-written ChaCha20 STREAM nonce, plaintext written before the
signed head is checked) that users already have on disk. The plan has already
decided XChaCha20-Poly1305 (L1352) and constrained the STREAM primitive
(L1353), so this item is narrower than the gap report listed.

## Plan facts (not up for decision)

- **Preamble**, exactly 64 bytes, big-endian, immutable (L1301-L1314):

  | Offset | Size | Field | Plan value |
  |---:|---:|---|---|
  | 0 | 8 | `magic` | ASCII `"SHARDXBK"` |
  | 8 | 2 | `envelope_version: u16` | `2` |
  | 10 | 2 | `preamble_length: u16` | `64` |
  | 12 | 2 | `suite_id: u16` | registry |
  | 14 | 2 | `flags: u16` | known-bit mask only |
  | 16 | 4 | `intent_len: u32` | |
  | 20 | 4 | `dek_slot_len: u32` | |
  | 24 | 4 | `frame_plaintext_size: u32` | |
  | 28 | 4 | `reserved: u32` | `0` |
  | 32 | 32 | `intent_sha256` | |

  Then `intent_bytes`, exactly one `dek_slot_bytes`, then one or more
  `FrameRecord { kind:u8 (0x00 DATA | 0x01 FINAL), counter:u32,
  ciphertext_len:u32, ciphertext }` (L1316-L1324).
- **Bounds before allocation:** intent <= 64 KiB, slot <= 16 KiB, frame
  plaintext 64 KiB..4 MiB, ciphertext per frame <= plaintext + overhead, total
  <= quota, checked arithmetic; empty or second slot and non-zero `reserved`
  fail (L1326). Intent bounds: `frame_plaintext_size` `65536..4194304`,
  `max_plaintext_size`/`max_ciphertext_size` `1..536870912`,
  `stream_nonce_prefix` `Bytes(1,64)` with a suite-specific exact length,
  `final_frame_required = true` (L649-L652). Pilot server cap 512 MiB (L2548).
- **Frame AAD** binds a domain separator, `intent_hash`, frame kind and
  counter, not the manifest (L1337).
- **Reject before restore:** the L1348 list (trailing bytes, zero frames,
  slot count, counter start/increment/LE31 exhaustion, length bounds, DATA
  after FINAL, missing/repeated/non-last FINAL, non-canonical encoding, any
  intent/slot/context/hash/manifest mismatch); a valid archive always ends in a
  **non-empty** final frame.
- **Algorithms:** XChaCha20-Poly1305 (L1352); RustCrypto STREAM LE31, or an equivalent
  primitive confirmed by an official-doc spike and test vectors, and no
  hand-written nonce counter (L1353, translated); default frame 1 MiB with an
  authenticated final frame (L1354).
- **Release order:** manifest verified before decrypt/commit (L1346);
  decrypt straight into the validated extractor/staging (L1365); tar+gzip with
  the strict v2 grammar and Windows path policy (L1362-L1367).
- **Manifest signer:** the plan requires a valid signature, role and explicit
  capability (L1412). ADR 0002 D-2 proposes: signer has a live
  `DeviceApprovalV2` covering the fleet or tenant, holds `profile.commit`
  covering the profile, and was the lease holder at commit; clients check the
  signer's approval and capability chain to the tenant's bootstrap anchor
  (ADR 0002 trust-chain section).

Production deltas (gap G2-27): magic `SHRDXBK2` and length-prefixed layout
(`backup.rs:62,312-314`), hand-written nonce (`envelope.rs:252-263`), counter
up to `u32::MAX` (`backup.rs:346-350,535-539`), plaintext written at
`backup.rs:531` before the head check at `:590`, 4 GiB ceiling
(`backup.rs:71`), 64 KiB frames (`backup.rs:65`), ChaCha20.

## Decision drivers

1. Conform to the frozen plan without an amendment where possible.
2. No hand-written nonce or counter code (L1353).
3. No plaintext reaches anything but staging before the signed manifest and
   the object hash are verified.
4. Keep shipped `SHXBAK01`/`SHXFLT01` files openable without letting them
   downgrade a v2 binding.
5. Smallest new dependency surface that passes L2443.

## Options

- **Option A: XChaCha20-Poly1305 + `StreamLE31` from `aead-stream`.** The
  RustCrypto home of STREAM for the `aead 0.6` line that
  `chacha20poly1305 0.11.0` uses (`aead-0.6.1/src/lib.rs:98-102`). One new
  crate. Verified on 2026-10-25 (see "Dependency review"): `aead-stream 0.6.0`
  builds against `aead 0.6.1` and `chacha20poly1305 0.11.0`, and its LE31 nonce
  layout matches. Its `StreamLE31::COUNTER_MAX` is `0x7fff_ffff`
  (`aead-stream-0.6.0/src/lib.rs:497`).
- **Option B: same algorithms, `StreamLE31` from `aead 0.5.2` (`stream`
  feature).** `aead 0.5.2` is already in the graph through `aes-gcm 0.10.3`;
  the real cost is adding `chacha20poly1305 0.10.x` beside `0.11.0`, on the
  older line. Its `StreamLE31::COUNTER_MAX` is `0x0fff_ffff`
  (`aead-0.5.2/src/stream.rs:493`), nonce = prefix then
  `u32le(position | last << 31)` (`:526-538`).
- **Option C: XChaCha20-Poly1305 + `StreamBE32` (architect review).** Keeps
  L1352. The nonce is a 19-byte random prefix, then `u32be(counter)`, then a
  1-byte last flag (`aead-0.5.2/src/stream.rs:437-446` layout, with the XChaCha
  24-byte nonce). It qualifies as L1353's "equivalent primitive" only with the
  official-doc spike and vectors that L1353 requires, and L1348's "exhaust LE31"
  is then read as "exhaust the chosen STREAM counter". Both crates in A and B
  provide `StreamBE32`. Revision 7's ChaCha20 + BE32, which would have amended
  L1352, is withdrawn: byte-identity with the shipped frame code has little
  value for a new suite, and it gives up XChaCha's margin against DEK reuse.

Every snapshot has a fresh random 32-byte DEK (L1291), so nonce uniqueness
only has to hold per DEK and all three are safe while that holds; XChaCha's
20-byte random prefix keeps frames safe even if a bug reuses a DEK.

## Provider order (critic M7)

1. Option A, if `aead-stream` passes L2443 (licence, MSRV, maintenance,
   features, advisories), builds against `aead 0.6.1`/`chacha20poly1305 0.11`,
   and its LE31 nonce matches the layout above byte for byte.
2. Otherwise Option B. Same nonce layout as A, so nothing below changes, except that
   its counter stops at `0x0fff_ffff` instead of `0x7fff_ffff`.
3. Otherwise Option C, with the L1353 spike and vectors and no plan amendment;
   `suite_id` would then be `3` with a 19-byte prefix. A change to L1352 is never pre-approved; it would be a fresh amendment if A, B and C all fail.

## Decision: Option A, with this exact contract

**Registry:**

| Item | Value |
|---|---|
| `envelope_suite_id` / preamble `suite_id` | `2` = `SHARDX_ENVELOPE_XCHACHA20POLY1305_STREAM_LE31_V1` |
| `envelope_suite_id = 1` | reserved for the shipped `SHRDXBK2` body; never valid in a `SHARDXBK` preamble |
| `stream_nonce_prefix` | exactly 20 bytes from the OS CSPRNG per snapshot |
| AEAD key / tag | per-snapshot 32-byte DEK / 16 bytes |
| `flags` | no bits defined; must be `0x0000` |

**Frame encryption.** Frame `i` uses STREAM position `i`, `last_block =
(kind == FINAL)`. AAD reuses the shipped function (`envelope.rs:270-277`):
`"SHARDX-ENVELOPE-FRAME-V2\0"` (25 bytes) || `intent_hash` (32) ||
`u32be(counter)` || `kind`, 62 bytes. L1337 lists these inputs without an
order. A legacy frame cannot validate here: cipher, nonce and `intent_hash`
(which covers `envelope_suite_id`) all differ.

**Frame sizes** (a tightening inside L1326): writer `frame_plaintext_size =
1048576`; readers accept `65536..4194304` when preamble and intent agree. DATA
frames carry exactly `frame_plaintext_size` bytes (`ciphertext_len = size +
16`); FINAL carries `1..size` (`17..size + 16`), so an exact multiple ends with
a full FINAL. `N = ceil(P / size)` for `P >= 1`; readers reject `counter >=
ceil(max_plaintext_size / size)` before any AEAD call (at most 8192 frames at
512 MiB, far below either provider's limit).

**Preimages** (named but undefined in the plan; proposed):

| Name | Preimage |
|---|---|
| preamble `intent_sha256` | equals `intent_hash = domain_hash("SHARDX-ENVELOPE-INTENT-V2\0", intent_bytes)` (L660), following the domain-separated `dek_slot_sha256` precedent (L633) |
| `preamble_sha256` (L519, L950, L1087, L1089) | `domain_hash("SHARDX-ENVELOPE-PREAMBLE-V2\0", preamble[0..64])` |
| `ciphertext_sha256` (L519, L548, L950) | plain SHA-256 of the whole stored object: preamble, intent, slot and all frame records |
| `ciphertext_size` (L520) | that object's length: `64 + intent_len + dek_slot_len + sum(9 + ciphertext_len_i)` |

`max_ciphertext_size` bounds the object and `max_plaintext_size` bounds `P`;
both `<= 536870912`.

**Reader selection (critic M3).** The reader is chosen from local binding
state, never from the object's magic. A Team binding whose pinned state
contains any v2 signed head, or whose server is a v2 server, accepts only
`SHARDXBK` suite 2 through the steps below; any other object is
`ENVELOPE_UNSUPPORTED` (L1240) and quarantines the binding. Legacy
`SHXBAK01`/`SHXFLT01` objects are opened only through explicit user actions
("restore local backup", "import legacy snapshot") that create a new local
profile and never touch a binding.

**Reader steps, no plaintext output before step 7:**

1. Download the object completely to a local spool file; length <=
   `min(server cap, 536870912)`.
2. Verify the exact `SignedSnapshotManifestV2` (hashes, signature, signer rule
   above, pinned previous head, instance and epoch) (L1346, L528-L539).
3. Pass 1 over the spool file: SHA-256 equals `ciphertext_sha256` and length
   equals `ciphertext_size`.
4. Parse the preamble: magic, version 2, length 64, `suite_id = 2 =
   intent.envelope_suite_id`, `flags = 0`, `reserved = 0`, `intent_len`
   `1..65536`, `dek_slot_len` `1..16384`, frame size equal to the intent,
   `intent_sha256 = intent_hash`; canonical-roundtrip intent and slot; every
   manifest/intent/slot equality including `preamble_sha256` and
   `dek_slot_sha256` (L631-L632, L1334-L1335).
5. Recompute `dek_slot_context_hash`, then unwrap the DEK.
6. Pass 2 reads **the same spool file**, never the network (critic minor 6):
   per frame check `kind`, `counter = i`, length rules, no DATA after FINAL;
   decrypt with the STREAM decryptor into the strict v2 extractor writing to
   staging (L1365).
7. After an authenticated FINAL with nothing after it and the extractor's
   whole-archive checks (L1366-L1367), promote staging atomically; any failure
   deletes staging.

Cost: two local passes; peak memory one frame (<= 4 MiB) plus extractor state.

## Dependency review (L2443), 2026-10-25

**Result: Option A passes.** Provider order step 1 applies, so B and C are not
used. Every check below was run on 2026-10-25.

| Check | Result |
|---|---|
| Crate and version | `aead-stream 0.6.0`, released 2026-06-28, newest stable. Repository `RustCrypto/AEADs` (same project as `chacha20poly1305`) |
| Licence | `Apache-2.0 OR MIT`, the same as the RustCrypto crates already in the graph |
| MSRV | `rust-version = "1.85"`. The spike builds with the CI-pinned `1.88.0` and with the local stable `1.99.0` |
| Dependencies | One: `aead ^0.6`. `aead 0.6.1` and `chacha20poly1305 0.11.0` are already in `server/Cargo.lock` and `src-tauri/Cargo.lock`, so only the `aead-stream` crate itself is new |
| Features | `alloc` (enables `aead/alloc`) is needed for the non-in-place `encrypt_next`/`decrypt_last`; the in-place API needs no feature |
| Unsafe code | No `unsafe` in `src/lib.rs` |
| Advisories | RustSec advisory DB has no entry for `aead-stream`, `aead`, `chacha20poly1305` or `poly1305`. The only `chacha20` entry, RUSTSEC-2019-0029, affects versions far older than the `0.10` line in use |
| Maintenance | Last commits to `aead-stream`: 2026-06-28 (v0.6.0), 2026-06-17 (lint config), 2026-06-08 (`aead` v0.6 bump); 12 reverse dependencies on crates.io |
| LE31 nonce layout | `prefix (20 bytes for XChaCha20) || u32le(position \| last << 31)` (`src/lib.rs:530-542`), byte for byte the layout in "Options" |
| Counter maximum | `0x7fff_ffff` (`src/lib.rs:497`). `aead 0.5.2` uses `0x0fff_ffff` (`aead-0.5.2/src/stream.rs:493`); see the parser note below |

**Spike** (throwaway crate pinned to `aead-stream =0.6.0` and
`chacha20poly1305 =0.11.0`, run with `cargo run` on both toolchains):

- a three-frame XChaCha20-Poly1305 STREAM round-trips;
- treating a DATA frame as FINAL fails (truncation), swapping two frames fails (reorder), and flipping one ciphertext bit fails;
- each frame also decrypts with a raw `XChaCha20Poly1305` and the 24-byte nonce `prefix || u32le(position | last << 31)` for positions 0, 1 and FINAL at 2.

That last check is the "each STREAM frame decrypted with a raw
`XChaCha20Poly1305`" provider proof listed under "Unblocks and tests". The
pinned draft-irtf-cfrg-xchacha A.3.1 vector and the golden vectors are still
G2 implementation work (W5).

**Parser note.** The contract's own bound (readers reject `counter >=
ceil(max_plaintext_size / size)` before any AEAD call; see "Frame sizes")
stops at 8192 frames, far below either provider maximum, so A and B accept the
same valid objects. The negative vector "counter at the provider maximum"
therefore cannot arrive through a valid intent; it stays as a unit test of the
decryptor wrapper, with `0x7fff_ffff` for provider A.

## Compatibility and migration

- New Team snapshots are only `SHARDXBK` suite 2. No shipped file is
  rewritten.
- `SHXBAK01` and `SHXFLT01` remain readable only through the explicit legacy
  actions above, which keep buffering everything before `snapshot::unpack`
  (`backup_file.rs:12-17`). A `SHRDXBK2` body claiming suite 2 or a `SHARDXBK`
  preamble claiming suite 1 is rejected.
- Recommended (ADR 0002 Q-6): legacy fleet blobs are never auto re-published.
  Recommended (Q-7, deferred): `SHXBAK02` needs its own design; until then
  `SHXBAK01` stays the local writer, with its frame code moved to the chosen
  provider's STREAM-BE32 (byte-identical; existing vectors must still pass).
- New dependency per the provider order, reviewed under L2443 (G2-62).

## Consequences

- Frame helpers in `shared/src/envelope.rs` move to the chosen STREAM
  encryptor/decryptor; `frame_aad` stays. Suite-1 constants become legacy.
- A new `shared` module writes and parses `PreambleV2` and frame records.
- Upload and manifest code compute `preamble_sha256` and whole-object
  `ciphertext_sha256`.

## Unblocks and tests

- Rows: G2-27; bound and nonce parts of G2-10, G2-11; `preamble_sha256` /
  `ciphertext_sha256` in G2-07, G2-23; G2-61; G2-62. Workstream W5.
- Provider proof: the XChaCha20-Poly1305 vector of draft-irtf-cfrg-xchacha
  section A.3.1 (to be fetched and pinned in G2; not verified offline); each
  STREAM frame decrypted with a raw `XChaCha20Poly1305` and the expected
  24-byte nonce.
- Golden vectors: preamble, intent, slot and whole object for `P = 1`,
  `P = size + 1`, `P = 2 * size`; LE31 nonces for counter 0, 1 and FINAL at 0
  and 2; the 62-byte AAD.
- Negative vectors: magic `SHRDXBK2`, version 1, length 63, suite 1 and 3,
  any flag bit, reserved 1, `intent_len` 0 and 65537, `dek_slot_len` 0 and
  16385, `intent_sha256` flip, frame size disagreement, kind 2, counter
  starting at 1 or skipped or repeated, DATA after FINAL, missing or empty
  FINAL, short DATA, oversized `ciphertext_len`, trailing byte, counter at the
  provider maximum, object hash or size mismatch.
- Release-order test: flip the last object byte; assert zero bytes reach
  staging and no DEK unwrap happens.
- Reader-selection test: a v2 binding served an `SHXFLT01` object
  quarantines with `ENVELOPE_UNSUPPORTED`.
