# G2 security review: providers and registry pins (G2-63)

Reviewed on 2026-10-26 against `team-custody-production`. This is the record
the plan asks G2 to keep for every value it delegates to G2 (plan L425, L610,
L628, L648, L1356): which provider implements each primitive, and which
numeric IDs and lengths the wire format commits to. The decisions behind the
providers are in ADR 0002 (contract decisions), ADR 0003 (envelope v2 and
STREAM) and ADR 0004 (credential store), all on `main`.

`shared/tests/registry_pins.rs` enforces this page: it fails if a pinned value
changes, if two signing domains or two hash labels share a value, or if one
is malformed. Each module's golden vectors pin its own bytes on top of that.

## Providers

Every crate that decides wire bytes is pinned exactly in `shared/Cargo.toml`,
so a minor release cannot change what a signature or tag covers.

| Primitive | Crate | Pin | Notes |
| --- | --- | --- | --- |
| Ed25519 signatures | `ed25519-dalek` | `=3.0.0` | `verify_strict` only; RFC 8032 and speccheck vectors (G2 W1). |
| AEAD | `chacha20poly1305` | `=0.11.0` | IETF ChaCha20-Poly1305, 96-bit nonce; XChaCha20-Poly1305, 192-bit nonce, for envelope suite 2. |
| STREAM | `aead-stream` | `=0.6.0` | STREAM LE31 for envelope v2 frames (ADR 0003); draft-irtf-cfrg-xchacha-03 A.3.1 KAT and a raw-nonce proof in `envelope_v2.rs`. |
| HPKE | `hpke` | `=0.14.0` | Default features off; only `x25519`, `chacha`, `hkdfsha2`. RFC 9180 base mode vectors. |
| Password KDF | `argon2` | `=0.5.3` | Argon2id v0x13; RFC 9106 KAT (G2-46). |
| Randomness | `getrandom` | `=0.4.3` | OS CSPRNG for keys, nonces and salts. |
| Secret wiping | `zeroize` | `=1.8.2` | Secrets in `Zeroizing`; no secret type derives `Debug`. |
| SHA-256 | `sha2` | `0.10` | A range on purpose: a hash's output is fixed by its spec, not its version. |

The dependency audit of all three lockfiles is in `dependency-review.md`.

## Numeric registry

Each registry has exactly one assigned value, except `envelope_suite_id`:
suite 1 is the shipped body, and suite 2 is only valid inside a `SHARDXBK`
envelope v2 object (ADR 0003). Readers accept nothing else:
the parsers check these fields, and restore compares the signed intent bytes
with bytes rebuilt from these constants. Adding a suite therefore means a new
ID, never a new meaning for an old one.

| Field | Value | Meaning | Constant |
| --- | --- | --- | --- |
| `signature_suite_id` | 1 | Ed25519, strict verification | `signing::SIGNATURE_SUITE_ID_ED25519` |
| `envelope_suite_id` | 1 | STREAM over ChaCha20-Poly1305 | `keys::ENVELOPE_SUITE_ID_CHACHA20POLY1305_STREAM` |
| `envelope_suite_id` | 2 | XChaCha20-Poly1305 under STREAM LE31, in a `SHARDXBK` object | `keys::ENVELOPE_SUITE_ID_XCHACHA20POLY1305_STREAM_LE31` |
| `wrap_suite_id` | 1 | DEK wrap under the FKEK with ChaCha20-Poly1305 | `keys::WRAP_SUITE_ID_CHACHA20POLY1305` |
| `archive_format_id` | 1 | tar, GNU and ustar headers | `keys::ARCHIVE_FORMAT_ID_TAR` |
| `archive_policy_id` | 1 | profile snapshot policy: relative paths only, no links or devices, one entry per path on the target filesystem | `keys::ARCHIVE_POLICY_ID_PROFILE_SNAPSHOT` |
| `compression_id` | 1 | gzip (RFC 1952) | `keys::COMPRESSION_ID_GZIP` |
| HPKE suite (grants) | 1 | the RFC 9180 tuple below | `grants::HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305`, `authz_record::HPKE_SUITE_ID_X25519_CHACHA` |
| HPKE (mode, KEM, KDF, AEAD) | (0, 0x0020, 0x0001, 0x0003) | base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 | `keys::HPKE_*` |

## Lengths

| Value | Bytes | Why |
| --- | --- | --- |
| DEK, FKEK, TRK | 32 | ChaCha20-Poly1305 key size. |
| `wrap_nonce_bytes` | 12 | The AEAD's nonce, inside the plan's bound of 1 to 64. |
| `stream_nonce_prefix` | 7 | Suite 1: leaves 5 bytes of the 12-byte nonce for a 4-byte frame counter and the final flag. |
| `stream_nonce_prefix` | 20 | Suite 2: leaves 4 bytes of the 24-byte nonce for `u32le(position \| last << 31)` (ADR 0003). |
| `PreambleV2` | 64 | Fixed `SHARDXBK` preamble; its hash is `preamble_sha256` under `SHARDX-ENVELOPE-PREAMBLE-V2`. |
| AEAD tag | 16 | Poly1305. |
| Ed25519 signature | 64 | RFC 8032. |
| Recovery bundle KDF | 64 MiB, t=3, p=4 | ADR 0002 D-5; the same profile wraps the fallback key file. |

## Domains and labels

Signed and encrypted records carry a domain, `shardx.<area>.<name>.v2`.
Hash preimages start with a label, `SHARDX-<NAME>-V2` and a NUL byte. The
registry test lists every published one. These are used inline and are not
published, so the test cannot see them; each has its own golden vector:

- `shardx.keys.fleet-key-grant.device-hpke.aad.v2` and
  `shardx.keys.fleet-key-id.v2` (`fleet_grants.rs`)
- `shardx.keys.tenant-root-key-grant.hpke-info.v2` (`grants.rs`)
- `shardx.envelope.dek-slot.v2`, `shardx.envelope.intent.v2`,
  `shardx.restore-epoch.profile-head-leaf.v2` (`envelope.rs`)
- `shardx.backup.head.v2` (`backup.rs`)
- `shardx.local.fallback-key-file-plaintext.v2` (`fallback_key_file.rs`)
- `shardx.recovery.bundle-plaintext.v2`, `shardx.recovery.readiness-probe.v2`
  (`recovery_bundle.rs`)
- `shardx.authorization.fleet-key-grant.v2` (server, legacy v2 fleet grants)

## Open items

- `rsa` is not built but stays in the server lockfile through `sqlx`'s
  optional MySQL driver; see `dependency-review.md`.
- The trust-boundary matrix (G2-61) and the fault-injection evidence for
  durable writes and SQLite (G2-49, G2-50) are separate rows.
- G2-64, the independent verifier pass, runs after every row is MET.
