# G2 security review: providers and registry pins (G2-63)

Reviewed on 2026-10-26 against `team-custody-production` and refreshed on
2026-11-01 against the head of PR #212 (`g2/trk-at-rest`, 5c1cd7b8). This is
the record the plan asks G2 to keep for every value it delegates to G2 (plan
L425, L610, L628, L648, L1356): which provider implements each primitive, and
which numeric IDs and lengths the wire format commits to. The decisions behind
the providers are in ADR 0002 (contract decisions), ADR 0003 (envelope v2 and
STREAM) and ADR 0004 (credential store), all on `main`.

`shared/tests/registry_pins.rs` enforces this page: it fails if a pinned value
changes, if two signing domains or two hash labels share a value, or if one
is malformed. Each module's golden vectors pin its own bytes on top of that.
The test lists 87 domain and label constants (`DOMAINS` at L18, `LABELS` at
L88); "Domains and labels" below says which constants it does not list.

What changed since 2026-10-26: HKDF-SHA256 and `sha2` 0.11 became direct
dependencies of `shared` for the profile label (ADR Q-41); the two label
constants joined the registry test; and the tenant root key (TRK) of a running
bootstrap moved out of `custody-bootstrap.json` into the credential store
(PR #212). Everything else in the tables is unchanged and was re-checked
against the code on the refresh date.

## Providers

Every crate that decides wire bytes is pinned exactly in `shared/Cargo.toml`,
so a minor release cannot change what a signature or tag covers.

| Primitive | Crate | Pin | Notes |
| --- | --- | --- | --- |
| Ed25519 signatures | `ed25519-dalek` | `=3.0.0` | `verify_strict` only (`signing.rs:105`); RFC 8032 and speccheck vectors (G2 W1). |
| AEAD | `chacha20poly1305` | `=0.11.0` | IETF ChaCha20-Poly1305, 96-bit nonce; XChaCha20-Poly1305, 192-bit nonce, for envelope suite 2. |
| STREAM | `aead-stream` | `=0.6.0` | STREAM LE31 for envelope v2 frames (ADR 0003); draft-irtf-cfrg-xchacha-03 A.3.1 KAT and a raw-nonce proof in `envelope_v2.rs`. |
| HPKE | `hpke` | `=0.14.0` | Default features off; only `x25519`, `chacha`, `hkdfsha2`. RFC 9180 base mode vectors. |
| Password KDF | `argon2` | `=0.5.3` | Argon2id v0x13; RFC 9106 KAT (G2-46). |
| Key derivation (profile label) | `hkdf` | `=0.13.0` | HKDF-SHA256 (RFC 5869), default features off (`shared/Cargo.toml:33`). Used once, for the label subkey (`keys.rs:201`, `keys.rs:216`). `hpke` 0.14.0 already depends on the same crate version, so no new crate entered any of the three lockfiles; `cargo tree --locked -e normal -f "{p} [{f}]"` in `shared/` prints `hkdf v0.13.0 []`. |
| SHA-256 under HKDF | `sha2` 0.11, as `sha2_11` | `=0.11.0` | Renamed beside the 0.10 crate because `hkdf` 0.13 and `hpke` 0.14 need `digest` 0.11 (`shared/Cargo.toml:34`); default features off. It is used only as the hash inside `Hkdf::<sha2_11::Sha256>` (`keys.rs:216`), and `ed25519-dalek` 3.0.0 and `hpke` 0.14.0 already depend on it (`cargo tree -i sha2@0.11.0` in `shared/`). |
| Randomness | `getrandom` | `=0.4.3` | OS CSPRNG for keys, nonces and salts. |
| Secret wiping | `zeroize` | `=1.8.2` | Secrets in `Zeroizing`. The secret-bearing types the repo defines print `<redacted>` from a hand-written `Debug` (`fallback_key_file.rs:169`, `recovery_bundle.rs:234`, `portable.rs:80` and `:104`, and in the launcher `root_bootstrap.rs:133`); the Ed25519 key is the dalek type, whose `Debug` omits the secret (`ed25519-dalek-3.0.0/src/signing.rs:586`). The launcher also turns on `zeroize`'s `serde` feature so config structs can hold `Zeroizing` values. |
| SHA-256 | `sha2` | `0.10` | A range on purpose: a hash's output is fixed by its spec, not its version. Hashes of record bytes use this one (`canonical.rs`); `shared/Cargo.toml:12`. |

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
| `root_wrap_suite_id` | 1 | FKEK wrap under the TRK in a fleet `RecoveryGrant`, ChaCha20-Poly1305 (ADR 0002 D-5) | `authz_record::ROOT_WRAP_SUITE_ID_CHACHA` |
| `archive_format_id` | 1 | tar, GNU and ustar headers | `keys::ARCHIVE_FORMAT_ID_TAR` |
| `archive_policy_id` | 1 | profile snapshot policy: relative paths only, no links or devices, one entry per path on the target filesystem | `keys::ARCHIVE_POLICY_ID_PROFILE_SNAPSHOT` |
| `compression_id` | 1 | gzip (RFC 1952) | `keys::COMPRESSION_ID_GZIP` |
| HPKE suite (grants) | 1 | the RFC 9180 tuple below | `grants::HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305`, `authz_record::HPKE_SUITE_ID_X25519_CHACHA` |
| HPKE (mode, KEM, KDF, AEAD) | (0, 0x0020, 0x0001, 0x0003) | base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 | `keys::HPKE_*` |

The profile label has no registry ID of its own: its format is fixed by the
two labels below and by the buckets, and a change of either is a new `-V3`
label, never a new meaning for `-V2`.

## Lengths

| Value | Bytes | Why |
| --- | --- | --- |
| DEK, FKEK, TRK | 32 | ChaCha20-Poly1305 key size. |
| Profile label subkey | 32 | HKDF-SHA256 output, expanded in one block (`keys.rs:216`). |
| `wrap_nonce_bytes`, `root_wrap_nonce_bytes` | 12 | The AEAD's nonce, inside the plan's bound of 1 to 64. |
| `stream_nonce_prefix` | 7 | Suite 1: leaves 5 bytes of the 12-byte nonce for a 4-byte frame counter and the final flag. |
| `stream_nonce_prefix` | 20 | Suite 2: leaves 4 bytes of the 24-byte nonce for `u32le(position \| last << 31)` (ADR 0003). |
| `PreambleV2` | 64 | Fixed `SHARDXBK` preamble; its hash is `preamble_sha256` under `SHARDX-ENVELOPE-PREAMBLE-V2`. |
| AEAD tag | 16 | Poly1305. |
| Ed25519 signature | 64 | RFC 8032. |
| Profile label plaintext | 64, 256 or 1024 | `LABEL_BUCKETS` (`keys.rs:174`): `u16be(len) \|\| label \|\| zeros`, in the smallest bucket that fits. A label is 1 to 1022 bytes (`MAX_LABEL_LEN`, `keys.rs:178`). |
| `label_ciphertext` | 12 + bucket + 16 | Nonce, padded plaintext, tag: at most 1052 bytes, under the 4096 the server stores. |
| Recovery bundle KDF | 64 MiB, t=3, p=4 | ADR 0002 D-5; the same profile wraps the fallback key file. `recovery_bundle.rs:41-42` and `KDF_PARALLELISM` at `:36`. |

## Profile label (ADR Q-41)

A profile's display label is sealed by the launcher before publish-create and
stored by the server as `label_ciphertext`, which the server never reads.
`seal_label` (`keys.rs:229`) and `open_label` (`keys.rs:274`) are the only
code that builds or opens one.

- **Subkey.** The fleet key never seals a label. The key is HKDF-SHA256 with
  no salt, the fleet key as input key material, and as `info` the label
  `SHARDX-PROFILE-LABEL-KEY-V2\0` followed by tenant, fleet and profile IDs
  (16 bytes each) and `u64be(generation)` (`label_key`, `keys.rs:201`;
  `label_context`, `keys.rs:182`). A label ciphertext therefore cannot be
  turned against the other uses of the fleet key, and the subkey differs per
  profile and generation.
- **AEAD.** ChaCha20-Poly1305 under the subkey with a caller-supplied 12-byte
  nonce. The AAD is `SHARDX-PROFILE-LABEL-V2\0` followed by the same IDs and
  generation, so the ciphertext opens nowhere else.
- **Bucket padding.** The server learns only which of the three buckets the
  label fell in. An empty label, or one over 1022 bytes, is refused before any
  key is derived (`keys.rs:238-247`).
- **Strict open.** After the tag verifies, `open_label` still refuses a zero
  length, a length whose smallest bucket is not the plaintext's size, and any
  non-zero padding byte (`keys.rs:303-311`). A genuine tag does not rescue a
  non-canonical plaintext.
- **Tests.** `a_profile_label_opens_only_where_it_was_sealed` (`keys.rs:427`),
  `a_profile_label_has_a_length_bound_both_ways` (`:470`),
  `a_profile_label_is_padded_to_a_bucket` (`:495`),
  `a_profile_label_that_is_not_canonical_is_refused` (`:524`) and the golden
  vector `g2_golden_vector_profile_label` (`:578`). The vector pins the subkey
  (`1b925281...e505dd` for the fixture key, tenant `0x11`, fleet `0x22`,
  profile `0x33`, generation 7), requires that it differs from the fleet key
  and per profile and generation, and pins the SHA-256 of two sealed labels
  (4 bytes in the 64 bucket, 100 bytes in the 256 bucket) that were
  cross-checked against Python's HMAC and `cryptography`.

## Key storage on the device

The detail is in `key-custody.md`; this is what the review checked.

- **Credential store.** A device key is one credential under the service
  `shardx-launcher`, filed with `persistence = Local` so it never roams
  (`credential.rs:1-13`, `:73`). It counts as stored only once it reads back
  unchanged (`os_store`, `credential.rs:90-98`, error
  `credential.readBackMismatch`). If the OS store cannot take it, it goes to
  the passphrase-protected key file once the user has opened that this run
  (`credential.rs:83-88`, `key_file.rs`); with neither, the call fails with
  `credential.unavailable` and the caller keeps the key where it was.
- **TRK of a running bootstrap (PR #212).** The key is created in memory,
  stored under the reference `tenant-root.{tenant}.{run nonce}` and
  `custody-bootstrap.json` keeps only that reference.
  - *Reference.* `trk_ref` (`root_bootstrap.rs:424`) names it. The run nonce is
    16 random bytes in lower-case hex (`nonce_ok`, `:416`) and is saved before
    the key is stored (`run_ref`, `:442`), so whatever sits under the
    reference afterwards belongs to this run and a key an abandoned run left
    is never picked up. `own_trk_ref` (`:431`) refuses a state whose
    reference is not the one its tenant and nonce give, so a damaged file
    cannot make the bootstrap read or delete another credential.
  - *No clear copy.* `BootstrapState` has no field that serialises a key:
    `legacy_trk` is `skip_serializing` (`:108`), `Zeroizing`, and redacted in
    `Debug` (`:133`). `create_trk` (`:485`) stores the key and only then
    saves the reference. With no OS store and no open key file the bootstrap
    stops with the `credential.*` error and writes nothing.
  - *Activation and forget.* `finish_activation` (`:519`) saves
    `activated` first and forgets the key afterwards, so a crash between the
    two resumes with the key still there; `release_trk` (`:501`) keeps the
    reference until the key is gone. `credential::forget`
    (`credential.rs:135`) succeeds only once the key is confirmed gone: an OS
    store that cannot be opened confirms nothing, and a key file that is only
    locked does not undo a delete the OS store confirmed.
  - *Legacy file.* A TRK an earlier launcher wrote in the clear is read once
    (`migrate_legacy_trk`, `:545`). With no self-grant, recovery bundle or
    create request saved, nobody else ever saw it and it is dropped for a
    fresh one. Otherwise it moves into the store under a nonce derived from
    the public root key ID, in one commit after the store holds the key
    (`:580-584`); a rerun after a crash reuses the stored copy. A store that
    refuses leaves the file as it was and fails the run. A reference that is
    already set, or a different key already held under the reference, is a
    damaged state and is never overwritten.
  - *Tests.* In `root_bootstrap.rs`:
    `the_trk_is_stored_and_the_saved_state_holds_only_its_reference`,
    `a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key`,
    `a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing`,
    `a_reference_to_another_credential_is_refused_and_that_credential_is_kept`,
    `the_activation_is_saved_before_the_key_is_forgotten`,
    `the_run_nonce_is_saved_before_the_key_is_stored`,
    `a_new_run_never_reuses_a_key_an_abandoned_run_left`,
    `a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it`,
    `a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed`,
    `a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made` and
    `a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it`;
    in `key_file.rs`, `a_forget_succeeds_only_once_the_key_is_confirmed_gone`.
- **Limits.** A launcher that held a cleartext TRK should rotate to the next
  root generation after activation, because the old file may have been copied.
  A key orphaned by an abandoned bootstrap run stays in the store (a new run
  never reuses it and nothing deletes it), and so does one left in a locked
  key file. Persistence of the OS store across a restart and a locked session
  is G2-48, a manual run on a real Windows machine (ADR 0002 Q-29,
  `g2-48-manual-check.md`); it is not proven by this review.

## Domains and labels

Signed and encrypted records carry a domain, `shardx.<area>.<name>.v2`.
Hash preimages start with a label, `SHARDX-<NAME>-V2` and a NUL byte. The
registry test lists every constant in its two lists (L17, L71), including the
two profile label constants `keys::L_PROFILE_LABEL` and
`keys::L_PROFILE_LABEL_KEY` (L89-90). They are not hash preimages: the first
prefixes the AAD of a sealed label and the second the HKDF `info` of its
subkey. The label test applies all the same, so each ends in `-V2\0`, has one
NUL, is distinct from every other label and is not also a domain.

The rest are used inline or are not in the lists, so the test cannot see
them; each has its own golden vector or codec test:

- `shardx.keys.fleet-key-grant.device-hpke.aad.v2` and
  `shardx.keys.fleet-key-id.v2` (`fleet_grants.rs`)
- `shardx.keys.tenant-root-key-grant.hpke-info.v2` (`grants.rs`)
- `shardx.envelope.dek-slot.v2`, `shardx.envelope.intent.v2`,
  `shardx.restore-epoch.profile-head-leaf.v2` (`envelope.rs`)
- `shardx.backup.head.v2` (`backup.rs`)
- `shardx.local.fallback-key-file-plaintext.v2` (`fallback_key_file.rs`)
- `shardx.recovery.bundle-plaintext.v2`, `shardx.recovery.readiness-probe.v2`
  (`recovery_bundle.rs`)
- `SHARDX-ROOT-CUSTODIAN-GRANT-SET-V2`, `SHARDX-FLEET-DEVICE-GRANT-SET-V2`,
  `SHARDX-IDEMPOTENT-MUTATION-REQUEST-V2`,
  `SHARDX-IDEMPOTENT-STORED-RESPONSE-V2` (`mutation.rs`, ADR 0002 D-4;
  `golden_vectors` at `mutation.rs:1783`)
- `SHARDX-LOCAL-BINDING-TOMBSTONE-V2` (`profile_lease.rs`, pinned by
  `the_unbind_maps_round_trip_and_pin_the_tombstone`)
- `SHARDX-RECOVERY-BUNDLE-V2` (`recovery_bundle.rs`, pinned by `GOLDEN_PIN` at `:572`)
- `SHARDX-ENROLLMENT-BINDING-V2`, `SHARDX-DEVICE-SESSION-POP-V2`
  (`session_binding.rs`, `golden_vectors` at `:533`)
- `shardx.authorization.fleet-key-grant.v2` (server, legacy v2 fleet grants)

The request and response maps of checkout, create-upload, finalize-upload,
publish-create, lease renewal and release, the unbind request, response and
tombstone, and the fleet profile page (`DOMAIN_CHECKOUT_REQUEST` and its
siblings in `profile_lease.rs`, `DOMAIN_FINALIZE_UPLOAD_REQUEST` in
`snapshot_v2.rs`, `DOMAIN_FLEET_PROFILE_PAGE` in `fleet_profiles.rs`) are in
`DOMAINS` too, so the registry test holds them distinct from every other domain
and in the `shardx.<area>.<name>.v2` shape; each codec also refuses any other
domain (`exact_version(.., DOMAIN_..)`).

## Open items

- `rsa` is not built but stays in the server lockfile through `sqlx`'s
  optional MySQL driver; see `dependency-review.md`.
- The trust-boundary matrix (G2-61) and the fault-injection evidence for
  durable writes and SQLite (G2-49, G2-50) are separate rows.
- G2-48 (credential store persistence across restart, locked session and a
  logon with no store) is pending the owner's manual run; see
  `g2-evidence/README.md`.
- G2-64, the independent verifier pass, runs on the evidence packet in
  `g2-evidence/`, after the merge to `main`.
