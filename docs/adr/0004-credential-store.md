# ADR 0004: Credential store (W7, G2-47 and G2-48)

## Status

Accepted for development on 2026-10-26. The owner delegated the decision for
the remaining G2 work ("Bạn toàn quyền quyết định"). This ADR records that
decision and the dependency review the plan requires before production code
(plan section 16, "G2 spike lane").

## Context

The launcher keeps the device signing seed, the HPKE seed and, since R2b, the
bootstrap TRK in plaintext files: `team.json`, `fleet_keys` and
`custody-bootstrap.json`. They are owner-only on Unix and readable by any
process of the user on Windows.

The plan settles the direction:

- Section 9.5 and L1372: the backend is an explicit OS credential store per
  platform. A dependency spike must pick `keyring-core` with a platform
  backend, rather than trust a cross-platform wrapper's implicit behavior.
- L2352 and L2449: Windows Credential Manager is the first runtime baseline.
- Section 9.5: `team-sync.db` keeps only a stable credential reference, never
  key bytes. When the OS store is unavailable, keys go to a local encrypted
  key file. ADR 0002 fixes that file's format, `FallbackKeyFileHeaderV2`.

What this ADR has to decide: the crates and versions, how one key maps to one
credential, and the review results.

## Decision

1. **Crates (Windows only).** `keyring-core = "=1.0.0"` and
   `windows-native-keyring-store = "=1.1.0"`. Both are declared under
   `[target.'cfg(windows)'.dependencies]` in the launcher. Other platforms have
   no OS backend yet and use the fallback key file. That is the plan's order,
   Windows first.
2. **One key, one credential.**
   - Every secret is a 32-byte key, stored as raw bytes with `set_secret` and
     read with `get_secret`. It is never stored as a password string.
   - The service is `shardx-launcher`. The user is the `credential_ref`, which
     matches the `credential_ref` that ADR 0002 gives each fallback-file entry.
   - Separate references keep the signing and HPKE keys apart, as the plan's
     `CHECK (signing_credential_ref <> hpke_credential_ref)` requires (L1507).
3. **Never roam.** Every entry is created with the modifier
   `persistence = Local` (`CRED_PERSIST_LOCAL_MACHINE`). The store's default is
   `Enterprise`, which follows a roaming profile to other machines. A device
   key that roams is a device identity on two machines.
4. **Write, read back, then forget.**
   - A key counts as stored only after `get_secret` returns the same bytes.
   - A plaintext copy is removed only after that read-back succeeds. That
     applies to the copy in `team.json`, `fleet_keys` or the bootstrap state.
   - A failed read-back keeps the plaintext copy and reports the error. It
     never loses a key.
5. **Unavailable store.** When the store returns a platform error, the key
   stays where it is today, and the UI says it is not protected. The fallback
   key file (ADR 0002) replaces this state in its own change.

   shortcut: until the fallback key file lands, an unavailable Credential
   Manager leaves keys in the existing owner-only plaintext files.

## Dependency review (plan section 16), 2026-10-26

**Result: passes.** Every check below was run on 2026-10-26.

| Check | Result |
|---|---|
| Crates and versions | `keyring-core 1.0.0` (2026-04-21) and `windows-native-keyring-store 1.1.0` (2026-05-24), both from `open-source-cooperative`, the maintainers of `keyring-rs`. `keyring-core 1.0.1` (2026-10-13) has "no functional changes" (release notes: test rework only), so the version with six months in circulation is pinned |
| Licence | `MIT OR Apache-2.0` for both, as for the RustCrypto crates already in the graph |
| MSRV | `1.85` for `keyring-core` and `1.88` for the Windows store. The spike builds and runs with the CI-pinned `1.88.0` and with local stable `1.99.0` |
| Dependencies | `log`, `byteorder`, `regex` (with `aho-corasick`, `memchr`, `regex-automata`, `regex-syntax`), `windows-sys 0.61`, `windows-link 0.2` and `zeroize`. Every one is already in `src-tauri/Cargo.lock`, so only the two keyring crates are new |
| Unsafe code | None in `keyring-core`. The Windows store has 21 `unsafe` sites, all FFI into `CredWriteW`, `CredReadW`, `CredDeleteW` and `CredFree` |
| Secret hygiene | The Windows store zeroizes its copies of the secret blob after write and read (`cred.rs:86,157`, `utils.rs:83-85`) |
| Advisories | `cargo audit` over the spike's 13-crate lock: no vulnerability and no warning |
| Maintenance | Commits on both repositories in October 2026 (latest 2026-10-16). Both have CI, semver checks and coverage |

**Spike** (a throwaway crate pinned to both versions, run with `cargo run` on
both toolchains, against the real Windows Credential Manager):

- a 32-byte key that is neither valid UTF-8 nor valid UTF-16 round-trips through `set_secret` and `get_secret`;
- the entry's attributes report `persistence = Local`;
- a second reference under the same service is a separate credential (`NoEntry`);
- overwriting replaces the secret;
- after `delete_credential`, the entry reads `NoEntry`, and a second delete also reports `NoEntry`;
- `cmdkey /list` shows no credential left after the run.

## Consequences

- Device keys leave plaintext files on Windows. Malware running as the same
  user can still ask Credential Manager for them; no user-mode store prevents
  that (plan 9.5: zeroize is not protection against a compromised process).
- A Windows profile reset or a move to a new machine loses the keys by design.
  Recovery goes through the recovery bundle (ADR 0002 D-5) and re-enrolment.
- One `cfg(windows)` dependency pair. Linux and macOS builds are unchanged.

## Unblocks and tests

- G2-47: implementation in the launcher. It needs a credential module with
  `store`, `load` and `forget`, a migration of existing plaintext seeds, and
  tests that use the store's mock backend on CI plus one ignored test against
  the real Credential Manager.
- G2-48: the fallback key file, as its own change, per ADR 0002.
