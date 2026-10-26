# Dependency review (G2-62)

Reviewed on 2026-10-26 with `cargo-audit 0.22.2` against the RustSec database
at commit `21d909e4` (2026-10-24), for the three lockfiles that ship team
custody code: `shared/`, `server/` and `src-tauri/`. The Rust SDK keeps its own
audit in `RUST_SDK_DEPENDENCY_AUDIT_0.1.28.md`.

CI enforces this review: the `Launcher, server and shared RustSec audit` step
in `ci.yml` denies vulnerabilities, unsound and yanked crates, and ignores
exactly the advisories listed under "Accepted" below. A new advisory, or a
lockfile change that brings one back, fails the build.

## Fixed in this review

Lockfile-only updates, all semver-compatible, with no change to any
`Cargo.toml`:

| Crate | From | To | Advisory |
| --- | --- | --- | --- |
| `tokio` (server, launcher) | 1.52.3 | 1.54.1 | RUSTSEC-2026-0386, unsound `AsyncFd::new` |
| `anyhow` (launcher) | 1.0.102 | 1.0.104 | RUSTSEC-2026-0221, unsound |
| `event-listener` (launcher) | 5.4.1 | 5.4.2 | RUSTSEC-2026-0190, unsound |
| `clipboard-win` (launcher) | 5.4.1 | 5.4.3 | yanked release |

The server, shared and launcher suites pass on the updated lockfiles.

## Accepted, with the reason each cannot reach us

| Advisory | Crate | Lockfile | Why it is accepted |
| --- | --- | --- | --- |
| RUSTSEC-2023-0071 | `rsa` 0.9.10 | server | Not built. It is an optional dependency of `sqlx-mysql`, which the server does not enable; `cargo tree -i rsa` is empty. No upstream fix exists. |
| RUSTSEC-2026-0367, -0368, -0369 | `zip` 4.6.1 | launcher | Reached only through `tauri-plugin-updater` 2.11.0 (latest stable). With `createUpdaterArtifacts: true` the updater installs a signed `.exe`/`.msi` on Windows, a `.tar.gz` on macOS and an AppImage on Linux, so it never extracts a zip; every artifact is minisign-verified before it is opened. The advisories are about Unix permission bits and symlinks during extraction. The launcher's own archive code uses `zip` 9, which is not affected. |
| RUSTSEC-2026-0194, -0195 | `quick-xml` 0.39.4 | launcher | Build time only, on Linux: `wayland-scanner` is a proc-macro that parses the Wayland protocol XML shipped with the crate. No runtime input reaches it. |
| RUSTSEC-2024-0429 | `glib` 0.18.5 | launcher | Unsound `VariantStrIter`, in the GTK stack Tauri uses on Linux. The launcher never calls it; the fix needs gtk-rs 0.20, which needs a Tauri release that moves off GTK 0.18. |

## Unmaintained (warnings, not denied)

`proc-macro-error` (RUSTSEC-2024-0370), `ttf-parser` (RUSTSEC-2026-0192), the
`unic-*` family (RUSTSEC-2025-0075, -0080, -0081, -0098, -0100), `zbus_names`,
`zvariant` and `zvariant_derive` (RUSTSEC-2026-0370 to -0372). They come in
through Tauri and its Linux GTK and D-Bus stack, through `urlpattern`, and, for
`ttf-parser`, through `ab_glyph`, which draws profile icons from the bundled
font. None parses custody data.
They clear when the upstream crates move, so they are tracked, not pinned.

## Licenses

From `cargo metadata --locked`, counting only crates in the resolved graph:

| Lockfile | Packages | Result |
| --- | --- | --- |
| shared | 118 | All permissive (MIT, Apache-2.0, BSD, Zlib, Unicode-3.0, 0BSD, CC0). |
| server | 335 | All permissive; also `Unlicense OR MIT`. |
| src-tauri | 687 | Permissive, except five `MPL-2.0` crates: the Servo CSS crates `dom_query` pulls into `tauri-utils` and `wry` (`cssparser`, `cssparser-macros`, `dtoa-short`, `selectors`) and `option-ext` (via `dirs`). MPL-2.0 is file-level copyleft; we ship them unmodified, so it asks only that their source stays available, which crates.io provides. |

No crate is GPL or LGPL only (`r-efi` offers LGPL-2.1 as a third choice next
to MIT and Apache-2.0), and every crate declares a license.

## MSRV

Only the Rust SDK declares `rust-version` (1.88) and CI checks it with the
1.88.0 toolchain. The launcher, server and shared crates are built with stable
only and declare no MSRV. Measured on 2026-10-26: `shared` checks on 1.88.0
with `--locked`; the server does not (E0658, it uses language features
stabilized after 1.88). Nothing promises an older compiler, so none is pinned.

## Re-running

```bash
cargo audit --deny unsound --deny yanked --file server/Cargo.lock --ignore RUSTSEC-2023-0071
cargo tree -i <crate> --locked --target all   # who pulls a flagged crate in
```

To retire an accepted advisory, remove its `--ignore` from `ci.yml` and its
row here in the same change.
