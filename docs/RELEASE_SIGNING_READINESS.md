# Release signing model

ShardX uses Tauri updater signing for public and internal releases. Windows
bundles are intentionally not Authenticode-signed, matching the current Youwee
release model.

Required repository secrets:

- `TAURI_SIGNING_PRIVATE_KEY`: Tauri updater signing private key.
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`: Tauri updater signing key password.

No `WINDOWS_CERTIFICATE`, PFX password, certificate subject, or Windows trust
chain is required. Manual Windows installs can therefore show SmartScreen or
**Unknown Publisher**. That warning describes Windows publisher identity; it
does not mean the Tauri updater signature is missing.

Before native builds start, the workflow signs a disposable fixture with the
updater private-key secret and verifies it using the exact public key shipped
in `src-tauri/tauri.conf.json`. A rotated or mismatched key stops the release.
Native builds emit updater bundles and `.sig` files, and the deterministic
`latest.json` maps those signatures to the Windows NSIS bundle and the Linux
x86_64 AppImage (macOS builds stopped after v2.11.1). Duplicate or missing
updater bundles fail publication.

Checksums and GitHub build-provenance attestations cover the release assets.
The updater verifier rejects modified artifacts or signatures that do not match
the embedded public key.

## First updater-capable release

Installed `v0.1.21` builds do not contain the Tauri updater plugin, so they
cannot self-update to `v0.1.22`. Users must manually install `v0.1.22` from
GitHub once and accept the expected Unknown Publisher prompt. Later releases
can use the in-app Download, signature verification, and Install and restart
flow without replacing profile data, settings, the Automation API token, or
the MCP folder.

## Future Authenticode option

A CA-issued Authenticode certificate can be added later if public adoption
justifies its cost and operational overhead. It is not a requirement or release
gate for `v0.1.22`; Tauri updater signing remains mandatory.
