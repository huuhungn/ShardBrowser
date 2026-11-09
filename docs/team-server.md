# ShardX Team Server core port

This branch ports only the self-hosted team-server core from
`chovizzz/ShardBrowser#2`:

- user login with Argon2 password hashes and bearer tokens
- admin/member roles
- folder/env/proxy CRUD with ACL filtering
- exclusive checkout locks with `lock_token` + lease renewal
- opaque snapshot upload/download with retention GC and SHA-256 metadata
- login throttling, token invalidation on password change, audit logging

Out of scope for this branch:

- Launcher Team UI / remote workspace commands
- portable cookie/Login Data/Web Data pack/unpack
- browser engine, fingerprint, profile isolation, proxy launch behavior

Snapshot bytes are intentionally opaque here. The portable snapshot safety layer
is ported separately so it can be reviewed without mixing it into server auth
and lock behavior.

## Upgrading to the 2.11 team server

Back up the server database before replacing the binary. Migration 0034 is
forward-only: a 2.10 server binary will not start on the upgraded database,
and a downgrade means restoring that backup. No data is rewritten at the
upgrade, and 2.10 launchers keep working against a 2.11 server.

## Discarding a stuck key rotation (offline)

A fleet key rotation or root key rotation can stop with its new generation
left PREPARING on the server (a device lost mid-rotation, an activation that
never came). Launchers then report `fleet.rotationStuck`,
`fleet.rootRotationStuck` or `fleet.rootRotationWaitsForFleetDiscard`. The
operator clears it with the server stopped (ADR 0002 Q-60):

```
shardx-team-server fleet discard-preparing --tenant <slug> --generation <n> [--fleet <hex>] [--force]
shardx-team-server root discard-preparing --tenant <slug> --generation <n>
```

1. Stop the server; this needs downtime. The command takes the data-directory
   lock and refuses while the server runs or while a restore is prepared
   (`restore status` must be clean).
2. Back up the database first.
3. The generation must be PREPARING and exactly one above the ACTIVE one.
   `--fleet` is needed when more than one fleet of the tenant has a PREPARING
   generation. A fleet discard is refused while the stuck rotation's grants
   are still in their window, so a launcher still running it reports
   `fleet.rotationStuck` first; `--force` overrides that.
4. In one transaction the generation and every grant filed for it (for a root
   generation, also the fleet recovery grants filed under it) are copied into
   `v2_discarded_records` and deleted, and an audit row is written. The output
   lists counts and a key ID prefix, never key material.
5. Start the server. The custodian starts the rotation again; the same
   generation number is used, under a new key.

Archived rows are kept forever. Nothing else deletes a key generation or a
grant: the live server never does.
