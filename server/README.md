# ShardX Team Server

Self-hosted team backend for ShardX: user/role management, shared environments,
and (in later phases) exclusive checkout locks + environment-data snapshots.

> Design & roadmap: [`../docs/team-server.md`](../docs/team-server.md).
> **Done: Phase 1** (accounts, roles, env/folder/proxy CRUD, per-user ACL) and
> **Phase 2** (exclusive checkout locks with leases + opaque snapshot
> upload/download with retention GC). Next: Phase 3 (client-side encryption
> normalization for Mac+Windows) and Phase 4 (launcher integration).

## Run

```bash
# dev (binds 127.0.0.1 by default — loopback only, so a simple password is fine)
cd server
SHARDX_TOKEN_SECRET=dev-secret SHARDX_ADMIN_PASS=dev-strong-pass cargo run

# docker (binds 0.0.0.0 → network-facing, so a strong admin password is REQUIRED;
# a weak/placeholder one makes first start refuse to boot)
docker build -t shardx-team-server server/
docker run -p 8080:8080 -v "$PWD/data:/data" \
  -e SHARDX_TOKEN_SECRET=$(openssl rand -hex 32) \
  -e SHARDX_ADMIN_USER=admin -e SHARDX_ADMIN_PASS="$(openssl rand -base64 18)" \
  shardx-team-server
```

Config is all environment variables — see [`.env.example`](.env.example).
SQLite DB + snapshot blobs live under `SHARDX_DATA_DIR` (`/data` in Docker).
On first start with an empty user table, an admin is bootstrapped from
`SHARDX_ADMIN_USER` / `SHARDX_ADMIN_PASS`. On a **non-loopback bind** (e.g. the
Docker default `0.0.0.0`), the server **refuses to start** if that password is
empty, too short, or a known placeholder (`admin`, `secret`, `change-me`, …), or
if an existing admin still uses one — set a strong `SHARDX_ADMIN_PASS`, bind
`127.0.0.1`, or set `SHARDX_ALLOW_INSECURE_ADMIN=1` to override.

## Team v2 server identity (operators)

The v2 team control plane only accepts writes once the server identity
verifies (ADR 0001). The identity's authority is an external record file,
`identity-record-v2.bin`, kept **outside** the data directory so restoring an
old database can never roll it back. The `v2_server_state` table only mirrors
it. v1 is not affected by any of this.

**`SHARDX_IDENTITY_DIR`** names the directory holding the record. It has no
default. It must already exist, be on a local disk filesystem (network shares,
remote FUSE mounts, 9p and Docker Desktop host shares are refused; use a named
volume), support hard links, and must not equal, contain or sit inside
`SHARDX_DATA_DIR`. In Docker, mount it as a second volume, e.g. `/identity`.
Avoid `tmpfs`: the record is lost on reboot and v2 then stays disabled.

All commands run with the **server stopped**. The server and every command
take an exclusive lock on `<SHARDX_DATA_DIR>/shardx.lock` and refuse while
another holder runs. That lock only orders processes that see the same
filesystem through the same kernel. Across a Docker Desktop bind mount it may
not exclude the server, so stop the server container before running a command.

```bash
# one-off container, server container stopped
docker run --rm -i -v <data-vol>:/data -v <identity-vol>:/identity \
  -e SHARDX_IDENTITY_DIR=/identity <image> identity init
```

- `identity init` creates the epoch-0 record, then its mirror row, and prints
  `server_instance_id` and `external_record_sha256`. Keep both to compare out
  of band with what the first client pins. It refuses if a record or
  `identity-record-v2.bin.tmp` exists, or if the database already has a mirror
  row or any v2 tenant.
- `identity show` checks the record against the mirror and prints `status=`
  (`OK` or a reason code) and `reason=`. It never repairs anything and exits
  non-zero unless the status is `OK`.
- `tenant create --slug <slug> --owner-username <name> [--password-stdin]`
  creates a tenant, its owner account and an audit event in one transaction.
  It refuses unless `identity show` would print `OK`. The password is read from
  a hidden prompt, or from one line of stdin with `--password-stdin` (e.g.
  `... --password-stdin < owner-password.txt`), never from arguments or the
  environment. Without a terminal and without `--password-stdin` it refuses
  instead of waiting. Ctrl-C at the prompt restores terminal echo. If the
  command is killed some other way mid-prompt, echo can stay off: run
  `stty echo` (Unix) or open a new console window (Windows).

### When v2 is disabled

While the identity does not verify, every state-changing `/v2/*` request and
`GET /v2/server-identity` return **HTTP 423** with
`{"error": "...", "code": "<reason>"}`. The server logs the reason at startup.
It never creates, repairs or rewrites the record.

| Code | Meaning |
|---|---|
| `EPOCH_AUTHORITY_MISSING` | `SHARDX_IDENTITY_DIR` unset or invalid, or no record |
| `EPOCH_AUTHORITY_CORRUPT` | The record fails its checksum or format rules, cannot be read, or is not a regular file (a symlink is refused) |
| `EPOCH_AUTHORITY_BEHIND_DB` | The record is from another instance, is behind the mirror's epoch, or is not the record the mirror attests. Treat as a security incident; never copy the mirror back into the record |
| `EPOCH_RECONCILIATION_REQUIRED` | The record is ahead of the mirror, or there is a record but no mirror row |

### Recovering an interrupted `identity init`

If `identity init` stopped after writing the record but before the mirror row
committed, `identity show` reports `EPOCH_RECONCILIATION_REQUIRED` with "no
mirror row", and init refuses because the record exists. No tenant can exist
in this state, because `tenant create` requires a verified identity, and no
client can have pinned the instance, because the server answered 423. Recover
it like this:

1. Stop the server. Run `identity show` and confirm that exact status and reason.
2. Confirm the database has no v2 tenants.
3. Move `identity-record-v2.bin` (and any `.tmp`) out of the identity
   directory. Keep it, do not delete it.
4. Run `identity init` again.

Never do this when the mirror row exists or any tenant exists. A database with
a mirror but no record has lost its authority: restore the record from a
backup of the identity volume, not by re-running init.

### Migration 0011 can stop startup

Migration 0011 binds root and fleet key generations to the server instance and
reconciles each tenant's `active_root_generation` with its root rows. On data it
cannot reconcile, it fails on purpose, and the whole server (v1 included) will
not start until an operator reviews it. Nothing is changed in that case. The
error names the check that failed:

- `m0011_generations_need_server_identity`: key generations exist but there is no mirror row.
- `m0011_root_pointer_disagrees_with_root_rows`: the pointer does not match the ACTIVE generation, or RETIRED rows exist with no ACTIVE one.
- `m0011_fleet_generation_needs_an_activated_root`: a fleet key rests on an unactivated root.
- `m0011_foreign_key_violation`: for example, a grant from another instance or for another key.

## API (Phase 1)

Every route except `/health` and `/auth/login` needs `Authorization: Bearer <token>`.
Admin-only routes return `403` for members.

| Method | Path | Who | Notes |
|---|---|---|---|
| GET | `/health` | — | liveness |
| POST | `/auth/login` | — | `{username,password}` → `{token,role,user_id}` |
| GET | `/me` | any | current identity |
| GET/POST | `/users` | admin | list / create (`{username,password,role?}`) |
| DELETE | `/users/:id` | admin | |
| PATCH | `/users/:id/role` | admin | `{role:"admin"\|"member"}` |
| GET/POST | `/folders` | any / admin | |
| PATCH/DELETE | `/folders/:id` | admin | |
| GET/POST | `/envs` | any / admin | list is ACL-filtered for members |
| GET/PATCH/DELETE | `/envs/:id` | access / admin | `config` is opaque JSON |
| POST/DELETE | `/acl` | admin | grant/revoke `{user_id,object_id,object_kind,perm?}` |
| GET/POST | `/proxies` | any / admin | |
| DELETE | `/proxies/:id` | admin | |
| POST | `/envs/:id/checkout` | access | acquire lock; `{client_id?}` → `{version,snapshot_url,lease_expires_at}`; `409` if held |
| POST | `/envs/:id/lease` | owner | renew lease |
| POST | `/envs/:id/checkin` | owner/admin | multipart `snapshot` (+`client_id`) → new version, releases lock |
| POST | `/envs/:id/release` | owner/admin | discard + unlock |
| POST | `/envs/:id/force-unlock` | admin | clear a stuck lock |
| GET | `/envs/:id/lock` | access | lock status + `expired` flag |
| GET | `/envs/:id/snapshot/:version` | access | download raw blob bytes |

### Checkout locks

One holder per environment at a time. `checkout` takes a lease
(`SHARDX_LEASE_TTL_SECS`, default 90s); the client renews via `lease` while the
browser runs. An expired lease can be reclaimed by anyone with access; admins
can `force-unlock`. The server stores snapshot blobs opaquely (the launcher
packs/encrypts them) and keeps the last `SHARDX_SNAPSHOT_KEEP` (default 5)
versions, GC'ing older blobs.

### Access model

A member sees an environment if they have a direct `env` grant **or** a grant on
the environment's `folder`. Admins see everything. Roles are re-read from the DB
on every request, so demotion/deletion takes effect immediately.

## Smoke test

```bash
BASE=http://127.0.0.1:8080
TOKEN=$(curl -s $BASE/auth/login -d '{"username":"admin","password":"dev-strong-pass"}' \
  -H 'content-type: application/json' | jq -r .token)

curl -s $BASE/me -H "Authorization: Bearer $TOKEN" | jq .
curl -s $BASE/envs -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"win-rtx4060","host_os":"Windows","config":{"webgl":{"renderer":"…"}}}' | jq .
```
