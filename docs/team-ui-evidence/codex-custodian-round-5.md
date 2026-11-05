# Independent custodian verification — round 5

Verified HEAD: `2d44437592d2a68ae3d87509ff95da4a3b484d78`

Scope: current worktree source and the requested contract excerpts. No prior plans or review reports were read. Tests use local fixtures; the real credential-store test is excluded.

## Execution evidence

### Server prerequisite build

`cargo build -j 4 --offline --manifest-path server/Cargo.toml`

```text
   Compiling proc-macro2 v1.0.106
   Compiling unicode-ident v1.0.24
   Compiling quote v1.0.46
   Compiling cfg-if v1.0.4
   Compiling version_check v0.9.5
   Compiling typenum v1.20.1
   Compiling generic-array v0.14.7
   Compiling windows-link v0.2.1
   Compiling futures-core v0.3.32
   Compiling pin-project-lite v0.2.17
   Compiling stable_deref_trait v1.2.1
   Compiling bytes v1.12.0
   Compiling once_cell v1.21.4
   Compiling getrandom v0.2.17
   Compiling itoa v1.0.18
   Compiling getrandom v0.4.3
   Compiling hybrid-array v0.4.14
   Compiling syn v2.0.118
   Compiling memchr v2.8.2
   Compiling rand_core v0.10.1
   Compiling rand_core v0.6.4
   Compiling serde_core v1.0.228
   Compiling find-msvc-tools v0.1.9
   Compiling autocfg v1.5.1
   Compiling writeable v0.6.3
   Compiling shlex v2.0.1
   Compiling litemap v0.8.2
   Compiling cc v1.2.65
   Compiling icu_normalizer_data v2.2.0
   Compiling scopeguard v1.2.0
   Compiling utf8_iter v1.0.4
   Compiling subtle v2.6.1
   Compiling lock_api v0.4.14
   Compiling crypto-common v0.1.7
   Compiling crypto-common v0.2.2
   Compiling smallvec v1.15.2
   Compiling icu_properties_data v2.2.0
   Compiling futures-task v0.3.32
   Compiling slab v0.4.12
   Compiling cpufeatures v0.2.17
   Compiling futures-io v0.3.32
   Compiling synstructure v0.13.2
   Compiling parking_lot_core v0.9.12
   Compiling futures-sink v0.3.32
   Compiling serde v1.0.228
   Compiling cmov v0.5.4
   Compiling pkg-config v0.3.33
   Compiling vcpkg v0.2.15
   Compiling ctutils v0.4.5
   Compiling block-buffer v0.12.1
   Compiling windows-sys v0.61.2
   Compiling percent-encoding v2.3.2
   Compiling thiserror v2.0.18
   Compiling form_urlencoded v1.2.2
   Compiling num-traits v0.2.19
   Compiling tracing-core v0.1.36
   Compiling zerofrom-derive v0.1.7
   Compiling yoke-derive v0.8.2
   Compiling zerovec-derive v0.11.3
   Compiling zerofrom v0.1.8
   Compiling displaydoc v0.2.6
   Compiling yoke v0.8.3
   Compiling tracing-attributes v0.1.31
   Compiling zerovec v0.11.6
   Compiling zerotrie v0.2.4
   Compiling serde_derive v1.0.228
   Compiling tinystr v0.8.3
   Compiling potential_utf v0.1.5
   Compiling icu_locale_core v2.2.0
   Compiling icu_collections v2.2.0
   Compiling socket2 v0.6.4
   Compiling mio v1.2.1
   Compiling icu_provider v2.2.0
   Compiling icu_properties v2.2.0
   Compiling tokio-macros v2.7.0
   Compiling thiserror-impl v2.0.18
   Compiling crossbeam-utils v0.8.21
   Compiling equivalent v1.0.2
   Compiling zmij v1.0.21
   Compiling log v0.4.33
   Compiling tokio v1.54.1
   Compiling spin v0.9.9
   Compiling foldhash v0.1.5
   Compiling allocator-api2 v0.2.21
   Compiling cpufeatures v0.3.1
   Compiling hashbrown v0.15.5
   Compiling tracing v0.1.44
   Compiling icu_normalizer v2.2.0
   Compiling digest v0.11.3
   Compiling futures-util v0.3.32
   Compiling block-buffer v0.10.4
   Compiling http v1.4.2
   Compiling semver v1.0.28
   Compiling hashbrown v0.17.1
   Compiling parking v2.2.1
   Compiling crc-catalog v2.5.0
   Compiling crc v3.4.0
   Compiling event-listener v5.4.2
   Compiling indexmap v2.14.0
   Compiling rustc_version v0.4.1
   Compiling digest v0.10.7
   Compiling idna_adapter v1.2.2
   Compiling crossbeam-queue v0.3.12
   Compiling hashlink v0.10.0
   Compiling either v1.16.0
   Compiling zeroize_derive v1.5.0
   Compiling inout v0.2.2
   Compiling ryu v1.0.23
   Compiling zerocopy v0.8.52
   Compiling windows_x86_64_msvc v0.52.6
   Compiling serde_urlencoded v0.7.1
   Compiling zeroize v1.8.2
   Compiling parking_lot v0.12.5
   Compiling idna v1.1.0
   Compiling curve25519-dalek v5.0.0
   Compiling http-body v1.0.1
   Compiling libsqlite3-sys v0.30.1
   Compiling ahash v0.8.12
   Compiling httparse v1.10.1
   Compiling base64 v0.22.1
   Compiling url v2.5.8
   Compiling tokio-stream v0.1.18
   Compiling futures-intrusive v0.5.0
   Compiling sha2 v0.10.9
   Compiling curve25519-dalek-derive v0.1.1
   Compiling futures-channel v0.3.32
   Compiling inout v0.1.4
   Compiling serde_json v1.0.150
   Compiling tower-service v0.3.3
   Compiling cipher v0.4.4
   Compiling sqlx-core v0.8.6
   Compiling atoi v2.0.0
   Compiling windows-targets v0.52.6
   Compiling futures-executor v0.3.32
   Compiling cipher v0.5.2
   Compiling aead v0.6.1
   Compiling flume v0.11.1
   Compiling universal-hash v0.6.1
   Compiling universal-hash v0.5.1
   Compiling tower-layer v0.3.3
   Compiling time-core v0.1.9
   Compiling num-conv v0.2.2
   Compiling opaque-debug v0.3.1
   Compiling crc32fast v1.5.1
   Compiling rustversion v1.0.22
   Compiling time-macros v0.2.30
   Compiling polyval v0.6.2
   Compiling sqlx-sqlite v0.8.6
   Compiling poly1305 v0.9.1
   Compiling hashbrown v0.14.5
   Compiling chacha20 v0.10.2
   Compiling windows-sys v0.59.0
   Compiling http-body-util v0.1.3
   Compiling hmac v0.13.0
   Compiling sha2 v0.11.0
   Compiling num-integer v0.1.46
   Compiling ring v0.17.14
   Compiling multer v3.1.0
   Compiling base64ct v1.8.3
   Compiling httpdate v1.0.3
   Compiling adler2 v2.0.1
   Compiling simd-adler32 v0.3.10
   Compiling bitflags v2.13.0
   Compiling atomic-waker v1.1.2
   Compiling anyhow v1.0.103
   Compiling heck v0.5.0
   Compiling powerfmt v0.2.0
   Compiling dotenvy v0.15.7
   Compiling mime v0.3.17
   Compiling hex v0.4.3
   Compiling deranged v0.5.8
   Compiling sync_wrapper v1.0.2
   Compiling signature v3.0.0
   Compiling regex-syntax v0.8.11
   Compiling sqlx-macros-core v0.8.6
   Compiling ed25519 v3.0.0
   Compiling hyper v1.10.1
   Compiling time v0.3.51
   Compiling regex-automata v0.4.14
   Compiling miniz_oxide v0.9.1
   Compiling password-hash v0.5.0
   Compiling num-bigint v0.4.6
   Compiling hkdf v0.13.0
   Compiling hashlink v0.9.1
   Compiling chacha20poly1305 v0.11.0
   Compiling ghash v0.5.1
   Compiling x25519-dalek v3.0.0
   Compiling aes v0.8.4
   Compiling ctr v0.9.2
   Compiling blake2 v0.10.6
   Compiling async-trait v0.1.89
   Compiling aead v0.5.2
   Compiling filetime v0.2.29
   Compiling encoding_rs v0.8.35
   Compiling fallible-streaming-iterator v0.1.9
   Compiling fallible-iterator v0.3.0
   Compiling thiserror v1.0.69
   Compiling lazy_static v1.5.0
   Compiling untrusted v0.9.0
   Compiling sharded-slab v0.1.7
   Compiling axum-core v0.4.5
   Compiling rusqlite v0.32.1
   Compiling tar v0.4.46
   Compiling aes-gcm v0.10.3
   Compiling argon2 v0.5.3
   Compiling hpke v0.14.0
   Compiling flate2 v1.1.10
   Compiling simple_asn1 v0.6.4
   Compiling matchers v0.2.0
   Compiling sqlx-macros v0.8.6
   Compiling hyper-util v0.1.20
   Compiling ed25519-dalek v3.0.0
   Compiling tower v0.5.3
   Compiling nu-ansi-term v0.50.3
   Compiling aead-stream v0.6.0
   Compiling pem v3.0.6
   Compiling tracing-log v0.2.0
   Compiling thiserror-impl v1.0.69
   Compiling serde_path_to_error v0.1.20
   Compiling thread_local v1.1.9
   Compiling matchit v0.7.3
   Compiling tracing-subscriber v0.3.23
   Compiling axum v0.7.9
   Compiling jsonwebtoken v9.3.1
   Compiling shardx-core v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\shared)
   Compiling sqlx v0.8.6
   Compiling tower-http v0.5.2
   Compiling tokio-util v0.7.18
   Compiling chrono v0.4.45
   Compiling uuid v1.23.4
   Compiling shardx-team-server v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\server)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 31s
```
Exit: 0; seconds: 91.79

### v2_auth

`cargo test -j 4 --manifest-path server/Cargo.toml --test v2_auth` (CARGO_NET_OFFLINE=true)

```text

running 82 tests
2026-11-05T18:50:09.963929Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:09.973541Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:09.975650Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:09.975713Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:09.979724Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28213
2026-11-05T18:50:09.998536Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:10.006731Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.008482Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.008536Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.012314Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28214
2026-11-05T18:50:10.047702Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:10.056553Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.058316Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.058375Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.061871Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28219
2026-11-05T18:50:10.268456Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:10.277785Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.296941Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:10.323340Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.323413Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.326983Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28215
2026-11-05T18:50:10.336377Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.338683Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.338746Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.342373Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28197
2026-11-05T18:50:10.414697Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:10.423434Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.425540Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.425599Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.429219Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28237
2026-11-05T18:50:10.441124Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:10.450640Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.485012Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.485084Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.489047Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28230
2026-11-05T18:50:10.561578Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:10.570647Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.572913Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.572977Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.576592Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28220
2026-11-05T18:50:10.608714Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:10.621960Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.624403Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.624472Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.626346Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.628152Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28396
2026-11-05T18:50:10.628348Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.628391Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.632041Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28213
2026-11-05T18:50:10.636871Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.638828Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.638886Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.639248Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:10.642340Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28219
2026-11-05T18:50:10.648709Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.650843Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.650904Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.654415Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28399
2026-11-05T18:50:10.662215Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.664111Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.664167Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.667680Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28214
2026-11-05T18:50:10.766404Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:10.777416Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.779564Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.779620Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.790027Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28194
2026-11-05T18:50:10.823607Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:10.834118Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.836220Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.836285Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.841163Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28235
2026-11-05T18:50:10.900216Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:10.902080Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:10.902135Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:10.905621Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28215
2026-11-05T18:50:11.033338Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.035388Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.035449Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.039554Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28230
2026-11-05T18:50:11.090708Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.092418Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.092476Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.095913Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28399
2026-11-05T18:50:11.104954Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.106868Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.106924Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.108202Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.109918Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.109972Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.110504Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28396
2026-11-05T18:50:11.113190Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28220
2026-11-05T18:50:11.306810Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:11.323627Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:11.332270Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.332270Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.334613Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.334677Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.334794Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.334831Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.338131Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28199
2026-11-05T18:50:11.338130Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28181
2026-11-05T18:50:11.391143Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.393170Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.393235Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.396652Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28237
2026-11-05T18:50:11.485334Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.485454Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.487065Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.487065Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.487119Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.487144Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.488310Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.490211Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28235
2026-11-05T18:50:11.490254Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.490288Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28197
2026-11-05T18:50:11.490319Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.494604Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28194
2026-11-05T18:50:11.496483Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:11.506093Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.507934Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.508004Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.512314Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28216
2026-11-05T18:50:11.680471Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:11.689333Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.691531Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.691592Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.694942Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28212
2026-11-05T18:50:11.858385Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:11.862898Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:11.862963Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:11.866276Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28199
2026-11-05T18:50:12.180018Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:12.181843Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:12.181914Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:12.184973Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28216
2026-11-05T18:50:12.357872Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:12.359695Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:12.359755Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:12.362892Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28212
test a_device_that_changed_since_its_challenge_gets_no_session ... ok
2026-11-05T18:50:12.549683Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:12.691265Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:12.692231Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:12.692297Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:12.698924Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28396
2026-11-05T18:50:12.888190Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:12.889485Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:12.889566Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:12.893584Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28399
test a_custodian_lists_the_tenant_devices_with_their_public_keys ... ok
2026-11-05T18:50:13.188105Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
test a_bootstrap_needs_a_first_self_grant_and_a_consumed_guard ... ok
2026-11-05T18:50:13.316974Z  WARN shardx_team_server::integrity: a quarantined device revocation verifies again and is served; its mark stays tenant="41414141414141414141414141414141" replay="90909090909090909090909090909090"
2026-11-05T18:50:13.318189Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 1, foreign_key_violations: 0 }
2026-11-05T18:50:13.320532Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:13.320577Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:13.323692Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28396
test a_custodian_files_an_existing_root_grant_only_to_a_tenant_approved_device ... ok
2026-11-05T18:50:13.474275Z  WARN shardx_team_server::integrity: a quarantined device revocation verifies again and is served; its mark stays tenant="41414141414141414141414141414141" replay="90909090909090909090909090909090"
2026-11-05T18:50:13.475406Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 1, foreign_key_violations: 0 }
2026-11-05T18:50:13.477510Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:13.477574Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:13.481072Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28399
test a_bootstrap_needs_d1_the_setup_session_and_an_exact_self_grant ... ok
test a_corrupt_container_is_marked_without_a_hash_and_served_again_once_restored ... ok
test a_container_of_another_row_is_marked_without_a_hash ... ok
test a_custodian_approves_a_second_device_into_an_ordinary_session ... ok
2026-11-05T18:50:14.272430Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:14.274354Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:14.274417Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 1
2026-11-05T18:50:14.278921Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28230
2026-11-05T18:50:14.836814Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:14.848732Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:14.850862Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:14.850923Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:14.853982Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28233
test a_device_session_reads_the_active_fleet_generation_and_its_own_root_grants ... ok
2026-11-05T18:50:14.949665Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
test a_device_reads_back_only_its_own_fleet_grant_as_an_exact_descriptor ... ok
2026-11-05T18:50:15.456935Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:15.466192Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:15.468445Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:15.468501Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:15.471604Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28195
2026-11-05T18:50:15.951180Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:15.953658Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:15.953707Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:15.956686Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28233
2026-11-05T18:50:16.243587Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:16.245383Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:16.245494Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:16.248691Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28195
2026-11-05T18:50:16.702216Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:16.704047Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:16.704101Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 1
2026-11-05T18:50:16.707053Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28233
2026-11-05T18:50:16.944341Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:16.947395Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:16.947444Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:16.950616Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28195
test a_custodian_acks_activates_rotates_and_revokes_fleet_grants ... ok
test a_custodian_revokes_a_root_grant_but_never_the_last_one ... ok
2026-11-05T18:50:17.336360Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:17.346307Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:17.348213Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:17.348267Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:17.351232Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28395
test a_custodian_creates_fleet_generations_and_files_their_grants ... ok
2026-11-05T18:50:17.443408Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:17.445615Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:17.445670Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 2
2026-11-05T18:50:17.448668Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28230
test a_custodian_rotates_the_root_to_a_new_custodian_set ... ok
2026-11-05T18:50:18.111518Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:18.123401Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:18.125117Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:18.125177Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:18.126451Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:18.128344Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:18.128392Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:18.128577Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28394
2026-11-05T18:50:18.132118Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28395
test a_closed_or_recovering_guard_never_approves ... ok
2026-11-05T18:50:18.401246Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:18.410112Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:18.412025Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:18.412077Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:18.415289Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28175
2026-11-05T18:50:18.920394Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:18.922632Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:18.922692Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:18.926179Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28394
test a_custodian_files_a_restore_epoch_transition_once_and_the_tenant_reads_it_back ... ok
2026-11-05T18:50:19.430663Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:19.440291Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:19.442372Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:19.442443Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:19.446178Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28511
2026-11-05T18:50:19.570452Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:19.582523Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:19.586192Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:19.586250Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:19.589682Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28512
2026-11-05T18:50:19.790831Z  WARN shardx_team_server::integrity: a quarantined device revocation verifies again and is served; its mark stays tenant="41414141414141414141414141414141" replay="90909090909090909090909090909090"
2026-11-05T18:50:19.791854Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 1, foreign_key_violations: 0 }
2026-11-05T18:50:19.793909Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:19.793953Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:19.796484Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28395
2026-11-05T18:50:20.058362Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:20.060156Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:20.060208Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:20.063596Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28511
test a_proof_belongs_to_its_own_ticket ... ok
2026-11-05T18:50:20.166860Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:20.168599Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:20.168646Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:20.172075Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28512
2026-11-05T18:50:20.218126Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:20.227265Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:20.229329Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:20.229474Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:20.229527Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:20.232603Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28391
2026-11-05T18:50:20.238836Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:20.240805Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:20.240863Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:20.244385Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28393
test a_mark_without_a_container_hash_is_served_again_once_the_row_verifies ... ok
2026-11-05T18:50:20.543206Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:20.553159Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:20.555099Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:20.555150Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:20.558337Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28392
2026-11-05T18:50:20.594054Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:20.603891Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:20.606260Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:20.606315Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:20.609805Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28453
2026-11-05T18:50:20.757425Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:20.758677Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:20.758727Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:20.762024Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28394
2026-11-05T18:50:21.059857Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:21.061576Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:21.061629Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:21.066079Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28393
2026-11-05T18:50:21.075846Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:21.077938Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:21.078013Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:21.081704Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28391
2026-11-05T18:50:21.270901Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:21.278987Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:21.280776Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:21.280826Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:21.284057Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28318
2026-11-05T18:50:21.307424Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:21.309427Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:21.309487Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:21.313095Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28392
2026-11-05T18:50:21.338524Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:21.340704Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:21.340762Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:21.342348Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 holds another container than the one that was quarantined; restoring the quarantined container and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:21.342425Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 holds another container than the one that was quarantined; restoring the quarantined container and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:21.344387Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28453
2026-11-05T18:50:21.345717Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28394
2026-11-05T18:50:21.693398Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:21.703216Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:21.705109Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:21.705172Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:21.708534Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28218
2026-11-05T18:50:22.005351Z  WARN shardx_team_server::integrity: a quarantined device revocation verifies again and is served; its mark stays tenant="41414141414141414141414141414141" replay="90909090909090909090909090909090"
2026-11-05T18:50:22.006383Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 1, foreign_key_violations: 0 }
2026-11-05T18:50:22.008334Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:22.008398Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:22.011664Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28394
2026-11-05T18:50:22.038826Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:22.047373Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.049275Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:22.049336Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:22.052717Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28222
2026-11-05T18:50:22.074943Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.077428Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:22.077483Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:22.081128Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28318
test a_revocation_commits_its_root_activation ... ok
2026-11-05T18:50:22.329364Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:22.339189Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.341239Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:22.341298Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:22.347074Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28204
test a_marked_row_swapped_for_another_genuine_revocation_is_not_served_again ... ok
2026-11-05T18:50:22.515512Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:22.525944Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.528201Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:22.528266Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:22.531661Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28218
2026-11-05T18:50:22.532766Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.534847Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:22.534903Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:22.538739Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28317
2026-11-05T18:50:22.587280Z  WARN shardx_team_server::routes::v2_trust: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 belongs to another server instance; restoring the row and restarting clears it
2026-11-05T18:50:22.657360Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:22.658638Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.658730Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:22.662608Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28393
2026-11-05T18:50:22.694267Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.696272Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:22.696331Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:22.700064Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28222
2026-11-05T18:50:22.719211Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:22.727869Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.729906Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:22.729965Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:22.733184Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28234
2026-11-05T18:50:22.779266Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 belongs to another server instance; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.779366Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 belongs to another server instance; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:22.783316Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28391
2026-11-05T18:50:22.816204Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:22.825124Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.826927Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:22.826983Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:22.830530Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28461
2026-11-05T18:50:22.834474Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.836728Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:22.836796Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:22.840166Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28204
2026-11-05T18:50:22.847997Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:22.924749Z  WARN shardx_team_server::routes::v2_trust: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it
test a_revocation_commits_its_fleet_activation_or_nothing ... ok
2026-11-05T18:50:22.936609Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:22.938637Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:22.938701Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:22.942105Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28317
test a_revocation_quarantined_at_runtime_refuses_the_trust_evidence ... ok
2026-11-05T18:50:23.081629Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:23.090480Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:23.092529Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:23.092594Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:23.096548Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28188
2026-11-05T18:50:23.099975Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:23.108653Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:23.110659Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:23.110711Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:23.114037Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28182
2026-11-05T18:50:23.116327Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:23.116430Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:23.120127Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28393
2026-11-05T18:50:23.132218Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:23.134904Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:23.134974Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:23.139087Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28234
2026-11-05T18:50:23.328982Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:23.331296Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:23.331368Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:23.335065Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28461
2026-11-05T18:50:23.434371Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:23.436360Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:23.436427Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:23.439846Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28391
test a_session_from_another_epoch_is_refused ... ok
test a_revocation_of_another_instance_turns_v2_off_until_it_is_put_back ... ok
2026-11-05T18:50:23.905334Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 is quarantined and its row is missing; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:23.905414Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 is quarantined and its row is missing; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:23.914560Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28393
2026-11-05T18:50:23.919246Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:23.921419Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:23.921488Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 1
2026-11-05T18:50:23.925551Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28234
2026-11-05T18:50:23.970974Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: the integrity pass failed: checking the device revocations failed: Internal("db: error occurred while decoding column 0: mismatched types; Rust type `alloc::vec::Vec<u8>` (as SQL type `BLOB`) is not compatible with SQL type `INTEGER`"); v1 is unaffected
2026-11-05T18:50:23.990688Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28318
2026-11-05T18:50:24.168594Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
test a_row_holding_another_rows_container_is_not_that_grant ... ok
test a_revocation_blocks_new_capabilities_and_inflight_session_proofs ... ok
2026-11-05T18:50:24.372904Z  WARN shardx_team_server::integrity: a quarantined device revocation verifies again and is served; its mark stays tenant="41414141414141414141414141414141" replay="90909090909090909090909090909090"
2026-11-05T18:50:24.374030Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 1, foreign_key_violations: 0 }
2026-11-05T18:50:24.376397Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:24.376457Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:24.380260Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28393
2026-11-05T18:50:24.445816Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:24.447916Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:24.447993Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:24.451842Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28318
2026-11-05T18:50:24.501239Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:24.503581Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:24.503652Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 1
2026-11-05T18:50:24.507328Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28234
test a_quarantined_revocation_that_verifies_again_is_served_again_after_a_restart ... ok
test a_revocation_row_the_startup_pass_cannot_read_turns_v2_off ... ok
2026-11-05T18:50:24.824343Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:24.836705Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:24.839191Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:24.839245Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:24.842418Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28174
test a_first_device_confirmed_before_a_restore_is_approved_or_cancelled_after_it ... ok
test a_revocation_row_swapped_for_another_genuine_one_does_not_answer_a_retry ... ok
test a_session_rotates_a_bounded_number_of_times ... ok
2026-11-05T18:50:25.639966Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:25.649745Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:25.651813Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:25.651874Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:25.655422Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28193
2026-11-05T18:50:25.918293Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:26.256448Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:26.268588Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:26.270732Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:26.270778Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:26.273824Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28172
test a_signing_only_proof_burns_the_challenge ... ok
2026-11-05T18:50:26.669036Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:26.678480Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:26.678536Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:26.683475Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28193
test a_same_account_v1_token_does_not_bypass_device_root_grant_isolation ... ok
2026-11-05T18:50:28.821549Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:28.831006Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:28.833533Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:28.841172Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:28.841226Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:28.844556Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28171
2026-11-05T18:50:28.875340Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
test a_ticket_authorizes_nothing_but_its_own_proofs ... ok
2026-11-05T18:50:28.886117Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:28.886187Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:28.889918Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28185
test a_stored_receipt_that_disagrees_closes_the_approval_path ... ok
test a_revoked_device_cannot_sign_in_again ... ok
2026-11-05T18:50:29.755576Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:29.765095Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:29.767239Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:29.767301Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:29.770798Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28183
2026-11-05T18:50:29.899611Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:29.909010Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:29.910935Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:29.910994Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:29.914738Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28187
test a_ticket_becomes_a_device_session_only_through_both_proofs ... ok
2026-11-05T18:50:30.576330Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:30.576855Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:30.586447Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:30.586589Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:30.588600Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:30.588664Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:30.589575Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:30.589637Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:30.592180Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28203
2026-11-05T18:50:30.593145Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28180
test a_ticket_enrolls_a_device_and_then_proves_it_into_a_session ... ok
2026-11-05T18:50:30.760583Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:30.774632Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:30.777144Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:30.777207Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:30.780795Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28231
2026-11-05T18:50:31.117515Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:31.129714Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:31.131753Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:31.131809Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:31.135325Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28186
2026-11-05T18:50:31.360702Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:31.369778Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:31.371818Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:31.371879Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:31.415127Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28211
2026-11-05T18:50:31.515349Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:31.524345Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:31.524860Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:31.526303Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:31.526362Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
test a_ticket_issues_five_challenges_in_its_life ... ok
test a_root_rotation_rewraps_every_retained_fleet_key_before_it_activates ... ok
2026-11-05T18:50:31.533597Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:31.543545Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28184
2026-11-05T18:50:31.549671Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:31.549739Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:31.553550Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28191
2026-11-05T18:50:31.627202Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:31.629181Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:31.629241Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:31.632745Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28203
2026-11-05T18:50:31.666489Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:31.668447Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:31.668510Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:31.672627Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28231
2026-11-05T18:50:31.675185Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:31.677322Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:31.677392Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:31.681598Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28180
2026-11-05T18:50:31.818794Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:31.829350Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:31.831117Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:31.831174Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:31.834943Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28192
2026-11-05T18:50:32.320309Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:32.322180Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:32.322241Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:32.325677Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28211
test a_wrong_enrollment_signature_burns_the_challenge ... ok
2026-11-05T18:50:32.642499Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:32.644072Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:32.644127Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:32.647800Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28192
test concurrent_challenges_stop_at_the_cap ... ok
test after_a_restart_a_new_login_reaches_the_same_device ... ok
2026-11-05T18:50:32.801741Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:32.811359Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:32.813320Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:32.813385Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:32.840545Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28198
2026-11-05T18:50:33.134228Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:33.143149Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:33.145107Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:33.145169Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:33.148928Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:33.212540Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:33.215615Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:33.215673Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 1
2026-11-05T18:50:33.219102Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28231
2026-11-05T18:50:33.244623Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:33.279720Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:33.281836Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:33.281898Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:33.285847Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28501
2026-11-05T18:50:33.402107Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:33.404223Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:33.404280Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:33.408179Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28191
2026-11-05T18:50:33.567938Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:33.569966Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:33.570025Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:33.573425Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28198
2026-11-05T18:50:33.661424Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:33.663375Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:33.663444Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:33.667075Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:33.748193Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:33.750170Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:33.750236Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:33.754410Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28501
test concurrent_identical_approvals_commit_once ... ok
2026-11-05T18:50:33.960745Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:33.960745Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:33.970247Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:33.970959Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:33.973215Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:33.973285Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:33.973743Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:33.973780Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:33.976863Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:33.977216Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
test a_trust_evidence_page_stays_within_four_mebibytes ... ok
2026-11-05T18:50:34.363704Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:34.372907Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:34.375574Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:34.375793Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:34.384779Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:34.662094Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:34.663853Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:34.663903Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:34.667356Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
2026-11-05T18:50:34.958972Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:34.961104Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:34.961155Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:34.964542Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
test concurrent_identical_bootstraps_commit_once_and_a_bad_ledger_is_refused ... ok
test an_approval_needs_the_confirmation_the_session_and_the_exact_subject ... ok
2026-11-05T18:50:35.107036Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:35.117403Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:35.119515Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:35.119572Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:35.122928Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28310
2026-11-05T18:50:35.130607Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:35.132754Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:35.132818Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:35.136446Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:35.343087Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:35.453757Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
test approvals_and_root_grants_from_before_a_restore_still_work_after_it ... ok
2026-11-05T18:50:35.548571Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:35.605979Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:35.608195Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:35.608253Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:35.611891Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28310
2026-11-05T18:50:35.673878Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:35.723775Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:35.734540Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:35.736368Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:35.736422Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:35.739927Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28189
2026-11-05T18:50:35.770165Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:35.793789Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:35.884119Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:35.958115Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:35.959350Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:36.007579Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:36.015668Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:36.032546Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:36.032604Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:36.036314Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28176
2026-11-05T18:50:36.119782Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:36.123114Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:36.132255Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:36.134220Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:36.134283Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:36.137857Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28232
2026-11-05T18:50:36.170216Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:36.208292Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:36.218950Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:36.222026Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:36.222098Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:36.225904Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
2026-11-05T18:50:36.265489Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:36.340716Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:36.425684Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:36.470422Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:36.481884Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:36.546802Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:36.553004Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:36.591877Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:36.670589Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:36.675652Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:36.688980Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:36.747248Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:36.821488Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:36.832350Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:36.883967Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:36.898410Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:36.928304Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:36.982434Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:37.023845Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.080445Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:37.129292Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.161523Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:37.181449Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:37.181719Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:37.240168Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:37.242034Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:37.242082Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:37.245131Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28232
2026-11-05T18:50:37.254381Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.273826Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:37.283262Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:37.283547Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:37.309023Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:37.317783Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:37.319677Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:37.319731Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:37.331952Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28179
2026-11-05T18:50:37.390390Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.390660Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:37.405738Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:37.448834Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:37.455059Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.464641Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:37.489341Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:37.491703Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:37.491758Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:37.494950Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28178
2026-11-05T18:50:37.497941Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:37.556948Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.576825Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:37.590819Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:37.593503Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:37.595500Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:37.595558Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:37.599103Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
2026-11-05T18:50:37.630905Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.684250Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:37.688815Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:37.693224Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.771475Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.802269Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:37.804032Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:37.804084Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:37.804915Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:37.807316Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:37.819641Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:37.828669Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.884504Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.894684Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:37.895679Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:37.928488Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:37.947378Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:37.953180Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:37.963156Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:37.965241Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:37.965296Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:37.969372Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28206
2026-11-05T18:50:38.019792Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:38.020008Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:38.021776Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:38.037266Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
test every_approval_column_is_compared_with_its_container_on_each_request ... ok
2026-11-05T18:50:38.117504Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:38.130032Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:38.151022Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:38.234361Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:38.251467Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:38.257137Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
test live_state_ends_tickets_and_sessions ... ok
2026-11-05T18:50:38.399589Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:38.402124Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:38.405476Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:38.406527Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:38.406579Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:38.409845Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:38.529825Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:38.553688Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:38.553937Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:38.578465Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:38.589670Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:38.591654Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:38.591715Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:38.595363Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28236
2026-11-05T18:50:38.641801Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:38.643831Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:38.643893Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:38.668850Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
2026-11-05T18:50:38.676577Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:38.683130Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:38.708802Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:38.879578Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:38.919097Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:38.920781Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:38.920850Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:38.924080Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28206
2026-11-05T18:50:38.948729Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:38.957756Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:38.958294Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:38.960289Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:38.960356Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:38.964378Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28207
2026-11-05T18:50:38.976795Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:38.982997Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:38.983078Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 1
2026-11-05T18:50:38.986599Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28232
2026-11-05T18:50:39.079525Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:39.127759Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:39.285767Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:39.286795Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:39.286851Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:39.290345Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:39.309664Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:39.344479Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:39.346400Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:39.346464Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:39.368679Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:39.419425Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:39.433345Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:39.517849Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:39.523321Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:39.535009Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:39.537340Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:39.537407Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:39.541337Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28207
test logout_ends_the_ticket_its_challenges_or_the_session ... ok
2026-11-05T18:50:39.632609Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:39.667676Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:39.726405Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:39.763590Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:39.770813Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:39.771987Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:39.772067Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:39.772848Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:39.775474Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:39.777262Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:39.777330Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:50:39.780807Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:39.866888Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:39.925974Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:39.927959Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:39.928014Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:39.931757Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
2026-11-05T18:50:39.936033Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:39.964866Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
test fleet_grants_from_before_a_restore_are_acknowledged_and_revoked_after_it ... ok
2026-11-05T18:50:40.070744Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:40.072036Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:40.113690Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:40.115942Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:40.116001Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:40.119643Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28236
2026-11-05T18:50:40.197116Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:40.210321Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:40.332508Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:40.333434Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:40.333476Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:40.336646Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:40.339037Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:40.345807Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:40.384482Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:40.397294Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:40.397348Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:50:40.404086Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:40.511709Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:40.514288Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:40.723303Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:40.725403Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:40.725472Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:40.729153Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
test an_account_holds_a_bounded_number_of_tickets ... ok
2026-11-05T18:50:40.850176Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:40.856043Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:40.986043Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:41.008871Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:41.031071Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:41.033798Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:41.033862Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:41.037784Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:41.061174Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:41.072854Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:41.073966Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:41.074029Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:41.093522Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:41.105565Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:41.173509Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:41.206671Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:41.218150Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:41.228019Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:41.230071Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:41.230136Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:41.233735Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28173
2026-11-05T18:50:41.341973Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:41.346927Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:41.452384Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:41.486355Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
test only_an_acknowledged_unrevoked_custody_grant_issues ... ok
2026-11-05T18:50:41.610134Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:41.617792Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:41.741536Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:41.752205Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:41.758165Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:41.761734Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:41.765503Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:41.765578Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:41.769149Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28217
test login_failures_are_throttled_and_say_nothing ... ok
2026-11-05T18:50:41.825156Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:41.866918Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:41.889897Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:41.903371Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:41.905973Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:41.906035Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:41.908149Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:41.909428Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:41.909487Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:41.912858Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:41.916381Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:41.935725Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:41.987561Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:42.052068Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:42.090642Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:42.128188Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:42.130302Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:42.130362Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:42.134039Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
2026-11-05T18:50:42.203503Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:42.218069Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
test only_a_live_custodian_files_an_issuable_grant_for_a_live_subject ... ok
2026-11-05T18:50:42.312350Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:42.313443Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:42.313495Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:42.317546Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:42.328664Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:42.344985Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:42.346960Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:42.347025Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:42.350728Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28217
2026-11-05T18:50:42.350727Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:42.366564Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:42.399113Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:42.401111Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:42.401177Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:42.404548Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:42.459351Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:42.561954Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
test only_the_accounts_own_pending_device_gets_a_challenge ... ok
2026-11-05T18:50:42.681389Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:42.683429Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:42.683487Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:42.687254Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:42.719588Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:42.854109Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:42.889989Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:42.891689Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:42.891766Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:42.895189Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:42.992701Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:42.993611Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:43.011154Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:43.013229Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:43.013286Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:43.016815Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:43.076847Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
test only_an_active_custodian_session_lists_the_tenant_devices ... ok
2026-11-05T18:50:43.126414Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:43.159249Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:43.159473Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:43.161247Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:43.161250Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:43.161301Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:43.161321Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:43.164678Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:43.169156Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
2026-11-05T18:50:43.185247Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:43.381122Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:43.426162Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:43.434784Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:43.436512Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:43.436567Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:43.439975Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28202
2026-11-05T18:50:43.447103Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:43.448089Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:43.448147Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:43.452118Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:43.463523Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:43.473332Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:43.475285Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:43.475340Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:43.478822Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28177
2026-11-05T18:50:43.505945Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:43.511072Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:43.518308Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:43.520302Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:43.520357Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:43.523993Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:43.708949Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:43.797862Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:43.839951Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:43.840028Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:50:43.843669Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:43.850881Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:43.979596Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:44.038801Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:44.040648Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:44.040697Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:44.041326Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:44.042216Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:44.042261Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:44.044039Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28202
2026-11-05T18:50:44.045329Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
test only_the_creator_files_its_own_grant_before_holding_the_generation ... ok
2026-11-05T18:50:44.084171Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:44.089655Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:44.097111Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:44.099058Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:44.099131Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:44.102652Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:44.203451Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:44.324040Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:44.368500Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:44.384602Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:44.386751Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:44.386807Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:44.390610Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
2026-11-05T18:50:44.399650Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:44.404655Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:44.404713Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:50:44.408085Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:44.408735Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:44.411155Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:44.411217Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:44.414787Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28190
2026-11-05T18:50:44.450791Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:44.526048Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:44.534537Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:44.536510Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:44.536569Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:44.539970Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28238
2026-11-05T18:50:44.564998Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:44.654366Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:44.655370Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:44.655426Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:44.659024Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:44.722528Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:44.722816Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:44.735939Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:44.738461Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:44.738521Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:44.741899Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:44.882909Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:44.993992Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:45.016378Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:45.050114Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:45.050169Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:50:45.053394Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:45.119202Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:45.220974Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:45.222933Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:45.222992Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:45.225418Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:45.226548Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28190
2026-11-05T18:50:45.312401Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:45.321583Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:45.329149Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:45.329221Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:45.331147Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:45.332240Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:45.332302Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:45.332985Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28205
2026-11-05T18:50:45.335868Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
test refresh_rotates_once_and_respects_expiry ... ok
2026-11-05T18:50:45.368256Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
test every_fleet_grant_column_is_compared_with_its_container_on_each_request ... ok
2026-11-05T18:50:45.467286Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:45.485844Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:45.487938Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:45.488001Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:45.491346Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28196
2026-11-05T18:50:45.516193Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:45.532310Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:45.534281Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:45.534359Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:45.537936Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:45.572734Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:45.574898Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:45.574961Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:45.579012Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
2026-11-05T18:50:45.587015Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:45.623374Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:45.623431Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:50:45.627298Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:45.768944Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:45.769997Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:45.770049Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:45.773774Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:45.811743Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:45.813810Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:45.813920Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:45.817857Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28205
2026-11-05T18:50:45.904200Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:45.906490Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:45.906552Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:45.910283Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28238
2026-11-05T18:50:45.914973Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:45.926053Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:45.928671Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:45.928740Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:45.932815Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28201
2026-11-05T18:50:45.998092Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:46.000289Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:46.000352Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:46.004475Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28196
2026-11-05T18:50:46.013530Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:46.027271Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:46.029304Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:46.029366Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:46.033094Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:46.144859Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:46.180717Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:46.184472Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:46.184533Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:46.188065Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:46.315526Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:46.324519Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:46.326338Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:46.326395Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:46.329900Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28452
2026-11-05T18:50:46.346220Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:46.348401Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:46.348461Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:46.352259Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28201
2026-11-05T18:50:46.360865Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:46.361968Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:46.362030Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:46.372993Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:46.448591Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:46.450716Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:46.450781Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:46.454423Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
test every_way_of_naming_the_tenant_shares_one_account_throttle ... ok
2026-11-05T18:50:46.576977Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:46.605101Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:46.619039Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:46.621118Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:46.621179Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:46.625127Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
test readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant ... ok
2026-11-05T18:50:46.779270Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:46.827145Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:46.829537Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:46.829603Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:46.833921Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:47.002375Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:47.003391Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:47.003446Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:47.008963Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:47.196397Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:47.211939Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:47.237663Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:47.237741Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:47.241480Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
test the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response ... ok
2026-11-05T18:50:47.417891Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:47.420014Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:47.420080Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:47.423902Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28221
2026-11-05T18:50:47.440638Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:47.476437Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:47.477366Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:47.479519Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:47.479616Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:47.484230Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:47.488750Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:47.490942Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:47.491003Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:47.494988Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28502
test the_legacy_guarded_routes_still_require_v1_auth ... ok
2026-11-05T18:50:47.652005Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:47.653085Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:47.653144Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:47.656958Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:47.822010Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:47.834207Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:47.836682Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:47.836741Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:47.840616Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
test an_expired_self_grant_is_neither_counted_nor_acknowledged ... ok
2026-11-05T18:50:48.032382Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:48.070547Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:48.073638Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:48.073708Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:48.077931Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:48.140153Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:48.142333Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:48.142390Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:48.145570Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28502
test every_custody_operation_replays_its_lost_response_after_a_restart ... ok
2026-11-05T18:50:48.261280Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:48.273533Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:48.275663Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:48.275727Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:48.279002Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28315
2026-11-05T18:50:48.329472Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:48.331882Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:48.331950Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:48.335201Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:48.391547Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:48.407527Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:48.409797Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:48.409852Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:48.413138Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:48.513745Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:48.636951Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:48.637340Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:48.650843Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:48.656577Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:48.656631Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:48.661008Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28311
2026-11-05T18:50:48.703888Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:48.707366Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:48.707442Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:48.710897Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:48.776656Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:48.790412Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:48.790471Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:48.793916Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28190
test server_identity_answers_a_ticket_and_a_session_without_a_v1_token ... ok
test the_first_device_reads_back_acknowledges_and_activates_generation_zero ... ok
2026-11-05T18:50:48.938334Z  WARN shardx_team_server::integrity: a device revocation mark could not be recorded: error returned from database: (code: 787) FOREIGN KEY constraint failed
2026-11-05T18:50:48.939449Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant be414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:48.939595Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant be414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
test the_active_custodian_files_capability_grants_once ... ok
2026-11-05T18:50:48.944448Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:48.947216Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:48.947270Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:48.949365Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:48.950313Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28315
2026-11-05T18:50:49.001068Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:49.013682Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:49.016089Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:49.016162Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:49.020323Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:49.106215Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:49.108719Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:49.108792Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:49.112108Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28311
2026-11-05T18:50:49.188932Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:49.222509Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:49.234031Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:49.234100Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:49.237749Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:49.554408Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:49.555625Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: ["device revocation 6f909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:49.555696Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 6f909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:49.559440Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:49.614353Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:49.616469Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:49.616535Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:49.620332Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28313
2026-11-05T18:50:49.788583Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:49.823404Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:49.825649Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:49.825721Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:49.829861Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
test every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... ok
2026-11-05T18:50:50.184336Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 belongs to another server instance; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.184421Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 belongs to another server instance; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:50.188244Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:50.322177Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:50.357834Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.359750Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:50.359812Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:50.363600Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:50.457979Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:50.467446Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.469309Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:50.469374Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:50.472840Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28208
2026-11-05T18:50:50.473975Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:50.484088Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.486140Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:50.486199Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:50.489730Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28209
2026-11-05T18:50:50.585890Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.588030Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:50.588104Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:50.592760Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28314
2026-11-05T18:50:50.623638Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:50.636766Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:50.637880Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 2, untrusted_revocations: ["device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it", "device revocation e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.637964Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (2 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:50.640949Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28315
2026-11-05T18:50:50.695390Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:50.706449Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.708757Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:50.708832Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:50.713076Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28210
2026-11-05T18:50:50.800091Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:50.823824Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-05T18:50:50.825603Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 2, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.827529Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:50.827594Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:50.831723Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28502
2026-11-05T18:50:50.833069Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:50.866713Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.868938Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:50.868995Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:50.872975Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:50.887605Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:50.897218Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.899357Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:50.899424Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:50.903299Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28316
2026-11-05T18:50:50.920833Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.923095Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:50.923162Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:50.927006Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28209
2026-11-05T18:50:50.927254Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:50.929403Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:50.929479Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:50.933835Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28208
test every_device_revocation_column_is_compared_with_its_container_on_each_request ... ok
2026-11-05T18:50:51.040816Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:50:51.050670Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:51.052581Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:51.052646Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:51.056602Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28200
2026-11-05T18:50:51.131563Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:51.133859Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:51.133935Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:51.137800Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28210
test the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt ... ok
2026-11-05T18:50:51.180057Z  WARN shardx_team_server::integrity: a quarantined device revocation verifies again and is served; its mark stays tenant="41414141414141414141414141414141" replay="90909090909090909090909090909090"
2026-11-05T18:50:51.181177Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: ["device revocation e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it"], revocations_served_again: 1, foreign_key_violations: 0 }
2026-11-05T18:50:51.181261Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:51.185203Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28315
2026-11-05T18:50:51.232370Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_device_hpke_grant"
2026-11-05T18:50:51.244437Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_recovery_grant"
2026-11-05T18:50:51.265879Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="fleet_rotation_grant"
2026-11-05T18:50:51.277605Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 3, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:51.279801Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:51.279866Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:51.283526Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28311
2026-11-05T18:50:51.366460Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:51.395544Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:51.397516Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:51.397583Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:51.401053Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:51.419411Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:51.421529Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:51.421611Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:51.426454Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28502
2026-11-05T18:50:51.431112Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:51.433272Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:51.433349Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:51.437306Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28316
2026-11-05T18:50:51.635261Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:51.637555Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:51.637632Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:51.641710Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28200
2026-11-05T18:50:51.721830Z  WARN shardx_team_server::integrity: a quarantined device revocation verifies again and is served; its mark stays tenant="41414141414141414141414141414141" replay="90909090909090909090909090909090"
2026-11-05T18:50:51.723042Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: ["device revocation e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8 of tenant 41414141414141414141414141414141 is quarantined and its row is missing; restoring the row and restarting clears it"], revocations_served_again: 1, foreign_key_violations: 0 }
2026-11-05T18:50:51.723119Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: device revocation e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8 of tenant 41414141414141414141414141414141 is quarantined and its row is missing; restoring the row and restarting clears it (1 untrusted device revocation(s) in all); v1 is unaffected
2026-11-05T18:50:51.727419Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28315
test the_startup_pass_quarantines_approvals_that_left_their_containers ... ok
2026-11-05T18:50:51.916790Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:51.928760Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:51.930896Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:51.930965Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:51.935505Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28311
2026-11-05T18:50:51.947061Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:51.949056Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:51.949132Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:51.953949Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
test the_startup_pass_quarantines_device_revocations_that_left_their_containers ... ok
test the_startup_pass_quarantines_fleet_grants_that_left_their_containers ... ok
2026-11-05T18:50:52.463740Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:52.491306Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:52.493512Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:52.493579Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:52.497012Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
test the_trust_evidence_pages_past_a_thousand_containers_and_leaves_nothing_out ... ok
2026-11-05T18:50:52.991767Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_revocation"
2026-11-05T18:50:53.007852Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:53.030129Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:53.035554Z  WARN shardx_team_server::routes::v2_trust: device revocation 90909090909090909090909090909090 of tenant 41414141414141414141414141414141 does not match its signed container; restoring the row and restarting clears it
2026-11-05T18:50:53.037056Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:53.039111Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:53.039176Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:53.040851Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
test the_trust_evidence_reports_a_revoked_device_from_its_record_not_its_column ... ok
2026-11-05T18:50:53.042662Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
test two_bootstraps_under_different_keys_commit_once_and_a_custodian_closes_it ... ok
2026-11-05T18:50:53.061656Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="capability_grant"
2026-11-05T18:50:53.073054Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 3, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:53.075086Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:53.075150Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:53.078651Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28208
test the_trust_evidence_is_the_full_ancestry_of_the_root_subjects ... ok
2026-11-05T18:50:53.558170Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:53.585729Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:53.587783Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:53.587834Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:53.590390Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:53.721585Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:53.723464Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:53.723531Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:53.726421Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28208
2026-11-05T18:50:54.095993Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:54.098191Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:54.098262Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:54.101353Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
test the_startup_pass_quarantines_grants_that_left_their_containers ... ok
2026-11-05T18:50:54.626665Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:54.628391Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:54.628459Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:54.631398Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:55.142422Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:55.161233Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:55.163082Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:55.163128Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:55.165727Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:55.678555Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:55.698449Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:55.698535Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:50:55.703871Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:56.222390Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:56.242061Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:56.242117Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:50:56.245118Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:56.772926Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:56.791467Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:56.791556Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:50:56.796633Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:57.311461Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:57.331740Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:57.331818Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:50:57.335445Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:57.859116Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:57.877570Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:57.879316Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:57.879359Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:57.882137Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:58.399457Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:58.421183Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:50:58.421253Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:50:58.423987Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:58.917813Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:58.937201Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:58.939063Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:58.939134Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:58.943068Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:50:59.489173Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:50:59.507784Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:50:59.509784Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:50:59.509841Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:50:59.512665Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:00.032419Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:00.051579Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:00.053565Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:00.053635Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:00.057918Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:00.581480Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:00.603187Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:00.604935Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:00.604985Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:00.608328Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:01.108102Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:01.130609Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:01.133291Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:01.133371Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:01.138193Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:01.681538Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:01.704274Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 1 }
2026-11-05T18:51:01.704353Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: 1 foreign-key violation(s) in the control plane; v1 is unaffected
2026-11-05T18:51:01.708334Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:02.205176Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:02.229087Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:02.231678Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:02.231768Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:02.237496Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:02.754584Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:02.774634Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:02.776703Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:02.776780Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:02.781233Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:03.279900Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:03.299993Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:03.301912Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:03.301975Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:03.305206Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:03.820857Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:03.844482Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:03.846581Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:03.846681Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:03.850427Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:04.368678Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:04.389407Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:04.391516Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:04.391588Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:04.395098Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:04.912324Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:04.932283Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:04.934259Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:04.934333Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:04.937795Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:05.435313Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:05.455443Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:05.457560Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:05.457636Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:05.461612Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:05.986077Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:06.007157Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:06.009354Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:06.009426Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:06.014225Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:06.516191Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:06.535848Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:06.537997Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:06.538072Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:06.542754Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:07.061685Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:07.082243Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:07.083941Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:07.084004Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:07.087844Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:07.613972Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-05T18:51:07.634683Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:07.636853Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:07.636923Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:07.640739Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-05T18:51:08.157699Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:08.159447Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:08.159570Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T18:51:08.162291Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
test every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... ok

test result: ok. 82 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 66.72s

   Compiling libc v0.2.186
   Compiling try-lock v0.2.5
   Compiling sync_wrapper v1.0.2
   Compiling rustls-pki-types v1.14.1
   Compiling want v0.3.1
   Compiling ipnet v2.12.0
   Compiling hyper v1.10.1
   Compiling tower v0.5.3
   Compiling rustls v0.23.46
   Compiling rustls-webpki v0.103.16
   Compiling unicase v2.9.0
   Compiling mime_guess v2.0.5
   Compiling axum-core v0.4.5
   Compiling hyper-util v0.1.20
   Compiling webpki-roots v1.0.10
   Compiling tower-http v0.6.11
   Compiling axum v0.7.9
   Compiling tokio-rustls v0.26.4
   Compiling hyper-rustls v0.27.9
   Compiling reqwest v0.12.28
   Compiling shardx-team-server v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\server)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 46.46s
     Running tests\v2_auth.rs (server\target\debug\deps\v2_auth-08d8e8e8895d1316.exe)
```
Exit: 0; seconds: 113.27

### identity_authority

`cargo test -j 4 --manifest-path server/Cargo.toml --test identity_authority` (CARGO_NET_OFFLINE=true)

```text

running 23 tests
test a_non_utf8_argument_is_a_usage_error ... ok
test init_requires_an_identity_directory ... ok
test init_refuses_an_identity_directory_inside_the_data_directory ... ok
test a_symlinked_record_is_refused ... ok
test init_writes_the_record_then_the_mirror_and_show_verifies_both ... ok
test tenant_create_refuses_before_identity_init ... ok
2026-11-05T18:51:14.694691Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:51:14.696326Z  WARN shardx_team_server: v2 writes disabled: EPOCH_AUTHORITY_MISSING: SHARDX_IDENTITY_DIR is not set; v1 is unaffected
2026-11-05T18:51:14.700686Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28151
test unknown_commands_print_usage_and_fail ... ok
test tenant_create_refuses_a_weak_password ... ok
2026-11-05T18:51:14.979906Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:51:14.988456Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T18:51:14.990270Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T18:51:14.990331Z  INFO shardx_team_server: server identity verified: instance 86fdc208f3f34ea0b2e346883610ac35 epoch 0
2026-11-05T18:51:14.994039Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28155
test tenant_create_rolls_back_everything_when_the_audit_insert_fails ... ok
test show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest ... ok
test tenant_create_rolls_back_everything_when_the_fleet_audit_insert_fails ... ok
test tenant_create_takes_no_password_from_argv_or_env_and_never_blocks ... ok
2026-11-05T18:51:15.222540Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:51:15.226718Z  WARN shardx_team_server: v2 writes disabled: EPOCH_RECONCILIATION_REQUIRED: the identity record exists but v2_server_state has no mirror row; v1 is unaffected
2026-11-05T18:51:15.231075Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28153
test cancel_closes_the_attempt_for_good ... ok
test confirm_first_device_records_the_operator_match_once ... ok
test a_running_server_holds_the_lock_against_commands_and_a_second_server ... ok
test init_refuses_existing_state_and_writes_nothing ... ok
test a_fingerprint_typo_writes_nothing_and_can_be_retried ... ok
test a_verified_identity_opens_v2_writes ... ok
test an_interrupted_init_is_reported_and_never_repaired ... ok
2026-11-05T18:51:16.087039Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T18:51:16.088613Z  WARN shardx_team_server: v2 writes disabled: EPOCH_AUTHORITY_MISSING: SHARDX_IDENTITY_DIR is not set; v1 is unaffected
2026-11-05T18:51:16.093068Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28154
test tenant_create_writes_tenant_owner_membership_and_offline_audit_together ... ok
test cancel_refuses_what_is_not_an_open_reservation ... ok
test without_an_identity_directory_v2_writes_are_refused_and_v1_works ... ok
test confirm_refuses_a_device_that_is_not_a_clean_pending_first_device ... ok

test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.64s

   Compiling shardx-team-server v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\server)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 4.23s
     Running tests\identity_authority.rs (server\target\debug\deps\identity_authority-a303ede03cce197b.exe)
Error: another instance holds the data directory lock C:\Users\User\AppData\Local\Temp\shardx-idauth-lock-49160\data\shardx.lock (the server is running?); stop it first
```
Exit: 0; seconds: 9.97

### fleet_custody::tests

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib fleet_custody::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process` (CARGO_NET_OFFLINE=true)

```text

running 39 tests
test fleet_custody::tests::a_refused_custody_post_hides_the_access_token_body ... ok
test fleet_custody::tests::a_collected_ack_survives_a_later_release_of_the_setup_key ... ok
test fleet_custody::tests::a_setup_collect_that_keeps_no_key_reports_its_own_error ... ok
test fleet_custody::tests::a_nested_error_code_does_not_replace_a_valid_saved_revocation ... ok
test fleet_custody::tests::a_formatted_window_error_recovers_a_stale_unfiled_revocation ... ok
test fleet_custody::tests::a_crash_between_holding_and_saving_the_fleet_key_reuses_the_held_key ... ok
test fleet_custody::tests::a_new_row_id_for_the_same_keys_keeps_the_first_sight_window ... ok
test fleet_custody::tests::an_echoed_marker_field_is_not_read_as_the_window_code ... ok
test fleet_custody::tests::an_old_server_without_the_listing_route_reports_server_too_old ... ok
test fleet_custody::tests::a_resumed_setup_resends_the_saved_bytes_and_never_makes_a_second_fleet_key ... ok
test fleet_custody::tests::a_custodian_does_not_revoke_itself ... ok
test fleet_custody::tests::a_retry_resends_a_saved_revocation_the_server_may_still_file ... ok
test fleet_custody::tests::a_failed_setup_leaves_no_verified_key ... ok
test fleet_custody::tests::a_device_row_with_a_bad_key_id_is_refused_before_anything_is_saved ... ok
test fleet_custody::tests::a_missing_or_locked_setup_key_after_its_id_is_saved_stops_and_never_regenerates ... ok
test fleet_custody::tests::a_generic_403_does_not_replace_a_saved_revocation ... ok
test fleet_custody::tests::only_retired_and_lost_are_accepted ... ok
test fleet_custody::tests::a_refused_device_listing_hides_the_access_token_body ... ok
test fleet_custody::tests::a_resumed_revocation_resends_the_same_bytes ... ok
test fleet_custody::tests::a_saved_approval_is_resent_after_the_window_closes ... ok
test fleet_custody::tests::a_setup_saved_for_another_tenant_device_or_server_is_refused ... ok
test fleet_custody::tests::a_stale_unfiled_revocation_is_rebuilt ... ok
test fleet_custody::tests::a_successful_device_listing_does_not_echo_its_access_token_to_ipc ... ok
test fleet_custody::tests::an_approval_is_not_signed_once_the_window_closes_during_the_generation_read ... ok
test fleet_custody::tests::approval_is_refused_ten_minutes_after_first_sight ... ok
test fleet_custody::tests::approval_is_refused_when_a_listed_key_does_not_hash_to_its_id ... ok
test fleet_custody::tests::approval_is_refused_when_the_confirmed_code_differs ... ok
test fleet_custody::tests::collect_custody_uses_the_tenant_fleet_when_none_is_configured ... ok
test fleet_custody::tests::collect_skips_the_ack_of_an_acknowledged_grant ... ok
test fleet_custody::tests::keys_first_seen_after_a_swap_start_their_window_then ... ok
test fleet_custody::tests::a_device_label_holding_the_token_body_is_not_echoed_to_ipc ... ok
test fleet_custody::tests::keys_moved_onto_a_row_seen_later_keep_their_first_sight_window ... ok
test fleet_custody::tests::team_commands_need_no_admin_token ... ok
test fleet_custody::tests::the_create_request_commits_to_the_one_device_grant_and_the_recovery_grant ... ok
test fleet_custody::tests::the_custodian_window_starts_when_it_first_sees_the_row_and_never_resets ... ok
test fleet_custody::tests::the_fleet_key_is_held_before_any_request_names_it ... ok
test fleet_custody::tests::the_member_grant_is_sealed_to_the_listed_hpke_key_and_opens_with_it ... ok
test fleet_custody::tests::the_recovery_grant_opens_to_the_fleet_key_and_runs_ten_years ... ok
test fleet_custody::tests::the_saved_state_and_its_debug_output_hold_no_key ... ok

test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 694 filtered out; finished in 1.73s

   Compiling proc-macro2 v1.0.106
   Compiling unicode-ident v1.0.24
   Compiling quote v1.0.45
   Compiling cfg-if v1.0.4
   Compiling itoa v1.0.18
   Compiling serde_core v1.0.228
   Compiling memchr v2.8.0
   Compiling windows-link v0.2.1
   Compiling syn v2.0.117
   Compiling log v0.4.30
   Compiling litemap v0.8.2
   Compiling writeable v0.6.3
   Compiling version_check v0.9.5
   Compiling utf8_iter v1.0.4
   Compiling icu_properties_data v2.2.0
   Compiling bytes v1.11.1
   Compiling icu_normalizer_data v2.2.0
   Compiling siphasher v1.0.3
   Compiling serde v1.0.228
   Compiling phf_shared v0.13.1
   Compiling zmij v1.0.21
   Compiling fastrand v2.4.1
   Compiling stable_deref_trait v1.2.1
   Compiling phf_generator v0.13.1
   Compiling thiserror v2.0.18
   Compiling typenum v1.20.0
   Compiling autocfg v1.5.1
   Compiling http v1.4.1
   Compiling synstructure v0.13.2
   Compiling parking_lot_core v0.9.12
   Compiling find-msvc-tools v0.1.9
   Compiling scopeguard v1.2.0
   Compiling windows_x86_64_msvc v0.48.5
   Compiling shlex v1.3.0
   Compiling cc v1.2.62
   Compiling lock_api v0.4.14
   Compiling smallvec v1.15.1
   Compiling generic-array v0.14.7
   Compiling num-conv v0.2.2
   Compiling serde_derive v1.0.228
   Compiling zerofrom-derive v0.1.7
   Compiling yoke-derive v0.8.2
   Compiling zerovec-derive v0.11.3
   Compiling displaydoc v0.2.5
   Compiling zerofrom v0.1.8
   Compiling thiserror-impl v2.0.18
   Compiling yoke v0.8.2
   Compiling time-core v0.1.8
   Compiling powerfmt v0.2.0
   Compiling windows-targets v0.48.5
   Compiling equivalent v1.0.2
   Compiling deranged v0.5.8
   Compiling zerovec v0.11.6
   Compiling phf_macros v0.13.1
   Compiling semver v1.0.28
   Compiling byteorder v1.5.0
   Compiling hashbrown v0.17.1
   Compiling winnow v1.0.3
   Compiling indexmap v2.14.0
   Compiling thiserror v1.0.69
   Compiling toml_parser v1.1.2+spec-1.1.0
   Compiling tinystr v0.8.3
   Compiling thiserror-impl v1.0.69
   Compiling phf_codegen v0.13.1
   Compiling typeid v1.0.3
   Compiling strsim v0.11.1
   Compiling ident_case v1.0.1
   Compiling toml_writer v1.1.1+spec-1.1.0
   Compiling darling_core v0.23.0
   Compiling icu_locale_core v2.2.0
   Compiling potential_utf v0.1.5
   Compiling zerotrie v0.2.4
   Compiling aho-corasick v1.1.4
   Compiling getrandom v0.2.17
   Compiling windows_x86_64_msvc v0.52.6
   Compiling erased-serde v0.4.10
   Compiling regex-syntax v0.8.10
   Compiling icu_provider v2.2.0
   Compiling icu_collections v2.2.0
   Compiling once_cell v1.21.4
   Compiling new_debug_unreachable v1.0.6
   Compiling unic-char-range v0.9.0
   Compiling regex-automata v0.4.14
   Compiling darling_macro v0.23.0
   Compiling unic-common v0.9.0
   Compiling fnv v1.0.7
   Compiling unic-ucd-version v0.9.0
   Compiling darling v0.23.0
   Compiling unic-char-property v0.9.0
   Compiling phf v0.13.1
   Compiling string_cache_codegen v0.6.1
   Compiling alloc-no-stdlib v2.0.4
   Compiling getrandom v0.4.3
   Compiling anyhow v1.0.104
   Compiling serde_json v1.0.150
   Compiling precomputed-hash v0.1.1
   Compiling utf-8 v0.7.6
   Compiling dunce v1.0.5
   Compiling web_atoms v0.2.4
   Compiling alloc-stdlib v0.2.2
   Compiling parking_lot v0.12.5
   Compiling windows-targets v0.52.6
   Compiling serde_with_macros v3.20.0
   Compiling regex v1.12.3
   Compiling unic-ucd-ident v0.9.0
   Compiling icu_properties v2.2.0
   Compiling icu_normalizer v2.2.0
   Compiling serde_spanned v1.1.1
   Compiling quick-xml v0.42.0
   Compiling base64 v0.23.1
   Compiling idna_adapter v1.2.2
   Compiling string_cache v0.9.0
   Compiling brotli-decompressor v5.0.0
   Compiling windows_x86_64_msvc v0.53.1
   Compiling dtoa v1.0.11
   Compiling percent-encoding v2.3.2
   Compiling rand_core v0.10.1
   Compiling ctor-proc-macro v0.0.7
   Compiling brotli v8.0.2
   Compiling ctor v0.8.0
   Compiling form_urlencoded v1.2.2
   Compiling dtoa-short v0.3.5
   Compiling uuid v1.23.1
   Compiling idna v1.1.0
   Compiling tendril v0.5.0
   Compiling selectors v0.36.1
   Compiling windows-sys v0.48.0
   Compiling cssparser-macros v0.6.1
   Compiling derive_more-impl v2.1.1
   Compiling indexmap v1.9.3
   Compiling toml_datetime v1.1.1+spec-1.1.0
   Compiling pin-project-lite v0.2.17
   Compiling camino v1.2.2
   Compiling libc v0.2.186
   Compiling glob v0.3.3
   Compiling derive_more v2.1.1
   Compiling toml v1.1.2+spec-1.1.0
   Compiling winapi-util v0.1.11
   Compiling cssparser v0.36.0
   Compiling markup5ever v0.38.0
   Compiling url v2.5.8
   Compiling serde_derive_internals v0.29.1
   Compiling servo_arc v0.4.3
   Compiling schemars v0.8.22
   Compiling rustc-hash v2.1.2
   Compiling hashbrown v0.12.3
   Compiling bitflags v2.11.1
   Compiling bit-vec v0.8.0
   Compiling schemars_derive v0.8.22
   Compiling bit-set v0.8.0
   Compiling windows-targets v0.53.5
   Compiling html5ever v0.38.0
   Compiling same-file v1.0.6
   Compiling cfb v0.7.3
   Compiling jsonptr v0.6.3
   Compiling cargo-platform v0.1.9
   Compiling time v0.3.47
   Compiling foldhash v0.2.0
   Compiling dyn-clone v1.0.20
   Compiling dom_query v0.27.0
   Compiling infer v0.19.0
   Compiling serde-untagged v0.1.9
   Compiling json-patch v3.0.1
   Compiling plist v1.10.1
   Compiling cargo_metadata v0.19.2
   Compiling walkdir v2.5.0
   Compiling windows-sys v0.60.2
   Compiling urlpattern v0.3.0
   Compiling serde_with v3.20.0
   Compiling subtle v2.6.1
   Compiling rustc_version v0.4.1
   Compiling windows-sys v0.61.2
   Compiling tauri-utils v2.9.2
   Compiling rand_core v0.6.4
   Compiling option-ext v0.2.0
   Compiling crc32fast v1.5.0
   Compiling mio v1.2.0
   Compiling socket2 v0.6.3
   Compiling windows-sys v0.59.0
   Compiling vswhom-sys v0.1.3
   Compiling tokio-macros v2.7.0
   Compiling cpufeatures v0.2.17
   Compiling simd-adler32 v0.3.9
   Compiling tokio v1.54.1
   Compiling futures-core v0.3.32
   Compiling crypto-common v0.1.7
   Compiling tracing-core v0.1.36
   Compiling tracing-attributes v0.1.31
   Compiling adler2 v2.0.1
   Compiling windows-link v0.1.3
   Compiling miniz_oxide v0.8.9
   Compiling tracing v0.1.44
   Compiling winreg v0.55.0
   Compiling vswhom v0.1.0
   Compiling toml_datetime v0.7.5+spec-1.1.0
   Compiling winnow v0.7.15
   Compiling base64 v0.22.1
   Compiling embed-resource v3.0.9
   Compiling toml v0.9.12+spec-1.1.0
   Compiling dirs-sys v0.5.0
   Compiling heck v0.5.0
   Compiling cargo_toml v0.22.3
   Compiling dirs v6.0.0
   Compiling tauri-winres v0.3.6
   Compiling windows-result v0.3.4
   Compiling windows-strings v0.4.2
   Compiling tauri-plugin v2.6.2
   Compiling time-macros v0.2.27
   Compiling windows-interface v0.59.3
   Compiling windows-implement v0.60.2
   Compiling hybrid-array v0.4.14
   Compiling crossbeam-utils v0.8.21
   Compiling futures-sink v0.3.32
   Compiling windows-core v0.61.2
   Compiling tauri-build v2.6.2
   Compiling zeroize_derive v1.5.0
   Compiling zeroize v1.8.2
   Compiling fdeflate v0.3.7
   Compiling crypto-common v0.2.2
   Compiling tauri v2.11.2
   Compiling windows-threading v0.1.0
   Compiling windows-future v0.2.1
   Compiling windows-numerics v0.2.0
   Compiling windows-collections v0.2.0
   Compiling futures-macro v0.3.32
   Compiling cookie v0.18.1
   Compiling slab v0.4.12
   Compiling futures-task v0.3.32
   Compiling futures-io v0.3.32
   Compiling raw-window-handle v0.6.2
   Compiling futures-util v0.3.32
   Compiling windows v0.61.3
   Compiling dpi v0.1.2
   Compiling webview2-com-sys v0.38.2
   Compiling bitflags v1.3.2
   Compiling block-buffer v0.10.4
   Compiling num-traits v0.2.19
   Compiling unicode-segmentation v1.13.2
   Compiling cmov v0.5.4
   Compiling ctutils v0.4.5
   Compiling digest v0.10.7
   Compiling crossbeam-channel v0.5.15
   Compiling block-buffer v0.12.1
   Compiling flate2 v1.1.9
   Compiling ring v0.17.14
   Compiling webview2-com-macros v0.8.1
   Compiling windows-version v0.1.7
   Compiling zerocopy v0.8.48
   Compiling png v0.17.16
   Compiling tauri-runtime v2.11.2
   Compiling wry v0.55.1
   Compiling httparse v1.10.1
   Compiling sha2 v0.10.9
   Compiling ico v0.5.0
   Compiling keyboard-types v0.7.0
   Compiling http-body v1.0.1
   Compiling tauri-runtime-wry v2.11.2
   Compiling untrusted v0.9.0
   Compiling getrandom v0.3.4
   Compiling mime v0.3.17
   Compiling muda v0.19.2
   Compiling tauri-codegen v2.6.2
   Compiling softbuffer v0.4.8
   Compiling rustls-pki-types v1.14.1
   Compiling futures-channel v0.3.32
   Compiling serialize-to-javascript-impl v0.1.2
   Compiling tower-service v0.3.3
   Compiling zlib-rs v0.6.8
   Compiling cpufeatures v0.3.1
   Compiling serialize-to-javascript v0.1.2
   Compiling tauri-macros v2.6.2
   Compiling tray-icon v0.23.1
   Compiling window-vibrancy v0.6.0
   Compiling digest v0.11.3
   Compiling serde_repr v0.1.20
   Compiling rustls v0.23.46
   Compiling try-lock v0.2.5
   Compiling want v0.3.1
   Compiling rustls-webpki v0.103.16
   Compiling inout v0.2.2
   Compiling sync_wrapper v1.0.2
   Compiling block-padding v0.3.3
   Compiling windows-strings v0.5.1
   Compiling windows-result v0.4.1
   Compiling pkg-config v0.3.33
   Compiling atomic-waker v1.1.2
   Compiling tower-layer v0.3.3
   Compiling vcpkg v0.2.15
   Compiling httpdate v1.0.3
   Compiling hyper v1.9.0
   Compiling windows-registry v0.6.1
   Compiling libsqlite3-sys v0.30.1
   Compiling inout v0.1.4
   Compiling curve25519-dalek v5.0.0
   Compiling ahash v0.8.12
   Compiling ipnet v2.12.0
   Compiling hyper-util v0.1.20
   Compiling cipher v0.4.4
   Compiling tower v0.5.3
   Compiling http-body-util v0.1.3
   Compiling tauri-plugin-fs v2.5.1
   Compiling curve25519-dalek-derive v0.1.1
   Compiling bytemuck v1.25.0
   Compiling allocator-api2 v0.2.21
   Compiling foldhash v0.1.5
   Compiling ryu v1.0.23
   Compiling winapi v0.3.9
   Compiling tao v0.35.3
   Compiling serde_urlencoded v0.7.1
   Compiling hashbrown v0.15.5
   Compiling webview2-com v0.38.2
   Compiling tokio-rustls v0.26.4
   Compiling aead v0.6.1
   Compiling cipher v0.5.2
   Compiling webpki-roots v1.0.10
   Compiling ppv-lite86 v0.2.21
   Compiling universal-hash v0.6.1
   Compiling universal-hash v0.5.1
   Compiling windows-sys v0.52.0
   Compiling parking v2.2.1
   Compiling pxfm v0.1.29
   Compiling winreg v0.10.1
   Compiling crc-catalog v2.5.0
   Compiling opaque-debug v0.3.1
   Compiling rustversion v1.0.22
   Compiling polyval v0.6.2
   Compiling crc v3.4.0
   Compiling moxcms v0.8.1
   Compiling event-listener v5.4.2
   Compiling poly1305 v0.9.1
   Compiling rand_chacha v0.3.1
   Compiling chacha20 v0.10.2
   Compiling hyper-rustls v0.27.9
   Compiling hashbrown v0.14.5
   Compiling hashlink v0.10.0
   Compiling tower-http v0.6.11
   Compiling sha2 v0.11.0
   Compiling hmac v0.13.0
   Compiling png v0.18.1
   Compiling num-integer v0.1.46
   Compiling futures-intrusive v0.5.0
   Compiling crossbeam-queue v0.3.14
   Compiling tauri-plugin-autostart v2.5.1
   Compiling tauri-plugin-opener v2.5.4
   Compiling tauri-plugin-updater v2.11.0
   Compiling tauri-plugin-dialog v2.7.1
   Compiling tauri-plugin-clipboard-manager v2.3.2
   Compiling tokio-stream v0.1.19
   Compiling either v1.18.0
   Compiling spin v0.9.9
   Compiling base64ct v1.8.3
   Compiling rfd v0.16.0
   Compiling byteorder-lite v0.1.0
   Compiling signature v3.0.0
   Compiling litrs v1.0.0
   Compiling error-code v3.3.2
   Compiling psl-types v2.0.11
   Compiling publicsuffix v2.3.0
   Compiling clipboard-win v5.4.3
   Compiling document-features v0.2.12
   Compiling image v0.25.10
   Compiling ed25519 v3.0.0
   Compiling password-hash v0.5.0
   Compiling sqlx-core v0.8.6
   Compiling flume v0.11.1
   Compiling num-bigint v0.4.6
   Compiling hkdf v0.13.0
   Compiling hashlink v0.9.1
   Compiling chacha20poly1305 v0.11.0
   Compiling rand v0.8.8
   Compiling ghash v0.5.1
   Compiling rustls-platform-verifier v0.7.0
   Compiling x25519-dalek v3.0.0
   Compiling ctr v0.9.2
   Compiling aes v0.8.4
   Compiling atoi v2.0.0
   Compiling blake2 v0.10.6
   Compiling sha1 v0.10.6
   Compiling futures-executor v0.3.32
   Compiling tokio-util v0.7.18
   Compiling aead v0.5.2
   Compiling async-trait v0.1.89
   Compiling filetime v0.2.29
   Compiling strict-num v0.1.1
   Compiling fallible-iterator v0.3.0
   Compiling arrayref v0.3.9
   Compiling fallible-streaming-iterator v0.1.9
   Compiling bumpalo v3.20.3
   Compiling ttf-parser v0.25.1
   Compiling data-encoding v2.11.1
   Compiling axum-core v0.4.5
   Compiling tungstenite v0.24.0
   Compiling zopfli v0.8.3
   Compiling owned_ttf_parser v0.25.1
   Compiling rusqlite v0.32.1
   Compiling tiny-skia-path v0.11.4
   Compiling tempfile v3.27.0
   Compiling reqwest v0.13.4
   Compiling tar v0.4.46
   Compiling aes-gcm v0.10.3
   Compiling sqlx-sqlite v0.8.6
   Compiling argon2 v0.5.3
   Compiling hpke v0.14.0
   Compiling auto-launch v0.5.0
   Compiling simple_asn1 v0.6.4
   Compiling arboard v3.6.1
   Compiling ed25519-dalek v3.0.0
   Compiling cookie_store v0.22.1
   Compiling aead-stream v0.6.0
   Compiling hmac v0.12.1
   Compiling dirs-sys v0.4.1
   Compiling shardx-launcher v2.6.1 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\src-tauri)
   Compiling pem v3.0.6
   Compiling zip v4.6.1
   Compiling open v5.3.5
   Compiling serde_path_to_error v0.1.20
   Compiling keyring-core v1.0.0
   Compiling matchit v0.7.3
   Compiling ab_glyph_rasterizer v0.1.10
   Compiling typed-path v0.12.4
   Compiling minisign-verify v0.2.5
   Compiling arrayvec v0.7.8
   Compiling tiny-skia v0.11.4
   Compiling zip v9.0.5
   Compiling ab_glyph v0.2.32
   Compiling axum v0.7.9
   Compiling windows-native-keyring-store v1.1.0
   Compiling jsonwebtoken v9.3.1
   Compiling dirs v5.0.1
   Compiling pbkdf2 v0.12.2
   Compiling shardx-core v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\shared)
   Compiling reqwest v0.12.28
   Compiling sqlx v0.8.6
   Compiling tokio-tungstenite v0.24.0
   Compiling tauri-plugin-single-instance v2.4.2
   Compiling cbc v0.1.2
    Finished `test` profile [unoptimized + debuginfo] target(s) in 3m 26s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 208.39

### fleet_client::tests

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib fleet_client::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process` (CARGO_NET_OFFLINE=true)

```text

running 19 tests
test fleet_client::tests::a_session_binding_must_name_every_expected_field ... ok
test fleet_client::tests::a_refusal_keeps_its_words_but_no_credential ... ok
test fleet_client::tests::a_session_debug_print_hides_its_tokens ... ok
test fleet_client::tests::a_password_goes_only_over_https_or_to_this_machine ... ok
test fleet_client::tests::hex_from_the_server_never_panics_or_takes_signs ... ok
test fleet_client::tests::ids_must_be_16_bytes_of_hex ... ok
test fleet_client::tests::replay_ids_are_unique ... ok
test fleet_client::tests::the_client_token_zeroizes_on_drop ... ok
test fleet_client::tests::a_base_url_must_carry_a_scheme ... ok
test fleet_client::tests::a_trailing_slash_does_not_double_up_in_paths ... ok
test fleet_client::tests::a_login_error_hides_the_echoed_password ... ok
test fleet_client::tests::a_login_error_hides_a_password_echoed_with_json_escapes ... ok
test fleet_client::tests::a_login_error_hides_a_password_echoed_with_an_escaped_slash ... ok
test fleet_client::tests::a_server_identity_that_is_not_an_id_is_refused ... ok
test fleet_client::tests::an_error_reply_hides_echoed_session_tokens ... ok
test fleet_client::tests::a_refusal_hides_the_v1_token_echoed_bare ... ok
test fleet_client::tests::a_login_error_hides_a_non_ascii_password_echoed_as_ascii_escapes ... ok
test fleet_client::tests::a_login_error_keeps_only_an_error_code_the_server_names ... ok
test fleet_client::tests::an_enrollment_reply_must_name_an_id_and_the_ticket_account ... ok

test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 714 filtered out; finished in 0.04s

   Compiling shardx-launcher v2.6.1 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\src-tauri)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 25.89s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 26.06

### custody_tests

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custody_tests -- --skip a_real_os_store_key_survives_into_a_fresh_process` (CARGO_NET_OFFLINE=true)

```text

running 46 tests
test custody_tests::a_fleet_descriptor_counts_only_for_this_device_and_generation ... ok
test custody_tests::a_collected_fleet_key_is_never_replaced ... ok
test custody_tests::a_join_confirm_is_refused_for_another_tenant_than_the_one_shown ... ok
test custody_tests::a_join_confirm_is_refused_when_the_server_instance_changed ... ok
test custody_tests::a_backdated_self_renewal_after_a_count_is_refused ... ok
test custody_tests::a_join_pin_is_refused_for_another_anchor_than_the_one_shown ... ok
test custody_tests::a_key_is_used_only_while_its_kept_record_reloads_exactly ... ok
test custody_tests::a_head_by_a_committer_a_sticky_revoked_key_appointed_is_refused ... ok
test custody_tests::a_joined_device_reads_its_anchor_from_the_join_pin ... ok
test custody_tests::a_pinned_pending_device_can_enroll_again ... ok
test custody_tests::a_late_join_confirm_is_refused_even_after_approval ... ok
test custody_tests::a_server_delivered_fleet_key_is_counted_but_never_cached ... ok
test custody_tests::an_approved_device_whose_join_code_expired_can_enroll_again ... ok
test custody_tests::a_lapse_is_the_known_end_of_custody_clipped_at_the_key_age ... ok
test custody_tests::a_kept_grant_is_reverified_before_its_key_is_used ... ok
test custody_tests::a_fleet_generation_never_goes_back ... ok
test custody_tests::a_lapsed_custodians_backdated_grant_is_refused_with_history ... ok
test custody_tests::a_renewal_issued_before_the_count_is_sticky_and_alerts_once ... ok
test custody_tests::a_server_cannot_lapse_a_custodian_or_age_its_key_for_good ... ok
test custody_tests::limit_a_backdated_grant_from_a_never_counted_custodian_is_accepted ... ok
test custody_tests::an_expired_code_whose_status_is_unanswered_is_not_plain_expired ... ok
test custody_tests::enroll_again_clears_a_pending_identity ... ok
test custody_tests::limit_a_new_device_counts_a_backdated_revocation_with_its_revoker ... ok
test custody_tests::only_the_bootstrapped_device_has_a_pinned_anchor ... ok
test custody_tests::limit_mutual_revocation_counts_both_on_a_new_device ... ok
test custody_tests::a_counted_revocation_outlives_the_server_omitting_it ... ok
test custody_tests::a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count ... ok
test custody_tests::an_omitted_first_root_grant_never_stretches_the_key_age_with_history ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_forged_container ... ok
test custody_tests::reverifying_a_kept_key_records_the_lapse_history_shows ... ok
test custody_tests::records_first_seen_before_a_count_keep_their_standing ... ok
test custody_tests::renewed_after_revocation_is_bounded_per_key ... ok
test custody_tests::local_distrust_ignores_what_is_first_seen_after_it ... ok
test custody_tests::the_pinned_anchor_never_changes ... ok
test custody_tests::a_lapse_from_history_refuses_a_backdated_grant_with_no_evaluation_between ... ok
test custody_tests::renewed_after_revocation_is_not_raised_for_a_distrusted_key ... ok
test custody_tests::a_verified_fleet_grant_opens_and_nothing_else_does ... ok
test custody_tests::revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key ... ok
test custody_tests::a_reported_revocation_outlives_the_server_omitting_it ... ok
test custody_tests::pull_uses_a_verified_key_only_while_its_issuer_stands ... ok
test custody_tests::the_join_code_expires_ten_minutes_after_this_device_enrolled ... ok
test custody_tests::a_revocation_counts_only_from_a_custodian_allowed_to_revoke ... ok
test custody_tests::enroll_again_is_refused_for_an_active_pinned_or_custodian_device ... ok
test custody_tests::an_expired_code_says_whether_enroll_again_is_allowed ... ok

test result: ok. 46 passed; 0 failed; 0 ignored; 0 measured; 687 filtered out; finished in 9.32s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.39s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 10.83

### team::ledger::tests

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::ledger::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process` (CARGO_NET_OFFLINE=true)

```text

running 7 tests
test team::ledger::tests::holdings_name_every_issuer_and_subject_of_a_key_carrying_grant ... ok
test team::ledger::tests::a_join_pin_never_replaces_an_earlier_pin ... ok
test team::ledger::tests::a_version_6_file_with_unreadable_kept_pages_still_opens ... ok
test team::ledger::tests::a_version_6_file_files_the_holdings_of_its_kept_evidence ... ok
test team::ledger::tests::a_second_origin_of_the_instance_files_a_new_generation ... ok
test team::ledger::tests::a_lapsed_key_counts_only_after_its_observed_lapse ... ok
test team::ledger::tests::a_filed_grant_files_the_key_state_it_names ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 726 filtered out; finished in 0.64s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.69s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 1.42

### UI dependencies (.)

`npm.cmd ci --offline --no-audit --no-fund --ignore-scripts`

```text

added 267 packages in 38s
npm warn deprecated eslint@9.39.5: This version is no longer supported. Please see https://eslint.org/version-support for other options.
```
Exit: 0

### UI dependencies (ui-kit)

`npm.cmd ci --offline --no-audit --no-fund --ignore-scripts`

```text

added 251 packages in 44s
npm warn deprecated eslint@9.39.5: This version is no longer supported. Please see https://eslint.org/version-support for other options.
```
Exit: 0

### join_sas

`cargo test -j 4 --manifest-path shared/Cargo.toml --lib join_sas`

```text

running 3 tests
test trust_chain::tests::join_sas_displays_eight_groups_of_four ... ok
test trust_chain::tests::join_sas_matches_an_independent_sha256 ... ok
test trust_chain::tests::join_sas_changes_with_every_input ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 303 filtered out; finished in 0.00s

   Compiling cfg-if v1.0.4
   Compiling typenum v1.20.1
   Compiling version_check v0.9.5
   Compiling getrandom v0.4.3
   Compiling rand_core v0.10.1
   Compiling getrandom v0.2.17
   Compiling generic-array v0.14.7
   Compiling rand_core v0.6.4
   Compiling proc-macro2 v1.0.106
   Compiling unicode-ident v1.0.24
   Compiling subtle v2.6.1
   Compiling hybrid-array v0.4.14
   Compiling quote v1.0.46
   Compiling cmov v0.5.4
   Compiling crypto-common v0.2.2
   Compiling crypto-common v0.1.7
   Compiling ctutils v0.4.5
   Compiling block-buffer v0.12.1
   Compiling cpufeatures v0.3.1
   Compiling semver v1.0.28
   Compiling syn v2.0.118
   Compiling rustc_version v0.4.1
   Compiling inout v0.2.2
   Compiling zerocopy v0.8.52
   Compiling digest v0.11.3
   Compiling cpufeatures v0.2.17
   Compiling curve25519-dalek v5.0.0
   Compiling ahash v0.8.12
   Compiling shlex v2.0.1
   Compiling find-msvc-tools v0.1.9
   Compiling block-buffer v0.10.4
   Compiling inout v0.1.4
   Compiling cc v1.2.65
   Compiling once_cell v1.21.4
   Compiling serde_core v1.0.228
   Compiling windows_x86_64_msvc v0.52.6
   Compiling vcpkg v0.2.15
   Compiling pkg-config v0.3.33
   Compiling libsqlite3-sys v0.30.1
   Compiling cipher v0.4.4
   Compiling digest v0.10.7
   Compiling aead v0.6.1
   Compiling cipher v0.5.2
   Compiling universal-hash v0.6.1
   Compiling universal-hash v0.5.1
   Compiling zmij v1.0.21
   Compiling opaque-debug v0.3.1
   Compiling crc32fast v1.5.0
   Compiling hashbrown v0.14.5
   Compiling polyval v0.6.2
   Compiling poly1305 v0.9.1
   Compiling chacha20 v0.10.2
   Compiling sha2 v0.11.0
   Compiling hmac v0.13.0
   Compiling simd-adler32 v0.3.9
   Compiling anyhow v1.0.103
   Compiling serde_json v1.0.150
   Compiling signature v3.0.0
   Compiling serde v1.0.228
   Compiling base64ct v1.8.3
   Compiling adler2 v2.0.1
   Compiling miniz_oxide v0.8.9
   Compiling password-hash v0.5.0
   Compiling ed25519 v3.0.0
   Compiling hkdf v0.13.0
   Compiling windows-targets v0.52.6
   Compiling chacha20poly1305 v0.11.0
   Compiling ghash v0.5.1
   Compiling hashlink v0.9.1
   Compiling blake2 v0.10.6
   Compiling aes v0.8.4
   Compiling ctr v0.9.2
   Compiling aead v0.5.2
   Compiling filetime v0.2.29
   Compiling fallible-streaming-iterator v0.1.9
   Compiling bitflags v2.13.0
   Compiling itoa v1.0.18
   Compiling memchr v2.8.2
   Compiling fallible-iterator v0.3.0
   Compiling smallvec v1.15.2
   Compiling tar v0.4.46
   Compiling rusqlite v0.32.1
   Compiling aes-gcm v0.10.3
   Compiling flate2 v1.1.9
   Compiling windows-sys v0.59.0
   Compiling aead-stream v0.6.0
   Compiling sha2 v0.10.9
   Compiling base64 v0.22.1
   Compiling zeroize_derive v1.5.0
   Compiling curve25519-dalek-derive v0.1.1
   Compiling serde_derive v1.0.228
   Compiling zeroize v1.8.2
   Compiling argon2 v0.5.3
   Compiling x25519-dalek v3.0.0
   Compiling ed25519-dalek v3.0.0
   Compiling hpke v0.14.0
   Compiling shardx-core v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\shared)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 58.43s
     Running unittests src\lib.rs (shared\target\debug\deps\shardx_core-031bef48b974c131.exe)
```
Exit: 0

### ui-kit

`npm.cmd run build:lib --prefix ui-kit`

```text
vite v6.4.5 building for production...
transforming...
✓ 63 modules transformed.
rendering chunks...

[unplugin:dts] Start generate declaration files...
computing gzip size...
dist/lib/link-context.js                       0.17 kB │ gzip: 0.14 kB
dist/lib/cn.js                                 0.23 kB │ gzip: 0.16 kB
dist/icons/svg/flashlight-fill.svg.js          0.31 kB │ gzip: 0.25 kB
dist/icons/svg/arrow-left-s-line.svg.js        0.39 kB │ gzip: 0.28 kB
dist/icons/svg/check-line.svg.js               0.39 kB │ gzip: 0.29 kB
dist/icons/svg/arrow-right-s-line.svg.js       0.40 kB │ gzip: 0.29 kB
dist/icons/svg/download-line.svg.js            0.41 kB │ gzip: 0.30 kB
dist/icons/svg/upload-line.svg.js              0.41 kB │ gzip: 0.30 kB
dist/icons/svg/information-fill.svg.js         0.43 kB │ gzip: 0.29 kB
dist/icons/svg/error-warning-fill.svg.js       0.43 kB │ gzip: 0.29 kB
dist/icons/svg/notification-3-line.svg.js      0.45 kB │ gzip: 0.32 kB
dist/theme/theme-context.js                    0.46 kB │ gzip: 0.31 kB
dist/icons/svg/arrow-left-double-line.svg.js   0.48 kB │ gzip: 0.32 kB
dist/icons/svg/arrow-right-double-line.svg.js  0.48 kB │ gzip: 0.32 kB
dist/icons/svg/delete-bin-line.svg.js          0.49 kB │ gzip: 0.34 kB
dist/lib/link.js                               0.49 kB │ gzip: 0.26 kB
dist/icons/svg/close-line.svg.js               0.49 kB │ gzip: 0.32 kB
dist/icons/svg/mail-line.svg.js                0.50 kB │ gzip: 0.34 kB
dist/icons/svg/checkbox-circle-fill.svg.js     0.50 kB │ gzip: 0.33 kB
dist/icons/svg/fire-fill.svg.js                0.52 kB │ gzip: 0.36 kB
dist/icons/svg/time-line.svg.js                0.53 kB │ gzip: 0.33 kB
dist/icons/svg/edit-line.svg.js                0.55 kB │ gzip: 0.38 kB
dist/icons/svg/lock-line.svg.js                0.57 kB │ gzip: 0.38 kB
dist/icons/svg/home-5-line.svg.js              0.57 kB │ gzip: 0.38 kB
dist/icons/svg/star-line.svg.js                0.63 kB │ gzip: 0.40 kB
dist/icons/svg/user-3-line.svg.js              0.64 kB │ gzip: 0.40 kB
dist/icons/svg/search-line.svg.js              0.67 kB │ gzip: 0.40 kB
dist/icons/svg/alert-fill.svg.js               0.72 kB │ gzip: 0.44 kB
dist/icons/svg/thumb-up-fill.svg.js            0.75 kB │ gzip: 0.48 kB
dist/icons/svg/shield-check-line.svg.js        0.77 kB │ gzip: 0.47 kB
dist/icons/svg/heart-line.svg.js               0.77 kB │ gzip: 0.48 kB
dist/icons/svg/eye-line.svg.js                 0.95 kB │ gzip: 0.48 kB
dist/icons/svg/global-line.svg.js              1.05 kB │ gzip: 0.55 kB
dist/icons/svg/links-line.svg.js               1.07 kB │ gzip: 0.54 kB
dist/lib/icons.js                              1.11 kB │ gzip: 0.51 kB
dist/components/Tooltip/index.js               1.13 kB │ gzip: 0.55 kB
dist/icons/svg/rocket-fill.svg.js              1.18 kB │ gzip: 0.60 kB
dist/theme/ThemeProvider.js                    1.20 kB │ gzip: 0.61 kB
dist/components/ProgressBar/index.js           1.24 kB │ gzip: 0.61 kB
dist/icons/svg/magic-fill.svg.js               1.25 kB │ gzip: 0.69 kB
dist/theme/ThemeToggle.js                      1.26 kB │ gzip: 0.63 kB
dist/components/Tag/index.js                   1.28 kB │ gzip: 0.58 kB
dist/components/SegmentControl/index.js        1.33 kB │ gzip: 0.62 kB
dist/components/Slider/index.js                1.44 kB │ gzip: 0.69 kB
dist/components/Breadcrumb/index.js            1.44 kB │ gzip: 0.61 kB
dist/components/Radio/index.js                 1.51 kB │ gzip: 0.68 kB
dist/components/Switch/index.js                1.63 kB │ gzip: 0.73 kB
dist/components/Badge/index.js                 1.78 kB │ gzip: 0.66 kB
dist/components/Tabs/index.js                  1.85 kB │ gzip: 0.65 kB
dist/components/Textarea/index.js              2.04 kB │ gzip: 0.87 kB
dist/components/Checkbox/index.js              2.06 kB │ gzip: 0.82 kB
dist/index.js                                  2.11 kB │ gzip: 0.55 kB
dist/components/Input/index.js                 2.54 kB │ gzip: 0.95 kB
dist/icons/svg/settings-3-line.svg.js          2.62 kB │ gzip: 1.19 kB
dist/icons/index.js                            2.71 kB │ gzip: 0.63 kB
dist/components/Button/index.js                3.09 kB │ gzip: 1.08 kB
dist/components/Alert/index.js                 3.27 kB │ gzip: 1.05 kB
dist/components/Modal/index.js                 3.40 kB │ gzip: 1.30 kB
dist/components/DialogModal/index.js           4.43 kB │ gzip: 1.53 kB
dist/components/Pagination/index.js            4.80 kB │ gzip: 1.76 kB
dist/components/AlertModal/index.js            4.81 kB │ gzip: 1.72 kB
dist/components/Select/index.js                7.94 kB │ gzip: 2.60 kB
[unplugin:dts] Declaration files built in 4077ms.

✓ built in 5.57s

> @proxyshard/shardx-ui-kit@0.1.15 build:css
> tailwindcss -i ./src/styles/lib.css -o ./dist/styles.css --minify


> @proxyshard/shardx-ui-kit@0.1.15 build:tokens
> node scripts/copy-tokens.mjs

Copied dist/tokens.css

> @proxyshard/shardx-ui-kit@0.1.15 build:icon-types
> node scripts/gen-icon-types.mjs

Generated dist/icons/index.d.ts (33 icons)
npm notice run @proxyshard/shardx-ui-kit@0.1.15 build:lib
npm notice run vite build --config vite.lib.config.ts && npm run build:css && npm run build:tokens && npm run build:icon-types
npm warn Unknown env config "global-ignore-file". This will stop working in the next major version of npm. See `npm help npmrc` for supported config options.
≈ tailwindcss v4.3.3

Done in 161ms
npm warn Unknown env config "global-ignore-file". This will stop working in the next major version of npm. See `npm help npmrc` for supported config options.
npm warn Unknown env config "global-ignore-file". This will stop working in the next major version of npm. See `npm help npmrc` for supported config options.
```
Exit: 0

### New round-5 regression probes

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib round5_ -- --skip a_real_os_store_key_survives_into_a_fresh_process`

```text
   Compiling shardx-launcher v2.6.1 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\src-tauri)
error: linking with `link.exe` failed: exit code: 1104
  |
  = note: "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\HostX64\\x64\\link.exe" "/NOLOGO" "C:\\Users\\User\\dev\\wt\\shardbrowser-custodian-verify\\src-tauri\\target\\debug\\deps\\rustcx9L5U8\\symbols.o" "<257 object files omitted>" "C:\\Users\\User\\dev\\wt\\shardbrowser-custodian-verify\\src-tauri\\target\\debug\\deps/{libtauri_plugin_dialog-b409cde6d834f9dd,librfd-5044277509b24626,libtauri_plugin_fs-0d5d654c92daa2e2,libtauri_plugin_opener-37debc120450dc4e,libopen-492cffe1a7383e72,libtauri_plugin_single_instance-cd5456bd575d294f,libdirs-55ec2a53ed58adfb,libdirs_sys-65ddba7d92a4eca3,libzip-868a4053d834eef1,libzopfli-4398e1ad3a8107e2,libbumpalo-235f4e5e32b38657,libtyped_path-4cb670beeacd81a7,libreqwest-f30144cff9d3e369,libcookie_store-09d84172fa836806,libpublicsuffix-20b232c088f26101,libpsl_types-60c419816f06bc3c,libwindows_native_keyring_store-faf8acb604178f62,libtauri_plugin_clipboard_manager-e30c602226d574db,libarboard-da43d101e40f2a09,libclipboard_win-eb56ff36d81d6702,liberror_code-ac97e14690455c3c,libimage-206d0ac8b43712a7,libmoxcms-18b5c09e5800ed14,libpxfm-c7a78f83afd826a5,libpng-eee4fa8158c4da2c,libbyteorder_lite-668598759dd25141}.rlib" "<sysroot>\\lib\\rustlib\\x86_64-pc-windows-msvc\\lib/{libtest-*,libgetopts-*,librustc_std_workspace_std-*}.rlib" "C:\\Users\\User\\dev\\wt\\shardbrowser-custodian-verify\\src-tauri\\target\\debug\\deps/{libtauri_plugin_updater-6c72714c05cc2578,libtempfile-b79fbdd01ca527e1,libfastrand-edc80b32fd6cd3ce,libzip-fcd8303eff74a233,libreqwest-a355aa75f53d22f1,librustls_platform_verifier-1161715d211ab769,libwindows_sys-e513d083c3fff5f7,libhyper_rustls-14b2264181fdfc00,libwebpki_roots-1860061996849cfc,libtower_http-22a4681e0fb6d7ad,libtokio_util-63985470c9f113e2,libminisign_verify-c6c5eab445a953a3,libtauri_plugin_autostart-e7ab9e9d6ddd5928,libauto_launch-98f8556add10b4e4,libwinreg-0c2308d2640d79e3,libwinapi-0caccb2c15c738ee,libtokio_rustls-f8fb0dfc189d4f16,librustls-f2a51b1a1f6980c2,libwebpki-a5bf4ab57c9256f7,librustls_pki_types-df85f4ce3d1da163,libtauri-6192edc3a023b67b,libdirs-49d146873808ff01,libdirs_sys-025e356cbcd7ee12,liboption_ext-6efe4a71938d9c81,libwindow_vibrancy-cbd34ff338ac3e5f,libgetrandom-6b94a27ab4a34a6c,libtauri_runtime_wry-54fc131f44ca3a6b,libsoftbuffer-a5db8ed357f0e0db,libwry-033597c64947f8c7,libtao-64d4e362bd35decd,libwindows_version-14a33b863c3ffb7c,libtray_icon-38ae87211048f339,libmuda-e30a04c442bfa80d,libkeyboard_types-bb3c4f65f45c4685,libunicode_segmentation-9b6ae3c1b70567d2,libcrossbeam_channel-035110bba0409522,libtauri_runtime-6c80ee8064264bcc,libwebview2_com-ed8ba5c4c4efa8fc,libwebview2_com_sys-2f8f256cd91446d7,libcookie-d5d76fc8c2a200ad,libwindows-ff30f75d52c1b6d1,libwindows_core-1984147a5e44a496,libwindows_strings-7718b728d650c9fa,libwindows_result-5b85a8d40987efc6,libwindows_link-e5b04dcd37c25a97,libdpi-089575d0bc65f8bb,libserialize_to_javascript-17540c8d6ee3cd5b,libraw_window_handle-b815fa44cbb750fe,libtauri_utils-654278cd84fdc611,libdunce-bd2f8adff865192a,libinfer-2438178a705bfe23,libcfb-7adbe3d399b288fe,libfnv-5ffe144f4827c15c,libuuid-347a4531db8de9b6,libbrotli-67b6a02ba02016a9,libbrotli_decompressor-e283e304f6d6a02b,liballoc_stdlib-3af06f552d62559f,liballoc_no_stdlib-8e87bbab91726580,liburlpattern-f6c2249b99c112df,libunic_ucd_ident-e6bc5d23de5c2fb4,libunic_ucd_version-9bfcd0603f2e2a49,libunic_common-79d825f9974cca45,libunic_char_property-31d06c2174b041b3,libunic_char_range-e7fd67f79c9f853c,libregex-a285e2abdb6106af,libregex_automata-8daff385028fc809,libaho_corasick-f61c87d984667330,libregex_syntax-bf421f4c57c8f954,libglob-eae9a1640ecc076f,libwalkdir-6f22aea3b43b8106,libsame_file-330aee69c40f916e,libwinapi_util-6b824bed3c77719b,libwindows_sys-8295704dfe29118a,libwindows_targets-f8d087f6f0da6415,libctor-a72e0f96028b9bac,libplist-6e83fabd9fc99015,libquick_xml-d5f6ecee63bb3796,libbase64-0c1493c90532fa22,libjson_patch-5d641531da531c15,libjsonptr-5db4f67971b4285c,libserde_with-019619fdc2e3bead,libphf-fb85705cbf750abb,libphf_shared-f8184cedcd740d46,libsiphasher-48e8f3d427bde0da,libtoml-0a04e8c1b4de60e5,libtoml_writer-a61802e59935c0cd,libtoml_parser-d946a493772acdd6,libwinnow-bbaf60d430908eba,libserde_spanned-c7b7ac00eec3c74e,libtoml_datetime-8ed25f603a8bb506,libserde_untagged-4c2d4b6a27ad2e75,liberased_serde-4b8895654ca7ac51,libtypeid-9203d51001c21637,libsemver-902513039023c508,libtiny_skia-b47379699b48966d,libpng-02ecbaadaf27e681,libbitflags-a2f51ef1ff1028f4,libfdeflate-4d68c352d97bbb96,libsimd_adler32-50418afa752b302d,libcrc32fast-e5b08453da6507f2,libarrayvec-38954f1eb5b9cfb8,libtiny_skia_path-33b02465eec9bf36,libbytemuck-8075afd9098559be,libstrict_num-3eb09e945b23b5b9,libarrayref-bb51627d13e9c974,libab_glyph-283469804926bc7f,libowned_ttf_parser-2e6545af570beea4,libttf_parser-5f087378613b3c63,libab_glyph_rasterizer-97c4b85fadf8513c,libshardx_core-95bb073bb4e9e8da,libtar-5cbc6894be7039a7,libfiletime-36acafda0c636f63,libflate2-8635ff48cb0d5c9b,libzlib_rs-7cb3d4f57d9ed5ca,libargon2-74c3ed20c77fa330,libblake2-3907dce3936925bf,libpassword_hash-72f6daaf304cde2e,libbase64ct-08f6f89ec19da6a1,libhpke-7375ceddd5996e7a,libx25519_dalek-a74c5387c1009ac1,libhkdf-e39ffca0760cb905,libhmac-27cabb746a9df0e7,libaead_stream-249ac1a8b4f5f873,libed25519_dalek-355bf2ae2f939280,libsha2-cff8833cd250c55b,libcurve25519_dalek-66c3f9dc9a563529,libdigest-6c5da24b9505148e,libed25519-8485c4d223d3d76a,libsignature-d194e68c225ff676,libchacha20poly1305-3ab5ab02c13f8565,libchacha20-8f7c138f189cee33,libpoly1305-984794b73a3a3d3e,libcpufeatures-abcbe0425e668a87,libuniversal_hash-c1247e67df298a41,libctutils-a1b07e829fd999d3,libcmov-514d55c52c492964,libaead-57699b34c86ee4ef,libcipher-10f71d6e11e06840,libblock_buffer-d6488c453ac2bd55,libinout-fbc0585029896627,libcrypto_common-6556462e693f3504,libgetrandom-b3ff7b3030d1b86f,librand_core-a09dc3fa5b9ff5af,libhybrid_array-4677cfa4272474b2,libsqlx-39914a1c99597f41,libsqlx_sqlite-abb63013a3727d3a,libfutures_executor-bdb4c87525b0cc33,libflume-87fa79dcaac3103d,libspin-2c96c2082af518a4,libfutures_intrusive-200b2ae8e801e33b,libparking_lot-18a4964bca1f8b07,libparking_lot_core-95aa679889513b05,liblock_api-c64f64ca353cf89f,libscopeguard-824898350ab2192f,libatoi-9b00c0001ca4e883,libsqlx_core-b70dda90ea802634,libindexmap-57630d4b2153f344,libhashbrown-f6ad043362481a48,libhashlink-bdde3588c4934ed1,libhashbrown-bc840b8914345b41,libfoldhash-79d93053c11dc736,libequivalent-13e743952c9c69e3,liballocator_api2-a43765d7357178a5,liburl-648877aadf09d765,libidna-1598611ef123c681,libidna_adapter-e9f9f81477b6b980,libicu_properties-7a5ecd577022caf2,libicu_properties_data-5bb15187ae0dfdc4,libicu_normalizer-a33ae8ad662b8dbc,libicu_normalizer_data-4abf5980b64ae970,libicu_collections-3278ecf1ec54ac63,libutf8_iter-1d8f2455ff528ed3,libpotential_utf-591a3667b1c128bc,libicu_provider-559fb2ec21260e7a,libicu_locale_core-8cc55879c5c385e4,libtinystr-736a3159c2095b4f,liblitemap-9bbeac7f6b7fa00f,libwriteable-b72a7a92105b358a,libzerovec-c6bb8f3370713bb3,libzerotrie-9d8677a30eefed27,libyoke-35881b9202d2e223,libstable_deref_trait-2e8d25a7d54e180e,libzerofrom-fa587b357931e57d,libcrossbeam_queue-4113568958e01b95,libcrossbeam_utils-1587ffcefbddca0f,libeither-cd88599066762df0,libevent_listener-32a34bf975af6efb,libparking-97adaa46d71ed825,libkeyring_core-efa30386e8406cc9,libzeroize-7f43728470e2bc26,librusqlite-c4a19b8ce7e79d3d,libbitflags-127390d7f4bec175,libfallible_streaming_iterator-66f0aef80a9fde2a,libfallible_iterator-9a944c3f9c017601,libhashlink-08e693db5f55fd50,libhashbrown-af7c0fe0fd28a2d4,libahash-be50730102ae3e7f,liblibsqlite3_sys-e4b000f53c536704,libaes_gcm-a6fa6caf45eac3bc,libctr-09b8847df8897e4d,libghash-f534827eb8a777c8,libpolyval-2e77732075f6e95c,libopaque_debug-a568b1fa0c12c9df,libuniversal_hash-72ecf5207b8bbafc,libaes-340494699cfbdb42,libcipher-230081c16a599208,libinout-448cc7f4b6af9794,libblock_padding-5c40e1bf0171fce0,libaead-b1fe79cff916c568,libsha2-b27cbbeb9b411cc5,libtokio_tungstenite-3493a9a8ef447d2b,libtungstenite-e2c393efa46988f5,libdata_encoding-9a1753ac6a70e25f,librand-d4aafad9e2b85f42,librand_chacha-104656eeaefdbcc5,libppv_lite86-1657b95de241afb9,libzerocopy-a6714c895301ef25,libutf8-4dafd8daed2c08af,libbyteorder-a32ef8632ca02f0e,libsha1-c7c4f31616f0cc00,libcpufeatures-8304637f10d937ba,libdigest-4633b0f395a1ceda,libsubtle-d4ac8f551bc37eff,libblock_buffer-da26d2280760e6c4,libcrypto_common-c17ddef0073a8c20,libgeneric_array-64e8a312563ebef1,libtypenum-662950c4717cdde7,librand_core-aaee90d048d32a9a,libthiserror-1972562abf92cc06,libanyhow-a36644b1b7cda343,libwindows_sys-8471ba2932ff84b1,libwindows_targets-2151d9fb0231a789,libjsonwebtoken-5b47bda973524dfc,libpem-e7f53f937ffff921,libsimple_asn1-03a74e75a55c8233,libtime-3a9085eb728bd597,libtime_core-5a379067263d80f9,libnum_conv-db8708ab2cdf9267,libderanged-d7c36f1e42ede483,libpowerfmt-429429ddb72abb5c,libthiserror-c2a5b15c6da478dc,libnum_bigint-3128a5df4ffda597,libnum_integer-933663a6a054961e,libnum_traits-3df59e162fd25459,libring-02560ba2e5fc9fff,libgetrandom-b68af3ad56f6d3f0,libuntrusted-886734c3df991993,libcfg_if-cc8c3f0437e30c5c,libaxum-089c5c22bbf72ca0,libserde_path_to_error-910ca48b7dc2db34,libserde_json-a93cf5d39495e64f,libzmij-fea72773d8e17f3d,libserde_urlencoded-6f30c3a373977b1d,libryu-36d31055e8dd496f,libform_urlencoded-49613a97fc194bab,libhyper_util-82575474aebfe0d8,libwindows_registry-88d2918dc86b7681,libwindows_strings-44dcea245ce88843,libwindows_result-16d9619a9e11d7aa,libbase64-1f9f5300156d97b2,libpercent_encoding-e350f14ec4226700,libipnet-27af37b21e03ecf5,libhyper-242af61f86f0dd58,libwant-12f8ae77da0ee599,libtry_lock-ca06111c31705f02,libsmallvec-64f9b3eb3a9cfb4a,libhttparse-3934b1481c689a1d,libatomic_waker-7b3560d00d4ed6f2,libhttpdate-3aeb53db40540981,libfutures_channel-41f6dee2c2ac2256,libmatchit-9eb4cdd37e5e78cc,libserde-2b5b205d63f4f8c4,libserde_core-9a628d0a95f24410,libaxum_core-201b1e9ed707faf3,libmime-d59ac7e78431c119,libhttp_body_util-442e79216e845528,libhttp_body-2d1402f49b47d404,libhttp-2861851353a99610,libitoa-d6391659dd20ef70,libtracing-773a949e74396c1c,liblog-46f6fdf643a40b21,libtracing_core-e37f3665a85c0534,libonce_cell-fd36a77660da678a,libtower-be9b3edfbdf65ffd,libsync_wrapper-f71908a2d1702d5d,libfutures_util-71f19399a3f40141,libmemchr-6e8a90676d452a68,libfutures_io-42005b8272e018a8,libslab-73264b5c8c8499bf,libfutures_sink-0b14163e5708f8d0,libfutures_task-853b801213f55e1f,libfutures_core-2c9d0e403b6efbe1,libtower_layer-b3c7d207747fb5fd,libtower_service-07d2747dbba20ec1,libtokio-0ae8af4536514c9c,libsocket2-4a30eff869d8b343,libwindows_sys-273445d234f2ef5b,libwindows_targets-ba35dba6952acdef,libbytes-0d423fbc9f78a2b3,libmio-c6545afb92e875cf,libwindows_sys-cbab6044b7a68360,libwindows_link-68aefdc6edfc1b3d,libpin_project_lite-45cc2132bea4ef6d}.rlib" "<sysroot>\\lib\\rustlib\\x86_64-pc-windows-msvc\\lib/{libstd-*,libpanic_unwind-*,libcfg_if-*,libwindows_link-*,librustc_demangle-*,libstd_detect-*,libhashbrown-*,librustc_std_workspace_alloc-*,libunwind-*,librustc_std_workspace_core-*,liballoc-*,libcore-*,libcompiler_builtins-*}.rlib" "shell32.lib" "ole32.lib" "kernel32.lib" "user32.lib" "shell32.lib" "gdi32.lib" "advapi32.lib" "kernel32.lib" "C:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\windows_x86_64_msvc-0.52.6\\lib\\windows.0.52.0.lib" "advapi32.lib" "kernel32.lib" "advapi32.lib" "C:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\windows_x86_64_msvc-0.48.5\\lib\\windows.0.48.5.lib" "C:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\windows_x86_64_msvc-0.52.6\\lib\\windows.0.52.0.lib" "bcrypt.lib" "advapi32.lib" "C:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\windows_x86_64_msvc-0.53.1\\lib\\windows.0.53.0.lib" "kernel32.lib" "kernel32.lib" "kernel32.lib" "ntdll.lib" "userenv.lib" "ws2_32.lib" "dbghelp.lib" "/defaultlib:msvcrt" "/NXCOMPAT" "/LIBPATH:C:\\Users\\User\\dev\\wt\\shardbrowser-custodian-verify\\src-tauri\\target\\debug\\build\\ring-af72b14d4db2e8e5\\out" "/LIBPATH:C:\\Users\\User\\dev\\wt\\shardbrowser-custodian-verify\\src-tauri\\target\\debug\\build\\libsqlite3-sys-c9ab9b62b67696ca\\out" "/LIBPATH:C:\\Users\\User\\dev\\wt\\shardbrowser-custodian-verify\\src-tauri\\target\\debug\\build\\webview2-com-sys-4546ca765db2053d\\out\\x64" "/LIBPATH:C:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\windows_x86_64_msvc-0.53.1\\lib" "/LIBPATH:C:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\windows_x86_64_msvc-0.48.5\\lib" "/LIBPATH:C:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\windows_x86_64_msvc-0.52.6\\lib" "/OUT:C:\\Users\\User\\dev\\wt\\shardbrowser-custodian-verify\\src-tauri\\target\\debug\\deps\\shardx_launcher_lib-f56ed3c5cad76fc7.exe" "/OPT:REF,NOICF" "/DEBUG" "/PDBALTPATH:%_PDB%" "/NATVIS:<sysroot>\\lib\\rustlib\\etc\\intrinsic.natvis" "/NATVIS:<sysroot>\\lib\\rustlib\\etc\\liballoc.natvis" "/NATVIS:<sysroot>\\lib\\rustlib\\etc\\libcore.natvis" "/NATVIS:<sysroot>\\lib\\rustlib\\etc\\libstd.natvis" "/NATVIS:C:\\Users\\User\\dev\\wt\\shardbrowser-custodian-verify\\src-tauri\\target\\debug\\deps\\rustcx9L5U8\\shardx_launcher_lib-0.natvis" "/NATVIS:C:\\Users\\User\\dev\\wt\\shardbrowser-custodian-verify\\src-tauri\\target\\debug\\deps\\rustcx9L5U8\\shardx_launcher_lib-1.natvis" "/NATVIS:C:\\Users\\User\\dev\\wt\\shardbrowser-custodian-verify\\src-tauri\\target\\debug\\deps\\rustcx9L5U8\\shardx_launcher_lib-2.natvis" "/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
  = note: some arguments are omitted. use `--verbose` to show all linker arguments
  = note: LINK : fatal error LNK1104: cannot open file 'C:\Users\User\dev\wt\shardbrowser-custodian-verify\src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe'
          

error: could not compile `shardx-launcher` (lib test) due to 1 previous error
```
Exit: 101; seconds: 31.43

### New round-5 regression probes

`cargo test -j 4 --manifest-path server/Cargo.toml --test v2_auth round5_`

```text

running 1 test
2026-11-05T19:02:26.631421Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T19:02:26.640850Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:02:26.643000Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:02:26.643055Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:02:26.650457Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28454
2026-11-05T19:02:28.473315Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:02:28.474609Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:02:28.474650Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:02:28.477323Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28454
test round5_a_revoked_custodian_loses_the_shared_reads_and_listing ... FAILED

failures:

---- round5_a_revoked_custodian_loses_the_shared_reads_and_listing stdout ----

thread 'round5_a_revoked_custodian_loses_the_shared_reads_and_listing' (46204) panicked at tests\v2_auth.rs:11012:5:
assertion `left == right` failed
  left: 409
 right: 201
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    round5_a_revoked_custodian_loses_the_shared_reads_and_listing

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 82 filtered out; finished in 5.51s

   Compiling shardx-team-server v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\server)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 32.50s
     Running tests\v2_auth.rs (server\target\debug\deps\v2_auth-08d8e8e8895d1316.exe)
error: test failed, to rerun pass `--test v2_auth`
```
Exit: 101; seconds: 38.72

### UI custody gate

`node node_modules/@playwright/test/cli.js test tests/e2e/app.spec.ts --grep custodian|join code|pinned device|fleet key|approval stays|revoke stays|reason list|refreshed keys|connecting needs|root custody|interrupted custody --output <temporary output directory> --reporter list`

```text

Running 17 tests using 4 workers

  ok  2 [chromium-desktop] › tests\e2e\app.spec.ts:254:1 › Team page warns about a custodian renewed after revocation (2.1s)
  ok  4 [chromium-desktop] › tests\e2e\app.spec.ts:843:1 › an expired join code offers Enroll again and a new code (2.9s)
  ok  6 [chromium-desktop] › tests\e2e\app.spec.ts:935:1 › an active pinned device is not offered reenrollment when a remounted code expires (8.2s)
  ok  1 [chromium-desktop] › tests\e2e\app.spec.ts:869:1 › an approved device whose join code expired can enroll again (11.3s)
  ok  5 [chromium-desktop] › tests\e2e\app.spec.ts:900:1 › an active pinned device is not offered reenrollment after reopening Team (10.3s)
  ok  7 [chromium-desktop] › tests\e2e\app.spec.ts:969:1 › a custodian with no usable key is not shown Fleet key ready (1.6s)
  ok  8 [chromium-desktop] › tests\e2e\app.spec.ts:994:1 › a custodian whose fleet key is blocked is shown the Q-18 notice (1.7s)
  ok 10 [chromium-desktop] › tests\e2e\app.spec.ts:1061:1 › the reason list offers only Retired and Lost (1.2s)
  ok 11 [chromium-desktop] › tests\e2e\app.spec.ts:1074:1 › approval stays disabled until the custodian creates its fleet key (1.2s)
  ok 12 [chromium-desktop] › tests\e2e\app.spec.ts:1084:1 › revoke stays disabled until the custodian creates its fleet key (1.2s)
  ok  9 [chromium-desktop] › tests\e2e\app.spec.ts:1034:1 › the custodian cannot approve a row it first saw more than ten minutes ago (3.3s)
  ok 13 [chromium-desktop] › tests\e2e\app.spec.ts:1093:1 › refreshed keys require a fresh join-code comparison (2.0s)
  ok 14 [chromium-desktop] › tests\e2e\app.spec.ts:1119:1 › connecting needs no token (1.1s)
  ok 16 [chromium-desktop] › tests\e2e\app.spec.ts:1160:1 › a fleet key Q-18 blocks is reported instead of the join steps (930ms)
  ok 17 [chromium-desktop] › tests\e2e\app.spec.ts:1167:1 › an interrupted custody setup resumes at its saved bundle without asking for a path (1.1s)
  ok 15 [chromium-desktop] › tests\e2e\app.spec.ts:1136:1 › the first device sets up root custody once its passphrases agree (1.6s)
  ok  3 [chromium-desktop] › tests\e2e\app.spec.ts:799:1 › a custodian revokes a device and the device can no longer pull (17.5s)

  17 passed (1.5m)
[WebServer] npm notice run shardx-launcher@2.6.1 build:e2e
[WebServer] npm notice run tsc && vite build --mode e2e
[WebServer] 
[WebServer] (!) Some chunks are larger than 500 kB after minification. Consider:
[WebServer] - Using dynamic import() to code-split the application
[WebServer] - Use build.rollupOptions.output.manualChunks to improve chunking: https://rollupjs.org/configuration-options/#output-manualchunks
[WebServer] - Adjust chunk size limit for this warning via build.chunkSizeWarningLimit.
[WebServer] npm notice run shardx-launcher@2.6.1 preview
[WebServer] npm notice run vite preview --host 127.0.0.1 --port 4173
(node:27676) Warning: The 'NO_COLOR' env is ignored due to the 'FORCE_COLOR' env being set.
(Use `node --trace-warnings ...` to show where the warning was created)
(node:42604) Warning: The 'NO_COLOR' env is ignored due to the 'FORCE_COLOR' env being set.
(Use `node --trace-warnings ...` to show where the warning was created)
(node:49604) Warning: The 'NO_COLOR' env is ignored due to the 'FORCE_COLOR' env being set.
(Use `node --trace-warnings ...` to show where the warning was created)
(node:49544) Warning: The 'NO_COLOR' env is ignored due to the 'FORCE_COLOR' env being set.
(Use `node --trace-warnings ...` to show where the warning was created)
```
Exit: 0; seconds: 91.03

### team::sync::tests

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process` (offline; APPDATA redirected to temporary directory)

```text

running 201 tests
test team::sync::tests::a_corrupt_revert_source_preserves_data_and_retries ... ok
test team::sync::tests::a_custodian_not_yet_appointed_signs_no_transition ... ok
test team::sync::tests::a_crash_inside_the_staging_swap_resumes ... ok
test team::sync::tests::a_blocked_publish_is_cancelled_by_its_command_and_stops_blocking_a_downgrade ... ok
test team::sync::tests::a_compromise_counted_mid_transfer_aborts_the_upload ... ok
test team::sync::tests::a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks ... ok
test team::sync::tests::a_custodian_reappointed_after_its_lapse_signs_again ... ok
test team::sync::tests::a_binding_and_its_rows_name_the_servers_account_and_key ... ok
test team::sync::tests::a_custodian_distrusted_here_signs_no_transition ... ok
test team::sync::tests::a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen ... ok
test team::sync::tests::a_device_clock_behind_the_server_still_binds_one_profile ... ok
test team::sync::tests::a_device_withdrawn_in_the_walks_evidence_sends_no_revert ... ok
test team::sync::tests::a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key ... ok
test team::sync::tests::a_failed_anchor_restore_keeps_the_quarantine_and_unresolved_rows ... ok
test team::sync::tests::a_compromised_custodian_blocks_every_fleet_through_the_root ... ok
test team::sync::tests::a_failed_record_leaves_no_evaluation_and_keeps_the_refusal ... ok
test team::sync::tests::a_failed_release_of_an_old_lease_is_retried_as_stored ... ok
test team::sync::tests::a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code ... ok
test team::sync::tests::a_folder_delete_keeps_a_profile_whose_pending_swap_cannot_land ... ok
test team::sync::tests::a_device_whose_own_key_is_withdrawn_sends_no_revert ... ok
test team::sync::tests::a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte ... ok
test team::sync::tests::a_head_committed_on_top_does_not_strand_the_push ... ok
test team::sync::tests::a_binding_changed_during_acceptance_is_not_moved has been running for over 60 seconds
test team::sync::tests::a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept has been running for over 60 seconds
test team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation has been running for over 60 seconds
test team::sync::tests::a_crash_after_finish_completes_the_staging_swap has been running for over 60 seconds
test team::sync::tests::a_head_met_again_after_an_unbind_reopens_its_row ... ok
test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind has been running for over 60 seconds
test team::sync::tests::a_join_past_an_untrusted_child_keeps_data_and_can_unbind ... ok
test team::sync::tests::a_failure_inside_a_run_writes_no_unresolved_rows has been running for over 60 seconds
test team::sync::tests::a_failed_join_recovers_by_pull_then_push_or_by_unbind ... ok
test team::sync::tests::a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind ... ok
test team::sync::tests::a_head_whose_signer_may_not_commit_is_not_restored has been running for over 60 seconds
test team::sync::tests::a_join_whose_pin_fails_keeps_the_local_profile ... ok
test team::sync::tests::a_kept_revocation_reloads_with_every_column_equal has been running for over 60 seconds
test team::sync::tests::a_key_the_checkout_does_not_name_is_never_used has been running for over 60 seconds
test team::sync::tests::a_crash_after_finish_completes_the_staging_swap ... ok
test team::sync::tests::a_key_without_its_kept_record_asks_to_be_collected_again has been running for over 60 seconds
test team::sync::tests::a_known_custodian_with_no_root_holding_blocks has been running for over 60 seconds
test team::sync::tests::a_landed_commit_whose_reply_was_lost_replays_after_its_pin_signer_is_revoked has been running for over 60 seconds
test team::sync::tests::a_key_without_its_kept_record_asks_to_be_collected_again ... ok
test team::sync::tests::a_known_custodian_with_no_root_holding_blocks ... ok
test team::sync::tests::a_landed_commit_whose_reply_was_lost_replays_after_its_pin_signer_is_revoked ... ok
test team::sync::tests::a_binding_changed_during_acceptance_is_not_moved ... ok
test team::sync::tests::a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull has been running for over 60 seconds
test team::sync::tests::a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull ... ok
test team::sync::tests::a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept ... ok
test team::sync::tests::a_lapse_seen_while_accepting_refuses_a_backdated_transition has been running for over 60 seconds
test team::sync::tests::a_lapse_seen_while_accepting_refuses_a_backdated_transition ... ok
test team::sync::tests::a_lapsed_or_former_custodian_signs_no_transition has been running for over 60 seconds
test team::sync::tests::a_lease_at_risk_is_still_a_held_lease ... ok
test team::sync::tests::a_leaf_head_is_accepted_only_as_a_new_head_is has been running for over 60 seconds
test team::sync::tests::a_key_the_checkout_does_not_name_is_never_used ... ok
test team::sync::tests::a_lease_from_before_the_restore_is_released_before_the_binding_moves ... ok
test team::sync::tests::a_new_head_from_an_earlier_epoch_is_a_rollback ... ok
test team::sync::tests::a_new_head_of_a_signer_revoked_in_this_pulls_evidence_is_refused ... ok
test team::sync::tests::a_head_whose_signer_may_not_commit_is_not_restored ... ok
test team::sync::tests::a_pinned_head_is_read_back_only_as_the_bindings_own ... ok
test team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation ... ok
test team::sync::tests::a_lapsed_or_former_custodian_signs_no_transition ... ok
test team::sync::tests::a_failure_inside_a_run_writes_no_unresolved_rows ... ok
test team::sync::tests::a_lease_expiry_outside_the_ttl_is_refused_by_name has been running for over 60 seconds
test team::sync::tests::a_pinned_head_stays_readable_after_its_signers_grants_expire ... ok
test team::sync::tests::a_profile_is_published_with_its_first_lease_and_then_pushed ... ok
test team::sync::tests::a_lost_session_or_rate_limit_keeps_the_stored_request ... ok
test team::sync::tests::a_missing_or_withdrawn_fleet_key_is_refused ... ok
test team::sync::tests::a_profile_published_after_a_restore_starts_at_the_servers_epoch ... ok
test team::sync::tests::a_profile_removed_for_good_drops_its_binding ... ok
test team::sync::tests::a_normal_push_still_refuses_a_quarantined_binding ... ok
test team::sync::tests::a_publish_replayed_after_its_lease_ended_binds_the_one_profile ... ok
test team::sync::tests::a_pinned_head_of_a_since_revoked_signer_is_not_restored ... ok
test team::sync::tests::a_publish_whose_operation_was_cancelled_meanwhile_binds_nothing ... ok
test team::sync::tests::a_published_profile_pushes_and_another_device_pulls_it ... ok
test team::sync::tests::a_pull_keeps_the_devices_local_state ... ok
test team::sync::tests::a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download ... ok
test team::sync::tests::a_profile_removed_for_good_releases_its_lease_unless_work_is_pending ... ok
test team::sync::tests::a_pull_whose_pin_fails_keeps_the_local_profile ... ok
test team::sync::tests::a_refused_sync_reply_hides_an_echoed_token ... ok
test team::sync::tests::a_refused_sync_reply_hides_the_bare_access_token_body ... ok
test team::sync::tests::a_push_behind_the_listed_head_is_refused ... ok
test team::sync::tests::a_receipt_or_readback_that_does_not_match_is_never_kept ... ok
test team::sync::tests::a_refused_or_mismatched_reply_is_never_kept ... ok
test team::sync::tests::a_pull_crossing_an_accepted_run_into_another_keeps_the_quarantine ... ok
test team::sync::tests::a_refused_publish_is_not_replayed_and_the_next_one_starts_afresh ... ok
test team::sync::tests::a_refused_revert_checkout_keeps_the_local_profile ... ok
test team::sync::tests::a_pull_waits_for_a_push_in_flight ... ok
test team::sync::tests::a_refused_revert_discards_its_staging ... ok
test team::sync::tests::a_publish_at_a_restore_epoch_never_waits_on_its_acceptance has been running for over 60 seconds
test team::sync::tests::a_publish_is_bound_whatever_its_lease_expiry_says has been running for over 60 seconds
test team::sync::tests::a_release_pending_for_another_lease_keeps_the_staging ... ok
test team::sync::tests::a_release_whose_reply_was_lost_is_replayed_byte_for_byte ... ok
test team::sync::tests::a_publish_reply_that_does_not_name_the_request_is_never_kept has been running for over 60 seconds
test team::sync::tests::a_lease_expiry_outside_the_ttl_is_refused_by_name ... ok
test team::sync::tests::a_kept_revocation_reloads_with_every_column_equal ... ok
test team::sync::tests::a_renewed_lease_moves_the_bindings_expiry_forward ... ok
test team::sync::tests::a_publish_that_cannot_be_trusted_stores_and_sends_nothing has been running for over 60 seconds
test team::sync::tests::a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned ... ok
test team::sync::tests::a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked ... ok
test team::sync::tests::a_reply_too_large_to_hold_is_refused ... ok
test team::sync::tests::a_report_of_a_revoked_signer_a_pull_saw_is_kept ... ok
test team::sync::tests::a_reported_only_quarantine_stays_once_the_approval_is_hidden ... ok
test team::sync::tests::a_restore_epoch_that_goes_back_is_a_rollback ... ok
test team::sync::tests::a_resumed_revert_never_commits_a_source_withdrawn_before_its_retry ... ok
test team::sync::tests::a_resumed_revert_whose_staging_is_gone_restores_p_again ... ok
test team::sync::tests::a_retried_revert_files_each_accepted_run_once ... ok
test team::sync::tests::a_revert_audits_the_accepted_runs_it_crosses ... ok
test team::sync::tests::a_replayed_checkout_on_an_old_head_is_released_and_taken_again ... ok
test team::sync::tests::a_revert_keeps_the_devices_local_state ... ok
test team::sync::tests::a_revert_lease_held_over_a_rollback_is_released ... ok
test team::sync::tests::a_revert_lease_whose_walk_fails_is_released_on_the_server ... ok
test team::sync::tests::a_revert_lease_whose_run_was_closed_elsewhere_is_released has been running for over 60 seconds
test team::sync::tests::a_revert_never_commits_a_source_withdrawn_during_its_download ... ok
test team::sync::tests::a_revert_pin_failure_preserves_local_data_and_retries has been running for over 60 seconds
test team::sync::tests::a_revert_refuses_a_mixed_run_without_touching_local_data has been running for over 60 seconds
test team::sync::tests::a_revert_uses_the_newest_valid_content_and_reads_back_remotely has been running for over 60 seconds
test team::sync::tests::a_revocation_naming_another_device_never_enables_a_skip has been running for over 60 seconds
test team::sync::tests::a_revocation_recorded_after_checkout_abandons_an_ordinary_push has been running for over 60 seconds
test team::sync::tests::a_rolled_back_head_or_epoch_quarantines_the_binding has been running for over 60 seconds
test team::sync::tests::a_server_integer_past_the_signed_range_is_refused_before_any_row has been running for over 60 seconds
test team::sync::tests::a_stacked_run_never_temporarily_pins_a_rejected_head has been running for over 60 seconds
test team::sync::tests::a_revert_pin_failure_preserves_local_data_and_retries ... ok
test team::sync::tests::a_staging_dir_without_a_swap_row_is_never_swapped_in has been running for over 60 seconds
test team::sync::tests::a_stored_column_that_drifts_from_its_bytes_is_never_sent has been running for over 60 seconds
test team::sync::tests::a_revert_uses_the_newest_valid_content_and_reads_back_remotely ... ok
test team::sync::tests::a_revocation_naming_another_device_never_enables_a_skip ... ok
test team::sync::tests::a_stacked_run_never_temporarily_pins_a_rejected_head ... ok
test team::sync::tests::a_revert_lease_whose_run_was_closed_elsewhere_is_released ... ok
test team::sync::tests::a_staging_dir_without_a_swap_row_is_never_swapped_in ... ok
test team::sync::tests::a_publish_at_a_restore_epoch_never_waits_on_its_acceptance ... ok
test team::sync::tests::a_publish_is_bound_whatever_its_lease_expiry_says ... ok
test team::sync::tests::a_stored_finalize_is_not_sent_once_a_compromise_is_counted ... ok
test team::sync::tests::a_leaf_head_is_accepted_only_as_a_new_head_is ... ok
test team::sync::tests::a_revert_refuses_a_mixed_run_without_touching_local_data ... ok
test team::sync::tests::a_stored_publish_goes_out_while_its_key_holds ... ok
test team::sync::tests::a_revocation_recorded_after_checkout_abandons_an_ordinary_push ... ok
test team::sync::tests::a_server_integer_past_the_signed_range_is_refused_before_any_row ... ok
test team::sync::tests::a_swap_row_for_a_deleted_profile_is_cleared ... ok
test team::sync::tests::a_verified_transition_moves_only_the_bindings_it_covers ... ok
test team::sync::tests::a_withdrawn_committer_sends_no_prepared_revert_commit ... ok
test team::sync::tests::a_withdrawn_device_releases_its_revert_lease_on_the_server ... ok
test team::sync::tests::a_stored_publish_is_not_sent_once_its_key_is_blocked_or_withdrawn ... ok
test team::sync::tests::an_abandoned_revert_with_a_lost_release_keeps_no_plaintext ... ok
test team::sync::tests::a_stored_publish_that_drifts_from_its_bytes_is_never_sent has been running for over 60 seconds
test team::sync::tests::an_exposure_survives_a_recollection_that_omits_its_grant ... ok
test team::sync::tests::a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh has been running for over 60 seconds
test team::sync::tests::an_interrupted_upload_resumes_at_the_offset_head_reports ... ok
test team::sync::tests::an_open_run_anchor_withdrawn_during_download_is_not_pinned ... ok
test team::sync::tests::an_open_run_restore_keeps_what_an_ordinary_pull_keeps ... ok
test team::sync::tests::a_tombstone_that_no_longer_recomputes_is_never_returned has been running for over 60 seconds
test team::sync::tests::a_transition_that_does_not_verify_keeps_the_binding_quarantined has been running for over 60 seconds
test team::sync::tests::an_open_upload_is_aborted_once_a_compromise_is_counted ... ok
    Finished `test` profile [unoptimized + debuginfo] target(s) in 2.55s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
error: test failed, to rerun pass `--lib`

Caused by:
  process didn't exit successfully: `C:\Users\User\dev\wt\shardbrowser-custodian-verify\src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe team::sync::tests --skip a_real_os_store_key_survives_into_a_fresh_process` (exit code: 0xffffffff)
note: test exited abnormally; to see the full output pass --no-capture to the harness.
```
Exit: 4294967295; seconds: 465.12

### Round-5 probes after fixture correction / releasing executable lock

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib round5_ -- --skip a_real_os_store_key_survives_into_a_fresh_process`

```text

running 1 test
test fleet_custody::tests::round5_device_key_ids_do_not_echo_the_session_token_body ... FAILED

failures:

---- fleet_custody::tests::round5_device_key_ids_do_not_echo_the_session_token_body stdout ----

thread 'fleet_custody::tests::round5_device_key_ids_do_not_echo_the_session_token_body' (12940) panicked at src\fleet_custody.rs:2237:9:
assertion `left == right` failed: bearer body crossed a custody boundary
  left: (4, 4)
 right: (0, 0)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    fleet_custody::tests::round5_device_key_ids_do_not_echo_the_session_token_body

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 733 filtered out; finished in 0.06s

   Compiling shardx-launcher v2.6.1 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\src-tauri)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 37.67s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
error: test failed, to rerun pass `--lib`
```
Exit: 101

### Round-5 probes after fixture correction / releasing executable lock

`cargo test -j 4 --manifest-path server/Cargo.toml --test v2_auth round5_`

```text

running 1 test
2026-11-05T19:06:26.368439Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T19:06:26.392120Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:06:26.401475Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:06:26.401559Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:06:26.417822Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28454
2026-11-05T19:06:27.399407Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:06:27.402396Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:06:27.402510Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:06:27.410188Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28454
test round5_a_revoked_custodian_loses_the_shared_reads_and_listing ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 82 filtered out; finished in 6.93s

   Compiling shardx-team-server v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\server)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 13.71s
     Running tests\v2_auth.rs (server\target\debug\deps\v2_auth-08d8e8e8895d1316.exe)
```
Exit: 0

### root_bootstrap::tests

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib root_bootstrap::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process` (offline; temporary APPDATA)

```text

running 31 tests
test root_bootstrap::tests::a_failed_save_leaves_the_callers_state_as_it_was ... ok
test root_bootstrap::tests::a_hex_secret_decodes_into_32_bytes_or_is_refused ... ok
test root_bootstrap::tests::a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key ... ok
test root_bootstrap::tests::a_legacy_trk_the_store_already_holds_is_only_dropped ... ok
test root_bootstrap::tests::a_legacy_trk_with_a_malformed_nonce_is_refused_before_anything_is_stored ... ok
test root_bootstrap::tests::a_stored_response_counts_only_when_it_answers_this_exact_request ... ok
test root_bootstrap::tests::a_receipt_counts_only_for_this_devices_own_approval ... ok
test root_bootstrap::tests::a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing ... ok
test root_bootstrap::tests::a_reference_for_another_tenant_or_with_a_malformed_nonce_is_refused ... ok
test root_bootstrap::tests::a_reference_to_another_credential_is_refused_and_that_credential_is_kept ... ok
test root_bootstrap::tests::the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written ... ok
test root_bootstrap::tests::a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it ... ok
test root_bootstrap::tests::the_saved_state_never_prints_the_legacy_trk ... ok
test root_bootstrap::tests::the_run_nonce_is_saved_before_the_key_is_stored ... ok
test root_bootstrap::tests::the_self_approval_names_this_device_tenant_wide_for_a_year ... ok
test root_bootstrap::tests::an_activated_run_forgets_a_key_that_an_earlier_run_left ... ok
test root_bootstrap::tests::the_self_grant_seals_the_trk_to_this_device_and_links_the_approval ... ok
test root_bootstrap::tests::a_resume_loads_the_stored_key_and_a_missing_one_is_not_made_up_again ... ok
test root_bootstrap::tests::a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed ... ok
test root_bootstrap::tests::a_store_that_refuses_a_new_key_leaves_no_reference_and_no_file ... ok
test root_bootstrap::tests::a_legacy_trk_is_refused_when_a_reference_is_already_set ... ok
test root_bootstrap::tests::a_legacy_file_that_names_no_tenant_or_holds_no_key_is_refused ... ok
test root_bootstrap::tests::the_activation_is_saved_before_the_key_is_forgotten ... ok
test root_bootstrap::tests::releasing_forgets_the_key_and_drops_the_reference ... ok
test root_bootstrap::tests::an_activated_run_keeps_the_root_records_and_they_reload_exactly ... ok
test root_bootstrap::tests::a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it ... ok
test root_bootstrap::tests::a_new_run_never_reuses_a_key_an_abandoned_run_left ... ok
test root_bootstrap::tests::a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made ... ok
test root_bootstrap::tests::a_legacy_trk_never_overwrites_a_different_stored_key ... ok
test root_bootstrap::tests::the_trk_is_stored_and_the_saved_state_holds_only_its_reference ... ok
test root_bootstrap::tests::the_recovery_export_is_read_back_and_its_pinned_hash_returned ... ok

test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 703 filtered out; finished in 26.74s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 2.47s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 29.48

### team_config::tests

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team_config::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process` (offline; temporary APPDATA)

```text

running 12 tests
test team_config::tests::a_device_without_an_identity_moves_nothing ... ok
test team_config::tests::team_config_golden_includes_enrolled_at_ms ... ok
test team_config::tests::debug_never_prints_the_token_or_a_seed ... ok
test team_config::tests::an_old_team_config_without_enrolled_at_ms_still_loads ... ok
test team_config::tests::secrets_zeroize_on_drop_and_the_file_format_is_unchanged ... ok
test team_config::tests::a_seed_the_store_refuses_stays_in_the_file ... ok
test team_config::tests::a_legacy_cached_fleet_key_alone_is_not_a_fleet_key ... ok
test team_config::tests::an_unopenable_dpapi_seed_is_named_kept_and_allows_re_enrollment ... ok
test team_config::tests::enrolled_seeds_move_to_the_credential_store_and_still_open ... ok
test team_config::tests::a_dpapi_protected_seed_moves_to_the_credential_store ... ok
test team_config::tests::saved_seeds_are_dpapi_protected_and_load_back ... ok
test team_config::tests::a_plaintext_file_still_loads_and_is_rewritten_protected ... ok

test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 722 filtered out; finished in 0.08s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.08s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 1.34

### credential::tests

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib credential::tests -- --skip a_real_os_store_key_survives_into_a_fresh_process` (offline; temporary APPDATA)

```text

running 10 tests
test credential::tests::child_files_a_key_in_the_key_file ... ignored, child process of the G2-48 check
test credential::tests::child_reads_and_deletes_the_real_credential ... ignored, child process of the G2-48 check
test credential::tests::child_unlocks_the_key_file ... ignored, child process of the G2-48 check
test credential::tests::child_with_no_store_fails_closed ... ignored, child process of the G2-48 check
test credential::tests::references_are_separate_credentials ... ok
test credential::tests::a_failed_write_or_read_back_is_reported ... ok
test credential::tests::a_namespace_keeps_one_devices_credentials_from_another ... ok
test credential::tests::a_key_round_trips_and_is_forgotten ... ok
test credential::tests::an_unavailable_store_fails_closed_in_a_fresh_process ... ok
test credential::tests::a_key_file_key_is_locked_then_served_in_a_fresh_process ... ok

test result: ok. 6 passed; 0 failed; 4 ignored; 0 measured; 724 filtered out; finished in 15.78s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.40s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 17.44

### Focused sync verification: key_status

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests::key_status -- --skip a_real_os_store_key_survives_into_a_fresh_process`

```text

running 2 tests
test team::sync::tests::key_status_agrees_with_a_compromise_blocked_push ... ok
test team::sync::tests::key_status_and_push_agree_after_the_fleet_key_is_lost ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 732 filtered out; finished in 1.52s

    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Finished `test` profile [unoptimized + debuginfo] target(s) in 2.51s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 4.25

### Focused sync verification: a_pinned_head_of_a_since_revoked_signer_is_not_restored

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests::a_pinned_head_of_a_since_revoked_signer_is_not_restored -- --skip a_real_os_store_key_survives_into_a_fresh_process`

```text

running 1 test
test team::sync::tests::a_pinned_head_of_a_since_revoked_signer_is_not_restored ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 733 filtered out; finished in 3.57s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.16s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 4.97

### Focused sync verification: an_ordinary_push_refuses_over_a_pinned_head_whose_signer_is_proven_revoked

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests::an_ordinary_push_refuses_over_a_pinned_head_whose_signer_is_proven_revoked -- --skip a_real_os_store_key_survives_into_a_fresh_process`

```text

running 1 test
test team::sync::tests::an_ordinary_push_refuses_over_a_pinned_head_whose_signer_is_proven_revoked ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 733 filtered out; finished in 2.17s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.63s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 3.99

### Focused sync verification: a_compromised_revocation_blocks_commits_under_an_exposed_generation

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation -- --skip a_real_os_store_key_survives_into_a_fresh_process`

```text

running 1 test
test team::sync::tests::a_compromised_revocation_blocks_commits_under_an_exposed_generation ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 733 filtered out; finished in 2.98s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.14s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 4.39

### Focused sync verification: a_compromised_custodian_blocks_every_fleet_through_the_root

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests::a_compromised_custodian_blocks_every_fleet_through_the_root -- --skip a_real_os_store_key_survives_into_a_fresh_process`

```text

running 1 test
test team::sync::tests::a_compromised_custodian_blocks_every_fleet_through_the_root ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 733 filtered out; finished in 4.10s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.84s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 6.36

### Focused sync verification: a_refused_sync_reply

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib team::sync::tests::a_refused_sync_reply -- --skip a_real_os_store_key_survives_into_a_fresh_process`

```text

running 2 tests
test team::sync::tests::a_refused_sync_reply_hides_an_echoed_token ... ok
test team::sync::tests::a_refused_sync_reply_hides_the_bare_access_token_body ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 732 filtered out; finished in 0.02s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.56s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 1.88

### New server probes, final source

`cargo test -j 4 --manifest-path server/Cargo.toml --test v2_auth round5_`

```text

running 2 tests
2026-11-05T19:09:57.862945Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T19:09:57.876164Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:09:57.881358Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:09:57.881432Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:09:57.889975Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28455
2026-11-05T19:09:57.969437Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T19:09:57.981825Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:09:57.984327Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:09:57.984403Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:09:57.988243Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28454
2026-11-05T19:09:58.367234Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:09:58.369851Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:09:58.369913Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:09:58.373857Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28455
2026-11-05T19:09:58.437194Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:09:58.439396Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:09:58.439517Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:09:58.444569Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28454
test round5_expired_required_grant_strands_a_preparing_generation ... ok
test round5_a_revoked_custodian_loses_the_shared_reads_and_listing ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 82 filtered out; finished in 5.97s

   Compiling shardx-team-server v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\server)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 14.78s
     Running tests\v2_auth.rs (server\target\debug\deps\v2_auth-08d8e8e8895d1316.exe)
```
Exit: 0

### custodian_it

`cargo test -j 4 --manifest-path src-tauri/Cargo.toml --lib custodian_it -- --skip a_real_os_store_key_survives_into_a_fresh_process` (offline; temporary APPDATA)

```text

running 9 tests
test custodian_it::the_journey_leak_scan_worker ... ignored, a worker of the_journey_leaks_no_secret_to_output_state_or_replies
test custodian_it::a_fleet_setup_resumes_after_a_failed_save_and_a_replayed_run_against_the_real_server ... ok
test custodian_it::the_journey_leaks_no_secret_to_output_state_or_replies ... ok
test custodian_it::a_revoked_device_is_cut_off_but_keeps_the_key_it_already_holds_against_a_real_server has been running for over 60 seconds
test custodian_it::a_setup_does_not_ack_again_after_its_acked_receipt has been running for over 60 seconds
test custodian_it::a_setup_whose_cleanup_fails_leaves_no_usable_verified_key has been running for over 60 seconds
test custodian_it::the_custodian_creates_and_collects_the_fleet_key_against_the_real_server has been running for over 60 seconds
test custodian_it::the_journey_writes_one_audit_row_per_mutation has been running for over 60 seconds
test custodian_it::two_devices_share_a_profile_through_a_real_server_after_approval has been running for over 60 seconds
test custodian_it::a_revoked_device_is_cut_off_but_keeps_the_key_it_already_holds_against_a_real_server ... ok
test custodian_it::a_setup_does_not_ack_again_after_its_acked_receipt ... ok
test custodian_it::a_setup_whose_cleanup_fails_leaves_no_usable_verified_key ... ok
test custodian_it::the_custodian_creates_and_collects_the_fleet_key_against_the_real_server ... ok
test custodian_it::the_journey_writes_one_audit_row_per_mutation ... ok
test custodian_it::two_devices_share_a_profile_through_a_real_server_after_approval ... ok

test result: ok. 8 passed; 0 failed; 1 ignored; 0 measured; 725 filtered out; finished in 162.79s

    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on build directory
    Finished `test` profile [unoptimized + debuginfo] target(s) in 2.87s
     Running unittests src\lib.rs (src-tauri\target\debug\deps\shardx_launcher_lib-f56ed3c5cad76fc7.exe)
```
Exit: 0; seconds: 165.82

### Final server probes including alternate root-grant read

`cargo test -j 4 --manifest-path server/Cargo.toml --test v2_auth round5_`

```text

running 3 tests
2026-11-05T19:12:50.952734Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T19:12:50.964569Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T19:12:50.997937Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:12:51.004430Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:12:51.007585Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:12:51.007586Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:12:51.007688Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:12:51.007812Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:12:51.029764Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T19:12:51.059011Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:12:51.067839Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28456
2026-11-05T19:12:51.069425Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:12:51.069504Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:12:51.074606Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28454
2026-11-05T19:12:51.084924Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28455
2026-11-05T19:12:51.524819Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:12:51.531325Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:12:51.531401Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:12:51.532967Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:12:51.536092Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28454
2026-11-05T19:12:51.538640Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:12:51.538721Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:12:51.543067Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28455
2026-11-05T19:12:51.556257Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:12:51.558560Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:12:51.558669Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:12:51.563257Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28456
test round5_expired_required_grant_strands_a_preparing_generation ... ok
test round5_a_pending_device_reads_another_devices_root_grant_in_trust_evidence ... FAILED
test round5_a_revoked_custodian_loses_the_shared_reads_and_listing ... ok

failures:

---- round5_a_pending_device_reads_another_devices_root_grant_in_trust_evidence stdout ----

thread 'round5_a_pending_device_reads_another_devices_root_grant_in_trust_evidence' (42376) panicked at tests\v2_auth.rs:466:5:
assertion `left == right` failed: {"error":"not found"}
  left: 404
 right: 201
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    round5_a_pending_device_reads_another_devices_root_grant_in_trust_evidence

test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 82 filtered out; finished in 4.75s

   Compiling shardx-team-server v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\server)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 9.92s
     Running tests\v2_auth.rs (server\target\debug\deps\v2_auth-08d8e8e8895d1316.exe)
error: test failed, to rerun pass `--test v2_auth`
```
Exit: 101

### Final server probes with matching account fixture

`cargo test -j 4 --manifest-path server/Cargo.toml --test v2_auth round5_`

```text

running 3 tests
2026-11-05T19:13:18.044156Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T19:13:18.058476Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:13:18.060780Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:13:18.060847Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:13:18.063927Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28456
2026-11-05T19:13:18.102137Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T19:13:18.109080Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:13:18.110994Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:13:18.111055Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:13:18.114191Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28455
2026-11-05T19:13:18.115105Z  WARN shardx_team_server::db: bootstrapped admin user 'admin' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, then change the password
2026-11-05T19:13:18.121933Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:13:18.123999Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:13:18.124068Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:13:18.128142Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28454
2026-11-05T19:13:18.246939Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:13:18.248559Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:13:18.248627Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:13:18.252555Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28456
2026-11-05T19:13:18.319240Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:13:18.319249Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-05T19:13:18.321258Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:13:18.321258Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-05T19:13:18.321321Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:13:18.321335Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-05T19:13:18.325033Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28454
2026-11-05T19:13:18.325372Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28455
test round5_expired_required_grant_strands_a_preparing_generation ... ok
test round5_a_pending_device_reads_another_devices_root_grant_in_trust_evidence ... ok
test round5_a_revoked_custodian_loses_the_shared_reads_and_listing ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 82 filtered out; finished in 4.02s

   Compiling shardx-team-server v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\server)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 6.99s
     Running tests\v2_auth.rs (server\target\debug\deps\v2_auth-08d8e8e8895d1316.exe)
```
Exit: 0

### UI two-device profile journey

`node node_modules/@playwright/test/cli.js test tests/e2e/app.spec.ts --grep two devices pass --output <temporary output directory> --reporter list`

```text

Running 1 test using 1 worker

  ok 1 [chromium-desktop] › tests\e2e\app.spec.ts:699:1 › two devices pass one team profile back and forth, then revert a revoked head to available (9.2s)

  1 passed (36.4s)
[WebServer] npm notice run shardx-launcher@2.6.1 build:e2e
[WebServer] npm notice run tsc && vite build --mode e2e
[WebServer] 
[WebServer] (!) Some chunks are larger than 500 kB after minification. Consider:
[WebServer] - Using dynamic import() to code-split the application
[WebServer] - Use build.rollupOptions.output.manualChunks to improve chunking: https://rollupjs.org/configuration-options/#output-manualchunks
[WebServer] - Adjust chunk size limit for this warning via build.chunkSizeWarningLimit.
[WebServer] npm notice run shardx-launcher@2.6.1 preview
[WebServer] npm notice run vite preview --host 127.0.0.1 --port 4173
(node:16352) Warning: The 'NO_COLOR' env is ignored due to the 'FORCE_COLOR' env being set.
(Use `node --trace-warnings ...` to show where the warning was created)
```
Exit: 0

### No-early-return check for the Windows symlink test

`CI=1 cargo test -j 4 --manifest-path server/Cargo.toml --test identity_authority a_symlinked_record_is_refused`

```text

running 1 test
test a_symlinked_record_is_refused ... FAILED

failures:

---- a_symlinked_record_is_refused stdout ----

thread 'a_symlinked_record_is_refused' (37940) panicked at tests\identity_authority.rs:216:9:
CI is set and a symlink cannot be created here: A required privilege is not held by the client. (os error 1314)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    a_symlinked_record_is_refused

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 22 filtered out; finished in 0.86s

   Compiling shardx-core v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\shared)
   Compiling shardx-team-server v0.1.0 (C:\Users\User\dev\wt\shardbrowser-custodian-verify\server)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1m 00s
     Running tests\identity_authority.rs (server\target\debug\deps\identity_authority-346602ad90221fa4.exe)
error: test failed, to rerun pass `--test identity_authority`
```
Exit: 101


## Structured independent findings

Pattern chosen before adding probes: exercise the repository's existing server-route, launcher custody, and Playwright fixture patterns; sources were `server/tests/v2_auth.rs`, `src-tauri/src/fleet_custody.rs`, `src-tauri/src/custodian_it.rs`, and `tests/e2e/app.spec.ts`.

The three added probes are in the working copy. They are deliberately retained as evidence even where one exposes a defect:

- `src-tauri/src/fleet_custody.rs:2213`, `round5_device_key_ids_do_not_echo_the_session_token_body`: FAIL, `(4, 4) != (0, 0)`. A server response can put a session-token body in a listed key ID; `FleetClient::list_tenant_devices` validates the field but does not redact it, and `see_devices` sends it to IPC.
- `server/tests/v2_auth.rs:10994`, `round5_a_revoked_custodian_loses_the_shared_reads_and_listing`: PASS.
- `server/tests/v2_auth.rs:11075`, `round5_expired_required_grant_strands_a_preparing_generation`: PASS. It demonstrates a PREPARING generation with an expired saved required grant; a fresh grant has a different required-set hash, while replacing the create request is rejected as `FLEET_GENERATION_EXISTS`.
- `server/tests/v2_auth.rs:11235`, `round5_a_pending_device_reads_another_devices_root_grant_in_trust_evidence`: PASS. A pending device is refused by the per-device root-grant route but receives another device's exact root-grant container in trust evidence.

## Goal-by-goal decision

### 1. Fleet grant target and listed key IDs — HOLDS

Enforcement: `src-tauri/src/fleet_custody.rs:768-778` recomputes signing and HPKE IDs from the listed public keys; `:789-800` checks the SAS; `:856-876` seals to the listed HPKE public key. Server-side checks are `server/src/routes/v2_fleet.rs:801-856` and `:864-904`; activation uses the exact required grant set at `server/src/routes/v2_fleet.rs:1583-1620`.

Tests: launcher `fleet_custody::tests` 39 passed, including `approval_is_refused_when_a_listed_key_does_not_hash_to_its_id` and `the_member_grant_is_sealed_to_the_listed_hpke_key_and_opens_with_it`; server `v2_auth` 82 passed, including `a_custodian_creates_fleet_generations_and_files_their_grants`; UI custody gate 17 passed. The inspected tests use real assertions. One pre-existing platform-specific symlink test has an environment-dependent early return; it was separately forced with `CI=1` and failed closed with the expected privilege error, so that test is not counted as passing.

### 2. Custodian and join windows — HOLDS

Enforcement: `src-tauri/src/fleet_custody.rs:697-763` persists first sight and never resets it; `:789-800` checks the ten-minute bound and exact SAS; `:928-949` checks again after the generation read. The joining device checks its own enrollment window at `src-tauri/src/lib.rs:2781-2788` and confirmation at `:2895-2927`.

Tests: `fleet_custody::tests` 39 passed (`the_custodian_window_starts_when_it_first_sees_the_row_and_never_resets`, `approval_is_refused_ten_minutes_after_first_sight`, `approval_is_refused_when_the_confirmed_code_differs`, and the in-flight close test); `custody_tests` 46 passed; E2E 17 passed, including the expired-window and first-sight cases.

### 3. JOIN pin binding and replacement — HOLDS

Enforcement: `src-tauri/src/lib.rs:2801-2820` verifies evidence and derives the binding; `:2897-2925` compares the shown anchor and SAS before `team::ledger::pin_anchor`; `src-tauri/src/team/ledger.rs:104-125` uses `ON CONFLICT DO NOTHING` and compares the existing pin. `shared/src/trust_chain.rs:675-700` defines the five-input SAS.

Tests: `shared` join-SAS 3 passed; `custody_tests` 46 passed, including server-instance, tenant, anchor, late-confirm and pin-replacement cases; E2E 17 passed (`join creates...`, expired and re-enrollment cases).

### 4. Revocation cutoff and retry — HOLDS

Enforcement: `server/src/routes/v2_device_revoke.rs:482-532` revokes device state, approvals, capability grants, root/fleet grants, leases and sessions atomically; `server/src/routes/v2_auth.rs:363-417` and `:419-429` recheck live sessions; `src-tauri/src/fleet_custody.rs:1040-1129` permits only retired/lost, blocks self-revoke, saves exact bytes, and rebuilds only a named outside-window refusal.

Tests: server `v2_auth` 82 passed (`a_revocation_blocks_new_capabilities_and_inflight_session_proofs`, `a_revoked_device_cannot_sign_in_again`); round-5 revoked-custodian probe passed; `custodian_it` 8 passed/1 intentionally ignored worker; fleet custody 39 passed, including saved-retry, stale rebuild, generic-403, nested-code, and formatted-window cases. The shipped limitation is recorded by the custody docs and test: an already revoked device retains its old fleet key until rotation.

### 5. FKEK setup lifecycle and saved-byte replay — VIOLATED

Enforcement: `src-tauri/src/fleet_custody.rs:175-200` holds/reuses one setup key; `:267-394` saves all request bytes before sending; `:409-574` replays them and releases before verified collect. Server activation requires exact terms and required-set hashes at `server/src/routes/v2_fleet.rs:1533-1620`.

Tests: existing fleet custody 39 passed, `custodian_it` 8 passed/1 ignored; round-5 expired-required-grant probe passed and exposes the defect. Scenario: a saved required device grant expires while generation 0 is PREPARING. Retrying the exact saved bytes is refused. A freshly signed grant for the same FKEK has a new container hash, so it cannot satisfy the generation's committed required-set hash; the create request cannot be replaced (`FLEET_GENERATION_EXISTS`). The generation remains PREPARING with no route in this implementation to advance or discard it. Defect: `server/src/routes/v2_fleet.rs:400-415` makes bootstrap existence permanent, while `:1583-1620` fixes activation to the original hash and there is no recovery/abort path.

### 6. Secret and token leakage — VIOLATED

Enforcement: broad redaction is at `src-tauri/src/fleet_client.rs:234-272`; label/status scrubbing is at `:719-749`. Key IDs are only length-decoded at `:723-734` and are returned unchanged. `src-tauri/src/fleet_custody.rs:730-749` places those IDs in the IPC listing.

Tests: existing leak journey passed in `custodian_it`; fleet-client redaction tests passed; UI and custody tests passed. The new `round5_device_key_ids_do_not_echo_the_session_token_body` fails with `(4, 4)`, proving a hostile server can place a bearer body in `signing_key_id` or `hpke_key_id` and have it reach both the IPC reply and saved listing state. This is a concrete defect at `src-tauri/src/fleet_client.rs:719-749`: the four key fields need the same secret scrub applied to free text before IPC/state use. No key material was printed by the probe.

### 7. Launcher revoke reasons and self-revocation — HOLDS

Enforcement: `src-tauri/src/fleet_custody.rs:1040-1046` accepts retired/lost only; `:1064-1066` blocks self-revoke; UI options are `src/features/manage-team/ui/TeamDevices.tsx:229-249`.

Tests: fleet custody 39 passed (`only_retired_and_lost_are_accepted`, `a_custodian_does_not_revoke_itself`); E2E reason-list test passed and showed exactly Retired/Lost.

### 8. Tenant device listing — HOLDS

Enforcement: `server/src/routes/v2_approval.rs:1067-1093` requires a live session in the path tenant and an active custodian; SQL at `:1095-1102` is tenant-scoped. `src-tauri/src/lib.rs:2614-2630` requires the local custodian pin.

Tests: server `v2_auth` 82 passed (`a_custodian_lists_the_tenant_devices_with_their_public_keys`, `only_an_active_custodian_session_lists_the_tenant_devices`); E2E custody gate passed.

### 9. Another device's root grants — VIOLATED

Enforcement for the direct route is correct: `server/src/routes/v2.rs:750-785` requires the caller's own session device, and `server/src/routes/v2_root_grants.rs:213-248` applies the same subject check. However, `server/src/routes/v2_trust.rs:4-12` defines trust evidence as every root grant and `:226-250` permits any tenant device session, including `pending_setup`; `:334-386` emits the exact containers.

Tests: server `v2_auth` 82 passed, including direct root-grant isolation; round-5 `round5_a_pending_device_reads_another_devices_root_grant_in_trust_evidence` passed and proves the gap. A pending device is denied the other device's direct root-grant endpoint but receives that exact signed root-grant container via `/v2/tenants/:tenant/trust-evidence`. This violates the attack goal as written.

### 10. v1-guarded routes and the three session reads — HOLDS

Enforcement: router registrations are `server/src/routes/mod.rs:34-290`; `Caller` and session parsing are `server/src/routes/v2_auth.rs:507-539`; `server/src/routes/v2.rs:114-132`, `:723-785`, and `:866-892` are the three intended session reads. Legacy handlers retain v1 auth.

Tests: `server/tests/v2_auth` 82 passed, including `the_legacy_guarded_routes_still_require_v1_auth`, `server_identity_answers_a_ticket_and_a_session_without_a_v1_token`, and `a_device_session_reads_the_active_fleet_generation_and_its_own_root_grants`.

### 11. UI fleet-key state and refused actions — HOLDS

Enforcement: backend status derives from verified usable key at `src-tauri/src/team_config.rs:320-345`; setup maps failed collect at `src-tauri/src/lib.rs:3165-3178`; UI gates readiness and actions at `src/features/manage-team/ui/TeamDevices.tsx:59-85`, `:129-150`, and `:186-249`.

Tests: Playwright custody gate 17 passed, covering unusable key, Q-18 blocked key, approval/revoke gates, refreshed keys, expired join, first-device setup and interrupted setup. E2E two-device profile journey was also run. Existing sync focused tests passed for key status, Q-18 blocks, revoked heads and no-send behavior. No backend-refused action was offered by the tested UI.

## Defects

1. `server/src/routes/v2_fleet.rs:400-415`, `:1583-1620`: an expired saved required grant strands a PREPARING generation. There is no abort, replacement, or rebind path; a fresh valid grant cannot activate because its hash differs from the committed set hash.
2. `src-tauri/src/fleet_client.rs:719-749`: listed signing and HPKE key IDs are validated but not redacted. A hostile server can echo a `v2a.` bearer body in a key-ID field, and the launcher exposes it in the device-list IPC/state projection. Reproduced by the new round-5 launcher probe (4/4 IPC and 4/4 state hits).
3. `server/src/routes/v2_trust.rs:4-12`, `:226-250`, `:334-386`: trust evidence intentionally serves every root-grant container to any tenant device session, including pending setup. The round-5 server probe reads another device's exact root grant this way.

## Verification limits

The real OS credential-store test was excluded exactly as instructed. The pre-existing `identity_authority::a_symlinked_record_is_refused` test was also run with `CI=1`; it failed at its explicit privilege guard (Windows error 1314), rather than silently returning.  The full `team::sync::tests` aggregate was attempted with the required skip and exited `0xffffffff` after 465 seconds while exercising many tests; the focused sync tests listed above all passed. The Playwright run used local loopback fixtures and installed local Chromium. No network endpoints, external services, commits, pushes, or PRs were used. The only working-copy changes are this report and the two new probe locations listed above.

VERDICT: FAIL
