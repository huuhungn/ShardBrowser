# Trust boundaries (G2-61)

The plan's trust model (sections 2.1 and 12.4) splits the team server in two:

- **Trusted control plane.** The coordinator process and the integrity and
  freshness of the live coordination and RBAC state in SQLite: accounts,
  sessions, roles, capabilities, revocation, leases and fences, the active
  generation, idempotency and audit.
- **Untrusted artifact stores.** Ciphertext and signed bytes in the database,
  the blob directory, logs and backups. They must not reveal plaintext, and a
  client must detect any change to them.

This page maps each boundary to the test that holds it. Rows marked
"outside the guarantee" are limits the product states, not defects to fix.

## Artifact stores: client-detected, confidentiality-preserving

| Threat | Result | Evidence |
| --- | --- | --- |
| Read a stored snapshot or backup | No plaintext: the body is sealed; the KEK needs the fleet key or the passphrase. | `backup_file_roundtrip::the_ciphertext_does_not_contain_the_plaintext` |
| Change any byte of a container | Refused before restore. | `backup::tests::every_single_byte_mutation_is_detected`, `backup_file_roundtrip::a_tampered_backup_body_is_refused` |
| Truncate a container | Refused; the profile is untouched. | `backup::tests::truncation_at_any_length_is_detected`, `backup_file_roundtrip::a_truncated_backup_is_refused_and_leaves_the_destination_untouched` |
| Splice frames from another container | Refused. | `backup::tests::cross_envelope_frame_splice_is_rejected` |
| Return another profile's genuine snapshot | Refused before the profile is touched: the signed intent names the profile it was sealed for. | `backup_file::tests::a_snapshot_sealed_for_another_profile_is_refused`, `sync_cmd::tests::pull_refuses_another_profiles_snapshot` |
| Open with another fleet's key | Refused. | `backup_file::tests::another_fleet_key_cannot_open_it`, `fleet_sync_it` (outsider device) |
| Replay a grant into another tenant, fleet, generation or epoch | Refused. | `grants::tests::grant_cannot_be_replayed_into_another_tenant_or_epoch`, `fleet_grants::tests::a_grant_cannot_be_replayed_into_a_different_*` |
| Tamper with a stored grant's HPKE info | The open fails. | `fleet_grants::tests::tampering_with_the_stored_info_fails_the_open` |
| Tamper with a stored identity record | Reported, and v2 writes stop (423). | `identity_authority::show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest` |
| Invent a device in the trust evidence | The client's trust-chain verifier refuses a device with no approved path to the pinned anchor. | `trust_chain` tests (G2 W3b) |
| Corrupt or archive-bomb a snapshot | Refused during unpack. | `snapshot::tests::unpack_rejects_*` |

## Control plane: fail closed when trust is lost

| Event | Result | Evidence |
| --- | --- | --- |
| Foreign-key violations found at startup | v2 writes refused with `CONTROL_PLANE_INTEGRITY_UNTRUSTED` (423); v1 keeps running. | `integrity::tests` (foreign-key case), `main.rs` startup pass |
| The integrity pass itself fails | Same refusal. | `main.rs` |
| A device record with bad keys, or a grant whose bindings do not hold | Quarantined, never served. | `integrity::tests::wrong_domain_hpke_ids_are_quarantined_once`, `quarantine` tests |
| An interrupted server init | Reported and never repaired automatically. | `identity_authority::an_interrupted_init_is_reported_and_never_repaired` |

Recovery from a refusal is an operator action: restore the live database from
trusted evidence. Artifact signatures cannot repair an authorization rollback.

## Outside the guarantee

Someone who can write to, or roll back, the live control-plane database, or
who controls the coordinator process, can:

- re-enable a revoked account or device;
- select an older generation, or mint leases and fences;
- suppress or rewrite audit;
- serve an older snapshot of a profile as the current head.

Signed artifacts still cannot be forged or read by that attacker without the
keys, but the product does not claim to prevent or detect these control-plane
attacks within one restore epoch. The external epoch record covers authorized
full restores only. No signed authorization transparency log is planned for
v0.2.x.

## Fleet keys from the server

The team server is not trusted to distribute fleet keys until grants carry an
issuer the device can verify. Since 2.4.3 the launcher counts fleet key grants
and never opens or caches them, and push always seals under the team
passphrase (`custody_tests::a_server_delivered_fleet_key_is_counted_but_never_cached`,
`sync_cmd::tests::push_seals_under_the_passphrase_even_with_a_cached_fleet_key`).
Pull still tries keys cached by 2.4.2; a snapshot opened with one of those is
only as trustworthy as the server that delivered the key.
