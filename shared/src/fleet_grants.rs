//! Fleet key encryption key (FKEK) grants (RFC 9180 HPKE, base mode).
//!
//! The FKEK is the key profile snapshots are actually encrypted under. It is a
//! per-fleet key with its own generation lifetime, not something derived from
//! the tenant root key: the root key authorises custody, the fleet key does
//! the wrapping. Deriving one from the other would tie the two lifetimes
//! together, so rotating a fleet key would force a root rotation, and a device
//! removed from a fleet would still hold the material to decrypt its
//! snapshots.
//!
//! This module implements the `DeviceHpkeGrant` variant from plan 5.6: a
//! custodian device that already holds the FKEK seals it to an authorised
//! device's HPKE public key. As with root grants, the HPKE `info` is the exact
//! canonical encoding of the closed info map, so fleet, generation, key id and
//! recipient are all bound into key derivation — a grant cannot be re-pointed
//! at another device, fleet or generation without the open failing.

use hpke::Kem as KemTrait;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::canonical::{self as c};
use crate::grants::{
    Aead, GrantError, Kdf, Kem, OsRng, SealedGrant,
    HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305,
};
use crate::keys::hpke_key_id;

/// An FKEK is a 32-byte symmetric key.
pub const FKEK_LEN: usize = 32;

/// The identity a fleet key grant is scoped to. Every field is bound into the
/// HPKE `info`, so all of them are covered by key derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetGrantScope {
    pub replay_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub fleet_id: [u8; 16],
    pub fkek_key_id: [u8; 32],
    pub generation: u64,
    pub subject_account_id: [u8; 16],
    pub subject_device_id: [u8; 16],
    pub recipient_hpke_key_id: [u8; 32],
}

/// Exact canonical `FleetKeyGrantHpkeInfoV2` bytes.
///
/// Passed to HPKE as `info` verbatim, and stored alongside the grant so a
/// verifier can re-derive and compare rather than trust the stored copy.
pub fn fleet_grant_info(scope: &FleetGrantScope) -> Vec<u8> {
    let m = c::m(vec![
        (
            "domain",
            c::t("shardx.keys.fleet-key-grant.device-hpke.hpke-info.v2"),
        ),
        ("version", c::u(2)),
        ("replay_id", c::b(&scope.replay_id)),
        ("tenant_id", c::b(&scope.tenant_id)),
        ("server_instance_id", c::b(&scope.server_instance_id)),
        ("restore_epoch", c::u(scope.restore_epoch)),
        ("fleet_id", c::b(&scope.fleet_id)),
        ("fkek_key_id", c::b(&scope.fkek_key_id)),
        ("generation", c::u(scope.generation)),
        ("subject_account_id", c::b(&scope.subject_account_id)),
        ("subject_device_id", c::b(&scope.subject_device_id)),
        ("recipient_hpke_key_id", c::b(&scope.recipient_hpke_key_id)),
        (
            "hpke_suite_id",
            c::u(HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305 as u64),
        ),
    ]);
    c::encode(&m)
}

/// AAD for the HPKE seal: the info bytes, under their own domain.
///
/// Distinct from the info itself so that a value which somehow round-tripped as
/// info cannot also be replayed as AAD.
fn fleet_grant_aad(info: &[u8]) -> Vec<u8> {
    let m = c::m(vec![
        (
            "domain",
            c::t("shardx.keys.fleet-key-grant.device-hpke.aad.v2"),
        ),
        ("version", c::u(2)),
        ("hpke_info_bytes", c::b(info)),
    ]);
    c::encode(&m)
}

/// Seal a fleet key to a recipient device's HPKE public key.
///
/// Randomness comes from the OS: two seals of the same FKEK to the same device
/// produce different encapsulated keys and ciphertexts, which is required
/// rather than incidental.
pub fn seal_fkek(
    recipient_pk_bytes: &[u8],
    scope: &FleetGrantScope,
    fkek: &[u8; FKEK_LEN],
) -> Result<SealedGrant, GrantError> {
    // The scope names a recipient key id; the caller passes the key itself. If
    // they disagree the grant would be sealed to one key while claiming
    // another, so check rather than trust.
    if hpke_key_id(recipient_pk_bytes) != scope.recipient_hpke_key_id {
        return Err(GrantError::FieldMismatch("recipient_hpke_key_id"));
    }

    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recipient_pk_bytes)
        .map_err(|_| GrantError::BadKeyMaterial)?;

    let info = fleet_grant_info(scope);
    let aad = fleet_grant_aad(&info);

    let mut rng = OsRng;
    let (encapped, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        &info,
        fkek.as_slice(),
        &aad,
        &mut rng,
    )
    .map_err(|_| GrantError::HpkeFailure)?;

    Ok(SealedGrant {
        encapped_key_bytes: encapped.to_bytes().to_vec(),
        ciphertext_bytes: ciphertext,
        hpke_info_bytes: info,
    })
}

/// Open a fleet key grant using the exact HPKE info bytes the issuer sealed
/// under.
///
/// A collecting device holds the stored grant, not the scope that produced it,
/// so it cannot rebuild the info map. The stored bytes are not trusted blindly:
/// they are the AAD as well as the info, so tampering with them fails the open.
pub fn open_fkek_with_info(
    recipient_sk_bytes: &[u8],
    grant: &SealedGrant,
) -> Result<Zeroizing<[u8; FKEK_LEN]>, GrantError> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_sk_bytes)
        .map_err(|_| GrantError::BadKeyMaterial)?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&grant.encapped_key_bytes)
        .map_err(|_| GrantError::BadKeyMaterial)?;

    let aad = fleet_grant_aad(&grant.hpke_info_bytes);

    let pt = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        &grant.hpke_info_bytes,
        &grant.ciphertext_bytes,
        &aad,
    )
    .map_err(|_| GrantError::HpkeFailure)
    // The plaintext is key material: wipe this buffer too, not only the copy.
    .map(Zeroizing::new)?;

    if pt.len() != FKEK_LEN {
        return Err(GrantError::BadFkekLength);
    }
    let mut out = Zeroizing::new([0u8; FKEK_LEN]);
    out.copy_from_slice(&pt);
    Ok(out)
}

/// Open a fleet key grant, re-deriving the info from a scope the caller
/// already trusts and requiring it to match the stored bytes.
///
/// Preferred over [`open_fkek_with_info`] when the caller knows the scope: it
/// proves the stored info describes the grant the caller expected.
pub fn open_fkek(
    recipient_sk_bytes: &[u8],
    scope: &FleetGrantScope,
    grant: &SealedGrant,
) -> Result<Zeroizing<[u8; FKEK_LEN]>, GrantError> {
    let expected = fleet_grant_info(scope);
    if expected != grant.hpke_info_bytes {
        return Err(GrantError::FieldMismatch("hpke_info_bytes"));
    }
    open_fkek_with_info(recipient_sk_bytes, grant)
}

/// Generate a fresh fleet key from the OS CSPRNG.
///
/// A `getrandom` failure means the OS entropy source is unavailable. That is
/// not recoverable and must never fall back to a weaker source, so it panics
/// rather than degrading silently.
pub fn generate_fkek() -> Zeroizing<[u8; FKEK_LEN]> {
    let mut fkek = Zeroizing::new([0u8; FKEK_LEN]);
    getrandom04::fill(fkek.as_mut_slice()).expect("OS entropy source unavailable");
    fkek
}

/// The key id for a fleet key: a domain-separated hash of the key itself.
///
/// Domain separation matters — an FKEK and a TRK of the same bytes must not
/// produce the same id, or a grant for one could be indexed as the other.
pub fn fkek_key_id(fkek: &[u8; FKEK_LEN]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let m = c::m(vec![
        ("domain", c::t("shardx.keys.fleet-key-id.v2")),
        ("version", c::u(2)),
        ("key_bytes", c::b(fkek.as_slice())),
    ]);
    let mut h = Sha256::new();
    h.update(c::encode(&m));
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::derive_keypair;

    fn scope(pk: &[u8]) -> FleetGrantScope {
        FleetGrantScope {
            replay_id: [1u8; 16],
            tenant_id: [2u8; 16],
            server_instance_id: [3u8; 16],
            restore_epoch: 7,
            fleet_id: [4u8; 16],
            fkek_key_id: [5u8; 32],
            generation: 3,
            subject_account_id: [6u8; 16],
            subject_device_id: [7u8; 16],
            recipient_hpke_key_id: hpke_key_id(pk),
        }
    }

    #[test]
    fn a_sealed_fleet_key_opens_to_the_exact_same_bytes() {
        let (sk, pk) = derive_keypair(&[9u8; 32]);
        let fkek = generate_fkek();
        let s = scope(&pk);

        let grant = seal_fkek(&pk, &s, &fkek).expect("seal");
        let opened = open_fkek(&sk, &s, &grant).expect("open");

        assert_eq!(opened.as_slice(), fkek.as_slice());
    }

    #[test]
    fn opening_with_only_the_stored_info_agrees_with_the_scoped_open() {
        let (sk, pk) = derive_keypair(&[10u8; 32]);
        let fkek = generate_fkek();
        let s = scope(&pk);

        let grant = seal_fkek(&pk, &s, &fkek).expect("seal");
        let a = open_fkek(&sk, &s, &grant).expect("scoped open");
        let b = open_fkek_with_info(&sk, &grant).expect("info open");

        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn another_device_cannot_open_a_grant_addressed_elsewhere() {
        let (_, pk) = derive_keypair(&[11u8; 32]);
        let (other_sk, _) = derive_keypair(&[12u8; 32]);
        let fkek = generate_fkek();
        let s = scope(&pk);

        let grant = seal_fkek(&pk, &s, &fkek).expect("seal");

        assert!(matches!(
            open_fkek_with_info(&other_sk, &grant),
            Err(GrantError::HpkeFailure)
        ));
    }

    #[test]
    fn tampering_with_the_stored_info_fails_the_open() {
        let (sk, pk) = derive_keypair(&[13u8; 32]);
        let fkek = generate_fkek();
        let s = scope(&pk);

        let mut grant = seal_fkek(&pk, &s, &fkek).expect("seal");
        // The info is both the HPKE info and the AAD, so a single flipped bit
        // has to break the open rather than merely being ignored.
        grant.hpke_info_bytes[0] ^= 0x01;

        assert!(matches!(
            open_fkek_with_info(&sk, &grant),
            Err(GrantError::HpkeFailure)
        ));
    }

    #[test]
    fn a_grant_cannot_be_replayed_into_a_different_generation() {
        let (sk, pk) = derive_keypair(&[14u8; 32]);
        let fkek = generate_fkek();
        let s = scope(&pk);

        let grant = seal_fkek(&pk, &s, &fkek).expect("seal");

        // Same grant bytes, but the reader expects the next generation. The
        // generation is bound into the info, so this must not open.
        let mut other = s.clone();
        other.generation += 1;

        assert!(matches!(
            open_fkek(&sk, &other, &grant),
            Err(GrantError::FieldMismatch("hpke_info_bytes"))
        ));
    }

    #[test]
    fn a_grant_cannot_be_replayed_into_a_different_fleet() {
        let (sk, pk) = derive_keypair(&[15u8; 32]);
        let fkek = generate_fkek();
        let s = scope(&pk);

        let grant = seal_fkek(&pk, &s, &fkek).expect("seal");

        let mut other = s.clone();
        other.fleet_id = [99u8; 16];

        assert!(matches!(
            open_fkek(&sk, &other, &grant),
            Err(GrantError::FieldMismatch("hpke_info_bytes"))
        ));
    }

    #[test]
    fn sealing_refuses_a_scope_naming_a_different_recipient_key() {
        let (_, pk) = derive_keypair(&[16u8; 32]);
        let fkek = generate_fkek();
        let mut s = scope(&pk);
        s.recipient_hpke_key_id = [0u8; 32];

        assert!(matches!(
            seal_fkek(&pk, &s, &fkek),
            Err(GrantError::FieldMismatch("recipient_hpke_key_id"))
        ));
    }

    #[test]
    fn two_seals_of_one_key_differ() {
        let (_, pk) = derive_keypair(&[17u8; 32]);
        let fkek = generate_fkek();
        let s = scope(&pk);

        let a = seal_fkek(&pk, &s, &fkek).expect("seal a");
        let b = seal_fkek(&pk, &s, &fkek).expect("seal b");

        // Repeating HPKE encapsulation randomness across grants would leak, so
        // identical inputs must still produce different ciphertexts.
        assert_ne!(a.encapped_key_bytes, b.encapped_key_bytes);
        assert_ne!(a.ciphertext_bytes, b.ciphertext_bytes);
    }

    #[test]
    fn a_fleet_key_id_is_not_the_root_key_id_of_the_same_bytes() {
        let key = [21u8; 32];
        // Domain separation: the same 32 bytes used as a fleet key and as a
        // root key must not collide, or a grant for one could be indexed as
        // the other.
        assert_ne!(fkek_key_id(&key), crate::keys::root_key_id(&key));
    }
}
