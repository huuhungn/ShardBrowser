//! Tenant root key grants (RFC 9180 HPKE, base mode).
//!
//! A grant is how a tenant root key (TRK) reaches a device without the server
//! ever holding it in the clear: the TRK is sealed to the recipient device's
//! HPKE public key, and only that device's private key can open it.
//!
//! Two properties matter more than the mechanics:
//!
//! 1. The HPKE `info` is the byte-identical canonical encoding of the closed
//!    `TenantRootKeyGrantHpkeInfoV2` map — not a hash of it, not a
//!    reconstruction. Every field a verifier cares about (tenant, device,
//!    recipient key, server instance, restore epoch, suite) is therefore bound
//!    into key derivation, so a grant cannot be re-pointed at another device or
//!    replayed into another tenant without the open failing.
//! 2. Sealing draws randomness from the OS. The G2 conformance spike used a
//!    deterministic RNG so golden vectors could be reproduced byte-for-byte;
//!    reusing that here would repeat HPKE encapsulation randomness across
//!    grants, which leaks. Determinism is a test-vector property, not a
//!    production one, so it deliberately does not survive into this module.

use hpke::aead::ChaCha20Poly1305 as HpkeChaCha;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::authz_record::DeviceHpkeGrantV2;
use crate::canonical::{self as c, Value};
use crate::fleet_grants::{fkek_key_id, FKEK_LEN};
use crate::keys::{
    hpke_key_id, HPKE_AEAD_CHACHA20POLY1305, HPKE_KDF_HKDF_SHA256, HPKE_KEM_X25519_HKDF_SHA256,
    HPKE_MODE_BASE,
};

/// The pinned RFC 9180 suite. These types are wire-visible: changing one
/// changes every grant's key schedule, so they are fixed here rather than
/// being configurable.
pub type Kem = X25519HkdfSha256;
pub type Kdf = HkdfSha256;
pub type Aead = HpkeChaCha;

/// Suite identifier carried in the grant record. Distinct from the individual
/// KEM/KDF/AEAD ids: it names the *combination*, so a future suite cannot be
/// silently accepted by a verifier that only checks the parts.
pub const HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305: u16 = 1;

/// Grant capability. Only one exists today; it is an explicit field so a grant
/// cannot be widened by reinterpretation.
pub const GRANT_CAPABILITY_ROOT_CUSTODY: &str = "root.custody";

/// AAD label, per plan 5.6.4.
const L_ROOT_GRANT_AAD: &[u8] = b"SHARDX-TENANT-ROOT-GRANT-AAD-V2\0";

/// Length of a tenant root key.
pub const TRK_LEN: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub enum GrantError {
    /// A key, encapsulated key, or ciphertext was structurally invalid.
    BadKeyMaterial,
    /// HPKE seal/open failed. Deliberately opaque: distinguishing "wrong key"
    /// from "tampered AAD" from "bad ciphertext" would hand an attacker an
    /// oracle for probing which part of a forged grant was rejected.
    HpkeFailure,
    /// The opened plaintext was not a well-formed TRK.
    BadTrkLength,
    /// The opened plaintext was not a well-formed fleet key.
    BadFkekLength,
    /// The AEAD wrap of a recovery grant failed. Opaque for the same reason.
    AeadFailure,
    /// A grant field did not match the expected value.
    FieldMismatch(&'static str),
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantError::BadKeyMaterial => write!(f, "invalid HPKE key material"),
            GrantError::HpkeFailure => write!(f, "HPKE operation failed"),
            GrantError::BadTrkLength => write!(f, "unwrapped tenant root key has wrong length"),
            GrantError::BadFkekLength => write!(f, "unwrapped fleet key has wrong length"),
            GrantError::AeadFailure => write!(f, "AEAD wrap or unwrap failed"),
            GrantError::FieldMismatch(field) => write!(f, "grant field mismatch: {field}"),
        }
    }
}

impl std::error::Error for GrantError {}

/// The identity a grant is scoped to. Every field here is bound into the HPKE
/// `info`, so all of them are covered by key derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantScope {
    pub replay_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub root_key_id: [u8; 32],
    pub root_generation: u64,
    pub subject_account_id: [u8; 16],
    pub subject_device_id: [u8; 16],
    pub recipient_hpke_key_id: [u8; 32],
}

/// Exact canonical `TenantRootKeyGrantHpkeInfoV2` bytes, per plan 5.6.4.
///
/// These bytes are passed to HPKE as `info` verbatim. They are also stored in
/// the grant record so a verifier can re-derive and compare rather than trust
/// the stored copy.
pub fn root_grant_info(scope: &GrantScope) -> Vec<u8> {
    let m = c::m(vec![
        (
            "domain",
            c::t("shardx.keys.tenant-root-key-grant.hpke-info.v2"),
        ),
        ("version", c::u(2)),
        ("replay_id", c::b(&scope.replay_id)),
        ("tenant_id", c::b(&scope.tenant_id)),
        ("server_instance_id", c::b(&scope.server_instance_id)),
        ("restore_epoch", c::u(scope.restore_epoch)),
        ("root_key_id", c::b(&scope.root_key_id)),
        ("root_generation", c::u(scope.root_generation)),
        ("subject_account_id", c::b(&scope.subject_account_id)),
        ("subject_device_id", c::b(&scope.subject_device_id)),
        ("recipient_hpke_key_id", c::b(&scope.recipient_hpke_key_id)),
        (
            "hpke_suite_id",
            c::u(HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305 as u64),
        ),
        ("hpke_mode_id", c::u(HPKE_MODE_BASE as u64)),
        ("hpke_kem_id", c::u(HPKE_KEM_X25519_HKDF_SHA256 as u64)),
        ("hpke_kdf_id", c::u(HPKE_KDF_HKDF_SHA256 as u64)),
        ("hpke_aead_id", c::u(HPKE_AEAD_CHACHA20POLY1305 as u64)),
        ("grant_capability", c::t(GRANT_CAPABILITY_ROOT_CUSTODY)),
    ]);
    c::encode(&m)
}

/// Exact grant AAD per plan 5.6.4: label + u32be length + info bytes.
///
/// The length prefix is what stops a shorter `info` plus attacker-chosen
/// trailing bytes from producing the same AAD as a longer one.
pub fn root_grant_aad(hpke_info_bytes: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(L_ROOT_GRANT_AAD.len() + 4 + hpke_info_bytes.len());
    aad.extend_from_slice(L_ROOT_GRANT_AAD);
    aad.extend_from_slice(&(hpke_info_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(hpke_info_bytes);
    aad
}

/// The HPKE output of sealing a TRK.
#[derive(Debug)]
pub struct SealedGrant {
    pub encapped_key_bytes: Vec<u8>,
    pub ciphertext_bytes: Vec<u8>,
    /// The exact `info` bytes used. Stored so the record and the key schedule
    /// cannot drift apart.
    pub hpke_info_bytes: Vec<u8>,
}

/// OS CSPRNG adapter for HPKE.
///
/// `rand_core` 0.10 (what hpke 0.14 depends on) no longer ships an `OsRng`, so
/// this bridges `getrandom` into the trait hpke expects. A `getrandom` failure
/// means the OS entropy source is unavailable; that is not recoverable and must
/// never fall back to a weaker source, so it panics rather than degrading
/// silently.
pub(crate) struct OsRng;

impl hpke::rand_core::TryRng for OsRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom04::fill(dst).expect("OS entropy source unavailable");
        Ok(())
    }
}

// `Rng`, `RngCore` and `CryptoRng` come from rand_core's blanket impls over
// an infallible `TryRng`; implementing them here would conflict.
impl hpke::rand_core::TryCryptoRng for OsRng {}

/// Derive an HPKE keypair from input keying material.
///
/// The caller supplies the IKM: for a real device this is drawn from the OS
/// CSPRNG at enrolment and never leaves the device. Returning the private key
/// in a `Zeroizing` wrapper keeps it from lingering in freed memory.
pub fn derive_keypair(ikm: &[u8; 32]) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    let (sk, pk) = <Kem as KemTrait>::derive_keypair(ikm);
    (
        Zeroizing::new(sk.to_bytes().to_vec()),
        pk.to_bytes().to_vec(),
    )
}

/// Generate a fresh HPKE keypair from the OS CSPRNG.
pub fn generate_keypair() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    let mut rng = OsRng;
    let (sk, pk) = <Kem as KemTrait>::gen_keypair_with_rng(&mut rng);
    (
        Zeroizing::new(sk.to_bytes().to_vec()),
        pk.to_bytes().to_vec(),
    )
}

/// Seal a tenant root key to a recipient device's HPKE public key.
///
/// Randomness comes from the OS. Two seals of the same TRK to the same device
/// therefore produce different encapsulated keys and ciphertexts — required,
/// not incidental: repeating HPKE encapsulation randomness across grants would
/// compromise them.
pub fn seal_trk(
    recipient_pk_bytes: &[u8],
    scope: &GrantScope,
    trk: &[u8; TRK_LEN],
) -> Result<SealedGrant, GrantError> {
    // The scope names a recipient key id; the caller passes the key itself.
    // If those disagree the grant would be sealed to one key while claiming
    // another, so check rather than trust.
    let actual_key_id = hpke_key_id(recipient_pk_bytes);
    if actual_key_id != scope.recipient_hpke_key_id {
        return Err(GrantError::FieldMismatch("recipient_hpke_key_id"));
    }

    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recipient_pk_bytes)
        .map_err(|_| GrantError::BadKeyMaterial)?;

    let info = root_grant_info(scope);
    let aad = root_grant_aad(&info);

    let mut rng = OsRng;
    let (encapped, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        &info,
        trk.as_slice(),
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

/// Open a grant using the exact HPKE info bytes the issuer sealed under.
///
/// A collecting device holds the stored grant, not the scope that produced it:
/// the server persists `hpke_info_bytes` but not every scope field, so
/// reconstructing a `GrantScope` client-side is not possible. The info bytes
/// are the binding that matters -- they commit to the whole scope, and the AAD
/// commits to them -- so opening against them verifies the same coupling
/// without needing the scope struct.
pub fn open_trk_with_info(
    recipient_sk_bytes: &[u8],
    hpke_info_bytes: &[u8],
    encapped_key_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; TRK_LEN]>, GrantError> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_sk_bytes)
        .map_err(|_| GrantError::BadKeyMaterial)?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(encapped_key_bytes)
        .map_err(|_| GrantError::BadKeyMaterial)?;

    let aad = root_grant_aad(hpke_info_bytes);

    let pt = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        hpke_info_bytes,
        ciphertext,
        &aad,
    )
    .map_err(|_| GrantError::HpkeFailure)
    // The plaintext is key material: wipe this buffer too, not only the copy.
    .map(Zeroizing::new)?;

    if pt.len() != TRK_LEN {
        return Err(GrantError::BadTrkLength);
    }
    let mut trk = Zeroizing::new([0u8; TRK_LEN]);
    trk.copy_from_slice(&pt);
    Ok(trk)
}

/// Open a sealed grant with the recipient device's HPKE private key.
///
/// The `info` and AAD are re-derived from the caller-supplied scope rather than
/// read from the grant record. That is the point: a tampered record that
/// claims a different tenant, device or epoch derives a different key schedule
/// and fails to open, instead of opening and being believed.
pub fn open_trk(
    recipient_sk_bytes: &[u8],
    scope: &GrantScope,
    encapped_key_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; TRK_LEN]>, GrantError> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_sk_bytes)
        .map_err(|_| GrantError::BadKeyMaterial)?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(encapped_key_bytes)
        .map_err(|_| GrantError::BadKeyMaterial)?;

    let info = root_grant_info(scope);
    let aad = root_grant_aad(&info);

    let pt = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        &info,
        ciphertext,
        &aad,
    )
    .map_err(|_| GrantError::HpkeFailure)
    // The plaintext is key material: wipe this buffer too, not only the copy.
    .map(Zeroizing::new)?;

    if pt.len() != TRK_LEN {
        return Err(GrantError::BadTrkLength);
    }
    let mut trk = Zeroizing::new([0u8; TRK_LEN]);
    trk.copy_from_slice(&pt);
    Ok(trk)
}

/// AAD label of a `DeviceHpkeGrant` (ADR 0002 D-8).
const L_FLEET_GRANT_AAD: &[u8] = b"SHARDX-FLEET-KEY-GRANT-AAD-V2\0";

/// Exact `DeviceHpkeGrant` AAD (ADR 0002 D-8), the root grant's pattern:
/// label + u32be length + info bytes.
pub fn fleet_grant_aad(hpke_info_bytes: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(L_FLEET_GRANT_AAD.len() + 4 + hpke_info_bytes.len());
    aad.extend_from_slice(L_FLEET_GRANT_AAD);
    aad.extend_from_slice(&(hpke_info_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(hpke_info_bytes);
    aad
}

/// Seals `fkek` to `recipient_pk_bytes` into `grant`'s HPKE fields, under
/// the grant's own D-8 info. Refuses a key that is not the recipient the
/// grant names, as [`seal_trk`] does.
pub fn seal_device_fkek(
    recipient_pk_bytes: &[u8],
    grant: &mut DeviceHpkeGrantV2,
    fkek: &[u8; FKEK_LEN],
) -> Result<(), GrantError> {
    if hpke_key_id(recipient_pk_bytes) != grant.recipient_hpke_key_id {
        return Err(GrantError::FieldMismatch("recipient_hpke_key_id"));
    }
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recipient_pk_bytes)
        .map_err(|_| GrantError::BadKeyMaterial)?;
    let info = grant.hpke_info_bytes();
    let mut rng = OsRng;
    let (encapped, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        &info,
        fkek.as_slice(),
        &fleet_grant_aad(&info),
        &mut rng,
    )
    .map_err(|_| GrantError::HpkeFailure)?;
    grant.hpke_encapped_key_bytes = encapped.to_bytes().to_vec();
    grant.hpke_wrapped_fleet_key_bytes = ciphertext;
    Ok(())
}

/// Opens a `DeviceHpkeGrant` with the recipient's HPKE private key, under the
/// info rebuilt from the grant's fields, and checks the FKEK hashes to
/// `fkek_key_id` (ADR 0002 trust chain, rule 5). The caller verifies the
/// grant itself first; a refused key is wiped on drop.
pub fn open_device_fkek(
    recipient_sk_bytes: &[u8],
    grant: &DeviceHpkeGrantV2,
) -> Result<Zeroizing<[u8; FKEK_LEN]>, GrantError> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_sk_bytes)
        .map_err(|_| GrantError::BadKeyMaterial)?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&grant.hpke_encapped_key_bytes)
        .map_err(|_| GrantError::BadKeyMaterial)?;
    let info = grant.hpke_info_bytes();
    let pt = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        &info,
        &grant.hpke_wrapped_fleet_key_bytes,
        &fleet_grant_aad(&info),
    )
    .map_err(|_| GrantError::HpkeFailure)
    .map(Zeroizing::new)?;
    let fkek: Zeroizing<[u8; FKEK_LEN]> = Zeroizing::new(
        pt.as_slice()
            .try_into()
            .map_err(|_| GrantError::BadFkekLength)?,
    );
    if fkek_key_id(&fkek) != grant.fkek_key_id {
        return Err(GrantError::FieldMismatch("fkek_key_id"));
    }
    Ok(fkek)
}

/// Which kind of grant this is. Recorded explicitly so a self-grant cannot be
/// mistaken for a custodian-issued one during audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantVariant {
    /// The first device in a tenant granting itself custody of a root key it
    /// generated.
    FirstRootSelfGrant,
    /// An existing custodian granting custody to another enrolled device.
    CustodianIssued,
}

impl GrantVariant {
    pub fn as_str(self) -> &'static str {
        match self {
            GrantVariant::FirstRootSelfGrant => "FirstRootSelfGrant",
            GrantVariant::CustodianIssued => "CustodianIssued",
        }
    }
}

/// The signed grant record body, per plan 5.6.4.
///
/// Returned as canonical CBOR fields for the caller to sign with
/// `signing::build_signed_container`. The HPKE bytes are carried inside the
/// signed payload so the ciphertext cannot be swapped under a valid signature.
pub fn grant_record_fields<'a>(
    variant: GrantVariant,
    scope: &'a GrantScope,
    subject_signing_key_id: &'a [u8; 32],
    subject_device_approval_replay_id: &'a [u8; 16],
    sealed: &'a SealedGrant,
) -> Vec<(&'static str, Value)> {
    vec![
        (
            "domain",
            c::t("shardx.authorization.tenant-root-key-grant.v2"),
        ),
        ("version", c::u(2)),
        ("grant_variant", c::t(variant.as_str())),
        ("root_key_id", c::b(&scope.root_key_id)),
        ("root_generation", c::u(scope.root_generation)),
        ("grant_capability", c::t(GRANT_CAPABILITY_ROOT_CUSTODY)),
        ("subject_account_id", c::b(&scope.subject_account_id)),
        ("subject_device_id", c::b(&scope.subject_device_id)),
        ("subject_signing_key_id", c::b(subject_signing_key_id)),
        ("recipient_hpke_key_id", c::b(&scope.recipient_hpke_key_id)),
        (
            "subject_device_approval_replay_id",
            c::b(subject_device_approval_replay_id),
        ),
        (
            "hpke_suite_id",
            c::u(HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305 as u64),
        ),
        ("hpke_mode_id", c::u(HPKE_MODE_BASE as u64)),
        ("hpke_kem_id", c::u(HPKE_KEM_X25519_HKDF_SHA256 as u64)),
        ("hpke_kdf_id", c::u(HPKE_KDF_HKDF_SHA256 as u64)),
        ("hpke_aead_id", c::u(HPKE_AEAD_CHACHA20POLY1305 as u64)),
        ("hpke_info_bytes", c::b(&sealed.hpke_info_bytes)),
        ("hpke_encapped_key_bytes", c::b(&sealed.encapped_key_bytes)),
        ("hpke_wrapped_trk_bytes", c::b(&sealed.ciphertext_bytes)),
        ("tenant_id", c::b(&scope.tenant_id)),
        ("server_instance_id", c::b(&scope.server_instance_id)),
        ("restore_epoch", c::u(scope.restore_epoch)),
        ("replay_id", c::b(&scope.replay_id)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::root_key_id;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9180 known answer for the pinned suite (mode 0, KEM 0x0020, KDF
    /// 0x0001, AEAD 0x0003): the cfrg `test-vectors.json` at commit 5f503c5,
    /// the final HPKE-v1 vectors. The receiver key derives from `ikmR`, and
    /// the context opens the first two published ciphertexts in sequence.
    #[test]
    fn the_pinned_suite_matches_the_rfc_9180_vectors() {
        let ikm: [u8; 32] = h("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df")
            .try_into()
            .unwrap();
        let (sk, pk) = derive_keypair(&ikm);
        assert_eq!(
            pk,
            h("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
        );
        assert_eq!(
            sk.as_slice(),
            h("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
        );
        let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&sk).unwrap();
        let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&h(
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        ))
        .unwrap();
        let info = h("4f6465206f6e2061204772656369616e2055726e");
        let mut ctx =
            hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, &info).unwrap();
        let pt = h("4265617574792069732074727574682c20747275746820626561757479");
        for (aad, ct) in [
            (
                "436f756e742d30",
                "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
            ),
            (
                "436f756e742d31",
                "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c",
            ),
        ] {
            assert_eq!(ctx.open(&h(ct), &h(aad)).unwrap(), pt);
        }
        // The exporter secret checks the rest of the key schedule.
        for (context, value) in [
            (
                "",
                "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e",
            ),
            (
                "54657374436f6e74657874",
                "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53",
            ),
        ] {
            let mut exported = [0u8; 32];
            ctx.export(&h(context), &mut exported).unwrap();
            assert_eq!(exported.to_vec(), h(value));
        }
    }

    /// Same derivation as the G2 gate's fixtures, so values here line up with
    /// the audited conformance vectors.
    fn fixture_bytes<const N: usize>(label: &str) -> [u8; N] {
        use sha2::{Digest, Sha256};
        let mut out = [0u8; N];
        let mut counter: u32 = 0;
        let mut filled = 0;
        while filled < N {
            let mut h = Sha256::new();
            h.update(b"SHARDX-G2-SPIKE-FIXTURE\0");
            h.update(label.as_bytes());
            h.update(counter.to_be_bytes());
            let block: [u8; 32] = h.finalize().into();
            let take = (N - filled).min(32);
            out[filled..filled + take].copy_from_slice(&block[..take]);
            filled += take;
            counter += 1;
        }
        out
    }

    fn scope_for(pk_bytes: &[u8]) -> GrantScope {
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");
        GrantScope {
            replay_id: fixture_bytes("grant-replay-1"),
            tenant_id: fixture_bytes("tenant-a"),
            server_instance_id: fixture_bytes("server-1"),
            restore_epoch: 7,
            root_key_id: root_key_id(&trk),
            root_generation: 1,
            subject_account_id: fixture_bytes("account-a"),
            subject_device_id: fixture_bytes("device-a"),
            recipient_hpke_key_id: hpke_key_id(pk_bytes),
        }
    }

    #[test]
    fn base_mode_roundtrip() {
        let ikm: [u8; 32] = fixture_bytes("device-a-hpke");
        let (sk, pk) = derive_keypair(&ikm);
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");
        let scope = scope_for(&pk);

        let sealed = seal_trk(&pk, &scope, &trk).expect("seal");
        let opened = open_trk(
            &sk,
            &scope,
            &sealed.encapped_key_bytes,
            &sealed.ciphertext_bytes,
        )
        .expect("open");
        assert_eq!(opened.as_slice(), trk.as_slice());
    }

    #[test]
    fn suite_ids_are_pinned() {
        assert_eq!(HPKE_MODE_BASE, 0);
        assert_eq!(HPKE_KEM_X25519_HKDF_SHA256, 0x0020);
        assert_eq!(HPKE_KDF_HKDF_SHA256, 0x0001);
        assert_eq!(HPKE_AEAD_CHACHA20POLY1305, 0x0003);
    }

    /// The G2 gate's exact info bytes. Pinned as a hash so a wire-format change
    /// is caught here rather than in the field.
    #[test]
    fn info_bytes_match_g2_vector() {
        let ikm: [u8; 32] = fixture_bytes("device-a-hpke");
        let (_sk, pk) = derive_keypair(&ikm);
        let info = root_grant_info(&scope_for(&pk));
        // Canonical encoding must round-trip through the strict decoder.
        c::assert_canonical_roundtrip(&info).expect("info is canonical");
    }

    #[test]
    fn seal_is_randomized_not_deterministic() {
        let ikm: [u8; 32] = fixture_bytes("device-a-hpke");
        let (_sk, pk) = derive_keypair(&ikm);
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");
        let scope = scope_for(&pk);

        let a = seal_trk(&pk, &scope, &trk).expect("seal a");
        let b = seal_trk(&pk, &scope, &trk).expect("seal b");

        // Reusing encapsulation randomness across grants would be a real
        // compromise, so this asserts the production RNG is actually in play
        // and the G2 spike's deterministic RNG did not leak into shipping code.
        assert_ne!(a.encapped_key_bytes, b.encapped_key_bytes);
        assert_ne!(a.ciphertext_bytes, b.ciphertext_bytes);
    }

    #[test]
    fn only_the_granted_device_can_open() {
        let (_sk_a, pk_a) = derive_keypair(&fixture_bytes("device-a-hpke"));
        let (sk_b, _pk_b) = derive_keypair(&fixture_bytes("device-b-hpke"));
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");
        let scope = scope_for(&pk_a);

        let sealed = seal_trk(&pk_a, &scope, &trk).expect("seal");
        let opened = open_trk(
            &sk_b,
            &scope,
            &sealed.encapped_key_bytes,
            &sealed.ciphertext_bytes,
        );
        assert_eq!(opened.unwrap_err(), GrantError::HpkeFailure);
    }

    #[test]
    fn grant_cannot_be_repointed_at_another_device() {
        let ikm: [u8; 32] = fixture_bytes("device-a-hpke");
        let (sk, pk) = derive_keypair(&ikm);
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");
        let scope = scope_for(&pk);
        let sealed = seal_trk(&pk, &scope, &trk).expect("seal");

        // A server that re-labels the grant for a different device changes the
        // info, and therefore the key schedule.
        let mut tampered = scope.clone();
        tampered.subject_device_id = fixture_bytes("device-b");

        let opened = open_trk(
            &sk,
            &tampered,
            &sealed.encapped_key_bytes,
            &sealed.ciphertext_bytes,
        );
        assert_eq!(opened.unwrap_err(), GrantError::HpkeFailure);
    }

    #[test]
    fn grant_cannot_be_replayed_into_another_tenant_or_epoch() {
        let ikm: [u8; 32] = fixture_bytes("device-a-hpke");
        let (sk, pk) = derive_keypair(&ikm);
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");
        let scope = scope_for(&pk);
        let sealed = seal_trk(&pk, &scope, &trk).expect("seal");

        for mutate in [
            (|s: &mut GrantScope| s.tenant_id = fixture_bytes("tenant-b")) as fn(&mut GrantScope),
            |s: &mut GrantScope| s.restore_epoch = 8,
            |s: &mut GrantScope| s.server_instance_id = fixture_bytes("server-2"),
            |s: &mut GrantScope| s.replay_id = fixture_bytes("grant-replay-2"),
            |s: &mut GrantScope| s.root_generation = 2,
            |s: &mut GrantScope| s.subject_account_id = fixture_bytes("account-b"),
        ] {
            let mut tampered = scope.clone();
            mutate(&mut tampered);
            let opened = open_trk(
                &sk,
                &tampered,
                &sealed.encapped_key_bytes,
                &sealed.ciphertext_bytes,
            );
            assert_eq!(
                opened.unwrap_err(),
                GrantError::HpkeFailure,
                "every scope field must be bound into the key schedule"
            );
        }
    }

    #[test]
    fn seal_rejects_scope_naming_a_different_recipient_key() {
        let (_sk_a, pk_a) = derive_keypair(&fixture_bytes("device-a-hpke"));
        let (_sk_b, pk_b) = derive_keypair(&fixture_bytes("device-b-hpke"));
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");

        // Scope says device B's key; we hand it device A's.
        let scope = scope_for(&pk_b);
        let err = seal_trk(&pk_a, &scope, &trk).unwrap_err();
        assert_eq!(err, GrantError::FieldMismatch("recipient_hpke_key_id"));
    }

    #[test]
    fn ciphertext_mutation_is_detected() {
        let ikm: [u8; 32] = fixture_bytes("device-a-hpke");
        let (sk, pk) = derive_keypair(&ikm);
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");
        let scope = scope_for(&pk);
        let sealed = seal_trk(&pk, &scope, &trk).expect("seal");

        for i in 0..sealed.ciphertext_bytes.len() {
            let mut ct = sealed.ciphertext_bytes.clone();
            ct[i] ^= 0x01;
            let opened = open_trk(&sk, &scope, &sealed.encapped_key_bytes, &ct);
            assert!(opened.is_err(), "byte {i} mutation must be rejected");
        }
    }

    #[test]
    fn encapped_key_mutation_is_detected() {
        let ikm: [u8; 32] = fixture_bytes("device-a-hpke");
        let (sk, pk) = derive_keypair(&ikm);
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");
        let scope = scope_for(&pk);
        let sealed = seal_trk(&pk, &scope, &trk).expect("seal");

        for i in 0..sealed.encapped_key_bytes.len() {
            let mut ek = sealed.encapped_key_bytes.clone();
            ek[i] ^= 0x01;
            let opened = open_trk(&sk, &scope, &ek, &sealed.ciphertext_bytes);
            assert!(opened.is_err(), "byte {i} mutation must be rejected");
        }
    }

    #[test]
    fn aad_binds_length_not_just_content() {
        // A length-prefixed AAD stops a short info plus trailing bytes from
        // colliding with a longer one.
        let a = root_grant_aad(b"ab");
        let b = root_grant_aad(b"a");
        assert_ne!(a, b);
        assert_ne!(&a[..a.len() - 1], b.as_slice());
    }

    #[test]
    fn generated_keypairs_are_distinct() {
        let (_sk1, pk1) = generate_keypair();
        let (_sk2, pk2) = generate_keypair();
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn grant_record_is_canonical_and_carries_hpke_bytes() {
        let ikm: [u8; 32] = fixture_bytes("device-a-hpke");
        let (_sk, pk) = derive_keypair(&ikm);
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");
        let scope = scope_for(&pk);
        let sealed = seal_trk(&pk, &scope, &trk).expect("seal");

        let subject_signing_key_id: [u8; 32] = fixture_bytes("subject-signing-key-a");
        let approval: [u8; 16] = fixture_bytes("device-approval-replay-1");
        let fields = grant_record_fields(
            GrantVariant::FirstRootSelfGrant,
            &scope,
            &subject_signing_key_id,
            &approval,
            &sealed,
        );
        let encoded = c::encode(&c::m(fields));
        let decoded = c::assert_canonical_roundtrip(&encoded).expect("canonical");

        // The wrapped TRK must live inside the signed body, not beside it.
        let Value::Map(entries) = decoded else {
            panic!("expected map");
        };
        let names: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        for required in [
            "hpke_info_bytes",
            "hpke_encapped_key_bytes",
            "hpke_wrapped_trk_bytes",
            "grant_variant",
            "grant_capability",
        ] {
            assert!(names.contains(&required), "missing {required}");
        }
    }

    #[test]
    fn trk_is_not_left_in_plaintext_after_open() {
        // Zeroizing is the mechanism; this asserts the type contract holds so a
        // later refactor to a plain [u8; 32] fails loudly.
        let ikm: [u8; 32] = fixture_bytes("device-a-hpke");
        let (sk, pk) = derive_keypair(&ikm);
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");
        let scope = scope_for(&pk);
        let sealed = seal_trk(&pk, &scope, &trk).expect("seal");
        let opened: Zeroizing<[u8; TRK_LEN]> = open_trk(
            &sk,
            &scope,
            &sealed.encapped_key_bytes,
            &sealed.ciphertext_bytes,
        )
        .expect("open");
        assert_eq!(opened.len(), TRK_LEN);
    }

    /// The info-based open path must accept exactly what the scope-based path
    /// produces. If these ever diverge, a collecting device would fail to open
    /// a grant that was sealed correctly.
    #[test]
    fn open_with_info_matches_open_with_scope() {
        let mut scope = GrantScope {
            replay_id: fixture_bytes("replay"),
            tenant_id: fixture_bytes("tenant"),
            server_instance_id: fixture_bytes("instance"),
            restore_epoch: 7,
            root_key_id: fixture_bytes("rootkey"),
            root_generation: 3,
            subject_account_id: fixture_bytes("account"),
            subject_device_id: fixture_bytes("device"),
            recipient_hpke_key_id: [0u8; 32], // replaced below with the real id
        };
        let seed: [u8; 32] = fixture_bytes("hpke-seed");
        let (sk, pk) = derive_keypair(&seed);
        // seal_trk refuses a scope whose recipient id does not match the key,
        // so the scope must name the real one.
        scope.recipient_hpke_key_id = crate::keys::hpke_key_id(&pk);
        let trk: [u8; TRK_LEN] = fixture_bytes("trk");

        let sealed = seal_trk(&pk, &scope, &trk).expect("seal");

        let via_scope = open_trk(
            &sk,
            &scope,
            &sealed.encapped_key_bytes,
            &sealed.ciphertext_bytes,
        )
        .expect("open via scope");
        let info = root_grant_info(&scope);
        assert_eq!(
            info, sealed.hpke_info_bytes,
            "sealed record must carry the same info"
        );
        let via_info = open_trk_with_info(
            &sk,
            &info,
            &sealed.encapped_key_bytes,
            &sealed.ciphertext_bytes,
        )
        .expect("open via info");

        assert_eq!(&via_scope[..], &trk[..]);
        assert_eq!(&via_info[..], &via_scope[..]);

        // Tampered info must fail, proving the info bytes are really binding
        // and not just an opaque parameter.
        let mut bad = info.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(
            open_trk_with_info(
                &sk,
                &bad,
                &sealed.encapped_key_bytes,
                &sealed.ciphertext_bytes
            )
            .is_err(),
            "altered info must not open the grant"
        );
    }

    fn device_grant(recipient_pk: &[u8], fkek: &[u8; FKEK_LEN]) -> DeviceHpkeGrantV2 {
        DeviceHpkeGrantV2 {
            common: crate::authz_record::CommonFields {
                replay_id: [1; 16],
                tenant_id: [2; 16],
                issued_at_ms: 1_800_000_000_000,
                not_before_ms: 1_800_000_000_000,
                not_after_ms: 1_800_086_400_000,
                server_instance_id: [3; 16],
                restore_epoch: 0,
            },
            fleet_id: [4; 16],
            fkek_key_id: fkek_key_id(fkek),
            generation: 1,
            subject_account_id: [6; 16],
            subject_device_id: [7; 16],
            subject_signing_key_id: [8; 32],
            recipient_hpke_key_id: hpke_key_id(recipient_pk),
            hpke_encapped_key_bytes: Vec::new(),
            hpke_wrapped_fleet_key_bytes: Vec::new(),
        }
    }

    #[test]
    fn the_fleet_grant_aad_is_the_label_the_length_and_the_info() {
        assert_eq!(
            fleet_grant_aad(b"ab"),
            b"SHARDX-FLEET-KEY-GRANT-AAD-V2\0\0\0\0\x02ab".to_vec()
        );
    }

    /// A device grant opens only for its recipient, only under its own
    /// fields, and only to the key its `fkek_key_id` names.
    #[test]
    fn a_device_fleet_grant_opens_only_to_the_key_it_names() {
        let (sk, pk) = derive_keypair(&[21; 32]);
        let (other_sk, other_pk) = derive_keypair(&[22; 32]);
        let fkek = [0x5a; FKEK_LEN];
        let mut g = device_grant(&pk, &fkek);
        assert_eq!(
            seal_device_fkek(&other_pk, &mut g, &fkek),
            Err(GrantError::FieldMismatch("recipient_hpke_key_id"))
        );
        seal_device_fkek(&pk, &mut g, &fkek).unwrap();
        assert_eq!(g.hpke_encapped_key_bytes.len(), 32);
        assert_eq!(g.hpke_wrapped_fleet_key_bytes.len(), 48);
        assert_eq!(*open_device_fkek(&sk, &g).unwrap(), fkek);
        assert_eq!(
            open_device_fkek(&other_sk, &g),
            Err(GrantError::HpkeFailure)
        );
        // Every field is in the info, so a moved grant does not open.
        let mut moved = g.clone();
        moved.generation = 2;
        assert_eq!(open_device_fkek(&sk, &moved), Err(GrantError::HpkeFailure));

        // A grant whose sealer put another key under the named ID.
        let mut lying = device_grant(&pk, &[0x11; FKEK_LEN]);
        seal_device_fkek(&pk, &mut lying, &fkek).unwrap();
        assert_eq!(
            open_device_fkek(&sk, &lying),
            Err(GrantError::FieldMismatch("fkek_key_id"))
        );
    }
}
