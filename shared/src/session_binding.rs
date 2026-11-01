//! Proof-bound enrollment and device sessions (ADR 0001 R2).
//!
//! A pre-device ticket becomes a device session only after two proofs over a
//! server-issued binding: the candidate signs the binding with its Ed25519
//! key, and it decrypts a secret the server sealed to its HPKE key. Each proof
//! covers a different private key; the signature alone proves nothing about
//! the HPKE key.
//!
//! Both bindings are closed `CanonicalCborV2` maps, capped at
//! [`MAX_BINDING_BYTES`]. Parsing rejects an unknown, missing or mistyped
//! field, a suite other than 1, and a stored key ID that is not the R4
//! derivation of its key, so a client checks the whole binding before it
//! signs or decrypts anything.

use ed25519_dalek::SigningKey;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};
use crate::grants::{Aead, Kdf, Kem, OsRng, HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305};
use crate::keys::{fill_random, hpke_key_id, signing_key_id};
use crate::signing::{
    verify_message_strict, Ed25519VerifyingKey, SignError, ED25519_SIG_LEN,
    SIGNATURE_SUITE_ID_ED25519,
};

pub const DOMAIN_ENROLLMENT_BINDING: &str = "shardx.auth.enrollment-binding.v2";
pub const DOMAIN_DEVICE_SESSION_BINDING: &str = "shardx.auth.device-session-binding.v2";
pub const BINDING_VERSION: u16 = 2;
/// Cap on either binding's canonical bytes, checked before decoding.
pub const MAX_BINDING_BYTES: usize = 4096;

pub const L_ENROLLMENT_BINDING: &str = "SHARDX-ENROLLMENT-BINDING-V2\0";
pub const L_DEVICE_SESSION_POP: &str = "SHARDX-DEVICE-SESSION-POP-V2\0";
pub const HPKE_POP_INFO: &[u8] = b"SHARDX-DEVICE-SESSION-HPKE-POP-V2\0";

pub const POP_SECRET_LEN: usize = 32;
/// Suite 1: an X25519 encapsulated key, and the secret plus its 16-byte tag.
pub const POP_ENCAPPED_LEN: usize = 32;
pub const POP_CIPHERTEXT_LEN: usize = POP_SECRET_LEN + 16;

/// The fields both bindings share. The server fills every one; a client only
/// compares them with what it expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingFields {
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub tenant_id: [u8; 16],
    pub account_id: [u8; 16],
    pub pre_device_session_id: [u8; 16],
    pub challenge_id: [u8; 16],
    pub nonce: [u8; 16],
    pub signing_suite: u16,
    pub signing_public_key: [u8; 32],
    pub signing_key_id: [u8; 32],
    pub hpke_suite: u16,
    pub hpke_public_key: [u8; 32],
    pub hpke_key_id: [u8; 32],
    pub expires_at_ms: u64,
}

impl BindingFields {
    fn put(&self, out: &mut Vec<(&'static str, Value)>) {
        out.extend([
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
            ("tenant_id", c::b(&self.tenant_id)),
            ("account_id", c::b(&self.account_id)),
            ("pre_device_session_id", c::b(&self.pre_device_session_id)),
            ("challenge_id", c::b(&self.challenge_id)),
            ("nonce", c::b(&self.nonce)),
            ("signing_suite", c::u(self.signing_suite.into())),
            ("signing_public_key", c::b(&self.signing_public_key)),
            ("signing_key_id", c::b(&self.signing_key_id)),
            ("hpke_suite", c::u(self.hpke_suite.into())),
            ("hpke_public_key", c::b(&self.hpke_public_key)),
            ("hpke_key_id", c::b(&self.hpke_key_id)),
            ("expires_at_ms", c::u(self.expires_at_ms)),
        ]);
    }

    fn take(f: &mut Fields) -> Result<Self, RecordError> {
        let fields = Self {
            server_instance_id: f.fixed("server_instance_id")?,
            restore_epoch: f.uint("restore_epoch")?,
            tenant_id: f.fixed("tenant_id")?,
            account_id: f.fixed("account_id")?,
            pre_device_session_id: f.fixed("pre_device_session_id")?,
            challenge_id: f.fixed("challenge_id")?,
            nonce: f.fixed("nonce")?,
            signing_suite: f.u16("signing_suite")?,
            signing_public_key: f.fixed("signing_public_key")?,
            signing_key_id: f.fixed("signing_key_id")?,
            hpke_suite: f.u16("hpke_suite")?,
            hpke_public_key: f.fixed("hpke_public_key")?,
            hpke_key_id: f.fixed("hpke_key_id")?,
            expires_at_ms: f.uint("expires_at_ms")?,
        };
        fields.check()?;
        Ok(fields)
    }

    /// Suite 1 only, a usable Ed25519 point, and both IDs derived by role (R4).
    fn check(&self) -> Result<(), RecordError> {
        if self.signing_suite != SIGNATURE_SUITE_ID_ED25519 {
            return Err(RecordError::Unsupported {
                field: "signing_suite",
                id: self.signing_suite.into(),
            });
        }
        if self.hpke_suite != HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305 {
            return Err(RecordError::Unsupported {
                field: "hpke_suite",
                id: self.hpke_suite.into(),
            });
        }
        for (field, n) in [
            ("restore_epoch", self.restore_epoch),
            ("expires_at_ms", self.expires_at_ms),
        ] {
            if n > c::MAX_SQLITE_WIRE_UINT {
                return Err(RecordError::BadValue(field));
            }
        }
        match Ed25519VerifyingKey::from_bytes(&self.signing_public_key) {
            Ok(vk) if !vk.is_weak() => {}
            _ => return Err(RecordError::BadValue("signing_public_key")),
        }
        if !hpke_key_usable(&self.hpke_public_key) {
            return Err(RecordError::BadValue("hpke_public_key"));
        }
        if self.signing_key_id != signing_key_id(&self.signing_public_key) {
            return Err(RecordError::BadValue("signing_key_id"));
        }
        if self.hpke_key_id != hpke_key_id(&self.hpke_public_key) {
            return Err(RecordError::BadValue("hpke_key_id"));
        }
        Ok(())
    }
}

fn header(domain: &'static str) -> Vec<(&'static str, Value)> {
    vec![
        ("domain", c::t(domain)),
        ("version", c::u(BINDING_VERSION.into())),
    ]
}

fn encode(entries: Vec<(&'static str, Value)>) -> Vec<u8> {
    c::encode(&Value::Map(
        entries.into_iter().map(|(k, v)| (k.into(), v)).collect(),
    ))
}

fn open(map: &'static str, domain: &str, bytes: &[u8]) -> Result<Fields, RecordError> {
    if bytes.len() > MAX_BINDING_BYTES {
        return Err(RecordError::BadValue("binding length"));
    }
    let mut f = Fields::decode(map, bytes)?;
    f.exact_text("domain", domain)?;
    let version = f.uint("version")?;
    if version != u64::from(BINDING_VERSION) {
        return Err(RecordError::Unsupported {
            field: "version",
            id: version,
        });
    }
    Ok(f)
}

/// The binding a candidate signs to enroll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentBindingV2 {
    pub fields: BindingFields,
}

impl EnrollmentBindingV2 {
    /// Refuses fields that [`Self::parse`] would refuse, so the server never
    /// issues a binding its clients reject.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        self.fields.check()?;
        let mut out = header(DOMAIN_ENROLLMENT_BINDING);
        self.fields.put(&mut out);
        Ok(encode(out))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = open("EnrollmentBindingV2", DOMAIN_ENROLLMENT_BINDING, bytes)?;
        let fields = BindingFields::take(&mut f)?;
        f.finish()?;
        Ok(Self { fields })
    }
}

/// The binding that promotes a pre-device ticket to a session for one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSessionBindingV2 {
    pub device_id: [u8; 16],
    pub fields: BindingFields,
}

impl DeviceSessionBindingV2 {
    /// Refuses fields that [`Self::parse`] would refuse.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        self.fields.check()?;
        let mut out = header(DOMAIN_DEVICE_SESSION_BINDING);
        out.push(("device_id", c::b(&self.device_id)));
        self.fields.put(&mut out);
        Ok(encode(out))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = open(
            "DeviceSessionBindingV2",
            DOMAIN_DEVICE_SESSION_BINDING,
            bytes,
        )?;
        let device_id = f.fixed("device_id")?;
        let fields = BindingFields::take(&mut f)?;
        f.finish()?;
        Ok(Self { device_id, fields })
    }
}

/// Callers bound `binding` by [`MAX_BINDING_BYTES`], so the length fits a u32.
fn labelled(label: &str, binding: &[u8], tail: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Vec::with_capacity(label.len() + 4 + binding.len() + tail.len());
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(&(binding.len() as u32).to_be_bytes());
    out.extend_from_slice(binding);
    out.extend_from_slice(tail);
    Zeroizing::new(out)
}

fn bounded(binding: &[u8]) -> Result<(), SignError> {
    if binding.len() > MAX_BINDING_BYTES {
        return Err(SignError::BadLength {
            field: "binding",
            got: binding.len(),
        });
    }
    Ok(())
}

/// A canonical X25519 encoding (top bit clear, u below 2^255 - 19) that is not
/// low order, so one key has exactly one encoding and one ID, and sealing to
/// it cannot fail later. A trial encapsulation catches the low-order points.
fn hpke_key_usable(pk: &[u8; 32]) -> bool {
    let at_least_p = pk[31] == 0x7f && pk[1..31].iter().all(|&b| b == 0xff) && pk[0] >= 0xed;
    pk[31] & 0x80 == 0
        && !at_least_p
        && seal_with(pk, &[], &[0; POP_SECRET_LEN], &mut FixedRng([1; 32])).is_ok()
}

/// Repeats its seed: for the trial above and for test vectors, never for a
/// real seal.
struct FixedRng([u8; 32]);

impl hpke::rand_core::TryRng for FixedRng {
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
        for (d, s) in dst.iter_mut().zip(self.0.iter().cycle()) {
            *d = *s;
        }
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for FixedRng {}

// --------------------------------------------------------- enrollment proof ---

/// `SHARDX-ENROLLMENT-BINDING-V2\0 || u32be(len) || binding`.
pub fn enrollment_signing_input(binding: &[u8]) -> Zeroizing<Vec<u8>> {
    labelled(L_ENROLLMENT_BINDING, binding, &[])
}

pub fn sign_enrollment(sk: &SigningKey, binding: &[u8]) -> [u8; ED25519_SIG_LEN] {
    use ed25519_dalek::Signer;
    sk.sign(&enrollment_signing_input(binding)).to_bytes()
}

pub fn verify_enrollment(
    signing_public_key: &[u8; 32],
    binding: &[u8],
    signature: &[u8],
) -> Result<(), SignError> {
    bounded(binding)?;
    verify_message_strict(
        signing_public_key,
        &enrollment_signing_input(binding),
        signature,
    )
}

// ------------------------------------------------------- device-session PoP ---

#[derive(Debug, PartialEq, Eq)]
pub enum PopError {
    /// Not a usable X25519 key, or an encapsulated key of the wrong length.
    BadKey,
    /// Encapsulation or decryption failed. A low-order recipient key fails
    /// here; there is no plaintext fallback.
    Hpke,
    BadLength,
}

impl std::fmt::Display for PopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKey => write!(f, "invalid HPKE key material"),
            Self::Hpke => write!(f, "HPKE operation failed"),
            Self::BadLength => write!(f, "invalid HPKE PoP length"),
        }
    }
}

impl std::error::Error for PopError {}

/// A fresh 32-byte PoP secret from the OS CSPRNG.
pub fn fresh_pop_secret() -> Result<Zeroizing<[u8; POP_SECRET_LEN]>, getrandom04::Error> {
    let mut s = Zeroizing::new([0u8; POP_SECRET_LEN]);
    fill_random(s.as_mut_slice())?;
    Ok(s)
}

/// What the server stores instead of the secret.
pub fn pop_secret_hash(secret: &[u8; POP_SECRET_LEN]) -> [u8; 32] {
    c::sha256(secret)
}

/// Constant-time check of a returned secret against the stored hash.
pub fn pop_secret_matches(stored_hash: &[u8; 32], secret: &[u8; POP_SECRET_LEN]) -> bool {
    let actual = pop_secret_hash(secret);
    stored_hash
        .iter()
        .zip(actual.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Seals the secret to the candidate's HPKE key: RFC 9180 base mode, suite 1,
/// `info = SHARDX-DEVICE-SESSION-HPKE-POP-V2\0`, `aad` = the exact binding.
pub fn seal_pop_secret(
    hpke_public_key: &[u8; 32],
    binding: &[u8],
    secret: &[u8; POP_SECRET_LEN],
) -> Result<([u8; POP_ENCAPPED_LEN], [u8; POP_CIPHERTEXT_LEN]), PopError> {
    if binding.len() > MAX_BINDING_BYTES {
        return Err(PopError::BadLength);
    }
    seal_with(hpke_public_key, binding, secret, &mut OsRng)
}

fn seal_with(
    hpke_public_key: &[u8; 32],
    binding: &[u8],
    secret: &[u8; POP_SECRET_LEN],
    rng: &mut impl hpke::rand_core::CryptoRng,
) -> Result<([u8; POP_ENCAPPED_LEN], [u8; POP_CIPHERTEXT_LEN]), PopError> {
    let pk =
        <Kem as KemTrait>::PublicKey::from_bytes(hpke_public_key).map_err(|_| PopError::BadKey)?;
    let (encapped, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        HPKE_POP_INFO,
        secret,
        binding,
        rng,
    )
    .map_err(|_| PopError::Hpke)?;
    let encapped: [u8; POP_ENCAPPED_LEN] = encapped
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| PopError::BadLength)?;
    let ciphertext: [u8; POP_CIPHERTEXT_LEN] = ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| PopError::BadLength)?;
    Ok((encapped, ciphertext))
}

/// The client's half: opens the secret with its HPKE private key. Parse and
/// check the binding first; this only proves the bytes were sealed with it.
pub fn open_pop_secret(
    hpke_private_key: &[u8],
    binding: &[u8],
    encapped: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; POP_SECRET_LEN]>, PopError> {
    if encapped.len() != POP_ENCAPPED_LEN || ciphertext.len() != POP_CIPHERTEXT_LEN {
        return Err(PopError::BadLength);
    }
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(hpke_private_key)
        .map_err(|_| PopError::BadKey)?;
    let encapped =
        <Kem as KemTrait>::EncappedKey::from_bytes(encapped).map_err(|_| PopError::BadKey)?;
    let pt = Zeroizing::new(
        hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &sk,
            &encapped,
            HPKE_POP_INFO,
            ciphertext,
            binding,
        )
        .map_err(|_| PopError::Hpke)?,
    );
    let mut s = Zeroizing::new([0u8; POP_SECRET_LEN]);
    s.copy_from_slice(pt.get(..POP_SECRET_LEN).ok_or(PopError::BadLength)?);
    Ok(s)
}

/// `SHARDX-DEVICE-SESSION-POP-V2\0 || u32be(len(binding)) || binding || s`.
pub fn pop_signing_input(binding: &[u8], secret: &[u8; POP_SECRET_LEN]) -> Zeroizing<Vec<u8>> {
    labelled(L_DEVICE_SESSION_POP, binding, secret)
}

pub fn sign_pop(
    sk: &SigningKey,
    binding: &[u8],
    secret: &[u8; POP_SECRET_LEN],
) -> [u8; ED25519_SIG_LEN] {
    use ed25519_dalek::Signer;
    sk.sign(&pop_signing_input(binding, secret)).to_bytes()
}

pub fn verify_pop(
    signing_public_key: &[u8; 32],
    binding: &[u8],
    secret: &[u8; POP_SECRET_LEN],
    signature: &[u8],
) -> Result<(), SignError> {
    bounded(binding)?;
    verify_message_strict(
        signing_public_key,
        &pop_signing_input(binding, secret),
        signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::derive_keypair;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn device() -> (SigningKey, Zeroizing<Vec<u8>>, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[0x11; 32]);
        let (hsk, hpk) = derive_keypair(&[0x22; 32]);
        (sk, hsk, hpk.try_into().unwrap())
    }

    fn fields() -> BindingFields {
        let (sk, _, hpk) = device();
        let spk = sk.verifying_key().to_bytes();
        BindingFields {
            server_instance_id: [1; 16],
            restore_epoch: 3,
            tenant_id: [2; 16],
            account_id: [3; 16],
            pre_device_session_id: [4; 16],
            challenge_id: [5; 16],
            nonce: [6; 16],
            signing_suite: 1,
            signing_public_key: spk,
            signing_key_id: signing_key_id(&spk),
            hpke_suite: 1,
            hpke_public_key: hpk,
            hpke_key_id: hpke_key_id(&hpk),
            expires_at_ms: 1_800_000_000_000,
        }
    }

    fn session() -> DeviceSessionBindingV2 {
        DeviceSessionBindingV2 {
            device_id: [7; 16],
            fields: fields(),
        }
    }

    /// Rewrites one entry of an encoded binding and re-encodes it canonically.
    fn edit(bytes: &[u8], key: &str, v: Option<Value>) -> Vec<u8> {
        let Value::Map(mut entries) = c::decode(bytes).unwrap() else {
            panic!()
        };
        entries.retain(|(k, _)| k != key);
        if let Some(v) = v {
            entries.push((key.into(), v));
        }
        c::encode(&Value::Map(entries))
    }

    #[test]
    fn both_bindings_round_trip_and_stay_apart() {
        let e = EnrollmentBindingV2 { fields: fields() };
        assert_eq!(
            EnrollmentBindingV2::parse(&e.encode().unwrap()),
            Ok(e.clone())
        );
        let s = session();
        assert_eq!(
            DeviceSessionBindingV2::parse(&s.encode().unwrap()),
            Ok(s.clone())
        );
        // Neither parses as the other.
        assert!(DeviceSessionBindingV2::parse(&e.encode().unwrap()).is_err());
        assert!(EnrollmentBindingV2::parse(&s.encode().unwrap()).is_err());
    }

    /// Pinned so a change to field names, order or types shows up as a diff.
    /// Cross-checked against an independent canonical CBOR encoder and the
    /// Python `cryptography` Ed25519 signer.
    #[test]
    fn golden_vectors() {
        let e = EnrollmentBindingV2 { fields: fields() }.encode().unwrap();
        let s = session().encode().unwrap();
        let sk = device().0;
        assert_eq!(hex(&c::sha256(&e)), GOLDEN_ENROLLMENT_SHA256);
        assert_eq!(hex(&c::sha256(&s)), GOLDEN_SESSION_SHA256);
        assert_eq!(hex(&sign_enrollment(&sk, &e)), GOLDEN_ENROLLMENT_SIG);
        assert_eq!(hex(&sign_pop(&sk, &s, &[0x33; 32])), GOLDEN_POP_SIG);
    }

    const GOLDEN_ENROLLMENT_SHA256: &str =
        "6cef872fc71cfa61c8268a05a6b99ca102519687bd978df7906598a601e6dd1d";
    const GOLDEN_SESSION_SHA256: &str =
        "c2e2066e6f268848692a26a05ca5a22feb9d00c24f2f84804f53f937df955ff6";
    const GOLDEN_ENROLLMENT_SIG: &str =
        "f151f37cd931b1a59f8ee9ce3ef6c2c2aa8aa70fbd6df3c7e0ce92d14110447446a94f4f9e225753703e23d84fc99412b9825081eaee61b65b5b5075f62bae0e";
    const GOLDEN_POP_SIG: &str =
        "bb23e4ec052b938285c80f24a98b08cf4c1910d38406cdc8eb0ceecc760b07bff05b51df3b5e9499a741f49226971dca1ab6899cd15b91ac014ed1e31426cc07";

    #[test]
    fn parse_rejects_every_contract_violation() {
        let good = session().encode().unwrap();
        let other_key = SigningKey::from_bytes(&[0x44; 32])
            .verifying_key()
            .to_bytes();
        let mut small_order = [0u8; 32];
        small_order[0] = 1;
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (edit(&good, "extra", Some(c::u(1))), "UnknownField"),
            (edit(&good, "nonce", None), "MissingField"),
            (edit(&good, "nonce", Some(c::b(&[6; 15]))), "BadField"),
            (edit(&good, "nonce", Some(c::t("x"))), "BadField"),
            (
                edit(&good, "domain", Some(c::t(DOMAIN_ENROLLMENT_BINDING))),
                "BadValue",
            ),
            (edit(&good, "version", Some(c::u(3))), "Unsupported"),
            (edit(&good, "signing_suite", Some(c::u(2))), "Unsupported"),
            (edit(&good, "hpke_suite", Some(c::u(2))), "Unsupported"),
            (edit(&good, "signing_suite", Some(c::u(70_000))), "BadField"),
            (
                edit(&good, "signing_public_key", Some(c::b(&other_key))),
                "BadValue(\"signing_key_id\")",
            ),
            // Small order, with an ID that matches it: only the point check stops it.
            (
                edit(
                    &edit(&good, "signing_public_key", Some(c::b(&small_order))),
                    "signing_key_id",
                    Some(c::b(&signing_key_id(&small_order))),
                ),
                "BadValue(\"signing_public_key\")",
            ),
            // The historical bug: the HPKE ID under the signing domain.
            (
                edit(
                    &good,
                    "hpke_key_id",
                    Some(c::b(&signing_key_id(&fields().hpke_public_key))),
                ),
                "BadValue(\"hpke_key_id\")",
            ),
            (
                vec![0u8; MAX_BINDING_BYTES + 1],
                "BadValue(\"binding length\")",
            ),
        ];
        for (bytes, want) in cases {
            let got = format!("{:?}", DeviceSessionBindingV2::parse(&bytes).unwrap_err());
            assert!(got.starts_with(want), "{want}: {got}");
        }
        // Non-canonical bytes never parse, even with every field right.
        let mut noncanonical = good.clone();
        noncanonical.push(0);
        assert!(DeviceSessionBindingV2::parse(&noncanonical).is_err());
    }

    #[test]
    fn enrollment_signature_binds_key_and_bytes() {
        let (sk, _, _) = device();
        let spk = sk.verifying_key().to_bytes();
        let binding = EnrollmentBindingV2 { fields: fields() }.encode().unwrap();
        let sig = sign_enrollment(&sk, &binding);
        assert_eq!(verify_enrollment(&spk, &binding, &sig), Ok(()));
        let other = edit(&binding, "nonce", Some(c::b(&[9; 16])));
        assert!(verify_enrollment(&spk, &other, &sig).is_err());
        let wrong = SigningKey::from_bytes(&[0x44; 32])
            .verifying_key()
            .to_bytes();
        assert!(verify_enrollment(&wrong, &binding, &sig).is_err());
        // A PoP signature over the same binding is not an enrollment proof.
        let pop = sign_pop(&sk, &binding, &[0; 32]);
        assert!(verify_enrollment(&spk, &binding, &pop).is_err());
        assert!(verify_enrollment(&spk, &binding, &sig[..63]).is_err());
    }

    #[test]
    fn hpke_pop_round_trip_binds_binding_key_and_secret() {
        let (sk, hsk, hpk) = device();
        let spk = sk.verifying_key().to_bytes();
        let binding = session().encode().unwrap();
        let secret = fresh_pop_secret().unwrap();
        let hash = pop_secret_hash(&secret);
        let (enc, ct) = seal_pop_secret(&hpk, &binding, &secret).unwrap();

        let opened = open_pop_secret(&hsk, &binding, &enc, &ct).unwrap();
        assert_eq!(*opened, *secret);
        assert!(pop_secret_matches(&hash, &opened));
        let sig = sign_pop(&sk, &binding, &opened);
        assert_eq!(verify_pop(&spk, &binding, &opened, &sig), Ok(()));

        // Another binding, another key or a flipped byte never opens.
        let other = edit(&binding, "device_id", Some(c::b(&[8; 16])));
        assert_eq!(
            open_pop_secret(&hsk, &other, &enc, &ct),
            Err(PopError::Hpke)
        );
        let (other_sk, _) = derive_keypair(&[0x55; 32]);
        assert_eq!(
            open_pop_secret(&other_sk, &binding, &enc, &ct),
            Err(PopError::Hpke)
        );
        let mut bad = ct;
        bad[0] ^= 1;
        assert_eq!(
            open_pop_secret(&hsk, &binding, &enc, &bad),
            Err(PopError::Hpke)
        );
        assert_eq!(
            open_pop_secret(&hsk, &binding, &enc[..31], &ct),
            Err(PopError::BadLength)
        );

        // The signature covers the secret and the binding.
        assert!(!pop_secret_matches(&hash, &[0; 32]));
        assert!(verify_pop(&spk, &binding, &[0; 32], &sig).is_err());
        assert!(verify_pop(&spk, &other, &opened, &sig).is_err());

        // Two seals of one secret differ: encapsulation is fresh each time.
        let (enc2, _) = seal_pop_secret(&hpk, &binding, &secret).unwrap();
        assert_ne!(enc, enc2);
    }

    /// A fixed ephemeral key makes the seal reproducible. Cross-checked
    /// against an independent RFC 9180 implementation in Python.
    #[test]
    fn hpke_golden_vector() {
        let (_, hsk, hpk) = device();
        let binding = session().encode().unwrap();
        let (enc, ct) = seal_with(&hpk, &binding, &[0x33; 32], &mut FixedRng([0xab; 32])).unwrap();
        assert_eq!(hex(&enc), GOLDEN_POP_ENC);
        assert_eq!(hex(&ct), GOLDEN_POP_CT);
        assert_eq!(
            *open_pop_secret(&hsk, &binding, &enc, &ct).unwrap(),
            [0x33; 32]
        );
    }

    const GOLDEN_POP_ENC: &str = "3b9eaeab62292c4205e5118a1be6ffbad4a57e2fcfb27d0e93d190ab8ae90463";
    const GOLDEN_POP_CT: &str = "7632e882657572a2813d1c3938c651a1e9b83ff7dcfe22baf1eeae15373ad59f\
                                 547cb526a1f68a7c36716b0f67f0d6c6";

    #[test]
    fn parse_and_encode_refuse_unusable_hpke_keys() {
        let good = session().encode().unwrap();
        let mut p = [0xffu8; 32];
        // p + 9: the base point written non-canonically, otherwise usable.
        p[0] = 0xf6;
        p[31] = 0x7f;
        let mut one = [0u8; 32];
        one[0] = 1;
        let mut high_bit = fields().hpke_public_key;
        high_bit[31] |= 0x80;
        for pk in [[0u8; 32], one, p, high_bit] {
            // The ID matches the key, so only the key check can stop it.
            let bytes = edit(
                &edit(&good, "hpke_public_key", Some(c::b(&pk))),
                "hpke_key_id",
                Some(c::b(&hpke_key_id(&pk))),
            );
            assert_eq!(
                DeviceSessionBindingV2::parse(&bytes),
                Err(RecordError::BadValue("hpke_public_key")),
                "{}",
                hex(&pk)
            );
            let mut f = fields();
            f.hpke_public_key = pk;
            f.hpke_key_id = hpke_key_id(&pk);
            assert!(EnrollmentBindingV2 { fields: f }.encode().is_err());
        }
        let mut f = fields();
        f.restore_epoch = u64::MAX;
        assert_eq!(
            EnrollmentBindingV2 { fields: f }.encode(),
            Err(RecordError::BadValue("restore_epoch"))
        );
    }

    #[test]
    fn a_low_order_hpke_key_never_gets_a_secret() {
        let binding = session().encode().unwrap();
        let mut one = [0u8; 32];
        one[0] = 1;
        for pk in [[0u8; 32], one] {
            assert_eq!(
                seal_pop_secret(&pk, &binding, &[7; 32]),
                Err(PopError::Hpke),
                "{}",
                hex(&pk)
            );
        }
    }
}
