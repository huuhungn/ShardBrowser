//! `RecoveryBundleV2`: the passphrase-protected file that recovers a tenant's
//! root key and retained fleet keys when no custodian device is left (ADR 0002
//! D-5; plan L1386-L1387).
//!
//! The file is one closed canonical map: the header fields plus `ciphertext`.
//! The header's own canonical bytes are the AEAD associated data, so no header
//! field can change without the file failing to open. The key comes from the
//! passphrase through Argon2id, with the cost stored in the header so a later
//! build can raise it without losing old bundles.
//!
//! Only `recovery_bundle_sha256` ever leaves the device: the root generation
//! create and activate requests pin it. The server never sees the file.

use std::ops::RangeInclusive;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::{Zeroize, Zeroizing};

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};
use crate::fleet_grants::{fkek_key_id, FKEK_LEN};
use crate::keys::{fill_random, root_key_id};
use crate::passphrase::MIN_PASSPHRASE_LEN;

pub const DOMAIN_RECOVERY_BUNDLE: &str = "shardx.recovery.bundle.v2";
const DOMAIN_PLAINTEXT: &str = "shardx.recovery.bundle-plaintext.v2";
const DOMAIN_READINESS_PROBE: &str = "shardx.recovery.readiness-probe.v2";
const VERSION: u64 = 2;
const KDF_SALT_CONTEXT: &[u8] = b"SHARDX-RECOVERY-BUNDLE-KDF-V2\0";
const L_RECOVERY_BUNDLE: &str = "SHARDX-RECOVERY-BUNDLE-V2\0";

/// Argon2id, version 0x13.
pub(crate) const KDF_ARGON2ID: u64 = 1;
pub(crate) const AEAD_CHACHA20_POLY1305: u64 = 1;
pub const KDF_MEMORY_KIB: RangeInclusive<u32> = 65_536..=1_048_576;
pub const KDF_ITERATIONS: RangeInclusive<u32> = 3..=64;
pub(crate) const KDF_PARALLELISM: u32 = 4;
/// What a new bundle costs. A later build may only raise these (L1375).
pub const DEFAULT_KDF_MEMORY_KIB: u32 = 65_536;
pub const DEFAULT_KDF_ITERATIONS: u32 = 3;
pub(crate) const CIPHERTEXT_BYTES: RangeInclusive<usize> = 48..=16_777_216;
/// Fits the ciphertext bound with room for the header.
pub(crate) const MAX_FILE_BYTES: usize = 16_777_216 + 1024;
pub const MAX_RETAINED_FKEKS: usize = 65_535;

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryBundleError {
    /// Not the closed canonical map the format defines, or a value outside
    /// its bound.
    Format(RecordError),
    PassphraseTooShort,
    Kdf,
    /// The wrong passphrase, or bytes changed since the export.
    Decrypt,
    /// The bundle opened but names a key it does not hold, or not the
    /// bundle the caller expected.
    Mismatch(&'static str),
    Entropy,
}

impl From<RecordError> for RecoveryBundleError {
    fn from(e: RecordError) -> Self {
        Self::Format(e)
    }
}

impl std::fmt::Display for RecoveryBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(e) => write!(f, "not a recovery bundle: {e}"),
            Self::PassphraseTooShort => write!(
                f,
                "a recovery passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
            ),
            Self::Kdf => write!(f, "could not derive a key from the passphrase"),
            Self::Decrypt => write!(
                f,
                "the recovery bundle does not open: wrong passphrase or a changed file"
            ),
            Self::Mismatch(what) => write!(f, "the recovery bundle's {what} does not match"),
            Self::Entropy => write!(f, "the OS entropy source is unavailable"),
        }
    }
}

impl std::error::Error for RecoveryBundleError {}

type Result<T> = std::result::Result<T, RecoveryBundleError>;

/// `RecoveryBundleHeaderV2`. Its canonical bytes are the AEAD associated data.
///
/// Only [`seal`] makes one, with a fresh salt and nonce each time: sealing
/// twice under one header would reuse the nonce under the same key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBundleHeaderV2 {
    pub tenant_id: [u8; 16],
    pub server_instance_id: [u8; 16],
    pub root_generation: u64,
    pub root_key_id: [u8; 32],
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_salt: [u8; 16],
    pub aead_nonce: [u8; 12],
    pub created_at_ms: u64,
}

impl RecoveryBundleHeaderV2 {
    /// A header at the default cost, with a fresh salt and nonce.
    fn fresh(
        tenant_id: [u8; 16],
        server_instance_id: [u8; 16],
        root_generation: u64,
        root_key_id: [u8; 32],
        created_at_ms: u64,
    ) -> Result<Self> {
        let mut kdf_salt = [0u8; 16];
        let mut aead_nonce = [0u8; 12];
        fill_random(&mut kdf_salt).map_err(|_| RecoveryBundleError::Entropy)?;
        fill_random(&mut aead_nonce).map_err(|_| RecoveryBundleError::Entropy)?;
        Ok(Self {
            tenant_id,
            server_instance_id,
            root_generation,
            root_key_id,
            kdf_memory_kib: DEFAULT_KDF_MEMORY_KIB,
            kdf_iterations: DEFAULT_KDF_ITERATIONS,
            kdf_salt,
            aead_nonce,
            created_at_ms,
        })
    }

    fn entries(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("domain", c::t(DOMAIN_RECOVERY_BUNDLE)),
            ("version", c::u(VERSION)),
            ("tenant_id", c::b(&self.tenant_id)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("root_generation", c::u(self.root_generation)),
            ("root_key_id", c::b(&self.root_key_id)),
            ("kdf_id", c::u(KDF_ARGON2ID)),
            ("kdf_memory_kib", c::u(self.kdf_memory_kib.into())),
            ("kdf_iterations", c::u(self.kdf_iterations.into())),
            ("kdf_parallelism", c::u(KDF_PARALLELISM.into())),
            ("kdf_salt", c::b(&self.kdf_salt)),
            ("aead_suite_id", c::u(AEAD_CHACHA20_POLY1305)),
            ("aead_nonce", c::b(&self.aead_nonce)),
            ("created_at_ms", c::u(self.created_at_ms)),
        ]
    }

    /// The exact canonical header map: the AEAD associated data.
    pub fn encode(&self) -> Vec<u8> {
        c::encode(&c::m(self.entries()))
    }

    fn check_cost(&self) -> std::result::Result<(), RecordError> {
        if !KDF_MEMORY_KIB.contains(&self.kdf_memory_kib) {
            return Err(RecordError::BadValue("kdf_memory_kib"));
        }
        if !KDF_ITERATIONS.contains(&self.kdf_iterations) {
            return Err(RecordError::BadValue("kdf_iterations"));
        }
        Ok(())
    }

    fn read(f: &mut Fields) -> std::result::Result<Self, RecordError> {
        f.exact_text("domain", DOMAIN_RECOVERY_BUNDLE)?;
        supported(f, "version", VERSION)?;
        let tenant_id = f.fixed("tenant_id")?;
        let server_instance_id = f.fixed("server_instance_id")?;
        let root_generation = f.uint("root_generation")?;
        let root_key_id = f.fixed("root_key_id")?;
        supported(f, "kdf_id", KDF_ARGON2ID)?;
        let kdf_memory_kib = u32_of(f, "kdf_memory_kib")?;
        let kdf_iterations = u32_of(f, "kdf_iterations")?;
        supported(f, "kdf_parallelism", KDF_PARALLELISM.into())?;
        let kdf_salt = f.fixed("kdf_salt")?;
        supported(f, "aead_suite_id", AEAD_CHACHA20_POLY1305)?;
        let aead_nonce = f.fixed("aead_nonce")?;
        let created_at_ms = f.uint("created_at_ms")?;
        let header = Self {
            tenant_id,
            server_instance_id,
            root_generation,
            root_key_id,
            kdf_memory_kib,
            kdf_iterations,
            kdf_salt,
            aead_nonce,
            created_at_ms,
        };
        header.check_cost()?;
        Ok(header)
    }
}

pub(crate) fn supported(
    f: &mut Fields,
    field: &'static str,
    id: u64,
) -> std::result::Result<(), RecordError> {
    if f.uint(field)? == id {
        Ok(())
    } else {
        Err(RecordError::Unsupported { field, id })
    }
}

pub(crate) fn u32_of(f: &mut Fields, field: &'static str) -> std::result::Result<u32, RecordError> {
    let n = f.uint(field)?;
    u32::try_from(n).map_err(|_| f.bad(field))
}

/// One retained fleet key. Its key id is derived from the key, never stored
/// apart from it.
pub struct RetainedFkek {
    pub fleet_id: [u8; 16],
    pub generation: u64,
    pub fkek: Zeroizing<[u8; FKEK_LEN]>,
}

/// `RecoveryBundlePlaintextV2`. The root key id is derived from `trk`.
pub struct RecoveryBundlePlaintextV2 {
    pub trk: Zeroizing<[u8; 32]>,
    pub bootstrap_anchor_signing_key_id: [u8; 32],
    /// Sorted by `(fleet_id, generation)`, each at most once. Empty at
    /// bootstrap.
    pub retained_fkeks: Vec<RetainedFkek>,
}

impl std::fmt::Debug for RecoveryBundlePlaintextV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryBundlePlaintextV2")
            .field("trk", &"<redacted>")
            .field(
                "bootstrap_anchor_signing_key_id",
                &self.bootstrap_anchor_signing_key_id,
            )
            .field("retained_fkeks", &self.retained_fkeks.len())
            .finish()
    }
}

// shortcut: the canonical codec copies key bytes into plain `Vec`s while
// encoding and decoding, and those copies are not zeroized; give the codec a
// zeroizing value type if bundles ever stay in memory longer than one export.
impl RecoveryBundlePlaintextV2 {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let keys = self
            .retained_fkeks
            .iter()
            .map(|k| (k.fleet_id, k.generation));
        if self.retained_fkeks.len() > MAX_RETAINED_FKEKS || !strictly_increasing(keys) {
            return Err(RecordError::BadValue("retained_fkeks").into());
        }
        let items = self
            .retained_fkeks
            .iter()
            .map(|k| {
                c::m(vec![
                    ("fleet_id", c::b(&k.fleet_id)),
                    ("generation", c::u(k.generation)),
                    ("fkek_key_id", c::b(&fkek_key_id(&k.fkek))),
                    ("fkek", c::b(k.fkek.as_slice())),
                ])
            })
            .collect();
        Ok(Zeroizing::new(c::encode(&c::m(vec![
            ("domain", c::t(DOMAIN_PLAINTEXT)),
            ("version", c::u(VERSION)),
            ("root_key_id", c::b(&root_key_id(&self.trk))),
            ("trk", c::b(self.trk.as_slice())),
            (
                "bootstrap_anchor_signing_key_id",
                c::b(&self.bootstrap_anchor_signing_key_id),
            ),
            ("retained_fkeks", Value::Array(items)),
        ]))))
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("RecoveryBundlePlaintextV2", bytes)?;
        f.exact_text("domain", DOMAIN_PLAINTEXT)?;
        supported(&mut f, "version", VERSION)?;
        let named_root = f.fixed::<32>("root_key_id")?;
        let trk = Zeroizing::new(f.fixed::<32>("trk")?);
        let bootstrap_anchor_signing_key_id = f.fixed("bootstrap_anchor_signing_key_id")?;
        let items = match f.req("retained_fkeks")? {
            Value::Array(items) if items.len() <= MAX_RETAINED_FKEKS => items,
            _ => return Err(f.bad("retained_fkeks").into()),
        };
        let mut retained_fkeks = Vec::with_capacity(items.len());
        for v in items {
            let mut r = Fields::open("RetainedFkek", v)?;
            let fleet_id = r.fixed("fleet_id")?;
            let generation = r.uint("generation")?;
            let named = r.fixed::<32>("fkek_key_id")?;
            let fkek = Zeroizing::new(r.fixed::<FKEK_LEN>("fkek")?);
            r.finish()?;
            if fkek_key_id(&fkek) != named {
                return Err(RecoveryBundleError::Mismatch("fkek_key_id"));
            }
            retained_fkeks.push(RetainedFkek {
                fleet_id,
                generation,
                fkek,
            });
        }
        f.finish()?;
        if root_key_id(&trk) != named_root {
            return Err(RecoveryBundleError::Mismatch("root_key_id"));
        }
        let keys = retained_fkeks.iter().map(|k| (k.fleet_id, k.generation));
        if !strictly_increasing(keys) {
            return Err(RecordError::BadValue("retained_fkeks").into());
        }
        Ok(Self {
            trk,
            bootstrap_anchor_signing_key_id,
            retained_fkeks,
        })
    }
}

pub(crate) fn strictly_increasing<T: Ord>(items: impl IntoIterator<Item = T>) -> bool {
    let mut last = None;
    items.into_iter().all(|item| {
        let ok = last.as_ref().is_none_or(|prev| *prev < item);
        last = Some(item);
        ok
    })
}

/// The passphrase length is checked only when sealing, so a later build that
/// raises the minimum still opens every older bundle.
fn kek(passphrase: &str, header: &RecoveryBundleHeaderV2) -> Result<Zeroizing<[u8; 32]>> {
    argon2id_kek(
        passphrase,
        KDF_SALT_CONTEXT,
        header.kdf_memory_kib,
        header.kdf_iterations,
        &header.kdf_salt,
    )
    .ok_or(RecoveryBundleError::Kdf)
}

/// Argon2id v0x13 at `p = 4`, salt = `context || salt`, out 32: the KDF of
/// every passphrase-protected file (D-5). `None` when it cannot run.
pub(crate) fn argon2id_kek(
    passphrase: &str,
    context: &[u8],
    memory_kib: u32,
    iterations: u32,
    salt: &[u8; 16],
) -> Option<Zeroizing<[u8; 32]>> {
    let params = Params::new(memory_kib, iterations, KDF_PARALLELISM, Some(32)).ok()?;
    let mut full_salt = Vec::with_capacity(context.len() + salt.len());
    full_salt.extend_from_slice(context);
    full_salt.extend_from_slice(salt);
    // A hostile file may ask for up to 1 GiB: allocate it fallibly, so a
    // machine short of memory gets an error instead of an abort.
    let mut blocks = Vec::new();
    blocks.try_reserve_exact(params.block_count()).ok()?;
    blocks.resize(params.block_count(), Block::default());
    let mut out = Zeroizing::new([0u8; 32]);
    let derived = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(
            passphrase.as_bytes(),
            &full_salt,
            out.as_mut(),
            &mut blocks,
        );
    blocks.iter_mut().for_each(Zeroize::zeroize);
    derived.ok()?;
    Some(out)
}

fn seal_exact(
    header: &RecoveryBundleHeaderV2,
    plaintext: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>> {
    header.check_cost()?;
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(RecoveryBundleError::PassphraseTooShort);
    }
    let kek = kek(passphrase, header)?;
    let ciphertext = ChaCha20Poly1305::new(&(*kek).into())
        .encrypt(
            &header.aead_nonce.into(),
            Payload {
                msg: plaintext,
                aad: &header.encode(),
            },
        )
        .map_err(|_| RecordError::BadValue("ciphertext"))?;
    if !CIPHERTEXT_BYTES.contains(&ciphertext.len()) {
        return Err(RecordError::BadValue("ciphertext").into());
    }
    let mut entries = header.entries();
    entries.push(("ciphertext", c::b(&ciphertext)));
    Ok(c::encode(&c::m(entries)))
}

fn seal_with(
    header: &RecoveryBundleHeaderV2,
    plaintext: &RecoveryBundlePlaintextV2,
    passphrase: &str,
) -> Result<Vec<u8>> {
    if root_key_id(&plaintext.trk) != header.root_key_id {
        return Err(RecoveryBundleError::Mismatch("root_key_id"));
    }
    seal_exact(header, &plaintext.encode()?, passphrase)
}

/// Exports `plaintext` under `passphrase` at the default cost, with a fresh
/// salt and nonce. Returns the header (for [`verify_export`]) and the exact
/// file bytes.
pub fn seal(
    tenant_id: [u8; 16],
    server_instance_id: [u8; 16],
    root_generation: u64,
    created_at_ms: u64,
    plaintext: &RecoveryBundlePlaintextV2,
    passphrase: &str,
) -> Result<(RecoveryBundleHeaderV2, Vec<u8>)> {
    let header = RecoveryBundleHeaderV2::fresh(
        tenant_id,
        server_instance_id,
        root_generation,
        root_key_id(&plaintext.trk),
        created_at_ms,
    )?;
    let file = seal_with(&header, plaintext, passphrase)?;
    Ok((header, file))
}

/// Opens exact bundle file bytes. After this, the TRK hashes to both root
/// key ids and every FKEK to its key id.
pub fn open(
    file: &[u8],
    passphrase: &str,
) -> Result<(RecoveryBundleHeaderV2, RecoveryBundlePlaintextV2)> {
    if file.len() > MAX_FILE_BYTES {
        return Err(RecordError::BadValue("bundle").into());
    }
    let mut f = Fields::decode("RecoveryBundleV2", file)?;
    let header = RecoveryBundleHeaderV2::read(&mut f)?;
    let ciphertext = f.bytes(
        "ciphertext",
        *CIPHERTEXT_BYTES.start(),
        *CIPHERTEXT_BYTES.end(),
    )?;
    f.finish()?;
    let kek = kek(passphrase, &header)?;
    let plaintext = Zeroizing::new(
        ChaCha20Poly1305::new(&(*kek).into())
            .decrypt(
                &header.aead_nonce.into(),
                Payload {
                    msg: &ciphertext,
                    aad: &header.encode(),
                },
            )
            .map_err(|_| RecoveryBundleError::Decrypt)?,
    );
    let plaintext = RecoveryBundlePlaintextV2::parse(&plaintext)?;
    if root_key_id(&plaintext.trk) != header.root_key_id {
        return Err(RecoveryBundleError::Mismatch("root_key_id"));
    }
    Ok((header, plaintext))
}

/// `recovery_bundle_sha256` over the exact file bytes.
pub fn recovery_bundle_sha256(file: &[u8]) -> [u8; 32] {
    c::domain_hash(L_RECOVERY_BUNDLE, file)
}

/// The readiness check (L819, L1387), run on the bytes re-read from the
/// file's final path: they open under `passphrase` to the header they were
/// sealed with, and a fresh key sealed under the recovered TRK opens again.
/// Returns the `recovery_bundle_sha256` to pin.
pub fn verify_export(
    file: &[u8],
    passphrase: &str,
    sealed_with: &RecoveryBundleHeaderV2,
) -> Result<[u8; 32]> {
    let (header, plaintext) = open(file, passphrase)?;
    if header != *sealed_with {
        return Err(RecoveryBundleError::Mismatch("header"));
    }
    readiness_probe(&plaintext.trk, &header.root_key_id)?;
    Ok(recovery_bundle_sha256(file))
}

fn readiness_probe(trk: &[u8; 32], root_key_id: &[u8; 32]) -> Result<()> {
    let mut probe_nonce = [0u8; 16];
    let mut aead_nonce = [0u8; 12];
    let mut key = Zeroizing::new([0u8; 32]);
    for buf in [&mut probe_nonce[..], &mut aead_nonce[..], &mut key[..]] {
        fill_random(buf).map_err(|_| RecoveryBundleError::Entropy)?;
    }
    let aad = c::encode(&c::m(vec![
        ("domain", c::t(DOMAIN_READINESS_PROBE)),
        ("version", c::u(VERSION)),
        ("root_key_id", c::b(root_key_id)),
        ("probe_nonce", c::b(&probe_nonce)),
    ]));
    let cipher = ChaCha20Poly1305::new(&(*trk).into());
    fn probe<'a>(msg: &'a [u8], aad: &'a [u8]) -> Payload<'a, 'a> {
        Payload { msg, aad }
    }
    let sealed = cipher
        .encrypt(&aead_nonce.into(), probe(key.as_slice(), &aad))
        .map_err(|_| RecoveryBundleError::Mismatch("readiness_probe"))?;
    let opened = Zeroizing::new(
        cipher
            .decrypt(&aead_nonce.into(), probe(&sealed, &aad))
            .map_err(|_| RecoveryBundleError::Mismatch("readiness_probe"))?,
    );
    if opened.as_slice() != key.as_slice() {
        return Err(RecoveryBundleError::Mismatch("readiness_probe"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery";
    const TRK: [u8; 32] = [0x7c; 32];

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn header() -> RecoveryBundleHeaderV2 {
        RecoveryBundleHeaderV2 {
            tenant_id: [0x41; 16],
            server_instance_id: [7; 16],
            root_generation: 0,
            root_key_id: root_key_id(&TRK),
            kdf_memory_kib: DEFAULT_KDF_MEMORY_KIB,
            kdf_iterations: DEFAULT_KDF_ITERATIONS,
            kdf_salt: [3; 16],
            aead_nonce: [4; 12],
            created_at_ms: 1_800_000_000_000,
        }
    }

    fn fkek(fleet: u8, generation: u64) -> RetainedFkek {
        RetainedFkek {
            fleet_id: [fleet; 16],
            generation,
            fkek: Zeroizing::new([fleet ^ generation as u8 ^ 0x55; 32]),
        }
    }

    fn plaintext(retained: Vec<RetainedFkek>) -> RecoveryBundlePlaintextV2 {
        RecoveryBundlePlaintextV2 {
            trk: Zeroizing::new(TRK),
            bootstrap_anchor_signing_key_id: [9; 32],
            retained_fkeks: retained,
        }
    }

    const GOLDEN_BUNDLE: &str = "a30861716f4f7506a7941cfa19e8bf04a17d0a685ebbf4cb2105145008564d76";
    const GOLDEN_PIN: &str = "4eb90c31ac10dfa8394d844728a448dfaae37b2801981ed6a8a808e338ab96ef";

    #[test]
    fn a_bundle_round_trips_is_pinned_and_passes_readiness() {
        let h = header();
        let file = seal_with(
            &h,
            &plaintext(vec![fkek(1, 0), fkek(1, 1), fkek(2, 0)]),
            PASS,
        )
        .unwrap();
        assert_eq!(hex(&c::sha256(&file)), GOLDEN_BUNDLE);
        assert_eq!(hex(&recovery_bundle_sha256(&file)), GOLDEN_PIN);

        let (opened, pt) = open(&file, PASS).unwrap();
        assert_eq!(opened, h);
        assert_eq!(*pt.trk, TRK);
        assert_eq!(pt.bootstrap_anchor_signing_key_id, [9; 32]);
        let got: Vec<_> = pt
            .retained_fkeks
            .iter()
            .map(|k| (k.fleet_id, k.generation, *k.fkek))
            .collect();
        let want: Vec<_> = [fkek(1, 0), fkek(1, 1), fkek(2, 0)]
            .iter()
            .map(|k| (k.fleet_id, k.generation, *k.fkek))
            .collect();
        assert_eq!(got, want);

        // The pinned hash is domain separated from a plain digest.
        assert_eq!(
            verify_export(&file, PASS, &h),
            Ok(recovery_bundle_sha256(&file))
        );
        assert_ne!(recovery_bundle_sha256(&file), c::sha256(&file));
        let other = RecoveryBundleHeaderV2 {
            created_at_ms: 1,
            ..h
        };
        assert_eq!(
            verify_export(&file, PASS, &other),
            Err(RecoveryBundleError::Mismatch("header"))
        );

        // A bootstrap bundle holds no fleet keys yet, and the debug print
        // never shows the TRK.
        let (_, empty) = open(&seal_with(&h, &plaintext(vec![]), PASS).unwrap(), PASS).unwrap();
        assert!(empty.retained_fkeks.is_empty());
        assert!(!format!("{empty:?}").contains("124"));
    }

    #[test]
    fn a_bundle_opens_only_with_its_passphrase_and_its_exact_bytes() {
        let h = header();
        let file = seal_with(&h, &plaintext(vec![]), PASS).unwrap();
        assert_eq!(
            open(&file, "correct horse batterz").unwrap_err(),
            RecoveryBundleError::Decrypt
        );
        assert_eq!(
            verify_export(&file, "correct horse batterz", &h).unwrap_err(),
            RecoveryBundleError::Decrypt
        );
        // The minimum length binds a new export, never an old bundle.
        assert_eq!(
            open(&file, "short").unwrap_err(),
            RecoveryBundleError::Decrypt
        );
        assert_eq!(
            seal_with(&h, &plaintext(vec![]), "short").unwrap_err(),
            RecoveryBundleError::PassphraseTooShort
        );

        // The last byte is ciphertext: the tag no longer verifies.
        let mut flipped = file.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert_eq!(
            open(&flipped, PASS).unwrap_err(),
            RecoveryBundleError::Decrypt
        );

        // A header field is associated data, so editing it breaks the file
        // even though the edited map is well formed.
        let Value::Map(mut entries) = c::decode(&file).unwrap() else {
            panic!("a map")
        };
        entries
            .iter_mut()
            .find(|(k, _)| k == "root_generation")
            .unwrap()
            .1 = c::u(1);
        let edited = c::encode(&Value::Map(entries));
        assert_eq!(
            open(&edited, PASS).unwrap_err(),
            RecoveryBundleError::Decrypt
        );
    }

    #[test]
    fn a_bundle_holds_only_keys_that_match_their_ids() {
        let h = header();
        // The TRK must be the header's root key.
        let wrong = RecoveryBundlePlaintextV2 {
            trk: Zeroizing::new([1; 32]),
            ..plaintext(vec![])
        };
        assert_eq!(
            seal_with(&h, &wrong, PASS).unwrap_err(),
            RecoveryBundleError::Mismatch("root_key_id")
        );
        // Fleet keys sorted and unique.
        for retained in [vec![fkek(2, 0), fkek(1, 0)], vec![fkek(1, 0), fkek(1, 0)]] {
            assert_eq!(
                seal_with(&h, &plaintext(retained), PASS).unwrap_err(),
                RecoveryBundleError::Format(RecordError::BadValue("retained_fkeks"))
            );
        }

        // A plaintext whose fleet key id names another key, sealed honestly.
        let Value::Map(mut pt) = c::decode(&plaintext(vec![fkek(1, 0)]).encode().unwrap()).unwrap()
        else {
            panic!("a map")
        };
        let Some((_, Value::Array(items))) = pt.iter_mut().find(|(k, _)| k == "retained_fkeks")
        else {
            panic!("retained_fkeks")
        };
        let Value::Map(item) = &mut items[0] else {
            panic!("an item")
        };
        item.iter_mut().find(|(k, _)| k == "fkek_key_id").unwrap().1 = c::b(&[0; 32]);
        let file = seal_exact(&h, &c::encode(&Value::Map(pt)), PASS).unwrap();
        assert_eq!(
            open(&file, PASS).unwrap_err(),
            RecoveryBundleError::Mismatch("fkek_key_id")
        );

        // A plaintext naming another root key, and one with its fleet keys
        // out of order, both sealed honestly: the reader checks for itself.
        type Entries = Vec<(String, Value)>;
        let edit = |change: &dyn Fn(&mut Entries)| {
            let raw = plaintext(vec![fkek(1, 0), fkek(2, 0)]).encode().unwrap();
            let Value::Map(mut pt) = c::decode(&raw).unwrap() else {
                panic!("a map")
            };
            change(&mut pt);
            let file = seal_exact(&h, &c::encode(&Value::Map(pt)), PASS).unwrap();
            open(&file, PASS).unwrap_err()
        };
        assert_eq!(
            edit(&|pt| pt.iter_mut().find(|(k, _)| k == "root_key_id").unwrap().1 = c::b(&[0; 32])),
            RecoveryBundleError::Mismatch("root_key_id")
        );
        assert_eq!(
            edit(&|pt| {
                let Some((_, Value::Array(items))) =
                    pt.iter_mut().find(|(k, _)| k == "retained_fkeks")
                else {
                    panic!("retained_fkeks")
                };
                items.reverse();
            }),
            RecoveryBundleError::Format(RecordError::BadValue("retained_fkeks"))
        );
    }

    #[test]
    fn a_bundle_header_is_closed_and_bounded() {
        // Every check here fails before the KDF runs.
        let mut h = header();
        h.kdf_memory_kib = *KDF_MEMORY_KIB.start() - 1;
        let pt = plaintext(vec![]);
        assert_eq!(
            seal_with(&h, &pt, PASS).unwrap_err(),
            RecoveryBundleError::Format(RecordError::BadValue("kdf_memory_kib"))
        );
        for iterations in [2, 65] {
            let h = RecoveryBundleHeaderV2 {
                kdf_iterations: iterations,
                ..header()
            };
            assert_eq!(
                seal_with(&h, &pt, PASS).unwrap_err(),
                RecoveryBundleError::Format(RecordError::BadValue("kdf_iterations"))
            );
        }

        let mut entries = header().entries();
        entries.push(("ciphertext", c::b(&[0; 48])));
        let parse =
            |entries: &Vec<(&'static str, Value)>| open(&c::encode(&c::m(entries.clone())), PASS);
        let mut extra = entries.clone();
        extra.push(("extra", c::u(1)));
        assert!(matches!(
            parse(&extra),
            Err(RecoveryBundleError::Format(
                RecordError::UnknownField { .. }
            ))
        ));
        let mut missing = entries.clone();
        missing.retain(|(k, _)| *k != "aead_nonce");
        assert!(matches!(
            parse(&missing),
            Err(RecoveryBundleError::Format(
                RecordError::MissingField { .. }
            ))
        ));
        for (field, value) in [
            ("domain", c::t("shardx.recovery.other.v2")),
            ("kdf_id", c::u(2)),
            ("kdf_parallelism", c::u(1)),
            ("aead_suite_id", c::u(2)),
            ("kdf_memory_kib", c::u(u64::from(u32::MAX) + 1)),
            ("kdf_salt", c::b(&[3; 15])),
            ("ciphertext", c::b(&[0; 47])),
            ("kdf_memory_kib", c::u(65_535)),
            ("kdf_memory_kib", c::u(1_048_577)),
            ("kdf_iterations", c::u(2)),
            ("version", c::u(3)),
            ("aead_nonce", c::b(&[4; 11])),
        ] {
            let mut edited = entries.clone();
            edited.iter_mut().find(|(k, _)| *k == field).unwrap().1 = value;
            assert!(
                matches!(parse(&edited), Err(RecoveryBundleError::Format(_))),
                "{field}"
            );
        }
    }

    #[test]
    fn every_export_draws_a_fresh_salt_and_nonce_at_the_default_cost() {
        let pt = plaintext(vec![]);
        let (a, file) = seal([0x41; 16], [7; 16], 0, 5, &pt, PASS).unwrap();
        let (b, _) = seal([0x41; 16], [7; 16], 0, 5, &pt, PASS).unwrap();
        assert_ne!((a.kdf_salt, a.aead_nonce), (b.kdf_salt, b.aead_nonce));
        assert_eq!(
            (a.kdf_memory_kib, a.kdf_iterations, a.root_key_id),
            (
                DEFAULT_KDF_MEMORY_KIB,
                DEFAULT_KDF_ITERATIONS,
                root_key_id(&TRK)
            )
        );
        assert_eq!(
            verify_export(&file, PASS, &a),
            Ok(recovery_bundle_sha256(&file))
        );
    }

    #[test]
    fn oversized_input_is_refused_before_any_work() {
        assert_eq!(
            open(&vec![0; MAX_FILE_BYTES + 1], PASS).unwrap_err(),
            RecoveryBundleError::Format(RecordError::BadValue("bundle"))
        );
        let many = (0..=MAX_RETAINED_FKEKS as u32)
            .map(|i| RetainedFkek {
                fleet_id: [0; 16],
                generation: i.into(),
                fkek: Zeroizing::new([0; 32]),
            })
            .collect();
        assert_eq!(
            seal_with(&header(), &plaintext(many), PASS).unwrap_err(),
            RecoveryBundleError::Format(RecordError::BadValue("retained_fkeks"))
        );
    }
}
