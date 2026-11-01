//! `keys-fallback.bin`: the passphrase-protected file that holds a device's
//! keys where no OS credential store is usable (ADR 0002 D-5; plan L1374).
//!
//! Same construction as the recovery bundle, under its own header and KDF
//! salt label: one closed canonical map of the header fields plus
//! `ciphertext`, the header's exact canonical bytes as AEAD associated data,
//! Argon2id with the cost stored in the header. The header names no tenant,
//! root or instance; each entry is bound to its use by `credential_ref`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};
use crate::keys::fill_random;
use crate::passphrase::MIN_PASSPHRASE_LEN;
use crate::recovery_bundle::{
    argon2id_kek, strictly_increasing, supported, u32_of, AEAD_CHACHA20_POLY1305, CIPHERTEXT_BYTES,
    DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY_KIB, KDF_ARGON2ID, KDF_ITERATIONS, KDF_MEMORY_KIB,
    KDF_PARALLELISM, MAX_FILE_BYTES,
};

pub const DOMAIN_FALLBACK_KEY_FILE: &str = "shardx.local.fallback-key-file.v2";
pub const DOMAIN_PLAINTEXT: &str = "shardx.local.fallback-key-file-plaintext.v2";
const VERSION: u64 = 2;
pub const KDF_SALT_CONTEXT: &[u8] = b"SHARDX-FALLBACK-KEY-FILE-KDF-V2\0";
pub const MAX_ENTRIES: usize = 4096;
const MAX_CREDENTIAL_REF_BYTES: usize = 255;

#[derive(Debug, PartialEq, Eq)]
pub enum FallbackKeyFileError {
    /// Not the closed canonical map the format defines, or a value outside
    /// its bound.
    Format(RecordError),
    PassphraseTooShort,
    Kdf,
    /// The wrong passphrase, or bytes changed since the file was written.
    Decrypt,
    Entropy,
}

impl From<RecordError> for FallbackKeyFileError {
    fn from(e: RecordError) -> Self {
        Self::Format(e)
    }
}

impl std::fmt::Display for FallbackKeyFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(e) => write!(f, "not a fallback key file: {e}"),
            Self::PassphraseTooShort => write!(
                f,
                "a key file passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
            ),
            Self::Kdf => write!(f, "could not derive a key from the passphrase"),
            Self::Decrypt => write!(
                f,
                "the key file does not open: wrong passphrase or a changed file"
            ),
            Self::Entropy => write!(f, "the OS entropy source is unavailable"),
        }
    }
}

impl std::error::Error for FallbackKeyFileError {}

type Result<T> = std::result::Result<T, FallbackKeyFileError>;

/// `FallbackKeyFileHeaderV2`. Its canonical bytes are the AEAD associated
/// data. Only [`seal`] makes one, with a fresh salt and nonce each time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackKeyFileHeaderV2 {
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_salt: [u8; 16],
    pub aead_nonce: [u8; 12],
    pub created_at_ms: u64,
}

impl FallbackKeyFileHeaderV2 {
    fn entries(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("domain", c::t(DOMAIN_FALLBACK_KEY_FILE)),
            ("version", c::u(VERSION)),
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
        f.exact_text("domain", DOMAIN_FALLBACK_KEY_FILE)?;
        supported(f, "version", VERSION)?;
        supported(f, "kdf_id", KDF_ARGON2ID)?;
        let kdf_memory_kib = u32_of(f, "kdf_memory_kib")?;
        let kdf_iterations = u32_of(f, "kdf_iterations")?;
        supported(f, "kdf_parallelism", KDF_PARALLELISM.into())?;
        let kdf_salt = f.fixed("kdf_salt")?;
        supported(f, "aead_suite_id", AEAD_CHACHA20_POLY1305)?;
        let aead_nonce = f.fixed("aead_nonce")?;
        let created_at_ms = f.uint("created_at_ms")?;
        let header = Self {
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

/// What a key is for. Encoded as its lowercase name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Signing,
    Hpke,
    Trk,
    Fkek,
}

impl KeyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signing => "signing",
            Self::Hpke => "hpke",
            Self::Trk => "trk",
            Self::Fkek => "fkek",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [Self::Signing, Self::Hpke, Self::Trk, Self::Fkek]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

/// One key in the file.
pub struct FallbackEntry {
    pub credential_ref: String,
    pub key_kind: KeyKind,
    pub key_bytes: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for FallbackEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackEntry")
            .field("credential_ref", &self.credential_ref)
            .field("key_kind", &self.key_kind)
            .field("key_bytes", &"<redacted>")
            .finish()
    }
}

fn valid_ref(r: &str) -> bool {
    (1..=MAX_CREDENTIAL_REF_BYTES).contains(&r.len())
}

// shortcut: as in the recovery bundle, the canonical codec copies key bytes
// into plain `Vec`s while encoding and decoding, and those copies are not
// zeroized.
fn encode_plaintext(entries: &[&FallbackEntry]) -> Result<Zeroizing<Vec<u8>>> {
    let refs = entries.iter().map(|e| e.credential_ref.as_str());
    if entries.len() > MAX_ENTRIES
        || !strictly_increasing(refs)
        || !entries.iter().all(|e| valid_ref(&e.credential_ref))
    {
        return Err(RecordError::BadValue("entries").into());
    }
    let items = entries
        .iter()
        .map(|e| {
            c::m(vec![
                ("credential_ref", c::t(&e.credential_ref)),
                ("key_kind", c::t(e.key_kind.as_str())),
                ("key_bytes", c::b(e.key_bytes.as_slice())),
            ])
        })
        .collect();
    Ok(Zeroizing::new(c::encode(&c::m(vec![
        ("domain", c::t(DOMAIN_PLAINTEXT)),
        ("version", c::u(VERSION)),
        ("entries", Value::Array(items)),
    ]))))
}

fn parse_plaintext(bytes: &[u8]) -> Result<Vec<FallbackEntry>> {
    let mut f = Fields::decode("FallbackKeyFilePlaintextV2", bytes)?;
    f.exact_text("domain", DOMAIN_PLAINTEXT)?;
    supported(&mut f, "version", VERSION)?;
    let items = match f.req("entries")? {
        Value::Array(items) if items.len() <= MAX_ENTRIES => items,
        _ => return Err(f.bad("entries").into()),
    };
    let mut entries = Vec::with_capacity(items.len());
    for v in items {
        let mut e = Fields::open("FallbackKeyFileEntry", v)?;
        let credential_ref = e.text("credential_ref")?;
        if !valid_ref(&credential_ref) {
            return Err(e.bad("credential_ref").into());
        }
        let key_kind = KeyKind::parse(&e.text("key_kind")?).ok_or(e.bad("key_kind"))?;
        let key_bytes = Zeroizing::new(e.fixed::<32>("key_bytes")?);
        e.finish()?;
        entries.push(FallbackEntry {
            credential_ref,
            key_kind,
            key_bytes,
        });
    }
    f.finish()?;
    if !strictly_increasing(entries.iter().map(|e| e.credential_ref.as_str())) {
        return Err(RecordError::BadValue("entries").into());
    }
    Ok(entries)
}

fn kek(passphrase: &str, header: &FallbackKeyFileHeaderV2) -> Result<Zeroizing<[u8; 32]>> {
    argon2id_kek(
        passphrase,
        KDF_SALT_CONTEXT,
        header.kdf_memory_kib,
        header.kdf_iterations,
        &header.kdf_salt,
    )
    .ok_or(FallbackKeyFileError::Kdf)
}

fn seal_exact(
    header: &FallbackKeyFileHeaderV2,
    plaintext: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>> {
    header.check_cost()?;
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(FallbackKeyFileError::PassphraseTooShort);
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
    let mut fields = header.entries();
    fields.push(("ciphertext", c::b(&ciphertext)));
    Ok(c::encode(&c::m(fields)))
}

fn seal_with(
    header: &FallbackKeyFileHeaderV2,
    entries: &[FallbackEntry],
    passphrase: &str,
) -> Result<Vec<u8>> {
    let mut sorted: Vec<&FallbackEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.credential_ref.cmp(&b.credential_ref));
    seal_exact(header, &encode_plaintext(&sorted)?, passphrase)
}

/// Writes `entries` (in any order, each `credential_ref` once) under
/// `passphrase` at the default cost, with a fresh salt and nonce. Returns the
/// exact file bytes.
pub fn seal(entries: &[FallbackEntry], passphrase: &str, created_at_ms: u64) -> Result<Vec<u8>> {
    let mut kdf_salt = [0u8; 16];
    let mut aead_nonce = [0u8; 12];
    fill_random(&mut kdf_salt).map_err(|_| FallbackKeyFileError::Entropy)?;
    fill_random(&mut aead_nonce).map_err(|_| FallbackKeyFileError::Entropy)?;
    let header = FallbackKeyFileHeaderV2 {
        kdf_memory_kib: DEFAULT_KDF_MEMORY_KIB,
        kdf_iterations: DEFAULT_KDF_ITERATIONS,
        kdf_salt,
        aead_nonce,
        created_at_ms,
    };
    seal_with(&header, entries, passphrase)
}

/// Opens exact file bytes. The entries come back sorted by `credential_ref`.
/// The passphrase length is checked only when sealing, so a later build that
/// raises the minimum still opens older files.
pub fn open(
    file: &[u8],
    passphrase: &str,
) -> Result<(FallbackKeyFileHeaderV2, Vec<FallbackEntry>)> {
    if file.len() > MAX_FILE_BYTES {
        return Err(RecordError::BadValue("file").into());
    }
    let mut f = Fields::decode("FallbackKeyFileV2", file)?;
    let header = FallbackKeyFileHeaderV2::read(&mut f)?;
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
            .map_err(|_| FallbackKeyFileError::Decrypt)?,
    );
    Ok((header, parse_plaintext(&plaintext)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn header() -> FallbackKeyFileHeaderV2 {
        FallbackKeyFileHeaderV2 {
            kdf_memory_kib: DEFAULT_KDF_MEMORY_KIB,
            kdf_iterations: DEFAULT_KDF_ITERATIONS,
            kdf_salt: [3; 16],
            aead_nonce: [4; 12],
            created_at_ms: 1_800_000_000_000,
        }
    }

    fn entry(r: &str, key_kind: KeyKind, byte: u8) -> FallbackEntry {
        FallbackEntry {
            credential_ref: r.into(),
            key_kind,
            key_bytes: Zeroizing::new([byte; 32]),
        }
    }

    fn sample() -> Vec<FallbackEntry> {
        vec![
            entry("fleet-key.ab.1", KeyKind::Fkek, 0x11),
            entry("device-signing.cd", KeyKind::Signing, 0x22),
            entry("device-hpke.cd", KeyKind::Hpke, 0x33),
        ]
    }

    /// The file with `plaintext` sealed exactly, for inputs `seal` refuses.
    fn raw(plaintext: Vec<(&'static str, Value)>) -> Vec<u8> {
        seal_exact(&header(), &c::encode(&c::m(plaintext)), PASS).unwrap()
    }

    fn item(r: &str, kind: &str) -> Value {
        c::m(vec![
            ("credential_ref", c::t(r)),
            ("key_kind", c::t(kind)),
            ("key_bytes", c::b(&[5; 32])),
        ])
    }

    fn plaintext_with(items: Vec<Value>) -> Vec<(&'static str, Value)> {
        vec![
            ("domain", c::t(DOMAIN_PLAINTEXT)),
            ("version", c::u(VERSION)),
            ("entries", Value::Array(items)),
        ]
    }

    const GOLDEN_FILE: &str = "9818525882351c221882db754a1f5d9c13717491b0d4dc5aa12fac7305335807";

    #[test]
    fn a_file_round_trips_sorted_and_is_pinned() {
        let file = seal_with(&header(), &sample(), PASS).unwrap();
        assert_eq!(hex(&c::sha256(&file)), GOLDEN_FILE);

        let (h, entries) = open(&file, PASS).unwrap();
        assert_eq!(h, header());
        let got: Vec<_> = entries
            .iter()
            .map(|e| (e.credential_ref.as_str(), e.key_kind, *e.key_bytes))
            .collect();
        assert_eq!(
            got,
            [
                ("device-hpke.cd", KeyKind::Hpke, [0x33; 32]),
                ("device-signing.cd", KeyKind::Signing, [0x22; 32]),
                ("fleet-key.ab.1", KeyKind::Fkek, [0x11; 32]),
            ]
        );
        assert!(!format!("{entries:?}").contains("51"), "{entries:?}");

        // An empty file is valid: every key moved to the OS store.
        let (_, none) = open(&seal_with(&header(), &[], PASS).unwrap(), PASS).unwrap();
        assert!(none.is_empty());

        // A fresh seal draws a new salt and nonce.
        let fresh = seal(&sample(), PASS, 1).unwrap();
        let (fh, _) = open(&fresh, PASS).unwrap();
        assert_ne!((fh.kdf_salt, fh.aead_nonce), ([3; 16], [4; 12]));
    }

    #[test]
    fn the_wrong_passphrase_or_a_changed_header_does_not_open() {
        let file = seal_with(&header(), &sample(), PASS).unwrap();
        assert!(matches!(
            open(&file, "correct horse battery!"),
            Err(FallbackKeyFileError::Decrypt)
        ));
        // Every header field is in the associated data.
        let moved = FallbackKeyFileHeaderV2 {
            created_at_ms: 1,
            ..header()
        };
        let ciphertext = {
            let mut f = Fields::decode("FallbackKeyFileV2", &file).unwrap();
            FallbackKeyFileHeaderV2::read(&mut f).unwrap();
            f.bytes("ciphertext", 0, usize::MAX).unwrap()
        };
        let mut fields = moved.entries();
        fields.push(("ciphertext", c::b(&ciphertext)));
        assert!(matches!(
            open(&c::encode(&c::m(fields)), PASS),
            Err(FallbackKeyFileError::Decrypt)
        ));
        // The recovery bundle's KDF label derives another key.
        assert_ne!(
            *kek(PASS, &header()).unwrap(),
            *argon2id_kek(
                PASS,
                b"SHARDX-RECOVERY-BUNDLE-KDF-V2\0",
                DEFAULT_KDF_MEMORY_KIB,
                DEFAULT_KDF_ITERATIONS,
                &[3; 16]
            )
            .unwrap()
        );
    }

    #[test]
    fn sealing_refuses_what_the_format_cannot_hold() {
        let short = "seven77";
        assert!(matches!(
            seal_with(&header(), &sample(), short),
            Err(FallbackKeyFileError::PassphraseTooShort)
        ));
        let twice = [entry("a", KeyKind::Trk, 1), entry("a", KeyKind::Hpke, 2)];
        assert!(matches!(
            seal_with(&header(), &twice, PASS),
            Err(FallbackKeyFileError::Format(_))
        ));
        for bad in ["".to_string(), "x".repeat(256)] {
            assert!(seal_with(&header(), &[entry(&bad, KeyKind::Trk, 1)], PASS).is_err());
        }
        assert!(seal_with(&header(), &[entry(&"x".repeat(255), KeyKind::Trk, 1)], PASS).is_ok());
        let cheap = FallbackKeyFileHeaderV2 {
            kdf_memory_kib: 65_535,
            ..header()
        };
        assert!(matches!(
            seal_with(&cheap, &sample(), PASS),
            Err(FallbackKeyFileError::Format(RecordError::BadValue(
                "kdf_memory_kib"
            )))
        ));
    }

    #[test]
    fn opening_refuses_a_header_outside_its_bounds_before_the_kdf() {
        let with = |h: &FallbackKeyFileHeaderV2, extra: Option<(&'static str, Value)>| {
            let mut fields = h.entries();
            fields.push(("ciphertext", c::b(&[0; 48])));
            fields.extend(extra);
            c::encode(&c::m(fields))
        };
        for (h, field) in [
            (
                FallbackKeyFileHeaderV2 {
                    kdf_memory_kib: 65_535,
                    ..header()
                },
                "kdf_memory_kib",
            ),
            (
                FallbackKeyFileHeaderV2 {
                    kdf_memory_kib: 1_048_577,
                    ..header()
                },
                "kdf_memory_kib",
            ),
            (
                FallbackKeyFileHeaderV2 {
                    kdf_iterations: 2,
                    ..header()
                },
                "kdf_iterations",
            ),
            (
                FallbackKeyFileHeaderV2 {
                    kdf_iterations: 65,
                    ..header()
                },
                "kdf_iterations",
            ),
        ] {
            assert_eq!(
                open(&with(&h, None), PASS).unwrap_err(),
                FallbackKeyFileError::Format(RecordError::BadValue(field))
            );
        }
        // A closed map: an unknown field is refused, not ignored.
        assert!(matches!(
            open(&with(&header(), Some(("tenant_id", c::b(&[1; 16])))), PASS),
            Err(FallbackKeyFileError::Format(_))
        ));
        // A well-formed header with a ciphertext that is not this file's.
        assert_eq!(
            open(&with(&header(), None), PASS).unwrap_err(),
            FallbackKeyFileError::Decrypt
        );
    }

    #[test]
    fn opening_refuses_a_plaintext_outside_the_format() {
        let ok = raw(plaintext_with(vec![item("a", "trk"), item("b", "fkek")]));
        assert_eq!(open(&ok, PASS).unwrap().1.len(), 2);
        for items in [
            vec![item("b", "trk"), item("a", "trk")],
            vec![item("a", "trk"), item("a", "hpke")],
            vec![item("a", "root")],
            vec![item("", "trk")],
        ] {
            assert!(
                matches!(
                    open(&raw(plaintext_with(items)), PASS),
                    Err(FallbackKeyFileError::Format(_))
                ),
                "accepted"
            );
        }
        let mut extra = plaintext_with(vec![]);
        extra.push(("note", c::t("x")));
        assert!(open(&raw(extra), PASS).is_err());
        let mut wrong_domain = plaintext_with(vec![]);
        wrong_domain[0] = ("domain", c::t("shardx.recovery.bundle-plaintext.v2"));
        assert!(open(&raw(wrong_domain), PASS).is_err());
    }
}
