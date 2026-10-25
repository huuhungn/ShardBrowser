//! `CanonicalCborV2` — the deterministic wire codec for ShardX v0.2 team/fleet
//! sync and encrypted profile backup.
//!
//! Every v2 container that is hashed, signed, wrapped or persisted is encoded
//! with this codec. Determinism is a security property here, not a convenience:
//! signatures and AEAD associated data are computed over these exact bytes, so
//! two peers must agree on them byte-for-byte or verification fails closed.
//!
//! `CanonicalCborV2` is RFC 8949 deterministic CBOR restricted to:
//!   * definite-length maps/arrays only
//!   * shortest integer/length form
//!   * text keys, ordered by encoded-key bytes, no duplicates
//!   * no tags, no floats, no simple values other than `true`/`false`
//!   * closed maps — unknown fields are rejected, never ignored
//!   * optional fields are OMITTED, never encoded as `null`
//!
//! The wire schema implemented here is fixed by section 5.6 of the v0.2.x plan
//! and was validated byte-for-byte by the G2 conformance gate; the golden
//! vectors in the test module below are pinned from that gate's report.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bool(bool),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    /// Entries are sorted at encode time by encoded-key bytes, so construction
    /// order never leaks into the wire form.
    Map(Vec<(String, Value)>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CborError {
    /// A length or count not in its shortest form.
    NonCanonicalIntegerForm,
    /// An integer (major type 0 or 1) not in its shortest form. Kept apart from
    /// lengths because plan L1236 gives integers `WIRE_INTEGER_OUT_OF_RANGE`.
    OverlongInteger,
    IndefiniteLength,
    UnsupportedMajorType(u8),
    FloatOrSimpleValue,
    Tag,
    DuplicateKey(String),
    UnsortedKey {
        previous: String,
        current: String,
    },
    NonTextKey,
    TrailingBytes(usize),
    UnexpectedEof,
    InvalidUtf8,
    NulInText,
    IntegerOutOfSqliteDomain(u64),
    /// Arrays and maps nested deeper than [`MAX_NESTING`].
    NestingTooDeep,
}

impl std::fmt::Display for CborError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonicalIntegerForm => write!(f, "non-canonical integer/length form"),
            Self::OverlongInteger => write!(f, "integer not in its shortest form"),
            Self::IndefiniteLength => write!(f, "indefinite-length item"),
            Self::UnsupportedMajorType(m) => write!(f, "unsupported CBOR major type {m}"),
            Self::FloatOrSimpleValue => write!(f, "float or disallowed simple value"),
            Self::Tag => write!(f, "CBOR tags are not permitted"),
            Self::DuplicateKey(k) => write!(f, "duplicate map key: {k}"),
            Self::UnsortedKey { previous, current } => {
                write!(f, "unsorted map key: {current} after {previous}")
            }
            Self::NonTextKey => write!(f, "non-text map key"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing byte(s) after top-level item"),
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in text string"),
            Self::NulInText => write!(f, "NUL byte in text string"),
            Self::IntegerOutOfSqliteDomain(v) => {
                write!(f, "integer {v} outside 0..=i64::MAX SQLite domain")
            }
            Self::NestingTooDeep => write!(f, "arrays or maps nested deeper than {MAX_NESTING}"),
        }
    }
}

impl std::error::Error for CborError {}

/// Every unsigned wire integer that is persisted or mirrored in SQLite has an
/// accepted domain of `0..=i64::MAX`. This is enforced at codec level so no
/// value can reach a cast or SQL bind out of range.
pub const MAX_SQLITE_WIRE_UINT: u64 = i64::MAX as u64;

/// Deepest array/map nesting a decoder accepts. Every v2 record is far
/// shallower; the bound stops a few kilobytes of nested arrays from
/// overflowing the stack of whoever parses untrusted bytes.
pub const MAX_NESTING: usize = 16;

// ---------------------------------------------------------------- encoding --

fn enc_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Deterministic key ordering: RFC 8949 §4.2.1 orders map keys by their encoded
/// byte representation.
fn encoded_key(key: &str) -> Vec<u8> {
    let mut out = Vec::new();
    enc_head(&mut out, 3, key.len() as u64);
    out.extend_from_slice(key.as_bytes());
    out
}

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(n) => enc_head(out, 0, *n),
        Value::Bytes(b) => {
            enc_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            enc_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            enc_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(entries) => {
            let mut sorted: BTreeMap<Vec<u8>, &Value> = BTreeMap::new();
            for (k, v) in entries {
                sorted.insert(encoded_key(k), v);
            }
            enc_head(out, 5, sorted.len() as u64);
            for (k, v) in sorted {
                out.extend_from_slice(&k);
                encode_into(v, out);
            }
        }
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
    }
}

// ---------------------------------------------------------------- decoding --

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Decoder<'a> {
    fn enter(&mut self) -> Result<(), CborError> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err(CborError::NestingTooDeep);
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.buf.get(self.pos).ok_or(CborError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::UnexpectedEof)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(CborError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    /// Reads a head and enforces shortest-form (canonical) argument encoding.
    fn head(&mut self) -> Result<(u8, u64), CborError> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        let overlong = if major <= 1 {
            CborError::OverlongInteger
        } else {
            CborError::NonCanonicalIntegerForm
        };
        let arg = match ai {
            0..=23 => ai as u64,
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(overlong);
                }
                v
            }
            25 => {
                let b = self.take(2)?;
                let v = u16::from_be_bytes([b[0], b[1]]) as u64;
                if v <= u8::MAX as u64 {
                    return Err(overlong);
                }
                v
            }
            26 => {
                let b = self.take(4)?;
                let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v <= u16::MAX as u64 {
                    return Err(overlong);
                }
                v
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v <= u32::MAX as u64 {
                    return Err(overlong);
                }
                v
            }
            31 => return Err(CborError::IndefiniteLength),
            _ => return Err(CborError::NonCanonicalIntegerForm),
        };
        Ok((major, arg))
    }

    fn value(&mut self) -> Result<Value, CborError> {
        let start = self.pos;
        let ib = *self.buf.get(start).ok_or(CborError::UnexpectedEof)?;
        let major = ib >> 5;

        // Reject simple/float/tag before generic head parsing so the error is exact.
        if major == 6 {
            return Err(CborError::Tag);
        }
        if major == 7 {
            self.pos += 1;
            return match ib {
                0xf4 => Ok(Value::Bool(false)),
                0xf5 => Ok(Value::Bool(true)),
                _ => Err(CborError::FloatOrSimpleValue),
            };
        }

        let (major, arg) = self.head()?;
        match major {
            0 => {
                if arg > MAX_SQLITE_WIRE_UINT {
                    return Err(CborError::IntegerOutOfSqliteDomain(arg));
                }
                Ok(Value::Uint(arg))
            }
            1 => Err(CborError::UnsupportedMajorType(1)),
            2 => Ok(Value::Bytes(self.take(arg as usize)?.to_vec())),
            3 => {
                let raw = self.take(arg as usize)?;
                let s = std::str::from_utf8(raw).map_err(|_| CborError::InvalidUtf8)?;
                if s.contains('\0') {
                    return Err(CborError::NulInText);
                }
                Ok(Value::Text(s.to_string()))
            }
            4 => {
                let mut items = Vec::with_capacity(arg.min(1024) as usize);
                self.enter()?;
                for _ in 0..arg {
                    items.push(self.value()?);
                }
                self.depth -= 1;
                Ok(Value::Array(items))
            }
            5 => {
                self.enter()?;
                let mut entries: Vec<(String, Value)> = Vec::with_capacity(arg.min(1024) as usize);
                let mut prev_key: Option<Vec<u8>> = None;
                for _ in 0..arg {
                    let key_start = self.pos;
                    let kb = *self.buf.get(key_start).ok_or(CborError::UnexpectedEof)?;
                    if kb >> 5 != 3 {
                        return Err(CborError::NonTextKey);
                    }
                    let (_, klen) = self.head()?;
                    let raw = self.take(klen as usize)?;
                    let key = std::str::from_utf8(raw)
                        .map_err(|_| CborError::InvalidUtf8)?
                        .to_string();
                    let enc = self.buf[key_start..self.pos].to_vec();
                    if let Some(prev) = &prev_key {
                        match enc.cmp(prev) {
                            std::cmp::Ordering::Equal => {
                                return Err(CborError::DuplicateKey(key));
                            }
                            std::cmp::Ordering::Less => {
                                let previous = entries
                                    .last()
                                    .map(|(k, _): &(String, Value)| k.clone())
                                    .unwrap_or_default();
                                return Err(CborError::UnsortedKey {
                                    previous,
                                    current: key,
                                });
                            }
                            std::cmp::Ordering::Greater => {}
                        }
                    }
                    prev_key = Some(enc);
                    let v = self.value()?;
                    entries.push((key, v));
                }
                self.depth -= 1;
                Ok(Value::Map(entries))
            }
            other => Err(CborError::UnsupportedMajorType(other)),
        }
    }
}

/// Strict decode: canonical form, no trailing bytes.
pub fn decode(buf: &[u8]) -> Result<Value, CborError> {
    let mut d = Decoder {
        buf,
        pos: 0,
        depth: 0,
    };
    let v = d.value()?;
    if d.pos != buf.len() {
        return Err(CborError::TrailingBytes(buf.len() - d.pos));
    }
    Ok(v)
}

/// Decode → re-encode → byte equality. Any input that does not survive this is
/// non-canonical by definition.
pub fn assert_canonical_roundtrip(buf: &[u8]) -> Result<Value, CborError> {
    let v = decode(buf)?;
    let re = encode(&v);
    if re != buf {
        return Err(CborError::NonCanonicalIntegerForm);
    }
    Ok(v)
}

// -------------------------------------------------------- hash preimages ----

/// Domain-separated hash preimage used by every named 5.6 contract:
/// `SHA256(ASCII domain-label + NUL + u32be(len(bytes)) + bytes)`.
///
/// The length prefix is what makes the preimage unambiguous: without it, two
/// different (label, body) splits could collide on the same byte string.
pub fn domain_hash(ascii_label_with_nul: &str, bytes: &[u8]) -> [u8; 32] {
    debug_assert!(ascii_label_with_nul.ends_with('\0'));
    let mut h = Sha256::new();
    h.update(ascii_label_with_nul.as_bytes());
    h.update((bytes.len() as u32).to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

// Exact domain labels from section 5.6 (NUL terminator included).
pub const L_SIGNED_RECORD: &str = "SHARDX-SIGNED-RECORD-V2\0";
pub const L_SIGNED_CONTAINER: &str = "SHARDX-SIGNED-CONTAINER-V2\0";
pub const L_DEK_SLOT_CONTEXT: &str = "SHARDX-DEK-SLOT-CONTEXT-V2\0";
pub const L_DEK_SLOT: &str = "SHARDX-DEK-SLOT-V2\0";
pub const L_ENVELOPE_INTENT: &str = "SHARDX-ENVELOPE-INTENT-V2\0";
pub const L_COMMIT_REQUEST: &str = "SHARDX-COMMIT-REQUEST-V2\0";
pub const L_RESTORE_EPOCH_LEAF: &str = "SHARDX-RESTORE-EPOCH-LEAF-V2\0";
pub const L_RESTORE_EPOCH_NODE2: &str = "SHARDX-RESTORE-EPOCH-NODE2-V2\0";
pub const L_RESTORE_EPOCH_NODE1: &str = "SHARDX-RESTORE-EPOCH-NODE1-V2\0";
pub const L_RESTORE_EPOCH_PROOF: &str = "SHARDX-RESTORE-EPOCH-PROOF-V2\0";

/// Bound on Merkle leaf count, enforced before any allocation sized by input.
pub const MAX_RESTORE_EPOCH_LEAVES_V2: u64 = 1_000_000;

// -------------------------------------------------------------- builders ----

/// Build a canonical map from `(key, value)` pairs. Ordering is applied at
/// encode time, so callers may list fields in schema order for readability.
pub fn m(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

pub fn t(s: &str) -> Value {
    Value::Text(s.to_string())
}

pub fn b(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.to_vec())
}

pub fn u(n: u64) -> Value {
    Value::Uint(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nesting_is_bounded_before_the_stack_is() {
        // [[...[0]...]] with `n` arrays.
        let nested = |n: usize| {
            let mut v = vec![0x81u8; n];
            v.push(0x00);
            v
        };
        assert!(decode(&nested(MAX_NESTING)).is_ok());
        assert_eq!(
            decode(&nested(MAX_NESTING + 1)),
            Err(CborError::NestingTooDeep)
        );
        // A few kilobytes that used to overflow the stack now fail cleanly.
        assert_eq!(decode(&nested(5_000)), Err(CborError::NestingTooDeep));
        // Maps count too: {"a": {"a": ... 0}}.
        let mut deep_map = Vec::new();
        for _ in 0..=MAX_NESTING {
            deep_map.extend_from_slice(&[0xa1, 0x61, b'a']);
        }
        deep_map.push(0x00);
        assert_eq!(decode(&deep_map), Err(CborError::NestingTooDeep));
        // Siblings do not add depth.
        let mut wide = vec![0x98, 100];
        wide.extend(std::iter::repeat_n([0x81u8, 0x00], 100).flatten());
        assert!(decode(&wide).is_ok());
    }

    fn hex32(h: &[u8; 32]) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Deterministic non-secret test material, byte-identical to the generator
    /// used by the G2 conformance gate so the pinned vectors below reproduce.
    /// Fixture material only — never a key-generation strategy.
    fn fixture_bytes<const N: usize>(label: &str) -> [u8; N] {
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

    // ------------------------------------------------------ codec basics ----

    #[test]
    fn map_keys_are_sorted_by_encoded_bytes_not_insertion_order() {
        // "z" (1 byte) sorts before "aa" (2 bytes): length-prefixed key ordering.
        let a = encode(&m(vec![("z", u(1)), ("aa", u(2))]));
        let b_enc = encode(&m(vec![("aa", u(2)), ("z", u(1))]));
        assert_eq!(a, b_enc, "insertion order must not affect the wire form");
        assert_eq!(a, vec![0xa2, 0x61, 0x7a, 0x01, 0x62, 0x61, 0x61, 0x02]);
    }

    #[test]
    fn shortest_form_is_required_on_decode() {
        // 24 encoded in two bytes (0x18 0x18) is canonical; 0x18 0x17 is not.
        assert_eq!(decode(&[0x18, 0x18]), Ok(Value::Uint(24)));
        assert_eq!(decode(&[0x18, 0x17]), Err(CborError::OverlongInteger));
        // -1 as 0x38 0x00, and 1 at every wider width.
        for overlong in [
            &[0x38, 0x00][..],
            &[0x19, 0x00, 0x01],
            &[0x1a, 0, 0, 0, 1],
            &[0x1b, 0, 0, 0, 0, 0, 0, 0, 1],
        ] {
            assert_eq!(decode(overlong), Err(CborError::OverlongInteger));
        }
        // A length keeps the generic code: a one-byte text string with a
        // two-byte length head.
        assert_eq!(
            decode(&[0x78, 0x01, b'a']),
            Err(CborError::NonCanonicalIntegerForm)
        );
    }

    #[test]
    fn indefinite_length_is_rejected() {
        assert_eq!(decode(&[0x5f]), Err(CborError::IndefiniteLength));
    }

    #[test]
    fn tags_and_floats_are_rejected() {
        assert_eq!(decode(&[0xc0]), Err(CborError::Tag));
        assert_eq!(
            decode(&[0xf9, 0x00, 0x00]),
            Err(CborError::FloatOrSimpleValue)
        );
        assert_eq!(decode(&[0xf6]), Err(CborError::FloatOrSimpleValue)); // null
    }

    #[test]
    fn negative_integers_are_rejected() {
        assert_eq!(decode(&[0x20]), Err(CborError::UnsupportedMajorType(1)));
    }

    #[test]
    fn unsorted_and_duplicate_keys_are_rejected() {
        // {"b":1,"a":2} — wrong order.
        let unsorted = [0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02];
        assert!(matches!(
            decode(&unsorted),
            Err(CborError::UnsortedKey { .. })
        ));
        // {"a":1,"a":2} — duplicate.
        let dup = [0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02];
        assert_eq!(decode(&dup), Err(CborError::DuplicateKey("a".into())));
    }

    #[test]
    fn non_text_keys_are_rejected() {
        // {1:1}
        assert_eq!(decode(&[0xa1, 0x01, 0x01]), Err(CborError::NonTextKey));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert_eq!(decode(&[0x01, 0x02]), Err(CborError::TrailingBytes(1)));
    }

    #[test]
    fn integers_above_i64_max_are_out_of_sqlite_domain() {
        let mut buf = vec![0x1b];
        buf.extend_from_slice(&(i64::MAX as u64 + 1).to_be_bytes());
        assert_eq!(
            decode(&buf),
            Err(CborError::IntegerOutOfSqliteDomain(i64::MAX as u64 + 1))
        );

        let mut ok = vec![0x1b];
        ok.extend_from_slice(&MAX_SQLITE_WIRE_UINT.to_be_bytes());
        assert_eq!(decode(&ok), Ok(Value::Uint(MAX_SQLITE_WIRE_UINT)));
    }

    #[test]
    fn nul_in_text_is_rejected() {
        // "a\0" as a 2-byte text string.
        assert_eq!(decode(&[0x62, 0x61, 0x00]), Err(CborError::NulInText));
    }

    #[test]
    fn truncated_input_is_eof_not_panic() {
        assert_eq!(decode(&[0x43, 0x01]), Err(CborError::UnexpectedEof));
        assert_eq!(decode(&[]), Err(CborError::UnexpectedEof));
    }

    #[test]
    fn roundtrip_preserves_bytes_for_nested_structures() {
        let v = m(vec![
            ("domain", t("shardx.test.v2")),
            ("version", u(2)),
            ("blob", b(&[0xde, 0xad, 0xbe, 0xef])),
            ("flag", Value::Bool(true)),
            ("list", Value::Array(vec![u(1), u(24), u(256), u(65536)])),
        ]);
        let bytes = encode(&v);

        // Decoding yields map entries in canonical (encoded-key) order, which is
        // not the declaration order above — so compare on the byte form, which is
        // what signatures and AAD actually commit to.
        let decoded = assert_canonical_roundtrip(&bytes).expect("canonical");
        assert_eq!(encode(&decoded), bytes);

        match decoded {
            Value::Map(entries) => {
                let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(keys, vec!["blob", "flag", "list", "domain", "version"]);
            }
            other => panic!("expected map, got {other:?}"),
        }
    }

    // ---------------------------------------------- domain-hash preimage ----

    #[test]
    fn domain_hash_is_length_prefixed_and_unambiguous() {
        // Same concatenated body, different split → different hash.
        let a = domain_hash(L_DEK_SLOT_CONTEXT, b"abc");
        let c = domain_hash(L_DEK_SLOT_CONTEXT, b"ab");
        assert_ne!(a, c);

        // Label separation: identical body under different labels must differ.
        assert_ne!(
            domain_hash(L_DEK_SLOT_CONTEXT, b"x"),
            domain_hash(L_ENVELOPE_INTENT, b"x")
        );
    }

    #[test]
    fn domain_labels_are_nul_terminated() {
        for label in [
            L_SIGNED_RECORD,
            L_SIGNED_CONTAINER,
            L_DEK_SLOT_CONTEXT,
            L_DEK_SLOT,
            L_ENVELOPE_INTENT,
            L_COMMIT_REQUEST,
            L_RESTORE_EPOCH_LEAF,
            L_RESTORE_EPOCH_NODE2,
            L_RESTORE_EPOCH_NODE1,
            L_RESTORE_EPOCH_PROOF,
        ] {
            assert!(label.ends_with('\0'), "missing NUL: {label}");
            assert!(label.is_ascii(), "non-ASCII label: {label}");
        }
    }

    // --------------------------------------------------- G2 golden vector ---

    /// Pinned from the G2 conformance report, probe `G2-VEC-dek-slot-context`.
    /// This is the exact closed map of plan 5.6.3 `DekSlotContextV2`; any field
    /// added, removed, renamed or reordered changes this hash and fails here.
    #[test]
    fn g2_golden_vector_dek_slot_context_hash() {
        let tenant_id: [u8; 16] = fixture_bytes("tenant-a");
        let fleet_id: [u8; 16] = fixture_bytes("fleet-a");
        let profile_id: [u8; 16] = fixture_bytes("profile-a");
        let snapshot_id: [u8; 16] = fixture_bytes("snapshot-1");
        let envelope_context_nonce: [u8; 16] = fixture_bytes("envelope-context-nonce-1");

        // fkek_key_id is derived, not fixture material: plan 5.6.4 defines it as
        // SHA256("SHARDX-TENANT-ROOT-KEY-ID-V2\0" + u32be(32) + fkek).
        let fkek: [u8; 32] = fixture_bytes("fkek-gen-1");
        let fkek_key_id = domain_hash("SHARDX-TENANT-ROOT-KEY-ID-V2\0", &fkek);

        let context = m(vec![
            ("domain", t("shardx.envelope.dek-slot-context.v2")),
            ("version", u(2)),
            ("slot_index", u(0)),
            ("tenant_id", b(&tenant_id)),
            ("fleet_id", b(&fleet_id)),
            ("profile_id", b(&profile_id)),
            ("snapshot_id", b(&snapshot_id)),
            ("fkek_key_id", b(&fkek_key_id)),
            ("key_generation", u(1)),
            ("wrap_suite_id", u(1)),
            ("envelope_context_nonce", b(&envelope_context_nonce)),
        ]);

        let bytes = encode(&context);
        // The encoded form must itself be canonical.
        assert!(assert_canonical_roundtrip(&bytes).is_ok());

        let hash = domain_hash(L_DEK_SLOT_CONTEXT, &bytes);
        assert_eq!(
            hex32(&hash),
            "26e487058f64657339c12e8f718816f3e1d3442c048354a40709f0c77b5014f1",
            "DekSlotContextV2 hash diverged from the G2-pinned golden vector"
        );
    }
}
