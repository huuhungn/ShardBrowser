//! Restore-preparation manifest and transition-set index (ADR 0002 D-1).
//!
//! The manifest `restore-preparation-v2.bin` lives in the identity directory,
//! outside the DB rollback scope (plan L2248), and binds a prepared restore
//! `E -> E+1` to its candidate DB, its transition set and record `E`. Like the
//! identity record it is a fixed 200-byte big-endian layout, so it is parsed
//! before any CBOR decoder is trusted:
//!
//! | Offset | Size | Field |
//! |---:|---:|---|
//! | 0 | 8 | magic `"SHARDXRP"` |
//! | 8 | 2 | version `u16` = 2 |
//! | 10 | 2 | record_length `u16` = 200 |
//! | 12 | 1 | state `u8`: 1 = PREPARED, 2 = TERMINAL |
//! | 13 | 3 | reserved = 0 |
//! | 16 | 16 | server_instance_id |
//! | 32 | 8 | previous_epoch `u64` |
//! | 40 | 8 | new_epoch `u64` |
//! | 48 | 16 | restore_txn_id |
//! | 64 | 32 | candidate_db_sha256 |
//! | 96 | 32 | transition_set_sha256 |
//! | 128 | 32 | previous_record_sha256 |
//! | 160 | 8 | prepared_at_ms `u64` |
//! | 168 | 32 | checksum = `domain_hash("SHARDX-RESTORE-PREPARATION-V2\0", bytes[0..168])` |

use shared::canonical::{self as c, domain_hash, Value};

pub const MANIFEST_FILE: &str = "restore-preparation-v2.bin";
pub const MAGIC: [u8; 8] = *b"SHARDXRP";
pub const VERSION: u16 = 2;
pub const MANIFEST_LEN: usize = 200;
const BODY_LEN: usize = 168;
const CHECKSUM_LABEL: &str = "SHARDX-RESTORE-PREPARATION-V2\0";
const MAX_WIRE_INT: u64 = i64::MAX as u64;

pub const INDEX_DOMAIN: &str = "shardx.restore-epoch.transition-set-index.v2";
pub const REQUEST_DOMAIN: &str = "shardx.restore-epoch.transition-request.v2";
const PROOF_SET_LABEL: &str = "SHARDX-RESTORE-PROOF-SET-V2\0";
const TRANSITION_SET_LABEL: &str = "SHARDX-RESTORE-TRANSITION-SET-V2\0";
/// D-1: at most 65535 tenants per transition set.
pub const MAX_INDEX_ENTRIES: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Prepared = 1,
    Terminal = 2,
}

/// Why bytes are not a valid manifest; every one is "unparsable" (D-1 `P`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    Length,
    Magic,
    Version,
    LengthField,
    State,
    Reserved,
    Checksum,
    /// An ID or hash is all zero.
    ZeroField,
    /// `new_epoch` is not `previous_epoch + 1`.
    Epoch,
    /// An epoch or `prepared_at_ms` is above `i64::MAX`.
    Range,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparationManifestV2 {
    pub state: State,
    pub server_instance_id: [u8; 16],
    pub previous_epoch: u64,
    pub new_epoch: u64,
    pub restore_txn_id: [u8; 16],
    pub candidate_db_sha256: [u8; 32],
    pub transition_set_sha256: [u8; 32],
    pub previous_record_sha256: [u8; 32],
    pub prepared_at_ms: u64,
}

impl PreparationManifestV2 {
    /// The exact 200 bytes, refusing what [`parse`] would reject.
    pub fn encode(&self) -> Result<[u8; MANIFEST_LEN], ManifestError> {
        let mut out = [0u8; MANIFEST_LEN];
        out[0..8].copy_from_slice(&MAGIC);
        out[8..10].copy_from_slice(&VERSION.to_be_bytes());
        out[10..12].copy_from_slice(&(MANIFEST_LEN as u16).to_be_bytes());
        out[12] = self.state as u8;
        out[16..32].copy_from_slice(&self.server_instance_id);
        out[32..40].copy_from_slice(&self.previous_epoch.to_be_bytes());
        out[40..48].copy_from_slice(&self.new_epoch.to_be_bytes());
        out[48..64].copy_from_slice(&self.restore_txn_id);
        out[64..96].copy_from_slice(&self.candidate_db_sha256);
        out[96..128].copy_from_slice(&self.transition_set_sha256);
        out[128..160].copy_from_slice(&self.previous_record_sha256);
        out[160..168].copy_from_slice(&self.prepared_at_ms.to_be_bytes());
        let checksum = domain_hash(CHECKSUM_LABEL, &out[..BODY_LEN]);
        out[BODY_LEN..].copy_from_slice(&checksum);
        parse(&out)?;
        Ok(out)
    }
}

/// Parse a manifest. Nothing is repaired: any failure is "unparsable".
pub fn parse(bytes: &[u8]) -> Result<PreparationManifestV2, ManifestError> {
    if bytes.len() != MANIFEST_LEN {
        return Err(ManifestError::Length);
    }
    if bytes[0..8] != MAGIC {
        return Err(ManifestError::Magic);
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != VERSION {
        return Err(ManifestError::Version);
    }
    if usize::from(u16::from_be_bytes([bytes[10], bytes[11]])) != MANIFEST_LEN {
        return Err(ManifestError::LengthField);
    }
    let state = match bytes[12] {
        1 => State::Prepared,
        2 => State::Terminal,
        _ => return Err(ManifestError::State),
    };
    if bytes[13..16] != [0; 3] {
        return Err(ManifestError::Reserved);
    }
    if domain_hash(CHECKSUM_LABEL, &bytes[..BODY_LEN])[..] != bytes[BODY_LEN..] {
        return Err(ManifestError::Checksum);
    }
    let u64_at = |i: usize| u64::from_be_bytes(bytes[i..i + 8].try_into().expect("8 bytes"));
    let m = PreparationManifestV2 {
        state,
        server_instance_id: bytes[16..32].try_into().expect("16 bytes"),
        previous_epoch: u64_at(32),
        new_epoch: u64_at(40),
        restore_txn_id: bytes[48..64].try_into().expect("16 bytes"),
        candidate_db_sha256: bytes[64..96].try_into().expect("32 bytes"),
        transition_set_sha256: bytes[96..128].try_into().expect("32 bytes"),
        previous_record_sha256: bytes[128..160].try_into().expect("32 bytes"),
        prepared_at_ms: u64_at(160),
    };
    if m.server_instance_id == [0; 16]
        || m.restore_txn_id == [0; 16]
        || m.candidate_db_sha256 == [0; 32]
        || m.transition_set_sha256 == [0; 32]
        || m.previous_record_sha256 == [0; 32]
    {
        return Err(ManifestError::ZeroField);
    }
    if m.new_epoch > MAX_WIRE_INT || m.prepared_at_ms > MAX_WIRE_INT {
        return Err(ManifestError::Range);
    }
    if m.previous_epoch.checked_add(1) != Some(m.new_epoch) {
        return Err(ManifestError::Epoch);
    }
    Ok(m)
}

/// One tenant's transition in the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub tenant_id: [u8; 16],
    pub exact_signed_transition_bytes_sha256: [u8; 32],
    pub mapping_count: u64,
    pub proof_set_sha256: [u8; 32],
}

/// `RestoreTransitionSetIndexV2` (closed map).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionSetIndexV2 {
    pub server_instance_id: [u8; 16],
    pub previous_epoch: u64,
    pub new_epoch: u64,
    pub restore_txn_id: [u8; 16],
    pub backup_db_sha256: [u8; 32],
    pub live_db_sha256: [u8; 32],
    pub entries: Vec<IndexEntry>,
}

impl TransitionSetIndexV2 {
    /// Canonical bytes; unsorted, duplicate or too many entries are refused.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let sorted = self
            .entries
            .windows(2)
            .all(|w| w[0].tenant_id < w[1].tenant_id);
        if !sorted || self.entries.len() > MAX_INDEX_ENTRIES {
            return None;
        }
        let entries = self
            .entries
            .iter()
            .map(|e| {
                c::m(vec![
                    ("tenant_id", c::b(&e.tenant_id)),
                    (
                        "exact_signed_transition_bytes_sha256",
                        c::b(&e.exact_signed_transition_bytes_sha256),
                    ),
                    ("mapping_count", c::u(e.mapping_count)),
                    ("proof_set_sha256", c::b(&e.proof_set_sha256)),
                ])
            })
            .collect();
        Some(c::encode(&c::m(vec![
            ("domain", c::t(INDEX_DOMAIN)),
            ("version", c::u(2)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("previous_epoch", c::u(self.previous_epoch)),
            ("new_epoch", c::u(self.new_epoch)),
            ("restore_txn_id", c::b(&self.restore_txn_id)),
            ("backup_db_sha256", c::b(&self.backup_db_sha256)),
            ("live_db_sha256", c::b(&self.live_db_sha256)),
            ("entries", Value::Array(entries)),
        ])))
    }

    /// The index the exact bytes encode, or None. Only bytes that re-encode
    /// to themselves are accepted, so one index has one encoding.
    pub fn parse(exact: &[u8]) -> Option<Self> {
        let Ok(Value::Map(fields)) = c::decode(exact) else {
            return None;
        };
        let get = |k: &str| fields.iter().find(|(key, _)| key == k).map(|(_, v)| v);
        let fixed = |v: Option<&Value>| match v {
            Some(Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        };
        let uint = |v: Option<&Value>| match v {
            Some(Value::Uint(n)) => Some(*n),
            _ => None,
        };
        let Some(Value::Array(items)) = get("entries") else {
            return None;
        };
        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            let Value::Map(e) = item else {
                return None;
            };
            let g = |k: &str| e.iter().find(|(key, _)| key == k).map(|(_, v)| v);
            entries.push(IndexEntry {
                tenant_id: fixed(g("tenant_id"))?.try_into().ok()?,
                exact_signed_transition_bytes_sha256: fixed(g(
                    "exact_signed_transition_bytes_sha256",
                ))?
                .try_into()
                .ok()?,
                mapping_count: uint(g("mapping_count"))?,
                proof_set_sha256: fixed(g("proof_set_sha256"))?.try_into().ok()?,
            });
        }
        let index = Self {
            server_instance_id: fixed(get("server_instance_id"))?.try_into().ok()?,
            previous_epoch: uint(get("previous_epoch"))?,
            new_epoch: uint(get("new_epoch"))?,
            restore_txn_id: fixed(get("restore_txn_id"))?.try_into().ok()?,
            backup_db_sha256: fixed(get("backup_db_sha256"))?.try_into().ok()?,
            live_db_sha256: fixed(get("live_db_sha256"))?.try_into().ok()?,
            entries,
        };
        (index.encode()?.as_slice() == exact).then_some(index)
    }
}

/// `transition_set_sha256` of the exact index bytes.
pub fn transition_set_sha256(index_bytes: &[u8]) -> [u8; 32] {
    domain_hash(TRANSITION_SET_LABEL, index_bytes)
}

/// `proof_set_sha256` over each proof's `proof_sha256`, in leaf order.
pub fn proof_set_sha256(proof_sha256s: &[[u8; 32]]) -> [u8; 32] {
    domain_hash(PROOF_SET_LABEL, &proof_sha256s.concat())
}

/// `RestoreEpochTransitionRequestV2`, the file handed to a custodian.
#[allow(clippy::too_many_arguments)]
pub fn encode_request(
    server_instance_id: &[u8; 16],
    tenant_id: &[u8; 16],
    previous_epoch: u64,
    restore_txn_id: &[u8; 16],
    backup_db_sha256: &[u8; 32],
    leaves: &[Vec<u8>],
) -> Vec<u8> {
    c::encode(&c::m(vec![
        ("domain", c::t(REQUEST_DOMAIN)),
        ("version", c::u(2)),
        ("server_instance_id", c::b(server_instance_id)),
        ("tenant_id", c::b(tenant_id)),
        ("previous_epoch", c::u(previous_epoch)),
        ("new_epoch", c::u(previous_epoch + 1)),
        ("restore_txn_id", c::b(restore_txn_id)),
        ("backup_db_sha256", c::b(backup_db_sha256)),
        ("mapping_codec", c::t(shared::restore_epoch::MAPPING_CODEC)),
        (
            "leaves",
            Value::Array(leaves.iter().map(|l| c::b(l)).collect()),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::canonical::sha256;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn fixture(state: State) -> PreparationManifestV2 {
        PreparationManifestV2 {
            state,
            server_instance_id: [0x5f; 16],
            previous_epoch: 0,
            new_epoch: 1,
            restore_txn_id: [0x0f; 16],
            candidate_db_sha256: sha256(b"candidate"),
            transition_set_sha256: sha256(b"set"),
            previous_record_sha256: sha256(b"record-0"),
            prepared_at_ms: 1_790_985_600_000,
        }
    }

    /// Bytes sealed with a correct checksum, so each later rule is reachable.
    fn sealed(mut b: [u8; MANIFEST_LEN]) -> Vec<u8> {
        let sum = domain_hash(CHECKSUM_LABEL, &b[..BODY_LEN]);
        b[BODY_LEN..].copy_from_slice(&sum);
        b.to_vec()
    }

    #[test]
    fn prepared_and_terminal_manifests_round_trip_and_pin_their_hashes() {
        let p = fixture(State::Prepared).encode().unwrap();
        let t = fixture(State::Terminal).encode().unwrap();
        assert_eq!(parse(&p).unwrap(), fixture(State::Prepared));
        assert_eq!(parse(&t).unwrap(), fixture(State::Terminal));
        assert_eq!(p[..12], t[..12]);
        assert_eq!((p[12], t[12]), (1, 2));
        // Matched by an independent Python encoder of the D-1 layout.
        assert_eq!(
            hex(&sha256(&p)),
            "9cbab5604954541268ff5222cc35094731c260e46e9442652322f08b47586e33"
        );
        assert_eq!(
            hex(&sha256(&t)),
            "f2427aaebf52a2c125f5c720c37aa7ad7247d761d4bcf2b22a09da84e94cc60c"
        );
    }

    #[test]
    fn every_negative_vector_is_unparsable_with_its_reason() {
        let good = fixture(State::Prepared).encode().unwrap();
        let with = |i: usize, v: u8| {
            let mut b = good;
            b[i] = v;
            sealed(b)
        };
        let mut wrong_epoch = good;
        wrong_epoch[40..48].copy_from_slice(&2u64.to_be_bytes());
        let mut over = good;
        over[32..40].copy_from_slice(&(MAX_WIRE_INT).to_be_bytes());
        over[40..48].copy_from_slice(&(MAX_WIRE_INT + 1).to_be_bytes());
        let mut late = good;
        late[160..168].copy_from_slice(&(MAX_WIRE_INT + 1).to_be_bytes());
        let mut flipped = good;
        flipped[199] ^= 1;
        let cases: Vec<(&str, Vec<u8>, ManifestError)> = vec![
            ("size_199", good[..199].to_vec(), ManifestError::Length),
            (
                "size_201",
                [&good[..], &[0]].concat(),
                ManifestError::Length,
            ),
            (
                "magic_SHARDXID",
                {
                    let mut b = good;
                    b[0..8].copy_from_slice(b"SHARDXID");
                    sealed(b)
                },
                ManifestError::Magic,
            ),
            ("version_1", with(9, 1), ManifestError::Version),
            (
                "length_field_199",
                with(11, 199),
                ManifestError::LengthField,
            ),
            ("state_0", with(12, 0), ManifestError::State),
            ("state_3", with(12, 3), ManifestError::State),
            ("reserved_1", with(14, 1), ManifestError::Reserved),
            ("checksum_flip", flipped.to_vec(), ManifestError::Checksum),
            (
                "txn_zero",
                {
                    let mut b = good;
                    b[48..64].fill(0);
                    sealed(b)
                },
                ManifestError::ZeroField,
            ),
            (
                "instance_zero",
                {
                    let mut b = good;
                    b[16..32].fill(0);
                    sealed(b)
                },
                ManifestError::ZeroField,
            ),
            (
                "candidate_zero",
                {
                    let mut b = good;
                    b[64..96].fill(0);
                    sealed(b)
                },
                ManifestError::ZeroField,
            ),
            (
                "set_zero",
                {
                    let mut b = good;
                    b[96..128].fill(0);
                    sealed(b)
                },
                ManifestError::ZeroField,
            ),
            (
                "previous_record_zero",
                {
                    let mut b = good;
                    b[128..160].fill(0);
                    sealed(b)
                },
                ManifestError::ZeroField,
            ),
            (
                "new_not_previous_plus_one",
                sealed(wrong_epoch),
                ManifestError::Epoch,
            ),
            ("epoch_over_i64", sealed(over), ManifestError::Range),
            ("prepared_at_over_i64", sealed(late), ManifestError::Range),
        ];
        for (name, bytes, want) in cases {
            assert_eq!(parse(&bytes), Err(want), "{name}");
        }
        let mut m = fixture(State::Prepared);
        m.new_epoch = 5;
        assert_eq!(
            m.encode(),
            Err(ManifestError::Epoch),
            "the encoder refuses too"
        );
    }

    fn entry(tenant: u8) -> IndexEntry {
        IndexEntry {
            tenant_id: [tenant; 16],
            exact_signed_transition_bytes_sha256: [tenant ^ 1; 32],
            mapping_count: 2,
            proof_set_sha256: [tenant ^ 2; 32],
        }
    }

    fn index(entries: Vec<IndexEntry>) -> TransitionSetIndexV2 {
        TransitionSetIndexV2 {
            server_instance_id: [0x5f; 16],
            previous_epoch: 0,
            new_epoch: 1,
            restore_txn_id: [0x0f; 16],
            backup_db_sha256: sha256(b"backup"),
            live_db_sha256: sha256(b"live"),
            entries,
        }
    }

    #[test]
    fn the_index_is_sorted_unique_and_round_trips_exactly() {
        let empty = index(vec![]).encode().unwrap();
        let two = index(vec![entry(1), entry(2)]).encode().unwrap();
        assert_eq!(TransitionSetIndexV2::parse(&empty), Some(index(vec![])));
        assert_eq!(
            TransitionSetIndexV2::parse(&two),
            Some(index(vec![entry(1), entry(2)]))
        );
        // An empty set still has a non-zero hash (ADR1 L242-L244).
        assert_ne!(transition_set_sha256(&empty), [0; 32]);
        assert_ne!(transition_set_sha256(&empty), transition_set_sha256(&two));
        assert_eq!(index(vec![entry(2), entry(1)]).encode(), None, "unsorted");
        assert_eq!(index(vec![entry(1), entry(1)]).encode(), None, "duplicate");
        // A different encoding of the same values is not the index.
        let mut trailing = two.clone();
        trailing.push(0);
        assert_eq!(TransitionSetIndexV2::parse(&trailing), None);
        assert_eq!(TransitionSetIndexV2::parse(b"junk"), None);
    }

    #[test]
    fn the_proof_set_hash_is_ordered_and_labelled() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(
            proof_set_sha256(&[a, b]),
            domain_hash(PROOF_SET_LABEL, &[a, b].concat())
        );
        assert_ne!(proof_set_sha256(&[a, b]), proof_set_sha256(&[b, a]));
        assert_ne!(proof_set_sha256(&[a]), sha256(&a));
    }
}
