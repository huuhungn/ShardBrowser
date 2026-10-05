//! External identity record (`IdentityRecordV2`, ADR 0001 P1).
//!
//! The record is the epoch authority for the pair `server_instance_id +
//! restore_epoch` (plan 5.5/12.4, ADR S1). It lives outside the SQLite
//! backup and rollback scope, so restoring an old database cannot move the
//! epoch backwards. `v2_server_state` only mirrors it (ADR S2).
//!
//! The encoding is a fixed 168-byte big-endian layout with no optional or
//! variable-length parts, so a field set has exactly one valid encoding:
//!
//! | Offset | Size | Field |
//! |---:|---:|---|
//! | 0 | 8 | magic `"SHARDXID"` |
//! | 8 | 2 | version `u16` = 2 |
//! | 10 | 2 | record_length `u16` = 168 |
//! | 12 | 4 | reserved `u32` = 0 |
//! | 16 | 16 | server_instance_id |
//! | 32 | 8 | previous_epoch `u64` |
//! | 40 | 8 | restore_epoch `u64` |
//! | 48 | 16 | restore_txn_id |
//! | 64 | 32 | restored_db_sha256 |
//! | 96 | 32 | transition_set_sha256 |
//! | 128 | 8 | written_at_ms `u64` |
//! | 136 | 32 | checksum = `domain_hash("SHARDX-IDENTITY-RECORD-V2\0", bytes[0..136])` |
//!
//! Parsing never repairs anything: every rule failure is reported as a
//! [`CorruptReason`], which the caller maps to `EPOCH_AUTHORITY_CORRUPT`.

// Wired into startup by the identity-authority slice that follows; until then
// only the tests exercise it.
#![allow(dead_code)]

use shared::canonical::{domain_hash, sha256};

/// ASCII magic. Deliberately distinct from the envelope's `"SHARDXBK"`.
pub const MAGIC: [u8; 8] = *b"SHARDXID";
pub const VERSION: u16 = 2;
/// Exact file size and the value of the `record_length` field.
pub const RECORD_LEN: usize = 168;
/// Bytes covered by the checksum.
const BODY_LEN: usize = 136;
const CHECKSUM_LABEL: &str = "SHARDX-IDENTITY-RECORD-V2\0";
/// Epochs and timestamps share the plan's `0..i64::MAX` range (L394, L2250).
const MAX_WIRE_INT: u64 = i64::MAX as u64;

/// Why a byte string is not a valid record. Names match the design fixtures
/// in `vectors.json` so the two can be compared directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptReason {
    /// File size is not exactly 168 bytes.
    Length,
    Magic,
    Version,
    /// The `record_length` field is not 168.
    LengthField,
    Reserved,
    Checksum,
    /// `server_instance_id` is all zero.
    InstanceNil,
    /// An epoch or `written_at_ms` is above `i64::MAX`.
    Range,
    /// Epoch 0 with a non-zero `previous_epoch` or restore field.
    GenesisFields,
    /// Epoch > 0 whose `previous_epoch` is not `restore_epoch - 1`.
    PreviousEpoch,
    /// Epoch > 0 with an all-zero restore field.
    RestoreFieldsZero,
}

/// A record that passed every P1 parser rule.
///
/// `previous_epoch` is not stored: for a valid record it is always
/// `restore_epoch - 1` (or `0` at genesis), and encoding derives it, so a
/// value cannot disagree with the epoch it precedes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRecordV2 {
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub restore_txn_id: [u8; 16],
    pub restored_db_sha256: [u8; 32],
    pub transition_set_sha256: [u8; 32],
    /// Informational only; never used to order epochs.
    pub written_at_ms: u64,
}

impl IdentityRecordV2 {
    /// The epoch-0 record written by `identity init`.
    pub fn genesis(server_instance_id: [u8; 16], written_at_ms: u64) -> Self {
        Self {
            server_instance_id,
            restore_epoch: 0,
            restore_txn_id: [0; 16],
            restored_db_sha256: [0; 32],
            transition_set_sha256: [0; 32],
            written_at_ms,
        }
    }

    /// Encode to the exact 168 bytes, refusing field values the parser would
    /// reject. Encoding and parsing therefore accept the same set of records.
    pub fn encode(&self) -> Result<[u8; RECORD_LEN], CorruptReason> {
        let previous_epoch = self.restore_epoch.saturating_sub(1);
        let mut out = [0u8; RECORD_LEN];
        out[0..8].copy_from_slice(&MAGIC);
        out[8..10].copy_from_slice(&VERSION.to_be_bytes());
        out[10..12].copy_from_slice(&(RECORD_LEN as u16).to_be_bytes());
        // 12..16 reserved stays zero.
        out[16..32].copy_from_slice(&self.server_instance_id);
        out[32..40].copy_from_slice(&previous_epoch.to_be_bytes());
        out[40..48].copy_from_slice(&self.restore_epoch.to_be_bytes());
        out[48..64].copy_from_slice(&self.restore_txn_id);
        out[64..96].copy_from_slice(&self.restored_db_sha256);
        out[96..128].copy_from_slice(&self.transition_set_sha256);
        out[128..136].copy_from_slice(&self.written_at_ms.to_be_bytes());
        let checksum = domain_hash(CHECKSUM_LABEL, &out[..BODY_LEN]);
        out[BODY_LEN..].copy_from_slice(&checksum);
        parse(&out)?;
        Ok(out)
    }
}

/// `external_record_sha256`: SHA-256 of all 168 bytes. This is the value
/// `v2_server_state.external_record_sha256` mirrors (plan L2248).
pub fn external_record_sha256(bytes: &[u8; RECORD_LEN]) -> [u8; 32] {
    sha256(bytes)
}

/// Parse a record, applying the P1 rules in their stated order.
pub fn parse(bytes: &[u8]) -> Result<IdentityRecordV2, CorruptReason> {
    // Rule 1: exact size.
    if bytes.len() != RECORD_LEN {
        return Err(CorruptReason::Length);
    }
    // Rule 2: fixed header fields.
    if bytes[0..8] != MAGIC {
        return Err(CorruptReason::Magic);
    }
    if be_u16(&bytes[8..10]) != VERSION {
        return Err(CorruptReason::Version);
    }
    if be_u16(&bytes[10..12]) as usize != RECORD_LEN {
        return Err(CorruptReason::LengthField);
    }
    if be_u32(&bytes[12..16]) != 0 {
        return Err(CorruptReason::Reserved);
    }
    // Rule 3: checksum first, then field ranges.
    if domain_hash(CHECKSUM_LABEL, &bytes[..BODY_LEN])[..] != bytes[BODY_LEN..] {
        return Err(CorruptReason::Checksum);
    }
    let server_instance_id: [u8; 16] = bytes[16..32].try_into().expect("16-byte slice");
    let previous_epoch = be_u64(&bytes[32..40]);
    let restore_epoch = be_u64(&bytes[40..48]);
    let restore_txn_id: [u8; 16] = bytes[48..64].try_into().expect("16-byte slice");
    let restored_db_sha256: [u8; 32] = bytes[64..96].try_into().expect("32-byte slice");
    let transition_set_sha256: [u8; 32] = bytes[96..128].try_into().expect("32-byte slice");
    let written_at_ms = be_u64(&bytes[128..136]);

    if server_instance_id == [0; 16] {
        return Err(CorruptReason::InstanceNil);
    }
    if restore_epoch > MAX_WIRE_INT || previous_epoch > MAX_WIRE_INT || written_at_ms > MAX_WIRE_INT
    {
        return Err(CorruptReason::Range);
    }
    // Rule 4: epoch-dependent fields.
    let txn_zero = restore_txn_id == [0; 16];
    let db_zero = restored_db_sha256 == [0; 32];
    let set_zero = transition_set_sha256 == [0; 32];
    if restore_epoch == 0 {
        if previous_epoch != 0 || !(txn_zero && db_zero && set_zero) {
            return Err(CorruptReason::GenesisFields);
        }
    } else {
        if previous_epoch != restore_epoch - 1 {
            return Err(CorruptReason::PreviousEpoch);
        }
        if txn_zero || db_zero || set_zero {
            return Err(CorruptReason::RestoreFieldsZero);
        }
    }

    Ok(IdentityRecordV2 {
        server_instance_id,
        restore_epoch,
        restore_txn_id,
        restored_db_sha256,
        transition_set_sha256,
        written_at_ms,
    })
}

fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes(b.try_into().expect("2-byte slice"))
}

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().expect("4-byte slice"))
}

fn be_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b.try_into().expect("8-byte slice"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    const INSTANCE: &str = "5f1c2b7a3d4e4f608a9b0c1d2e3f4a5b";
    const TXN: &str = "0f0e0d0c0b0a09080706050403020100";

    // ADR 0001 design fixture 1 (epoch 0) and fixture 2 (restore 0 -> 1).
    // The Rust encoder must reproduce them byte for byte.
    const GENESIS_HEX: &str = "5348415244584944000200a8000000005f1c2b7a3d4e4f608a9b0c1d2e3f4a5b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0ff0f7c0066fb4cb79060d64dbdeff8b3a0f23330a0f65ad8dc2bbd52cb58f837db3c298e";
    const GENESIS_SHA: &str = "9309a920a7bd36386b15988ba8c39d8cf07351e2b75065ea130d811130f1160b";
    const RESTORE_HEX: &str = "5348415244584944000200a8000000005f1c2b7a3d4e4f608a9b0c1d2e3f4a5b000000000000000000000000000000010f0e0d0c0b0a0908070605040302010067fad5f05b79fcdabc71a470dcc2446ee72def5c6716e0099410ddb9548dbb8a8d900cbf5a9c552cc99178c05aea71f9d54e73b56d6abbacd6001639528e3d0c000001a0ff466a80a949806f69918996d1be6cf327a401d6c137ac2970c1760908717a4c8d320a27";
    const RESTORE_CHECKSUM: &str =
        "a949806f69918996d1be6cf327a401d6c137ac2970c1760908717a4c8d320a27";
    const RESTORE_SHA: &str = "828ad5d4dedb26d228160aad1d9118be1495cb975730c3324e3ae0be7e5a3bf4";

    fn genesis_fixture() -> IdentityRecordV2 {
        IdentityRecordV2::genesis(unhex(INSTANCE), 1_790_985_600_000)
    }

    fn restore_fixture() -> IdentityRecordV2 {
        IdentityRecordV2 {
            server_instance_id: unhex(INSTANCE),
            restore_epoch: 1,
            restore_txn_id: unhex(TXN),
            restored_db_sha256: sha256(b"fixture-restored-db"),
            transition_set_sha256: sha256(b"fixture-transition-set"),
            written_at_ms: 1_790_989_200_000,
        }
    }

    /// Mirror of the reference encoder in the ADR evidence (`idrec.py`): it
    /// writes any field values, including invalid ones, and seals them with a
    /// correct checksum so each parser rule can be reached on its own.
    #[allow(clippy::too_many_arguments)]
    fn raw(
        iid: [u8; 16],
        prev: u64,
        epoch: u64,
        txn: [u8; 16],
        dbh: [u8; 32],
        tsh: [u8; 32],
        ms: u64,
        header: ([u8; 8], u16, u16, u32),
    ) -> Vec<u8> {
        let (magic, version, length, reserved) = header;
        let mut b = Vec::with_capacity(RECORD_LEN);
        b.extend_from_slice(&magic);
        b.extend_from_slice(&version.to_be_bytes());
        b.extend_from_slice(&length.to_be_bytes());
        b.extend_from_slice(&reserved.to_be_bytes());
        b.extend_from_slice(&iid);
        b.extend_from_slice(&prev.to_be_bytes());
        b.extend_from_slice(&epoch.to_be_bytes());
        b.extend_from_slice(&txn);
        b.extend_from_slice(&dbh);
        b.extend_from_slice(&tsh);
        b.extend_from_slice(&ms.to_be_bytes());
        let checksum = domain_hash(CHECKSUM_LABEL, &b);
        b.extend_from_slice(&checksum);
        b
    }

    const OK_HEADER: ([u8; 8], u16, u16, u32) = (MAGIC, VERSION, RECORD_LEN as u16, 0);

    #[test]
    fn rust_encoder_reproduces_the_design_fixtures() {
        let g = genesis_fixture().encode().unwrap();
        assert_eq!(hex(&g), GENESIS_HEX);
        assert_eq!(hex(&external_record_sha256(&g)), GENESIS_SHA);

        let r = restore_fixture().encode().unwrap();
        assert_eq!(hex(&r), RESTORE_HEX);
        assert_eq!(hex(&r[136..]), RESTORE_CHECKSUM);
        assert_eq!(hex(&external_record_sha256(&r)), RESTORE_SHA);
    }

    #[test]
    fn valid_records_round_trip() {
        for record in [genesis_fixture(), restore_fixture()] {
            let bytes = record.encode().unwrap();
            assert_eq!(parse(&bytes).unwrap(), record);
        }
    }

    #[test]
    fn every_design_negative_case_fails_with_its_stated_reason() {
        let iid: [u8; 16] = unhex(INSTANCE);
        let txn: [u8; 16] = unhex(TXN);
        let dbh = sha256(b"fixture-restored-db");
        let tsh = sha256(b"fixture-transition-set");
        let (z16, z32) = ([0u8; 16], [0u8; 32]);
        let ms = 1_790_985_600_000;
        let g = genesis_fixture().encode().unwrap().to_vec();
        let flip = |i: usize| {
            let mut b = g.clone();
            b[i] ^= 1;
            b
        };
        let max = MAX_WIRE_INT;

        let cases: Vec<(&str, Vec<u8>, CorruptReason)> = vec![
            ("truncated_167", g[..167].to_vec(), CorruptReason::Length),
            (
                "extended_169",
                [g.as_slice(), &[0]].concat(),
                CorruptReason::Length,
            ),
            (
                "magic_SHARDXBK",
                raw(iid, 0, 0, z16, z32, z32, ms, (*b"SHARDXBK", 2, 168, 0)),
                CorruptReason::Magic,
            ),
            (
                "version_1",
                raw(iid, 0, 0, z16, z32, z32, ms, (MAGIC, 1, 168, 0)),
                CorruptReason::Version,
            ),
            (
                "length_field_167",
                raw(iid, 0, 0, z16, z32, z32, ms, (MAGIC, 2, 167, 0)),
                CorruptReason::LengthField,
            ),
            (
                "reserved_1",
                raw(iid, 0, 0, z16, z32, z32, ms, (MAGIC, 2, 168, 1)),
                CorruptReason::Reserved,
            ),
            ("checksum_bitflip", flip(167), CorruptReason::Checksum),
            ("body_bitflip_unsealed", flip(40), CorruptReason::Checksum),
            (
                "instance_nil",
                raw(z16, 0, 0, z16, z32, z32, ms, OK_HEADER),
                CorruptReason::InstanceNil,
            ),
            (
                "epoch_over_i64",
                raw(iid, max, max + 1, txn, dbh, tsh, 1, OK_HEADER),
                CorruptReason::Range,
            ),
            (
                "genesis_nonzero_txn",
                raw(iid, 0, 0, txn, z32, z32, 1, OK_HEADER),
                CorruptReason::GenesisFields,
            ),
            (
                "genesis_prev_nonzero",
                raw(iid, 1, 0, z16, z32, z32, 1, OK_HEADER),
                CorruptReason::GenesisFields,
            ),
            (
                "restore_prev_wrong",
                raw(iid, 0, 2, txn, dbh, tsh, 1, OK_HEADER),
                CorruptReason::PreviousEpoch,
            ),
            (
                "restore_zero_db_hash",
                raw(iid, 0, 1, txn, z32, tsh, 1, OK_HEADER),
                CorruptReason::RestoreFieldsZero,
            ),
        ];
        assert_eq!(cases.len(), 14, "ADR P1 lists fourteen negative cases");
        for (name, bytes, want) in cases {
            assert_eq!(parse(&bytes), Err(want), "{name}");
        }
    }

    #[test]
    fn encoder_refuses_what_the_parser_rejects() {
        let mut r = genesis_fixture();
        r.server_instance_id = [0; 16];
        assert_eq!(r.encode(), Err(CorruptReason::InstanceNil));

        let mut r = genesis_fixture();
        r.restore_txn_id = [1; 16];
        assert_eq!(r.encode(), Err(CorruptReason::GenesisFields));

        let mut r = restore_fixture();
        r.transition_set_sha256 = [0; 32];
        assert_eq!(r.encode(), Err(CorruptReason::RestoreFieldsZero));

        let mut r = restore_fixture();
        r.written_at_ms = MAX_WIRE_INT + 1;
        assert_eq!(r.encode(), Err(CorruptReason::Range));

        let mut r = restore_fixture();
        r.restore_epoch = MAX_WIRE_INT + 1;
        assert_eq!(r.encode(), Err(CorruptReason::Range));
    }

    #[test]
    fn highest_epoch_in_range_is_accepted() {
        let mut r = restore_fixture();
        r.restore_epoch = MAX_WIRE_INT;
        let bytes = r.encode().unwrap();
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.restore_epoch, MAX_WIRE_INT);
        assert_eq!(be_u64(&bytes[32..40]), MAX_WIRE_INT - 1);
    }
}
