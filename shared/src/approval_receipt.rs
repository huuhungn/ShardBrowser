//! `DeviceApprovalReceiptV2` and the device-approval request digest
//! (ADR 0001 R3).
//!
//! The receipt acknowledges one committed approval transaction. The server
//! stores its exact bytes and returns them on an exact retry; a retry reparses
//! them and compares every field with the stored row, and never re-encodes.
//! A receipt says what was committed, not what is authorized now.

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c};

pub const DOMAIN_DEVICE_APPROVAL_RECEIPT: &str = "shardx.auth.device-approval-receipt.v2";
pub const RECEIPT_VERSION: u16 = 2;
/// R3: the stored receipt is at most this long.
pub const MAX_RECEIPT_BYTES: usize = 4096;
/// The fixed `operation_scope` of a `DEVICE_APPROVE` idempotency row.
pub const DEVICE_APPROVE_SCOPE: &str = "tenant.device-approve.v2";
/// ADR 0002 D-6: the longest `not_after_ms - not_before_ms` of a
/// `DeviceApprovalV2` (730 days).
pub const MAX_DEVICE_APPROVAL_TTL_MS: u64 = 63_072_000_000;
/// ADR 0002 D-6: the longest `not_after_ms - not_before_ms` of a
/// `TenantCapabilityGrantV2` (365 days).
pub const MAX_CAPABILITY_GRANT_TTL_MS: u64 = 31_536_000_000;
/// ADR 0002 D-6: the longest window of a `DeviceHpkeGrant` (365 days).
pub const MAX_FLEET_DEVICE_GRANT_TTL_MS: u64 = 31_536_000_000;
/// ADR 0002 D-6: the longest window of a `RecoveryGrant` (3650 days).
pub const MAX_FLEET_RECOVERY_GRANT_TTL_MS: u64 = 315_360_000_000;
/// ADR 0002 D-6: the longest window of a fleet `RotationGrant` (30 days).
pub const MAX_FLEET_ROTATION_GRANT_TTL_MS: u64 = 2_592_000_000;
/// ADR 0002 D-6 `authorization_replay_retention` (90 days): how long past
/// `not_after_ms` a derived ledger row such as a stored receipt is kept.
pub const AUTHORIZATION_REPLAY_RETENTION_MS: u64 = 7_776_000_000;
pub const REQUEST_HASH_LABEL: &[u8] = b"SHARDX-DEVICE-APPROVE-REQUEST-V2\0";
const OUTCOME_SUCCEEDED: &str = "succeeded";

/// The closed receipt map. `confirmation_id` is present exactly for a D1
/// approval, which consumes the tenant's first-device confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceApprovalReceiptV2 {
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub tenant_id: [u8; 16],
    pub actor_account_id: [u8; 16],
    pub actor_device_id: [u8; 16],
    pub subject_device_id: [u8; 16],
    pub approval_replay_id: [u8; 16],
    pub request_hash: [u8; 32],
    pub approval_payload_sha256: [u8; 32],
    pub approval_signed_container_hash: [u8; 32],
    pub approval_outer_sha256: [u8; 32],
    pub confirmation_id: Option<[u8; 16]>,
    pub committed_at_ms: u64,
}

impl DeviceApprovalReceiptV2 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            ("domain", c::t(DOMAIN_DEVICE_APPROVAL_RECEIPT)),
            ("version", c::u(RECEIPT_VERSION.into())),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
            ("tenant_id", c::b(&self.tenant_id)),
            ("actor_account_id", c::b(&self.actor_account_id)),
            ("actor_device_id", c::b(&self.actor_device_id)),
            ("subject_device_id", c::b(&self.subject_device_id)),
            ("approval_replay_id", c::b(&self.approval_replay_id)),
            ("request_hash", c::b(&self.request_hash)),
            (
                "approval_payload_sha256",
                c::b(&self.approval_payload_sha256),
            ),
            (
                "approval_signed_container_hash",
                c::b(&self.approval_signed_container_hash),
            ),
            ("approval_outer_sha256", c::b(&self.approval_outer_sha256)),
            ("committed_at_ms", c::u(self.committed_at_ms)),
            ("outcome", c::t(OUTCOME_SUCCEEDED)),
        ];
        if let Some(id) = &self.confirmation_id {
            out.push(("confirmation_id", c::b(id)));
        }
        c::encode(&c::m(out))
    }

    /// Parses exact stored bytes: canonical, closed, bounded.
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(RecordError::BadField {
                map: "DeviceApprovalReceiptV2",
                field: "exact_response_bytes",
            });
        }
        let mut f = Fields::decode("DeviceApprovalReceiptV2", bytes)?;
        f.exact_text("domain", DOMAIN_DEVICE_APPROVAL_RECEIPT)?;
        if f.u16("version")? != RECEIPT_VERSION {
            return Err(RecordError::BadValue("version"));
        }
        let receipt = Self {
            server_instance_id: f.fixed("server_instance_id")?,
            restore_epoch: f.uint("restore_epoch")?,
            tenant_id: f.fixed("tenant_id")?,
            actor_account_id: f.fixed("actor_account_id")?,
            actor_device_id: f.fixed("actor_device_id")?,
            subject_device_id: f.fixed("subject_device_id")?,
            approval_replay_id: f.fixed("approval_replay_id")?,
            request_hash: f.fixed("request_hash")?,
            approval_payload_sha256: f.fixed("approval_payload_sha256")?,
            approval_signed_container_hash: f.fixed("approval_signed_container_hash")?,
            approval_outer_sha256: f.fixed("approval_outer_sha256")?,
            confirmation_id: f.opt_fixed("confirmation_id")?,
            committed_at_ms: f.uint("committed_at_ms")?,
        };
        f.exact_text("outcome", OUTCOME_SUCCEEDED)?;
        f.finish()?;
        Ok(receipt)
    }
}

/// R3 request digest. It is compared, never used as a key, so a changed
/// request under the same identity is a mismatch rather than a new operation.
#[allow(clippy::too_many_arguments)]
pub fn device_approve_request_hash(
    server_instance_id: &[u8; 16],
    restore_epoch: u64,
    tenant_id: &[u8; 16],
    actor_account_id: &[u8; 16],
    actor_device_id: &[u8; 16],
    subject_device_id: &[u8; 16],
    body: &[u8],
) -> [u8; 32] {
    let len = u32::try_from(body.len()).expect("request bodies are capped far below 4 GiB");
    let mut pre = Vec::with_capacity(REQUEST_HASH_LABEL.len() + 4 * 16 + 8 + 4 + body.len());
    pre.extend_from_slice(REQUEST_HASH_LABEL);
    pre.extend_from_slice(server_instance_id);
    pre.extend_from_slice(&restore_epoch.to_be_bytes());
    pre.extend_from_slice(tenant_id);
    pre.extend_from_slice(actor_account_id);
    pre.extend_from_slice(actor_device_id);
    pre.extend_from_slice(subject_device_id);
    pre.extend_from_slice(&len.to_be_bytes());
    pre.extend_from_slice(body);
    c::sha256(&pre)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::Value;

    fn receipt(confirmation: Option<[u8; 16]>) -> DeviceApprovalReceiptV2 {
        DeviceApprovalReceiptV2 {
            server_instance_id: [1; 16],
            restore_epoch: 3,
            tenant_id: [2; 16],
            actor_account_id: [3; 16],
            actor_device_id: [4; 16],
            subject_device_id: [4; 16],
            approval_replay_id: [5; 16],
            request_hash: [6; 32],
            approval_payload_sha256: [7; 32],
            approval_signed_container_hash: [8; 32],
            approval_outer_sha256: [9; 32],
            confirmation_id: confirmation,
            committed_at_ms: 1_790_985_600_000,
        }
    }

    fn edited(bytes: &[u8], edit: impl FnOnce(&mut Vec<(String, Value)>)) -> Vec<u8> {
        let Value::Map(mut entries) = c::decode(bytes).unwrap() else {
            panic!("a receipt is a map")
        };
        edit(&mut entries);
        c::encode(&Value::Map(entries))
    }

    #[test]
    fn a_receipt_round_trips_with_and_without_a_confirmation() {
        for r in [receipt(Some([10; 16])), receipt(None)] {
            let bytes = r.encode();
            assert_eq!(DeviceApprovalReceiptV2::parse(&bytes).unwrap(), r);
            assert!(bytes.len() <= MAX_RECEIPT_BYTES);
        }
    }

    #[test]
    fn a_receipt_is_a_closed_map() {
        let good = receipt(Some([10; 16])).encode();
        let unknown = edited(&good, |e| e.push(("note".into(), c::t("x"))));
        let missing = edited(&good, |e| e.retain(|(k, _)| k != "request_hash"));
        let outcome = edited(&good, |e| {
            for (k, v) in e.iter_mut() {
                if k == "outcome" {
                    *v = c::t("failed");
                }
            }
        });
        let short = edited(&good, |e| {
            for (k, v) in e.iter_mut() {
                if k == "approval_replay_id" {
                    *v = c::b(&[5; 15]);
                }
            }
        });
        for bad in [unknown, missing, outcome, short] {
            assert!(DeviceApprovalReceiptV2::parse(&bad).is_err());
        }
        assert!(DeviceApprovalReceiptV2::parse(&[]).is_err());
        assert!(DeviceApprovalReceiptV2::parse(&vec![0; MAX_RECEIPT_BYTES + 1]).is_err());
    }

    #[test]
    fn the_request_hash_is_the_r3_preimage_and_binds_every_input() {
        let h = |inst: u8, epoch: u64, tenant: u8, acct: u8, dev: u8, subj: u8, body: &[u8]| {
            device_approve_request_hash(
                &[inst; 16],
                epoch,
                &[tenant; 16],
                &[acct; 16],
                &[dev; 16],
                &[subj; 16],
                body,
            )
        };
        // label || instance || u64be(epoch) || tenant || actor account ||
        // actor device || subject device || u32be(len) || body
        let mut pre = b"SHARDX-DEVICE-APPROVE-REQUEST-V2\0".to_vec();
        pre.extend_from_slice(&[1; 16]);
        pre.extend_from_slice(&7u64.to_be_bytes());
        for part in [[2u8; 16], [3; 16], [4; 16], [5; 16]] {
            pre.extend_from_slice(&part);
        }
        pre.extend_from_slice(&3u32.to_be_bytes());
        pre.extend_from_slice(b"abc");
        let base = h(1, 7, 2, 3, 4, 5, b"abc");
        assert_eq!(base, c::sha256(&pre));
        for other in [
            h(9, 7, 2, 3, 4, 5, b"abc"),
            h(1, 8, 2, 3, 4, 5, b"abc"),
            h(1, 7, 9, 3, 4, 5, b"abc"),
            h(1, 7, 2, 9, 4, 5, b"abc"),
            h(1, 7, 2, 3, 9, 5, b"abc"),
            h(1, 7, 2, 3, 4, 9, b"abc"),
            h(1, 7, 2, 3, 4, 5, b"abd"),
        ] {
            assert_ne!(other, base);
        }
    }
}
