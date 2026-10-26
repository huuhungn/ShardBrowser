//! Client-side verification of a tenant's trust evidence (ADR 0002 B2,
//! "Verification algorithm", rules 1-4).
//!
//! [`Evidence::collect`] keeps the usable containers of a full set of
//! [`TenantTrustEvidencePageV2`] pages: they parse exactly, their signature
//! verifies under a public key whose ID matches, and they name the binding's
//! tenant and instance. [`TrustChain::evaluate`] then derives, as a least
//! fixpoint rooted at the tenant's one `FirstRootSelfGrant`, the custodian
//! windows of every key, and answers approval and capability questions from
//! them.
//!
//! Nothing a page says is taken on trust: a container that fails a check is
//! dropped, and the server's revocation reports only end windows early. So an
//! omission or a forgery can only make the client refuse.
//!
//! shortcut: this is the evaluation of a device without history. The W6
//! ledger (first sighting, sticky lapse, sticky proven revocation, local
//! distrust) and `DeviceRevocationV2` arrive with W6 and Q-13; until then a
//! client evaluates every container as first seen now.

use std::collections::{BTreeMap, BTreeSet};

use crate::authz_record::{
    ApprovalScopeKind, AuthorizationRecord, Capability, CapabilityScopeKind, CommonFields,
    DeviceApprovalV2, GrantSubject, Payload, RootGrantVariant, TenantCapabilityGrantV2,
    TenantRootKeyGrantV2,
};
use crate::keys::signing_key_id;
use crate::trust_evidence::{TenantTrustEvidencePageV2, MAX_EVIDENCE_CONTAINERS};

/// D-6 (c): a key's custodian windows end this long after its first one.
pub const MAX_CUSTODIAN_KEY_AGE_MS: u64 = 1095 * 86_400_000;
/// The local clock's tolerance for "now".
pub const CLOCK_TOLERANCE_MS: u64 = 300_000;

type KeyId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    /// The pages are not one complete, ordered set for this binding.
    BadPages(&'static str),
    /// More containers than a client evaluates (fail closed).
    TooMuchEvidence,
    /// No usable `FirstRootSelfGrant`, or no usable D1 approval linked by it.
    NoAnchor,
    /// More than one usable `FirstRootSelfGrant`: the tenant has one.
    ConflictingAnchors,
    /// The anchor differs from the one this client pinned.
    AnchorMismatch,
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPages(why) => write!(f, "the trust evidence pages are unusable: {why}"),
            Self::TooMuchEvidence => write!(f, "the trust evidence exceeds the client cap"),
            Self::NoAnchor => write!(f, "the trust evidence holds no usable bootstrap anchor"),
            Self::ConflictingAnchors => write!(f, "the trust evidence holds two bootstrap anchors"),
            Self::AnchorMismatch => write!(f, "the bootstrap anchor is not the pinned one"),
        }
    }
}

impl std::error::Error for TrustError {}

/// The `(server_instance_id, tenant_id)` the client is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    pub server_instance_id: [u8; 16],
    pub tenant_id: [u8; 16],
}

/// What a capability or approval is asked to cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Tenant,
    Fleet([u8; 16]),
    Profile([u8; 16]),
}

/// A usable container: checked bytes, signature, tenant and instance.
#[derive(Debug, Clone)]
struct Usable<T> {
    issuer: KeyId,
    payload: T,
    /// The server reported it revoked from this time on.
    revoked_at_ms: Option<u64>,
}

/// The usable containers of one complete evidence set.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    roots: Vec<Usable<TenantRootKeyGrantV2>>,
    approvals: Vec<Usable<DeviceApprovalV2>>,
    grants: Vec<Usable<TenantCapabilityGrantV2>>,
    /// Devices the server reported revoked, and from when.
    revoked_devices: BTreeMap<[u8; 16], u64>,
}

fn names(common: &CommonFields, binding: &Binding) -> bool {
    common.tenant_id == binding.tenant_id && common.server_instance_id == binding.server_instance_id
}

impl Evidence {
    /// Keeps the usable containers of `pages`, which must be every page of
    /// one listing, in order, for `binding`.
    pub fn collect(
        binding: &Binding,
        pages: &[TenantTrustEvidencePageV2],
    ) -> Result<Self, TrustError> {
        let Some(last) = pages.last() else {
            return Err(TrustError::BadPages("no page"));
        };
        if !last.next_cursor.is_empty() {
            return Err(TrustError::BadPages("the last page names a next one"));
        }
        let mut keys = BTreeMap::new();
        let mut revoked = BTreeMap::new();
        let mut out = Evidence::default();
        let mut total = 0usize;
        for (i, page) in pages.iter().enumerate() {
            if usize::try_from(page.page_index).ok() != Some(i) {
                return Err(TrustError::BadPages("pages out of order"));
            }
            if i + 1 < pages.len() && page.next_cursor.is_empty() {
                return Err(TrustError::BadPages(
                    "a page before the last ends the listing",
                ));
            }
            if page.tenant_id != binding.tenant_id
                || page.server_instance_id != binding.server_instance_id
            {
                return Err(TrustError::BadPages(
                    "a page names another tenant or server",
                ));
            }
            total += page.containers.len();
            if total > MAX_EVIDENCE_CONTAINERS {
                return Err(TrustError::TooMuchEvidence);
            }
            // A key is used only for the ID it hashes to.
            for pk in &page.signing_public_keys {
                keys.insert(signing_key_id(pk), *pk);
            }
            for r in &page.revocations {
                let at = revoked
                    .entry((r.payload_domain.clone(), r.replay_id))
                    .or_insert(u64::MAX);
                *at = (*at).min(r.revoked_at_ms);
            }
            for d in &page.device_revocations {
                let at = out.revoked_devices.entry(d.device_id).or_insert(u64::MAX);
                *at = (*at).min(d.revoked_at_ms);
            }
        }

        let mut seen = BTreeSet::new();
        for container in pages.iter().flat_map(|p| &p.containers) {
            let Ok(record) = AuthorizationRecord::parse(container) else {
                continue;
            };
            if !seen.insert(*record.signed_container_hash()) {
                continue;
            }
            let issuer = *record.issuer_signing_key_id();
            let domain = record.payload_domain().to_string();
            let Some(pk) = keys.get(&issuer) else {
                continue;
            };
            let Ok(verified) = record.verify_signature(pk) else {
                continue;
            };
            let revoked_at = |replay: &[u8; 16]| revoked.get(&(domain.clone(), *replay)).copied();
            match verified.payload().clone() {
                Payload::TenantRootKeyGrant(g) if names(&g.common, binding) => {
                    let revoked_at_ms = revoked_at(&g.common.replay_id);
                    out.roots.push(Usable {
                        issuer,
                        payload: g,
                        revoked_at_ms,
                    });
                }
                Payload::DeviceApproval(a) if names(&a.common, binding) => {
                    let revoked_at_ms = revoked_at(&a.common.replay_id);
                    out.approvals.push(Usable {
                        issuer,
                        payload: a,
                        revoked_at_ms,
                    });
                }
                Payload::TenantCapabilityGrant(g) if names(&g.common, binding) => {
                    let revoked_at_ms = revoked_at(&g.common.replay_id);
                    out.grants.push(Usable {
                        issuer,
                        payload: g,
                        revoked_at_ms,
                    });
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

/// The end of a record's standing: its `not_after_ms`, or earlier when the
/// server reported the record, or its subject device, revoked.
fn end_of(common: &CommonFields, revoked_at: Option<u64>, device_revoked_at: Option<u64>) -> u64 {
    common
        .not_after_ms
        .min(revoked_at.unwrap_or(u64::MAX))
        .min(device_revoked_at.unwrap_or(u64::MAX))
}

fn holds(window: (u64, u64), t: u64) -> bool {
    window.0 <= t && t < window.1
}

/// The result of evaluating one evidence set.
#[derive(Debug, Clone)]
pub struct TrustChain {
    anchor: KeyId,
    /// `Cust(K)`, already clipped.
    custodians: BTreeMap<KeyId, Vec<(u64, u64)>>,
    evidence: Evidence,
    /// The replay ID of the D1 approval `g0` links.
    anchor_approval: [u8; 16],
}

impl TrustChain {
    /// Rules 1-4 over `evidence`. With `pinned`, the anchor must be it.
    pub fn evaluate(evidence: Evidence, pinned: Option<&KeyId>) -> Result<Self, TrustError> {
        let mut anchors = evidence.roots.iter().filter(|r| {
            r.payload.variant == RootGrantVariant::FirstRootSelfGrant
                && r.issuer == r.payload.subject_signing_key_id
                && r.payload.root_generation == 0
        });
        let g0 = anchors.next().ok_or(TrustError::NoAnchor)?.clone();
        if anchors.next().is_some() {
            return Err(TrustError::ConflictingAnchors);
        }
        let anchor = g0.issuer;
        if pinned.is_some_and(|p| *p != anchor) {
            return Err(TrustError::AnchorMismatch);
        }
        let mut chain = TrustChain {
            anchor,
            custodians: BTreeMap::new(),
            anchor_approval: g0.payload.subject_device_approval_replay_id,
            evidence,
        };
        // Base: g0 counts only with its D1 approval, A0's own, valid when g0
        // was issued.
        if !chain.approval_holds(
            &anchor,
            Some(&chain.anchor_approval),
            g0.payload.common.issued_at_ms,
        ) {
            return Err(TrustError::NoAnchor);
        }
        let mut counted = BTreeSet::new();
        chain.add_window(&g0);
        counted.insert(g0.payload.common.replay_id);

        // Step, to the least fixpoint: every pass either counts a new grant or
        // ends, and nothing counted is ever taken back.
        loop {
            let next: Vec<_> = chain
                .evidence
                .roots
                .iter()
                .filter(|r| !counted.contains(&r.payload.common.replay_id))
                .filter(|r| r.payload.variant != RootGrantVariant::FirstRootSelfGrant)
                .filter(|r| {
                    let t = r.payload.common.issued_at_ms;
                    chain.custodian_at(&r.issuer, t)
                        && chain.approval_holds(
                            &r.payload.subject_signing_key_id,
                            Some(&r.payload.subject_device_approval_replay_id),
                            t,
                        )
                })
                .cloned()
                .collect();
            if next.is_empty() {
                break;
            }
            for r in &next {
                counted.insert(r.payload.common.replay_id);
                chain.add_window(r);
            }
        }
        Ok(chain)
    }

    /// The bootstrap anchor `A0`.
    pub fn anchor(&self) -> &KeyId {
        &self.anchor
    }

    fn add_window(&mut self, r: &Usable<TenantRootKeyGrantV2>) {
        let g = &r.payload;
        let device_revoked = self
            .evidence
            .revoked_devices
            .get(&g.subject_device_id)
            .copied();
        let window = (
            g.common.not_before_ms,
            end_of(&g.common, r.revoked_at_ms, device_revoked),
        );
        let windows = self.custodians.entry(g.subject_signing_key_id).or_default();
        windows.push(window);
    }

    /// D-6 (c): the first `not_before_ms` of any usable root grant naming `key`.
    fn first_not_before(&self, key: &KeyId) -> Option<u64> {
        self.evidence
            .roots
            .iter()
            .filter(|r| r.payload.subject_signing_key_id == *key)
            .map(|r| r.payload.common.not_before_ms)
            .min()
    }

    fn windows(&self, key: &KeyId) -> Vec<(u64, u64)> {
        let Some(first) = self.first_not_before(key) else {
            return Vec::new();
        };
        let cap = first.saturating_add(MAX_CUSTODIAN_KEY_AGE_MS);
        self.custodians
            .get(key)
            .into_iter()
            .flatten()
            .map(|&(nb, na)| (nb, na.min(cap)))
            .collect()
    }

    /// Rule 1: `key` holds a custodian window containing `t`.
    pub fn custodian_at(&self, key: &KeyId, t: u64) -> bool {
        self.windows(key).into_iter().any(|w| holds(w, t))
    }

    /// Rule 2: `key` is a custodian now, within the clock tolerance.
    pub fn custodian_now(&self, key: &KeyId, now: u64) -> bool {
        let (lo, hi) = (
            now.saturating_sub(CLOCK_TOLERANCE_MS),
            now.saturating_add(CLOCK_TOLERANCE_MS),
        );
        self.windows(key)
            .into_iter()
            .any(|(nb, na)| nb <= hi && lo < na)
    }

    /// Rule 3: a usable approval of `key` valid at `t`, optionally the one
    /// with replay ID `linked`.
    fn approval_holds(&self, key: &KeyId, linked: Option<&[u8; 16]>, t: u64) -> bool {
        self.evidence.approvals.iter().any(|a| {
            let p = &a.payload;
            let device_revoked = self
                .evidence
                .revoked_devices
                .get(&p.subject_device_id)
                .copied();
            p.subject_signing_key_id == *key
                && linked.is_none_or(|id| p.common.replay_id == *id)
                && holds(
                    (
                        p.common.not_before_ms,
                        end_of(&p.common, a.revoked_at_ms, device_revoked),
                    ),
                    t,
                )
                && self.approval_issuer_ok(a)
        })
    }

    fn approval_issuer_ok(&self, a: &Usable<DeviceApprovalV2>) -> bool {
        let p = &a.payload;
        // A0's D1 self-approval, the one g0 links.
        if a.issuer == self.anchor
            && p.subject_signing_key_id == self.anchor
            && p.common.replay_id == self.anchor_approval
        {
            return true;
        }
        let scope = match p.approval_scope_kind {
            ApprovalScopeKind::Tenant => Scope::Tenant,
            ApprovalScopeKind::Fleet => Scope::Fleet(p.approval_scope_id),
        };
        let t = p.common.issued_at_ms;
        self.custodian_at(&a.issuer, t)
            && self.capability_at(&a.issuer, Capability::DeviceApprove, scope, t)
    }

    /// Rule 3, public: `key` holds an approval valid at `t`.
    pub fn approval_valid_at(&self, key: &KeyId, t: u64) -> bool {
        self.approval_holds(key, None, t)
    }

    /// Rule 4: `key` holds `capability` over `scope` at `t`, through a usable
    /// device-scoped grant whose issuer was a custodian when it was issued.
    pub fn capability_at(&self, key: &KeyId, capability: Capability, scope: Scope, t: u64) -> bool {
        self.evidence.grants.iter().any(|g| {
            let p = &g.payload;
            let GrantSubject::Device {
                signing_key_id,
                device_id,
                ..
            } = &p.subject
            else {
                return false;
            };
            let device_revoked = self.evidence.revoked_devices.get(device_id).copied();
            *signing_key_id == *key
                && p.capability == capability
                && covers(p.scope_kind, &p.scope_id, scope)
                && holds(
                    (
                        p.common.not_before_ms,
                        end_of(&p.common, g.revoked_at_ms, device_revoked),
                    ),
                    t,
                )
                && self.custodian_at(&g.issuer, p.common.issued_at_ms)
        })
    }
}

/// Whether a grant over `(kind, id)` covers `scope`. A tenant grant covers
/// everything in its tenant (the parser pins its `scope_id` to the tenant).
// shortcut: a fleet grant does not cover the profiles in its fleet, because
// the evidence does not say which fleet a profile is in; profile questions
// need a profile- or tenant-scoped grant until the fleet evidence lands (W4).
fn covers(kind: CapabilityScopeKind, id: &[u8; 16], scope: Scope) -> bool {
    match (kind, scope) {
        (CapabilityScopeKind::Tenant, _) => true,
        (CapabilityScopeKind::Fleet, Scope::Fleet(f)) => *id == f,
        (CapabilityScopeKind::Profile, Scope::Profile(p)) => *id == p,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz_record::{
        build_record, DOMAIN_DEVICE_APPROVAL, DOMAIN_TENANT_CAPABILITY_GRANT,
        DOMAIN_TENANT_ROOT_KEY_GRANT,
    };
    use crate::trust_evidence::{RevokedDevice, RevokedRecord};
    use ed25519_dalek::SigningKey;

    const T0: u64 = 1_800_000_000_000;
    const DAY: u64 = 86_400_000;
    const TENANT: [u8; 16] = [1; 16];
    const INSTANCE: [u8; 16] = [2; 16];
    const BINDING: Binding = Binding {
        server_instance_id: INSTANCE,
        tenant_id: TENANT,
    };

    struct Device {
        sk: SigningKey,
        id: [u8; 16],
    }

    impl Device {
        fn new(n: u8) -> Self {
            Self {
                sk: SigningKey::from_bytes(&[n; 32]),
                id: [n; 16],
            }
        }
        fn pk(&self) -> [u8; 32] {
            *self.sk.verifying_key().as_bytes()
        }
        fn key(&self) -> KeyId {
            signing_key_id(&self.pk())
        }
    }

    thread_local! {
        /// The tenant the helpers sign records for; another one only in the
        /// test of foreign containers.
        static SIGNED_TENANT: std::cell::Cell<[u8; 16]> = const { std::cell::Cell::new(TENANT) };
    }

    fn common(replay: u8, nb: u64, na: u64) -> CommonFields {
        CommonFields {
            replay_id: [replay; 16],
            tenant_id: SIGNED_TENANT.get(),
            issued_at_ms: nb,
            not_before_ms: nb,
            not_after_ms: na,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        }
    }

    fn approval(issuer: &Device, subject: &Device, replay: u8, nb: u64, na: u64) -> Vec<u8> {
        let a = DeviceApprovalV2 {
            common: common(replay, nb, na),
            subject_account_id: [9; 16],
            subject_device_id: subject.id,
            subject_signing_key_id: subject.key(),
            subject_hpke_key_id: [subject.id[0]; 32],
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: SIGNED_TENANT.get(),
        };
        build_record(&issuer.sk, DOMAIN_DEVICE_APPROVAL, &a.encode())
    }

    fn root(
        issuer: &Device,
        subject: &Device,
        variant: RootGrantVariant,
        replay: u8,
        approval_replay: u8,
        nb: u64,
        na: u64,
    ) -> Vec<u8> {
        let g = TenantRootKeyGrantV2 {
            common: common(replay, nb, na),
            variant,
            root_key_id: [7; 32],
            root_generation: 0,
            subject_account_id: [9; 16],
            subject_device_id: subject.id,
            subject_signing_key_id: subject.key(),
            recipient_hpke_key_id: [subject.id[0]; 32],
            subject_device_approval_replay_id: [approval_replay; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        build_record(&issuer.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode())
    }

    fn grant(
        issuer: &Device,
        subject: &Device,
        capability: Capability,
        replay: u8,
        nb: u64,
        na: u64,
    ) -> Vec<u8> {
        let g = TenantCapabilityGrantV2 {
            common: common(replay, nb, na),
            subject: GrantSubject::Device {
                account_id: [9; 16],
                device_id: subject.id,
                signing_key_id: subject.key(),
                hpke_key_id: [subject.id[0]; 32],
            },
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: SIGNED_TENANT.get(),
            capability,
        };
        build_record(&issuer.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
    }

    fn page(keys: &[&Device], containers: Vec<Vec<u8>>) -> TenantTrustEvidencePageV2 {
        TenantTrustEvidencePageV2 {
            server_instance_id: INSTANCE,
            tenant_id: TENANT,
            server_now_ms: T0,
            page_index: 0,
            next_cursor: Vec::new(),
            signing_public_keys: keys.iter().map(|d| d.pk()).collect(),
            containers,
            revocations: Vec::new(),
            device_revocations: Vec::new(),
        }
    }

    fn chain(p: TenantTrustEvidencePageV2) -> Result<TrustChain, TrustError> {
        TrustChain::evaluate(Evidence::collect(&BINDING, &[p])?, None)
    }

    /// A0 bootstraps; A0 then approves B, grants it `device.approve`, and
    /// makes it a custodian with an ExistingRootGrant.
    fn tenant(a0: &Device, b: &Device) -> Vec<Vec<u8>> {
        vec![
            approval(a0, a0, 10, T0, T0 + 365 * DAY),
            root(
                a0,
                a0,
                RootGrantVariant::FirstRootSelfGrant,
                11,
                10,
                T0,
                T0 + 365 * DAY,
            ),
            approval(a0, b, 20, T0 + DAY, T0 + 365 * DAY),
            grant(a0, a0, Capability::DeviceApprove, 12, T0, T0 + 365 * DAY),
            root(
                a0,
                b,
                RootGrantVariant::ExistingRootGrant,
                21,
                20,
                T0 + 2 * DAY,
                T0 + 100 * DAY,
            ),
        ]
    }

    #[test]
    fn the_anchor_and_a_custodian_it_appointed_are_found() {
        let (a0, b) = (Device::new(1), Device::new(2));
        let c = chain(page(&[&a0, &b], tenant(&a0, &b))).unwrap();
        assert_eq!(c.anchor(), &a0.key());
        assert!(c.custodian_now(&a0.key(), T0 + 50 * DAY));
        assert!(c.custodian_at(&b.key(), T0 + 50 * DAY));
        assert!(
            !c.custodian_at(&b.key(), T0 + 100 * DAY),
            "windows are half-open"
        );
        assert!(!c.custodian_at(&b.key(), T0 + DAY), "not before its grant");
        assert!(c.approval_valid_at(&b.key(), T0 + 3 * DAY));
        assert!(c.capability_at(
            &a0.key(),
            Capability::DeviceApprove,
            Scope::Fleet([5; 16]),
            T0 + DAY
        ));
        assert!(!c.capability_at(&b.key(), Capability::DeviceApprove, Scope::Tenant, T0 + DAY));
    }

    #[test]
    fn a_custodian_needs_an_approval_from_someone_allowed_to_approve() {
        let (a0, b) = (Device::new(1), Device::new(2));
        // Without A0's device.approve, B's approval does not hold, so its
        // root grant does not count.
        let mut evidence = tenant(&a0, &b);
        evidence.remove(3);
        let c = chain(page(&[&a0, &b], evidence)).unwrap();
        assert!(c.custodian_now(&a0.key(), T0 + 50 * DAY));
        assert!(!c.custodian_at(&b.key(), T0 + 50 * DAY));
    }

    #[test]
    fn grants_from_a_non_custodian_never_count() {
        let (a0, b, m) = (Device::new(1), Device::new(2), Device::new(3));
        // M signs its own approval and an ExistingRootGrant for itself.
        let mut evidence = tenant(&a0, &b);
        evidence.push(approval(&m, &m, 30, T0, T0 + 365 * DAY));
        evidence.push(root(
            &m,
            &m,
            RootGrantVariant::ExistingRootGrant,
            31,
            30,
            T0,
            T0 + 365 * DAY,
        ));
        // And B, a custodian, appoints M without a valid approval for M.
        evidence.push(root(
            &b,
            &m,
            RootGrantVariant::ExistingRootGrant,
            32,
            30,
            T0 + 3 * DAY,
            T0 + 365 * DAY,
        ));
        let c = chain(page(&[&a0, &b, &m], evidence)).unwrap();
        assert!(!c.custodian_at(&m.key(), T0 + 50 * DAY));
    }

    #[test]
    fn an_approved_device_that_is_no_custodian_appoints_nobody() {
        let (a0, b, d) = (Device::new(1), Device::new(2), Device::new(4));
        let mut evidence = tenant(&a0, &b);
        // D holds a valid approval from A0 but no custodian window, and
        // files a root grant for itself.
        evidence.push(approval(&a0, &d, 70, T0 + DAY, T0 + 365 * DAY));
        evidence.push(root(
            &d,
            &d,
            RootGrantVariant::ExistingRootGrant,
            71,
            70,
            T0 + 2 * DAY,
            T0 + 365 * DAY,
        ));
        // And a device.approve grant for B issued by D.
        evidence.push(grant(
            &d,
            &b,
            Capability::DeviceApprove,
            72,
            T0 + 2 * DAY,
            T0 + 365 * DAY,
        ));
        let c = chain(page(&[&a0, &b, &d], evidence)).unwrap();
        assert!(c.approval_valid_at(&d.key(), T0 + 3 * DAY));
        assert!(!c.custodian_at(&d.key(), T0 + 3 * DAY));
        assert!(!c.capability_at(
            &b.key(),
            Capability::DeviceApprove,
            Scope::Tenant,
            T0 + 3 * DAY
        ));
    }

    #[test]
    fn containers_of_another_tenant_are_dropped() {
        let (a0, b) = (Device::new(1), Device::new(2));
        SIGNED_TENANT.set([8; 16]);
        let foreign = tenant(&a0, &b);
        SIGNED_TENANT.set(TENANT);
        assert_eq!(
            chain(page(&[&a0, &b], foreign)).unwrap_err(),
            TrustError::NoAnchor
        );
    }

    #[test]
    fn the_fixpoint_follows_a_chain_of_custodians() {
        let (a0, b, c3) = (Device::new(1), Device::new(2), Device::new(3));
        let mut evidence = tenant(&a0, &b);
        // A0 approves C; B (a custodian from day 2) appoints C on day 5.
        evidence.push(approval(&a0, &c3, 40, T0 + 4 * DAY, T0 + 365 * DAY));
        evidence.push(root(
            &b,
            &c3,
            RootGrantVariant::ExistingRootGrant,
            41,
            40,
            T0 + 5 * DAY,
            T0 + 50 * DAY,
        ));
        // Listed first, so one pass cannot find it before B counts.
        evidence.reverse();
        let c = chain(page(&[&a0, &b, &c3], evidence)).unwrap();
        assert!(c.custodian_at(&c3.key(), T0 + 6 * DAY));
    }

    #[test]
    fn reported_revocations_and_the_key_age_end_windows_early() {
        let (a0, b) = (Device::new(1), Device::new(2));
        let mut p = page(&[&a0, &b], tenant(&a0, &b));
        p.revocations.push(RevokedRecord {
            payload_domain: DOMAIN_TENANT_ROOT_KEY_GRANT.into(),
            replay_id: [21; 16],
            revoked_at_ms: T0 + 10 * DAY,
        });
        let c = chain(p.clone()).unwrap();
        assert!(c.custodian_at(&b.key(), T0 + 9 * DAY));
        assert!(!c.custodian_at(&b.key(), T0 + 10 * DAY));

        p.revocations.clear();
        p.device_revocations.push(RevokedDevice {
            device_id: b.id,
            revoked_at_ms: T0 + 20 * DAY,
        });
        let c = chain(p).unwrap();
        assert!(!c.custodian_at(&b.key(), T0 + 20 * DAY));

        // A self-renewal far past the key's age is clipped at 1095 days.
        let mut evidence = tenant(&a0, &b);
        let late = T0 + 1000 * DAY;
        evidence.push(approval(&a0, &a0, 50, late, late + 400 * DAY));
        evidence.push(root(
            &a0,
            &a0,
            RootGrantVariant::ExistingRootGrant,
            51,
            50,
            late,
            late + 400 * DAY,
        ));
        evidence[0] = approval(&a0, &a0, 10, T0, late + DAY);
        evidence[1] = root(
            &a0,
            &a0,
            RootGrantVariant::FirstRootSelfGrant,
            11,
            10,
            T0,
            late + DAY,
        );
        evidence[3] = grant(&a0, &a0, Capability::DeviceApprove, 12, T0, late + DAY);
        let c = chain(page(&[&a0, &b], evidence)).unwrap();
        assert!(c.custodian_at(&a0.key(), T0 + 1094 * DAY));
        assert!(!c.custodian_at(&a0.key(), T0 + 1095 * DAY));
    }

    #[test]
    fn forged_or_foreign_containers_are_dropped() {
        let (a0, b) = (Device::new(1), Device::new(2));
        let mut evidence = tenant(&a0, &b);
        // B's appointment with one signature byte flipped.
        let last = evidence.last_mut().unwrap();
        let n = last.len();
        last[n - 1] ^= 1;
        let c = chain(page(&[&a0, &b], evidence)).unwrap();
        assert!(!c.custodian_at(&b.key(), T0 + 50 * DAY));

        // A container whose issuer key is not served is dropped: without
        // A0's key nothing roots the chain.
        let c = chain(page(&[&b], tenant(&a0, &b)));
        assert_eq!(c.unwrap_err(), TrustError::NoAnchor);
    }

    #[test]
    fn the_anchor_is_unique_linked_and_pinnable() {
        let (a0, b) = (Device::new(1), Device::new(2));
        // No D1 approval linked by g0.
        let mut evidence = tenant(&a0, &b);
        evidence.remove(0);
        assert_eq!(
            chain(page(&[&a0, &b], evidence)).unwrap_err(),
            TrustError::NoAnchor
        );

        // A second self-grant.
        let mut evidence = tenant(&a0, &b);
        evidence.push(approval(&b, &b, 60, T0, T0 + DAY));
        evidence.push(root(
            &b,
            &b,
            RootGrantVariant::FirstRootSelfGrant,
            61,
            60,
            T0,
            T0 + DAY,
        ));
        assert_eq!(
            chain(page(&[&a0, &b], evidence)).unwrap_err(),
            TrustError::ConflictingAnchors
        );

        let ev = Evidence::collect(&BINDING, &[page(&[&a0, &b], tenant(&a0, &b))]).unwrap();
        assert!(TrustChain::evaluate(ev.clone(), Some(&a0.key())).is_ok());
        assert_eq!(
            TrustChain::evaluate(ev, Some(&b.key())).unwrap_err(),
            TrustError::AnchorMismatch
        );
    }

    #[test]
    fn pages_must_be_one_complete_ordered_set() {
        let (a0, b) = (Device::new(1), Device::new(2));
        let mut first = page(&[&a0, &b], tenant(&a0, &b));
        first.next_cursor = vec![1];
        let mut second = page(&[], Vec::new());
        second.page_index = 1;
        assert!(Evidence::collect(&BINDING, &[first.clone(), second.clone()]).is_ok());
        assert!(
            Evidence::collect(&BINDING, &[first.clone()]).is_err(),
            "truncated"
        );
        assert!(Evidence::collect(&BINDING, &[second.clone(), first.clone()]).is_err());
        let mut foreign = second.clone();
        foreign.tenant_id = [8; 16];
        assert!(Evidence::collect(&BINDING, &[first.clone(), foreign]).is_err());
        assert!(Evidence::collect(&BINDING, &[]).is_err());
        let mut twice = first.clone();
        twice.page_index = 0;
        let mut last = second.clone();
        last.page_index = 0;
        assert!(
            Evidence::collect(&BINDING, &[twice, last]).is_err(),
            "an index repeats"
        );
    }
}
