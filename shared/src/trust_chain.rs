//! Client-side verification of a tenant's trust evidence (ADR 0002 B2,
//! "Verification algorithm", rules 1-5).
//!
//! [`Evidence::collect`] keeps the usable containers of a full set of
//! [`TenantTrustEvidencePageV2`] pages: they parse exactly, their signature
//! verifies under a public key whose ID matches, and they name the binding's
//! tenant and instance. [`TrustChain::evaluate`] then derives, as a least
//! fixpoint rooted at the tenant's one `FirstRootSelfGrant`, the custodian
//! windows of every key, and answers approval, capability and fleet key grant
//! questions from them.
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
    DeviceApprovalV2, DeviceHpkeGrantV2, GrantSubject, Payload, RootGrantVariant,
    TenantCapabilityGrantV2, TenantRootKeyGrantV2,
};
use crate::keys::signing_key_id;
use crate::trust_evidence::{TenantTrustEvidencePageV2, MAX_EVIDENCE_CONTAINERS};

/// D-6 (c): a key's custodian windows end this long after its first one.
pub const MAX_CUSTODIAN_KEY_AGE_MS: u64 = 1095 * 86_400_000;
/// The local clock's tolerance for "now".
pub const CLOCK_TOLERANCE_MS: u64 = 300_000;
/// A client stops at this many pages: enough for the container cap at the
/// smallest pages the byte limit forces, and a bound on empty pages.
pub const MAX_EVIDENCE_PAGES: usize = 4096;

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

/// A device as rule 5 compares a `DeviceHpkeGrant`'s subject to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recipient {
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
    pub signing_key_id: KeyId,
    pub hpke_key_id: KeyId,
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
    /// `DeviceHpkeGrant`s by `signed_container_hash`.
    device_grants: BTreeMap<[u8; 32], Usable<DeviceHpkeGrantV2>>,
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
        if pages.len() > MAX_EVIDENCE_PAGES {
            return Err(TrustError::TooMuchEvidence);
        }
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
            let hash = *record.signed_container_hash();
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
                Payload::DeviceHpkeGrant(g) if names(&g.common, binding) => {
                    let revoked_at_ms = revoked_at(&g.common.replay_id);
                    out.device_grants.insert(
                        hash,
                        Usable {
                            issuer,
                            payload: g,
                            revoked_at_ms,
                        },
                    );
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

/// Positions in `items` by the key `key_of` names, so a question about one
/// key reads only that key's records.
fn index<T>(items: &[T], key_of: impl Fn(&T) -> Option<KeyId>) -> BTreeMap<KeyId, Vec<usize>> {
    let mut by_key: BTreeMap<KeyId, Vec<usize>> = BTreeMap::new();
    for (i, item) in items.iter().enumerate() {
        if let Some(key) = key_of(item) {
            by_key.entry(key).or_default().push(i);
        }
    }
    by_key
}

/// The result of evaluating one evidence set.
#[derive(Debug, Clone)]
pub struct TrustChain {
    anchor: KeyId,
    /// `Cust(K)`: clipped, non-empty windows.
    custodians: BTreeMap<KeyId, Vec<(u64, u64)>>,
    /// D-6 (c): the first `not_before_ms` of any usable root grant naming a
    /// key, over every usable root grant so the clip is fixed up front.
    first_not_before: BTreeMap<KeyId, u64>,
    approvals_by_subject: BTreeMap<KeyId, Vec<usize>>,
    /// Capability grants by subject, then issuer: a question reads only the
    /// grants that custodians issued, however many others name the subject.
    grants_by_subject: BTreeMap<KeyId, BTreeMap<KeyId, Vec<usize>>>,
    evidence: Evidence,
    /// The replay ID of the D1 approval `g0` links.
    anchor_approval: [u8; 16],
}

impl TrustChain {
    /// Rules 1-4 over `evidence`. With `pinned`, the anchor must be it.
    pub fn evaluate(evidence: Evidence, pinned: Option<&KeyId>) -> Result<Self, TrustError> {
        let mut anchors = evidence.roots.iter().enumerate().filter(|(_, r)| {
            r.payload.variant == RootGrantVariant::FirstRootSelfGrant
                && r.issuer == r.payload.subject_signing_key_id
                && r.payload.root_generation == 0
        });
        let (g0, first) = anchors.next().ok_or(TrustError::NoAnchor)?;
        if anchors.next().is_some() {
            return Err(TrustError::ConflictingAnchors);
        }
        let anchor = first.issuer;
        if pinned.is_some_and(|p| *p != anchor) {
            return Err(TrustError::AnchorMismatch);
        }
        let mut first_not_before: BTreeMap<KeyId, u64> = BTreeMap::new();
        for r in &evidence.roots {
            let at = first_not_before
                .entry(r.payload.subject_signing_key_id)
                .or_insert(u64::MAX);
            *at = (*at).min(r.payload.common.not_before_ms);
        }
        let mut chain = TrustChain {
            anchor,
            custodians: BTreeMap::new(),
            first_not_before,
            approvals_by_subject: index(&evidence.approvals, |a| {
                Some(a.payload.subject_signing_key_id)
            }),
            grants_by_subject: {
                let mut by: BTreeMap<KeyId, BTreeMap<KeyId, Vec<usize>>> = BTreeMap::new();
                for (i, g) in evidence.grants.iter().enumerate() {
                    if let GrantSubject::Device { signing_key_id, .. } = &g.payload.subject {
                        by.entry(*signing_key_id)
                            .or_default()
                            .entry(g.issuer)
                            .or_default()
                            .push(i);
                    }
                }
                by
            },
            anchor_approval: first.payload.subject_device_approval_replay_id,
            evidence,
        };
        // Base: g0 counts only with its D1 approval, A0's own, valid when g0
        // was issued.
        let base = chain.evidence.roots[g0].payload.clone();
        if !chain.linked_approval_holds(&base) {
            return Err(TrustError::NoAnchor);
        }
        chain.add_window(g0);

        // Step, to the least fixpoint: every pass either counts a new grant or
        // ends, and nothing counted is ever taken back.
        let mut pending: Vec<usize> = (0..chain.evidence.roots.len())
            .filter(|&i| i != g0)
            .filter(|&i| {
                chain.evidence.roots[i].payload.variant != RootGrantVariant::FirstRootSelfGrant
            })
            .collect();
        loop {
            let (ready, rest): (Vec<usize>, Vec<usize>) = pending.into_iter().partition(|&i| {
                let r = &chain.evidence.roots[i];
                // The cheap test first: most junk names an issuer with no window.
                chain.custodians.contains_key(&r.issuer)
                    && chain.custodian_at(&r.issuer, r.payload.common.issued_at_ms)
                    && chain.linked_approval_holds(&r.payload)
            });
            if ready.is_empty() {
                break;
            }
            for i in ready {
                chain.add_window(i);
            }
            pending = rest;
        }
        Ok(chain)
    }

    /// The bootstrap anchor `A0`.
    pub fn anchor(&self) -> &KeyId {
        &self.anchor
    }

    fn add_window(&mut self, i: usize) {
        let r = &self.evidence.roots[i];
        let g = &r.payload;
        let device_revoked = self
            .evidence
            .revoked_devices
            .get(&g.subject_device_id)
            .copied();
        let cap = self.first_not_before[&g.subject_signing_key_id]
            .saturating_add(MAX_CUSTODIAN_KEY_AGE_MS);
        let (nb, na) = (
            g.common.not_before_ms,
            end_of(&g.common, r.revoked_at_ms, device_revoked).min(cap),
        );
        // A window the clip or a revocation emptied holds nothing.
        if nb < na {
            self.custodians
                .entry(g.subject_signing_key_id)
                .or_default()
                .push((nb, na));
        }
    }

    fn windows(&self, key: &KeyId) -> &[(u64, u64)] {
        self.custodians.get(key).map_or(&[], Vec::as_slice)
    }

    /// Rule 1: `key` holds a custodian window containing `t`.
    pub fn custodian_at(&self, key: &KeyId, t: u64) -> bool {
        self.windows(key).iter().any(|&w| holds(w, t))
    }

    /// Rule 2: `key` is a custodian now, within the clock tolerance.
    pub fn custodian_now(&self, key: &KeyId, now: u64) -> bool {
        let (lo, hi) = (
            now.saturating_sub(CLOCK_TOLERANCE_MS),
            now.saturating_add(CLOCK_TOLERANCE_MS),
        );
        self.windows(key)
            .iter()
            .any(|&(nb, na)| nb <= hi && lo < na)
    }

    /// Rule 1's link: `g`'s own approval, the one it names by replay ID for
    /// exactly its subject device, account and HPKE key, valid when `g` was
    /// issued.
    fn linked_approval_holds(&self, g: &TenantRootKeyGrantV2) -> bool {
        // The link fields first: they are cheap, and pick out at most a few
        // of the approvals the server lists for this key.
        self.approvals_by_subject
            .get(&g.subject_signing_key_id)
            .into_iter()
            .flatten()
            .map(|&i| &self.evidence.approvals[i])
            .filter(|a| {
                let p = &a.payload;
                p.common.replay_id == g.subject_device_approval_replay_id
                    && p.subject_device_id == g.subject_device_id
                    && p.subject_account_id == g.subject_account_id
                    && p.subject_hpke_key_id == g.recipient_hpke_key_id
                    // Root custody spans the tenant: its TRK opens every
                    // fleet's RecoveryGrant, so a fleet approval cannot carry
                    // it (ADR 0002 rule 1).
                    && approval_scope(p) == Scope::Tenant
            })
            .any(|a| self.approval_holds_at(a, g.common.issued_at_ms))
    }

    /// Rule 3 for one approval: in force at `t`, from an allowed issuer.
    fn approval_holds_at(&self, a: &Usable<DeviceApprovalV2>, t: u64) -> bool {
        let p = &a.payload;
        let device_revoked = self
            .evidence
            .revoked_devices
            .get(&p.subject_device_id)
            .copied();
        holds(
            (
                p.common.not_before_ms,
                end_of(&p.common, a.revoked_at_ms, device_revoked),
            ),
            t,
        ) && self.approval_issuer_ok(a)
    }

    /// Rule 3: the usable approvals of `key` valid at `t`, whatever their scope.
    fn approvals_of(
        &self,
        key: &KeyId,
        t: u64,
    ) -> impl Iterator<Item = &Usable<DeviceApprovalV2>> + '_ {
        self.approvals_by_subject
            .get(key)
            .into_iter()
            .flatten()
            .map(|&i| &self.evidence.approvals[i])
            .filter(move |a| self.approval_holds_at(a, t))
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
        let t = p.common.issued_at_ms;
        self.custodian_at(&a.issuer, t)
            && self.capability_at(&a.issuer, Capability::DeviceApprove, approval_scope(p), t)
    }

    /// Rule 3, public: `key` holds an approval valid at `t` that covers `scope`.
    pub fn approval_valid_at(&self, key: &KeyId, scope: Scope, t: u64) -> bool {
        self.approvals_of(key, t)
            .any(|a| match (approval_scope(&a.payload), scope) {
                (Scope::Tenant, _) => true,
                (Scope::Fleet(f), Scope::Fleet(g)) => f == g,
                _ => false,
            })
    }

    /// Rule 4: `key` holds `capability` over `scope` at `t`, through a usable
    /// device-scoped grant whose issuer was a custodian when it was issued.
    /// Custody itself is never a capability grant: only root grants carry it
    /// (D-2), so `root.custody` is never held this way.
    pub fn capability_at(&self, key: &KeyId, capability: Capability, scope: Scope, t: u64) -> bool {
        if capability == Capability::RootCustody {
            return false;
        }
        let Some(by_issuer) = self.grants_by_subject.get(key) else {
            return false;
        };
        // Only a custodian's grants can count, and the server cannot add
        // custodians, so walk those rather than every issuer it lists.
        self.custodians
            .keys()
            .filter_map(|issuer| by_issuer.get(issuer))
            .flatten()
            .map(|&i| &self.evidence.grants[i])
            .any(|g| {
                let p = &g.payload;
                let GrantSubject::Device { device_id, .. } = &p.subject else {
                    return false;
                };
                let device_revoked = self.evidence.revoked_devices.get(device_id).copied();
                p.capability == capability
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

    /// Rule 5 up to the HPKE open: the usable `DeviceHpkeGrant` whose exact
    /// container is `container`, for fleet `fleet_id` generation
    /// `generation`, naming `to` as its subject and recipient, in force at
    /// `now`, from an issuer that at the grant's `issued_at_ms` was a
    /// custodian with an approval and `fleet.manage` covering the fleet. The
    /// parser already pinned `grant_capability`, the suite and the info bytes.
    /// The caller opens it, checks `fkek_key_id`, and checks no other key is
    /// pinned for the generation.
    pub fn device_hpke_grant(
        &self,
        container: &[u8],
        to: &Recipient,
        fleet_id: &[u8; 16],
        generation: u64,
        now: u64,
    ) -> Option<&DeviceHpkeGrantV2> {
        let record = AuthorizationRecord::parse(container).ok()?;
        let g = self
            .evidence
            .device_grants
            .get(record.signed_container_hash())?;
        let p = &g.payload;
        let device_revoked = self
            .evidence
            .revoked_devices
            .get(&p.subject_device_id)
            .copied();
        let (fleet, t) = (Scope::Fleet(p.fleet_id), p.common.issued_at_ms);
        (p.fleet_id == *fleet_id
            && p.generation == generation
            && p.subject_account_id == to.account_id
            && p.subject_device_id == to.device_id
            && p.subject_signing_key_id == to.signing_key_id
            && p.recipient_hpke_key_id == to.hpke_key_id
            && holds(
                (
                    p.common.not_before_ms,
                    end_of(&p.common, g.revoked_at_ms, device_revoked),
                ),
                now,
            )
            && self.custodian_at(&g.issuer, t)
            && self.approval_valid_at(&g.issuer, fleet, t)
            && self.capability_at(&g.issuer, Capability::FleetManage, fleet, t))
        .then_some(p)
    }
}

fn approval_scope(a: &DeviceApprovalV2) -> Scope {
    match a.approval_scope_kind {
        ApprovalScopeKind::Tenant => Scope::Tenant,
        ApprovalScopeKind::Fleet => Scope::Fleet(a.approval_scope_id),
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
        build_record, DOMAIN_DEVICE_APPROVAL, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        DOMAIN_TENANT_CAPABILITY_GRANT, DOMAIN_TENANT_ROOT_KEY_GRANT,
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
        assert!(c.approval_valid_at(&b.key(), Scope::Fleet([5; 16]), T0 + 3 * DAY));
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
        assert!(c.approval_valid_at(&d.key(), Scope::Tenant, T0 + 3 * DAY));
        assert!(!c.custodian_at(&d.key(), T0 + 3 * DAY));
        assert!(!c.capability_at(
            &b.key(),
            Capability::DeviceApprove,
            Scope::Tenant,
            T0 + 3 * DAY
        ));
    }

    /// B's ExistingRootGrant from A0, with `edit` applied before signing.
    fn appointment(
        a0: &Device,
        b: &Device,
        edit: impl FnOnce(&mut TenantRootKeyGrantV2),
    ) -> Vec<u8> {
        let mut g = TenantRootKeyGrantV2 {
            common: common(21, T0 + 2 * DAY, T0 + 100 * DAY),
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [7; 32],
            root_generation: 0,
            subject_account_id: [9; 16],
            subject_device_id: b.id,
            subject_signing_key_id: b.key(),
            recipient_hpke_key_id: [b.id[0]; 32],
            subject_device_approval_replay_id: [20; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        edit(&mut g);
        build_record(&a0.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode())
    }

    #[test]
    fn a_root_grant_counts_only_with_its_exact_approval() {
        let (a0, b) = (Device::new(1), Device::new(2));
        let custodian = |root: Vec<u8>| {
            let mut evidence = tenant(&a0, &b);
            evidence[4] = root;
            chain(page(&[&a0, &b], evidence))
                .unwrap()
                .custodian_at(&b.key(), T0 + 50 * DAY)
        };
        assert!(custodian(appointment(&a0, &b, |_| {})));
        type Edit = fn(&mut TenantRootKeyGrantV2);
        let edits: [Edit; 4] = [
            |g| g.subject_device_id = [6; 16],
            |g| g.subject_account_id = [6; 16],
            |g| g.recipient_hpke_key_id = [6; 32],
            |g| g.subject_device_approval_replay_id = [6; 16],
        ];
        for (n, edit) in edits.into_iter().enumerate() {
            assert!(!custodian(appointment(&a0, &b, edit)), "edit {n}");
        }
    }

    #[test]
    fn a_fleet_approval_covers_only_its_fleet() {
        let (a0, b, d) = (Device::new(1), Device::new(2), Device::new(4));
        let mut evidence = tenant(&a0, &b);
        let a = DeviceApprovalV2 {
            common: common(70, T0 + DAY, T0 + 365 * DAY),
            subject_account_id: [9; 16],
            subject_device_id: d.id,
            subject_signing_key_id: d.key(),
            subject_hpke_key_id: [4; 32],
            approval_scope_kind: ApprovalScopeKind::Fleet,
            approval_scope_id: [5; 16],
        };
        evidence.push(build_record(&a0.sk, DOMAIN_DEVICE_APPROVAL, &a.encode()));
        let c = chain(page(&[&a0, &b, &d], evidence)).unwrap();
        let t = T0 + 2 * DAY;
        assert!(c.approval_valid_at(&d.key(), Scope::Fleet([5; 16]), t));
        assert!(!c.approval_valid_at(&d.key(), Scope::Fleet([6; 16]), t));
        assert!(!c.approval_valid_at(&d.key(), Scope::Tenant, t));
    }

    #[test]
    fn a_root_grant_linked_to_a_fleet_approval_makes_no_custodian() {
        let (a0, b) = (Device::new(1), Device::new(2));
        let mut evidence = tenant(&a0, &b);
        // B's linked approval (replay 20) is for one fleet only.
        let a = DeviceApprovalV2 {
            common: common(20, T0 + DAY, T0 + 365 * DAY),
            subject_account_id: [9; 16],
            subject_device_id: b.id,
            subject_signing_key_id: b.key(),
            subject_hpke_key_id: [b.id[0]; 32],
            approval_scope_kind: ApprovalScopeKind::Fleet,
            approval_scope_id: [5; 16],
        };
        evidence[2] = build_record(&a0.sk, DOMAIN_DEVICE_APPROVAL, &a.encode());
        let c = chain(page(&[&a0, &b], evidence)).unwrap();
        assert!(c.approval_valid_at(&b.key(), Scope::Fleet([5; 16]), T0 + 3 * DAY));
        assert!(!c.custodian_at(&b.key(), T0 + 50 * DAY));
    }

    #[test]
    fn a_grant_sharing_a_counted_grants_replay_id_still_counts() {
        let (a0, b) = (Device::new(1), Device::new(2));
        let mut evidence = tenant(&a0, &b);
        // B's appointment reuses g0's replay ID.
        evidence[4] = root(
            &a0,
            &b,
            RootGrantVariant::ExistingRootGrant,
            11,
            20,
            T0 + 2 * DAY,
            T0 + 100 * DAY,
        );
        let c = chain(page(&[&a0, &b], evidence)).unwrap();
        assert!(c.custodian_at(&b.key(), T0 + 50 * DAY));
    }

    #[test]
    fn a_window_the_clip_empties_holds_nothing_even_now() {
        let (a0, b) = (Device::new(1), Device::new(2));
        let cap = T0 + MAX_CUSTODIAN_KEY_AGE_MS;
        let mut evidence = tenant(&a0, &b);
        // A0 (custodian until T0 + 2000 days) renews itself starting just
        // past its key age.
        evidence[0] = approval(&a0, &a0, 10, T0, T0 + 2000 * DAY);
        evidence[1] = root(
            &a0,
            &a0,
            RootGrantVariant::FirstRootSelfGrant,
            11,
            10,
            T0,
            T0 + 10 * DAY,
        );
        evidence[3] = grant(&a0, &a0, Capability::DeviceApprove, 12, T0, T0 + 2000 * DAY);
        evidence.push(root(
            &a0,
            &a0,
            RootGrantVariant::ExistingRootGrant,
            80,
            10,
            T0 + 5 * DAY,
            cap - 1000,
        ));
        evidence.push(root(
            &a0,
            &a0,
            RootGrantVariant::ExistingRootGrant,
            81,
            10,
            cap - 2000,
            cap + 50 * DAY,
        ));
        let c = chain(page(&[&a0, &b], evidence)).unwrap();
        assert!(c.custodian_now(&a0.key(), cap - 1500));
        let mut evidence = tenant(&a0, &b);
        evidence[0] = approval(&a0, &a0, 10, T0, T0 + 2000 * DAY);
        evidence[1] = root(
            &a0,
            &a0,
            RootGrantVariant::FirstRootSelfGrant,
            11,
            10,
            T0,
            T0 + 10 * DAY,
        );
        evidence.push(root(
            &a0,
            &a0,
            RootGrantVariant::ExistingRootGrant,
            80,
            10,
            T0 + 5 * DAY,
            T0 + 10 * DAY,
        ));
        // Issued while A0 holds a window, starting past the clip.
        let late = TenantRootKeyGrantV2 {
            common: CommonFields {
                issued_at_ms: T0 + 6 * DAY,
                ..common(82, cap + 100_000, cap + 50 * DAY)
            },
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [7; 32],
            root_generation: 0,
            subject_account_id: [9; 16],
            subject_device_id: a0.id,
            subject_signing_key_id: a0.key(),
            recipient_hpke_key_id: [a0.id[0]; 32],
            subject_device_approval_replay_id: [10; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        evidence.push(build_record(
            &a0.sk,
            DOMAIN_TENANT_ROOT_KEY_GRANT,
            &late.encode(),
        ));
        let c = chain(page(&[&a0, &b], evidence)).unwrap();
        for now in [cap - 100_000, cap, cap + 250_000] {
            assert!(!c.custodian_now(&a0.key(), now), "{now}");
        }
    }

    #[test]
    fn root_custody_is_never_a_capability() {
        let (a0, b) = (Device::new(1), Device::new(2));
        let mut evidence = tenant(&a0, &b);
        evidence.push(grant(
            &a0,
            &b,
            Capability::RootCustody,
            90,
            T0,
            T0 + 365 * DAY,
        ));
        let c = chain(page(&[&a0, &b], evidence)).unwrap();
        assert!(!c.capability_at(&b.key(), Capability::RootCustody, Scope::Tenant, T0 + DAY));
    }

    #[test]
    fn junk_from_a_key_with_no_window_costs_one_pass() {
        let (a0, b, m) = (Device::new(1), Device::new(2), Device::new(3));
        let mut evidence = tenant(&a0, &b);
        // A chain ten custodians deep, listed last-first.
        let deep: Vec<Device> = (10..20).map(Device::new).collect();
        let mut prev = &b;
        for (n, d) in deep.iter().enumerate() {
            let at = T0 + (3 + n as u64) * DAY;
            evidence.push(approval(&a0, d, 100 + n as u8, at, T0 + 365 * DAY));
            evidence.push(root(
                prev,
                d,
                RootGrantVariant::ExistingRootGrant,
                150 + n as u8,
                100 + n as u8,
                at,
                T0 + 300 * DAY,
            ));
            prev = d;
        }
        evidence.reverse();
        let mut keys: Vec<&Device> = vec![&a0, &b];
        keys.extend(deep.iter());
        let mut ev = Evidence::collect(&BINDING, &[page(&keys, evidence)]).unwrap();
        // And the cap's worth of root grants a non-custodian signed: built as
        // already-usable entries, since signing 60000 records costs more
        // than the evaluation under test.
        let junk = TenantRootKeyGrantV2 {
            common: common(0, T0, T0 + DAY),
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [7; 32],
            root_generation: 0,
            subject_account_id: [9; 16],
            subject_device_id: m.id,
            subject_signing_key_id: m.key(),
            recipient_hpke_key_id: [3; 32],
            subject_device_approval_replay_id: [0; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        for n in 0..60_000u32 {
            let mut g = junk.clone();
            g.common.replay_id[..4].copy_from_slice(&n.to_be_bytes());
            ev.roots.push(Usable {
                issuer: m.key(),
                payload: g,
                revoked_at_ms: None,
            });
        }
        let started = std::time::Instant::now();
        let c = TrustChain::evaluate(ev, None).unwrap();
        assert!(c.custodian_at(&deep[9].key(), T0 + 20 * DAY));
        assert!(!c.custodian_at(&m.key(), T0 + 1000));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn junk_aimed_at_a_real_issuers_grants_and_approvals_stays_cheap() {
        let (a0, b) = (Device::new(1), Device::new(2));
        let deep: Vec<Device> = (10..40).map(Device::new).collect();
        let mut evidence = tenant(&a0, &b);
        for (n, d) in deep.iter().enumerate() {
            let at = T0 + (3 + n as u64) * DAY;
            evidence.push(approval(&a0, d, 100 + n as u8, at, T0 + 365 * DAY));
            evidence.push(root(
                &a0,
                d,
                RootGrantVariant::ExistingRootGrant,
                150 + n as u8,
                100 + n as u8,
                at,
                T0 + 300 * DAY,
            ));
        }
        let mut keys: Vec<&Device> = vec![&a0, &b];
        keys.extend(deep.iter());
        let mut ev = Evidence::collect(&BINDING, &[page(&keys, evidence)]).unwrap();
        // device.approve grants and approvals for A0, each under its own
        // throwaway issuer, built as usable entries.
        let grant = ev.grants[0].payload.clone();
        let approval = ev.approvals[0].payload.clone();
        let (mut grants, mut approvals) = (Vec::new(), Vec::new());
        for n in 0..30_000u32 {
            let mut issuer = [0xee; 32];
            issuer[..4].copy_from_slice(&n.to_be_bytes());
            let (mut g, mut a) = (grant.clone(), approval.clone());
            g.common.replay_id[..4].copy_from_slice(&n.to_be_bytes());
            a.common.replay_id[..4].copy_from_slice(&n.to_be_bytes());
            grants.push(Usable {
                issuer,
                payload: g,
                revoked_at_ms: None,
            });
            approvals.push(Usable {
                issuer,
                payload: a,
                revoked_at_ms: None,
            });
        }
        // Listed ahead of the real ones.
        grants.append(&mut ev.grants);
        approvals.append(&mut ev.approvals);
        (ev.grants, ev.approvals) = (grants, approvals);
        let started = std::time::Instant::now();
        let c = TrustChain::evaluate(ev, None).unwrap();
        assert!(c.custodian_at(&deep[29].key(), T0 + 40 * DAY));
        for _ in 0..1000 {
            assert!(c.capability_at(
                &a0.key(),
                Capability::DeviceApprove,
                Scope::Tenant,
                T0 + DAY
            ));
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_grant_issued_before_its_issuers_window_never_counts() {
        let (a0, b, d) = (Device::new(1), Device::new(2), Device::new(4));
        let mut evidence = tenant(&a0, &b);
        // B is a custodian from day 2; a grant it dated day 1 does not count,
        // one dated day 3 does.
        evidence.push(grant(
            &b,
            &d,
            Capability::DeviceApprove,
            75,
            T0 + DAY,
            T0 + 365 * DAY,
        ));
        evidence.push(grant(
            &b,
            &d,
            Capability::KeyRotate,
            76,
            T0 + 3 * DAY,
            T0 + 365 * DAY,
        ));
        let c = chain(page(&[&a0, &b, &d], evidence)).unwrap();
        let t = T0 + 10 * DAY;
        assert!(!c.capability_at(&d.key(), Capability::DeviceApprove, Scope::Tenant, t));
        assert!(c.capability_at(&d.key(), Capability::KeyRotate, Scope::Tenant, t));
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
        let endless: Vec<_> = (0..=MAX_EVIDENCE_PAGES as u32)
            .map(|i| TenantTrustEvidencePageV2 {
                page_index: i,
                next_cursor: vec![1],
                ..second.clone()
            })
            .collect();
        assert_eq!(
            Evidence::collect(&BINDING, &endless).unwrap_err(),
            TrustError::TooMuchEvidence
        );
        let mut twice = first.clone();
        twice.page_index = 0;
        let mut last = second.clone();
        last.page_index = 0;
        assert!(
            Evidence::collect(&BINDING, &[twice, last]).is_err(),
            "an index repeats"
        );
    }

    const FLEET: [u8; 16] = [5; 16];

    fn recipient(d: &Device) -> Recipient {
        Recipient {
            account_id: [9; 16],
            device_id: d.id,
            signing_key_id: d.key(),
            hpke_key_id: [d.id[0]; 32],
        }
    }

    /// A `DeviceHpkeGrant` of `FLEET` generation 1 to `subject`, issued at
    /// `nb`; the chain never opens it, so the HPKE bytes are placeholders.
    fn fleet_grant(issuer: &Device, subject: &Device, replay: u8, nb: u64, na: u64) -> Vec<u8> {
        let g = DeviceHpkeGrantV2 {
            common: common(replay, nb, na),
            fleet_id: FLEET,
            fkek_key_id: [6; 32],
            generation: 1,
            subject_account_id: [9; 16],
            subject_device_id: subject.id,
            subject_signing_key_id: subject.key(),
            recipient_hpke_key_id: [subject.id[0]; 32],
            hpke_encapped_key_bytes: vec![3; 32],
            hpke_wrapped_fleet_key_bytes: vec![4; 48],
        };
        build_record(&issuer.sk, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode())
    }

    /// The tenant, A0 holding `fleet.manage`, D approved by A0, and A0's
    /// grant to D issued on day 3 for a year.
    fn fleet_tenant(a0: &Device, b: &Device, d: &Device) -> Vec<Vec<u8>> {
        let mut evidence = tenant(a0, b);
        evidence.push(grant(
            a0,
            a0,
            Capability::FleetManage,
            13,
            T0,
            T0 + 365 * DAY,
        ));
        evidence.push(approval(a0, d, 30, T0 + DAY, T0 + 365 * DAY));
        evidence.push(fleet_grant(a0, d, 31, T0 + 3 * DAY, T0 + 300 * DAY));
        evidence
    }

    const NOW: u64 = T0 + 10 * DAY;

    fn accepts(p: TenantTrustEvidencePageV2, container: &[u8], to: &Recipient) -> bool {
        chain(p)
            .unwrap()
            .device_hpke_grant(container, to, &FLEET, 1, NOW)
            .is_some()
    }

    #[test]
    fn a_fleet_grant_from_a_custodian_with_fleet_manage_is_accepted() {
        let (a0, b, d) = (Device::new(1), Device::new(2), Device::new(4));
        let evidence = fleet_tenant(&a0, &b, &d);
        let g = evidence.last().unwrap().clone();
        let c = chain(page(&[&a0, &b, &d], evidence)).unwrap();
        let got = c
            .device_hpke_grant(&g, &recipient(&d), &FLEET, 1, NOW)
            .unwrap();
        assert_eq!(got.subject_device_id, d.id);
        // Another fleet or generation is not this grant.
        assert!(c
            .device_hpke_grant(&g, &recipient(&d), &[6; 16], 1, NOW)
            .is_none());
        assert!(c
            .device_hpke_grant(&g, &recipient(&d), &FLEET, 2, NOW)
            .is_none());
        // Its window, half-open.
        for (now, ok) in [
            (T0 + 3 * DAY - 1, false),
            (T0 + 3 * DAY, true),
            (T0 + 300 * DAY - 1, true),
            (T0 + 300 * DAY, false),
        ] {
            let got = c.device_hpke_grant(&g, &recipient(&d), &FLEET, 1, now);
            assert_eq!(got.is_some(), ok, "{now}");
        }
        // Bytes the evidence does not hold, and junk.
        let unlisted = fleet_grant(&a0, &d, 32, T0 + 3 * DAY, T0 + 300 * DAY);
        assert!(c
            .device_hpke_grant(&unlisted, &recipient(&d), &FLEET, 1, NOW)
            .is_none());
        assert!(c
            .device_hpke_grant(b"junk", &recipient(&d), &FLEET, 1, NOW)
            .is_none());
    }

    #[test]
    fn a_fleet_grant_names_exactly_this_device() {
        let (a0, b, d) = (Device::new(1), Device::new(2), Device::new(4));
        let evidence = fleet_tenant(&a0, &b, &d);
        let g = evidence.last().unwrap().clone();
        let p = page(&[&a0, &b, &d], evidence);
        assert!(accepts(p.clone(), &g, &recipient(&d)));
        type Edit = fn(&mut Recipient);
        let edits: [Edit; 4] = [
            |r| r.account_id = [6; 16],
            |r| r.device_id = [6; 16],
            |r| r.signing_key_id = [6; 32],
            |r| r.hpke_key_id = [6; 32],
        ];
        for (n, edit) in edits.into_iter().enumerate() {
            let mut to = recipient(&d);
            edit(&mut to);
            assert!(!accepts(p.clone(), &g, &to), "edit {n}");
        }
    }

    #[test]
    fn a_fleet_grant_needs_a_custodian_with_approval_and_fleet_manage() {
        let (a0, b, d, m) = (
            Device::new(1),
            Device::new(2),
            Device::new(4),
            Device::new(3),
        );
        let keys = [&a0, &b, &d, &m];
        let with = |extra: Vec<Vec<u8>>, g: &[u8]| {
            let mut evidence = fleet_tenant(&a0, &b, &d);
            evidence.extend(extra);
            evidence.push(g.to_vec());
            accepts(page(&keys, evidence), g, &recipient(&d))
        };
        // M is approved and holds fleet.manage, but is no custodian.
        let g = fleet_grant(&m, &d, 40, T0 + 3 * DAY, T0 + 300 * DAY);
        assert!(!with(
            vec![
                approval(&a0, &m, 41, T0 + DAY, T0 + 365 * DAY),
                grant(
                    &a0,
                    &m,
                    Capability::FleetManage,
                    42,
                    T0 + DAY,
                    T0 + 365 * DAY
                ),
            ],
            &g
        ));
        // B is a custodian with an approval, but without fleet.manage, or
        // with it only for another fleet.
        let g = fleet_grant(&b, &d, 43, T0 + 3 * DAY, T0 + 300 * DAY);
        assert!(!with(Vec::new(), &g));
        let other_fleet = TenantCapabilityGrantV2 {
            common: common(44, T0 + 2 * DAY, T0 + 365 * DAY),
            subject: GrantSubject::Device {
                account_id: [9; 16],
                device_id: b.id,
                signing_key_id: b.key(),
                hpke_key_id: [b.id[0]; 32],
            },
            scope_kind: CapabilityScopeKind::Fleet,
            scope_id: [6; 16],
            capability: Capability::FleetManage,
        };
        let other_fleet = build_record(
            &a0.sk,
            DOMAIN_TENANT_CAPABILITY_GRANT,
            &other_fleet.encode(),
        );
        assert!(!with(vec![other_fleet], &g));
        let fleet_manage = grant(
            &a0,
            &b,
            Capability::FleetManage,
            45,
            T0 + 2 * DAY,
            T0 + 365 * DAY,
        );
        assert!(with(vec![fleet_manage.clone()], &g));
        // B, a custodian holding fleet.manage until day 100, issues on day 50
        // after its approval ended on day 40.
        let late = fleet_grant(&b, &d, 46, T0 + 50 * DAY, T0 + 300 * DAY);
        let mut evidence = fleet_tenant(&a0, &b, &d);
        evidence[2] = approval(&a0, &b, 20, T0 + DAY, T0 + 40 * DAY);
        evidence.extend([fleet_manage, late.clone()]);
        let c = chain(page(&keys, evidence)).unwrap();
        assert!(c.custodian_at(&b.key(), T0 + 50 * DAY));
        assert!(c.capability_at(
            &b.key(),
            Capability::FleetManage,
            Scope::Fleet(FLEET),
            T0 + 50 * DAY
        ));
        assert!(c
            .device_hpke_grant(&late, &recipient(&d), &FLEET, 1, T0 + 60 * DAY)
            .is_none());
    }

    #[test]
    fn revocations_end_a_fleet_grant() {
        let (a0, b, d) = (Device::new(1), Device::new(2), Device::new(4));
        let keys = [&a0, &b, &d];
        let evidence = fleet_tenant(&a0, &b, &d);
        let g = evidence.last().unwrap().clone();
        let p = page(&keys, evidence.clone());
        // The grant itself, reported revoked before now.
        let mut revoked = p.clone();
        revoked.revocations.push(RevokedRecord {
            payload_domain: DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE.into(),
            replay_id: [31; 16],
            revoked_at_ms: NOW - 1,
        });
        assert!(!accepts(revoked.clone(), &g, &recipient(&d)));
        revoked.revocations[0].revoked_at_ms = NOW + 1;
        assert!(accepts(revoked, &g, &recipient(&d)));
        // Its subject device.
        let mut revoked = p.clone();
        revoked.device_revocations.push(RevokedDevice {
            device_id: d.id,
            revoked_at_ms: NOW - 1,
        });
        assert!(!accepts(revoked, &g, &recipient(&d)));
        // Its issuer, B, revoked on day 5: a grant it issued on day 4 keeps
        // its standing, one it issued on day 6 never had any.
        let fleet_manage = grant(
            &a0,
            &b,
            Capability::FleetManage,
            45,
            T0 + 2 * DAY,
            T0 + 365 * DAY,
        );
        let early = fleet_grant(&b, &d, 47, T0 + 4 * DAY, T0 + 300 * DAY);
        let late = fleet_grant(&b, &d, 48, T0 + 6 * DAY, T0 + 300 * DAY);
        let mut evidence = evidence;
        evidence.extend([fleet_manage, early.clone(), late.clone()]);
        let mut p = page(&keys, evidence);
        p.device_revocations.push(RevokedDevice {
            device_id: b.id,
            revoked_at_ms: T0 + 5 * DAY,
        });
        assert!(accepts(p.clone(), &early, &recipient(&d)));
        assert!(!accepts(p, &late, &recipient(&d)));
    }

    #[test]
    fn a_fleet_scoped_approval_and_fleet_manage_are_enough() {
        let (a0, b, d) = (Device::new(1), Device::new(2), Device::new(4));
        // B's tenant approval ends on day 40; from then on only an approval
        // and a fleet.manage for FLEET cover it, when it issues on day 50.
        let mut evidence = fleet_tenant(&a0, &b, &d);
        evidence[2] = approval(&a0, &b, 20, T0 + DAY, T0 + 40 * DAY);
        let fleet_approval = DeviceApprovalV2 {
            common: common(50, T0 + 30 * DAY, T0 + 365 * DAY),
            subject_account_id: [9; 16],
            subject_device_id: b.id,
            subject_signing_key_id: b.key(),
            subject_hpke_key_id: [b.id[0]; 32],
            approval_scope_kind: ApprovalScopeKind::Fleet,
            approval_scope_id: FLEET,
        };
        let fleet_manage = TenantCapabilityGrantV2 {
            common: common(51, T0 + 2 * DAY, T0 + 365 * DAY),
            subject: GrantSubject::Device {
                account_id: [9; 16],
                device_id: b.id,
                signing_key_id: b.key(),
                hpke_key_id: [b.id[0]; 32],
            },
            scope_kind: CapabilityScopeKind::Fleet,
            scope_id: FLEET,
            capability: Capability::FleetManage,
        };
        let late = fleet_grant(&b, &d, 52, T0 + 50 * DAY, T0 + 300 * DAY);
        evidence.extend([
            build_record(&a0.sk, DOMAIN_DEVICE_APPROVAL, &fleet_approval.encode()),
            build_record(
                &a0.sk,
                DOMAIN_TENANT_CAPABILITY_GRANT,
                &fleet_manage.encode(),
            ),
            late.clone(),
        ]);
        let c = chain(page(&[&a0, &b, &d], evidence)).unwrap();
        assert!(c
            .device_hpke_grant(&late, &recipient(&d), &FLEET, 1, T0 + 60 * DAY)
            .is_some());
    }

    #[test]
    fn a_fleet_grant_of_another_tenant_is_dropped() {
        let (a0, b, d) = (Device::new(1), Device::new(2), Device::new(4));
        SIGNED_TENANT.set([8; 16]);
        let foreign = fleet_grant(&a0, &d, 60, T0 + 3 * DAY, T0 + 300 * DAY);
        SIGNED_TENANT.set(TENANT);
        let mut evidence = fleet_tenant(&a0, &b, &d);
        evidence.push(foreign.clone());
        assert!(!accepts(
            page(&[&a0, &b, &d], evidence),
            &foreign,
            &recipient(&d)
        ));
    }
}
