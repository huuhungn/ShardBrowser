//! Exact `SnapshotManifestV2`, `SignedSnapshotManifestV2`, `CommitRequestV2`
//! and `CommitReceiptBindingV2` codecs (plan 5.6.2, L509-L587; G2-07..G2-09).
//!
//! Build order is one way (plan L1301): `DekSlotV2` -> `EnvelopeIntentV2` ->
//! ciphertext -> manifest. The manifest only carries the hashes the envelope
//! code already produces (`envelope_v2::preamble_sha256`, `IntentMaterial::
//! intent_hash`, `SlotMaterial::dek_slot_sha256`, `ObjectDigest`); nothing in
//! the envelope refers back to it.
//!
//! As in [`crate::authz_record`], a parser never trusts a value it can
//! recompute, every map is closed, and a manifest payload is reachable only
//! after its signature verified. Checks that need live state (upload, lease
//! and profile rows, the pinned head, the client's accepted epoch, the signer's
//! capabilities) belong to the caller.
//!
//! The legacy flat manifest in [`crate::fleet_manifest`] is still what the
//! server commit route and the launcher use; these codecs are not wired yet.

use ed25519_dalek::SigningKey;

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};
use crate::envelope_v2::MAX_OBJECT_SIZE;
use crate::keys::signing_key_id;
use crate::signing::{self, ED25519_SIG_LEN, SIGNATURE_SUITE_ID_ED25519, SIGNATURE_VERSION};

/// Plan L511-L512.
pub const DOMAIN_MANIFEST_PAYLOAD: &str = "shardx.snapshot.manifest-payload.v2";
/// Plan L531.
pub const DOMAIN_SIGNED_MANIFEST_CONTAINER: &str = "shardx.snapshot.signed-manifest-container.v2";
/// Plan L542.
pub const DOMAIN_COMMIT_REQUEST: &str = "shardx.sync.commit-request.v2";
/// Plan L570.
pub const DOMAIN_COMMIT_RECEIPT_BINDING: &str = "shardx.sync.commit-receipt-binding.v2";
/// Plan L547: the only `operation_scope` a commit request may carry.
pub const OPERATION_SCOPE_COMMIT: &str = "profile.commit.v2";
pub use crate::canonical::L_SNAPSHOT_HEAD;
/// Every version field of the four records (plan L512, L532, L542, L571).
pub const VERSION: u16 = 2;

/// The container uses the authorization container's construction (plan
/// L528-L529, L429), so it keeps that container's payload cap. Its
/// `signature_bytes:Bytes(1,4096)` is exactly 64 bytes under suite 1.
const MAX_MANIFEST_PAYLOAD_BYTES: usize = 65536;
/// `signed_manifest_container_bytes:Bytes(1,131072)` (plan L551).
pub const MAX_SIGNED_MANIFEST_CONTAINER_BYTES: usize = 131072;
/// The embedded container at its cap plus room for the other 21 fields,
/// checked before decoding.
pub const MAX_COMMIT_REQUEST_BYTES: usize = MAX_SIGNED_MANIFEST_CONTAINER_BYTES + 4096;

/// Why a manifest, request or receipt was refused. [`SnapshotError::code`]
/// gives the plan's wire code (L1231-L1234).
#[derive(Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// Malformed, non-canonical, unsupported or wrongly signed record.
    Record(RecordError),
    /// A commit request whose hash, embedded manifest bytes or copied field
    /// does not match (plan L558-L563, L1233).
    ManifestReplayMismatch(&'static str),
    /// A receipt field that does not bind the stored request (plan L1105).
    ReceiptMismatch(&'static str),
}

impl SnapshotError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Record(e) => e.code(),
            Self::ManifestReplayMismatch(_) => "MANIFEST_REPLAY_MISMATCH",
            Self::ReceiptMismatch(_) => "RECEIPT_MISMATCH",
        }
    }
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Record(e) => write!(f, "{e}"),
            Self::ManifestReplayMismatch(field) => {
                write!(f, "commit request {field} does not match")
            }
            Self::ReceiptMismatch(field) => {
                write!(f, "commit receipt {field} does not bind the request")
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<RecordError> for SnapshotError {
    fn from(e: RecordError) -> Self {
        Self::Record(e)
    }
}

type Result<T> = std::result::Result<T, SnapshotError>;

fn bad(field: &'static str) -> SnapshotError {
    SnapshotError::Record(RecordError::BadValue(field))
}

fn unsupported(field: &'static str, id: u16) -> SnapshotError {
    SnapshotError::Record(RecordError::Unsupported {
        field,
        id: id.into(),
    })
}

// ------------------------------------------------------ SnapshotManifestV2 ---

/// The `SnapshotManifestV2` payload (plan L511-L526), besides `domain` and
/// `version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotManifestV2 {
    pub snapshot_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub fleet_id: [u8; 16],
    pub profile_id: [u8; 16],
    pub lease_id: [u8; 16],
    pub target_version: u64,
    pub base_version: u64,
    pub fencing_token: u64,
    pub key_generation: u64,
    pub fkek_key_id: [u8; 32],
    pub preamble_sha256: [u8; 32],
    pub intent_hash: [u8; 32],
    pub dek_slot_sha256: [u8; 32],
    pub ciphertext_sha256: [u8; 32],
    pub ciphertext_size: u64,
    /// Omitted iff `base_version == 0` (plan L521).
    pub previous_signed_head_hash: Option<[u8; 32]>,
    pub signer_signing_key_id: [u8; 32],
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub manifest_replay_id: [u8; 16],
    /// Informational only (plan L526; ADR 0002 trust chain rule 6).
    pub created_at_ms: u64,
}

impl SnapshotManifestV2 {
    pub fn encode(&self) -> Vec<u8> {
        let mut f = vec![
            ("domain", c::t(DOMAIN_MANIFEST_PAYLOAD)),
            ("version", c::u(VERSION.into())),
            ("snapshot_id", c::b(&self.snapshot_id)),
            ("tenant_id", c::b(&self.tenant_id)),
            ("fleet_id", c::b(&self.fleet_id)),
            ("profile_id", c::b(&self.profile_id)),
            ("lease_id", c::b(&self.lease_id)),
            ("target_version", c::u(self.target_version)),
            ("base_version", c::u(self.base_version)),
            ("fencing_token", c::u(self.fencing_token)),
            ("key_generation", c::u(self.key_generation)),
            ("fkek_key_id", c::b(&self.fkek_key_id)),
            ("preamble_sha256", c::b(&self.preamble_sha256)),
            ("intent_hash", c::b(&self.intent_hash)),
            ("dek_slot_sha256", c::b(&self.dek_slot_sha256)),
            ("ciphertext_sha256", c::b(&self.ciphertext_sha256)),
            ("ciphertext_size", c::u(self.ciphertext_size)),
            ("signer_signing_key_id", c::b(&self.signer_signing_key_id)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
            ("manifest_replay_id", c::b(&self.manifest_replay_id)),
            ("created_at_ms", c::u(self.created_at_ms)),
        ];
        if let Some(h) = &self.previous_signed_head_hash {
            f.push(("previous_signed_head_hash", c::b(h)));
        }
        c::encode(&c::m(f))
    }

    /// Parses exact canonical payload bytes by the closed schema.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("SnapshotManifestV2", bytes)?;
        f.exact_text("domain", DOMAIN_MANIFEST_PAYLOAD)?;
        let version = f.u16("version")?;
        if version != VERSION {
            return Err(unsupported("version", version));
        }
        let m = Self {
            snapshot_id: f.fixed("snapshot_id")?,
            tenant_id: f.fixed("tenant_id")?,
            fleet_id: f.fixed("fleet_id")?,
            profile_id: f.fixed("profile_id")?,
            lease_id: f.fixed("lease_id")?,
            target_version: f.uint("target_version")?,
            base_version: f.uint("base_version")?,
            fencing_token: f.uint("fencing_token")?,
            key_generation: f.uint("key_generation")?,
            fkek_key_id: f.fixed("fkek_key_id")?,
            preamble_sha256: f.fixed("preamble_sha256")?,
            intent_hash: f.fixed("intent_hash")?,
            dek_slot_sha256: f.fixed("dek_slot_sha256")?,
            ciphertext_sha256: f.fixed("ciphertext_sha256")?,
            ciphertext_size: f.uint("ciphertext_size")?,
            previous_signed_head_hash: f.opt_fixed("previous_signed_head_hash")?,
            signer_signing_key_id: f.fixed("signer_signing_key_id")?,
            server_instance_id: f.fixed("server_instance_id")?,
            restore_epoch: f.uint("restore_epoch")?,
            manifest_replay_id: f.fixed("manifest_replay_id")?,
            created_at_ms: f.uint("created_at_ms")?,
        };
        f.finish()?;
        m.check()?;
        Ok(m)
    }

    /// The invariants the record alone decides (plan L517, L520, L521).
    fn check(&self) -> Result<()> {
        if self.base_version.checked_add(1) != Some(self.target_version) {
            return Err(bad("target_version"));
        }
        // Hard bound: the envelope v2 object cap (ADR 0003).
        if !(1..=MAX_OBJECT_SIZE).contains(&self.ciphertext_size) {
            return Err(bad("ciphertext_size"));
        }
        if (self.base_version == 0) != self.previous_signed_head_hash.is_none() {
            return Err(bad("previous_signed_head_hash"));
        }
        Ok(())
    }
}

// ------------------------------------------------ SignedSnapshotManifestV2 ---

/// The nine TBS fields (plan L429-L432 applied to the L530-L533 names).
fn tbs_fields(
    payload_bytes: &[u8],
    payload_sha256: &[u8; 32],
    signer_signing_key_id: &[u8; 32],
) -> Vec<(&'static str, Value)> {
    vec![
        ("container_domain", c::t(DOMAIN_SIGNED_MANIFEST_CONTAINER)),
        ("container_version", c::u(VERSION.into())),
        ("payload_domain", c::t(DOMAIN_MANIFEST_PAYLOAD)),
        ("payload_version", c::u(VERSION.into())),
        ("canonical_manifest_payload_bytes", c::b(payload_bytes)),
        ("manifest_payload_sha256", c::b(payload_sha256)),
        (
            "signature_suite_id",
            c::u(SIGNATURE_SUITE_ID_ED25519.into()),
        ),
        ("signature_version", c::u(SIGNATURE_VERSION.into())),
        ("signer_signing_key_id", c::b(signer_signing_key_id)),
    ]
}

/// An exact `SignedSnapshotManifestV2` container (plan L528-L539) whose bytes
/// and hashes were checked. The payload is reachable only through
/// [`SignedSnapshotManifestV2::verify_signature`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSnapshotManifestV2 {
    payload: SnapshotManifestV2,
    canonical_manifest_payload_bytes: Vec<u8>,
    manifest_payload_sha256: [u8; 32],
    signature_bytes: Vec<u8>,
    signed_container_hash: [u8; 32],
    exact_bytes: Vec<u8>,
    exact_bytes_sha256: [u8; 32],
    tbs_bytes: Vec<u8>,
}

/// A manifest whose signature verified under the signer key the caller supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSnapshotManifestV2 {
    container: SignedSnapshotManifestV2,
}

impl VerifiedSnapshotManifestV2 {
    pub fn container(&self) -> &SignedSnapshotManifestV2 {
        &self.container
    }

    pub fn payload(&self) -> &SnapshotManifestV2 {
        &self.container.payload
    }
}

impl SignedSnapshotManifestV2 {
    /// Signs `payload` with `sk`, which must be the key `signer_signing_key_id`
    /// names (plan L522). An invalid payload is refused by the closing parse.
    pub fn sign(sk: &SigningKey, payload: &SnapshotManifestV2) -> Result<Self> {
        if signing_key_id(sk.verifying_key().as_bytes()) != payload.signer_signing_key_id {
            return Err(bad("signer_signing_key_id"));
        }
        let bytes = payload.encode();
        let fields = tbs_fields(&bytes, &c::sha256(&bytes), &payload.signer_signing_key_id);
        Self::parse(&signing::build_signed_container(sk, fields).exact_bytes)
    }

    /// Parses exact container bytes. Accepts only signature suite 1 version 1
    /// (ADR 0002 D-8); a newer container or payload version is
    /// `SCHEMA_UNSUPPORTED`.
    pub fn parse(exact: &[u8]) -> Result<Self> {
        const MAP: &str = "SignedSnapshotManifestV2";
        if exact.len() > MAX_SIGNED_MANIFEST_CONTAINER_BYTES {
            return Err(RecordError::BadField {
                map: MAP,
                field: "exact_signed_manifest_container_bytes",
            }
            .into());
        }
        let mut f = Fields::decode(MAP, exact)?;
        f.exact_text("container_domain", DOMAIN_SIGNED_MANIFEST_CONTAINER)?;
        let container_version = f.u16("container_version")?;
        if container_version != VERSION {
            return Err(unsupported("container_version", container_version));
        }
        f.exact_text("payload_domain", DOMAIN_MANIFEST_PAYLOAD)?;
        let payload_version = f.u16("payload_version")?;
        if payload_version != VERSION {
            return Err(unsupported("payload_version", payload_version));
        }
        let payload_bytes = f.bytes(
            "canonical_manifest_payload_bytes",
            1,
            MAX_MANIFEST_PAYLOAD_BYTES,
        )?;
        let payload_sha256 = f.fixed::<32>("manifest_payload_sha256")?;
        let suite = f.u16("signature_suite_id")?;
        if suite != SIGNATURE_SUITE_ID_ED25519 {
            return Err(unsupported("signature_suite_id", suite));
        }
        let signature_version = f.u16("signature_version")?;
        if signature_version != SIGNATURE_VERSION {
            return Err(unsupported("signature_version", signature_version));
        }
        let signer = f.fixed::<32>("signer_signing_key_id")?;
        let signature_bytes = f.fixed::<ED25519_SIG_LEN>("signature_bytes")?.to_vec();
        let signed_container_hash = f.fixed::<32>("signed_container_hash")?;
        f.finish()?;

        if c::sha256(&payload_bytes) != payload_sha256 {
            return Err(RecordError::PayloadHashMismatch.into());
        }
        let mut core = tbs_fields(&payload_bytes, &payload_sha256, &signer);
        let tbs_bytes = c::encode(&c::m(core.clone()));
        core.push(("signature_bytes", c::b(&signature_bytes)));
        let core_bytes = c::encode(&c::m(core));
        if c::domain_hash(c::L_SIGNED_CONTAINER, &core_bytes) != signed_container_hash {
            return Err(RecordError::ContainerHashMismatch.into());
        }

        let payload = SnapshotManifestV2::parse(&payload_bytes)?;
        if payload.signer_signing_key_id != signer {
            return Err(bad("signer_signing_key_id"));
        }
        Ok(Self {
            payload,
            canonical_manifest_payload_bytes: payload_bytes,
            manifest_payload_sha256: payload_sha256,
            signature_bytes,
            signed_container_hash,
            exact_bytes: exact.to_vec(),
            exact_bytes_sha256: c::sha256(exact),
            tbs_bytes,
        })
    }

    fn check_signature(&self, signer_public_key: &[u8; 32]) -> Result<()> {
        if signing_key_id(signer_public_key) != self.payload.signer_signing_key_id {
            return Err(RecordError::IssuerKeyMismatch.into());
        }
        signing::verify_tbs(signer_public_key, &self.tbs_bytes, &self.signature_bytes)
            .map_err(|_| RecordError::Signature.into())
    }

    /// Checks the signature under the key the caller looked up by
    /// `signer_signing_key_id`. A key with another ID is refused before any
    /// curve arithmetic; the signature is checked under `verify_strict`.
    /// Whether that device may sign this manifest is the caller's check
    /// (ADR 0002 D-2; trust chain rule 6).
    pub fn verify_signature(
        self,
        signer_public_key: &[u8; 32],
    ) -> Result<VerifiedSnapshotManifestV2> {
        self.check_signature(signer_public_key)?;
        Ok(VerifiedSnapshotManifestV2 { container: self })
    }

    /// `SHA256("SHARDX-SNAPSHOT-HEAD-V2\0" + u32be(len) + exact container
    /// bytes)` (plan L535-L537).
    pub fn head_hash(&self) -> [u8; 32] {
        c::domain_hash(L_SNAPSHOT_HEAD, &self.exact_bytes)
    }

    pub fn signer_signing_key_id(&self) -> &[u8; 32] {
        &self.payload.signer_signing_key_id
    }

    pub fn canonical_manifest_payload_bytes(&self) -> &[u8] {
        &self.canonical_manifest_payload_bytes
    }

    pub fn manifest_payload_sha256(&self) -> &[u8; 32] {
        &self.manifest_payload_sha256
    }

    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature_bytes
    }

    /// Internal hash of the container core, without itself (plan L537-L539).
    pub fn signed_container_hash(&self) -> &[u8; 32] {
        &self.signed_container_hash
    }

    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    /// `exact_signed_manifest_container_bytes_sha256` (plan L534).
    pub fn exact_bytes_sha256(&self) -> &[u8; 32] {
        &self.exact_bytes_sha256
    }

    pub fn tbs_bytes(&self) -> &[u8] {
        &self.tbs_bytes
    }
}

// --------------------------------------------------------- CommitRequestV2 ---

/// An exact `CommitRequestV2` (plan L541-L563) whose hash, embedded manifest
/// container and every field copied from the manifest were checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRequestV2 {
    upload_id: [u8; 16],
    idempotency_key: [u8; 16],
    client_request_nonce: [u8; 16],
    manifest: SignedSnapshotManifestV2,
    canonical_request_hash: [u8; 32],
    exact_bytes: Vec<u8>,
    exact_bytes_sha256: [u8; 32],
}

/// A commit request whose embedded manifest signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCommitRequestV2 {
    request: CommitRequestV2,
}

impl VerifiedCommitRequestV2 {
    pub fn request(&self) -> &CommitRequestV2 {
        &self.request
    }

    pub fn manifest(&self) -> &SnapshotManifestV2 {
        &self.request.manifest.payload
    }
}

impl CommitRequestV2 {
    /// Builds the exact request around `manifest`, copying every field the
    /// request repeats from it (plan L1013, L2597).
    pub fn build(
        manifest: &SignedSnapshotManifestV2,
        upload_id: [u8; 16],
        idempotency_key: [u8; 16],
        client_request_nonce: [u8; 16],
    ) -> Self {
        let p = &manifest.payload;
        let mut fields = vec![
            ("domain", c::t(DOMAIN_COMMIT_REQUEST)),
            ("version", c::u(VERSION.into())),
            ("tenant_id", c::b(&p.tenant_id)),
            ("fleet_id", c::b(&p.fleet_id)),
            ("profile_id", c::b(&p.profile_id)),
            ("upload_id", c::b(&upload_id)),
            ("snapshot_id", c::b(&p.snapshot_id)),
            ("manifest_replay_id", c::b(&p.manifest_replay_id)),
            ("operation_scope", c::t(OPERATION_SCOPE_COMMIT)),
            ("idempotency_key", c::b(&idempotency_key)),
            ("lease_id", c::b(&p.lease_id)),
            ("fencing_token", c::u(p.fencing_token)),
            ("base_version", c::u(p.base_version)),
            ("intent_hash", c::b(&p.intent_hash)),
            ("ciphertext_sha256", c::b(&p.ciphertext_sha256)),
            ("ciphertext_size", c::u(p.ciphertext_size)),
            (
                "signed_manifest_container_bytes",
                c::b(&manifest.exact_bytes),
            ),
            (
                "signed_manifest_container_bytes_sha256",
                c::b(&manifest.exact_bytes_sha256),
            ),
            (
                "signed_manifest_container_hash",
                c::b(&manifest.signed_container_hash),
            ),
            ("server_instance_id", c::b(&p.server_instance_id)),
            ("restore_epoch", c::u(p.restore_epoch)),
            ("client_request_nonce", c::b(&client_request_nonce)),
        ];
        let core_bytes = c::encode(&c::m(fields.clone()));
        let canonical_request_hash = c::domain_hash(c::L_COMMIT_REQUEST, &core_bytes);
        fields.push(("canonical_request_hash", c::b(&canonical_request_hash)));
        let exact_bytes = c::encode(&c::m(fields));
        Self {
            upload_id,
            idempotency_key,
            client_request_nonce,
            manifest: manifest.clone(),
            canonical_request_hash,
            exact_bytes_sha256: c::sha256(&exact_bytes),
            exact_bytes,
        }
    }

    /// Parses exact request bytes (plan L558-L561): closed map, the embedded
    /// container parsed and matched to its full-bytes and internal hashes,
    /// every copied field equal to the manifest, then the request hash.
    pub fn parse(exact: &[u8]) -> Result<Self> {
        const MAP: &str = "CommitRequestV2";
        if exact.len() > MAX_COMMIT_REQUEST_BYTES {
            return Err(RecordError::BadField {
                map: MAP,
                field: "exact_commit_request_bytes",
            }
            .into());
        }
        let mut f = Fields::decode(MAP, exact)?;
        f.exact_text("domain", DOMAIN_COMMIT_REQUEST)?;
        let version = f.u16("version")?;
        if version != VERSION {
            return Err(unsupported("version", version));
        }
        let tenant_id = f.fixed::<16>("tenant_id")?;
        let fleet_id = f.fixed::<16>("fleet_id")?;
        let profile_id = f.fixed::<16>("profile_id")?;
        let upload_id = f.fixed::<16>("upload_id")?;
        let snapshot_id = f.fixed::<16>("snapshot_id")?;
        let manifest_replay_id = f.fixed::<16>("manifest_replay_id")?;
        f.exact_text("operation_scope", OPERATION_SCOPE_COMMIT)?;
        let idempotency_key = f.fixed::<16>("idempotency_key")?;
        let lease_id = f.fixed::<16>("lease_id")?;
        let fencing_token = f.uint("fencing_token")?;
        let base_version = f.uint("base_version")?;
        let intent_hash = f.fixed::<32>("intent_hash")?;
        let ciphertext_sha256 = f.fixed::<32>("ciphertext_sha256")?;
        let ciphertext_size = f.uint("ciphertext_size")?;
        let container = f.bytes(
            "signed_manifest_container_bytes",
            1,
            MAX_SIGNED_MANIFEST_CONTAINER_BYTES,
        )?;
        let container_sha256 = f.fixed::<32>("signed_manifest_container_bytes_sha256")?;
        let container_hash = f.fixed::<32>("signed_manifest_container_hash")?;
        let server_instance_id = f.fixed::<16>("server_instance_id")?;
        let restore_epoch = f.uint("restore_epoch")?;
        let client_request_nonce = f.fixed::<16>("client_request_nonce")?;
        let canonical_request_hash = f.fixed::<32>("canonical_request_hash")?;
        f.finish()?;

        let manifest = SignedSnapshotManifestV2::parse(&container)?;
        let p = &manifest.payload;
        let copied = [
            (
                "signed_manifest_container_bytes_sha256",
                container_sha256 == manifest.exact_bytes_sha256,
            ),
            (
                "signed_manifest_container_hash",
                container_hash == manifest.signed_container_hash,
            ),
            ("tenant_id", tenant_id == p.tenant_id),
            ("fleet_id", fleet_id == p.fleet_id),
            ("profile_id", profile_id == p.profile_id),
            ("snapshot_id", snapshot_id == p.snapshot_id),
            (
                "manifest_replay_id",
                manifest_replay_id == p.manifest_replay_id,
            ),
            ("lease_id", lease_id == p.lease_id),
            ("fencing_token", fencing_token == p.fencing_token),
            ("base_version", base_version == p.base_version),
            ("intent_hash", intent_hash == p.intent_hash),
            (
                "ciphertext_sha256",
                ciphertext_sha256 == p.ciphertext_sha256,
            ),
            ("ciphertext_size", ciphertext_size == p.ciphertext_size),
            (
                "server_instance_id",
                server_instance_id == p.server_instance_id,
            ),
            ("restore_epoch", restore_epoch == p.restore_epoch),
        ];
        if let Some((field, _)) = copied.iter().find(|(_, equal)| !equal) {
            return Err(SnapshotError::ManifestReplayMismatch(field));
        }
        // Every decoded field now equals what `build` writes, so its core is
        // this request's core and its exact bytes are `exact`.
        let rebuilt = Self::build(&manifest, upload_id, idempotency_key, client_request_nonce);
        if rebuilt.canonical_request_hash != canonical_request_hash {
            return Err(SnapshotError::ManifestReplayMismatch(
                "canonical_request_hash",
            ));
        }
        Ok(rebuilt)
    }

    /// Verifies the embedded manifest's signature (plan L559-L560); see
    /// [`SignedSnapshotManifestV2::verify_signature`].
    pub fn verify_signature(self, signer_public_key: &[u8; 32]) -> Result<VerifiedCommitRequestV2> {
        self.manifest.check_signature(signer_public_key)?;
        Ok(VerifiedCommitRequestV2 { request: self })
    }

    pub fn upload_id(&self) -> &[u8; 16] {
        &self.upload_id
    }

    pub fn idempotency_key(&self) -> &[u8; 16] {
        &self.idempotency_key
    }

    pub fn client_request_nonce(&self) -> &[u8; 16] {
        &self.client_request_nonce
    }

    /// The embedded container, not yet signature-checked.
    pub fn manifest(&self) -> &SignedSnapshotManifestV2 {
        &self.manifest
    }

    pub fn canonical_request_hash(&self) -> &[u8; 32] {
        &self.canonical_request_hash
    }

    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    /// `exact_commit_request_bytes_sha256` (plan L557-L558).
    pub fn exact_bytes_sha256(&self) -> &[u8; 32] {
        &self.exact_bytes_sha256
    }
}

// -------------------------------------------------- CommitReceiptBindingV2 ---

/// `lease_release_outcome` (plan L576).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseReleaseOutcome {
    Released,
    /// Only an idempotent replay of the same commit.
    AlreadyReleasedSameCommit,
}

impl LeaseReleaseOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Released => "released",
            Self::AlreadyReleasedSameCommit => "already_released_same_commit",
        }
    }
}

/// `CommitReceiptBindingV2` (plan L565-L587), besides `domain` and `version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitReceiptBindingV2 {
    pub exact_request_hash: [u8; 32],
    pub snapshot_id: [u8; 16],
    pub resulting_version: u64,
    pub resulting_head_hash: [u8; 32],
    pub lease_release_outcome: LeaseReleaseOutcome,
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub commit_timestamp_ms: u64,
    pub server_receipt_id: [u8; 16],
}

impl CommitReceiptBindingV2 {
    /// The receipt a commit of `request` produces: every binding comes from
    /// the verified request and its manifest; the rest is the server's.
    pub fn for_request(
        request: &VerifiedCommitRequestV2,
        lease_release_outcome: LeaseReleaseOutcome,
        commit_timestamp_ms: u64,
        server_receipt_id: [u8; 16],
    ) -> Self {
        let r = &request.request;
        let p = &r.manifest.payload;
        Self {
            exact_request_hash: r.canonical_request_hash,
            snapshot_id: p.snapshot_id,
            resulting_version: p.target_version,
            resulting_head_hash: r.manifest.head_hash(),
            lease_release_outcome,
            server_instance_id: p.server_instance_id,
            restore_epoch: p.restore_epoch,
            commit_timestamp_ms,
            server_receipt_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        c::encode(&c::m(vec![
            ("domain", c::t(DOMAIN_COMMIT_RECEIPT_BINDING)),
            ("version", c::u(VERSION.into())),
            ("exact_request_hash", c::b(&self.exact_request_hash)),
            ("snapshot_id", c::b(&self.snapshot_id)),
            ("resulting_version", c::u(self.resulting_version)),
            ("resulting_head_hash", c::b(&self.resulting_head_hash)),
            (
                "lease_release_outcome",
                c::t(self.lease_release_outcome.as_str()),
            ),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
            ("commit_timestamp_ms", c::u(self.commit_timestamp_ms)),
            ("server_receipt_id", c::b(&self.server_receipt_id)),
        ]))
    }

    /// Parses exact receipt bytes by the closed schema. Binding them to a
    /// request is [`CommitReceiptBindingV2::check_binds`].
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("CommitReceiptBindingV2", bytes)?;
        f.exact_text("domain", DOMAIN_COMMIT_RECEIPT_BINDING)?;
        let version = f.u16("version")?;
        if version != VERSION {
            return Err(unsupported("version", version));
        }
        let r = Self {
            exact_request_hash: f.fixed("exact_request_hash")?,
            snapshot_id: f.fixed("snapshot_id")?,
            resulting_version: f.uint("resulting_version")?,
            resulting_head_hash: f.fixed("resulting_head_hash")?,
            lease_release_outcome: match f.text("lease_release_outcome")?.as_str() {
                "released" => LeaseReleaseOutcome::Released,
                "already_released_same_commit" => LeaseReleaseOutcome::AlreadyReleasedSameCommit,
                _ => return Err(bad("lease_release_outcome")),
            },
            server_instance_id: f.fixed("server_instance_id")?,
            restore_epoch: f.uint("restore_epoch")?,
            commit_timestamp_ms: f.uint("commit_timestamp_ms")?,
            server_receipt_id: f.fixed("server_receipt_id")?,
        };
        f.finish()?;
        Ok(r)
    }

    /// Requires every binding field to match the stored exact request and its
    /// manifest (plan L572-L579, L584-L587); any difference is `RECEIPT_MISMATCH`.
    /// `request` must be the request the caller stored or verified itself,
    /// never one parsed from the same reply as the receipt.
    pub fn check_binds(&self, request: &CommitRequestV2) -> Result<()> {
        let p = &request.manifest.payload;
        let bindings = [
            (
                "exact_request_hash",
                self.exact_request_hash == request.canonical_request_hash,
            ),
            ("snapshot_id", self.snapshot_id == p.snapshot_id),
            (
                "resulting_version",
                self.resulting_version == p.target_version,
            ),
            (
                "resulting_head_hash",
                self.resulting_head_hash == request.manifest.head_hash(),
            ),
            (
                "server_instance_id",
                self.server_instance_id == p.server_instance_id,
            ),
            ("restore_epoch", self.restore_epoch == p.restore_epoch),
        ];
        match bindings.iter().find(|(_, equal)| !equal) {
            Some((field, _)) => Err(SnapshotError::ReceiptMismatch(field)),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{build_dek_slot, IntentIds, IntentNumbers, SlotIds};
    use crate::envelope_v2::{build_intent_v2, seal, MIN_FRAME_PLAINTEXT_SIZE};
    use crate::keys::WRAP_NONCE_LEN;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Deterministic test bytes, the same generator as the other G2 tests.
    fn fx<const N: usize>(label: &str) -> [u8; N] {
        use sha2::{Digest, Sha256};
        let mut out = [0u8; N];
        let (mut filled, mut counter) = (0, 0u32);
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

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&fx::<32>("manifest-signer"))
    }

    fn signer_pk() -> [u8; 32] {
        *signer().verifying_key().as_bytes()
    }

    fn payload(base_version: u64) -> SnapshotManifestV2 {
        SnapshotManifestV2 {
            snapshot_id: fx("snapshot"),
            tenant_id: fx("tenant-a"),
            fleet_id: fx("fleet-1"),
            profile_id: fx("profile"),
            lease_id: fx("lease"),
            target_version: base_version + 1,
            base_version,
            fencing_token: 9,
            key_generation: 3,
            fkek_key_id: fx("fkek-1"),
            preamble_sha256: fx("preamble"),
            intent_hash: fx("intent"),
            dek_slot_sha256: fx("dek-slot"),
            ciphertext_sha256: fx("ciphertext"),
            ciphertext_size: 4096,
            previous_signed_head_hash: (base_version > 0).then(|| fx("previous-head")),
            signer_signing_key_id: signing_key_id(&signer_pk()),
            server_instance_id: fx("server-1"),
            restore_epoch: 7,
            manifest_replay_id: fx("manifest-replay"),
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn signed(p: &SnapshotManifestV2) -> SignedSnapshotManifestV2 {
        SignedSnapshotManifestV2::sign(&signer(), p).unwrap()
    }

    fn request(m: &SignedSnapshotManifestV2) -> CommitRequestV2 {
        CommitRequestV2::build(m, fx("upload"), fx("idempotency"), fx("nonce"))
    }

    fn receipt(r: &CommitRequestV2) -> CommitReceiptBindingV2 {
        let verified = r.clone().verify_signature(&signer_pk()).unwrap();
        CommitReceiptBindingV2::for_request(
            &verified,
            LeaseReleaseOutcome::Released,
            1_700_000_100_000,
            fx("receipt"),
        )
    }

    fn edit_map(bytes: &[u8], edit: impl FnOnce(&mut Vec<(String, Value)>)) -> Vec<u8> {
        let Value::Map(mut entries) = c::decode(bytes).unwrap() else {
            panic!("not a map")
        };
        edit(&mut entries);
        c::encode(&Value::Map(entries))
    }

    fn set(entries: &mut Vec<(String, Value)>, key: &str, v: Value) {
        entries.retain(|(k, _)| k != key);
        entries.push((key.to_string(), v));
    }

    /// The map with its `"version": 2` entry written twice; the encoder
    /// cannot produce this, so the bytes are spliced by hand.
    fn with_duplicate_version(bytes: &[u8]) -> Vec<u8> {
        let Value::Map(entries) = c::decode(bytes).unwrap() else {
            panic!("not a map")
        };
        let n = entries.len();
        assert!((23..255).contains(&n), "one-byte count after the splice");
        let entry = [c::encode(&c::t("version")), c::encode(&c::u(2))].concat();
        let at = bytes.windows(entry.len()).position(|w| w == entry).unwrap();
        let body = &bytes[if n < 24 { 1 } else { 2 }..];
        let at = at - (bytes.len() - body.len());
        [&[0xb8, n as u8 + 1][..], &body[..at], &entry, &body[at..]].concat()
    }

    fn code_of<T: std::fmt::Debug>(r: Result<T>) -> &'static str {
        r.expect_err("expected a rejection").code()
    }

    /// A correctly signed and hashed container around arbitrary payload bytes,
    /// so payload-level defects reach the payload parser.
    fn container_around(payload_bytes: &[u8], signer_id: &[u8; 32]) -> Vec<u8> {
        let fields = tbs_fields(payload_bytes, &c::sha256(payload_bytes), signer_id);
        signing::build_signed_container(&signer(), fields).exact_bytes
    }

    /// Re-encodes the request with `edit` applied, then recomputes
    /// `canonical_request_hash` over the edited core.
    fn rehashed(exact: &[u8], edit: impl FnOnce(&mut Vec<(String, Value)>)) -> Vec<u8> {
        let core = edit_map(exact, |e| {
            e.retain(|(k, _)| k != "canonical_request_hash");
            edit(e);
        });
        let h = c::domain_hash(c::L_COMMIT_REQUEST, &core);
        edit_map(&core, |e| set(e, "canonical_request_hash", c::b(&h)))
    }

    #[test]
    fn golden_vectors() {
        // Per base version: payload SHA-256, signed_container_hash, container
        // bytes SHA-256, head_hash, canonical_request_hash, request bytes
        // SHA-256; then the receipt bytes SHA-256 for base 4.
        let pinned = [
            "0cca9d8ae28562954aaf442d4a686af10728051f8ef3884cde47dfdd14e2b2ef",
            "13f2499fb62337ddaee154105ddaf72be72f59dcb9bc0155d4278fb5cb698354",
            "46664f3fb39e7c62950a8b052a2f31b469d8f192dbc0281525008ae8bdd1fad3",
            "a421285491c928413d00b2d486f14c2d4e5b86d07c425401b79d99873a76abf1",
            "40c6010a9a3d843b18d191a7424665c8def76f0d8cdae235550c4d813173f8c7",
            "5c1f9b388e908e815d7a1c6d3a42412d4f87f41aeff260038a5094d54d8068cb",
            "d6eb8e774096acca9554be0ada38677550adddc4113816cb8c36bda3fe917850",
            "c977b09d2ddb6953d0a11780dcc2852590226367187db622245593f1882d4170",
            "639c55b6104cbeb4918a2e8d29da53f1a34bfd4a82631f85cbcfa9f45bebe4f4",
            "36753cb14ee69c3c0585b0e901c254303561a96ad656c7390fc2a17764081403",
            "979b9c8b40c39cf54ae161d412587cf250f1af2309dab44ad4f5d71da3fac2bd",
            "0df7d0161b0487a91a0e34a94e22ba251ff345c9a84c8586f6b99c8d4899be0c",
            "a6fadd3dce5e28ec4180d701c5c48aae3e2e712dc47b35f2b3632dcb6e6450cb",
        ];
        let mut actual = Vec::new();
        for base in [0, 4] {
            let p = payload(base);
            let m = signed(&p);
            let r = request(&m);
            actual.extend([
                hex(&c::sha256(&p.encode())),
                hex(m.signed_container_hash()),
                hex(m.exact_bytes_sha256()),
                hex(&m.head_hash()),
                hex(r.canonical_request_hash()),
                hex(r.exact_bytes_sha256()),
            ]);
        }
        let rc = receipt(&request(&signed(&payload(4))));
        actual.push(hex(&c::sha256(&rc.encode())));
        assert_eq!(actual, pinned);
    }

    #[test]
    fn every_record_roundtrips_exactly() {
        for base in [0, 4] {
            let p = payload(base);
            assert_eq!(SnapshotManifestV2::parse(&p.encode()).unwrap(), p);
            let m = signed(&p);
            assert_eq!(m.canonical_manifest_payload_bytes(), p.encode());
            assert_eq!(m.manifest_payload_sha256(), &c::sha256(&p.encode()));
            assert_eq!(m.signer_signing_key_id(), &p.signer_signing_key_id);
            assert_eq!(m.signature_bytes().len(), ED25519_SIG_LEN);
            assert_eq!(SignedSnapshotManifestV2::parse(m.exact_bytes()).unwrap(), m);
            let v = m.clone().verify_signature(&signer_pk()).unwrap();
            assert_eq!(v.payload(), &p);
            assert_eq!(v.container(), &m);

            let r = request(&m);
            assert_eq!(CommitRequestV2::parse(r.exact_bytes()).unwrap(), r);
            assert_eq!(
                (r.upload_id(), r.idempotency_key(), r.client_request_nonce()),
                (&fx("upload"), &fx("idempotency"), &fx("nonce"))
            );
            assert_eq!(r.manifest(), &m);
            assert_eq!(r.exact_bytes_sha256(), &c::sha256(r.exact_bytes()));
            let vr = r.clone().verify_signature(&signer_pk()).unwrap();
            assert_eq!((vr.request(), vr.manifest()), (&r, &p));

            for outcome in [
                LeaseReleaseOutcome::Released,
                LeaseReleaseOutcome::AlreadyReleasedSameCommit,
            ] {
                let rc = CommitReceiptBindingV2 {
                    lease_release_outcome: outcome,
                    ..receipt(&r)
                };
                assert_eq!(CommitReceiptBindingV2::parse(&rc.encode()).unwrap(), rc);
                rc.check_binds(&r).unwrap();
            }
        }
    }

    #[test]
    fn hashes_follow_their_labels() {
        let m = signed(&payload(4));
        let mut pre = L_SNAPSHOT_HEAD.as_bytes().to_vec();
        pre.extend((m.exact_bytes().len() as u32).to_be_bytes());
        pre.extend(m.exact_bytes());
        assert_eq!(m.head_hash(), c::sha256(&pre));
        // The head hash is neither the internal nor the full-bytes hash.
        assert_ne!(&m.head_hash(), m.signed_container_hash());
        assert_ne!(&m.head_hash(), m.exact_bytes_sha256());

        let r = request(&m);
        let core = edit_map(r.exact_bytes(), |e| {
            e.retain(|(k, _)| k != "canonical_request_hash")
        });
        assert_eq!(
            r.canonical_request_hash(),
            &c::domain_hash(c::L_COMMIT_REQUEST, &core)
        );
        // A signature over the TBS bytes without the signed-record label fails.
        let raw = ed25519_dalek::Signer::sign(&signer(), m.tbs_bytes()).to_bytes();
        let core = edit_map(m.exact_bytes(), |e| {
            set(e, "signature_bytes", c::b(&raw));
            e.retain(|(k, _)| k != "signed_container_hash");
        });
        let h = c::domain_hash(c::L_SIGNED_CONTAINER, &core);
        let relabelled = edit_map(&core, |e| set(e, "signed_container_hash", c::b(&h)));
        let parsed = SignedSnapshotManifestV2::parse(&relabelled).unwrap();
        assert_eq!(
            code_of(parsed.verify_signature(&signer_pk())),
            "SIGNATURE_INVALID"
        );
    }

    #[test]
    fn payload_rejects_every_field_level_defect() {
        let good = payload(4).encode();
        let with = |key: &str, v: Value| edit_map(&good, |e| set(e, key, v));
        let without = |key: &str| edit_map(&good, |e| e.retain(|(k, _)| k != key));
        let parse = |b: &[u8]| SnapshotManifestV2::parse(b);
        let bad_value = |f| Err(SnapshotError::Record(RecordError::BadValue(f)));

        assert!(matches!(
            parse(&with("extra", c::u(1))),
            Err(SnapshotError::Record(RecordError::UnknownField { .. }))
        ));
        for field in [
            "snapshot_id",
            "intent_hash",
            "ciphertext_size",
            "created_at_ms",
        ] {
            assert_eq!(
                parse(&without(field)),
                Err(SnapshotError::Record(RecordError::MissingField {
                    map: "SnapshotManifestV2",
                    field
                }))
            );
        }
        // Duplicate key and non-canonical forms never reach the schema.
        assert_eq!(
            parse(&with_duplicate_version(&good)),
            Err(SnapshotError::Record(RecordError::Cbor(
                crate::canonical::CborError::DuplicateKey("version".into())
            )))
        );
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(code_of(parse(&trailing)), "NON_CANONICAL_RECORD");
        assert_eq!(
            code_of(parse(&with("fencing_token", c::u(i64::MAX as u64 + 1)))),
            "WIRE_INTEGER_OUT_OF_RANGE"
        );
        assert!(matches!(
            parse(&with("lease_id", c::b(&[0; 15]))),
            Err(SnapshotError::Record(RecordError::BadField {
                field: "lease_id",
                ..
            }))
        ));
        assert!(matches!(
            parse(&with("base_version", c::t("4"))),
            Err(SnapshotError::Record(RecordError::BadField {
                field: "base_version",
                ..
            }))
        ));
        assert_eq!(
            parse(&with("domain", c::t(DOMAIN_COMMIT_REQUEST))),
            bad_value("domain")
        );
        assert_eq!(
            code_of(parse(&with("version", c::u(3)))),
            "SCHEMA_UNSUPPORTED"
        );
        // target_version = base_version + 1, nothing else.
        for target in [4, 6] {
            assert_eq!(
                parse(&with("target_version", c::u(target))),
                bad_value("target_version")
            );
        }
        // Genesis omits the previous head; every later manifest carries it.
        let genesis = payload(0).encode();
        assert_eq!(
            parse(&edit_map(&genesis, |e| set(
                e,
                "previous_signed_head_hash",
                c::b(&[1; 32])
            ))),
            bad_value("previous_signed_head_hash")
        );
        assert_eq!(
            parse(&without("previous_signed_head_hash")),
            bad_value("previous_signed_head_hash")
        );
        // ciphertext_size in 1..=MAX_OBJECT_SIZE.
        for size in [0, MAX_OBJECT_SIZE + 1] {
            assert_eq!(
                parse(&with("ciphertext_size", c::u(size))),
                bad_value("ciphertext_size")
            );
        }
        for size in [1, MAX_OBJECT_SIZE] {
            parse(&with("ciphertext_size", c::u(size))).unwrap();
        }
        // The largest base still has no successor inside the wire domain.
        let top = c::MAX_SQLITE_WIRE_UINT;
        assert_eq!(
            parse(&with("base_version", c::u(top))),
            bad_value("target_version")
        );
    }

    #[test]
    fn container_rejects_every_field_level_defect() {
        let good = signed(&payload(4)).exact_bytes().to_vec();
        let with = |key: &str, v: Value| edit_map(&good, |e| set(e, key, v));
        let without = |key: &str| edit_map(&good, |e| e.retain(|(k, _)| k != key));
        let parse = |b: &[u8]| SignedSnapshotManifestV2::parse(b);

        assert!(matches!(
            parse(&with("extra", c::u(1))),
            Err(SnapshotError::Record(RecordError::UnknownField { .. }))
        ));
        assert!(matches!(
            parse(&without("manifest_payload_sha256")),
            Err(SnapshotError::Record(RecordError::MissingField { .. }))
        ));
        // Another role's container or payload domain is not a manifest.
        for (field, v) in [
            ("container_domain", crate::authz_record::CONTAINER_DOMAIN),
            (
                "payload_domain",
                crate::authz_record::DOMAIN_DEVICE_APPROVAL,
            ),
        ] {
            assert_eq!(
                parse(&with(field, c::t(v))),
                Err(SnapshotError::Record(RecordError::BadValue(field)))
            );
        }
        for (field, v) in [
            ("container_version", 3),
            ("payload_version", 3),
            ("signature_suite_id", 2),
            ("signature_version", 2),
        ] {
            assert_eq!(
                parse(&with(field, c::u(v))),
                Err(SnapshotError::Record(RecordError::Unsupported {
                    field,
                    id: v
                }))
            );
            assert_eq!(code_of(parse(&with(field, c::u(v)))), "SCHEMA_UNSUPPORTED");
        }
        for len in [63, 65] {
            assert!(matches!(
                parse(&with("signature_bytes", c::b(&vec![0; len]))),
                Err(SnapshotError::Record(RecordError::BadField {
                    field: "signature_bytes",
                    ..
                }))
            ));
        }
        assert!(matches!(
            parse(&with(
                "canonical_manifest_payload_bytes",
                c::b(&vec![0; MAX_MANIFEST_PAYLOAD_BYTES + 1])
            )),
            Err(SnapshotError::Record(RecordError::BadField {
                field: "canonical_manifest_payload_bytes",
                ..
            }))
        ));
        let oversized = with("extra", c::b(&vec![0; MAX_SIGNED_MANIFEST_CONTAINER_BYTES]));
        assert!(matches!(
            parse(&oversized),
            Err(SnapshotError::Record(RecordError::BadField {
                field: "exact_signed_manifest_container_bytes",
                ..
            }))
        ));
        assert_eq!(
            code_of(parse(&with("manifest_payload_sha256", c::b(&[0; 32])))),
            "SIGNED_BYTES_MISMATCH"
        );
        assert_eq!(
            code_of(parse(&with("signed_container_hash", c::b(&[0; 32])))),
            "SIGNED_CONTAINER_HASH_MISMATCH"
        );
        // A defective payload inside a well-formed container is refused too.
        let mut genesis_with_head = payload(0);
        genesis_with_head.previous_signed_head_hash = Some([1; 32]);
        let id = signing_key_id(&signer_pk());
        assert_eq!(
            parse(&container_around(&genesis_with_head.encode(), &id)),
            Err(bad("previous_signed_head_hash"))
        );
        // The payload signer must be the container signer.
        assert_eq!(
            parse(&container_around(&payload(4).encode(), &[0x55; 32])),
            Err(bad("signer_signing_key_id"))
        );
        // A manifest container is not an authorization record, either way.
        assert!(crate::authz_record::AuthorizationRecord::parse(&good).is_err());
        let approval = crate::authz_record::build_record(
            &signer(),
            crate::authz_record::DOMAIN_DEVICE_APPROVAL,
            &payload(4).encode(),
        );
        assert_eq!(
            parse(&approval),
            Err(SnapshotError::Record(RecordError::BadValue(
                "container_domain"
            )))
        );
    }

    #[test]
    fn signing_binds_the_signer_key() {
        let m = signed(&payload(4));
        let other = SigningKey::from_bytes(&fx::<32>("other-signer"));
        assert_eq!(
            code_of(m.clone().verify_signature(other.verifying_key().as_bytes())),
            "KEY_SUBSTITUTION_DETECTED"
        );
        // A flipped signature bit, with the container hash recomputed.
        let mut sig = m.signature_bytes().to_vec();
        sig[0] ^= 1;
        let core = edit_map(m.exact_bytes(), |e| {
            set(e, "signature_bytes", c::b(&sig));
            e.retain(|(k, _)| k != "signed_container_hash");
        });
        let h = c::domain_hash(c::L_SIGNED_CONTAINER, &core);
        let forged = edit_map(&core, |e| set(e, "signed_container_hash", c::b(&h)));
        let parsed = SignedSnapshotManifestV2::parse(&forged).unwrap();
        assert_eq!(
            code_of(parsed.verify_signature(&signer_pk())),
            "SIGNATURE_INVALID"
        );
        // sign() refuses a key the payload does not name, and invalid payloads.
        assert_eq!(
            SignedSnapshotManifestV2::sign(&other, &payload(4)),
            Err(bad("signer_signing_key_id"))
        );
        let mut p = payload(4);
        p.target_version = 6;
        assert_eq!(
            SignedSnapshotManifestV2::sign(&signer(), &p),
            Err(bad("target_version"))
        );
    }

    #[test]
    fn request_rejects_every_field_level_defect() {
        let m = signed(&payload(4));
        let good = request(&m).exact_bytes().to_vec();
        let parse = |b: &[u8]| CommitRequestV2::parse(b);
        let with = |key: &str, v: Value| rehashed(&good, |e| set(e, key, v));

        assert!(matches!(
            parse(&with("extra", c::u(1))),
            Err(SnapshotError::Record(RecordError::UnknownField { .. }))
        ));
        assert!(matches!(
            parse(&rehashed(&good, |e| e.retain(|(k, _)| k != "upload_id"))),
            Err(SnapshotError::Record(RecordError::MissingField {
                field: "upload_id",
                ..
            }))
        ));
        assert_eq!(
            parse(&with("domain", c::t(DOMAIN_COMMIT_RECEIPT_BINDING))),
            Err(bad("domain"))
        );
        assert_eq!(
            parse(&with("operation_scope", c::t("profile.finalize-upload.v2"))),
            Err(bad("operation_scope"))
        );
        assert_eq!(
            code_of(parse(&with("version", c::u(3)))),
            "SCHEMA_UNSUPPORTED"
        );
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(code_of(parse(&trailing)), "NON_CANONICAL_RECORD");
        for len in [0, MAX_SIGNED_MANIFEST_CONTAINER_BYTES + 1] {
            assert!(matches!(
                parse(&with(
                    "signed_manifest_container_bytes",
                    c::b(&vec![0; len])
                )),
                Err(SnapshotError::Record(RecordError::BadField {
                    field: "signed_manifest_container_bytes",
                    ..
                }))
            ));
        }
        let oversized = edit_map(&good, |e| {
            set(e, "extra", c::b(&vec![0; MAX_COMMIT_REQUEST_BYTES]))
        });
        assert!(matches!(
            parse(&oversized),
            Err(SnapshotError::Record(RecordError::BadField {
                field: "exact_commit_request_bytes",
                ..
            }))
        ));
        // An embedded container that is not a valid manifest.
        let broken = edit_map(m.exact_bytes(), |e| {
            set(e, "signed_container_hash", c::b(&[0; 32]))
        });
        assert_eq!(
            code_of(parse(&with(
                "signed_manifest_container_bytes",
                c::b(&broken)
            ))),
            "SIGNED_CONTAINER_HASH_MISMATCH"
        );
    }

    #[test]
    fn request_binds_the_manifest_and_its_own_hash() {
        let m = signed(&payload(4));
        let good = request(&m).exact_bytes().to_vec();
        let parse = |b: &[u8]| CommitRequestV2::parse(b);
        let mismatch = |f| Err(SnapshotError::ManifestReplayMismatch(f));

        // Every field the request repeats from the manifest, changed with the
        // request hash recomputed, is refused by name.
        for (field, v) in [
            ("signed_manifest_container_bytes_sha256", c::b(&[0xaa; 32])),
            ("signed_manifest_container_hash", c::b(&[0xaa; 32])),
            ("tenant_id", c::b(&[0xaa; 16])),
            ("fleet_id", c::b(&[0xaa; 16])),
            ("profile_id", c::b(&[0xaa; 16])),
            ("snapshot_id", c::b(&[0xaa; 16])),
            ("manifest_replay_id", c::b(&[0xaa; 16])),
            ("lease_id", c::b(&[0xaa; 16])),
            ("fencing_token", c::u(10)),
            ("base_version", c::u(5)),
            ("intent_hash", c::b(&[0xaa; 32])),
            ("ciphertext_sha256", c::b(&[0xaa; 32])),
            ("ciphertext_size", c::u(4097)),
            ("server_instance_id", c::b(&[0xaa; 16])),
            ("restore_epoch", c::u(8)),
        ] {
            let tampered = rehashed(&good, |e| set(e, field, v));
            assert_eq!(parse(&tampered), mismatch(field), "{field}");
            assert_eq!(code_of(parse(&tampered)), "MANIFEST_REPLAY_MISMATCH");
        }
        // A different, valid manifest swapped in with its own hashes.
        let other = signed(&SnapshotManifestV2 {
            ciphertext_sha256: [0xbb; 32],
            ..payload(4)
        });
        let swapped = rehashed(&good, |e| {
            set(
                e,
                "signed_manifest_container_bytes",
                c::b(other.exact_bytes()),
            );
            set(
                e,
                "signed_manifest_container_bytes_sha256",
                c::b(other.exact_bytes_sha256()),
            );
            set(
                e,
                "signed_manifest_container_hash",
                c::b(other.signed_container_hash()),
            );
        });
        assert_eq!(parse(&swapped), mismatch("ciphertext_sha256"));
        // Request-only fields are bound by the request hash alone.
        for (field, v) in [
            ("upload_id", c::b(&[0xaa; 16])),
            ("idempotency_key", c::b(&[0xaa; 16])),
            ("client_request_nonce", c::b(&[0xaa; 16])),
            ("canonical_request_hash", c::b(&[0xaa; 32])),
        ] {
            let tampered = edit_map(&good, |e| set(e, field, v));
            assert_eq!(
                parse(&tampered),
                mismatch("canonical_request_hash"),
                "{field}"
            );
        }
        // The embedded manifest's signature is checked under the signer key.
        let other_key = SigningKey::from_bytes(&fx::<32>("other-signer"));
        assert_eq!(
            code_of(
                parse(&good)
                    .unwrap()
                    .verify_signature(other_key.verifying_key().as_bytes())
            ),
            "KEY_SUBSTITUTION_DETECTED"
        );
    }

    #[test]
    fn receipt_binds_exactly_the_request_manifest_and_head() {
        let r = request(&signed(&payload(4)));
        let good = receipt(&r);
        good.check_binds(&r).unwrap();
        assert_eq!(good.exact_request_hash, *r.canonical_request_hash());
        assert_eq!(good.resulting_head_hash, r.manifest().head_hash());
        assert_eq!(good.resulting_version, 5);

        let mismatch = |f| Err(SnapshotError::ReceiptMismatch(f));
        let cases: [(&str, CommitReceiptBindingV2); 6] = [
            (
                "exact_request_hash",
                CommitReceiptBindingV2 {
                    exact_request_hash: *r.exact_bytes_sha256(),
                    ..good.clone()
                },
            ),
            (
                "snapshot_id",
                CommitReceiptBindingV2 {
                    snapshot_id: [0xaa; 16],
                    ..good.clone()
                },
            ),
            (
                "resulting_version",
                CommitReceiptBindingV2 {
                    resulting_version: 4,
                    ..good.clone()
                },
            ),
            (
                // The internal container hash is not the head hash.
                "resulting_head_hash",
                CommitReceiptBindingV2 {
                    resulting_head_hash: *r.manifest().signed_container_hash(),
                    ..good.clone()
                },
            ),
            (
                "server_instance_id",
                CommitReceiptBindingV2 {
                    server_instance_id: [0xaa; 16],
                    ..good.clone()
                },
            ),
            (
                "restore_epoch",
                CommitReceiptBindingV2 {
                    restore_epoch: 8,
                    ..good.clone()
                },
            ),
        ];
        for (field, tampered) in cases {
            assert_eq!(tampered.check_binds(&r), mismatch(field), "{field}");
            assert_eq!(code_of(tampered.check_binds(&r)), "RECEIPT_MISMATCH");
        }
        // The same receipt does not bind a request that differs only in nonce.
        let other = CommitRequestV2::build(r.manifest(), fx("upload"), fx("idempotency"), [0; 16]);
        assert_eq!(good.check_binds(&other), mismatch("exact_request_hash"));
        // Server-only fields carry no binding.
        CommitReceiptBindingV2 {
            commit_timestamp_ms: 1,
            server_receipt_id: [0; 16],
            ..good.clone()
        }
        .check_binds(&r)
        .unwrap();
    }

    #[test]
    fn receipt_rejects_every_field_level_defect() {
        let good = receipt(&request(&signed(&payload(4)))).encode();
        let with = |key: &str, v: Value| edit_map(&good, |e| set(e, key, v));
        let parse = |b: &[u8]| CommitReceiptBindingV2::parse(b);

        assert!(matches!(
            parse(&with("extra", c::u(1))),
            Err(SnapshotError::Record(RecordError::UnknownField { .. }))
        ));
        assert!(matches!(
            parse(&edit_map(&good, |e| e.retain(|(k, _)| k != "server_receipt_id"))),
            Err(SnapshotError::Record(RecordError::MissingField { .. }))
        ));
        assert_eq!(
            parse(&with("domain", c::t(DOMAIN_COMMIT_REQUEST))),
            Err(bad("domain"))
        );
        assert_eq!(
            code_of(parse(&with("version", c::u(3)))),
            "SCHEMA_UNSUPPORTED"
        );
        for outcome in ["release", "Released", ""] {
            assert_eq!(
                parse(&with("lease_release_outcome", c::t(outcome))),
                Err(bad("lease_release_outcome"))
            );
        }
        assert_eq!(
            code_of(parse(&with("restore_epoch", c::u(i64::MAX as u64 + 1)))),
            "WIRE_INTEGER_OUT_OF_RANGE"
        );
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(code_of(parse(&trailing)), "NON_CANONICAL_RECORD");
    }

    /// The manifest commits to the hashes the real envelope v2 code produces.
    #[test]
    fn manifest_binds_a_sealed_envelope_v2_object() {
        let (tenant, fleet, profile, snapshot) =
            (fx("tenant-a"), fx("fleet-1"), fx("profile"), fx("snapshot"));
        let fkek_key_id: [u8; 32] = fx("fkek-1");
        let slot = build_dek_slot(
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; WRAP_NONCE_LEN],
            &SlotIds {
                tenant_id: &tenant,
                fleet_id: &fleet,
                profile_id: &profile,
                snapshot_id: &snapshot,
                fkek_key_id: &fkek_key_id,
                envelope_context_nonce: &fx("context-nonce"),
            },
            3,
        )
        .unwrap();
        let p0 = payload(4);
        let intent = build_intent_v2(
            &IntentIds {
                snapshot_id: snapshot,
                tenant_id: tenant,
                fleet_id: fleet,
                profile_id: profile,
                lease_id: p0.lease_id,
                manifest_replay_id: p0.manifest_replay_id,
                server_instance_id: p0.server_instance_id,
                fkek_key_id,
                intended_signer_signing_key_id: p0.signer_signing_key_id,
            },
            &IntentNumbers {
                target_version: 5,
                base_version: 4,
                fencing_token: p0.fencing_token,
                key_generation: 3,
                restore_epoch: p0.restore_epoch,
                frame_plaintext_size: MIN_FRAME_PLAINTEXT_SIZE,
                max_plaintext_size: MAX_OBJECT_SIZE,
                max_ciphertext_size: MAX_OBJECT_SIZE,
                created_at_ms: p0.created_at_ms,
            },
            &[0x44; crate::envelope_v2::STREAM_NONCE_PREFIX_LEN],
            p0.previous_signed_head_hash.as_ref(),
            &slot,
        )
        .unwrap();
        let mut object = Vec::new();
        let digest = seal(
            &mut std::io::Cursor::new(vec![7u8; 1000]),
            &mut object,
            &[0x22; 32],
            &intent,
            &slot,
        )
        .unwrap();
        let p = SnapshotManifestV2 {
            preamble_sha256: digest.preamble_sha256,
            intent_hash: intent.intent_hash,
            dek_slot_sha256: slot.dek_slot_sha256,
            ciphertext_sha256: digest.ciphertext_sha256,
            ciphertext_size: digest.ciphertext_size,
            ..p0
        };
        assert_eq!(digest.ciphertext_size, object.len() as u64);
        let preamble: [u8; crate::envelope_v2::PREAMBLE_LEN] = object
            [..crate::envelope_v2::PREAMBLE_LEN]
            .try_into()
            .unwrap();
        assert_eq!(
            p.preamble_sha256,
            crate::envelope_v2::preamble_sha256(&preamble)
        );
        let r = request(&signed(&p));
        let v = CommitRequestV2::parse(r.exact_bytes())
            .unwrap()
            .verify_signature(&signer_pk())
            .unwrap();
        assert_eq!(v.manifest(), &p);
    }
}
