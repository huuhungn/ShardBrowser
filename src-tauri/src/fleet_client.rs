//! HTTP client for the v2 team/fleet control plane.
//!
//! The server stores and moves ciphertext: every byte it sees is sealed by
//! `shardx_core::backup` before it leaves this process. What this module adds
//! is the transfer choreography (lease, staged upload, signed commit, ranged
//! download) so a sealed profile snapshot can reach a teammate.
//!
//! Two rules shape the code:
//!
//! * **Sign against live server facts.** A manifest commits to the server
//!   instance and restore epoch, fetched per sync from `/v2/server-identity`
//!   and never cached across runs: after a server restore the epoch moves, and
//!   a stale value produces records the server rightly refuses.
//! * **Publish only what verified.** Commit runs after every chunk is
//!   accepted, and a downloaded container is opened before it is promoted.

// Not yet reachable from the UI: wiring this to the Launcher needs device
// enrollment (the server has no endpoint to register a signing key) and a
// place to store the server URL and token. Tracked in issue #17. The
// allowance is scoped to this module so unused code elsewhere still fails
// the build, and the end-to-end test in server/tests/v2_e2e.rs exercises
// the wire format this module produces.
#![allow(dead_code)]

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use shardx_core::canonical as c;
use shardx_core::fleet_manifest::{build_snapshot_manifest, ManifestFields};
use shardx_core::signing::Ed25519SigningKey;

/// Upload chunk size. The server caps a ranged read at 8 MiB; staying below it
/// keeps one chunk to one request and bounds peak memory per call.
const CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// How long a signed manifest stays valid. Short: it authorizes one publish
/// that is about to happen, not a window for later replay.
const MANIFEST_VALIDITY_MS: u64 = 5 * 60 * 1000;

/// Server-side facts a signed record must bind to.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerIdentity {
    pub server_instance_id: String,
    pub restore_epoch: i64,
}

/// A write claim on one profile, plus the fencing token ordering writers.
#[derive(Debug, Clone, Deserialize)]
pub struct Lease {
    pub lease_id: String,
    pub fencing_token: i64,
}

/// What the server currently publishes for a profile.
#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotHead {
    pub version: i64,
    pub container_size: i64,
    pub container_sha256: String,
}

/// Everything the caller must supply to publish a sealed container.
pub struct UploadRequest<'a> {
    pub tenant_id: &'a str,
    pub profile_id: &'a str,
    pub fleet_id: &'a str,
    pub snapshot_id: &'a str,
    pub account_id: &'a str,
    pub device_id: &'a str,
    /// Version this snapshot derives from. The server refuses a commit that
    /// does not extend the current version, which is what stops a stale
    /// client silently clobbering a newer upload.
    pub base_version: i64,
    pub key_generation: i64,
    /// The sealed container. Opaque to the server.
    pub container: &'a [u8],
}

/// Server response to an enrollment challenge request.
#[derive(Deserialize)]
struct EnrollmentChallenge {
    challenge_id: String,
    nonce: String,
    account_id: String,
}

/// Ids the server assigned to a freshly enrolled device.
#[derive(Deserialize, Debug)]
pub struct EnrolledDevice {
    pub device_id: String,
    pub signing_key_id: String,
    /// Account the server bound this device to. Fleet routes require it, and
    /// the challenge is the only place it is disclosed.
    #[serde(default)]
    pub account_id: String,
}

pub struct FleetClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl FleetClient {
    pub fn new(base_url: &str, token: &str) -> Result<Self> {
        let base = base_url.trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            bail!(crate::errcode::code("fleet.serverUrlScheme"));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .context(crate::errcode::code("fleet.netClientFailed"))?;
        Ok(Self {
            http,
            base_url: base,
            token: token.to_string(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Turn a non-2xx response into an error that keeps the server reason.
    /// The body carries refusal text (version conflicts, expired leases), no
    /// key material.
    async fn ok_or_err(res: reqwest::Response, key: &str) -> Result<reqwest::Response> {
        let status = res.status();
        if status.is_success() {
            return Ok(res);
        }
        let body = res.text().await.unwrap_or_default();
        let detail = body.chars().take(300).collect::<String>();
        // `key` is the locale key for this exact refusal, so a translator sees
        // a whole sentence rather than a verb spliced into one. `detail` is
        // the server's own words, passed through as sent.
        Err(anyhow!(crate::errcode::code_with(
            key,
            &[("status", &status.as_u16().to_string()), ("detail", &detail)],
        )))
    }

    /// Register this device's signing key with the server.
    ///
    /// Two round trips: the server issues a nonce committed to the key pair,
    /// and the device signs it. The private key never leaves this process —
    /// what proves possession is the signature, not the key.
    ///
    /// Returns the ids the server assigned. The caller stores them; a device
    /// enrolls once per server.
    pub async fn enroll_device(
        &self,
        tenant_id: &str,
        signer: &Ed25519SigningKey,
        hpke_public_key: &[u8; 32],
        label_ciphertext: &[u8],
    ) -> Result<EnrolledDevice> {
        let signing_public_key = signer.verifying_key().to_bytes();

        let res = self
            .http
            .post(self.url("/v2/devices/enrollment-challenges"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "tenant_id": tenant_id,
                "signing_public_key": hex(&signing_public_key),
                "hpke_public_key": hex(hpke_public_key),
            }))
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableRegister"))?;
        let challenge: EnrollmentChallenge = Self::ok_or_err(res, "fleet.refusedRegister")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplyRegister"))?;

        let nonce = decode_hex32(&challenge.nonce, "challenge nonce")?;
        let challenge_id = decode_hex16(&challenge.challenge_id, "challenge_id")?;
        let account_id = decode_hex16(&challenge.account_id, "account_id")?;
        let tenant_bytes = decode_hex16(tenant_id, "tenant_id")?;

        let tbs = enrollment_proof_bytes(
            &challenge_id,
            &nonce,
            &tenant_bytes,
            &account_id,
            &signing_public_key,
            hpke_public_key,
        );
        let signature = shardx_core::signing::sign_tbs(signer, &tbs);

        let res = self
            .http
            .post(self.url("/v2/devices/enrollment-proofs"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "tenant_id": tenant_id,
                "challenge_id": challenge.challenge_id,
                "nonce": challenge.nonce,
                "signing_public_key": hex(&signing_public_key),
                "hpke_public_key": hex(hpke_public_key),
                "proof_signature": hex(&signature),
                "label_ciphertext": hex(label_ciphertext),
            }))
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableRegisterFinish"))?;

        Self::ok_or_err(res, "fleet.refusedRegisterFinish")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplyRegisterFinish"))
    }

    pub async fn server_identity(&self) -> Result<ServerIdentity> {
        let res = self
            .http
            .get(self.url("/v2/server-identity"))
            .bearer_auth(&self.token)
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableIdentity"))?;
        Self::ok_or_err(res, "fleet.refusedIdentity")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplyIdentity"))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn acquire_lease(
        &self,
        tenant_id: &str,
        profile_id: &str,
        lease_id: &str,
        account_id: &str,
        device_id: &str,
        ttl_seconds: i64,
    ) -> Result<Lease> {
        let res = self
            .http
            .post(self.url("/v2/fleet/leases"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "tenant_id": tenant_id,
                "profile_id": profile_id,
                "lease_id": lease_id,
                "account_id": account_id,
                "device_id": device_id,
                "ttl_seconds": ttl_seconds,
            }))
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableClaim"))?;
        Self::ok_or_err(res, "fleet.refusedClaim")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplyClaim"))
    }

    pub async fn release_lease(&self, tenant_id: &str, lease_id: &str) -> Result<()> {
        let res = self
            .http
            .post(self.url("/v2/fleet/leases/release"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "tenant_id": tenant_id, "lease_id": lease_id }))
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableRelease"))?;
        Self::ok_or_err(res, "fleet.refusedRelease").await?;
        Ok(())
    }

    pub async fn head(&self, tenant_id: &str, profile_id: &str) -> Result<SnapshotHead> {
        let res = self
            .http
            .get(self.url(&format!("/v2/fleet/snapshots/{tenant_id}/{profile_id}")))
            .bearer_auth(&self.token)
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableHead"))?;
        Self::ok_or_err(res, "fleet.refusedHead")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplyHead"))
    }

    /// Download a published container in ranges.
    ///
    /// Returns raw bytes: still sealed, still unverified. The caller must run
    /// the backup-file restore path before treating any of it as a profile,
    /// because the signed head proving completeness sits at the end.
    pub async fn download(
        &self,
        tenant_id: &str,
        profile_id: &str,
        version: i64,
    ) -> Result<Vec<u8>> {
        let head = self.head(tenant_id, profile_id).await?;
        let total = head.container_size.max(0) as usize;
        let mut out = Vec::with_capacity(total);

        while out.len() < total {
            let length = (total - out.len()).min(CHUNK_BYTES);
            let res = self
                .http
                .get(self.url(&format!(
                    "/v2/fleet/snapshots/{tenant_id}/{profile_id}/range"
                )))
                .bearer_auth(&self.token)
                .query(&[
                    ("version", version.to_string()),
                    ("offset", out.len().to_string()),
                    ("length", length.to_string()),
                ])
                .send()
                .await
                .context(crate::errcode::code("fleet.unreachableDownload"))?;
            let bytes = Self::ok_or_err(res, "fleet.refusedDownload")
                .await?
                .bytes()
                .await
                .context(crate::errcode::code("fleet.downloadBrokeOff"))?;
            // A server returning nothing while bytes remain would spin this
            // loop forever; treat it as a failed download.
            if bytes.is_empty() {
                bail!(
                    "server returned no bytes at offset {} of {total}",
                    out.len()
                );
            }
            out.extend_from_slice(&bytes);
        }

        if out.len() != total {
            bail!(crate::errcode::code_with(
                "fleet.downloadIncomplete",
                &[("got", &out.len().to_string()), ("total", &total.to_string())],
            ));
        }
        Ok(out)
    }

    /// Fetch the root key grants issued to this device, newest generation first.
    ///
    /// The server stores grants it cannot read: every one is HPKE-sealed to a
    /// device public key. Collecting is therefore safe to do over the wire,
    /// but useless without the matching private half held locally.
    pub async fn root_key_grants(
        &self,
        tenant_id: &str,
        device_id: &str,
    ) -> Result<Vec<RootKeyGrant>> {
        let res = self
            .http
            .get(self.url(&format!(
                "/v2/tenants/{tenant_id}/devices/{device_id}/root-key-grants"
            )))
            .bearer_auth(&self.token)
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableAccountKeys"))?;
        let body: RootKeyGrantsResponse = Self::ok_or_err(res, "fleet.refusedAccountKeys")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplyAccountKeys"))?;
        Ok(body.grants)
    }

    /// Fleet key grants filed for this device.
    ///
    /// The fleet key is what actually opens profile snapshots, so this is the
    /// call that lets an enrolled device read what its fleet has pushed.
    pub async fn fleet_key_grants(
        &self,
        tenant_id: &str,
        device_id: &str,
    ) -> Result<Vec<FleetKeyGrant>> {
        let res = self
            .http
            .get(self.url(&format!(
                "/v2/tenants/{tenant_id}/devices/{device_id}/fleet-key-grants"
            )))
            .bearer_auth(&self.token)
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableTeamKeys"))?;
        let body: FleetKeyGrantsResponse = Self::ok_or_err(res, "fleet.refusedTeamKeys")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplyTeamKeys"))?;
        Ok(body.grants)
    }

    /// Lease, stage, and publish a sealed container. Returns the new version.
    ///
    /// The lease is released on every path, including failure: an upload that
    /// died holding its lease would block the profile until the TTL expired.
    pub async fn upload(
        &self,
        req: &UploadRequest<'_>,
        signer: &Ed25519SigningKey,
        ttl_seconds: i64,
    ) -> Result<i64> {
        let identity = self.server_identity().await?;
        let lease_id = random_id_hex();
        let session_id = random_id_hex();

        let lease = self
            .acquire_lease(
                req.tenant_id,
                req.profile_id,
                &lease_id,
                req.account_id,
                req.device_id,
                ttl_seconds,
            )
            .await?;

        let result = self
            .upload_with_lease(req, signer, &identity, &lease, &session_id)
            .await;

        // Best effort: the server expires leases on its own, so a failed
        // release must not mask the real error.
        let _ = self.release_lease(req.tenant_id, &lease.lease_id).await;
        result
    }

    async fn upload_with_lease(
        &self,
        req: &UploadRequest<'_>,
        signer: &Ed25519SigningKey,
        identity: &ServerIdentity,
        lease: &Lease,
        session_id: &str,
    ) -> Result<i64> {
        let container_sha256 = c::sha256(req.container);
        let intent_hash = c::sha256(&c::encode(&c::m(vec![
            ("profile_id", c::t(req.profile_id)),
            ("snapshot_id", c::t(req.snapshot_id)),
            ("container_sha256", c::b(&container_sha256)),
        ])));

        let open = self
            .http
            .post(self.url("/v2/fleet/uploads"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "tenant_id": req.tenant_id,
                "profile_id": req.profile_id,
                "session_id": session_id,
                "lease_id": lease.lease_id,
                "fencing_token": lease.fencing_token,
                "target_version": req.base_version + 1,
                "intent_hash": hex(&intent_hash),
                "declared_size": req.container.len() as i64,
            }))
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableUploadBegin"))?;
        Self::ok_or_err(open, "open upload").await?;

        // Staging failure leaves a session the server can discard; nothing is
        // published until commit succeeds.
        if let Err(e) = self.stage_chunks(req, session_id).await {
            let _ = self.abort(req.tenant_id, session_id).await;
            return Err(e);
        }

        let manifest = self.sign_manifest(req, signer, identity, &container_sha256)?;

        let commit = self
            .http
            .post(self.url("/v2/fleet/uploads/commit"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "tenant_id": req.tenant_id,
                "profile_id": req.profile_id,
                "session_id": session_id,
                "manifest_hex": hex(&manifest),
                "snapshot_id": req.snapshot_id,
                "fleet_id": req.fleet_id,
                "base_version": req.base_version,
                "key_generation": req.key_generation,
                "container_sha256": hex(&container_sha256),
                "author_account_id": req.account_id,
                "author_device_id": req.device_id,
            }))
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableUploadPublish"))?;

        let body: serde_json::Value = Self::ok_or_err(commit, "commit upload")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplyUploadPublish"))?;

        body.get("version")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow!(crate::errcode::code("fleet.commitNoVersion")))
    }

    async fn stage_chunks(&self, req: &UploadRequest<'_>, session_id: &str) -> Result<()> {
        let mut offset = 0usize;
        while offset < req.container.len() {
            let end = (offset + CHUNK_BYTES).min(req.container.len());
            let res = self
                .http
                .post(self.url(&format!(
                    "/v2/fleet/uploads/{}/{}/chunk",
                    req.tenant_id, session_id
                )))
                .bearer_auth(&self.token)
                .header("x-chunk-offset", offset.to_string())
                .header("content-type", "application/octet-stream")
                .body(req.container[offset..end].to_vec())
                .send()
                .await
                .context(crate::errcode::code("fleet.unreachableUploadChunk"))?;
            Self::ok_or_err(res, "fleet.refusedUploadChunk").await?;
            offset = end;
        }
        Ok(())
    }

    async fn abort(&self, tenant_id: &str, session_id: &str) -> Result<()> {
        let res = self
            .http
            .post(self.url("/v2/fleet/uploads/abort"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "tenant_id": tenant_id, "session_id": session_id }))
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableUploadAbort"))?;
        Self::ok_or_err(res, "fleet.refusedUploadAbort").await?;
        Ok(())
    }

    /// Build the signed manifest authorizing this publish.
    ///
    /// The field list lives in `shardx_core::fleet_manifest` so client and
    /// server cannot drift apart.
    fn sign_manifest(
        &self,
        req: &UploadRequest<'_>,
        signer: &Ed25519SigningKey,
        identity: &ServerIdentity,
        container_sha256: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let fields = ManifestFields {
            tenant_id: decode_hex16(req.tenant_id, "tenant_id")?,
            server_instance_id: decode_hex16(&identity.server_instance_id, "server_instance_id")?,
            restore_epoch: identity.restore_epoch.max(0) as u64,
            replay_id: random_id_bytes(),
            profile_id: decode_hex16(req.profile_id, "profile_id")?,
            snapshot_id: decode_hex16(req.snapshot_id, "snapshot_id")?,
            fleet_id: decode_hex16(req.fleet_id, "fleet_id")?,
            base_version: req.base_version.max(0) as u64,
            key_generation: req.key_generation.max(0) as u64,
            container_sha256: *container_sha256,
            not_before_ms: now_ms.saturating_sub(60_000),
            not_after_ms: now_ms + MANIFEST_VALIDITY_MS,
        };
        Ok(build_snapshot_manifest(signer, &fields))
    }
}

fn decode_hex32(s: &str, field: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!(crate::errcode::code_with("fleet.malformedHex64", &[("field", field)]));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!(crate::errcode::code_with("fleet.malformedHexDigits", &[("field", field)])))?;
    }
    Ok(out)
}

/// Canonical bytes a device signs to prove it holds its signing key.
///
/// Must match the server's `enrollment::proof_tbs_bytes` exactly; the domain
/// label keeps this signature from being valid as any other record.
fn enrollment_proof_bytes(
    challenge_id: &[u8; 16],
    nonce: &[u8; 32],
    tenant_id: &[u8; 16],
    account_id: &[u8; 16],
    signing_public_key: &[u8; 32],
    hpke_public_key: &[u8; 32],
) -> Vec<u8> {
    // Shared with the server: one definition, so a mismatch is impossible
    // rather than merely unlikely.
    shardx_core::enrollment_proof::enrollment_proof_tbs(
        &shardx_core::enrollment_proof::EnrollmentProofFields {
            challenge_id,
            nonce,
            tenant_id,
            account_id,
            signing_public_key,
            hpke_public_key,
        },
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex16(s: &str, field: &str) -> Result<[u8; 16]> {
    if s.len() != 32 {
        bail!(crate::errcode::code_with("fleet.malformedHex32", &[("field", field)]));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!(crate::errcode::code_with("fleet.malformedHexDigits", &[("field", field)])))?;
    }
    Ok(out)
}

fn random_id_bytes() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}

/// One grant as the server hands it back.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RootKeyGrant {
    pub grant_variant: String,
    pub root_key_id: String,
    pub root_generation: i64,
    pub recipient_hpke_key_id: String,
    pub hpke_info_hex: String,
    pub hpke_encapped_key_hex: String,
    pub hpke_wrapped_trk_hex: String,
}

#[derive(Debug, serde::Deserialize)]
struct RootKeyGrantsResponse {
    grants: Vec<RootKeyGrant>,
}

/// A fleet key grant as the server returns it.
#[derive(Debug, serde::Deserialize)]
pub struct FleetKeyGrant {
    pub grant_variant: String,
    pub fleet_id: String,
    pub fkek_key_id: String,
    pub fleet_generation: i64,
    pub recipient_hpke_key_id: String,
    pub hpke_info_hex: String,
    pub hpke_encapped_key_hex: String,
    pub hpke_wrapped_fkek_hex: String,
}

#[derive(Debug, serde::Deserialize)]
struct FleetKeyGrantsResponse {
    grants: Vec<FleetKeyGrant>,
}

pub fn random_id_hex() -> String {
    hex(&random_id_bytes())
}

#[cfg(test)]
mod tests {
    use super::{decode_hex16, random_id_hex, FleetClient};

    #[test]
    fn a_base_url_must_carry_a_scheme() {
        assert!(FleetClient::new("example.com", "t").is_err());
        assert!(FleetClient::new("https://example.com", "t").is_ok());
    }

    #[test]
    fn a_trailing_slash_does_not_double_up_in_paths() {
        let c = FleetClient::new("https://example.com/", "t").unwrap();
        assert_eq!(
            c.url("/v2/server-identity"),
            "https://example.com/v2/server-identity"
        );
    }

    #[test]
    fn ids_must_be_16_bytes_of_hex() {
        assert!(decode_hex16("00", "x").is_err());
        assert!(decode_hex16(&"z".repeat(32), "x").is_err());
        assert!(decode_hex16(&"ab".repeat(16), "x").is_ok());
    }

    /// Replay ids must not repeat: the server keys its replay table on them.
    #[test]
    fn replay_ids_are_unique() {
        assert_ne!(random_id_hex(), random_id_hex());
    }
}
