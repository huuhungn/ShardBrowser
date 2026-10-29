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
use shardx_core::session_binding::{
    open_pop_secret, sign_enrollment, sign_pop, DeviceSessionBindingV2, EnrollmentBindingV2,
};
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

/// The v2 account that enrolls this device. The password serves one login
/// and is never stored.
pub struct AccountLogin<'a> {
    pub tenant_id: &'a str,
    pub username: &'a str,
    pub password: &'a str,
}

/// A v2 device session: the bearer every custody route takes. Its class says
/// what it may do (`pending_setup`, `root_setup`); the server decides it.
#[derive(Clone, Deserialize)]
pub struct DeviceSession {
    pub session_id: String,
    pub class: String,
    pub access_token: String,
    pub access_expires_at_ms: i64,
    pub refresh_token: String,
    pub absolute_expires_at_ms: i64,
}

impl std::fmt::Debug for DeviceSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceSession")
            .field("session_id", &self.session_id)
            .field("class", &self.class)
            .field("access_token", &"<redacted>")
            .field("access_expires_at_ms", &self.access_expires_at_ms)
            .field("refresh_token", &"<redacted>")
            .field("absolute_expires_at_ms", &self.absolute_expires_at_ms)
            .finish()
    }
}

/// What a device session binding must name. The device, its keys and the
/// tenant come from this machine; the rest only has to agree with the ticket
/// and challenge the same server issued.
struct SessionExpectation {
    device_id: [u8; 16],
    signing_public_key: [u8; 32],
    hpke_public_key: [u8; 32],
    tenant_id: [u8; 16],
    account_id: [u8; 16],
    ticket_id: [u8; 16],
    challenge_id: [u8; 16],
    server_instance_id: [u8; 16],
    restore_epoch: u64,
}

/// Whether `got` names exactly what `want` expects. The nonce and expiry are
/// the server's to choose, and `parse` already pins the suites and derives
/// the key ids from the keys compared here.
fn session_binding_matches(got: &DeviceSessionBindingV2, want: &SessionExpectation) -> bool {
    let f = &got.fields;
    got.device_id == want.device_id
        && f.signing_public_key == want.signing_public_key
        && f.hpke_public_key == want.hpke_public_key
        && f.tenant_id == want.tenant_id
        && f.account_id == want.account_id
        && f.pre_device_session_id == want.ticket_id
        && f.challenge_id == want.challenge_id
        && f.server_instance_id == want.server_instance_id
        && f.restore_epoch == want.restore_epoch
}

/// Server response to a device session challenge request.
#[derive(Deserialize)]
struct SessionChallenge {
    challenge_id: String,
    /// Hex of the exact `DeviceSessionBindingV2` bytes the proofs cover.
    binding: String,
    encapsulated_key: String,
    ciphertext: String,
}

/// An account-only pre-device ticket and the server facts it was issued under.
#[derive(Deserialize)]
struct Ticket {
    ticket: String,
    ticket_id: String,
    account_id: String,
    server_instance_id: String,
    restore_epoch: u64,
}

/// Server response to an enrollment challenge request.
#[derive(Deserialize)]
struct EnrollmentChallenge {
    challenge_id: String,
    /// Hex of the exact `EnrollmentBindingV2` bytes to sign.
    binding: String,
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
            // A redirect would resend the body, and a login body holds the
            // account password. The API never redirects.
            .redirect(reqwest::redirect::Policy::none())
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
}

/// True for `https://`, or `http://` to this machine.
fn sends_secrets_safely(base_url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(base_url) else {
        return false;
    };
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => true,
        ("http", Some(url::Host::Domain(d))) => d.eq_ignore_ascii_case("localhost"),
        ("http", Some(url::Host::Ipv4(ip))) => ip.is_loopback(),
        ("http", Some(url::Host::Ipv6(ip))) => ip.is_loopback(),
        _ => false,
    }
}

impl FleetClient {
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
            &[
                ("status", &status.as_u16().to_string()),
                ("detail", &detail)
            ],
        )))
    }

    /// Register this device's keys with the server, as `login`'s account.
    ///
    /// The account logs in for a pre-device ticket, the server issues an
    /// `EnrollmentBindingV2` naming both keys, and the device signs it. The
    /// binding is checked against the keys, tenant, account and ticket before
    /// signing, so a server cannot get a signature over anything else. The
    /// private key never leaves this process; the signature proves possession.
    ///
    /// Returns the ids the server assigned. The caller stores them; a device
    /// enrolls once per server.
    pub async fn enroll_device(
        &self,
        login: &AccountLogin<'_>,
        signer: &Ed25519SigningKey,
        hpke_public_key: &[u8; 32],
        label_ciphertext: &[u8],
    ) -> Result<EnrolledDevice> {
        let tenant = decode_hex16(login.tenant_id, "tenant_id")?;
        let ticket = self.login_ticket(login).await?;
        let enrolled = self
            .enroll_with_ticket(&ticket, &tenant, signer, hpke_public_key, label_ciphertext)
            .await;
        self.end_ticket(&ticket).await;
        enrolled
    }

    /// Logs `login` in for an account-only ticket.
    async fn login_ticket(&self, login: &AccountLogin<'_>) -> Result<Ticket> {
        // The password is a long-lived account secret, unlike the token, so
        // it never crosses a network in clear.
        if !sends_secrets_safely(&self.base_url) {
            bail!(crate::errcode::code("fleet.insecureLogin"));
        }
        let res = self
            .http
            .post(self.url("/v2/auth/login"))
            .json(&serde_json::json!({
                "tenant_id": login.tenant_id,
                "username": login.username,
                "password": login.password,
            }))
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableLogin"))?;
        Self::ok_or_err(res, "fleet.refusedLogin")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplyLogin"))
    }

    /// Ends a device session. Best effort: it expires on its own.
    pub async fn end_session(&self, access_token: &str) {
        let _ = self
            .http
            .post(self.url("/v2/auth/logout"))
            .bearer_auth(access_token)
            .send()
            .await;
    }

    /// Ends a ticket that served one step. Best effort: it expires in ten
    /// minutes regardless.
    async fn end_ticket(&self, ticket: &Ticket) {
        let _ = self
            .http
            .post(self.url("/v2/auth/logout"))
            .bearer_auth(&ticket.ticket)
            .send()
            .await;
    }

    /// Opens a v2 device session for this enrolled device, as `login`'s
    /// account (ADR 0001 R2).
    ///
    /// The account logs in for a ticket; the server issues a
    /// `DeviceSessionBindingV2` naming this device and its keys, with a secret
    /// sealed to its HPKE key. Before anything is opened or signed, the
    /// binding must name this device, its keys and the tenant, and agree with
    /// the ticket and challenge, so a server cannot get a proof for another
    /// device or key. Opening the secret proves the HPKE key; signing binding
    /// and secret proves the signing key.
    pub async fn open_device_session(
        &self,
        login: &AccountLogin<'_>,
        device_id: &str,
        signer: &Ed25519SigningKey,
        hpke_seed: &[u8; 32],
    ) -> Result<DeviceSession> {
        let tenant = decode_hex16(login.tenant_id, "tenant_id")?;
        let device = decode_hex16(device_id, "device_id")?;
        let ticket = self.login_ticket(login).await?;
        let session = self
            .session_with_ticket(&ticket, &tenant, &device, signer, hpke_seed)
            .await;
        self.end_ticket(&ticket).await;
        session
    }

    async fn session_with_ticket(
        &self,
        ticket: &Ticket,
        tenant: &[u8; 16],
        device: &[u8; 16],
        signer: &Ed25519SigningKey,
        hpke_seed: &[u8; 32],
    ) -> Result<DeviceSession> {
        let res = self
            .http
            .post(self.url("/v2/auth/device-session-challenges"))
            .bearer_auth(&ticket.ticket)
            .json(&serde_json::json!({ "device_id": hex(device) }))
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableSession"))?;
        let challenge: SessionChallenge = Self::ok_or_err(res, "fleet.refusedSession")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplySession"))?;

        let mismatch = || anyhow!(crate::errcode::code("fleet.sessionBindingMismatch"));
        let binding = decode_hex(&challenge.binding).ok_or_else(mismatch)?;
        let parsed = DeviceSessionBindingV2::parse(&binding).map_err(|_| mismatch())?;
        let (hpke_secret, hpke_public) = shardx_core::grants::derive_keypair(hpke_seed);
        let want = SessionExpectation {
            device_id: *device,
            signing_public_key: signer.verifying_key().to_bytes(),
            hpke_public_key: hpke_public.as_slice().try_into().map_err(|_| mismatch())?,
            tenant_id: *tenant,
            account_id: decode_hex16(&ticket.account_id, "account_id")?,
            ticket_id: decode_hex16(&ticket.ticket_id, "ticket_id")?,
            challenge_id: decode_hex16(&challenge.challenge_id, "challenge_id")?,
            server_instance_id: decode_hex16(&ticket.server_instance_id, "server_instance_id")?,
            restore_epoch: ticket.restore_epoch,
        };
        if !session_binding_matches(&parsed, &want) {
            return Err(mismatch());
        }
        let unsealed = || anyhow!(crate::errcode::code("fleet.sessionProofFailed"));
        let secret = open_pop_secret(
            &hpke_secret,
            &binding,
            &decode_hex(&challenge.encapsulated_key).ok_or_else(unsealed)?,
            &decode_hex(&challenge.ciphertext).ok_or_else(unsealed)?,
        )
        .map_err(|_| unsealed())?;
        let signature = sign_pop(signer, &binding, &secret);

        let res = self
            .http
            .post(self.url("/v2/auth/device-session-proofs"))
            .bearer_auth(&ticket.ticket)
            .json(&serde_json::json!({
                "challenge_id": challenge.challenge_id,
                "secret": hex(&*secret),
                "signature": hex(&signature),
            }))
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableSession"))?;
        Self::ok_or_err(res, "fleet.refusedSession")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplySession"))
    }

    /// POSTs exact CBOR bytes under a device session and returns the exact
    /// response bytes. Custody routes take and answer canonical CBOR.
    async fn post_cbor(&self, path: &str, access_token: &str, body: &[u8]) -> Result<Vec<u8>> {
        let res = self
            .http
            .post(self.url(path))
            .bearer_auth(access_token)
            .header("content-type", "application/cbor")
            .body(body.to_vec())
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableCustody"))?;
        let body = Self::ok_or_err(res, "fleet.refusedCustody")
            .await?
            .bytes()
            .await
            .context(crate::errcode::code("fleet.badReplyCustody"))?;
        Ok(body.to_vec())
    }

    /// D1: files this device's approval of itself (ADR 0001 D1). Returns the
    /// exact `DeviceApprovalReceiptV2` bytes.
    pub async fn approve_device(
        &self,
        access_token: &str,
        device_id: &str,
        approval_container: &[u8],
    ) -> Result<Vec<u8>> {
        self.post_cbor(
            &format!("/v2/devices/{device_id}/approve"),
            access_token,
            approval_container,
        )
        .await
    }

    /// Creates a root key generation. Returns the exact stored response.
    pub async fn create_root_generation(
        &self,
        access_token: &str,
        tenant_id: &str,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        self.post_cbor(
            &format!("/v2/tenants/{tenant_id}/root-key-generations"),
            access_token,
            request,
        )
        .await
    }

    /// Reads one root grant back as its exact `TenantRootGrantDescriptorV2`.
    pub async fn read_root_grant(
        &self,
        access_token: &str,
        tenant_id: &str,
        generation: u64,
        replay_id: &str,
    ) -> Result<Vec<u8>> {
        let res = self
            .http
            .get(self.url(&format!(
                "/v2/tenants/{tenant_id}/root-key-generations/{generation}/grants/{replay_id}"
            )))
            .bearer_auth(access_token)
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableCustody"))?;
        let body = Self::ok_or_err(res, "fleet.refusedCustody")
            .await?
            .bytes()
            .await
            .context(crate::errcode::code("fleet.badReplyCustody"))?;
        Ok(body.to_vec())
    }

    /// Every page of the tenant's trust evidence, following the cursors. The
    /// pages are only parsed here; `trust_chain` verifies what they hold.
    pub async fn trust_evidence(
        &self,
        access_token: &str,
        tenant_id: &str,
    ) -> Result<Vec<shardx_core::trust_evidence::TenantTrustEvidencePageV2>> {
        use shardx_core::trust_chain::MAX_EVIDENCE_PAGES;
        use shardx_core::trust_evidence::TenantTrustEvidencePageV2;
        let mut pages = Vec::new();
        let mut cursor = String::new();
        loop {
            if pages.len() >= MAX_EVIDENCE_PAGES {
                bail!(crate::errcode::code("fleet.trustEvidenceRefused"));
            }
            let mut url = self.url(&format!("/v2/tenants/{tenant_id}/trust-evidence"));
            if !cursor.is_empty() {
                url = format!("{url}?cursor={cursor}");
            }
            let res = self
                .http
                .get(url)
                .bearer_auth(access_token)
                .send()
                .await
                .context(crate::errcode::code("fleet.unreachableCustody"))?;
            let body = Self::ok_or_err(res, "fleet.refusedCustody")
                .await?
                .bytes()
                .await
                .context(crate::errcode::code("fleet.badReplyCustody"))?;
            let page = TenantTrustEvidencePageV2::parse(&body)
                .map_err(|_| anyhow!(crate::errcode::code("fleet.badReplyCustody")))?;
            cursor = hex(&page.next_cursor);
            pages.push(page);
            if cursor.is_empty() {
                return Ok(pages);
            }
        }
    }

    /// Acknowledges one root grant. Returns the exact stored response.
    pub async fn ack_root_grant(
        &self,
        access_token: &str,
        tenant_id: &str,
        generation: u64,
        replay_id: &str,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        self.post_cbor(
            &format!(
                "/v2/tenants/{tenant_id}/root-key-generations/{generation}/grants/{replay_id}/ack"
            ),
            access_token,
            request,
        )
        .await
    }

    /// Activates a root key generation. Returns the exact stored response.
    pub async fn activate_root_generation(
        &self,
        access_token: &str,
        tenant_id: &str,
        generation: u64,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        self.post_cbor(
            &format!("/v2/tenants/{tenant_id}/root-key-generations/{generation}/activate"),
            access_token,
            request,
        )
        .await
    }

    /// Rotates a device session's tokens. The old refresh token is spent:
    /// never retry with it, because a reused token revokes the session.
    pub async fn refresh_device_session(&self, refresh_token: &str) -> Result<DeviceSession> {
        if !sends_secrets_safely(&self.base_url) {
            bail!(crate::errcode::code("fleet.insecureSession"));
        }
        let res = self
            .http
            .post(self.url("/v2/auth/refresh"))
            .json(&serde_json::json!({ "refresh_token": refresh_token }))
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableSession"))?;
        Self::ok_or_err(res, "fleet.refusedRefresh")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplySession"))
    }

    async fn enroll_with_ticket(
        &self,
        ticket: &Ticket,
        tenant: &[u8; 16],
        signer: &Ed25519SigningKey,
        hpke_public_key: &[u8; 32],
        label_ciphertext: &[u8],
    ) -> Result<EnrolledDevice> {
        let signing_public_key = signer.verifying_key().to_bytes();
        let res = self
            .http
            .post(self.url("/v2/devices/enrollment-challenges"))
            .bearer_auth(&ticket.ticket)
            .json(&serde_json::json!({
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

        let mismatch = || anyhow!(crate::errcode::code("fleet.bindingMismatch"));
        let binding = decode_hex(&challenge.binding).ok_or_else(mismatch)?;
        let parsed = EnrollmentBindingV2::parse(&binding).map_err(|_| mismatch())?;
        let f = &parsed.fields;
        let expected = f.signing_public_key == signing_public_key
            && f.hpke_public_key == *hpke_public_key
            && f.tenant_id == *tenant
            && f.account_id == decode_hex16(&ticket.account_id, "account_id")?
            && f.pre_device_session_id == decode_hex16(&ticket.ticket_id, "ticket_id")?
            && f.challenge_id == decode_hex16(&challenge.challenge_id, "challenge_id")?
            && f.server_instance_id
                == decode_hex16(&ticket.server_instance_id, "server_instance_id")?
            && f.restore_epoch == ticket.restore_epoch;
        if !expected {
            return Err(mismatch());
        }
        let signature = sign_enrollment(signer, &binding);

        let res = self
            .http
            .post(self.url("/v2/devices/enrollment-proofs"))
            .bearer_auth(&ticket.ticket)
            .json(&serde_json::json!({
                "challenge_id": challenge.challenge_id,
                "signature": hex(&signature),
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
                bail!(crate::errcode::code_with(
                    "fleet.downloadStalled",
                    &[
                        ("offset", &out.len().to_string()),
                        ("total", &total.to_string())
                    ]
                ));
            }
            out.extend_from_slice(&bytes);
        }

        if out.len() != total {
            bail!(crate::errcode::code_with(
                "fleet.downloadIncomplete",
                &[
                    ("got", &out.len().to_string()),
                    ("total", &total.to_string())
                ],
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

    /// The fleet's ACTIVE key generation, if it has one.
    pub async fn active_fleet_generation(
        &self,
        tenant_id: &str,
        fleet_id: &str,
    ) -> Result<Option<u64>> {
        let res = self
            .http
            .get(self.url(&format!(
                "/v2/tenants/{tenant_id}/fleets/{fleet_id}/key-generation"
            )))
            .bearer_auth(&self.token)
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableTeamKeys"))?;
        let body: Option<ActiveFleetGeneration> = Self::ok_or_err(res, "fleet.refusedTeamKeys")
            .await?
            .json()
            .await
            .context(crate::errcode::code("fleet.badReplyTeamKeys"))?;
        Ok(body.map(|g| g.generation))
    }

    /// This device's D-9 `DeviceHpkeGrant` of `generation` as its exact
    /// `FleetDeviceGrantDescriptorV2` (plan L1131), `None` when none is filed.
    /// The server serves it to this device's own session only.
    pub async fn read_fleet_device_grant(
        &self,
        access_token: &str,
        fleet_id: &str,
        generation: u64,
        device_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let res = self
            .http
            .get(self.url(&format!(
                "/v2/fleets/{fleet_id}/key-generations/{generation}/grants/{device_id}"
            )))
            .bearer_auth(access_token)
            .send()
            .await
            .context(crate::errcode::code("fleet.unreachableTeamKeys"))?;
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = Self::ok_or_err(res, "fleet.refusedTeamKeys")
            .await?
            .bytes()
            .await
            .context(crate::errcode::code("fleet.badReplyTeamKeys"))?;
        Ok(Some(body.to_vec()))
    }

    /// Sends `req` under a device session and returns the reply as received.
    /// Only a reply that never arrived is an error: the caller decides what a
    /// status means, and replays the same stored bytes after a lost one.
    async fn exact(&self, req: reqwest::RequestBuilder, access_token: &str) -> Result<Exact> {
        let lost = || crate::errcode::code("fleet.unreachableSync");
        let res = req.bearer_auth(access_token).send().await.context(lost())?;
        let status = res.status().as_u16();
        let headers = res.headers().clone();
        let body = res.bytes().await.context(lost())?.to_vec();
        Ok(Exact {
            status,
            headers,
            body,
        })
    }

    /// POSTs exact CBOR request bytes (plan 8.1 L1137-L1152).
    async fn post_exact(&self, path: &str, access_token: &str, body: &[u8]) -> Result<Exact> {
        let req = self
            .http
            .post(self.url(path))
            .header("content-type", "application/cbor")
            .body(body.to_vec());
        self.exact(req, access_token).await
    }

    /// `GET /v2/fleets/{fleet_id}/profiles`, one `FleetProfilePageV2`.
    pub async fn list_fleet_profiles(
        &self,
        access_token: &str,
        fleet_id: &[u8; 16],
        after: Option<&[u8; 16]>,
    ) -> Result<Exact> {
        let mut url = self.url(&format!("/v2/fleets/{}/profiles", hex(fleet_id)));
        if let Some(a) = after {
            url = format!("{url}?after={}", hex(a));
        }
        self.exact(self.http.get(url), access_token).await
    }

    /// `PROFILE_PUBLISH_CREATE` (L1137).
    // shortcut: nothing calls publish yet; the Team profile UI that lets a
    // user publish a local profile (and records its binding) triggers it.
    pub async fn publish_profile(
        &self,
        access_token: &str,
        fleet_id: &[u8; 16],
        request: &[u8],
    ) -> Result<Exact> {
        let path = format!("/v2/fleets/{}/profiles", hex(fleet_id));
        self.post_exact(&path, access_token, request).await
    }

    /// `PROFILE_CHECKOUT` (L1138).
    pub async fn checkout_profile(
        &self,
        access_token: &str,
        profile_id: &[u8; 16],
        request: &[u8],
    ) -> Result<Exact> {
        let path = format!("/v2/profiles/{}/checkout", hex(profile_id));
        self.post_exact(&path, access_token, request).await
    }

    /// `LeaseRenewV2` (L1139).
    pub async fn renew_lease_v2(
        &self,
        access_token: &str,
        profile_id: &[u8; 16],
        lease_id: &[u8; 16],
        request: &[u8],
    ) -> Result<Exact> {
        let path = format!(
            "/v2/profiles/{}/leases/{}/renew",
            hex(profile_id),
            hex(lease_id)
        );
        self.post_exact(&path, access_token, request).await
    }

    /// `RELEASE_LEASE` (L1140).
    pub async fn release_lease_v2(
        &self,
        access_token: &str,
        profile_id: &[u8; 16],
        lease_id: &[u8; 16],
        request: &[u8],
    ) -> Result<Exact> {
        let path = format!(
            "/v2/profiles/{}/leases/{}/release",
            hex(profile_id),
            hex(lease_id)
        );
        self.post_exact(&path, access_token, request).await
    }

    /// `CREATE_UPLOAD` (L1147).
    pub async fn create_upload(
        &self,
        access_token: &str,
        profile_id: &[u8; 16],
        request: &[u8],
    ) -> Result<Exact> {
        let path = format!("/v2/profiles/{}/uploads", hex(profile_id));
        self.post_exact(&path, access_token, request).await
    }

    /// `HEAD /v2/uploads/{upload_id}`: the committed offset and state (L1148).
    pub async fn upload_head(&self, access_token: &str, upload_id: &[u8; 16]) -> Result<Exact> {
        let url = self.url(&format!("/v2/uploads/{}", hex(upload_id)));
        self.exact(self.http.head(url), access_token).await
    }

    /// `PATCH /v2/uploads/{upload_id}`: one chunk at `offset` (L1149).
    pub async fn upload_patch(
        &self,
        access_token: &str,
        upload_id: &[u8; 16],
        offset: u64,
        chunk: &[u8],
    ) -> Result<Exact> {
        let req = self
            .http
            .patch(self.url(&format!("/v2/uploads/{}", hex(upload_id))))
            .header("upload-offset", offset.to_string())
            .header(
                "upload-chunk-sha256",
                hex(&shardx_core::canonical::sha256(chunk)),
            )
            .body(chunk.to_vec());
        self.exact(req, access_token).await
    }

    /// `FINALIZE_UPLOAD` (L1150).
    pub async fn finalize_upload(
        &self,
        access_token: &str,
        upload_id: &[u8; 16],
        request: &[u8],
    ) -> Result<Exact> {
        let path = format!("/v2/uploads/{}/finalize", hex(upload_id));
        self.post_exact(&path, access_token, request).await
    }

    /// The exact `CommitRequestV2` (L1151).
    pub async fn commit_upload(
        &self,
        access_token: &str,
        upload_id: &[u8; 16],
        request: &[u8],
    ) -> Result<Exact> {
        let path = format!("/v2/uploads/{}/commit", hex(upload_id));
        self.post_exact(&path, access_token, request).await
    }

    /// The exact signed manifest of a committed version (L1153).
    pub async fn snapshot_manifest(
        &self,
        access_token: &str,
        profile_id: &[u8; 16],
        version: u64,
    ) -> Result<Exact> {
        let url = self.url(&format!(
            "/v2/profiles/{}/snapshots/{version}/manifest",
            hex(profile_id)
        ));
        self.exact(self.http.get(url), access_token).await
    }

    /// Bytes `start..=end` of a committed version's ciphertext (L1153).
    pub async fn snapshot_range(
        &self,
        access_token: &str,
        profile_id: &[u8; 16],
        version: u64,
        start: u64,
        end: u64,
    ) -> Result<Exact> {
        let req = self
            .http
            .get(self.url(&format!(
                "/v2/profiles/{}/snapshots/{version}",
                hex(profile_id)
            )))
            .header("range", format!("bytes={start}-{end}"));
        self.exact(req, access_token).await
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
        Self::ok_or_err(open, "fleet.refusedUploadOpen").await?;

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

        let body: serde_json::Value = Self::ok_or_err(commit, "fleet.refusedUploadCommit")
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

pub(crate) fn decode_hex32(s: &str, field: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!(crate::errcode::code_with(
            "fleet.malformedHex64",
            &[("field", field)]
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| {
            anyhow!(crate::errcode::code_with(
                "fleet.malformedHexDigits",
                &[("field", field)]
            ))
        })?;
    }
    Ok(out)
}

pub(crate) fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn decode_hex16(s: &str, field: &str) -> Result<[u8; 16]> {
    if s.len() != 32 {
        bail!(crate::errcode::code_with(
            "fleet.malformedHex32",
            &[("field", field)]
        ));
    }
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(crate::errcode::code_with(
            "fleet.malformedHexDigits",
            &[("field", field)]
        ));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| {
            anyhow!(crate::errcode::code_with(
                "fleet.malformedHexDigits",
                &[("field", field)]
            ))
        })?;
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
struct ActiveFleetGeneration {
    generation: u64,
}

/// A v2 reply exactly as received.
pub struct Exact {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub body: Vec<u8>,
}

pub fn random_id_hex() -> String {
    hex(&random_id_bytes())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_hex, decode_hex16, random_id_hex, sends_secrets_safely, session_binding_matches,
        DeviceSession, FleetClient, SessionExpectation,
    };
    use shardx_core::session_binding::{BindingFields, DeviceSessionBindingV2};

    fn binding() -> DeviceSessionBindingV2 {
        DeviceSessionBindingV2 {
            device_id: [1; 16],
            fields: BindingFields {
                server_instance_id: [2; 16],
                restore_epoch: 3,
                tenant_id: [4; 16],
                account_id: [5; 16],
                pre_device_session_id: [6; 16],
                challenge_id: [7; 16],
                nonce: [8; 16],
                signing_suite: 1,
                signing_public_key: [9; 32],
                signing_key_id: [10; 32],
                hpke_suite: 1,
                hpke_public_key: [11; 32],
                hpke_key_id: [12; 32],
                expires_at_ms: 13,
            },
        }
    }

    fn expectation() -> SessionExpectation {
        SessionExpectation {
            device_id: [1; 16],
            signing_public_key: [9; 32],
            hpke_public_key: [11; 32],
            tenant_id: [4; 16],
            account_id: [5; 16],
            ticket_id: [6; 16],
            challenge_id: [7; 16],
            server_instance_id: [2; 16],
            restore_epoch: 3,
        }
    }

    #[test]
    fn a_session_binding_must_name_every_expected_field() {
        assert!(session_binding_matches(&binding(), &expectation()));
        // The server's own choices do not have to match anything.
        let mut b = binding();
        b.fields.nonce = [0xEE; 16];
        b.fields.expires_at_ms = 99;
        assert!(session_binding_matches(&b, &expectation()));

        type Mutation = fn(&mut DeviceSessionBindingV2);
        let changes: [(&str, Mutation); 9] = [
            ("device_id", |b| b.device_id[0] ^= 1),
            ("signing_public_key", |b| {
                b.fields.signing_public_key[0] ^= 1
            }),
            ("hpke_public_key", |b| b.fields.hpke_public_key[0] ^= 1),
            ("tenant_id", |b| b.fields.tenant_id[0] ^= 1),
            ("account_id", |b| b.fields.account_id[0] ^= 1),
            ("pre_device_session_id", |b| {
                b.fields.pre_device_session_id[0] ^= 1
            }),
            ("challenge_id", |b| b.fields.challenge_id[0] ^= 1),
            ("server_instance_id", |b| {
                b.fields.server_instance_id[0] ^= 1
            }),
            ("restore_epoch", |b| b.fields.restore_epoch += 1),
        ];
        for (name, change) in changes {
            let mut b = binding();
            change(&mut b);
            assert!(
                !session_binding_matches(&b, &expectation()),
                "a binding with another {name} must be refused"
            );
        }
    }

    #[test]
    fn a_session_debug_print_hides_its_tokens() {
        let s = DeviceSession {
            session_id: "sid".into(),
            class: "pending_setup".into(),
            access_token: "access-secret".into(),
            access_expires_at_ms: 1,
            refresh_token: "refresh-secret".into(),
            absolute_expires_at_ms: 2,
        };
        let printed = format!("{s:?}");
        assert!(printed.contains("sid"));
        assert!(!printed.contains("access-secret") && !printed.contains("refresh-secret"));
    }

    #[test]
    fn hex_from_the_server_never_panics_or_takes_signs() {
        // 32 bytes, but a multi-byte char straddles a digit pair.
        let straddle = format!("a\u{e9}{}", "0".repeat(29));
        assert_eq!(straddle.len(), 32);
        assert!(decode_hex16(&straddle, "x").is_err());
        assert!(decode_hex16(&format!("+f{}", "0".repeat(30)), "x").is_err());
        assert_eq!(decode_hex("+f"), None);
        assert_eq!(decode_hex("0aFF"), Some(vec![0x0a, 0xff]));
    }

    #[test]
    fn a_password_goes_only_over_https_or_to_this_machine() {
        for ok in [
            "https://team.example",
            "https://10.0.0.5:8443",
            "http://127.0.0.1:38200",
            "http://localhost:8080",
            "http://[::1]:9000",
        ] {
            assert!(sends_secrets_safely(ok), "{ok}");
        }
        for bad in [
            "http://team.lan",
            "http://10.0.0.5:8080",
            "http://127.0.0.1.example",
            "ftp://127.0.0.1",
            "not a url",
        ] {
            assert!(!sends_secrets_safely(bad), "{bad}");
        }
    }

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
