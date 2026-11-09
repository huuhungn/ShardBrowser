// Root key rotation (v2.11 RR) tests, included into `root_bootstrap::tests`
// so they run under the names the v2.11 plan gives them.

use crate::root_rotation::{rotate_root, RootRotation, CRASH_AFTER_STEP};
use shardx_core::authz_record::{RecoveryGrantV2, DOMAIN_FLEET_KEY_GRANT_RECOVERY};

const OLD_TRK: [u8; 32] = [9; 32];
const FK0: [u8; 32] = [0x50; 32];
const FK1: [u8; 32] = [0x51; 32];
const RR_PASS: &str = "correct horse battery";

/// A credential store in memory, for one test.
#[derive(Default)]
struct MemVault(Mutex<std::collections::BTreeMap<String, [u8; 32]>>);

impl TrkStore for MemVault {
    fn store(&self, credential_ref: &str, key: &[u8; 32]) -> Result<()> {
        self.0.lock().unwrap().insert(credential_ref.into(), *key);
        Ok(())
    }
    fn load(&self, credential_ref: &str) -> Result<Zeroizing<[u8; 32]>> {
        self.0
            .lock()
            .unwrap()
            .get(credential_ref)
            .map(|k| Zeroizing::new(*k))
            .ok_or_else(|| anyhow!(crate::errcode::code("credential.missing")))
    }
    fn forget(&self, credential_ref: &str) -> Result<()> {
        self.0.lock().unwrap().remove(credential_ref);
        Ok(())
    }
}

/// What the root rotation server holds and is told.
struct RootServer {
    now: u64,
    evidence: Vec<Vec<u8>>,
    /// The signing keys its evidence pages list.
    keys: Vec<[u8; 32]>,
    active_fleet: Option<u64>,
    /// The root grants filed for the PREPARING generation, by replay ID.
    grants: std::collections::BTreeMap<[u8; 16], Vec<u8>>,
    /// The operator discarded the PREPARING generation.
    discarded: bool,
    /// The first call containing the text is answered with this status and
    /// code.
    refuse: Option<(&'static str, u16, &'static str)>,
    /// POST paths whose reply was lost once (the server kept the request).
    lost: std::collections::BTreeSet<String>,
    /// Lose the reply of the first POST to each path not yet in `lost`.
    lose_each: bool,
    /// The bundle path, and its bytes when the create arrived.
    bundle: Option<std::path::PathBuf>,
    bundle_at_create: Option<Vec<u8>>,
}

fn coded(status: u16, code: &str) -> (u16, Vec<u8>) {
    (status, format!(r#"{{"code":"{code}"}}"#).into_bytes())
}

fn rr_reply(server: Arc<Mutex<RootServer>>) -> Arc<crate::fleet_custody::tests::Reply> {
    use crate::fleet_custody::tests::stored;
    use shardx_core::fleet_lifecycle::*;
    use shardx_core::mutation::*;
    Arc::new(move |call: &str, body: &[u8]| {
        let mut s = server.lock().unwrap();
        if let Some((_, status, code)) = s.refuse.filter(|(t, ..)| call.contains(t)) {
            s.refuse = None;
            return coded(status, code);
        }
        let (cx, _) = custodian_cx([5; 16], &OLD_TRK);
        let post = call.starts_with("POST ");
        let path = call.trim_start_matches("POST ").to_string();
        let lose = post && s.lose_each && s.lost.insert(path);
        let root = call.contains("/root-key-generations");
        let reply = match call {
            "GET /v2/server-identity" => (
                200,
                serde_json::to_vec(&serde_json::json!({
                    "server_instance_id": hex(&cx.instance),
                    "restore_epoch": 0,
                }))
                .unwrap(),
            ),
            c if c.contains("/trust-evidence") => {
                let page = shardx_core::trust_evidence::TenantTrustEvidencePageV2 {
                    server_instance_id: cx.instance,
                    tenant_id: cx.tenant,
                    server_now_ms: s.now,
                    page_index: 0,
                    next_cursor: Vec::new(),
                    signing_public_keys: s.keys.clone(),
                    containers: s.evidence.clone(),
                    revocations: Vec::new(),
                    device_revocations: Vec::new(),
                };
                (200, page.encode())
            }
            c if c.ends_with("/key-generation") => match s.active_fleet {
                Some(g) => (200, format!(r#"{{"generation":{g}}}"#).into_bytes()),
                None => (200, b"null".to_vec()),
            },
            "POST /v2/capability-grants" => (201, body.to_vec()),
            c if post && c.ends_with("/root-key-generations") => {
                s.bundle_at_create = s.bundle.as_ref().and_then(|p| std::fs::read(p).ok());
                let reply = stored(body, RECORD_TYPE_ROOT_GENERATION_CREATED, |p| {
                    let create = TenantRootGenerationCreateV2::parse(p).unwrap();
                    let RootGenerationMode::Rotation {
                        previous_root_key_id,
                        previous_root_generation,
                    } = create.mode
                    else {
                        panic!("a rotation")
                    };
                    TenantRootGenerationCreatedV2 {
                        target: create.target,
                        mode: RootGenerationMode::Rotation {
                            previous_root_key_id,
                            previous_root_generation,
                        },
                        created_at_ms: 1,
                    }
                    .encode()
                });
                (201, reply)
            }
            _ if root && s.discarded => coded(404, "RESOURCE_NOT_FOUND"),
            c if post && root && c.ends_with("/activate") => {
                let reply = stored(body, RECORD_TYPE_ROOT_GENERATION_ACTIVATED, |p| {
                    let a = TenantRootGenerationActivateV2::parse(p).unwrap();
                    TenantRootGenerationActivatedV2 {
                        target: a.target,
                        previous: a.previous,
                        activated_at_ms: 1,
                    }
                    .encode()
                });
                (201, reply)
            }
            c if post && root && c.ends_with("/ack") => {
                let reply = stored(body, RECORD_TYPE_ROOT_GRANT_ACKED, |p| {
                    TenantRootGrantAckedV2 {
                        grant: TenantRootGrantAckV2::parse(p).unwrap().grant,
                        acked_at_ms: 1,
                    }
                    .encode()
                });
                (201, reply)
            }
            c if post && root && c.ends_with("/grants") => {
                let request = IdempotentMutationRequestV2::parse(body).unwrap();
                let filing =
                    TenantRootGrantCreateV2::parse(&request.canonical_payload_bytes).unwrap();
                s.grants.insert(
                    filing.grant.replay_id,
                    filing.exact_signed_grant_container_bytes.clone(),
                );
                let reply = stored(body, RECORD_TYPE_ROOT_GRANT_CREATED, |_| {
                    TenantRootGrantCreatedV2 {
                        grant: filing.grant.clone(),
                        grant_variant: "RotationGrant",
                        subject_device_id: cx.device,
                        recipient_hpke_key_id: cx.hpke_key_id,
                        created_at_ms: 1,
                    }
                    .encode()
                });
                (201, reply)
            }
            c if c.starts_with("GET ") && root => {
                let replay = c.rsplit('/').next().unwrap();
                match s.grants.iter().find(|(r, _)| hex(r.as_slice()) == replay) {
                    Some((_, container)) => {
                        let record = AuthorizationRecord::parse(container)
                            .unwrap()
                            .verify_signature(signer().verifying_key().as_bytes())
                            .unwrap();
                        let d = TenantRootGrantDescriptorV2::new(
                            record,
                            RootGrantState::PendingAck,
                            RootGenerationState::Preparing,
                        )
                        .unwrap();
                        (200, d.encode())
                    }
                    None => coded(404, "RESOURCE_NOT_FOUND"),
                }
            }
            _ if s.discarded => coded(400, "BAD_REQUEST"),
            c if post && c.starts_with("POST /v2/fleets/") && c.ends_with("/grants") => {
                let reply = stored(body, RECORD_TYPE_FLEET_GRANT_CREATED, |p| {
                    FleetKeyGrantCreatedV2 {
                        grant: FleetKeyGrantCreateV2::parse(p).unwrap().grant,
                        target: FleetGrantTarget::Root {
                            recipient_root_generation: 1,
                        },
                        created_at_ms: 1,
                    }
                    .encode()
                });
                (201, reply)
            }
            c if post && c.starts_with("POST /v2/fleets/") && c.ends_with("/ack") => {
                let reply = stored(body, RECORD_TYPE_FLEET_GRANT_ACKED, |p| {
                    FleetKeyGrantAckedV2 {
                        grant: FleetKeyGrantAckV2::parse(p).unwrap().grant,
                        acked_at_ms: 1,
                    }
                    .encode()
                });
                (201, reply)
            }
            _ => (500, Vec::new()),
        };
        if lose {
            return (500, Vec::new());
        }
        reply
    })
}

/// A `RecoveryGrant` of `fkek` as fleet `generation`, under `trk` as root
/// `root_generation`, from `issuer`, issued at `now`.
fn recovery_grant_of(
    issuer: &Ed25519SigningKey,
    generation: u64,
    fkek: &[u8; 32],
    trk: &[u8; 32],
    root_generation: u64,
    now: u64,
) -> Vec<u8> {
    let (cx, _) = custodian_cx([5; 16], &OLD_TRK);
    let mut common = cx.common(random().unwrap(), now);
    common.not_after_ms =
        common.not_before_ms + shardx_core::approval_receipt::MAX_FLEET_RECOVERY_GRANT_TTL_MS;
    let mut g = RecoveryGrantV2 {
        common,
        fleet_id: cx.tenant,
        fkek_key_id: shardx_core::fleet_grants::fkek_key_id(fkek),
        generation,
        recipient_root_key_id: root_key_id(trk),
        recipient_root_generation: root_generation,
        root_wrap_nonce_bytes: [0; 12],
        wrapped_fleet_key_bytes: [0; 48],
    };
    g.seal(trk, fkek).unwrap();
    build_record(issuer, DOMAIN_FLEET_KEY_GRANT_RECOVERY, &g.encode())
}

/// A root custodian of root 0 whose fleet has generations 0 (RETIRED) and
/// 1 (ACTIVE), each with a recovery grant under root 0, against a mock
/// server whose clock reads ten days after `START`.
struct Rotating {
    rt: tokio::runtime::Runtime,
    client: FleetClient,
    seen: crate::fleet_custody::tests::Seen,
    server: Arc<Mutex<RootServer>>,
    state: BootstrapState,
    custody: crate::fleet_custody::FleetCustodyState,
    vault: MemVault,
    local: Vec<(u64, Zeroizing<[u8; 32]>)>,
    path: std::path::PathBuf,
    db: crate::team::db::Db,
    pin: (shardx_core::trust_chain::Binding, [u8; 32]),
    _dir: tempfile::TempDir,
}

fn rotating() -> Rotating {
    let rt = crate::fleet_custody::tests::runtime();
    let (cx, _) = custodian_cx([5; 16], &OLD_TRK);
    let (_, pk) = derive_keypair(&HPKE_SEED);
    let built = START + CLOCK_SKEW_MS;
    let approval = self_approval(&cx, &signer(), built).unwrap();
    let replay = approval_of(&approval).common.replay_id;
    let grant = self_grant(&cx, &signer(), &pk, &OLD_TRK, replay, built).unwrap();
    let own = crate::fleet_custody::own_grants(&cx, cx.tenant);
    let grants =
        crate::fleet_custody::capability_grants(&cx, &signer(), &me_subject(&cx), own, built)
            .unwrap();
    let mut evidence = vec![approval.clone(), grant.clone()];
    evidence.extend(grants.iter().map(|g| unhex_vec(g).unwrap()));
    for (generation, fkek) in [(0, FK0), (1, FK1)] {
        evidence.push(recovery_grant_of(
            &signer(),
            generation,
            &fkek,
            &OLD_TRK,
            0,
            built + DAY,
        ));
    }
    let state = BootstrapState {
        tenant_id: hex(&cx.tenant),
        device_id: hex(&cx.device),
        server_instance_id: hex(&cx.instance),
        approval: hex(&approval),
        self_grant: hex(&grant),
        activated: true,
        anchor: hex(&cx.signing_key_id),
        ..Default::default()
    };
    let custody = crate::fleet_custody::FleetCustodyState {
        tenant_id: hex(&cx.tenant),
        device_id: hex(&cx.device),
        server_instance_id: hex(&cx.instance),
        capability_grants: grants,
        ..Default::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rotated.shxrecovery");
    let server = Arc::new(Mutex::new(RootServer {
        now: START + 10 * DAY,
        evidence,
        keys: vec![signer().verifying_key().to_bytes()],
        active_fleet: Some(1),
        grants: Default::default(),
        discarded: false,
        refuse: None,
        lost: Default::default(),
        lose_each: false,
        bundle: Some(path.clone()),
        bundle_at_create: None,
    }));
    let (client, seen) = rt.block_on(crate::fleet_custody::tests::mock(rr_reply(server.clone())));
    Rotating {
        rt,
        client,
        seen,
        server,
        state,
        custody,
        vault: MemVault::default(),
        local: vec![(0, Zeroizing::new(FK0)), (1, Zeroizing::new(FK1))],
        path,
        db: crate::team::db::Db::open_at(&dir.path().join("team-ledger.db")).unwrap(),
        pin: (
            shardx_core::trust_chain::Binding {
                server_instance_id: cx.instance,
                tenant_id: cx.tenant,
            },
            cx.signing_key_id,
        ),
        _dir: dir,
    }
}

impl Rotating {
    fn rotate(&mut self) -> Result<()> {
        self.rotate_saving(&mut |_| Ok(()))
    }

    fn rotate_saving(&mut self, save: &mut impl FnMut(&BootstrapState) -> Result<()>) -> Result<()> {
        let (signer, account) = (signer(), hex(&[4; 16]));
        let me = RenewingDevice {
            account_id: &account,
            signer: &signer,
            hpke_seed: &HPKE_SEED,
        };
        let recovery = RecoveryExport {
            path: &self.path,
            passphrase: RR_PASS,
        };
        let now = self.server.lock().unwrap().now;
        let mut ledger = crate::fleet_custody::Ledger {
            db: &mut self.db,
            pin: &self.pin,
        };
        self.rt.block_on(rotate_root(
            &self.client,
            "access",
            &me,
            &self.vault,
            &mut ledger,
            &self.custody,
            &self.local,
            &recovery,
            now,
            &mut self.state,
            save,
        ))
    }

    fn calls(&self) -> Vec<(String, Vec<u8>)> {
        self.seen.lock().unwrap().clone()
    }

    fn posts(&self) -> Vec<(String, Vec<u8>)> {
        self.calls()
            .into_iter()
            .filter(|(c, _)| c.starts_with("POST "))
            .collect()
    }

    fn run(&self) -> RootRotation {
        self.state.root_rotation.clone().expect("a root rotation")
    }

    /// The new TRK, from the current root grant once the rotation is done.
    fn new_trk(&self) -> Zeroizing<[u8; 32]> {
        let (grant, _, _) = current_root_grant(&self.state, &signer()).unwrap();
        grant.open_trk(&derive_keypair(&HPKE_SEED).0).unwrap()
    }
}

fn rr_short(call: &str) -> String {
    let (method, path) = call.split_once(' ').unwrap();
    let parts: Vec<&str> = path.split('/').collect();
    let name = match parts.as_slice() {
        [.., "capability-grants"] => "capability",
        [.., "root-key-generations"] => "create",
        [.., "root-key-generations", _, "grants"] => "root grant",
        [.., "root-key-generations", _, "grants", _] => "read back",
        [.., "root-key-generations", _, "grants", _, "ack"] => "root ack",
        [.., "root-key-generations", _, "activate"] => "activate",
        [.., "key-generations", _, "grants"] => "recovery grant",
        [.., "key-generations", _, "ack"] => "recovery ack",
        _ => return format!("{method} {path}"),
    };
    name.to_string()
}

fn has(e: &anyhow::Error, key: &str) -> bool {
    crate::errcode::has_code(&e.to_string(), key)
}

/// RR step 5: the capability grant, the create, the RotationGrant read back
/// and acked, each retained generation's recovery grant and its ack, and
/// the activation, in that order; then the RotationGrant is current.
#[test]
fn root_rotation_files_capability_create_grant_ack_recovery_grants_and_activation_in_order() {
    let mut f = rotating();
    f.rotate().unwrap();
    let order: Vec<String> = f
        .calls()
        .iter()
        .map(|(c, _)| rr_short(c))
        .filter(|c| !c.starts_with("GET "))
        .collect();
    let want = [
        "capability",
        "create",
        "root grant",
        "read back",
        "root ack",
        "recovery grant",
        "recovery ack",
        "recovery grant",
        "recovery ack",
        "activate",
    ];
    assert_eq!(order, want);
    // The capability is tenant-wide key.rotate to this device.
    let capability = &f.posts()[0].1;
    match AuthorizationRecord::parse(capability)
        .unwrap()
        .verify_signature(signer().verifying_key().as_bytes())
        .unwrap()
        .payload()
    {
        Payload::TenantCapabilityGrant(g) => {
            assert_eq!(
                g.capability,
                shardx_core::authz_record::Capability::KeyRotate
            );
            assert_eq!(
                g.scope_kind,
                shardx_core::authz_record::CapabilityScopeKind::Tenant
            );
        }
        other => panic!("{other:?}"),
    }
    let run = f.run();
    assert!(run.done && run.trk_nonce.is_empty());
    assert_eq!(run.generation, 1);
    assert_eq!(run.recovery_requests.len(), 2);
}

/// RR step 2: a retained generation whose recovery grant under the ACTIVE
/// root does not open (here: none is listed) stops the run before anything
/// is saved or filed.
#[test]
fn root_rotation_refuses_before_filing_when_a_retained_fleet_key_does_not_open() {
    let mut f = rotating();
    // Generation 0's recovery grant wraps under another key.
    f.server.lock().unwrap().evidence[8] =
        recovery_grant_of(&signer(), 0, &FK0, &[0x77; 32], 0, START + DAY);
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationMissingFleetKey"), "{err}");
    assert!(err.to_string().contains("generation=0"), "{err}");
    assert!(f.posts().is_empty());
    assert!(f.state.root_rotation.is_none());
    assert!(f.vault.0.lock().unwrap().is_empty());
}

/// D7: the retained keys come from the evidence, opened with the old TRK,
/// even when this device holds none of them; a held key that differs from
/// the evidence's stops the run.
#[test]
fn root_rotation_unwraps_retained_keys_from_evidence_with_the_old_trk() {
    let mut f = rotating();
    f.local[1] = (1, Zeroizing::new([0x66; 32]));
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationMissingFleetKey"), "{err}");
    assert!(f.posts().is_empty());

    f.local.clear();
    f.rotate().unwrap();
    let new_trk = f.new_trk();
    let (_, bundle) = open(&std::fs::read(&f.path).unwrap(), RR_PASS).unwrap();
    let held: Vec<(u64, [u8; 32])> = bundle
        .retained_fkeks
        .iter()
        .map(|r| (r.generation, *r.fkek))
        .collect();
    assert_eq!(held, vec![(0, FK0), (1, FK1)]);
    assert_eq!(*bundle.trk, *new_trk);
    // Each filed recovery grant opens with the new TRK, never the old one.
    let filed: Vec<RecoveryGrantV2> = f
        .posts()
        .iter()
        .filter(|(c, _)| rr_short(c) == "recovery grant")
        .map(|(_, body)| {
            let request = IdempotentMutationRequestV2::parse(body).unwrap();
            let container = shardx_core::fleet_lifecycle::FleetKeyGrantCreateV2::parse(
                &request.canonical_payload_bytes,
            )
            .unwrap()
            .exact_signed_grant_container_bytes;
            match AuthorizationRecord::parse(&container)
                .unwrap()
                .verify_signature(signer().verifying_key().as_bytes())
                .unwrap()
                .payload()
            {
                Payload::RecoveryGrant(g) => g.clone(),
                other => panic!("{other:?}"),
            }
        })
        .collect();
    assert_eq!(filed.len(), 2);
    for (g, fkek) in filed.iter().zip([FK0, FK1]) {
        assert_eq!(g.recipient_root_generation, 1);
        assert_eq!(*g.open_fkek(&new_trk).unwrap(), fkek);
        assert!(g.open_fkek(&OLD_TRK).is_err());
    }
}

/// D7: a recovery grant from a key the chain never counted as a custodian
/// is not a source, even though it opens.
#[test]
fn root_rotation_ignores_a_recovery_grant_from_an_uncounted_issuer() {
    let mut f = rotating();
    let stranger = Ed25519SigningKey::from_bytes(&[0x5e; 32]);
    {
        let mut s = f.server.lock().unwrap();
        s.evidence[9] = recovery_grant_of(&stranger, 1, &FK1, &OLD_TRK, 0, START + DAY);
        s.keys.push(stranger.verifying_key().to_bytes());
    }
    f.local.clear();
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationMissingFleetKey"), "{err}");
    assert!(err.to_string().contains("generation=1"), "{err}");
    assert!(f.posts().is_empty());
}

/// RR step 4: the bundle is on disk, reads back and opens, before the create
/// that pins its hash; it carries the new TRK, every retained key and this
/// device's own RotationGrant.
#[test]
fn root_rotation_writes_and_pins_the_bundle_before_create() {
    let mut f = rotating();
    f.rotate().unwrap();
    let at_create = f.server.lock().unwrap().bundle_at_create.clone().unwrap();
    let run = f.run();
    let (create, _) = saved(&run.create_request).unwrap();
    let target = TenantRootGenerationCreateV2::parse(&create.canonical_payload_bytes)
        .unwrap()
        .target;
    assert_eq!(
        recovery_bundle_sha256(&at_create),
        target.recovery_bundle_sha256
    );
    assert_eq!(
        hex(&target.recovery_bundle_sha256),
        f.state.recovery_bundle_sha256
    );
    assert_eq!(f.state.recovery_path, f.path.to_string_lossy());
    let (header, bundle) = open(&at_create, RR_PASS).unwrap();
    assert_eq!(header.root_generation, 1);
    assert_eq!(*bundle.trk, *f.new_trk());
    assert_eq!(bundle.retained_fkeks.len(), 2);
    let c = bundle.root_custodian.unwrap();
    assert_eq!(hex(&c.root_grant), run.root_grant);
    assert_eq!(
        c.root_grant_issuer,
        Some(signer().verifying_key().to_bytes())
    );
}

/// Every step's reply is lost once (the server kept the request): each
/// resumed run resends exactly the saved bytes.
#[test]
fn root_rotation_resumes_each_step_with_byte_identical_requests() {
    let mut f = rotating();
    f.server.lock().unwrap().lose_each = true;
    let mut failures = 0;
    while f.rotate().is_err() {
        failures += 1;
        assert!(failures <= 9, "too many failed runs");
    }
    assert_eq!(failures, 9);
    let mut by_path: std::collections::BTreeMap<String, Vec<Vec<u8>>> = Default::default();
    for (call, body) in f.posts() {
        by_path.entry(call).or_default().push(body);
    }
    assert_eq!(by_path.len(), 9);
    for (call, bodies) in by_path {
        assert_eq!(bodies.len(), 2, "{call}");
        assert_eq!(bodies[0], bodies[1], "{call}");
    }
    assert!(f.run().done);
}

/// A create whose reply was lost is resent byte-identical, and a saved run
/// is never built again: one create request, ever.
#[test]
fn root_rotation_never_files_two_creates() {
    let mut f = rotating();
    f.server.lock().unwrap().refuse = Some(("/root-key-generations/1/grants", 503, "BUSY"));
    assert!(f.rotate().is_err());
    let saved_create = f.run().create_request;
    f.rotate().unwrap();
    assert_eq!(f.run().create_request, saved_create);
    let creates: Vec<Vec<u8>> = f
        .posts()
        .into_iter()
        .filter(|(c, _)| rr_short(c) == "create")
        .map(|(_, b)| b)
        .collect();
    assert_eq!(creates.len(), 1);
    assert_eq!(hex(&creates[0]), saved_create);
}

/// A create refused because another root generation is PREPARING ends as
/// `fleet.rootRotationStuck`; the run stays saved and resumes once the
/// operator discarded it.
#[test]
fn a_root_prepare_refusal_ends_as_root_rotation_stuck() {
    let mut f = rotating();
    f.server.lock().unwrap().refuse =
        Some(("/root-key-generations", 409, "ROOT_GENERATION_MISMATCH"));
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationStuck"), "{err}");
    assert_eq!(f.run().step, 1);
    f.rotate().unwrap();
    assert!(f.run().done);
}

/// D-5: an activation refused because a fleet generation has no recovery
/// grant under the new root (a stuck PREPARING one) waits; the run resumes
/// with the same activation once it is discarded.
#[test]
fn an_activation_blocked_by_a_preparing_fleet_generation_waits_and_resumes() {
    let mut f = rotating();
    f.server.lock().unwrap().refuse = Some(("/activate", 409, "ROOT_GENERATION_MISMATCH"));
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationWaitsForFleetDiscard"), "{err}");
    assert!(crate::root_rotation::unfinished(&f.state));
    f.rotate().unwrap();
    let activations: Vec<Vec<u8>> = f
        .posts()
        .into_iter()
        .filter(|(c, _)| rr_short(c) == "activate")
        .map(|(_, b)| b)
        .collect();
    assert_eq!(activations.len(), 2);
    assert_eq!(activations[0], activations[1]);
    assert!(f.run().done);
}

/// A fleet generation the evidence shows above the ACTIVE one is PREPARING:
/// the run refuses before the root create, with nothing saved.
#[test]
fn root_rotation_refuses_before_create_while_a_fleet_generation_is_preparing() {
    let mut f = rotating();
    f.server.lock().unwrap().evidence.push(recovery_grant_of(
        &signer(),
        2,
        &[0x52; 32],
        &OLD_TRK,
        0,
        START + 2 * DAY,
    ));
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationWaitsForFleetDiscard"), "{err}");
    assert!(f.posts().is_empty());
    assert!(f.state.root_rotation.is_none());
}

/// A quarantined fleet grant refuses the whole D-5 check: its own code, not
/// the wait for a discard, and the run stays resumable.
#[test]
fn an_activation_blocked_by_a_quarantined_fleet_grant_has_its_own_code() {
    let mut f = rotating();
    f.server.lock().unwrap().refuse = Some(("/activate", 422, "AUTH_CLAIM_COLUMN_MISMATCH"));
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationBlockedByQuarantine"), "{err}");
    assert!(
        !has(&err, "fleet.rootRotationWaitsForFleetDiscard"),
        "{err}"
    );
    assert!(crate::root_rotation::unfinished(&f.state));
    f.rotate().unwrap();
    assert!(f.run().done);
}

/// D2: once the operator discarded `N + 1`, the next step finds its grant
/// gone: the run is cleared and the new TRK forgotten, so Start begins anew.
#[test]
fn a_discarded_root_generation_clears_the_run_and_releases_the_new_trk() {
    let mut f = rotating();
    f.server.lock().unwrap().refuse = Some(("/key-generations/0/grants", 503, "BUSY"));
    assert!(f.rotate().is_err());
    assert_eq!(f.run().step, 4);
    assert_eq!(f.vault.0.lock().unwrap().len(), 1);
    f.server.lock().unwrap().discarded = true;
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationDiscarded"), "{err}");
    assert!(f.state.root_rotation.is_none());
    assert!(f.vault.0.lock().unwrap().is_empty());
    assert!(f.state.root_grant.is_empty(), "root 0 stays current");
}

/// A crash while a discarded run is cleared: its one save fails after the
/// new TRK was forgotten, and the next run reopens that TRK from the saved
/// RotationGrant, finds the generation discarded and clears the run.
#[test]
fn a_failed_save_while_clearing_a_discarded_run_resumes_into_the_same_discard() {
    let mut f = rotating();
    f.server.lock().unwrap().refuse = Some(("/key-generations/0/grants", 503, "BUSY"));
    assert!(f.rotate().is_err());
    f.server.lock().unwrap().discarded = true;
    let err = f
        .rotate_saving(&mut |s| match s.root_rotation {
            None => Err(anyhow!("disk full")),
            Some(_) => Ok(()),
        })
        .unwrap_err();
    assert!(!has(&err, "fleet.rootRotationDiscarded"), "{err}");
    assert!(crate::root_rotation::unfinished(&f.state));
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationDiscarded"), "{err}");
    assert!(f.state.root_rotation.is_none());
    assert!(f.vault.0.lock().unwrap().is_empty());
}

/// A credential store that lost the new TRK mid-run (a wiped keyring): the
/// run reopens it from its saved RotationGrant and finishes.
#[test]
fn a_new_trk_the_store_lost_mid_run_reopens_from_the_rotation_grant() {
    let mut f = rotating();
    f.server.lock().unwrap().refuse = Some(("/key-generations/0/grants", 503, "BUSY"));
    assert!(f.rotate().is_err());
    let id = f.run().root_key_id;
    f.vault.0.lock().unwrap().clear();
    f.rotate().unwrap();
    assert!(f.run().done);
    assert_eq!(f.run().root_key_id, id);
    assert_eq!(hex(&root_key_id(&f.new_trk())), id);
    assert!(f.vault.0.lock().unwrap().is_empty(), "released after activation");
}

/// A bundle moved away stops the run before activation; once the operator
/// discarded the generation, the server is asked and the run is cleared.
#[test]
fn a_discarded_generation_whose_bundle_was_moved_still_clears_the_run() {
    let mut f = rotating();
    f.server.lock().unwrap().refuse = Some(("/activate", 409, "ROOT_GENERATION_MISMATCH"));
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationWaitsForFleetDiscard"), "{err}");
    std::fs::remove_file(&f.path).unwrap();
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.recoveryBundleChanged"), "{err}");
    assert!(crate::root_rotation::unfinished(&f.state));
    f.server.lock().unwrap().discarded = true;
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationDiscarded"), "{err}");
    assert!(f.state.root_rotation.is_none());
    assert!(f.vault.0.lock().unwrap().is_empty());
}

/// Root N's bundle is never written over by the rotation away from it.
#[test]
fn a_root_rotation_refuses_to_write_over_the_current_recovery_bundle() {
    let mut f = rotating();
    std::fs::write(&f.path, b"root 0 bundle").unwrap();
    f.state.recovery_path = f.path.to_string_lossy().into_owned();
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.rootRotationBundlePathInUse"), "{err}");
    assert!(f.posts().is_empty());
    assert!(f.state.root_rotation.is_none());
    assert_eq!(std::fs::read(&f.path).unwrap(), b"root 0 bundle");
}

/// Q-62: the evidence is read through the multi-listing path, naming this
/// device's signer.
#[test]
fn root_rotation_reads_its_evidence_through_the_ledger_listings() {
    let mut f = rotating();
    f.rotate().unwrap();
    let own = signing_key_id(signer().verifying_key().as_bytes());
    let named = format!("/trust-evidence?signer={}", hex(&own));
    assert!(f.calls().iter().any(|(c, _)| c.contains(&named)));
}

/// v2.10 U6: a root custodian that handed its custody over never rotates.
#[test]
fn a_handed_over_root_cannot_rotate_the_root() {
    let mut f = rotating();
    f.custody.handed_over_to = hex(&[0x0c; 16]);
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.custodyHandedOver"), "{err}");
    assert!(f.calls().is_empty());
    assert!(f.state.root_rotation.is_none());
}

/// A member holds no activated root state of its own.
#[test]
fn a_member_cannot_rotate_the_root() {
    let mut f = rotating();
    f.state = BootstrapState::default();
    let err = f.rotate().unwrap_err();
    assert!(has(&err, "fleet.notCustodian"), "{err}");
    assert!(f.calls().is_empty());
}

/// RR step 6: the RotationGrant of `N + 1` is the current root grant, with
/// the new bundle and the fleet rotation it asks for, and no TRK copy is
/// left in the store.
#[test]
fn after_activation_the_current_grant_is_the_rotation_grant_and_the_old_trk_is_released() {
    let mut f = rotating();
    f.rotate().unwrap();
    let (grant, container, issuer) = current_root_grant(&f.state, &signer()).unwrap();
    assert_eq!(hex(&container), f.run().root_grant);
    assert_eq!(issuer, signer().verifying_key().to_bytes());
    assert_eq!(grant.root_generation, 1);
    assert!(matches!(
        grant.variant,
        RootGrantVariant::RotationGrant {
            previous_root_generation: 0,
            ..
        }
    ));
    let new_trk = f.new_trk();
    assert_ne!(*new_trk, OLD_TRK);
    assert_eq!(grant.root_key_id, root_key_id(&new_trk));
    assert!(f.vault.0.lock().unwrap().is_empty());
    assert!(f.state.trk_ref.is_empty());
    assert_eq!(f.state.fleet_rotation_due_after_root, Some(1));
    let status = BootstrapStatus::of(&f.state);
    assert!(!status.root_rotation_unfinished && status.fleet_rotation_due);
}

/// Renewal then files an `ExistingRootGrant` of the new generation (F5).
#[test]
fn renewal_after_a_root_rotation_files_an_existing_root_grant_for_the_new_generation() {
    let mut f = rotating();
    f.rotate().unwrap();
    let (signer, account) = (signer(), hex(&[4; 16]));
    let me = RenewingDevice {
        account_id: &account,
        signer: &signer,
        hpke_seed: &HPKE_SEED,
    };
    let cx = renewal_context(&f.state, &me).unwrap();
    let t = START + 20 * DAY;
    let run =
        f.rt.block_on(build_renewal(
            &f.client,
            "access",
            &cx,
            &me,
            &f.state,
            t,
            &|_| Ok(Zeroizing::new(FK1)),
        ))
        .unwrap();
    let container = unhex_vec(&run.root_grant).unwrap();
    let (grant, _) = verified_root_grant(&container, signer.verifying_key().as_bytes()).unwrap();
    assert_eq!(grant.variant, RootGrantVariant::ExistingRootGrant);
    assert_eq!(grant.root_generation, 1);
    assert_eq!(grant.root_key_id, root_key_id(&f.new_trk()));
}

/// Export again after the rotation writes v4 under root 1, holding the new
/// TRK and the RotationGrant from this device.
#[test]
fn export_after_a_root_rotation_writes_v4_with_the_new_trk() {
    let mut f = rotating();
    f.rotate().unwrap();
    let grant = unhex_vec(&f.state.root_grant).unwrap();
    let (header, plaintext) = export_again_from(&f.state, &grant, &signer());
    assert_eq!(header.root_generation, 1);
    assert_eq!(*plaintext.trk, *f.new_trk());
    let c = plaintext.root_custodian.unwrap();
    assert_eq!(c.root_grant, grant);
    assert_eq!(
        c.root_grant_issuer,
        Some(signer().verifying_key().to_bytes())
    );
}

/// No key is among the rotation state, mid-run or finished: not the old or
/// new TRK, a fleet key or a seed.
#[test]
fn the_root_rotation_state_holds_no_key_bytes() {
    let mut f = rotating();
    CRASH_AFTER_STEP.with(|c| c.set(4));
    let err = f.rotate().unwrap_err();
    let mid = serde_json::to_string(&f.state).unwrap();
    let mid_trk = *f.vault.0.lock().unwrap().values().next().unwrap();
    f.rotate().unwrap();
    let done = serde_json::to_string(&f.state).unwrap();
    let debug = format!("{:?}", f.state);
    let new_trk = *f.new_trk();
    assert_eq!(mid_trk, new_trk);
    let secrets = [signer().to_bytes(), HPKE_SEED, OLD_TRK, new_trk, FK0, FK1];
    for text in [mid, done, debug, err.to_string()] {
        for secret in secrets {
            assert!(!text.contains(&hex(&secret)), "a key in the state");
        }
    }
}
