# ShardBrowser v0.2.x — Team/Fleet Sync và Encrypted Profile Backup

> **Trạng thái:** Consensus-approved design (Architect `APPROVE` → Critic `APPROVE`); G2 chưa chạy; non-production-ready
>
> **Vai trò tài liệu:** RALPLAN deliberate / PRD / ADR / execution handoff
>
> **Phạm vi lượt hiện tại:** Chỉ thiết kế và lập kế hoạch; không sửa code, commit, push, tag hoặc release
>
> **Baseline bảo toàn:** ShardBrowser v0.1.28; local profile JSON là source of truth; đúng 96 MCP tools hiện hữu không đổi

## Change log — 2026-08-14

- Sửa toàn bộ P0 và contract-level P1 từ `architect-review-v1.md`: trust model, authenticity/signing plane, tenant RBAC/root custody, upload crash consistency và safe downgrade.
- Khóa strict envelope/archive contracts, single-current-lease/server-time semantics, key-generation lifecycle, idempotency retention, executable local DDL và full 96-tool schema fixture.
- Thêm dependency/security pre-phase; xác định v0.2.0 là internal foundation và Windows là Team runtime đầu tiên. Không thêm transparency service, distributed consensus hoặc CRDT.
- Revision pass 2 đóng Architect findings 17–21: tách pre-encryption `EnvelopeIntentV2` khỏi post-encryption signed `SnapshotManifestV2`; dùng một snapshot DEK slot dưới immutable FKEK generation; bổ sung recovery matrix không treo `FINALIZING`; sửa local workflow DDL/probes; và khóa downgrade clone/full-restore/`RestoreEpochTransitionV2` thành ba contract riêng.
- Revision pass 3 đóng findings 22–25: exact signed authorization claims + indexed-column equality; tenant-scoped multi-profile restore-epoch proofs trên server-global epoch; durable exact manifest/request replay qua close/reopen; và tách G0–G7 implementation completion khỏi production-operator gate.
- Revision pass 4 đóng `architect-review-v4.md`: khóa provider-independent field schemas cho năm authorization records, exact `SignedSnapshotManifestV2`/`CommitRequestV2`/`CommitReceiptBindingV2` byte containers, HPKE byte-to-column equality, và thứ tự handoff Architect → Critic → G2 spike → verifier PASS → production implementation.
- Revision loop 5 đóng `architect-review-v5.md`: bind local replay rows vào exact `server_instance_id`/`restore_epoch`; chọn checksummed/fsync'd external epoch record ngoài SQLite rollback làm authority và `v2_server_state` chỉ là mirror; chặn mọi SQLite-backed unsigned wire integer ngoài `0..i64::MAX`; đồng bộ durable consensus → G2 → verifier → production handoff và thay stale v0.1.27 goal bằng superseded pointer.
- Planner revision v6 đóng năm Critic blockers: exact golden-ready contracts cho slot/intent/restore-transition/Merkle proof; exact `TenantRootKeyGrantV2` + HPKE/bootstrap/rotation/revocation/readback; canonical idempotent request/stored-response contracts cho publish/checkout/upload/finalize/release/unbind; minimal trusted-control-plane repair; và manifest/key-generation schema + migration probes đồng bộ theo `server_instance_id`.
- Planner patch v6.1 chỉ đóng hai Architect blockers còn lại: pin exact base-mode HPKE suite/AAD/TRK/root-key-ID bytes + `ROOT_GRANT_CREATE` replay contract/readback-by-replay-ID; và làm mọi fleet-generation grant/upload/snapshot relation thành exact composite UNIQUE/FK có executable migration probes.

## Architect review closure matrix

| Review item | Contract đã sửa | Plan sections |
|---|---|---|
| P0.1 Trust model | Trusted coordinator process + live coordination/RBAC SQLite integrity; artifact ciphertext/signed bytes trong DB/blob/log/backup không được trust cho confidentiality/artifact integrity; active malicious control plane ngoài guarantee | 2.1, 5, 12, 17, 19 |
| P0.2 Signing/authenticity | Distinct signing + HPKE keys/IDs, PoP, OOB bootstrap, signed grants/manifests/heads | 5.5, 7.1–7.2, 9.1, 19 |
| P0.3 RBAC/root custody | owner/admin/member + explicit capabilities; root custody riêng; capability+audit transaction | 4.2, 7.1, 7.4, 8.1 |
| P0.4 Blob/SQLite crash consistency | Executable PATCH/finalize/commit/fsync/recovery ordering + crash points | 6.2, 8.1, 17 |
| P0.5 Safe downgrade | No old-binary ignore; unbind/clone hoặc complete pre-v2 restore; instance/epoch quarantine | 12.4–12.5, 19 |
| P1.1 Strict envelope | Immutable bounded grammar, canonical intent + exactly one DEK slot, final/counter/trailing rejects | 9.2–9.3 |
| P1.2 Lease | One current row, server time, no relaunch grace | 7.3–7.4, 10.1 |
| P1.3 Generations | `PREPARING -> ACTIVE -> RETIRED`, all-grant exact-byte readback, revoke+activate logical op | 7.2, 9.6 |
| P1.4 Idempotency | Canonical scope/hash, retention floor, explicit chunk digest, HEAD/resume | 8.1, 10.2 |
| P1.5 Local DB | Executable singleton/canonical-origin/PK/FK/UNIQUE/CHECK/recovery-journal DDL | 11.1 |
| P1.6 Strict v2 archive | Unsupported/duplicate/case-fold/ADS/reserved/file-dir rejects; v1 preserved | 9.4, 17.1 |
| P1.7 Full contracts | 96 full descriptors + fixture SHA-256, OpenAPI v2 và stable HTTP/error mapping | 8.2–8.3, 15, 17 |
| P1.8 Pre-phase/release scope | Dependency/security/durability gate; v0.2.0 internal; Windows-first Team runtime | 14, 17, 18 |
| 17 Commitment cycle | `EnvelopeIntentV2` trước encrypt; frames bind `intent_hash`; detached exact `SignedSnapshotManifestV2` sau encrypt, không back-reference từ envelope | 5.5–5.6, 6.2–6.3, 7.3–7.4, 8.1, 9.2–9.3, 17, 19 |
| 18 Authoritative slot model | Một `DekSlotV2` dưới immutable FKEK generation; canonical signed HPKE FKEK grants nằm ngoài envelope và được persist full bytes | 5.4–5.5, 7.2–7.4, 8.1, 9.1–9.2, 11.1, 17, 19 |
| 19 Upload recovery matrix | Exhaustive precedence/matrix cho `OPEN`/`FINALIZING`/`READY`/`COMMITTED`/`QUARANTINED`, object validity và exact receipt; mọi `FINALIZING` kết thúc deterministic | 8.1, 13, 17, 19 |
| 20 Local workflow DDL | Unbind receipt survives binding delete; `RELEASE`; resumable-upload/exact bytes; instance-keyed root/fleet generations; eleven workflow probes | 11.1–11.3, 14–17, 19 |
| 21 Downgrade/restore | Original moved khỏi mọi v0.1.28 discovery path; clone ID mới; full pre-v2 restore riêng; root-signed epoch transition | 5.5, 8.1–8.2, 11.1–11.2, 12.3–12.5, 17, 19 |
| 22 Exact signed authorization claims | Năm record types persist exact payload/container bytes+hashes, signature metadata/bytes và typed fields; authorization/key release/rotation verify full container và exact indexed-column equality | 5.5–5.6, 7.1–7.4, 8.1–8.2, 9.1, 11.1, 17, 19 |
| 23 Tenant/profile-aware restore epoch | Server-global monotonic epoch; tenant-scoped `RestoreEpochTransitionV2` keyed by instance/tenant/previous/new epoch; canonical multi-profile head-set commitment + per-binding inclusion proof; cross-tenant reject | 5.5, 7.2–7.4, 8.1–8.2, 11.1–11.2, 12.4–12.5, 17, 19 |
| 24 Durable manifest replay | Exact `SignedSnapshotManifestV2` + `CommitRequestV2` durably persisted before finalize/commit; exact `CommitReceiptBindingV2` persisted transactionally; server/local close/reopen replay request/receipt byte-identically | 5.6, 6.2, 7.3–7.4, 8.1, 10.2, 11.1–11.3, 17, 19 |
| 25 Definition of done | G0–G7 define implementation completion; production operator/drills are a separate `P-OP` gate; blocked `P-OP` requires non-production-ready labeling and forbids release/tag/publish/production migration | 14, 17–19, 21–22 |
| V4.1 Canonical authorization byte schemas | Exact domain/version/field/type/optionality/replay/validity contracts cho `DeviceApprovalV2`, `TenantCapabilityGrantV2` và ba `FleetKeyGrantV2` variants; signed-container construction và full payload-to-column equality gồm HPKE suite/encapped/wrapped bytes | 5.6, 7.1–7.4, 8.1, 9.1, 11.1, 17, 19 |
| V4.2 Manifest/commit/receipt byte schemas | Exact `SignedSnapshotManifestV2`, `CommitRequestV2`, `CommitReceiptBindingV2`; server/local persist exact bytes + internal/external hashes; restart replays stored request/receipt byte-for-byte | 5.6, 6.2–6.3, 7.3–7.4, 8.1, 10.2, 11.1–11.3, 17, 19 |
| V4.3 Handoff order | Architect accept rồi Critic approve; bounded research/dependency/durability lane chạy G2; production executor chỉ được staff sau independent verifier PASS; goal coordinate spike và stop khi G2 fail/blocked | 0, 14, 17–20, 22 |
| V5.1 Replay-row instance/epoch binding | Local `operations` và `upload_sessions` persist `server_instance_id` + `restore_epoch`, dùng composite FK để COMMIT/upload không cross-instance/epoch; exact request/container bytes vẫn là authority và mọi column mismatch fail closed | 5.6, 7.3–7.4, 8.1–8.2, 11.1–11.2, 17, 19, 21 |
| V5.2 Restore-epoch authority | Checksummed/fsync'd external identity record ngoài SQLite rollback scope là authority; `v2_server_state`/`server_origins.last_restore_epoch` chỉ mirror/cache; explicit prepare → external replace/fsync → DB install/open/reconcile ordering và crash table | 5.5, 7.1–7.4, 11.2–11.3, 12.1, 12.4–12.5, 17, 19, 21 |
| V5.3 SQLite integer domain | Mọi unsigned wire integer persisted vào SQLite decode và schema-check trong `0..9223372036854775807`; over-i64 vectors reject trước cast/insert; future full-U64 cần versioned BLOB/text encoding | 5.6, 7.4, 8.2, 11.1, 17, 19, 21 |
| V5.4 Durable handoff/no stale goal | Chỉ durable Architect+Critic consensus mới mở bounded G2; independent verifier PASS mới mở production implementation; stale goal là pointer v0.1.28, không còn v0.1.27 implementation/release authority | 0, 14, 17–22; `docs/NEXT_V0.2_X_GOAL.md` |
| C6.1 Exact envelope/restore bytes | Closed-map field/type/bound/optionality/domain/version/hash/TBS/container contracts cho `DekSlotV2`, `EnvelopeIntentV2`, `RestoreEpochTransitionV2` và deterministic Merkle inclusion proof; explicit leaf/node/unary domains, order/duplicate/empty/direction rules | 5.6.3, 9.2, 12.4, 17, 19 |
| C6.2 Tenant root-key grant | Exact `TenantRootKeyGrantV2` payload trong `SignedAuthorizationRecordV2`, deterministic HPKE info, root-generation/grant endpoints, first self-grant/rotation/revoke/readback/all-column equality và tests | 5.6.4, 7.2, 8.1, 9.1, 9.6, 11.1, 17, 19 |
| C6.3 Mutation idempotency | Exact common request/stored-response container + operation payload/response schemas cho profile publish-create, checkout, create-upload, finalize, release và local unbind; response-loss replay; no second checkout lease/fence; publish atomically acquires initial lease | 4.5–4.6, 5.6.5, 7.3–7.4, 8.1, 10.2, 11.1, 17, 19 |
| C6.4 Minimal trust repair | Coordinator process và live coordination/RBAC SQLite integrity là trusted control plane; DB/blob/log backups chỉ là untrusted artifact stores; explicit malicious DB/rollback limits, không thêm signed auth transparency | 2.1–2.6, 5, 12.4, 17–19 |
| C6.5 Manifest/key schema parity | `snapshot_id` + `manifest_replay_id` immutable/indexed/unique/FK across upload/snapshot; root/fleet generation rows keyed by `server_instance_id`; executable fresh/upgrade migration probes | 5.6.2, 7.2–7.4, 8.1, 11.1, 12.1, 17, 19 |
| C6.6 Root grant golden readiness | Base-mode HPKE tuple/IDs, non-empty domain-separated AAD, raw 32-byte TRK plaintext, deterministic root-key-ID preimage, exact `ROOT_GRANT_CREATE` request/stored response và deterministic readback by `replay_id` | 5.6.4–5.6.5, 7.2–7.4, 8.1, 11.1, 17, 19 |
| C6.7 Executable fleet-generation relations | Exact generation candidate UNIQUE; all fleet grant/upload/snapshot rows carry instance/fleet/generation/key identity and composite FK; migration probes assert exact columns/index/FK tuples | 7.2–7.4, 12.1, 17, 19 |

## 0. Kết quả cần đạt và điểm dừng

Thiết kế v0.2.x phải cho phép một người dùng hoặc một team:

1. Đăng ký thiết bị và tham gia tenant/fleet theo cơ chế opt-in.
2. Checkout độc quyền một profile với lease, `base_version` và fencing token tăng đơn điệu.
3. Backup/check-in profile theo luồng streaming: canonical `EnvelopeIntentV2` được khóa trước encrypt, mọi frame bind `intent_hash`, envelope chỉ có một DEK slot dưới immutable FKEK generation, rồi canonical `SnapshotManifestV2` mới được tạo/ký sau encrypt; coordinator process + live coordination/RBAC SQLite integrity là trusted control plane, còn ciphertext/signed artifact bytes trong DB/blob/log/backup vẫn được client kiểm chứng độc lập.
4. Restore an toàn sang cùng máy hoặc máy khác, reseal secret theo destination, atomic swap và rollback nếu smoke test thất bại.
5. Tiếp tục dùng ShardBrowser local-only như v0.1.28 nếu không bật Team/Fleet; v0.2.0 chỉ là internal foundation và Team runtime đầu tiên chỉ hỗ trợ Windows.

Tài liệu đã đạt **durable design consensus** theo đúng thứ tự Architect `APPROVE` → Critic `APPROVE`. Bounded research/dependency/durability spike lane G2 được phép bắt đầu trong một goal riêng, nhưng chưa chạy trong lượt thiết kế này. Chưa staff hoặc bắt đầu production implementation. Production executor chỉ nhận handoff sau independent verifier readback và verdict G2 `PASS`. Nếu G2 fail/blocked hoặc verifier không PASS, goal dừng tại evidence packet của spike, không chọn primitive thay và không mở v0.2.0. G0–G7 có thể xác nhận implementation completion độc lập với production; khi `P-OP` còn blocked, artifact bắt buộc gắn nhãn **non-production-ready** và không release/tag/publish/production migration. Các giới hạn chống coordinator/control-plane compromise được ghi rõ; v0.2.x không thêm transparency service, distributed consensus hoặc CRDT.

---

## 1. Evidence từ repository và tài liệu chính thức

### 1.1. Hiện trạng đã kiểm tra trong repo

| Khu vực | Evidence hiện tại | Hệ quả thiết kế |
|---|---|---|
| Handoff/runtime | `docs/CODEX_SHARDX_HANDOFF.md` mô tả boundary secret, profile chuẩn và các smoke helper; thông tin release trong file dừng ở v0.1.27, còn baseline v0.1.28 do người dùng xác nhận mới hơn | Không thay wrapper/runtime hiện hành; không dùng profile chuẩn cho thử nghiệm phá hủy; coi v0.1.28 là source of truth |
| Goal v0.2.x | `docs/NEXT_V0.2_X_GOAL.md` là superseded pointer: runtime/baseline v0.1.28 và canonical goal/PRD/ADR/handoff nằm trong plan này; old v0.1.27 text không còn implementation/release authority | Mọi executor phải đọc plan + open questions; pointer không tự cấp execution/release authority |
| Team server | `docs/team-server.md`, `server/src/routes/*`, `server/migrations/*` cho thấy auth/ACL/lock/snapshot/audit đã tồn tại nhưng schema và phần lớn query còn global | Không vá tenant filter rải rác; tạo boundary/repository tenant-aware v2 |
| Lock/check-in | `server/src/routes/locks.rs` dùng UUID lock token và current version; chưa có monotonic fence, `base_version`, idempotency hoặc resumable upload | Cần protocol v2 mới, không mở rộng mơ hồ contract v1 |
| Server data | `server/migrations/0001_init.sql` có `proxies.username/password`, `environments.config_json/notes`; snapshot blob là opaque nhưng comment/test hiện chưa bảo đảm ciphertext | V2 không được ghi plaintext; legacy phải bị quarantine hoặc migrate có kiểm soát |
| Archive safety | `shared/src/snapshot.rs` đã có traversal/symlink/size/decompression guards, staging/backup, recovery và reseal; `pack()`/`unpack()` dùng `Vec<u8>` | Tái sử dụng policy validator và atomic swap, nhưng thêm streaming v2 API thay vì thay contract v1 ngay |
| Portable secrets | `shared/src/portable.rs` chứa cookies, saved logins và web secrets dạng plaintext trong `shardx-portable.json` bên trong tar.gz | Inner archive phải luôn nằm trong encrypted envelope khi rời máy; v2 nên segment portable records để không gom toàn bộ vào RAM |
| Launcher state | `src-tauri/src/store.rs`, `src-tauri/src/profile.rs` lưu profile JSON cục bộ; launcher chưa phụ thuộc `shardx-core` và chưa có durable sync/restore journal | Thêm `team-sync.db` riêng; không migrate toàn bộ local JSON |
| Lifecycle | `src-tauri/src/profile.rs`, `src-tauri/src/launch.rs`, `src-tauri/src/api.rs` đã có common launch claim và running-state guard | Gắn team checkout guard vào common launch boundary thay vì từng UI/API caller |
| UI | `src/App.tsx` là bề mặt lớn, hiện có polling start/stop và các section local | Tạo feature modules Team/Fleet có boundary rõ, chỉ tích hợp mỏng vào `App.tsx` |
| CI | `.github/workflows/ci.yml` chủ yếu kiểm tra launcher/MCP/SDK; server/shared chưa là release gate đầy đủ | Bổ sung server/shared/migration/security/restore gates trước release |
| E2E server | `server/tests/e2e_sync.rs` khóa nhiều behavior v1 nhưng chưa có tenant collision, fencing, base-version, idempotency, encryption, resume hoặc crash matrix | Giữ regression v1 và tạo suite v2 độc lập |

### 1.2. Ràng buộc từ primitives chính thức

- Dùng AEAD streaming từ thư viện đã được review, không tự tạo counter/nonce scheme. RustCrypto cung cấp STREAM framing và XChaCha20-Poly1305: [RustCrypto `aead::stream`](https://docs.rs/aead/latest/aead/stream/struct.StreamLE31.html), [RustCrypto `chacha20poly1305`](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/index.html).
- Device recipient-key wrapping dùng HPKE theo RFC 9180 và signing dùng key/suite riêng đã qua spike; không tự thiết kế hybrid encryption: [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html), [Rust `hpke` crate](https://docs.rs/hpke/latest/hpke/index.html).
- Passphrase fallback dùng Argon2id; mặc định memory-constrained đề xuất phải bám profile của RFC 9106 và được benchmark trên máy đích: [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html).
- SQLite WAL vẫn có một writer, có checkpoint/busy semantics và không phù hợp network filesystem; backup phải dùng online backup API hoặc snapshot nhất quán: [SQLite WAL](https://www.sqlite.org/wal.html), [SQLite Backup API](https://www.sqlite.org/backup.html), [SQLite PRAGMA](https://sqlite.org/pragma.html).

---

## 2. RALPLAN-DR

### 2.1. Product/architecture principles

1. **Local-first, explicit opt-in:** profile local-only và mọi hành vi v0.1.28 tiếp tục hoạt động khi chưa bind vào fleet.
2. **Minimal trusted control plane, untrusted artifact storage:** coordinator process và integrity/freshness của live coordination/RBAC SQLite state được tin cậy để xác thực, phân quyền, revoke, chọn generation và điều phối lease/idempotency. Ciphertext/signed artifact bytes trong DB/blob/log/backup không được tin cậy cho confidentiality hoặc artifact integrity; client vẫn verify exact signed bytes/hash/head. Quyền sửa/rollback live control-plane DB là quyền phá authorization/exclusivity và nằm ngoài guarantee v0.2.x.
3. **Single writer trong trust model đã nêu, fail closed:** một profile chỉ có một current lease row; commit phải dùng server time, lease chưa hết hạn, current fence và exact `base_version`. Coordinator chủ động độc hại có thể equivocate/cấp hai lease hoặc DoS; ngăn tuyệt đối việc đó cần transparency/consensus và nằm ngoài v0.2.x.
4. **Tách encryption khỏi identity/authorization và tránh commitment cycle:** device signing key và HPKE recipient key là hai key pair/key ID riêng; TRK/FKEK/DEK không bao giờ được dùng để ký. Pre-encryption intent không commit post-encryption manifest; final signed manifest chỉ tham chiếu các hashes đã hoàn tất theo một chiều.
5. **Versioned, reversible compatibility:** schema/API/envelope đều versioned; migration additive; restore/rollback được kiểm thử; 96 MCP tools và toàn bộ descriptor schema hiện hữu không đổi.
6. **Evidence before rollout:** dependency/security spike, observability không secret, security/crash/fuzz tests và recovery drill là hard gates chứ không phải follow-up tùy chọn.

### 2.2. Top 3 decision drivers

1. **Confidentiality + artifact authenticity khi artifact stores/backups bị compromise:** ciphertext/signed records trong DB/blob/log/backup không tiết lộ plaintext/key và clients verify exact authorization/grant containers + equality columns, one-slot envelope intent, exact signed snapshot/head chain. Guarantee này giả định live coordination/RBAC SQLite state và coordinator process không bị kẻ tấn công sửa/rollback.
2. **Correctness khi partition, crash, retry và stale writer:** server-time lease/fence/base CAS, deterministic recovery cho mọi DB/object/receipt state, durable PATCH/finalize/commit ordering và exact idempotent receipts không được để mất dữ liệu, treo `FINALIZING` hoặc tự merge.
3. **Khả năng nâng cấp/downgrade mà không cho v0.1.28 bypass Team guard:** local JSON vẫn là source of truth, nhưng binary cũ chỉ được chạy sau explicit unbind, downgrade clone đã move original khỏi mọi discovery path, hoặc full pre-v2 config/profile/user-data restore riêng; server restore cần root-signed epoch transition và 96-tool contract phải được so toàn descriptor.

### 2.3. Các phương án khả thi

#### Phương án A — Tenantize in-place toàn bộ v1 schema/routes

**Cách làm:** thêm `tenant_id` vào các bảng hiện tại, đổi mọi primary/foreign key, update toàn bộ query v1 và tái sử dụng `/v1`.

**Ưu điểm**
- Ít bảng và ít route bị trùng về dài hạn.
- Không duy trì hai control plane lâu.

**Nhược điểm/rủi ro**
- Dễ bỏ sót một query global và gây cross-tenant disclosure.
- Phải xử lý ngay plaintext proxy/config legacy trong cùng migration.
- Rollback khó; v0.1.28 có thể đọc schema/data ở trạng thái không còn tương thích.
- Khó giữ nguyên regression contract v1 trong một lượt thay đổi lớn.

#### Phương án B — Additive v2 control plane + local `team-sync.db` riêng

**Cách làm:** giữ v1 không đổi để regression/rollback; thêm bảng và `/v2` tenant-scoped; launcher vẫn giữ profile JSON, chỉ lưu binding, lease, outbox và restore journal trong SQLite riêng.

**Ưu điểm**
- Boundary tenant rõ; có thể dùng composite keys từ đầu.
- Dễ canary, feature flag, rollback và so sánh v1/v2.
- Không buộc migrate local JSON hoặc 96 MCP tools.
- Cho phép envelope/protocol mới mà không làm mơ hồ contract snapshot v1.

**Nhược điểm/rủi ro**
- Tồn tại code/schema song song trong v0.2.x.
- Cần quy tắc quarantine legacy rõ để không tuyên bố sai rằng toàn server không có plaintext.
- Có chi phí xóa v1 ở phiên bản sau, ngoài scope v0.2.x.

#### Phương án C — Service/database Team Sync tách hoàn toàn khỏi server v1

**Cách làm:** tạo binary/service và DB mới, launcher nói chuyện với endpoint riêng; server v1 không đổi.

**Ưu điểm**
- Blast radius thấp nhất; security boundary dễ audit.
- Rollback chỉ cần tắt service mới.

**Nhược điểm/rủi ro**
- Tăng deployment, auth, monitoring và support burden.
- Trùng hạ tầng Axum/SQLite/auth/audit.
- Không phù hợp quy mô self-hosted v0.2.x nếu chưa cần scale độc lập.

### 2.4. Quyết định đề xuất

**Chọn Phương án B.** Đây là điểm cân bằng tốt nhất giữa tenant isolation, rollback và effort hiện tại.

Các ràng buộc bắt buộc của lựa chọn:

- V2 dùng repository/service tenant-aware; route không tự viết raw SQL ngoài boundary này.
- Tất cả FK nhận diện tài nguyên v2 phải bao gồm `tenant_id`.
- V1 không được dùng cho Team/Fleet mới. Remote v1 bị tắt mặc định; legacy data được đánh dấu/quarantine.
- Không tự động import hoặc xóa dữ liệu v1. Migration plaintext legacy chỉ chạy bằng flow riêng, có backup/readback và xác nhận phá hủy sau cùng.
- Local JSON tiếp tục là source of truth; team DB không sao chép toàn bộ profile payload.

### 2.5. Các phương án bị loại như kiến trúc đích

- **Server-managed master key/KMS decrypt server-side:** đơn giản vận hành nhưng vi phạm mục tiêu ciphertext-only và mở rộng trust boundary.
- **Multi-writer/CRDT:** không phù hợp dữ liệu browser profile/SQLite và tăng conflict surface; v0.2.x dùng exclusive checkout.
- **Whole-buffer encryption quanh `Vec<u8>` hiện tại:** chỉ che plaintext trên server nhưng không đáp ứng streaming/large-profile/crash-resume requirement.
- **Transparency service/distributed consensus:** có thể phát hiện/ngăn coordinator equivocation mạnh hơn nhưng vượt nhu cầu self-hosted Windows-first v0.2.x; plan chỉ phát hiện rollback/fork tương đối với signed state client đã quan sát.

### 2.6. ADR record cho quyết định kiến trúc

**Decision:** dùng additive `/v2` control plane trong server hiện có, local `team-sync.db` riêng, client-side streaming encryption với `EnvelopeIntentV2` → one FKEK-wrapped DEK slot → exact detached `SignedSnapshotManifestV2`, fixed authorization payload/container records ngoài envelope, exact mutation request/stored-response bindings và exclusive lease/fencing. Coordinator process + live coordination/RBAC SQLite integrity là trusted control plane tối thiểu; artifact ciphertext/signed bytes trong DB/blob/log/backup vẫn không được trust cho confidentiality/artifact integrity.

**Drivers:** (1) giữ v0.1.28 local-only và 96-tool contract; (2) fail closed khi artifact bytes/blob bị sửa hoặc client stale trong khi nêu rõ live control-plane DB là trust assumption; (3) migration/downgrade có đường phục hồi đầy đủ trên Windows.

**Alternatives considered:** tenantize v1 in-place; tách service/database mới; server-side master key; multi-writer/CRDT; transparency/consensus. Các phương án đầu được phân tích ở 2.3; ba phương án sau bị loại ở 2.5 vì phá trust boundary hoặc vượt scope.

**Why chosen:** boundary `/v2` + DB cục bộ riêng cô lập regression tốt nhất, cho phép protocol/envelope strict từ đầu và vẫn reuse Axum/SQLite/auth/audit hiện hữu.

**Consequences:** phải duy trì v1/v2 song song trong v0.2.x; server/client schema phải lưu exact canonical signed bytes bên cạnh indexed claims và verify chúng khớp; reconciliation phải phân loại toàn bộ object/receipt state; downgrade cần journal + path-discovery proof; Team runtime ban đầu chỉ Windows; active malicious coordinator vẫn ngoài exclusivity guarantee.

**Follow-ups:** Architect re-review revision này; sau Architect `APPROVE`, Critic thực hiện adversarial review; chỉ sau Critic `APPROVE` mới mở G2 dependency/security/durability spike; production implementation chỉ được staff sau verifier xác nhận G2 `PASS`; production release vẫn chờ named operator drill.

---

## 3. Premortem — ba failure scenarios ưu tiên

| Failure scenario | Dấu hiệu sớm | Phòng ngừa bắt buộc | Recovery |
|---|---|---|---|
| **Cross-tenant data leak do thiếu tenant predicate** | Test với cùng UUID ở hai tenant trả cùng tài nguyên; query route chứa raw SQL không qua repository | Composite PK/FK có `tenant_id`; tenant context bắt buộc trong repository API; deny-by-default auth; static grep/lint rule; adversarial E2E collision matrix | Tắt feature flag v2, revoke session/FKEK grants, giữ audit reason code, điều tra snapshot access; không tự động xóa evidence |
| **Stale writer overwrite sau lease expiry/network partition** | Client cũ vẫn upload/commit được; version nhảy không tương ứng fence; retry tạo hai snapshot | Fencing monotonic; unexpired lease check trong cùng commit transaction; `base_version`; idempotency request hash; offline-fork state; không auto takeover/replay | Giữ encrypted pending snapshot; pull snapshot hiện hành hoặc tạo local recovered copy; không merge/overwrite tự động |
| **Restore/downgrade làm hỏng profile hoặc nhận server rollback giả** | Decrypt chỉ thất bại sau swap; clone vẫn để original trong v0.1.28 discovery path; epoch tăng nhưng tenant/profile không có root-signed transition + proof | Key/recovery drill; intent-bound final frame; detached signed manifest; durable restore+downgrade journals; discovery scan/readback; verify tenant-scoped multi-profile `RestoreEpochTransitionV2` và every binding proof; old generations chỉ GC sau restore drill | Atomic rollback metadata+user-data; giữ original ngoài discovery; quarantine đúng tenant/profile tới khi journal, transition và inclusion proof được reconcile |

---

## 4. PRD

### 4.1. Problem statement

ShardBrowser hiện quản lý profile trên một máy. Team cần chia sẻ profile mà không gửi plaintext cookies/secrets/proxy credentials lên server, đồng thời tránh hai máy cùng ghi và tránh làm hỏng profile khi backup/restore hoặc mất mạng.

### 4.2. Personas

- **Owner:** quản lý tenant/membership theo role, nhưng không mặc nhiên là root custodian nếu capability đó chưa được cấp.
- **Admin:** quản lý fleet/device/lease theo explicit capability; deny-by-default và không nhận TRK chỉ vì có role admin.
- **Member/Operator:** checkout, dùng, check-in hoặc release profile được cấp quyền.
- **Root custodian:** thiết bị/người giữ capability tách biệt để bootstrap/recovery/rotation TRK; ordinary fleet devices chỉ nhận FKEK generation được cấp.
- **Local-only user:** không bật Team/Fleet và không thấy regression.
- **Self-hosted operator:** nâng cấp server, giám sát metadata an toàn, backup/rollback DB/blob.

### 4.3. In scope v0.2.x

- Tenant/fleet/account/device enrollment, owner/admin/member RBAC, explicit capabilities và root-custodian boundary tenant-scoped.
- Device signing + HPKE recipient key pairs riêng, proof-of-possession, six exact authorization/key-grant payload/container records ngoài envelope và detached exact signed snapshot/head chain.
- Exclusive profile checkout với lease, renew, fencing và `base_version`.
- Resumable ciphertext upload/download và idempotent commit.
- Streaming encrypted profile backup/restore với cross-machine reseal.
- Per-snapshot DEK với đúng một wrap slot dưới immutable FKEK generation, fleet/team key hierarchy, OS credential store và Argon2id recovery fallback.
- Separate local team-sync SQLite, durable outbox và restore journal.
- Launcher UI cho connect/enroll/checkout/check-in/restore/conflict/recovery.
- Migration/quarantine/rollback cho server và local state.
- Secret-safe observability, security/fuzz/crash tests và release gates.
- Windows-first Team runtime; macOS/Linux tiếp tục local-only tới khi credential-store/platform tests pass.

### 4.4. Non-goals

- Multi-writer, live collaborative browser session, CRDT hoặc semantic merge profile SQLite.
- Server-side decrypt, searchable plaintext labels/config, key escrow bởi server.
- Tự động migrate/xóa dữ liệu server v1 hoặc toàn bộ local profile JSON.
- Thay browser engine, fingerprint engine, proxy model hoặc MCP tool surface.
- Object storage/cloud SaaS/multi-region HA/dedup giữa ciphertext trong v0.2.x.
- Transparency service, distributed consensus hoặc guarantee ngăn active malicious coordinator equivocate/DoS.
- Background auto-checkin sau lease expiry hoặc conflict resolution im lặng.
- Mobile/web client.

### 4.5. User journeys

#### Journey A — Enroll và publish profile lần đầu

1. First owner kết nối HTTPS server, pin `server_instance_id`, tạo device signing key và HPKE recipient key riêng rồi nhận enrollment challenge.
2. Client ký proof-of-possession; first root bootstrap hiển thị fingerprint để xác nhận out-of-band trước khi tạo root-custodian record/TRK. Các device sau cần owner/root-signed approval và key grant.
3. Owner/Admin có capability phù hợp tạo fleet và cấp quyền member; ordinary fleet device nhận canonical root/owner-signed HPKE FKEK grant nằm ngoài snapshot envelope, verify exact signed bytes rồi mới unwrap FKEK; không nhận TRK.
4. Operator chọn local profile đang stopped, chọn **Publish to fleet**. Client gửi exact `ProfilePublishCreateRequestV2`; một coordinator transaction duy nhất create remote profile version `0`, cấp initial lease/fence/base, persist exact stored response + audit rồi mới trả. Response loss/retry cùng exact key trả cùng lease/fence, không create profile hay fence thứ hai.
5. Client claim local profile dưới initial lease, tạo exact `DekSlotV2` + canonical `EnvelopeIntentV2` trước encrypt → streaming pack/encrypt với frame AAD bind `intent_hash` → tính ciphertext hash/size → tạo và ký detached `SnapshotManifestV2` → encrypted spool → crash-safe create-upload/finalize/commit version 1.
6. Sau readback hash/version, binding được ghi vào `team-sync.db`; local JSON/profile data vẫn giữ nguyên.

#### Journey B — Checkout và sử dụng trên máy khác

1. Member chọn fleet profile và checkout bằng exact `ProfileCheckoutRequestV2`. Coordinator atomically allocate current lease + fence + stored response; response-loss replay cùng request trả byte-identical lease/fence cũ kể cả khi receipt đã hết hạn, không mint lease/fence thứ hai. Sau expiry client phải reconcile rồi dùng idempotency key mới.
2. Server cấp lease, `fencing_token` và `base_version`.
3. Client resume-download ciphertext + detached manifest; verify root/owner-signed FKEK grant bytes, manifest signature/head continuity, `intent_hash`, exact preamble/intent/slot hashes và ciphertext hash/size trước khi decrypt trực tiếp vào validated staging rồi reseal destination secrets.
4. Client atomic swap, chạy smoke test; nếu pass mới đánh dấu ready.
5. Common launch guard chỉ cho start/relaunch khi current lease còn hợp lệ theo server time. Browser đã chạy có thể tiếp tục với warning sau mất renew, nhưng sau expiry không start/relaunch hoặc remote commit.

#### Journey C — Check-in

1. Browser phải stopped; client có local claim độc quyền.
2. Client tạo intent/one DEK slot trước encrypt, streaming pack/encrypt với frame AAD bind `intent_hash`, rồi tính ciphertext hash/size và ký final `SnapshotManifestV2`.
3. Create/resume upload bind exact expected ciphertext digest/size + `intent_hash`; commit gửi exact `CommitRequestV2` nhúng exact `SignedSnapshotManifestV2`, rồi nhận/persist exact `CommitReceiptBindingV2`.
4. Server chỉ commit object đã hash/fsync bền vững; trong một CAS transaction kiểm tra role/capability, current lease theo server time, fence/base/signature/grant, insert snapshot + head, tăng version, release lease, audit và lưu exact receipt.
5. Client readback receipt rồi cập nhật binding; encrypted spool chỉ xóa sau receipt bền vững.

#### Journey D — Mất mạng hoặc conflict

1. Browser đang chạy có thể tiếp tục cục bộ nhưng UI chuyển `lease_at_risk`, sau expiry là `offline_fork`.
2. Client không tự renew giả, takeover hoặc commit stale.
3. Khi reconnect, nếu fence/version đã đổi, user chọn: discard và pull; export encrypted recovery; hoặc tạo local recovered copy.
4. Không có lựa chọn “overwrite remote” mặc định.

#### Journey E — Key recovery/rotation

1. Owner export recovery bundle được mã hóa bằng passphrase và xác nhận fingerprint.
2. Rotation tạo generation `PREPARING`; chỉ chuyển `ACTIVE` sau root-wrapped recovery grant và mọi required device HPKE FKEK grant đều exact-byte readback/ack; generation cũ chuyển `RETIRED`.
3. Revoke device + activate generation mới là một logical operation có capability check và audit transaction; revoked device không nhận generation mới. UI cảnh báo rằng dữ liệu/key cũ đã sao chép không thể bị thu hồi hồi tố.
4. Chỉ GC generation cũ sau retention scan và restore drill thành công.

### 4.6. Product acceptance criteria

- Local-only profile có cùng create/edit/start/stop/delete behavior và cùng MCP surface như v0.1.28.
- Server v2 không lưu plaintext secret/config/label; secret scan trên DB/blob/log/fixtures không tìm thấy fixture marker.
- Hai tenant có thể dùng cùng resource UUID mà không đọc/ghi chéo.
- Stale/expired lease, wrong fence hoặc wrong `base_version` không thể commit dù upload đã hoàn tất.
- Retry cùng idempotency key + cùng request hash trả cùng receipt; cùng key + khác body fail `IDEMPOTENCY_MISMATCH`.
- Profile publish-create atomically create version-0 profile **và** acquire initial lease/fence trong cùng transaction với idempotency row + audit. Checkout retry sau response loss trả exact stored response và không tăng fence/đổi lease lần hai; create-upload/finalize/release/local-unbind replay exact stored response, không tái diễn side effect.
- Commit idempotency request/receipt tồn tại ít nhất lâu bằng snapshot retention liên quan; duplicate chunk chỉ được công nhận bằng digest đã persist, còn offset mismatch mặc định HEAD/resume.
- Envelope không chứa commitment tới final manifest. Test vector chứng minh `EnvelopeIntentV2` và one `DekSlotV2` được khóa trước encrypt, mọi DATA/FINAL frame bind exact `intent_hash`, và exact `SignedSnapshotManifestV2` chỉ được tạo sau khi biết ciphertext hash/size.
- Mỗi snapshot envelope có đúng một DEK slot bind immutable `(tenant_id,fleet_id,fkek_key_id,generation)`; không có per-device HPKE slot trong envelope. Device chỉ lấy FKEK qua exact `FleetKeyGrantV2::DeviceHpkeGrant` ngoài envelope và reject nếu any payload/container/index equality—gồm HPKE suite/info/recipient/encapped/wrapped bytes—không match.
- Sáu authorization/key-grant records ở 5.6.1 và 5.6.4—including exact `TenantRootKeyGrantV2`—persist exact payload/container bytes + internal/full hashes, signature metadata/bytes và typed indexed fields. Authorization/key release/rotation phải verify canonical roundtrip, signature/container hashes và **mọi** mapped column; một mismatch fail closed trước mutation/unwrap.
- Startup/server reconciliation bao phủ mọi `OPEN`/`FINALIZING`/`READY`/`COMMITTED`/`QUARANTINED` × staging/immutable validity × exact receipt state; không row `FINALIZING` nào còn lại sau một pass thành công.
- Exact `SignedSnapshotManifestV2` container và exact `CommitRequestV2` bytes + internal/full hashes được persist durable trước finalize/commit; server transaction persist exact `CommitReceiptBindingV2` bytes/hash. Server/local close/reopen chỉ replay byte-identical request/receipt; re-encoding hoặc bất kỳ binding/hash mismatch nào quarantine/fail closed.
- Restore bị crash ở bất kỳ phase đã instrument vẫn trở về old-good hoặc new-good state, không half-swap.
- Backup profile lớn chạy với bounded memory đã đặt trước; không materialize cả archive/plaintext payload trong RAM hoặc disk temp ngoài staging.
- Cross-machine restore reseal cookies/login/web secrets và pass functional smoke.
- Upgrade và rollback từ v0.1.28 có backup hash, integrity checks và documented readback; downgrade clone chỉ pass sau khi original metadata + user-data đã được move/fsync/readback ngoài mọi discovery path của v0.1.28 và clone dùng local ID mới không Team artifact. Full pre-v2 restore là flow riêng; server-global epoch rollback quarantine chỉ được gỡ cho từng tenant/profile bằng valid tenant-scoped root-signed `RestoreEpochTransitionV2` + inclusion proof bao phủ exact previous/new signed head của binding đó. Cross-tenant transition/proof luôn bị reject.
- Client fail closed khi key/grant/head signature sai, artifact bị sửa, `server_instance_id`/`restore_epoch` rollback hoặc signed head không nối tiếp state đã pin.
- MCP contract test deep-compare fixture canonical đủ 96 tool descriptors: name, description, annotations và input schema.
- V0.2.0 chỉ tạo internal foundation; Team runtime macOS/Linux bị disable/local-only tới khi platform credential-store tests được phê duyệt.
- G0–G7 pass là implementation completion. Nếu production-operator gate chưa pass, evidence packet và artifacts phải ghi **non-production-ready**; không được claim release-ready/production-ready hoặc chạy tag/publish/production migration.

---

## 5. ADR — Trust boundaries và threat model

### 5.1. Decision

Triển khai Team/Fleet dưới control plane `/v2`, schema tenant-scoped additive, client-side envelope encryption + authenticity/signing plane và local `team-sync.db`. **Coordinator process và integrity/freshness của live coordination/RBAC SQLite là trusted control plane** cho session, role, revocation, lease/fence, active generation, idempotency và transaction ordering. **Ciphertext/signed artifact bytes trong SQLite/blob/log/backup không được tin cậy cho confidentiality hoặc artifact integrity** và server không có decryption key; clients verify exact containers/hashes/heads. Đồng bộ dùng one-current-lease-row + monotonic fencing + exact base-version CAS theo server time.

### 5.2. Trust boundaries

| Boundary | Tin cậy | Không tin cậy / giới hạn |
|---|---|---|
| Launcher process + local profile directory | Được tin cậy trong phiên người dùng hiện tại | Malware/admin trên cùng máy nằm ngoài khả năng bảo vệ tuyệt đối; log/temp vẫn phải không secret |
| OS credential store | Nơi ưu tiên giữ device signing private key, HPKE private key và key references riêng | Có thể unavailable/roaming không đồng nhất; Windows là Team runtime đầu tiên, platform khác fail closed/local-only |
| `team-sync.db` | Trusted local workflow cache only khi host/user integrity còn nguyên; exact request/response bytes là replay authority cục bộ | Không chứa raw token, passphrase, DEK/KEK hoặc plaintext profile payload; local admin/malware rollback nằm ngoài guarantee |
| Network/reverse proxy | Không tin cậy | Remote bắt buộc HTTPS; body và auth không được log |
| Team coordinator process | Tin cậy cho authenticated request context, tenant RBAC/capability checks, lease coordination, server time và transaction ordering | Coordinator chủ động độc hại có thể equivocate, cấp hai lease, rewrite auth state hoặc DoS; ngăn tuyệt đối cần trust architecture khác và ngoài v0.2.x |
| Live coordination/RBAC SQLite state | **Trusted integrity/freshness assumption** cho accounts/sessions/roles/capabilities/revocation/current lease+fence/active generation/idempotency/audit | Host/DB attacker có write/rollback quyền có thể re-enable revoked principals, chọn generation cũ, cấp lease/fence giả hoặc suppress audit; sản phẩm không claim ngăn/phát hiện toàn bộ lớp này |
| Ciphertext/signed artifact columns, blob/log và DB/blob/log backups | Không tin cậy cho confidentiality hoặc artifact integrity | Chỉ metadata allowlist, canonical signed records và ciphertext; client verify signature, commitment, exact equality, hash chain và pinned head. Backup read/tamper không tự cấp auth vì live control plane vẫn là authority |
| Other tenant/member/device | Không tin cậy ngoài ACL | Mọi request bị tenant/fleet/device scoped; revoked device không nhận key generation mới |
| Recovery bundle | Bí mật cấp root do user giữ | Mất bundle + mất mọi device key có thể làm mất dữ liệu vĩnh viễn; flow phải cảnh báo và drill |

### 5.3. Threat model

**Phải chống:**

- DB/blob/log server bị đọc trộm.
- Ciphertext, signed artifact rows, blob hoặc backup bị sửa/substitute/replay trong khi live coordination/RBAC control plane không bị compromise.
- Cross-tenant IDOR và ACL bypass.
- Replay checkout/upload/commit; stale holder sau partition.
- Multipart/chunk truncation, reorder, duplicate, corrupted ciphertext.
- Device-key substitution, forged grant/approval, unsigned snapshot head và rollback/substitution tương đối với signed state client đã pin.
- Archive traversal, symlink, reserved path, decompression bomb, oversized entry.
- Crash/power loss giữa download, decrypt, reseal, swap, smoke và cleanup.
- Key/device revocation cho dữ liệu tương lai; accidental key deletion/rotation.
- Secret leakage qua tracing, error, fixtures, metrics, audit detail hoặc UI telemetry.

**Không hứa chống:**

- Malware/keylogger hoặc local administrator trên thiết bị đã unlock.
- Member hợp lệ tự sao chép plaintext hoặc key khi đang được cấp quyền.
- Hồi tố xóa key/snapshot cũ đã được device hợp lệ sao chép.
- Guarantee exclusivity/linearizability hoặc global fork detection khi chính active coordinator chủ động cấp hai lease, che giấu branch hay DoS. Không thêm transparency service hoặc distributed consensus trong v0.2.x.
- Traffic analysis hoàn toàn: server vẫn thấy kích thước, thời gian, tenant/fleet/profile opaque IDs và lease state.
- Kẻ tấn công sửa/rollback live coordination/RBAC SQLite hoặc chiếm coordinator process. Khi đó authorization, revocation, exclusivity, generation freshness, idempotency và audit đều có thể bị phá; exact signed artifact verification chỉ còn bảo vệ artifact bytes/head mà không phục hồi control-plane correctness.

### 5.4. Accepted metadata leakage

Server được phép lưu đúng các nhóm sau: canonical server origin/tenant locator; opaque IDs; tenant/fleet membership; account/device status; signing/HPKE public keys và key IDs; generation/grant/ack state; lease owner/device, version/fence và server timestamps; ciphertext size/hash/path; exact canonical `EnvelopeIntentV2`, `DekSlotV2`; six authorization/key-grant payload/container records + hashes/index columns; exact mutation request/stored-response bytes; exact `SignedSnapshotManifestV2`/`CommitRequestV2`/`CommitReceiptBindingV2` bytes + hashes; tenant-scoped `RestoreEpochTransitionV2` bytes/signature/index claims; canonical profile-head-set commitments/inclusion proofs; structured audit action/outcome/reason code. Tên profile thật, notes, config, proxy và labels phải nằm trong encrypted payload hoặc ciphertext field; danh sách chưa unlock hiển thị opaque alias cục bộ.

### 5.5. Authenticity và rollback guarantees

- Mỗi device có **hai key pair riêng**: signing key và HPKE recipient key; mỗi public key có immutable `key_id`, lifecycle/status và proof-of-possession riêng. Không dùng TRK/FKEK/DEK làm signing key.
- Enrollment challenge bind `server_instance_id`, `restore_epoch`, tenant, nonce, cả hai key ID/public-key commitments và expiry; client ký challenge trước khi server lưu pending device.
- First owner/root bootstrap cần fingerprint xác nhận out-of-band. Sáu authorization/key-grant payloads—including `TenantRootKeyGrantV2` bootstrap/self-grant—phải được signer hợp lệ theo exact bootstrap/issuer rule ký và đóng gói đúng TBS/core/container construction ở 5.6. Server persist canonical payload bytes/hash, signature metadata/bytes, internal signed-container hash, exact outer bytes/full hash và every typed mapped column. Authorization/key release/rotation parse bounded canonical bytes, verify domain/version/TBS signature/all hashes, replay+validity và exact all-column equality; HPKE fields được so trước open. Artifact columns không tự là authenticity authority, dù live RBAC/revocation/generation rows thuộc trusted control plane.
- `EnvelopeIntentV2` được canonicalize/hash trước encrypt và không chứa ciphertext hash/size hay final-manifest commitment. Mọi frame AAD bind `intent_hash`; envelope có đúng một `DekSlotV2` dưới immutable FKEK `key_id` + generation.
- Sau encrypt, exact `SnapshotManifestV2` payload và `SignedSnapshotManifestV2` container mới được tạo; container bind tenant/fleet/profile, version/base/lease/fence, immutable FKEK generation, `intent_hash`, exact preamble/slot/ciphertext/head/instance/epoch claims. Exact container + `CommitRequestV2` artifacts phải persist/fsync durable trước finalize/commit; exact `CommitReceiptBindingV2` persist transactionally. Client chỉ chấp nhận chain nối tiếp head đã pin và chỉ replay stored request/receipt byte-identically after restart.
- Authority cho cặp monotonic `server_instance_id + restore_epoch` là exact checksummed/fsync'd external identity record nằm trong operator-owned identity root **ngoài** SQLite DB/blob backup và rollback scope. Record bind magic/version, instance ID, previous/current epoch, restore transaction ID, restored-DB SHA-256, transition-set SHA-256, write timestamp và checksum của canonical bytes không chứa checksum. `v2_server_state` và local `server_origins.last_restore_epoch` chỉ mirror/cache; DB restore không bao giờ được hạ, tái tạo hoặc thay thế authority này.
- `restore_epoch` vẫn monotonic server-global, nhưng mỗi `RestoreEpochTransitionV2` là tenant-scoped và keyed `(server_instance_id, tenant_id, previous_epoch, new_epoch)`. Root-custodian của chính tenant ký canonical record commit `mapping_codec`, `mapping_count` và Merkle root của canonical sorted leaves `(tenant_id, profile_id, previous_signed_head_hash, new_signed_head_hash)`. Mỗi binding chỉ gỡ quarantine sau exact transition/signature/capability/epoch verification và inclusion proof cho leaf của profile đó; tenant/root/proof mismatch hoặc proof từ tenant khác fail closed.
- Client quarantine binding khi signature/grant invalid, indexed claims khác signed bytes, key ID bị thay, signed head rollback/diverge, `server_instance_id` thay hoặc `restore_epoch` giảm/tăng mà chưa có valid transition. Đây là phát hiện tương đối với state đã quan sát, không phải global transparency guarantee.
- **Giới hạn rollback/DB compromise:** external epoch record chỉ xử lý authorized restore/DB-image rollback có tăng epoch và exact transition set; nó không phát hiện mọi rollback chọn lọc của role/session/revocation/lease/generation rows trong cùng epoch. Nếu live control-plane SQLite integrity/freshness không còn được tin cậy, toàn bộ v2 writes fail operationally và phải restore từ trusted operator evidence; v0.2.x không thêm signed authorization transparency log để mở rộng guarantee.

### 5.6. Canonical signed-record và commit-byte contracts — provider-independent

Các contract dưới đây khóa **wire schema**, không khóa crate/provider. G2 chỉ được
chọn implementation provider/suite đáp ứng đúng schema và vectors; executor
không được đổi field, domain, optionality, hash preimage hoặc equality map để
phù hợp API của provider.

**Canonical codec và primitive types**

- `CanonicalCborV2` là RFC 8949 deterministic CBOR với definite-length map/array,
  shortest integer/length form, exact UTF-8 text keys dưới đây, key order theo
  encoded-key bytes, không duplicate key, tag, float, simple value, indefinite
  length hoặc unknown field. Optional field hợp lệ phải **omitted**, không encode
  `null`; mọi record ở đây là closed map.
- `Uuid16` = CBOR `bstr` đúng 16 bytes theo UUID network byte order;
  `ReplayId16`/`Nonce16` = random CBOR `bstr` đúng 16 bytes; `KeyId32` và
  `Hash32` = CBOR `bstr` đúng 32 bytes; `UnixMs` = CBOR unsigned integer trong
  `[0, 2^63-1]`; `U16`/`U32`/`U64` = bounded unsigned integer; `Bool` = CBOR
  boolean; `Capability` = lowercase ASCII `tstr` match
  `[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+`; `Bytes(min,max)` = bounded CBOR `bstr`.
  `Text(min,max)` = CBOR `tstr` whose canonical UTF-8 byte length is in the
  inclusive bound, valid scalar UTF-8, no NUL; no Unicode normalization is
  performed, so producer must emit the exact application identifier bytes.
- **SQLite wire-integer invariant:** mọi unsigned wire integer hiện tại được persist hoặc mirror trong SQLite—gồm version/generation, fencing token, offset, size, epoch, count và millisecond timestamp—có accepted domain `0..i64::MAX` (`0..9223372036854775807`) dù canonical CBOR major type là unsigned. Decoder phải reject `2^63`, `2^64-1`, negative, overlong/non-canonical và mọi value không fit trước cast/SQL bind; SQLite DDL lặp lại upper-bound `CHECK`. Không dùng saturating/wrapping cast hoặc để SQLite coerce qua REAL/TEXT. Nếu protocol tương lai thật sự cần full U64, field phải có version mới và canonical fixed-width big-endian BLOB hoặc canonical decimal TEXT riêng, không silently map vào `INTEGER`.
- DB `TEXT` UUID/key renderings, nếu dùng, phải là lowercase canonical rendering
  round-trip lossless về exact `Uuid16`/`KeyId32`; hashes và protocol/key bytes
  dùng BLOB exact length. Equality guard so sánh decoded typed value, không so
  display string hoặc provider object.
- Mọi authorization payload có `replay_id`, `issued_at_ms`, `not_before_ms`,
  `not_after_ms`; require `issued_at_ms <= not_before_ms < not_after_ms`,
  `server_now ∈ [not_before_ms,not_after_ms)`, và TTL không vượt tenant policy.
  Unique replay scope là `(tenant_id,payload_domain,replay_id)`; tombstone giữ ít
  nhất tới `not_after_ms + authorization_replay_retention`, không cho reuse sau
  revoke. `server_instance_id` và `restore_epoch` luôn required.

**Signed authorization container — exact construction**

Mọi record authorization dùng exact outer map `SignedAuthorizationRecordV2`:

| Field | Type | Required | Contract |
|---|---|---:|---|
| `container_domain` | `tstr` | yes | exact `shardx.authorization.signed-container.v2` |
| `container_version` | `U16` | yes | exact `2` |
| `payload_domain` | `tstr` | yes | exact domain của decoded payload |
| `payload_version` | `U16` | yes | exact `2`, equal decoded payload `version` |
| `canonical_payload_bytes` | `Bytes(1,65536)` | yes | exact canonical payload bytes; không reconstruct |
| `payload_sha256` | `Hash32` | yes | SHA-256 của exact `canonical_payload_bytes` |
| `signature_suite_id` | `U16` | yes | protocol registry ID; provider mapping chỉ được G2 pin |
| `signature_version` | `U16` | yes | exact `1` cho suite profile được G2 chốt |
| `issuer_signing_key_id` | `KeyId32` | yes | key được lookup trong same tenant/epoch và có capability phù hợp |
| `signature_bytes` | `Bytes(1,4096)` | yes | signature trên TBS bytes dưới đây |
| `signed_container_hash` | `Hash32` | yes | domain-separated hash của canonical container core |

`authorization_tbs_bytes` là `CanonicalCborV2` map chứa chín field từ
`container_domain` tới `issuer_signing_key_id`, không có `signature_bytes` hoặc
`signed_container_hash`. Signature input là ASCII
`SHARDX-SIGNED-RECORD-V2\0` + `u32be(len(authorization_tbs_bytes))` + exact TBS
bytes. `authorization_container_core_bytes` là canonical map của TBS fields +
`signature_bytes`. `signed_container_hash = SHA256(ASCII
"SHARDX-SIGNED-CONTAINER-V2\0" + u32be(len(core_bytes)) + core_bytes)`. Exact
outer container bytes là canonical map của core fields + `signed_container_hash`;
storage còn persist `exact_signed_container_bytes_sha256 = SHA256(exact outer
bytes)` để phát hiện byte drift. Parser recompute tất cả bytes/hashes và reject
container canonical nhưng TBS/core tái dựng không byte-identical.

#### 5.6.1. Authorization payload schemas

Các field common sau required trong cả năm payload: `domain:tstr`,
`version:U16=2`, `replay_id:ReplayId16`, `tenant_id:Uuid16`,
`issued_at_ms:UnixMs`, `not_before_ms:UnixMs`, `not_after_ms:UnixMs`,
`server_instance_id:Uuid16`, `restore_epoch:U64`.

**`DeviceApprovalV2`** — domain exact `shardx.auth.device-approval.v2`; không có
optional field.

| Field riêng | Type | Required | Indexed equality target |
|---|---|---:|---|
| `subject_account_id` | `Uuid16` | yes | `v2_device_approvals.subject_account_id` |
| `subject_device_id` | `Uuid16` | yes | `subject_device_id` |
| `subject_signing_key_id` | `KeyId32` | yes | `subject_signing_key_id` |
| `subject_hpke_key_id` | `KeyId32` | yes | `subject_hpke_key_id` |
| `approval_scope_kind` | enum `tenant`,`fleet` | yes | `approval_scope_kind` |
| `approval_scope_id` | `Uuid16` | yes | `approval_scope_id`; equals tenant/fleet selected by kind |
| `approved_use` | enum `team.device` | yes | `approved_use` |

Common equality map cho cả năm records là `domain -> payload_domain`,
`version -> payload_version`, và one-for-one cho `replay_id`, `tenant_id`,
`issued_at_ms`, `not_before_ms`, `not_after_ms`, `server_instance_id`,
`restore_epoch`. `replay_id` của approval là approval replay identity; không có
separate mutable approval ID. Subject signing và HPKE key IDs phải khác nhau.

**`TenantCapabilityGrantV2`** — domain exact
`shardx.auth.tenant-capability-grant.v2`.

| Field riêng | Type | Optionality | Indexed equality target |
|---|---|---|---|
| `subject_kind` | enum `account`,`device` | required | `subject_kind` |
| `subject_account_id` | `Uuid16` | required | `subject_account_id` |
| `subject_device_id` | `Uuid16` | required iff `subject_kind=device`; otherwise omitted | nullable `subject_device_id` |
| `subject_signing_key_id` | `KeyId32` | required iff `subject_kind=device`; otherwise omitted | nullable `subject_signing_key_id` |
| `subject_hpke_key_id` | `KeyId32` | required iff `subject_kind=device`; otherwise omitted | nullable `subject_hpke_key_id` |
| `scope_kind` | enum `tenant`,`fleet`,`profile` | required | `scope_kind` |
| `scope_id` | `Uuid16` | required | `scope_id` |
| `capability` | `Capability` | required | `capability` |

Account-scoped grant có cả ba device/key fields `NULL`/omitted; device-scoped
grant có cả ba field present. `root.custody` chỉ hợp lệ cho device-scoped grant
và bắt buộc `subject_hpke_key_id`.

**`FleetKeyGrantV2` common fields** — ngoài common authorization fields, cả ba
variants có `grant_variant:tstr`, `fleet_id:Uuid16`, `fkek_key_id:KeyId32`,
`generation:U64`, `grant_capability:Capability`. Unique replay scope vẫn dùng
payload domain riêng của variant.

| Variant/domain | Variant-only exact fields | Optionality và invariants |
|---|---|---|
| `FleetKeyGrantV2::DeviceHpkeGrant`; `shardx.keys.fleet-key-grant.device-hpke.v2` | `grant_variant="DeviceHpkeGrant"`; `subject_account_id:Uuid16`; `subject_device_id:Uuid16`; `subject_signing_key_id:KeyId32`; `recipient_hpke_key_id:KeyId32`; `hpke_suite_id:U16`; `hpke_info_bytes:Bytes(1,1024)`; `hpke_encapped_key_bytes:Bytes(1,2048)`; `hpke_wrapped_fleet_key_bytes:Bytes(1,4096)` | tất cả required; `grant_capability="fleet.key.receive"`; subject signing key khác recipient HPKE key. **Suite, info, recipient key ID, encapped bytes và wrapped bytes đều nằm trong signed payload.** |
| `FleetKeyGrantV2::RecoveryGrant`; `shardx.keys.fleet-key-grant.recovery.v2` | `grant_variant="RecoveryGrant"`; `recipient_root_key_id:KeyId32`; `recipient_root_generation:U64`; `root_wrap_suite_id:U16`; `root_wrap_nonce_bytes:Bytes(1,64)`; `root_wrap_context_bytes:Bytes(1,1024)`; `wrapped_fleet_key_bytes:Bytes(1,4096)` | tất cả required; `grant_capability="fleet.key.recover"`; không có device/HPKE fields |
| `FleetKeyGrantV2::RotationGrant`; `shardx.keys.fleet-key-grant.rotation.v2` | `grant_variant="RotationGrant"`; `previous_fkek_key_id:KeyId32`; `previous_generation:U64`; `required_device_grant_count:U32`; `required_device_grant_set_hash:Hash32`; `recovery_grant_signed_container_hash:Hash32`; `activation_not_before_ms:UnixMs` | tất cả required; common `fkek_key_id/generation` là target generation; require `generation=previous_generation+1`, key IDs khác nhau, `activation_not_before_ms ∈ [not_before_ms,not_after_ms)`, `grant_capability="key.rotate"` |

Equality map cho ba fleet variants là exact one-for-one từ mọi decoded field tới
same-name indexed column trong bảng variant tương ứng. Đặc biệt
`hpke_suite_id`, `hpke_info_bytes`, `hpke_encapped_key_bytes` và
`hpke_wrapped_fleet_key_bytes` phải BLOB-compare exact trước HPKE open/FKEK
release; query index chỉ tìm candidate, không cấp authority. Common container
fields map tới `canonical_payload_bytes`, `payload_sha256`,
`signature_suite_id`, `signature_version`, `issuer_signing_key_id`,
`signature_bytes`, `signed_container_hash`, `exact_signed_container_bytes` và
`exact_signed_container_bytes_sha256`. Bất kỳ missing/extra/column mismatch nào
trả `AUTH_CLAIM_COLUMN_MISMATCH`, quarantine record và không mutate/unwrap.

#### 5.6.2. Exact snapshot manifest, commit request và receipt schemas

**`SnapshotManifestV2` payload** — domain exact
`shardx.snapshot.manifest-payload.v2`, version `2`; closed canonical map:

| Field | Type | Optionality / equality |
|---|---|---|
| `snapshot_id`, `tenant_id`, `fleet_id`, `profile_id`, `lease_id` | `Uuid16` | required; `snapshot_id` equals upload+snapshot rows; identity/lease fields equal upload/profile/current-lease rows; no lease `snapshot_id` column exists |
| `target_version`, `base_version`, `fencing_token`, `key_generation` | `U64` | required; `target_version=base_version+1` |
| `fkek_key_id` | `KeyId32` | required; exact ACTIVE immutable generation |
| `preamble_sha256`, `intent_hash`, `dek_slot_sha256`, `ciphertext_sha256` | `Hash32` | required; exact upload/object columns |
| `ciphertext_size` | `U64` | required; hard bounded and exact object size |
| `previous_signed_head_hash` | `Hash32` | omitted only when `base_version=0`; otherwise required and equals pinned/current head |
| `signer_signing_key_id` | `KeyId32` | required; equals signed-container signer field |
| `server_instance_id` | `Uuid16` | required; exact upload/server identity |
| `restore_epoch` | `U64` | required; exact current accepted epoch |
| `manifest_replay_id` | `ReplayId16` | required; equal immutable upload+snapshot columns and unique per `(server_instance_id,tenant_id,profile_id)` |
| `created_at_ms` | `UnixMs` | required; informational, not lease/validity authority |

**`SignedSnapshotManifestV2` exact container** dùng cùng TBS/core/hash
construction ở trên nhưng exact fields là:
`container_domain="shardx.snapshot.signed-manifest-container.v2"`,
`container_version=2`, `payload_domain`, `payload_version=2`,
`canonical_manifest_payload_bytes`, `manifest_payload_sha256`,
`signature_suite_id`, `signature_version`, `signer_signing_key_id`,
`signature_bytes`, `signed_container_hash`. Exact outer bytes được persist cùng
`exact_signed_manifest_container_bytes_sha256`. `head_hash = SHA256(ASCII
"SHARDX-SNAPSHOT-HEAD-V2\0" + u32be(len(exact container bytes)) + exact
container bytes)`. Không field nào tự hash full outer bytes; internal
`signed_container_hash` hash core không chứa chính nó, còn external bytes hash
hash exact full container.

**`CommitRequestV2`** — exact closed canonical map. Core domain là
`shardx.sync.commit-request.v2`, version `2` và gồm các field required:

`tenant_id:Uuid16`, `fleet_id:Uuid16`, `profile_id:Uuid16`, `upload_id:Uuid16`,
`snapshot_id:Uuid16`, `manifest_replay_id:ReplayId16`,
`operation_scope:tstr` exact `profile.commit.v2`, `idempotency_key:ReplayId16`,
`lease_id:Uuid16`, `fencing_token:U64`, `base_version:U64`,
`intent_hash:Hash32`, `ciphertext_sha256:Hash32`, `ciphertext_size:U64`,
`signed_manifest_container_bytes:Bytes(1,131072)`,
`signed_manifest_container_bytes_sha256:Hash32`,
`signed_manifest_container_hash:Hash32`, `server_instance_id:Uuid16`,
`restore_epoch:U64`, `client_request_nonce:Nonce16`.

`canonical_request_hash = SHA256(ASCII "SHARDX-COMMIT-REQUEST-V2\0" +
u32be(len(canonical core bytes)) + canonical core bytes)`. Exact
`CommitRequestV2` bytes là canonical outer map của toàn bộ core fields cộng
`canonical_request_hash:Hash32`; storage còn persist
`exact_commit_request_bytes_sha256 = SHA256(exact request bytes)`. Request
parser phải verify exact manifest outer bytes hash, internal signed-container
hash, manifest signature/payload equality và every request-to-upload/lease/
object column before CAS. Same scope/key với bất kỳ core byte khác bị
`IDEMPOTENCY_MISMATCH`; same canonical hash nhưng exact request bytes khác bị
`MANIFEST_REPLAY_MISMATCH`/non-canonical reject.

**`CommitReceiptBindingV2`** — exact closed canonical map, không reconstruct từ
snapshot row khi replay:

| Field | Type | Required / contract |
|---|---|---|
| `domain` | `tstr` | exact `shardx.sync.commit-receipt-binding.v2` |
| `version` | `U16` | exact `2` |
| `exact_request_hash` | `Hash32` | equals verified `CommitRequestV2.canonical_request_hash` |
| `snapshot_id` | `Uuid16` | equals signed manifest/snapshot row |
| `resulting_version` | `U64` | equals `base_version+1` and profile row |
| `resulting_head_hash` | `Hash32` | equals derived signed-manifest `head_hash` |
| `lease_release_outcome` | enum `released`,`already_released_same_commit` | exact transaction outcome; second value only idempotent replay of same commit |
| `server_instance_id` | `Uuid16` | exact server identity |
| `restore_epoch` | `U64` | exact committed epoch |
| `commit_timestamp_ms` | `UnixMs` | server transaction time |
| `server_receipt_id` | `ReplayId16` | immutable unique receipt ID |

Server transaction persist exact receipt bytes và
`commit_receipt_binding_bytes_sha256 = SHA256(exact receipt bytes)` trước response.
Local client verify every receipt field against stored exact request/manifest and
persist the same exact bytes/hash before marking COMMIT complete. Response loss,
server restart và local close/reopen replay the stored bytes byte-for-byte; a
row-only reserialization, different key order hoặc semantically-equal alternate
encoding is a security/consistency failure.

#### 5.6.3. Exact envelope-intent, restore-transition và Merkle-proof contracts

Các contract trong mục này là closed `CanonicalCborV2` maps. `TBS = N/A` cho
`DekSlotV2`, `EnvelopeIntentV2` và inclusion proof vì chúng không tự được ký;
authority của chúng là exact bytes + domain-separated hash và, với proof, root
trong signed transition. `RestoreEpochTransitionV2` có TBS/container riêng dưới
đây. Hằng số `MAX_RESTORE_EPOCH_LEAVES_V2 = 1000000`; mọi integer vẫn bị chặn
thêm bởi `0..i64::MAX`.

**`DekSlotContextV2` và `DekSlotV2` — exact dependency đầu tiên**

`DekSlotContextV2` là exact closed map:

| Field | Type | Contract |
|---|---|---|
| `domain` | `tstr` | exact `shardx.envelope.dek-slot-context.v2` |
| `version` | `U16` | exact `2` |
| `snapshot_id`, `tenant_id`, `fleet_id`, `profile_id` | `Uuid16` | required |
| `fkek_key_id` | `KeyId32` | required immutable generation key ID |
| `key_generation` | `U64` | required, `0..i64::MAX` |
| `wrap_suite_id` | `U16` | required; numeric suite mapping only G2 may pin |
| `slot_index` | `U16` | exact `0`; v2 has exactly one slot |
| `envelope_context_nonce` | `Nonce16` | required random per snapshot |

`canonical_dek_slot_context_bytes` là exact canonical bytes của map trên.
`dek_slot_context_hash = SHA256(ASCII "SHARDX-DEK-SLOT-CONTEXT-V2\0" +
u32be(len(context_bytes)) + context_bytes)`. DEK-wrap AAD là **exact context
bytes**, không phải reconstructed map hoặc `intent_hash`.

`DekSlotV2` là exact closed map:

| Field | Type | Contract |
|---|---|---|
| `domain` | `tstr` | exact `shardx.envelope.dek-slot.v2` |
| `version` | `U16` | exact `2` |
| `slot_index` | `U16` | exact `0` |
| `canonical_dek_slot_context_bytes` | `Bytes(1,4096)` | exact bytes ở trên |
| `dek_slot_context_hash` | `Hash32` | recompute theo domain trên |
| `wrap_nonce_bytes` | `Bytes(1,64)` | required; exact nonce length cho suite do G2 pin trong bound này |
| `wrapped_dek_bytes` | `Bytes(1,4096)` | required; provider output exact bytes |

Parser decode context bytes, require canonical roundtrip, one-for-one equality
với outer `slot_index` và intent fields, rồi recompute context hash trước unwrap.
`dek_slot_sha256 = SHA256(ASCII "SHARDX-DEK-SLOT-V2\0" +
u32be(len(exact_dek_slot_bytes)) + exact_dek_slot_bytes)`. Không field/hash nào
trong slot được tham chiếu `EnvelopeIntentV2`, ciphertext hoặc manifest.

**`EnvelopeIntentV2` — exact pre-encryption closed map**

| Field | Type | Optionality / bound |
|---|---|---|
| `domain` | `tstr` | required exact `shardx.envelope.intent.v2` |
| `version` | `U16` | required exact `2` |
| `snapshot_id`, `tenant_id`, `fleet_id`, `profile_id`, `lease_id` | `Uuid16` | required |
| `manifest_replay_id` | `ReplayId16` | required; preallocated and immutable through upload/snapshot |
| `target_version`, `base_version`, `fencing_token`, `key_generation` | `U64` | required; `target_version=base_version+1` |
| `fkek_key_id` | `KeyId32` | required; equal slot context |
| `preamble_version` | `U16` | exact `2` |
| `envelope_suite_id`, `wrap_suite_id`, `archive_format_id`, `archive_policy_id`, `compression_id` | `U16` | required; G2 pins registry values, not fields |
| `frame_plaintext_size` | `U32` | required `65536..4194304` |
| `stream_nonce_prefix` | `Bytes(1,64)` | required; suite-specific exact length pinned by G2 |
| `final_frame_required` | `Bool` | required exact `true` |
| `max_plaintext_size`, `max_ciphertext_size` | `U64` | required `1..536870912`; plaintext/ciphertext actuals may be lower |
| `created_at_ms` | `UnixMs` | required informational timestamp |
| `previous_signed_head_hash` | `Hash32` | omitted iff `base_version=0`; otherwise required |
| `intended_signer_signing_key_id` | `KeyId32` | required |
| `server_instance_id` | `Uuid16` | required |
| `restore_epoch` | `U64` | required |
| `dek_slot_context_hash`, `dek_slot_sha256` | `Hash32` | required exact slot bindings |

`intent_hash = SHA256(ASCII "SHARDX-ENVELOPE-INTENT-V2\0" +
u32be(len(exact_intent_bytes)) + exact_intent_bytes)`. TBS/container không áp
dụng; exact intent bytes + hash là authority. Intent tuyệt đối không có archive
content hash, ciphertext hash/size actual, manifest hash/signature hoặc field
unknown/extension. Build order bất biến: context → wrapped slot → exact slot
hash → exact intent → intent hash → preamble/frames → signed manifest.

**`RestoreEpochLeafV2`, tree và inclusion proof**

Mỗi leaf là exact closed map với `domain:tstr` exact
`shardx.restore-epoch.profile-head-leaf.v2`, `version:U16=2`,
`tenant_id:Uuid16`, `profile_id:Uuid16`, `previous_signed_head_hash:Hash32` và
`new_signed_head_hash:Hash32`; không optional field. Transition chỉ bao phủ
profile đã có pinned previous head. Profile chưa có previous head không được
encode bằng zero/null/empty hash và vẫn quarantine/re-enroll qua flow riêng.

`leaf_hash = SHA256(ASCII "SHARDX-RESTORE-EPOCH-LEAF-V2\0" +
u32be(len(exact_leaf_bytes)) + exact_leaf_bytes)`. Builder sort ascending theo
raw tuple `(tenant_id[16],profile_id[16])`; duplicate tuple hoặc duplicate exact
leaf bị reject. `mapping_count` phải trong `1..MAX_RESTORE_EPOCH_LEAVES_V2`;
empty tree/transition bị reject, không có empty-root constant.

Mỗi level pair adjacent hashes left-to-right:

- binary node: `SHA256(ASCII "SHARDX-RESTORE-EPOCH-NODE2-V2\0" + left[32] + right[32])`;
- odd unpaired node: `SHA256(ASCII "SHARDX-RESTORE-EPOCH-NODE1-V2\0" + child[32])`.

Root của một leaf là chính `leaf_hash`; không apply unary ở level rỗng. Tree
không sort hash và không duplicate odd last node. Quy tắc này cùng sorted leaves
là exact `mapping_codec="PROFILE_HEAD_SET_MERKLE_V2"`.

`MerkleProofStepV2` là closed map với `direction:U16`: `0=SiblingLeft`,
`1=SiblingRight`, `2=UnaryPromote`. `sibling_hash:Hash32` required cho `0/1` và
phải omitted cho `2`; unknown direction/field reject. `RestoreEpochInclusionProofV2`
là closed map:

| Field | Type | Contract |
|---|---|---|
| `domain` | `tstr` | exact `shardx.restore-epoch.inclusion-proof.v2` |
| `version` | `U16` | exact `2` |
| `server_instance_id`, `tenant_id`, `profile_id` | `Uuid16` | required |
| `previous_epoch`, `new_epoch` | `U64` | required; `new_epoch>previous_epoch` |
| `mapping_codec` | `tstr` | exact `PROFILE_HEAD_SET_MERKLE_V2` |
| `leaf_index` | `U64` | required `0..leaf_count-1` |
| `leaf_count` | `U64` | required `1..1000000` |
| `canonical_leaf_bytes` | `Bytes(1,1024)` | exact leaf bytes |
| `leaf_hash`, `expected_root` | `Hash32` | recomputed leaf and signed transition root |
| `steps` | array of `MerkleProofStepV2` | required length `0..20`; exact shape derived from index/count |

Verifier recomputes expected parity/width at every level: left/right sibling
direction must match index; `UnaryPromote` only at an odd level's last index;
no omitted/extra/repeated step; final width/index must be `1/0`; computed root,
tenant/profile/epochs/count/codec must equal signed transition. `proof_sha256 =
SHA256(ASCII "SHARDX-RESTORE-EPOCH-PROOF-V2\0" +
u32be(len(exact_proof_bytes)) + exact_proof_bytes)`. Proof không có signature
riêng; exact signed transition container + root là authority.

**`RestoreEpochTransitionV2` signed payload/TBS/container**

Payload là closed map:

| Field | Type | Contract |
|---|---|---|
| `domain` | `tstr` | exact `shardx.restore-epoch.transition-payload.v2` |
| `version` | `U16` | exact `2` |
| `transition_replay_id` | `ReplayId16` | unique `(server_instance_id,tenant_id,replay_id)` |
| `server_instance_id`, `tenant_id` | `Uuid16` | required |
| `previous_epoch`, `new_epoch` | `U64` | required; `new_epoch>previous_epoch` |
| `mapping_codec` | `tstr` | exact `PROFILE_HEAD_SET_MERKLE_V2` |
| `mapping_count` | `U64` | required `1..1000000` |
| `profile_head_mapping_root` | `Hash32` | exact deterministic root |
| `reason_code` | enum | exact one of `operator_restore`,`disaster_recovery`,`verified_backup_rollback` |
| `approver_account_id`, `approver_device_id` | `Uuid16` | required same tenant |
| `approver_signing_key_id` | `KeyId32` | required active `root.custody` signer |
| `issued_at_ms` | `UnixMs` | required operator restore time |
| `nonce` | `Nonce16` | required; unique same tenant/instance |

`SignedRestoreEpochTransitionV2` outer closed map gồm exact fields:
`container_domain="shardx.restore-epoch.signed-transition-container.v2"`,
`container_version=2`, `payload_domain`, `payload_version=2`,
`canonical_transition_payload_bytes:Bytes(1,131072)`,
`transition_payload_sha256:Hash32`, `signature_suite_id:U16`,
`signature_version:U16=1`, `approver_signing_key_id:KeyId32`,
`signature_bytes:Bytes(1,4096)`, `signed_transition_container_hash:Hash32`.
TBS là canonical map của chín outer fields trước signature/hash. Signature input
là ASCII `SHARDX-RESTORE-EPOCH-TRANSITION-TBS-V2\0` +
`u32be(len(tbs_bytes))` + exact TBS bytes. Core là TBS fields + signature;
`signed_transition_container_hash = SHA256(ASCII
"SHARDX-RESTORE-EPOCH-TRANSITION-CONTAINER-V2\0" + u32be(len(core)) + core)`.
Exact outer bytes là core + container hash; `exact_signed_transition_bytes_sha256
= SHA256(exact outer bytes)`. Container signer key must equal decoded payload
key. Any payload/container/index/proof mismatch fails before unquarantine.

Golden-vector corpus cho mục này phải pin exact hex bytes + SHA-256 cho slot,
intent, transition, leaf, `n=1/2/3` roots và both direction/unary proofs; negative
vectors cover field omission/addition, wrong bound/domain/version/hash, empty
set, duplicate/reordered leaves, odd-last duplication, wrong direction/sibling,
extra/missing step và cross-tenant replay. G2 chỉ chọn suite/provider and fill
suite-specific nonce/output lengths; không đổi schema/preimage.

#### 5.6.4. Exact `TenantRootKeyGrantV2` contract

`TenantRootKeyGrantV2` dùng common authorization fields/validity/replay rules ở
5.6 và exact outer `SignedAuthorizationRecordV2`; payload domain là
`shardx.keys.tenant-root-key-grant.v2`, version `2`. Các field riêng:

| Field | Type | Optionality / contract |
|---|---|---|
| `grant_variant` | enum | required one of `FirstRootSelfGrant`,`ExistingRootGrant`,`RotationGrant` |
| `root_key_id` | `KeyId32` | required deterministic target TRK ID derived below |
| `root_generation` | `U64` | required target generation |
| `grant_capability` | `Capability` | exact `root.custody` |
| `subject_account_id`, `subject_device_id` | `Uuid16` | required same tenant |
| `subject_signing_key_id`, `recipient_hpke_key_id` | `KeyId32` | required and distinct |
| `subject_device_approval_replay_id` | `ReplayId16` | required exact active `DeviceApprovalV2` linkage |
| `hpke_suite_id` | `U16` | exact `1` = `SHARDX_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305_V1` |
| `hpke_mode_id` | `U8` | exact RFC 9180 base mode `0x00`; no PSK/auth mode |
| `hpke_kem_id` | `U16` | exact RFC 9180 `DHKEM(X25519, HKDF-SHA256)=0x0020` |
| `hpke_kdf_id` | `U16` | exact RFC 9180 `HKDF-SHA256=0x0001` |
| `hpke_aead_id` | `U16` | exact RFC 9180 `ChaCha20Poly1305=0x0003` |
| `hpke_info_bytes` | `Bytes(1,1024)` | required exact context bytes below |
| `hpke_encapped_key_bytes` | `Bytes32` | exact X25519 base-mode encapsulation output |
| `hpke_wrapped_trk_bytes` | `Bytes48` | exact 32-byte TRK plaintext + 16-byte ChaCha20Poly1305 tag |
| `previous_root_key_id` | `KeyId32` | required iff `grant_variant=RotationGrant`; otherwise omitted |
| `previous_root_generation` | `U64` | required iff rotation; otherwise omitted; target = previous + 1 |

Exact `TenantRootKeyGrantHpkeInfoV2` closed map gồm
`domain="shardx.keys.tenant-root-key-grant.hpke-info.v2"`, `version=2`,
`replay_id`, `tenant_id`, `server_instance_id`, `restore_epoch`, `root_key_id`,
`root_generation`, `subject_account_id`, `subject_device_id`,
`recipient_hpke_key_id`, `hpke_suite_id=1`, `hpke_mode_id=0`,
`hpke_kem_id=0x0020`, `hpke_kdf_id=0x0001`, `hpke_aead_id=0x0003`,
`grant_capability="root.custody"`.
`hpke_info_bytes` phải byte-identical canonical encoding của map đó và được đưa
trực tiếp làm RFC 9180 `info`; không hash/reconstruct/provider-label thêm.

TRK plaintext là đúng **32 raw uniformly random octets**, không CBOR/text/base64,
không prefix/suffix và không padding. `root_key_id` là toàn bộ 32-byte output:
`SHA256(ASCII "SHARDX-TENANT-ROOT-KEY-ID-V2\0" + u32be(32) + trk_bytes[32])`;
generation create, grant payload và post-open key-ID check đều phải bằng exact
giá trị này. HPKE dùng RFC 9180 `SetupBaseS/SetupBaseR` rồi one-shot sequence `0`.
AAD không rỗng và được tính duy nhất là `ASCII
"SHARDX-TENANT-ROOT-GRANT-AAD-V2\0" + u32be(len(hpke_info_bytes)) +
hpke_info_bytes`; exact bytes đó được truyền trực tiếp vào `Seal/Open`. Không
provider label, PSK, authenticated mode, exporter hoặc alternate AAD được phép.
Signed payload bind mode + every suite component, info, recipient, exact
32-byte encapsulation và exact 48-byte wrapped TRK. Parser verify exact container,
derived AAD/root key ID và all-column equality **trước/giữa HPKE open**; plaintext
khác 32 bytes hoặc derived ID mismatch fail closed và zeroize plaintext buffer.

Issuer/lifecycle rules không có placeholder:

1. `FirstRootSelfGrant` chỉ được nhận trong một `BEGIN IMMEDIATE` tenant-root
   bootstrap transaction khi no root generation, no root grant và no active
   `root.custody` exist. Subject enrollment PoP, exact active device approval và
   operator-confirmed OOB signing+HPKE fingerprints phải pass. Issuer key trong
   container bằng subject signing key. Transaction insert generation `0` as
   `PREPARING`, exact self-grant, bootstrap audit and idempotency response; second
   self-grant/bootstrap always rejects. Activation waits for client readback,
   HPKE unwrap/key-ID check and recovery-bundle readiness acknowledgment.
2. `ExistingRootGrant` targets current ACTIVE generation and must be signed by
   a different-or-same active same-tenant root custodian whose live capability,
   session, device and non-revoked grant all pass. It does not create/activate a
   generation.
3. `RotationGrant` targets a PREPARING N+1 generation, names exact previous
   ACTIVE N/key ID and is signed by an active custodian of N. Activation is one
   transaction after required custodian grant set + recovery readback pass:
   N+1 ACTIVE, N RETIRED, tenant active pointer update, idempotency response and
   audit. No snapshot/fleet rotation uses PREPARING root generation.
4. Revoking a root grant transactionally revokes its sessions/capability use,
   persists revocation response + audit and blocks future unwrap/grants. It
   cannot retract an already copied old TRK; excluding that device requires a
   new root generation and rewrapped fleet recovery grants. Retained snapshots
   remain subject to retention/recovery policy.

Exact endpoints:

- `POST /v2/tenants/{tenant_id}/root-key-generations` — bootstrap atomically
  creates generation `0` **with embedded exact first self-grant container**, or
  creates rotation PREPARING generation; exact idempotent request.
- `POST /v2/tenants/{tenant_id}/root-key-generations/{generation}/grants` — exact
  `ROOT_GRANT_CREATE` idempotent outer request whose payload embeds one exact
  existing/rotation `SignedAuthorizationRecordV2<TenantRootKeyGrantV2>`;
  `FirstRootSelfGrant` is rejected here because bootstrap only uses atomic create.
- `GET /v2/tenants/{tenant_id}/root-key-generations/{generation}/grants/{replay_id}`
  — deterministic primary-key readback; returns exact outer bytes + typed descriptor
  only when generation/root/replay tuple and byte/all-column equality all pass.
- `POST /v2/tenants/{tenant_id}/root-key-generations/{generation}/grants/{replay_id}/ack`
  — ack binds exact signed-container/full-byte hashes + successful local TRK key-ID check.
- `POST /v2/tenants/{tenant_id}/root-key-generations/{generation}/activate` —
  atomic activation/readback-set check.
- `POST /v2/tenants/{tenant_id}/root-key-generations/{generation}/grants/{replay_id}/revoke`
  — atomic revoke/session invalidation/audit; exact idempotent response.

Lifecycle endpoint payloads are also closed maps, never free-form JSON:

- `TenantRootGenerationCreateV2`: domain exact
  `shardx.keys.tenant-root-generation-create.v2`, version `2`, tenant/instance/
  epoch, `root_key_id`, `root_generation`, `mode` enum `bootstrap|rotation`,
  optional previous-root ID/generation required iff rotation,
  `required_custodian_grant_count:U32` in `1..65535`,
  `required_custodian_grant_set_hash:Hash32`,
  `recovery_bundle_sha256:Hash32`; `first_self_grant_container_bytes:Bytes(1,131072)`,
  `first_self_grant_signed_container_hash:Hash32` and
  `first_self_grant_container_bytes_sha256:Hash32` are required iff bootstrap
  and omitted iff rotation. Response returns exact PREPARING row + embedded grant identity.
- `TenantRootGrantCreateV2`: domain exact
  `shardx.keys.tenant-root-grant-create.v2`, version `2`, tenant/instance/epoch,
  target `root_generation`, `root_key_id`, grant `replay_id`,
  `exact_signed_grant_container_bytes:Bytes(1,131072)`,
  `signed_container_hash:Hash32` và
  `exact_signed_grant_container_bytes_sha256:Hash32`. Embedded bytes must decode
  to exactly one `ExistingRootGrant` or `RotationGrant` whose tenant/instance/
  epoch/root/replay fields equal the outer payload; `FirstRootSelfGrant` rejects.
  Exact response `TenantRootGrantCreatedV2` has domain
  `shardx.keys.tenant-root-grant-created.v2`, version `2`, same tenant/instance/
  epoch/root generation/root key/replay ID, exact `grant_variant`,
  `subject_device_id`, `recipient_hpke_key_id`, both container hashes,
  `grant_state="PENDING_ACK"` and `created_at_ms:UnixMs`; no optional fields.
- `TenantRootGrantAckV2`: domain exact `shardx.keys.tenant-root-grant-ack.v2`,
  version `2`, tenant/instance/epoch/generation/replay ID, root key ID,
  `signed_container_hash`, `exact_signed_container_bytes_sha256`, and
  `locally_unwrapped_trk_key_id` equal target root key ID.
- `TenantRootGenerationActivateV2`: domain exact
  `shardx.keys.tenant-root-generation-activate.v2`, version `2`, tenant/instance/
  epoch/generation/root key ID, required grant count/set hash and recovery bundle
  hash; response names prior/target generation and exact activation timestamp.
- `TenantRootGrantRevokeV2`: domain exact `shardx.keys.tenant-root-grant-revoke.v2`,
  version `2`, tenant/instance/epoch/generation/replay ID, both exact container
  hashes and `reason_code` enum `device_lost|custody_removed|rotation_exclusion`;
  response binds revocation timestamp and session-invalidated count.

These POSTs use the exact idempotent outer request/stored-response construction
of 5.6.5 with operation kinds `ROOT_GENERATION_CREATE`, `ROOT_GRANT_CREATE`, `ROOT_GRANT_ACK`,
`ROOT_GENERATION_ACTIVATE`, `ROOT_GRANT_REVOKE` and scopes respectively
`tenant.root-generation-create.v2`, `tenant.root-grant-create.v2`, `tenant.root-grant-ack.v2`,
`tenant.root-generation-activate.v2`, `tenant.root-grant-revoke.v2`; same-key response-loss replay
cannot create generation/grant, activate, acknowledge or revoke twice. GET descriptor is a closed map containing
the exact outer grant bytes/full hash plus every typed column named in 7.2;
missing/extra descriptor field is a readback failure. Its domain is `shardx.keys.tenant-root-grant-descriptor.v2`; the
payload's own `domain`/`version` columns are named `payload_domain`/`payload_version`, and every
map that names a stored grant calls its replay ID `replay_id`, as the 7.2 column does.

Every write/read/ack/activate/revoke reparses exact payload/container and compares
all fields one-for-one to indexed columns: common replay/tenant/time/instance/
epoch fields, variant/root IDs/generations/capability/subject/approval linkage,
every HPKE field, previous-root optional pair, signature metadata/bytes,
internal container hash and exact outer bytes/full hash. Any mismatch returns
`AUTH_CLAIM_COLUMN_MISMATCH`, quarantines the grant and performs no unwrap/mutation.

#### 5.6.5. Exact mutation request/stored-response/idempotency contracts

All remote non-COMMIT mutations below use `IdempotentMutationRequestV2`, an exact
closed map: `domain:tstr="shardx.sync.idempotent-mutation-request.v2"`,
`version:U16=2`, `operation_kind` exact enum
`PROFILE_PUBLISH_CREATE|PROFILE_CHECKOUT|CREATE_UPLOAD|FINALIZE_UPLOAD|RELEASE_LEASE|LOCAL_UNBIND|ROOT_GENERATION_CREATE|ROOT_GRANT_CREATE|ROOT_GRANT_ACK|ROOT_GENERATION_ACTIVATE|ROOT_GRANT_REVOKE`,
`operation_scope:tstr` exact per operation,
`idempotency_key:ReplayId16`, `canonical_payload_bytes:Bytes(1,262144)`,
`payload_sha256:Hash32`, `client_request_nonce:Nonce16`,
`server_instance_id:Uuid16`, `restore_epoch:U64`,
`canonical_request_hash:Hash32`. Request core omits only
`canonical_request_hash`; its hash is `SHA256(ASCII
"SHARDX-IDEMPOTENT-MUTATION-REQUEST-V2\0" + u32be(len(core_bytes)) + core_bytes)`.
`exact_request_bytes_sha256=SHA256(exact outer bytes)` is stored beside it.
Payload domain/version and outer operation/scope must match the table below.

Successful mutation returns and persists exact `IdempotentStoredResponseV2`
closed map: `domain="shardx.sync.idempotent-stored-response.v2"`, `version=2`,
same `operation_kind`, `operation_scope`, `idempotency_key`,
`exact_request_hash:Hash32`, `response_record_type:tstr`,
`canonical_response_payload_bytes:Bytes(1,262144)`,
`response_payload_sha256:Hash32`, `outcome:tstr="succeeded"`,
`server_instance_id:Uuid16`, `restore_epoch:U64`, `committed_at_ms:UnixMs`,
`receipt_id:ReplayId16`, `stored_response_hash:Hash32`. Response core omits only
`stored_response_hash`; hash domain is
`SHARDX-IDEMPOTENT-STORED-RESPONSE-V2\0` with length prefix. Storage also keeps
`exact_response_bytes_sha256=SHA256(exact outer bytes)`. Remote coordinator—or
Launcher DB for local unbind—persists mutation, audit/tombstone and exact response
in the same transaction before side effects are reported complete.

Operation payload/response maps are exact closed maps; every listed field required
unless explicitly optional:

| Operation / scope / payload domains | Exact request payload | Exact response payload |
|---|---|---|
| `ROOT_GENERATION_CREATE`; `tenant.root-generation-create.v2`; request `shardx.keys.tenant-root-generation-create.v2`; response `shardx.keys.tenant-root-generation-created.v2` | Exact `TenantRootGenerationCreateV2`: `domain`, `version=2`, tenant/instance/epoch, target root generation/key ID, `mode=bootstrap|rotation`, previous-root pair required iff rotation, required-custodian count/set hash, recovery-bundle hash, and exact first-self-grant bytes/internal/full hashes required iff bootstrap | `response_record_type="TenantRootGenerationCreatedV2"`; closed response has `domain`, `version=2`, same tenant/instance/epoch/root/mode/previous-root pair, required-custodian count/set hash, recovery-bundle hash, `generation_state="PREPARING"`, embedded first-self-grant replay/container hashes iff bootstrap, `created_at_ms`; transaction inserts generation, optional first self-grant, audit and exact stored response atomically |
| `ROOT_GRANT_CREATE`; `tenant.root-grant-create.v2`; request `shardx.keys.tenant-root-grant-create.v2`; response `shardx.keys.tenant-root-grant-created.v2` | Exact `TenantRootGrantCreateV2`: `domain`, `version=2`, tenant/instance/epoch, target root generation/key ID, grant replay ID, exact signed grant container bytes, internal container hash and full-bytes SHA-256; embedded grant must be exact existing/rotation variant and match every outer field | `response_record_type="TenantRootGrantCreatedV2"`; exact closed response has `domain`, `version=2`, same tenant/instance/epoch/root/replay identity, exact grant variant, subject device ID, recipient HPKE key ID, both container hashes, `grant_state="PENDING_ACK"`, `created_at_ms`; transaction also persists grant row + audit before response |
| `ROOT_GRANT_ACK`; `tenant.root-grant-ack.v2`; request `shardx.keys.tenant-root-grant-ack.v2`; response `shardx.keys.tenant-root-grant-acked.v2` | Exact `TenantRootGrantAckV2`: `domain`, `version=2`, tenant/instance/epoch, root generation/key ID, grant replay ID, signed-container internal/full hashes, `locally_unwrapped_trk_key_id` equal target root key ID | `response_record_type="TenantRootGrantAckedV2"`; closed response has `domain`, `version=2`, same tenant/instance/epoch/root/replay/container hashes, `ack_outcome="acknowledged"`, `acked_at_ms`; transaction verifies exact grant/HPKE key-ID readback, sets the one ack, writes audit and exact stored response atomically; replay never creates a second ack |
| `ROOT_GENERATION_ACTIVATE`; `tenant.root-generation-activate.v2`; request `shardx.keys.tenant-root-generation-activate.v2`; response `shardx.keys.tenant-root-generation-activated.v2` | Exact `TenantRootGenerationActivateV2`: `domain`, `version=2`, tenant/instance/epoch, target root generation/key ID, required grant count/set hash, recovery-bundle hash, previous ACTIVE generation/key ID omitted only for bootstrap generation `0` | `response_record_type="TenantRootGenerationActivatedV2"`; closed response has `domain`, `version=2`, same tenant/instance/epoch/target/previous pair and required hashes, `target_state="ACTIVE"`, `previous_state="RETIRED"` iff previous pair exists, tenant active root pointer, `activated_at_ms`; transaction validates all acknowledgements/recovery evidence, flips generation states/pointer, writes audit and exact stored response atomically |
| `ROOT_GRANT_REVOKE`; `tenant.root-grant-revoke.v2`; request `shardx.keys.tenant-root-grant-revoke.v2`; response `shardx.keys.tenant-root-grant-revoked.v2` | Exact `TenantRootGrantRevokeV2`: `domain`, `version=2`, tenant/instance/epoch, root generation/key ID, grant replay ID, signed-container internal/full hashes, exact `reason_code=device_lost|custody_removed|rotation_exclusion` | `response_record_type="TenantRootGrantRevokedV2"`; closed response has `domain`, `version=2`, same tenant/instance/epoch/root/replay/container hashes/reason, `revoke_outcome="revoked"`, `sessions_invalidated_count:U32`, `revoked_at_ms`; transaction revokes grant/capability sessions, writes audit and exact stored response atomically; replay never repeats invalidation or changes the timestamp/count |
| `PROFILE_PUBLISH_CREATE`; `profile.publish-create.v2`; request `shardx.sync.profile-publish-create-request.v2`; response `shardx.sync.profile-publish-create-response.v2` | `domain`, `version=2`, `tenant_id`, `fleet_id`, client-generated `profile_id:Uuid16`, `label_ciphertext:Bytes(1,4096)`, `requested_lease_ttl_seconds:U32` in `30..900`, `fkek_key_id:KeyId32`, `key_generation:U64` | `domain`, `version=2`, same tenant/fleet/profile, `lease_id:Uuid16`, `fencing_token:U64`, `base_version:U64=0`, `expires_at_ms:UnixMs`, exact active FKEK ID/generation, `current_signed_head_hash` omitted, instance/epoch |
| `PROFILE_CHECKOUT`; `profile.checkout.v2`; request `shardx.sync.profile-checkout-request.v2`; response `shardx.sync.profile-checkout-response.v2` | `domain`, `version=2`, tenant/fleet/profile, `observed_version:U64`, `observed_signed_head_hash:Hash32` omitted iff observed version `0`, requested TTL `30..900` | same IDs, `lease_id`, `fencing_token`, `base_version`, `expires_at_ms`, active FKEK ID/generation, `current_signed_head_hash` omitted iff base `0`, instance/epoch |
| `CREATE_UPLOAD`; `profile.create-upload.v2`; request `shardx.sync.create-upload-request.v2`; response `shardx.sync.create-upload-response.v2` | `domain`, `version=2`, tenant/fleet/profile, `snapshot_id:Uuid16`, `manifest_replay_id:ReplayId16`, lease/fence/base, intent/preamble/slot `Hash32`, FKEK ID/generation, expected ciphertext size `1..536870912` and hash | same identity/bindings, server `upload_id:Uuid16`, `committed_offset:U64=0`, `state="OPEN"`, `expires_at_ms`, instance/epoch |
| `FINALIZE_UPLOAD`; `profile.finalize-upload.v2`; request `shardx.sync.finalize-upload-request.v2`; response `shardx.sync.finalize-upload-response.v2` | `domain`, `version=2`, tenant/profile/upload/snapshot/replay IDs, exact signed-manifest bytes + internal/full `Hash32`, exact `CommitRequestV2` bytes + canonical/full `Hash32`, expected ciphertext size/hash, instance/epoch | same upload/snapshot/replay, `state="READY"`, immutable ciphertext size/hash, `object_receipt_id:ReplayId16`, instance/epoch |
| `RELEASE_LEASE`; `profile.release-lease.v2`; request `shardx.sync.release-lease-request.v2`; response `shardx.sync.release-lease-response.v2` | `domain`, `version=2`, tenant/fleet/profile, lease ID/fence/base, `reason_code` exact one of `user_release`,`cancel_publish`,`shutdown_cleanup` | same IDs/fence/base, `release_outcome="released"`, `released_at_ms`, instance/epoch |
| `LOCAL_UNBIND`; `local.profile.unbind.v2`; request `shardx.local.unbind-request.v2`; response `shardx.local.unbind-response.v2` | `domain`, `version=2`, `server_id:Text(1,512)`, instance/epoch, tenant/fleet/remote profile IDs, `local_profile_id:Text(1,255)`, `remote_version`, `expected_signed_head_hash` omitted iff version `0`, `require_no_lease=true`, `require_no_pending_operation=true` | same identity/versions, `unbind_outcome="unbound"`, `binding_tombstone_sha256:Hash32`, `completed_at_ms`, instance/epoch |

`COMMIT` remains exact `CommitRequestV2` → exact `CommitReceiptBindingV2`; it is
not wrapped/re-encoded by the common maps. Scope uniqueness for all operations is
`(tenant_id,actor_device_id,operation_scope,idempotency_key)` remotely and
`(operation_scope,idempotency_key)` locally. Same key requires canonical hash,
full exact bytes and all relational columns to match; otherwise
`IDEMPOTENCY_MISMATCH`/`MANIFEST_REPLAY_MISMATCH`.

Publish transaction atomically inserts version-0 profile, increments/sets initial
fence exactly once, inserts one current lease, exact idempotency response and audit;
no separate lease-less published state is exposed. Checkout transaction atomically
allocates lease/fence + response. Retry after response loss returns exact stored
bytes even if that lease has since expired; it never mints a replacement. Client
must HEAD/reconcile and use a **new** key for a new checkout. Create-upload retry
returns same upload ID; finalize retry returns same READY receipt; release retry
returns same release receipt after lease deletion; unbind retry returns tombstone
response after binding deletion. No handler reconstructs response from current rows.

---

## 6. ADR — Component và data flow

### 6.1. Component boundaries

1. **`shardx-core` / shared snapshot v2**
   - Streaming archive writer/reader.
   - Versioned envelope codec.
   - Archive policy validator và destination reseal.
   - Không biết HTTP, tenant auth hoặc UI.

2. **Server v2**
   - Auth/membership/device/fleet metadata.
   - Lease/fence/version state machine.
   - Resumable opaque ciphertext transfer.
   - Không import shared decrypt/key code.

3. **Launcher team client**
   - Credential/key provider.
   - Local bindings, outbox, encrypted spool, restore journal.
   - HTTP v2 client và state machine.
   - Common launch/stop claim integration.

4. **UI**
   - Hiển thị team state, key/recovery readiness, checkout/check-in và conflict choices.
   - Không trực tiếp quản lý key bytes hoặc gọi server ngoài Tauri commands.

### 6.2. Backup/check-in flow

```text
Stopped profile
  -> acquire local ProfileClaimGuard
  -> read consistent profile/SQLite state in bounded batches
  -> resolve/verify exact FleetKeyGrantV2::DeviceHpkeGrant payload/container/index equality outside envelope
  -> random DEK -> one DekSlotV2 wrapped under immutable FKEK key_id + generation
  -> canonical EnvelopeIntentV2 -> intent_hash (no ciphertext hash/size/final-manifest commitment)
  -> streaming tar+gzip v2 archive
  -> strict envelope STREAM AEAD encrypt; every DATA/FINAL frame AAD binds intent_hash
  -> encrypted .part spool + sha256/size
  -> canonical SnapshotManifestV2 payload -> exact SignedSnapshotManifestV2 container
  -> build exact CommitRequestV2; durably persist manifest container/request exact bytes + internal/full-byte hashes
  -> create/resume upload session bound to intent_hash + expected ciphertext digest/size
  -> PATCH exact-offset chunks with explicit chunk digest
  -> finalize: recompute hash/size -> immutable content-addressed object -> file+parent fsync
  -> commit(byte-identical persisted CommitRequestV2 with exact SignedSnapshotManifestV2 container)
  -> CAS server version/head bump + lease release + audit + exact CommitReceiptBindingV2 bytes/hash
  -> verify and durably persist byte-identical local receipt binding
  -> delete encrypted spool
```

Không có plaintext tar file trung gian. Nếu phải dùng temporary file cho SQLite consistency, file đó phải là SQLite snapshot trong validated local staging có restrictive ACL và được cleanup qua journal; ưu tiên online backup/read transaction.

### 6.3. Restore/checkout flow

```text
checkout -> one current lease/fence/base_version/server expiry
  -> verify exact signed FKEK grant bytes outside envelope + snapshot/head continuity against pinned state
  -> claim stopped destination profile
  -> create durable restore journal
  -> range-download ciphertext .part + exact detached SignedSnapshotManifestV2 outer bytes/hash
  -> verify payload/container/full-byte hashes, signature/head/epoch; ciphertext sha256/size; preamble/intent/one-slot hashes
  -> verify EnvelopeIntentV2 has no final-manifest commitment; every frame binds exact intent_hash
  -> decrypt -> decompress -> strict v2 validated staging extractor
  -> reseal destination cookies/login/web secrets
  -> pre-swap structural/integrity checks
  -> atomic swap user-data + profile metadata under journal
  -> restricted smoke launch
  -> commit local ready state OR rollback both trees
```

Smoke launch phải dùng profile test/disposable, mở URL tĩnh như `about:blank`, tắt/background-network hạn chế theo khả năng runtime, không truy cập tài khoản thật và không dùng canonical profile cho destructive test.

Server upload và local restore là hai durable state machines riêng. Không phase nào được suy luận từ việc file “có vẻ tồn tại”; mọi resume/recovery phải đọc journal/committed offset, verify exact signed bytes/hash/length và chọn transition fail-closed được mô tả ở mục 8.1 và 12. Commit retry sau process close/reopen phải load exact persisted `SignedSnapshotManifestV2`/`CommitRequestV2` artifacts; receipt replay phải load exact `CommitReceiptBindingV2`; verify toàn bộ upload/idempotency/lease/fence/base/intent/ciphertext/head/instance/epoch bindings và không re-serialize. Server startup reconciliation phải kết thúc hoặc quarantine mọi `FINALIZING` row trong cùng pass có bounded lock/timeout; không để trạng thái treo chờ retry vô hạn.

---

## 7. ADR — Server schema v2

Tên bảng là đề xuất; Architect có thể đổi naming nhưng không được làm yếu composite tenant boundary.

### 7.1. Identity và membership

- `v2_server_state(singleton CHECK singleton=1, server_instance_id, restore_epoch, external_record_sha256, updated_at)` — **transactional mirror/cache only**. Authority là external identity record ở 5.5/12.4, đặt ngoài mọi SQLite rollback/backup target, ghi temp → flush → atomic replace → parent-directory fsync. Startup không được mở v2 writes trước khi checksum/instance/epoch của external record và mirror reconciliation pass.
- `v2_tenants(id, slug, status, active_root_generation, created_at)`
- `v2_accounts(id, tenant_id, username, pw_hash, token_version, status, created_at, UNIQUE(tenant_id, username))`
- `v2_tenant_memberships(tenant_id, account_id, role CHECK role IN ('owner','admin','member'), status, created_at)`
- `v2_sessions(id, tenant_id, account_id, device_id, refresh_token_hash, expires_at, revoked_at)`
- `v2_devices(id, tenant_id, account_id, label_ciphertext, signing_key_id, signing_public_key, signing_suite, hpke_key_id, hpke_public_key, hpke_suite, status, last_seen_at, created_at)`
- `v2_enrollment_challenges(id, tenant_id, server_instance_id, restore_epoch, nonce_hash, key_commitment, expires_at, consumed_at)`
- `v2_device_approvals(tenant_id, replay_id, payload_domain, payload_version, subject_account_id, subject_device_id, subject_signing_key_id, subject_hpke_key_id, approval_scope_kind, approval_scope_id, approved_use, issued_at_ms, not_before_ms, not_after_ms, server_instance_id, restore_epoch, canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version, signature_bytes, issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes, exact_signed_container_bytes_sha256, revoked_at, created_at)` — exact `DeviceApprovalV2` map/columns ở 5.6.1; unique `(tenant_id,payload_domain,replay_id)`.
- `v2_capability_grants(tenant_id, replay_id, payload_domain, payload_version, subject_kind, subject_account_id, subject_device_id NULL, subject_signing_key_id NULL, subject_hpke_key_id NULL, scope_kind, scope_id, capability, issued_at_ms, not_before_ms, not_after_ms, server_instance_id, restore_epoch, canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version, signature_bytes, issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes, exact_signed_container_bytes_sha256, revoked_at, created_at)` — exact `TenantCapabilityGrantV2`; device fields all-present hoặc all-NULL theo `subject_kind`.
- `v2_fleets(id, tenant_id, label_ciphertext, status, created_by, created_at)`
- `v2_fleet_memberships(tenant_id, fleet_id, account_id, permission, created_at)`

RBAC deny-by-default dùng role `owner`, `admin`, `member` làm coarse baseline và explicit capabilities cho mutation nhạy cảm. Capability tối thiểu: `tenant.manage`, `membership.manage`, `fleet.manage`, `device.approve`, `device.revoke`, `key.rotate`, `recovery.manage`, `lease.force_expire`, `profile.publish`, `profile.checkout`, `profile.commit`, `root.custody`. `root.custody` là capability riêng, không tự suy ra từ role owner/admin; ordinary fleet device không nhận TRK grant.

### 7.2. Key distribution metadata

- `v2_root_key_generations(server_instance_id, tenant_id, generation, root_key_id, state CHECK state IN ('PREPARING','ACTIVE','RETIRED'), recovery_bundle_sha256, required_custodian_grant_count, required_custodian_grant_set_hash, created_at, activated_at, retired_at, PRIMARY KEY(server_instance_id,tenant_id,generation), UNIQUE(server_instance_id,tenant_id,root_key_id), UNIQUE(server_instance_id,tenant_id,generation,root_key_id))`
- `v2_tenant_root_key_grants(server_instance_id, tenant_id, replay_id, container_domain, container_version, payload_domain, payload_version, grant_variant, root_key_id, root_generation, grant_capability, subject_account_id, subject_device_id, subject_signing_key_id, subject_device_approval_replay_id, recipient_hpke_key_id, hpke_suite_id, hpke_mode_id, hpke_kem_id, hpke_kdf_id, hpke_aead_id, hpke_info_bytes, hpke_encapped_key_bytes, hpke_wrapped_trk_bytes, previous_root_key_id NULL, previous_root_generation NULL, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version, issuer_signing_key_id, signature_bytes, signed_container_hash, exact_signed_container_bytes, exact_signed_container_bytes_sha256, acked_at, revoked_at, created_at, PRIMARY KEY(server_instance_id,tenant_id,replay_id), UNIQUE(server_instance_id,tenant_id,payload_domain,replay_id), FOREIGN KEY(server_instance_id,tenant_id,root_generation,root_key_id) REFERENCES v2_root_key_generations(server_instance_id,tenant_id,generation,root_key_id))` — exact `TenantRootKeyGrantV2`; previous-root pair both present iff rotation; HPKE tuple exact `(suite,mode,KEM,KDF,AEAD)=(1,0,0x0020,0x0001,0x0003)`, encapped/wrapped lengths exact `32/48`, và mọi HPKE/container column bounded per 5.6.4.
- Partial UNIQUE `(server_instance_id,tenant_id) WHERE grant_variant='FirstRootSelfGrant'`; first self-grant also requires generation `0`. Application `BEGIN IMMEDIATE` emptiness check + this index jointly reject concurrent/second bootstrap.
- `v2_fleet_key_generations(server_instance_id, tenant_id, fleet_id, generation, fkek_key_id, state CHECK state IN ('PREPARING','ACTIVE','RETIRED'), recovery_grant_hash, required_grant_set_hash, activated_at, retired_at, PRIMARY KEY(server_instance_id,tenant_id,fleet_id,generation), UNIQUE(server_instance_id,tenant_id,fleet_id,fkek_key_id), UNIQUE(server_instance_id,tenant_id,fleet_id,generation,fkek_key_id))`
- `v2_fleet_device_hpke_grants(server_instance_id, tenant_id, replay_id, payload_domain, payload_version, grant_variant, fleet_id, fkek_key_id, generation, grant_capability, subject_account_id, subject_device_id, subject_signing_key_id, recipient_hpke_key_id, hpke_suite_id, hpke_info_bytes, hpke_encapped_key_bytes, hpke_wrapped_fleet_key_bytes, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version, signature_bytes, issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes, exact_signed_container_bytes_sha256, acked_at, revoked_at, created_at, PRIMARY KEY(server_instance_id,tenant_id,replay_id), UNIQUE(server_instance_id,tenant_id,payload_domain,replay_id), FOREIGN KEY(server_instance_id,tenant_id,fleet_id,generation,fkek_key_id) REFERENCES v2_fleet_key_generations(server_instance_id,tenant_id,fleet_id,generation,fkek_key_id))`
- `v2_fleet_recovery_grants(server_instance_id, tenant_id, replay_id, payload_domain, payload_version, grant_variant, fleet_id, fkek_key_id, generation, grant_capability, recipient_root_key_id, recipient_root_generation, root_wrap_suite_id, root_wrap_nonce_bytes, root_wrap_context_bytes, wrapped_fleet_key_bytes, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version, signature_bytes, issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes, exact_signed_container_bytes_sha256, acked_at, revoked_at, created_at, PRIMARY KEY(server_instance_id,tenant_id,replay_id), UNIQUE(server_instance_id,tenant_id,payload_domain,replay_id), FOREIGN KEY(server_instance_id,tenant_id,fleet_id,generation,fkek_key_id) REFERENCES v2_fleet_key_generations(server_instance_id,tenant_id,fleet_id,generation,fkek_key_id))`
- `v2_fleet_rotation_grants(server_instance_id, tenant_id, replay_id, payload_domain, payload_version, grant_variant, fleet_id, fkek_key_id, generation, grant_capability, previous_fkek_key_id, previous_generation, required_device_grant_count, required_device_grant_set_hash, recovery_grant_signed_container_hash, activation_not_before_ms, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version, signature_bytes, issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes, exact_signed_container_bytes_sha256, acked_at, revoked_at, created_at, PRIMARY KEY(server_instance_id,tenant_id,replay_id), UNIQUE(server_instance_id,tenant_id,payload_domain,replay_id), FOREIGN KEY(server_instance_id,tenant_id,fleet_id,generation,fkek_key_id) REFERENCES v2_fleet_key_generations(server_instance_id,tenant_id,fleet_id,generation,fkek_key_id))`
- `v2_restore_epoch_transitions(server_instance_id, tenant_id, previous_epoch, new_epoch, transition_replay_id, mapping_codec, mapping_count, profile_head_mapping_root, reason_code, approver_account_id, approver_device_id, approver_signing_key_id, issued_at_ms, nonce, canonical_transition_payload_bytes, transition_payload_sha256, signature_suite_id, signature_version, signature_bytes, signed_transition_container_hash, exact_signed_transition_bytes, exact_signed_transition_bytes_sha256, created_at, PRIMARY KEY(server_instance_id,tenant_id,previous_epoch,new_epoch), UNIQUE(server_instance_id,tenant_id,transition_replay_id), UNIQUE(server_instance_id,tenant_id,nonce))`
- `v2_restore_epoch_transition_proofs(server_instance_id, tenant_id, previous_epoch, new_epoch, profile_id, previous_signed_head_hash, new_signed_head_hash, leaf_index, leaf_count, canonical_leaf_bytes, leaf_hash, canonical_inclusion_proof_bytes, proof_sha256, created_at, PRIMARY KEY(server_instance_id,tenant_id,previous_epoch,new_epoch,profile_id), FOREIGN KEY(server_instance_id,tenant_id,previous_epoch,new_epoch) REFERENCES v2_restore_epoch_transitions(...))`

Mọi trường `wrapped_*` là ciphertext; server không có private key. Sáu payload/grant + signed containers ở 5.6.1/5.6.4 được persist exact bytes + internal/external hashes; exact transition payload/container và proof artifacts theo 5.6.3 được persist đầy đủ. Không record nào được tái dựng từ indexed columns. Trước mọi authorization hoặc key release, bounded parser phải verify domain/version/canonical encoding, payload hash, TBS signature, signed-container hash, exact outer-bytes hash và issuer key, rồi require exact equality của **mọi** field tới bảng variant. Với `DeviceHpkeGrant` và `TenantRootKeyGrantV2`, equality bắt buộc gồm HPKE suite, exact info, recipient key, encapped và wrapped bytes trước HPKE open. Mismatch là security incident, không chỉ validation error. Device HPKE grants chỉ phân phối FKEK generation **ngoài snapshot envelope**. Snapshot envelope không chứa recipient-device list và không đổi khi membership đổi. `PREPARING` không được dùng cho snapshot mới; root/fleet activation chỉ được phép sau exact grant/readback/ack set và recovery evidence tương ứng.

### 7.3. Profile, lease, upload và snapshot

- `v2_profiles(tenant_id, fleet_id, id, label_ciphertext, current_version, last_fencing_token, current_key_generation, status, created_at, updated_at)`
- `v2_profile_leases(tenant_id, profile_id, lease_id, owner_account_id, owner_device_id, fencing_token, base_version, acquired_at, expires_at, checkout_request_id, PRIMARY KEY(tenant_id, profile_id))`
- `v2_uploads(server_instance_id, tenant_id, upload_id, fleet_id, profile_id, snapshot_id, manifest_replay_id, lease_id, fencing_token, base_version, restore_epoch, operation_scope, idempotency_key, canonical_request_hash, exact_commit_request_bytes, exact_commit_request_bytes_sha256, intent_hash, preamble_sha256, dek_slot_sha256, fkek_key_id, key_generation, expected_ciphertext_size, expected_ciphertext_sha256, committed_offset, staging_path, immutable_path, state, signed_manifest_container_bytes, signed_manifest_container_hash, signed_manifest_container_bytes_sha256, exact_finalize_response_bytes, exact_commit_receipt_binding_bytes, commit_receipt_binding_bytes_sha256, expires_at, created_at, PRIMARY KEY(server_instance_id,tenant_id,upload_id), UNIQUE(server_instance_id,tenant_id,profile_id,snapshot_id), UNIQUE(server_instance_id,tenant_id,profile_id,manifest_replay_id), UNIQUE(server_instance_id,tenant_id,upload_id,fleet_id,snapshot_id,manifest_replay_id), FOREIGN KEY(server_instance_id,tenant_id,fleet_id,key_generation,fkek_key_id) REFERENCES v2_fleet_key_generations(server_instance_id,tenant_id,fleet_id,generation,fkek_key_id))`
- `v2_upload_chunks(tenant_id, upload_id, chunk_offset, chunk_length, chunk_sha256, PRIMARY KEY(tenant_id, upload_id, chunk_offset))`
- `v2_snapshots(server_instance_id, tenant_id, fleet_id, profile_id, version, snapshot_id, manifest_replay_id, upload_id, fkek_key_id, key_generation, envelope_version, intent_hash, preamble_sha256, dek_slot_sha256, immutable_blob_path, ciphertext_sha256, ciphertext_size, signed_manifest_container_bytes, signed_manifest_container_hash, signed_manifest_container_bytes_sha256, previous_head_hash, head_hash, signing_key_id, signature_suite_id, signature_version, signature_bytes, restore_epoch, created_by_device, created_at, PRIMARY KEY(server_instance_id,tenant_id,profile_id,version), UNIQUE(server_instance_id,tenant_id,profile_id,snapshot_id), UNIQUE(server_instance_id,tenant_id,profile_id,manifest_replay_id), FOREIGN KEY(server_instance_id,tenant_id,upload_id,fleet_id,snapshot_id,manifest_replay_id) REFERENCES v2_uploads(server_instance_id,tenant_id,upload_id,fleet_id,snapshot_id,manifest_replay_id), FOREIGN KEY(server_instance_id,tenant_id,fleet_id,key_generation,fkek_key_id) REFERENCES v2_fleet_key_generations(server_instance_id,tenant_id,fleet_id,generation,fkek_key_id))`
- `v2_idempotency(server_instance_id, tenant_id, actor_device_id, operation_scope, idempotency_key, operation_kind, canonical_request_hash, exact_request_bytes, exact_request_bytes_sha256, status, response_record_type, exact_response_bytes, exact_response_bytes_sha256, retained_until, PRIMARY KEY(server_instance_id,tenant_id,actor_device_id,operation_scope,idempotency_key))` — non-COMMIT response là exact `IdempotentStoredResponseV2`; commit response là exact `CommitReceiptBindingV2`.
- `v2_audit_events(tenant_id, id, actor_account_id, actor_device_id, action, target_type, target_id, outcome, reason_code, request_id, created_at)`

### 7.4. Schema invariants

- Tài nguyên tenant-owned coordination v2 dùng `server_instance_id` + `tenant_id` trong composite PK/UNIQUE/FK; không FK/key-generation row nào ngầm dựa vào instance của process hiện tại.
- Mọi server/local SQLite column ánh xạ unsigned wire value có explicit domain `0..9223372036854775807`; decoder reject out-of-range trước SQL bind và DDL reject bypassed/fixture inserts. U16/U32 fields giữ bound hẹp hơn khi schema biết exact type.
- `v2_profile_leases` có đúng một current-row key `(tenant_id, profile_id)` khi đang held; checkout replace expired row trong transaction, release/commit delete row. Không lưu lịch sử lease trong bảng current; lịch sử nằm ở audit.
- Fencing token là signed 64-bit monotonic integer; increment và grant lease trong cùng transaction; overflow fail closed.
- `(server_instance_id, tenant_id, profile_id, version)` unique; version chỉ tăng một khi commit thành công.
- `(server_instance_id, tenant_id, actor_device_id, operation_scope, idempotency_key)` unique. Publish/checkout/create-upload/finalize/release dùng exact `IdempotentMutationRequestV2`/`IdempotentStoredResponseV2`; local unbind dùng cùng exact bytes trong local authority. Commit dùng exact `CommitRequestV2`: `canonical_request_hash` domain-separately hash canonical core và exact request bytes/hash được persist; request chứa exact `SignedSnapshotManifestV2` outer bytes, outer-bytes hash và internal signed-container hash.
- Mỗi tenant/fleet có tối đa một root/fleet generation `ACTIVE` per `server_instance_id`; root rows key `(server_instance_id,tenant_id,generation)`, fleet rows key `(server_instance_id,tenant_id,fleet_id,generation)` và expose exact candidate UNIQUE `(server_instance_id,tenant_id,fleet_id,generation,fkek_key_id)`. Cả ba fleet grant tables cùng upload/snapshot đều carry `server_instance_id,tenant_id,fleet_id,generation/key_generation,fkek_key_id` và composite-FK tới candidate key đó; không current-instance hoặc profile-join lookup ngầm. `root_key_id`/`fkek_key_id` immutable và không tái sử dụng qua generation.
- Mỗi snapshot upload bind đúng một preallocated `snapshot_id`, `manifest_replay_id`, `intent_hash` và `dek_slot_sha256` dưới exact immutable `(server_instance_id,tenant_id,fleet_id,fkek_key_id,generation)`. Upload/snapshot equality được khóa bằng UNIQUE + composite FK trên `(server_instance_id,tenant_id,upload_id,fleet_id,snapshot_id,manifest_replay_id)`; manifest parse phải bằng cả hai rows. Không có lease snapshot column, per-device slot hoặc final-manifest commitment trong intent/header.
- Exact `signed_manifest_container_bytes` và exact `CommitRequestV2` bytes phải đã được persist durable trước finalize/commit; **exact bytes là replay authority**. Internal hash + full outer/request bytes hashes và exact request binding phải match upload/idempotency/lease/fence/base/intent/ciphertext/`server_instance_id`/`restore_epoch` columns. Parser verify signature, canonical payload/container/request bytes, bounded integers, `intent_hash`, preamble/slot hashes, previous head, version, instance/epoch và equality với upload/snapshot columns trước CAS; restart replay không được re-encode hoặc lấy relational columns làm authority.
- Mọi approval/capability/fleet/root-key record phải dùng exact schema ở 5.6.1/5.6.4, persist payload bytes/hash, signature metadata/bytes, signed-container hash, exact outer bytes/hash và toàn bộ variant columns. Authorization/key release chỉ xảy ra sau signature verification **và** exact all-column equality; artifact columns riêng lẻ không có authenticity. Root HPKE equality gồm exact suite/mode/KEM/KDF/AEAD tuple, info-derived AAD, recipient, 32-byte encapsulation, 48-byte ciphertext, post-open raw-32 TRK và deterministic root-key-ID preimage; mismatch reject trước key use.
- Commit transaction persist exact canonical `CommitReceiptBindingV2` bytes + SHA-256 cùng snapshot/head/profile-version/lease-release/idempotency row. `exact_response_bytes` của commit là chính bytes đó; replay trả nguyên bytes, không serialize lại. Receipt field/request/snapshot/head/instance/epoch mismatch là `RECEIPT_MISMATCH`.
- Commit idempotency row không GC trước snapshot/receipt retention liên quan; retention floor là max snapshot retention của tenant.
- Publish-create/checkout/release, approval, root/fleet grant/revoke/rotate/activate, recovery export/import metadata và force-expire phải check trusted live role/session/capability state, persist mutation + exact idempotency response + structured audit trong **cùng transaction**; audit/response insert fail thì mutation rollback.
- Revoke + activation generation mới là một logical operation: transaction revoke device/session/grant, `PREPARING -> ACTIVE`, prior `ACTIVE -> RETIRED`, update profile/fleet generation pointer và audit; thiếu exact grant ack/capability làm toàn bộ fail.
- Audit dùng enum/reason code; cấm free-form request body/detail.
- Server DB/blob path phải local filesystem; network share bị preflight reject.
- Server time từ một transaction/request context là authority cho checkout/renew/commit; client timestamp không tham gia validity decision.
- `RestoreEpochTransitionV2`/proof dùng exact 5.6.3: `new_epoch > previous_epoch`, codec exact `PROFILE_HEAD_SET_MERKLE_V2`, count `1..1000000`, sorted unique leaves, explicit binary/unary domains và direction shape. Transition/cache/proof tenant-scoped theo unique `(server_instance_id,tenant_id,previous_epoch,new_epoch)` + replay/nonce uniqueness. Mỗi binding cần exact same-tenant inclusion proof trước unquarantine; empty/duplicate/reordered/cross-tenant sets reject.

---

## 8. ADR — API v2, MCP và UI

### 8.1. API surface đề xuất

#### Auth/device/fleet

- `POST /v2/auth/login` — tenant slug + credentials; short-lived access token, opaque refresh token hash lưu server.
- `POST /v2/auth/refresh`, `POST /v2/auth/logout`, `GET /v2/me`.
- `POST /v2/devices/enrollment-challenges`, `POST /v2/devices/enrollment-proofs` — challenge + PoP bind cả signing/HPKE key IDs và server epoch.
- `POST /v2/devices/{id}/approve`, `POST /v2/devices/{id}/revoke` — nhận exact `SignedAuthorizationRecordV2<DeviceApprovalV2>` outer bytes; server parse/recompute payload/TBS/container/full-bytes hashes và verify exact equality map ở 5.6.1 trước capability + audit transaction.
- `GET/POST /v2/fleets`, `GET/PATCH /v2/fleets/{id}/members`, `POST /v2/capability-grants` — capability grant nhận exact `SignedAuthorizationRecordV2<TenantCapabilityGrantV2>`; account/device optionality và every indexed field phải match trước authorization.
- `POST /v2/fleets/{id}/key-generations`, `POST /v2/fleets/{id}/key-generations/{generation}/ack`, `POST /v2/fleets/{id}/key-generations/{generation}/activate`.
- `POST /v2/fleets/{id}/key-generations/{generation}/grants` — nhận một trong ba exact `FleetKeyGrantV2` signed containers; domain/variant mismatch reject. Rotation activation require exact RecoveryGrant + required DeviceHpkeGrant set hashes.
- `GET /v2/fleets/{id}/key-generations/{generation}/grants/{device_id}` — trả byte-identical exact `DeviceHpkeGrant` outer container + indexed descriptor. Client/server verify signature/container hashes và exact equality, gồm HPKE suite/info/encapped/wrapped bytes, trước HPKE open/FKEK release.
- Root custody endpoints là exact set ở 5.6.4: create generation; idempotent `ROOT_GRANT_CREATE`; deterministic grant readback by `{replay_id}`; ack; activate; revoke. First bootstrap self-grant và subsequent/rotation issuer rules không được đi đường admin/grant chung khác.
- `POST /v2/recovery/restore-epoch-transitions`, `GET /v2/recovery/restore-epoch-transitions/{tenant_id}/{previous_epoch}/{new_epoch}`, `GET /v2/recovery/restore-epoch-transitions/{tenant_id}/{previous_epoch}/{new_epoch}/proofs/{profile_id}` — persist/read exact `SignedRestoreEpochTransitionV2` + `RestoreEpochInclusionProofV2` bytes theo 5.6.3; mutation cần same-tenant `root.custody` + audit transaction, cross-tenant request trả deny/not-found.
- Remote endpoint bắt buộc HTTPS; plaintext HTTP chỉ được phép loopback development.

#### Profile/lease

- `GET /v2/fleets/{fleet_id}/profiles`
- `POST /v2/fleets/{fleet_id}/profiles` — exact `PROFILE_PUBLISH_CREATE`; atomically create version-0 profile + initial current lease/fence + stored response + audit. Không có successful response không lease.
- `POST /v2/profiles/{profile_id}/checkout` — exact `PROFILE_CHECKOUT`; atomically allocate one lease/fence + stored response. Same exact replay returns same bytes/lease/fence, kể cả receipt đã expired; không mint second lease/fence.
- `POST /v2/profiles/{profile_id}/leases/{lease_id}/renew`
- `POST /v2/profiles/{profile_id}/leases/{lease_id}/release` — exact `RELEASE_LEASE`; lease delete + stored response + audit same transaction; replay after delete returns stored bytes.
- `POST /v2/profiles/{profile_id}/leases/{lease_id}/force-expire` — cần `lease.force_expire`; capability check + mutation + audit cùng transaction.

Publish/checkout responses là exact `IdempotentStoredResponseV2` chứa payload ở 5.6.5: lease ID, fence, base, server expiry, instance/epoch, current signed head optionality và active key generation; không chứa plaintext. Renew chỉ thành công khi current row khớp và `expires_at > server_now`; không có relaunch grace. Local Launcher unbind dùng exact `LOCAL_UNBIND` request/response/tombstone contract ở 5.6.5 và chỉ xóa binding sau no-lease/no-pending readback.

#### Resumable ciphertext transfer

- `POST /v2/profiles/{profile_id}/uploads` — exact `CREATE_UPLOAD`; bind immutable `snapshot_id`, `manifest_replay_id`, intent/preamble/one-slot hashes, FKEK ID/generation, expected ciphertext size/hash, base/fence và scoped idempotency; không nhận final-manifest commitment. Replay returns same upload ID.
- `HEAD /v2/uploads/{upload_id}` — current offset/state.
- `PATCH /v2/uploads/{upload_id}` — chunk với `Upload-Offset` + `Upload-Chunk-SHA256`; exact-offset durable state machine dưới đây.
- `POST /v2/uploads/{upload_id}/finalize` — exact `FINALIZE_UPLOAD`; client chỉ gọi sau khi exact `SignedSnapshotManifestV2` container + exact `CommitRequestV2` đã được persist durable locally. Server verifies upload/snapshot/replay equality, recompute hash/size, strict envelope contracts, promote/fsync immutable object và persist exact container/request + exact READY stored response without advancing version. Replay returns same READY/object receipt bytes.
- `POST /v2/uploads/{upload_id}/commit` — body là byte-identical exact `CommitRequestV2` ở 5.6.2. Server verify canonical request hash/full-bytes hash; exact signed-manifest outer bytes/full hash/internal container hash; every request-to-upload/idempotency/lease/fence/base/intent/ciphertext/instance/epoch equality; applicable signed authorization record equality; rồi CAS insert signed head, bump version, release lease, audit và persist exact `CommitReceiptBindingV2` bytes/hash. Response loss/restart replay chính receipt bytes; re-encoded request hoặc receipt fail closed.
- `DELETE /v2/uploads/{upload_id}` — abort idempotent.
- `GET /v2/profiles/{profile_id}/snapshots/{version}` — hỗ trợ `Range`, `ETag` bằng ciphertext SHA-256, `Content-Length`, immutable FKEK generation và exact detached signed-manifest bytes/URL; manifest signature + hash phải verify trước decrypt.

Không dùng một multipart request kéo dài cho profile lớn. Chunk size transport độc lập với AEAD frame size; chunk boundary không được làm thay đổi ciphertext. Tenant aggregate quota, concurrent-upload slots, chunk cap, encrypted-spool reserve và minimum-free-disk preflight đều là config có hard ceiling; pilot per-snapshot default vẫn 512 MiB tới khi fixture evidence cho phép đổi.

#### PATCH/finalize/commit/fsync/recovery state machine

Upload states: `OPEN -> FINALIZING -> READY -> COMMITTED`; terminal lỗi là `ABORTED` hoặc `QUARANTINED`. Mỗi upload có một process-local writer lock cộng DB CAS; concurrent PATCH/reconciliation cùng upload không được interleave. `FINALIZING` là transient recovery state, không phải waiting room.

**PATCH — thứ tự bắt buộc**

1. Validate auth/scope/state, chunk cap và `Upload-Chunk-SHA256`; đọc `committed_offset` trong transaction ngắn. Request offset phải bằng exact committed offset. Offset cũ chỉ được trả như duplicate success khi `(offset,length,digest)` trùng chunk receipt đã persist; mọi mismatch trả `UPLOAD_OFFSET_MISMATCH` và client phải `HEAD` rồi resume.
2. Ghi bytes vào encrypted staging file đúng offset; không advance DB trước file.
3. Gọi `sync_data`/Windows durable file flush và kiểm tra lỗi.
4. Trong SQLite transaction CAS `state='OPEN' AND committed_offset=old`, insert chunk receipt rồi advance `committed_offset`; commit DB trước khi trả success.
5. Sau crash/restart: file dài hơn DB offset bị truncate về committed offset rồi flush; file ngắn hơn offset, thiếu file hoặc digest segment sai chuyển `QUARANTINED` và không resume.

**Finalize/commit — thứ tự bắt buộc**

1. CAS `OPEN -> FINALIZING` chỉ khi committed offset bằng expected size; stream-recompute full ciphertext SHA-256/size và strict envelope public grammar. Verify exact 5.6.3 preamble/`EnvelopeIntentV2`/one `DekSlotV2`, context/slot/intent domain hashes, snapshot/replay IDs và DATA/FINAL framing; reject mọi field/hash/optional/bound drift hoặc final-manifest commitment trong intent/header.
2. Rename sang immutable content-addressed path từ ciphertext SHA-256. Existing object chỉ reuse khi byte size/hash khớp; mismatch là quarantine.
3. Flush immutable file và fsync parent directory bằng Windows durability adapter đã được G2 prove; không có durable equivalent thì G2 fail và Team runtime không mở.
4. Client phải đã persist/fsync exact `SignedSnapshotManifestV2` outer container bytes/internal+full hashes và exact `CommitRequestV2` bytes/canonical+full hashes trước finalize. Persist `READY` + immutable path + exact artifact hashes + exact finalize stored response bằng CAS. Trong SQLite commit transaction kế tiếp: compare byte-identical request/manifest to persisted bytes/hashes; parse/verify exact schemas ở 5.6.2; require manifest/request/upload/snapshot `snapshot_id` + `manifest_replay_id` equality; check trusted live role/capability/session/revocation, every applicable signed approval/capability/FKEK record with signature + all-column equality, one current lease row với `expires_at > server_now`, exact fence/base, immutable FKEK generation, intent/ciphertext binding và idempotency hash; insert snapshot/signed head through composite upload FK, advance version, delete lease, persist exact `CommitReceiptBindingV2` + audit, rồi mark upload `COMMITTED`.
5. DB failure trước transaction commit để lại `READY` hoặc unreferenced immutable ciphertext; không tự advance profile. Client retry cùng scoped key có thể commit nếu lease vẫn valid; nếu không, fail closed và object đi vào reconciliation/GC sau retention floor.
6. Crash after DB commit/before response được giải quyết bằng exact persisted receipt. Startup reconciliation dùng matrix dưới đây; object không có DB reference giữ immutable, không phục vụ download và chỉ GC sau grace + audit khi không có mismatch/security incident.

Crash injection bắt buộc tại: trước/sau write, file flush, offset DB update, hash verify, rename, file fsync, parent fsync, READY CAS, DB commit và HTTP response.

**Recovery classification và precedence — exhaustive contract**

- `S ∈ {Ø,V,X}`: staging absent; valid; hoặc invalid/short/corrupt. Với `OPEN`, `V` nghĩa prefix `[0, committed_offset)` khớp persisted chunk digests; tail dài hơn offset được truncate+flush trước classification, còn missing/short khi offset > 0 là `X`. Với state khác, `V` nghĩa exact expected full hash/size.
- `I ∈ {Ø,V,X}`: immutable absent; exact expected full hash/size và content-addressed path valid; hoặc present nhưng invalid/short/corrupt.
- `R ∈ {Ø,V,X}`: snapshot receipt absent; exact canonical receipt bytes + request hash + snapshot row + signed head/version cross-links đều valid; hoặc receipt present nhưng bất kỳ link/hash/bytes nào mismatch.
- Rule được đọc từ trên xuống trong đúng state. `*` bao phủ mọi giá trị còn lại, nên bảng phân hoạch toàn bộ DB state × staging × immutable × hash/size × receipt. Mọi `X` preserve evidence; không silent retry commit/GC.

| DB state | Receipt `R` | Immutable `I` | Staging `S` | Deterministic action |
|---|---|---|---|---|
| `OPEN` | `V`/`X` | `*` | `*` | Impossible receipt state → `QUARANTINED`, security event; không sửa head |
| `OPEN` | `Ø` | `V`/`X` | `*` | Immutable object trước finalize hoặc invalid object → `QUARANTINED` |
| `OPEN` | `Ø` | `Ø` | `X` | `QUARANTINED`; không resume short/corrupt prefix |
| `OPEN` | `Ø` | `Ø` | `V` | Giữ `OPEN` tại exact committed offset; `HEAD`/PATCH có thể resume |
| `OPEN` | `Ø` | `Ø` | `Ø` | Chỉ giữ `OPEN` khi committed offset = 0; ngược lại classify `X` và quarantine |
| `FINALIZING` | `X` | `*` | `*` | `QUARANTINED`, security event |
| `FINALIZING` | `*` | `X` | `*` | `QUARANTINED`; immutable invalid không được GC/overwrite |
| `FINALIZING` | `*` | `*` | `X` | `QUARANTINED`; staging short/corrupt không được retry commit |
| `FINALIZING` | `V` | `V` | `Ø`/`V` | Re-hash/fsync immutable, verify exact receipt/snapshot/head, CAS `COMMITTED`; nếu `S=V`, chỉ xóa staging sau durable CAS/readback |
| `FINALIZING` | `V` | `Ø` | `Ø`/`V` | Receipt không có immutable object → `QUARANTINED`, security event |
| `FINALIZING` | `Ø` | `V` | `Ø` | Re-hash + file/parent fsync rồi CAS `READY` |
| `FINALIZING` | `Ø` | `V` | `V` | Require cùng expected hash/size; immutable thắng, CAS `READY`, readback rồi xóa staging |
| `FINALIZING` | `Ø` | `Ø` | `V` | Resume rename/promote + file/parent fsync, CAS `READY` |
| `FINALIZING` | `Ø` | `Ø` | `Ø` | `QUARANTINED`; không đủ bytes để finalize |
| `READY` | `X` | `*` | `*` | `QUARANTINED`, security event |
| `READY` | `*` | `X`/`Ø` | `*` | `QUARANTINED`; profile head chưa advance |
| `READY` | `*` | `V` | `X` | `QUARANTINED`; preserve staging evidence |
| `READY` | `V` | `V` | `Ø`/`V` | Verify receipt/snapshot/head, CAS `COMMITTED`; cleanup matching staging chỉ sau readback |
| `READY` | `Ø` | `V` | `Ø` | Giữ `READY`, chờ explicit commit/retry với lease còn valid |
| `READY` | `Ø` | `V` | `V` | Require same hash/size; giữ `READY`, xóa staging sau durable state readback |
| `COMMITTED` | `X`/`Ø` | `*` | `*` | `QUARANTINED` + security incident; exact receipt/snapshot/head là bắt buộc, không GC |
| `COMMITTED` | `V` | `X`/`Ø` | `*` | `QUARANTINED` + security incident; immutable object/hash là bắt buộc, không rewrite head |
| `COMMITTED` | `V` | `V` | `X` | `QUARANTINED`; preserve corrupt staging as evidence |
| `COMMITTED` | `V` | `V` | `Ø` | Giữ `COMMITTED`; exact receipt replay available |
| `COMMITTED` | `V` | `V` | `V` | Require same hash/size; giữ `COMMITTED`, xóa staging sau committed readback |
| `QUARANTINED` | `*` | `*` | `*` | Giữ `QUARANTINED`; không auto resume/commit/delete. Chỉ audited operator reconciliation có evidence mới được tạo transition riêng |

Reconciler giữ per-upload lock, re-read DB sau mỗi fsync/CAS và chạy tới một terminal/stable state. Một pass thành công phải để zero `FINALIZING` rows; I/O/CAS failure bounded-retry rồi chuyển `QUARANTINED` với reason code, không để treo vô hạn. Crash của chính reconciler có thể để row transient, nhưng startup/readiness gate chạy lại matrix và không mở v2 writes cho tới khi zero `FINALIZING` được chứng minh.

### 8.2. Stable error contract

JSON lỗi gồm `code`, `request_id`, `retryable`, `safe_message`, optional allowlisted fields và optional `retry_after_seconds`. Contract tối thiểu:

| Codes | HTTP | Retry policy / client transition |
|---|---:|---|
| `AUTH_REQUIRED`, `SESSION_REVOKED` | 401 | Không retry mù; clear session, chuyển `auth_required` |
| `TENANT_SCOPE_DENIED`, `FLEET_ACCESS_DENIED`, `CAPABILITY_DENIED` | 403 | Không retry; giữ state, hiển thị access denied |
| `RESOURCE_NOT_FOUND` | 404 | Không phân biệt cross-tenant resource |
| `LEASE_HELD` | 409 | Retry chỉ theo server `Retry-After`/expiry; không launch |
| `LEASE_EXPIRED`, `FENCE_STALE`, `BASE_VERSION_MISMATCH` | 409 | Không commit/relaunch; chuyển `offline_fork`/reconcile |
| `IDEMPOTENCY_MISMATCH` | 409 | Không retry cùng key với body khác; operator/developer error |
| `ROOT_BOOTSTRAP_ALREADY_EXISTS`, `ROOT_GENERATION_MISMATCH` | 409 | Không retry self-grant/rotation mù; re-read exact root generation/grant set |
| `UPLOAD_OFFSET_MISMATCH` | 409 | `retryable=true`; bắt buộc `HEAD`, verify digest rồi resume |
| `UPLOAD_QUARANTINED`, `CIPHERTEXT_HASH_MISMATCH`, `RECEIPT_MISMATCH` | 422 | Không resume/GC object; giữ evidence và security event, tạo upload mới chỉ sau diagnosis |
| `NON_CANONICAL_RECORD`, `SIGNATURE_INVALID`, `SIGNED_BYTES_MISMATCH`, `SIGNED_CONTAINER_HASH_MISMATCH`, `AUTH_CLAIM_COLUMN_MISMATCH`, `KEY_SUBSTITUTION_DETECTED`, `HEAD_ROLLBACK_DETECTED` | 422 | Quarantine binding; không authorize/key-release/decrypt/launch/commit từ indexed columns; HPKE suite/info/encapped/wrapped mismatch dùng `AUTH_CLAIM_COLUMN_MISMATCH` |
| `MANIFEST_REPLAY_MISMATCH` | 422 | Exact persisted signed-manifest/request/receipt bytes hoặc internal/full hashes/upload/idempotency/lease/fence/base/intent/ciphertext/head binding khác; không regenerate/retry mù |
| `MUTATION_RESPONSE_MISMATCH`, `SNAPSHOT_REPLAY_MISMATCH` | 422 | Exact request/stored response hoặc upload/snapshot `snapshot_id`/`manifest_replay_id`/instance FK differs; no side-effect replay |
| `WIRE_INTEGER_OUT_OF_RANGE` | 422 | Unsigned canonical value âm, non-canonical hoặc ngoài `0..i64::MAX`, hay exact bytes khác SQLite mirror; reject trước cast/SQL bind, không clamp/wrap/retry |
| `RESTORE_EPOCH_TRANSITION_REQUIRED`, `RESTORE_EPOCH_TRANSITION_INVALID`, `RESTORE_EPOCH_PROOF_MISSING`, `RESTORE_EPOCH_CROSS_TENANT` | 423 | Giữ đúng tenant/profile binding quarantine; cần valid same-tenant transition + inclusion proof continuity |
| `EPOCH_AUTHORITY_MISSING`, `EPOCH_AUTHORITY_CORRUPT`, `EPOCH_AUTHORITY_BEHIND_DB`, `EPOCH_RECONCILIATION_REQUIRED` | 423 | Disable toàn bộ v2 writes; external record là authority, không rebuild/lower từ SQLite; chỉ exact prepared restore bundle + signed tenant transitions được resume |
| `CONTROL_PLANE_INTEGRITY_UNTRUSTED` | 423 | Disable toàn bộ v2 writes; restore live RBAC/coordination state from trusted operator evidence. Artifact signatures alone cannot repair authorization rollback |
| `ENVELOPE_UNSUPPORTED`, `SCHEMA_UNSUPPORTED` | 426 | Fail closed; cần compatible/newer client |
| `KEY_UNAVAILABLE`, `RECOVERY_REQUIRED`, `RESTORE_ROLLBACK_REQUIRED` | 423 | Khóa Team action; vào recovery/rollback flow |
| `CONFLICT_LOCAL_PENDING` | 409 | User chọn discard/export/clone; không auto overwrite |
| `SNAPSHOT_TOO_LARGE`, `TENANT_QUOTA_EXCEEDED`, `DISK_RESERVE_LOW` | 413 | Không retry tới khi size/quota/disk thay đổi |
| `RATE_LIMITED`, `UPLOAD_CAPACITY` | 429 | Retry đúng `Retry-After`; không mở parallel storm |
| `AUDIT_PERSIST_FAILED`, `COORDINATOR_UNAVAILABLE` | 503 | Mutation chưa xảy ra; bounded backoff + re-read state |

Unknown code hoặc HTTP/code mismatch fail closed và được telemetry bằng code allowlist, không log body.

### 8.3. MCP compatibility contract

- Không thêm, xóa, rename hoặc thay schema bất kỳ MCP tool nào trong v0.2.x scope này.
- Tạo canonical fixture `mcp/fixtures/v0.1.28-tools.json` bằng fresh standalone `tools/list` từ baseline v0.1.28. Fixture chứa đủ **96 descriptors** với `name`, `description`, `annotations` (kể cả giá trị absent/null được canonical hóa theo một rule duy nhất) và full `inputSchema`; sort tool theo name và canonicalize object keys, không hand-edit.
- `mcp/contract.test.js` phải deep-compare toàn fixture, assert exactly 96 unique names, version `0.1.28` cho baseline fixture và SHA-256 fixture được pin trong manifest/test metadata. Count/subset assertion hiện tại không đủ.
- Local-only MCP behavior không đổi.
- Nếu một MCP/API caller cố launch profile đã team-bound mà chưa checkout hợp lệ, common launch guard trả lỗi domain an toàn; không tạo MCP tool mới để checkout/check-in.
- Team workflow trong v0.2.x đi qua Launcher UI/Tauri commands, không qua MCP public surface.
- `server/openapi.yaml` hiện hữu được mở rộng bằng `/v2`, canonical request/receipt schemas và toàn bộ HTTP/error mapping ở 8.2; OpenAPI contract test phải fail khi implementation/error mapping drift.

### 8.4. UI đề xuất

- **Team connection:** server URL, TLS status, tenant, account, device enrollment, key/recovery readiness.
- **Fleet browser:** opaque/local-decrypted labels, role/permission, online/offline state.
- **Profile badges:** `local`, `available`, `checked_out_here`, `checked_out_elsewhere`, `lease_at_risk`, `offline_fork`, `uploading`, `restore_required`, `conflict`.
- **Actions:** publish, checkout, renew/release, check-in, restore version, export recovery, resolve conflict.
- **Safety UX:** destructive restore hiển thị local backup path/fingerprint; không log/copy secret; không có “force overwrite remote” mặc định.
- Tạo feature modules mới thay vì tiếp tục nhồi logic vào `src/App.tsx`; App chỉ giữ navigation/state wiring mỏng.

---

## 9. ADR — Encryption envelope và key lifecycle

### 9.1. Key hierarchy

```text
Tenant Root KEK (TRK, client-held)
  -> wraps/authorizes immutable Fleet KEK generations for recovery/administration
Fleet KEK (FKEK, client-held by authorized fleet devices)
  -> distributed to devices by signed HPKE grants outside snapshot envelopes
  -> wraps each per-snapshot DEK in exactly one DekSlotV2
Per-snapshot DEK
  -> encrypts streaming archive frames

Device signing key (identity/authenticity; distinct key_id)
  -> signs enrollment proof, canonical approval/FKEK grant bytes, SnapshotManifestV2/head
  -> root-custodian key signs RestoreEpochTransitionV2
Device HPKE recipient key (key distribution; distinct key_id)
  -> receives TRK only through exact TenantRootKeyGrantV2 for explicit root custodians
  -> receives FKEK generations through out-of-envelope canonical signed grants
```

- Mỗi tenant có TRK generation keyed `(server_instance_id,tenant_id,generation)`; mỗi fleet có FKEK generation keyed `(server_instance_id,tenant_id,fleet_id,generation)`; mỗi snapshot có DEK random 32 bytes.
- Device có signing và HPKE key pair riêng; private keys lưu OS credential store/fallback encrypted file bằng references tách biệt, public keys/key IDs lưu server.
- Mỗi FKEK generation có immutable `(fkek_key_id,generation)`; exact `FleetKeyGrantV2::DeviceHpkeGrant` phân phối FKEK cho từng authorized device **ngoài envelope**, persist payload/container exact bytes + hashes và full issuer/subject/scope/validity/instance/epoch + HPKE suite/info/encapped/wrapped indexed bytes, nên thêm/revoke device không rewrite snapshot.
- FKEK cũng được AEAD-wrap dưới TRK cho owner recovery. Snapshot DEK được AEAD-wrap dưới exact immutable FKEK generation và đặt trong **một** `DekSlotV2`; envelope không có per-device recipient slot/table.
- Join device cần một authorized device/owner client unwrap rồi HPKE-wrap key cho device mới; server chỉ relay ciphertext.
- Bootstrap tenant do first approved owner/root device tạo TRK và exact `TenantRootKeyGrantV2::FirstRootSelfGrant` theo one-time transaction ở 5.6.4; bootstrap fleet do authorized owner device tạo FKEK, root-wrapped recovery grant và device HPKE grants trong client-driven transaction. Server không tự sinh hoặc nhìn thấy plaintext KEK.
- First root bootstrap pin cả signing/HPKE fingerprint out-of-band; subsequent existing/rotation root grants, revocation, ack/readback và activation theo exact 5.6.4. Mọi authorization/grant persist exact payload/container artifacts + typed equality columns. Không dùng TRK/FKEK/DEK để ký; key release/rotation require signature/hash verification + exact equality của mọi extracted column, gồm HPKE suite/info/recipient/encapped/wrapped bytes.

### 9.2. Envelope v2

Định dạng contract bắt buộc, big-endian và immutable cho envelope version 2. Dependency flow chỉ đi một chiều: `DekSlotV2` → `EnvelopeIntentV2`/`intent_hash` → ciphertext → exact `SignedSnapshotManifestV2`; không record nào commit ngược về record được tạo sau nó.

```text
PreambleV2 (exactly 64 bytes)
  magic[8]               = ASCII "SHARDXBK"
  envelope_version:u16   = 2
  preamble_length:u16    = 64
  suite_id:u16
  flags:u16              = known-bit mask only
  intent_len:u32
  dek_slot_len:u32
  frame_plaintext_size:u32
  reserved:u32           = 0
  intent_sha256[32]

intent_bytes[intent_len]      = canonical EnvelopeIntentV2 CBOR map
dek_slot_bytes[dek_slot_len]  = canonical DekSlotV2 CBOR map (exactly one)

FrameRecord repeated one-or-more times
  kind:u8                = 0x00 DATA | 0x01 FINAL
  counter:u32            = 0,1,2,... exact monotonic
  ciphertext_len:u32
  ciphertext[ciphertext_len]
```

Hard bounds trước allocation: intent <= 64 KiB; one DEK slot <= 16 KiB; frame plaintext 64 KiB..4 MiB; ciphertext/frame <= frame plaintext + provider overhead; total ciphertext <= declared/configured quota. `dek_slot_len=0`, slot thứ hai/trailing slot bytes hoặc reserved khác 0 đều fail. Length arithmetic dùng checked integers.

`DekSlotContextV2`, `DekSlotV2` và `EnvelopeIntentV2` dùng **đúng** closed-map
field/type/bound/optionality/domain/hash contracts ở 5.6.3; mục này không có
"bind tối thiểu" hoặc implementation-defined extension. Slot context bytes là
DEK-wrap AAD; slot không tham chiếu intent. Intent được tạo sau exact slot hash
nhưng trước encrypt, chứa preallocated `snapshot_id` + `manifest_replay_id`, và
không chứa actual ciphertext/archive-content hash/size hay manifest commitment.
Parser recompute context/slot/intent domain hashes, canonical-roundtrip exact
bytes và one-for-one slot/intent/upload equality trước allocation/unwrap.

**AAD/context:** mỗi DATA/FINAL frame AAD bind domain separator, exact `intent_hash`, frame kind và counter. Frame AAD không bind final manifest. FKEK HPKE grant context và DEK-wrap context có domain riêng; unknown flag/critical field/suite/version fail closed.

Sau khi encryption hoàn tất và exact ciphertext SHA-256/size đã biết, client tạo
exact `SnapshotManifestV2` payload rồi exact `SignedSnapshotManifestV2` container
theo field/type/optionality/TBS/core/hash/head-hash contract ở 5.6.2. Manifest
nằm ngoài envelope; server/local persist payload bytes/hash, exact outer container
bytes, internal signed-container hash và full outer-bytes SHA-256. Commit request
nhúng byte-identical outer container, không payload-only placeholder. Manifest
được verify trước decrypt/commit; envelope/intent không chứa manifest hash nên
không có commitment cycle.

Parser phải reject trước restore: trailing bytes; zero frame records; zero/multiple DEK slot; recipient-device/per-device slot fields; counter không bắt đầu 0/tăng sai/exhaust LE31; `ciphertext_len` ngoài bound; DATA sau FINAL; missing hoặc repeated FINAL; final không phải record cuối; non-canonical CBOR/preamble; intent/slot/context/hash mismatch; intent chứa ciphertext/final-manifest commitment; manifest signature/header/slot/ciphertext/head/epoch mismatch. Archive hợp lệ luôn có ít nhất một non-empty final frame.

### 9.3. Algorithms và framing

- Payload AEAD: XChaCha20-Poly1305 qua RustCrypto/audited provider.
- Streaming: RustCrypto STREAM LE31 hoặc primitive tương đương đã được official-doc spike và test vector xác nhận; không tự viết nonce counter.
- Frame plaintext mặc định: 1 MiB, configurable bằng envelope; bắt buộc authenticated final frame để phát hiện truncation.
- Key wrapping: TRK wraps/authorizes FKEK generations qua out-of-envelope recovery grant; exact one `DekSlotV2` wraps snapshot DEK dưới immutable FKEK generation bằng exact context/AAD/hash construction 5.6.3.
- Device distribution: HPKE RFC 9180, suite mặc định đề xuất X25519 + HKDF-SHA256 + ChaCha20-Poly1305; exact `DeviceHpkeGrant` signed payload bind suite, info, recipient key ID, encapped bytes, wrapped FKEK bytes, tenant/fleet/generation/issuer/validity/instance/epoch và replay ID. G2 pin numeric suite ID/provider; không đổi wire fields.
- Signing candidate: Ed25519 hoặc audited equivalent có algorithm ID/versioning; dependency spike phải prove canonical-signature vectors, key parsing, malformed-key rejection, MSRV và maintenance trước khi khóa suite.
- Randomness lấy từ OS CSPRNG qua crate tiêu chuẩn; không deterministic key/nonce ngoài test fixture.

### 9.4. Streaming archive v2

- Giữ tar+gzip trong v0.2.x để giảm migration/dependency surface, nhưng tách API `pack_v2_to_writer`/`restore_v2_from_reader` và validator v2 khỏi `Vec<u8>`/validator v1.
- Portable secrets được chia thành versioned, bounded CBOR/JSONL batches trong inner archive thay vì một `shardx-portable.json` lớn.
- Compression xảy ra trước encryption; không dedup ciphertext.
- Decrypt trực tiếp vào validated extractor/staging; không ghi plaintext `.tar.gz` temp.
- V2 chỉ chấp nhận regular file, directory và bounded GNU-longname metadata theo grammar writer phát ra; PAX/global PAX, GNU sparse, symlink, hardlink, device/FIFO và mọi unsupported entry **fail**, không skip.
- Trước swap, validator giữ index canonical của mọi entry và reject duplicate normalized path, Unicode/case-fold collision theo Windows policy, ADS/colon, drive/root/traversal, reserved device names, trailing dot/space, file-vs-directory conflict và ancestor-is-file conflict. Cùng bytes/path policy được dùng ở pack và restore.
- V1 `pack`/`unpack` và regression behavior hiện hữu giữ nguyên để tránh làm v0.1.28 fixture thay đổi; strict rules chỉ áp dụng archive format v2.

### 9.5. Credential store và passphrase fallback

- Ưu tiên backend OS credential store explicit theo platform; dependency spike phải chọn `keyring-core` + platform backend thay vì ngầm tin behavior cross-platform của wrapper chung.
- `team-sync.db` chỉ lưu stable credential reference, không key bytes.
- Nếu OS store unavailable, private key/TRK/FKEK cache nằm trong local encrypted key file với Argon2id-derived KEK.
- Default fallback: salt random >=16 bytes; Argon2id profile khởi điểm 64 MiB, `t=3`, `p=4`, output 32 bytes theo profile memory-constrained RFC 9106; benchmark lúc setup và chỉ tăng cost, không tự giảm dưới policy nếu máy chậm.
- Passphrase không lưu, không đưa vào command line/log/telemetry; UI yêu cầu xác nhận và rate-limit local attempts.

### 9.6. Rotation, revocation và recovery

- Rotation tạo generation N+1 ở `PREPARING`; snapshot mới chưa được dùng generation đó.
- Root rotation tạo exact `TenantRootKeyGrantV2::RotationGrant` set dưới previous ACTIVE TRK; root generation activation/revocation/readback semantics theo 5.6.4 và key-generation PK luôn gồm `server_instance_id`.
- Client tạo exact `RecoveryGrant`, required `DeviceHpkeGrant` set và `RotationGrant`, upload/readback exact payload/container bytes+hashes và ký ack. Chỉ khi recovery grant + mọi required device grant + rotation commitments match mới cho activation.
- Activation transaction chuyển N+1 `PREPARING -> ACTIVE`, prior N `ACTIVE -> RETIRED`, update active pointer và audit. Revoke device + activate replacement generation là một logical operation; transaction revoke sessions/grants và activation cùng fail/pass.
- Old generations được giữ tới khi không còn retained snapshot tham chiếu và recovery drill đã pass.
- Revoke device ngăn nhận generation mới và chặn session/lease mới; không hứa thu hồi dữ liệu/key cũ đã copy.
- Recovery bundle chứa TRK và retained FKEKs, encrypted dưới passphrase-derived key, có version/suite/KDF params/fingerprint và integrity authentication.
- Export recovery yêu cầu re-auth, passphrase confirmation, write-readback và test unwrap một synthetic key; không export raw key.
- Mất mọi device private key và recovery bundle là unrecoverable; UI phải chặn Team rollout tới khi owner xác nhận recovery readiness.
- Ordinary fleet devices chỉ nhận out-of-envelope HPKE FKEK grants; TRK chỉ cấp qua exact `TenantRootKeyGrantV2` cho device có explicit `root.custody` còn hiệu lực và first self-grant chỉ one-time bootstrap. Retained snapshot envelopes không đổi khi grant/device membership đổi vì mỗi envelope chỉ tham chiếu immutable FKEK generation.

---

## 10. ADR — Lease, fencing, idempotency, conflict và offline semantics

### 10.1. Lease state machine

```text
AVAILABLE
  --checkout transaction/server_now--> HELD(one current row, lease_id, device, fence=N+1, base=current_version)
HELD --renew where expires_at > server_now--> HELD(same fence, later server expiry)
HELD --release--> AVAILABLE
HELD --valid commit--> AVAILABLE + current_version+1
HELD --server_now >= expires_at--> EXPIRED (row replaceable; cannot renew/commit)
EXPIRED --new checkout transaction--> HELD(replace current row, new lease_id, fence=N+1)
```

- Checkout grant/reacquire/takeover tăng fence; renew không tăng.
- `v2_profile_leases` thực thi **one current lease row per profile** bằng PK `(tenant_id, profile_id)`, nên không thể tồn tại hai current rows. History chỉ ở audit; không dùng partial “active lease” index phụ thuộc clock.
- TTL mặc định đề xuất 90 giây, renew target 30 giây; một `server_now` do transaction/request lấy là authority. Client clock chỉ để hiển thị countdown và không thể kéo dài validity.
- Sau hai renew failure client hiển thị `lease_at_risk`; sau expiry là `offline_fork`.
- Không có relaunch grace: chỉ browser process đã chạy được tiếp tục với warning khi renew fail; sau expiry common launch guard cấm start/relaunch, checkout-derived restore mới và remote commit.
- Commit transaction phải kiểm tra: tenant/fleet role + explicit capability, active session/device/grant/signature, đúng current lease owner/device, `expires_at > server_now`, fence bằng current fence, `base_version == current_version`, upload `READY` hash/size/manifest/generation hoàn tất và idempotency match.

### 10.2. Idempotency

- Profile publish-create, checkout, create-upload, finalize, release và local unbind dùng exact request/payload/stored-response contracts ở 5.6.5; commit dùng exact 5.6.2. Caller-generated `ReplayId16` key và immutable operation scope luôn bind actor, method/route version, resource IDs, instance/epoch và operation kind.
- Server/Launcher lưu canonical request hash **và** full exact request bytes SHA-256; relational columns chỉ là lookup/equality indexes. Create-upload binds preallocated snapshot/replay IDs, intent/preamble/one-slot hashes, immutable FKEK generation và expected ciphertext size/hash. Finalize binds exact manifest + commit request bytes/hashes. Không có final-manifest commitment trong create-upload intent.
- Trước finalize/commit, local durable operation row phải chứa exact `SignedSnapshotManifestV2` container bytes/internal+full hashes, exact `CommitRequestV2` bytes/canonical+full hashes, idempotency key, remote upload ID, lease/fence/base, intent/ciphertext/instance/epoch bindings. Close/reopen retry chỉ gửi stored request bytes byte-for-byte; recompute/re-encode hoặc mismatch giữa row, upload session, spool hash và request body fail closed.
- Cùng key + cùng canonical request hash + byte-identical request trả exact prior `IdempotentStoredResponseV2` hoặc `CommitReceiptBindingV2`; cùng key + khác hash fail, same hash + alternate bytes/noncanonical encoding fail. Replay không serialize lại response/receipt.
- Upload chunk dùng `Upload-Offset` + required `Upload-Chunk-SHA256`; duplicate offset chỉ trả success khi persisted `(offset,length,digest)` match. Mọi offset/digest mismatch trả conflict và client mặc định `HEAD`/resume, không resend đoán.
- Commit receipt được lưu trước khi trả response để retry sau network loss không tạo version mới.
- Publish-create/checkout/create-upload/finalize/release mutation + exact stored response + audit commit atomically. Checkout replay không allocate lease/fence thứ hai; publish replay không create profile/initial lease thứ hai; response expiry không biến old key thành permission để mint resource mới. Release/unbind tombstone response sống sau current lease/binding delete.
- Commit idempotency request/receipt được giữ ít nhất tới khi snapshot/receipt liên quan hết retention và không ngắn hơn tenant max snapshot retention; GC phải chứng minh không còn snapshot/head/reference.

### 10.3. Offline/conflict behavior

- Local-only profile luôn hoạt động offline.
- Team-bound profile chưa checkout không thể checkout offline.
- Nếu mất mạng khi browser đang chạy, không kill browser tự động; UI cảnh báo. Sau expiry, profile bị `offline_fork` và common guard không cho relaunch như một valid team checkout.
- `lease_at_risk` không phải grace token và không cho start/relaunch/remote commit; server không nhận client grace timestamp.
- Encrypted pending snapshot được giữ cục bộ; không auto-replay commit nếu lease/fence/base không còn hợp lệ.
- Conflict choices duy nhất: discard local rồi pull; export encrypted recovery artifact; hoặc clone thành local recovered profile không còn binding. Không CRDT, không silent overwrite.

---

## 11. ADR — Local team-sync database và launcher integration

### 11.1. Vị trí và schema cục bộ

Đề xuất path: `<config_root>/team-sync/team-sync.db`; encrypted spool ở `<config_root>/team-sync/spool/*.part` với opaque filename.

Reference DDL dưới đây là executable SQLite contract; implementation có thể thêm index nhưng không được bỏ PK/FK/UNIQUE/CHECK hoặc làm lỏng state enums:

```sql
PRAGMA foreign_keys = ON;

-- MAX_SQLITE_WIRE_U64 = 9223372036854775807 (i64::MAX).
-- Every INTEGER below that mirrors an unsigned wire value repeats this bound.

CREATE TABLE schema_meta (
  singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version      INTEGER NOT NULL CHECK (schema_version BETWEEN 1 AND 9223372036854775807),
  min_reader_version  INTEGER NOT NULL CHECK (min_reader_version BETWEEN 1 AND 9223372036854775807),
  migration_state     TEXT NOT NULL CHECK (migration_state IN ('CLEAN','MIGRATING','RECOVERY_REQUIRED')),
  applied_at          TEXT NOT NULL
) STRICT;
INSERT INTO schema_meta(singleton, schema_version, min_reader_version, migration_state, applied_at)
VALUES (1, 1, 1, 'CLEAN', '1970-01-01T00:00:00Z');

CREATE TABLE server_origins (
  server_id                 TEXT PRIMARY KEY,
  scheme                    TEXT NOT NULL CHECK (scheme IN ('https','http')),
  host                      TEXT NOT NULL CHECK (
                              length(host) BETWEEN 1 AND 253 AND
                              host = lower(trim(host)) AND
                              instr(host, '/') = 0 AND instr(host, '?') = 0 AND
                              instr(host, '#') = 0 AND instr(host, '@') = 0 AND
                              instr(host, ' ') = 0
                            ),
  port                      INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  origin                    TEXT GENERATED ALWAYS AS
                              (scheme || '://' || host || ':' || CAST(port AS TEXT)) STORED,
  tls_policy                TEXT NOT NULL CHECK (tls_policy IN ('SYSTEM','PINNED')),
  server_instance_id        TEXT NOT NULL,
  last_restore_epoch        INTEGER NOT NULL CHECK (last_restore_epoch BETWEEN 0 AND 9223372036854775807),
  status                    TEXT NOT NULL CHECK (status IN ('ACTIVE','QUARANTINED','DISABLED')),
  UNIQUE(origin),
  UNIQUE(server_id, server_instance_id),
  CHECK (scheme = 'https' OR host IN ('127.0.0.1','localhost','[::1]'))
) STRICT;

CREATE TABLE accounts (
  server_id       TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  tenant_id       TEXT NOT NULL,
  account_id      TEXT NOT NULL,
  device_id       TEXT NOT NULL,
  role            TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
  status          TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED','AUTH_REQUIRED')),
  PRIMARY KEY(server_id, tenant_id, account_id, device_id),
  UNIQUE(server_id, tenant_id, device_id)
) STRICT;

CREATE TABLE device_state (
  server_id              TEXT NOT NULL,
  tenant_id              TEXT NOT NULL,
  account_id             TEXT NOT NULL,
  device_id              TEXT NOT NULL,
  signing_key_id         TEXT NOT NULL,
  hpke_key_id            TEXT NOT NULL,
  signing_credential_ref TEXT NOT NULL UNIQUE,
  hpke_credential_ref    TEXT NOT NULL UNIQUE,
  recovery_ready         INTEGER NOT NULL CHECK (recovery_ready IN (0,1)),
  PRIMARY KEY(server_id, tenant_id, device_id),
  FOREIGN KEY(server_id, tenant_id, account_id, device_id)
    REFERENCES accounts(server_id, tenant_id, account_id, device_id) ON DELETE CASCADE,
  CHECK (signing_key_id <> hpke_key_id),
  CHECK (signing_credential_ref <> hpke_credential_ref)
) STRICT;

CREATE TABLE signed_authorization_records (
  record_id                           TEXT PRIMARY KEY,
  server_id                           TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  tenant_id                           TEXT NOT NULL,
  record_kind                         TEXT NOT NULL CHECK (record_kind IN (
                                        'DeviceApprovalV2','TenantCapabilityGrantV2',
                                        'FleetKeyGrantV2::DeviceHpkeGrant',
                                        'FleetKeyGrantV2::RecoveryGrant',
                                        'FleetKeyGrantV2::RotationGrant'
                                      )),
  container_domain                    TEXT NOT NULL CHECK (container_domain = 'shardx.authorization.signed-container.v2'),
  container_version                   INTEGER NOT NULL CHECK (container_version = 2),
  payload_domain                      TEXT NOT NULL,
  payload_version                     INTEGER NOT NULL CHECK (payload_version = 2),
  replay_id                           BLOB NOT NULL CHECK (length(replay_id) = 16),
  subject_kind                        TEXT CHECK (subject_kind IN ('account','device')),
  subject_account_id                  TEXT,
  subject_device_id                   TEXT,
  subject_signing_key_id              TEXT,
  subject_hpke_key_id                 TEXT,
  approval_scope_kind                 TEXT CHECK (approval_scope_kind IN ('tenant','fleet')),
  approval_scope_id                   TEXT,
  approved_use                        TEXT CHECK (approved_use IS NULL OR approved_use = 'team.device'),
  scope_kind                          TEXT CHECK (scope_kind IN ('tenant','fleet','profile')),
  scope_id                            TEXT,
  capability                          TEXT,
  grant_variant                       TEXT CHECK (grant_variant IN ('DeviceHpkeGrant','RecoveryGrant','RotationGrant')),
  fleet_id                            TEXT,
  fkek_key_id                         TEXT,
  generation                          INTEGER CHECK (generation IS NULL OR generation BETWEEN 0 AND 9223372036854775807),
  grant_capability                    TEXT,
  recipient_hpke_key_id               TEXT,
  hpke_suite_id                       INTEGER CHECK (hpke_suite_id IS NULL OR hpke_suite_id BETWEEN 0 AND 65535),
  hpke_info_bytes                     BLOB,
  hpke_encapped_key_bytes             BLOB,
  hpke_wrapped_fleet_key_bytes        BLOB,
  recipient_root_key_id               TEXT,
  recipient_root_generation           INTEGER CHECK (recipient_root_generation IS NULL OR recipient_root_generation BETWEEN 0 AND 9223372036854775807),
  root_wrap_suite_id                  INTEGER CHECK (root_wrap_suite_id IS NULL OR root_wrap_suite_id BETWEEN 0 AND 65535),
  root_wrap_nonce_bytes               BLOB,
  root_wrap_context_bytes             BLOB,
  wrapped_fleet_key_bytes             BLOB,
  previous_fkek_key_id                TEXT,
  previous_generation                 INTEGER CHECK (previous_generation IS NULL OR previous_generation BETWEEN 0 AND 9223372036854775807),
  required_device_grant_count         INTEGER CHECK (required_device_grant_count IS NULL OR required_device_grant_count BETWEEN 0 AND 4294967295),
  required_device_grant_set_hash      BLOB CHECK (required_device_grant_set_hash IS NULL OR length(required_device_grant_set_hash) = 32),
  recovery_grant_signed_container_hash BLOB CHECK (recovery_grant_signed_container_hash IS NULL OR length(recovery_grant_signed_container_hash) = 32),
  activation_not_before_ms            INTEGER CHECK (activation_not_before_ms IS NULL OR activation_not_before_ms BETWEEN 0 AND 9223372036854775807),
  issued_at_ms                        INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
  not_before_ms                       INTEGER NOT NULL CHECK (not_before_ms BETWEEN 0 AND 9223372036854775807),
  not_after_ms                        INTEGER NOT NULL CHECK (
                                         not_after_ms BETWEEN 0 AND 9223372036854775807 AND
                                         not_after_ms > not_before_ms
                                       ),
  server_instance_id                  TEXT NOT NULL,
  restore_epoch                       INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
  canonical_payload_bytes             BLOB NOT NULL CHECK (length(canonical_payload_bytes) > 0),
  payload_sha256                      BLOB NOT NULL CHECK (length(payload_sha256) = 32),
  signature_suite_id                  INTEGER NOT NULL CHECK (signature_suite_id BETWEEN 0 AND 65535),
  signature_version                   INTEGER NOT NULL CHECK (signature_version = 1),
  issuer_signing_key_id               TEXT NOT NULL,
  signature_bytes                     BLOB NOT NULL CHECK (length(signature_bytes) > 0),
  signed_container_hash               BLOB NOT NULL CHECK (length(signed_container_hash) = 32),
  exact_signed_container_bytes        BLOB NOT NULL CHECK (length(exact_signed_container_bytes) > 0),
  exact_signed_container_bytes_sha256 BLOB NOT NULL CHECK (length(exact_signed_container_bytes_sha256) = 32),
  verified_at_ms                      INTEGER NOT NULL CHECK (verified_at_ms BETWEEN 0 AND 9223372036854775807),
  revoked_at_ms                       INTEGER CHECK (
                                         revoked_at_ms IS NULL OR
                                         (revoked_at_ms BETWEEN 0 AND 9223372036854775807 AND revoked_at_ms >= issued_at_ms)
                                       ),
  UNIQUE(server_id, tenant_id, payload_domain, replay_id),
  CHECK (issued_at_ms <= not_before_ms),
  CHECK (
    (record_kind = 'DeviceApprovalV2' AND
      payload_domain = 'shardx.auth.device-approval.v2' AND
      subject_account_id IS NOT NULL AND subject_device_id IS NOT NULL AND
      subject_signing_key_id IS NOT NULL AND subject_hpke_key_id IS NOT NULL AND
      approval_scope_kind IS NOT NULL AND approval_scope_id IS NOT NULL AND approved_use = 'team.device' AND
      subject_kind IS NULL AND scope_kind IS NULL AND scope_id IS NULL AND capability IS NULL AND
      grant_variant IS NULL AND fleet_id IS NULL AND fkek_key_id IS NULL AND generation IS NULL AND grant_capability IS NULL AND
      recipient_hpke_key_id IS NULL AND hpke_suite_id IS NULL AND hpke_info_bytes IS NULL AND
      hpke_encapped_key_bytes IS NULL AND hpke_wrapped_fleet_key_bytes IS NULL AND
      recipient_root_key_id IS NULL AND recipient_root_generation IS NULL AND root_wrap_suite_id IS NULL AND
      root_wrap_nonce_bytes IS NULL AND root_wrap_context_bytes IS NULL AND wrapped_fleet_key_bytes IS NULL AND
      previous_fkek_key_id IS NULL AND previous_generation IS NULL AND required_device_grant_count IS NULL AND
      required_device_grant_set_hash IS NULL AND recovery_grant_signed_container_hash IS NULL AND activation_not_before_ms IS NULL) OR
    (record_kind = 'TenantCapabilityGrantV2' AND
      payload_domain = 'shardx.auth.tenant-capability-grant.v2' AND
      subject_kind IS NOT NULL AND subject_account_id IS NOT NULL AND
      scope_kind IS NOT NULL AND scope_id IS NOT NULL AND capability IS NOT NULL AND
      approval_scope_kind IS NULL AND approval_scope_id IS NULL AND approved_use IS NULL AND
      grant_variant IS NULL AND fleet_id IS NULL AND fkek_key_id IS NULL AND generation IS NULL AND grant_capability IS NULL AND
      recipient_hpke_key_id IS NULL AND hpke_suite_id IS NULL AND hpke_info_bytes IS NULL AND
      hpke_encapped_key_bytes IS NULL AND hpke_wrapped_fleet_key_bytes IS NULL AND
      recipient_root_key_id IS NULL AND recipient_root_generation IS NULL AND root_wrap_suite_id IS NULL AND
      root_wrap_nonce_bytes IS NULL AND root_wrap_context_bytes IS NULL AND wrapped_fleet_key_bytes IS NULL AND
      previous_fkek_key_id IS NULL AND previous_generation IS NULL AND required_device_grant_count IS NULL AND
      required_device_grant_set_hash IS NULL AND recovery_grant_signed_container_hash IS NULL AND activation_not_before_ms IS NULL AND
      ((subject_kind = 'account' AND subject_device_id IS NULL AND subject_signing_key_id IS NULL AND subject_hpke_key_id IS NULL) OR
       (subject_kind = 'device' AND subject_device_id IS NOT NULL AND subject_signing_key_id IS NOT NULL AND subject_hpke_key_id IS NOT NULL))) OR
    (record_kind = 'FleetKeyGrantV2::DeviceHpkeGrant' AND
      payload_domain = 'shardx.keys.fleet-key-grant.device-hpke.v2' AND grant_variant = 'DeviceHpkeGrant' AND
      fleet_id IS NOT NULL AND fkek_key_id IS NOT NULL AND generation IS NOT NULL AND
      grant_capability = 'fleet.key.receive' AND subject_account_id IS NOT NULL AND subject_device_id IS NOT NULL AND
      subject_signing_key_id IS NOT NULL AND recipient_hpke_key_id IS NOT NULL AND
      hpke_suite_id IS NOT NULL AND hpke_info_bytes IS NOT NULL AND hpke_encapped_key_bytes IS NOT NULL AND
      hpke_wrapped_fleet_key_bytes IS NOT NULL AND length(hpke_info_bytes) BETWEEN 1 AND 1024 AND
      length(hpke_encapped_key_bytes) BETWEEN 1 AND 2048 AND length(hpke_wrapped_fleet_key_bytes) BETWEEN 1 AND 4096 AND
      subject_kind IS NULL AND subject_hpke_key_id IS NULL AND approval_scope_kind IS NULL AND approval_scope_id IS NULL AND
      approved_use IS NULL AND scope_kind IS NULL AND scope_id IS NULL AND capability IS NULL AND
      recipient_root_key_id IS NULL AND recipient_root_generation IS NULL AND root_wrap_suite_id IS NULL AND
      root_wrap_nonce_bytes IS NULL AND root_wrap_context_bytes IS NULL AND wrapped_fleet_key_bytes IS NULL AND
      previous_fkek_key_id IS NULL AND previous_generation IS NULL AND required_device_grant_count IS NULL AND
      required_device_grant_set_hash IS NULL AND recovery_grant_signed_container_hash IS NULL AND activation_not_before_ms IS NULL) OR
    (record_kind = 'FleetKeyGrantV2::RecoveryGrant' AND
      payload_domain = 'shardx.keys.fleet-key-grant.recovery.v2' AND grant_variant = 'RecoveryGrant' AND
      fleet_id IS NOT NULL AND fkek_key_id IS NOT NULL AND generation IS NOT NULL AND
      grant_capability = 'fleet.key.recover' AND recipient_root_key_id IS NOT NULL AND
      recipient_root_generation IS NOT NULL AND root_wrap_suite_id IS NOT NULL AND
      root_wrap_nonce_bytes IS NOT NULL AND root_wrap_context_bytes IS NOT NULL AND wrapped_fleet_key_bytes IS NOT NULL AND
      length(root_wrap_nonce_bytes) BETWEEN 1 AND 64 AND length(root_wrap_context_bytes) BETWEEN 1 AND 1024 AND
      length(wrapped_fleet_key_bytes) BETWEEN 1 AND 4096 AND
      subject_kind IS NULL AND subject_account_id IS NULL AND subject_device_id IS NULL AND subject_signing_key_id IS NULL AND
      subject_hpke_key_id IS NULL AND approval_scope_kind IS NULL AND approval_scope_id IS NULL AND approved_use IS NULL AND
      scope_kind IS NULL AND scope_id IS NULL AND capability IS NULL AND recipient_hpke_key_id IS NULL AND
      hpke_suite_id IS NULL AND hpke_info_bytes IS NULL AND hpke_encapped_key_bytes IS NULL AND hpke_wrapped_fleet_key_bytes IS NULL AND
      previous_fkek_key_id IS NULL AND previous_generation IS NULL AND required_device_grant_count IS NULL AND
      required_device_grant_set_hash IS NULL AND recovery_grant_signed_container_hash IS NULL AND activation_not_before_ms IS NULL) OR
    (record_kind = 'FleetKeyGrantV2::RotationGrant' AND
      payload_domain = 'shardx.keys.fleet-key-grant.rotation.v2' AND grant_variant = 'RotationGrant' AND
      fleet_id IS NOT NULL AND fkek_key_id IS NOT NULL AND generation IS NOT NULL AND
      grant_capability = 'key.rotate' AND previous_fkek_key_id IS NOT NULL AND previous_generation IS NOT NULL AND
      generation = previous_generation + 1 AND fkek_key_id <> previous_fkek_key_id AND
      required_device_grant_count IS NOT NULL AND required_device_grant_set_hash IS NOT NULL AND
      recovery_grant_signed_container_hash IS NOT NULL AND activation_not_before_ms IS NOT NULL AND
      length(required_device_grant_set_hash) = 32 AND length(recovery_grant_signed_container_hash) = 32 AND
      activation_not_before_ms BETWEEN not_before_ms AND not_after_ms - 1 AND
      subject_kind IS NULL AND subject_account_id IS NULL AND subject_device_id IS NULL AND subject_signing_key_id IS NULL AND
      subject_hpke_key_id IS NULL AND approval_scope_kind IS NULL AND approval_scope_id IS NULL AND approved_use IS NULL AND
      scope_kind IS NULL AND scope_id IS NULL AND capability IS NULL AND recipient_hpke_key_id IS NULL AND
      hpke_suite_id IS NULL AND hpke_info_bytes IS NULL AND hpke_encapped_key_bytes IS NULL AND hpke_wrapped_fleet_key_bytes IS NULL AND
      recipient_root_key_id IS NULL AND recipient_root_generation IS NULL AND root_wrap_suite_id IS NULL AND
      root_wrap_nonce_bytes IS NULL AND root_wrap_context_bytes IS NULL AND wrapped_fleet_key_bytes IS NULL)
  )
) STRICT;

CREATE TABLE tenant_root_key_generations (
  server_id                       TEXT NOT NULL,
  server_instance_id              TEXT NOT NULL,
  tenant_id                       TEXT NOT NULL,
  root_generation                 INTEGER NOT NULL CHECK (root_generation BETWEEN 0 AND 9223372036854775807),
  root_key_id                     TEXT NOT NULL,
  state                           TEXT NOT NULL CHECK (state IN ('PREPARING','ACTIVE','RETIRED')),
  recovery_bundle_sha256          BLOB CHECK (recovery_bundle_sha256 IS NULL OR length(recovery_bundle_sha256) = 32),
  required_custodian_grant_count  INTEGER NOT NULL CHECK (required_custodian_grant_count BETWEEN 1 AND 4294967295),
  required_custodian_grant_set_hash BLOB NOT NULL CHECK (length(required_custodian_grant_set_hash) = 32),
  created_at                      TEXT NOT NULL,
  activated_at                   TEXT,
  retired_at                     TEXT,
  PRIMARY KEY(server_id, server_instance_id, tenant_id, root_generation),
  UNIQUE(server_id, server_instance_id, tenant_id, root_key_id),
  UNIQUE(server_id, server_instance_id, tenant_id, root_generation, root_key_id),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX tenant_root_key_one_active_generation
ON tenant_root_key_generations(server_id, server_instance_id, tenant_id)
WHERE state = 'ACTIVE';

CREATE TABLE tenant_root_key_grants (
  server_id                           TEXT NOT NULL,
  server_instance_id                  TEXT NOT NULL,
  tenant_id                           TEXT NOT NULL,
  replay_id                           BLOB NOT NULL CHECK (length(replay_id) = 16),
  container_domain                    TEXT NOT NULL CHECK (container_domain = 'shardx.authorization.signed-container.v2'),
  container_version                   INTEGER NOT NULL CHECK (container_version = 2),
  payload_domain                      TEXT NOT NULL CHECK (payload_domain = 'shardx.keys.tenant-root-key-grant.v2'),
  payload_version                     INTEGER NOT NULL CHECK (payload_version = 2),
  grant_variant                       TEXT NOT NULL CHECK (grant_variant IN ('FirstRootSelfGrant','ExistingRootGrant','RotationGrant')),
  root_key_id                         TEXT NOT NULL,
  root_generation                     INTEGER NOT NULL CHECK (root_generation BETWEEN 0 AND 9223372036854775807),
  grant_capability                    TEXT NOT NULL CHECK (grant_capability = 'root.custody'),
  subject_account_id                  TEXT NOT NULL,
  subject_device_id                   TEXT NOT NULL,
  subject_signing_key_id              TEXT NOT NULL,
  subject_device_approval_replay_id   BLOB NOT NULL CHECK (length(subject_device_approval_replay_id) = 16),
  recipient_hpke_key_id               TEXT NOT NULL,
  hpke_suite_id                       INTEGER NOT NULL CHECK (hpke_suite_id = 1),
  hpke_mode_id                        INTEGER NOT NULL CHECK (hpke_mode_id = 0),
  hpke_kem_id                         INTEGER NOT NULL CHECK (hpke_kem_id = 32),
  hpke_kdf_id                         INTEGER NOT NULL CHECK (hpke_kdf_id = 1),
  hpke_aead_id                        INTEGER NOT NULL CHECK (hpke_aead_id = 3),
  hpke_info_bytes                     BLOB NOT NULL CHECK (length(hpke_info_bytes) BETWEEN 1 AND 1024),
  hpke_encapped_key_bytes             BLOB NOT NULL CHECK (length(hpke_encapped_key_bytes) = 32),
  hpke_wrapped_trk_bytes              BLOB NOT NULL CHECK (length(hpke_wrapped_trk_bytes) = 48),
  previous_root_key_id                TEXT,
  previous_root_generation            INTEGER CHECK (previous_root_generation IS NULL OR previous_root_generation BETWEEN 0 AND 9223372036854775807),
  issued_at_ms                        INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
  not_before_ms                       INTEGER NOT NULL CHECK (not_before_ms BETWEEN 0 AND 9223372036854775807),
  not_after_ms                        INTEGER NOT NULL CHECK (not_after_ms BETWEEN 0 AND 9223372036854775807 AND not_after_ms > not_before_ms),
  restore_epoch                       INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
  canonical_payload_bytes             BLOB NOT NULL CHECK (length(canonical_payload_bytes) BETWEEN 1 AND 65536),
  payload_sha256                      BLOB NOT NULL CHECK (length(payload_sha256) = 32),
  signature_suite_id                  INTEGER NOT NULL CHECK (signature_suite_id BETWEEN 0 AND 65535),
  signature_version                   INTEGER NOT NULL CHECK (signature_version = 1),
  issuer_signing_key_id               TEXT NOT NULL,
  signature_bytes                     BLOB NOT NULL CHECK (length(signature_bytes) BETWEEN 1 AND 4096),
  signed_container_hash               BLOB NOT NULL CHECK (length(signed_container_hash) = 32),
  exact_signed_container_bytes        BLOB NOT NULL CHECK (length(exact_signed_container_bytes) BETWEEN 1 AND 131072),
  exact_signed_container_bytes_sha256 BLOB NOT NULL CHECK (length(exact_signed_container_bytes_sha256) = 32),
  trk_credential_ref                  TEXT,
  acknowledged_at_ms                 INTEGER CHECK (acknowledged_at_ms IS NULL OR acknowledged_at_ms BETWEEN 0 AND 9223372036854775807),
  revoked_at_ms                       INTEGER CHECK (revoked_at_ms IS NULL OR revoked_at_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_id, server_instance_id, tenant_id, replay_id),
  UNIQUE(server_id, server_instance_id, tenant_id, payload_domain, replay_id),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, server_instance_id, tenant_id, root_generation, root_key_id)
    REFERENCES tenant_root_key_generations(server_id, server_instance_id, tenant_id, root_generation, root_key_id) ON DELETE RESTRICT,
  CHECK (subject_signing_key_id <> recipient_hpke_key_id),
  CHECK (issued_at_ms <= not_before_ms),
  CHECK (grant_variant <> 'FirstRootSelfGrant' OR root_generation = 0),
  CHECK (
    (grant_variant = 'RotationGrant' AND previous_root_key_id IS NOT NULL AND
      previous_root_generation IS NOT NULL AND root_generation = previous_root_generation + 1 AND
      root_key_id <> previous_root_key_id) OR
    (grant_variant IN ('FirstRootSelfGrant','ExistingRootGrant') AND
      previous_root_key_id IS NULL AND previous_root_generation IS NULL)
  )
) STRICT;

CREATE UNIQUE INDEX tenant_root_one_first_self_grant
ON tenant_root_key_grants(server_id, server_instance_id, tenant_id)
WHERE grant_variant = 'FirstRootSelfGrant';

CREATE TABLE fleet_key_state (
  server_id                  TEXT NOT NULL,
  server_instance_id         TEXT NOT NULL,
  tenant_id                  TEXT NOT NULL,
  fleet_id                   TEXT NOT NULL,
  generation                 INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
  fkek_key_id                TEXT NOT NULL,
  device_id                  TEXT NOT NULL,
  device_hpke_grant_record_id TEXT NOT NULL UNIQUE REFERENCES signed_authorization_records(record_id) ON DELETE RESTRICT,
  fkek_credential_ref        TEXT NOT NULL UNIQUE,
  state                      TEXT NOT NULL CHECK (state IN ('PREPARING','ACTIVE','RETIRED')),
  acknowledged_at            TEXT,
  created_at                 TEXT NOT NULL,
  PRIMARY KEY(server_id, server_instance_id, tenant_id, fleet_id, generation),
  UNIQUE(server_id, server_instance_id, tenant_id, fleet_id, fkek_key_id),
  UNIQUE(server_id, server_instance_id, tenant_id, fleet_id, generation, fkek_key_id),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, tenant_id, device_id)
    REFERENCES device_state(server_id, tenant_id, device_id) ON DELETE RESTRICT,
  CHECK (length(device_hpke_grant_record_id) > 0)
) STRICT;

CREATE UNIQUE INDEX fleet_key_one_active_generation
ON fleet_key_state(server_id, server_instance_id, tenant_id, fleet_id)
WHERE state = 'ACTIVE';

CREATE TABLE profile_bindings (
  local_profile_id       TEXT PRIMARY KEY,
  server_id              TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  server_instance_id     TEXT NOT NULL,
  tenant_id              TEXT NOT NULL,
  account_id             TEXT NOT NULL,
  device_id              TEXT NOT NULL,
  fleet_id               TEXT NOT NULL,
  remote_profile_id      TEXT NOT NULL,
  remote_version         INTEGER NOT NULL CHECK (remote_version BETWEEN 0 AND 9223372036854775807),
  base_version           INTEGER NOT NULL CHECK (base_version BETWEEN 0 AND 9223372036854775807),
  fencing_token          INTEGER CHECK (fencing_token IS NULL OR fencing_token BETWEEN 0 AND 9223372036854775807),
  lease_id               TEXT,
  lease_expires_at       TEXT,
  fkek_key_id            TEXT NOT NULL,
  key_generation         INTEGER NOT NULL CHECK (key_generation BETWEEN 0 AND 9223372036854775807),
  last_observed_head_hash BLOB CHECK (last_observed_head_hash IS NULL OR length(last_observed_head_hash) = 32),
  sync_state             TEXT NOT NULL CHECK (sync_state IN (
                           'LOCAL','AVAILABLE','CHECKED_OUT','LEASE_AT_RISK','OFFLINE_FORK',
                           'UPLOADING','RESTORE_REQUIRED','CONFLICT','QUARANTINED'
                         )),
  dirty                  INTEGER NOT NULL CHECK (dirty IN (0,1)),
  last_error_code        TEXT,
  UNIQUE(server_id, tenant_id, remote_profile_id),
  UNIQUE(server_id, server_instance_id, tenant_id, remote_profile_id),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, tenant_id, account_id, device_id)
    REFERENCES accounts(server_id, tenant_id, account_id, device_id) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, server_instance_id, tenant_id, fleet_id, key_generation, fkek_key_id)
    REFERENCES fleet_key_state(server_id, server_instance_id, tenant_id, fleet_id, generation, fkek_key_id) ON DELETE RESTRICT,
  CHECK (
    (lease_id IS NULL AND fencing_token IS NULL AND lease_expires_at IS NULL) OR
    (lease_id IS NOT NULL AND fencing_token IS NOT NULL AND lease_expires_at IS NOT NULL)
  )
) STRICT;

CREATE TABLE operations (
  op_id             TEXT PRIMARY KEY,
  local_profile_id  TEXT REFERENCES profile_bindings(local_profile_id) ON DELETE SET NULL,
  local_profile_id_at_request TEXT NOT NULL,
  server_id         TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  server_instance_id TEXT NOT NULL,
  restore_epoch     INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
  tenant_id         TEXT NOT NULL,
  fleet_id          TEXT,
  remote_profile_id TEXT,
  snapshot_id       BLOB CHECK (snapshot_id IS NULL OR length(snapshot_id) = 16),
  manifest_replay_id BLOB CHECK (manifest_replay_id IS NULL OR length(manifest_replay_id) = 16),
  operation_scope   TEXT NOT NULL,
  kind              TEXT NOT NULL CHECK (kind IN ('PUBLISH','CHECKOUT','UPLOAD','FINALIZE','COMMIT','RELEASE','UNBIND','RECOVERY_EXPORT')),
  idempotency_key   TEXT NOT NULL,
  canonical_request_hash BLOB NOT NULL CHECK (length(canonical_request_hash) = 32),
  exact_request_bytes BLOB NOT NULL CHECK (length(exact_request_bytes) > 0),
  exact_request_bytes_sha256 BLOB NOT NULL CHECK (length(exact_request_bytes_sha256) = 32),
  remote_upload_id  TEXT,
  lease_id          TEXT,
  fencing_token     INTEGER CHECK (fencing_token IS NULL OR fencing_token BETWEEN 0 AND 9223372036854775807),
  base_version      INTEGER CHECK (base_version IS NULL OR base_version BETWEEN 0 AND 9223372036854775807),
  intent_hash       BLOB CHECK (intent_hash IS NULL OR length(intent_hash) = 32),
  ciphertext_sha256 BLOB CHECK (ciphertext_sha256 IS NULL OR length(ciphertext_sha256) = 32),
  signed_manifest_container_bytes BLOB,
  signed_manifest_container_hash BLOB CHECK (
    signed_manifest_container_hash IS NULL OR length(signed_manifest_container_hash) = 32
  ),
  signed_manifest_container_bytes_sha256 BLOB CHECK (
    signed_manifest_container_bytes_sha256 IS NULL OR length(signed_manifest_container_bytes_sha256) = 32
  ),
  state             TEXT NOT NULL CHECK (state IN ('PENDING','RUNNING','AWAITING_RETRY','COMPLETED','FAILED','QUARANTINED')),
  retry_count       INTEGER NOT NULL DEFAULT 0 CHECK (retry_count BETWEEN 0 AND 9223372036854775807),
  next_retry_at     TEXT,
  response_record_type TEXT,
  exact_response_bytes BLOB,
  exact_response_bytes_sha256 BLOB CHECK (
    exact_response_bytes_sha256 IS NULL OR length(exact_response_bytes_sha256) = 32
  ),
  exact_receipt_bytes BLOB,
  receipt_sha256   BLOB CHECK (receipt_sha256 IS NULL OR length(receipt_sha256) = 32),
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  UNIQUE(operation_scope, idempotency_key),
  UNIQUE(op_id, server_id, server_instance_id, restore_epoch),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT,
  CHECK ((exact_response_bytes IS NULL) = (exact_response_bytes_sha256 IS NULL)),
  CHECK ((exact_response_bytes IS NULL) = (response_record_type IS NULL)),
  CHECK ((exact_receipt_bytes IS NULL) = (receipt_sha256 IS NULL)),
  CHECK ((signed_manifest_container_bytes IS NULL) = (signed_manifest_container_hash IS NULL)),
  CHECK ((signed_manifest_container_bytes IS NULL) = (signed_manifest_container_bytes_sha256 IS NULL)),
  CHECK (state <> 'COMPLETED' OR exact_response_bytes IS NOT NULL),
  CHECK (state <> 'COMPLETED' OR kind NOT IN ('COMMIT','RELEASE','UNBIND') OR exact_receipt_bytes IS NOT NULL),
  CHECK (kind <> 'COMMIT' OR (
    remote_upload_id IS NOT NULL AND lease_id IS NOT NULL AND fencing_token IS NOT NULL AND
    base_version IS NOT NULL AND snapshot_id IS NOT NULL AND manifest_replay_id IS NOT NULL AND
    intent_hash IS NOT NULL AND ciphertext_sha256 IS NOT NULL AND
    signed_manifest_container_bytes IS NOT NULL
  ))
) STRICT;

CREATE TABLE upload_sessions (
  upload_local_id             TEXT PRIMARY KEY,
  local_profile_id            TEXT REFERENCES profile_bindings(local_profile_id) ON DELETE SET NULL,
  local_profile_id_at_request TEXT NOT NULL,
  commit_op_id                 TEXT NOT NULL UNIQUE REFERENCES operations(op_id) ON DELETE RESTRICT,
  server_id                   TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  server_instance_id          TEXT NOT NULL,
  restore_epoch               INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
  tenant_id                   TEXT NOT NULL,
  fleet_id                    TEXT NOT NULL,
  remote_profile_id           TEXT NOT NULL,
  remote_upload_id            TEXT NOT NULL,
  snapshot_id                 BLOB NOT NULL CHECK (length(snapshot_id) = 16),
  manifest_replay_id          BLOB NOT NULL CHECK (length(manifest_replay_id) = 16),
  operation_scope             TEXT NOT NULL,
  idempotency_key             TEXT NOT NULL,
  canonical_request_hash      BLOB NOT NULL CHECK (length(canonical_request_hash) = 32),
  intent_hash                 BLOB NOT NULL CHECK (length(intent_hash) = 32),
  preamble_sha256             BLOB NOT NULL CHECK (length(preamble_sha256) = 32),
  dek_slot_sha256             BLOB NOT NULL CHECK (length(dek_slot_sha256) = 32),
  fkek_key_id                 TEXT NOT NULL,
  key_generation              INTEGER NOT NULL CHECK (key_generation BETWEEN 0 AND 9223372036854775807),
  committed_offset            INTEGER NOT NULL DEFAULT 0 CHECK (committed_offset BETWEEN 0 AND 9223372036854775807),
  expected_ciphertext_sha256  BLOB NOT NULL CHECK (length(expected_ciphertext_sha256) = 32),
  expected_ciphertext_size    INTEGER NOT NULL CHECK (expected_ciphertext_size BETWEEN 0 AND 9223372036854775807),
  spool_ref                   TEXT NOT NULL CHECK (
                                length(spool_ref) > 0 AND
                                instr(spool_ref, '/') = 0 AND instr(spool_ref, char(92)) = 0
                              ),
  state                       TEXT NOT NULL CHECK (state IN ('OPEN','FINALIZING','READY','COMMITTED','ABORTED','QUARANTINED')),
  retry_state                 TEXT NOT NULL CHECK (retry_state IN ('NONE','BACKOFF','MANUAL')),
  retry_count                 INTEGER NOT NULL DEFAULT 0 CHECK (retry_count BETWEEN 0 AND 9223372036854775807),
  next_retry_at               TEXT,
  last_error_code             TEXT,
  exact_finalize_response_bytes BLOB,
  finalize_response_sha256    BLOB CHECK (finalize_response_sha256 IS NULL OR length(finalize_response_sha256) = 32),
  exact_commit_receipt_binding_bytes BLOB,
  commit_receipt_binding_bytes_sha256 BLOB CHECK (
    commit_receipt_binding_bytes_sha256 IS NULL OR length(commit_receipt_binding_bytes_sha256) = 32
  ),
  created_at                  TEXT NOT NULL,
  updated_at                  TEXT NOT NULL,
  UNIQUE(server_id, server_instance_id, tenant_id, remote_upload_id),
  UNIQUE(server_id, server_instance_id, tenant_id, remote_profile_id, snapshot_id),
  UNIQUE(server_id, server_instance_id, tenant_id, remote_profile_id, manifest_replay_id),
  UNIQUE(operation_scope, idempotency_key),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT,
  FOREIGN KEY(commit_op_id, server_id, server_instance_id, restore_epoch)
    REFERENCES operations(op_id, server_id, server_instance_id, restore_epoch) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, server_instance_id, tenant_id, fleet_id, key_generation, fkek_key_id)
    REFERENCES fleet_key_state(server_id, server_instance_id, tenant_id, fleet_id, generation, fkek_key_id) ON DELETE RESTRICT,
  CHECK (committed_offset <= expected_ciphertext_size),
  CHECK ((exact_finalize_response_bytes IS NULL) = (finalize_response_sha256 IS NULL)),
  CHECK ((exact_commit_receipt_binding_bytes IS NULL) = (commit_receipt_binding_bytes_sha256 IS NULL)),
  CHECK (state NOT IN ('READY','COMMITTED') OR exact_finalize_response_bytes IS NOT NULL),
  CHECK (state <> 'COMMITTED' OR exact_commit_receipt_binding_bytes IS NOT NULL)
) STRICT;

CREATE TABLE restore_journals (
  local_profile_id   TEXT PRIMARY KEY REFERENCES profile_bindings(local_profile_id) ON DELETE RESTRICT,
  journal_id         TEXT NOT NULL UNIQUE,
  phase              TEXT NOT NULL CHECK (phase IN (
                       'CREATED','DOWNLOADING','VERIFIED','EXTRACTING','VALIDATED','RESEALED',
                       'SWAP_STARTED','SWAPPED','SMOKE_PASSED','ROLLBACK_REQUIRED','ROLLED_BACK','COMPLETED'
                     )),
  staged_path        TEXT NOT NULL,
  backup_path        TEXT NOT NULL,
  old_binding_json   TEXT NOT NULL,
  target_version     INTEGER NOT NULL CHECK (target_version BETWEEN 0 AND 9223372036854775807),
  target_head_hash   BLOB NOT NULL CHECK (length(target_head_hash) = 32),
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
) STRICT;

CREATE TABLE downgrade_journals (
  journal_id                    TEXT PRIMARY KEY,
  mode                          TEXT NOT NULL CHECK (mode IN ('CLONE','PRE_V2_RESTORE')),
  original_local_profile_id     TEXT NOT NULL,
  new_local_profile_id          TEXT,
  phase                         TEXT NOT NULL CHECK (phase IN (
                                  'CREATED','CLAIMED','ORIGINAL_METADATA_MOVED','ORIGINAL_USER_DATA_MOVED',
                                  'DISCOVERY_SCAN_PASSED','CLONE_WRITTEN','PRE_V2_SET_RESTORED',
                                  'TEAM_ARTIFACTS_RETIRED','READBACK_PASSED','COMPLETED',
                                  'ROLLBACK_REQUIRED','ROLLED_BACK'
                                )),
  original_metadata_archive_path TEXT,
  original_user_data_archive_path TEXT,
  pre_v2_manifest_sha256        BLOB CHECK (pre_v2_manifest_sha256 IS NULL OR length(pre_v2_manifest_sha256) = 32),
  discovery_readback_sha256     BLOB CHECK (discovery_readback_sha256 IS NULL OR length(discovery_readback_sha256) = 32),
  created_at                    TEXT NOT NULL,
  updated_at                    TEXT NOT NULL,
  CHECK (new_local_profile_id IS NULL OR new_local_profile_id <> original_local_profile_id)
) STRICT;

CREATE TABLE restore_epoch_transitions (
  server_id                  TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  tenant_id                  TEXT NOT NULL,
  server_instance_id         TEXT NOT NULL,
  transition_replay_id       BLOB NOT NULL CHECK (length(transition_replay_id) = 16),
  previous_epoch             INTEGER NOT NULL CHECK (previous_epoch BETWEEN 0 AND 9223372036854775807),
  new_epoch                  INTEGER NOT NULL CHECK (
                               new_epoch BETWEEN 0 AND 9223372036854775807 AND
                               new_epoch > previous_epoch
                             ),
  mapping_codec              TEXT NOT NULL CHECK (mapping_codec = 'PROFILE_HEAD_SET_MERKLE_V2'),
  mapping_count              INTEGER NOT NULL CHECK (mapping_count BETWEEN 1 AND 1000000),
  profile_head_mapping_root  BLOB NOT NULL CHECK (length(profile_head_mapping_root) = 32),
  reason_code                TEXT NOT NULL CHECK (reason_code IN ('operator_restore','disaster_recovery','verified_backup_rollback')),
  approver_account_id        TEXT NOT NULL,
  approver_device_id         TEXT NOT NULL,
  approver_signing_key_id    TEXT NOT NULL,
  issued_at_ms               INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
  nonce                      BLOB NOT NULL CHECK (length(nonce) = 16),
  canonical_transition_payload_bytes BLOB NOT NULL CHECK (length(canonical_transition_payload_bytes) BETWEEN 1 AND 131072),
  transition_payload_sha256  BLOB NOT NULL CHECK (length(transition_payload_sha256) = 32),
  signature_suite_id         INTEGER NOT NULL CHECK (signature_suite_id BETWEEN 0 AND 65535),
  signature_version          INTEGER NOT NULL CHECK (signature_version = 1),
  signature_bytes            BLOB NOT NULL CHECK (length(signature_bytes) BETWEEN 1 AND 4096),
  signed_transition_container_hash BLOB NOT NULL CHECK (length(signed_transition_container_hash) = 32),
  exact_signed_transition_bytes BLOB NOT NULL CHECK (length(exact_signed_transition_bytes) BETWEEN 1 AND 262144),
  exact_signed_transition_bytes_sha256 BLOB NOT NULL CHECK (length(exact_signed_transition_bytes_sha256) = 32),
  verified_at                TEXT NOT NULL,
  PRIMARY KEY(server_id, tenant_id, server_instance_id, previous_epoch, new_epoch),
  UNIQUE(server_id, server_instance_id, tenant_id, transition_replay_id),
  UNIQUE(server_id, server_instance_id, tenant_id, nonce),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE restore_epoch_binding_proofs (
  server_id                  TEXT NOT NULL,
  tenant_id                  TEXT NOT NULL,
  server_instance_id         TEXT NOT NULL,
  previous_epoch             INTEGER NOT NULL CHECK (previous_epoch BETWEEN 0 AND 9223372036854775807),
  new_epoch                  INTEGER NOT NULL CHECK (
                               new_epoch BETWEEN 0 AND 9223372036854775807 AND
                               new_epoch > previous_epoch
                             ),
  remote_profile_id          TEXT NOT NULL,
  previous_signed_head_hash  BLOB NOT NULL CHECK (length(previous_signed_head_hash) = 32),
  new_signed_head_hash       BLOB NOT NULL CHECK (length(new_signed_head_hash) = 32),
  leaf_index                 INTEGER NOT NULL CHECK (leaf_index BETWEEN 0 AND 999999),
  leaf_count                 INTEGER NOT NULL CHECK (leaf_count BETWEEN 1 AND 1000000 AND leaf_index < leaf_count),
  canonical_leaf_bytes       BLOB NOT NULL CHECK (length(canonical_leaf_bytes) BETWEEN 1 AND 1024),
  leaf_hash                  BLOB NOT NULL CHECK (length(leaf_hash) = 32),
  expected_root              BLOB NOT NULL CHECK (length(expected_root) = 32),
  canonical_inclusion_proof_bytes BLOB NOT NULL CHECK (length(canonical_inclusion_proof_bytes) BETWEEN 1 AND 65536),
  proof_sha256               BLOB NOT NULL CHECK (length(proof_sha256) = 32),
  verified_at                TEXT NOT NULL,
  PRIMARY KEY(server_id, tenant_id, server_instance_id, previous_epoch, new_epoch, remote_profile_id),
  FOREIGN KEY(server_id, tenant_id, server_instance_id, previous_epoch, new_epoch)
    REFERENCES restore_epoch_transitions(
      server_id, tenant_id, server_instance_id, previous_epoch, new_epoch
    ) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, tenant_id, remote_profile_id)
    REFERENCES profile_bindings(server_id, tenant_id, remote_profile_id) ON DELETE RESTRICT
) STRICT;
```

Startup contract: query exactly one `schema_meta` row; `migration_state != CLEAN`, row count khác 1, `schema_version` mới hơn reader hoặc `min_reader_version` cao hơn binary đều disable Team và fail closed. `server_origins` được tạo từ URL parser/canonicalizer; `last_restore_epoch` chỉ mirror external authority. `operations`/`upload_sessions` bind exact instance+epoch; upload additionally mirrors immutable `snapshot_id` + `manifest_replay_id`. Exact request/container/response bytes remain authority and every relational equality is checked before send/commit. `signed_authorization_records` persist five approval/capability/fleet-grant schemas; dedicated `tenant_root_key_generations` + `tenant_root_key_grants` persist exact sixth root-grant schema and are keyed by `server_instance_id`. `fleet_key_state` is also instance-keyed. Before key use, reparse/reverify exact record + all-column/HPKE equality + instance/tenant/device/generation association; no cache flag grants authority.

Reference workflow probes bắt buộc chạy trên fresh DB và reopen thật:

1. **UNBIND delete:** insert completed `UNBIND` với exact response/receipt bytes, delete `profile_bindings` row, assert `operations.local_profile_id IS NULL` nhưng tombstone context, request hash và exact receipt bytes/hash còn nguyên.
2. **RELEASE response loss:** insert completed `RELEASE`, close/reopen, replay cùng scope/key/hash/full bytes và assert exact `IdempotentStoredResponseV2` + release receipt không bị serialize lại after lease row absent.
3. **Canonical authorization/root grants + equality:** cho năm records ở 5.6.1 và `TenantRootKeyGrantV2`, encode→decode→re-encode byte-identical; reject every noncanonical/domain/version/type/bound/optionality error. Close/reopen then mutate each mapped field. Root grant matrix mutates variant, root IDs/generations, approval link, HPKE suite/info/recipient/encapped/wrapped bytes, previous-root pair, signature/container/full hashes; reject before unwrap/bootstrap/rotation/revoke. Second `FirstRootSelfGrant` and cross-instance generation FK reject.
4. **Upload resume/digest + identity/replay FK:** persist upload `snapshot_id`, `manifest_replay_id`, offset/digest/size, intent/preamble/slot hashes, instance/epoch and key generation; close/reopen. Duplicate upload/snapshot/replay/scope-key UNIQUE rejects; upload referencing COMMIT op with different instance/epoch or fleet generation from another instance rejects.
5. **Manifest/request byte-identical replay + equality mismatch:** before finalize persist COMMIT operation + upload with exact manifest/request bytes/hashes and matching snapshot/replay/upload/lease/fence/base/intent/ciphertext/instance/epoch bindings. Close/reopen at three request/response crash points; retry emits exact stored bytes. Mutate each operation/upload instance, epoch, snapshot or replay column against exact bytes; reject before network/commit even if fixture bypasses FK.
6. **Receipt replay/mismatch:** server commit persists exact `CommitReceiptBindingV2` bytes/hash atomically; local verifies request/snapshot/version/head/lease-release/instance/epoch fields, persists same bytes, close/reopen và replays byte-identical receipt. Same scope/key với khác canonical request hash bị `IDEMPOTENCY_MISMATCH`; same hash nhưng alternate bytes/noncanonical order bị reject. `COMMITTED` không insert được nếu thiếu finalize response hoặc exact receipt binding bytes/hash.
7. **Tenant/profile epoch transition:** exact 5.6.3 vectors for `n=1/2/3`, binary/unary nodes and directions; create colliding profile IDs across tenants and multiple A bindings. Empty/duplicate/reordered leaves, wrong count/root/index/direction/sibling/step, missing head, uncovered profile and cross-tenant replay reject. Close/reopen unquarantines only exact covered A leaves.
8. **Unknown schema:** mutate test DB thành `schema_version = reader_max + 1`, `min_reader_version = binary_version + 1`, non-singleton hoặc `migration_state != CLEAN`; startup compatibility query phải disable Team trước mọi binding/credential read.
9. **Recovery journal:** advance durable restore journal qua phase, close/reopen tại từng crash point và assert replay chọn đúng next/rollback phase; completed journal phải xóa/retire trước unbind. Chạy tương tự cho downgrade journal path-move/readback phases.
10. **SQLite unsigned wire range:** boundary vectors `0` và `9223372036854775807` pass cho mỗi wire-integer class; `-1`, `9223372036854775808`, `18446744073709551615`, overlong CBOR, REAL/TEXT coercion và wrap/saturating-cast fixtures đều reject với `WIRE_INTEGER_OUT_OF_RANGE` hoặc DDL `CHECK`/STRICT failure before mutation. Close/reopen confirms max accepted value remains exact.
11. **Exact mutation replay:** for publish-create, checkout, create-upload, finalize and local unbind, simulate response loss before client receipt persistence then close/reopen. Assert exact stored response bytes return and no second profile/lease/fence/upload/promotion/binding deletion occurs. Checkout retry after stored expiry still returns original expired lease/fence; new lease requires new key after reconcile.

Không lưu access/refresh token raw, passphrase, DEK/FKEK/TRK hoặc plaintext profile payload trong SQLite.

### 11.2. Source-of-truth rule

- `profiles/*.json` và `user-data/<id>` tiếp tục là local profile source of truth.
- `team-sync.db` chỉ quyết định binding/sync state và không được dùng để rebuild toàn bộ profile nếu local JSON mất.
- Mọi mutation local profile đang team-bound đi qua common claim + sync guard; profile local-only không chịu network/key dependency.
- API/MCP/UI launch phải hội tụ vào cùng `launch_profile`/claim boundary để tránh bypass.
- `signed_authorization_records` giữ exact payload/container artifacts và typed equality columns; `fleet_key_state` chỉ giữ generation/device association, verified `DeviceHpkeGrant` record reference và credential reference, không giữ raw FKEK. Trước key use phải reparse/reverify signature/container/full-byte hashes + exact all-column/HPKE equality; cache flag không cấp authority.
- Exact external authority `server_instance_id + restore_epoch`, local mirror `server_origins.last_restore_epoch`, replay-row instance/epoch và per-binding pinned signed head được so trước mọi Team mutation. Missing/corrupt/behind external record disable toàn bộ v2 writes; external-ahead legitimate restore chỉ reconcile từ exact prepared bundle + same-tenant signed transitions/proofs. Binding mismatch/rollback đặt đúng server + tenant bindings thành `QUARANTINED`; chỉ valid same-tenant root-signed `RestoreEpochTransitionV2` và per-binding inclusion proof được persist/readback mới gỡ từng binding; cross-tenant cache/proof không bao giờ hợp lệ.

### 11.3. WAL và backup

- Chỉ bật WAL sau khi test crash/checkpoint/busy/upgrade/rollback pass trên Windows; reject config root trên network filesystem.
- Trước migration dùng SQLite online backup API; sau backup chạy `integrity_check` và `foreign_key_check`, ghi hash artifact không chứa row data.
- Shutdown/rollback phải checkpoint đúng cách; không copy riêng `.db` trong khi bỏ quên `-wal`/`-shm`.
- Eleven workflow DDL probes phải close/reopen DB để chứng minh exact UNBIND/RELEASE/claim/manifest-request/upload/receipt/tenant-transition/journal state, instance/epoch binding và max-i64 values sống qua WAL/checkpoint; in-memory-only test không đủ. External epoch authority crash-order table được test riêng trên filesystem thật vì in-memory SQLite không thể chứng minh file/parent fsync ordering.

---

## 12. ADR — Migration, quarantine và rollback

### 12.1. Server migration

1. Preflight version, free disk, local filesystem, permissions và process exclusivity.
2. Snapshot coordination identity (`server_instance_id`, external-to-DB monotonic `restore_epoch` record), online backup DB + blob manifest; SHA-256; `integrity_check`; `foreign_key_check`.
3. Apply additive migrations, ví dụ `0004_v2_tenant_control_plane.sql`, `0005_v2_sync_and_keys.sql`.
4. Reopen, rerun checks, verify v1 regression và empty v2 tenant smoke.
5. Bật v2 bằng feature flag/canary; không tự migrate data.

**Executable server migration probes — fresh và upgrade-from-v0.1.28**

Migration test harness phải mở SQLite thật với `PRAGMA foreign_keys=ON`, chạy
fresh chain và separately restore v0.1.28 fixture rồi upgrade. Mỗi assertion
dưới đây là executable SQL/result assertion, không phải schema-review checkbox:

```sql
CREATE TEMP TABLE _assert(ok INTEGER NOT NULL CHECK(ok = 1));

INSERT INTO _assert SELECT COUNT(*) = 2
FROM pragma_table_info('v2_uploads')
WHERE name IN ('snapshot_id','manifest_replay_id') AND type = 'BLOB' AND "notnull" = 1;
INSERT INTO _assert SELECT COUNT(*) = 1
FROM pragma_table_info('v2_uploads')
WHERE name = 'fleet_id' AND "notnull" = 1;

INSERT INTO _assert SELECT COUNT(*) = 3
FROM pragma_table_info('v2_snapshots')
WHERE name IN ('upload_id','snapshot_id','manifest_replay_id') AND "notnull" = 1;
INSERT INTO _assert SELECT COUNT(*) = 1
FROM pragma_table_info('v2_snapshots')
WHERE name = 'fleet_id' AND "notnull" = 1;

INSERT INTO _assert SELECT COUNT(*) = 1
FROM pragma_table_info('v2_root_key_generations')
WHERE name = 'server_instance_id' AND "notnull" = 1;
INSERT INTO _assert SELECT COUNT(*) = 1
FROM pragma_table_info('v2_fleet_key_generations')
WHERE name = 'server_instance_id' AND "notnull" = 1;

INSERT INTO _assert
SELECT EXISTS (
  SELECT 1
  FROM pragma_index_list('v2_fleet_key_generations') AS il
  JOIN pragma_index_info(il.name) AS ii
  WHERE il."unique" = 1
  GROUP BY il.name
  HAVING COUNT(*) = 5 AND
    MAX(ii.seqno = 0 AND ii.name = 'server_instance_id') = 1 AND
    MAX(ii.seqno = 1 AND ii.name = 'tenant_id') = 1 AND
    MAX(ii.seqno = 2 AND ii.name = 'fleet_id') = 1 AND
    MAX(ii.seqno = 3 AND ii.name = 'generation') = 1 AND
    MAX(ii.seqno = 4 AND ii.name = 'fkek_key_id') = 1
);

-- Exact five-column generation FK; run once per listed child table.
INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_fleet_device_hpke_grants')
  WHERE "table" = 'v2_fleet_key_generations'
  GROUP BY id HAVING COUNT(*) = 5 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 3 AND "from" = 'generation' AND "to" = 'generation') = 1 AND
    MAX(seq = 4 AND "from" = 'fkek_key_id' AND "to" = 'fkek_key_id') = 1
);
INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_fleet_recovery_grants')
  WHERE "table" = 'v2_fleet_key_generations'
  GROUP BY id HAVING COUNT(*) = 5 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 3 AND "from" = 'generation' AND "to" = 'generation') = 1 AND
    MAX(seq = 4 AND "from" = 'fkek_key_id' AND "to" = 'fkek_key_id') = 1
);
INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_fleet_rotation_grants')
  WHERE "table" = 'v2_fleet_key_generations'
  GROUP BY id HAVING COUNT(*) = 5 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 3 AND "from" = 'generation' AND "to" = 'generation') = 1 AND
    MAX(seq = 4 AND "from" = 'fkek_key_id' AND "to" = 'fkek_key_id') = 1
);

-- Upload/snapshot use key_generation -> generation; both must carry fleet_id.
INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_uploads')
  WHERE "table" = 'v2_fleet_key_generations'
  GROUP BY id HAVING COUNT(*) = 5 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 3 AND "from" = 'key_generation' AND "to" = 'generation') = 1 AND
    MAX(seq = 4 AND "from" = 'fkek_key_id' AND "to" = 'fkek_key_id') = 1
);
INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_snapshots')
  WHERE "table" = 'v2_fleet_key_generations'
  GROUP BY id HAVING COUNT(*) = 5 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 3 AND "from" = 'key_generation' AND "to" = 'generation') = 1 AND
    MAX(seq = 4 AND "from" = 'fkek_key_id' AND "to" = 'fkek_key_id') = 1
);

INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_snapshots')
  WHERE "table" = 'v2_uploads'
  GROUP BY id HAVING COUNT(*) = 6 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'upload_id' AND "to" = 'upload_id') = 1 AND
    MAX(seq = 3 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 4 AND "from" = 'snapshot_id' AND "to" = 'snapshot_id') = 1 AND
    MAX(seq = 5 AND "from" = 'manifest_replay_id' AND "to" = 'manifest_replay_id') = 1
);

PRAGMA integrity_check;
PRAGMA foreign_key_check;
```

Transaction fixtures then execute and assert exact SQLite result codes:

1. insert upload+snapshot with equal `(server_instance_id,tenant_id,upload_id,
   fleet_id,snapshot_id,manifest_replay_id)` and exact same fleet-generation tuple
   → pass; change any one fleet/snapshot/replay/instance/generation/key field in
   snapshot → `SQLITE_CONSTRAINT_FOREIGNKEY`;
2. duplicate snapshot ID or duplicate manifest replay ID under same
   `(server_instance_id,tenant_id,profile_id)` → `SQLITE_CONSTRAINT_UNIQUE`;
   same opaque IDs in a different tenant are allowed;
3. insert root/fleet generation then each device/recovery/rotation grant, upload
   and snapshot under exact same `(server_instance_id,tenant_id,fleet_id,
   generation,fkek_key_id)` → pass; mutate each tuple component in every child
   table → `SQLITE_CONSTRAINT_FOREIGNKEY`;
4. close/reopen and rerun `_assert`, `integrity_check='ok'`, empty
   `foreign_key_check`; migration down/rollback restores the pre-migration copy,
   never drops columns in-place on the only backup.

The harness fails if a required index is non-UNIQUE, column order differs from
7.2/7.3, FK candidate key is missing, or a migration silently backfills random
snapshot/replay IDs. Existing rows may only be backfilled from exact persisted
manifest/request bytes; no exact authority means quarantine/manual migration.

### 12.2. Legacy plaintext quarantine

- Nếu v1 `proxies`, `environments.config_json/notes` hoặc snapshot legacy có dữ liệu, instance phải báo `legacy_plaintext_present`.
- V1 remote routes tắt mặc định; chỉ loopback/admin recovery mode nếu operator chủ động bật.
- Không được marketing/telemetry báo “ciphertext-only server” khi legacy plaintext còn tồn tại.
- Flow migrate sau này phải: backup → local authorized export → client encrypt/upload v2 → readback/decrypt drill → explicit scrub old rows/blobs → vacuum/secure-delete policy review. Bước scrub là destructive và luôn cần xác nhận riêng.

### 12.3. Launcher migration

- Tạo DB/folder team-sync additive; không rewrite `profiles/*.json` hàng loạt.
- Binding chỉ được ghi sau publish/checkout receipt hoàn chỉnh.
- Nếu migration team DB fail, local-only launcher vẫn start và Team/Fleet bị disable với safe error.
- Mọi restore/downgrade tạo durable journal trước path mutation; journal persist original/new IDs, exact source/destination paths, manifest hashes, phase và readback. Unknown/newer journal phase fail closed.

### 12.4. Rollback

- **Không được** nói hoặc dựa vào việc v0.1.28 “ignore” `team-sync.db`: binary cũ không hiểu Team binding và có thể launch profile, bypass lease guard.
- Launcher downgrade chỉ được đánh dấu `downgrade_ready` khi không còn browser running, current lease, non-terminal operation/encrypted spool hoặc restore journal. Mỗi binding phải hoàn tất đúng một flow: explicit unbind; downgrade clone; hoặc complete pre-v2 restore. Không trộn steps giữa các flow.
- **Explicit unbind:** check-in/release nếu cần, persist completed exact UNBIND receipt độc lập, delete binding, re-scan discovery paths và readback local-only state. Receipt/tombstone sống sau binding delete.
- **Downgrade clone:** tạo durable `CLONE` journal; claim stopped original; same-volume atomic move original `profiles/<id>.json` và toàn bộ original user-data ra một archive root nằm ngoài **mọi** path/pattern discovery mà v0.1.28 hiểu; flush files + source/destination parent directories; chạy discovery scan chứng minh old ID/path không còn thấy. Sau đó materialize clone với cryptographically random **new local profile ID**, new metadata/user-data paths, không Team marker, remote lineage, credential reference hoặc copied `team-sync` artifact. Chỉ set `downgrade_ready` sau close/reopen/readback bằng v0.1.28 discovery logic. Original vẫn retained ngoài discovery để recovery, không “quarantined in place”.
- **Complete pre-v2 restore là flow riêng:** tạo `PRE_V2_RESTORE` journal; verify complete pre-v2 manifest/hash; restore đồng bộ Launcher config/settings, `profiles/*.json` và toàn bộ user-data từ cùng backup epoch; sau readback mới archive/retire Team DB/spool/credential references/key artifacts theo manifest. Restore từng phần, reuse clone journal hoặc chỉ xóa DB bị cấm.
- Server rollback phải disable v2, chặn checkout mới, drain/force-expire theo capability + audit, không còn pending upload/finalize/commit, rồi restore verified pre-migration server config/DB/blob set. Verify SHA-256, `integrity_check`, `foreign_key_check`, blob manifest và v1 read-only smoke trước mở write.
- `server_instance_id` là coordination identity ổn định; authoritative server restore phải tăng server-global `restore_epoch` trong checksummed/fsync'd external identity record ngoài SQLite rollback scope. Với mỗi tenant có retained/bound profile, same-tenant root custodian tạo exact `SignedRestoreEpochTransitionV2` + `PROFILE_HEAD_SET_MERKLE_V2` leaves/proofs theo 5.6.3. Client chỉ exit quarantine sau exact container/signature/all-column equality, count/root/tree-shape, epoch continuity và per-binding proof đều pass. Empty/duplicate/reordered/uncovered/cross-tenant sets hoặc instance drift quarantine; không auto-push pending data.
- Local `team-sync.db`/spool không được orphan rồi cho old binary chạy. Chỉ archive/remove sau unbind/clone/full-restore gate và readback chứng minh mọi local profile còn lại là local-only.

#### Server restore epoch authority, write order và crash reconciliation

External record path là operator-configured identity root riêng, không nằm dưới server DB/blob directory và không được đưa vào DB rollback restore set. `v2_server_state` chỉ mirror `(server_instance_id,restore_epoch,external_record_sha256)`. Mọi restore chạy khi v2 writes đã quiesce theo thứ tự bất biến:

1. Đọc/verify external record hiện tại `E`: exact magic/version, checksum, `server_instance_id`, epoch trong `0..i64::MAX`; record missing/corrupt hoặc instance mismatch dừng ngay.
2. Tạo restored SQLite candidate tại inactive path, exact tenant-scoped signed transition/proof set cho `E -> E+1`, và external restore-preparation manifest bind candidate DB SHA-256, transition-set SHA-256, instance, previous/new epoch và restore transaction ID. Chạy `integrity_check`/`foreign_key_check`, fsync mọi file rồi fsync parent directories; live DB chưa mở write.
3. Atomically write temp external epoch record `E+1`, fsync temp, replace authority record và fsync identity-root parent directory. Đây là authority commit point; không bao giờ write SQLite mirror trước bước này hoặc hạ record về `E`.
4. Atomically install pre-fsynced DB candidate vào configured DB path và fsync DB parent directory. Crash giữa bước 3–4 chỉ được resume từ exact preparation manifest/candidate hash; không open DB cũ cho v2 writes.
5. Open installed DB read-only; require external record, preparation manifest, restored DB hash, all same-tenant signed transitions/proofs và profile-head mappings match. Trong một SQLite transaction, persist transitions/proofs và rebuild `v2_server_state` mirror tới exact external record; commit/readback rồi mới enable writes. Retire preparation artifacts chỉ sau readback + directory fsync.

| Startup/crash state | Evidence | Deterministic action |
|---|---|---|
| External record missing/corrupt | Bất kỳ DB/mirror | `EPOCH_AUTHORITY_MISSING/CORRUPT`; disable v2 writes, không rebuild authority từ DB/backup |
| External instance/epoch = DB mirror | Không có non-terminal restore preparation | Normal read-only verification rồi open; checksum/hash mismatch vẫn fail closed |
| Preparation durable, external vẫn `E`, DB mirror `E` | Candidate + transition set valid, authority commit point chưa qua | Giữ writes off; resume validation/step 3 hoặc audited abort bỏ candidate; không mutate mirror |
| External `E+1`, live DB vẫn mirror `E` | Exact preparation manifest/candidate/transition hashes valid | Resume atomic DB install rồi read-only reconcile; không open old DB write |
| External `E+1`, installed restored DB mirror `< E+1` | Same-instance preparation manifest và complete tenant transition/proof set valid | Verify candidate/integrity/head coverage; transactionally rebuild mirror tới `E+1`, readback, rồi enable writes |
| External ahead DB nhưng preparation/transition/proof thiếu, corrupt, uncovered hoặc cross-tenant | Không đủ exact recovery evidence | `EPOCH_RECONCILIATION_REQUIRED`; quarantine/disable writes, operator recovery only |
| External epoch hoặc instance **behind/different from DB mirror** | Bất kỳ | `EPOCH_AUTHORITY_BEHIND_DB`; security incident, fail closed; không copy/lower/rewrite external record từ SQLite |
| External = reconciled DB mirror `E+1`, preparation journal terminal | Hash/readback/fsync pass | Retire preparation bundle; subsequent startup normal |

External record không bao giờ bị rollback, xóa hoặc hạ epoch bởi DB restore. Bất kỳ crash point trước/sau candidate fsync, preparation-manifest fsync, external temp write/fsync/replace/parent-fsync, DB install/parent-fsync, read-only open, mirror transaction hoặc final readback phải map đúng một row trên; không có “best effort” fallback.

**Trust limit của cơ chế này:** external record là authority cho authorized full
DB restore epoch, không phải signed transparency log cho mutable auth state. Nó
không chứng minh freshness của individual role/session/revocation/lease/generation
rows trong cùng epoch. Coordinator process + live coordination/RBAC SQLite
integrity/freshness vẫn là trusted control plane. Nếu operator không còn tin
integrity đó, disable toàn bộ v2 writes và restore/reconcile từ trusted host-level
evidence; artifact signatures chỉ phát hiện artifact tamper, không sửa được RBAC
rollback. Không thêm signed auth transparency trong v0.2.x.

### 12.5. Downgrade/restore acceptance matrix

| Tình trạng | Cho chạy v0.1.28? | Hành động bắt buộc |
|---|---:|---|
| Có running browser, active lease, pending op/spool hoặc restore/downgrade journal chưa stable | Không | Hoàn tất/reconcile; không bypass bằng delete DB |
| Binding đã explicit unbind, receipt độc lập còn replay được, discovery scan sạch | Có | Close/reopen readback local-only state rồi set downgrade-ready marker |
| Downgrade clone journal chưa move cả original metadata và user-data khỏi mọi v0.1.28 discovery path | Không | Resume/rollback journal; không tạo clone in-place |
| Original đã move+fsync ngoài discovery; clone có new local ID, no Team/credential artifact; discovery readback pass | Có | Giữ original archive ngoài discovery; pin journal/readback hash |
| Có complete pre-v2 backup nhưng chưa restore đủ config/profile/user-data hoặc Team artifacts chưa retire | Không | Chạy riêng full-restore journal; partial restore bị cấm |
| Complete pre-v2 set restored + Team artifacts archived/retired + readback pass | Có | Pin manifest/readback hashes; không reuse clone state |
| Server-global epoch đổi nhưng tenant/profile chưa có valid root-signed `RestoreEpochTransitionV2` + inclusion proof | Không cho Team writes của binding đó | Giữ tenant-scoped quarantine; verify previous/new epoch, canonical multi-profile root, exact previous/new head leaf, reason, approver, timestamp, nonce và signature |
| External epoch record missing/corrupt, behind DB, instance mismatch hoặc ahead DB không có exact prepared restore bundle + signed transition/proof set | Không | Disable toàn bộ v2 writes; không rebuild/lower authority từ SQLite; chỉ resume deterministic crash row bằng exact hashes/readback |
| Chỉ có partial backup, transition invalid/replayed, missing profile proof, cross-tenant root/proof hoặc instance ID mismatch | Không | Quarantine đúng tenant/bindings và recovery/operator decision |

---

## 13. Observability không secret

### 13.1. Structured logs/metrics

Cho phép: request ID, route template, tenant/profile opaque ID đã hash/truncate theo policy, status/error code, latency, bytes, upload offset, version/fence, lease duration, key/envelope generation, migration phase.

Cấm: `Authorization`, cookies, passphrase, key bytes, HPKE plaintext, proxy URL credentials, profile config, archive filenames có user data, raw multipart/chunk body, raw `response_json` ngoài allowlist.

Metrics tối thiểu:

- checkout grant/conflict/expiry/renew failure;
- stale fence/base mismatch/idempotency mismatch;
- upload resume/retry/hash mismatch/receipt replay/recovery-matrix transition/orphan cleanup; gauge `FINALIZING` phải về zero trước readiness;
- backup/restore bytes/duration/peak-memory bucket;
- restore rollback/smoke failure;
- key enrollment/rotation/recovery status không chứa identity label;
- DB busy/checkpoint/migration/GC outcomes;
- authorization claim signature/index equality failures, manifest replay mismatch, downgrade discovery-scan/readback và tenant/profile restore-epoch proof verify/replay/cross-tenant outcomes, không log paths/signed bytes.

### 13.2. Audit

- Audit event là structured enum + outcome + reason code.
- Force-expire, device revoke, key rotation, recovery export, restore-epoch transition, downgrade-ready, legacy mode enable và plaintext scrub đều bắt buộc audit.
- Audit failure policy: security-sensitive admin mutation fail closed nếu không ghi được audit; high-frequency chunk transfer dùng aggregate event để tránh overload.

---

## 14. Phased implementation plan

### G2 spike lane — Dependency/security/durability research (sau durable Architect + Critic consensus, trước verifier/production)

G2 là bounded research/dependency/durability execution lane duy nhất được phép
chạy sau G1. Nó không phải production implementation và không trao authority
cho production executor chọn primitive/provider. Goal coordinator có thể staff,
coordinate và collect evidence cho lane này; nếu bất kỳ row fail/blocked thì
goal phải stop tại G2 và không mở phase v0.2.0.

**Deliverables**

- Reproducible spike matrix cho STREAM/final-frame AAD, HPKE out-of-envelope TRK/FKEK grants, signing suite và every exact `CanonicalCborV2` contract named in 5.6: six authorization/key-grant containers, slot context/slot/intent, signed transition + deterministic Merkle proof, manifest/commit/receipt và idempotent mutation request/stored-response. Pin golden hex/SHA-256 vectors without changing fields/preimages; include Argon2id, secrecy/zeroization và Windows credential store.
- Official vectors + malformed/counter/final/trailing-byte tests; prove exact API semantics, algorithm IDs, license, maintenance, MSRV, feature graph và advisories.
- Windows durability harness prove file `sync_data`, immutable rename, parent-directory fsync/durable equivalent và SQLite WAL/busy/crash ordering trên supported filesystems; network share fail closed.
- Strict Windows path/case-fold/discovery corpus và current SQLite support cho local DDL + eleven probes, plus fresh/upgrade server migration probes for snapshot/replay UNIQUE/FK and instance-keyed root/fleet generations. Include six grant all-column equality matrices, response-loss replay/no-second-lease-fence, over-i64 rejects and exact n=1/2/3 Merkle/direction/cross-tenant vectors.
- Filesystem restore-epoch harness prove external checksummed record nằm ngoài SQLite rollback scope; candidate/transition/preparation fsync; external replace+parent fsync authority commit; DB install/open/mirror reconcile; và mọi row trong crash-order table mục 12.4, đặc biệt missing/corrupt/behind/ahead-without-proof fail closed.
- Trust-boundary tests distinguish guarantees: artifact/blob/backup tamper is client-detected and confidentiality-preserving; live coordination/RBAC DB rollback/compromise is outside guarantee and causes operator fail-closed when trust is lost. Không add signed auth transparency artifact.
- Security review artifact chốt suite/provider hoặc ghi blocker; không được “tạm implement” primitive chưa pass.

**Gate:** mọi row có reproducible evidence, rồi independent verifier readback commands/fixtures/versions/SHA-256 và phát verdict `PASS`. Bất kỳ uncertainty về exact field/preimage/vector, root/fleet HPKE context/equality, response-loss/no-second-resource semantics, snapshot/replay migration probes, instance-keyed generation FKs, over-i64 rejection, external epoch crash reconciliation, trust-assumption documentation, credential-store persistence, directory durability hoặc MSRV làm G2 `FAIL/BLOCKED`. Goal dừng; chỉ verifier-confirmed G2 `PASS` mới mở v0.2.0.

### Phase v0.2.0 — Internal encrypted-backup foundation (Windows-only Team runtime)

**Entry condition:** durable Architect→Critic consensus + G2 artifact đã được
independent verifier readback với verdict `PASS`. Không implementation deliverable nào dưới đây bắt đầu
trước điều kiện này.

**Deliverables**

- Shared strict streaming archive/envelope v2 với pre-encryption `EnvelopeIntentV2`, one FKEK-wrapped `DekSlotV2`, post-encryption exact `SignedSnapshotManifestV2`, exact commit request/receipt codecs, bounded memory và authenticated final frame.
- Windows Credential Manager provider + distinct signing/HPKE keys + Argon2id encrypted recovery bundle.
- Local `team-sync.db`, per-fleet exact signed-claim state, durable exact manifest/request operation rows, exact operation/upload receipts, encrypted spool, durable restore/downgrade journals và tenant-scoped epoch-transition/proof cache.
- Additive server v2 migrations, trusted coordinator/RBAC control plane, six exact authorization/key-grant schemas + indexed HPKE bytes, exact mutation responses, manifest/upload snapshot+replay FK parity, instance-keyed root/fleet generations, exact transition/Merkle contracts, signed heads và crash-safe ciphertext upload skeleton; v1 quarantine flag.
- Launcher local encrypted export/import/restore trên disposable profiles; chưa mở fleet multi-device mặc định.
- macOS/Linux build/local-only behavior vẫn pass nhưng Team controls fail closed/ẩn tới platform credential-store tests.

**Acceptance/release gate**

- Golden/test-vector envelope; corruption/truncation/wrong-AAD/wrong-key fail closed.
- Commitment-direction vectors prove no intent/header final-manifest commitment; device membership changes do not mutate retained one-slot envelopes.
- Fresh local eleven probes + fresh/upgrade server migration probes pass: root/fleet grant equality, mutation response loss/no duplicate resource, upload/snapshot/replay UNIQUE/FK, instance-keyed generations, exact request/response/receipt replay, n=1/2/3 transition/proof directions, unknown schema/journal replay và all unsigned SQLite wire integer bounds.
- External epoch authority harness pass toàn bộ prepare/fsync/replace/install/open/reconcile crash table; `v2_server_state` chỉ mirror và không có path nào lower/rebuild authority từ SQLite.
- Peak RSS dưới budget đã chốt trên fixture lớn; không xuất hiện plaintext marker trong spool/server DB/blob/log.
- Crash injection restore luôn old-good/new-good.
- Upgrade/rollback v0.1.28 drill pass.
- Full 96-tool descriptor fixture pass.
- Đây là internal foundation artifact; **không production release**, không claim Team-ready.

### Phase v0.2.1 — Team/Fleet sync pilot

**Deliverables**

- Tenant/fleet ACL, device enrollment và out-of-envelope canonical signed HPKE FKEK grants.
- Signing PoP, one-time OOB `FirstRootSelfGrant`, subsequent/rotation/revoke/readback root lifecycle, and all six authorization/key-grant containers with all-column equality—including HPKE suite/info/recipient/encapped/wrapped bytes.
- Atomic publish-create initial lease and checkout/release exact idempotency state machine; no response-loss path mints a second lease/fence/resource.
- One-current-lease/server-time semantics; crash-safe PATCH/finalize/commit/fsync, durable exact `SignedSnapshotManifestV2`/`CommitRequestV2` replay across close/reopen, exhaustive recovery matrix với zero lingering `FINALIZING`, và retained byte-identical `CommitReceiptBindingV2` bytes/hash.
- Launcher checkout/check-in/release/offline-fork state và common launch guard.
- Team/Fleet UI cho pilot; server feature flag và disposable fleet.

**Acceptance/release gate**

- Cross-tenant same-UUID adversarial matrix và six-record payload/container/index tamper matrix pass; second self-grant/cross-instance generation rejects; HPKE mutations fail before open; artifact columns never authorize alone.
- Stale/expired/wrong-device/wrong-fence/wrong-base commit đều bị chặn trong concurrent E2E.
- Network loss ở mọi chunk/commit response resume đúng; exact `CommitRequestV2` và replayed `CommitReceiptBindingV2` remain byte-identical after server/local close/reopen, không duplicate version.
- Recovery matrix injects every DB/object/receipt class; corrupt/short/missing object quarantines deterministically và `COMMITTED` mismatch raises security incident rather than GC.
- Active coordinator limitation hiển thị trong threat model/docs; test rollback/substitution relative to pinned signed state, không claim global equivocation prevention.
- Hai máy disposable thực hiện publish → checkout → restore → use → check-in → checkout máy đầu.
- Local-only regression và 96 MCP contract vẫn pass.

### Phase v0.2.2 — Rotation/recovery, hardening và rollout readiness

**Deliverables**

- `PREPARING -> ACTIVE -> RETIRED` rotation/revocation/recovery UI, canonical grant readback/ack và retained-generation GC policy.
- Tenant-scoped root-signed `RestoreEpochTransitionV2` over server-global epoch, canonical multi-profile head mapping commitment + per-binding inclusion proofs, downgrade clone discovery evacuation/new-ID flow và separate complete pre-v2 restore workflow.
- Legacy migration assistant chỉ khi được phê duyệt; không auto scrub.
- Security hardening, quotas/rate limits, observability, orphan GC.
- Fuzz/property/crash/soak tests; release docs/runbooks/canary rollback.

**Acceptance/release gate**

- Lost-device + recovery-bundle drill; revoked device không nhận generation mới.
- Restore mọi retained snapshot generation pass trước key GC.
- Downgrade clone proves original metadata/user-data absent from every v0.1.28 discovery path; full pre-v2 restore và multi-tenant/multi-profile epoch-transition quarantine/release drills pass independently, gồm missing-profile proof và cross-tenant rejection.
- Fuzz corpus không crash/OOM/path escape; 24h soak không orphan/duplicate version.
- Independent Architect/security/verifier sign-off.
- Production release vẫn blocked tới khi named operator hoàn thành verified backup, safe downgrade/rollback và recovery-bundle readback drills; commit/push/tag/release cần yêu cầu riêng.

---

## 15. File/module impact dự kiến

Đây là impact map, không phải yêu cầu phải tạo đúng mọi filename.

| Khu vực | File/module dự kiến | Thay đổi |
|---|---|---|
| Shared | `shared/Cargo.toml` | Thêm dependency crypto/KDF/serialization đã pin và audit; tránh feature không cần thiết |
| Shared | `shared/src/snapshot.rs` hoặc tách `snapshot/v1.rs`, `snapshot/v2.rs` | Giữ API/tests v1; thêm strict-v2 streaming writer/reader, collision index và validator không làm đổi v1 behavior |
| Shared | `shared/src/portable.rs` | Versioned segmented portable records, bounded SQLite reads, no Debug secret |
| Shared | mới `shared/src/envelope.rs`, `shared/src/keys.rs`, `shared/src/signing.rs` | Exact 5.6 codecs: slot context/slot/intent, six authorization/key-grant containers, mutation request/stored responses, manifest/commit/receipt, signed transition/Merkle proofs; distinct signing/HPKE identities và recovery primitives |
| Server | `server/Cargo.toml` | HTTP range/upload/hash dependencies chỉ khi existing stack không đủ |
| Server | `server/migrations/0004_*.sql`, `0005_*.sql` | Additive trusted RBAC control plane; six grant schemas; exact mutation responses; snapshot/replay UNIQUE/FK; instance-keyed root/fleet generations; exact transition/proof/upload/head schema |
| Server | `server/src/models.rs`, `config.rs`, `db.rs` | V2 models, quotas, WAL/backup/preflight policy |
| Server | mới `server/src/v2/{auth,repo,capabilities,leases,uploads,keys,signatures,recovery,audit}.rs` | Tenant-aware repository, canonical/noncanonical parser, exact signed-container/all-column equality verification—including HPKE bytes—before auth/key release, byte-identical commit request/receipt replay, tenant/profile transition proofs, same-transaction capability/audit và durable transfer boundary |
| Server | `server/src/routes/mod.rs`, `main.rs`, `blob.rs`, `server/openapi.yaml` | Mount `/v2`, stable error/OpenAPI contract, fsync/content-addressing, range/resume, exhaustive reconciliation/GC readiness gate |
| Server tests | `server/tests/e2e_sync.rs` giữ regression; mới `e2e_sync_v2.rs`, `migration_v2.rs` | Tenant/fence/idempotency/resume, exact claim-column tamper, byte-identical manifest replay, full DB×object×receipt recovery và multi-tenant/multi-profile transition matrix |
| Launcher | `src-tauri/Cargo.toml` | Depend `shardx-core` path và credential/SQLite features được chọn |
| Launcher | `src-tauri/src/store.rs` | Team paths, local filesystem checks, backup paths |
| Launcher | `src-tauri/src/profile.rs`, `launch.rs`, `api.rs` | Common team guard, claim/restore integration, local-only bypass |
| Launcher | mới `src-tauri/src/team/{db,client,keys,signing,sync,restore,downgrade,commands}.rs` | Executable DDL/eleven workflow probes, exact signed authorization cache + HPKE equality, durable signed-manifest/commit-request replay, operation/upload instance+epoch bindings, over-i64 rejection, exact receipt bindings, pinned server/tenant/profile head/epoch-transition proof state, Team/downgrade state machines và Tauri commands |
| Launcher | `src-tauri/src/lib.rs` | Register internal Team commands; không thay MCP registration |
| UI | mới `src/team/*`, tích hợp mỏng `src/App.tsx` | Team/Fleet pages, state badges, recovery/conflict UX |
| UI tests | `tests/e2e/app.spec.ts` và fixture/helper mới | Local-only + Team workflow UI regression |
| MCP contract | `mcp/contract.test.js`, mới `mcp/fixtures/v0.1.28-tools.json` + fixture hash metadata | Deep-compare đủ 96 names/descriptions/annotations/input schemas; không chỉ count/subset |
| CI/release | `.github/workflows/ci.yml`, release workflow, audit config | Server/shared/migration/security/contract gates; không publish tự động nếu gate thiếu |
| Docs | `docs/team-server.md`, `docs/snapshot-safety.md`, runbook mới | V2 protocol, key recovery, migration/rollback, threat model |

---

## 16. Dependency notes

Mọi dependency mới phải pass **G2 spike lane** bằng dependency-expert/research + durability/security review, pin version và kiểm tra license/advisory/MSRV trước production implementation. Candidate dưới đây là provisional; production executor không có authority chọn package/suite trước independent verifier-confirmed G2 PASS.

- **AEAD/STREAM:** `chacha20poly1305` + `aead` RustCrypto; test vectors và final-frame behavior bắt buộc.
- **HPKE:** crate bám RFC 9180; chỉ dùng cho out-of-envelope TRK/FKEK grants, không cho snapshot DEK slots; disable suites không dùng; kiểm tra constant-time/provider và maintenance.
- **Signing:** Ed25519/audited equivalent với strict public-key/signature parsing, canonical claim vectors, key ID derivation và domain separation; không reuse encryption keys.
- **Argon2id:** tái sử dụng `argon2` nếu feature phù hợp; tách password-hash params và recovery-KDF params.
- **Credential store:** ưu tiên `keyring-core` + platform backend explicit; Windows Credential Manager là baseline runtime đầu tiên.
- **Canonical serialization:** provider thực thi every named 5.6 contract, gồm six grants, slot context/slot/intent, signed transition/Merkle proof, manifest/commit/receipt và idempotent mutation request/stored-response; field/type/bound/optionality/domain/version/hash/TBS/container preimages đã khóa và provider không được đổi.
- **Zeroization/secrecy:** dùng crate mature để giảm accidental copies/Debug; không coi zeroize là bảo vệ khỏi compromised process.
- **Streaming HTTP:** ưu tiên Axum/Reqwest/Tokio hiện có; không thêm tus protocol dependency nếu bounded custom offset protocol đủ và test được.
- **SQLite:** giữ `sqlx` server và `rusqlite` launcher/shared hiện có; không thêm ORM/DB mới.
- **Durability/path:** prove Windows file flush + parent-directory durability adapter, atomic rename semantics và Unicode/case-fold collision policy; nếu cần crate mới phải cùng license/MSRV/security gate, không đoán bằng Unix-only behavior.

---

## 17. Test strategy và release gates

### 17.1. Test pyramid

**Unit/property**

- Exact 64-byte preamble plus closed-map `DekSlotContextV2`/`DekSlotV2`/`EnvelopeIntentV2`: golden bytes/domain hashes, field/type/bound/optionality rejects, no cycle, slot→intent order, snapshot/replay equality, frame AAD/final/counter/trailing behavior.
- Per-record codec matrix for every named 5.6 contract: golden canonical encode→decode→re-encode byte equality; reject unsorted/duplicate/unknown/indefinite/overlong/null/optional/domain/version/type/bound and hash/TBS/core/full-byte mismatch.
- Six authorization/key-grant all-column matrices including `TenantRootKeyGrantV2`: pin RFC 9180 base mode tuple `(mode,KEM,KDF,AEAD)=(0,0x0020,0x0001,0x0003)`, exact non-empty AAD preimage, raw 32-byte TRK plaintext, deterministic `root_key_id` preimage/output, `ROOT_GRANT_CREATE` exact request/stored response and readback by `replay_id`; wrong bootstrap variant/second self-grant/root generation/previous-root pair/issuer/subject/context/instance/epoch or any HPKE suite/info/AAD/recipient/encapped/wrapped byte fails before mutation/unwrap.
- Exact transition/Merkle vectors: n=1/2/3, sorted unique leaves, binary/unary domain separation, direction codec and proof shape; empty/duplicate/reordered/cross-tenant/missing-or-extra-step reject before unquarantine.
- Exact idempotency vectors for publish-create/checkout/create-upload/finalize/release/unbind: response loss returns identical stored bytes; checkout/publish never mint second lease/fence/profile; same key alternate bytes reject.
- Exact idempotency/golden-response vectors for `ROOT_GENERATION_CREATE`, `ROOT_GRANT_CREATE`, `ROOT_GRANT_ACK`, `ROOT_GENERATION_ACTIVATE` and `ROOT_GRANT_REVOKE`: assert request/response domain, `response_record_type`, all closed fields, same-transaction side effects/audit/stored bytes and byte-identical response-loss replay without duplicate generation/grant/ack/activation/revocation.
- `CommitRequestV2` core/internal hash/full exact bytes và embedded signed-manifest container equality; `CommitReceiptBindingV2` exact request/snapshot/version/head/lease-release/instance/epoch equality. Semantically equal alternate encodings never qualify as idempotent replay.
- Unsigned wire integer boundary matrix cho mọi SQLite-backed class: canonical `0`/`i64::MAX` accept; negative, `i64::MAX+1`, `u64::MAX`, overlong CBOR và coercion/wrap fixtures reject trước SQL bind với stable error.
- KDF params, HPKE/wrap unwrap, wrong key/passphrase, recovery fingerprint; prove signing and HPKE keys/references never alias.
- One-current-lease/server-now renew/expiry, fence overflow, canonical operation scope/hash và retention-aware idempotency GC.
- Strict-v2 archive unsupported entry, duplicate normalized path, case-fold collision, ADS/reserved, file/dir/ancestor conflict; giữ full v1 validator regression.

**Integration**

- Local SQLite DDL eleven close/reopen probes plus server fresh/upgrade migration probes: snapshot/replay columns+UNIQUE+composite FK, instance-keyed root/fleet generations, six grant equality maps, exact mutation replay/no-duplicate-resource, manifest/receipt replay, transition proof vectors, unknown schema/journals and over-i64 rejection.
- External restore-epoch authority integration table: corrupt/missing/behind external record, external-ahead with/without exact preparation+transition evidence, crash before/after each file/parent fsync/replace/DB install/mirror CAS, and invariant that DB mirror never raises or lowers authority.
- Server tenant/fleet ACL with same UUID and same username across tenants.
- PATCH file-tail vs committed-offset recovery; finalize rename/file+parent fsync; exhaustive `OPEN`/`FINALIZING`/`READY`/`COMMITTED`/`QUARANTINED` × staging/immutable validity × receipt matrix; zero `FINALIZING` readiness; response-loss exact receipt; hash/digest/offset mismatch và range download.
- Credential store unavailable/locked/fallback/restart.
- Restore journal phase-by-phase process kill and disk-full injection.
- Capability + audit + exact stored response same-transaction rollback for publish/checkout/release/approve/root+fleet grant/revoke/rotate/recovery/force-expire; all six grant paths verify exact containers/all columns before action.
- Trust matrix tests: read/tamper artifact DB/blob/backup cannot reveal plaintext and artifact substitution is detected; tests/docs must not claim protection from malicious rollback of trusted live RBAC/session/revocation/lease/generation state in the same epoch.

**E2E**

- Two-device disposable fleet happy path.
- Network partition/response loss after each publish/checkout/create-upload/finalize/commit/release/unbind transaction; exact replay and no duplicate profile/lease/fence/upload/version/tombstone.
- Browser-already-running warning vs no start/relaunch/commit after expiry; no client-time or grace bypass.
- Key rotation/revoke/recovery across old/new snapshot generations; membership/grant changes không rewrite retained one-slot envelopes.
- Cross-machine reseal cookies/login/web data on disposable accounts/profile.
- Local-only launcher/API/MCP regression.
- Safe unbind receipt tombstone; clone downgrade move original metadata+user-data khỏi toàn bộ v0.1.28 discovery paths + new local ID; separate full pre-v2 config/profile/user-data restore; two-tenant/colliding-profile and one-tenant/multi-profile valid/invalid/replayed/missing-proof/cross-tenant root-signed epoch-transition quarantine matrix.

**Fuzz/security**

- Envelope/header/slot/signature/archive parser fuzz plus structured mutations for all named 5.6 records in the codec matrix; path traversal/Windows reserved/ADS/case-fold/file-dir/symlink corpus.
- Auth/tenant IDOR, token version/revocation, upload quota/rate limit.
- Secret canary scan across process logs, DB, blobs, temp/spool, crash dump fixtures và CI artifacts.
- Dependency audit, `cargo fmt`, `clippy -D warnings`, tests, frontend lint/typecheck/build/E2E; Windows Team runtime + macOS/Linux local-only feature-gate builds.

### 17.2. Gate matrix

| Gate | Bằng chứng bắt buộc | Stop nếu fail |
|---|---|---|
| G0 Baseline | Clean status; v0.1.28 build/tests; canonical full 96-descriptor fixture + SHA-256; complete backup paths | Có unrelated changes hoặc baseline/fixture fail |
| G1 Architecture | Architect re-approves C6.1–C6.7 plus prior findings: exact slot/intent/transition/proof fields/preimages; exact root grant lifecycle and golden-ready HPKE/idempotency; exact mutation stored responses; minimal trusted-control-plane model; manifest/replay + executable instance-keyed generation relations; prior hash/i64/epoch/handoff invariants remain. Critic approve **after** that creates consensus | Placeholder/underspecified bytes, trust contradiction, second lease/fence replay, root grant gap, snapshot/replay/generation schema drift, Hash32 regression, or any path to G2 before ordered approvals |
| G2 Spike lane | Only after durable ordered Architect+Critic approval: official golden vectors for all named 5.6 contracts; six grant all-column/HPKE matrices; response-loss/no-second-resource; local DDL + server migration probes; trust matrix; over-i64/external epoch/STREAM/Windows durability/dependency evidence; independent verifier artifact SHA-256 + verdict | Any row unproved or verifier non-PASS => G2 FAIL/BLOCKED; goal stop, no production executor/v0.2.0 |
| G3 Migration/downgrade | Fresh + upgrade v0.1.28 schema parity probes; unbind tombstone; discovery-safe clone/full restore; external epoch reconciliation; exact tenant transition/proofs; explicit trusted-control-plane rollback limitation | Missing snapshot/replay UNIQUE/FK, cross-instance generation reference, partial restore, invalid proof, or claim that same-epoch malicious RBAC rollback is covered |
| G4 Shared/restore | Intent→one-slot→ciphertext→durably persisted exact signed-manifest/commit-request direction; all named 5.6 canonical codecs; strict archive; signed-chain/tenant transition proofs; bounded memory; canary/fuzz/crash/reseal/smoke/rollback | Commitment cycle, per-device envelope slots, any noncanonical acceptance, exact bytes regenerated after restart, plaintext leak, signature/parser gap, OOM hoặc half-swap |
| G5 Server sync | Six exact grant schemas/equality; atomic publish initial lease; checkout/create/finalize/release response replay; snapshot/replay FK parity; instance-keyed generations; current lease/server time; upload recovery + exact commit receipt | Any second resource/fence on replay, root self-grant/rotation gap, schema mismatch, cross-tenant/capability bypass, stale commit or artifact mismatch |
| G6 Launcher/UI | Windows Team E2E; executable local eleven probes; exact unbind/release/publish/checkout replay; root/fleet cache equality; snapshot/replay/instance bindings; exact transition proofs; over-i64/local-only/MCP/downgrade/accessibility | Local/MCP drift, duplicate mutation side effect, uncovered proof, instance/replay mismatch, over-i64 acceptance or unproven platform enabled |
| G7 Independent verify | Verifier reruns commands from clean checkout/artifacts; disposable two-device drill; fresh per-record canonical/noncanonical, each-column/HPKE mismatch, operation/upload instance+epoch mismatch, over-i64 boundary, external epoch crash-order, server+local close/reopen request/receipt và multi-tenant/multi-profile probes | Evidence không reproducible hoặc chỉ in-memory/single-record/single-tenant/single-profile proof; external authority/file fsync path chưa được readback |

**Implementation definition of done:** G0–G7 đều pass bằng fresh reproducible evidence. `H0` là evidence handoff packet (diff inventory, requirement→test map, risk register, rollback artifacts và gate logs), không phải gate thứ tám và không thay đổi trạng thái implementation completion.

**Production operator gate — tách khỏi G0–G7**

| Gate | Bằng chứng bắt buộc | Trạng thái khi blocked |
|---|---|---|
| `P-OP` Production operator | Named operator nhận runbook và verifier xác nhận fresh server + Launcher backup, safe downgrade/rollback, recovery-bundle readback và artifact SHA-256 trên disposable/internal environment | Implementation có thể complete nhưng artifact phải gắn **non-production-ready**; cấm production-ready/release-ready claim, tag, publish, release và production migration |

### 17.3. Release stop rules

- Execution goal dừng sau khi G0–G7 pass và `H0` evidence packet được lập; không commit/push/tag/publish/release nếu chưa có yêu cầu riêng, dù implementation đã complete.
- Trước durable Architect+Critic consensus không chạy G2; trước independent verifier-confirmed G2 `PASS` chỉ bounded spike artifacts được tạo, không production implementation/production executor và không chọn primitive ngoài spike decision record. G2 fail/blocked hoặc verifier không PASS bắt buộc goal stop.
- Không dùng canonical profile hoặc production server/account để destructive restore/migration/security test.
- Không release nếu legacy plaintext còn tồn tại mà instance không ở quarantine/local-only mode được ghi rõ.
- Không release nếu bất kỳ field nào trong canonical 96-tool descriptor fixture (name/description/annotations/inputSchema) hoặc fixture SHA-256 khác baseline chưa được phê duyệt.
- Không production release v0.2.0; nó chỉ là internal foundation. macOS/Linux Team runtime vẫn disabled/local-only tới credential-store/platform gates.
- Khi `P-OP` blocked: bắt buộc label **non-production-ready**, không claim production-ready/release-ready, không tag/publish/release/production migration. Production-ready chỉ khi G0–G7 và `P-OP` đều pass; mọi release vẫn cần yêu cầu riêng.
- Không release nếu all named 5.6 canonical roundtrip/noncanonical matrices, six authorization/key-grant equality maps gồm HPKE bytes, eleven workflow DDL probes, operation/upload instance+epoch mismatch, over-i64 rejects, external epoch authority crash-order table, server/local close-reopen exact commit request/receipt replay, recovery matrix, downgrade discovery scan hoặc multi-tenant/multi-profile `RestoreEpochTransitionV2` proof/rejection tests chưa pass với fresh artifacts.
- Không “waive” tenant isolation, stale-writer hoặc recovery/rollback test bằng manual claim.
- Không claim chống active malicious coordinator equivocation/DoS; không thêm transparency/consensus/CRDT để “sửa nhanh” scope này.

---

## 18. Assumptions và quyết định còn mở

### 18.1. Assumptions được dùng trong draft

- Baseline hiện hành là v0.1.28 theo evidence người dùng; handoff ghi v0.1.27 là stale ở phần version.
- V0.2.x nhắm self-hosted, single-region, local filesystem server trước; không object storage/network filesystem.
- Remote traffic đi qua HTTPS; HTTP chỉ loopback development.
- Profile name/notes/config/proxy/cookies là sensitive và được mã hóa; server list có thể dùng opaque/local alias.
- Default retention tiếp tục 5 snapshots; default server cap tạm giữ 512 MiB cho pilot cho tới khi performance test biện minh tăng.
- Browser đang chạy không bị kill ngay khi lease renew fail; sau expiry dữ liệu trở thành offline fork và không được commit đè.
- V1 legacy data không tự migrate hoặc tự scrub.
- Coordinator process + live coordination/RBAC SQLite integrity/freshness là trusted control plane; artifact ciphertext/signed bytes trong DB/blob/log/backup không trusted cho confidentiality/artifact integrity. Same-epoch control-plane DB compromise/rollback ngoài guarantee; external epoch record không phải auth transparency. Không thêm signed auth transparency/consensus trong v0.2.x.
- Team runtime đầu tiên là Windows; macOS/Linux giữ local-only tới khi credential-store/platform evidence pass.
- Snapshot key model là một DEK slot dưới immutable FKEK generation; device HPKE FKEK grants là signed records ngoài envelope. Đây là contract đã chốt, không còn là dependency choice.
- Epoch/head rollback quarantine chỉ được gỡ per binding bằng valid same-tenant root-signed `RestoreEpochTransitionV2` trên server-global epoch + inclusion proof cho exact previous/new signed head; downgrade clone và full pre-v2 restore là hai workflow riêng.
- Exact authorization payload/container bytes/signatures and indexed columns are a dual representation with mandatory equality verification, not two authorities. Exact `SignedSnapshotManifestV2`/`CommitRequestV2`/`CommitReceiptBindingV2` bytes + internal/full hashes are durable replay artifacts, not values regenerated from columns after restart.
- External checksummed/fsync'd `server_instance_id + restore_epoch` record ngoài SQLite rollback scope là server authority; server/local SQLite values chỉ mirror/cache. Mọi current SQLite-backed unsigned wire integer bị giới hạn `0..i64::MAX` ở decoder + DDL.
- Exact root grant, mutation idempotency, slot/intent/transition/proof và manifest/replay schema contracts ở 5.6/7 đã chốt; root/fleet generation keys luôn gồm `server_instance_id`.

### 18.2. Hard gates còn mở sau design consensus

| Hard gate | Trạng thái/default | Điều kiện đóng |
|---|---|---|
| G2 dependency/security/durability spike | Architect `APPROVE` + Critic `APPROVE` đã persist thành durable consensus; G2 **chưa chạy**. Candidate providers implement fixed 5.6 contracts; **không production implementation trước independent verifier PASS** | Golden bytes/hashes for all named contracts; six grant equality maps; response-loss/no-second-resource; local eleven + server migration probes; snapshot/replay/generation FK parity; trust matrix; over-i64/external epoch/Windows durability/dependency evidence reproducible + hashed. Fail/blocked/verifier non-PASS => goal stop |
| `P-OP` production operator assignment | **Blocked**; tách khỏi G0–G7, v0.2.0 internal-only và các phase sau disposable/internal canary | Named operator nhận runbook và verifier xác nhận fresh server + Launcher backup, safe downgrade/rollback và recovery-bundle readback drill với artifact hashes; tới lúc đó label **non-production-ready** |

Các quyết định exact 5.6 contracts, six grant/root lifecycle, atomic mutation idempotency, minimal trust model, manifest/replay + instance-keyed generation schema, local eleven/server migration probes, external epoch/i64/recovery/downgrade/privacy/quota/lease/handoff và DoD split đã chốt ở plan level; xem `.omx/plans/open-questions.md`. Durable Architect→Critic consensus đã hoàn tất; chỉ G2 và `P-OP` còn mở.

---

## 19. Goal prompt end-to-end cho agent triển khai sau này

```text
Bạn là goal coordinator cho ShardBrowser v0.2.x Team/Fleet Sync và Encrypted Profile Backup. Bạn không có execution authority cho tới khi durable Architect+Critic consensus record hoàn chỉnh. Khi đó bạn chỉ được coordinate bounded G2 spike; production implementation authority chỉ mở sau independent verifier readback và verdict G2 PASS.

Workspace:
C:\Users\Administrator\Documents\GitHub\ShardBrowser

Source plan bắt buộc:
.omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md
.omx/plans/open-questions.md

Mục tiêu và authority boundary:
1. Architect `APPROVE` và Critic `APPROVE` cho revision v6.1 đã được persist đúng thứ tự thành durable design consensus. Trước khi chạy, readback exact plan/open-question/review hashes; sau đó coordinate bounded research/dependency/durability lane để thực hiện G2.
2. Goal có thể staff researcher/dependency-expert/durability-test cho bounded G2. Chỉ sau khi spike evidence packet đóng mới staff independent verifier để readback; verifier không đồng tác giả evidence mình phê duyệt. Không giao production executor quyền chọn primitive hoặc viết production implementation trước verifier PASS.
3. Nếu bất kỳ G2 row fail/blocked hoặc verifier không PASS, stop goal tại spike evidence packet, ghi blocker và không mở v0.2.0. Chỉ sau verifier readback commands/fixtures/versions/SHA-256 và xác nhận G2 PASS mới triển khai v0.2.0 -> v0.2.1 -> v0.2.2.
4. V0.2.0 là internal foundation, không production release. Team runtime đầu tiên chỉ là Windows; macOS/Linux giữ local-only cho tới khi credential-store/platform gates pass. Giữ local profile JSON/user-data là source of truth và giữ nguyên full v0.1.28 96-tool MCP contract.

Trust model bắt buộc:
1. Coordinator process + integrity/freshness của live coordination/RBAC SQLite là trusted control plane cho authenticated context, roles/capabilities, sessions/revocation, active generations, leases/fences, idempotency, server time và audit ordering.
2. Ciphertext/signed artifact bytes trong DB/blob/log/backup không trusted cho confidentiality/artifact integrity; clients verify encryption, exact containers/equality, hashes và pinned heads. Backup read/tamper không tự cấp authorization.
3. Malicious coordinator hoặc write/rollback compromise của live control-plane DB có thể re-enable revoked principals, chọn generation cũ, mint leases/fences, suppress audit hoặc equivocate. Đây là explicit out-of-guarantee boundary. External epoch record chỉ covers authorized full restore, không same-epoch selective RBAC rollback; không thêm signed auth transparency/distributed consensus.

Security/authenticity invariants:
1. Mỗi device có signing key và HPKE recipient key riêng, mỗi key có immutable key_id và proof-of-possession. Không reuse TRK/FKEK/DEK làm signing keys.
2. Implement exact six authorization/key-grant contracts in 5.6.1/5.6.4. `TenantRootKeyGrantV2` pins RFC 9180 base mode tuple `(0,0x0020,0x0001,0x0003)`, exact canonical `info`, exact non-empty domain-separated AAD, raw 32-byte TRK plaintext, deterministic `root_key_id` derivation, one-time `FirstRootSelfGrant`, exact idempotent `ROOT_GRANT_CREATE` request/stored response, deterministic readback by `replay_id`, existing/rotation issuer rules, revoke/ack/activation and every-column equality. Second self-grant, cross-instance generation or any HPKE/container mismatch fails before unwrap/mutation.
3. Implement exact closed-map `DekSlotContextV2`/`DekSlotV2`/`EnvelopeIntentV2` in 5.6.3 with fixed types/bounds/optionality/domain hashes and build order. Intent contains preallocated snapshot/replay IDs but no actual ciphertext/content/final-manifest commitment. Every frame AAD binds exact `intent_hash`.
4. Chỉ sau encrypt mới tạo exact `SnapshotManifestV2` payload và exact `SignedSnapshotManifestV2` outer container theo 5.6.2. Build exact `CommitRequestV2` nhúng byte-identical container bytes/hash; commit returns exact `CommitReceiptBindingV2`. Server/local persist internal hashes + exact full bytes hashes. Key substitution, invalid signature, payload/container/request/receipt mismatch hoặc rollback/divergence so với pinned state => quarantine.
5. Tenant RBAC deny-by-default gồm owner/admin/member + explicit capabilities. root.custody là capability riêng; ordinary fleet devices không nhận TRK.
6. Exact signed `RestoreEpochTransitionV2` and `RestoreEpochInclusionProofV2` follow 5.6.3: codec `PROFILE_HEAD_SET_MERKLE_V2`, non-empty sorted unique leaves, exact leaf/binary/unary domains and numeric direction codec. n=1/2/3 golden vectors pass; empty/duplicate/reordered/wrong-shape/cross-tenant proof rejects before unquarantine.
7. Authority cho `server_instance_id + restore_epoch` là checksummed/fsync'd external identity record ngoài SQLite DB/blob rollback scope; `v2_server_state` và local `server_origins.last_restore_epoch` chỉ mirror/cache. Missing/corrupt/behind record fail closed; external-ahead legitimate restore chỉ reconcile bằng exact fsync'd preparation bundle + same-tenant signed transitions/proofs. Không lower/rebuild external authority từ SQLite.
8. Mọi unsigned wire integer được persist/mirror trong SQLite, gồm fence/version/offset/size/epoch/timestamps, accept đúng `0..i64::MAX`; decoder + DDL reject `i64::MAX+1`, `u64::MAX`, negative, noncanonical và coercion trước mutation. Future full-U64 phải có versioned BLOB/text encoding riêng.
9. Publish-create/checkout/create-upload/finalize/release and local unbind use exact 5.6.5 request/stored-response bytes; commit uses 5.6.2. Mutation + exact response + audit/tombstone commit atomically. Any response-loss retry returns stored bytes and cannot mint a second profile/lease/fence/upload/promotion/delete. Approve/root+fleet grant/revoke/rotate/recovery/force-expire follow same audit rollback rule.

Sync/data invariants:
1. Không multi-writer, CRDT, silent overwrite hoặc forced remote overwrite mặc định.
2. Server model chỉ có một current lease row per profile. Profile publish-create atomically creates version 0 + initial lease/fence. Checkout allocates lease/fence once with exact stored response; same-key retry—even after expiry—returns original receipt and never increments fence. A new checkout requires reconcile + new key.
3. Browser đã chạy có thể tiếp tục với warning khi mất renew. Sau expiry: offline_fork; cấm start/relaunch, checkout-derived restore mới và remote commit.
4. Commit CAS cùng transaction phải check role/capability, active session/device/full signed FKEK grant bytes, exact current lease owner, expires_at > server_now, current fence, exact base_version, READY object hash/size, post-encryption signed manifest, immutable ACTIVE FKEK generation và canonical idempotency match.
5. Commit idempotency request/receipt giữ ít nhất lâu bằng snapshot retention liên quan. operation_scope + canonical request hash immutable. Duplicate chunk cần explicit persisted digest; offset mismatch luôn HEAD/resume.
6. `snapshot_id` and `manifest_replay_id` are preallocated, stored in upload and snapshot, unique per instance/tenant/profile and linked by composite FK through upload ID. Root/fleet key-generation PK/FK always include `server_instance_id`; no current-instance implicit lookup.

Crypto/envelope/archive invariants:
1. Sau durable Architect→Critic consensus, chạy G2 spike trước production implementation. G2 phải prove provider thực thi nguyên vẹn fixed wire schemas/hash preimages ở 5.6 cùng primitive/nonce/HPKE/signature/KDF vectors, final-frame semantics, MSRV, license, maintenance và advisories. Fail/blocked hoặc verifier non-PASS => stop goal; không production fallback.
2. Sau independent verifier-confirmed G2 PASS, implement exact strict envelope v2 grammar trong source plan: immutable 64-byte preamble; bounded canonical `EnvelopeIntentV2`; exactly one canonical `DekSlotV2` under immutable FKEK generation; one-or-more counters; exactly one final frame; detached exact `SignedSnapshotManifestV2` after encryption.
3. Prove acyclic dependency `DekSlotV2 -> EnvelopeIntentV2/intent_hash -> ciphertext -> SnapshotManifestV2`. Reject intent/header containing ciphertext or final-manifest commitment and reject per-device/multiple envelope slots.
4. Reject unknown/noncanonical fields, wrong bounds/optional pairs/domain/preimage, trailing/zero/final/counter errors and all equality mismatches. Pin golden exact bytes/SHA-256 for every named 5.6 contract; G2 chooses only provider/suite IDs and suite-specific lengths within fixed bounds.
5. Strict v2 archive validator fail trước swap trên unsupported entry, duplicate normalized path, Windows case-fold collision, ADS/reserved/traversal/root, file-dir và ancestor conflicts. Preserve v1 pack/unpack behavior/tests unchanged.
6. Key generations là PREPARING -> ACTIVE -> RETIRED. Chỉ activate sau recovery grant và every required-device signed FKEK grant exact-byte readback/ack. Revoke + new-generation activation là one logical audited transaction.

Crash-consistency invariants:
1. PATCH exact committed offset -> write encrypted staging -> sync_data/Windows flush -> DB CAS insert chunk digest + advance offset. Restart truncates file tail longer than DB offset; file shorter/missing/digest mismatch => QUARANTINED.
2. Finalize stream-recomputes ciphertext hash/size -> rename immutable content-addressed object -> fsync file + parent directory/durable Windows equivalent -> persist READY.
3. Commit transaction verifies exact `SignedSnapshotManifestV2` outer bytes/internal+full hashes and exact `CommitRequestV2` bytes/canonical+full hashes; inserts signed snapshot/head, advances version, releases lease, persists exact `CommitReceiptBindingV2` bytes/hash + audit. DB failure leaves unreferenced immutable ciphertext for fail-closed retry/reconciliation/GC; never auto-advance profile.
4. Before finalize/commit, persist exact signed-manifest container and exact commit-request artifacts in the local COMMIT operation row, bound to idempotency/upload/lease/fence/base/intent/ciphertext/instance/epoch columns. After local/server close/reopen, send byte-identical stored request and replay byte-identical stored receipt binding or fail closed; never regenerate either from indexed columns.
5. Local `operations` và `upload_sessions` persist `server_instance_id` + `restore_epoch`; composite FK chặn cross-instance/epoch association, còn exact stored request/container bytes vẫn là replay authority. Parse/reject any relational mismatch before network send/commit.
6. Implement exhaustive deterministic recovery matrix for DB `OPEN`/`FINALIZING`/`READY`/`COMMITTED`/`QUARANTINED` × staging/immutable absent/valid/invalid × receipt absent/valid/invalid. Every successful readiness pass leaves zero `FINALIZING`; short/corrupt/mismatched committed evidence quarantines and is never silent GC.
7. Server restore ordering bắt buộc: fsync restored DB candidate + tenant transition/proof set + external preparation manifest; atomically replace/fsync external epoch authority; install candidate; open read-only; verify exact hashes/proofs; transactionally rebuild SQLite mirror; readback rồi mới enable writes. Mọi crash row trong mục 12.4 fail closed hoặc deterministic resume, không lower authority.
8. Inject crash before/after write, file flush, offset DB update, hash, rename, file fsync, parent fsync, READY CAS, before commit request, after request before response, after response before local receipt commit, DB commit, every upload reconciliation CAS/cleanup và every external epoch preparation/replace/install/mirror-reconcile point.
9. Restore stop/claim profile, resume ciphertext + detached manifest, verify signed FKEK grant/head/tenant epoch proof + strict intent/one-slot envelope, decrypt into strict-v2 validated staging, reseal destination, atomic swap, restricted smoke and rollback metadata+user-data via durable journal.

Migration/downgrade invariants:
1. Không migrate toàn bộ local JSON. Run executable local DDL + eleven close/reopen probes and fresh/upgrade server migration probes in 12.1. Assert upload/snapshot snapshot+replay columns, exact UNIQUE/FK tuples, instance-keyed root/fleet generations, response-loss/no-second-resource, six grant equality, exact Merkle directions, unknown schema/journals and over-i64 rejects.
2. Track/pin exact external authority server_instance_id/restore_epoch, SQLite mirrors, operation/upload replay bindings, tenant-scoped root-signed epoch transition/proofs và per-binding signed head. Authority/mirror mismatch, epoch rollback/change thiếu valid same-tenant transition + exact profile proof hoặc non-descendant head => quarantine/no auto-push; missing/corrupt/behind external record disable all v2 writes.
3. Không bao giờ cho rằng v0.1.28 có thể ignore Team DB. Downgrade chỉ khi no running browser/current lease/pending operation/spool hoặc unstable restore/downgrade journal.
4. Downgrade clone phải durable-move original profile metadata + user-data khỏi mọi v0.1.28 discovery path, fsync/readback, rồi tạo clone bằng new local profile ID không Team marker/credential/remote lineage. Không giữ original quarantined in place.
5. Complete pre-v2 restore là path riêng: restore cùng backup epoch cho config/settings + profiles JSON + full user-data; sau readback mới archive/retire Team credential/DB/spool artifacts. Không trộn với clone hoặc partial restore.
6. Legacy v1 plaintext stays quarantined/remote-off; no automatic migration/scrub.

Compatibility/secrecy invariants:
1. Capture canonical baseline fixture mcp/fixtures/v0.1.28-tools.json từ fresh tools/list và deep-compare đủ 96 name, description, annotations và full inputSchema + fixture SHA-256. Count/subset test không đủ.
2. V0.1.28 local-only create/edit/start/stop/delete, startup-in-tray, automation và MCP behavior không đổi.
3. Không log/fixture/chat token, cookies, proxy credentials, key bytes, passphrase, profile payload, raw grant body hoặc full fingerprint.

Execution order bắt buộc:
A. Preflight read-only/G0: đọc AGENTS.md, docs/CODEX_SHARDX_HANDOFF.md, source plan, repo status, current tests/workflows và xác minh baseline v0.1.28. Không đụng canonical profile cho destructive tests.
B. G1 durable consensus: Architect accept revision này; chỉ sau accept mới Critic review/approve. Persist both approving verdicts đúng Architect→Critic và set consensus complete; thiếu/sai thứ tự/non-approve thì dừng. Ghi ADR delta nếu evidence buộc đổi contract; không tự hạ trust/RBAC/fixed schemas/equality/one-slot/replay/tenant-proof/recovery/downgrade invariant.
C. G2 bounded spike lane: chỉ sau durable consensus, prove all named 5.6 golden vectors, root/fleet HPKE/provider semantics, mutation response-loss/no-second-resource, local eleven + server migration probes, trust matrix, over-i64/external epoch/Windows durability/path/dependency evidence. Không production executor/code authority. Any fail/blocked => evidence + **stop goal**.
D. Verifier gate: independent verifier readback G2 commands/fixtures/versions/SHA-256 và phát PASS/FAIL/BLOCKED; ADR pin exact suite/provider IDs và implementation constraints. Chỉ verifier `PASS` mới mở production implementation staffing; FAIL/BLOCKED kết thúc goal.
E. V0.2.0 internal foundation: exact 5.6 codecs, trusted-control-plane boundary, instance-keyed root/fleet generations, snapshot/replay schema, constrained local DB/spool/journals and additive server skeleton. No production release.
F. V0.2.1 Windows internal pilot: six exact grants/root lifecycle, atomic publish+checkout idempotency, tenant repository, one-current-lease/server time, durable upload/response replay + exhaustive reconciliation, launcher/common guard and Team UI.
G. V0.2.2 hardening: PREPARING/ACTIVE/RETIRED rotation/revoke/recovery, tenant-scoped multi-profile root-signed epoch transitions/proofs, discovery-safe downgrade clone/separate full restore, quotas/observability/GC, optional explicit legacy assistant, fuzz/crash/soak/security hardening.
H. Independent verification: verifier reruns every gate from clean evidence path on disposable two-device Windows fleet; macOS/Linux verify local-only gates.

Implementation constraints:
- Giữ diff nhỏ theo phase; reuse existing validators/claims/atomic swap helpers; không thêm abstraction/dependency nếu existing/native đủ.
- V1 tests phải tiếp tục pass. V2 routes/schema additive; raw route SQL không được bypass tenant-aware repository.
- Bounded memory; không materialize whole plaintext archive hoặc whole ciphertext upload trong Vec.
- Encrypted spool only; plaintext chỉ tồn tại trong live process/validated destination staging với restrictive permissions và journal cleanup.
- Remote non-loopback HTTP fail closed.
- Tất cả log/audit/error dùng allowlist structured fields và stable safe error codes.
- Không thêm transparency service, distributed consensus hoặc CRDT.

Required evidence per phase:
- File/diff inventory và mapping requirement -> implementation -> test.
- cargo fmt, clippy -D warnings, unit/integration/E2E; frontend lint/typecheck/build/Playwright phù hợp.
- Fresh/upgrade-from-v0.1.28/rollback migration evidence with executable snapshot/replay UNIQUE/FK + instance-generation probes, backup SHA-256, integrity_check and foreign_key_check.
- Full 96 MCP descriptor fixture deep comparison + SHA-256.
- Tenant same-UUID + capability denial tests; current-row/server-time/stale fence/base/idempotency-retention/chunk-digest concurrency tests.
- Golden exact bytes/hashes for all named 5.6 contracts; six grant all-column/HPKE matrices; root bootstrap/rotation/revoke/readback; n=1/2/3 Merkle direction vectors; key substitution/rollback/replay rejects before mutation/unwrap.
- Exact envelope grammar vectors including no commitment cycle, exactly one FKEK-wrapped DEK slot, intent-hash frame AAD, canonical/trailing/zero/repeated-final/counter cases; strict-v2 archive collision corpus while v1 behavior remains stable.
- PATCH/finalize/fsync exhaustive DB×staging×immutable×hash×receipt recovery crash matrix, zero lingering `FINALIZING`, server+local close/reopen byte-identical `CommitRequestV2` replay at three request/response crash points và byte-identical `CommitReceiptBindingV2` after response loss.
- Local eleven probes + server migration probes; exact publish/checkout/create/finalize/release/unbind response-loss replay with no duplicate side effect; snapshot/replay/instance/generation mismatch; exact request/receipt replay; transition shape/cross-tenant rejects; unknown schema/journals and integer boundaries.
- External epoch authority evidence: exact record/preparation/candidate/transition SHA-256, file+parent fsync commands, and every crash-order table row including missing/corrupt/behind/ahead-without-proof fail-closed readback.
- Bounded peak-memory proof trên profile fixture lớn.
- Crash injection ở từng restore phase; old-good/new-good invariant; cross-machine reseal và restricted smoke.
- PREPARING/ACTIVE/RETIRED canonical-grant readback and lost-device/recovery/revoke+activate drill trên disposable fleet.
- Safe unbind tombstone; original-out-of-discovery/new-ID clone; separate full-pre-v2 restore; server-global epoch + tenant/profile head valid/invalid/replayed/uncovered/cross-tenant transition-proof quarantine drill.
- Windows Team runtime evidence; macOS/Linux local-only/disabled Team evidence.

Stop conditions — dừng và báo blocker, không đoán:
- Repo có unrelated dirty work không thể cô lập an toàn.
- Cần secret/credential/external-production authority chưa được cấp.
- Chỉ có canonical profile hoặc production server để chạy destructive test.
- Unknown/newer schema hoặc backup/rollback/integrity readback fail.
- Bất kỳ plaintext canary xuất hiện trong server DB/blob/log/spool/CI artifact.
- Cross-tenant/capability bypass, stale/expired commit/relaunch, duplicate version hoặc half-restored profile còn tái hiện.
- Crypto/signing/HPKE/canonical codec/Windows durability dependency không prove exact invariants.
- G2 fail/blocked hoặc verifier không readback được commands/fixtures/versions/SHA-256; dừng goal và không staff production executor.
- Durable Architect→Critic consensus record thiếu/sai thứ tự/non-approve; không chạy G2.
- Key substitution, signed-head rollback, upload tail/offset inconsistency, exact request replay mismatch hoặc server/tenant/profile epoch-proof mismatch không quarantine.
- Operation/upload instance/epoch mismatch hoặc unsigned SQLite-backed wire value ngoài `0..i64::MAX` được nhận; external epoch authority missing/corrupt/behind DB hay ahead thiếu exact preparation/transition evidence mà v2 writes vẫn mở.
- Any 5.6 field/preimage/golden drift; second root self-grant; HPKE column mismatch; response replay creates second profile/lease/fence/upload/side effect; snapshot/replay FK mismatch; cross-instance generation lookup; invalid Merkle shape; regenerated response/receipt; or recovery leaves `FINALIZING`.
- Implementation claims protection against same-epoch malicious live RBAC/control-plane DB rollback, or adds signed auth transparency outside approved scope.
- Full MCP descriptor fixture hoặc local-only behavior drift.
- Downgrade original còn trong bất kỳ v0.1.28 discovery path, clone reuse local ID/Team artifact, journal chưa stable, tenant/profile epoch transition/proof invalid/uncovered/cross-tenant hoặc chỉ có partial pre-v2 restore set.
- Một release gate fail hoặc evidence không reproducible.

Commit/release boundary:
- Không commit, push, tag, publish, tạo release hoặc chạm production trong execution goal này.
- Sau khi G0-G7 pass, implementation được xem là complete; chỉ trình bày `H0` evidence packet và dừng.
- `P-OP` là production gate riêng và có thể vẫn blocked khi implementation complete. Khi blocked, mọi artifact/evidence bắt buộc ghi **non-production-ready** và cấm production-ready/release-ready claim, tag, publish, release hoặc production migration. Production-ready chỉ khi G0-G7 + `P-OP` pass; mọi Git/release action vẫn cần yêu cầu riêng.

Definition of done cho implementation goal:
- Tất cả acceptance criteria và implementation gates G0–G7 trong source plan pass với fresh evidence.
- Không còn pending migration/recovery/security task bắt buộc trong scope v0.2.x.
- Architect/critic/verifier sign-off được ghi lại.
- Dependency/security spike đóng. `P-OP` được ghi rõ là pass hoặc blocked; blocked không làm mất implementation-complete nhưng bắt buộc **non-production-ready** và không production/release claim.
- `H0` evidence packet sẵn sàng; working tree chưa commit vì goal không có commit/release scope.
```

---

## 20. Handoff và staffing guidance

### 20.1. Available agent types

Repo catalog hiện có các lane phù hợp: `explore`, `researcher`, `dependency-expert`, `planner`, `architect`, `critic`, `executor`, `debugger`, `test-engineer`, `verifier`, `designer`, `code-reviewer`, `git-master`, `writer`. Không giả định có security specialist riêng; dùng Architect + dependency-expert + critic + verifier và công cụ audit hiện có.

### 20.2. Deliberate review trước execution — đã hoàn tất

1. **Architect (xhigh): APPROVE persisted.** C6.1–C6.7, prior Follow-ups order, Hash32 BLOB32 và epoch/i64/recovery/downgrade invariants đã được re-review.
2. **Critic (xhigh): APPROVE persisted sau Architect.** Exact bytes, HPKE/all-column root path, all root-lifecycle stored responses, response-loss/no-second-resource, trust limitation và fresh/upgrade schema probes không còn blocker trong targeted final review.
3. **G2 spike lane — dependency-expert/researcher + durability/test-engineer (high/xhigh):** chỉ sau durable consensus; official docs/vectors, canonical codec conformance, HPKE/signing/provider decision, crate health/license/MSRV/advisories, Windows credential/fsync/path, DDL instance/epoch + over-i64 probes và external epoch crash table. Đây là bounded research lane, không production implementation.
4. **Verifier (xhigh):** readback G2 commands/fixtures/versions/SHA-256 và phát verdict PASS/FAIL/BLOCKED. FAIL/BLOCKED kết thúc goal; không handoff production.
5. **Production executors:** chỉ staff sau independent verifier verdict G2 `PASS`; nhận provider/suite IDs và immutable wire contracts từ G2 ADR, không tự chọn lại primitive.

### 20.3. Đường triển khai đề xuất

- **Mặc định:** dùng `$ultragoal` cho durable follow-up **sau khi** Architect+Critic consensus được ghi nhận. Goal coordinate G2 trước; nếu G2 fail/blocked hoặc verifier không PASS thì stop và trả spike evidence packet. Chỉ verifier-confirmed G2 PASS mới cho goal mở implementation phases. Nếu Codex App không có OMX runtime trực tiếp, launch goal trong OMX CLI/tmux rồi dùng source plan này.
- **G2 staffing:** bounded spike lane gồm `researcher`, `dependency-expert`, `test-engineer`/durability owner; không dùng production `executor` để chọn primitive. Sau khi spike evidence packet đóng, một independent `verifier` lane riêng readback và phát PASS/FAIL/BLOCKED; verifier không đồng tác giả evidence mình phê duyệt.
- **Production Team path sau verifier-confirmed G2 PASS:** `$team` với tối đa 5 lane độc lập:
  1. server schema/API/migrations;
  2. shared archive/envelope/key primitives;
  3. launcher DB/client/restore/lifecycle;
  4. UI/E2E/local compatibility;
  5. independent security/test/verifier lane.
- **Integration order:** durable Architect+Critic consensus; bounded G2; independent verifier PASS + fixed-contract/provider ADR; server/shared implementations; launcher; UI; independent implementation verification. Shared-file owner phải rõ để tránh conflict.
- **Ralph fallback:** nếu team runtime không sẵn, single-owner Ralph/CLI loop chỉ chạy bounded G2 trước và phải stop khi G2 fail/blocked; sau PASS mới có loop production riêng. `$ultragoal` vẫn là follow-up bền vững ưu tiên.
- **Research-only branch:** dùng `$autoresearch-goal` cho G2 nếu crypto/dependency decision tách thành dự án nghiên cứu riêng; output vẫn phải quay về verifier verdict trước production handoff.
- **Performance-only branch:** dùng `$performance-goal` nếu bounded-memory/throughput trở thành workstream tối ưu độc lập sau khi correctness đã khóa.

### 20.4. Team verification path

- Executor không tự xác nhận security/release gate của phần mình.
- Không có production executor trước durable consensus **và** verifier-confirmed G2 PASS; spike lane không được lén mở source implementation ngoài bounded harness/artifact cần để prove G2.
- Verifier nhận clean command list, fixture IDs không secret và artifact hashes; chạy lại từ baseline.
- Architect/critic review mọi deviation khỏi ADR trước khi merge vào execution branch.
- Git/release lane không thuộc implementation goal. Chỉ staffing sau `H0`, explicit user authorization và—cho production—`P-OP` pass; trước đó không commit/push/tag/release.

---

## 21. Acceptance checklist cho Architect review

- [ ] Trust model khóa minimal repair: coordinator + live coordination/RBAC SQLite integrity/freshness là trusted control plane; ciphertext/signed artifact bytes trong DB/blob/log/backup không trusted cho confidentiality/artifact integrity; same-epoch DB rollback/compromise và active coordinator ngoài guarantee; không thêm signed auth transparency.
- [ ] Lựa chọn additive v2 + local team DB đủ cô lập v1 và có lộ trình quarantine legacy.
- [ ] Device signing/HPKE keys, PoP, OOB root bootstrap, full canonical signed FKEK grants/manifests/heads/transitions và pinned rollback detection tách khỏi TRK/FKEK/DEK.
- [ ] Sáu exact authorization/key-grant contracts gồm `TenantRootKeyGrantV2`; deterministic root HPKE info, first self-grant/rotation/revoke/readback/ack/activate endpoints và all-column equality không còn placeholder.
- [ ] Owner/admin/member + explicit capabilities/root custody deny-by-default; sensitive mutation + audit cùng transaction.
- [ ] One-current-lease-row, server-time renew/commit và no-relaunch grace chặn stale writer trong trust model.
- [ ] `DekSlotContextV2`, `DekSlotV2`, `EnvelopeIntentV2`, `RestoreEpochTransitionV2` và inclusion proof có exact closed-map field/type/bound/optionality/domain/version/hash/TBS/container contracts; deterministic leaf/binary/unary/order/duplicate/empty/direction rules golden-ready.
- [ ] Snapshot envelope có exactly one DEK slot dưới immutable FKEK generation; device HPKE grants chỉ ở ngoài envelope và server/local schema persist full canonical signed bytes + extracted-column equality checks.
- [ ] PATCH/finalize/commit/fsync + full `OPEN`/`FINALIZING`/`READY`/`COMMITTED`/`QUARANTINED` object/receipt matrix deterministic; zero lingering `FINALIZING`; committed mismatch là security incident, không GC.
- [ ] Exact 64-byte envelope grammar, intent/one-slot bindings, final/counter/trailing/canonical rejects và strict-v2 archive validator đầy đủ; v1 behavior giữ nguyên.
- [ ] Key generations `PREPARING -> ACTIVE -> RETIRED`, all-grant exact-byte readback và revoke+activate logical operation được khóa.
- [ ] Exact publish-create/checkout/create-upload/finalize/release/unbind requests + stored responses persist before reply; response-loss replay byte-identical; checkout/publish never mint second lease/fence/profile; commit manifest/request/receipt remains exact specialized contract.
- [ ] Manifest equality map matches schema: upload + snapshot persist immutable `snapshot_id`/`manifest_replay_id`, exact UNIQUE/index/composite FK; root/fleet generation records consistently key by `server_instance_id`; migration mismatch probes executable.
- [ ] Local `operations`/`upload_sessions` persist instance/epoch/snapshot/replay exact bindings; dedicated root grant/generation tables and fleet state are instance-keyed; extracted DDL executes with `integrity_check`/`foreign_key_check` and eleven probes.
- [ ] Mọi SQLite-backed unsigned wire integer có decoder + schema bound `0..i64::MAX`; `0`/max pass, negative/`i64::MAX+1`/`u64::MAX`/noncanonical/coercion vectors reject, không wrap/clamp.
- [ ] External checksummed/fsync'd epoch record ngoài SQLite rollback scope là authority; `v2_server_state`/local epoch chỉ mirror; prepare→external replace/fsync→DB install/open/reconcile ordering và missing/corrupt/behind/ahead crash table fail closed/deterministic.
- [ ] Downgrade/restore uses exact V2 transition/proof contracts and external epoch ordering, while explicitly not claiming detection of malicious same-epoch control-plane row rollback.
- [ ] MCP canonical fixture deep-compare đủ 96 names/descriptions/annotations/input schemas và local-only regression là hard gate.
- [ ] Every named 5.6 contract has golden byte/hash roundtrip + noncanonical reject; every grant mapped column and every Merkle direction/shape has single-field mismatch rejection.
- [ ] Handoff order nhất quán: persisted Architect accept → persisted Critic approve → durable consensus complete → bounded G2 spike lane → independent verifier PASS → production implementation; G2 fail/blocked/verifier non-PASS làm goal stop. Không path nào chạy G2 trước Critic hoặc production trước verifier. V0.2.0 internal-only và Team runtime Windows-first.
- [ ] Goal prompt có đủ stop conditions/evidence, không giao primitive choice trước durable consensus, không giao production authority trước independent verifier-confirmed G2 PASS và không cho commit/release sớm.
- [ ] `docs/NEXT_V0.2_X_GOAL.md` chỉ là short superseded pointer: runtime/baseline v0.1.28, canonical goal ở plan này, old v0.1.27 text không có implementation/release authority.
- [ ] DoD phân biệt G0–G7 implementation completion với `P-OP`; nếu `P-OP` blocked thì artifact non-production-ready và cấm production-ready/release-ready claim, tag/publish/release/production migration.

## 22. Plan completion/stop rule

**Trạng thái kết thúc: consensus-approved design.** Architect `APPROVE` rồi Critic `APPROVE` đã được persist; Planner không chạy G2 hoặc implementation. Bounded G2 có thể bắt đầu trong goal tiếp theo, nhưng production implementation chỉ mở sau independent verifier G2 `PASS`. G2 fail/blocked/non-PASS dừng goal; `P-OP` blocked vẫn bắt buộc non-production-ready/no release claim.
