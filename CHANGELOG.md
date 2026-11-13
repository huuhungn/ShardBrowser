# Changelog

## v2.12.1

A fix release for the cookie import added in v2.12.0. The browser engine is
unchanged (Chromium 157.0.8103.50).

- Cookie import: a far-future expiry written in milliseconds or microseconds
  (a year-9999 "never") is read in its own unit instead of as an already
  expired 1978 date or an out-of-range value.

## v2.12.0

Ports the browser engine and the launcher-side fixes of upstream ProxyShard
v2.1.1–v2.1.5 that this fork can use, plus ideas harvested from third-party
forks and similar open-source launchers (ledger: `docs/V2.12_PORT_LEDGER.md`).

### Upgrade notes

- The engine moves to Chromium 157. Install the engine update when the
  launcher offers it, with no profile running; profiles are migrated after
  the swap.
- This release ships Windows and Linux builds only; v2.11.1 is the last
  macOS build. `latest.json` no longer carries a macOS entry, so from now on
  the in-app updater on a macOS install reports that it found no update for
  its platform.
- macOS installs stay on 2.11.1, where protected video breaks with the 157
  engine (see Widevine below). Skip the 157 engine update there if you need
  protected video.

### Engine

- **Chromium 157.0.8103.50 (upstream v2.1.5).** Carries Chrome's November 9
  security fix for an XML flaw exploited in the wild, and upstream's engine
  fixes since 156: WebRTC behind proxies without UDP, canvas/WebGL/WebGPU
  reads, audio written by a page, Widevine license requests, fonts and
  processor results of another system, headless screens, touch on profiles
  without a touch screen. The shared engine bucket already served this build
  while `runtime.json` still named 156, so a fresh install got a 157 engine
  under profiles describing 156; the manifest now names the build it serves.
- **Profiles follow the new engine.** Migration brings saved profiles and the
  fingerprint library to 157 (user agent, client hints, GREASE `Not-A.Brand`
  99). Phone profiles report the Chrome for Android build and the
  `Google Chrome` brand; Apple M-series profiles gain the WebGPU features
  Chrome 156/157 report on their chip.
- **Operating system versions Chrome can report.** New Windows and macOS
  profiles get a version that exists (Windows 10.0.0 / 15.0.0 / 19.0.0, macOS
  releases current as of 2026-11, never older than the claimed Apple chip
  shipped with). Saved profiles with a version Chrome never reports are
  corrected once by migration, and again at every start before the engine
  sees them.
- Profiles are migrated only once the engine on disk is the published one
  (upstream v2.1.1): while an engine update is pending, has failed, or is
  refused, profiles keep describing the engine they run on; the install
  migrates them after the swap.
- Fingerprints imported into the library (stored with their config under
  `payload`) are migrated too; before, only bare configs were.
- Migration writes each profile atomically, so an interrupted start cannot
  leave a truncated profile file.
- **Widevine on macOS** goes into the engine's own `Versions/<build>` folder on
  disk instead of one named after the launcher's compiled-in version, so a
  manifest that moves ahead of the launcher no longer breaks protected video.
  This fix ships in no macOS build, since macOS releases stop at 2.11.1.

### Fixes

- **Relay sockets on Windows.** Mio 1.2.0 created inheritable sockets, so the
  browser inherited the local proxy relay's sockets and could keep a stopped
  relay's port open. Updated to mio 1.2.4, with a regression test (harvested
  from the shiranzby/ShardBrowser-ProxyChain fork).
- **Browser cache of deleted profiles (upstream v2.1.3).** Deleting a profile
  for good (purge from the trash, a temporary profile closing) now removes its
  browser cache on macOS and Linux, where Chromium keeps it under the OS cache
  folder; moving to the trash keeps it so a restore finds it. Caches left by
  profiles deleted earlier are swept once at the first start. On Windows the
  cache sits inside the profile folder and was already removed.

### Security

- rustix 1.1.4 → 1.1.6 in the launcher, team server and shared lockfiles
  (RUSTSEC-2026-0486, unsound xattr reads; denied by the CI audit).

### Launcher

- **Delete many bookmarks.** The Bookmarks page has row checkboxes and a
  select-all box that follows the search and folder tab; delete the selection
  in one go, and Undo in the toast brings them all back.
- **Hide the profile name in the browser.** Settings › Profile name in the
  browser: turned off, the engine shows no name next to the address bar or in
  the window title (useful on a recorded or shared screen). Needs the 157
  engine; an older engine ignores the switch.
- **Maximized window (upstream v2.1.4).** Profile editor › "Report the window
  as maximized": the window opens the size of the profile's screen and sites
  see it maximized; resized, they see its real size. Not offered on phone
  profiles.
- **Open a profile from a link.** `shardbrowser://open/<profile id or exact
  name>` brings the launcher forward and asks before starting that profile.
  Links can only open: no create, delete, URLs, proxies or launch arguments,
  and a malformed link is refused with a notice (idea from the
  mathisspr/ShardBrowser fork, re-implemented with a confirmation).
- **Cookie import formats.** Import cookies from a Netscape `cookies.txt`,
  a Cookie-Editor / EditThisCookie export, or a Playwright/Puppeteer cookie
  list or `storageState`, as well as the launcher's own format, from the
  profile menu, the API (`text` or `cookies`) or MCP. Skipped entries are
  reported by line or position with a reason, never with their values
  (format handling adapted from polyackiy/camoufox-profile-manager, MIT).
- **Proxy test details.** A proxy test tries up to three times within the
  same time budget and reports working, unstable or failed, with the reason
  for a failure: authentication, timeout, DNS, unreachable or protocol error.

### SDKs

- `CHROMIUM_VERSION` in the Node, Python and Rust SDKs is 157.0.8103.50 (the
  macOS framework path and the fallback when the manifest is unreachable).
- **Install the engine ahead of time (upstream v2.1.3):** `npx shardx install`
  and `shardx install` / `python -m shardx install`, with `--force` and
  `--cache-dir`; in Rust, `Runtime::install`. Suits Docker images.
- **Graceful close:** stopping a session asks the browser to quit over CDP
  and waits up to 5 seconds before killing it, so recent saves and logins
  survive (upstream v2.1.3).
- Phone profiles report the Chrome for Android build and the `Google Chrome`
  brand; Apple M-series profiles gain the Chrome 156/157 WebGPU features.

## v2.11.1

A security and Team fix release: the launcher refuses a profile database whose
write-ahead log does not match it (RUSTSEC-2026-0459), and the team server
codes its refusals of a device approval, so a launcher tells a refused member
from a server too old to renew members. The browser engine is unchanged.

### Upgrade notes

- Replace the team server binary. There is no new migration (0034 is still the
  latest); back up the database first as usual.
- Update the team server together with the root custodian's launcher: a 2.11.1
  launcher reads a 2.11.0 server's refusal of a member's renewal as a server
  too old, and the Team page asks for the update.

### Security

- **SQLite write-ahead log guard (RUSTSEC-2026-0459, CVE-2026-119375).** SQLite
  before 3.54.0 can return uninitialized memory when a database is opened with
  a `-wal` whose page size differs from the database's. Profile databases can
  arrive with their `-wal` in another device's snapshot, so the launcher now
  refuses such a pair before SQLite opens it, for cookies, saved passwords, web
  data and automation databases. The patched SQLite cannot be built yet
  (`sqlx` caps `libsqlite3-sys` below 0.38), so the advisory is accepted with
  this guard; see `docs/dependency-review.md`.

### Team

- **Coded approval refusals.** The team server answers every 403 of an
  ordinary device approval with the code `APPROVAL_REFUSED`. Member renewal
  reports a team server too old only for a 403 without a code, as a 2.10
  server sends, instead of guessing from whether the server ever renewed a
  member. The Team page asks to update the team server to the latest version.

### Known limitations

- The bundled SQLite stays at 3.46 until `sqlx` allows `libsqlite3-sys` 0.39;
  the guard covers the published trigger only.

## v2.11.0

A Team release: the root custodian can rotate the tenant root key, renews
members' approvals and fleet key grants before they end, and a revoked old root
device can be reset. Teams with more than 64 devices no longer stop at "too
many signers". The team server gains offline discard commands for a stuck key
rotation. The browser engine is unchanged.

### Upgrade notes

- Back up the team server database, then replace the binary. Migration 0034 is
  forward-only: a 2.10 server will not start on a database it has migrated, so
  a downgrade means restoring the backup.
- 2.10 launchers keep working against a 2.11 server. Member renewal and Reset
  need the 2.11 server.
- After a root rotation, export is refused until the rotation is finished, and
  every older recovery bundle stops working. Keep the new bundle and delete the
  old ones by hand.
- Do not downgrade a launcher after a root rotation: 2.10 cannot open a v4
  bundle that holds a rotation grant, and reads trust evidence stored from
  several listings as unreadable (Collect again after upgrading back).

### Team

- **Rotate root key.** On the root custodian, Rotate root key replaces the
  tenant root key (TRK) N with a fresh N+1. It opens every fleet key the team
  ever used from its recovery grant, writes a new v4 recovery bundle holding
  the new key, every fleet key and a self-issued rotation grant, and pins that
  bundle's hash on the server before it creates N+1. Every step is saved
  before it is sent, so a crash or a lost reply resumes with the same bytes.
  The new bundle path must differ from the current bundle.
- **Finish with a fleet rotation.** The Team page then asks for Rotate fleet
  key until a fleet generation activates under N+1. Members are not
  interrupted by the root rotation itself.
- **Refused while unfinished.** Rotate root key is refused when the device is
  not the root custodian, has handed custody over, or has a fleet rotation,
  re-seal, renewal or hand-over unfinished. Export recovery bundle is refused
  while a root rotation is unfinished.
- **Member renewal.** The root custodian renews each member's approval,
  capability grants and fleet key grant at half-life, on the team server's
  clock, as part of its own custody renewal. It renews only the
  capability and scope pairs a member already holds, and a device grant only
  if the member already holds one of the active fleet generation: a member
  left out of a rotation does not get the key back this way. Recovery grants
  and member grants of retired generations are not renewed.
- **Reset of a revoked old root.** A revoked old root device, or a cancelled
  new custodian, can now be reset when it holds a signed revocation from a key
  it already trusts. Reset wipes its keys and root state and the device can
  join again. A live root custodian never resets.
- **Larger teams.** Trust evidence is read as several complete listings of at
  most 64 signers each and merged, so a custodian revocation or a long history
  no longer stops at "too many signers" for teams up to 1024 signers.

### Team server

- **Discard a stuck rotation.** `shardx-team-server fleet discard-preparing`
  and `shardx-team-server root discard-preparing` archive and delete a stuck
  PREPARING generation, so the same generation number can be used again. Stop
  the server and back up the database first.
- **Renewal of an active device.** The approve route accepts the renewal of an
  active device by any holder of `device.approve` for the scope. A revoked
  device is never approved again.
- **Signed revocation in the ticket listing.** The ticket listing carries a
  revoked device's signed revocation and its issuer's public key, which is what
  Reset checks.
- **Migration 0034.** It ties the no-delete triggers on key generations and
  grants to the offline discard marker. It is forward-only.

### Known limitations

- **Root rotation cuts off an old TRK going forward only.** A TRK is cut off
  only after the following fleet rotation. Recovery grants under N stay on the
  server and in trust evidence, so whoever holds TRK N reads every fleet key up
  to that point; copied keys cannot be recalled.
- **The current custodian is not cut off.** Its own leaked bundle or stolen
  machine receives TRK N+1 like the rest of its keys. Hand custody over first
  (v2.10), then rotate.
- **One custodian.** The required set of a root rotation is one rotation
  grant. A device lost mid-rotation needs the old bundle (generation N is still
  active) plus `root discard-preparing` on the server.
- **Discard needs downtime.** Discarding needs the server stopped and the
  operator. Archived rows are kept forever. A replayed create of a discarded
  generation returns its stored reply, and launchers recover.
- **Member renewal runs only when the custodian uses the launcher** (custody
  commands, syncs) and needs a 2.11 server. A member that holds no grant of the
  active fleet generation gets its approval and capability grants renewed but
  no first device grant; the next fleet rotation grants it, or it is revoked and
  enrolls again.
- **Reset trusts only a saved issuer.** Reset needs a 2.11 server. It trusts
  only the saved appointment signer (the old root) or the saved hand-over
  issuer before the appointee's own rotation (a cancelled appointee). It checks
  the issuer's revocations in the ticket listing and those this device filed.
  Otherwise the machine stays inert and is wiped by hand.
- **Reset leaves some files.** The TRK of a run abandoned before its reference
  was saved, and recovery bundle files on disk, are not wiped. Delete old
  bundles by hand.
- **Evidence limit.** Evidence beyond 1024 signers fails closed. Listings
  fetched moments apart are merged as a union, so a revocation in any of them
  counts.
- **Downgrade.** 2.10 cannot open a v4 bundle holding a rotation grant, and
  reads an evidence store of several listings as unreadable.
- **Still open from earlier releases.** `compromised` for custodian rows,
  cleanup of retained fleet generations, the members' banner, the revocations
  of an imported custodian, a change of the server URL alone, revocations a
  hostile server hides, and members that missed two rotations and must enroll
  again.

## v2.10.0

A Team release: root custody can move to a new device in an enforced order,
the root custodian renews its own custody records before they end, and Re-seal
all profiles moves every profile head to the newest fleet key at once. Member
devices can be revoked as compromised. The browser engine and the team server
are unchanged.

### Upgrade notes

- The team server is unchanged: a 2.9.x server works with launcher 2.10.0.
- Every member should run 2.10 before a hand-over, and sync once after it
  begins and before the old root is revoked. A member still on 2.9.x when the
  old root is revoked distrusts peers it has not seen and must enroll again.
- 2.9.x cannot open a v4 recovery bundle. A root custodian writes v4 once a
  renewal or a hand-over has replaced its first root grant.
- Export the recovery bundle again after a renewal and after a hand-over (the
  Team page asks). Once the old root is revoked, its bundles stop working.
- Re-seal moves each profile it touches up one version, so a member with
  unpushed changes to such a profile must Pull first, which replaces those
  changes.
- Do not downgrade to 2.9.x after a hand-over, a renewal or a re-seal: 2.9.x
  ignores the current root grant and the re-seal, renewal and hand-over state.
- After a hand-over, the old root machine stays inert until v2.11 adds Reset.
  Keep it switched off.

### Team

- **Root custody hand-over.** On the root custodian, Approve as root custodian
  appoints a device that has joined the team. It is refused until the
  custodian's own Re-seal all profiles has left every profile head under the
  active fleet key. From then on the old root refuses every custody action,
  and it can cancel only by revoking the new device before that device
  rotates. Appointing an already approved member is refused.
- **Accept and checklist.** On the new device, Accept root custody keeps the
  root grant only if its own trust chain counts it. A checklist then enforces
  the order: Export recovery bundle, Rotate fleet key (with no grant to the old
  root), Re-seal all profiles, Export recovery bundle again, and revoke the old
  root as retired or lost. Every revoke re-checks these steps and every profile
  head live.
- **Lost old root.** Revoking the old root as lost accepts heads it pushed
  after the re-seal. They are listed, each must be joined on the new device,
  and they are reverted right after the revoke once you confirm that exact
  list. A revert that fails is retried by the next revoke.
- **Members stay trusted.** When a custodian is revoked, each device checks
  every device it approved in one closure evaluation, so their approvals keep
  standing.
- **Root custody renewal.** The root custodian renews its own approval, root
  grant, capability grants and fleet key grant at half-life, on the team
  server's clock, before custody actions and during team sync. The approval and
  the root grant now run two years. The Team page shows when renewal is due,
  when custody ends and when the key age ends, warns from 75%, and offers Renew
  custody.
- **Re-seal all profiles.** The root custodian seals every profile head under
  an older fleet key again under the active one, from the team server's copy,
  without a profile folder. It skips and lists profiles in use, in error,
  quarantined or under a key this device does not hold, and resumes where it
  stopped after a crash without committing a head twice.
- **Recovery bundle v4.** Once a renewal or a hand-over has replaced the first
  root grant, Export recovery bundle writes v4, which carries the current root
  grant. Import of a v4 bundle checks that the trust chain counts the bundle's
  device as a custodian now.
- **Compromised for members.** Revoke offers `compromised` for member devices.
  Until the fleet key is rotated and each device collects the new one, no
  device can push or publish under the current key. Custodian rows keep
  retired and lost.
- **Skip a failing member.** If the team server keeps failing one member's new
  fleet key grant, Skip member finishes the rotation without it. That device
  must then be revoked and enroll again.

### Fixed

- **Collect after a rotation.** A push, pull or revert refused because the
  fleet key rotated collects the new key once and retries once when a key was
  opened. Push and revert report the collected key.
- **Back-to-back rotations.** A rotation keeps the key holders of the previous
  one, so a revoked device's banner survives an expired second rotation.
- **Re-export prompt.** The prompt to export the recovery bundle again clears
  after an export that finished while another custody action was running.
- **Second grant of the same key.** The acknowledgement of a second fleet key
  grant for the same generation no longer collides with the first.

### Known limitations

- **Cut-off is server-enforced.** The root key is unchanged until root
  rotation in v2.11, and the server hands every fleet key's recovery grant to
  any device session. Until its row is revoked, the old root can open every
  fleet key; afterwards anyone with the old root key and the server's data (a
  hostile server, a copy of its database) still can.
- **Old root stays inert until v2.11.** A revoked device cannot open a session
  to read its own signed revocation, so the old root machine, or a cancelled
  appointee, stays inert with its seeds and root state until v2.11 brings
  Reset and the wipe of its seeds. Keep it switched off.
- **Members still on 2.9.x.** A member still on 2.9.x when the old root is
  revoked distrusts peers it has not seen and must enroll again.
- **Closure limits.** The closure evaluation names every device ever granted a
  fleet key, revoked and retired ones included. More than 64 fails closed
  (`fleet.trustClosureTooLarge`) and team sync stays paused on that device
  until v2.11. A member the server leaves out of the evidence is distrusted and
  must enroll again (a denial of service, not forged trust).
- **History below the heads.** Once the old root is revoked, the fleet keys its
  grants delivered stop opening on every device that counts the revocation.
  Re-sealed heads, later pushes and the new custodian's own key stay readable;
  older snapshots below the heads do not.
- **Restore from before the rotation.** A custodian restored from a recovery
  bundle exported before its rotation loses the hand-over checklist and its
  live checks. It must not revoke the old root by hand.
- **Expired members block a hand-over.** A member whose 365-day approval ran
  out and whose head is current blocks a hand-over until v2.11 renews members.
- **Revoked appointee and a resumed Appoint.** If the appointee is revoked
  during a crash window and the old root then resumes Approve as root
  custodian, the old root refuses custody steps until it cancels again.
- **Bundles and renewal.** A bundle exported before a renewal does not import
  over the same device's renewed state. Export again after a renewal.
- **Re-seal skips.** Profiles in use, in error or quarantined are skipped and
  block revoking the old root until fixed; a stolen old root that keeps pushing
  is handled by revoking it as lost with the listed reverts. A skip reason
  whose message has placeholders shows them unfilled.
- **Server listing trust.** A profile the server hides from every listing and
  that no device here binds is not re-sealed or checked.
- **Members' records still end.** Members' approvals and fleet key grants still
  end after 365 days; renewing them needs the v2.11 server change. A member
  offline past the old root grant's end treats the custodian as lapsed and must
  be re-appointed or enroll again.
- **Renewal needs use.** Renewal runs on custody actions and team sync, so a
  custodian unused for half a year renews only on its next use; the warning
  shows from 75%.
- **Key age.** A root custodian's key counts for 1095 days unless custody is
  handed over.
- **No `compromised` for custodian rows** until v2.11.
- **One hand-over at a time.** It can be cancelled only before the new device
  rotates.
- **Expired rotations.** A rotation that expires (30 days) or is undone by a
  server restore before activation leaves the team on the old key. If the
  server still holds the unfinished key as `PREPARING`, starting a rotation,
  and so a hand-over, is refused with `FLEET_GENERATION_EXISTS`, and each retry
  files one extra `key.rotate` grant. Discarding it comes with the v2.11
  server.
- **Old snapshots.** Snapshots stay under the keys they were sealed with, and a
  revoked device can read any of them that leaks to it.
- **Hidden revocations.** A device revoked while the server hides its
  revocation can still write under the old key to a profile that has not moved
  to the new key. The generation floor stops it once that profile is pushed
  under the new key.
- **Retired keys from a hostile server.** A hostile server can serve a valid
  member's head under a retired key that is not older than the head before it,
  and readers accept it.
- **Two missed rotations.** A member offline across two rotations must enroll
  again.
- **Banner source.** The banner is derived on the root custodian's device from
  its own signed revocations and known key holders, plus its trust ledger.
- **Imported custodian.** A root custodian restored from a recovery bundle
  starts with no saved revocations and a fresh trust ledger. If the server
  hides a revocation, the rotation can still grant the new key to that device.
- **Pending devices revoked later.** A device still pending during a rotation
  and revoked afterwards by another custodian relies on the server to refuse
  it when an approval is resumed across the rotation.
- **A valid member under an older key.** A still-valid member's head under an
  older key than its profile already uses stops pulls of that profile (fail
  closed, nothing pinned) until the member is revoked; Revert then skips it.
- **Older-key list.** The list reads the generation of the local binding:
  profiles not bound on the root custodian's device are missing, and after a
  server restore a row keeps the previous generation until the next pin.
- **Refused or skipped members.** A member refused or skipped during a
  rotation (expired approval, changed keys, no signed approval, Skip member)
  must be revoked and enroll again. A member already granted in an earlier run
  may show as skipped when a resumed run finds it no longer eligible.
- **Server restore.** A server restore after a rotation is not covered by a
  test.
- **Reset of a pending device.** Credentials left by a Reset of a pending
  device stay; only the credentials of a revoked old identity are forgotten.
- The 2.8.x limitation about the server URL still applies.

## v2.9.0

A Team release: the root custodian can rotate the team's fleet key, so a
revoked device cannot read snapshots pushed from then on. Heads pushed under
the old key stay readable. The browser engine and the team server are
unchanged.

### Upgrade notes

- The team server is unchanged: a 2.8.x server works with launcher 2.9.0.
- After a rotation, export the recovery bundle again. A bundle exported
  before the rotation does not open the newest fleet key.
- After a rotation, use Push once on every profile the Team page lists under
  an older key. Devices approved or restored after the rotation
  cannot read a head until it is pushed again, and a head left under the old
  key becomes unreadable for every device when the old key's grants end, one
  year after each was issued.
- Finish a rotation before downgrading. Do not downgrade a device that rotated
  the fleet key, or that collected a rotated key, to 2.8.x: 2.8.x refuses
  heads under older keys as stale, drops the rotation state and orphans its
  setup key.

### Team

- **Rotate fleet key.** The root custodian rotates the team's fleet key from
  the Team page. The new key must be activated within 30 days; an unfinished
  rotation offers Resume fleet key rotation, and approvals wait until it is
  done. After a rotation expires, Rotate fleet key stays available; it stays
  stuck only while the team server still holds the unfinished key. Only
  snapshots pushed from then on are protected.
- **Banner after a revoke.** While a revoked device still holds the current
  fleet key, the Team page asks to rotate: urgently for a lost device, or one
  whose saved revocation cannot be checked, and when convenient for a retired
  one.
- **Members get the new key automatically.** A rotation grants the new key to
  every device with a signed approval. Revoked devices are not granted, and a
  device that is offline collects the key later with Collect key custody.
- **Old heads stay readable.** Pull reads heads sealed under an older fleet
  key as long as that key's grant still verifies.
- **Generation floor.** Each profile refuses a head under an older fleet key
  than the one it already uses, so a revoked device cannot write under the old
  key once the profile has moved to the new one.
- **Clear messages for members.** A push or pull refused because the fleet key
  rotated says to press Collect key custody. A device that missed two
  rotations is told to have a custodian revoke it and enroll again.
- **Profiles still under an older key.** The Team page lists them with Push,
  which only pushes. If this device's copy is behind the server, it says to
  Pull the profile from the profile list first (pulling replaces local changes
  on this device), then push again.
- **Export the recovery bundle again.** After a rotation the Team page prompts
  the root custodian to export the recovery bundle again.
- **Revoke confirmation.** The revoke confirmation now says that the device
  keeps the fleet key it holds until the fleet key is rotated.

### Fixed

- **State file checks.** A team state file or folder whose existence cannot be
  checked is an error instead of a missing one.
- **Old credentials forgotten.** After a device enrolls again, the saved
  credentials of its old identity are forgotten once the server lists that
  identity as revoked.
- **Hex keys.** A stored hex key with non-ASCII characters is refused with an
  error instead of crashing the launcher.
- **Resumed approvals across a rotation.** An approval resumed across a
  rotation never resends anything for a device revoked on this device, or
  whose signing key the trust ledger records as withdrawn.
- **Account password in a server listing.** A device or account ID in a server
  listing that equals the account password is refused, and is never logged or
  saved.
- **Rotation deadline.** The rotation checks its 30-day deadline again after
  each wait on the team server.

### Known limitations

- **Heads not pushed again.** A device approved after a rotation, or restored
  from a recovery bundle, cannot read a head that was not pushed again under
  the new key. The older-key list covers only profiles bound on the root
  custodian's own device.
- **Old keys end with their grants.** A head left under a retired key becomes
  unreadable for every device once the old key's device grants end (365 days
  from each grant). Grants of a retired key cannot be renewed; bulk re-sealing
  comes later.
- **Root machine and recovery bundle.** Rotating the fleet key does not cut off
  a stolen root custodian machine or a leaked recovery bundle: both can open
  the new key. Root key rotation and moving custody come later.
- **Old snapshots.** Snapshots stay under the keys they were sealed with, and a
  revoked device can read any of them that leaks to it.
- **Hidden revocations.** A device revoked while the server hides its
  revocation can still write under the old key to a profile that has not moved
  to the new key. The generation floor stops it once that profile is pushed
  under the new key.
- **Retired keys from a hostile server.** A hostile server can serve a valid
  member's head under a retired key that is not older than the head before it,
  and readers accept it.
- **Expired rotations.** A rotation that expires (30 days) or is undone by a
  server restore before activation leaves the team on the old key, and
  approvals work again. A new rotation can start, unless the server still
  holds the unfinished key as `PREPARING`: then starting is refused with
  `FLEET_GENERATION_EXISTS`, and each retry files one extra `key.rotate`
  grant. Discarding it needs a later server version.
- **Back-to-back rotations.** Starting a rotation replaces the member results
  of the previous one. If the new rotation then expires, a revoked device
  known to hold the previous key only from those results can lose its banner.
- **Member grant errors.** If a member's grant keeps failing with a server
  error, the rotation stays activated but unfinished, and approvals stay
  refused until the grant goes through.
- **Two missed rotations.** A member offline across two rotations must enroll
  again.
- **No compromised reason.** Revoke has no `compromised` reason, so the Team
  page cannot freeze the team after a compromise.
- **Members learn of a new key late.** A member learns of a new fleet key only
  on Collect key custody or from a push or pull error.
- **Banner source.** The banner is derived on the root custodian's device from
  its own signed revocations and known key holders, plus its trust ledger.
- **Imported custodian.** A root custodian restored from a recovery bundle
  starts with no saved revocations and a fresh trust ledger. If the server
  hides a revocation, the rotation can still grant the new key to that device.
- **Pending devices revoked later.** A device still pending during a rotation
  and revoked afterwards by another custodian relies on the server to refuse
  it when an approval is resumed across the rotation.
- **A valid member under an older key.** A still-valid member's head under an
  older key than its profile already uses stops pulls of that profile (fail
  closed, nothing pinned) until the member is revoked; Revert then skips it.
- **Older-key list.** The list reads the generation of the local binding:
  profiles not bound on the root custodian's device are missing, and after a
  server restore a row keeps the previous generation until the next pin.
- **Refused or skipped members.** A member refused or skipped during a
  rotation (expired approval, changed keys, no signed approval) must be
  revoked and enroll again, as before. A member already granted in an earlier
  run may show as skipped when a resumed run finds it no longer eligible.
- **Re-export prompt.** The prompt to export the recovery bundle again can stay
  after an export that finished while another custody action was running.
  Exporting again clears it.
- **Server restore.** A server restore after a rotation is not covered by a
  test.
- **Reset of a pending device.** Credentials left by a Reset of a pending
  device stay; only the credentials of a revoked old identity are forgotten.
- The 2.8.x limitations about the server URL and renewal still apply.

## v2.8.1

A Team fix release: the launcher checks the team server's answers more
strictly during recovery. It fixes the known limitations of 2.8.0 that a
misreporting server could trigger. The browser engine and the team server
are unchanged.

### Team

- **Import binds the login to the bundle.** Import recovery bundle refuses a
  login ticket or device session for another account or server than the
  bundle's, before any proof or write.
- **Reset keeps a pending device's keys.** When the server says a device is
  pending, Reset keeps a copy of `team.json` and the device keys, as it does
  for a revoked device.
- **No crash on a malformed root key grant.** A root key grant with a
  malformed hex field is refused with an error instead of crashing the
  launcher.
- **A verified cached fleet key is marked verified.** A fleet key cached by
  2.4.2 that a grant verifies is now marked verified, so Export recovery
  bundle works on that device.
- **Root custodian actions on the Team page.** While the root custodian's
  status loads, and for an unfinished root setup, the Team page offers no
  Reset or Enroll again, and an unfinished setup no longer says the device is
  the root custodian. A root state left by another team or device no longer
  hides Reset.
- **Trust ledger checks.** A trust ledger that cannot be checked is an error,
  and an unreadable ledger blocks Reset only for an active device.
- **Root state checks.** A root or custody state file that cannot be checked
  is an error instead of a missing file, so a server or tenant change and
  Reset no longer clear a working root custodian.
- **Another device's root state.** A root state left by another device,
  finished or not, no longer shows the bootstrap anchor, Show devices, Export
  recovery bundle or Resume custody setup, and the device's own join steps
  stay visible.

### Known limitations

- The known limitations of 2.8.0 about the recovery bundle, the server URL
  and fleet key rotation still apply.

## v2.8.0

A Team release: a team survives losing its devices' keys. The root custodian
can be restored from a recovery bundle on a fresh device, and a member whose
keys are lost or that was revoked can reset and enroll again from the Team
page. The browser engine and the team server are unchanged.

### Upgrade notes

- The team server is unchanged: a 2.7.x server works with launcher 2.8.0.
- Root custodians: after updating, export a new recovery bundle from the Team
  page. A bundle exported by 2.7.x holds no root custodian and cannot restore
  the team.
- Do not downgrade a device that imported a recovery bundle, or that holds a
  v3 bundle state, to 2.7.x. 2.7.x cannot open a v3 bundle and ignores the
  imported state, so it reports `fleet.notCustodian`.

### Team

- **Recovery import.** A fresh device, or the root custodian's own machine
  after its keys were lost, restores the root custodian from a recovery bundle
  and its passphrase, so Publish, Pull, Approve and Revoke work as before. The
  import needs the "old root custodian device is lost or its keys were reset"
  box ticked and checks the bundle against the saved tenant, the team's anchor
  and the server's own record of the device before it writes anything. It
  refuses to run over another device's identity.
- **Export recovery bundle.** The root custodian can export the bundle again
  once it holds the fleet key. A new bundle carries the root custodian's own
  identity and the team's fleet keys, and files nothing on the server. The
  export shows the root key fingerprint and stays off until the owner ticks
  that it was recorded.
- **Reset this device.** A member device whose keys are lost, or whose key
  store did not answer, is shown as such on the Team page. Once a custodian
  revokes it, Reset this device clears its identity so it can enroll again,
  and the old files are kept as copies. The root custodian is offered import
  instead.
- **Revoked devices may enroll again.** The server's own listing decides: a
  pending device, an active device that is not pinned, or a revoked device. An
  expired join code of a revoked device offers Enroll again.
- **The root custodian keeps its connection.** Changing the server URL or
  tenant is refused on the root custodian unless both its device keys are
  lost.
- **Fleet ID recorded.** Enrollment records the team's fleet ID, so a legacy
  profile that was never published finds its fleet key when it is pulled.

### Known limitations

- A recovery bundle plus its passphrase is the root custodian device, and the
  account password shared by the team does not add a factor. A leaked bundle,
  or a root machine stolen with readable keys, stays a root custodian until
  custody moves to a new device row and the old one is revoked, which comes
  with rotation.
- A bundle restores the team only while the root's approval and grants run
  (365 days from bootstrap); renewal comes later.
- After an import, a device that was pending gets a new approval window, and
  an approval the lost root left unfinished needs that device revoked and
  enrolled again.
- The server's recovery bundle pin keeps naming the first bundle.
- A root custodian cannot change the server URL, not even to a new address of
  the same server. With the launcher closed, edit `server_url` in
  `team.json`.
- Fleet key rotation is not available yet: a revoked device keeps the fleet
  key it holds and can still decrypt snapshots sealed under it.
- A fleet key setup left unfinished for more than a year cannot be finished or
  discarded: its saved requests have expired and the generation stays
  `PREPARING`. Finishing or discarding it comes with fleet key rotation.
- The launcher trusts the team server's answers about device status. A
  server that misreports them can still make Reset forget a working member's
  keys (by reporting the device as pending), make an import accept a login
  ticket for another account, or keep the Team page from offering the right
  action while the root custodian's status loads or its setup is unfinished.
  Tightening these checks is tracked for the next release.
- A fleet key cached by 2.4.2 that a later collect verifies is not marked
  verified, so Export recovery bundle stays refused on that device until the
  key is collected again from a new grant.
- A malformed hex field in a root key grant from the server crashes the
  launcher instead of returning an error.

## v2.7.1

A Team fix release from the first real two-machine run of v2.7.0. The
browser engine and the team server protocol are unchanged.

### Team

- **This device's key IDs.** An enrolled device's Team page shows its full
  signing key ID and encryption (HPKE) key ID next to its Device ID, with a
  copy button, so the operator can compare them with what
  `tenant confirm-first-device` prints.
- **Why Approve is off.** With a pending device listed, the device list says
  when Approve waits for the account password or for Create fleet key.

## v2.7.0

A Team release: the root custodian creates the team's fleet key, approves a
new device through its join code and revokes devices from the Team page,
without an admin token, so Team profiles can be published and shared between
devices through a real team server. The browser engine is unchanged (Chromium
156.0.8078.48, engine build 1).

### Upgrade notes

- Update the launcher and the team server together. Launcher 2.7.0 needs the
  2.7.0 team server, released as assets of the same tag: it uses the
  custodian device listing, reads without a token, and rebuilds a saved
  revocation only when the server answers `REVOCATION_OUTSIDE_WINDOW`, which
  an older server never sends.
- `tenant create` now also creates the tenant's default fleet. A tenant
  created by an older server has no fleet and is not backfilled: recreate it
  with the 2.7.0 server.
- A refused login now shows only the server's error code, not the text of
  its reply.

### Team

- **Create fleet key.** The root custodian creates the team's fleet key from
  the Team page. A notice says that the recovery bundle does not include the
  fleet key yet; it stays recoverable through the server's recovery grant.
- **Devices.** The root custodian lists the team's devices. A pending device
  shows its code, the time left on this computer's clock, and its full key IDs
  on request. Approve and Revoke are available once the fleet key is created.
  Approve needs the "code matches" box ticked and closes ten minutes after
  this computer first saw either of the device's keys. Rows that share a label
  tag the newest enrollment. Any other active device can be revoked as Retired
  or Lost, behind a confirmation that says what revoking does not protect.
- **Join code.** A new device shows its join code for ten minutes after it
  enrolls; "Codes match" pins the team's anchor, then "Collect key custody"
  keeps the fleet key. An expired code offers Enroll again. A device that has
  joined says so instead of offering its code again, and a device whose fleet
  key is blocked because a device that may hold it was revoked as compromised
  shows a notice instead of the join code.
- **No token needed.** Connecting needs only the server URL and the tenant ID.
  The API token is optional and serves legacy passphrase sync only.
- The approval window and the "code matches" tick belong to the device's keys
  and code, and the window is checked again right before the approval is
  signed.
- A revocation is saved before it is sent, and a retry resends the same bytes.
  It is rebuilt only when the server's top-level error code says the saved one
  is outside its time window and the device is not yet revoked; any other
  refusal keeps it as saved.
- Passwords and session tokens that a team server echoes back are removed from
  the error text, in the forms the launcher recognizes. A device listing with a
  pending device whose key IDs do not hash from its keys is refused.
- An expired join code offers Enroll again only after the server confirms the
  device may enroll again; the local countdown alone shows only that the code
  expired.
- **Root key grants.** On the team server, a device's root key grants are
  served only to that device's own v2 session; a legacy v1 token now gets 403.

### Known limitations

- Enrollment does not record the team's fleet id, so a legacy profile that was
  never published cannot use a fleet key cached by 2.4.2 when it is pulled.
  Published profiles are unaffected. This is planned for a later release.
- Fleet key rotation is not available yet: a revoked device keeps the fleet
  key it holds and can still decrypt snapshots sealed under it. The recovery
  bundle does not include the fleet key yet.
- A fleet key setup left unfinished for more than a year cannot be finished or
  discarded: its saved requests have expired and the generation stays
  `PREPARING`. Finishing or discarding it comes with fleet key rotation.

## v2.6.1

A Team fix release: removing a profile for good now unbinds it from the team,
and the decrypted revert staging is removed with it. The browser engine is
unchanged (Chromium 156.0.8078.48, engine build 1).

### Upgrade notes

- None beyond the 2.6.0 notes. The team server is unchanged.

### Team

- Removing a Team profile for good (emptying the trash, a trash entry
  expiring, deleting a folder when the trash is unavailable, and temporary
  profiles) now unbinds it: a held lease is released on the next sync or
  lapses, and open uploads are aborted. A profile in the trash keeps its
  binding. A removal is refused while the profile has unsent work, and
  emptying the trash continues past a refused entry.
- Deleting a profile for good removes its decrypted revert staging even when
  the Team database cannot be opened. Moving a profile to the trash and the
  folder-delete fallback still refuse in that case.
- A pull that moved the profile to the last valid earlier snapshot, because
  the newest one was signed by a revoked device, now says so.

## v2.6.0

A Team release: the launcher gets a Team page, and a profile whose latest
pushed snapshot was signed by a revoked device can be rolled back to the last
valid one. The team server hardens how it counts compromises. The browser
engine is unchanged (Chromium 156.0.8078.48, engine build 1).

### Upgrade notes

- Update the team server before the launchers. This release changes the
  server's device-revocation, fleet and root-grant routes, and launcher 2.6.0
  expects the new behavior.
- The launcher's local Team database moves to schema version 9 on first start.
  The migration keeps every row. Because the new schema cannot be read by
  earlier launchers, back up the Team database before upgrading if you may
  need to go back to 2.5.x.
- The Team card is no longer in Settings; it is the first part of the new Team
  page in the sidebar.

### Team page

- Team is now its own section in the sidebar. Each profile shows a binding
  badge and its sync state, and custodian alerts appear on the page instead
  of being buried in Settings.
- From the page you can publish a profile, check it in, pull the latest
  snapshot and unbind it.
- The page lists the profiles of a fleet, so you can join one of them from
  another device.

### Security

- Rule-6 revert: when the signer of a pushed head is proven revoked, the
  profile is quarantined instead of being restored. A device can then revert
  it to the last valid earlier snapshot, and other devices accept that revert
  when they pull.
- A new `custodian.renewed_after_revocation` alert shows when a custodian was
  renewed after a revocation, so the owner can review it.
- Pull and join replace the profile's data only after the new pin is
  committed, so a failed or interrupted pull leaves the profile as it was.
- A restore never pins a leaf whose signer is revoked.
- A head whose signer is withdrawn while its snapshot downloads, or while a
  revert is read back, is never pinned.
- A revert never commits the content of an earlier snapshot whose signer was
  withdrawn while it was downloaded or before the revert was retried.
- Deleting a profile or a folder (from the app or the local API) and cloning
  a Team profile into a local one remove any decrypted revert staging, and a
  device whose own key is withdrawn sends no prepared revert.
- A device revocation counts only when the device it names is one its signing
  key was approved for.
- A revert leaves no decrypted staging data on disk, and the device keeps its
  own `Local State` instead of taking the snapshot's.

### Team server

- A compromise that exposes a key through the tenant root now blocks every
  fleet it can reach, an exposure that was seen is never forgotten, and open
  uploads are aborted so nothing more is sent under an exposed key.
- A device revocation filed under a fleet-scoped `device.revoke` is counted
  when it covers every approval of the revoked device.
- A device revocation can carry generation activations, and they commit
  together with it in one step.
- After a server restart, a repeat of any closed operation returns the same
  bytes as the first time and creates no second resource.
- A pulled or pinned head whose signer is revoked is quarantined, and each
  pull records the evidence it evaluated.

### Changed

- Dependencies: `async-executor` is updated from 1.14.0, which was yanked, to
  1.14.1.
- Local Team database schema 9 adds `skipped_heads`, `trust_custodian_alerts`
  and `revert_swaps`.
- The release workflow ignores RUSTSEC-2026-0429 for the `zip` 4 that the
  updater plugin pulls, for the same reason as the other `zip` 4 advisories:
  the plugin extracts nothing before it verifies the payload's signature.

## v2.5.0

A Team sync release: the team server gains the v2 control plane for root
custody, fleet keys and published profiles, and the launcher keeps every Team
key in the OS credential store. The browser engine is unchanged (Chromium
156.0.8078.48, engine build 1).

### Upgrade notes

- Update the team server before the launchers. Launcher 2.5.0 enrolls a device
  through the new pre-device ticket, which a 2.4.x team server does not offer.
- On Windows the launcher refuses to start when its config folder or data
  root is not on a local NTFS volume (for example an exFAT drive or a network
  share). Move the data root to a local NTFS folder with 2.4.4 before
  upgrading.
- The backend for publishing a profile, cancelling a publish, unbinding,
  downgrading and showing lease state is in this release. The Team screens for
  those commands come in a later release.

### Security

- Device signing and HPKE keys, fleet keys and the tenant root key of a
  running custody setup live in the OS credential store (Windows Credential
  Manager on Windows), and keys from earlier versions move there on first
  start. Where no credential store is usable, device keys can be kept in a
  passphrase-protected key file, and the Team card warns when this device's
  keys are not protected by the OS store.
- A fleet key is opened and stored only after its grant verifies against the
  tenant's trust chain, rooted at the first device's anchor.
- Pull refuses a snapshot sealed for another profile, one with two entries for
  the same path, and entries with names Windows reserves (such as `COM0`,
  `CONIN$` or `NUL .txt`); the name check applies to v1 archives too.
- Signatures use strict Ed25519 verification, and the decoder bounds nesting
  so untrusted bytes cannot overflow the stack.
- Patched releases of `tokio`, `anyhow` and `event-listener`; all three
  lockfiles are checked against the RustSec advisory database in CI.

### Team server

- Root custody: the first device sets up the tenant root from the Team card,
  is confirmed offline, and approves further devices. A revoked device cannot
  sign in again.
- Fleet key generations are created, granted, acknowledged, activated and
  revoked through one lifecycle, and the tenant root can be rotated once every
  fleet generation is rewrapped under the new root.
- Profiles can be published, checked out under one fenced lease, renewed,
  released and uploaded in chunks with a readback of the stored snapshot.
- An offline server restore prepares, commits or aborts by crash class, and
  launchers accept the new restore epoch only through a custodian-signed
  transition.
- Records that leave their signed containers are quarantined at request time
  and at startup, and the v2 control plane stays off while a device revocation
  is not served correctly.
- The server refuses to start when `SHARDX_IDENTITY_DIR` is set but fails
  its checks (missing, not local NTFS, a link or on another volume), and it waits for the SQLite write lock instead of
  failing requests under load.

### Changed

- The launcher's local Team database moves to schema version 6 on first start.
  The migration keeps every row and refuses a file it cannot upgrade safely,
  leaving it unchanged.

## v2.4.4

A user interface release. Team sync and the browser engine are unchanged
(Chromium 156.0.8078.48, engine build 1).

### Changed

- Table headers on the Browsers and Proxies pages line up with their columns at
  every window width, including 2K and 4K screens and while a profile is
  starting.
- Every page puts its title in the same place, and empty pages (Trash,
  Extensions, Bookmarks, Automation, Fingerprints, an empty folder, an empty
  proxy list) share one empty-state layout. In Vietnamese, the "All" folder tab
  and the patch log are translated.
- The fingerprint library states a GPU mismatch once, above the cards, with a
  count. Each mismatched card keeps a small warning mark that opens the same
  explanation, and the remove button is a quiet icon instead of a red one.
- Row buttons on the Browsers and Proxies pages have names that screen readers
  read with the profile or proxy name, and the current page is marked in the
  sidebar.

## v2.4.3

A security fix release for Team sync. The browser engine is unchanged
(Chromium 156.0.8078.48, engine build 1).

### Security

- Team sync no longer accepts fleet keys from the team server. 2.4.2 opened
  every fleet key grant the server listed, without verifying who issued it,
  and used that key for every later push, so a malicious or compromised team
  server could read profiles pushed after it planted a key. Push now always
  seals under the team passphrase; pull still tries fleet keys already on the
  device, so snapshots pushed under a fleet key keep restoring. Passphrase-free
  sync returns once key grants are verified against a trust chain (v0.2.x).
- Device keys are protected at rest on Windows. The device signing and HPKE
  seeds in `team.json` and cached fleet keys are DPAPI-protected for the
  current Windows user, migrated in place on first start, and no longer appear
  in debug output.
- Team server: only an active tenant owner can begin or activate a root key
  generation. Any member could before.

### Known issues

- A protected `team.json` or fleet key cache opens only under the same Windows
  account. After an administrator password reset, a reinstall that copies
  `%APPDATA%` back, or a move to another account or machine, enroll the device
  again; the launcher keeps a copy of the old `team.json` first. Re-push
  profiles that were pushed under a fleet key so they are sealed under the
  passphrase.
- Downgrading to 2.4.2 after 2.4.3 has started breaks Team on that device,
  because 2.4.2 cannot read the protected seeds. Enroll it again.
- A fleet key a hostile server planted before this release stays usable for
  pulls until the cached key is removed.

## v2.4.2

A fix release for the launcher and the team server. The browser engine is
unchanged (Chromium 156.0.8078.48, engine build 1).

### Fixed

- Selecting profiles no longer moves the profile table. The selection bar now
  sits in the title row, so a quick second click lands on the row that was
  under the cursor. The selection count on the Browsers and Proxies pages is
  translated.
- Team server: a database created by the Windows build was refused by the
  Linux and macOS builds, and the other way round, because the migration files
  were embedded with different line endings and SQLx checksums them. Every
  build now accepts either and never rewrites the stored checksums, so the
  previous version can still open the database.
- Team server: device enrollment derived the stored HPKE key id in the signing
  domain. New enrollments use the HPKE domain. Existing devices keep their id,
  and the same HPKE key can no longer be enrolled a second time.

### Internal

- ADR 0001 (draft) on server identity and first-tenant bootstrap is in
  `docs/adr/`, with its architect reviews.

### Known issues

The two engine build 1 issues listed under v2.3.1 (audio noise on a filled
`AudioBuffer`, upstream #120; the `window.chrome` keys, upstream #118) still
apply; they need a new engine build.

A team server database created by 2.4.2 does not open in the 2.4.1 Windows
team server, which accepts only the line endings it was built with. A database
the 2.4.1 Windows server created still opens in it after 2.4.2 has run on it.

## v2.4.1

A fix and security release. The browser engine is unchanged
(Chromium 156.0.8078.48, engine build 1).

### Fixed

- Selecting profiles in a narrow window no longer pushes **From template** and
  **New profile** off screen or squeezes the folder tabs: the toolbar moves
  under the tabs and wraps instead. The Proxies page toolbar wraps the same way.

### Security

- npm advisories published after 2.4.0: the MCP server takes `body-parser`
  2.4.0 (GHSA-27r3-jxmh-p828, a denial of service through trailing bytes after
  a compressed request body; the server talks over stdio and parses no HTTP
  bodies), with `qs` 6.16.1 and `content-type` 2.1.0. The Node SDK takes
  `undici` 6.29.1 (GHSA-4qv8-2p9j-2685, GHSA-xjj6-f33q-929c) and now requires
  at least that version.

### Internal

- The MCP contract test checks every tool in the v0.1.28 fixture: none may be
  removed, lose an argument, change an argument's type or item type, drop an
  enum value or gain a required argument.
  The MCP release archive now ships the fixture so the test runs there too.

### Known issues

The two engine build 1 issues listed under v2.3.1 (audio noise on a filled
`AudioBuffer`, upstream #120; the `window.chrome` keys, upstream #118) still
apply; they need a new engine build.

## v2.4.0

A feature release: profile tags. The browser engine is unchanged
(Chromium 156.0.8078.48, engine build 1).

### Added

- Profiles can carry tags. A profile still lives in one folder, and can now
  have any number of tags as well. They show as chips under the profile name,
  the search box matches them, and **Filters** has a **Tag** filter.
  - Edit a profile's tags from its row menu (**Edit tags**), or by clicking its
    chips. With several profiles selected, **Tag** on the selection bar adds a
    tag to all of them, or removes it when they all have it.
  - **Settings → Tags** lists every tag with how many profiles carry it, and
    renames, recolors and deletes tags. A delete can be undone until the next
    change.
  - Names are trimmed, cut to 32 characters and matched case-insensitively,
    so "client a" joins an existing "Client A". Renaming a tag to the name of
    another one merges the two.
  - Tags are stored in each profile's file, next to its folder, so backups,
    export and import, and the trash keep them. Colors are kept in `tags.json`
    in the settings folder.
  - A running profile's tags cannot change, as with its folder: stop it first.
    A change to several profiles skips the running ones and says how many.
- The Automation API returns `tags` on every profile, accepts `tags` on
  `POST /profiles` and `PATCH /profiles/{id}`, and lists tags with their
  profile counts at `GET /tags`. The MCP server's `list_profiles` passes the
  field through unchanged.

### Security

- The MCP server moves to `zod` 4.6.7 (GHSA-mrhx-c7xc-m3w5; no 3.x release
  carries the fix). Its 114 tools and their required arguments are unchanged.
  The published input schemas no longer set `additionalProperties: false`;
  integer arguments are now limited to the safe-integer range (±2^53 − 1).
  After downloading or repairing the MCP files, run `npm ci` in that folder:
  the new server does not start on the old dependencies, and
  **Settings → MCP server** now says `npm ci` is required until it is done.

### Before you update

Version 2.3.x does not know about tags. If you go back to it, each profile
keeps its tags in its file only until 2.3.x saves that profile again (an edit,
a proxy change or a launch), which drops them.

### Known issues

The two engine build 1 issues listed under v2.3.1 (audio noise on a filled
`AudioBuffer`, upstream #120; the `window.chrome` keys, upstream #118) still
apply; they need a new engine build.

## v2.3.1

A fix release on top of 2.3.0. The browser engine is unchanged
(Chromium 156.0.8078.48, engine build 1).

### Fixed

- Installing a launcher update, or restarting for one, now waits until the
  browsers ShardX started are closed, as quitting already does. Before, the
  update ended the launcher and left those browsers running without it.

### Before you update

The update from 2.3.0 is still installed by 2.3.0, which does not wait yet:
close your profiles before you install it. The wait applies from the next
update on.

### Known issues

Both come from engine build 1 and need a new engine build; checked on this
fork on 2026-10-23.

- With audio noise turned on, the engine changes every sample of an
  `AudioBuffer` the page filled itself, and shifts a constant signal (0.5
  reads back as 0.50001335), so a page can detect it with a single read
  (upstream #120). Audio noise is off by default.
- `window.chrome` on an ordinary page lists `csi`, `loadTimes` and a `runtime`
  key with no value, where stock Chrome lists `app`, `csi` and `loadTimes`
  (upstream #118 reports a populated `runtime` on the same build).

### Internal

- The release RustSec step fails when it cannot read any `zip` version from
  the launcher lockfile, instead of skipping the check that guards its
  `zip` ignores.
- `ctutils` is updated from 0.4.2 to 0.4.5 in the launcher, `shared` and
  `server` lockfiles for RUSTSEC-2026-0385 (non-constant-time mask generation
  and `u128` comparisons). It reaches the launcher through the Ed25519, HPKE
  and ChaCha20-Poly1305 crates.

## v2.3.0

A catch-up release: the browser engine moves to Chromium 156, and the launcher
fixes and features worth having from upstream ProxyShard v2.0.2 to v2.1.0 and
from other forks are brought onto this fork's own interface. Every item, with
its source and the reason for what was left out, is in
`docs/V2.3_PORT_LEDGER.md`.

### Added

- The engine is Chromium 156.0.8078.48 (upstream v2.1.0). Profiles report
  Chrome 156 in the user agent, client hints and TLS handshake, and pick up the
  engine's own fixes: canvas, WebGL, SVG and text measurements that no longer
  disagree with each other, form error messages in the profile's language,
  clicks that reach embedded frames on mobile profiles, and proxy logins with
  special characters. The new engine downloads once, the first time the
  launcher starts after the update; profiles keep their data.
- A profile that is still starting (a slow proxy check, a geo lookup) can be
  cancelled from the same button before its browser opens.
- The SDKs (Node, Python, Rust) are 2.1.0: they read this fork's engine
  manifest, carry upstream's `Motion` wrappers for human-like pointer, keyboard
  and touch input, keep WebGPU on desktop Linux profiles, and can claim a
  display refresh rate when creating a profile.

### Fixed

- Human clicks and typing over CDP. The engine only answers its `Motion` domain
  when launched with `--shardx-automation`, which this launcher never passed, so
  the MCP `human_click` and `human_type` tools failed on every profile. The
  earlier conclusion that the engine lacked the domain came from a probe with
  the same omission; the probe now uses the launcher's own switches.
- A failed engine download no longer leaves the computer with no browser. The
  new engine is unpacked beside the old one and swapped in only when complete,
  and a swap cut short is undone at the next start.
- The launcher window no longer stays blank on a network that accepts
  connections but never answers (#114 upstream): the engine manifest check
  gives up after a few seconds.
- A profile whose browser is still open is no longer shown as idle on Windows
  (#109 upstream). Chromium can hand a launch to another process and exit; the
  launcher now follows the profile's own lock, keeps Stop working, keeps its
  proxy relay open, and refuses to start a profile already open in a browser it
  did not start.
- One unreadable byte in `settings.json` no longer wipes your settings. The
  launcher runs on defaults for that session, says so in Settings, and refuses
  to write over the file — it held where your profiles live and the API key.
  Files saved by PowerShell with a byte-order mark or as UTF-16 now read.
- A profile without its own window size opens inside the screen it claims
  instead of filling the real monitor (#67 upstream), and a screen that fits the
  monitor is kept on Windows and Linux rather than replaced by the monitor's.
- A SOCKS5 proxy that accepts the sign-in but cannot reach the internet now
  fails its test; the test used to stop after the greeting. The whole test is
  also bounded.
- A profile with no proxy goes direct instead of through whatever proxy the
  operating system is set to, which disagreed with the timezone and location
  worked out for it. A proxy named in the global extra arguments still wins.
- A UDP check that fails keeps QUIC and proxied WebRTC off, instead of trusting
  an older passing result.
- Starting with CDP waits up to 30 seconds for the debugging address, not six.
- The automation Wait step takes its delay from a variable (#66 upstream).
- Pasting from an empty clipboard says the clipboard is empty instead of
  showing a system error.
- Updating a proxy's password through the API updates the proxy the profile is
  bound to, and proxies that differ only by password or scheme are no longer
  merged on import (#72 upstream, from upstream PR #85 by aleekaz).
- Labels that were still English: the profile row's Starting and Cancel states,
  thirteen busy labels in Settings, Team and ProxyShard cards, and a profile
  store toast.
- The macOS menu bar icon follows the light and dark bar.

### Security

- `zip` 9.0.5 replaces 2.x in the launcher and the Rust SDK (RUSTSEC-2026-0367,
  -0368, -0369: extraction could follow symlinks out of the destination or keep
  SUID bits). The engine archive extracts byte-for-byte as before.
- `quinn-proto` 0.11.19, `rustls` 0.23.46, `rustls-webpki` 0.103.16 and
  `webpki-roots` 1.0.10 in the launcher and the team server, for the advisories
  published after 2.2.10.
- The Rust SDK's minimum Rust version is now 1.88, the oldest `zip` 9 builds
  on; no `zip` release below 9 carries the fix.
- npm advisories published since 2.2.10 are patched in every package. The
  MCP server moves to `@modelcontextprotocol/sdk` 1.32.1, with `proxy-addr`,
  `hono`, `ip-address` and `fast-uri` on fixed releases; the Node SDK takes
  `ip-address` 10.7.4. Build tooling: `vite-plugin-dts` 5 for the UI kit's
  type declarations (output unchanged apart from quote style), and
  `@parcel/watcher` 2.6.0 under the Tailwind CLI, which drops the vulnerable
  `micromatch`/`braces` chain.
- The release audit ignores the same three advisories for the `zip` 4 that
  `tauri-plugin-updater` still pulls: the updater extracts only payloads whose
  signature it has already checked, and this launcher's Windows payload is not
  a zip. A check fails the release if any other crate brings in a `zip` below 9.

### Internal

- The locale guard also reads labels chosen by a condition and messages passed
  straight to a toast; that rule found the thirteen labels above.
- Engine probes can run against a candidate engine before it is installed
  (`SHARDX_TEST_ENGINE`); the whole engine suite passed on Chromium 156.
- Python bytecode caches are no longer tracked in Git.

### Credits

Ported or adapted, all MIT-licensed like this fork: ProxyShard/ShardBrowser
v2.0.2–v2.1.0 (Chromium 156 manifest, settings protection, window from screen,
CDP wait, lock check, cancel-start, proxy checker, clipboard, tray icon, SDK
Motion wrappers); aleekaz (upstream PR #85, proxy duplicate check);
CarterLeeAlt/ShardBrowser (`--no-proxy-server` for direct profiles, UDP fail
closed, block quitting while browsers run); phuducnguyen/ShardBrowser (engine
replaced by rename).

## v2.2.10

### Fixed

- The last two English labels in the interface, both in the extension picker's
  empty state: the line saying the library holds nothing yet, and the link that
  offers to add one. Anyone whose library is empty opens the profile editor and
  reads them, so on a fresh install they were the first English on the screen.
- A button on each fingerprint card that still read "Use" in English. It sat on
  a screen that was otherwise translated, which made it look like a mistake
  rather than a choice.
- The check for untranslated interface text now sees two shapes it used to walk
  past: a label decorated with an arrow, and a sentence whose trailing spacing
  expression made the line look like code to the check. Both labels above hid in
  exactly those blind spots, so each fix came with the rule that would have
  caught it.

## v2.2.9

### Fixed

- Four small labels that stayed English through a release that translated every
  screen around them: the sidebar's API pill, the patch log's version marker and
  its locked badge, and the tags on each patch log entry. They were written into
  the code rather than read from a translation file. An entry tag's colour still
  comes from the value stored with the entry, so translating the label changes
  what you read without changing what you see.
- The check for untranslated interface text no longer walks past short labels.
  One rule wanted a leading capital, so a lowercase badge was invisible to it;
  another wanted two letters before the text began, so a pill sitting between
  its tags on one line slipped through. The check now reads the line above to
  tell a label someone reads from a setting the code passes along.
- A slow asset upload no longer fails a release that already published. Version
  2.2.7 uploaded all twenty of its files and still reported failure: one file
  stalled for 148 seconds of a 197 second step, and the error arrived after the
  work was done. The upload is now retried once, and the action that performs it
  is pinned to an exact revision rather than a moving tag. A retry replaces what
  the first attempt sent, so nothing uploads twice, and a release that genuinely
  cannot publish still reports failure.

## v2.2.8

### Added

- The launcher speaks Vietnamese. Every screen, menu, button, toast and error
  message now comes from a translation file rather than being written into the
  code, and the language is chosen in Settings under Language. The choice
  survives a restart. Nothing about a profile changes with it — the interface
  language is not part of a browser's fingerprint.
- A profile can be driven through a scripted list of steps, and a probe reports
  whether a profile's GPU story is internally consistent.

### Fixed

- Errors raised by the engine reach the operator in their own language. A
  command that failed used to answer in English no matter the setting, because
  the message was built in Rust and handed straight to the toast. Roughly
  twenty groups of them were moved across: profiles that will not start,
  proxies, extensions, backups, cookies, the database, the automation runner,
  the graphics probe, engine download and migration.
- Toasts no longer show raw error markers. Twelve of them printed an internal
  code beside the message, which told the operator nothing and hid the part
  that mattered.
- Menu entries and dialog questions that were still English are translated.
  Three profile-menu items, two confirm questions and one Settings button had
  been missed because the guard that looks for untranslated text could not see
  a label ending in `…` or `?`, nor a button whose label is a single word.
- The patch log reads in Vietnamese, and the paths it tells you to click match
  the labels actually on screen. Four of them named Settings cards by a name
  the interface never used, so the instruction pointed at nothing.

### Internal

- The translation guard covers the shapes that hid real text: labels ending in
  punctuation, single-word buttons, prose in a plain `.ts` module, text frozen
  at import time, and instructions that quote an interface label. Each rule was
  checked by breaking it on purpose and confirming the suite fails.
- CI checks Rust formatting and runs Clippy.

## v2.2.7

### Fixed

- The profile and proxy tables no longer run past the right edge of a narrow
  window. On a portrait monitor the content column is about 780px wide, but
  the narrowest layout still asked for 904px, and the table clipped the
  overflow instead of scrolling it — the Start button and the row menu were
  simply unreachable. Narrow windows now drop the columns that repeat
  elsewhere, and anything still too wide scrolls rather than disappearing.
- Column headings line up with their rows again below 1280px. The Last run
  cell was hidden in the rows but not in the heading, so every heading after
  Notes sat above the wrong column.

## v2.2.6

### Added

- The patch log can be reopened from Settings, under What's new. The launcher
  shows it once after an update and records the version, so closing the page
  put the notes out of reach — awkward when the update lands mid-task, or when
  somebody else installs it on a shared machine. The sidebar's Patch log entry
  already led there; the button puts a door where people go looking.

## v2.2.5

### Added

- A profile's session restore can be turned on and off from the profile editor,
  under Privacy. Automation profiles accumulate tabs nobody closes, and
  reopening all of them on every launch costs time for no gain. Profiles
  without the setting keep restoring, exactly as before.

### Fixed

- The Shard Helper panel no longer deadlocks the launcher on Windows. Building
  the webview from a synchronous command occupied the message loop WebView2
  itself needs, so the panel came up blank and the whole window stopped
  responding.
- A browser that exits no longer leaves a phantom "Running" row behind. The
  bookkeeping that runs at exit could fail (a profile that is missing or has
  unreadable JSON) and abandon the tracker entry, stranding a Stop button that
  could never clear because the process it referred to was already gone.
- Pressing Stop on a row whose browser has already exited clears that row and
  says so, instead of doing nothing.
- Losing contact with the backend surfaces an error and empties the running
  list after three consecutive failures, rather than freezing the last known
  state on screen indefinitely.
- Starting or stopping several selected profiles at once reports what failed.
  Both paths discarded every error, so ten selected profiles yielding three
  browsers looked exactly like success.
- Closing every window in a sync group clears that group's state. Suspension,
  layout, and driving-member records were keyed by group name and outlived the
  group itself, so a new browser joining under a previously suspended group
  name arrived suspended with nothing on screen to explain why.
- `rustls` is updated to 0.23.45 in the launcher and server lockfiles, clearing
  RUSTSEC-2026-0285.

## v2.2.4

### Changed

- The Rust SDK is tested on Windows and macOS. Its host probes and runtime
  layout branch on the operating system, and those branches were compiled but
  never exercised anywhere: the crate reported `0 tests` while passing.
- The SDK's suite runs in the release build on all three platforms, so a
  platform-specific fault blocks publishing instead of reaching an installer.

### Fixed

- The SDK's display parsing rejects malformed geometry instead of accepting it.
  Twelve unit tests now cover screen and memory probing, the archive and
  executable layout for each platform, and the cache directory each one uses.
  Each assertion was verified against a deliberately broken build.

## v2.2.3

### Fixed

- Snapshot restore is verified correctly on Linux and macOS. Two round-trip
  tests asserted that a restored profile contains `Local State`, which
  snapshots deliberately exclude because the key it holds is bound to one
  machine. The file reappeared on Windows only because the key lives there and
  is minted on first read, so a Windows-specific side effect was being
  asserted as a cross-platform rule.

### Changed

- The Rust crates are tested on Windows in CI. Every runner was Linux, so the
  `cfg(windows)` half of the codebase — os_crypt key handling, cookie
  decryption, process control and autostart — was never compiled or tested
  there, on the launcher's primary platform.
- The shared core's tests and the interface toolkit's lint run in CI. The
  shared core is linked into the launcher, yet its tests had never run: a
  crate compiled as a dependency is not tested by its dependent.
- A release stops on a missing changelog section before any installer is
  built, rather than after all three platform builds finish.
- The interface toolkit is free of lint warnings. The theme and link contexts
  moved out of their provider modules so those files export components only,
  which restores state-preserving refreshes during development. The package's
  public API is unchanged.

## v2.2.2

### Security

- The release gate audits every lockfile that ships. It previously covered
  five of eight: `ui-kit` is compiled into each bundle by the prebuild step,
  `shared` links into the launcher as `shardx-core`, and `server` is
  published as a release asset, yet none of the three were scanned.
- `event-listener` and `spin` are updated in the team server, clearing an
  unsoundness advisory and a yanked release.
- RUSTSEC-2023-0071 (`rsa`) has no fixed release and is exempted with the
  reasoning recorded in the workflow: `rsa` enters the lockfile only through
  the `sqlx` MySQL feature, which the server does not enable, and a release
  build emits no `rsa` artifact. The exemption lapses if a MySQL backend is
  ever switched on.

## v2.2.1

### Security

- The Node SDK no longer bundles `adm-zip`, which followed archive entries
  that escape the extraction directory and let a crafted archive overwrite
  arbitrary files (GHSA-vwc7-r8mq-g2x9). No patched release exists: 0.6.0 is
  the newest version, and the automated fix downgrades to 0.5.8, which
  carries a high-severity 4GB-allocation advisory instead.
- Windows now extracts runtime archives with bsdtar (`tar.exe`, shipped
  since Windows 10 build 17063); macOS and Linux continue to use the system
  `unzip`. Neither writes outside the destination directory.
- `hono` is pinned past three advisories that reached the MCP package
  through the Model Context Protocol SDK.

### Release integrity

- The release workflow verifies every updater signature in the generated
  manifest before uploading it, so a manifest that would fail auto-update
  cannot be published.

### Continuous integration

- CI runs the Node SDK tests, which previously ran only during a release.

## v2.2.0

### MCP host

- Settings now leads with **Check Hermes registration**. Hermes is the
  primary MCP host for this fork, so its check is the primary action and
  the Codex check moves under Advanced actions.
- A new Hermes probe reads the resolved entry from
  `hermes config get mcp_servers.shardbrowser` and compares it against the
  selected `index.js` path and the running Automation API URL. It reports
  only whether `SHARDX_TOKEN` is present, never its value.
- The Codex repair copy is always available under Advanced actions. It was
  previously hidden whenever it duplicated the primary action, which would
  have left a broken Codex entry with no way to copy its repair command.

### Documentation

- `mcp/README.md` documents Hermes registration and maps each reported
  state to the action that resolves it.

## v2.1.2

### Patch log

- Ships the 2.1.0 and 2.1.1 patch log entries, which landed on main after the
  2.1.1 tag was cut. Without this release the installed app badges 2.0.1 as
  the latest entry and records nothing about the two releases since.

## v2.1.1

### Launcher

- An engine install now stops before deleting anything when a profile still
  has the browser open, and names the profiles it is waiting on. Replacing a
  held-open engine previously left it half written, which made the setup
  screen reappear on every launch.
- Settings offers **Use existing MCP folder** beside the download button, so
  the launcher can adopt an MCP server you already have instead of
  downloading a second copy.
- A running profile's window can be raised when a site is waiting on a human
  check.
- The Ctrl K search shortcut hint no longer wraps onto two lines.

## v2.1.0

### Team and profiles

- A device can be enrolled with a team server to sync encrypted profiles
  between machines.
- Profiles can be backed up and restored as ciphertext, keyed to your fleet.

### Engine

- The launcher checks the published engine hash before deciding an update is
  needed, so the pinned manifest decides rather than a version string.

## v0.2.4

### Root key custody

- Tenant root keys now have a recorded lifecycle. A generation is created in
  `PREPARING`, is activated only once its first grant exists, and grants are
  refused unless they name a generation that exists, is not retired, and
  wraps that generation's key.
- The first grant for a generation must be a `FirstRootSelfGrant`, and a
  second one is refused. Custodian-issued grants are only accepted afterwards,
  so a tenant cannot end up with two competing roots.
- Enrolled devices keep the HPKE private key generated during enrollment.
  Previously it was discarded, so a device could be sent a wrapped root key it
  could never open. Devices enrolled before this change are reported as unable
  to receive custody, and Settings says so rather than failing later.
- The Launcher can collect and open its own grants (`team_collect_custody`).

### Releases

- Releases now ship `shardx-team-server-<platform>` for all three platforms.
  The grant and generation endpoints are server-side, so earlier releases
  delivered them as source only. The release job fails if a server binary is
  missing rather than publishing an incomplete set.

### Note on scope

Profile sync still derives its file key from a passphrase. Moving sync onto
fleet keys needs the fleet key generation and grant tables that the plan
specifies, which are not built yet; the root key work here is the layer
underneath that. This release is not production-ready.

## v0.2.3

Tenant root key grants are stored and retrievable, and a class of silently
swallowed database errors is closed.

### Key custody

- `POST /v2/tenant-root-key-grants` now stores the grant it verifies. It
  previously checked the signature and discarded the payload, so
  `v2_tenant_root_key_grants` never held a row and a second device had no way
  to obtain the tenant root key.
- Add `GET /v2/tenants/:tenant/devices/:device/root-key-grants` to collect a
  device's sealed grants. Storing grants without a way to read them back would
  not have moved custody forward.
- Grant fields are read from the signed field map rather than the request body.
  A caller who could pair another issuer's signature with their own account and
  device ids would redirect the custody that signature authorises.
- The collection route derives tenant membership from the session, not the
  path, matching the fix in #21.
- `seal_trk` and `open_trk` now have a runtime caller and end-to-end coverage:
  a grant is sealed, filed, collected, and opened with the device's private key
  to recover the original root key.

### Replay ledger

- Fix a silent failure in `v2_replay_ledger`. Its `record_table` CHECK omitted
  the root key grant table, and because the claim uses `INSERT OR IGNORE`, the
  violation was indistinguishable from a duplicate key: zero rows affected,
  reported as "already used". Every grant was refused as a replay of a record
  that had never been stored, and grants had no replay protection at all,
  because no ledger row was ever written.
- Migration `0005` widens the constraint while preserving existing rows.
  Rebuilding the ledger empty would let every previously consumed record be
  presented again.
- The claim now confirms the row exists before reporting a replay, and the
  operation ledger reports the same class of fault instead of failing with an
  unexplained database error.

### Notes

Grants must still be filed by an external custodian. Nothing generates a tenant
root key, seals it to a newly enrolled device, or implements the root
generation lifecycle and recovery bundle, so profile sync continues to use a
passphrase-derived key. See `docs/key-custody.md`.

This release is not production-ready: the P-OP gate is unmet, and key custody
lifecycle and recovery are incomplete.

## v0.2.2

Enrollment and profile sync reach the shipped binary, plus the tenant-boundary
fix from #21.

### Device enrollment

- Add `POST /v2/devices/enrollment-challenges` and
  `/v2/devices/enrollment-proofs`. The server issues a nonce bound to a key
  commitment and verifies the device holds the key it claims; registering a
  public key without proof would let a caller enroll a key they cannot use.
- Store the challenge nonce hashed and consume it once, so a captured proof
  cannot be replayed.
- Add `shared::enrollment_proof`: one canonical encoding for both sides. The
  manifest format had already shown what happens when a wire format is defined
  in two places.
- Add Team settings for server URL and token, with device key material in its
  own `team.json` so an unrelated settings save cannot destroy device identity.
  The status command never returns the token or any key.

### Profile sync

- Wire the fleet client to the Launcher: `profile_sync_push`,
  `profile_sync_pull` and `profile_sync_status`, with push and pull in the
  profile menu on an enrolled device. The client shipped in v0.2.1 with no
  caller, so the linker dropped it — `/v2/fleet/uploads` was absent from the
  binary. It is present now.
- Sync uploads the same sealed container a local backup writes; the server
  stores ciphertext, a digest and a version, and holds no key.
- Enrollment now returns the account id the server assigned. Fleet routes are
  account-scoped and the client cannot infer that id, so a device enrolled
  before this change reports `can_sync: false` and must re-enroll.
- Both sync commands check running state before configuration, so a user with a
  running browser is told to close it rather than sent to fix server settings.

### Security fix: tenant boundary on every fleet route

Eight `/v2/` fleet handlers took `tenant_id` from the request and never checked
the caller belonged to it. Any authenticated user could lease, upload to or
download from any tenant. All eight now call `require_tenant_member`; the
regression test receives `201 Created` before the fix and is refused after it.

`AuthUser` carries no tenant, so at each individual call site an authentication
check looked sufficient. It was not.

### Documentation

- `docs/v1-authorization-audit.md` — every v1 route checked for the same flaw;
  none has it, and the one route that resembles it is explained rather than
  left for a future reader to re-derive.
- `docs/key-custody.md` — how profile keys are held, why sync currently needs a
  shared passphrase, and what is missing before per-device key wrapping works.
  The tenant root key machinery exists in `shared/src/grants.rs` but has no
  caller, and `POST /v2/tenant-root-key-grants` verifies a grant and then
  discards it.

### Still not production-ready

The `P-OP` gate remains blocked: no independent verifier, no full product-flow
or downgrade drill, and no two-device destructive verification.

## v0.2.1

First v0.2.x release with installable artifacts. v0.2.0 was tagged but its
release build failed before producing any, so it stays a prerelease with no
downloads; v0.1.29 remained the latest installable version. Nothing about the
v0.2.0 tag is changed or moved.

- Fix the release build: `npm audit --audit-level=moderate` failed the
  validation job on a high-severity `browserslist` advisory, so no build or
  publish step ever ran. Updated to 4.28.8; all three npm workspaces are clean.
- Read the MCP contract version from `package.json` rather than a literal, so
  a version bump no longer fails a test that exists to guard the tool contract.

### Fleet transfer client and a commit-path authorization fix

Adds the `/v2/` client from #17 and fixes a server flaw the work exposed.

- Add `shared::fleet_manifest`: one definition of the signed snapshot manifest,
  used by both the client that signs and the tests that verify, so the two
  cannot drift into a format only one side accepts.
- Add `fleet_client` in the Launcher: lease, chunked upload, signed commit and
  ranged download. The lease is released on every path, a failed upload aborts
  its staging session, and a download that stalls is an error rather than a
  silent truncation.
- Add `GET /v2/server-identity`. A client must bind its signed records to the
  live `server_instance_id` and `restore_epoch`; without this endpoint it could
  only guess them.
- **Security fix.** `/v2/fleet/uploads/commit` verified the manifest signature
  and then trusted the request body for `container_sha256`, `profile_id`,
  `snapshot_id`, `fleet_id`, `base_version` and `key_generation`. A caller with
  a valid token could present a genuine manifest signed for one snapshot and
  publish different bytes under it. The handler now rejects any body that
  contradicts the signed manifest, covered by a regression test that publishes
  version 1 when the check is removed.

`fleet_client` has no UI caller yet: that needs device enrollment, which the
server does not expose an endpoint for. #17 stays open.

### Encrypted profile backup, wired into the Launcher

Closes the gap recorded in #17: v0.2.0 shipped the sealing library and the
fleet server, but nothing in the app could reach them. `shared::backup` now has
a production caller.

- Add `shared::passphrase`: Argon2id (64 MiB, 3 passes) derivation of the
  backup FKEK from a user passphrase. Nothing is persisted but a random salt,
  so a backup opens on a machine that has never seen the source.
- Add `shared::backup_file`: `create`/`restore`/`inspect` over a self-contained
  `.shxbak` file (magic, salt, verifying key, sealed container). Written via a
  temp file and renamed, so an interrupted backup cannot replace a good file
  with a truncated one.
- Add Tauri commands `profile_backup_create`, `profile_backup_restore` and
  `profile_backup_inspect`. Both mutating commands take the same
  `begin_user_mutation` claim as delete/clone: a backup of a running profile is
  torn, and a restore under one corrupts it.
- Add "Back up (encrypted)" and "Restore from backup" to the profile menu, with
  a passphrase prompt that requires confirmation on backup and warns that a lost
  passphrase makes the backup unreadable.

Restore recovers and authenticates the whole container in memory before
`snapshot::unpack` touches the profile. `backup::open` streams authenticated
frames and only detects truncation at the signed head, so an in-place restore
could otherwise leave a profile that looks complete and was never verified.

## 0.2.0 - 2026-09-02

> Scope: this release adds a library and a server. It is not wired into the
> app — `shared::backup::{seal, open}` has no production caller, and the
> Launcher exposes no backup, restore, fleet or sync command. The entries
> below describe implemented and tested building blocks, not user-facing
> features.

### Team/fleet control plane (new)

- Add `shared/src/grants.rs`: RFC 9180 HPKE (DHKEM-X25519 / HKDF-SHA256 /
  ChaCha20Poly1305) tenant root key grants. The grant scope — tenant, fleet,
  profile, snapshot, key generation, recipient device — is bound as AEAD
  associated data, so a grant cannot be replayed under a different scope.
  Sealing uses the OS CSPRNG.
- Add the v2 control-plane schema (`0004_v2_team_fleet.sql`), additive over v1.
  Tenant-scoped rows join their parent by composite `(tenant_id, id)` foreign
  key, so cross-tenant references are rejected by the database rather than
  relying on every query remembering to filter. One-shot records are claimed
  through a UNIQUE index.
- Add signed authorization records: a request must carry a record binding the
  action to this domain, tenant, server instance and restore epoch, signed by
  an issuer the tenant trusts.
- Add replay rejection and idempotent retries: a record is consumable once, and
  a completed operation replays its exact original response bytes.
- Add `/v2/device-approvals`, `/v2/capability-grants`,
  `/v2/tenant-root-key-grants`, `/v2/operations/complete`. The server files
  root key grants without being able to read them — the payload stays sealed
  to the recipient device.

### Encrypted profile backup (new)

- Add a v2 encrypted backup container: streaming ChaCha20-Poly1305 frames over a
  wrapped per-snapshot DEK, with an Ed25519-signed head record.
- Add `shared/src/canonical.rs`: deterministic canonical CBOR encoding with
  strict rejection of non-canonical input, so signed bytes cannot be re-encoded
  into a different-but-accepted form.
- Add `shared/src/keys.rs`: key identities (`root_key_id`, `signing_key_id`) and
  DEK wrap/unwrap bound to a canonical slot context as AEAD associated data.
- Add `shared/src/signing.rs`: domain-separated signing over a length-prefixed
  transcript, with an acyclic commitment structure (the signature is not part of
  its own signed payload).
- Add `shared/src/envelope.rs`: DEK slots, pre-encryption intent records, STREAM
  frame nonces/AAD, and the restore-epoch Merkle tree with inclusion proofs.
- Add `shared/src/backup.rs`: the `seal`/`open` container API joining the above.

### Format guarantees

- Frames bind the exact envelope intent, frame counter, and final-frame flag, so
  truncation, reordering, and cross-envelope splicing all fail closed.
- The prologue is bound to the signed head, so slot/intent substitution before
  the signature check is rejected.
- Every single-byte mutation of a container is detected (exhaustive test).
- Merkle leaves enforce ordering, reject duplicates, and use domain-separated
  leaf/node hashing; unary promotion is only legal at an odd tail.

### Compatibility

- The v1 portable snapshot format is unchanged: `snapshot::pack`/`unpack` keep
  their existing behaviour and byte format.
- The v2 container wraps a v1 snapshot losslessly — sealing then opening returns
  the exact v1 bytes, which still restore through the v1 reader.
- The v1 reader rejects a v2 container rather than misparsing it.
- The MCP tool contract is unchanged at 96 tools.

### Notes

- `open` streams plaintext as it is decrypted, so its output must be treated as
  untrusted until the call returns `Ok`; this is a deliberate trade-off to keep
  memory bounded on large profiles. Callers restoring to disk should write to a
  staging path and promote only on success.
- Fleet sync transfer operations are not implemented in this release: the
  schema and authorization exist, the upload/download path does not.

## 0.1.29 - 2026-08-28

### Process ownership

- Assign an opaque in-memory UUID to every API-launched browser and require the exact profile, PID, and launch-instance token for conditional cleanup.
- Disable the legacy PID-only conditional stop endpoint with HTTP 410 so recycled numeric PIDs cannot stop replacement processes.
- Keep launch-instance tokens out of running-profile inventory, persistence, logs, API errors, and public MCP results.

### MCP lifecycle

- Preserve the page opened by `safe_open_url` as the active target for follow-up tab, screenshot, ARIA, and network tools.
- Preflight Launcher ownership capability before spawning a stopped profile and fail closed when CDP startup, restoration, or launch-instance ownership cannot be verified.
- Restore the profile state owned by `safe_open_url` without PID-only retries; stale-process cleanup is now inventory-only.

### Release integrity

- Enforce exact MCP archive-entry equality across staging, raw tar inspection, and extracted payload verification.
- Reject missing, extra, duplicate, nested-extra, symlink, non-regular, unsafe-root, and malformed release-staging inputs before publication.
- Preserve the 96-tool MCP contract, startup-in-tray behavior, signed updater flow, and existing headless automation compatibility.

## 0.1.28 - 2026-08-14

### Rust SDK

- Update the crate-level quickstart doctest to create a `Profile` before calling `ShardX::session`.
- Gate the CDP-control doctest and `quickstart` example behind the existing `control` feature so `--no-default-features` remains buildable.
- Upgrade `dirs` from 5 to 6 and `rand` from 0.8 to 0.9 after isolated default-feature, no-default-feature, and Rust 1.74.1 compatibility checks.
- Keep `chromiumoxide` 0.7, `reqwest` 0.12, and `zip` 2 because their current release lines are RustSec-clean while the next majors exceed the SDK's Rust 1.74 MSRV.
- Add stable, RustSec, and Rust 1.74.1 SDK gates to CI and release validation so vulnerable dependency graphs, doctest failures, feature-minimal regressions, and MSRV breaks cannot bypass packaging.

## 0.1.27 - 2026-08-13

### Security

- Resolved the current npm audit findings in the Launcher, MCP server, and Node SDK dependency graphs with compatible patch-level updates.
- Added a Node SDK archive extraction regression test for nested Windows paths and Unicode fingerprint bundles.

### Profile safety

- Reject profile mutations while the browser is running or while launch/exit cleanup owns the profile lifecycle.
- Serialize concurrent profile-name allocation and mutation while preserving unrelated profile launches.
- Validate profile names consistently across UI, API, create, edit, clone, and batch import paths.
- Reject unsafe Windows names, separators, control characters, overlong names, and case-insensitive collisions.
- Fail closed when profile inventory contains an unreadable or malformed record.
- Persist profile records with atomic replacement and report folder-operation write/delete failures instead of returning false success.

### Compatibility

- Preserve the 96-tool MCP contract, startup-in-tray behavior, signed updater flow, and existing headless automation compatibility.
- Defer SQLite/WAL dependency migration to the Team/Fleet Sync and encrypted-backup development line because the current server does not enable WAL.
