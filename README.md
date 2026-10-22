<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/shardx-logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/screenshots/shardx-logo-light.png">
    <img src="docs/screenshots/shardx-logo-light.png" alt="ShardX" width="460">
  </picture>
</p>

<h1 align="center">ShardX Launcher</h1>

<p align="center">
  <strong>A free, open-source anti-detect browser launcher for web scraping and multi-accounting.</strong><br>
  Patched Chromium 156 with engine-level fingerprint spoofing, a local API, an MCP server and SDKs.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"></a>
  <a href="https://github.com/ProxyShard/ShardBrowser/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/ProxyShard/ShardBrowser?style=flat-square&logo=github&label=release&color=blueviolet"></a>
  <a href="https://github.com/ProxyShard/ShardBrowser/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/ProxyShard/ShardBrowser?style=flat-square&logo=github&label=stars&color=lightgrey"></a>
  <a href="https://github.com/ProxyShard/ShardBrowser/commits"><img alt="Last commit" src="https://img.shields.io/github/last-commit/ProxyShard/ShardBrowser?style=flat-square&color=success"></a>
</p>

<p align="center">
  <a href="https://pypi.org/project/shardx/"><img alt="PyPI version" src="https://img.shields.io/pypi/v/shardx?style=flat-square&logo=pypi&logoColor=white&label=pypi&color=blue"></a>
  <a href="https://www.npmjs.com/package/@proxyshard/shardx"><img alt="npm version" src="https://img.shields.io/npm/v/@proxyshard/shardx?style=flat-square&logo=npm&logoColor=white&label=npm&color=red"></a>
  <a href="https://crates.io/crates/shardx"><img alt="crates.io version" src="https://img.shields.io/crates/v/shardx?style=flat-square&logo=rust&logoColor=white&label=crates.io&color=orange"></a>
  <a href="https://docs.rs/shardx"><img alt="docs.rs" src="https://img.shields.io/docsrs/shardx?style=flat-square&logo=docsdotrs&logoColor=white&label=docs.rs"></a>
</p>

<p align="center">
  <a href="#what-it-is">Overview</a> ·
  <a href="#launcher-features">Features</a> ·
  <a href="#screenshots">Screenshots</a> ·
  <a href="#comparison-with-other-anti-detect-browsers">Comparison</a> ·
  <a href="#quick-start">Install</a> ·
  <a href="#usage">Usage</a>
</p>

ShardX is built by the **[ProxyShard](https://proxyshard.com?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher)** team.
ProxyShard provides full **SOCKS5 UDP relay** support (RFC 1928 §7) and
active **p0f TCP fingerprint spoofing** at the proxy exit. This keeps the
operating system presented by the proxy consistent with the SYN/ACK shape
seen by websites. ShardX is the anti-detect browser stack built to use
those capabilities. The launcher manages profiles, binds proxies and
ships a patched **Chromium 156** build that applies fingerprint changes
inside the browser engine.

<p align="center">
  <a href="https://proxyshard.com?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher"><strong>Website</strong></a> ·
  <a href="https://docs.proxyshard.com?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher"><strong>Documentation</strong></a> ·
  <a href="https://docs.proxyshard.com/eng/usage-instructions/shardx-browser?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher"><strong>Browser guide</strong></a> ·
  <a href="https://docs.proxyshard.com/eng/our-products/about-udp?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher"><strong>UDP relay</strong></a> ·
  <a href="https://docs.proxyshard.com/eng/our-products/p0f-spoofing?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher"><strong>p0f spoofing</strong></a>
</p>

<table>
  <tr>
    <td width="33%" align="center"><strong>Native fingerprinting</strong><br><sub>Blink, V8 and the network stack</sub></td>
    <td width="33%" align="center"><strong>Proxy-native networking</strong><br><sub>QUIC, HTTP/3 and WebRTC over SOCKS5 UDP</sub></td>
    <td width="33%" align="center"><strong>Four control surfaces</strong><br><sub>Desktop UI, HTTP API, MCP and SDKs</sub></td>
  </tr>
</table>

ShardX provides four ways to control the same profiles. They all use the
same local state, so no additional synchronization is required:

* **Desktop UI:** workspace for daily work with profiles, proxies,
  cookies and the fingerprint editor.
* **Local HTTP API:** Bearer JWT authentication on `127.0.0.1:40325`.
  Create, start and stop profiles from any language, then obtain a CDP endpoint.
* **MCP server:** connects ShardX to Claude Desktop, Cursor and other
  MCP clients for natural-language profile orchestration through the
  HTTP API and CDP.
* **Standalone SDKs:** Python, Node and Rust libraries that ship the
  browser engine and run without the desktop UI. They are intended for
  scrapers, CI jobs and servers.

Configuration details are available in [Usage](#usage).

<p align="center">
  <kbd>
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/00-launcher-dark.png">
      <source media="(prefers-color-scheme: light)" srcset="docs/screenshots/00-launcher-light.png">
      <img src="docs/screenshots/00-launcher-light.png" alt="ShardX Launcher with active browser profiles" width="920">
    </picture>
  </kbd>
</p>

---

## What it is

ShardX can run hundreds of isolated browser identities side by side.
Each profile defines a complete device identity, including GPU, screen,
fonts, audio settings, timezone, locale, WebGL and WebGPU capabilities,
TLS ClientHello, UA-CH, WebRTC policy, geolocation and cookies. The
signals within a profile are kept consistent with one another.

Fingerprint changes are applied inside Chromium's C++ engine, including
Blink, V8 and the network stack. ShardX does not rely on JavaScript
injection, so the same values are visible in frames, workers, developer
tools and headless sessions.

The launcher includes 170 ready-made device profiles for Mac M1 to M5,
Windows desktops and laptops with NVIDIA RTX or GTX, Intel, and AMD
GPUs, and Linux workstations. You can bind a SOCKS5 or HTTP proxy to each profile.
The launcher resolves timezone, locale and geolocation from the proxy
exit country. It also manages an isolated `user-data-dir` for each
profile, persistent cookies, Widevine pre-warming and QUIC over the
proxy UDP relay. WebRTC traffic follows the configured proxy policy and
does not expose the host IP.

ShardX is free to use. ProxyShard proxies support end-to-end QUIC and
WebRTC over SOCKS5 UDP relay. Other proxy providers can also be used,
but full QUIC and WebRTC operation requires SOCKS5 UDP relay support.

Verification results and test pages:

| Test                                                            | Result                                                                   |
|-----------------------------------------------------------------|--------------------------------------------------------------------------|
| [browserleaks.com/quic](https://browserleaks.com/quic)          | QUIC `True`, JA4 matches real Chrome, MTU 1232 over SOCKS5 UDP relay     |
| [fingerprint.com](https://fingerprint.com/demo)                 | Bot / VPN / DevTools / browser-tampering all `Not detected`              |
| [browserscan.net](https://www.browserscan.net)                  | Authenticity **100%**                                                    |
| [pixelscan.net](https://pixelscan.net)                          | Fingerprint **consistent**, no proxy / automation detected               |
| [deviceandbrowserinfo.com/are_you_a_bot](https://deviceandbrowserinfo.com/are_you_a_bot) | Browser fingerprinting and CDP bot-detection test          |
| [antcpt.com/score_detector](https://antcpt.com/score_detector/) | reCAPTCHA v3 score **0.9**                                               |
| [networktest.twilio.com](https://networktest.twilio.com)        | TURN UDP / TCP / TLS + Voice. All checks **Pass** with no real-IP leak    |

---

## Fingerprint surfaces patched

All overrides are applied inside the browser engine. There is no
JavaScript shim layer, so the configured values remain consistent in
iframes, web workers, developer tools and headless mode.

* **Device identity:** user agent, platform, vendor, CPU cores, RAM,
  touch points, full Sec-CH-UA stack (brand, version, architecture,
  bitness, mobile, model) with stable GREASE.
* **Graphics:** WebGL renderer / vendor / extensions / limits, WebGPU
  adapter + limits, deterministic per-profile noise for Canvas, DOMRect
  and ClientRects, color gamut and HDR claims.
* **Audio:** sample rate, channel count, optional per-profile noise on
  raw audio samples.
* **Screen & window:** full resolution + available area + DPR + color
  depth, max-size cap so the OS won't resize past the claimed
  dimensions.
* **Locale:** timezone, ICU locale, primary language and the
  Accept-Language header auto-derived from the bound proxy's country.
* **Geolocation:** coordinates set manually or derived from the proxy's
  exit IP. Host GPS and Wi-Fi data are never used.
* **Network capability:** connection type, downlink, RTT, save-data,
  storage quota, JS heap limit, battery state, media-device counts.
* **TLS ClientHello:** Chrome 156 cipher suites and signature algorithms
  with extension shuffling. JA4, Akamai and Peetprint
  fingerprints match the browser version.
* **HTTP-3 over the proxy's UDP relay:** QUIC works end to end through
  SOCKS5. Origin hostnames are resolved by the proxy.
* **WebRTC policy:** `block` / `tcp_only` / `auto`. In `auto`, traffic
  uses the proxy's UDP relay. In the other modes, WebRTC candidates report the
  proxy exit IP, never the host. STUN / TURN targets on private
  networks are dropped.
* **Speech voices:** full per-OS `speechSynthesis.getVoices()`
  enumeration (200+ macOS voices, SAPI + Google for Windows, Google-only
  for Linux).
* **Fonts:** system font enumeration pinned to a per-profile set so
  font-list probes return the claimed device's fonts, not the host's.
* **WebGPU on Linux:** disabled to match what real Linux Chrome
  actually exposes (most distros ship WebGPU off).
* **Google validation headers:** headers added by Google Chrome to
  requests for Google properties are reproduced, including `x-client-data`.
  Its absence is a strong reCAPTCHA bot signal.
* **WebAuthn:** platform-authenticator availability matches the
  claimed device.
* **Hardening:** Widevine pre-warmed per profile, headless markers
  stripped, devtools-protocol side-channels closed, sync hard-disabled,
  no keychain prompts, no Google account telemetry, no Privacy Sandbox
  enrollment data leaked.

---

## Launcher features

* **Profile workspace:** per-profile `user-data-dir`, persistent
  Chrome sessions ("Continue where you left off" without the
  crash-restore bubble), bulk import, folder / tag organization, pin
  to top, clone.
* **Fingerprint library:** 170 starter profiles shipped via CDN
  (31 mac-arm64 / 120 windows-x64 / 19 linux-x64). Profile editor
  randomizes CPU / RAM / platform-version when you change the GPU.
* **Proxy manager:** SOCKS5 / HTTP / HTTPS, bulk paste-import,
  per-proxy live test (TCP + UDP_ASSOCIATE probe + geo lookup), bind a
  proxy to a profile by id or inline-on-launch. Auto-resolves timezone
  / locale / geolocation from the proxy's exit country.
* **Auto-runtime:** first launch downloads the patched ShardX Chromium
  build, Widevine CDM and the fingerprint library from CDN. Widevine is
  placed inside the browser framework. An ETag is stored so later
  launches do not repeat these downloads.
* **Local automation API:** axum HTTP server on `127.0.0.1`,
  Bearer JWT authentication. Full reference at
  [docs.proxyshard.com/eng/shardx-launcher-api](https://docs.proxyshard.com/eng/shardx-launcher-api/binding-and-lifecycle?fallback=true&utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher),
  raw schema in [openapi.yaml](openapi.yaml). Create / start / stop
  profiles and get a CDP WebSocket URL programmatically.
* **MCP server bundled:** connect ShardX to Claude Desktop, Cursor and
  other MCP clients for natural-language profile orchestration.
* **Cookie I/O:** import / export the profile's Chromium Cookies
* **Launch at sign-in** — optional per-user startup entry keeps the
  Launcher and embedded Automation API ready in the system tray.
* **MCP server bundled** — drop into Claude Desktop / IDE for
  natural-language profile orchestration.
* **Cookie I/O** — import / export the profile's Chromium Cookies
  SQLite with v10 (mac / linux) and AES-GCM + DPAPI (win) decryption.
* **Extension library:** paste a Web Store link or extension ID and the
  launcher downloads the `.crx`. Local `.crx` and `.zip` files and unpacked
  folders also work. Extensions can be selected per profile. The grid reads
  the name, version, description and icon from `manifest.json`, including
  localized `__MSG_*__` values from the default locale.
* **Folder bookmarks:** a site linked to a folder appears in the bookmarks
  bar of every profile in it. ShardX rewrites its own `ShardX` folder on each
  launch without changing the user's bookmarks.
* **Per-profile window icon:** each profile gets a platform-specific badge
  with its name. macOS uses a squircle and shadow, Windows uses a full-bleed
  design and Linux uses an Adwaita-style icon with an outline. The badge uses
  the profile color, which is also passed to the browser as
  `--shardx-profile-color`.
* **Trash:** deleting a profile archives its cookies, logins, web data,
  preferences, Local Storage and IndexedDB for 7 days. Caches are excluded,
  so a gigabyte-sized profile can shrink to a few megabytes.
* **Movable data root:** profiles, user data, extensions and trash can be
  stored in any folder or on any disk. The move copies and verifies the data
  before deleting the original, shows progress and prevents profiles from
  launching while it runs.
* **Extra launch arguments:** switches are appended to every profile launch
  and applied last, so they can override the launcher's defaults.
* **Cross-platform:** macOS arm64, Windows x64 and Linux x64. The app uses
  native traffic lights on macOS and a custom title bar elsewhere.

---

## Screenshots

### Network: QUIC + WebRTC over SOCKS5

The QUIC handshake completes end to end through the SOCKS5 UDP relay.
Twilio's UDP, TCP and TLS WebRTC tests pass without exposing the host IP.

| [browserleaks.com/quic](https://browserleaks.com/quic): QUIC `True`, JA4 matches Chrome 152 | [networktest.twilio.com](https://networktest.twilio.com): every probe `Pass` |
|-------------------------------------------------------------|------------------------------------------------------------|
| <kbd><img src="docs/screenshots/01-browserleaks-quic.jpg" alt="QUIC over SOCKS5 UDP relay" width="100%"></kbd> | <kbd><img src="docs/screenshots/04-twilio-webrtc.jpg" alt="Twilio WebRTC network test" width="100%"></kbd> |

### Bot / automation detection

<p align="center">
  <strong><a href="https://fingerprint.com/demo">fingerprint.com</a></strong><br>
  <sub>Bot, VPN, DevTools and browser tampering are not detected</sub>
</p>

<p align="center">
  <kbd><img src="docs/screenshots/03-fingerprint-com.jpg" alt="Fingerprint.com bot detection result" width="880"></kbd>
</p>

<p align="center">
  <sub>Additional fingerprinting test: <a href="https://deviceandbrowserinfo.com/are_you_a_bot">deviceandbrowserinfo.com/are_you_a_bot</a></sub>
</p>

### Fingerprint consistency

| **ProxyShard browser checker:** no issues across 9 categories | [pixelscan.net](https://pixelscan.net): Fingerprint **consistent** |
|-------------------------------------------------------------------|---------------------------------------------------------|
| <kbd><img src="docs/screenshots/02-proxyshard-checker.jpg" alt="ProxyShard browser checker" width="100%"></kbd> | <kbd><img src="docs/screenshots/06-pixelscan.jpg" alt="Pixelscan fingerprint consistency result" width="100%"></kbd> |

### Authenticity score

| [browserscan.net](https://www.browserscan.net): Authenticity 100%, locale honored | [antcpt.com](https://antcpt.com/score_detector/): reCAPTCHA v3 score **0.9** |
|-----------------------------------------------------------|------------------------------------------------------------|
| <kbd><img src="docs/screenshots/05-browserscan.jpg" alt="Browserscan authenticity score" width="100%"></kbd> | <kbd><img src="docs/screenshots/08-recaptcha-score.jpg" alt="reCAPTCHA v3 score" width="100%"></kbd> |

---

## Comparison with other anti-detect browsers

All three products use patched Chromium builds. The table compares
fingerprint coverage, network behavior and the tools provided around
the browser engine.

| Feature                                                       | ShardX (this project)        | CloakBrowser                 | Multilogin / AdsPower / Dolphin                |
|---------------------------------------------------------------|------------------------------|------------------------------|------------------------------------------------|
| WebGPU spoofing (`navigator.gpu` adapter + every limit)       | ✅ full                       | ❌ untouched, host GPU leaks | ✅ full                                         |
| Client Hints (Sec-CH-UA-* full stack with GREASE)             | ✅ full                       | ❌ partial / inconsistent     | ✅ full on Multilogin / AdsPower, ❌ Dolphin     |
| Font enumeration pinned per profile                           | ✅ system-level               | ❌ JS-only, host fonts still leak via CSS / canvas font-render | ⚠️ partial          |
| V8 / CDP side-channel hardening (preview-getters, inspector)  | ✅ closed                     | ❌ open, CDP automation detectable | ⚠️ partial                                |
| TLS ClientHello fingerprint (JA4)                             | ✅ matches real Chrome 156    | ⚠️ static, may drift after browser updates | ✅ matches the forked Chrome version            |
| QUIC / HTTP-3 over SOCKS5                                     | ✅ stable end to end via UDP relay | ⚠️ unstable, falls back to TCP or drops mid-session | ❌ disabled when proxy is set |
| WebRTC over SOCKS5 (no real-IP leak via STUN)                 | ✅ proxy UDP relay or synth candidates | ⚠️ same UDP relay path, same instability | ⚠️ disable-only            |
| Consistency of generated profiles                             | ✅ coherent device (GPU, CPU, RAM, UA and fonts) | ❌ frequent contradictions (Win UA + Mac GPU, mobile UA + desktop screen, etc.) | ⚠️ varies |
| Bundled fingerprint library                                   | 170 profiles from real-device samples | ❌ random generator, may combine a Windows UA with a Mac GPU or a mobile UA with a desktop screen | catalog (subscription) |
| Pricing                                                       | **Free**, proxy costs only   | **Free**, engine only        | Paid / freemium                                |
| Management UI                                                 | ✅ desktop app (this launcher) | ⚠️ CLI only, manual profile management | ✅ desktop app                |
| Launcher source                                               | **Open** (MIT, this repo)     | **Open** (CLI)                | Closed                                         |

### Why this matters in practice

Public browser checkers such as fingerprint.com, pixelscan.net,
browserscan.net, [deviceandbrowserinfo.com](https://deviceandbrowserinfo.com/are_you_a_bot)
and antcpt test only part of the browser fingerprint. An anti-detect
browser can pass these checks while still
exposing inconsistent values on surfaces that are not tested there.

Production anti-fraud systems inspect these additional surfaces.
Inconsistencies can cause an account to be flagged after several
sessions even when the initial public checks passed:

* `navigator.gpu.requestAdapter()` returns the **host** GPU on
  CloakBrowser, so a profile claiming an RTX 4060 on Windows leaks the
  Mac M-series adapter underneath. ShardX (and the paid anti-detects)
  return the claimed GPU with full WebGPU limits.
* CDP wrappers, V8 inspector preview-getters and `Object.toString`
  side-channels remain exposed on CloakBrowser and are only partially
  handled by some paid anti-detects. ShardX patches the documented side
  channels so they do not expose automation.
* Font lists scraped via canvas font rendering or
  `document.fonts.check()` return the **host** font list on
  CloakBrowser no matter what the profile claims. ShardX pins the font
  enumeration at the system level so the result matches the device.
* CloakBrowser's profile generator routinely emits incoherent
  fingerprints (Win32 platform with macOS user-agent, mobile UA with
  1920×1080 screen, RTX GPU with `hardwareConcurrency=2`). ShardX's
  library is derived from real-device samples so every signal agrees
  with the others.
* QUIC and HTTP/3 over SOCKS5 are increasingly important because major
  Google properties do not always fall back to HTTP/2 cleanly. The paid
  products listed in the table disable QUIC when a proxy is configured.
  CloakBrowser provides UDP relay support, but the connection can drop
  during a session. ShardX routes QUIC through the proxy UDP relay so
  HTTP/3 remains available for the full session.

---

## Quick start

### Option A: download a release

Download the build for your OS from [GitHub Releases](../../releases),
then run it. Use `.dmg` for macOS, `.msi` or the portable `.exe` for
Windows, and `.AppImage` or `.deb` for Linux.

Vietnamese walkthrough: [Hướng dẫn cài đặt](docs/CAI-DAT-TIENG-VIET.md).

The release is not code-signed with Apple Developer ID or Authenticode,
so the operating system may show a warning on first launch:

* **macOS:** Gatekeeper may report that Apple cannot verify the app.
  On macOS 14 and later, it may instead report that the app is damaged
  and should be moved to the Trash. Both messages can be resolved by
  removing the quarantine attribute once in Terminal:
  ```bash
  xattr -dr com.apple.quarantine "/Applications/ShardX Launcher.app"
  ```
  The app should then open normally. For the developer verification
  warning, right-click the app, select *Open* and confirm once.
* **Windows:** SmartScreen may show *"Windows protected your PC"*.
  Select **More info**, then **Run anyway**. Later launches do not show
  the same prompt.
* **Linux:** for `.AppImage`, run `chmod +x ShardX-Launcher.AppImage && ./ShardX-Launcher.AppImage`.
  For `.deb`, run `sudo apt install ./ShardX-Launcher.deb`.

### Linux system dependencies

The bundled Chromium engine needs `unzip` and the standard shared
libraries any Chromium fork links against. On a fresh Debian / Ubuntu:

```bash
sudo apt install -y \
  unzip ca-certificates fonts-liberation \
  libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
  libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
  libgbm1 libpango-1.0-0 libcairo2 libasound2 libxshmfence1
```

### Option B: build from source

Run these commands from the repository root:

```bash
npm install
npm run tauri dev      # dev (hot reload)
# or
npm run tauri build    # release .app / .msi / .AppImage in src-tauri/target/release/bundle/
```

### First launch

The app downloads the patched browser (~150 MB), Widevine (~16 MB) and
the fingerprint library (~470 KB) from our CDN, places everything
under

* `~/Library/Application Support/shardx-launcher/` (mac)
* `%APPDATA%\shardx-launcher\` (win)
* `~/.config/shardx-launcher/` (linux)

and you're ready to bind a proxy and launch your first profile.

---

## Usage

ShardX provides four interfaces for different workflows. They all read
the same local state. A profile created in the UI is immediately
available through the API, MCP server and SDKs.

### 1. Desktop UI

Use the desktop app for daily profile management. Open *Proxies > Add
proxy* and enter `socks5://user:pass@host:port`, or paste a list for
bulk import. Select *Test* to run a TCP check, UDP_ASSOCIATE probe and
IP geolocation lookup. Open *Profiles*, select a profile, choose *Bind
proxy* and then select *Start*. The launcher handles the following tasks:

* downloading the engine + Widevine + 170 starter profiles on first
  launch, with subsequent requests cached by ETag.
* per-profile `user-data-dir` so cookies / cache / extensions stay
  isolated.
* resolving timezone / locale / geolocation from the proxy's exit
  country before each launch.
* deciding QUIC + WebRTC policy from a live UDP probe. QUIC remains on
  when the proxy supports UDP and turns off when it does not. No manual
  toggle is required.
* re-binding to the same `user-data-dir` next time so you get
  *"Continue where you left off"* without the crash-restore bubble.

The workspace also includes bulk import and export, folders, tags,
pinning, cloning, and cookie import and export for Chromium SQLite v10
and DPAPI. The fingerprint editor randomizes CPU, RAM and platform
version together to keep hardware combinations consistent.
Bulk import / export, folders, tags, pin-to-top, clone, cookie
import / export (Chromium SQLite v10 / DPAPI), and a fingerprint
editor that randomises coherent hardware (CPU ↔ RAM ↔ platform version)
are all in the workspace. Enable *Settings → Startup & background
services* to start the Launcher and embedded API at desktop sign-in,
optionally without showing the main window.

### 2. Local automation API

An axum HTTP server bound to `127.0.0.1:40325` (port configurable in
*Settings > Automation API*). Use it to control the launcher from
Python, Go, curl or any other HTTP client. Every endpoint except
`GET /health` requires the Bearer JWT shown in *Settings > Automation API*.
Regenerating the token rotates the signing secret immediately.

* **Reference docs:** [https://docs.proxyshard.com/eng/shardx-launcher-api/binding-and-lifecycle](https://docs.proxyshard.com/eng/shardx-launcher-api/binding-and-lifecycle?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher)
* **OpenAPI schema:** [openapi.yaml](openapi.yaml)

Launching a profile and getting a CDP endpoint:

```bash
TOKEN="<from Settings / Automation API>"
BASE="http://127.0.0.1:40325"

# Start the profile in CDP mode and return its websocket endpoint.
# Reuse the endpoint with Puppeteer, patchright, a raw WebSocket client
# or another CDP client.
curl -s -X POST "$BASE/profiles/win-rtx4060/start?cdp=true&headless=false" \
     -H "Authorization: Bearer $TOKEN" | jq .
# Response: {"id":"win-rtx4060","cdp_url":"ws://127.0.0.1:53217/devtools/browser/...","pid":48211}

# Stop it.
curl -s -X POST "$BASE/profiles/win-rtx4060/stop" \
     -H "Authorization: Bearer $TOKEN"
```

Endpoints cover profiles (create, edit, delete, start, stop, and list running
profiles), proxies (add, delete, and list), extensions (add from a Web Store
link or local file, list, and remove), bookmarks (add, list, and delete),
trash (list, restore, and purge), fingerprint generation and library listing,
folders, and cookie import or export. See the OpenAPI file for the complete
list.

The `color` and `extensions` fields can be set when a profile is created
or edited. This lets a script create a recognizable profile with the
extensions it needs from the first launch:

```bash
EXTENSION_ID="$(
  curl -s -X POST "$BASE/extensions" \
       -H "Authorization: Bearer $TOKEN" \
       -H 'Content-Type: application/json' \
       -d '{"url":"https://chromewebstore.google.com/detail/rabby-wallet/acmacodkjbdgmoleebolmdjonilkdbch"}' |
    jq -r '.id'
)"

FINGERPRINT="$(
  curl -s "$BASE/fingerprint/new" \
       -H "Authorization: Bearer $TOKEN" |
    jq -c '.fingerprint'
)"

jq -n \
  --arg extension "$EXTENSION_ID" \
  --argjson fingerprint "$FINGERPRINT" \
  '{
    name: "kz-01",
    color: "#2FCB80",
    extensions: [$extension],
    fingerprint: $fingerprint
  }' |
curl -s -X POST "$BASE/profiles" \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     --data-binary @- | jq .
```

#### Throwaway profiles with noise

`POST /profiles/temporary` makes a profile that is hidden from the
list and deleted when its browser closes. It takes a `noise` block, so
a scripted run can decide per vector instead of taking the default
(everything off):

```bash
curl -s -X POST "$BASE/profiles/temporary" \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{
           "platform": "Windows",
           "proxy": "socks5://user:pass@host:1080",
           "noise": {
             "canvas": true,
             "webgl": { "enabled": true, "intensity": 0.0005 },
             "fonts": true
           }
         }'
```

Shorthand (`true`) and full blocks can be mixed. A block is merged into
the vector instead of replacing it, so `{"webgl": {"intensity": 0.001}}`
leaves `enabled` unchanged. Enabling `webgl` or `client_rects` with
shorthand also sets the strength used by the UI because an enabled vector
with zero strength has no effect. A `seed` of `0`, or an omitted seed,
still derives a stable value from the profile ID. This prevents temporary
profiles created a second apart from sharing a fingerprint.

#### Human input over CDP

Once you have a CDP endpoint, the patched core provides a **`Motion`**
domain for pointer movement and keystrokes. It uses the same engine as
the browser's own *Human Type* menu item. Text is typed one key at a time
through the browser's input path. It is not pasted or set directly on the
element, and no script is injected.

The domain is merged into the browser-level protocol, so it is available
from the **browser** target but does not appear in `/json/protocol` or
`Schema.getDomains`. This is intentional. A client that knows the commands
can use them, while a page that enumerates the protocol cannot discover
them. The command names also differ from those used by other products
because matching a known tool's vocabulary would create its own
fingerprint.

| Command | Parameters | Returns |
| --- | --- | --- |
| `Motion.createPointer` | `x`, `y`, `paceScale?`, `seed?` | No fields |
| `Motion.glideTo` | `x`, `y`, `targetWidth?` | `durationMs` |
| `Motion.tap` | `button?`, `clickCount?` | No fields |
| `Motion.enterText` | `text`, `allowTypos?` | `durationMs` |
| `Motion.destroyPointer` | No parameters | No fields |

* Coordinates are **viewport CSS pixels**.
* `targetWidth` is the element's real width. It feeds Fitts's law, so
  passing it is what makes a small target take longer to reach than a
  large one. Defaults to 32.
* `paceScale` multiplies the profile's own speed. A value of `1.0` keeps
  its default pace.
* `seed` overrides the profile's motor seed. Leave it unset in production
  so profiles do not end up moving identically.
* `allowTypos` lets the profile's typo rate introduce a mistake and
  correct it with a real backspace. Off by default, because it changes
  the value that ends up in the field.
* Call `createPointer` first. A session without a pointer answers every
  other command with an error instead of inventing an origin. A guessed
  starting point would produce the wrong duration and curve.

```python
# pip install websockets
import asyncio, json, websockets

CDP = "ws://127.0.0.1:53217/devtools/browser/..."  # from /profiles/{id}/start

async def main():
    async with websockets.connect(CDP, max_size=None) as ws:
        n = 0
        async def call(method, params=None):
            nonlocal n
            n += 1
            await ws.send(json.dumps({"id": n, "method": method,
                                      "params": params or {}}))
            while True:
                msg = json.loads(await ws.recv())
                if msg.get("id") == n:
                    if "error" in msg:
                        raise RuntimeError(msg["error"])
                    return msg.get("result", {})

        # Where the cursor starts. Not a movement.
        await call("Motion.createPointer", {"x": 20, "y": 20})

        # Aim at the field. Pass its real width.
        r = await call("Motion.glideTo", {"x": 640, "y": 360,
                                          "targetWidth": 220})
        print("moved in", r["durationMs"], "ms")

        await call("Motion.tap")                       # focus it
        await call("Motion.enterText", {"text": "hello there"})
        await call("Motion.destroyPointer")

asyncio.run(main())
```

The same sequence in Node over an existing Puppeteer connection:

```js
const s = await browser.target().createCDPSession();
await s.send("Motion.createPointer", { x: 20, y: 20 });
await s.send("Motion.glideTo", { x: 640, y: 360, targetWidth: 220 });
await s.send("Motion.tap");
await s.send("Motion.enterText", { text: "hello there" });
await s.send("Motion.destroyPointer");
```

Typing happens in real time. `enterText` returns only when the last key is
released, and `durationMs` reports how long it took. Allow as much time as
you would for a person typing the same text.
Endpoints cover startup status/configuration, profiles (create / edit /
delete / start / stop / list running), proxies (add / delete / list),
fingerprints (generate, list library), folders, cookies (export / import)
and a fingerprint generator — full list in the OpenAPI file.

### 3. MCP server

A [Model Context Protocol](https://modelcontextprotocol.io) server for
Claude Desktop, Cursor and any other MCP client. It wraps the launcher's
HTTP API and browser control over CDP through patchright, allowing a
language model to:

* manage profiles / proxies / fingerprints / folders / cookies through
  the launcher.
* navigate / click / type / wait / screenshot in a live ShardX
  profile, with the profile auto-starting when needed.

The app does not run the server itself. Open *Settings > MCP server >
Download MCP server*, choose a folder, run `npm install` and register
the server with your MCP client. Setup instructions, environment
variables and tools are listed in
The Launcher startup entry keeps its embedded API available. MCP itself
remains a stdio process spawned on demand by your MCP client — open
*Settings → MCP server → Download MCP server*, pick a folder, then
`npm install` and register it. Full setup, env vars and tool list in
**[mcp/README.md](mcp/README.md)**.

Minimal stdio registration:

```json
{
  "mcpServers": {
    "shardx": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/mcp/index.js"],
      "env": {
        "SHARDX_API": "http://127.0.0.1:40325",
        "SHARDX_TOKEN": "<Bearer token>"
      }
    }
  }
}
```

### 4. Standalone SDKs (Python / Node / Rust)

These client libraries do not require the desktop app. On first use,
they download the same engine and fingerprint library, then launch
profiles directly as subprocesses. Python and Node use
[patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright) as a
stealth Playwright client. Rust uses
[chromiumoxide](https://docs.rs/chromiumoxide) over CDP. The SDKs use the
same pre-launch pipeline as the desktop app, including a UDP probe,
conditional QUIC, automatic resolution of timezone, locale and geolocation,
the same screen strategy and host-aware hardware randomization.

Use an SDK when you want ShardX as a library inside a scraper, CI job or
server-side worker without installing the GUI.

* **Python:** [sdks/python/README.md](sdks/python/README.md), `pip install shardx`
* **Node:** [sdks/node/README.md](sdks/node/README.md), `npm install @proxyshard/shardx`
* **Rust:** [sdks/rust/README.md](sdks/rust/README.md), `cargo add shardx`

---

## Licensing

The desktop launcher source in this repository, including the Tauri shell,
React UI and Rust source, is available under the **MIT License**. See
[LICENSE](LICENSE). You may use, fork, modify and distribute the launcher,
including for commercial projects.

The **browser engine** (the patched Chromium 156 binary that the
launcher downloads from our CDN on first run) is distributed as a
**closed-source binary**. Its source is not published in this
repository or elsewhere, and the following are explicitly **not
permitted**:

* reverse engineering, disassembly, decompilation, or any attempt to
  extract or reconstruct the engine source.
* redistributing a modified version of the engine.
* using the engine or any binary derived from it, with or without
  modification, as part of a commercial anti-detect, browser or
  fingerprint-spoofing product or service.

Permitted uses include personal projects, web scraping,
multi-accounting and integration with the launcher's automation API.
Contact us before building a commercial product on top of the engine.
