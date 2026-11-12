use crate::errcode;
use crate::{settings, store};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Socks5,
    Http,
    Https,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEntry {
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    /// "PL", "US", …
    #[serde(default)]
    pub country: String,
    /// Free-form note.
    #[serde(default)]
    pub notes: String,
}

impl ProxyEntry {
    /// Two entries are the same proxy only when the whole connection tuple
    /// matches. The password is part of it: with some providers it carries the
    /// session or the routing, so the same host/port/user with a different
    /// password is a different exit.
    fn same_connection(&self, other: &ProxyEntry) -> bool {
        self.same_login(other) && self.password == other.password
    }

    /// Same endpoint and the same login; the password may differ.
    fn same_login(&self, other: &ProxyEntry) -> bool {
        self.kind == other.kind
            && self.host == other.host
            && self.port == other.port
            && self.username == other.username
    }

    /// Build `--proxy-server=<scheme>://[user:pass@]host:port` for ShardX.
    pub fn to_proxy_server_arg(&self) -> String {
        let scheme = match self.kind {
            ProxyKind::Socks5 => "socks5",
            ProxyKind::Http => "http",
            ProxyKind::Https => "https",
        };
        let host_port = format!("{}:{}", self.host, self.port);
        if self.username.is_empty() && self.password.is_empty() {
            format!("{scheme}://{host_port}")
        } else {
            let user =
                url::form_urlencoded::byte_serialize(self.username.as_bytes()).collect::<String>();
            let pass =
                url::form_urlencoded::byte_serialize(self.password.as_bytes()).collect::<String>();
            format!("{scheme}://{user}:{pass}@{host_port}")
        }
    }

    /// Proxy URL for the launcher's own `reqwest` clients. `reqwest`
    /// percent-decodes the userinfo, so every byte outside the unreserved set
    /// is written as `%XX` — `form_urlencoded` turns a space into `+`, which
    /// `reqwest` would then send literally. `socks_scheme` picks `socks5` or
    /// `socks5h` for SOCKS5 entries.
    pub fn reqwest_proxy_url(&self, socks_scheme: &str) -> String {
        let scheme = match self.kind {
            ProxyKind::Socks5 => socks_scheme,
            ProxyKind::Http => "http",
            ProxyKind::Https => "https",
        };
        let host_port = format!("{}:{}", self.host, self.port);
        if self.username.is_empty() && self.password.is_empty() {
            return format!("{scheme}://{host_port}");
        }
        let encode = |s: &str| {
            s.bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect::<String>()
        };
        format!(
            "{scheme}://{}:{}@{host_port}",
            encode(&self.username),
            encode(&self.password)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyStore {
    #[serde(default)]
    pub proxies: Vec<ProxyEntry>,
}

pub fn load() -> Result<ProxyStore> {
    let path = store::proxies_path()?;
    if !path.exists() {
        return Ok(ProxyStore::default());
    }
    let body = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&body).unwrap_or_default())
}

fn save(s: &ProxyStore) -> Result<()> {
    let body = serde_json::to_string_pretty(s)?;
    fs::write(store::proxies_path()?, body)?;
    Ok(())
}

pub fn list() -> Result<Vec<ProxyEntry>> {
    Ok(load()?.proxies)
}

pub fn upsert(mut entry: ProxyEntry) -> Result<ProxyEntry> {
    if entry.id.is_empty() {
        entry.id = uuid::Uuid::new_v4().to_string();
    }
    let mut s = load()?;
    if let Some(slot) = s.proxies.iter_mut().find(|p| p.id == entry.id) {
        *slot = entry.clone();
    } else {
        s.proxies.push(entry.clone());
    }
    save(&s)?;
    Ok(entry)
}

/// Upsert that reuses an entry with the same connection tuple.
pub fn upsert_dedup(mut entry: ProxyEntry) -> Result<ProxyEntry> {
    let mut s = load()?;
    if let Some(existing) = s.proxies.iter().find(|p| p.same_connection(&entry)) {
        return Ok(existing.clone());
    }
    if entry.id.is_empty() {
        entry.id = uuid::Uuid::new_v4().to_string();
    }
    s.proxies.push(entry.clone());
    save(&s)?;
    Ok(entry)
}

/// Where `entry` lands when a profile already bound to `bound_id` is given it.
///
/// An exact copy already in the store is reused, as in `upsert_dedup`. Failing
/// that, when the bound entry is the same endpoint and login with another
/// password, the new password is a change to that proxy rather than a second
/// one: the bound entry takes it and keeps its id, name, country and notes, so
/// the profile stays bound and nothing is left behind with the old password.
/// Anything else is a different proxy and is added. Returns the entry the
/// profile should be bound to and whether the store changed.
fn place_for_binding(
    store: &mut Vec<ProxyEntry>,
    mut entry: ProxyEntry,
    bound_id: Option<&str>,
) -> (ProxyEntry, bool) {
    if let Some(existing) = store.iter().find(|p| p.same_connection(&entry)) {
        return (existing.clone(), false);
    }
    let bound = bound_id
        .filter(|id| !id.is_empty())
        .and_then(|id| store.iter_mut().find(|p| p.id == id));
    if let Some(bound) = bound.filter(|p| p.same_login(&entry)) {
        bound.password = entry.password;
        return (bound.clone(), true);
    }
    if entry.id.is_empty() {
        entry.id = uuid::Uuid::new_v4().to_string();
    }
    store.push(entry.clone());
    (entry, true)
}

/// `upsert_dedup` for a profile that may already be bound to a proxy; a new
/// password for the bound endpoint and login updates that proxy in place.
pub fn upsert_for_binding(entry: ProxyEntry, bound_id: Option<&str>) -> Result<ProxyEntry> {
    let mut s = load()?;
    let (placed, changed) = place_for_binding(&mut s.proxies, entry, bound_id);
    if changed {
        save(&s)?;
    }
    Ok(placed)
}

pub fn delete(id: &str) -> Result<()> {
    let mut s = load()?;
    s.proxies.retain(|p| p.id != id);
    save(&s)?;
    // Also wipe persisted test history.
    let mut hs = load_history()?;
    if hs.by_proxy.remove(id).is_some() {
        save_history(&hs)?;
    }
    Ok(())
}

pub fn get(id: &str) -> Result<Option<ProxyEntry>> {
    Ok(load()?.proxies.into_iter().find(|p| p.id == id))
}

/// SOCKS5/HTTP CONNECT probe; returns RTT in ms on success.
/// The whole test, greeting to reply: a proxy that accepts and then stalls must
/// fail rather than hold the Test button forever.
const TEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

pub async fn probe(entry: &ProxyEntry) -> Result<u128> {
    tokio::time::timeout(TEST_DEADLINE, probe_inner(entry))
        .await
        .context(errcode::code("proxy.readTimeout"))?
}

async fn probe_inner(entry: &ProxyEntry) -> Result<u128> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration, Instant};

    let started = Instant::now();
    let addr = format!("{}:{}", entry.host, entry.port);
    // Resolve apart from connecting so a name that does not resolve is told
    // from a host that refuses.
    let mut stream = timeout(Duration::from_secs(8), async {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(addr.as_str())
            .await
            .context(errcode::code("proxy.dnsFailed"))?
            .collect();
        if addrs.is_empty() {
            anyhow::bail!("{}", errcode::code("proxy.dnsFailed"));
        }
        Ok(TcpStream::connect(&addrs[..]).await?)
    })
    .await
    .context(errcode::code("proxy.connectTimeout"))??;

    match entry.kind {
        ProxyKind::Socks5 => {
            // RFC 1928 §3 greeting
            let auth_method: u8 = if entry.username.is_empty() {
                0x00
            } else {
                0x02
            };
            stream.write_all(&[0x05, 0x01, auth_method]).await?;
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp[0] != 0x05 {
                anyhow::bail!("{}", errcode::code("proxy.notSocks5"));
            }
            if resp[1] == 0xFF {
                anyhow::bail!("{}", errcode::code("proxy.authRefused"));
            }
            if auth_method == 0x02 {
                // RFC 1929 user/pass sub-negotiation
                let mut buf = vec![0x01u8];
                buf.push(entry.username.len() as u8);
                buf.extend_from_slice(entry.username.as_bytes());
                buf.push(entry.password.len() as u8);
                buf.extend_from_slice(entry.password.as_bytes());
                stream.write_all(&buf).await?;
                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    anyhow::bail!("{}", errcode::code("proxy.authRefused"));
                }
            }
            // A greeting proves only that something speaks SOCKS5 on the port.
            // Ask it to reach a real host, as the browser will; a proxy whose
            // upstream is dead used to pass here (upstream 081770c,
            // "proxy-checker").
            let host = b"example.com";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
            req.extend_from_slice(host);
            req.extend_from_slice(&443u16.to_be_bytes());
            stream.write_all(&req).await?;
            let mut reply = [0u8; 2];
            stream.read_exact(&mut reply).await?;
            if reply[1] != 0x00 {
                anyhow::bail!(
                    "{}",
                    errcode::code_with("proxy.socksRefused", &[("code", &reply[1].to_string())])
                );
            }
        }
        ProxyKind::Http | ProxyKind::Https => {
            // CONNECT with Basic auth; read until CRLFCRLF to avoid clipping headers.
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let mut req = String::from(
                "CONNECT example.com:443 HTTP/1.1\r\n\
                 Host: example.com:443\r\n",
            );
            if !entry.username.is_empty() || !entry.password.is_empty() {
                let creds = format!("{}:{}", entry.username, entry.password);
                let encoded = STANDARD.encode(creds.as_bytes());
                req.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
            }
            req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
            stream.write_all(req.as_bytes()).await?;

            // Read until CRLFCRLF or 4 KB cap.
            let mut buf = Vec::with_capacity(512);
            let mut tmp = [0u8; 256];
            let head: String = loop {
                let n = timeout(Duration::from_secs(8), stream.read(&mut tmp))
                    .await
                    .context(errcode::code("proxy.readTimeout"))??;
                if n == 0 {
                    break String::from_utf8_lossy(&buf).to_string();
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 4096 {
                    break String::from_utf8_lossy(&buf).to_string();
                }
            };
            let first_line = head.lines().next().unwrap_or("");
            if !first_line.starts_with("HTTP/1.1 200") && !first_line.starts_with("HTTP/1.0 200") {
                anyhow::bail!(
                    "{}",
                    errcode::code_with("proxy.connectFailed", &[("first_line", first_line)])
                );
            }
        }
    }
    Ok(started.elapsed().as_millis())
}

// ---- Bulk import ----
//
// Accepted: socks5://user:pass@host:port, user:pass@host:port, host:port:user:pass,
//           host:port@user:pass, host:port. A trailing `#` is the proxy's name
//           (`#facebook`); `country=X` and `note=Y` there are still read, for
//           lines exported by older builds, but the country a proxy reports is
//           filled in by its test. Whole-line `#` comments are skipped.
//           SOCKS5 when no scheme given.

/// Parse a single proxy line for inline (unsaved) use by the API.
pub fn parse_single(line: &str) -> Option<ProxyEntry> {
    parse_one(line.trim(), &ProxyKind::Socks5)
}

pub fn parse_bulk(text: &str, default_kind: ProxyKind) -> Vec<ProxyEntry> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(p) = parse_one(line, &default_kind) {
            out.push(p);
        }
    }
    out
}

fn parse_one(line: &str, default_kind: &ProxyKind) -> Option<ProxyEntry> {
    // Optional trailing `# country=US name=foo note=bar`.
    let (main, comment) = match line.find('#') {
        Some(i) => (line[..i].trim(), Some(line[i + 1..].trim())),
        None => (line, None),
    };
    let (kind, rest) = if let Some(r) = main.strip_prefix("socks5://") {
        (ProxyKind::Socks5, r)
    } else if let Some(r) = main.strip_prefix("https://") {
        (ProxyKind::Https, r)
    } else if let Some(r) = main.strip_prefix("http://") {
        (ProxyKind::Http, r)
    } else {
        (default_kind.clone(), main)
    };

    let (host_part, user, pass) = if let Some((u, hp)) = rest.split_once('@') {
        let (un, pw) = u.split_once(':').unwrap_or((u, ""));
        (hp.to_string(), un.to_string(), pw.to_string())
    } else {
        // host:port or host:port:user:pass
        let parts: Vec<&str> = rest.split(':').collect();
        match parts.len() {
            2 => (rest.to_string(), String::new(), String::new()),
            4 => (
                format!("{}:{}", parts[0], parts[1]),
                parts[2].to_string(),
                parts[3].to_string(),
            ),
            _ => return None,
        }
    };

    let (host, port_s) = host_part.rsplit_once(':')?;
    let port: u16 = port_s.parse().ok()?;
    let mut country = String::new();
    let mut name = String::new();
    let mut notes = String::new();
    // The comment is the name; `key=value` is only for lines older builds wrote.
    let mut name_parts: Vec<&str> = Vec::new();
    if let Some(c) = comment {
        for kv in c.split_whitespace() {
            if let Some(v) = kv.strip_prefix("country=") {
                country = v.to_string();
            } else if let Some(v) = kv.strip_prefix("name=") {
                name = v.to_string();
            } else if let Some(v) = kv.strip_prefix("note=") {
                notes = v.to_string();
            } else {
                name_parts.push(kv.trim_start_matches('#'));
            }
        }
    }
    // A bare comment is the name; fall back to a legacy `name=` when the line
    // carried only `key=value` fields.
    let name = if name_parts.is_empty() {
        name
    } else {
        name_parts.join(" ")
    };
    Some(ProxyEntry {
        // ID assigned now so pre-save test snapshots key under the kept uuid.
        id: uuid::Uuid::new_v4().to_string(),
        name: if name.is_empty() {
            format!("{host}:{port}")
        } else {
            name
        },
        kind,
        host: host.to_string(),
        port,
        username: user,
        password: pass,
        country,
        notes,
    })
}

/// Append the entries that are not already present; returns how many landed.
/// Split out of `bulk_save` so the rule can be tested without a store on disk.
fn append_new(existing: &mut Vec<ProxyEntry>, incoming: Vec<ProxyEntry>) -> usize {
    let mut added = 0usize;
    for mut e in incoming {
        if existing.iter().any(|x| x.same_connection(&e)) {
            continue;
        }
        if e.id.is_empty() {
            e.id = uuid::Uuid::new_v4().to_string();
        }
        existing.push(e);
        added += 1;
    }
    added
}

/// Save many entries; returns count actually persisted. Same duplicate rule as
/// `upsert_dedup`, so a bulk import and an API add agree about what is a copy.
pub fn bulk_save(entries: Vec<ProxyEntry>) -> Result<usize> {
    let mut store_data = load()?;
    let added = append_new(&mut store_data.proxies, entries);
    save(&store_data)?;
    Ok(added)
}

// ---- UDP probe (SOCKS5 UDP_ASSOCIATE; RFC 1928 §7) ----

/// Resolve a public STUN server to IPv4 (probe target for the UDP relay).
async fn resolve_stun_ipv4() -> Result<(std::net::Ipv4Addr, u16)> {
    const HOSTS: &[&str] = &[
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun.cloudflare.com:3478",
    ];
    for h in HOSTS {
        if let Ok(addrs) = tokio::net::lookup_host(*h).await {
            for a in addrs {
                if let std::net::IpAddr::V4(v4) = a.ip() {
                    return Ok((v4, a.port()));
                }
            }
        }
    }
    anyhow::bail!("{}", errcode::code("proxy.stunNoIpv4"))
}

pub async fn probe_udp(entry: &ProxyEntry) -> Result<u128> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UdpSocket};
    use tokio::time::{timeout, Duration, Instant};

    if !matches!(entry.kind, ProxyKind::Socks5) {
        anyhow::bail!("{}", errcode::code("proxy.udpOnlySocks5"));
    }
    let started = Instant::now();
    let mut tcp = timeout(
        Duration::from_secs(8),
        TcpStream::connect(format!("{}:{}", entry.host, entry.port)),
    )
    .await
    .context(errcode::code("proxy.connectTimeout"))??;

    let auth_method: u8 = if entry.username.is_empty() {
        0x00
    } else {
        0x02
    };
    tcp.write_all(&[0x05, 0x01, auth_method]).await?;
    let mut greet = [0u8; 2];
    tcp.read_exact(&mut greet).await?;
    if greet[1] == 0xFF {
        anyhow::bail!("{}", errcode::code("proxy.authRefused"));
    }
    if auth_method == 0x02 {
        let mut buf = vec![0x01u8];
        buf.push(entry.username.len() as u8);
        buf.extend_from_slice(entry.username.as_bytes());
        buf.push(entry.password.len() as u8);
        buf.extend_from_slice(entry.password.as_bytes());
        tcp.write_all(&buf).await?;
        let mut ar = [0u8; 2];
        tcp.read_exact(&mut ar).await?;
        if ar[1] != 0x00 {
            anyhow::bail!("auth failed");
        }
    }
    // UDP_ASSOCIATE: cmd=0x03, ATYP=IPv4, addr=0.0.0.0, port=0
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        anyhow::bail!(
            "{}",
            errcode::code_with("proxy.udpRefused", &[("rep", &format!("{:#x}", hdr[1]))])
        );
    }
    let bind_addr: SocketAddr = match hdr[3] {
        0x01 => {
            // IPv4
            let mut ip = [0u8; 4];
            tcp.read_exact(&mut ip).await?;
            let mut p = [0u8; 2];
            tcp.read_exact(&mut p).await?;
            let port = u16::from_be_bytes(p);
            let v4 = std::net::Ipv4Addr::from(ip);
            // 0.0.0.0 → fall back to TCP peer (where the relay lives).
            if v4.is_unspecified() {
                let peer = tcp.peer_addr()?;
                SocketAddr::new(peer.ip(), port)
            } else {
                SocketAddr::new(std::net::IpAddr::V4(v4), port)
            }
        }
        0x04 => {
            let mut ip = [0u8; 16];
            tcp.read_exact(&mut ip).await?;
            let mut p = [0u8; 2];
            tcp.read_exact(&mut p).await?;
            SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                u16::from_be_bytes(p),
            )
        }
        _ => anyhow::bail!("{}", errcode::code("proxy.udpReplyBadAtyp")),
    };

    // Probe with STUN binding request (DNS-port-53 often blocked, STUN passes).
    let (stun_ip, stun_port) = resolve_stun_ipv4()
        .await
        .context(errcode::code("proxy.stunUnresolved"))?;

    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(bind_addr).await?;
    let mut pkt: Vec<u8> = Vec::with_capacity(32);
    // SOCKS5 UDP header: RSV(2)=0, FRAG=0, ATYP=IPv4, DST=<stun>, PORT.
    pkt.extend_from_slice(&[0, 0, 0, 0x01]);
    pkt.extend_from_slice(&stun_ip.octets());
    pkt.extend_from_slice(&stun_port.to_be_bytes());
    // STUN Binding Request (RFC 5389): type=0x0001, magic 0x2112A442, 12B txid.
    let mut stun = vec![0x00u8, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
    stun.extend_from_slice(&uuid::Uuid::new_v4().as_bytes()[..12]);
    pkt.extend_from_slice(&stun);
    udp.send(&pkt).await?;

    let mut buf = vec![0u8; 1500];
    let n = timeout(Duration::from_secs(6), udp.recv(&mut buf))
        .await
        .context(errcode::code("proxy.udpTimeout"))??;
    if n < 20 {
        anyhow::bail!("{}", errcode::code("proxy.udpReplyTooShort"));
    }
    // RFC 1928: dropping TCP control tears down the relay; keep it alive.
    drop(tcp);
    Ok(started.elapsed().as_millis())
}

// ---- Geo lookup ----

#[derive(Debug, Clone, Serialize)]
pub struct GeoInfo {
    pub ip: String,
    pub country: String,
    /// ISO 3166-1 alpha-2.
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub isp: String,
    pub timezone: String,
    pub latitude: f64,
    pub longitude: f64,
    pub provider: String,
}

/// Probe IP/country the world sees when traffic exits the proxy.
pub async fn geo_check(entry: &ProxyEntry, provider_override: Option<String>) -> Result<GeoInfo> {
    geo_check_via(Some(entry), provider_override).await
}

/// Probe geo through `entry` if Some, else direct; provider default ip-api.com.
pub async fn geo_check_via(
    entry: Option<&ProxyEntry>,
    provider_override: Option<String>,
) -> Result<GeoInfo> {
    let provider = provider_override
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            settings::load()
                .ok()
                .and_then(|s| s.geo_checker)
                .unwrap_or_else(|| "ip-api.com".into())
        });

    let url = match provider.as_str() {
        "ip-api.com" => "http://ip-api.com/json/?fields=status,message,query,country,countryCode,regionName,city,isp,timezone,lat,lon",
        "ipapi.co" => "https://ipapi.co/json/",
        "ipwho.is" => "https://ipwho.is/",
        _ => "http://ip-api.com/json/?fields=status,message,query,country,countryCode,regionName,city,isp,timezone,lat,lon",
    };

    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(8));
    if let Some(entry) = entry {
        // socks5h: DNS via proxy.
        let proxy_url = entry.reqwest_proxy_url("socks5h");
        let proxy = reqwest::Proxy::all(&proxy_url).context(errcode::code("proxy.badUrl"))?;
        builder = builder.proxy(proxy);
    } else {
        // Direct check: bypass any system proxy.
        builder = builder.no_proxy();
    }
    let client = builder.build()?;

    let body: serde_json::Value = client.get(url).send().await?.json().await?;

    let s = |v: &serde_json::Value, k: &str| {
        v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
    };
    let f = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0);
    let info = match provider.as_str() {
        "ip-api.com" => {
            if s(&body, "status") == "fail" {
                anyhow::bail!("ip-api.com: {}", s(&body, "message"));
            }
            GeoInfo {
                ip: s(&body, "query"),
                country: s(&body, "country"),
                country_code: s(&body, "countryCode"),
                region: s(&body, "regionName"),
                city: s(&body, "city"),
                isp: s(&body, "isp"),
                timezone: s(&body, "timezone"),
                latitude: f(&body, "lat"),
                longitude: f(&body, "lon"),
                provider,
            }
        }
        "ipapi.co" => GeoInfo {
            ip: s(&body, "ip"),
            country: s(&body, "country_name"),
            country_code: s(&body, "country_code"),
            region: s(&body, "region"),
            city: s(&body, "city"),
            isp: s(&body, "org"),
            timezone: s(&body, "timezone"),
            latitude: f(&body, "latitude"),
            longitude: f(&body, "longitude"),
            provider,
        },
        "ipwho.is" => GeoInfo {
            ip: s(&body, "ip"),
            country: s(&body, "country"),
            country_code: s(&body, "country_code"),
            region: s(&body, "region"),
            city: s(&body, "city"),
            isp: body
                .get("connection")
                .and_then(|c| c.get("isp"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            timezone: body
                .get("timezone")
                .and_then(|t| t.get("id"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            latitude: f(&body, "latitude"),
            longitude: f(&body, "longitude"),
            provider,
        },
        _ => GeoInfo {
            ip: s(&body, "query"),
            country: s(&body, "country"),
            country_code: s(&body, "countryCode"),
            region: String::new(),
            city: String::new(),
            isp: String::new(),
            timezone: String::new(),
            latitude: 0.0,
            longitude: 0.0,
            provider,
        },
    };
    Ok(info)
}

/// Map ISO-3166 alpha-2 to BCP-47 locale (coarse).
pub fn country_to_locale(cc: &str) -> &'static str {
    match cc.to_ascii_uppercase().as_str() {
        "US" => "en-US",
        "GB" | "UK" => "en-GB",
        "CA" => "en-CA",
        "AU" => "en-AU",
        "NZ" => "en-NZ",
        "IE" => "en-IE",
        "ZA" => "en-ZA",
        "IN" => "en-IN",
        "DE" => "de-DE",
        "AT" => "de-AT",
        "CH" => "de-CH",
        "FR" => "fr-FR",
        "BE" => "fr-BE",
        "ES" => "es-ES",
        "MX" => "es-MX",
        "AR" => "es-AR",
        "CO" => "es-CO",
        "CL" => "es-CL",
        "IT" => "it-IT",
        "NL" => "nl-NL",
        "PL" => "pl-PL",
        "BR" => "pt-BR",
        "PT" => "pt-PT",
        "RO" => "ro-RO",
        "RU" => "ru-RU",
        "BY" => "be-BY",
        "UA" => "uk-UA",
        "TR" => "tr-TR",
        "GR" => "el-GR",
        "CZ" => "cs-CZ",
        "SK" => "sk-SK",
        "HU" => "hu-HU",
        "SE" => "sv-SE",
        "FI" => "fi-FI",
        "NO" => "nb-NO",
        "DK" => "da-DK",
        "BG" => "bg-BG",
        "HR" => "hr-HR",
        "SI" => "sl-SI",
        "RS" => "sr-RS",
        "IL" => "he-IL",
        "SA" | "AE" | "EG" => "ar-SA",
        "ID" => "id-ID",
        "MY" => "ms-MY",
        "PH" => "fil-PH",
        "VN" => "vi-VN",
        "TH" => "th-TH",
        "CN" => "zh-CN",
        "HK" => "zh-HK",
        "TW" => "zh-TW",
        "JP" => "ja-JP",
        "KR" => "ko-KR",
        _ => "en-US",
    }
}

// ---- Test history ----

/// One observation of a proxy's exit state; same-IP consecutive entries collapse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSnapshot {
    pub first_seen: String,
    pub last_seen: String,
    pub ip: String,
    pub country_code: String,
    pub country: String,
    pub region: String,
    pub city: String,
    pub isp: String,
    pub timezone: String,
    pub latitude: f64,
    pub longitude: f64,
    pub tcp_ms: Option<u128>,
    pub udp_ms: Option<u128>,
    pub udp_error: Option<String>,
    pub provider: String,
    /// `None` for snapshots written before retries existed.
    #[serde(default)]
    pub status: Option<TestStatus>,
    #[serde(default)]
    pub failure_reason: Option<FailureReason>,
    /// TCP attempts made; 0 for snapshots written before retries existed.
    #[serde(default)]
    pub attempts: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    Working,
    /// Connected, but only after at least one failed attempt.
    Unstable,
    Failed,
}

// `proxy_bypassed` (exit IP equals this machine's direct IP) is not a reason
// yet: a test never looks up the direct IP, and a second geo call per test is
// not cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    AuthenticationFailed,
    Timeout,
    DnsFailed,
    Unreachable,
    ProtocolError,
}

/// Derive why an attempt failed from the error kinds it carried.
fn classify_failure(err: &anyhow::Error) -> FailureReason {
    use std::io::ErrorKind::{ConnectionRefused, HostUnreachable, NetworkUnreachable, TimedOut};
    let text = format!("{err:#}");
    if errcode::has_code(&text, "proxy.authRefused")
        || ["1.0", "1.1"]
            .iter()
            .any(|v| text.contains(&format!("proxy.connectFailed|first_line=HTTP/{v} 407")))
    {
        return FailureReason::AuthenticationFailed;
    }
    if errcode::has_code(&text, "proxy.dnsFailed") {
        return FailureReason::DnsFailed;
    }
    if errcode::has_code(&text, "proxy.connectTimeout")
        || errcode::has_code(&text, "proxy.readTimeout")
    {
        return FailureReason::Timeout;
    }
    // SOCKS5 replies 3, 4, 5: network unreachable, host unreachable, refused.
    if ["3", "4", "5"]
        .iter()
        .any(|c| text.contains(&format!("proxy.socksRefused|code={c}]]")))
    {
        return FailureReason::Unreachable;
    }
    match err
        .chain()
        .find_map(|e| e.downcast_ref::<std::io::Error>())
        .map(|e| e.kind())
    {
        Some(ConnectionRefused | HostUnreachable | NetworkUnreachable) => {
            FailureReason::Unreachable
        }
        Some(TimedOut) => FailureReason::Timeout,
        _ => FailureReason::ProtocolError,
    }
}

struct TcpOutcome {
    ms: Option<u128>,
    attempts: u8,
    status: TestStatus,
    reason: Option<FailureReason>,
}

const MAX_ATTEMPTS: u8 = 3;
const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

/// Up to `MAX_ATTEMPTS` TCP probes, stopping at the first success or at an
/// authentication failure (retrying a wrong password only risks a lockout).
/// All attempts share `budget`, so a dead proxy is no slower than one probe.
async fn probe_with_retries(entry: &ProxyEntry, budget: std::time::Duration) -> TcpOutcome {
    let started = tokio::time::Instant::now();
    let mut attempts = 0u8;
    loop {
        attempts += 1;
        let remaining = budget.saturating_sub(started.elapsed());
        let res = tokio::time::timeout(remaining, probe_inner(entry))
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!(errcode::code("proxy.readTimeout"))));
        let err = match res {
            Ok(ms) => {
                let status = if attempts == 1 {
                    TestStatus::Working
                } else {
                    TestStatus::Unstable
                };
                return TcpOutcome {
                    ms: Some(ms),
                    attempts,
                    status,
                    reason: None,
                };
            }
            Err(e) => e,
        };
        let reason = classify_failure(&err);
        let backoff = RETRY_BACKOFF * u32::from(attempts);
        if attempts == MAX_ATTEMPTS
            || reason == FailureReason::AuthenticationFailed
            || started.elapsed() + backoff >= budget
        {
            return TcpOutcome {
                ms: None,
                attempts,
                status: TestStatus::Failed,
                reason: Some(reason),
            };
        }
        tokio::time::sleep(backoff).await;
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct HistoryStore {
    #[serde(default)]
    by_proxy: HashMap<String, Vec<TestSnapshot>>,
}

fn history_path() -> Result<PathBuf> {
    Ok(store::config_root()?.join("proxies-history.json"))
}

fn load_history() -> Result<HistoryStore> {
    let path = history_path()?;
    if !path.exists() {
        return Ok(HistoryStore::default());
    }
    let body = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&body).unwrap_or_default())
}

fn save_history(s: &HistoryStore) -> Result<()> {
    let body = serde_json::to_string_pretty(s)?;
    fs::write(history_path()?, body)?;
    Ok(())
}

/// Persist a test result; same-IP entries collapse, capped at 50 per proxy.
fn record_test(proxy_id: &str, mut snap: TestSnapshot) -> Result<TestSnapshot> {
    if proxy_id.is_empty() {
        if snap.first_seen.is_empty() {
            snap.first_seen = snap.last_seen.clone();
        }
        return Ok(snap);
    }
    let mut hs = load_history()?;
    let entries = hs.by_proxy.entry(proxy_id.into()).or_default();
    if let Some(last) = entries.last_mut() {
        if !snap.ip.is_empty() && last.ip == snap.ip {
            last.last_seen = snap.last_seen.clone();
            last.tcp_ms = snap.tcp_ms;
            last.udp_ms = snap.udp_ms;
            last.udp_error = snap.udp_error.clone();
            last.status = snap.status;
            last.failure_reason = snap.failure_reason;
            last.attempts = snap.attempts;
            let out = last.clone();
            save_history(&hs)?;
            return Ok(out);
        }
    }
    if snap.first_seen.is_empty() {
        snap.first_seen = snap.last_seen.clone();
    }
    entries.push(snap.clone());
    if entries.len() > 50 {
        let drop = entries.len() - 50;
        entries.drain(..drop);
    }
    save_history(&hs)?;
    Ok(snap)
}

pub fn history(proxy_id: &str) -> Result<Vec<TestSnapshot>> {
    let hs = load_history()?;
    Ok(hs.by_proxy.get(proxy_id).cloned().unwrap_or_default())
}

pub fn latest_test(proxy_id: &str) -> Option<TestSnapshot> {
    load_history()
        .ok()
        .and_then(|hs| hs.by_proxy.get(proxy_id).and_then(|v| v.last().cloned()))
}

fn unix_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("@{s}")
}

/// Run TCP + UDP + geo, persist into history, auto-fill country tag.
pub async fn full_test(entry: &ProxyEntry) -> Result<TestSnapshot> {
    let now = unix_now();

    let tcp = probe_with_retries(entry, TEST_DEADLINE).await;
    let udp_res = if matches!(entry.kind, ProxyKind::Socks5) {
        Some(probe_udp(entry).await)
    } else {
        None
    };
    let geo_res = geo_check(entry, None).await;

    // TCP failure → zero geo so snapshot reads "Failed, no IP".
    let tcp_failed = tcp.ms.is_none();
    let (ip, country_code, country, region, city, isp, tz, lat, lng, provider) =
        match (&geo_res, tcp_failed) {
            (Ok(g), false) => (
                g.ip.clone(),
                g.country_code.clone(),
                g.country.clone(),
                g.region.clone(),
                g.city.clone(),
                g.isp.clone(),
                g.timezone.clone(),
                g.latitude,
                g.longitude,
                g.provider.clone(),
            ),
            _ => (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                0.0,
                0.0,
                String::new(),
            ),
        };

    let snap = TestSnapshot {
        first_seen: String::new(),
        last_seen: now,
        ip,
        country_code,
        country,
        region,
        city,
        isp,
        timezone: tz,
        latitude: lat,
        longitude: lng,
        tcp_ms: tcp.ms,
        udp_ms: udp_res.as_ref().and_then(|r| r.as_ref().ok().copied()),
        udp_error: udp_res
            .as_ref()
            .and_then(|r| r.as_ref().err().map(|e| e.to_string())),
        provider,
        status: Some(tcp.status),
        failure_reason: tcp.reason,
        attempts: tcp.attempts,
    };

    let recorded = record_test(&entry.id, snap)?;

    // Backfill empty country tag on the stored entry.
    if !recorded.country_code.is_empty() {
        let mut store_data = load()?;
        if let Some(p) = store_data.proxies.iter_mut().find(|p| p.id == entry.id) {
            if p.country.is_empty() || p.country == "—" {
                p.country = recorded.country_code.clone();
                save(&store_data)?;
            }
        }
    }

    Ok(recorded)
}

/// Fallback country → IANA timezone for providers that omit timezone.
pub fn country_to_timezone(cc: &str) -> &'static str {
    match cc.to_ascii_uppercase().as_str() {
        "US" => "America/New_York",
        "CA" => "America/Toronto",
        "GB" | "UK" => "Europe/London",
        "DE" => "Europe/Berlin",
        "FR" => "Europe/Paris",
        "ES" => "Europe/Madrid",
        "IT" => "Europe/Rome",
        "NL" => "Europe/Amsterdam",
        "PL" => "Europe/Warsaw",
        "PT" => "Europe/Lisbon",
        "RO" => "Europe/Bucharest",
        "RU" => "Europe/Moscow",
        "UA" => "Europe/Kyiv",
        "TR" => "Europe/Istanbul",
        "GR" => "Europe/Athens",
        "CZ" => "Europe/Prague",
        "HU" => "Europe/Budapest",
        "SE" => "Europe/Stockholm",
        "FI" => "Europe/Helsinki",
        "NO" => "Europe/Oslo",
        "DK" => "Europe/Copenhagen",
        "CH" => "Europe/Zurich",
        "AT" => "Europe/Vienna",
        "BR" => "America/Sao_Paulo",
        "AR" => "America/Argentina/Buenos_Aires",
        "MX" => "America/Mexico_City",
        "AU" => "Australia/Sydney",
        "NZ" => "Pacific/Auckland",
        "IN" => "Asia/Kolkata",
        "ID" => "Asia/Jakarta",
        "MY" => "Asia/Kuala_Lumpur",
        "SG" => "Asia/Singapore",
        "TH" => "Asia/Bangkok",
        "VN" => "Asia/Ho_Chi_Minh",
        "CN" => "Asia/Shanghai",
        "HK" => "Asia/Hong_Kong",
        "TW" => "Asia/Taipei",
        "JP" => "Asia/Tokyo",
        "KR" => "Asia/Seoul",
        "IL" => "Asia/Jerusalem",
        "SA" => "Asia/Riyadh",
        "AE" => "Asia/Dubai",
        _ => "UTC",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(user: &str, pass: &str) -> ProxyEntry {
        ProxyEntry {
            id: String::new(),
            name: format!("{user}@proxy.example.com"),
            kind: ProxyKind::Socks5,
            host: "proxy.example.com".into(),
            port: 1080,
            username: user.into(),
            password: pass.into(),
            country: String::new(),
            notes: String::new(),
        }
    }

    /// A one-connection SOCKS5 server on loopback: no-auth greeting, then
    /// answers the CONNECT with `reply` (0x00 = succeeded, 0x05 = refused),
    /// or never answers it when `reply` is None.
    async fn socks5_server(reply: Option<u8>) -> ProxyEntry {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greet = [0u8; 3];
            s.read_exact(&mut greet).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut req = [0u8; 256];
            let _ = s.read(&mut req).await;
            match reply {
                Some(rep) => {
                    let _ = s
                        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                }
                None => tokio::time::sleep(std::time::Duration::from_secs(120)).await,
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        });
        ProxyEntry {
            host: "127.0.0.1".into(),
            port,
            ..entry("", "")
        }
    }

    /// A SOCKS5 proxy that takes the sign-in but cannot reach anything used to
    /// test as working: the probe stopped after the greeting.
    #[tokio::test]
    async fn a_socks5_proxy_that_refuses_the_connect_fails_its_test() {
        let p = socks5_server(Some(0x05)).await;
        let err = probe(&p)
            .await
            .expect_err("a refused CONNECT is a dead proxy");
        assert!(format!("{err:#}").contains("proxy.socksRefused"), "{err:#}");
    }

    #[tokio::test]
    async fn a_socks5_proxy_that_connects_passes_its_test() {
        let p = socks5_server(Some(0x00)).await;
        probe(&p).await.expect("CONNECT succeeded");
    }

    #[tokio::test]
    async fn a_socks5_proxy_that_never_answers_the_connect_times_out() {
        let p = socks5_server(None).await;
        let started = std::time::Instant::now();
        assert!(probe(&p).await.is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
    }

    #[derive(Clone, Copy)]
    enum Conn {
        Ok,
        /// SOCKS5 "no acceptable method" reply.
        AuthRefused,
        /// Hang up straight after the greeting.
        Close,
        /// Never answer the CONNECT.
        Hang,
    }

    /// A SOCKS5 server on loopback whose n-th connection behaves as `script[n]`
    /// (the last entry repeats).
    async fn scripted_socks5(script: Vec<Conn>) -> ProxyEntry {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for n in 0.. {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let conn = script[n.min(script.len() - 1)];
                tokio::spawn(async move {
                    let mut greet = [0u8; 3];
                    let _ = s.read_exact(&mut greet).await;
                    match conn {
                        Conn::AuthRefused => {
                            let _ = s.write_all(&[0x05, 0xFF]).await;
                        }
                        Conn::Close => {}
                        Conn::Ok | Conn::Hang => {
                            let _ = s.write_all(&[0x05, 0x00]).await;
                            let mut req = [0u8; 256];
                            let _ = s.read(&mut req).await;
                            if matches!(conn, Conn::Ok) {
                                let _ = s
                                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                                    .await;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                    }
                });
            }
        });
        ProxyEntry {
            host: "127.0.0.1".into(),
            port,
            ..entry("", "")
        }
    }

    const BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

    #[tokio::test]
    async fn a_first_try_success_is_working() {
        let p = scripted_socks5(vec![Conn::Ok]).await;
        let o = probe_with_retries(&p, BUDGET).await;
        assert_eq!(
            (o.status, o.attempts, o.reason),
            (TestStatus::Working, 1, None)
        );
        assert!(o.ms.is_some());
    }

    #[tokio::test]
    async fn a_success_after_a_failed_attempt_is_unstable() {
        let p = scripted_socks5(vec![Conn::Close, Conn::Ok]).await;
        let o = probe_with_retries(&p, BUDGET).await;
        assert_eq!(
            (o.status, o.attempts, o.reason),
            (TestStatus::Unstable, 2, None)
        );
        assert!(o.ms.is_some());
    }

    #[tokio::test]
    async fn every_attempt_failing_is_failed_with_a_reason() {
        let p = scripted_socks5(vec![Conn::Close]).await;
        let o = probe_with_retries(&p, BUDGET).await;
        assert_eq!(o.status, TestStatus::Failed);
        assert_eq!(o.attempts, MAX_ATTEMPTS);
        assert_eq!(o.reason, Some(FailureReason::ProtocolError));
        assert!(o.ms.is_none());
    }

    /// A wrong password is not retried: it only risks a lockout.
    #[tokio::test]
    async fn an_authentication_failure_stops_after_one_attempt() {
        let p = scripted_socks5(vec![Conn::AuthRefused, Conn::Ok]).await;
        let o = probe_with_retries(&p, BUDGET).await;
        assert_eq!(o.status, TestStatus::Failed);
        assert_eq!(o.attempts, 1);
        assert_eq!(o.reason, Some(FailureReason::AuthenticationFailed));
    }

    /// A proxy that goes quiet spends the budget once, not once per attempt.
    #[tokio::test]
    async fn a_silent_proxy_times_out_within_the_budget() {
        let p = scripted_socks5(vec![Conn::Hang]).await;
        let started = std::time::Instant::now();
        let o = probe_with_retries(&p, std::time::Duration::from_secs(1)).await;
        assert_eq!(o.reason, Some(FailureReason::Timeout));
        assert!(started.elapsed() < std::time::Duration::from_millis(1500));
    }

    #[tokio::test]
    async fn an_http_407_is_an_authentication_failure() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 512];
            let _ = s.read(&mut req).await;
            let _ = s
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await;
        });
        let p = ProxyEntry {
            kind: ProxyKind::Http,
            host: "127.0.0.1".into(),
            port,
            ..entry("u", "wrong")
        };
        let o = probe_with_retries(&p, BUDGET).await;
        assert_eq!(o.reason, Some(FailureReason::AuthenticationFailed));
        assert_eq!(o.attempts, 1);
    }

    #[tokio::test]
    async fn a_closed_port_is_unreachable() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let p = ProxyEntry {
            host: "127.0.0.1".into(),
            port,
            ..entry("", "")
        };
        let err = probe_inner(&p).await.expect_err("nothing listens there");
        assert_eq!(classify_failure(&err), FailureReason::Unreachable);
    }

    /// `.invalid` is reserved (RFC 6761) and never resolves.
    #[tokio::test]
    async fn an_unresolvable_host_is_a_dns_failure() {
        let p = ProxyEntry {
            host: "proxy.invalid".into(),
            ..entry("", "")
        };
        let err = probe_inner(&p).await.expect_err("cannot resolve");
        assert_eq!(classify_failure(&err), FailureReason::DnsFailed);
    }

    #[test]
    fn a_socks_refusal_splits_into_unreachable_and_protocol_error() {
        let refusal = |code: &str| {
            anyhow::anyhow!(errcode::code_with("proxy.socksRefused", &[("code", code)]))
        };
        assert_eq!(classify_failure(&refusal("5")), FailureReason::Unreachable);
        assert_eq!(
            classify_failure(&refusal("1")),
            FailureReason::ProtocolError
        );
    }

    /// `proxies-history.json` written before retries existed has none of the
    /// new fields and must still load.
    #[test]
    fn an_old_snapshot_still_loads() {
        let old = r#"{"by_proxy":{"p1":[{"first_seen":"@1","last_seen":"@2","ip":"1.2.3.4",
            "country_code":"PL","country":"Poland","region":"","city":"","isp":"",
            "timezone":"UTC","latitude":0.0,"longitude":0.0,"tcp_ms":42,"udp_ms":null,
            "udp_error":null,"provider":"ip-api.com"}]}}"#;
        let hs: HistoryStore = serde_json::from_str(old).unwrap();
        let snap = &hs.by_proxy["p1"][0];
        assert_eq!(snap.tcp_ms, Some(42));
        assert_eq!(
            (snap.status, snap.failure_reason, snap.attempts),
            (None, None, 0)
        );
    }

    /// #72: the password carries the session with some providers, so two
    /// entries that differ only there are two proxies, not one.
    #[test]
    fn a_different_password_is_a_different_proxy() {
        let mut store = Vec::new();
        let added = append_new(
            &mut store,
            vec![entry("user", "pass-a"), entry("user", "pass-b")],
        );
        assert_eq!(added, 2);
        assert_eq!(store.len(), 2);
        assert_ne!(store[0].id, store[1].id);
    }

    /// The other half: an exact copy is still skipped.
    #[test]
    fn an_identical_entry_is_still_skipped() {
        let mut store = Vec::new();
        assert_eq!(append_new(&mut store, vec![entry("user", "pass")]), 1);
        assert_eq!(append_new(&mut store, vec![entry("user", "pass")]), 0);
        assert_eq!(store.len(), 1);
    }

    fn stored(id: &str, user: &str, pass: &str) -> ProxyEntry {
        ProxyEntry {
            id: id.into(),
            name: "kept name".into(),
            country: "PL".into(),
            notes: "kept note".into(),
            ..entry(user, pass)
        }
    }

    /// A new password for the bound endpoint and login is a change to that
    /// proxy: same id, same metadata, new password, nothing added.
    #[test]
    fn a_new_password_updates_the_bound_entry() {
        let mut store = vec![stored("bound", "user", "old")];
        let (placed, changed) = place_for_binding(&mut store, entry("user", "new"), Some("bound"));
        assert!(changed);
        assert_eq!(store.len(), 1);
        assert_eq!(placed.id, "bound");
        assert_eq!(store[0].password, "new");
        assert_eq!(
            (
                store[0].name.as_str(),
                store[0].country.as_str(),
                store[0].notes.as_str()
            ),
            ("kept name", "PL", "kept note")
        );
    }

    /// An exact copy elsewhere in the store wins: rebinding to it creates
    /// nothing, and the bound entry is not turned into a second copy of it.
    #[test]
    fn an_exact_copy_is_reused_before_the_bound_entry_is_touched() {
        let mut store = vec![
            stored("bound", "user", "old"),
            stored("other", "user", "new"),
        ];
        let (placed, changed) = place_for_binding(&mut store, entry("user", "new"), Some("bound"));
        assert!(!changed);
        assert_eq!(placed.id, "other");
        assert_eq!(store.len(), 2);
        assert_eq!(store[0].password, "old");
    }

    /// Only the password is a change in place. Another login, another scheme,
    /// or no bound entry at all is a different proxy and is added.
    #[test]
    fn anything_but_the_password_is_still_a_new_proxy() {
        let mut other_user = vec![stored("bound", "user", "old")];
        let (placed, _) =
            place_for_binding(&mut other_user, entry("someone", "new"), Some("bound"));
        assert_ne!(placed.id, "bound");
        assert_eq!(other_user.len(), 2);
        assert_eq!(other_user[0].password, "old");

        let mut other_scheme = vec![stored("bound", "user", "old")];
        let http = ProxyEntry {
            kind: ProxyKind::Http,
            ..entry("user", "new")
        };
        place_for_binding(&mut other_scheme, http, Some("bound"));
        assert_eq!(other_scheme.len(), 2);
        assert_eq!(other_scheme[0].password, "old");

        let mut unbound = vec![stored("kept", "user", "old")];
        place_for_binding(&mut unbound, entry("user", "new"), None);
        assert_eq!(unbound.len(), 2, "with no binding, #72 still applies");
        assert_eq!(unbound[0].password, "old");
    }

    /// `bulk_save` used to ignore `kind`, so an HTTP and a SOCKS5 entry on one
    /// endpoint collapsed into whichever was imported first.
    #[test]
    fn the_scheme_is_part_of_the_identity() {
        let socks = entry("user", "pass");
        let mut http = entry("user", "pass");
        http.kind = ProxyKind::Http;
        assert!(!socks.same_connection(&http));

        let mut store = Vec::new();
        assert_eq!(append_new(&mut store, vec![socks.clone(), http]), 2);
        assert_eq!(append_new(&mut store, vec![socks]), 0);
    }

    #[test]
    fn bulk_import_accepts_name_tag() {
        let parsed = parse_bulk(
            "host.example:1080:user:pass # name=proxy-PL-1 country=PL note=keep",
            ProxyKind::Socks5,
        );

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "proxy-PL-1");
        assert_eq!(parsed[0].country, "PL");
        assert_eq!(parsed[0].notes, "keep");
    }
}
