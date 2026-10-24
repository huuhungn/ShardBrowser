//! Local relay for proxy credentials the engine cannot carry inline (#100).
//!
//! The engine takes its proxy as `--proxy-server=scheme://user:pass@host:port`
//! and sends the userinfo exactly as written: it does not percent-decode it,
//! and it cannot carry `,` `;` `=` `:` or non-ASCII there at all. So when the
//! stored credentials hold anything beyond the bytes in [`needs_relay`], the
//! engine is pointed at a relay on 127.0.0.1 instead.
//!
//! The engine authenticates to the relay with a per-launch alphanumeric token,
//! which it can carry inline. The relay authenticates upstream with the stored
//! credentials as raw bytes, so they never reach the engine's command line.
//! The relay speaks the upstream's own protocol family to the engine (HTTP for
//! HTTP/HTTPS proxies, SOCKS5 for SOCKS5), so plain HTTP still goes upstream as
//! an absolute-form request and SOCKS commands pass through untouched.
//!
//! There is no direct path: when the upstream is unreachable or refuses, the
//! request fails. The relay lives exactly as long as its [`RelayHandle`].

use crate::errcode;
use crate::proxy::{ProxyEntry, ProxyKind};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

const HEAD_LIMIT: usize = 64 * 1024;
/// The engine keeps preconnected sockets idle for a while before using them.
const CLIENT_IDLE: Duration = Duration::from_secs(120);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);
/// The upstream answers a SOCKS CONNECT only after reaching the target.
const UPSTREAM_REPLY: Duration = Duration::from_secs(60);

/// Bytes the engine carries inline unchanged. They are also exactly the bytes
/// `form_urlencoded` leaves alone, so for credentials made only of these the
/// inline argument is byte-for-byte what it has always been.
fn inline_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'*' | b'-' | b'.' | b'_')
}

/// Whether `entry` has credentials the engine cannot carry inline.
pub fn needs_relay(entry: &ProxyEntry) -> bool {
    entry
        .username
        .bytes()
        .chain(entry.password.bytes())
        .any(|b| !inline_safe(b))
}

/// A running relay. Dropping it closes the port and every open connection.
pub struct RelayHandle {
    port: u16,
    scheme: &'static str,
    user: String,
    pass: String,
    task: JoinHandle<()>,
}

impl RelayHandle {
    /// The engine's `--proxy-server` value: loopback plus the launch token.
    pub fn proxy_server_arg(&self) -> String {
        format!(
            "{}://{}:{}@127.0.0.1:{}",
            self.scheme, self.user, self.pass, self.port
        )
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Relay {
    upstream: ProxyEntry,
    tls: Option<tokio_rustls::TlsConnector>,
    user: String,
    pass: String,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Start a relay to `upstream` on an ephemeral loopback port.
pub async fn start(upstream: ProxyEntry) -> Result<RelayHandle> {
    if matches!(upstream.kind, ProxyKind::Socks5)
        && (upstream.username.len() > 255 || upstream.password.len() > 255)
    {
        // RFC 1929 carries each in a one-byte length.
        anyhow::bail!("{}", errcode::code("proxy.credentialsTooLong"));
    }
    let tls = match upstream.kind {
        ProxyKind::Https => {
            Some(tls_connector().context(errcode::code("launch.proxyRelayFailed"))?)
        }
        _ => None,
    };
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .context(errcode::code("launch.proxyRelayFailed"))?;
    let port = listener
        .local_addr()
        .context(errcode::code("launch.proxyRelayFailed"))?
        .port();
    let scheme = match upstream.kind {
        ProxyKind::Socks5 => "socks5",
        ProxyKind::Http | ProxyKind::Https => "http",
    };
    let user = uuid::Uuid::new_v4().simple().to_string();
    let pass = uuid::Uuid::new_v4().simple().to_string();
    let relay = Arc::new(Relay {
        upstream,
        tls,
        user: user.clone(),
        pass: pass.clone(),
    });
    let task = tokio::spawn(accept_loop(listener, relay));
    Ok(RelayHandle {
        port,
        scheme,
        user,
        pass,
        task,
    })
}

async fn accept_loop(listener: TcpListener, relay: Arc<Relay>) {
    // Owned by this task, so aborting it drops (and aborts) every connection.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let relay = relay.clone();
                    connections.spawn(async move {
                        let _ = stream.set_nodelay(true);
                        let client = BufReader::new(stream);
                        let _ = match relay.upstream.kind {
                            ProxyKind::Socks5 => relay.serve_socks(client).await,
                            ProxyKind::Http | ProxyKind::Https => relay.serve_http(client).await,
                        };
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

fn tls_connector() -> Result<tokio_rustls::TlsConnector> {
    use tokio_rustls::rustls;
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// Constant-time byte comparison for the launch token.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn header_name_is(line: &[u8], name: &str) -> bool {
    line.iter()
        .position(|&b| b == b':')
        .is_some_and(|i| line[..i].trim_ascii().eq_ignore_ascii_case(name.as_bytes()))
}

fn header_value(line: &[u8]) -> &[u8] {
    line.iter()
        .position(|&b| b == b':')
        .map(|i| line[i + 1..].trim_ascii())
        .unwrap_or_default()
}

/// Read an HTTP request head; lines come back without their line endings.
async fn read_head<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Vec<Vec<u8>>> {
    let mut lines = Vec::new();
    let mut total = 0usize;
    loop {
        let mut line = Vec::new();
        let n = (&mut *reader)
            .take((HEAD_LIMIT - total) as u64)
            .read_until(b'\n', &mut line)
            .await?;
        anyhow::ensure!(n > 0 && line.ends_with(b"\n"), "incomplete request head");
        total += n;
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        if line.is_empty() {
            if lines.is_empty() {
                continue;
            }
            return Ok(lines);
        }
        lines.push(line);
    }
}

impl Relay {
    async fn connect_upstream(&self) -> Result<(Box<dyn Io>, IpAddr)> {
        let addr = (self.upstream.host.as_str(), self.upstream.port);
        let tcp = timeout(UPSTREAM_TIMEOUT, TcpStream::connect(addr))
            .await
            .context("upstream connect timed out")??;
        let _ = tcp.set_nodelay(true);
        let peer = tcp.peer_addr()?.ip();
        match &self.tls {
            None => Ok((Box::new(tcp), peer)),
            Some(tls) => {
                let name = tokio_rustls::rustls::pki_types::ServerName::try_from(
                    self.upstream.host.clone(),
                )?;
                let stream = timeout(UPSTREAM_TIMEOUT, tls.connect(name, tcp))
                    .await
                    .context("upstream TLS handshake timed out")??;
                Ok((Box::new(stream), peer))
            }
        }
    }

    fn upstream_basic(&self) -> String {
        let pair = format!("{}:{}", self.upstream.username, self.upstream.password);
        format!("Basic {}", STANDARD.encode(pair))
    }

    async fn serve_http(&self, mut client: BufReader<TcpStream>) -> Result<()> {
        let lines = timeout(CLIENT_IDLE, read_head(&mut client)).await??;
        let (request_line, headers) = lines.split_first().context("empty request head")?;
        let expected = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.user, self.pass))
        );
        let authorized = headers.iter().any(|h| {
            header_name_is(h, "proxy-authorization") && same(header_value(h), expected.as_bytes())
        });
        if !authorized {
            client
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"ShardX\"\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            return Ok(());
        }

        // Upstream proxies authenticate each request, so anything but a
        // tunnel is one request per connection: the relay only touches the
        // first head it sees on a connection.
        let tunnel = request_line.starts_with(b"CONNECT ");
        let mut head = Vec::with_capacity(lines.iter().map(|l| l.len() + 2).sum::<usize>() + 128);
        head.extend_from_slice(request_line);
        head.extend_from_slice(b"\r\n");
        for h in headers {
            let hop = header_name_is(h, "proxy-authorization")
                || header_name_is(h, "proxy-connection")
                || (!tunnel && header_name_is(h, "connection"));
            if !hop {
                head.extend_from_slice(h);
                head.extend_from_slice(b"\r\n");
            }
        }
        head.extend_from_slice(
            format!("Proxy-Authorization: {}\r\n", self.upstream_basic()).as_bytes(),
        );
        if !tunnel {
            head.extend_from_slice(b"Connection: close\r\n");
        }
        head.extend_from_slice(b"\r\n");

        let mut upstream = match self.connect_upstream().await {
            Ok((upstream, _)) => upstream,
            Err(_) => {
                client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await?;
                return Ok(());
            }
        };
        upstream.write_all(&head).await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    }

    async fn socks_upstream(&self) -> Result<(Box<dyn Io>, IpAddr)> {
        let (mut upstream, peer) = self.connect_upstream().await?;
        let user = self.upstream.username.as_bytes();
        let pass = self.upstream.password.as_bytes();
        upstream.write_all(&[0x05, 0x01, 0x02]).await?;
        let mut reply = [0u8; 2];
        timeout(UPSTREAM_TIMEOUT, upstream.read_exact(&mut reply)).await??;
        anyhow::ensure!(
            reply == [0x05, 0x02],
            "upstream refused username/password auth"
        );
        let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
        auth.push(0x01);
        auth.push(user.len() as u8);
        auth.extend_from_slice(user);
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass);
        upstream.write_all(&auth).await?;
        timeout(UPSTREAM_TIMEOUT, upstream.read_exact(&mut reply)).await??;
        anyhow::ensure!(reply[1] == 0x00, "upstream rejected the credentials");
        Ok((upstream, peer))
    }

    async fn serve_socks(&self, mut client: BufReader<TcpStream>) -> Result<()> {
        let mut greeting = [0u8; 2];
        timeout(CLIENT_IDLE, client.read_exact(&mut greeting)).await??;
        anyhow::ensure!(greeting[0] == 0x05, "not SOCKS5");
        let mut methods = vec![0u8; greeting[1] as usize];
        client.read_exact(&mut methods).await?;
        if !methods.contains(&0x02) {
            client.write_all(&[0x05, 0xFF]).await?;
            return Ok(());
        }
        client.write_all(&[0x05, 0x02]).await?;
        let mut version_len = [0u8; 2];
        client.read_exact(&mut version_len).await?;
        let mut user = vec![0u8; version_len[1] as usize];
        client.read_exact(&mut user).await?;
        let mut pass = vec![0u8; client.read_u8().await? as usize];
        client.read_exact(&mut pass).await?;
        let token_ok = same(&user, self.user.as_bytes()) & same(&pass, self.pass.as_bytes());
        if version_len[0] != 0x01 || !token_ok {
            client.write_all(&[0x01, 0x01]).await?;
            return Ok(());
        }
        client.write_all(&[0x01, 0x00]).await?;

        // The engine's request (CONNECT, or UDP ASSOCIATE when the upstream
        // relays UDP) goes upstream verbatim, and so does the reply.
        let mut request = [0u8; 3];
        timeout(CLIENT_IDLE, client.read_exact(&mut request)).await??;
        anyhow::ensure!(request[0] == 0x05, "not SOCKS5");
        let target = read_socks_addr(&mut client).await?;
        let (mut upstream, peer) = match self.socks_upstream().await {
            Ok(upstream) => upstream,
            Err(_) => {
                // General SOCKS server failure.
                client
                    .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                return Ok(());
            }
        };
        upstream.write_all(&request).await?;
        upstream.write_all(&target).await?;
        let mut reply = [0u8; 3];
        timeout(UPSTREAM_REPLY, upstream.read_exact(&mut reply)).await??;
        let mut bound = timeout(UPSTREAM_TIMEOUT, read_socks_addr(&mut upstream)).await??;
        // An unspecified UDP relay address means "the address you dialled",
        // which for the engine is 127.0.0.1; name the upstream instead.
        if request[1] == 0x03 && reply[1] == 0x00 && is_unspecified(&bound) {
            bound = socks_addr(
                peer,
                u16::from_be_bytes([bound[bound.len() - 2], bound[bound.len() - 1]]),
            );
        }
        client.write_all(&reply).await?;
        client.write_all(&bound).await?;
        if reply[1] != 0x00 {
            return Ok(());
        }
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    }
}

/// Read a SOCKS5 `ATYP ADDR PORT` block, returned as it was on the wire.
async fn read_socks_addr<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let atyp = reader.read_u8().await?;
    let mut out = vec![atyp];
    let len = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let len = reader.read_u8().await?;
            out.push(len);
            len as usize
        }
        _ => anyhow::bail!("unknown SOCKS address type"),
    };
    let start = out.len();
    out.resize(start + len + 2, 0);
    reader.read_exact(&mut out[start..]).await?;
    Ok(out)
}

fn is_unspecified(addr: &[u8]) -> bool {
    match addr.first() {
        Some(0x01) => addr[1..5] == [0; 4],
        Some(0x04) => addr[1..17] == [0; 16],
        _ => false,
    }
}

fn socks_addr(ip: IpAddr, port: u16) -> Vec<u8> {
    let mut out = match ip {
        IpAddr::V4(v4) => [&[0x01][..], &v4.octets()].concat(),
        IpAddr::V6(v6) => [&[0x04][..], &v6.octets()].concat(),
    };
    out.extend_from_slice(&port.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    const USER: &str = "user,country-GB;session=ab é+đ";
    const PASS: &str = "p a+s%2C;s=é,đ:x";
    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

    fn entry(kind: ProxyKind, port: u16) -> ProxyEntry {
        ProxyEntry {
            id: String::new(),
            name: "relay-test".into(),
            kind,
            host: "127.0.0.1".into(),
            port,
            username: USER.into(),
            password: PASS.into(),
            country: String::new(),
            notes: String::new(),
        }
    }

    fn token_basic(relay: &RelayHandle) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", relay.user, relay.pass))
        )
    }

    struct Task(JoinHandle<()>);
    impl Drop for Task {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    /// HTTP proxy that records each request head and answers or tunnels.
    async fn http_upstream() -> (u16, Arc<Mutex<Vec<Vec<String>>>>, Task) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let log = log.clone();
                tokio::spawn(async move {
                    let mut s = BufReader::new(stream);
                    let Ok(head) = read_head(&mut s).await else {
                        return;
                    };
                    let head: Vec<String> = head
                        .iter()
                        .map(|l| String::from_utf8_lossy(l).into_owned())
                        .collect();
                    let tunnel = head[0].starts_with("CONNECT ");
                    log.lock().unwrap().push(head);
                    if tunnel {
                        let _ = s
                            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                            .await;
                        let mut buf = [0u8; 5];
                        if s.read_exact(&mut buf).await.is_ok() {
                            let _ = s.write_all(&buf).await;
                        }
                    } else {
                        let _ = s.write_all(OK).await;
                    }
                });
            }
        });
        (port, seen, Task(task))
    }

    type SocksLog = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>>>;

    /// SOCKS5 proxy that records credentials and the CONNECT target, then
    /// answers one HTTP request.
    async fn socks_upstream() -> (u16, SocksLog, Task) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: SocksLog = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let log = log.clone();
                tokio::spawn(async move {
                    let _ = async {
                        let mut s = BufReader::new(stream);
                        let mut g = [0u8; 2];
                        s.read_exact(&mut g).await?;
                        let mut methods = vec![0u8; g[1] as usize];
                        s.read_exact(&mut methods).await?;
                        s.write_all(&[5, 2]).await?;
                        let mut v = [0u8; 2];
                        s.read_exact(&mut v).await?;
                        let mut user = vec![0u8; v[1] as usize];
                        s.read_exact(&mut user).await?;
                        let mut pass = vec![0u8; s.read_u8().await? as usize];
                        s.read_exact(&mut pass).await?;
                        s.write_all(&[1, 0]).await?;
                        let mut req = [0u8; 4];
                        s.read_exact(&mut req).await?;
                        let mut target = match req[3] {
                            1 => vec![0u8; 6],
                            4 => vec![0u8; 18],
                            _ => vec![0u8; s.read_u8().await? as usize + 2],
                        };
                        s.read_exact(&mut target).await?;
                        log.lock().unwrap().push((user, pass, target));
                        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                        read_head(&mut s).await?;
                        s.write_all(OK).await?;
                        anyhow::Ok(())
                    }
                    .await;
                });
            }
        });
        (port, seen, Task(task))
    }

    /// A destination that counts connections; the relay must never dial it.
    async fn destination() -> (u16, Arc<AtomicUsize>, Task) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let count = hits.clone();
        let task = tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                count.fetch_add(1, Ordering::SeqCst);
            }
        });
        (port, hits, Task(task))
    }

    async fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn read_all(stream: &mut TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        timeout(Duration::from_secs(10), stream.read_to_end(&mut out))
            .await
            .expect("relay answered in time")
            .expect("read");
        out
    }

    async fn socks_client(
        relay: &RelayHandle,
        user: &str,
        pass: &str,
        dst: u16,
    ) -> (TcpStream, u8) {
        let mut c = TcpStream::connect(("127.0.0.1", relay.port)).await.unwrap();
        c.write_all(&[5, 1, 2]).await.unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 2]);
        let mut auth = vec![1, user.len() as u8];
        auth.extend_from_slice(user.as_bytes());
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass.as_bytes());
        c.write_all(&auth).await.unwrap();
        c.read_exact(&mut r).await.unwrap();
        if r[1] != 0 {
            return (c, r[1]);
        }
        let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
        req.extend_from_slice(&dst.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        (c, reply[1])
    }

    #[test]
    fn relay_only_for_credentials_the_engine_cannot_carry() {
        let mut e = entry(ProxyKind::Http, 1);
        e.username = "Abc-1.2_x*".into();
        e.password = "S3cret".into();
        assert!(!needs_relay(&e));
        for bad in [",", ";", "=", ":", " ", "+", "%", "@", "é", "đ", "~"] {
            e.password = format!("a{bad}b");
            assert!(needs_relay(&e), "{bad:?} must go through the relay");
        }
        e.username.clear();
        e.password.clear();
        assert!(!needs_relay(&e));
    }

    #[tokio::test]
    async fn http_request_gets_raw_upstream_credentials_and_one_request_per_connection() {
        let (port, seen, _up) = http_upstream().await;
        let relay = start(entry(ProxyKind::Http, port)).await.unwrap();
        assert!(relay.proxy_server_arg().starts_with("http://"));
        assert!(!relay.proxy_server_arg().contains("ab é"));
        let mut c = TcpStream::connect(("127.0.0.1", relay.port)).await.unwrap();
        let request = format!(
            "GET http://example.test/x HTTP/1.1\r\nHost: example.test\r\n\
             Proxy-Connection: keep-alive\r\nProxy-Authorization: {}\r\n\r\n",
            token_basic(&relay)
        );
        c.write_all(request.as_bytes()).await.unwrap();
        assert!(read_all(&mut c).await.ends_with(b"\r\n\r\nok"));

        let heads = seen.lock().unwrap().clone();
        assert_eq!(heads.len(), 1);
        let head = &heads[0];
        assert_eq!(head[0], "GET http://example.test/x HTTP/1.1");
        let auth: Vec<&String> = head
            .iter()
            .filter(|l| l.to_ascii_lowercase().starts_with("proxy-authorization:"))
            .collect();
        let expected = format!(
            "Proxy-Authorization: Basic {}",
            STANDARD.encode(format!("{USER}:{PASS}"))
        );
        assert_eq!(auth, vec![&expected]);
        assert!(head.contains(&"Connection: close".to_string()));
        assert!(!head
            .iter()
            .any(|l| l.to_ascii_lowercase().starts_with("proxy-connection")));
    }

    #[tokio::test]
    async fn http_connect_tunnels_after_authenticating_upstream() {
        let (port, seen, _up) = http_upstream().await;
        let relay = start(entry(ProxyKind::Http, port)).await.unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", relay.port)).await.unwrap();
        let request = format!(
            "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: {}\r\n\r\n",
            token_basic(&relay)
        );
        c.write_all(request.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(c);
        let head = read_head(&mut reader).await.unwrap();
        assert!(head[0].starts_with(b"HTTP/1.1 200"));
        reader.write_all(b"hello").await.unwrap();
        let mut echo = [0u8; 5];
        reader.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello");
        let heads = seen.lock().unwrap().clone();
        let expected = format!(
            "Proxy-Authorization: Basic {}",
            STANDARD.encode(format!("{USER}:{PASS}"))
        );
        assert!(heads[0].contains(&expected));
        assert!(!heads[0].contains(&"Connection: close".to_string()));
    }

    #[tokio::test]
    async fn http_without_the_launch_token_is_challenged_and_goes_nowhere() {
        let (port, seen, _up) = http_upstream().await;
        let relay = start(entry(ProxyKind::Http, port)).await.unwrap();
        for auth in ["", "Proxy-Authorization: Basic d3Jvbmc6dG9rZW4=\r\n"] {
            let mut c = TcpStream::connect(("127.0.0.1", relay.port)).await.unwrap();
            let request =
                format!("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n{auth}\r\n");
            c.write_all(request.as_bytes()).await.unwrap();
            let reply = read_all(&mut c).await;
            assert!(reply.starts_with(b"HTTP/1.1 407"));
        }
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn socks_passes_raw_credentials_and_forwards_the_request_verbatim() {
        let (port, seen, _up) = socks_upstream().await;
        let relay = start(entry(ProxyKind::Socks5, port)).await.unwrap();
        assert!(relay.proxy_server_arg().starts_with("socks5://"));
        let (user, pass) = (relay.user.clone(), relay.pass.clone());
        let (mut c, status) = socks_client(&relay, &user, &pass, 8080).await;
        assert_eq!(status, 0);
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        assert!(read_all(&mut c).await.ends_with(b"\r\n\r\nok"));
        let log = seen.lock().unwrap().clone();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].0, USER.as_bytes());
        assert_eq!(log[0].1, PASS.as_bytes());
        assert_eq!(log[0].2, [127, 0, 0, 1, 0x1F, 0x90]);
    }

    #[tokio::test]
    async fn socks_with_a_wrong_token_never_reaches_upstream() {
        let (port, seen, _up) = socks_upstream().await;
        let relay = start(entry(ProxyKind::Socks5, port)).await.unwrap();
        let (_c, status) = socks_client(&relay, "wrong", "token", 80).await;
        assert_eq!(status, 1);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unreachable_upstream_fails_closed_without_dialling_the_destination() {
        let (dst, hits, _dst) = destination().await;
        let relay = start(entry(ProxyKind::Http, closed_port().await))
            .await
            .unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", relay.port)).await.unwrap();
        let request = format!(
            "GET http://127.0.0.1:{dst}/ HTTP/1.1\r\nHost: 127.0.0.1:{dst}\r\nProxy-Authorization: {}\r\n\r\n",
            token_basic(&relay)
        );
        c.write_all(request.as_bytes()).await.unwrap();
        assert!(read_all(&mut c).await.starts_with(b"HTTP/1.1 502"));

        let relay = start(entry(ProxyKind::Socks5, closed_port().await))
            .await
            .unwrap();
        let (user, pass) = (relay.user.clone(), relay.pass.clone());
        let (_c, status) = socks_client(&relay, &user, &pass, dst).await;
        assert_eq!(status, 1);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn dropping_the_handle_closes_the_port() {
        let (port, _seen, _up) = http_upstream().await;
        let relay = start(entry(ProxyKind::Http, port)).await.unwrap();
        let relay_port = relay.port;
        assert!(TcpStream::connect(("127.0.0.1", relay_port)).await.is_ok());
        drop(relay);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let probe = timeout(
            Duration::from_secs(10),
            TcpStream::connect(("127.0.0.1", relay_port)),
        )
        .await
        .expect("connect attempt finished");
        assert!(probe.is_err(), "relay port still accepts after drop");
    }

    #[tokio::test]
    async fn socks_credentials_over_255_bytes_are_refused_up_front() {
        let mut e = entry(ProxyKind::Socks5, 1);
        e.password = "é".repeat(128);
        let err = start(e).await.err().expect("must refuse");
        assert!(err.to_string().contains("proxy.credentialsTooLong"));
    }

    #[tokio::test]
    async fn reqwest_decodes_the_launcher_proxy_url_back_to_raw_credentials() {
        let (port, seen, _up) = http_upstream().await;
        let client = reqwest::Client::builder()
            .proxy(
                reqwest::Proxy::all(entry(ProxyKind::Http, port).reqwest_proxy_url("socks5h"))
                    .unwrap(),
            )
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let body = client
            .get("http://example.test/")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "ok");
        let expected = format!(
            "proxy-authorization: Basic {}",
            STANDARD.encode(format!("{USER}:{PASS}"))
        );
        assert!(seen.lock().unwrap()[0]
            .iter()
            .any(|l| l.eq_ignore_ascii_case(&expected)
                && l.ends_with(&expected["proxy-authorization: ".len()..])));

        let (port, seen, _up) = socks_upstream().await;
        let client = reqwest::Client::builder()
            .proxy(
                reqwest::Proxy::all(entry(ProxyKind::Socks5, port).reqwest_proxy_url("socks5h"))
                    .unwrap(),
            )
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let body = client
            .get("http://example.test/")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "ok");
        let log = seen.lock().unwrap().clone();
        assert_eq!(log[0].0, USER.as_bytes());
        assert_eq!(log[0].1, PASS.as_bytes());
    }
}
