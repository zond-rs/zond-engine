// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Loopback services that hear only this process
//!
//! Loopback is shared by the whole machine, so another scanner running on it
//! reaches the services tests stand up. The services here take connections only
//! from this process and close any other unread, so what they report is what the
//! test's own pass sent.
//!
//! A connection is this process's when its far end is the local end of a socket
//! this process holds, checked at accept. Every pass a service here answers keeps
//! its connection open for half a second or more while waiting on the answer,
//! well past an accept on loopback. A connection closed sooner (a connect scan's)
//! is closed unread like a foreign one; [`SilentPort`] keeps those too.
//!
//! A datagram is this process's when its source is the local end of a datagram
//! socket this process holds. A pass waits on its socket for the answer, so the
//! socket is still held when a peer reads. [`SilentUdpPort`], which answers
//! nothing, reads each datagram on arrival from its own thread for the same
//! reason.

use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Whether `endpoint` is the local end of a socket this process holds.
///
/// Every open descriptor is asked for its local address. One closed or reused
/// meanwhile is no socket of the pass's either way.
#[cfg(unix)]
pub(crate) fn held_here(endpoint: SocketAddr) -> bool {
    let Ok(descriptors) = std::fs::read_dir("/dev/fd") else {
        return false;
    };
    descriptors
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .any(|fd| local_end(fd) == Some(endpoint))
}

/// Whether `source` is the local end of a datagram socket this process holds.
///
/// A socket bound to the unspecified address matches by port alone: one bound
/// to `0.0.0.0` sends to loopback from `127.0.0.1`. Stream sockets are skipped.
#[cfg(unix)]
pub(crate) fn sent_here(source: SocketAddr) -> bool {
    let Ok(descriptors) = std::fs::read_dir("/dev/fd") else {
        return false;
    };
    descriptors
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| is_datagram_socket(*fd))
        .filter_map(local_end)
        .any(|local| {
            local.port() == source.port()
                && (local.ip().is_unspecified()
                    || local.ip().to_canonical() == source.ip().to_canonical())
        })
}

/// Without `/dev/fd`, every datagram counts as this process's, as in
/// [`held_here`].
#[cfg(not(unix))]
pub(crate) fn sent_here(_source: SocketAddr) -> bool {
    true
}

/// Whether `fd` names a datagram socket.
#[cfg(unix)]
fn is_datagram_socket(fd: libc::c_int) -> bool {
    let mut kind: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `kind` and `len` are live locals, and `len` states the size of
    // `kind`, which `getsockopt` writes no more than. A descriptor that is
    // closed or no socket is an error it returns having written nothing.
    let asked = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut kind).cast(),
            &raw mut len,
        )
    };
    asked == 0 && kind == libc::SOCK_DGRAM
}

/// Without `/dev/fd`, every connection counts as this process's, so another
/// scanner can still reach the services there.
#[cfg(not(unix))]
pub(crate) fn held_here(_endpoint: SocketAddr) -> bool {
    true
}

/// The local address of the socket `fd` names, or `None` where it names no
/// internet socket.
#[cfg(unix)]
fn local_end(fd: libc::c_int) -> Option<SocketAddr> {
    // SAFETY: `try_init` hands over zeroed storage and its size, which
    // `getsockname` writes no more than, setting the size to what it wrote.
    // A descriptor that is closed or no socket is an error it returns having
    // written nothing.
    let ((), address) = unsafe {
        socket2::SockAddr::try_init(|storage, len| {
            match libc::getsockname(fd, storage.cast(), len) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            }
        })
    }
    .ok()?;
    address.as_socket()
}

/// The connections `listener` accepts from this process, in the order it
/// accepts them. Any other process's is closed unread.
pub(crate) fn from_this_process(
    listener: &std::net::TcpListener,
) -> impl Iterator<Item = std::net::TcpStream> + '_ {
    listener
        .incoming()
        .flatten()
        .filter(|sock| sock.peer_addr().is_ok_and(held_here))
}

/// The next connection `listener` accepts from this process. Any other
/// process's is closed unread.
pub(crate) async fn accept_from_this_process(
    listener: &tokio::net::TcpListener,
) -> std::io::Result<tokio::net::TcpStream> {
    loop {
        let (sock, peer) = listener.accept().await?;
        if held_here(peer) {
            return Ok(sock);
        }
    }
}

/// The next datagram `socket` receives from this process, into `buf`, with
/// its length and source. Any other process's is read and dropped.
pub(crate) async fn recv_from_this_process(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    loop {
        let (len, source) = socket.recv_from(buf).await?;
        if sent_here(source) {
            return Ok((len, source));
        }
    }
}

/// [`recv_from_this_process`] for a peer served from a thread of its own. A
/// read timeout set on `socket` ends the wait as it ends a plain read.
pub(crate) fn recv_from_this_process_blocking(
    socket: &std::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    loop {
        let (len, source) = socket.recv_from(buf)?;
        if sent_here(source) {
            return Ok((len, source));
        }
    }
}

/// A TLS acceptor with a certificate for `name` alone, so a handshake naming
/// nothing or another name is refused. Minted per call, so no key is in the tree.
pub(crate) fn tls_by_name(name: &str) -> tokio_rustls::TlsAcceptor {
    use rustls::server::ResolvesServerCertUsingSni;
    use rustls::sign::CertifiedKey;

    let cert = rcgen::generate_simple_self_signed(vec![name.to_string()])
        .expect("a self-signed certificate");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.key_pair.serialize_der(),
    ));
    let signing = rustls::crypto::ring::sign::any_supported_type(&key).expect("a signing key");
    let mut by_name = ResolvesServerCertUsingSni::new();
    by_name
        .add(
            name,
            CertifiedKey::new(vec![cert.cert.der().clone()], signing),
        )
        .expect("the name takes the certificate");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default versions")
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(by_name));
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// A loopback HTTPS site named `name`, as on a virtual-hosting server: a handshake
/// that does not name it is refused, and a request whose `Host` is not `name` and
/// the port gets `404`. A request for the site gets `200` with the body `page`
/// gives, or `404` where it gives none.
pub(crate) async fn https_site(name: &str, page: fn(&str) -> Option<&'static str>) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let acceptor = tls_by_name(name);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds loopback");
    let addr = listener.local_addr().expect("a local address");
    let site = format!("\r\nhost: {name}:{}\r\n", addr.port());
    tokio::spawn(async move {
        while let Ok(stream) = accept_from_this_process(&listener).await {
            let (acceptor, site) = (acceptor.clone(), site.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buffer = [0u8; 4096];
                let read = tls.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]);
                let body = request
                    .to_ascii_lowercase()
                    .contains(&site)
                    .then(|| page(&request))
                    .flatten();
                let reply = match body {
                    Some(body) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    None => {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    }
                };
                let _ = tls.write_all(reply.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

/// A loopback port that says nothing and records each connection this process
/// opens to it and what it sends. Stands in for a service that waits to be spoken
/// to, a printer's raw-print port, or a port a pass must not reach.
///
/// Served from its own threads, independent of the pass's runtime.
pub(crate) struct SilentPort {
    addr: SocketAddr,
    heard: Arc<(Mutex<Vec<Connection>>, Condvar)>,
    /// The far ends of its own marker connections, left out of every count.
    markers: Mutex<Vec<SocketAddr>>,
}

/// One connection a [`SilentPort`] took.
struct Connection {
    /// Its far end.
    from: SocketAddr,
    /// What it had sent by the last read.
    sent: Vec<u8>,
    /// Whether it has been read to its close.
    closed: bool,
    /// Whether its far end identified it as this process's; false where that
    /// end had hung up before the accept.
    told: bool,
}

/// How long [`SilentPort::heard`] waits for earlier connections to close. Only
/// a connection left open runs it out.
const CLOSE_PATIENCE: Duration = Duration::from_secs(60);

/// Everything `sock` was sent if its far end had hung up by the accept, or `None`
/// where it is still open. See [`SilentPort::open`].
fn already_ended(sock: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    use std::io::{ErrorKind, Read};
    sock.set_nonblocking(true).ok()?;
    let mut sent = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        match sock.read(&mut buffer) {
            Ok(0) => return Some(sent),
            Ok(read) => sent.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == ErrorKind::WouldBlock => return None,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Some(sent),
        }
    }
}

/// When this process last opened a [`SilentPort`] at each address.
static OPENED: std::sync::LazyLock<
    Mutex<std::collections::HashMap<SocketAddr, std::time::Instant>>,
> = std::sync::LazyLock::new(Mutex::default);

/// When this process last opened a [`SilentPort`] at `addr`, for a count of
/// connections begun there to start from: tests share a process, and one begun
/// earlier went to whatever held the port then, often an earlier test's listener.
pub(crate) fn opened_at(addr: SocketAddr) -> Option<std::time::Instant> {
    OPENED.lock().unwrap().get(&addr).copied()
}

impl SilentPort {
    /// Opens one on an unused loopback port.
    ///
    /// Unlike [`from_this_process`], it keeps a connection whose far end hung up
    /// before the accept, since its owner can no longer be told. A pass that
    /// connects and at once lets go, or writes and hangs up as a print job does,
    /// is then still caught by [`heard`](Self::heard).
    ///
    /// So another process can affect the record only by connecting, writing and
    /// hanging up within moments of the handshake without waiting for a reply.
    /// Scanners that ask wait on an answer, and ones that only knock write
    /// nothing.
    ///
    /// Its address is noted as [opened](opened_at), since a connection begun
    /// there earlier went to whatever held the port then.
    pub(crate) fn open() -> Self {
        Self::listening(std::net::TcpListener::bind("127.0.0.1:0").expect("binds loopback"))
    }

    /// [`open`](Self::open), on `addr`, for a test that must reuse a port.
    pub(crate) fn open_at(addr: SocketAddr) -> Self {
        Self::listening(std::net::TcpListener::bind(addr).expect("binds the port"))
    }

    /// One serving `listener`.
    fn listening(listener: std::net::TcpListener) -> Self {
        let addr = listener.local_addr().expect("a local address");
        OPENED
            .lock()
            .unwrap()
            .insert(addr, std::time::Instant::now());
        let heard = Arc::new((Mutex::new(Vec::<Connection>::new()), Condvar::new()));
        let log = Arc::clone(&heard);
        std::thread::spawn(move || {
            loop {
                let Ok((mut sock, from)) = listener.accept() else {
                    continue;
                };
                let ended = match held_here(from) {
                    true => None,
                    false => match already_ended(&mut sock) {
                        Some(sent) => Some(sent),
                        None => continue,
                    },
                };
                let closed = ended.is_some();
                let index = {
                    let mut connections = log.0.lock().unwrap();
                    connections.push(Connection {
                        from,
                        sent: ended.unwrap_or_default(),
                        closed,
                        told: !closed,
                    });
                    log.1.notify_all();
                    connections.len() - 1
                };
                if closed {
                    continue;
                }
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    use std::io::Read;
                    let mut buffer = [0u8; 1024];
                    loop {
                        let read = sock.read(&mut buffer).unwrap_or(0);
                        let mut connections = log.0.lock().unwrap();
                        let connection = &mut connections[index];
                        connection.sent.extend_from_slice(&buffer[..read]);
                        connection.closed = read == 0;
                        log.1.notify_all();
                        if read == 0 {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            addr,
            heard,
            markers: Mutex::new(Vec::new()),
        }
    }

    /// Where it listens.
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every byte this process has sent it, once each connection opened to it
    /// before the call has been read to its close.
    ///
    /// What a connection closed before the accept sent is counted too; see
    /// [`open`](Self::open).
    pub(crate) fn heard(&self) -> usize {
        self.settled().iter().map(|(sent, _)| sent.len()).sum()
    }

    /// The bytes [`heard`](Self::heard) counts, in the order the port accepted
    /// their connections.
    pub(crate) fn received(&self) -> Vec<u8> {
        self.settled()
            .into_iter()
            .flat_map(|(sent, _)| sent)
            .collect()
    }

    /// How many connections this process has opened to it that were still
    /// open when the port took them, once each opened before the call has been
    /// read to its close, whether or not they sent anything.
    ///
    /// Only this process moves this count. Connections that hung up before the
    /// accept are left out, since another scanner's connect sweep makes those at
    /// any moment; a test that must see a connect scan's connections counts where
    /// the crate opens them.
    pub(crate) fn connections_told(&self) -> usize {
        self.settled().iter().filter(|(_, told)| *told).count()
    }

    /// What each connection opened before the call sent (markers excluded), once
    /// each is read to its close, and whether it was told for this process's.
    ///
    /// A marker connection is accepted after every earlier one, so once it is,
    /// the earlier ones still open are known and each is waited on.
    fn settled(&self) -> Vec<(Vec<u8>, bool)> {
        let marker = std::net::TcpStream::connect(self.addr).expect("connects to loopback");
        let from = marker.local_addr().expect("a local address");
        let mut markers = self.markers.lock().unwrap();
        markers.push(from);
        let (lock, changed) = &*self.heard;
        let (connections, waited) = changed
            .wait_timeout_while(lock.lock().unwrap(), CLOSE_PATIENCE, |connections| {
                match connections.iter().position(|c| c.from == from) {
                    Some(marker) => connections[..marker].iter().any(|c| !c.closed),
                    None => true,
                }
            })
            .unwrap();
        let before = connections
            .iter()
            .position(|c| c.from == from)
            .unwrap_or(connections.len());
        let before = &connections[..before];
        assert!(
            !waited.timed_out(),
            "a connection to the port was still open after {CLOSE_PATIENCE:?}: {:?}",
            before
                .iter()
                .filter(|c| !c.closed)
                .map(|c| c.from)
                .collect::<Vec<_>>()
        );
        before
            .iter()
            .filter(|c| !markers.contains(&c.from))
            .map(|c| (c.sent.clone(), c.told))
            .collect()
    }
}

/// A loopback UDP port that answers nothing and keeps each datagram this process
/// sends it. Stands in for an absent name server or a server a pass must not ask.
///
/// Its own thread reads each datagram on arrival, while the sender still holds its
/// socket, so the [`recv_from_this_process`] check works. Other processes'
/// datagrams are dropped.
///
/// Dropping it stops the thread and closes the port before returning, so tests
/// under a low descriptor limit do not run out.
pub(crate) struct SilentUdpPort {
    addr: SocketAddr,
    heard: Arc<(Mutex<Heard>, Condvar)>,
    /// Set by the drop, and read by the thread after every datagram.
    stopping: Arc<std::sync::atomic::AtomicBool>,
    reader: Option<std::thread::JoinHandle<()>>,
}

/// What a [`SilentUdpPort`] has kept.
#[derive(Default)]
struct Heard {
    /// Each datagram's source and payload, in the order they arrived.
    datagrams: Vec<(SocketAddr, Vec<u8>)>,
    /// The sources of its own marker datagrams, left out of every report.
    markers: Vec<SocketAddr>,
}

impl Heard {
    /// The payloads a pass sent, in the order they arrived.
    fn sent(&self) -> impl Iterator<Item = &[u8]> {
        self.datagrams
            .iter()
            .filter(|(from, _)| !self.markers.contains(from))
            .map(|(_, payload)| payload.as_slice())
    }
}

/// How long [`SilentUdpPort`] waits for expected datagrams. Only one never sent
/// runs it out.
const DATAGRAM_PATIENCE: Duration = Duration::from_secs(30);

impl SilentUdpPort {
    /// Opens one on an unused loopback port.
    pub(crate) fn open() -> Self {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds loopback");
        let addr = socket.local_addr().expect("a local address");
        let heard = Arc::new((Mutex::new(Heard::default()), Condvar::new()));
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (log, stop) = (Arc::clone(&heard), Arc::clone(&stopping));
        let reader = std::thread::spawn(move || {
            let mut buffer = [0u8; 65_535];
            while let Ok((len, from)) = recv_from_this_process_blocking(&socket, &mut buffer) {
                if stop.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                let mut heard = log.0.lock().unwrap();
                heard.datagrams.push((from, buffer[..len].to_vec()));
                log.1.notify_all();
            }
        });
        Self {
            addr,
            heard,
            stopping,
            reader: Some(reader),
        }
    }

    /// Where it listens.
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every datagram this process sent it before the call, in the order they
    /// arrived.
    ///
    /// A loopback datagram is queued by the time its send returns, so once a
    /// marker sent now has been read, everything before it is recorded.
    pub(crate) fn datagrams(&self) -> Vec<Vec<u8>> {
        let marker = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds loopback");
        let from = marker.local_addr().expect("a local address");
        let (lock, arrived) = &*self.heard;
        lock.lock().unwrap().markers.push(from);
        marker.send_to(&[], self.addr).expect("sends on loopback");
        let (heard, waited) = arrived
            .wait_timeout_while(lock.lock().unwrap(), DATAGRAM_PATIENCE, |heard| {
                !heard.datagrams.iter().any(|(source, _)| *source == from)
            })
            .unwrap();
        assert!(
            !waited.timed_out(),
            "the port's own datagram was not read in {DATAGRAM_PATIENCE:?}"
        );
        heard.sent().map(<[u8]>::to_vec).collect()
    }

    /// Waits, without holding up the runtime it is awaited on, until this
    /// process has sent it at least `count` datagrams.
    ///
    /// # Panics
    ///
    /// Where they have not all arrived within [`DATAGRAM_PATIENCE`].
    pub(crate) async fn arrived(&self, count: usize) {
        let heard = Arc::clone(&self.heard);
        tokio::task::spawn_blocking(move || {
            let (lock, arrived) = &*heard;
            let (_heard, waited) = arrived
                .wait_timeout_while(lock.lock().unwrap(), DATAGRAM_PATIENCE, |heard| {
                    heard.sent().count() < count
                })
                .unwrap();
            assert!(
                !waited.timed_out(),
                "fewer than {count} datagrams arrived in {DATAGRAM_PATIENCE:?}"
            );
        })
        .await
        .expect("the wait does not panic");
    }
}

impl Drop for SilentUdpPort {
    /// Stops the thread and closes the port. A datagram is what ends a blocking
    /// read on every platform, so one is sent from a socket held until the thread
    /// returns (which also makes it pass the this-process check).
    fn drop(&mut self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::Release);
        let Some(reader) = self.reader.take() else {
            return;
        };
        if let Ok(waker) = std::net::UdpSocket::bind("127.0.0.1:0")
            && waker.send_to(&[], self.addr).is_ok()
        {
            let _ = reader.join();
        }
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

/// `count` TCP ports at `ip`, a loopback address, that refuse a connection now
/// and go on refusing one for as long as the test runs, highest first.
///
/// A port found by binding and releasing one is soon handed to another test's
/// service. These count down from 1023, below the ephemeral range where no test
/// binds, and each is kept only if it refuses, since the machine may serve on it.
///
/// # Panics
///
/// Where fewer than `count` of those ports refuse, which is a machine serving
/// on nearly all of them.
pub(crate) fn refused_ports(ip: std::net::IpAddr, count: usize) -> Vec<u16> {
    // Long enough for a stack that retries a reset handshake; only spent on a
    // port that holds a service.
    const REFUSAL_PATIENCE: Duration = Duration::from_secs(3);

    let refused: Vec<u16> = (1..1024u16)
        .rev()
        .filter(|&port| {
            let asked =
                std::net::TcpStream::connect_timeout(&SocketAddr::new(ip, port), REFUSAL_PATIENCE);
            matches!(asked, Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused)
        })
        .take(count)
        .collect();
    assert_eq!(refused.len(), count, "too few ports refuse at {ip}");
    refused
}

/// A TCP port at `ip`, a loopback address, that refuses a connection for as
/// long as the test runs; see [`refused_ports`].
pub(crate) fn refused_port(ip: std::net::IpAddr) -> SocketAddr {
    SocketAddr::new(ip, refused_ports(ip, 1)[0])
}

/// A loopback UDP port that draws the system's port-unreachable and that no other
/// socket can take while the value lives.
///
/// Held by a socket connected to a second one, both bound by
/// [`ClosedUdpPort::open`]. A connected datagram socket takes only its peer's
/// datagrams, so anything else is answered as at a closed port, and the bound port
/// is never handed out. The peer is held too, since its datagrams would be taken.
pub(crate) struct ClosedUdpPort {
    port: u16,
    _held: [std::net::UdpSocket; 2],
}

impl ClosedUdpPort {
    /// Takes one at `ip`.
    pub(crate) fn open(ip: std::net::IpAddr) -> Self {
        let peer = std::net::UdpSocket::bind((ip, 0)).expect("binds loopback");
        let held = std::net::UdpSocket::bind((ip, 0)).expect("binds loopback");
        held.connect(peer.local_addr().expect("a local address"))
            .expect("connects on loopback");
        let port = held.local_addr().expect("a local address").port();
        Self {
            port,
            _held: [held, peer],
        }
    }

    /// Its number.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

/// A loopback TCP port that nothing listens on, held while the value lives and
/// bound so a scan can also use it as its pinned source port. For tests needing
/// source and target to be one number.
///
/// The holder is bound, never listens, and sets `SO_REUSEPORT` as the scan's socket
/// does, so the scan binds beside it and other sockets are refused. A connection
/// to it is refused on Linux and dropped unanswered on macOS.
///
/// It does not set `SO_REUSEADDR`: Linux lets two sockets that both set it share a
/// port while neither listens, and listeners set it, so the next listener would
/// take the port. Windows has no port reuse; there the scan's address reuse binds
/// beside any socket.
pub(crate) struct HeldTcpPort {
    port: u16,
    _held: socket2::Socket,
}

impl HeldTcpPort {
    /// Takes one at `ip`.
    pub(crate) fn open(ip: std::net::IpAddr) -> Self {
        use socket2::{Domain, Socket, Type};

        let domain = match ip {
            std::net::IpAddr::V4(_) => Domain::IPV4,
            std::net::IpAddr::V6(_) => Domain::IPV6,
        };
        let held = Socket::new(domain, Type::STREAM, None).expect("a socket");
        #[cfg(unix)]
        held.set_reuse_port(true).expect("port reuse");
        held.bind(&SocketAddr::new(ip, 0).into())
            .expect("binds loopback");
        let port = held
            .local_addr()
            .ok()
            .and_then(|addr| addr.as_socket())
            .expect("a local address")
            .port();
        Self { port, _held: held }
    }

    /// Its number.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A silent UDP port lets go of its port when dropped.
    ///
    /// Polled, since a process spawned by a concurrent test briefly holds a copy
    /// of every descriptor until its exec, close-on-exec or not.
    #[test]
    fn a_silent_udp_port_lets_go_of_its_port_when_dropped() {
        const RELEASE_PATIENCE: Duration = Duration::from_secs(10);

        let silent = SilentUdpPort::open();
        let addr = silent.addr();
        assert!(
            std::net::UdpSocket::bind(addr).is_err(),
            "the port is held while it is open"
        );

        drop(silent);
        let dropped = std::time::Instant::now();
        while std::net::UdpSocket::bind(addr).is_err() {
            assert!(
                dropped.elapsed() < RELEASE_PATIENCE,
                "the port was still held {RELEASE_PATIENCE:?} after the drop"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// A closed UDP port refuses a datagram while held, and no other socket can
    /// take it.
    #[test]
    fn a_closed_udp_port_refuses_and_stays_taken_while_held() {
        for ip in [
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ] {
            let closed = ClosedUdpPort::open(ip);
            let target = SocketAddr::new(ip, closed.port());

            let asker = std::net::UdpSocket::bind((ip, 0)).expect("binds loopback");
            asker.connect(target).expect("connects on loopback");
            asker
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("a timeout");
            asker.send(b"anyone").expect("sends on loopback");
            let answer = asker.recv(&mut [0u8; 16]).map_err(|error| error.kind());
            assert_eq!(
                answer,
                Err(std::io::ErrorKind::ConnectionRefused),
                "{ip}: the port did not refuse"
            );

            assert!(
                std::net::UdpSocket::bind(target).is_err(),
                "{ip}: another socket took the port while it was held"
            );
        }
    }

    /// A held TCP port admits a socket bound as a scan binds a pinned source
    /// port, and refuses a standard-library listener (which sets address reuse
    /// on Unix).
    #[test]
    fn a_held_tcp_port_stays_taken_and_admits_a_pinned_source() {
        use socket2::{Domain, Socket, Type};

        for ip in [
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ] {
            let held = HeldTcpPort::open(ip);
            let target = SocketAddr::new(ip, held.port());

            assert!(
                std::net::TcpListener::bind(target).is_err(),
                "{ip}: another socket took the port while it was held"
            );

            let domain = match ip {
                std::net::IpAddr::V4(_) => Domain::IPV4,
                std::net::IpAddr::V6(_) => Domain::IPV6,
            };
            let pinned = Socket::new(domain, Type::STREAM, None).expect("a socket");
            pinned.set_reuse_address(true).expect("address reuse");
            #[cfg(unix)]
            pinned.set_reuse_port(true).expect("port reuse");
            let wildcard = match ip {
                std::net::IpAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            };
            pinned
                .bind(&SocketAddr::new(wildcard, held.port()).into())
                .unwrap_or_else(|error| panic!("{ip}: a pinned source was refused: {error}"));
        }
    }

    /// A connection's far end is this process's while held and not once let go.
    #[cfg(unix)]
    #[test]
    fn a_connection_is_this_processs_while_it_holds_the_far_end() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds loopback");
        let near = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_accepted, far) = listener.accept().expect("accepts");

        assert!(held_here(far), "a socket this process holds was not found");
        drop(near);
        assert!(
            !held_here(far),
            "an endpoint no socket of this process holds was taken for one"
        );
    }

    /// A refused port refuses and is never handed to a socket asking for any
    /// port.
    #[test]
    fn a_refused_port_is_never_handed_to_a_socket_asking_for_any() {
        let ip = std::net::IpAddr::from([127, 0, 0, 1]);
        let refused = refused_ports(ip, 2);
        assert_ne!(refused[0], refused[1], "two ports, not one twice");

        // Held together, so each gets a distinct port; few enough for a low
        // descriptor limit.
        let asking: Vec<std::net::TcpListener> = (0..32)
            .map(|_| std::net::TcpListener::bind((ip, 0)).expect("binds loopback"))
            .collect();
        for listener in &asking {
            let handed = listener.local_addr().expect("an address").port();
            assert!(!refused.contains(&handed), "port {handed} was handed out");
        }
        for port in refused {
            let asked = std::net::TcpStream::connect(SocketAddr::new(ip, port));
            assert_eq!(
                asked.map(|_| ()).map_err(|error| error.kind()),
                Err(std::io::ErrorKind::ConnectionRefused),
                "port {port}"
            );
        }
    }

    /// A datagram's source is this process's while held, bound to loopback or
    /// to every address, and not once let go; a stream socket at the same number
    /// does not count.
    #[cfg(unix)]
    #[test]
    fn a_datagram_is_this_processs_while_it_holds_the_socket_it_came_from() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds loopback");
        let to = peer.local_addr().unwrap();
        let mut buf = [0u8; 8];
        for bound in ["127.0.0.1:0", "0.0.0.0:0"] {
            let sender = std::net::UdpSocket::bind(bound).expect("binds");
            sender.send_to(b"x", to).expect("sends");
            let (_, source) = peer.recv_from(&mut buf).expect("receives");
            assert!(sent_here(source), "a socket bound to {bound} was not found");
            drop(sender);
            assert!(!sent_here(source), "a socket let go of was taken for one");

            // A listener on the same number is not a datagram sender.
            if let Ok(listener) = std::net::TcpListener::bind(source) {
                assert!(!sent_here(source), "a stream socket was taken for one");
                drop(listener);
            }
        }
    }

    /// A peer's read passes over a datagram from a socket this process does
    /// not hold and hands back the next from one it does.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_datagram_from_elsewhere_is_passed_over() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let to = peer.local_addr().unwrap();
        let elsewhere = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        elsewhere.send_to(b"elsewhere", to).unwrap();
        drop(elsewhere);
        let here = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        here.send_to(b"here", to).unwrap();

        let mut buf = [0u8; 16];
        let (len, source) = recv_from_this_process(&peer, &mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"here");
        assert_eq!(source, here.local_addr().unwrap());
    }

    /// Everything sent before the count is counted, and the markers are not.
    #[test]
    fn a_silent_port_hears_everything_sent_before_it_is_asked() {
        use std::io::Write;

        let silent = SilentPort::open();
        let held: Vec<std::net::TcpStream> = [&b"GET / HTTP/1.0\r\n\r\n"[..], b"\r\n\r\n"]
            .into_iter()
            .map(|bytes| {
                let mut sock = std::net::TcpStream::connect(silent.addr()).unwrap();
                sock.write_all(bytes).unwrap();
                // Closed for writing and still held, as a pass waiting on an
                // answer holds it.
                sock.shutdown(std::net::Shutdown::Write).unwrap();
                sock
            })
            .collect();

        assert_eq!(silent.heard(), 22);
        assert_eq!(silent.received(), b"GET / HTTP/1.0\r\n\r\n\r\n\r\n");
        assert_eq!(silent.heard(), 22, "the count's own connection counted");
        assert_eq!(
            silent.connections_told(),
            2,
            "the counts' own connections counted"
        );
        drop(held);
    }

    /// Where [`send_one_datagram`] sends, in the process it runs in.
    #[cfg(unix)]
    const SEND_TO: &str = "ZOND_TEST_DATAGRAM_TO";

    /// A silent UDP port keeps what this process sent it, even after the
    /// sending socket is let go, and nothing another process sent.
    #[cfg(unix)]
    #[test]
    fn a_silent_udp_port_keeps_this_processs_datagrams_and_no_others() {
        let silent = SilentUdpPort::open();
        let here = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        here.send_to(b"here", silent.addr()).unwrap();
        assert_eq!(silent.datagrams(), [b"here"]);
        drop(here);

        let path = format!(
            "{}::send_one_datagram",
            module_path!().split_once("::").expect("a crate path").1
        );
        let elsewhere = std::process::Command::new(std::env::current_exe().unwrap())
            .args([path.as_str(), "--exact", "--ignored", "--test-threads=1"])
            .env(SEND_TO, silent.addr().to_string())
            .output()
            .expect("another process runs");
        let said = String::from_utf8_lossy(&elsewhere.stdout);
        assert!(
            elsewhere.status.success() && said.contains("1 passed"),
            "the other process sent nothing:\n{said}"
        );

        assert_eq!(
            silent.datagrams(),
            [b"here"],
            "another process's datagram was kept"
        );
    }

    /// The other process for
    /// [`a_silent_udp_port_keeps_this_processs_datagrams_and_no_others`]: sends
    /// one datagram to [`SEND_TO`].
    #[cfg(unix)]
    #[test]
    #[ignore = "the sender another test runs in a process of its own"]
    fn send_one_datagram() {
        if let Ok(to) = std::env::var(SEND_TO) {
            let to: SocketAddr = to.parse().expect("an address");
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.send_to(b"elsewhere", to).unwrap();
        }
    }
}
