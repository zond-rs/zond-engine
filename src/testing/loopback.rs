// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Loopback services that hear only this process
//!
//! The engine's tests, the crate's own and the tiers under `tests/` alike,
//! stand services up on loopback for a pass to talk to, and loopback belongs
//! to the whole machine. Any other scanner running on it reaches every port
//! listening there: a scan of all of loopback's ports connects to the test's
//! service as readily as to anything else, and asks it what it asks every
//! open port. A service that answered it, or counted what it sent, would be
//! telling its test about a pass that was not the test's. What a test's
//! service reports has to be what the test's own pass sent, so the services
//! here take connections from this process and close any other unread.
//!
//! A connection is told for this process's by its far end: the local end of a
//! socket this process holds. It is looked for when the connection is
//! accepted, and every pass a service here answers keeps its connection open
//! for at least the wait on the answer, half a second or more, after
//! connecting, which an accept on loopback is well inside. A connection this
//! process closes sooner, as a connect scan closes the one its handshake
//! completed, is closed unread with any other process's, which a connection
//! that asks nothing never notices. [`SilentPort`], which answers nothing and
//! keeps a record of what reached it, keeps those too.

use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Whether `endpoint` is the local end of a socket this process holds, which
/// is what a connection from this process to one of its own listeners has at
/// its far end.
///
/// Every descriptor the process has open is asked for its local address.
/// One closed or reused meanwhile answers for whatever it is by then, which
/// is no socket of the pass's either way.
#[cfg(unix)]
pub(crate) fn held_here(endpoint: SocketAddr) -> bool {
    let Ok(descriptors) = std::fs::read_dir("/dev/fd") else {
        return false;
    };
    descriptors
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .any(|fd| local_end(fd) == Some(endpoint))
}

/// Anywhere without a directory of the process's descriptors, every
/// connection counts as this process's, so a scanner running beside the test
/// there can still reach its services.
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

/// A TLS acceptor keeping a certificate for `name` alone, as a server holding
/// its sites by name keeps one per site, so a handshake naming nothing, or
/// another name, is refused. The certificate is minted per call, so no key
/// lives in the tree.
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

/// A loopback HTTPS site held by `name`, as a server holding several sites at
/// one address holds one: a handshake that does not name it is refused, and a
/// request whose `Host` is not `name` and the port is answered `404`, as the
/// default site would. A request for the site is answered `200` with the body
/// `page` gives for it, or `404` where it gives none.
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

/// A loopback port that says nothing and keeps a record of each connection
/// this process opens to it and everything it sends, standing in for a
/// service that waits to be spoken to first, for a printer's raw-print port,
/// or for a port a pass has promised not to reach.
///
/// Served from threads of its own, so what it hears does not wait on the
/// runtime a pass runs on.
pub(crate) struct SilentPort {
    addr: SocketAddr,
    heard: Arc<(Mutex<Vec<Connection>>, Condvar)>,
    /// The far ends of the connections its counts opened to it, which are
    /// no pass's and are left out of every later count.
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
}

/// How long [`SilentPort::heard`] waits for the connections before it to
/// close, which a pass that has returned has closed already. Long enough
/// that only a connection left open runs it out.
const CLOSE_PATIENCE: Duration = Duration::from_secs(60);

/// Everything `sock` was sent, where its far end had hung up by the time it
/// was accepted, or `None` where the far end still holds it open.
///
/// A connection from this process that ended that soon is no longer told for
/// this process's by its far end; see [`SilentPort::open`].
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

impl SilentPort {
    /// Opens one on an unused loopback port.
    ///
    /// Its record differs from what [`from_this_process`] serves in one case:
    /// a connection whose far end had hung up before it was accepted. No
    /// socket holds that end any more, so which process opened it cannot be
    /// told, and the record keeps it as this process's. A pass that connects
    /// and at once lets go, the way a pass that ought to have connected to
    /// nothing is likeliest to, is then still counted, where a service that
    /// answered would only have been spared a connection it had nothing to
    /// say to. Another process's connection is kept by mistake only if it
    /// ends that soon too, and one that ends having sent nothing adds
    /// nothing but itself to the record.
    pub(crate) fn open() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds loopback");
        let addr = listener.local_addr().expect("a local address");
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
    /// A connection closed before the port took it is not this process's by
    /// then, and goes unheard; see the [module](self) docs.
    pub(crate) fn heard(&self) -> usize {
        self.settled().iter().map(Vec::len).sum()
    }

    /// The bytes [`heard`](Self::heard) counts, a connection's after the one
    /// before it, in the order the port took them.
    pub(crate) fn received(&self) -> Vec<u8> {
        self.settled().concat()
    }

    /// How many connections this process has opened to it, once each opened
    /// before the call has been read to its close, whether or not it sent
    /// anything.
    ///
    /// A connection that sends nothing is still one a pass promised not to
    /// make, so a promise to connect to nothing is checked here rather than
    /// by [`heard`](Self::heard). Like it, it misses a connection closed
    /// before the port took it.
    pub(crate) fn connections(&self) -> usize {
        self.settled().len()
    }

    /// What each connection this process opened before the call sent, other
    /// than the counts' own, once each has been read to its close.
    ///
    /// A pass that has returned has closed its connections, but what it sent
    /// on them may still be on its way to being read. A connection of the
    /// call's own is accepted after all of theirs, since a listener takes
    /// connections in the order they arrive, so once it is, which of theirs
    /// remain open is known, and each is waited on until it closes.
    fn settled(&self) -> Vec<Vec<u8>> {
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
            .map(|c| c.sent.clone())
            .collect()
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
/// A port found by binding one and letting it go is not closed for long: the
/// system hands it straight back to the next socket that asks for any port,
/// which in a test run is another test's service, and the scan counted on a
/// refusal connects to that service instead and is answered or counted there.
/// These are taken from below the range the system hands such a socket, where
/// no test binds, counting down from the top of the ports the system keeps for
/// its own services. Each is asked first and kept only if it refuses, since
/// one may hold a service of the machine's.
///
/// # Panics
///
/// Where fewer than `count` of those ports refuse, which is a machine serving
/// on nearly all of them.
pub(crate) fn refused_ports(ip: std::net::IpAddr, count: usize) -> Vec<u16> {
    // Long enough for a refusal from a stack that retries a reset handshake
    // before giving up, and only ever spent on a port that holds a service.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A connection's far end is one of this process's sockets while this
    /// process holds it and not once it lets go, which is the difference a
    /// service here tells this process's connections from another's by.
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

    /// A refused port refuses, and is none a socket asking for any port is
    /// handed, however many ask.
    ///
    /// Found by binding a port and letting it go, a closed port is the next
    /// one handed out, and a test's scan connects to whichever service took it.
    #[test]
    fn a_refused_port_is_never_handed_to_a_socket_asking_for_any() {
        let ip = std::net::IpAddr::from([127, 0, 0, 1]);
        let refused = refused_ports(ip, 2);
        assert_ne!(refused[0], refused[1], "two ports, not one twice");

        // Held together, so each is handed a port none of the others holds;
        // few enough for a run under a low descriptor limit.
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

    /// What was sent before the count is counted, all of it and nothing
    /// else: the count waits for every earlier connection to be read to its
    /// close, and the connections the counts open are neither heard nor
    /// counted as connections.
    #[test]
    fn a_silent_port_hears_everything_sent_before_it_is_asked() {
        use std::io::Write;

        let silent = SilentPort::open();
        let held: Vec<std::net::TcpStream> = [&b"GET / HTTP/1.0\r\n\r\n"[..], b"\r\n\r\n"]
            .into_iter()
            .map(|bytes| {
                let mut sock = std::net::TcpStream::connect(silent.addr()).unwrap();
                sock.write_all(bytes).unwrap();
                // Closed for writing and still held, as a pass holds a
                // connection until it has waited on the answer.
                sock.shutdown(std::net::Shutdown::Write).unwrap();
                sock
            })
            .collect();

        assert_eq!(silent.heard(), 22);
        assert_eq!(silent.received(), b"GET / HTTP/1.0\r\n\r\n\r\n\r\n");
        assert_eq!(silent.heard(), 22, "the count's own connection counted");
        assert_eq!(
            silent.connections(),
            2,
            "the counts' own connections counted"
        );
        drop(held);
    }
}
