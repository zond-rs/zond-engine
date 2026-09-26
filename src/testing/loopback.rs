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
