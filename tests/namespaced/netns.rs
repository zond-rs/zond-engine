// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A network built out of namespaces, for the tier that needs a real one.
//!
//! An unprivileged user namespace carries the full capability set inside
//! itself, so a process that enters one may create links, address them, shape
//! them and capture on them without ever being root on the machine. That is what
//! lets this tier run under an ordinary `cargo test`.
//!
//! # Why this happens before `main`
//!
//! A network namespace is a property of a task, and a thread created before the
//! move stays where it was. The engine reads its interfaces through a rayon pool
//! and reads frames on threads that [`transport::capture`] spawns, so a scanner
//! whose process moved late would send from one network and listen on another.
//! `CLONE_NEWUSER` also refuses a process that is already threaded.
//!
//! Both problems disappear at the same point: an `.init_array` entry runs before
//! `main`, while the process is still one thread. Nothing has to be re-executed
//! and no wrapper command is needed, which is what keeps
//! `cargo test --test namespaced` an ordinary line.
//!
//! # The shape of a segment
//!
//! ```text
//!   this process                      peer process
//!   10.99.N.1  zvNa <=============> zvNb  10.99.N.2
//!              (this netns)         (its own netns)
//! ```
//!
//! Both ends of a veth pair in one namespace would be short-circuited by the
//! kernel: traffic to a local address never reaches the wire, and a capture
//! would see nothing. So the far end is moved into a namespace of its own,
//! held open by a parked child process, and everything the far side needs is
//! done through `nsenter`. Each [`Segment`] numbers its own links and subnet, so
//! tests that build one at the same time do not collide.

#![allow(dead_code)]

use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// What [`enter`] concluded, since a constructor that runs before `main` has
/// nowhere to return a result to. Zero means the process is in a namespace of
/// its own; anything else is the `errno` that stopped it.
static ENTERED: AtomicI32 = AtomicI32::new(-1);

/// Moves this process into a user and network namespace of its own.
///
/// Registered in `.init_array`, so it runs before `main` and before any thread
/// exists. A failure is recorded rather than raised: the tests report it as a
/// skip, which reads better than a suite that aborts on a kernel that will not
/// hand out user namespaces.
extern "C" fn enter() {
    // SAFETY: called on the only thread this process has, which is what
    // `CLONE_NEWUSER` requires. `getuid` and `getgid` cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };

    // SAFETY: both flags are valid for `unshare`, which touches no memory.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
        ENTERED.store(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            Ordering::SeqCst,
        );
        return;
    }

    // `gid_map` is refused while the process can still call `setgroups`, and
    // the refusal is silent in the sense that it looks like a permission
    // problem rather than an ordering one.
    let denied = fs::write("/proc/self/setgroups", "deny");
    let mapped = denied
        .and_then(|()| fs::write("/proc/self/uid_map", format!("0 {uid} 1")))
        .and_then(|()| fs::write("/proc/self/gid_map", format!("0 {gid} 1")));

    ENTERED.store(
        match mapped {
            Ok(()) => 0,
            Err(e) => e.raw_os_error().unwrap_or(-1),
        },
        Ordering::SeqCst,
    );
}

#[used]
#[unsafe(link_section = ".init_array")]
static ENTER_BEFORE_MAIN: extern "C" fn() = enter;

/// Whether this tier can run, printing why it cannot.
///
/// A test calls this first and returns early when it answers `false`. The
/// environments that answer `false` are the ones where unprivileged user
/// namespaces are switched off, which is a machine's policy rather than a
/// defect in anything here.
pub fn available() -> bool {
    match ENTERED.load(Ordering::SeqCst) {
        0 => true,
        code => {
            eprintln!(
                "SKIP: no user namespace available ({}). \
                 Unprivileged user namespaces are disabled on this machine.",
                std::io::Error::from_raw_os_error(code)
            );
            false
        }
    }
}

/// Numbers each segment, so two built at once get different links and subnets.
static NEXT: AtomicU32 = AtomicU32::new(1);

/// A veth pair with its far end in a namespace of its own.
///
/// Dropping it kills the process holding that namespace open, and the kernel
/// takes the namespace and both ends of the pair with it. Nothing is named in
/// `/var/run/netns`, so nothing survives a test that panics.
pub struct Segment {
    peer: Child,
    index: u32,
    listeners: Vec<Arc<AtomicBool>>,
    firewalled: AtomicBool,
}

impl Segment {
    /// Builds the pair and addresses both ends.
    pub fn new() -> Self {
        let index = NEXT.fetch_add(1, Ordering::SeqCst);
        let (near, far) = (format!("zv{index}a"), format!("zv{index}b"));

        let mut spawn = Command::new("unshare");
        spawn
            .args(["--net", "sleep", "3600"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: `prctl` is async-signal-safe and touches nothing this side of
        // the fork. Without it a test killed outright leaves the peer parked
        // forever, holding a namespace `Drop` never got to release.
        unsafe {
            spawn.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
        let peer = spawn.spawn().expect("unshare spawns a parked peer");
        let pid = peer.id();
        wait_for_namespace(pid);

        ip(&["link", "add", &near, "type", "veth", "peer", "name", &far]);
        ip(&["link", "set", &far, "netns", &pid.to_string()]);
        ip(&["link", "set", "lo", "up"]);
        ip(&[
            "addr",
            "add",
            &format!("{}/24", scanner_v4(index)),
            "dev",
            &near,
        ]);
        ip(&[
            "addr",
            "add",
            &format!("{}/64", scanner_v6(index)),
            "dev",
            &near,
            "nodad",
        ]);
        ip(&["link", "set", &near, "up"]);

        let there = ["nsenter", "--net", "--target"];
        let pid = pid.to_string();
        for args in [
            vec!["link", "set", "lo", "up"],
            vec![
                "addr",
                "add",
                &format!("{}/24", peer_v4(index)),
                "dev",
                &far,
            ],
            vec![
                "addr",
                "add",
                &format!("{}/64", peer_v6(index)),
                "dev",
                &far,
                "nodad",
            ],
            vec!["link", "set", &far, "up"],
        ] {
            let mut cmd = Command::new(there[0]);
            cmd.args(&there[1..])
                .arg(&pid)
                .arg("--preserve-credentials")
                .arg("ip")
                .args(&args);
            run(cmd, &format!("nsenter ip {}", args.join(" ")));
        }

        Self {
            peer,
            index,
            listeners: Vec::new(),
            firewalled: AtomicBool::new(false),
        }
    }

    /// The address this process scans from.
    pub fn scanner(&self) -> IpAddr {
        IpAddr::V4(scanner_v4(self.index))
    }

    /// The address on the far side of the wire.
    pub fn peer(&self) -> IpAddr {
        IpAddr::V4(peer_v4(self.index))
    }

    /// The far side's IPv6 address, reached over NDP rather than ARP.
    pub fn peer_v6(&self) -> IpAddr {
        IpAddr::V6(peer_v6(self.index))
    }

    /// The name of the link this process sends from.
    pub fn link(&self) -> String {
        format!("zv{}a", self.index)
    }

    /// Silently discards anything arriving for this TCP port.
    ///
    /// The verdict a firewall produces and loopback cannot: no answer at all,
    /// which a scanner has to tell apart from a port that answered nothing
    /// because the probe never arrived.
    pub fn drop_tcp(&self, port: u16) {
        self.rule(&["tcp", "dport", &port.to_string(), "drop"]);
    }

    /// Refuses this TCP port with an ICMP administrative prohibition.
    ///
    /// The near miss worth guarding: an ICMP error that is not a port
    /// unreachable means a filter said no, which is `Filtered` rather than the
    /// `Closed` a reset would mean.
    pub fn prohibit_tcp(&self, port: u16) {
        self.rule(&[
            "tcp",
            "dport",
            &port.to_string(),
            "counter",
            "reject",
            "with",
            "icmp",
            "type",
            "admin-prohibited",
        ]);
    }

    /// Shapes the near end of the pair, in `tc netem` terms.
    ///
    /// Assertions against this stay qualitative: `netem` draws from its own
    /// generator and will not honour a precise count.
    pub fn degrade(&self, netem: &[&str]) {
        let link = self.link();
        let mut args = vec!["qdisc", "add", "dev", link.as_str(), "root", "netem"];
        args.extend_from_slice(netem);
        tc(&args);
    }

    /// Runs a server on a thread inside the peer's namespace.
    ///
    /// `setns` moves the calling thread alone, which is what makes this work:
    /// the socket is created over there and stays there, while everything else
    /// in the process goes on scanning from here. The server reports the port
    /// it bound and then runs until the flag it was handed is raised.
    fn serve<F>(&mut self, server: F) -> u16
    where
        F: FnOnce(&AtomicBool, &mpsc::Sender<u16>) + Send + 'static,
    {
        let ns = fs::File::open(format!("/proc/{}/ns/net", self.peer.id()))
            .expect("the peer's network namespace is readable");
        let stop = Arc::new(AtomicBool::new(false));
        let raised = Arc::clone(&stop);
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            // SAFETY: `ns` is an open namespace file and stays open for the
            // duration of the call.
            if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return;
            }
            server(&raised, &tx);
        });

        self.listeners.push(stop);
        rx.recv_timeout(Duration::from_secs(5))
            .expect("the peer namespace accepts a server")
    }

    /// Binds a TCP listener in the peer's namespace and returns its port.
    pub fn listen_tcp(&mut self) -> u16 {
        let address = peer_v4(self.index);
        self.serve(move |stop, tx| {
            let Ok(listener) = TcpListener::bind((address, 0)) else {
                return;
            };
            let Ok(local) = listener.local_addr() else {
                return;
            };
            if listener.set_nonblocking(true).is_err() || tx.send(local.port()).is_err() {
                return;
            }
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok(_) => {}
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        })
    }

    /// A TCP listener on the peer's IPv6 address.
    pub fn listen_tcp_v6(&mut self) -> u16 {
        let address = peer_v6(self.index);
        self.serve(move |stop, tx| {
            let Ok(listener) = TcpListener::bind((address, 0)) else {
                return;
            };
            let Ok(local) = listener.local_addr() else {
                return;
            };
            if listener.set_nonblocking(true).is_err() || tx.send(local.port()).is_err() {
                return;
            }
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok(_) => {}
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        })
    }

    /// Binds a UDP socket in the peer's namespace that answers what it is sent.
    ///
    /// A UDP port is only positively open when something replies, so a listener
    /// that stayed silent would be indistinguishable from a filtered one and the
    /// test would pass for the wrong reason.
    pub fn echo_udp(&mut self) -> u16 {
        let address = peer_v4(self.index);
        self.serve(move |stop, tx| {
            let Ok(socket) = UdpSocket::bind((address, 0)) else {
                return;
            };
            let Ok(local) = socket.local_addr() else {
                return;
            };
            if socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .is_err()
                || tx.send(local.port()).is_err()
            {
                return;
            }
            let mut buf = [0u8; 2048];
            while !stop.load(Ordering::SeqCst) {
                match socket.recv_from(&mut buf) {
                    Ok((_, from)) => {
                        let _ = socket.send_to(b"zond-echo\r\n", from);
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                    Err(_) => return,
                }
            }
        })
    }

    /// A UDP port in the peer's namespace that nothing is bound to.
    ///
    /// The peer's kernel answers a datagram sent there with an ICMP port
    /// unreachable, which is the only thing that makes a UDP port positively
    /// closed rather than merely quiet.
    pub fn closed_udp_port(&mut self) -> u16 {
        let port = self.echo_udp();
        self.release();
        port
    }

    /// Stops the server started most recently and waits for it to let go.
    fn release(&mut self) {
        self.listeners
            .pop()
            .expect("a server was started")
            .store(true, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(60));
    }

    /// Adds one rule to the peer's input chain, creating the table on first use.
    fn rule(&self, rule: &[&str]) {
        if !self.firewalled.swap(true, Ordering::SeqCst) {
            self.there(&["nft", "add", "table", "inet", "zond"]);
            self.there(&[
                "nft",
                "add",
                "chain",
                "inet",
                "zond",
                "input",
                "{ type filter hook input priority 0; policy accept; }",
            ]);
        }
        let mut args = vec!["nft", "add", "rule", "inet", "zond", "input"];
        args.extend_from_slice(rule);
        self.there(&args);
    }

    /// Runs a command inside the peer's namespace.
    fn there(&self, args: &[&str]) {
        let mut cmd = Command::new("nsenter");
        cmd.args(["--net", "--target"])
            .arg(self.peer.id().to_string())
            .arg("--preserve-credentials")
            .args(args);
        run(cmd, &format!("nsenter {}", args.join(" ")));
    }

    /// A port in the peer's namespace that nothing is listening on.
    ///
    /// Bound and released over there, so the number is one the peer's kernel
    /// has just confirmed is free and will answer for with a reset.
    pub fn closed_tcp_port(&mut self) -> u16 {
        let port = self.listen_tcp();
        self.release();
        port
    }
}

impl Drop for Segment {
    fn drop(&mut self) {
        for stop in &self.listeners {
            stop.store(true, Ordering::SeqCst);
        }
        let _ = self.peer.kill();
        let _ = self.peer.wait();
    }
}

fn scanner_v4(index: u32) -> Ipv4Addr {
    Ipv4Addr::new(10, 99, index as u8, 1)
}

fn peer_v4(index: u32) -> Ipv4Addr {
    Ipv4Addr::new(10, 99, index as u8, 2)
}

fn scanner_v6(index: u32) -> Ipv6Addr {
    Ipv6Addr::new(0xfd00, 0x99, 0, index as u16, 0, 0, 0, 1)
}

fn peer_v6(index: u32) -> Ipv6Addr {
    Ipv6Addr::new(0xfd00, 0x99, 0, index as u16, 0, 0, 0, 2)
}

/// `unshare` creates the namespace and then execs, so for a moment the child is
/// still in ours. Waiting for the link to differ is the only signal that does
/// not race.
fn wait_for_namespace(pid: u32) {
    let ours = fs::read_link("/proc/self/ns/net").expect("this process has a network namespace");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if fs::read_link(format!("/proc/{pid}/ns/net")).is_ok_and(|theirs| theirs != ours) {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("the peer never entered a namespace of its own");
}

fn tc(args: &[&str]) {
    let mut cmd = Command::new("tc");
    cmd.args(args);
    run(cmd, &format!("tc {}", args.join(" ")));
}

fn ip(args: &[&str]) {
    let mut cmd = Command::new("ip");
    cmd.args(args);
    run(cmd, &format!("ip {}", args.join(" ")));
}

fn run(mut cmd: Command, what: &str) {
    let out = cmd.output().unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(
        out.status.success(),
        "{what}: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
}
