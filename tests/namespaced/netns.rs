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

    // SAFETY: the flags are valid for `unshare`, which touches no memory. The
    // mount namespace comes along because `/sys` has to be replaced; see below.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWNS) } != 0 {
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

    if let Err(e) = mapped {
        ENTERED.store(e.raw_os_error().unwrap_or(-1), Ordering::SeqCst);
        return;
    }

    ENTERED.store(mount_fresh_sysfs(), Ordering::SeqCst);
}

/// Replaces `/sys` with one belonging to this network namespace.
///
/// Without this the engine finds an empty network. `netdev` reads a link's
/// RFC 2863 operational state from `/sys/class/net/<link>/operstate`, and `/sys`
/// is inherited from the host, where a veth that exists only in here has no
/// entry at all. So `is_oper_up` answers false for every link, and
/// `Link::is_up` requires it alongside the `IFF_UP` flag that is set. A planner
/// that can find no source address abandons the raw path, which is the one path
/// this tier exists to exercise.
///
/// The mount is private first. A new mount namespace may inherit shared
/// propagation from its parent, and a `/sys` mounted under that would appear on
/// the machine outside the test.
fn mount_fresh_sysfs() -> i32 {
    let root = c"/";
    let sys = c"/sys";
    let sysfs = c"sysfs";

    // SAFETY: every pointer is a literal C string with a static lifetime, and
    // this runs before `main` on the only thread there is.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
    }

    // SAFETY: as above.
    let rc = unsafe {
        libc::mount(
            sysfs.as_ptr(),
            sys.as_ptr(),
            sysfs.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    match rc {
        0 => 0,
        _ => std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
    }
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
///
/// # Skipping is not allowed everywhere
///
/// A tier that skips reports the same green as a tier that ran, and a job that
/// is always green whatever it did is one nobody reads. So a caller that has
/// arranged for the namespace to exist sets `ZOND_REQUIRE_NETNS`, and a skip
/// becomes a failure. CI sets it; a workstation does not, because there the skip
/// is the correct answer for a machine whose policy forbids this.
pub fn available() -> bool {
    match ENTERED.load(Ordering::SeqCst) {
        0 => true,
        code => {
            let why = std::io::Error::from_raw_os_error(code);
            assert!(
                std::env::var_os("ZOND_REQUIRE_NETNS").is_none(),
                "ZOND_REQUIRE_NETNS is set, so this tier may not skip, \
                 and no user namespace is available: {why}"
            );
            eprintln!(
                "SKIP: no user namespace available ({why}). \
                 Unprivileged user namespaces are disabled on this machine."
            );
            false
        }
    }
}

/// The link holding `address`, as the engine names it.
///
/// For a link a test built without a name it can see, such as the near end of
/// a [`Segment::tunnel`], found by the address the fixture gave it.
pub fn zone_holding(address: Ipv4Addr) -> zond_engine::model::ip::scoped::Zone {
    zond_engine::system::interface::interfaces()
        .into_iter()
        .find(|link| {
            link.addresses()
                .iter()
                .any(|held| held.address() == IpAddr::V4(address))
        })
        .map(|link| link.zone())
        .unwrap_or_else(|| panic!("the engine can see the link holding {address}"))
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

    /// Gives this process a second address on the segment, and returns it.
    ///
    /// The first stays primary, so the routing table never picks this one: a
    /// probe sent from it is sent from a source the kernel did not choose, which
    /// is what a forced source is.
    pub fn add_scanner_address(&self) -> IpAddr {
        let address = Ipv4Addr::new(10, 99, self.index as u8, 3);
        ip(&["addr", "add", &format!("{address}/24"), "dev", &self.link()]);
        IpAddr::V4(address)
    }

    /// An address held behind the peer and routed to it, and returns it: a
    /// target this process reaches through a gateway, as it reaches anything
    /// off its own segment.
    pub fn routed_peer(&self) -> Ipv4Addr {
        let address = Ipv4Addr::new(10, 98, self.index as u8, 2);
        self.there(&["ip", "addr", "add", &format!("{address}/32"), "dev", "lo"]);
        ip(&[
            "route",
            "add",
            &format!("{address}/32"),
            "via",
            &peer_v4(self.index).to_string(),
        ]);
        address
    }

    /// An address routed through the peer that nothing holds, and returns it:
    /// a host that is not there, reached the way a real one would be.
    ///
    /// The peer resolves and takes the frames, and its kernel, which holds no
    /// such address and forwards nothing, drops them without a word. That is
    /// the silence an address nobody answers for produces, built here rather
    /// than borrowed from a documentation range, whose probes would leave the
    /// machine by its default route.
    pub fn silent_host(&self) -> Ipv4Addr {
        let address = Ipv4Addr::new(10, 98, self.index as u8, 9);
        ip(&[
            "route",
            "add",
            &format!("{address}/32"),
            "via",
            &peer_v4(self.index).to_string(),
        ]);
        address
    }

    /// Routes a `/28` through an address on the segment that nothing holds,
    /// and returns the `/28`'s addresses: hosts behind a gateway that never
    /// answers address resolution.
    ///
    /// The kernel queues every write to them on the gateway's unresolved
    /// entry, as it queues a write to a dead on-link address on that
    /// address's own, and throws the queue away when it gives the gateway up.
    pub fn behind_dead_gateway(&self) -> Vec<Ipv4Addr> {
        let gateway = Ipv4Addr::new(10, 99, self.index as u8, 250);
        let prefix = Ipv4Addr::new(10, 95, self.index as u8, 0);
        ip(&[
            "route",
            "add",
            &format!("{prefix}/28"),
            "via",
            &gateway.to_string(),
        ]);
        (1..15)
            .map(|host| Ipv4Addr::new(10, 95, self.index as u8, host))
            .collect()
    }

    /// An address routed through the peer that the peer refuses by policy,
    /// and returns it: a host behind a firewall that rejects rather than drops.
    ///
    /// The peer forwards, and holds a `prohibit` route for the address, so
    /// every packet sent there is answered with an ICMP administrative
    /// prohibition from the peer, which is the reply a firewall's reject
    /// sends and a connect is handed as a host it cannot reach. Built from a
    /// route rather than a firewall rule, so it needs nothing but `ip`.
    ///
    /// The peer's kernel limits the ICMP errors it sends each destination, to
    /// a burst of six and then one a second, so a test asks a handful of
    /// questions here and no more.
    pub fn prohibited_host(&self) -> Ipv4Addr {
        let address = Ipv4Addr::new(10, 98, self.index as u8, 13);
        self.there(&["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"]);
        self.there(&["ip", "route", "add", "prohibit", &format!("{address}/32")]);
        ip(&[
            "route",
            "add",
            &format!("{address}/32"),
            "via",
            &peer_v4(self.index).to_string(),
        ]);
        address
    }

    /// Four addresses this process has no way to, one for each way its own
    /// routing table can say so, and returns them: one no route covers, and
    /// one each behind an `unreachable`, a `prohibit` and a `blackhole` route.
    ///
    /// The routes are this process's, so every refusal is raised by its own
    /// kernel before anything is sent, and nothing reaches the peer.
    pub fn refused_routes(&self) -> [Ipv4Addr; 4] {
        let at = |last| Ipv4Addr::new(10, 97, self.index as u8, last);
        for (kind, last) in [("unreachable", 2), ("prohibit", 3), ("blackhole", 4)] {
            ip(&["route", "add", kind, &format!("{}/32", at(last))]);
        }
        [at(1), at(2), at(3), at(4)]
    }

    /// Refuses the peer by a host route of this process's own of `kind`,
    /// `prohibit`, `unreachable` or `blackhole`, over the segment's connected
    /// prefix: an address on this process's own segment that its routing
    /// table will not send to, which is what an administrator's route or a
    /// VPN's kill switch makes of a neighbour.
    ///
    /// Left in place when the segment goes: it names this segment's peer, and
    /// no later segment is numbered alike.
    pub fn refuse_peer_by_route(&self, kind: &str) {
        ip(&["route", "add", kind, &format!("{}/32", self.peer())]);
    }

    /// Lifts the ration the peer's kernel sends its ICMP errors under, so it
    /// answers every closed UDP port it is asked about however fast.
    pub fn unrationed_icmp(&self) {
        self.there(&["sh", "-c", "echo 0 > /proc/sys/net/ipv4/icmp_ratelimit"]);
    }

    /// Holds `address` behind this segment's peer too, and routes it there at
    /// `metric`, so a second segment offers another way to a target another
    /// one already reaches.
    ///
    /// With the first route at the kernel's default metric, the routing table
    /// sends the target out by the first segment and this one stands behind
    /// it: reached only by a socket bound to this segment's link, which is
    /// what a forced source is.
    pub fn also_routes(&self, address: Ipv4Addr, metric: u32) {
        self.there(&["ip", "addr", "add", &format!("{address}/32"), "dev", "lo"]);
        ip(&[
            "route",
            "add",
            &format!("{address}/32"),
            "via",
            &peer_v4(self.index).to_string(),
            "metric",
            &metric.to_string(),
        ]);
    }

    /// Joins the two ends with a tunnel carried over the segment, gives each
    /// end an address in one `/24` on it, and returns the peer's.
    ///
    /// The shape a WireGuard peer or an OpenVPN server in subnet topology
    /// has: the far end sits inside the prefix of an address this process
    /// holds, on a link that has no hardware address and no segment, so the
    /// prefix is a route through the tunnel and nothing behind it answers
    /// ARP. An IP-in-IP tunnel stands in for WireGuard because it needs
    /// nothing but `ip`, where WireGuard needs keys and a tool that reads them;
    /// to the engine the two are the same kind of link, point-to-point,
    /// without a MAC, in an operational state Linux reports as unknown.
    pub fn tunnel(&self) -> Ipv4Addr {
        let (ours, theirs) = (
            Ipv4Addr::new(10, 97, self.index as u8, 1),
            Ipv4Addr::new(10, 97, self.index as u8, 2),
        );
        self.join_by_tunnel("zt", &[&format!("{ours}/24")], &[&format!("{theirs}/24")]);
        theirs
    }

    /// [`tunnel`](Self::tunnel), addressed the way pppd and OpenVPN's p2p
    /// topology address a link: each end holds one address and names the
    /// other as its peer, with no subnet between them. Returns the peer's.
    ///
    /// Linux reports such an address as a pair, the peer first, which is the
    /// order that makes a reader keeping only one of them keep the wrong one.
    pub fn peer_tunnel(&self) -> Ipv4Addr {
        let (ours, theirs) = (
            Ipv4Addr::new(10, 96, self.index as u8, 1),
            Ipv4Addr::new(10, 96, self.index as u8, 2),
        );
        let (ours, theirs_s) = (ours.to_string(), theirs.to_string());
        self.join_by_tunnel(
            "zp",
            &[&ours, "peer", &theirs_s],
            &[&theirs_s, "peer", &ours],
        );
        theirs
    }

    /// Joins the two ends with a GRE tunnel carried over the segment, gives
    /// each end an address in one `/24` on it, and returns the peer's.
    ///
    /// The link [`tunnel`](Self::tunnel) is not, to `libpcap`: it has no
    /// mapping for GRE's hardware type, so it brings the link up cooked, as
    /// `DLT_LINUX_SLL`, and says so with a warning rather than a plain success.
    /// An `ip6tnl` or `ip6gre` link comes up the same way.
    pub fn gre_tunnel(&self) -> Ipv4Addr {
        let (ours, theirs) = (
            Ipv4Addr::new(10, 95, self.index as u8, 1),
            Ipv4Addr::new(10, 95, self.index as u8, 2),
        );
        self.join_by(
            "gre",
            "zg",
            &[&format!("{ours}/24")],
            &[&format!("{theirs}/24")],
        );
        theirs
    }

    /// An IP-in-IP link between the two ends of the segment, named `<stem>Na`
    /// here and `<stem>Nb` over there, each end given `ip addr add` with the
    /// arguments for its side.
    fn join_by_tunnel(&self, stem: &str, near_address: &[&str], far_address: &[&str]) {
        self.join_by("ipip", stem, near_address, far_address);
    }

    /// [`join_by_tunnel`](Self::join_by_tunnel), with a tunnel of `kind`.
    fn join_by(&self, kind: &str, stem: &str, near_address: &[&str], far_address: &[&str]) {
        let (near, far) = (
            format!("{stem}{}a", self.index),
            format!("{stem}{}b", self.index),
        );
        let (scanner, peer) = (
            scanner_v4(self.index).to_string(),
            peer_v4(self.index).to_string(),
        );

        ip(&[
            "link", "add", &near, "type", kind, "local", &scanner, "remote", &peer,
        ]);
        let mut add = vec!["addr", "add"];
        add.extend_from_slice(near_address);
        add.extend_from_slice(&["dev", &near]);
        ip(&add);
        ip(&["link", "set", &near, "up"]);

        self.there(&[
            "ip", "link", "add", &far, "type", kind, "local", &peer, "remote", &scanner,
        ]);
        let mut add = vec!["ip", "addr", "add"];
        add.extend_from_slice(far_address);
        add.extend_from_slice(&["dev", &far]);
        self.there(&add);
        self.there(&["ip", "link", "set", &far, "up"]);
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

    /// Silently discards anything arriving over TCP except for this port.
    ///
    /// A `DROP` policy with one service let through, which is the host a
    /// liveness probe to any other port reports down: its kernel never sees a
    /// SYN to a closed port, so it resets none.
    pub fn drop_tcp_except(&self, port: u16) {
        self.rule(&["tcp", "dport", "!=", &port.to_string(), "drop"]);
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

    /// Drops only the segments that open a connection to this TCP port.
    ///
    /// A stateful filter, in the sense `characterise` looks for: conntrack
    /// classifies a lone ACK as invalid rather than new, so it is not matched
    /// here and reaches the port, where an ordinary SYN does not.
    pub fn drop_new_connections_to(&self, port: u16) {
        // Conntrack's loose mode, on by default, will open a NEW entry for a
        // mid-stream ACK, which would put the diagnostic ACK in the same class
        // as the SYN and leave nothing for the rule below to distinguish. With
        // it off, a lone ACK is invalid, which is what "not a new connection"
        // has to mean for this test to be about connection state at all.
        self.there(&["sysctl", "-wq", "net.netfilter.nf_conntrack_tcp_loose=0"]);
        // Counts everything arriving for the port, so a test can tell a probe
        // that was refused from one that never came. No verdict, so evaluation
        // falls through to the rule below.
        self.rule(&["tcp", "dport", &port.to_string(), "counter"]);
        self.rule(&[
            "tcp",
            "dport",
            &port.to_string(),
            "ct",
            "state",
            "new",
            "counter",
            "drop",
        ]);
    }

    /// Answers one mDNS query for `hostname` with the peer's own address.
    ///
    /// The response is built by copying the query's own question section and
    /// appending an answer that points back at it, which is both what RFC 6762
    /// asks for and far less to get wrong than composing a name from scratch.
    /// It replies to the querier directly rather than to the group: a unicast
    /// answer is allowed, and it arrives on the same socket the query left from.
    pub fn answers_mdns_for(&mut self, hostname: &str) -> Ipv4Addr {
        let address = peer_v4(self.index);
        let wanted = format!("{}.local", hostname.trim_end_matches(".local"));
        self.serve(move |stop, tx| {
            let Some(socket) = mdns_socket(address) else {
                return;
            };
            if tx.send(5353).is_err() {
                return;
            }
            let mut buf = [0u8; 2048];
            while !stop.load(Ordering::SeqCst) {
                let Ok((len, from)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                let query = &buf[..len];
                let Some(end) = question_end(query) else {
                    continue;
                };
                if !asks_for(query, &wanted) {
                    continue;
                }
                let mut reply = Vec::with_capacity(end + 16);
                reply.extend_from_slice(&query[..2]);
                reply.extend_from_slice(&[0x84, 0x00]);
                reply.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                reply.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                reply.extend_from_slice(&query[12..end]);
                reply.extend_from_slice(&[0xc0, 0x0c]);
                reply.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                reply.extend_from_slice(&120u32.to_be_bytes());
                reply.extend_from_slice(&4u16.to_be_bytes());
                reply.extend_from_slice(&address.octets());
                let _ = socket.send_to(&reply, from);
            }
        });
        address
    }

    /// The `Zone` naming the near end of the pair, as the engine sees it.
    ///
    /// A listening scope is given links rather than addresses, so this is what
    /// a test hands `ListenScope::on`.
    pub fn zone(&self) -> zond_engine::model::ip::scoped::Zone {
        let name = self.link();
        zond_engine::system::interface::interfaces()
            .into_iter()
            .find(|link| link.name() == name)
            .map(|link| link.zone())
            .unwrap_or_else(|| panic!("the engine can see {name}"))
    }

    /// Makes the peer speak, so a listener has something to overhear.
    ///
    /// A ping is the cheapest way to put a machine's own frames on the wire:
    /// it resolves the near end first, so the listener sees an ARP request and
    /// an echo carrying the peer's hardware and network address alike.
    pub fn peer_speaks(&self) {
        self.there(&[
            "ping",
            "-c",
            "3",
            "-i",
            "0.2",
            "-W",
            "1",
            &scanner_v4(self.index).to_string(),
        ]);
    }

    /// Counts segments arriving for this TCP port without changing their fate.
    pub fn count_tcp(&self, port: u16) {
        self.rule(&["tcp", "dport", &port.to_string(), "counter"]);
    }

    /// How many segments the peer has counted for this TCP port.
    ///
    /// Needs [`count_tcp`](Self::count_tcp) to have been called for it.
    pub fn count_of(&self, port: u16) -> u64 {
        let needle = format!("tcp dport {port} counter packets ");
        self.ruleset()
            .lines()
            .find_map(|line| {
                let rest = line.trim().strip_prefix(&needle)?;
                rest.split_whitespace().next()?.parse().ok()
            })
            .unwrap_or(0)
    }

    /// Admits this TCP port only from one source port, dropping the rest.
    ///
    /// An ACL that trusts where a segment claims to come from rather than what
    /// it is. `trusted` is the number the engine tries, which is 53.
    pub fn trust_source_port_to(&self, port: u16, trusted: u16) {
        self.rule(&["tcp", "dport", &port.to_string(), "counter"]);
        self.rule(&[
            "tcp",
            "dport",
            &port.to_string(),
            "tcp",
            "sport",
            "!=",
            &trusted.to_string(),
            "counter",
            "drop",
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
        self.listen_tcp_on(peer_v4(self.index))
    }

    /// Binds a TCP listener on `address` in the peer's namespace and returns
    /// its port. For an address [`routed_peer`](Self::routed_peer) added.
    pub fn listen_tcp_on(&mut self, address: Ipv4Addr) -> u16 {
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

    /// Binds an HTTP listener on `address` in the peer's namespace, and returns
    /// its port and the source address of every connection it accepted.
    ///
    /// It answers each request with a page, so a scan's service pass finds a
    /// web server and goes on to do everything it does to one: dial again for
    /// its later questions, fetch the icon, run the detections. Every one of
    /// those connections is recorded, which is what makes the list a record
    /// of where a scan's connections came from rather than of its first.
    pub fn listen_http_recording_on(
        &mut self,
        address: Ipv4Addr,
    ) -> (u16, Arc<std::sync::Mutex<Vec<IpAddr>>>) {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let port = self.serve(move |stop, tx| {
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
                    Ok((mut stream, from)) => {
                        record.lock().expect("the record").push(from.ip());
                        answer_http(&mut stream);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });
        (port, seen)
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

    /// The peer's firewall as it stands, counters included.
    pub fn ruleset(&self) -> String {
        let mut cmd = Command::new("nsenter");
        cmd.args(["--net", "--target"])
            .arg(self.peer.id().to_string())
            .arg("--preserve-credentials")
            .args(["nft", "list", "ruleset"]);
        String::from_utf8_lossy(&cmd.output().expect("nft lists").stdout).into_owned()
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

/// Reads what a client sent, briefly, and answers it with a small page.
///
/// Whatever was asked gets the same answer, since what is being tested is where
/// the question came from rather than what it was.
fn answer_http(stream: &mut std::net::TcpStream) {
    use std::io::{Read, Write};

    if stream.set_nonblocking(false).is_err()
        || stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .is_err()
    {
        return;
    }
    let mut request = [0u8; 2048];
    let _ = stream.read(&mut request);
    let body = "<html><head><title>zond</title></head><body>ok</body></html>";
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nServer: zond-test\r\nContent-Type: text/html\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// A socket on the mDNS group, in whichever namespace the caller is in.
fn mdns_socket(interface: Ipv4Addr) -> Option<UdpSocket> {
    use std::net::{Ipv4Addr as V4, SocketAddrV4};
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    socket.set_reuse_address(true).ok()?;
    socket.set_reuse_port(true).ok()?;
    socket
        .bind(&SocketAddrV4::new(V4::UNSPECIFIED, 5353).into())
        .ok()?;
    socket
        .join_multicast_v4(&V4::new(224, 0, 0, 251), &interface)
        .ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .ok()?;
    Some(socket.into())
}

/// Where a DNS message's single question ends, walking its labels.
fn question_end(message: &[u8]) -> Option<usize> {
    let mut at = 12;
    loop {
        let len = *message.get(at)? as usize;
        at += 1;
        if len == 0 {
            return Some(at + 4).filter(|end| *end <= message.len());
        }
        if len & 0xc0 != 0 {
            return None;
        }
        at += len;
    }
}

/// Whether the message's question names `wanted`, case-insensitively.
fn asks_for(message: &[u8], wanted: &str) -> bool {
    let mut labels = Vec::new();
    let mut at = 12;
    while let Some(&len) = message.get(at) {
        at += 1;
        if len == 0 {
            break;
        }
        let end = at + len as usize;
        let Some(label) = message.get(at..end) else {
            return false;
        };
        labels.push(String::from_utf8_lossy(label).to_lowercase());
        at = end;
    }
    labels.join(".") == wanted.to_lowercase()
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
