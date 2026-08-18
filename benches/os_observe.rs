// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prints everything a single TCP reply says about the stack that sent it.
//!
//! This is the instrument phase 1 of `docs/os-fingerprinting.md` exists to
//! produce, and it comes before any classifier on purpose. The features that
//! separate one operating system from another are widely published, widely
//! repeated, and routinely wrong — a stack's defaults change between releases, a
//! tunnel rewrites them, and a middlebox normalises them away. Authoring rules
//! from the literature and then testing them against the same literature proves
//! only that both were copied from the same place. So this measures first, on a
//! real segment, and the table it prints is what the rules are written against.
//!
//! ## Two arms, because our own probe is part of the measurement
//!
//! The first run of this instrument disproved the assumption it was built on.
//! Every SYN+ACK on a mixed segment came back carrying **only** an MSS option —
//! no SACK-permitted, no timestamp, no window scale — which is not what any of
//! Linux, Windows or macOS is documented to send, and identical across all
//! three. The cause is not the hosts. TCP option negotiation is **reciprocal**:
//! RFC 7323 §2.2 permits a window scale in a SYN+ACK only if the SYN carried
//! one, §3.2 says the same of timestamps, and RFC 2018 §2 of SACK-permitted. A
//! peer reports the options it was *asked* about. `tcp::create_probe` offers MSS
//! and nothing else, so the option layout — the strongest single feature in the
//! design — was being suppressed by this engine's own probe.
//!
//! So there are two arms, one SYN each, sent to every target and port:
//!
//! * **mss-only** — `tcp::create_probe` verbatim, which is what the SYN port
//!   scanner sends today. Not a reproduction of it; the actual function.
//! * **negotiating** — the same segment field for field, same window, same MSS,
//!   nonce in the same place, offering the option set an ordinary client offers.
//!
//! The `what the offered options changed` block is the result: how many hosts
//! name more options when asked about more. It is the number that decides
//! whether the shipped SYN should carry the fuller option list, and it is a
//! question about this engine, not about the hosts.
//!
//! Neither arm sends anything a port scan would not. Both are a single SYN, and
//! the negotiating one looks *more* like an ordinary connection attempt than the
//! MSS-only one does, because that is what it is shaped like.
//!
//! ```text
//! cargo bench --no-run --bench os_observe
//! sudo -E target/release/deps/os_observe-<hash> 192.168.0.0/24 22,80,443,445
//! ```
//!
//! Built with `--no-run` and invoked directly rather than through `cargo bench`,
//! for the reason `verify_scan` gives, plus one this needs anyway: it wants root,
//! and `sudo cargo` would run the build as root and leave `target/` owned by it.
//!
//! ## Finding the binary you just built
//!
//! A `harness = false` bench builds to a hashed name, several accumulate across
//! rebuilds, and nothing warns you that the one you ran is not the one you
//! built — this engine has already lost three debugging rounds to exactly that.
//! **Select by newest, and select executables** rather than by excluding the
//! extensions you happen to know about:
//!
//! ```text
//! # fish
//! sudo -E (command ls -t (path filter -fx target/release/deps/os_observe-*))[1] 192.168.0.0/24
//!
//! # bash / zsh
//! sudo -E "$(find target/release/deps -name 'os_observe-*' -type f -perm -u+x | xargs ls -t | head -1)" 192.168.0.0/24
//! ```
//!
//! `command ls` and the quoted `$(...)` are not decoration. An interactive shell
//! that aliases `ls` to `eza` or `lsd` silently changes what `-t` means — in
//! `eza` it takes an argument and swallows the first path — and the substitution
//! comes back empty, at which point `sudo` treats the target address as the
//! command to run. Asking for executables (`-fx`, `-perm -u+x`) rather than
//! filtering out `.d` and `.o` says what is actually meant and cannot be caught
//! out by an artifact extension nobody listed.
//!
//! ## Reading the table
//!
//! One row per reply. Nothing in it is inferred:
//!
//! * `hops_left` is the TTL or hop limit **as it arrived**, already decremented
//!   once per router crossed. `start>=` beside it is the smallest of the usual
//!   initial values that is not below it, which is a lower bound on what the
//!   sender wrote and not a guess at it. Two hosts behind different path lengths
//!   can share a starting value and show different `hops_left`; that is the
//!   measurement working, not failing.
//! * `layout` is the TCP options in the order they appeared, one letter each:
//!   `M` maximum segment size, `S` SACK permitted, `K` a SACK block, `T`
//!   timestamp, `N` no-op, `W` window scale, `E` end of list, `?n` anything
//!   else. The *order* is the interesting part — it is chosen by whoever wrote
//!   the stack and copied by nobody.
//! * `raw` is the option bytes in hex, so a row can be re-read by hand if the
//!   letters above turn out to have lost something.
//!
//! The summary at the end groups rows by their whole feature vector. Hosts
//! running the same stack collapse into one line; the number of distinct lines
//! is the number of stacks the segment holds, before anyone has said which is
//! which. **Label them by hand, from outside** — from what the machines are
//! known to be, never from what a fingerprint said — and that labelled table is
//! the corpus phases 3 and 4 are built and measured against.
//!
//! ## What it cannot see
//!
//! A reply that crossed a VPN, a NAT or a load balancer describes whatever
//! rewrote it. Run it on the segment the hosts are actually on, note the
//! interface, and do not merge two runs taken over different paths.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use tokio::time::timeout;

use zond_engine::model::capture::IpObservation;
use zond_engine::model::parse::ip::to_set;
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::protocols::craft;
use zond_engine::protocols::tcp;
use zond_engine::system::interface::SourceResolver;
use zond_engine::transport::probe::{ProbeKind, ProbeTransport};

/// Ports to try on each address, chosen for being the ones a host on an office
/// or home segment is most likely to have open. Only one has to answer.
const DEFAULT_PORTS: &str = "22,80,443,445,3389,8080";

/// How long to keep reading replies after the last probe goes out.
///
/// Generous, because this is not measuring latency and a slow answer is worth
/// exactly as much as a fast one here — the features being read are the same in
/// both.
const LISTEN_FOR: Duration = Duration::from_secs(4);

/// How long to wait on the receive channel before checking whether the listening
/// window has closed.
const RECV_TICK: Duration = Duration::from_millis(200);

/// The maximum segment size both arms advertise, matching what
/// `tcp::create_probe` sends so the *only* difference between them is the
/// options offered alongside it.
const PROBE_MSS: u16 = 1412;

/// The receive window both arms advertise, matching `tcp::create_probe` for the
/// same reason.
const PROBE_WINDOW: u16 = 1024;

/// Everything read, keyed by the host, the arm that asked, and which segment
/// came back.
///
/// The reply kind is part of the key rather than folded away because a RST and a
/// SYN+ACK from the *same* host are the only way to tell a stack's policy from a
/// segment type's. Both of this segment's SYN+ACK hosts set don't-fragment with a
/// zero identifier and both of its RST hosts did neither — which reads as a
/// stack difference and is equally consistent with a code path difference, and
/// nothing that keeps one reply per host can separate the two.
type Seen = BTreeMap<(IpAddr, ProbeVariant, &'static str), (u16, Observed)>;

/// Which SYN drew a reply.
///
/// Two arms, because TCP option negotiation is **reciprocal** and that turns out
/// to decide the whole question. RFC 7323 §2.2 permits a window scale in a
/// SYN+ACK only if the SYN carried one; RFC 7323 §3.2 says the same of
/// timestamps, and RFC 2018 §2 of SACK-permitted. A peer therefore reports the
/// options *it was asked about*, not the options it supports — so what a probe
/// declines to offer, its answer cannot reveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProbeVariant {
    /// What this engine's SYN scan sends today: an MSS announcement and nothing
    /// else.
    MssOnly,

    /// The same SYN, offering the option set an ordinary client offers — MSS,
    /// SACK-permitted, timestamp, window scale.
    ///
    /// Not an extra packet and not a stranger one. It is *one* SYN, exactly as
    /// the other arm is, and it looks more like a real connection attempt than
    /// the MSS-only probe does, because a real connection attempt is what it is
    /// shaped like.
    Negotiating,
}

impl ProbeVariant {
    const ALL: [ProbeVariant; 2] = [ProbeVariant::MssOnly, ProbeVariant::Negotiating];

    const fn name(self) -> &'static str {
        match self {
            ProbeVariant::MssOnly => "mss-only",
            ProbeVariant::Negotiating => "negotiating",
        }
    }

    /// Builds this arm's SYN.
    ///
    /// [`MssOnly`](Self::MssOnly) goes through `tcp::create_probe`, so it is the
    /// engine's own probe rather than a reproduction of it. The other arm is
    /// built here and mirrors it field for field — same window, same MSS, nonce
    /// in the same place — so the two differ in the options and in nothing else.
    fn build(
        self,
        source: &IpAddr,
        target: &IpAddr,
        src_port: u16,
        dst_port: u16,
        nonce: u32,
    ) -> anyhow::Result<Vec<u8>> {
        match self {
            ProbeVariant::MssOnly => Ok(tcp::create_probe(
                TcpScanTechnique::Syn,
                source,
                target,
                src_port,
                dst_port,
                nonce,
            )?),
            ProbeVariant::Negotiating => {
                let mut segment = craft::Tcp::new(src_port, dst_port)
                    .with_flags(craft::tcp_flags::SYN)
                    // The nonce goes in the sequence field for a SYN, which is
                    // what `tcp::echoed_nonce` reads it back out of.
                    .with_sequence(nonce);
                segment.window = PROBE_WINDOW;
                segment.options = negotiating_options();
                Ok(segment.to_bytes(Some((*source, *target)))?)
            }
        }
    }
}

/// The option list a client offers when it wants to know what the peer supports:
/// MSS, SACK-permitted, a timestamp, and a window scale, twenty bytes in total
/// so the header needs no padding.
///
/// The timestamp value is random. It is never compared against anything here —
/// reading a peer's clock rate needs two samples and is phase 6's work — and a
/// fixed value would be a constant on the wire for no reason.
fn negotiating_options() -> Vec<u8> {
    let [mss_high, mss_low] = PROBE_MSS.to_be_bytes();
    let timestamp: u32 = rand::random();

    let mut options = Vec::with_capacity(20);
    options.extend_from_slice(&[2, 4, mss_high, mss_low]); // MSS
    options.extend_from_slice(&[4, 2]); // SACK permitted
    options.extend_from_slice(&[8, 10]); // timestamp, kind and length
    options.extend_from_slice(&timestamp.to_be_bytes()); // TSval
    options.extend_from_slice(&0u32.to_be_bytes()); // TSecr, nothing to echo yet
    options.push(1); // NOP, to align what follows
    options.extend_from_slice(&[3, 3, 7]); // window scale
    options
}

/// The initial hop counters a lower bound is reported against. Not a claim that
/// a stack uses one of these — it is the set that makes `start>=` a useful
/// column, and a host whose real initial value is not here still reports a
/// correct bound.
const COMMON_INITIAL_HOPS: [u8; 4] = [32, 64, 128, 255];

/// Everything one reply said, in the order the table prints it.
///
/// The IP half and the TCP half are kept in one record because they were read
/// off one packet: a stack chose all of it at once, and splitting them would
/// invite counting them as two independent observations, which they are not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Observed {
    /// `SYN+ACK` or `RST`, which decides how much of the rest exists at all — a
    /// reset carries no options worth reading.
    reply: &'static str,
    hops_left: u8,
    /// `None` for IPv6, which has no identification field.
    ip_id: Option<u16>,
    dont_fragment: bool,
    /// IPv4's DSCP and ECN, or IPv6's traffic class, rendered as written.
    traffic: String,
    /// IPv6 only.
    flow_label: Option<u32>,
    window: u16,
    /// The option kinds in the order they appeared.
    layout: String,
    mss: Option<u16>,
    window_scale: Option<u8>,
    timestamp: bool,
    /// The option bytes verbatim, so nothing above is the only record.
    raw_options: String,
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| {
        eprintln!("usage: os_observe <target> [ports]");
        std::process::exit(2);
    });
    let ports = args.next().unwrap_or_else(|| DEFAULT_PORTS.to_string());

    // No resolver, deliberately: an instrument that silently followed whatever
    // DNS answered with would be measuring a moving target.
    let addresses = match to_set(&[target.as_str()], None, None) {
        Ok(addresses) => addresses,
        Err(e) => {
            eprintln!("cannot read target `{target}`: {e}");
            std::process::exit(2);
        }
    };
    let ports: Vec<u16> = ports
        .split(',')
        .filter_map(|port| port.trim().parse().ok())
        .collect();
    if ports.is_empty() {
        eprintln!("no usable port in `{ports:?}`");
        std::process::exit(2);
    }

    let src_port: u16 = rand::random_range(50_000..u16::MAX);
    let mut transport = match ProbeTransport::open(ProbeKind::TcpProbe {
        reply_port: src_port,
        icmp_errors: false,
    }) {
        Ok(transport) => transport,
        Err(e) => {
            eprintln!("cannot open a probe transport: {e}");
            eprintln!("this needs root: it opens a raw socket and a capture.");
            std::process::exit(1);
        }
    };

    let mut resolver = SourceResolver::from_system();
    // nonce -> which probe it belongs to, so a reply names its own target and its
    // own arm rather than being attributed to whichever is closest in the list.
    let mut sent: BTreeMap<u32, (IpAddr, u16, ProbeVariant)> = BTreeMap::new();

    for address in addresses.iter() {
        let Some(source) = resolver.resolve(address) else {
            eprintln!("no source address reaches {address}, skipping");
            continue;
        };
        for &port in &ports {
            for variant in ProbeVariant::ALL {
                let nonce: u32 = rand::random();
                let segment = match variant.build(&source, &address, src_port, port, nonce) {
                    Ok(segment) => segment,
                    Err(e) => {
                        eprintln!(
                            "cannot build a {} probe for {address}:{port}: {e:#}",
                            variant.name()
                        );
                        continue;
                    }
                };
                match transport.tx.send(&segment, source, address) {
                    Ok(()) => {
                        sent.insert(nonce, (address, port, variant));
                    }
                    Err(e) => eprintln!("cannot send to {address}:{port}: {e}"),
                }
            }
        }
    }

    println!("sent {} probes from port {src_port}", sent.len());
    println!("listening for {LISTEN_FOR:?}\n");

    // One row per host, per arm, per kind of reply. A second SYN+ACK from a host
    // that already gave one adds nothing a row does not say; a *RST* from that
    // host says something no SYN+ACK can. The IP identification field is the one
    // thing that would need several samples of the same kind, and reading its
    // policy is phase 6's job.
    let mut observed: Seen = BTreeMap::new();
    let until = Instant::now() + LISTEN_FOR;

    while Instant::now() < until {
        let Ok(Some(reply)) = timeout(RECV_TICK, transport.rx.recv()).await else {
            continue;
        };
        if reply.protocol != IpNextHeaderProtocols::Tcp {
            continue;
        }
        let Ok(segment) = tcp::parse(&reply.bytes) else {
            continue;
        };
        if segment.get_destination() != src_port {
            continue;
        }
        // A reply is this instrument's only if it echoes back a nonce this
        // instrument sent. Without the check, any TCP segment reaching the
        // capture is read as an answer, and a busy host produces a table of
        // other people's connections.
        let nonce = tcp::echoed_nonce(TcpScanTechnique::Syn, &segment);
        let Some(&(address, port, variant)) = sent.get(&nonce) else {
            continue;
        };
        // The address that answered, not the one probed: they differ when
        // something in the path answered on the host's behalf, and that is worth
        // seeing rather than papering over.
        if reply.source != address {
            eprintln!("{address}:{port} was answered by {}", reply.source);
        }

        let Some(observation) = reply.observation else {
            eprintln!("{}: no IP header was kept for this reply", reply.source);
            continue;
        };
        if observation.is_fragment() {
            eprintln!("{}: reply arrived fragmented, skipping", reply.source);
            continue;
        }

        let row = describe(&segment, observation);
        observed
            .entry((reply.source, variant, row.reply))
            .or_insert((port, row));
    }

    print_rows(&observed);
    print_negotiation_effect(&observed);
    print_summary(&observed);
}

/// Everything one reply says, read once.
fn describe(segment: &pnet::packet::tcp::TcpPacket<'_>, observation: IpObservation) -> Observed {
    let flags = segment.get_flags();
    let reply = if flags & tcp::flags::SYN != 0 && flags & tcp::flags::ACK != 0 {
        "SYN+ACK"
    } else if flags & tcp::flags::RST != 0 {
        "RST"
    } else {
        "other"
    };

    let options = segment.get_options_raw();
    let walked = walk_options(options);

    let (ip_id, dont_fragment, traffic, flow_label) = match observation {
        IpObservation::V4(v4) => (
            Some(v4.identification),
            v4.dont_fragment,
            format!("dscp={} ecn={}", v4.dscp, v4.ecn),
            None,
        ),
        IpObservation::V6(v6) => (
            None,
            // An IPv6 datagram is never fragmented in transit, so the question
            // the IPv4 bit answers is settled by the protocol here.
            true,
            format!("class={}", v6.traffic_class),
            Some(v6.flow_label),
        ),
    };

    Observed {
        reply,
        hops_left: observation.remaining_hops(),
        ip_id,
        dont_fragment,
        traffic,
        flow_label,
        window: segment.get_window(),
        layout: walked.layout,
        mss: walked.mss,
        window_scale: walked.window_scale,
        timestamp: walked.timestamp,
        raw_options: options.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

/// The part of an [`Observed`] that describes the *stack* rather than the path
/// or the moment.
///
/// The hop counter and the identification field are left out: the first depends
/// on how far away the host is and the second on what else it was doing. What
/// remains is what the stack's authors chose, so two hosts with the same shape
/// are running the same stack, whatever else differs between them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StackShape {
    layout: String,
    window: u16,
    dont_fragment: bool,
    mss: Option<u16>,
    window_scale: Option<u8>,
    timestamp: bool,
}

impl Observed {
    fn shape(&self) -> StackShape {
        StackShape {
            layout: self.layout.clone(),
            window: self.window,
            dont_fragment: self.dont_fragment,
            mss: self.mss,
            window_scale: self.window_scale,
            timestamp: self.timestamp,
        }
    }
}

/// What one walk of a TCP option list found.
struct Options {
    layout: String,
    mss: Option<u16>,
    window_scale: Option<u8>,
    timestamp: bool,
}

/// Walks a TCP option list, recording the kinds in order and pulling out the
/// three values worth naming.
///
/// Written here rather than in the library on purpose. The typed parse belongs
/// in `src/fingerprinting/os/observation.rs` and is phase 2's work; building it
/// now would mean designing the type this instrument exists to inform. This walk
/// is deliberately forgiving — an option whose length is nonsense stops it
/// rather than failing the row — because its job is to show what arrived, not to
/// decide whether it was well formed.
fn walk_options(options: &[u8]) -> Options {
    let mut kinds: Vec<String> = Vec::new();
    let mut mss = None;
    let mut window_scale = None;
    let mut timestamp = false;
    let mut at = 0;

    while at < options.len() {
        let kind = options[at];
        kinds.push(match kind {
            0 => "E".to_string(),
            1 => "N".to_string(),
            2 => "M".to_string(),
            3 => "W".to_string(),
            4 => "S".to_string(),
            5 => "K".to_string(),
            8 => "T".to_string(),
            // Named rather than collapsed to one `?`, because an option this
            // walk does not have a letter for is the most interesting thing it
            // can find.
            other => format!("?{other}"),
        });

        // End-of-list ends the list: whatever follows is padding to the next
        // four-byte boundary and is not an option. No-op is the other
        // single-byte kind. Everything else carries its own length, counting
        // the kind and length bytes themselves.
        if kind == 0 {
            break;
        }
        if kind == 1 {
            at += 1;
            continue;
        }
        let Some(&length) = options.get(at + 1) else {
            break;
        };
        let length = usize::from(length);
        if length < 2 || at + length > options.len() {
            break;
        }
        let value = &options[at + 2..at + length];
        match kind {
            2 if value.len() == 2 => mss = Some(u16::from_be_bytes([value[0], value[1]])),
            3 if value.len() == 1 => window_scale = Some(value[0]),
            8 => timestamp = true,
            _ => {}
        }
        at += length;
    }

    Options {
        layout: kinds.join(","),
        mss,
        window_scale,
        timestamp,
    }
}

/// The smallest of the usual initial hop counters that `hops_left` could have
/// been decremented from. A bound, not a guess: a host further away than the
/// gap between two of these is reported against the higher one, which is still
/// true.
fn initial_hops_at_least(hops_left: u8) -> u8 {
    COMMON_INITIAL_HOPS
        .into_iter()
        .find(|&start| start >= hops_left)
        .unwrap_or(u8::MAX)
}

fn print_rows(observed: &Seen) {
    if observed.is_empty() {
        println!("nothing answered.");
        return;
    }

    println!(
        "{:<18} {:<12} {:>5}  {:<8} {:>4} {:>7} {:>7} {:>6} {:>3} {:<18} {:>6} {:>3} {:>3}  traffic",
        "address",
        "probe",
        "port",
        "reply",
        "hops",
        "start>=",
        "ip_id",
        "window",
        "df",
        "layout",
        "mss",
        "ws",
        "ts"
    );

    for ((address, variant, _), (port, row)) in observed {
        println!(
            "{:<18} {:<12} {:>5}  {:<8} {:>4} {:>7} {:>7} {:>6} {:>3} {:<18} {:>6} {:>3} {:>3}  {}{}",
            address.to_string(),
            variant.name(),
            port,
            row.reply,
            row.hops_left,
            initial_hops_at_least(row.hops_left),
            row.ip_id
                .map_or_else(|| "-".to_string(), |id| id.to_string()),
            row.window,
            if row.dont_fragment { "yes" } else { "no" },
            if row.layout.is_empty() {
                "-"
            } else {
                &row.layout
            },
            row.mss.map_or_else(|| "-".to_string(), |m| m.to_string()),
            row.window_scale
                .map_or_else(|| "-".to_string(), |w| w.to_string()),
            if row.timestamp { "yes" } else { "no" },
            row.traffic,
            row.flow_label
                .map_or_else(String::new, |label| format!(" flow={label}")),
        );
    }

    println!("\nraw option bytes");
    for ((address, variant, _), (_, row)) in observed {
        println!(
            "  {:<18} {:<12} {}",
            address.to_string(),
            variant.name(),
            if row.raw_options.is_empty() {
                "-"
            } else {
                &row.raw_options
            }
        );
    }
}

/// What offering the fuller option set actually bought, host by host.
///
/// The number this instrument exists to produce. TCP option negotiation is
/// reciprocal, so a peer answers about the options it was *asked* about — which
/// means the option layout, the strongest single feature available, is decided as
/// much by our probe as by their stack. This says by how much: how many hosts
/// revealed a longer layout under the negotiating SYN than under the MSS-only one
/// that the port scanner sends today.
fn print_negotiation_effect(observed: &Seen) {
    let addresses: std::collections::BTreeSet<IpAddr> =
        observed.keys().map(|(address, _, _)| *address).collect();
    if addresses.is_empty() {
        return;
    }

    println!("\nwhat the offered options changed");
    println!(
        "  {:<18} {:<18} {:<18} verdict",
        "address", "mss-only", "negotiating"
    );

    let mut revealed = 0usize;
    let mut unchanged = 0usize;
    let mut incomparable = 0usize;

    for address in &addresses {
        // Compared on the SYN+ACK rows, because that is where options live: a RST
        // carries none whatever was offered, so a host with only closed ports
        // cannot answer this question either way.
        let synack = |variant| observed.get(&(*address, variant, "SYN+ACK"));
        let mss_only = synack(ProbeVariant::MssOnly);
        let negotiating = synack(ProbeVariant::Negotiating);

        let show = |row: Option<&(u16, Observed)>| match row {
            Some((_, row)) if row.layout.is_empty() => format!("{} (none)", row.reply),
            Some((_, row)) => row.layout.clone(),
            None => "no reply".to_string(),
        };

        // Counted by option *count*, not string length: a layout is a list, and
        // "did the peer name more options" is the question, not "is the text
        // longer".
        let count = |row: Option<&(u16, Observed)>| {
            row.map(|(_, row)| {
                if row.layout.is_empty() {
                    0
                } else {
                    row.layout.split(',').count()
                }
            })
        };

        let verdict = match (count(mss_only), count(negotiating)) {
            (Some(before), Some(after)) if after > before => {
                revealed += 1;
                format!("+{} option(s) revealed", after - before)
            }
            (Some(before), Some(after)) if after < before => {
                incomparable += 1;
                format!("-{} option(s), unexpected", before - after)
            }
            (Some(_), Some(_)) => {
                unchanged += 1;
                "no change".to_string()
            }
            (None, None) => {
                incomparable += 1;
                // Every reply this host gave was a reset, and a reset carries no
                // options at all. Not a gap in the measurement — a limit on what
                // a closed port can ever say.
                "no open port, so no options".to_string()
            }
            _ => {
                incomparable += 1;
                "only one arm drew a SYN+ACK".to_string()
            }
        };

        println!(
            "  {:<18} {:<18} {:<18} {verdict}",
            address.to_string(),
            show(mss_only),
            show(negotiating),
        );
    }

    println!(
        "\n  {revealed} host(s) revealed more, {unchanged} unchanged, \
         {incomparable} not comparable, out of {} that answered either arm",
        addresses.len()
    );
    if revealed > 0 {
        println!(
            "  The layout is decided partly by what the probe offers. A rule set \n               authored against the mss-only arm would be authored against this \n               engine's probe rather than against the hosts."
        );
    }
}

/// Groups the rows by [`StackShape`], so hosts running one stack collapse to one
/// line and the number of groups is the number of distinct stacks the segment
/// holds.
fn print_summary(observed: &Seen) {
    if observed.is_empty() {
        return;
    }

    // Grouped per arm, not across them: the two arms ask different questions, and
    // collapsing a host's answers together would report one stack as two.
    let mut groups: BTreeMap<(ProbeVariant, StackShape), Vec<IpAddr>> = BTreeMap::new();
    for ((address, variant, _), (_, row)) in observed {
        groups
            .entry((*variant, row.shape()))
            .or_default()
            .push(*address);
    }

    for arm in ProbeVariant::ALL {
        let of_this_arm: Vec<_> = groups
            .iter()
            .filter(|((variant, _), _)| *variant == arm)
            .collect();
        if of_this_arm.is_empty() {
            continue;
        }
        let hosts: usize = of_this_arm
            .iter()
            .map(|(_, addresses)| addresses.len())
            .sum();

        println!(
            "\nunder the {} probe: {} distinct stack{} across {hosts} host{}",
            arm.name(),
            of_this_arm.len(),
            if of_this_arm.len() == 1 { "" } else { "s" },
            if hosts == 1 { "" } else { "s" },
        );
        for ((_, shape), addresses) in of_this_arm {
            println!(
                "  layout={:<18} window={:<6} df={:<5} mss={} ws={} ts={}  ({} host{})",
                if shape.layout.is_empty() {
                    "-"
                } else {
                    &shape.layout
                },
                shape.window,
                shape.dont_fragment,
                shape.mss.map_or_else(|| "-".to_string(), |m| m.to_string()),
                shape
                    .window_scale
                    .map_or_else(|| "-".to_string(), |w| w.to_string()),
                shape.timestamp,
                addresses.len(),
                if addresses.len() == 1 { "" } else { "s" },
            );
            for address in addresses {
                println!("      {address}");
            }
        }
    }

    println!(
        "\nLabel each group from what the machine is known to be, not from what \
         any fingerprint says about it."
    );
}
