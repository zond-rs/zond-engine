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
//! The first run disproved the assumption the design was built on. Every SYN+ACK
//! on a mixed segment came back carrying **only** an MSS option — no
//! SACK-permitted, no timestamp, no window scale — which is not what any of
//! Linux, Windows or macOS is documented to send, and identical across all
//! three. The cause is not the hosts. TCP option negotiation is **reciprocal**:
//! RFC 7323 §2.2 permits a window scale in a SYN+ACK only if the SYN carried
//! one, §3.2 says the same of timestamps, and RFC 2018 §2 of SACK-permitted. A
//! peer reports the options it was *asked* about. `tcp::create_probe` offers MSS
//! and nothing else, so the option layout — the strongest single feature in the
//! design — was being suppressed by this engine's own probe.
//!
//! So there are two arms, one SYN each:
//!
//! * **mss-only** — `tcp::create_probe` verbatim, which is what the SYN port
//!   scanner sends today. Not a reproduction of it; the actual function.
//! * **negotiating** — the same segment field for field, same window, same MSS,
//!   nonce in the same place, offering the option set an ordinary client offers.
//!
//! Neither arm sends anything a port scan would not. Both are a single SYN, and
//! the negotiating one looks *more* like an ordinary connection attempt than the
//! MSS-only one does, because that is what it is shaped like.
//!
//! ## Why the arms run as separate passes, from separate source ports
//!
//! The second run showed why this matters, by getting it wrong. With both arms
//! sent back to back from **one** source port, the negotiating arm drew no
//! SYN+ACK from any open port at all, while the MSS-only arm drew one from every
//! one of them — and open ports additionally produced a reply carrying neither
//! SYN nor RST, which nothing had predicted.
//!
//! Both effects are one cause. Two SYNs from the same source port to the same
//! host and port are the same **4-tuple**, so the second does not arrive as a
//! second connection attempt: the first has already put the peer in
//! SYN-RECEIVED, and a SYN whose sequence number falls outside that connection's
//! window is answered with a *challenge ACK* (RFC 793 §3.9, and RFC 5961 §4
//! makes it mandatory) rather than a fresh SYN+ACK. So the second arm was not
//! measuring the peer's stack; it was measuring the state the first arm had put
//! it in. Closed ports hold no state, which is exactly why both arms drew
//! identical resets from them and the result looked partly plausible.
//!
//! Each arm therefore runs as a complete pass of its own, with its own source
//! port and its own transport, separated by a settle period. This is the lesson
//! `docs/os-fingerprinting.md` §7 records from the NDP work restated: when two
//! probes look alike on the wire, build the arm that sends only one.
//!
//! ## Running it
//!
//! ```text
//! cargo bench --no-run --bench os_observe
//! sudo -E target/release/deps/os_observe-<hash> <target> [ports] [rate]
//! ```
//!
//! `rate` is probes per second, defaulting to 5000. It matters more than it
//! looks: this instrument sends **one probe per host, port and arm and never
//! retransmits** — a second probe from the same source port would be a duplicate
//! on the same 4-tuple and draw a challenge ACK rather than a fresh answer — so
//! first-attempt loss lands straight in the result as a host that did not answer.
//! Pacing is the whole budget for coverage here. The achieved rate is printed
//! beside the requested one, because a pacer delivering a rate other than the one
//! it was given has already made one of this project's measurements wrong.
//!
//! ## The safety gate
//!
//! `does the fuller option list change any port verdict?` is the block that
//! decides whether the shipped SYN may carry the fuller option list, and it is a
//! different question from whether the fuller list reveals more. A probe that
//! reveals four extra options and loses one open port is not an improvement: the
//! port table is what every other finding in a scan hangs off.
//!
//! Run it wide, and run it across a routed path as well as the local segment —
//! everything on-link has no middlebox in front of it, and a middlebox is the
//! thing most likely to object to an option list:
//!
//! ```text
//! # local segment, wide port list, gently paced
//! sudo -E <binary> 192.168.0.0/24 21,22,23,25,53,80,110,143,443,445,3389,5432,8080,8443 1000
//!
//! # a routed path, where something in the middle gets a say
//! sudo -E <binary> 1.1.1.1 53,80,443 1000
//! ```
//!
//! A disagreement is **not** proof of refusal. With one probe per port and no
//! retransmission, first-attempt loss and deliberate refusal are the same
//! observation. Lower the rate and re-run: a real refusal reproduces, and loss
//! moves around.
//!
//! Built with `--no-run` and invoked directly rather than through `cargo bench`,
//! for the reason `verify_scan` gives, plus one this needs anyway: it wants root,
//! and `sudo cargo` would run the build as root and leave `target/` owned by it.
//!
//! ### Finding the binary you just built
//!
//! A `harness = false` bench builds to a hashed name, several accumulate across
//! rebuilds, and nothing warns you that the one you ran is not the one you
//! built — this engine has already lost three debugging rounds to exactly that.
//! **Select by newest, and select executables** rather than by excluding the
//! extensions you happen to know about:
//!
//! ```text
//! # fish
//! set bin (command ls -t (path filter -fx target/release/deps/os_observe-*))[1]
//! test -x "$bin"; and sudo -E $bin 192.168.0.0/24
//!
//! # bash / zsh
//! bin=$(find target/release/deps -name 'os_observe-*' -type f -perm -u+x -print0 \
//!       | xargs -0 ls -t 2>/dev/null | head -1)
//! [ -x "$bin" ] && sudo -E "$bin" 192.168.0.0/24 || echo "not built yet"
//! ```
//!
//! **Guard the result before running it.** `path filter` is a fish builtin and
//! `$(...)[1]` is fish array syntax; neither exists in bash, so the two forms are
//! not interchangeable. And unguarded, both fail in the same confusing way when
//! nothing has been built: `find` matches nothing, `xargs ls -t` runs with no
//! arguments and lists the *current directory* instead, and `sudo` is handed the
//! first entry in the repository as a command to run. The error then names a
//! directory nobody mentioned.
//!
//! `command ls` is not decoration either. An interactive shell that aliases `ls`
//! to `eza` or `lsd` silently changes what `-t` means — in `eza` it takes an
//! argument and swallows the first path — and the substitution comes back empty
//! again. Asking for executables (`-fx`, `-perm -u+x`) rather than filtering out
//! `.d` and `.o` says what is actually meant and cannot be caught out by an
//! artifact extension nobody listed.
//!//!
//! ## Reading the table
//!
//! One row per host, per arm, per distinct **flag combination** that came back.
//! Nothing in it is inferred:
//!
//! * `flags` is the TCP flag byte as letters, so a reply this instrument has no
//!   name for is identified rather than filed under "other". It is part of the
//!   row key for the same reason: a challenge ACK and a SYN+ACK from one host are
//!   two facts, and folding them together loses the more surprising one.
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
//!   the stack and copied by nobody. A reset carries no options at all, whatever
//!   was offered, so a host with no open port cannot produce this column.
//! * `raw` is the option bytes in hex, so a row can be re-read by hand if the
//!   letters above turn out to have lost something.
//!
//! `what the offered options changed` compares the two arms on their SYN+ACK
//! rows, since that is the only segment options live in. The summary then groups
//! by everything describing the stack rather than the path, per arm and per reply
//! kind, and counts **distinct hosts** — a host answering two ways is one host.
//!
//! Label the groups by hand, from outside — from what the machines are known to
//! be, never from what a fingerprint said — and that labelled table is the corpus
//! phases 3 and 4 are built and measured against.
//!
//! ## What it cannot see
//!
//! A reply that crossed a VPN, a NAT or a load balancer describes whatever
//! rewrote it. Run it on the segment the hosts are actually on, note the
//! interface, and do not merge two runs taken over different paths.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::util::MacAddr;
use tokio::time::timeout;

use zond_engine::model::capture::IpObservation;
use zond_engine::model::ip::set::IpSet;
use zond_engine::model::parse::ip::to_set;
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::protocols::{craft, tcp};
use zond_engine::system::interface::SourceResolver;
use zond_engine::transport::probe::{ProbeKind, ProbeTransport};

/// Ports to try on each address, chosen for being the ones a host on an office
/// or home segment is most likely to have open. Only one has to answer.
const DEFAULT_PORTS: &str = "22,80,443,445,3389,8080";

/// How long to keep reading replies after the last probe of a pass goes out.
///
/// Generous, because this is not measuring latency and a slow answer is worth
/// exactly as much as a fast one here — the features being read are the same in
/// both.
const LISTEN_FOR: Duration = Duration::from_secs(4);

/// How long to wait between passes.
///
/// A pass leaves half-open connections behind it on every open port it found: it
/// never completes a handshake, so each peer sits in SYN-RECEIVED until
/// something clears it. This host's own kernel does clear them — a SYN+ACK
/// arriving for a port no socket owns draws a reset — but that happens on its
/// own schedule, and a peer still holding the connection would answer the next
/// pass's SYN with a challenge ACK instead of a SYN+ACK. Waiting is what keeps
/// the second arm measuring the stack rather than the first arm's leftovers.
const SETTLE_BETWEEN_PASSES: Duration = Duration::from_secs(3);

/// How long to wait on the receive channel before checking whether the listening
/// window has closed.
const RECV_TICK: Duration = Duration::from_millis(200);

/// The initial hop counters a lower bound is reported against. Not a claim that
/// a stack uses one of these — it is the set that makes `start>=` a useful
/// column, and a host whose real initial value is not here still reports a
/// correct bound.
const COMMON_INITIAL_HOPS: [u8; 4] = [32, 64, 128, 255];

/// How fast probes go on the wire by default, in probes per second.
///
/// Paced at all because this instrument has **no retransmission** — one probe per
/// host, port and arm, since a second probe from the same source port would be a
/// duplicate on the same 4-tuple and draw a challenge ACK rather than a fresh
/// answer. With no retry to recover a lost probe, first-attempt loss lands
/// directly in the result as a host that "did not answer", and a burst loses
/// most of its first attempt on a policed or wireless path. Pacing is what buys
/// coverage here, and it is the whole budget for it.
const DEFAULT_RATE: u32 = 5_000;

/// What each arm concluded about each port, which is what the agreement check
/// compares. Absent means the probe went out and nothing came back.
type Outcomes = BTreeMap<(IpAddr, u16), &'static str>;

/// The maximum segment size both arms advertise, matching what
/// `tcp::create_probe` sends so the *only* difference between them is the
/// options offered alongside it.
const PROBE_MSS: u16 = 1412;

/// The receive window both arms advertise, matching `tcp::create_probe` for the
/// same reason.
const PROBE_WINDOW: u16 = 1024;

/// Everything read, keyed by the host, the arm that asked, and the flag byte that
/// came back.
///
/// The flag byte is part of the key rather than folded away for two reasons. A
/// reset and a SYN+ACK from the *same* host are the only way to tell a stack's
/// policy from a per-segment-type code path — the first run showed every SYN+ACK
/// host setting don't-fragment with a zero identifier and every reset host doing
/// neither, which reads as a stack difference and is equally consistent with two
/// code paths, and nothing keyed by host alone can separate them. And a reply
/// carrying some third combination is the most interesting thing a pass can find;
/// keying by host would discard it as a duplicate.
type Seen = BTreeMap<(IpAddr, ProbeVariant, u8), (u16, Observed)>;

/// Which SYN drew a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProbeVariant {
    /// What this engine's SYN scan sends today: an MSS announcement and nothing
    /// else.
    MssOnly,

    /// The same SYN, offering the option set an ordinary client offers — MSS,
    /// SACK-permitted, timestamp, window scale.
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

/// Everything one reply said, in the order the table prints it.
///
/// The IP half and the TCP half are kept in one record because they were read
/// off one packet: a stack chose all of it at once, and splitting them would
/// invite counting them as two independent observations, which they are not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Observed {
    /// The TCP flag byte, verbatim. Every other reading of what kind of reply
    /// this is derives from here rather than being recorded beside it.
    flags: u8,
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
    /// Who actually put this frame on the wire, where the link says.
    ///
    /// The column that says whether a row describes the host in the address
    /// beside it. Everything else here can be produced by something answering in
    /// that host's place, because an interceptor uses the target's IP address;
    /// this cannot. Two hosts on one segment reporting one hardware address are
    /// one machine answering for both.
    source_mac: Option<String>,
    /// Whether that address has the locally-administered bit set — that is,
    /// whether it was made up rather than assigned to a manufacturer.
    ///
    /// Recorded because it is the difference between an address that identifies
    /// hardware and one that deliberately does not. It says nothing about which
    /// operating system chose it: randomisation is a privacy default, and several
    /// unrelated systems ship it.
    locally_administered: Option<bool>,
}

/// The flag byte as letters, in the conventional header order.
fn flag_letters(flags: u8) -> String {
    let named = [
        (tcp::flags::URG, 'U'),
        (tcp::flags::ACK, 'A'),
        (tcp::flags::PSH, 'P'),
        (tcp::flags::RST, 'R'),
        (tcp::flags::SYN, 'S'),
        (tcp::flags::FIN, 'F'),
    ];
    let letters: String = named
        .into_iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, letter)| letter)
        .collect();

    if letters.is_empty() {
        "none".to_string()
    } else {
        letters
    }
}

/// Which of the answers a SYN can draw this is.
///
/// Three outcomes, and the third is not a catch-all for noise: a segment with
/// ACK alone is a *challenge ACK*, which only a host already holding a half-open
/// connection sends, and which therefore says a listener is there. The engine's
/// `tcp::classify_probe_response` discards it; see `docs/bugs.md`.
fn kind(flags: u8) -> &'static str {
    if flags & tcp::flags::RST != 0 {
        "RST"
    } else if flags & tcp::flags::SYN != 0 && flags & tcp::flags::ACK != 0 {
        "SYN+ACK"
    } else {
        "other"
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

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| {
        eprintln!("usage: os_observe <target> [ports]");
        std::process::exit(2);
    });
    let ports = args.next().unwrap_or_else(|| DEFAULT_PORTS.to_string());
    let rate: u32 = args
        .next()
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(DEFAULT_RATE)
        .max(1);

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
        eprintln!("no usable port in the port list");
        std::process::exit(2);
    }

    let mut resolver = SourceResolver::from_system();
    let mut observed: Seen = BTreeMap::new();
    let mut outcomes: BTreeMap<ProbeVariant, Outcomes> = BTreeMap::new();
    let mut probed: BTreeSet<(IpAddr, u16)> = BTreeSet::new();

    // A warm-up pass, discarded entire. Without it the *first* arm is systematically
    // penalised, and not by the network: a raw-socket send to an on-link address
    // whose hardware address this host has not learned yet fails outright with
    // "host is down" while the kernel resolves it, so a host that is up and
    // listening can go unprobed in pass one and be probed cleanly in pass two.
    // That produces a clean-looking, entirely false result — every port of such a
    // host reads as "gained under the fuller option list", when what changed was
    // this machine's neighbour cache. Paying that cost once, before either arm
    // counts, is what makes the two arms comparable.
    //
    // The engine does not need this: it retransmits, so a probe lost to a cold
    // cache goes out again. This instrument cannot, since a second probe from one
    // source port is a duplicate on the same 4-tuple.
    println!("warm-up pass (discarded): teaching this host the segment's neighbours");
    let _ = run_pass(
        ProbeVariant::MssOnly,
        &addresses,
        &ports,
        rate,
        &mut resolver,
    )
    .await;

    for variant in ProbeVariant::ALL {
        println!("\nsettling for {SETTLE_BETWEEN_PASSES:?} before the next pass");
        tokio::time::sleep(SETTLE_BETWEEN_PASSES).await;
        let pass = run_pass(variant, &addresses, &ports, rate, &mut resolver).await;
        observed.extend(pass.observed);
        outcomes.insert(variant, pass.outcomes);
        probed.extend(pass.probed);
    }

    println!();
    print_rows(&observed);
    print_negotiation_effect(&observed);
    print_state_agreement(&outcomes, &probed);
    print_summary(&observed);
}

/// One pass's results: what was read, what each port concluded, and what was
/// asked in the first place.
///
/// The third is not redundant. A port that answered and a port that was never
/// probed are the same absence in the first two, and completely different
/// findings — the distinction the engine's own `send_failure` field exists to
/// preserve.
struct Pass {
    observed: Seen,
    outcomes: Outcomes,
    probed: BTreeSet<(IpAddr, u16)>,
}

/// Runs one arm end to end: its own source port, its own transport, its own
/// listening window.
///
/// A pass of its own per arm is the whole point — see the module docs. Sharing a
/// source port across arms makes the second arm's SYN a duplicate of the first
/// arm's on the same 4-tuple, and what comes back then describes the connection
/// the first arm opened rather than the stack that holds it.
async fn run_pass(
    variant: ProbeVariant,
    addresses: &IpSet,
    ports: &[u16],
    rate: u32,
    resolver: &mut SourceResolver,
) -> Pass {
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

    // nonce -> which probe it belongs to, so a reply names its own target rather
    // than being attributed to whichever address is closest in the list.
    let mut sent: BTreeMap<u32, (IpAddr, u16)> = BTreeMap::new();
    let mut probed: BTreeSet<(IpAddr, u16)> = BTreeSet::new();
    let mut failures: BTreeMap<String, usize> = BTreeMap::new();

    // Derived batch-first, per the pacing rule this project learned the hard way:
    // a batch cannot be smaller than one probe, so computing a batch from a fixed
    // tick silently rounds every rate below the tick frequency up to it, and two
    // arms of a rate sweep become the same arm. Take the interval from the batch
    // instead.
    let batch = (rate / 1_000).max(1);
    let interval = Duration::from_micros(u64::from(batch) * 1_000_000 / u64::from(rate));
    let mut in_batch = 0u32;
    let send_began = Instant::now();

    for address in addresses.iter() {
        let Some(source) = resolver.resolve(address) else {
            eprintln!("no source address reaches {address}, skipping");
            continue;
        };
        for &port in ports {
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
                    // Recorded *after* a successful send, which is the whole
                    // point of recording it. A probe the kernel refused to put on
                    // the wire is not a port that stayed silent, and counting the
                    // two together makes a scan of a mostly-empty range look like
                    // a range of mostly-silent hosts.
                    sent.insert(nonce, (address, port));
                    probed.insert((address, port));
                }
                Err(e) => {
                    // Counted, not printed. A /24 with a dozen hosts on it
                    // produces thousands of these — the kernel cannot resolve a
                    // next hop for an address nobody is using — and a wall of
                    // them buries every other line this instrument writes. One
                    // example of each distinct message is enough to recognise
                    // which failure it is.
                    *failures.entry(format!("{e}")).or_insert(0usize) += 1;
                }
            }

            in_batch += 1;
            if in_batch >= batch {
                in_batch = 0;
                tokio::time::sleep(interval).await;
            }
        }
    }

    // The rate achieved, not the rate asked for. A pacer that quietly delivers a
    // different rate than it was configured with has already turned one arm of a
    // sweep into a duplicate of another on this project once; printing what
    // happened is what keeps that from being invisible. Sub-millisecond intervals
    // are the usual reason the two differ — the timer's granularity is about a
    // millisecond, so a batch of one cannot be paced faster than that.
    let elapsed = send_began.elapsed().as_secs_f64();
    let achieved = if elapsed > 0.0 {
        sent.len() as f64 / elapsed
    } else {
        f64::INFINITY
    };
    let refused: usize = failures.values().sum();
    println!(
        "{} pass: sent {} probes from port {src_port} in {elapsed:.2}s \
         (asked {rate}/s, achieved {achieved:.0}/s), listening for {LISTEN_FOR:?}",
        variant.name(),
        sent.len()
    );
    if refused > 0 {
        // Printed per arm, because an asymmetry here is the first thing to
        // suspect when the two arms disagree: a probe the kernel would not send
        // in one pass and did send in the next is a difference in this host's
        // neighbour cache, not a difference in what the target thinks of the
        // option list.
        println!("  {refused} probe(s) the host would not send:");
        for (reason, count) in &failures {
            println!("    {count:>6} x {reason}");
        }
    }

    let mut observed: Seen = BTreeMap::new();
    let mut outcomes: Outcomes = BTreeMap::new();
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
        // A reply is this pass's only if it echoes back a nonce this pass sent.
        // Without the check, any TCP segment reaching the capture is read as an
        // answer, and a busy host produces a table of other people's
        // connections.
        let nonce = tcp::echoed_nonce(TcpScanTechnique::Syn, &segment);
        let Some(&(address, port)) = sent.get(&nonce) else {
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

        let row = describe(&segment, observation, reply.source_mac);
        // Recorded against the address *probed*, not the one that answered: this
        // is what the port scan concluded about a target, and a reply arriving
        // from elsewhere still resolves that target's port. The row above keys on
        // the answering address, because that is whose stack it describes.
        outcomes
            .entry((address, port))
            .or_insert_with(|| kind(row.flags));
        observed
            .entry((reply.source, variant, row.flags))
            .or_insert((port, row));
    }

    Pass {
        observed,
        outcomes,
        probed,
    }
}

/// Everything one reply says, read once.
fn describe(
    segment: &TcpPacket<'_>,
    observation: IpObservation,
    source_mac: Option<MacAddr>,
) -> Observed {
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
        flags: segment.get_flags(),
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
        source_mac: source_mac.map(|mac| mac.to_string()),
        // Bit 1 of the first octet, per IEEE 802: clear means the address was
        // assigned from a manufacturer's OUI, set means whoever sent it made it
        // up.
        locally_administered: source_mac.map(|mac| mac.0 & 0b10 != 0),
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

/// Renders an optional value, or `-` where there is none. A dash is not zero:
/// several of these fields do not exist in one address family or one segment
/// type, and printing `0` for an absent field invents a measurement.
fn or_dash<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "-".to_string(), |value| value.to_string())
}

fn print_rows(observed: &Seen) {
    if observed.is_empty() {
        println!("nothing answered.");
        return;
    }

    println!(
        "{:<16} {:<12} {:>5} {:<6} {:<8} {:>4} {:>7} {:>7} {:>6} {:>3} {:<16} {:>6} {:>3} {:>3}  traffic",
        "address",
        "probe",
        "port",
        "flags",
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

    for ((address, variant, flags), (port, row)) in observed {
        println!(
            "{:<16} {:<12} {:>5} {:<6} {:<8} {:>4} {:>7} {:>7} {:>6} {:>3} {:<16} {:>6} {:>3} {:>3}  {}{}",
            address.to_string(),
            variant.name(),
            port,
            flag_letters(*flags),
            kind(*flags),
            row.hops_left,
            initial_hops_at_least(row.hops_left),
            or_dash(row.ip_id),
            row.window,
            if row.dont_fragment { "yes" } else { "no" },
            if row.layout.is_empty() {
                "-"
            } else {
                &row.layout
            },
            or_dash(row.mss),
            or_dash(row.window_scale),
            if row.timestamp { "yes" } else { "no" },
            row.traffic,
            row.flow_label
                .map_or_else(String::new, |label| format!(" flow={label}")),
        );
    }

    println!("\nraw option bytes");
    for ((address, variant, flags), (_, row)) in observed {
        println!(
            "  {:<16} {:<12} {:<6} {}",
            address.to_string(),
            variant.name(),
            flag_letters(*flags),
            if row.raw_options.is_empty() {
                "-"
            } else {
                &row.raw_options
            }
        );
    }

    print_provenance(observed);
}

/// Which hardware address each answer actually came from.
///
/// Printed apart from the feature table because it is not a feature: it says
/// whether the row above it describes the host in its address column at all.
/// Everything else this instrument reads can be produced by something answering
/// in a host's place — an interceptor, a proxy, a firewall resetting on a host's
/// behalf — because all of those use the target's IP address and the reply looks
/// entirely ordinary. The hardware address does not, and **several addresses
/// resolving to one of them is the signature of exactly that**.
///
/// On a link that prepends no addresses — loopback, a tunnel, raw IP — there is
/// nothing to read and the column is empty. That is not evidence of anything.
fn print_provenance(observed: &Seen) {
    let mut senders: BTreeMap<&str, BTreeSet<IpAddr>> = BTreeMap::new();
    let mut unknown: BTreeSet<IpAddr> = BTreeSet::new();
    let mut randomised: BTreeMap<&str, bool> = BTreeMap::new();
    for ((address, _, _), (_, row)) in observed {
        match row.source_mac.as_deref() {
            Some(mac) => {
                senders.entry(mac).or_default().insert(*address);
                if let Some(local) = row.locally_administered {
                    randomised.insert(mac, local);
                }
                true
            }
            None => unknown.insert(*address),
        };
    }

    if senders.is_empty() {
        return;
    }

    println!("\nwho actually sent each answer");
    for (mac, addresses) in &senders {
        let shared = addresses.len() > 1;
        println!(
            "  {mac}  {:<9} {} address{}{}",
            match randomised.get(mac) {
                Some(true) => "randomised",
                Some(false) => "vendor",
                None => "",
            },
            addresses.len(),
            if shared { "es" } else { "" },
            if shared {
                "   <- one machine answering for several"
            } else {
                ""
            }
        );
        for address in addresses {
            println!("      {address}");
        }
    }

    if !unknown.is_empty() {
        println!(
            "  {} address(es) arrived over a link with no hardware addresses to read",
            unknown.len()
        );
    }

    let made_up = randomised.values().filter(|local| **local).count();
    if made_up > 0 {
        println!(
            "\n  {made_up} of {} answered from a made-up hardware address (the \
             locally-administered\n  bit is set), so no vendor can be read from it. That is a \
             privacy default and not\n  an operating system: several unrelated systems ship \
             it, and a segment whose\n  randomising devices happen to share an OS will make it \
             look like one.",
            randomised.len()
        );
    }

    if senders.values().any(|addresses| addresses.len() > 1) {
        println!();
        println!("  One hardware address answering for several IP addresses means those rows");
        println!("  describe that machine, not the hosts they are filed under. Read every");
        println!("  feature of the shared rows as belonging to whatever holds that address.");
    }
}

/// What offering the fuller option set actually bought, host by host.
///
/// The number this instrument exists to produce. TCP option negotiation is
/// reciprocal, so a peer answers about the options it was *asked* about — which
/// means the option layout, the strongest single feature available, is decided as
/// much by our probe as by their stack. This says by how much.
fn print_negotiation_effect(observed: &Seen) {
    let addresses: BTreeSet<IpAddr> = observed.keys().map(|(address, _, _)| *address).collect();
    if addresses.is_empty() {
        return;
    }

    println!("\nwhat the offered options changed");
    println!(
        "  {:<16} {:<18} {:<18} verdict",
        "address", "mss-only", "negotiating"
    );

    let mut revealed = 0usize;
    let mut unchanged = 0usize;
    let mut no_open_port = 0usize;
    let mut one_armed = 0usize;

    for address in &addresses {
        // Compared on the SYN+ACK rows, because that is where options live: a
        // reset carries none whatever was offered, so a host with only closed
        // ports cannot answer this question either way.
        let synack = |variant| {
            observed
                .iter()
                .find(|((host, arm, flags), _)| {
                    host == address && *arm == variant && kind(*flags) == "SYN+ACK"
                })
                .map(|(_, (_, row))| row)
        };
        let mss_only = synack(ProbeVariant::MssOnly);
        let negotiating = synack(ProbeVariant::Negotiating);

        let show = |row: Option<&Observed>| match row {
            Some(row) if row.layout.is_empty() => "no options".to_string(),
            Some(row) => row.layout.clone(),
            None => "no SYN+ACK".to_string(),
        };

        // Counted by option *count*, not string length: a layout is a list, and
        // "did the peer name more options" is the question, not "is the text
        // longer".
        let count = |row: Option<&Observed>| {
            row.map(|row| {
                if row.layout.is_empty() {
                    0
                } else {
                    row.layout.split(',').count()
                }
            })
        };

        let anything_at_all = observed
            .keys()
            .any(|(host, _, flags)| host == address && kind(*flags) == "SYN+ACK");

        let verdict = match (count(mss_only), count(negotiating)) {
            (Some(before), Some(after)) if after > before => {
                revealed += 1;
                format!("+{} option(s) revealed", after - before)
            }
            (Some(before), Some(after)) if after < before => {
                one_armed += 1;
                format!("-{} option(s), unexpected", before - after)
            }
            (Some(_), Some(_)) => {
                unchanged += 1;
                "no change".to_string()
            }
            _ if !anything_at_all => {
                no_open_port += 1;
                // Every reply this host gave was a reset or a bare ACK, and
                // neither carries options. Not a gap in the measurement — a limit
                // on what a closed port can ever say.
                "no open port, so no options".to_string()
            }
            _ => {
                one_armed += 1;
                "only one arm drew a SYN+ACK".to_string()
            }
        };

        println!(
            "  {:<16} {:<18} {:<18} {verdict}",
            address.to_string(),
            show(mss_only),
            show(negotiating),
        );
    }

    println!(
        "\n  of {} host(s) that answered: {revealed} revealed more, {unchanged} unchanged, \
         {no_open_port} with no open port, {one_armed} answered only one arm",
        addresses.len()
    );
    if one_armed > 0 {
        println!(
            "  A host answering only one arm is not a result. Both arms are one SYN each,\n  \
             so an open port that answers one and not the other is either loss or\n  \
             leftover half-open state — re-run before reading anything into it."
        );
    }
}

/// **The safety gate.** Whether the two arms concluded the same thing about every
/// port they both asked about.
///
/// This is the question that decides whether the shipped SYN may carry the fuller
/// option list, and it is separate from whether the fuller list reveals more. A
/// probe that reveals four extra options and loses one open port is not an
/// improvement; the port table is what every other finding in a scan hangs off.
///
/// The dangerous direction is asymmetric and reported as such. An open port under
/// one arm and silence under the other means something dropped the probe or its
/// answer — a host that dislikes the option list, or a middlebox in the path — and
/// that is a coverage regression. Silence under both is not a finding either way.
///
/// **A disagreement here is not proof of refusal.** This instrument sends one
/// probe per port per arm and cannot retransmit — a second probe from the same
/// source port would be a duplicate on the same 4-tuple — so first-attempt loss
/// and deliberate refusal look identical. Lower the rate and re-run before
/// concluding anything from a small number of disagreements; a real refusal
/// reproduces and loss moves around.
fn print_state_agreement(
    outcomes: &BTreeMap<ProbeVariant, Outcomes>,
    probed: &BTreeSet<(IpAddr, u16)>,
) {
    let Some(mss_only) = outcomes.get(&ProbeVariant::MssOnly) else {
        return;
    };
    let Some(negotiating) = outcomes.get(&ProbeVariant::Negotiating) else {
        return;
    };

    let mut agreed = 0usize;
    let mut silent_both = 0usize;
    let mut disagreements: Vec<(IpAddr, u16, &'static str, &'static str)> = Vec::new();

    for &(address, port) in probed {
        let before = mss_only.get(&(address, port)).copied();
        let after = negotiating.get(&(address, port)).copied();
        match (before, after) {
            (None, None) => silent_both += 1,
            (a, b) if a == b => agreed += 1,
            (a, b) => {
                disagreements.push((address, port, a.unwrap_or("silent"), b.unwrap_or("silent")))
            }
        }
    }

    println!("\ndoes the fuller option list change any port verdict?");
    println!(
        "  {} port(s) probed: {agreed} agreed, {} disagreed, {silent_both} silent under both",
        probed.len(),
        disagreements.len()
    );

    if disagreements.is_empty() {
        println!(
            "  No port concluded differently. This is the gate the shipped probe has to pass."
        );
        return;
    }

    // A host that disagreed on *every* port it was asked about was not weighing
    // the option list — it was absent for one of the two passes. A sleeping
    // wireless device does exactly this, and so did a host whose hardware address
    // this machine had not yet learned. Counting those alongside a genuine
    // single-port difference buries the one that means something: fourteen
    // "disagreements" from one phone reads as a serious result and is not one.
    //
    // The signature is all-or-nothing per host. A stack objecting to an option
    // list would answer some ports and not others, because that is what having
    // open and closed ports means.
    let mut probed_per_host: BTreeMap<IpAddr, usize> = BTreeMap::new();
    for (address, _) in probed {
        *probed_per_host.entry(*address).or_default() += 1;
    }
    let mut disagreed_per_host: BTreeMap<IpAddr, usize> = BTreeMap::new();
    for (address, _, _, _) in &disagreements {
        *disagreed_per_host.entry(*address).or_default() += 1;
    }
    let absent: BTreeSet<IpAddr> = disagreed_per_host
        .iter()
        .filter(|(address, count)| probed_per_host.get(address) == Some(count))
        .map(|(address, _)| *address)
        .collect();
    let absent_rows: usize = absent
        .iter()
        .filter_map(|address| disagreed_per_host.get(address))
        .sum();

    if !absent.is_empty() {
        println!();
        println!(
            "  {absent_rows} of those are {} host(s) that disagreed on *every* port asked,",
            absent.len()
        );
        println!("  which is a host present for one pass and not the other rather than a");
        println!("  stack weighing options:");
        for address in &absent {
            println!("      {address}");
        }
    }
    println!();
    println!(
        "  {} disagreement(s) on hosts that answered both passes. Those are the ones",
        disagreements.len() - absent_rows
    );
    println!("  that say anything about the option list.");

    println!(
        "\n  {:<16} {:>5} {:<10} {:<10} direction",
        "address", "port", "mss-only", "negotiating"
    );
    let mut lost = 0usize;
    let mut gained = 0usize;
    for (address, port, before, after) in &disagreements {
        // "lost" means the fuller option list drew *less* than the MSS-only probe
        // did. That is the only direction that argues against the change.
        let direction = match (*before, *after) {
            ("silent", _) => {
                gained += 1;
                "gained under the fuller list"
            }
            (_, "silent") => {
                lost += 1;
                "LOST under the fuller list"
            }
            _ => "different reply, both answered",
        };
        println!(
            "  {:<16} {port:>5} {before:<10} {after:<10} {direction}",
            address.to_string()
        );
    }

    println!();
    println!("  {lost} lost, {gained} gained. Re-run at a lower rate before reading either");
    println!("  as refusal: with one probe per port and no retransmission, loss and");
    println!("  refusal are the same observation here.");
}

/// Groups the rows by [`StackShape`], per arm and per reply kind, so hosts
/// running one stack collapse to one line.
///
/// Split by reply kind as well as by arm because a reset and a SYN+ACK describe
/// different code paths in the same stack, and counting them as two stacks would
/// double every host that gave both. Counted by **distinct host**, for the same
/// reason: a host answering three ways is one machine.
fn print_summary(observed: &Seen) {
    if observed.is_empty() {
        return;
    }

    let mut groups: BTreeMap<(ProbeVariant, &'static str, StackShape), BTreeSet<IpAddr>> =
        BTreeMap::new();
    for ((address, variant, flags), (_, row)) in observed {
        groups
            .entry((*variant, kind(*flags), row.shape()))
            .or_default()
            .insert(*address);
    }

    for arm in ProbeVariant::ALL {
        for reply in ["SYN+ACK", "RST", "other"] {
            let of_this_slice: Vec<_> = groups
                .iter()
                .filter(|((variant, seen, _), _)| *variant == arm && *seen == reply)
                .collect();
            if of_this_slice.is_empty() {
                continue;
            }
            let hosts: BTreeSet<IpAddr> = of_this_slice
                .iter()
                .flat_map(|(_, addresses)| addresses.iter().copied())
                .collect();

            println!(
                "\n{} probe, {reply} replies: {} distinct shape{} across {} host{}",
                arm.name(),
                of_this_slice.len(),
                if of_this_slice.len() == 1 { "" } else { "s" },
                hosts.len(),
                if hosts.len() == 1 { "" } else { "s" },
            );
            for ((_, _, shape), addresses) in of_this_slice {
                println!(
                    "  layout={:<16} window={:<6} df={:<5} mss={:<6} ws={:<3} ts={}",
                    if shape.layout.is_empty() {
                        "-"
                    } else {
                        &shape.layout
                    },
                    shape.window,
                    shape.dont_fragment,
                    or_dash(shape.mss),
                    or_dash(shape.window_scale),
                    shape.timestamp,
                );
                for address in addresses {
                    println!("      {address}");
                }
            }
        }
    }

    print_zero_hop_note(observed);

    println!(
        "\nLabel each group from what the machine is known to be, not from what \
         any fingerprint says about it."
    );
}

/// Names the hosts whose reply crossed no router at all.
///
/// A hop counter that arrives at exactly one of the usual initial values has been
/// decremented zero times. On the local segment that is simply what on-link means.
/// On a **routed** target it means the answer did not come from where it claims
/// to: something in the path — a transparent proxy, a DNS interceptor, a captive
/// portal — answered on the target's behalf, and every feature in its row belongs
/// to that middlebox rather than to the host named in the address column.
///
/// Worth a line of its own because the source address does not give it away. An
/// interceptor answers *as* the target, so the row looks entirely ordinary and the
/// "answered by" warning never fires.
fn print_zero_hop_note(observed: &Seen) {
    let untraversed: BTreeSet<IpAddr> = observed
        .iter()
        .filter(|(_, (_, row))| COMMON_INITIAL_HOPS.contains(&row.hops_left))
        .map(|((address, _, _), _)| *address)
        .collect();

    if untraversed.is_empty() {
        return;
    }

    println!(
        "\n{} host(s) answered with a hop counter at its initial value, so no router \
         was crossed:",
        untraversed.len()
    );
    for address in &untraversed {
        println!("      {address}");
    }
    println!("  Expected for anything on this segment. For a target that should be routed,");
    println!("  it means something local answered in its place, and the row describes that");
    println!("  instead.");
}
