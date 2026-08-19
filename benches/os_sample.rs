// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reads the counters a stack keeps, by asking the same host more than once.
//!
//! Everything the passive path knows comes from **one** reply, and three of the
//! features `docs/os-fingerprinting.md` §3.2 names cannot be read from one reply
//! at all. The IP identification field is interesting for how it *changes* —
//! zero, per-socket, globally incrementing and random are four different stack
//! policies and a single value is consistent with all four. The initial sequence
//! number is the same: one is a number, several are a generation algorithm. And
//! the TCP timestamp clock's frequency is a stack-build constant that needs two
//! samples and an interval to compute.
//!
//! This instrument takes those samples and prints what they say. It authors no
//! rules and decides nothing; it exists so that phase 6 is built against
//! measurement rather than against the published sequence-generation folklore,
//! which is the mistake phase 1 caught itself making about option layouts.
//!
//! ## The probe is the one the scanner already sends
//!
//! There is no new packet shape here. Every probe is `tcp::create_probe` for
//! `TcpScanTechnique::Syn` — the engine's own function, not a reproduction of it
//! — and the only thing that differs from an ordinary SYN scan is that each
//! target is asked more than once.
//!
//! That is worth being explicit about, because it decides what
//! [`OsDetection::Active`] costs. A repeated SYN is not a probe a firewall has a
//! separate opinion about, it carries nothing malformed, and it is
//! indistinguishable from a client retrying a connection. The **cheapest thing
//! phase 6 can do is not a new probe at all.** Whether it is also a *useful*
//! thing is the question this instrument answers.
//!
//! [`OsDetection::Active`]: zond_engine::config::OsDetection::Active
//!
//! ## Every sample leaves from its own source port
//!
//! Two SYNs to one host and port from one source port are the same 4-tuple, so
//! the second is not a second connection attempt: the first has already put the
//! peer in SYN-RECEIVED, and what comes back describes that state rather than
//! the stack holding it. `benches/os_observe.rs` has the full account, and
//! `docs/os-fingerprinting.md` §7 records the two earlier measurements this
//! project lost to probes that looked alike on the wire.
//!
//! So each sample uses a fresh source port. That also makes each sample a
//! genuine new connection attempt, which is what the sequence-number question
//! needs — an initial sequence number is chosen per connection, and sampling one
//! connection repeatedly would measure nothing.
//!
//! Unlike `os_observe` this needs **no settle period between samples**, and the
//! reason is the same fact read the other way: a fresh source port is a fresh
//! 4-tuple, so nothing left behind by the previous sample is in the way. That
//! matters because the spacing between samples is a *measurement parameter*
//! here, not hygiene — see below — and a three-second settle would destroy the
//! identifier question outright.
//!
//! ## Why the spacing is small, and what happens when it is not
//!
//! A 16-bit identifier counter wraps every 65 536 packets. Sampled across a gap
//! long enough for a busy host to wrap it, a counter and a random number are the
//! same observation, and six samples cannot separate them. The default spacing
//! is therefore short, and this instrument **refuses to classify** an identifier
//! series whose consecutive intervals exceeded [`MAX_INTERVAL_FOR_ID`]: it
//! prints the raw values and says `unclear` rather than reporting a class it
//! cannot support. A wrong class here is exactly the kind of confident wrong
//! answer this project keeps a trap list about.
//!
//! The consequence is a scope limit worth knowing before running it: the sweep
//! for one sample has to *finish* inside that interval, so this is an instrument
//! for a small set of hosts. That is the population phase 6 aims at anyway —
//! active probes fire only where the passive posterior was thin — but pointing
//! it at a /24 will produce `unclear` for every host and it will be right to.
//!
//! ## What a host with no open port still says
//!
//! A reset carries no options and no useful sequence number, so a closed host
//! says nothing about timestamps or sequence generation. It does carry an IP
//! header, and therefore an identifier, so the identifier series is readable
//! from resets alone. This instrument follows a host on whichever answer it gave
//! — a SYN+ACK where there was one, a reset otherwise — and says which, because
//! the two are not equivalent evidence.
//!
//! **Read a reset-derived series against the retraction in
//! `docs/os-fingerprinting.md`.** The identifier and don't-fragment values that
//! six labelled Apple devices put in their resets changed when the same targets
//! were measured from a different machine on the same segment, and the feature
//! built on them was withdrawn. Nothing about that is explained yet. A series
//! read off resets is a candidate for the same failure and has to be reproduced
//! from a second vantage point before anything is built on it.
//!
//! ## Running it
//!
//! ```text
//! cargo bench --no-run --bench os_sample
//! sudo -E <binary> <target> [ports] [samples] [spacing_ms] [rate]
//! ```
//!
//! ### Finding the binary you just built
//!
//! A `harness = false` bench builds to a hashed name, several accumulate across
//! rebuilds, and nothing warns you that the one you ran is not the one you
//! built. **Select by newest, and select executables:**
//!
//! ```text
//! # fish
//! set bin (command ls -t (path filter -fx target/release/deps/os_sample-*))[1]
//! test -x "$bin"; and sudo -E $bin 192.168.0.0/28
//!
//! # bash / zsh
//! bin=$(find target/release/deps -name 'os_sample-*' -type f -perm -u+x -print0 \
//!       | xargs -0 ls -t 2>/dev/null | head -1)
//! [ -x "$bin" ] && sudo -E "$bin" 192.168.0.0/28 || echo "not built yet"
//! ```
//!
//! Guard the result before running it. Unguarded on a tree that has not been
//! built, `xargs ls -t` receives no input and lists the current directory
//! instead, so `sudo` is handed the first entry in the repository as a command.
//! `command ls` defeats an interactive alias to `eza`, where `-t` takes an
//! argument and swallows the first path.
//!
//! ## Reading the output
//!
//! The last block is the one that decides anything. **`what the extra samples
//! bought`** groups the hosts by the stack shape their *first* reply gave —
//! which is everything phases 1 to 5 can see — and then asks whether the series
//! tells any two hosts in one group apart. A probe that never refines that
//! partition cannot change a verdict, whatever else it reveals, and should not
//! ship: that is the acceptance test `docs/os-fingerprinting.md` sets for phase
//! 6, and it is the ndp_pace lesson restated — measure the number a user sees,
//! not a proxy for it.
//!
//! A split is necessary, not sufficient. Two hosts running the same operating
//! system can differ here for reasons that are not the stack: uptime moves a
//! timestamp clock's *offset* though not its rate, and load moves an identifier
//! counter's step. **Label the hosts from outside and check that the splits fall
//! between families rather than inside one.** A feature that separates a
//! labelled corpus perfectly is the one to re-measure from a second machine
//! before building on it.
//!
//! `per-sample reach` is printed for its own reason. A host that answers the
//! first three samples and none of the last three has rate-limited this
//! instrument, and averaging that into a class would report a stack policy where
//! what happened was a firewall. A decay down the column is that, and it is
//! visible only because the samples are counted separately.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use tokio::time::timeout;

use zond_engine::fingerprinting::os::StackObservation;
use zond_engine::model::capture::IpObservation;
use zond_engine::model::parse::ip::to_set;
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::protocols::tcp;
use zond_engine::system::interface::SourceResolver;
use zond_engine::transport::capture::CapturedSegment;
use zond_engine::transport::probe::{ProbeKind, ProbeTransport};

/// Ports tried on each address in the first sweep, chosen for being the ones a
/// host on an office or home segment is most likely to have open. Only one has
/// to answer: the series follows a single port per host.
const DEFAULT_PORTS: &str = "22,80,443,445,3389,8080";

/// How many times each host is asked *after* the discovery sweep.
///
/// Six is the smallest number that answers the three questions here. An
/// identifier policy needs at least three values before "constant" and "counting
/// up" are different observations, a clock rate wants a span rather than a pair
/// so that one late reply cannot set it, and a sequence generator's step is a
/// property of several differences rather than one. Beyond six the marginal
/// sample buys precision on a rate, not a class, and every one of them is a
/// packet per host.
const DEFAULT_SAMPLES: usize = 6;

/// The gap between one sample's sweep and the next, in milliseconds.
///
/// A measurement parameter, not politeness. See the module docs: too long and
/// the identifier question stops having an answer, because a counter can wrap
/// inside the gap and become indistinguishable from a random value.
const DEFAULT_SPACING_MS: u64 = 100;

/// How long to keep reading after the last sample goes out. Generous: a slow
/// answer carries the same counters as a fast one, and dropping it costs a
/// sample the series cannot get back.
const LISTEN_AFTER_LAST: Duration = Duration::from_secs(4);

/// How long to block on the receive channel before checking the clock again.
/// Short, because this loop is also what paces the gap between samples and a
/// coarse tick would smear the interval the clock rate is computed over.
const RECV_TICK: Duration = Duration::from_millis(5);

/// How fast probes go on the wire within one sweep, in probes per second.
///
/// This instrument never retransmits — a second probe for one sample would be a
/// duplicate on that sample's 4-tuple — so first-attempt loss lands directly in
/// the result as a missing sample. Pacing is the whole budget for coverage.
const DEFAULT_RATE: u32 = 5_000;

/// The longest gap between two consecutive replies that still permits an
/// identifier series to be classified.
///
/// Beyond this the instrument reports the raw values and declines to name a
/// class. The bound comes from the field's width: at
/// [`PLAUSIBLE_ID_RATE`] a global counter advances far enough inside a longer
/// gap to wrap a 16-bit field, and a wrapped counter and a random number are the
/// same six numbers.
const MAX_INTERVAL_FOR_ID: Duration = Duration::from_millis(500);

/// The fastest a host's global identifier counter is assumed to advance, in
/// steps per second, when deciding whether a series can be classified at all.
///
/// Deliberately generous. It is not a claim about any stack — it is the point
/// past which this instrument stops trusting itself, and being wrong about it in
/// the cautious direction costs a `unclear` line rather than a wrong class.
const PLAUSIBLE_ID_RATE: f64 = 20_000.0;

/// The largest per-second advance an identifier series may show and still read
/// as a counter rather than as randomness.
///
/// Same number, used for the classification rather than for the refusal: a
/// series whose steps imply a faster rate than any host plausibly sends is not a
/// counter being observed, it is sixteen bits of noise.
const COUNTER_RATE_CEILING: f64 = PLAUSIBLE_ID_RATE;

/// The largest gap between two identifiers from one host, answered in a single
/// sweep, that still reads as one counter stepping rather than two unrelated
/// values.
///
/// Small on purpose: these replies left within milliseconds of each other, so a
/// shared counter has had almost nothing else to count in between.
const ACROSS_PORT_STEP: u16 = 64;

/// The fastest a TCP timestamp clock is taken to plausibly run, in hertz.
///
/// RFC 7323 §4 asks for a tick between 1 ms and 1 second, which is 1 to 1000 Hz.
/// This leaves an order of magnitude above that, so the ceiling is not a claim
/// about any stack — it is the point past which a "rate" is arithmetic on two
/// unrelated numbers rather than a clock being observed.
const CLOCK_CEILING: f64 = 10_000.0;

/// How far the per-interval rates of one clock may spread before they stop
/// describing one clock.
///
/// A factor of two is generous for jitter: this instrument's own timing error
/// across a hundred-millisecond interval is a couple of percent. It is far
/// tighter than the gap between one clock and a series of random offsets, which
/// is what it exists to separate.
const CLOCK_SPREAD: f64 = 2.0;

/// The smallest common divisor of the sequence-number differences that counts as
/// evidence of a fixed step rather than a coincidence.
///
/// A stack that advances its initial sequence number by a constant leaves that
/// constant as the divisor of every difference. Random 32-bit values share a
/// small divisor by chance — two random numbers are both even a quarter of the
/// time — so a threshold well above the small factors is what separates the two.
const MEANINGFUL_ISN_STEP: u32 = 1_024;

/// What one reply carried, and when.
#[derive(Debug, Clone)]
struct Reading {
    /// When this reply was read. The interval between two of these is what a
    /// clock rate and an identifier step are computed against — a nominal
    /// spacing is what the sender intended, not what happened.
    at: Instant,
    /// The TCP flag byte, so a series can say whether it is reading SYN+ACKs or
    /// resets. The two are different code paths in one stack and mixing them
    /// would compare a host against itself under two policies.
    flags: u8,
    /// The sequence number as it arrived: the peer's initial sequence number in
    /// a SYN+ACK, and usually zero in a reset.
    sequence: u32,
    /// The IPv4 identification field. `None` over IPv6, which has none.
    ip_id: Option<u16>,
    /// The peer's own clock, where it sent a timestamp option.
    tsval: Option<u32>,
    /// Everything about this reply that describes the stack rather than the
    /// path, for the partition this instrument is measured against.
    shape: StackShape,
    /// Who answered, which is not always who was asked.
    from: IpAddr,
}

/// The stack-describing half of a reply, as the passive path can see it.
///
/// The hop counter and the identification field are deliberately absent: the
/// first depends on how far away the host is and the second on what else it was
/// doing. What remains is what the stack's authors chose, so two hosts with one
/// shape are — as far as a single reply can say — running the same stack. That
/// is the partition the extra samples have to refine to be worth sending.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StackShape {
    layout: String,
    window: u16,
    dont_fragment: bool,
    mss: Option<u16>,
    window_scale: Option<u8>,
    timestamps: bool,
}

impl StackShape {
    fn of(observed: &StackObservation) -> Self {
        Self {
            layout: observed.layout_string(),
            window: observed.window,
            dont_fragment: match observed.ip {
                IpObservation::V4(v4) => v4.dont_fragment,
                // An IPv6 datagram is never fragmented in transit, so the
                // question the IPv4 bit asks is settled by the protocol.
                IpObservation::V6(_) => true,
            },
            mss: observed.mss,
            window_scale: observed.window_scale,
            timestamps: observed.timestamps.is_some(),
        }
    }
}

/// One probe, recorded when it reached the wire and not before. A probe the
/// kernel refused is not a host that stayed silent.
#[derive(Debug, Clone, Copy)]
struct Sent {
    address: IpAddr,
    port: u16,
    sample: usize,
}

/// Nonce to the probe that carried it, which is how a reply names its own target
/// rather than being attributed to whichever address is closest in the list.
type SentMap = BTreeMap<u32, Sent>;

/// Everything read, keyed by the address asked, the sample, and the port. First
/// answer wins: a duplicate is the path repeating itself, not a second reading.
type Readings = BTreeMap<(IpAddr, usize, u16), Reading>;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| {
        eprintln!("usage: os_sample <target> [ports] [samples] [spacing_ms] [rate]");
        eprintln!("       os_sample self-check   (no root, no network)");
        std::process::exit(2);
    });
    if target == "self-check" {
        std::process::exit(i32::from(!self_check()));
    }
    let ports = args.next().unwrap_or_else(|| DEFAULT_PORTS.to_string());
    let samples: usize = args
        .next()
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(DEFAULT_SAMPLES)
        .max(2);
    let spacing = Duration::from_millis(
        args.next()
            .and_then(|arg| arg.parse().ok())
            .unwrap_or(DEFAULT_SPACING_MS),
    );
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

    // Every SYN and RST on IPv4, and every IPv6 TCP segment, rather than one
    // narrow port filter. A filter narrowed to a reply port is only expressible
    // for a scan that sends from one port, and this one deliberately sends from a
    // fresh port per sample. What comes up is matched against the nonces actually
    // sent, so the wider filter costs work in userspace and nothing in accuracy.
    //
    // One transport for all samples, not one per sample. Opening a capture takes
    // long enough to swallow the spacing, and the spacing is the measurement.
    let mut transport = match ProbeTransport::open(ProbeKind::TcpSyn) {
        Ok(transport) => transport,
        Err(e) => {
            eprintln!("cannot open a probe transport: {e}");
            eprintln!("this needs root: it opens a raw socket and a capture.");
            std::process::exit(1);
        }
    };

    let sweep_targets: Vec<(IpAddr, u16)> = addresses
        .iter()
        .flat_map(|address| ports.iter().map(move |&port| (address, port)))
        .collect();

    let mut sent: SentMap = BTreeMap::new();
    let mut readings: Readings = BTreeMap::new();

    // A warm-up sweep, discarded entire. A raw-socket send to an on-link address
    // whose hardware address this host has not learned yet fails outright while
    // the kernel resolves it, so a host that is up and listening can go unprobed
    // in the first sweep and be probed cleanly in the second. Here that would not
    // merely lose a host — it would lose it from *sample 0*, which is what
    // decides which port the whole series follows, so the host would be dropped
    // from the run rather than showing up short by one sample.
    println!("warm-up sweep (discarded): teaching this host the segment's neighbours");
    let mut discard: SentMap = BTreeMap::new();
    sweep(
        &mut transport,
        &mut resolver,
        &sweep_targets,
        usize::MAX,
        rate,
        &mut discard,
        &mut readings,
    )
    .await;
    drain_until(
        &mut transport,
        Instant::now() + spacing,
        &discard,
        &mut readings,
    )
    .await;
    readings.clear();

    // Sample 0 asks every port, because it is also what finds them. Later samples
    // ask one port per host: the series question is about a host's counters over
    // time, and following several ports at once would interleave several answers
    // per sample with no way to order them.
    println!("\nsample 0: sweeping {} probe(s)", sweep_targets.len());
    let first = sweep(
        &mut transport,
        &mut resolver,
        &sweep_targets,
        0,
        rate,
        &mut sent,
        &mut readings,
    )
    .await;
    report_sweep(0, &first);
    drain_until(
        &mut transport,
        Instant::now() + spacing,
        &sent,
        &mut readings,
    )
    .await;

    let followed = choose_followed(&readings);
    let series_targets: Vec<(IpAddr, u16)> = followed.iter().flat_map(Followed::targets).collect();
    if series_targets.is_empty() {
        println!("\nnothing answered the first sweep; there is no series to take.");
        return;
    }
    println!(
        "\nfollowing {} host(s) on {} port(s) for {samples} sample(s), {:?} apart",
        followed.len(),
        series_targets.len(),
        spacing,
    );

    for sample in 1..=samples {
        let swept = sweep(
            &mut transport,
            &mut resolver,
            &series_targets,
            sample,
            rate,
            &mut sent,
            &mut readings,
        )
        .await;
        report_sweep(sample, &swept);
        drain_until(
            &mut transport,
            Instant::now() + spacing,
            &sent,
            &mut readings,
        )
        .await;
    }

    drain_until(
        &mut transport,
        Instant::now() + LISTEN_AFTER_LAST,
        &sent,
        &mut readings,
    )
    .await;

    println!();
    print_reach(&readings, &sent, samples);
    print_series(&readings, &followed, samples);
    print_identifiers_across_ports(&readings);
    print_refinement(&readings, &followed, samples);
    print_scope(&addresses.iter().count(), &readings);
}

/// What one sweep managed to put on the wire.
struct Swept {
    source_port: u16,
    sent: usize,
    elapsed: Duration,
    /// One entry per distinct reason, counted rather than printed per probe: a
    /// range with a dozen live hosts produces thousands of "no route" failures
    /// and a wall of them buries everything else.
    failures: BTreeMap<String, usize>,
}

/// Sends one probe per target, from a source port of this sample's own.
///
/// Returns as soon as the last probe is away; reading is the caller's job,
/// because the gap between two sweeps is where the replies to the first one
/// arrive and that gap is also the interval the whole measurement rests on.
async fn sweep(
    transport: &mut ProbeTransport,
    resolver: &mut SourceResolver,
    targets: &[(IpAddr, u16)],
    sample: usize,
    rate: u32,
    sent: &mut SentMap,
    readings: &mut Readings,
) -> Swept {
    let source_port: u16 = rand::random_range(50_000..u16::MAX);
    let mut failures: BTreeMap<String, usize> = BTreeMap::new();
    let mut put_on_wire = 0usize;

    // Derived batch-first. A batch cannot be smaller than one probe, so computing
    // a batch from a fixed tick silently rounds every rate below the tick
    // frequency up to it, and two arms of a rate sweep become one arm.
    let batch = (rate / 1_000).max(1);
    let interval = Duration::from_micros(u64::from(batch) * 1_000_000 / u64::from(rate));
    let mut in_batch = 0u32;
    let began = Instant::now();

    for &(address, port) in targets {
        let Some(source) = resolver.resolve(address) else {
            *failures
                .entry(format!("no source address reaches {address}"))
                .or_insert(0) += 1;
            continue;
        };
        let nonce: u32 = rand::random();
        // The engine's own probe, not a reproduction of it. If the shipped SYN
        // changes, this measurement changes with it rather than quietly
        // describing a packet the scanner no longer sends.
        let segment = match tcp::create_probe(
            TcpScanTechnique::Syn,
            &source,
            &address,
            source_port,
            port,
            nonce,
        ) {
            Ok(segment) => segment,
            Err(e) => {
                *failures
                    .entry(format!("cannot build a probe: {e}"))
                    .or_insert(0) += 1;
                continue;
            }
        };
        match transport.tx.send(&segment, source, address) {
            Ok(()) => {
                // Recorded after a successful send, which is the point of
                // recording it: a probe the kernel refused is not a port that
                // stayed silent, and counting the two together makes a mostly
                // empty range look like a range of mostly silent hosts.
                sent.insert(
                    nonce,
                    Sent {
                        address,
                        port,
                        sample,
                    },
                );
                put_on_wire += 1;
            }
            Err(e) => *failures.entry(format!("{e}")).or_insert(0) += 1,
        }

        in_batch += 1;
        if in_batch >= batch {
            in_batch = 0;
            // Everything already queued, before sleeping. A reply is stamped
            // when it is *read*, so a send phase that reads nothing until it
            // finishes stamps every early reply with the moment the sweep
            // ended — and the first interval of every series is then far
            // shorter than what the target's clock actually lived through. The
            // first run of this instrument reported one host's clock as 1065 Hz
            // over a short sweep and 2336 Hz over a long one, which is the same
            // clock and two different amounts of this delay.
            file_queued(transport, sent, readings);
            tokio::time::sleep(interval).await;
        }
    }
    file_queued(transport, sent, readings);

    Swept {
        source_port,
        sent: put_on_wire,
        elapsed: began.elapsed(),
        failures,
    }
}

/// Prints what a sweep achieved, including the rate it actually managed.
///
/// A pacer quietly delivering a rate other than the one it was given has already
/// turned one arm of a sweep on this project into a duplicate of another.
fn report_sweep(sample: usize, swept: &Swept) {
    let seconds = swept.elapsed.as_secs_f64();
    let achieved = if seconds > 0.0 {
        swept.sent as f64 / seconds
    } else {
        f64::INFINITY
    };
    println!(
        "  sample {sample}: {} probe(s) from port {} in {seconds:.3}s ({achieved:.0}/s)",
        swept.sent, swept.source_port,
    );
    let refused: usize = swept.failures.values().sum();
    if refused > 0 {
        println!("    {refused} probe(s) the host would not send:");
        for (reason, count) in &swept.failures {
            println!("      {count:>6} x {reason}");
        }
    }
}

/// Files every reply already waiting, without blocking.
///
/// Called from inside the send loop as well as between samples, because the
/// arrival time is half of every reading here and the only record of it is the
/// moment this function reads the reply.
fn file_queued(transport: &mut ProbeTransport, sent: &SentMap, readings: &mut Readings) {
    while let Ok(reply) = transport.rx.try_recv() {
        file(reply, sent, readings);
    }
}

/// Reads replies until `until`, filing each against the probe whose nonce it
/// echoes.
async fn drain_until(
    transport: &mut ProbeTransport,
    until: Instant,
    sent: &SentMap,
    readings: &mut Readings,
) {
    while Instant::now() < until {
        let Ok(Some(reply)) = timeout(RECV_TICK, transport.rx.recv()).await else {
            continue;
        };
        file(reply, sent, readings);
    }
}

/// Files one reply against the probe whose nonce it echoes.
fn file(reply: CapturedSegment, sent: &SentMap, readings: &mut Readings) {
    {
        if reply.protocol != IpNextHeaderProtocols::Tcp {
            return;
        }
        let at = Instant::now();
        let Ok(segment) = tcp::parse(&reply.bytes) else {
            return;
        };
        // A reply is one of ours only if it echoes back a nonce we sent. Without
        // the check, every TCP segment reaching a filter this wide is read as an
        // answer, and a busy host produces a table of other people's connections.
        let nonce = tcp::echoed_nonce(TcpScanTechnique::Syn, &segment);
        let Some(&Sent {
            address,
            port,
            sample,
        }) = sent.get(&nonce)
        else {
            return;
        };
        let Some(observation) = reply.observation else {
            eprintln!("{}: no IP header was kept for this reply", reply.source);
            return;
        };
        if observation.is_fragment() {
            // A fragment's header describes the fragment. Its identifier belongs
            // to a datagram the path split, not to a counter policy.
            eprintln!("{}: reply arrived fragmented, skipping", reply.source);
            return;
        }
        let Some(observed) = StackObservation::from_tcp(observation, &reply.bytes) else {
            return;
        };

        let ip_id = match observation {
            IpObservation::V4(v4) => Some(v4.identification),
            IpObservation::V6(_) => None,
        };
        readings.entry((address, sample, port)).or_insert(Reading {
            at,
            flags: observed.flags,
            sequence: segment.get_sequence(),
            ip_id,
            tsval: observed.timestamps.map(|stamps| stamps.value),
            shape: StackShape::of(&observed),
            from: reply.source,
        });
    }
}

/// The ports one host will be followed on.
///
/// **Two of them, and the reason is a measurement.** The first run of this
/// instrument followed one port per host, preferring an open one, and reported
/// "identifiers zero throughout" for all five hosts that answered — no
/// discrimination whatsoever. The same run's cross-port block, reading the
/// *closed* ports of the same hosts in the same sweep, separated three of them
/// three ways: one counting up by one, one scattered, one zero.
///
/// The two answers live in different replies. A SYN+ACK is an atomic datagram
/// with don't-fragment set, and RFC 6864 §4.1 releases a sender from putting
/// anything meaningful in the identification field of one — several stacks
/// write zero. A reset from the same host is where the identifier policy is
/// visible. Meanwhile a reset carries no options and opens no connection, so the
/// sequence generator and the timestamp clock are only readable from the
/// SYN+ACK.
///
/// Following one port answers half the question and reports the other half as
/// "nothing here", which is not the same as measuring it.
struct Followed {
    address: IpAddr,
    /// A port that answered with a SYN+ACK: where the sequence generator and the
    /// peer's clock are readable.
    open: Option<u16>,
    /// A port that answered with a reset: where the identifier policy is.
    closed: Option<u16>,
}

impl Followed {
    /// The probes one sample sends for this host.
    fn targets(&self) -> impl Iterator<Item = (IpAddr, u16)> + '_ {
        self.open
            .into_iter()
            .chain(self.closed)
            .map(|port| (self.address, port))
    }
}

/// Picks the ports each host will be followed on, from what the first sweep
/// found.
///
/// The lowest port of each kind, so a re-run over one segment follows the same
/// ports and two runs are comparable.
fn choose_followed(readings: &Readings) -> Vec<Followed> {
    let mut best: BTreeMap<IpAddr, (Option<u16>, Option<u16>)> = BTreeMap::new();
    for ((address, sample, port), reading) in readings {
        if *sample != 0 {
            continue;
        }
        let entry = best.entry(*address).or_insert((None, None));
        let slot = if reading.flags & tcp::flags::SYN != 0 {
            &mut entry.0
        } else {
            &mut entry.1
        };
        if slot.is_none_or(|held| *port < held) {
            *slot = Some(*port);
        }
    }
    best.into_iter()
        .map(|(address, (open, closed))| Followed {
            address,
            open,
            closed,
        })
        .collect()
}

/// The readings for one host's series, in sample order.
///
/// **Sample 0 is not in it.** That sweep asks every port of every address, so on
/// anything wider than a handful of hosts it takes far longer than the spacing
/// between the samples that follow — and the gap between it and sample 1 is the
/// sweep's own length, not the interval this instrument was asked for. Including
/// it would put one enormous interval at the head of every series, which the
/// identifier reading would rightly refuse to classify and the clock reading
/// would divide by.
///
/// Sample 0 keeps its two jobs: it finds the ports, and its reply is the
/// first-reply shape the whole acceptance report is measured against.
fn series_of(readings: &Readings, address: IpAddr, port: u16, samples: usize) -> Vec<&Reading> {
    (1..=samples)
        .filter_map(|sample| readings.get(&(address, sample, port)))
        .collect()
}

/// How many hosts answered each sample.
///
/// Printed per sample rather than totalled because a decay down this column is a
/// host rate-limiting the instrument, and folding it into an average would report
/// a stack policy where what happened was a firewall.
fn print_reach(readings: &Readings, sent: &SentMap, samples: usize) {
    println!("per-sample reach (0 is the discovery sweep, not part of any series)");
    for sample in 0..=samples {
        let asked: BTreeSet<IpAddr> = sent
            .values()
            .filter(|probe| probe.sample == sample)
            .map(|probe| probe.address)
            .collect();
        let answered: BTreeSet<IpAddr> = readings
            .keys()
            .filter(|(_, seen, _)| *seen == sample)
            .map(|(address, _, _)| *address)
            .collect();
        println!(
            "  sample {sample}: {} of {} host(s) answered",
            answered.len(),
            asked.len(),
        );
    }
    println!("  A column that decays is rate limiting, not a stack policy.");
}

/// What the counters did, one host per block.
fn print_series(readings: &Readings, followed: &[Followed], samples: usize) {
    println!("\nwhat the counters did");
    for host in followed {
        println!("\n  {}", host.address);
        for (port, reply_kind) in [(host.open, "SYN+ACK"), (host.closed, "RST")] {
            let Some(port) = port else {
                continue;
            };
            let series = series_of(readings, host.address, port, samples);
            if series.is_empty() {
                println!("    :{port} {reply_kind:<7} nothing answered after the first sweep");
                continue;
            }

            let answered_by: BTreeSet<IpAddr> = series.iter().map(|reading| reading.from).collect();
            println!(
                "    :{port} {reply_kind:<7} {} of {samples} sample(s)",
                series.len(),
            );
            if answered_by.iter().any(|source| *source != host.address) {
                // Not folded away: something answering in a host's place uses
                // that host's address, so this is the rare case where it did not.
                println!("       answered by {answered_by:?}, not only by the address asked");
            }

            let identifiers = read_identifiers(&series);
            println!("       identifiers  {}", identifiers.line);
            if let Some(note) = identifiers.note {
                println!("                    {note}");
            }
            // Only the SYN+ACK series can answer these two, and it says so on
            // the reset line rather than leaving them out, so a reader can tell
            // "not asked" from "asked and got nothing".
            let sequences = read_sequences(&series, reply_kind);
            println!("       sequence     {}", sequences.line);
            let clock = read_clock(&series);
            println!("       timestamps   {}", clock.line);
            if let Some(note) = clock.note {
                println!("                    {note}");
            }
        }
    }
}

/// What a series of identifiers turned out to be.
///
/// A named class rather than a rendered string, because two things read it: the
/// table a person looks at, and the key two hosts are compared on. Deriving the
/// second by taking the first apart again would make the comparison depend on
/// the wording of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdClass {
    /// IPv6, which has no identification field to have a policy about.
    Absent,
    /// Fewer values than a policy can be read from.
    TooFew,
    /// Sampled too slowly for the question to have an answer. See
    /// [`MAX_INTERVAL_FOR_ID`].
    Unclear,
    Zero,
    Constant,
    Counting,
    Scattered,
}

impl IdClass {
    /// The name this class is compared under. Carries no rate: how *fast* a
    /// counter advances is a fact about what else the host was doing, not about
    /// the stack, and putting it in the key would report two identical machines
    /// as different because one was busier.
    const fn name(self) -> &'static str {
        match self {
            IdClass::Absent => "absent",
            IdClass::TooFew => "too few",
            IdClass::Unclear => "unclear",
            IdClass::Zero => "zero",
            IdClass::Constant => "constant",
            IdClass::Counting => "counting",
            IdClass::Scattered => "scattered",
        }
    }
}

/// A reading of one series, in the two forms the output needs.
struct Classified<T> {
    class: T,
    /// The raw values and the class, for a person. Always leads with the values,
    /// so a class this instrument declines to give — or gives wrongly — can be
    /// overruled by reading the numbers behind it.
    line: String,
    /// A caveat worth a line of its own, where there is one.
    note: Option<String>,
}

/// Reads the identifier series.
fn read_identifiers(series: &[&Reading]) -> Classified<IdClass> {
    // Paired with their arrival times rather than collected separately. The rate
    // each step implies is what decides the class, and pairing the values to the
    // intervals in one pass is what makes it impossible for the two to fall out
    // of step — a filter on one and a window on the other would misalign
    // silently the first time a reply arrived without one.
    let sampled: Vec<(Instant, u16)> = series
        .iter()
        .filter_map(|reading| reading.ip_id.map(|id| (reading.at, id)))
        .collect();

    let values: Vec<u16> = sampled.iter().map(|(_, id)| *id).collect();
    if values.is_empty() {
        return Classified {
            class: IdClass::Absent,
            line: "none — IPv6 has no identification field".to_string(),
            note: None,
        };
    }
    if values.len() < 3 {
        return Classified {
            class: IdClass::TooFew,
            line: format!("{values:?} — too few to read a policy from"),
            note: None,
        };
    }

    let raw = format!("{values:?}");
    let widest = sampled
        .windows(2)
        .map(|pair| pair[1].0.duration_since(pair[0].0))
        .max()
        .unwrap_or_default();
    if widest > MAX_INTERVAL_FOR_ID {
        return Classified {
            class: IdClass::Unclear,
            line: format!("{raw} — unclear"),
            note: Some(format!(
                "samples were up to {widest:?} apart; a counter can wrap a 16-bit \
                 field inside that and become indistinguishable from noise",
            )),
        };
    }

    if values.iter().all(|&value| value == 0) {
        return Classified {
            class: IdClass::Zero,
            line: format!("{raw} — zero throughout"),
            note: None,
        };
    }
    if values.windows(2).all(|pair| pair[0] == pair[1]) {
        return Classified {
            class: IdClass::Constant,
            line: format!("{raw} — constant"),
            note: None,
        };
    }

    // Wrapping, because a counter crossing 65535 is still a counter and a naive
    // subtraction turns one step into a jump of sixty-five thousand.
    //
    // Judged per interval, not over the whole span. A counter never jumps, so
    // one step implying an implausible rate is enough to say this is not one
    // being followed — where a total advance divided by a total span would let a
    // single large jump hide behind several small ones and report a tidy average
    // describing nothing that happened.
    let steps: Vec<u16> = sampled
        .windows(2)
        .map(|pair| pair[1].1.wrapping_sub(pair[0].1))
        .collect();
    let fastest = sampled
        .windows(2)
        .zip(&steps)
        .map(|(pair, &step)| {
            let seconds = pair[1].0.duration_since(pair[0].0).as_secs_f64();
            if seconds > 0.0 {
                f64::from(step) / seconds
            } else {
                f64::INFINITY
            }
        })
        .fold(0.0_f64, f64::max);

    if fastest < COUNTER_RATE_CEILING {
        Classified {
            class: IdClass::Counting,
            line: format!("{raw} — counting up, steps {steps:?}, at most {fastest:.0}/s"),
            note: None,
        }
    } else {
        Classified {
            class: IdClass::Scattered,
            line: format!("{raw} — scattered, steps {steps:?}"),
            note: Some(
                "consistent with a randomised identifier, and with a counter this \
                  instrument sampled too slowly to follow"
                    .to_string(),
            ),
        }
    }
}

/// What a series of initial sequence numbers turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IsnClass {
    /// A reset opens no connection, so there is no generator behind its
    /// sequence number to describe.
    NotRead,
    TooFew,
    Zero,
    /// The generator advances by a constant, which *is* a stack constant and so
    /// belongs in the comparison key.
    FixedStep(u32),
    /// Not a constant step, but every difference is a multiple of one.
    Multiples(u32),
    /// No common step: a hashed generator, per RFC 6528.
    Hashed,
}

impl IsnClass {
    fn name(&self) -> String {
        match self {
            IsnClass::NotRead => "not read".to_string(),
            IsnClass::TooFew => "too few".to_string(),
            IsnClass::Zero => "zero".to_string(),
            IsnClass::FixedStep(step) => format!("step {step}"),
            IsnClass::Multiples(step) => format!("multiples of {step}"),
            IsnClass::Hashed => "hashed".to_string(),
        }
    }
}

/// Reads the sequence-number series.
fn read_sequences(series: &[&Reading], reply_kind: &str) -> Classified<IsnClass> {
    let plain = |class: IsnClass, line: &str| Classified {
        class,
        line: line.to_string(),
        note: None,
    };

    if reply_kind != "SYN+ACK" {
        return plain(
            IsnClass::NotRead,
            "not read — a reset opens no connection to number",
        );
    }
    let values: Vec<u32> = series.iter().map(|reading| reading.sequence).collect();
    if values.iter().all(|&value| value == 0) {
        return plain(IsnClass::Zero, "zero throughout");
    }
    if values.len() < 3 {
        return Classified {
            class: IsnClass::TooFew,
            line: format!("{values:?} — too few to read a generator from"),
            note: None,
        };
    }

    let steps: Vec<u32> = values
        .windows(2)
        .map(|pair| pair[1].wrapping_sub(pair[0]))
        .collect();
    if steps.windows(2).all(|pair| pair[0] == pair[1]) {
        return Classified {
            class: IsnClass::FixedStep(steps[0]),
            line: format!("fixed step of {}", steps[0]),
            note: None,
        };
    }
    let divisor = steps.iter().copied().fold(0u32, gcd);
    if divisor >= MEANINGFUL_ISN_STEP {
        return Classified {
            class: IsnClass::Multiples(divisor),
            line: format!("stepping in multiples of {divisor}, steps {steps:?}"),
            note: None,
        };
    }
    Classified {
        class: IsnClass::Hashed,
        line: format!("no common step (divisor {divisor}) — consistent with a hashed generator"),
        note: None,
    }
}

/// What a series of timestamp values turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClockClass {
    /// The peer offered no timestamp option.
    None,
    /// It sent the option and left the value at zero, which is a stack policy
    /// rather than a clock.
    Zero,
    TooFew,
    /// The values move, but not as one clock read repeatedly does.
    ///
    /// **This is a finding, not a failure.** RFC 7323 §5.4 recommends a sender
    /// add a *per-connection* random offset to its timestamp clock, and every
    /// sample here is a separate connection, so on a stack that follows the
    /// recommendation the differences between samples are differences between
    /// random offsets. Whether a stack does this is itself a discriminator, and
    /// it is readable from exactly the probes already being sent — but it means
    /// the clock's *rate* cannot be recovered from separate connections at all.
    /// Recovering that needs two timestamps from **one** connection, which needs
    /// a completed handshake, which is a much more intrusive probe than this.
    Randomised,
    /// The clock ticks more slowly than this instrument samples: the values are
    /// nonzero and never changed. A real reading, and one that needs a longer
    /// run to put a number on.
    Slower,
    /// The clock's frequency, rounded to the nearest ten hertz.
    ///
    /// Rounded because the raw figure carries this instrument's own timing
    /// jitter: two readings a few milliseconds off across a half-second span
    /// move the answer by well under one percent, and a key built on the exact
    /// number would report one machine as two. Ten hertz is coarse enough to
    /// absorb that and fine enough to keep the frequencies stacks actually use
    /// apart.
    Hertz(u32),
}

impl ClockClass {
    fn name(self) -> String {
        match self {
            ClockClass::None => "none".to_string(),
            ClockClass::Zero => "zero".to_string(),
            ClockClass::TooFew => "too few".to_string(),
            ClockClass::Randomised => "randomised per connection".to_string(),
            ClockClass::Slower => "slower than sampled".to_string(),
            ClockClass::Hertz(hz) => format!("{hz} Hz"),
        }
    }
}

/// Reads the peer's clock, where it sent one.
///
/// Every interval is checked, not just the span from first to last. A stack that
/// randomises its offset per connection can produce a first-to-last difference
/// that looks perfectly reasonable by chance while every step in between is
/// nonsense, and reading only the endpoints would report a confident frequency
/// for a host that has no comparable clock at all.
fn read_clock(series: &[&Reading]) -> Classified<ClockClass> {
    let plain = |class: ClockClass, line: &str| Classified {
        class,
        line: line.to_string(),
        note: None,
    };

    // Paired with their arrival times in one pass, for the reason
    // `read_identifiers` gives: the interval is half the measurement, and a
    // value separated from the moment it arrived can be matched to the wrong
    // one.
    let stamped: Vec<(Instant, u32)> = series
        .iter()
        .filter_map(|reading| reading.tsval.map(|value| (reading.at, value)))
        .collect();

    if stamped.is_empty() {
        return plain(ClockClass::None, "none offered");
    }
    if stamped.iter().all(|(_, value)| *value == 0) {
        return plain(ClockClass::Zero, "sent, but always zero");
    }
    if stamped.len() < 2 {
        return Classified {
            class: ClockClass::TooFew,
            line: format!("one value ({}), which is not a rate", stamped[0].1),
            note: None,
        };
    }

    // Wrapping: a clock crossing the end of a 32-bit counter is still running,
    // and a subtraction that does not wrap turns a thousand hertz into a
    // ten-digit number. A value that went *backwards* wraps to an enormous
    // positive one, which the ceiling below is what catches.
    let steps: Vec<u32> = stamped
        .windows(2)
        .map(|pair| pair[1].1.wrapping_sub(pair[0].1))
        .collect();
    let rates: Vec<f64> = stamped
        .windows(2)
        .zip(&steps)
        .map(|(pair, &step)| {
            let seconds = pair[1].0.duration_since(pair[0].0).as_secs_f64();
            if seconds > 0.0 {
                f64::from(step) / seconds
            } else {
                f64::INFINITY
            }
        })
        .collect();

    if steps.iter().all(|&step| step == 0) {
        return plain(
            ClockClass::Slower,
            "sent, nonzero, and unchanged across every sample",
        );
    }

    let fastest = rates.iter().copied().fold(0.0_f64, f64::max);
    let slowest = rates.iter().copied().fold(f64::INFINITY, f64::min);
    // Two ways to fail to be one clock: a rate no timestamp clock runs at — RFC
    // 7323 §4 asks for a tick between 1 ms and 1 s, so 1 to 1000 Hz, and the
    // ceiling here leaves an order of magnitude of margin — or intervals that
    // disagree with each other, which one clock read repeatedly does not do.
    let implausible = fastest > CLOCK_CEILING;
    let inconsistent = slowest <= 0.0 || fastest / slowest > CLOCK_SPREAD;
    if implausible || inconsistent {
        return Classified {
            class: ClockClass::Randomised,
            line: format!("no single rate — steps {steps:?}"),
            note: Some(
                "each sample is its own connection, and RFC 7323 §5.4 recommends a \
                 per-connection random offset; a stack that follows it has no clock \
                 rate recoverable from separate connections"
                    .to_string(),
            ),
        };
    }

    let span = stamped[stamped.len() - 1]
        .0
        .duration_since(stamped[0].0)
        .as_secs_f64();
    let ticks: f64 = steps.iter().map(|&step| f64::from(step)).sum();
    let hertz = ticks / span;
    Classified {
        class: ClockClass::Hertz(((hertz / 10.0).round() * 10.0) as u32),
        line: format!(
            "about {hertz:.0} Hz over {span:.3}s ({} tick(s))",
            ticks as u64
        ),
        note: None,
    }
}

/// Whether one host's identifier counter is shared across connections.
///
/// Read from the *first* sweep alone, where several ports of one host were asked
/// within a few milliseconds. Identifiers that step across those near-simultaneous
/// replies come from one counter the whole host shares; identifiers that repeat
/// or sit at zero across them do not. This is the reading that separates a global
/// counter from a per-connection one, and it is free — the packets were sent to
/// find the ports.
fn print_identifiers_across_ports(readings: &Readings) {
    let mut by_host: BTreeMap<IpAddr, Vec<(u16, char, u16)>> = BTreeMap::new();
    for ((address, sample, port), reading) in readings {
        if *sample != 0 {
            continue;
        }
        if let Some(id) = reading.ip_id {
            // The reply kind travels with the value. The first run of this
            // instrument printed identifiers without it and produced a pattern
            // nobody could read: on one host three ports carried a counter and
            // three carried zero, which looks like an inconsistent stack and is
            // actually the difference between its resets and its SYN+ACKs.
            let kind = if reading.flags & tcp::flags::SYN != 0 {
                'S'
            } else {
                'R'
            };
            by_host.entry(*address).or_default().push((*port, kind, id));
        }
    }
    by_host.retain(|_, seen| seen.len() > 1);
    if by_host.is_empty() {
        return;
    }

    println!("\nidentifiers across ports answered in one sweep (S = SYN+ACK, R = reset)");
    for (address, mut seen) in by_host {
        seen.sort_unstable();
        let rendered: Vec<String> = seen
            .iter()
            .map(|(port, kind, id)| format!("{port}{kind}={id}"))
            .collect();
        println!("  {address}: {}", rendered.join(" "));
        // Split by reply kind before judging, because they are two code paths.
        // A host writing zero into its SYN+ACKs and a counter into its resets is
        // one consistent stack, and one verdict over both would call it neither.
        for (kind, name) in [('S', "SYN+ACK"), ('R', "reset")] {
            let values: Vec<u16> = seen
                .iter()
                .filter(|(_, seen_kind, _)| *seen_kind == kind)
                .map(|(_, _, id)| *id)
                .collect();
            if values.len() < 2 {
                continue;
            }
            let verdict = if values.iter().all(|&value| value == 0) {
                "zero on every connection"
            } else if values.windows(2).all(|pair| pair[0] == pair[1]) {
                "one value across connections"
            } else if values
                .windows(2)
                .all(|pair| pair[1].wrapping_sub(pair[0]) < ACROSS_PORT_STEP)
            {
                "stepping — one counter the whole host shares"
            } else {
                "different and unrelated per connection"
            };
            println!("      {name}s: {verdict}");
        }
    }
    println!("  These replies left within milliseconds of each other, so a counter that");
    println!("  steps across them is shared by the whole host rather than kept per socket.");
}

/// The acceptance test: did the extra samples separate anything the first reply
/// could not?
fn print_refinement(readings: &Readings, followed: &[Followed], samples: usize) {
    println!("\nwhat the extra samples bought");

    let mut groups: BTreeMap<StackShape, Vec<(IpAddr, String)>> = BTreeMap::new();
    for host in followed {
        // The shape of the *first* reply, which is everything phases 1-5 see.
        // Taken from the open port where there was one, since that is the reply
        // the passive path reads: a reset carries no options and would group
        // every silent-but-answering host together whatever stack it ran.
        let first = host
            .open
            .or(host.closed)
            .and_then(|port| readings.get(&(host.address, 0, port)));
        let Some(first) = first else {
            continue;
        };
        groups
            .entry(first.shape.clone())
            .or_default()
            .push((host.address, series_signature(readings, host, samples)));
    }

    let mut split = 0usize;
    let mut comparable = 0usize;
    for (shape, members) in &groups {
        if members.len() < 2 {
            continue;
        }
        comparable += 1;
        let distinct: BTreeSet<&String> = members.iter().map(|(_, key)| key).collect();
        if distinct.len() < 2 {
            continue;
        }
        split += 1;
        println!(
            "\n  one first-reply shape, {} hosts, {} distinct series:",
            members.len(),
            distinct.len(),
        );
        println!(
            "    layout={} window={} df={} mss={:?} ws={:?} ts={}",
            if shape.layout.is_empty() {
                "-"
            } else {
                &shape.layout
            },
            shape.window,
            shape.dont_fragment,
            shape.mss,
            shape.window_scale,
            shape.timestamps,
        );
        for (address, key) in members {
            println!("      {address}  {key}");
        }
    }

    if comparable == 0 {
        println!(
            "  every host had a first reply unlike every other host's, so there was \
             nothing for the extra samples to separate. Run this where at least two \
             hosts look alike passively."
        );
        return;
    }
    println!(
        "\n  {split} of {comparable} group(s) of passively-identical hosts were split \
         by the series."
    );
    if split == 0 {
        println!(
            "  On this segment the extra samples changed nothing a verdict could read. \
             That is the result, and it is an argument against sending them."
        );
    } else {
        println!(
            "  A split is necessary, not sufficient. Label these hosts from outside and \
             check the splits fall between operating systems rather than inside one: \
             uptime and load move these counters too."
        );
    }
}

/// The series reduced to one comparable key.
///
/// Deliberately coarse — classes, not the raw values. Two hosts running one
/// stack will not produce identical numbers, and comparing the numbers would
/// report every pair as different, which is the instrument agreeing with itself
/// rather than a measurement.
///
/// Both ports appear. The identifier policy is read from each separately because
/// a stack can and does write zero into its SYN+ACKs while keeping a counter for
/// its resets, and folding those together would report a policy neither path
/// follows.
fn series_signature(readings: &Readings, host: &Followed, samples: usize) -> String {
    let open = host
        .open
        .map(|port| series_of(readings, host.address, port, samples));
    let closed = host
        .closed
        .map(|port| series_of(readings, host.address, port, samples));
    signature_of(open.as_deref(), closed.as_deref())
}

/// The key itself, over the two series rather than over the map they came from.
///
/// Separated so it can be checked against series whose answer is known, without
/// a capture, a network or a host to have taken them from.
fn signature_of(open: Option<&[&Reading]>, closed: Option<&[&Reading]>) -> String {
    let id_of = |series: Option<&[&Reading]>| {
        series.map_or("-".to_string(), |series| {
            read_identifiers(series).class.name().to_string()
        })
    };
    let (sequence, clock) = open.map_or(("-".to_string(), "-".to_string()), |series| {
        (
            read_sequences(series, "SYN+ACK").class.name(),
            read_clock(series).class.name(),
        )
    });

    format!(
        "id/syn[{}] id/rst[{}] isn[{sequence}] clock[{clock}]",
        id_of(open),
        id_of(closed),
    )
}

/// What this instrument could not reach, said plainly.
fn print_scope(asked: &usize, readings: &Readings) {
    let answered: BTreeSet<IpAddr> = readings.keys().map(|(address, _, _)| *address).collect();
    println!("\nscope");
    println!(
        "  {} of {asked} address(es) answered anything at all.",
        answered.len(),
    );
    println!("  A host that answers no probe is untouched by this: every reading here");
    println!("  starts from a reply. Naming a silent host needs something it emits on");
    println!("  its own, which is a different phase.");
}

/// Runs the readings this instrument makes past series whose answer is already
/// known, and says whether it got them right.
///
/// Needs no root and touches no network. It exists because the classifiers below
/// are the whole instrument: a measurement taken with a mis-reading of a counter
/// would come back confident, self-consistent and wrong, which is the failure
/// this project keeps a list about. The cases that matter are the ones designed
/// to come back *negative* — a series of random identifiers that must not read
/// as a counter, and a real counter sampled too slowly, which must be refused
/// rather than guessed at.
///
/// Returns whether every case passed.
fn self_check() -> bool {
    let base = Instant::now();
    let mut failures = 0usize;

    let mut check = |name: &str, produced: &str, expected: &str| {
        let ok = produced.contains(expected);
        failures += usize::from(!ok);
        println!(
            "  {} {name}\n      expected to contain: {expected}\n      got: {produced}",
            if ok { "pass" } else { "FAIL" },
        );
    };

    // Identifiers, sampled 100 ms apart, which is inside the interval a series
    // may be classified over.
    let spaced = |count: usize| -> Vec<Duration> {
        (0..count)
            .map(|step| Duration::from_millis(100 * step as u64))
            .collect()
    };

    let zeros = series_from(base, &spaced(6), &[0, 0, 0, 0, 0, 0], &[], &[]);
    check(
        "identifiers all zero",
        &read_identifiers(&borrowed(&zeros)).line,
        "zero throughout",
    );

    let constant = series_from(base, &spaced(6), &[4242; 6], &[], &[]);
    check(
        "identifiers constant",
        &read_identifiers(&borrowed(&constant)).line,
        "constant",
    );

    let counting = series_from(base, &spaced(6), &[100, 101, 102, 103, 104, 105], &[], &[]);
    check(
        "identifiers counting by one",
        &read_identifiers(&borrowed(&counting)).line,
        "counting up",
    );

    // The wrap. A counter crossing 65535 is still a counter, and a subtraction
    // that does not wrap turns one step into a jump of sixty-five thousand and
    // files a well-behaved host under "scattered".
    let wrapping = series_from(base, &spaced(6), &[65533, 65534, 65535, 0, 1, 2], &[], &[]);
    check(
        "identifiers counting across the wrap",
        &read_identifiers(&borrowed(&wrapping)).line,
        "counting up",
    );

    // Must not read as a counter. Every step here implies a rate no host sends
    // at, which is the only thing separating sixteen bits of noise from a
    // counter followed too slowly.
    let scattered = series_from(
        base,
        &spaced(6),
        &[41_112, 3_907, 58_220, 12_004, 49_881, 22_336],
        &[],
        &[],
    );
    check(
        "identifiers randomised",
        &read_identifiers(&borrowed(&scattered)).line,
        "scattered",
    );

    // A genuine counter, sampled two seconds apart. The values are the same
    // well-behaved sequence as above, and the answer must still be a refusal:
    // at this spacing a counter can wrap between samples, so these six numbers
    // no longer distinguish one from noise. Getting a *right-looking* answer
    // here would be the instrument agreeing with the theory rather than
    // measuring it.
    let too_slow = series_from(
        base,
        &[
            Duration::ZERO,
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(6),
            Duration::from_secs(8),
            Duration::from_secs(10),
        ],
        &[100, 101, 102, 103, 104, 105],
        &[],
        &[],
    );
    check(
        "a counter sampled too slowly is refused",
        &read_identifiers(&borrowed(&too_slow)).line,
        "unclear",
    );

    // Sequence numbers.
    let stepping = series_from(
        base,
        &spaced(4),
        &[],
        &[1_000_000, 1_064_000, 1_128_000, 1_192_000],
        &[],
    );
    check(
        "sequence numbers stepping by a constant",
        &read_sequences(&borrowed(&stepping), "SYN+ACK").line,
        "fixed step of 64000",
    );

    let hashed = series_from(
        base,
        &spaced(4),
        &[],
        &[2_147_483_647, 91_827_361, 3_918_273_645, 771_293_811],
        &[],
    );
    check(
        "sequence numbers from a hashed generator",
        &read_sequences(&borrowed(&hashed), "SYN+ACK").line,
        "no common step",
    );

    let zero_isn = series_from(base, &spaced(4), &[], &[0, 0, 0, 0], &[]);
    check(
        "sequence numbers all zero",
        &read_sequences(&borrowed(&zero_isn), "SYN+ACK").line,
        "zero throughout",
    );

    check(
        "a reset's sequence number is not read as a generator",
        &read_sequences(&borrowed(&stepping), "RST").line,
        "not read",
    );

    // Clocks. A thousand ticks across half a second is a thousand hertz.
    let clock = series_from(
        base,
        &spaced(6),
        &[],
        &[],
        &[500_000, 500_100, 500_200, 500_300, 500_400, 500_500],
    );
    check(
        "a 1000 Hz timestamp clock",
        &read_clock(&borrowed(&clock)).line,
        "about 1000 Hz",
    );

    // The same clock, crossing the end of a 32-bit counter. Wrapping or not is
    // the difference between 1000 Hz and a number with ten digits.
    let wrapping_clock = series_from(
        base,
        &spaced(6),
        &[],
        &[],
        &[u32::MAX - 200, u32::MAX - 100, u32::MAX, 99, 199, 299],
    );
    check(
        "a timestamp clock crossing its wrap",
        &read_clock(&borrowed(&wrapping_clock)).line,
        "about 1000 Hz",
    );

    // A stack that adds a random offset per connection. Every sample here is a
    // separate connection, so this is what RFC 7323 §5.4 looks like from the
    // outside — and the first run against real hardware produced exactly this
    // and had it reported as a clock running at 1.9 GHz.
    let randomised = series_from(
        base,
        &spaced(6),
        &[],
        &[],
        &[
            1_913_402_881,
            88_120_004,
            3_774_119_855,
            412_998_002,
            2_660_001_913,
            955_218_744,
        ],
    );
    check(
        "a per-connection random offset is not a clock",
        &read_clock(&borrowed(&randomised)).class.name(),
        "randomised per connection",
    );

    // The case that decides whether checking every interval was worth it. The
    // first and last values here are five hundred ticks apart across half a
    // second, so an endpoint-only reading reports a tidy 1000 Hz — while every
    // step in between is nonsense. A confident wrong answer is the failure mode
    // this whole instrument is arranged against.
    let plausible_endpoints = series_from(
        base,
        &spaced(6),
        &[],
        &[],
        &[500_000, 900_000, 100_000, 700_000, 200_000, 500_500],
    );
    check(
        "endpoints that agree do not make the middle a clock",
        &read_clock(&borrowed(&plausible_endpoints)).class.name(),
        "randomised per connection",
    );

    // A clock ticking more slowly than this instrument samples. Not a failure
    // and not zero: a real reading that needs a longer run to put a number on.
    let slow = series_from(base, &spaced(6), &[], &[], &[77_777; 6]);
    check(
        "a clock slower than the sampling says so",
        &read_clock(&borrowed(&slow)).class.name(),
        "slower than sampled",
    );

    // The comparison key. Everything above is read by a person, who can weigh a
    // rate against a class; this is read by the block that decides whether the
    // extra samples bought anything, and it has to be *coarse in the right
    // places*. Two machines running one stack never produce identical numbers —
    // a key that kept them would report every pair as different, which is the
    // instrument agreeing with itself rather than measuring.
    let slow_counter = series_from(base, &spaced(6), &[10, 11, 12, 13, 14, 15], &[], &[]);
    let fast_counter = series_from(
        base,
        &spaced(6),
        &[900, 950, 1000, 1050, 1100, 1150],
        &[],
        &[],
    );
    check(
        "two counters at different rates share one key",
        &format!(
            "{} vs {}",
            signature_of(Some(&borrowed(&slow_counter)), None),
            signature_of(Some(&borrowed(&fast_counter)), None),
        ),
        &format!(
            "{} vs {}",
            signature_of(Some(&borrowed(&slow_counter)), None),
            signature_of(Some(&borrowed(&slow_counter)), None),
        ),
    );
    check(
        "a counter and a scattered series do not",
        &(signature_of(Some(&borrowed(&slow_counter)), None)
            != signature_of(Some(&borrowed(&scattered)), None))
        .to_string(),
        "true",
    );

    // A clock read twice with this instrument's own timing jitter is one clock.
    let clock_jittered = series_from(
        base,
        &[Duration::ZERO, Duration::from_millis(502)],
        &[],
        &[],
        &[500_000, 500_500],
    );
    let clock_exact = series_from(
        base,
        &[Duration::ZERO, Duration::from_millis(500)],
        &[],
        &[],
        &[700_000, 700_500],
    );
    check(
        "one clock measured with jitter reads as one clock",
        &format!(
            "{} vs {}",
            read_clock(&borrowed(&clock_jittered)).class.name(),
            read_clock(&borrowed(&clock_exact)).class.name(),
        ),
        "1000 Hz vs 1000 Hz",
    );
    let clock_slow = series_from(
        base,
        &[Duration::ZERO, Duration::from_millis(500)],
        &[],
        &[],
        &[900_000, 900_050],
    );
    check(
        "a 100 Hz clock and a 1000 Hz clock are two clocks",
        &(read_clock(&borrowed(&clock_slow)).class != read_clock(&borrowed(&clock_exact)).class)
            .to_string(),
        "true",
    );

    println!();
    if failures == 0 {
        println!("all checks passed.");
    } else {
        println!("{failures} check(s) failed. The instrument is not trustworthy until they do.");
    }
    failures == 0
}

/// Builds a synthetic series for [`self_check`].
///
/// Absent slices mean the field was not present in those replies, which is a
/// different thing from a zero: a stack that offers no timestamp and one whose
/// clock reads zero are two findings.
fn series_from(
    base: Instant,
    offsets: &[Duration],
    identifiers: &[u16],
    sequences: &[u32],
    stamps: &[u32],
) -> Vec<Reading> {
    offsets
        .iter()
        .enumerate()
        .map(|(index, offset)| Reading {
            at: base + *offset,
            flags: tcp::flags::SYN | tcp::flags::ACK,
            sequence: sequences.get(index).copied().unwrap_or(0),
            ip_id: identifiers.get(index).copied(),
            tsval: stamps.get(index).copied(),
            shape: StackShape {
                layout: "M,S,T,N,W".to_string(),
                window: 65535,
                dont_fragment: true,
                mss: Some(1460),
                window_scale: Some(7),
                timestamps: !stamps.is_empty(),
            },
            from: IpAddr::from([192, 0, 2, 1]),
        })
        .collect()
}

/// The readings as the classifiers take them.
fn borrowed(series: &[Reading]) -> Vec<&Reading> {
    series.iter().collect()
}

/// Greatest common divisor, for finding a fixed step in a set of differences.
fn gcd(a: u32, b: u32) -> u32 {
    let (mut a, mut b) = (a, b);
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}
