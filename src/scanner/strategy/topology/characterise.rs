// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Characterising the filter in front of a host
//!
//! A diagnostic pass, run after the ports are known and only against hosts that
//! answered. It sends a few specially shaped probes to a host's ports and reads
//! what the filter in front of it let through, as [`Filtering`] conclusions:
//!
//! - **An inline middlebox**: a reply to a bad-checksum probe to an *open* port.
//!   A conformant host drops the corrupt segment unread, so something inline
//!   answered without validating.
//! - **A stateful filter**: an ACK probe draws a reset from a *silent or
//!   blocked* port the scan's plain SYN did not reach.
//! - **A port-trusting ACL**: a SYN from a trusted source port reaches a
//!   *silent or blocked* port an ordinary SYN did not.
//! - **A stateless filter**: a *fragmented* SYN reaches a *silent or blocked*
//!   port a whole one did not, so the filter judged only the first fragment
//!   (ports, no flags). A raw socket cannot place this probe, so it goes over
//!   the self-built Ethernet path; a host that path cannot route to gets no
//!   conclusion.
//!
//! The comparative three read the plain SYN's fate off the recorded port state,
//! so only the alternative shape is sent. Every conclusion is positive: silence
//! records nothing. Replies are matched by the nonce they echo, so a filter that
//! answers without acknowledging the probe is missed.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::logging::error;
use crate::model::host::Filtering;
use crate::model::technique::TcpScanTechnique;
use crate::protocols::tcp;
use crate::report::ScannerKind;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::raw::neighbors::{NeighborGates, resolve_ahead, send_when_admitted};
use crate::system::interface::SourceResolver;
use crate::transport::link::EthernetSender;
use crate::transport::probe::{
    Emission, NeighborWatch, ProbeKind, ProbeSender, ProbeTransport, SendMode,
};
use crate::{counted, info};

/// How long to listen for replies once the last diagnostic probe has left: the
/// tail for a slow path. Each probe is sent once.
const REPLY_WINDOW: Duration = Duration::from_secs(2);

/// The source port a port-trusting ACL is most likely to hold a door open for:
/// a rule that lets "returning DNS" back in lets anything from port 53 in.
const TRUSTED_SOURCE_PORT: u16 = 53;

/// The largest each fragment of the stateless-filter probe may be, in bytes.
///
/// Twenty-eight is an IP header (20) plus one eight-byte fragment, the smallest
/// a conformant path carries. It puts the ports in the first fragment and the
/// flags in a later one.
const STATELESS_FRAGMENT_MTU: u16 = 28;

/// One host and the ports the pass aims its diagnostic probes at.
pub(crate) struct Subject {
    /// The host to characterise.
    pub(crate) host: IpAddr,
    /// An open TCP port, for the bad-checksum middlebox probe. `None` skips it.
    pub(crate) open_port: Option<u16>,
    /// A TCP port the scan's plain SYN did not reach (`NoReply` or `Blocked`),
    /// for the comparative probes. `None` skips them.
    pub(crate) unreached_port: Option<u16>,
}

/// The probes still outstanding: each nonce names the host its probe went to
/// and the conclusion a reply echoing it would prove.
type Awaiting = HashMap<u32, (IpAddr, Filtering)>;

/// Sends each host's diagnostic probes and records what the filter in front of
/// it demonstrably did.
pub(crate) async fn characterise(ctx: &ScanContext, subjects: Vec<Subject>) {
    if subjects.is_empty() {
        return;
    }

    let mut transport = match ProbeTransport::open_capturing(
        ProbeKind::TcpSyn,
        SendMode::Auto,
        &ctx.capture_links(),
    ) {
        Ok(transport) => transport,
        Err(error) => {
            ctx.record_failure(
                ScannerKind::Routed,
                format!("no transport to characterise a filter with: {error}"),
            );
            return;
        }
    };

    // For the fragmented stateless probe, which a raw socket cannot place.
    // `None` without an Ethernet path, and a send is refused for any host that
    // path cannot route to; either way only the stateless conclusion is lost.
    let ethernet = EthernetSender::from_system(ProbeKind::TcpSyn.ip_protocols());
    let fragmenting = ethernet.as_ref().map(|sender| Fragmenting {
        sender,
        neighbors: NeighborWatch::Frames(sender.neighbors()),
    });

    info!(
        "characterising the filter in front of {}",
        counted(subjects.len() as u128, "host", "hosts")
    );

    run(
        ctx,
        &mut transport,
        fragmenting.as_ref(),
        &mut SourceResolver::from_system(),
        subjects,
    )
    .await;
}

/// The frame sender the fragmented stateless probe leaves on, and where its
/// neighbour resolutions stand.
struct Fragmenting<'a> {
    sender: &'a dyn ProbeSender,
    neighbors: NeighborWatch,
}

/// Sends every subject its probes, once the neighbour each is framed to has
/// been asked for, and folds in what the replies prove.
///
/// Every neighbour is resolved at once before the first probe, on the
/// transport and then on the fragmenting sender, which resolves its own, so
/// the pass does not wait out one resolution per host in turn. A host whose
/// neighbour never answered is sent nothing on that sender.
///
/// The transport's probes are then admitted one by one, since through the
/// kernel nothing is asked before a probe is written. See
/// [`send_when_admitted`].
async fn run(
    ctx: &ScanContext,
    transport: &mut ProbeTransport,
    fragmenting: Option<&Fragmenting<'_>>,
    resolver: &mut SourceResolver,
    subjects: Vec<Subject>,
) {
    let hosts = subjects.iter().map(|subject| subject.host);
    let (mut gates, unreached) = resolve_ahead(ctx, transport.neighbors(), resolver, hosts).await;
    let mut subjects: Vec<Subject> = subjects
        .into_iter()
        .filter(|subject| !unreached.contains_key(&subject.host))
        .collect();

    let unframed = match fragmenting {
        Some(fragmenting) => {
            let comparative = subjects
                .iter()
                .filter(|subject| subject.unreached_port.is_some())
                .map(|subject| subject.host);
            resolve_ahead(ctx, Some(&fragmenting.neighbors), resolver, comparative)
                .await
                .1
        }
        None => BTreeMap::new(),
    };

    let mut awaiting = Awaiting::new();
    let planned = plan_diagnostics(&subjects, resolver);
    let sender = transport.tx.as_ref();
    let unadmitted = send_when_admitted(
        &mut gates,
        ctx,
        transport.neighbors(),
        resolver,
        planned,
        |host, diagnostic| diagnostic.send(sender, &mut awaiting, host),
    )
    .await;
    subjects.retain(|subject| !unadmitted.contains_key(&subject.host));
    for (host, why) in unreached.iter().chain(&unadmitted) {
        info!(
            verbosity = 2,
            "{host} not characterised: unreachable ({why})"
        );
    }

    if let Some(fragmenting) = fragmenting
        && !ctx.handle.should_stop()
    {
        send_fragmented(
            ctx,
            &subjects,
            fragmenting.sender,
            &unframed,
            resolver,
            &mut awaiting,
        )
        .await;
    }
    // Timed from the last send, so pacing gaps do not eat the reply window.
    collect_replies(ctx, transport, &awaiting).await;
}

/// One diagnostic probe the transport sends, from the source it leaves by.
#[derive(Debug, Clone, Copy)]
struct Diagnostic {
    source: IpAddr,
    port: u16,
    conclusion: Filtering,
}

impl Diagnostic {
    /// Sends this probe to `host` and files what a reply to it would prove,
    /// saying whether it reached the wire.
    fn send(self, sender: &dyn ProbeSender, awaiting: &mut Awaiting, host: IpAddr) -> bool {
        let Self {
            source,
            port,
            conclusion,
        } = self;
        match conclusion {
            Filtering::InlineMiddlebox => {
                probe_inline_middlebox(sender, awaiting, source, host, port)
            }
            Filtering::StatefulFilter => {
                probe_stateful_filter(sender, awaiting, source, host, port)
            }
            Filtering::PortTrustingAcl => {
                probe_port_trusting_acl(sender, awaiting, source, host, port)
            }
            // Sent on the fragmenting sender; see `send_fragmented`.
            _ => false,
        }
    }
}

/// The probes every subject's ports allow on the transport, in the order they
/// are sent: the middlebox probe to an open port, and the two comparative
/// probes to one a plain SYN did not reach.
///
/// A host with no source address to send from is skipped.
fn plan_diagnostics(
    subjects: &[Subject],
    resolver: &mut SourceResolver,
) -> Vec<(IpAddr, Diagnostic)> {
    let mut planned = Vec::new();
    for subject in subjects {
        let Some(source) = resolver.resolve(subject.host) else {
            continue;
        };
        let diagnostic = |port, conclusion| {
            (
                subject.host,
                Diagnostic {
                    source,
                    port,
                    conclusion,
                },
            )
        };
        if let Some(port) = subject.open_port {
            planned.push(diagnostic(port, Filtering::InlineMiddlebox));
        }
        if let Some(port) = subject.unreached_port {
            planned.push(diagnostic(port, Filtering::StatefulFilter));
            planned.push(diagnostic(port, Filtering::PortTrustingAcl));
        }
    }
    planned
}

/// Sends the fragmented stateless-filter probe, on the frame sender, to every
/// subject with a port a plain SYN did not reach, except the `unframed` hosts
/// whose neighbour did not answer.
///
/// Paced by the scan's probe gaps. Neighbours were resolved ahead.
async fn send_fragmented(
    ctx: &ScanContext,
    subjects: &[Subject],
    sender: &dyn ProbeSender,
    unframed: &BTreeMap<IpAddr, String>,
    resolver: &mut SourceResolver,
    awaiting: &mut Awaiting,
) {
    let mut planned = Vec::new();
    for subject in subjects {
        let Some(port) = subject.unreached_port else {
            continue;
        };
        if unframed.contains_key(&subject.host) {
            continue;
        }
        let Some(source) = resolver.resolve(subject.host) else {
            continue;
        };
        planned.push((subject.host, (source, port)));
    }
    send_when_admitted(
        &mut NeighborGates::default(),
        ctx,
        None,
        resolver,
        planned,
        |host, (source, port)| probe_stateless_filter(sender, awaiting, source, host, port),
    )
    .await;
}

/// Sends a SYN with a deliberately bad checksum to an open port. A conformant
/// host drops the corrupt segment unread, so a reply was sent by something
/// inline that answered without validating.
fn probe_inline_middlebox(
    sender: &dyn ProbeSender,
    awaiting: &mut Awaiting,
    source: IpAddr,
    host: IpAddr,
    port: u16,
) -> bool {
    let nonce: u32 = rand::random();
    let src_port: u16 = rand::random_range(50_000..u16::MAX);
    send_diagnostic(
        sender,
        awaiting,
        source,
        host,
        nonce,
        tcp::build_probe_shaped(
            TcpScanTechnique::Syn,
            source,
            host,
            src_port,
            port,
            nonce,
            None,
            true,
        ),
        Emission::routed(),
        Filtering::InlineMiddlebox,
    )
}

/// Sends an ACK to a port the scan's plain SYN did not reach. A reset back
/// means a filter judges a segment by its place in a connection.
fn probe_stateful_filter(
    sender: &dyn ProbeSender,
    awaiting: &mut Awaiting,
    source: IpAddr,
    host: IpAddr,
    port: u16,
) -> bool {
    let nonce: u32 = rand::random();
    let src_port: u16 = rand::random_range(50_000..u16::MAX);
    send_diagnostic(
        sender,
        awaiting,
        source,
        host,
        nonce,
        tcp::build_probe(TcpScanTechnique::Ack, source, host, src_port, port, nonce),
        Emission::routed(),
        Filtering::StatefulFilter,
    )
}

/// Sends a SYN from the trusted source port to a port an ordinary SYN did not
/// reach. A reply means a rule admits segments by their source port.
fn probe_port_trusting_acl(
    sender: &dyn ProbeSender,
    awaiting: &mut Awaiting,
    source: IpAddr,
    host: IpAddr,
    port: u16,
) -> bool {
    let nonce: u32 = rand::random();
    send_diagnostic(
        sender,
        awaiting,
        source,
        host,
        nonce,
        tcp::build_probe(
            TcpScanTechnique::Syn,
            source,
            host,
            TRUSTED_SOURCE_PORT,
            port,
            nonce,
        ),
        Emission::routed(),
        Filtering::PortTrustingAcl,
    )
}

/// Sends a SYN fragmented small enough that its flags fall past the first
/// fragment. A reply means a filter judged the first fragment alone. Goes over
/// the self-built Ethernet path.
fn probe_stateless_filter(
    sender: &dyn ProbeSender,
    awaiting: &mut Awaiting,
    source: IpAddr,
    host: IpAddr,
    port: u16,
) -> bool {
    let nonce: u32 = rand::random();
    let src_port: u16 = rand::random_range(50_000..u16::MAX);
    send_diagnostic(
        sender,
        awaiting,
        source,
        host,
        nonce,
        tcp::build_probe(TcpScanTechnique::Syn, source, host, src_port, port, nonce),
        Emission {
            fragment: Some(STATELESS_FRAGMENT_MTU),
            ..Emission::routed()
        },
        Filtering::StatelessFilter,
    )
}

/// Builds `packet`, sends it from `source` to `host`, and, if it reached the
/// wire, files its `nonce` under the `conclusion` a reply to it would prove.
/// Says whether it did.
#[allow(clippy::too_many_arguments)]
fn send_diagnostic(
    sender: &dyn ProbeSender,
    awaiting: &mut Awaiting,
    source: IpAddr,
    host: IpAddr,
    nonce: u32,
    packet: crate::protocols::error::Result<Vec<u8>>,
    emission: Emission,
    conclusion: Filtering,
) -> bool {
    let packet = match packet {
        Ok(packet) => packet,
        Err(e) => {
            error!(
                verbosity = 2,
                "cannot build a diagnostic probe for {host}: {e}"
            );
            return false;
        }
    };
    // A refused send files nothing, so no conclusion is credited unprobed.
    let sent = sender.send(&packet, source, host, None, emission).is_ok();
    if sent {
        awaiting.insert(nonce, (host, conclusion));
    }
    sent
}

/// Listens until the reply window closes or the scan is stopped, folding every
/// reply that names a probe into the findings of the host that probe went to.
async fn collect_replies(ctx: &ScanContext, transport: &mut ProbeTransport, awaiting: &Awaiting) {
    let deadline = Instant::now() + REPLY_WINDOW;
    loop {
        if ctx.handle.should_stop() {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        match tokio::time::timeout(remaining, transport.rx.recv()).await {
            Ok(Some(reply)) => {
                if let Some((host, conclusion)) = matched_conclusion(&reply.bytes, awaiting) {
                    ctx.update_host(host, |host| {
                        host.add_filtering(conclusion);
                    });
                }
            }
            // The stream closed or the window elapsed.
            Ok(None) | Err(_) => return,
        }
    }
}

/// The host and conclusion a reply implicates, if it echoes the nonce of a probe
/// we sent.
///
/// A nonce comes back in the acknowledgement field of a reply to a SYN and the
/// sequence field of a reply to an ACK, so both are tried; a random 32-bit
/// nonce collides with neither by accident. A reply matching nothing is someone
/// else's traffic and names no host.
fn matched_conclusion(reply: &[u8], awaiting: &Awaiting) -> Option<(IpAddr, Filtering)> {
    let tcp = tcp::parse(reply).ok()?;
    let as_syn = tcp::echoed_nonce(TcpScanTechnique::Syn, &tcp, 0);
    let as_ack = tcp::echoed_nonce(TcpScanTechnique::Ack, &tcp, 0);
    awaiting
        .get(&as_syn)
        .or_else(|| awaiting.get(&as_ack))
        .copied()
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
    use crate::protocols::craft;
    use std::net::Ipv4Addr;

    const HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    /// A conformant SYN+ACK reply to a SYN that carried `nonce` in its sequence
    /// number: it acknowledges `nonce + 1`, the one octet the SYN occupied.
    fn syn_ack_echoing(nonce: u32) -> Vec<u8> {
        let mut segment = craft::Tcp::new(80, 50_000).with_flags(tcp::flags::SYN | tcp::flags::ACK);
        segment.acknowledgement = nonce.wrapping_add(1);
        segment
            .to_bytes(Some((HOST, HOST)))
            .expect("a segment builds")
    }

    /// A conformant RST reply to an ACK that carried `nonce` in its
    /// acknowledgement field: RFC 793 §3.4 takes the reset's sequence number
    /// from that field, so it comes back as the reply's sequence number.
    fn rst_echoing_ack(nonce: u32) -> Vec<u8> {
        let mut segment = craft::Tcp::new(80, 50_000).with_flags(tcp::flags::RST);
        segment.sequence = nonce;
        segment
            .to_bytes(Some((HOST, HOST)))
            .expect("a segment builds")
    }

    #[test]
    fn a_reply_names_the_host_and_conclusion_of_the_probe_it_answers() {
        let syn_nonce = 0xDEAD_BEEF;
        let ack_nonce = 0x0BAD_F00D;
        let awaiting = HashMap::from([
            (syn_nonce, (HOST, Filtering::PortTrustingAcl)),
            (ack_nonce, (HOST, Filtering::StatefulFilter)),
        ]);

        // A SYN reply is read through the acknowledgement field, an ACK reply
        // through the sequence field.
        assert_eq!(
            matched_conclusion(&syn_ack_echoing(syn_nonce), &awaiting),
            Some((HOST, Filtering::PortTrustingAcl))
        );
        assert_eq!(
            matched_conclusion(&rst_echoing_ack(ack_nonce), &awaiting),
            Some((HOST, Filtering::StatefulFilter))
        );

        // A nonce we never sent settles nothing.
        assert_eq!(
            matched_conclusion(&syn_ack_echoing(0x1234_5678), &awaiting),
            None
        );
        // Bytes too short for a TCP header name no host, without panicking.
        assert_eq!(matched_conclusion(&[0u8; 4], &awaiting), None);
    }

    /// The fragmenting sender's neighbours are resolved at once before the first
    /// probe, and a dead one is sent no fragmented probe. Resolved inside each
    /// send, every dead neighbour would cost the whole budget in turn.
    #[tokio::test]
    async fn neighbours_behind_the_fragmenting_sender_are_asked_for_before_the_first_probe() {
        use crate::scanner::session::ScanSession;
        use crate::system::interface::{Link, LinkAddress};
        use crate::transport::link::{LinkNeighbors, SIMULATED_HOST};
        use crate::transport::probe::MockSender;

        const LIVE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 64);
        let dead: Vec<IpAddr> = (211..=220)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();
        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = tokio::sync::mpsc::channel(1024);
        let raw = MockSender::default();
        let asked = raw.sent.clone();
        let mut transport = ProbeTransport::from_parts(Box::new(raw), rx);
        let frames = MockSender::default();
        let framed = frames.sent.clone();
        let fragmenting = Fragmenting {
            sender: &frames,
            neighbors: NeighborWatch::Frames(LinkNeighbors::on_simulated_segment(
                "sim-filter0",
                &[LIVE],
            )),
        };
        let subjects = dead
            .iter()
            .copied()
            .chain([IpAddr::V4(LIVE)])
            .map(|host| Subject {
                host,
                open_port: Some(80),
                unreached_port: Some(81),
            })
            .collect();
        let mut resolver = SourceResolver::from_links(&[Link::new("test0", 0)
            .with_addresses(vec![LinkAddress::new(IpAddr::V4(SIMULATED_HOST), 24)])]);

        run(
            &ctx,
            &mut transport,
            Some(&fragmenting),
            &mut resolver,
            subjects,
        )
        .await;

        let framed = framed.lock().unwrap();
        assert!(
            !framed.is_empty(),
            "the live neighbour is sent the fragmented probe"
        );
        assert!(
            framed.iter().all(|(_, _, dst)| *dst == IpAddr::V4(LIVE)),
            "a fragmented probe was handed to the sender for a neighbour nobody had resolved"
        );
        assert_eq!(
            asked.lock().unwrap().len(),
            (dead.len() + 1) * 3,
            "the raw probes, through a transport with nothing to read, go to every host"
        );
    }

    /// Under the per-host and scan-wide gaps every filter probe is still sent,
    /// and the pass takes the time that costs.
    #[tokio::test]
    async fn the_filter_probes_keep_the_gaps_between_probes() {
        use crate::scanner::session::ScanSession;
        use crate::system::interface::{Link, LinkAddress};
        use crate::transport::probe::MockSender;

        const HOST_GAP: Duration = Duration::from_millis(120);
        const SCAN_GAP: Duration = Duration::from_millis(15);
        let hosts = [HOST, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))];
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(HOST_GAP))
            .probe_interval(Some(SCAN_GAP))
            .build();
        // A closed stream, so the listening window ends at once and the time
        // taken is the sending's.
        let (_, rx) = tokio::sync::mpsc::channel(1);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let mut transport = ProbeTransport::from_parts(Box::new(sender), rx);
        let subjects = hosts
            .iter()
            .map(|&host| Subject {
                host,
                open_port: Some(80),
                unreached_port: Some(81),
            })
            .collect();
        let mut resolver =
            SourceResolver::from_links(&[Link::new("test0", 1).with_addresses(vec![
                LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), 24),
            ])]);

        let started = Instant::now();
        run(&ctx, &mut transport, None, &mut resolver, subjects).await;
        let elapsed = started.elapsed();

        let sent = sent.lock().unwrap();
        for host in hosts {
            let to = sent.iter().filter(|(_, _, dst)| *dst == host).count();
            assert_eq!(to, 3, "{host} is sent every probe the gaps held");
        }
        // Three probes at each host, so two gaps at each, run side by side.
        let least = HOST_GAP * 2;
        assert!(
            elapsed >= least,
            "three probes {HOST_GAP:?} apart at each host cannot all leave in {elapsed:?}"
        );
    }

    /// Through the kernel, the first filter probe to an uncached neighbour is
    /// the write that asks, and the probes behind it wait on the verdict: a
    /// dead neighbour is sent nothing more; a live or cached one gets every
    /// probe.
    #[tokio::test]
    async fn probes_behind_the_kernel_asking_for_a_neighbour_wait_on_its_verdict() {
        use crate::scanner::session::ScanSession;
        use crate::system::interface::{Link, LinkAddress};
        use crate::transport::kernel_neighbors::KernelNeighbors;
        use crate::transport::probe::MockSender;

        let held = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 67));
        let live = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 68));
        let dead: Vec<IpAddr> = (225..=228)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();
        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = tokio::sync::mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let table = KernelNeighbors::asking_on_write(sent.clone(), &[held], &[live]);
        let mut transport =
            ProbeTransport::from_parts(Box::new(sender), rx).with_kernel_neighbors(table);
        let subjects = dead
            .iter()
            .copied()
            .chain([held, live])
            .map(|host| Subject {
                host,
                open_port: Some(80),
                unreached_port: Some(81),
            })
            .collect();
        let mut resolver =
            SourceResolver::from_links(&[Link::new("test0", 1).with_addresses(vec![
                LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
            ])]);

        run(&ctx, &mut transport, None, &mut resolver, subjects).await;

        let sent = sent.lock().unwrap();
        let to = |address: IpAddr| sent.iter().filter(|(_, _, dst)| *dst == address).count();
        for &address in &dead {
            assert_eq!(
                to(address),
                1,
                "{address} was sent past the write that asked"
            );
        }
        assert_eq!(to(held), 3, "a neighbour the kernel held");
        assert_eq!(to(live), 3, "a neighbour that answered");
    }
}
