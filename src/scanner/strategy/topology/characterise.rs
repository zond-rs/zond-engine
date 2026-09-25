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
//! answered. It sends a few deliberately-shaped probes to a host's ports and
//! reads what the filter in front of it let through, as
//! [`Filtering`] conclusions:
//!
//! - **An inline middlebox**, from a reply to a bad-checksum probe to an *open*
//!   port. A conformant host drops the corrupt segment unread, so a reply was
//!   sent by something inline that answered without validating. One probe.
//! - **A stateful filter**, from an ACK probe reaching a *filtered* port, a
//!   reset, which is unfiltered, where the scan's plain SYN did not.
//! - **A port-trusting ACL**, from a SYN out of a trusted source port reaching a
//!   *filtered* port where an ordinary SYN did not.
//! - **A stateless filter**, from a *fragmented* SYN reaching a *filtered* port
//!   where a whole one did not. A filter that reassembled would have judged the
//!   same segment either way; one that lets the fragments through judged only
//!   the first, where the ports are and the flags are not yet. The one probe a
//!   raw socket cannot place, so it goes over the self-built Ethernet path, and
//!   a host that path cannot route to goes without this conclusion rather than
//!   against it.
//!
//! The comparative three read the plain SYN's fate off the port state the scan
//! already recorded, so only the alternative shape is sent here. Every one is a
//! positive claim: silence proves nothing and records nothing. Correlation is by
//! the nonce a reply echoes, so a segment we never provoked names no host, and
//! a filter that answers without acknowledging the probe is missed rather than
//! guessed at, the safe direction for a claim made only when it is proven.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::logging::error;
use crate::model::host::Filtering;
use crate::model::technique::TcpScanTechnique;
use crate::protocols::tcp;
use crate::report::ScannerKind;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::raw::neighbors::{resolve_ahead, send_when_admitted};
use crate::system::interface::SourceResolver;
use crate::transport::link::EthernetSender;
use crate::transport::probe::{Emission, NeighborWatch, ProbeKind, ProbeSender, ProbeTransport};
use crate::{counted, info};

/// How long to listen for replies once the last diagnostic probe has left. A
/// filter answers as promptly as any host; this is the tail for a slow path, not
/// a retry schedule, because the pass sends each probe once.
const REPLY_WINDOW: Duration = Duration::from_secs(2);

/// The source port a port-trusting ACL is most likely to hold a door open for:
/// a rule that lets "returning DNS" back in lets anything from port 53 in.
const TRUSTED_SOURCE_PORT: u16 = 53;

/// The largest each fragment of the stateless-filter probe may be, in bytes.
///
/// Twenty-eight is an IP header (20) plus one eight-byte fragment, the smallest
/// a conformant path carries. It puts the ports in the first fragment and the
/// flags in a later one, so a filter that judges only the first sees a segment
/// to nowhere in particular and lets the rest through, which is the thing this
/// probe is built to catch.
const STATELESS_FRAGMENT_MTU: u16 = 28;

/// One host and the ports the pass aims its diagnostic probes at.
pub struct Subject {
    /// The host to characterise.
    pub host: IpAddr,
    /// An open TCP port, for the bad-checksum middlebox probe. `None` skips it:
    /// a probe whose whole point is that a listener answers has nowhere to land.
    pub open_port: Option<u16>,
    /// A port the scan found filtered, for the comparative probes: each tests
    /// whether a differently-shaped probe reaches where a plain SYN did not.
    /// `None` skips them: an unfiltered port shows no filter doing anything.
    pub filtered_port: Option<u16>,
}

/// The probes still outstanding. Each nonce names the host its probe went to
/// and the conclusion a reply echoing it would prove, so a reply that echoes
/// none of them is somebody else's traffic and settles nothing.
type Awaiting = HashMap<u32, (IpAddr, Filtering)>;

/// Sends each host's diagnostic probes and records what the filter in front of
/// it demonstrably did.
pub async fn characterise(ctx: &ScanContext, subjects: Vec<Subject>) {
    if subjects.is_empty() {
        return;
    }

    let mut transport = match ProbeTransport::open(ProbeKind::TcpSyn) {
        Ok(transport) => transport,
        Err(error) => {
            ctx.record_failure(
                ScannerKind::Routed,
                format!("no transport to characterise a filter with: {error}"),
            );
            return;
        }
    };

    // A self-built Ethernet sender for the one probe that needs one: the
    // fragmented stateless probe, which a raw socket cannot place. `None` where
    // this host has no Ethernet path at all, and even when it is `Some` a send
    // is refused for any host that path cannot route to; either way the
    // stateless conclusion simply goes undrawn there, while the raw probes below
    // still reach every host.
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

/// The sender the fragmented stateless probe leaves on, which frames it
/// itself because a raw socket cannot place it, and where that sender's
/// address resolutions stand.
struct Fragmenting<'a> {
    sender: &'a dyn ProbeSender,
    neighbors: NeighborWatch,
}

/// Sends every subject its probes, once the neighbour each is framed to has
/// been asked for, and folds in what the replies prove.
///
/// Every neighbour is asked for at once and waited for before the first probe,
/// on the transport's resolution and then on the fragmenting sender's, which
/// runs its own: probes sent host by host through a sender that met each new
/// neighbour inside the send would wait out a resolution per host in turn. A
/// host whose neighbour never answered is sent nothing on that sender.
///
/// The transport's probes are then admitted one by one, as every pass's are,
/// since through the kernel nothing is asked before a probe is written: the
/// first to a neighbour the kernel does not hold is the write that asks, and
/// the ones behind it wait on the verdict. See [`send_when_admitted`].
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
            let filtered = subjects
                .iter()
                .filter(|subject| subject.filtered_port.is_some())
                .map(|subject| subject.host);
            resolve_ahead(ctx, Some(&fragmenting.neighbors), resolver, filtered)
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

    if let Some(fragmenting) = fragmenting {
        send_fragmented(
            &subjects,
            fragmenting.sender,
            &unframed,
            resolver,
            &mut awaiting,
        );
    }
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
    /// Sends this probe to `host` and files what a reply to it would prove.
    fn send(self, sender: &dyn ProbeSender, awaiting: &mut Awaiting, host: IpAddr) {
        let Self {
            source,
            port,
            conclusion,
        } = self;
        match conclusion {
            Filtering::InlineMiddlebox => {
                probe_inline_middlebox(sender, awaiting, source, host, port);
            }
            Filtering::StatefulFilter => {
                probe_stateful_filter(sender, awaiting, source, host, port);
            }
            Filtering::PortTrustingAcl => {
                probe_port_trusting_acl(sender, awaiting, source, host, port);
            }
            // Sent on the fragmenting sender instead; see `send_fragmented`.
            _ => {}
        }
    }
}

/// The probes every subject's ports allow on the transport, in the order they
/// are sent: the middlebox probe to an open port, and the two comparative
/// probes to a filtered one.
///
/// A host with no source address to send from is passed over: a probe that
/// never left proves nothing about the filter in front of it.
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
        if let Some(port) = subject.filtered_port {
            planned.push(diagnostic(port, Filtering::StatefulFilter));
            planned.push(diagnostic(port, Filtering::PortTrustingAcl));
        }
    }
    planned
}

/// Sends the fragmented stateless-filter probe to every subject with a
/// filtered port, on the frame sender that can place it, except where that
/// sender's neighbour did not answer, `unframed`, whose hosts go without this
/// one conclusion.
fn send_fragmented(
    subjects: &[Subject],
    sender: &dyn ProbeSender,
    unframed: &BTreeMap<IpAddr, String>,
    resolver: &mut SourceResolver,
    awaiting: &mut Awaiting,
) {
    for subject in subjects {
        let Some(port) = subject.filtered_port else {
            continue;
        };
        if unframed.contains_key(&subject.host) {
            continue;
        }
        let Some(source) = resolver.resolve(subject.host) else {
            continue;
        };
        probe_stateless_filter(sender, awaiting, source, subject.host, port);
    }
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
) {
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
    );
}

/// Sends an ACK to a port the scan's plain SYN found filtered. A reset back is
/// a port that is unfiltered to an ACK and filtered to a SYN, which is a filter
/// judging a segment by where it sits in a connection.
fn probe_stateful_filter(
    sender: &dyn ProbeSender,
    awaiting: &mut Awaiting,
    source: IpAddr,
    host: IpAddr,
    port: u16,
) {
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
    );
}

/// Sends a SYN out of the trusted source port to a port an ordinary SYN found
/// filtered. A reply is a rule admitting the segment on the port it claims to
/// come from rather than on what it is.
fn probe_port_trusting_acl(
    sender: &dyn ProbeSender,
    awaiting: &mut Awaiting,
    source: IpAddr,
    host: IpAddr,
    port: u16,
) {
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
    );
}

/// Sends a whole SYN fragmented small enough that its flags fall past the first
/// fragment. A reply is a filter that judged the first fragment alone and
/// passed the rest.
///
/// The one probe a raw socket cannot place, so it goes over the self-built
/// Ethernet path, and a host that path cannot route to goes without this one
/// conclusion.
fn probe_stateless_filter(
    sender: &dyn ProbeSender,
    awaiting: &mut Awaiting,
    source: IpAddr,
    host: IpAddr,
    port: u16,
) {
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
    );
}

/// Builds `packet`, sends it from `source` to `host`, and, if it reached the
/// wire, files its `nonce` under the `conclusion` a reply to it would prove.
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
) {
    let packet = match packet {
        Ok(packet) => packet,
        Err(e) => {
            error!(
                verbosity = 2,
                "cannot build a diagnostic probe for {host}: {e}"
            );
            return;
        }
    };
    // A refused send files nothing: the fragmented stateless probe reaches only
    // a host the Ethernet path can route to, and one it cannot simply goes
    // uncharacterised rather than credited a conclusion no probe proved.
    if sender.send(&packet, source, host, None, emission).is_ok() {
        awaiting.insert(nonce, (host, conclusion));
    }
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
            // The stream closed, or the window elapsed. Either way there is
            // nothing more to hear.
            Ok(None) | Err(_) => return,
        }
    }
}

/// The host and conclusion a reply implicates, if it echoes the nonce of a probe
/// we sent.
///
/// A nonce comes back in the acknowledgement field of a reply to a SYN and the
/// sequence field of a reply to an ACK, so both readings are tried; a random
/// 32-bit nonce collides with neither by accident. A reply matching nothing here
/// is somebody else's traffic on a promiscuous capture and names no host, which
/// is what keeps the pass from crediting a conclusion to a segment it never
/// provoked.
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
        // through the sequence field, and each names the conclusion its own
        // probe was sent to prove.
        assert_eq!(
            matched_conclusion(&syn_ack_echoing(syn_nonce), &awaiting),
            Some((HOST, Filtering::PortTrustingAcl))
        );
        assert_eq!(
            matched_conclusion(&rst_echoing_ack(ack_nonce), &awaiting),
            Some((HOST, Filtering::StatefulFilter))
        );

        // A reply echoing a nonce we never sent settles nothing: a mutant that
        // credited it would report a filter in front of a host that answered
        // nothing of ours.
        assert_eq!(
            matched_conclusion(&syn_ack_echoing(0x1234_5678), &awaiting),
            None
        );
        // Bytes too short to be a TCP header name no host rather than panicking.
        assert_eq!(matched_conclusion(&[0u8; 4], &awaiting), None);
    }

    /// The fragmented probe, which goes out on a frame sender of its own
    /// whatever the transport, is sent to no neighbour that sender is still
    /// asking for: every one is asked for at once, before the first probe, and
    /// one that never answers is sent none.
    ///
    /// A frame sender resolves a neighbour nobody asked for ahead inside the
    /// send and holds the pass for the whole wait, which for a neighbour that
    /// never answers is the resolution's whole budget, paid again for each one
    /// in turn.
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
                filtered_port: Some(81),
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

    /// Through the kernel, which asks for a neighbour only once a probe is
    /// written to it, the first filter probe to a host whose neighbour it does
    /// not hold is the one write that asks, and the probes behind it wait on
    /// the verdict: a neighbour that never answers is sent nothing more, while
    /// a live one, and one the kernel already held, is sent every probe.
    ///
    /// Written freely, every probe to a dead neighbour queues in the kernel
    /// and is thrown away, where each was meant to prove something about the
    /// filter in front of a host nothing reached.
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
                filtered_port: Some(81),
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
