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
//! [`Filtering`](crate::model::host::Filtering) conclusions:
//!
//! - **An inline middlebox**, from a reply to a bad-checksum probe to an *open*
//!   port. A conformant host drops the corrupt segment unread, so a reply was
//!   sent by something inline that answered without validating. One probe.
//! - **A stateful filter**, from an ACK probe reaching a *filtered* port — a
//!   reset, which is unfiltered — where the scan's plain SYN did not.
//! - **A port-trusting ACL**, from a SYN out of a trusted source port reaching a
//!   *filtered* port where an ordinary SYN did not.
//!
//! The comparative two read the plain SYN's fate off the port state the scan
//! already recorded, so only the alternative shape is sent here. Every one is a
//! positive claim: silence proves nothing and records nothing. Correlation is by
//! the nonce a reply echoes, so a segment we never provoked names no host — and
//! a filter that answers without acknowledging the probe is missed rather than
//! guessed at, the safe direction for a claim made only when it is proven.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet_packet::tcp::TcpPacket;

use crate::model::host::Filtering;
use crate::model::technique::TcpScanTechnique;
use crate::protocols::tcp;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::system::interface::SourceResolver;
use crate::transport::link::EthernetSender;
use crate::transport::probe::{Emission, ProbeKind, ProbeSender, ProbeTransport};
use crate::{error, info};

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
/// to nowhere in particular and lets the rest through — which is the thing this
/// probe is built to catch.
const STATELESS_FRAGMENT_MTU: u16 = 28;

/// One host and the ports the pass aims its diagnostic probes at.
pub struct Target {
    /// The host to characterise.
    pub host: IpAddr,
    /// An open TCP port, for the bad-checksum middlebox probe. `None` skips it —
    /// a probe whose whole point is that a listener answers has nowhere to land.
    pub open_port: Option<u16>,
    /// A port the scan found filtered, for the comparative probes: each tests
    /// whether a differently-shaped probe reaches where a plain SYN did not.
    /// `None` skips them — an unfiltered port shows no filter doing anything.
    pub filtered_port: Option<u16>,
}

/// Sends each host's diagnostic probes and records what the filter in front of
/// it demonstrably did.
pub async fn characterise(ctx: &ScanContext, targets: Vec<Target>) {
    if targets.is_empty() {
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

    let mut resolver = SourceResolver::from_system();

    // A self-built Ethernet sender for the one probe that needs one — the
    // fragmented stateless probe, which a raw socket cannot place. `None` where
    // this host has no Ethernet path at all, and even when it is `Some` a send
    // is refused for any host that path cannot route to; either way the
    // stateless conclusion simply goes undrawn there, while the raw probes below
    // still reach every host.
    let ethernet = EthernetSender::from_system(ProbeKind::TcpSyn.ip_protocols());

    info!(
        "characterising the filter in front of {} host(s)",
        targets.len()
    );

    // Each probe carries a nonce that maps back to the host and the conclusion a
    // reply to it would prove. A reply that echoes no nonce here is somebody
    // else's traffic and settles nothing.
    let mut awaiting: HashMap<u32, (IpAddr, Filtering)> = HashMap::new();
    for target in &targets {
        let Some(source) = resolver.resolve(target.host) else {
            continue;
        };

        if let Some(port) = target.open_port {
            let nonce: u32 = rand::random();
            let src_port: u16 = rand::random_range(50_000..u16::MAX);
            send_diagnostic(
                transport.tx.as_ref(),
                &mut awaiting,
                source,
                target.host,
                nonce,
                tcp::create_probe_shaped(
                    TcpScanTechnique::Syn,
                    &source,
                    &target.host,
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

        if let Some(port) = target.filtered_port {
            let nonce: u32 = rand::random();
            let src_port: u16 = rand::random_range(50_000..u16::MAX);
            send_diagnostic(
                transport.tx.as_ref(),
                &mut awaiting,
                source,
                target.host,
                nonce,
                tcp::create_probe(
                    TcpScanTechnique::Ack,
                    &source,
                    &target.host,
                    src_port,
                    port,
                    nonce,
                ),
                Emission::routed(),
                Filtering::StatefulFilter,
            );

            let nonce: u32 = rand::random();
            send_diagnostic(
                transport.tx.as_ref(),
                &mut awaiting,
                source,
                target.host,
                nonce,
                tcp::create_probe(
                    TcpScanTechnique::Syn,
                    &source,
                    &target.host,
                    TRUSTED_SOURCE_PORT,
                    port,
                    nonce,
                ),
                Emission::routed(),
                Filtering::PortTrustingAcl,
            );

            // The stateless probe, and the one that needs a self-built frame: a
            // whole SYN fragmented small enough that its flags fall past the
            // first fragment. A filter reachable only by a raw path never sees
            // it, and the host goes without this one conclusion.
            if let Some(ethernet) = ethernet.as_ref() {
                let nonce: u32 = rand::random();
                let src_port: u16 = rand::random_range(50_000..u16::MAX);
                send_diagnostic(
                    ethernet,
                    &mut awaiting,
                    source,
                    target.host,
                    nonce,
                    tcp::create_probe(
                        TcpScanTechnique::Syn,
                        &source,
                        &target.host,
                        src_port,
                        port,
                        nonce,
                    ),
                    Emission {
                        fragment: Some(STATELESS_FRAGMENT_MTU),
                        ..Emission::routed()
                    },
                    Filtering::StatelessFilter,
                );
            }
        }
    }

    // Listen until the window closes or the scan is stopped, folding each reply
    // that names a probe into its host's findings.
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
                if let Some((host, conclusion)) = matched_conclusion(&reply.bytes, &awaiting) {
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

/// Builds `packet`, sends it from `source` to `host`, and — if it reached the
/// wire — files its `nonce` under the `conclusion` a reply to it would prove.
#[allow(clippy::too_many_arguments)]
fn send_diagnostic(
    sender: &dyn ProbeSender,
    awaiting: &mut HashMap<u32, (IpAddr, Filtering)>,
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
    if sender.send(&packet, source, host, emission).is_ok() {
        awaiting.insert(nonce, (host, conclusion));
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
fn matched_conclusion(
    reply: &[u8],
    awaiting: &HashMap<u32, (IpAddr, Filtering)>,
) -> Option<(IpAddr, Filtering)> {
    let tcp = TcpPacket::new(reply)?;
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

        // A reply echoing a nonce we never sent settles nothing — a mutant that
        // credited it would report a filter in front of a host that answered
        // nothing of ours.
        assert_eq!(
            matched_conclusion(&syn_ack_echoing(0x1234_5678), &awaiting),
            None
        );
        // Bytes too short to be a TCP header name no host rather than panicking.
        assert_eq!(matched_conclusion(&[0u8; 4], &awaiting), None);
    }
}
