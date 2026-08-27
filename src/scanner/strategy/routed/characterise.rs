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
//! answered. It sends a probe carrying a deliberately wrong TCP checksum to one
//! open port of each host: a conformant host drops such a segment unread, so a
//! reply to it was sent by something inline that answered without validating —
//! a firewall, an IPS, a transparent proxy — and the host is marked
//! [`Filtering::InlineMiddlebox`].
//!
//! Silence proves nothing, since most hosts drop the probe correctly, so only
//! the positive is recorded. Correlation is by the nonce the reply echoes,
//! exactly as a port scan's is: a reply that echoes no nonce we sent is somebody
//! else's traffic and records nothing, and a middlebox that answers without
//! acknowledging the probe is missed rather than guessed at — the safe direction
//! for a claim made only when it is proven.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet_packet::tcp::TcpPacket;

use crate::model::host::Filtering;
use crate::model::technique::TcpScanTechnique;
use crate::protocols::tcp;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::system::interface::SourceResolver;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport};
use crate::{error, info};

/// How long to listen for replies once the last diagnostic probe has left. A
/// middlebox answers as promptly as any host; this is the tail for a slow path,
/// not a retry schedule, because the pass sends each probe once.
const REPLY_WINDOW: Duration = Duration::from_secs(2);

/// Sends a bad-checksum probe to one open port of each `(host, port)` target and
/// records [`Filtering::InlineMiddlebox`] on every host that answered one.
pub async fn characterise(ctx: &ScanContext, targets: Vec<(IpAddr, u16)>) {
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

    info!(
        "characterising the filter in front of {} host(s)",
        targets.len()
    );

    // One bad-checksum SYN per host, remembering which nonce belongs to which
    // host so a reply can be tied back to it and to no other.
    let mut awaiting: HashMap<u32, IpAddr> = HashMap::with_capacity(targets.len());
    for (host, port) in &targets {
        let Some(source) = resolver.resolve(*host) else {
            continue;
        };
        let nonce: u32 = rand::random();
        let src_port: u16 = rand::random_range(50_000..u16::MAX);
        let packet = match tcp::create_probe_shaped(
            TcpScanTechnique::Syn,
            &source,
            host,
            src_port,
            *port,
            nonce,
            None,
            true,
        ) {
            Ok(packet) => packet,
            Err(e) => {
                error!(
                    verbosity = 2,
                    "cannot build a bad-checksum probe for {host}: {e}"
                );
                continue;
            }
        };
        if transport
            .tx
            .send(&packet, source, *host, Emission::routed())
            .is_ok()
        {
            awaiting.insert(nonce, *host);
        }
    }

    // A reply to any of them is proof of a middlebox: the host itself dropped
    // the corrupt segment, so whatever answered was not the host.
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
                if let Some(host) = middlebox_host(&reply.bytes, &awaiting) {
                    ctx.update_host(host, |host| {
                        host.add_filtering(Filtering::InlineMiddlebox);
                    });
                }
            }
            // The stream closed, or the window elapsed. Either way there is
            // nothing more to hear.
            Ok(None) | Err(_) => return,
        }
    }
}

/// The host a reply implicates, if it echoes the nonce of a probe we sent.
///
/// A reply whose echoed nonce is not one we are awaiting is somebody else's
/// traffic on a promiscuous capture, and names no host — which is what keeps the
/// pass from crediting a middlebox to a segment it never provoked.
fn middlebox_host(reply: &[u8], awaiting: &HashMap<u32, IpAddr>) -> Option<IpAddr> {
    let tcp = TcpPacket::new(reply)?;
    let nonce = tcp::echoed_nonce(TcpScanTechnique::Syn, &tcp, 0);
    awaiting.get(&nonce).copied()
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

    /// A conformant SYN+ACK reply to a SYN that carried `nonce` in its sequence
    /// number: it acknowledges `nonce + 1`, the one octet the SYN occupied.
    fn syn_ack_echoing(nonce: u32) -> Vec<u8> {
        let mut segment = craft::Tcp::new(80, 50_000).with_flags(tcp::flags::SYN | tcp::flags::ACK);
        segment.acknowledgement = nonce.wrapping_add(1);
        let host = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        segment
            .to_bytes(Some((host, host)))
            .expect("a segment builds")
    }

    #[test]
    fn a_reply_echoing_our_nonce_names_its_host_and_a_stray_names_none() {
        let host = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let nonce = 0xDEAD_BEEF;
        let awaiting = HashMap::from([(nonce, host)]);

        // The reply to our own probe names the host behind the middlebox.
        assert_eq!(
            middlebox_host(&syn_ack_echoing(nonce), &awaiting),
            Some(host)
        );

        // A reply echoing a nonce we never sent is somebody else's traffic and
        // names no host — a mutant that credited it would report a middlebox in
        // front of a host that answered nothing of ours.
        assert_eq!(
            middlebox_host(&syn_ack_echoing(nonce ^ 0x1234), &awaiting),
            None
        );

        // Bytes too short to be a TCP header name no host rather than panicking.
        assert_eq!(middlebox_host(&[0u8; 4], &awaiting), None);
    }
}
