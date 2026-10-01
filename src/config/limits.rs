// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the unprivileged paths cannot measure for themselves
//!
//! The timeouts and concurrency ceilings every TCP-connect path runs against. The
//! connect port scanner, the connect discovery sweep, the service-detection pass and
//! the detection tiers open the same kind of connection, so they share one set of
//! numbers.
//!
//! A raw scanner measures its round trips and sizes its own patience through
//! `AdaptiveDeadline`. A connect probe cannot: it sends one SYN, the kernel owns the
//! retransmission, and the scanner never sees a round trip. Its numbers come from what
//! the protocol guarantees, and each one below says which guarantee.

use std::time::Duration;

/// How long a single TCP connect probe waits before treating silence as a drop.
/// Shared by the connect port and host scanners and by the service-detection
/// connect, which all open the same kind of connection for the same purpose.
///
/// Set against **the host stack's first SYN retransmission**. A connect probe sends one
/// SYN; the operating system's retransmission is its only second attempt, and RFC 6298
/// puts the initial retransmission timeout at one second, as Linux and the BSDs use. A
/// budget at or below a second expires while that retransmission is in flight, so every
/// host that ignores a first SYN (a rate limiter, a busy embedded stack, the SYN-flood
/// mitigations common in consumer routers) is reported `NoReply`, which looks exactly
/// like a firewall.
///
/// So it sits above one second by a round trip, and well below three, where the
/// *second* retransmission would arrive. The cost is half a second per port that
/// genuinely drops probes, paid only on the unprivileged path.
///
/// A refusal has to arrive inside the same budget. Unix stacks report one at the first
/// reset. Windows resends a refused SYN until its retransmissions run out, which at its
/// default count outlasts this budget, so there every connection the engine makes is
/// limited to the one retransmission this value waits for.
pub const CONNECT_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// The initial retransmission timeout a host TCP stack uses for a SYN
/// (RFC 6298 §2.1), which [`CONNECT_PROBE_TIMEOUT`] has to outlive.
pub(crate) const HOST_SYN_RETRANSMIT: Duration = Duration::from_secs(1);

/// How long a connect waits where it is how the path to a host is found: the
/// first a liveness sweep makes to an address, and the one a port scan makes
/// again to a host that answered none of its ports.
///
/// [`CONNECT_PROBE_TIMEOUT`] hears a host across a path of up to half a second, which
/// covers every ordinary path; on a longer one each connect gives up while the answer is
/// on its way, and a live host reads silent. A connect cannot time a path it has not
/// crossed, so one connect per host waits this long, and what it measures sizes the
/// waits that follow.
///
/// Three seconds, the longest a connect can wait without relying on the second
/// retransmission: the first SYN's answer is heard across a round trip of up to three
/// seconds, the retransmission's across one of up to two. Three seconds is also how
/// long the kernel waits before declaring a neighbour on its own segment failed.
pub(crate) const PATH_FINDING_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the connect that finds the path waits where the address is on one
/// of this host's own segments: [`PATH_FINDING_TIMEOUT`] twice over.
///
/// A connect to a neighbour whose hardware address the kernel does not hold waits on
/// address resolution before the SYN leaves, which is another round trip across the
/// same path. Across a path of 1.9 s a cold neighbour's first answer arrives at 3.8 s,
/// past the path-finding wait, so a live host reads silent every time. Twice that wait
/// covers resolution and handshake across the longest path a connect looks for.
///
/// The cost is up to three seconds more on a segment that does not answer, paid once,
/// since a sweep asks its addresses together. Linux gives up a lone neighbour's
/// resolution after three seconds and fails the connect; a sweep of one such address
/// measured 7.8 s against 6.2, and a `/24` holding two hosts 12.1 s against 9.1. A live
/// neighbour whose every port drops probes pays the three seconds in full.
pub(crate) const NEIGHBOUR_PATH_FINDING_TIMEOUT: Duration = Duration::from_secs(6);

/// How many targets the connect port scan and the passes after it (service
/// detection, detections, TLS enumeration) work on at once.
///
/// A pace. The socket table is protected by the descriptor budget (the soft file limit
/// minus a reserve for the rest of the process), which every connection takes a share
/// of before opening its socket, waiting when there is none. This is enough
/// conversations that a wide scan is not queued one port deep, and few enough that one
/// host is not asked fifty things at once.
pub const CONNECT_CONCURRENCY: usize = 50;

/// How many of one port's detection flows run at once.
///
/// A port's flows are independent conversations, and an HTTP port attracts dozens:
/// forty-seven against the built-in corpus, forty-three asking different questions, so
/// a shared reply cache saves almost nothing. Run in sequence, a host 140 ms away would
/// spend ten seconds on detections for ports settled in one.
///
/// [`CONNECT_CONCURRENCY`] still caps sockets in flight, through the gate the detection
/// phase acquires probes from. This only stops a scan of one host with four web ports
/// from queueing its work one deep.
pub const DETECTION_FLOW_CONCURRENCY: usize = 8;

/// How many connect probes the unprivileged discovery sweep keeps in flight.
/// Far higher than [`CONNECT_CONCURRENCY`] because each probe is a bare liveness
/// check against a handful of ports, not a full fingerprint conversation.
///
/// A ceiling, not always the one that binds. Every connect probe takes its socket from
/// a budget of half the process's descriptor limit (less under a very small one),
/// shared by every scan in the process, so a shell's default of 256 or 1,024 slows a
/// sweep below this without losing addresses.
pub const DISCOVERY_CONCURRENCY: usize = 2048;

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

    /// The connect budget outlives the host stack's first SYN retransmission.
    /// Measured against a router that ignores a first SYN and answers the
    /// retransmission: the refusal lands at 1.01 s to 1.04 s, and a one-second budget
    /// missed every one. It must also end before the second retransmission.
    #[test]
    fn a_connect_probe_outlives_one_host_retransmission_and_not_two() {
        assert!(
            CONNECT_PROBE_TIMEOUT > HOST_SYN_RETRANSMIT,
            "a budget of {CONNECT_PROBE_TIMEOUT:?} expires while the host stack's \
             retransmission is still in flight, and reports refusing hosts as no reply"
        );
        assert!(
            CONNECT_PROBE_TIMEOUT < HOST_SYN_RETRANSMIT * 3,
            "a budget of {CONNECT_PROBE_TIMEOUT:?} waits for a second retransmission"
        );
    }

    /// A neighbour's path is found across a resolution and a handshake, each a round
    /// trip. Measured: across a path of 1.9 s with the neighbour's hardware address not
    /// yet held, the first answer arrived at 3.8 s, and a three-second wait read a live
    /// host silent in three runs of three.
    #[test]
    fn a_neighbour_s_path_finding_covers_its_resolution_too() {
        assert!(NEIGHBOUR_PATH_FINDING_TIMEOUT >= PATH_FINDING_TIMEOUT * 2);
        assert!(NEIGHBOUR_PATH_FINDING_TIMEOUT > Duration::from_millis(3800));
    }
}
