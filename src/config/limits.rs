// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the unprivileged paths cannot measure for themselves
//!
//! The timeouts and concurrency ceilings every TCP-connect path runs against.
//! The connect port scanner, the connect discovery sweep, the service-detection
//! pass and the detection tiers all open the same kind of connection for the
//! same purpose, so they share one set of numbers. Spelled separately in each,
//! a budget gets tuned in one place and left behind in the others, and nothing
//! reports the disagreement.
//!
//! Only the connect paths need constants at all. A raw scanner measures the
//! round trips it is getting and sizes its own patience from them, through
//! `AdaptiveDeadline`. A
//! connect probe cannot: it sends one SYN, the kernel owns the retransmission,
//! and the scanner never sees a round trip it could learn from. Its numbers come
//! from what the protocol guarantees instead, and each one below says which
//! guarantee.

use std::time::Duration;

/// How long a single TCP connect probe waits before treating silence as a drop.
/// Shared by the connect port and host scanners and by the service-detection
/// connect, which all open the same kind of connection for the same purpose.
///
/// The value is set against **the host stack's first SYN retransmission**, and
/// that is the only thing that decides it. A connect probe sends one SYN and has
/// no retransmission of its own: the operating system's is the only second
/// attempt it gets, and RFC 6298 puts the initial retransmission timeout at one
/// second, which is what Linux and the BSDs both use. A budget at or below a
/// second therefore expires while that retransmission is still in flight, and
/// every host that ignores a first SYN - a rate limiter, a busy embedded stack,
/// any of the SYN-flood mitigations common in consumer routers - is reported
/// `Filtered` when it is merely slow to answer the first time. That failure is
/// silent, total, and looks exactly like a firewall.
///
/// So it sits above one second by enough to cover a round trip on top, and well
/// below three, where the *second* retransmission would arrive: one extra
/// attempt is worth waiting for, a third is a scan that has stopped being a
/// scan. What it costs is half a second per genuinely filtered port, paid only
/// on the unprivileged path, which is the right way round - the raw scanners
/// retransmit for themselves and size their own patience from measured round
/// trips.
///
/// A refusal has to arrive inside the same budget. Unix stacks report one at
/// the first reset. Windows resends a refused SYN until its SYN retransmissions
/// run out, which at its default count outlasts this budget, so there every
/// connection the engine makes keeps only the one retransmission this value
/// waits for.
pub const CONNECT_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// The initial retransmission timeout a host TCP stack uses for a SYN
/// (RFC 6298 §2.1), which [`CONNECT_PROBE_TIMEOUT`] has to outlive.
pub(crate) const HOST_SYN_RETRANSMIT: Duration = Duration::from_secs(1);

/// How long a connect waits where it is how the path to a host is found: the
/// first a liveness sweep makes to an address, and the one a port scan makes
/// again to a host that answered none of its ports.
///
/// [`CONNECT_PROBE_TIMEOUT`] hears a host across a path of up to half a
/// second, which is every ordinary path, and on a longer one it hears
/// nothing: each connect gives up while the answer to its SYN is on the way,
/// so a live host reads silent and its open ports filtered. A connect cannot
/// time the path it has not yet crossed, so one connect per host waits this
/// long instead, and what it measures sizes the waits that follow it.
///
/// Three seconds, the longest a connect waits without waiting on the host
/// stack's second retransmission, as [`CONNECT_PROBE_TIMEOUT`] declines to:
/// the first SYN's answer is heard across a round trip of up to three
/// seconds, the retransmission's across one of up to two. Three seconds is
/// also the evidence the kernel takes before it calls a neighbour on its own
/// segment failed.
pub(crate) const PATH_FINDING_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the connect that finds the path waits where the address is on one
/// of this host's own segments: [`PATH_FINDING_TIMEOUT`] twice over.
///
/// A connect to a neighbour whose hardware address the kernel does not hold
/// waits on its resolution before the SYN leaves, and the resolution is a
/// round trip across the same path the handshake takes after it. Across a
/// path of 1.9 s a cold neighbour's first answer arrives at 3.8 s, past the
/// path-finding wait, and a live host reads silent every time. Twice that
/// wait hears the resolution and the handshake each across the longest path
/// a connect looks for.
///
/// What it costs is up to three seconds more per address on a segment that
/// does not answer, paid once for all of them, since a sweep asks its
/// addresses together. Linux gives a lone neighbour's resolution up after
/// three seconds of asking and fails the connect then, and a sweep of one
/// such address was measured at 7.8 s against 6.2; with a segment's worth
/// asked at once not every connect is failed, and a `/24` holding two hosts
/// took 12.1 s against 9.1. A live neighbour whose every port is filtered
/// pays the three seconds in full.
pub(crate) const NEIGHBOUR_PATH_FINDING_TIMEOUT: Duration = Duration::from_secs(6);

/// How many targets the connect port scan and the passes after it (service
/// detection, detections, TLS enumeration) work on at once.
///
/// A pace, not a guard on the socket table. What keeps the process's table
/// from filling is its descriptor budget, what the soft file limit leaves
/// once a reserve for the rest of the process is set aside, which every
/// connection a scan opens takes a share of before its socket and waits
/// for when there is none; a table full for other reasons is waited out
/// rather than read as the target's answer. This is how many conversations a
/// pass keeps going, enough that a wide scan is not queued one port deep and
/// few enough that one host is not asked fifty things at the same instant.
pub const CONNECT_CONCURRENCY: usize = 50;

/// How many of one port's detection flows run at once.
///
/// A port's flows are independent conversations that happen to share an address,
/// and an HTTP port attracts dozens of them: forty-seven against the built-in
/// corpus, forty-three of them asking a different question, so a shared reply
/// cache collapses almost none of it. Run one after another that is forty-seven
/// round trips in a row, and a host 140ms away spends ten seconds on detections
/// for a scan whose ports were settled in one.
///
/// It does not raise what a scan opens at once. [`CONNECT_CONCURRENCY`] is still
/// the ceiling on sockets in flight, held by the gate the detection phase
/// acquires a probe through, so this changes how that budget is spent rather
/// than how large it is: it keeps a scan of one host with four web ports from
/// queueing its work one deep, and leaves a scan of two hundred doing the same
/// total work it would one flow at a time.
pub const DETECTION_FLOW_CONCURRENCY: usize = 8;

/// How many connect probes the unprivileged discovery sweep keeps in flight.
/// Far higher than [`CONNECT_CONCURRENCY`] because each probe is a bare liveness
/// check against a handful of ports, not a full fingerprint conversation.
///
/// A ceiling, and not always the one that binds. Each probe in flight holds a
/// socket, and the process may hold only so many: every connect probe takes its
/// socket from a budget of half the process's descriptor limit, less under a
/// very small one, shared by every scan the process runs, so a shell's default
/// of 256 or 1,024 holds a sweep below this and slows it rather than letting
/// it lose the addresses it has no socket for.
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

    /// The boundary the connect budget must stay clear of, and the reason it is
    /// the value it is.
    ///
    /// A connect probe sends one SYN; the host stack's retransmission is the
    /// only second attempt it gets. Set at or below that boundary, the budget
    /// expires while the answer is in flight and reports a live, refusing host
    /// as filtered - measured against a router that ignores a first SYN and
    /// answers the retransmission, where the refusal lands at 1.01 s to 1.04 s
    /// and a one-second budget missed every one of them.
    ///
    /// The upper bound matters too: past the second retransmission the probe is
    /// waiting for an attempt nobody should wait for.
    #[test]
    fn a_connect_probe_outlives_one_host_retransmission_and_not_two() {
        assert!(
            CONNECT_PROBE_TIMEOUT > HOST_SYN_RETRANSMIT,
            "a budget of {CONNECT_PROBE_TIMEOUT:?} expires while the host stack's \
             retransmission is still in flight, and reports refusing hosts as filtered"
        );
        assert!(
            CONNECT_PROBE_TIMEOUT < HOST_SYN_RETRANSMIT * 3,
            "a budget of {CONNECT_PROBE_TIMEOUT:?} waits for a second retransmission"
        );
    }

    /// A neighbour's path is found across a resolution and a handshake, each a
    /// round trip across it, and the wait covers both across the longest path
    /// the path-finding wait covers one of. Measured: across a path of 1.9 s
    /// with the neighbour's hardware address not yet held, the first answer
    /// arrived at 3.8 s, and a three-second wait read a live host silent in
    /// three runs of three.
    #[test]
    fn a_neighbour_s_path_finding_covers_its_resolution_too() {
        assert!(NEIGHBOUR_PATH_FINDING_TIMEOUT >= PATH_FINDING_TIMEOUT * 2);
        assert!(NEIGHBOUR_PATH_FINDING_TIMEOUT > Duration::from_millis(3800));
    }
}
