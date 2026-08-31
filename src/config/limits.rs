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
//! [`AdaptiveDeadline`](crate::scanner::pacing::deadline::AdaptiveDeadline). A
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
pub const CONNECT_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// The initial retransmission timeout a host TCP stack uses for a SYN
/// (RFC 6298 §2.1), which [`CONNECT_PROBE_TIMEOUT`] has to outlive.
#[cfg(test)]
const HOST_SYN_RETRANSMIT: Duration = Duration::from_secs(1);

/// How many TCP connects the port-scan and service-detection fan-outs keep in
/// flight at once. Bounded so a wide scan stays fast without exhausting OS
/// sockets.
pub const CONNECT_CONCURRENCY: usize = 50;

/// How many connect probes the unprivileged discovery sweep keeps in flight.
/// Far higher than [`CONNECT_CONCURRENCY`] because each probe is a bare liveness
/// check against a handful of ports, not a full fingerprint conversation.
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
}
