// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Holding a probe while its neighbour is asked for
//!
//! A probe to a host on one of this host's links, or through a gateway on
//! one, leaves only once the hardware address of the neighbour it is framed to
//! is known. Where a transport's sends wait on that address resolution, and
//! the scan can read where it stands (see [`NeighborWatch`]), a pass does not
//! hand a probe over while the resolution runs:
//!
//! - **The kernel's**, behind a raw socket on Linux, takes a write to a
//!   neighbour it is still asking for, queues it and says nothing when the
//!   asking fails, so probes written freely to a dead neighbour read as
//!   silence though none of them left, and fill the socket's send buffer
//!   until every write is refused.
//! - **A frame sender's** waits inside the send for a resolution nobody asked
//!   for ahead, holding the pass with it, so every new neighbour a pass meets
//!   costs the resolution's budget in turn, and a dead one the whole of it.
//!
//! Two ways a pass keeps its probes out of both. One that can hold a probe and
//! send it later asks per probe, with [`NeighborGates::admit`]: the port scans
//! and the echo probe. One whose probes are a measurement or a walk, which a
//! probe held mid-way would bend, asks for every host it is about to probe at
//! once, with [`resolve_ahead`], and waits for them together before its first
//! probe: the series probe per batch, the trace and the filter probes per run.
//! Either way a wave of new neighbours costs one resolution's wait rather than
//! one each, and a neighbour that never answers is an address nothing reaches,
//! with nothing sent to it.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::scanner::session::ScanContext;
use crate::system::interface::SourceResolver;
use crate::transport::kernel_neighbors::NeighborState;
use crate::transport::link::ARP_TIMEOUT;
use crate::transport::probe::NeighborWatch;

/// How long a probe to a host whose neighbour is still being resolved is held
/// before the resolution is read again.
///
/// Short, because a neighbour that is there answers in well under a
/// millisecond and the hold is then the whole of what it cost; long enough
/// that holding a thousand ports of a dead host costs a table read per hold
/// rather than one per port, since every probe held for the same instant is
/// answered from the same reading.
pub(crate) const NEIGHBOR_RECHECK: Duration = Duration::from_millis(50);

/// The longest a probe can be held while its neighbour is asked for: the
/// resolution's budget, which is the kernel's three requests a second apart
/// on either path, and the one recheck it takes to read the verdict.
///
/// What a pass with a fixed deadline allows its first probes on top of their
/// own schedule, so a probe held for a neighbour that answers late is not
/// left with no time to be answered in.
pub(crate) const RESOLUTION_BUDGET: Duration = ARP_TIMEOUT.saturating_add(NEIGHBOR_RECHECK);

/// How far a pass has read the resolution of one neighbour. See
/// [`NeighborGates::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NeighborGate {
    /// The neighbour was asked for at `at`, by the one probe handed to the
    /// kernel or by asking the frame sender, and no reading since has shown
    /// it answering.
    Asked {
        /// When it was asked for, which a reading of the kernel's table has
        /// to postdate to show the entry the probe's write created.
        at: Instant,
    },
    /// The neighbour answered, or there is nothing to go on: the hosts behind
    /// it are asked freely.
    Open,
}

/// What becomes of one probe before it reaches the sender. See
/// [`NeighborGates::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// Hand it to the sender.
    Send,
    /// Hold it until the instant given, then ask again.
    Hold(Instant),
    /// Send nothing: the address cannot be reached from here.
    Unreachable,
}

/// How far a pass has read the resolution of each neighbour its probes wait
/// on.
#[derive(Debug, Default)]
pub(crate) struct NeighborGates {
    /// Each neighbour's gate, by the neighbour.
    gates: HashMap<IpAddr, NeighborGate>,
    /// The neighbour each gated host's probes wait on, which keys its gate:
    /// the host itself, or on the kernel's path the gateway it is routed
    /// through.
    gated: HashMap<IpAddr, IpAddr>,
}

impl NeighborGates {
    /// Decides what becomes of a probe to `host`, sent through a transport
    /// whose resolution `watch` reads and from the source `resolver` picks:
    ///
    /// - **resolved**, or nothing to go on, and the host is asked freely from
    ///   then on;
    /// - **still resolving**, and the probe is held for [`NEIGHBOR_RECHECK`]
    ///   and asks again;
    /// - **failed**, and the address is unreachable: the neighbour was asked
    ///   three times across three seconds and said nothing.
    ///
    /// The kernel's asking starts with a write, so the first probe that needs
    /// a neighbour goes, which starts it, and every probe behind that one
    /// waits on the kernel's table. A host reached through a gateway waits on
    /// the gateway's entry, the one its writes queue on: the first probe
    /// through a gateway starts its resolution, and every host behind a
    /// gateway that never answers is unreachable on the one verdict.
    ///
    /// A frame sender asks for a neighbour when it is asked where the
    /// resolution stands, so no probe goes until the resolution concludes,
    /// and asking about every host as its first probe comes up starts every
    /// resolution at once.
    ///
    /// For a host that has answered nothing in this pass: an answer shows its
    /// neighbour resolved, and the caller sends to such a host freely.
    pub(crate) fn admit(
        &mut self,
        watch: Option<&NeighborWatch>,
        resolver: &mut SourceResolver,
        host: IpAddr,
        now: Instant,
    ) -> Admission {
        let Some(watch) = watch else {
            return Admission::Send;
        };
        let Some(neighbor) = neighbor_of(watch, resolver, host) else {
            return Admission::Send;
        };
        let asked = match self.gates.get(&neighbor) {
            Some(NeighborGate::Open) => return Admission::Send,
            Some(NeighborGate::Asked { at }) => *at,
            None if matches!(watch, NeighborWatch::Kernel(_)) => {
                // Stamped here rather than from `now`, which the caller read
                // before this batch of sends: the table has to be read after
                // this probe's write to show the entry the write creates.
                self.gates
                    .insert(neighbor, NeighborGate::Asked { at: Instant::now() });
                self.gated.insert(host, neighbor);
                return Admission::Send;
            }
            None => {
                let at = Instant::now();
                self.gates.insert(neighbor, NeighborGate::Asked { at });
                at
            }
        };
        self.gated.insert(host, neighbor);
        match state(watch, resolver, host, neighbor, asked) {
            Some(NeighborState::Resolving) => Admission::Hold(now + NEIGHBOR_RECHECK),
            Some(NeighborState::Failed) => Admission::Unreachable,
            Some(NeighborState::Resolved) | None => {
                self.gates.insert(neighbor, NeighborGate::Open);
                Admission::Send
            }
        }
    }

    /// Where the resolution of `host`'s neighbour stands, for a host whose
    /// probes have been waiting on it, and `None` for any other host.
    pub(crate) fn pending(
        &self,
        watch: Option<&NeighborWatch>,
        resolver: &mut SourceResolver,
        host: IpAddr,
    ) -> Option<NeighborState> {
        let neighbor = *self.gated.get(&host)?;
        let Some(NeighborGate::Asked { at }) = self.gates.get(&neighbor).copied() else {
            return None;
        };
        state(watch?, resolver, host, neighbor, at)
    }

    /// Every host whose probes are waiting on a neighbour not yet seen
    /// answering.
    pub(crate) fn waiting(&self) -> Vec<IpAddr> {
        self.gated
            .iter()
            .filter(|(_, neighbor)| {
                matches!(self.gates.get(neighbor), Some(NeighborGate::Asked { .. }))
            })
            .map(|(host, _)| *host)
            .collect()
    }

    /// Why `host` went unreached, for a neighbour whose resolution stands at
    /// `state`: in the resolution's own word, and naming the gateway where
    /// the host's probes waited on one.
    pub(crate) fn unreached(&self, host: IpAddr, state: NeighborState) -> String {
        let resolution = if host.is_ipv4() { "ARP" } else { "NDP" };
        let how = match state {
            NeighborState::Failed => format!("no {resolution} reply"),
            _ => format!("{resolution} pending"),
        };
        match self.gated.get(&host).filter(|neighbor| **neighbor != host) {
            Some(gateway) => format!("{how} from gateway {gateway}"),
            None => how,
        }
    }
}

/// Asks for the neighbour of every host in `hosts` at once, and waits until
/// each has answered or been given up, which is one resolution's wait for all
/// of them. Returns the hosts whose neighbour was given up, which nothing
/// reaches from here, each with why.
///
/// For a pass that cannot hold a probe once it has begun; see the module
/// documentation. Through the kernel it waits for nothing, since the kernel
/// asks only once a probe is written and the write waits in the kernel's
/// queue rather than in the send. Ends early, with the rest unresolved, when
/// the scan is stopped.
pub(crate) async fn resolve_ahead(
    ctx: &ScanContext,
    watch: Option<&NeighborWatch>,
    resolver: &mut SourceResolver,
    hosts: impl IntoIterator<Item = IpAddr>,
) -> BTreeMap<IpAddr, String> {
    let mut gates = NeighborGates::default();
    let mut unanswered = BTreeMap::new();
    let mut waiting: Vec<IpAddr> = hosts.into_iter().collect();
    while !waiting.is_empty() && !ctx.handle.should_stop() {
        let now = Instant::now();
        waiting.retain(|host| match gates.admit(watch, resolver, *host, now) {
            Admission::Send => false,
            Admission::Hold(_) => true,
            Admission::Unreachable => {
                unanswered.insert(*host, gates.unreached(*host, NeighborState::Failed));
                false
            }
        });
        if !waiting.is_empty() {
            tokio::time::sleep(NEIGHBOR_RECHECK).await;
        }
    }
    unanswered
}

/// The neighbour whose resolution `host`'s probes wait on, which keys its
/// gate: on the kernel's path the host itself where it is on a link of this
/// host's, and otherwise the gateway the routing table sends it through; for
/// a frame sender the host, whose next hop the sender finds for itself.
/// `None` where no neighbour stands in the way.
fn neighbor_of(watch: &NeighborWatch, resolver: &SourceResolver, host: IpAddr) -> Option<IpAddr> {
    match watch {
        NeighborWatch::Kernel(_) if resolver.is_on_link(host) => Some(host),
        NeighborWatch::Kernel(table) => table.next_hop(host),
        NeighborWatch::Frames(_) => Some(host),
    }
}

/// Where the resolution of `host`'s neighbour stands, asked as `watch` needs:
/// the kernel's entry for `neighbor` from a reading taken after `asked` and no
/// older than [`NEIGHBOR_RECHECK`], or the frame sender's resolution of the
/// next hop a probe from `resolver`'s source to `host` is framed to.
fn state(
    watch: &NeighborWatch,
    resolver: &mut SourceResolver,
    host: IpAddr,
    neighbor: IpAddr,
    asked: Instant,
) -> Option<NeighborState> {
    match watch {
        NeighborWatch::Kernel(table) => {
            let recent = Instant::now()
                .checked_sub(NEIGHBOR_RECHECK)
                .map_or(asked, |recent| recent.max(asked));
            table.state(neighbor, recent)
        }
        NeighborWatch::Frames(link) => {
            let source = resolver.resolve(host)?;
            link.state(source, host)
        }
    }
}
