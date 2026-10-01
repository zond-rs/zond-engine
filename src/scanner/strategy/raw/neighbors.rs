// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Holding a probe while its neighbour is asked for
//!
//! A probe to an on-link host, or through an on-link gateway, leaves only once
//! the neighbour's hardware address is known. Where the scan can read the
//! resolution (see [`NeighborWatch`]), a pass holds probes while it runs:
//!
//! - **The kernel** (raw socket on Linux) queues a write to a neighbour it is
//!   still asking for and says nothing when the asking fails. Probes written
//!   freely to a dead neighbour read as silence though none left, and fill the
//!   send buffer until every write is refused.
//! - **A frame sender** waits inside the send for the resolution, so every new
//!   neighbour costs the pass the resolution's budget in turn, and a dead one
//!   the whole of it.
//!
//! Every pass asks per probe with [`NeighborGates::admit`]. The first write to a
//! neighbour the kernel does not hold goes, since the write starts the kernel's
//! asking, and every probe behind it waits on the verdict. A silent neighbour is
//! asked a second time first; see [`NEIGHBOR_ROUNDS`]. Each pass handles a held
//! probe its own way: the port scans and the echo probe send it later; the trace
//! and the filter probes wait for it with [`admit_waiting`] and
//! [`send_when_admitted`]; the series probe drops it, because its sample spacing
//! is the measurement and a late sample costs more than a missing one.
//!
//! Those three also call [`resolve_ahead`] for every host before their first
//! probe (the series probe per batch, the others per run). A frame sender runs
//! the resolutions together; on the kernel's path the table is read once and
//! hosts whose neighbour it holds are asked freely. Either way a wave of new
//! neighbours costs one resolution's wait, two where any is silent.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::scanner::session::ScanContext;
use crate::system::interface::SourceResolver;
use crate::transport::kernel_neighbors::{KernelNeighbors, NeighborState};
use crate::transport::link::ARP_TIMEOUT;
use crate::transport::probe::NeighborWatch;

/// How long a probe to a host whose neighbour is still being resolved is held
/// before the resolution is read again.
///
/// Short, because a live neighbour answers in well under a millisecond and
/// the hold is then its whole cost. Long enough that a thousand held ports of a
/// dead host cost one table read per hold, since probes held for the same
/// instant share a reading.
pub(crate) const NEIGHBOR_RECHECK: Duration = Duration::from_millis(50);

/// The longest one resolution holds a probe: three requests a second apart on
/// either path, plus the recheck that reads the verdict.
pub(crate) const RESOLUTION_BUDGET: Duration = ARP_TIMEOUT.saturating_add(NEIGHBOR_RECHECK);

/// How many resolutions of one neighbour a pass waits out unanswered before
/// it gives the neighbour up, and every host behind it with it.
///
/// Two, because a live machine can be silent for one resolution's three
/// seconds: an interface or switch port in power save sleeping through three
/// broadcasts, or a loaded switch dropping them. Given up on the first, such a
/// host would be unreachable for the whole scan. Two resolutions are six
/// requests over six seconds, close to macOS's own five a second apart. A third
/// would cost every dead neighbour another resolution.
///
/// The second starts as soon as the first is given up. On the kernel's path a
/// write starts it, since Linux asks afresh when a write needs a neighbour it
/// gave up on; a frame sender is told to forget the first. A wave of dead
/// neighbours runs its second resolutions together, costing one more wait.
pub(crate) const NEIGHBOR_ROUNDS: u8 = 2;

/// The longest a probe can be held while its neighbour is asked for, every
/// resolution of it: [`RESOLUTION_BUDGET`] for each of [`NEIGHBOR_ROUNDS`].
///
/// A pass with a fixed deadline adds this for its first probes, so a probe
/// held for a neighbour that answers late still has time to be answered.
pub(crate) const NEIGHBOR_BUDGET: Duration =
    RESOLUTION_BUDGET.saturating_mul(NEIGHBOR_ROUNDS as u32);

/// The longest one resolution of a neighbour may be read as still running
/// before the neighbour is given up on and the host behind it filed
/// unreached: twice [`RESOLUTION_BUDGET`].
///
/// Every resolution concludes within its budget, so a longer wait means one
/// that never will, such as a driver wedged in a read that keeps resolutions
/// pending. Unbounded, a pass would wait until the scan stopped. Twice the
/// budget still lets a late resolution on a loaded machine count.
pub(crate) const RESOLUTION_WAIT_LIMIT: Duration = RESOLUTION_BUDGET.saturating_mul(2);

/// How many of the kernel's hold-downs on one host's neighbour a pass meets,
/// the last read as the kernel's verdict on the host.
///
/// Two, because the first hold-down may rest on a resolution another process
/// or an earlier pass asked for while the neighbour slept. It is waited out
/// and the next probe has the kernel ask afresh; a second hold-down means that
/// fresh resolution failed too. A resolution the kernel gives up on at this
/// pass's own write refuses it with `EHOSTUNREACH` instead, read as no route at
/// once.
///
/// A live neighbour asleep through one resolution costs one hold-down: see
/// [`kernel_neighbors::hold_down`](crate::transport::kernel_neighbors::hold_down).
pub(crate) const HELD_DOWN_REFUSALS: u8 = 2;

/// The kernel's hold-downs on the neighbours of the hosts one pass probes:
/// which hosts are held, until when, and how often each has been.
///
/// A send refused for a hold-down
/// ([`SendError::HeldDown`](crate::transport::probe::SendError::HeldDown),
/// `EHOSTDOWN` on macOS) sent nothing, and the first says nothing about the
/// host; see [`HELD_DOWN_REFUSALS`]. Every pass that can meet one keeps these,
/// so each holds the host for the whole hold-down and asks again after it.
#[derive(Debug)]
pub(crate) struct HoldDowns {
    held: HashMap<IpAddr, HeldDown>,
    /// How long the kernel holds a neighbour down; see
    /// [`kernel_neighbors::hold_down`](crate::transport::kernel_neighbors::hold_down).
    pub(crate) hold_down_for: Duration,
}

/// How far a pass has got with the kernel's hold-downs on one host's
/// neighbour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeldDown {
    /// How many sends to the host the kernel has refused for one.
    refusals: u8,
    /// When the latest hold-down is over, and the host may be asked again.
    until: Instant,
}

impl Default for HoldDowns {
    fn default() -> Self {
        Self {
            held: HashMap::new(),
            hold_down_for: crate::transport::kernel_neighbors::hold_down(),
        }
    }
}

impl HoldDowns {
    /// Holds `host` through the hold-down a send to it was refused for at
    /// `now`, and returns when it is over; `None` once the host has been held
    /// down [`HELD_DOWN_REFUSALS`] times, when the refusal is the kernel's
    /// verdict on it.
    ///
    /// A refusal while the host is held is the same hold-down, met by a
    /// concurrent send made before the first refusal was heard.
    pub(crate) fn hold(&mut self, host: IpAddr, now: Instant) -> Option<Instant> {
        let held = self.held.entry(host).or_insert(HeldDown {
            refusals: 0,
            until: now,
        });
        if held.until > now {
            return Some(held.until);
        }
        held.refusals = held.refusals.saturating_add(1);
        if held.refusals >= HELD_DOWN_REFUSALS {
            return None;
        }
        held.until = crate::scanner::pacing::timer::later(now, self.hold_down_for);
        Some(held.until)
    }

    /// Until when `host` is held, if it still is at `now`.
    pub(crate) fn until(&self, host: IpAddr, now: Instant) -> Option<Instant> {
        self.held
            .get(&host)
            .map(|held| held.until)
            .filter(|until| *until > now)
    }

    /// Ends `host`'s hold-down now, as its passing would.
    #[cfg(all(test, unix))]
    pub(crate) fn lift(&mut self, host: IpAddr) {
        if let Some(held) = self.held.get_mut(&host) {
            held.until = Instant::now();
        }
    }
}

/// How far a pass has read the resolution of one neighbour. See
/// [`NeighborGates::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NeighborGate {
    /// The neighbour was asked for at `at` and has not been seen answering.
    Asked {
        /// A kernel table reading must postdate this to show the entry the
        /// probe's write created.
        at: Instant,
        /// Which of the [`NEIGHBOR_ROUNDS`] resolutions this is, from one.
        round: u8,
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
    gates: HashMap<IpAddr, NeighborGate>,
    /// The neighbour each gated host waits on: the host itself, or on the
    /// kernel's path its gateway.
    gated: HashMap<IpAddr, IpAddr>,
    /// Each neighbour [`admit`](Self::admit) gave up on, with its state then:
    /// failed (not there), or still resolving at [`RESOLUTION_WAIT_LIMIT`]
    /// (never concluded). The reason filed for a host says which.
    given_up: HashMap<IpAddr, NeighborState>,
    /// When [`admit`](Self::admit) last asked for a neighbour again, not yet
    /// taken by [`take_asked_again`](Self::take_asked_again).
    asked_again: Option<Instant>,
}

impl NeighborGates {
    /// Decides what becomes of a probe to `host`, sent through a transport
    /// whose resolution `watch` reads and from the source `resolver` picks:
    ///
    /// - **resolved**, or nothing to go on, and the host is asked freely from
    ///   then on;
    /// - **still resolving**, and the probe is held for [`NEIGHBOR_RECHECK`]
    ///   and asks again;
    /// - **failed**, and the neighbour is asked again at once, the probe held
    ///   while it is, or on the kernel's path sent, since its write is what
    ///   asks; see [`NEIGHBOR_ROUNDS`];
    /// - **failed again**, and the address is unreachable. So is one still
    ///   resolving [`RESOLUTION_WAIT_LIMIT`] after it was last asked for.
    ///
    /// On the kernel's path the first probe goes, since its write starts the
    /// asking, and the rest wait on the table. A host behind a gateway waits on
    /// the gateway's entry, so one verdict covers every host behind it.
    ///
    /// A frame sender starts resolving when asked where the resolution stands,
    /// so no probe goes until it concludes.
    ///
    /// Only for a host that has answered nothing in this pass; the caller sends
    /// freely to one that has.
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
        let (asked, round) = match self.gates.get(&neighbor) {
            Some(NeighborGate::Open) => return Admission::Send,
            Some(NeighborGate::Asked { at, round }) => (*at, *round),
            None if matches!(watch, NeighborWatch::Kernel(_)) => {
                // Stamped now, not from `now`: the caller read that before this
                // batch, and the table must be read after this probe's write.
                self.ask(neighbor, 1);
                self.gated.insert(host, neighbor);
                return Admission::Send;
            }
            None => (self.ask(neighbor, 1), 1),
        };
        self.gated.insert(host, neighbor);
        match state(watch, resolver, host, neighbor, asked) {
            Some(NeighborState::Resolving)
                if now.saturating_duration_since(asked) >= RESOLUTION_WAIT_LIMIT =>
            {
                self.given_up.insert(neighbor, NeighborState::Resolving);
                Admission::Unreachable
            }
            Some(NeighborState::Resolving) => Admission::Hold(now + NEIGHBOR_RECHECK),
            Some(NeighborState::Failed) if round < NEIGHBOR_ROUNDS => {
                self.asked_again = Some(self.ask(neighbor, round + 1));
                match watch {
                    // The write has the kernel ask again.
                    NeighborWatch::Kernel(_) => Admission::Send,
                    NeighborWatch::Frames(link) => {
                        if let Some(source) = resolver.resolve(host) {
                            link.ask_again(source, host);
                        }
                        Admission::Hold(now + NEIGHBOR_RECHECK)
                    }
                }
            }
            Some(NeighborState::Failed) => {
                self.given_up.insert(neighbor, NeighborState::Failed);
                Admission::Unreachable
            }
            Some(NeighborState::Resolved) | None => {
                self.gates.insert(neighbor, NeighborGate::Open);
                Admission::Send
            }
        }
    }

    /// Marks `neighbor` asked for, in resolution `round`, as of now, and
    /// returns when.
    fn ask(&mut self, neighbor: IpAddr, round: u8) -> Instant {
        let at = Instant::now();
        self.gates
            .insert(neighbor, NeighborGate::Asked { at, round });
        at
    }

    /// When [`admit`](Self::admit) last asked for a neighbour again, taken
    /// once, so a pass can extend its deadline for the second resolution.
    pub(crate) fn take_asked_again(&mut self) -> Option<Instant> {
        self.asked_again.take()
    }

    /// Opens the gate of every host in `hosts` whose neighbour the kernel's
    /// table, read once, already resolves. The rest are gated as usual.
    fn open_held(
        &mut self,
        watch: &NeighborWatch,
        table: &KernelNeighbors,
        resolver: &SourceResolver,
        hosts: &[IpAddr],
    ) {
        let read = Instant::now();
        for host in hosts {
            let Some(neighbor) = neighbor_of(watch, resolver, *host) else {
                continue;
            };
            if table.state(neighbor, read) == Some(NeighborState::Resolved) {
                self.gates.insert(neighbor, NeighborGate::Open);
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
        let Some(NeighborGate::Asked { at, .. }) = self.gates.get(&neighbor).copied() else {
            return None;
        };
        state(watch?, resolver, host, neighbor, at)
    }

    /// Every host whose probes are waiting on a neighbour not yet seen
    /// answering.
    pub(crate) fn waiting(&self) -> Vec<IpAddr> {
        self.gated
            .keys()
            .copied()
            .filter(|host| self.is_waiting(*host))
            .collect()
    }

    /// Whether `host`'s probes are waiting on a neighbour not yet seen
    /// answering, including a host whose first probe [`admit`](Self::admit)
    /// just let through to start the asking.
    pub(crate) fn is_waiting(&self, host: IpAddr) -> bool {
        self.gated.get(&host).is_some_and(|neighbor| {
            matches!(self.gates.get(neighbor), Some(NeighborGate::Asked { .. }))
        })
    }

    /// Why [`admit`](Self::admit) turned `host` away, worded by
    /// [`unreached`](Self::unreached).
    pub(crate) fn refusal(&self, host: IpAddr) -> String {
        self.unreached(host, self.given_up_in(host))
    }

    /// Where the resolution of `host`'s neighbour stood when
    /// [`admit`](Self::admit) gave it up: [`NeighborState::Resolving`] at
    /// [`RESOLUTION_WAIT_LIMIT`], otherwise [`NeighborState::Failed`].
    pub(crate) fn given_up_in(&self, host: IpAddr) -> NeighborState {
        self.gated
            .get(&host)
            .and_then(|neighbor| self.given_up.get(neighbor))
            .copied()
            .unwrap_or(NeighborState::Failed)
    }

    /// Why `host` went unreached, given its neighbour's `state`, naming the
    /// gateway if the host waited on one.
    pub(crate) fn unreached(&self, host: IpAddr, state: NeighborState) -> String {
        unreached(host, self.gated.get(&host).copied(), state)
    }
}

/// Why `host` went unreached, given its `neighbor`'s `state`, naming the
/// neighbour if it is a gateway.
pub(crate) fn unreached(host: IpAddr, neighbor: Option<IpAddr>, state: NeighborState) -> String {
    let resolution = if host.is_ipv4() { "ARP" } else { "NDP" };
    let how = match state {
        NeighborState::Failed => format!("no {resolution} reply"),
        _ => format!("{resolution} pending"),
    };
    match neighbor.filter(|neighbor| *neighbor != host) {
        Some(gateway) => format!("{how} from gateway {gateway}"),
        None => how,
    }
}

/// Asks for the neighbour of every host in `hosts` at once and waits until
/// each has answered or been given up: one resolution's wait, or two where any
/// went unanswered once (see [`NEIGHBOR_ROUNDS`]). Returns the gates for the
/// pass's probes, and the unreachable hosts, each with why.
///
/// For a pass that cannot hold a probe as the port scans do. Through the
/// kernel it waits for nothing, since the kernel asks only once a probe is
/// written: it reads the table once and opens the gates of hosts whose
/// neighbour is held there. Waits at most [`RESOLUTION_WAIT_LIMIT`] a
/// resolution (see [`NeighborGates::admit`]), and ends early, with the rest
/// unresolved, when the scan is stopped.
pub(crate) async fn resolve_ahead(
    ctx: &ScanContext,
    watch: Option<&NeighborWatch>,
    resolver: &mut SourceResolver,
    hosts: impl IntoIterator<Item = IpAddr>,
) -> (NeighborGates, BTreeMap<IpAddr, String>) {
    let mut gates = NeighborGates::default();
    let mut unanswered = BTreeMap::new();
    let mut waiting: Vec<IpAddr> = hosts.into_iter().collect();
    if let Some(watch @ NeighborWatch::Kernel(table)) = watch {
        gates.open_held(watch, table, resolver, &waiting);
        return (gates, unanswered);
    }
    while !waiting.is_empty() && !ctx.handle.should_stop() {
        let now = Instant::now();
        waiting.retain(|host| match gates.admit(watch, resolver, *host, now) {
            Admission::Send => false,
            Admission::Hold(_) => true,
            Admission::Unreachable => {
                unanswered.insert(*host, gates.refusal(*host));
                false
            }
        });
        if !waiting.is_empty() {
            tokio::time::sleep(NEIGHBOR_RECHECK).await;
        }
    }
    (gates, unanswered)
}

/// Waits until a probe to `host` may be sent. Errs with the reason if its
/// neighbour was given up on, or with `None` if the scan was stopped.
///
/// For the trace, which probes one host at a time and does not read send
/// times. Bounded by [`RESOLUTION_WAIT_LIMIT`] a resolution (see
/// [`NeighborGates::admit`]).
pub(crate) async fn admit_waiting(
    gates: &mut NeighborGates,
    ctx: &ScanContext,
    watch: Option<&NeighborWatch>,
    resolver: &mut SourceResolver,
    host: IpAddr,
) -> Result<(), Option<String>> {
    loop {
        match gates.admit(watch, resolver, host, Instant::now()) {
            Admission::Send => return Ok(()),
            Admission::Unreachable => {
                return Err(Some(gates.refusal(host)));
            }
            Admission::Hold(ready) => {
                if ctx.handle.should_stop() {
                    return Err(None);
                }
                tokio::time::sleep_until(ready.into()).await;
            }
        }
    }
}

/// Hands each of `probes` to `send` once its host's neighbour and the scan's
/// probe spacing allow, in order per host. Returns the hosts whose neighbour
/// was given up on, each with why; they are sent nothing more.
///
/// Each round sends every probe whose neighbour has answered and whose slot is
/// free, then waits [`NEIGHBOR_RECHECK`], or less if a held slot frees sooner.
/// A wave of new neighbours thus costs one resolution's wait, or two where any
/// went unanswered once. For the filter probes, which send each probe once and
/// do not read send times. A stop drops the unsent probes and ends a wait at
/// once.
///
/// A probe's slot is claimed before its neighbour is asked about, since
/// admitting it can start a resolution only its own write completes. The slot
/// is refunded if the probe is held or `send` reports it did not reach the
/// wire.
pub(crate) async fn send_when_admitted<P>(
    gates: &mut NeighborGates,
    ctx: &ScanContext,
    watch: Option<&NeighborWatch>,
    resolver: &mut SourceResolver,
    probes: Vec<(IpAddr, P)>,
    mut send: impl FnMut(IpAddr, P) -> bool,
) -> BTreeMap<IpAddr, String> {
    let mut unreached = BTreeMap::new();
    let mut held = probes;
    loop {
        let now = Instant::now();
        let mut wake = now + NEIGHBOR_RECHECK;
        let mut still = Vec::new();
        for (host, probe) in held {
            if unreached.contains_key(&host) {
                continue;
            }
            // Per probe: a round can hold every probe of a wide scan.
            if ctx.handle.should_stop() {
                return unreached;
            }
            let claimed = match ctx.probe_ready_at(host, now) {
                Some(ready) => Err(ready),
                None => ctx.claim_probe(host),
            };
            let claim = match claimed {
                Ok(claim) => claim,
                Err(ready) => {
                    wake = wake.min(ready);
                    still.push((host, probe));
                    continue;
                }
            };
            match gates.admit(watch, resolver, host, now) {
                Admission::Send => {
                    if !send(host, probe) {
                        ctx.refund_probe(claim);
                    }
                }
                Admission::Hold(_) => {
                    ctx.refund_probe(claim);
                    still.push((host, probe));
                }
                Admission::Unreachable => {
                    ctx.refund_probe(claim);
                    unreached.insert(host, gates.refusal(host));
                }
            }
        }
        held = still;
        if held.is_empty() || ctx.handle.should_stop() {
            return unreached;
        }
        ctx.handle
            .or_stopped(tokio::time::sleep_until(wake.into()))
            .await;
    }
}

/// The neighbour `host`'s probes wait on, which keys its gate. On the
/// kernel's path the host if on-link, else its gateway from the routing table;
/// for a frame sender the host, whose next hop the sender finds itself. `None`
/// where no neighbour stands in the way.
fn neighbor_of(watch: &NeighborWatch, resolver: &SourceResolver, host: IpAddr) -> Option<IpAddr> {
    match watch {
        NeighborWatch::Kernel(_) if resolver.is_on_link(host) => Some(host),
        NeighborWatch::Kernel(table) => table.next_hop(host),
        NeighborWatch::Frames(_) => Some(host),
    }
}

/// Where the resolution of `host`'s neighbour stands: the kernel's entry for
/// `neighbor` from a reading taken after `asked` and no older than
/// [`NEIGHBOR_RECHECK`], or the frame sender's resolution of the next hop from
/// `resolver`'s source to `host`.
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
    use crate::system::interface::{Link, LinkAddress};
    use crate::transport::kernel_neighbors::{KernelNeighbors, NeighborTable};
    use std::net::Ipv4Addr;

    const HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    /// A kernel watch whose table always shows [`HOST`] at `state`, and a
    /// resolver that puts [`HOST`] on-link.
    fn kernel_showing(state: NeighborState) -> (NeighborWatch, SourceResolver) {
        let table = KernelNeighbors::with_reader(Box::new(move || {
            Ok(NeighborTable::from([(HOST, state)]))
        }));
        let resolver = SourceResolver::from_links(&[Link::new("test0", 1).with_addresses(vec![
            LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
        ])]);
        (NeighborWatch::Kernel(table), resolver)
    }

    /// A resolution that never concludes is given up on at twice the longest
    /// any resolution takes.
    #[test]
    fn a_neighbour_that_never_concludes_is_given_up_on_at_the_limit() {
        let (watch, mut resolver) = kernel_showing(NeighborState::Resolving);
        let mut gates = NeighborGates::default();
        let start = Instant::now();

        assert_eq!(
            gates.admit(Some(&watch), &mut resolver, HOST, start),
            Admission::Send,
            "the first write is what starts the kernel's asking"
        );
        // After the first admission, which stamped the asking.
        let asked = Instant::now();
        assert!(
            matches!(
                gates.admit(Some(&watch), &mut resolver, HOST, start),
                Admission::Hold(_)
            ),
            "and the probes behind it wait while it runs"
        );
        assert!(
            matches!(
                gates.admit(Some(&watch), &mut resolver, HOST, asked + RESOLUTION_BUDGET),
                Admission::Hold(_)
            ),
            "a resolution's own budget is not yet cause to give up"
        );
        assert_eq!(
            gates.admit(
                Some(&watch),
                &mut resolver,
                HOST,
                asked + RESOLUTION_WAIT_LIMIT
            ),
            Admission::Unreachable,
            "a wait past any resolution's is an address nothing reaches"
        );
    }

    /// A resolution that never concluded is filed as pending, distinct from a
    /// neighbour that failed to answer.
    #[test]
    fn a_neighbour_given_up_at_the_limit_is_filed_pending_and_a_failed_one_not() {
        let (watch, mut resolver) = kernel_showing(NeighborState::Resolving);
        let mut gates = NeighborGates::default();
        let start = Instant::now();
        gates.admit(Some(&watch), &mut resolver, HOST, start);
        let limit = Instant::now() + RESOLUTION_WAIT_LIMIT;
        assert_eq!(
            gates.admit(Some(&watch), &mut resolver, HOST, limit),
            Admission::Unreachable
        );
        assert_eq!(gates.refusal(HOST), "ARP pending");

        let (watch, mut resolver) = kernel_showing(NeighborState::Failed);
        let mut gates = NeighborGates::default();
        gates.admit(Some(&watch), &mut resolver, HOST, start);
        gates.admit(Some(&watch), &mut resolver, HOST, Instant::now());
        assert_eq!(
            gates.admit(Some(&watch), &mut resolver, HOST, Instant::now()),
            Admission::Unreachable
        );
        assert_eq!(gates.refusal(HOST), "no ARP reply");
    }
}
