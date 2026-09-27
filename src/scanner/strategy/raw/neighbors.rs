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
//! Every pass asks per probe, with [`NeighborGates::admit`], so one rule holds
//! a probe whichever path it leaves by: the first write to a neighbour the
//! kernel does not hold goes, since the write is what starts the kernel's
//! asking, and every probe behind it waits on the verdict. A neighbour that
//! does not answer is asked a second time before the verdict is taken; see
//! [`NEIGHBOR_ROUNDS`]. What a pass does
//! with a probe held is its own. The port scans and the echo probe send it
//! later. The trace and the filter probes wait for it, with [`admit_waiting`]
//! and [`send_when_admitted`], since neither reads the moment a probe left.
//! The series probe drops it: the spacing of its samples is the measurement,
//! and a sample sent late costs the reading where a sample missing costs one
//! sample.
//!
//! Those three also ask for every host they are about to probe at once, with
//! [`resolve_ahead`], before their first probe: the series probe per batch,
//! the trace and the filter probes per run. A frame sender runs every
//! resolution asked of it together, so the pass waits once for all of them.
//! The kernel asks only once a probe is written, so its table is read once
//! instead, and the hosts whose neighbour it already holds are asked freely
//! from then on. Either way a wave of new neighbours costs one resolution's
//! wait rather than one each, two where any is silent, and a neighbour that
//! never answers is an address nothing reaches, with nothing sent to it past
//! the writes that asked.

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
/// Short, because a neighbour that is there answers in well under a
/// millisecond and the hold is then the whole of what it cost; long enough
/// that holding a thousand ports of a dead host costs a table read per hold
/// rather than one per port, since every probe held for the same instant is
/// answered from the same reading.
pub(crate) const NEIGHBOR_RECHECK: Duration = Duration::from_millis(50);

/// The longest one resolution of a neighbour holds a probe: the
/// resolution's budget, which is the kernel's three requests a second apart
/// on either path, and the one recheck it takes to read the verdict.
pub(crate) const RESOLUTION_BUDGET: Duration = ARP_TIMEOUT.saturating_add(NEIGHBOR_RECHECK);

/// How many resolutions of one neighbour a pass waits out unanswered before
/// it gives the neighbour up, and every host behind it with it.
///
/// Two, because one unanswered resolution is three seconds of a neighbour's
/// silence, and a live machine can be silent that long: a wired interface or
/// switch port in power save sleeping through three broadcasts, or a switch
/// under load dropping them. Given up on the first, such a host is
/// unreachable for the rest of the scan with every port unasked, on a silence
/// that has ended a moment later. Two resolutions are six requests across six
/// seconds, about the evidence macOS's own kernel takes, five requests a
/// second apart, before it gives a neighbour up. A third would cost every
/// dead neighbour another resolution to learn what two said.
///
/// The second is asked as soon as the first is given up, not after a pause:
/// a pause is time in which nobody asks, and buys nothing a request sent in
/// it would not. On the kernel's path a write starts it, as it started the
/// first, since Linux asks afresh for a neighbour it gave up on when a write
/// needs one; a frame sender is told to set its memory of the first aside.
/// Either way the second resolutions of a wave of dead neighbours run
/// together as the first did, so what they cost a pass is one more
/// resolution's wait for the whole wave, not one each.
pub(crate) const NEIGHBOR_ROUNDS: u8 = 2;

/// The longest a probe can be held while its neighbour is asked for, every
/// resolution of it: [`RESOLUTION_BUDGET`] for each of [`NEIGHBOR_ROUNDS`].
///
/// What a pass with a fixed deadline allows its first probes on top of their
/// own schedule, so a probe held for a neighbour that answers late, or only
/// when asked again, is not left with no time to be answered in.
pub(crate) const NEIGHBOR_BUDGET: Duration =
    RESOLUTION_BUDGET.saturating_mul(NEIGHBOR_ROUNDS as u32);

/// The longest one resolution of a neighbour may be read as still running
/// before the neighbour is given up on and the host behind it filed
/// unreached: twice [`RESOLUTION_BUDGET`].
///
/// Both resolutions conclude on their own within their budget, the kernel's
/// after its third request and the frame path's after its own, so a wait past
/// it is no longer a neighbour being asked for. It is a resolution that will
/// not conclude: a driver wedged in a read that never returns keeps its
/// resolutions pending for as long as anything reads them. Without a bound of
/// its own, a pass waiting on one would wait until the scan stopped, and a
/// port scan would hold the host's probes until its deadline. Twice the budget
/// leaves a resolution concluding late on a loaded machine read as what it
/// concluded, and still bounds the wait by seconds.
pub(crate) const RESOLUTION_WAIT_LIMIT: Duration = RESOLUTION_BUDGET.saturating_mul(2);

/// How many of the kernel's hold-downs on one host's neighbour a pass meets,
/// the last read as the kernel's verdict on the host.
///
/// Two, because the second is a different fact from the first. The first
/// hold-down rests on a resolution the pass may never have seen, asked for by
/// another process or an earlier pass at whatever moment the neighbour was
/// asleep. It is waited out, and the host's next probe has the kernel ask
/// afresh. A second comes only once a resolution begun after the first
/// hold-down ended has gone unanswered as well: two resolutions a hold-down
/// apart, and a third would cost another hold-down to learn what those two
/// said. A resolution the kernel gives up on at one of this pass's own writes
/// refuses that write with `EHOSTUNREACH`, not with a hold-down, and is read
/// as no route at once.
///
/// What a live neighbour asleep through one resolution costs a pass is one
/// hold-down: see
/// [`kernel_neighbors::hold_down`](crate::transport::kernel_neighbors::hold_down).
pub(crate) const HELD_DOWN_REFUSALS: u8 = 2;

/// The kernel's hold-downs on the neighbours of the hosts one pass probes:
/// which hosts are held, until when, and how often each has been.
///
/// A send the kernel refuses for a hold-down
/// ([`SendError::HeldDown`](crate::transport::probe::SendError::HeldDown),
/// `EHOSTDOWN` on macOS) sent nothing, and the first says nothing about the
/// host; see [`HELD_DOWN_REFUSALS`]. Every pass that can meet one keeps
/// these, so the same refusal is read the same way whichever pass met it:
/// the host is held for the whole hold-down, sent nothing while it lasts,
/// and asked again after it.
#[derive(Debug)]
pub(crate) struct HoldDowns {
    /// Each host held down, by the host.
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
    /// A refusal while the host is held is the same hold-down, met by a send
    /// made before the first refusal was heard, as a pass whose sends run side
    /// by side makes them.
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
    /// The neighbour was asked for at `at`, by the one probe handed to the
    /// kernel or by asking the frame sender, and no reading since has shown
    /// it answering.
    Asked {
        /// When it was asked for, which a reading of the kernel's table has
        /// to postdate to show the entry the probe's write created.
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
    /// Each neighbour's gate, by the neighbour.
    gates: HashMap<IpAddr, NeighborGate>,
    /// The neighbour each gated host's probes wait on, which keys its gate:
    /// the host itself, or on the kernel's path the gateway it is routed
    /// through.
    gated: HashMap<IpAddr, IpAddr>,
    /// Each neighbour [`admit`](Self::admit) gave up on, with where its
    /// resolution stood when it did: failed, or still resolving at
    /// [`RESOLUTION_WAIT_LIMIT`]. Kept so the reason a host behind it is
    /// filed under says which, since the two are different faults: a
    /// neighbour that is not there, and a resolution that never concluded.
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
    /// - **failed again**, and the address is unreachable: the neighbour was
    ///   asked three times across three seconds, twice, and said nothing. So
    ///   is one still read as resolving [`RESOLUTION_WAIT_LIMIT`] after it was
    ///   last asked for, whose resolution is not going to conclude, so no
    ///   caller waits on one resolution for longer than that whatever the
    ///   resolution does.
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
        let (asked, round) = match self.gates.get(&neighbor) {
            Some(NeighborGate::Open) => return Admission::Send,
            Some(NeighborGate::Asked { at, round }) => (*at, *round),
            None if matches!(watch, NeighborWatch::Kernel(_)) => {
                // Stamped here rather than from `now`, which the caller read
                // before this batch of sends: the table has to be read after
                // this probe's write to show the entry the write creates.
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
                    // The write is what has the kernel ask again, as it was
                    // what had it ask the first time.
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

    /// When [`admit`](Self::admit) last asked for a neighbour again, once:
    /// for a pass that gives its deadline the time the second resolution
    /// takes.
    pub(crate) fn take_asked_again(&mut self) -> Option<Instant> {
        self.asked_again.take()
    }

    /// Opens the gate of every host in `hosts` whose neighbour the kernel's
    /// table, read once, already holds a hardware address for, so a write to
    /// it leaves and its host is asked freely.
    ///
    /// The rest are left as nothing is known of them: the first probe to each
    /// starts the kernel's asking, and those behind it wait on the verdict.
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
    /// answering: true of a host [`admit`](Self::admit) just let a probe
    /// through to because that probe's write is what asks for it.
    pub(crate) fn is_waiting(&self, host: IpAddr) -> bool {
        self.gated.get(&host).is_some_and(|neighbor| {
            matches!(self.gates.get(neighbor), Some(NeighborGate::Asked { .. }))
        })
    }

    /// Why `host` is unreachable, for a host [`admit`](Self::admit) turned
    /// away: in the words of [`unreached`](Self::unreached), for where its
    /// neighbour's resolution stood when it was given up on.
    pub(crate) fn refusal(&self, host: IpAddr) -> String {
        self.unreached(host, self.given_up_in(host))
    }

    /// Where the resolution of `host`'s neighbour stood when
    /// [`admit`](Self::admit) gave it up: [`NeighborState::Resolving`] for
    /// one given up at [`RESOLUTION_WAIT_LIMIT`], and otherwise
    /// [`NeighborState::Failed`], the one other reason it turns a host away.
    pub(crate) fn given_up_in(&self, host: IpAddr) -> NeighborState {
        self.gated
            .get(&host)
            .and_then(|neighbor| self.given_up.get(neighbor))
            .copied()
            .unwrap_or(NeighborState::Failed)
    }

    /// Why `host` went unreached, for a neighbour whose resolution stands at
    /// `state`: in the resolution's own word, and naming the gateway where
    /// the host's probes waited on one.
    pub(crate) fn unreached(&self, host: IpAddr, state: NeighborState) -> String {
        unreached(host, self.gated.get(&host).copied(), state)
    }
}

/// Why `host` went unreached, for a `neighbor` whose resolution stands at
/// `state`: in the resolution's own word, and naming the gateway where the
/// neighbour is one rather than the host itself.
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

/// Asks for the neighbour of every host in `hosts` at once, and waits until
/// each has answered or been given up, which is one resolution's wait for all
/// of them, or two where any went unanswered once; see [`NEIGHBOR_ROUNDS`].
/// Returns the gates the pass admits its probes through from then on,
/// and the hosts whose neighbour was given up, which nothing reaches from
/// here, each with why.
///
/// For a pass that cannot hold a probe as the port scans do; see the module
/// documentation. Through the kernel it waits for nothing, since the kernel
/// asks only once a probe is written: it reads the kernel's table once, and
/// opens the gate of every host whose neighbour is held there, so those are
/// asked freely and only the rest wait on the resolution their first probe
/// starts. Waits no longer than [`RESOLUTION_WAIT_LIMIT`] a resolution, past
/// which [`NeighborGates::admit`] gives a neighbour up, and ends early, with the
/// rest unresolved, when the scan is stopped.
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

/// Waits until a probe to `host` may be handed over, and returns why not
/// where it may not be at all: its neighbour was given up on, or the scan was
/// stopped while it waited.
///
/// For a pass that sends its probes to one host at a time and reads nothing
/// from when a probe left, the trace. Bounded by [`RESOLUTION_WAIT_LIMIT`] a
/// resolution, past which [`NeighborGates::admit`] gives the neighbour up.
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

/// Hands each of `probes` to `send` as its host's neighbour allows, in order
/// for each host, and returns the hosts whose neighbour was given up on, each
/// with why, which are sent nothing more.
///
/// The probes held go together: each pass over them sends every one whose
/// neighbour has answered and waits one [`NEIGHBOR_RECHECK`] for the rest, so
/// the first probes of every new neighbour start their resolutions together
/// and a wave of them costs one resolution's wait, or two where any went
/// unanswered once. For a pass that sends each
/// probe once and reads nothing from when it left, the filter probes. Probes
/// not yet sent when the scan is stopped are dropped.
pub(crate) async fn send_when_admitted<P>(
    gates: &mut NeighborGates,
    ctx: &ScanContext,
    watch: Option<&NeighborWatch>,
    resolver: &mut SourceResolver,
    probes: Vec<(IpAddr, P)>,
    mut send: impl FnMut(IpAddr, P),
) -> BTreeMap<IpAddr, String> {
    let mut unreached = BTreeMap::new();
    let mut held = probes;
    loop {
        let now = Instant::now();
        let mut still = Vec::new();
        for (host, probe) in held {
            if unreached.contains_key(&host) {
                continue;
            }
            // Read before each probe rather than once a pass, since a pass
            // can hold every probe of a wide scan at once.
            if ctx.handle.should_stop() {
                return unreached;
            }
            match gates.admit(watch, resolver, host, now) {
                Admission::Send => send(host, probe),
                Admission::Hold(_) => still.push((host, probe)),
                Admission::Unreachable => {
                    unreached.insert(host, gates.refusal(host));
                }
            }
        }
        held = still;
        if held.is_empty() || ctx.handle.should_stop() {
            return unreached;
        }
        tokio::time::sleep(NEIGHBOR_RECHECK).await;
    }
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

    /// A kernel watch whose table shows [`HOST`]'s neighbour at `state` on
    /// every read, and a resolver that puts [`HOST`] on a link of this host's.
    fn kernel_showing(state: NeighborState) -> (NeighborWatch, SourceResolver) {
        let table = KernelNeighbors::with_reader(Box::new(move || {
            Ok(NeighborTable::from([(HOST, state)]))
        }));
        let resolver = SourceResolver::from_links(&[Link::new("test0", 1).with_addresses(vec![
            LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
        ])]);
        (NeighborWatch::Kernel(table), resolver)
    }

    /// A resolution that never concludes, a driver wedged in a read or a table
    /// that never moves, is given up on once it has run twice as long as any
    /// resolution takes, rather than holding the host's probes until the scan
    /// itself stops.
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
        // Read after that first admission, which stamped when the neighbour
        // was asked for.
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

    /// A host turned away because its neighbour's resolution never concluded
    /// is filed as that, not as a neighbour that failed to answer. The two
    /// are different faults to whoever reads why: one is a machine that is
    /// not there, the other a resolution the kernel was still running.
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
