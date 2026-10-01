// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Address resolution on the frame path
//!
//! A sender that writes the Ethernet header itself must know the next hop's hardware
//! address before a probe can leave: an on-link destination's own, or a gateway's the
//! operating system did not know. This module asks for it, waits for the reply, and
//! remembers how each resolution went.
//!
//! Resolutions run concurrently, on one thread per link that sends every pending
//! resolution's requests on schedule and reads every reply. A scan that meets two
//! hundred dead neighbours waits one resolution's budget for all of them, and since a
//! silent neighbour holds nothing else up, the budget can be as long as the slowest
//! live neighbour needs; see [`ARP_TIMEOUT`].
//!
//! Two ways in. A scan asks where a resolution stands with [`Resolutions::state`],
//! which starts one where nothing is known, and sends nothing towards the neighbour
//! while it runs, holding a probe or asking for all its hosts first: the port scans,
//! the operating-system probes and the path probes do this, as they read the kernel's
//! table on Linux's raw path. A send nothing asked ahead of waits with
//! [`Resolutions::resolve`].

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::model::mac::MacAddr;
use crate::protocols::mac::IntoCoreMac;
use pnet_packet::Packet;
use pnet_packet::arp::{ArpOperations, ArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};

use crate::protocols::arp;
use crate::transport::capture::{self, FrameSink};
use crate::transport::kernel_neighbors::NeighborState;
use crate::transport::neighbor;
use crate::transport::probe::SendError;

/// How long a resolution waits for its neighbour's reply before giving up.
///
/// Three seconds, for two reasons. A Wi-Fi client in power save hears a broadcast only
/// when it wakes for the access point's DTIM beacon, which can be hundreds of
/// milliseconds off; a reply has been measured at 627 ms on an ordinary home network.
/// And three seconds is the evidence the kernel needs before it calls a neighbour
/// failed (three solicitations a second apart), which is the verdict a scan on Linux's
/// raw path reads from the kernel's table, so a dead neighbour is judged the same way
/// on either path.
///
/// Affordable because resolutions run concurrently and a scan sends nothing towards a
/// neighbour while it is asked, so a wave of dead neighbours pays the budget once. A
/// send that waits on a resolution pays it once per dead neighbour, and not again for
/// [`NEIGHBOR_UNREACHABLE_TTL`].
pub(crate) const ARP_TIMEOUT: Duration = Duration::from_secs(3);

/// How many times one resolution asks, spread evenly across [`ARP_TIMEOUT`]: at its
/// start, a second in, and two seconds in.
///
/// A lost request or reply is not rare: ARP is broadcast, and a switch under load
/// drops broadcast first. One lost frame would cost far more than the resolution: the
/// neighbour is remembered as unanswered for [`NEIGHBOR_UNREACHABLE_TTL`], leaving
/// every port of a live host unasked for that long.
///
/// Three, a second apart, as the kernel asks. A wired neighbour that will answer does
/// so in well under a millisecond, so a request unanswered for a second was lost; one
/// asleep on Wi-Fi gets each broadcast at its next beacon however often it is asked.
/// A dead address still costs exactly [`ARP_TIMEOUT`]: the requests share the wait.
const ARP_REQUESTS: u32 = 3;

/// How long a neighbour that did not answer its address resolution is left unasked.
///
/// Without it, every probe to a dead address, each port and each retry within a port,
/// would start and wait out its own resolution. With it, the first probe waits and
/// every probe behind it is turned away at once.
///
/// It ages out so a host that was down when first probed and has since come up is
/// found on a later pass of a long scan, and so a hardware address learned after a
/// transient failure is not shadowed for good. It is long enough that one scan's
/// repeated probes to an address, and their retries, all reuse the one failure.
const NEIGHBOR_UNREACHABLE_TTL: Duration = Duration::from_secs(30);

/// How long one read of a link's channel waits for a frame, so the thread driving its
/// resolutions wakes often enough to send each request and give up on each neighbour
/// on time.
const CHANNEL_READ_TIMEOUT: Duration = Duration::from_millis(50);

/// The longest [`Resolutions::resolve`] waits for a resolution to conclude.
///
/// A guard: the thread driving the link concludes every resolution within
/// [`ARP_TIMEOUT`] of its first request, plus one read, and refuses them if it panics.
/// This only matters if that thread stops without ending, as a read that never returns
/// would, so a send cannot hang on a resolution nothing drives.
const WAIT_GUARD: Duration = Duration::from_secs(10);

/// A link a resolution runs over: somewhere to put a request, and the frames that come
/// back.
///
/// The seam between the resolutions and their capture, so the request schedule can be
/// tested against neighbours that answer late, sometimes, or never.
pub(super) trait ResolutionLink: FrameSink {
    /// The next frame the link's filter admitted, or `None` once its read timeout
    /// passes with nothing.
    fn next_frame(&mut self) -> Option<&[u8]>;

    /// The time on the clock the link's reads wait against, which the request
    /// schedule and the timeout are both measured on.
    ///
    /// A real capture's reads take real time, so its clock is the real one. A
    /// simulated link keeps its own clock that its reads advance, so tests can check
    /// the schedule to the millisecond.
    fn now(&self) -> Instant {
        Instant::now()
    }
}

impl ResolutionLink for capture::FrameChannel {
    fn next_frame(&mut self) -> Option<&[u8]> {
        capture::FrameChannel::next_frame(self)
    }
}

/// Opens the link a resolution on the named interface runs over. The seam a test
/// replaces with a simulated segment.
///
/// Bound to unwind safety because the sender holding it is public, and its auto traits
/// carry whatever it holds.
pub(super) type Opener = Box<
    dyn Fn(&str) -> Result<Box<dyn ResolutionLink>, String>
        + Send
        + Sync
        + UnwindSafe
        + RefUnwindSafe,
>;

/// The one resolution to run: which neighbour, on which link, asked from which of this
/// host's addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ask {
    /// The interface the neighbour is on.
    pub(crate) interface: String,
    /// This host's hardware address on that interface.
    pub(crate) src_mac: MacAddr,
    /// This host's address on that interface's segment.
    pub(crate) src_ip: Ipv4Addr,
    /// The neighbour whose hardware address is wanted.
    pub(crate) target: Ipv4Addr,
}

impl Ask {
    /// The frames each of this resolution's scheduled requests puts on the wire: a
    /// broadcast, and for a neighbour heard from before, the same question addressed to
    /// the hardware address it gave then.
    ///
    /// The addressed copy is for a client asleep on Wi-Fi. An access point holds
    /// broadcast for such a client until its DTIM beacon, but a frame addressed to the
    /// client only until the client next wakes to check, which is sooner. The kernels
    /// re-confirm known neighbours the same way. The broadcast still goes, in case the
    /// address has moved to another machine.
    fn requests(&self) -> Vec<Vec<u8>> {
        let broadcast = arp::build_request(self.src_mac, self.src_ip, self.target);
        match neighbor::heard_neighbor(&self.interface, IpAddr::V4(self.target)) {
            Some(heard) => vec![
                arp::build_unicast_request(self.src_mac, heard, self.src_ip, self.target),
                broadcast,
            ],
            None => vec![broadcast],
        }
    }
}

/// The address resolutions one frame sender runs, on every link it sends on.
pub(crate) struct Resolutions {
    state: Mutex<State>,
    /// Signalled whenever a resolution concludes, for callers waiting in
    /// [`resolve`](Self::resolve).
    concluded: Condvar,
    open: Opener,
}

/// Everything behind the [`Resolutions`] lock.
#[derive(Default)]
struct State {
    links: HashMap<String, LinkResolutions>,
    unanswered: UnansweredNeighbors,
}

/// The resolutions on one link.
#[derive(Default)]
struct LinkResolutions {
    /// Every resolution still waiting for its reply, by the neighbour asked.
    pending: HashMap<Ipv4Addr, Pending>,
    /// Whether a thread is driving this link's resolutions. At most one is, and it runs
    /// while anything is pending; one that panics clears this as it unwinds (see
    /// [`UndrivenOnUnwind`]).
    driven: bool,
    /// Resolutions the link could not carry, and why: the link would not open, or
    /// would not take a request. Says nothing about the neighbour, so it is not
    /// remembered against it; a later ask asks again.
    refused: HashMap<Ipv4Addr, String>,
}

/// One resolution in flight.
struct Pending {
    /// The frames each scheduled request sends. See [`Ask::requests`].
    requests: Vec<Vec<u8>>,
    /// When its first request went out, on the link's clock; its budget runs from
    /// here. `None` until the driving thread has sent it.
    started: Option<Instant>,
    /// How many of its [`ARP_REQUESTS`] have gone out.
    sent: u32,
}

impl Resolutions {
    /// Resolutions over the system's own links, each opened for ARP when it first has
    /// one to run.
    pub(crate) fn from_system() -> Self {
        Self::over(Box::new(|interface| {
            // ARP alone: this channel only resolves next hops.
            capture::FrameChannel::open(interface, "arp", CHANNEL_READ_TIMEOUT)
                .map(|channel| Box::new(channel) as Box<dyn ResolutionLink>)
                .map_err(|error| format!("no datalink channel on {interface}: {error}"))
        }))
    }

    /// Resolutions over the links `open` opens.
    pub(super) fn over(open: Opener) -> Self {
        Self {
            state: Mutex::new(State::default()),
            concluded: Condvar::new(),
            open,
        }
    }

    /// Where the resolution of `ask`'s neighbour stands, starting one when nothing is
    /// known.
    ///
    /// [`Resolved`](NeighborState::Resolved) when a neighbour gave its address lately,
    /// to this sender or anything else in the process;
    /// [`Failed`](NeighborState::Failed) when a resolution went unanswered within
    /// [`NEIGHBOR_UNREACHABLE_TTL`]; [`Resolving`](NeighborState::Resolving) while one
    /// runs. `None` when the link refused to carry the last one, which says nothing
    /// about the neighbour: a send finds out for itself and reports the refusal.
    ///
    /// Never waits, so asking about many neighbours starts all their resolutions at
    /// once.
    pub(crate) fn state(self: &Arc<Self>, ask: &Ask) -> Option<NeighborState> {
        let target = IpAddr::V4(ask.target);
        if neighbor::learned_neighbor(&ask.interface, target).is_some() {
            return Some(NeighborState::Resolved);
        }
        let mut state = self.lock();
        if state
            .unanswered
            .is_fresh(&ask.interface, target, Instant::now())
        {
            return Some(NeighborState::Failed);
        }
        let link = state.links.entry(ask.interface.clone()).or_default();
        if link.pending.contains_key(&ask.target) {
            return Some(NeighborState::Resolving);
        }
        if link.refused.contains_key(&ask.target) {
            return None;
        }
        drop(self.begin(state, ask));
        Some(NeighborState::Resolving)
    }

    /// [`state`](Self::state), after first discarding this sender's record of an
    /// earlier unanswered resolution, so a new one starts.
    ///
    /// For a scan that treats one unanswered resolution as a reason to ask again. The
    /// record exists so the sender does not ask on every send; a caller that has
    /// decided to ask once more is the exception. A resolution already running is left
    /// to run.
    pub(crate) fn ask_again(self: &Arc<Self>, ask: &Ask) -> Option<NeighborState> {
        self.lock()
            .unanswered
            .clear(&ask.interface, IpAddr::V4(ask.target));
        self.state(ask)
    }

    /// The hardware address of `ask`'s neighbour, waiting for its resolution when
    /// nothing recent is known.
    ///
    /// A neighbour whose resolution went unanswered lately is refused at once as
    /// [`SendError::Unresolved`]. A link that would not carry the resolution gives
    /// [`SendError::Refused`], which says nothing about the neighbour and is not
    /// remembered against it.
    pub(crate) fn resolve(self: &Arc<Self>, ask: &Ask) -> Result<MacAddr, SendError> {
        let target = IpAddr::V4(ask.target);
        let give_up = Instant::now() + WAIT_GUARD;
        let mut state = self.lock();
        let link = state.links.entry(ask.interface.clone()).or_default();
        // A refusal on record is from an earlier resolution; the link may take this
        // one, so ask again.
        if !link.pending.contains_key(&ask.target) {
            link.refused.remove(&ask.target);
        }

        loop {
            if let Some(mac) = neighbor::learned_neighbor(&ask.interface, target) {
                return Ok(mac);
            }
            if state
                .unanswered
                .is_fresh(&ask.interface, target, Instant::now())
            {
                return Err(unanswered_neighbor(target, &ask.interface));
            }
            let link = state.links.entry(ask.interface.clone()).or_default();
            if let Some(reason) = link.refused.get(&ask.target) {
                return Err(SendError::Refused(format!(
                    "sending an ARP request: {reason}"
                )));
            }
            if !link.pending.contains_key(&ask.target) {
                state = self.begin(state, ask);
            }

            let left = give_up.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(SendError::Refused(format!(
                    "the address resolution of {target} on {} did not conclude",
                    ask.interface
                )));
            }
            state = self
                .concluded
                .wait_timeout(state, left)
                .unwrap_or_else(|held| held.into_inner())
                .0;
        }
    }

    /// Adds `ask` to its link's pending resolutions, and starts a thread to drive the
    /// link if none is.
    fn begin<'a>(
        self: &'a Arc<Self>,
        mut state: MutexGuard<'a, State>,
        ask: &Ask,
    ) -> MutexGuard<'a, State> {
        let link = state.links.entry(ask.interface.clone()).or_default();
        link.refused.remove(&ask.target);
        link.pending.insert(
            ask.target,
            Pending {
                requests: ask.requests(),
                started: None,
                sent: 0,
            },
        );
        if link.driven {
            return state;
        }
        link.driven = true;

        let resolutions = Arc::clone(self);
        let interface = ask.interface.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("zond-arp-{interface}"))
            .spawn(move || resolutions.drive_link(&interface));
        if let Err(error) = spawned {
            let link = state.links.entry(ask.interface.clone()).or_default();
            refuse_all(link, &format!("no thread to resolve on: {error}"));
            self.concluded.notify_all();
        }
        state
    }

    /// Opens `interface` and drives its resolutions until none is left.
    fn drive_link(&self, interface: &str) {
        let _released = UndrivenOnUnwind {
            resolutions: self,
            interface,
        };
        match (self.open)(interface) {
            Ok(mut link) => self.drive(interface, link.as_mut()),
            Err(reason) => {
                let mut state = self.lock();
                let link = state.links.entry(interface.to_owned()).or_default();
                refuse_all(link, &reason);
                link.driven = false;
                drop(state);
                self.concluded.notify_all();
            }
        }
    }

    /// Runs every resolution pending on `interface` over `link`: sends each one's
    /// requests as [`ARP_REQUESTS`] schedules them, reads the replies, and concludes
    /// each when its neighbour answers or its [`ARP_TIMEOUT`] passes. Returns once none
    /// is pending, having marked the link undriven.
    ///
    /// One loop serves every pending resolution, which is what makes a wave of dead
    /// neighbours cost one timeout: each resolution's budget runs from its own first
    /// request on the link's clock, and one read serves them all.
    fn drive<L: ResolutionLink + ?Sized>(&self, interface: &str, link: &mut L) {
        loop {
            let now = link.now();
            let (due, concluded, idle) = {
                let mut state = self.lock();
                let State { links, unanswered } = &mut *state;
                let resolutions = links.entry(interface.to_owned()).or_default();
                let step = step(&mut resolutions.pending, now);
                for target in &step.unanswered {
                    unanswered.note(interface, IpAddr::V4(*target), now);
                }
                // Decided under the lock a new resolution is queued under, so none is
                // left pending with nothing driving it.
                let idle = resolutions.pending.is_empty();
                if idle {
                    resolutions.driven = false;
                }
                (step.due, !step.unanswered.is_empty(), idle)
            };
            if concluded {
                self.concluded.notify_all();
            }
            if idle {
                return;
            }

            for frame in &due {
                if let Err(reason) = link.send_frame(frame) {
                    let mut state = self.lock();
                    let resolutions = state.links.entry(interface.to_owned()).or_default();
                    refuse_all(resolutions, &reason);
                    resolutions.driven = false;
                    drop(state);
                    self.concluded.notify_all();
                    return;
                }
            }

            let Some((address, mac)) = link.next_frame().and_then(parse_arp_reply) else {
                continue; // a read timeout, or somebody else's ARP
            };
            let mut state = self.lock();
            let resolutions = state.links.entry(interface.to_owned()).or_default();
            if resolutions.pending.remove(&address).is_some() {
                neighbor::learn_neighbor(interface, IpAddr::V4(address), mac);
                state.unanswered.clear(interface, IpAddr::V4(address));
                drop(state);
                self.concluded.notify_all();
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Nothing here panics while holding the lock, and every section leaves the
        // state whole between statements, so a poisoned lock's contents are sound.
        self.state.lock().unwrap_or_else(|held| held.into_inner())
    }
}

/// Releases a link whose driving thread unwinds: every resolution it was running is
/// refused, and the link is marked undriven.
///
/// Without it a panic in the thread (in the link's opener, or a capture binding's read
/// or write) would leave the link marked driven with nothing driving it, and no
/// resolution on it would start again for the sender's life: each send waiting on one
/// would sit out [`WAIT_GUARD`] and be refused.
///
/// The resolutions are refused, not handed to a fresh thread, so a fault that hits
/// every driver cannot become a loop of panicking threads. A refusal says nothing
/// about the neighbours, so none is remembered as unanswered, and the next ask starts
/// a new driver: the link stays usable, and each fault costs only the resolutions
/// running when it struck.
struct UndrivenOnUnwind<'a> {
    resolutions: &'a Resolutions,
    interface: &'a str,
}

impl Drop for UndrivenOnUnwind<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let mut state = self.resolutions.lock();
        let link = state.links.entry(self.interface.to_owned()).or_default();
        refuse_all(link, "the thread resolving on the link panicked");
        link.driven = false;
        drop(state);
        self.resolutions.concluded.notify_all();
    }
}

/// What one pass over a link's pending resolutions owes the wire, and which ones it
/// gave up on.
struct Step {
    /// The request frames due now, in the order they go out.
    due: Vec<Vec<u8>>,
    /// The neighbours whose budget ran out unanswered, taken off `pending`.
    unanswered: Vec<Ipv4Addr>,
}

/// Advances every resolution in `pending` to `now` on the link's clock: stamps the new
/// ones, collects the requests due, and concludes those whose [`ARP_TIMEOUT`] has
/// passed.
///
/// A request goes out once its share of the wait has begun. Reads end on the channel's
/// own timeout, so a request is at most that late.
fn step(pending: &mut HashMap<Ipv4Addr, Pending>, now: Instant) -> Step {
    let spacing = ARP_TIMEOUT / ARP_REQUESTS;
    let mut due = Vec::new();
    let mut unanswered = Vec::new();
    for (target, resolution) in pending.iter_mut() {
        let started = *resolution.started.get_or_insert(now);
        let elapsed = now.saturating_duration_since(started);
        if elapsed >= ARP_TIMEOUT {
            unanswered.push(*target);
        } else if resolution.sent < ARP_REQUESTS && elapsed >= spacing * resolution.sent {
            due.extend(resolution.requests.iter().cloned());
            resolution.sent += 1;
        }
    }
    for target in &unanswered {
        pending.remove(target);
    }
    Step { due, unanswered }
}

/// Ends every resolution pending on `link` as refused for `reason`.
fn refuse_all(link: &mut LinkResolutions, reason: &str) {
    for (target, _) in link.pending.drain() {
        link.refused.insert(target, reason.to_owned());
    }
}

/// The neighbours whose address resolution last went unanswered, so the sender can
/// decline to ask again until the record ages out. Keyed by `(interface, next-hop IP)`,
/// like the learned addresses.
///
/// The negative half of the learned-address table: it holds the instant a resolution
/// timed out. See [`NEIGHBOR_UNREACHABLE_TTL`] for why an entry expires.
#[derive(Default)]
struct UnansweredNeighbors {
    seen: HashMap<(String, IpAddr), Instant>,
}

impl UnansweredNeighbors {
    /// Records that resolution for `next_hop` on `interface` went unanswered at `at`.
    fn note(&mut self, interface: &str, next_hop: IpAddr, at: Instant) {
        self.seen.insert((interface.to_string(), next_hop), at);
    }

    /// Forgets any record for `next_hop` on `interface`, for a neighbour that has since
    /// answered.
    fn clear(&mut self, interface: &str, next_hop: IpAddr) {
        self.seen.remove(&(interface.to_string(), next_hop));
    }

    /// Whether `next_hop` on `interface` went unanswered within
    /// [`NEIGHBOR_UNREACHABLE_TTL`] of `now`, so it should not be asked again yet.
    fn is_fresh(&self, interface: &str, next_hop: IpAddr, now: Instant) -> bool {
        self.seen
            .get(&(interface.to_string(), next_hop))
            .is_some_and(|at| now.saturating_duration_since(*at) < NEIGHBOR_UNREACHABLE_TTL)
    }
}

/// The refusal for a next hop that did not answer its address resolution, whether the
/// resolution just timed out or a recent one already did.
///
/// [`Unresolved`](SendError::Unresolved) because it is a fact about that address: the
/// neighbour is not answering. A scan reads it as it reads no route.
///
/// Not [`Unroutable`](SendError::Unroutable), which a transport holding a raw socket
/// behind this sender takes as a reason to try the socket. This is the answer, and
/// asking the kernel again would turn one dead host into ports that disagree about it.
pub(super) fn unanswered_neighbor(next_hop: IpAddr, interface: &str) -> SendError {
    SendError::Unresolved(format!(
        "{next_hop} did not answer address resolution on {interface}"
    ))
}

/// Reads an Ethernet frame as an ARP reply, returning the address it answers for and
/// the hardware address it gives.
fn parse_arp_reply(frame: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    (arp.get_operation() == ArpOperations::Reply).then(|| {
        (
            arp.get_sender_proto_addr(),
            arp.get_sender_hw_addr().into_core(),
        )
    })
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
pub(crate) mod tests {
    use super::*;
    use crate::protocols::mac::IntoPnetMac;
    use pnet_packet::arp::{ArpHardwareTypes, MutableArpPacket};
    use pnet_packet::ethernet::MutableEthernetPacket;

    /// This host's hardware address on every simulated segment.
    const LOCAL_MAC: MacAddr = MacAddr::new(0x02, 0, 0, 0, 0, 0x01);
    /// This host's address on every simulated segment.
    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    /// Builds an Ethernet-framed ARP reply from `sender_ip`/`sender_mac`.
    pub(crate) fn arp_reply(sender_ip: Ipv4Addr, sender_mac: MacAddr) -> Vec<u8> {
        let mut buf = vec![0u8; 42];
        {
            let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
            eth.set_ethertype(EtherTypes::Arp);
            eth.set_source(sender_mac.into_pnet());
            eth.set_destination(LOCAL_MAC.into_pnet());
        }
        {
            let mut a = MutableArpPacket::new(&mut buf[14..]).unwrap();
            a.set_hardware_type(ArpHardwareTypes::Ethernet);
            a.set_protocol_type(EtherTypes::Ipv4);
            a.set_hw_addr_len(6);
            a.set_proto_addr_len(4);
            a.set_operation(ArpOperations::Reply);
            a.set_sender_hw_addr(sender_mac.into_pnet());
            a.set_sender_proto_addr(sender_ip);
            a.set_target_proto_addr(LOCAL_IP);
        }
        buf
    }

    /// The resolution of `target` on `interface`, asked from this host.
    pub(crate) fn ask(interface: &str, target: Ipv4Addr) -> Ask {
        Ask {
            interface: interface.to_owned(),
            src_mac: LOCAL_MAC,
            src_ip: LOCAL_IP,
            target,
        }
    }

    /// How long one quiet read of a [`Segment`] takes on its clock.
    ///
    /// Shorter than [`CHANNEL_READ_TIMEOUT`], as a capture woken early by a frame for
    /// another host would be, so the loop runs many reads per request and a schedule
    /// keyed to read boundaries instead of time would show.
    const QUIET_READ: Duration = Duration::from_millis(5);

    /// How one simulated neighbour answers.
    #[derive(Clone, Copy)]
    pub(crate) enum Answers {
        /// The request numbered this and none before it, as a neighbour behind a
        /// segment that lost the earlier ones would.
        Request(u32),
        /// The first request, this long after it was sent, as a client asleep on
        /// Wi-Fi hears a broadcast only at the next DTIM beacon.
        After(Duration),
        /// The first request addressed to it (not broadcast), as a client asleep on
        /// Wi-Fi hears a frame for it at its next wake.
        OnlyAddressed,
        /// Every request sent at or after this instant on the link's clock, and none
        /// before, as a machine asleep through the first asking would. Kept across the
        /// link's openings, since the clock is the process's.
        AwakeFrom(Instant),
    }

    /// A segment of simulated neighbours on its own clock: each quiet read advances it
    /// by [`QUIET_READ`], and it records the time of every request it is sent, by
    /// neighbour. Or, where a test needs real elapsed time, on the real clock, each
    /// quiet read sleeping for [`QUIET_READ`].
    pub(crate) struct Segment {
        neighbours: HashMap<Ipv4Addr, (MacAddr, Answers)>,
        /// Every request sent, by neighbour: when, and whether it was addressed to
        /// the neighbour or broadcast.
        pub(crate) asked: HashMap<Ipv4Addr, Vec<(Duration, bool)>>,
        replies: Vec<(Duration, Vec<u8>)>,
        reply: Vec<u8>,
        epoch: Instant,
        pub(crate) clock: Duration,
        real_time: bool,
    }

    impl Segment {
        pub(crate) fn new() -> Self {
            Self {
                neighbours: HashMap::new(),
                asked: HashMap::new(),
                replies: Vec::new(),
                reply: Vec::new(),
                epoch: Instant::now(),
                clock: Duration::ZERO,
                real_time: false,
            }
        }

        /// This segment, taking real time for its quiet reads.
        pub(crate) fn in_real_time(mut self) -> Self {
            self.real_time = true;
            self
        }

        pub(crate) fn with(mut self, ip: Ipv4Addr, mac: MacAddr, answers: Answers) -> Self {
            self.neighbours.insert(ip, (mac, answers));
            self
        }

        fn requests_to(&self, ip: Ipv4Addr) -> u32 {
            self.asked.get(&ip).map_or(0, |sent| sent.len() as u32)
        }

        /// The time on this segment's clock since it was built.
        fn elapsed(&self) -> Duration {
            self.now().saturating_duration_since(self.epoch)
        }
    }

    impl FrameSink for Segment {
        fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
            let eth = EthernetPacket::new(frame).expect("a frame");
            let request = ArpPacket::new(eth.payload()).expect("an ARP request");
            let target = request.get_target_proto_addr();
            let addressed = eth.get_destination().into_core() != MacAddr::BROADCAST;
            let at = self.elapsed();
            self.asked.entry(target).or_default().push((at, addressed));
            let Some(&(mac, answers)) = self.neighbours.get(&target) else {
                return Ok(());
            };
            let asked = self.requests_to(target);
            let answer_at = match answers {
                Answers::Request(n) => (asked == n).then_some(at),
                Answers::After(delay) => (asked == 1).then_some(at + delay),
                Answers::OnlyAddressed => {
                    let first_addressed = self.asked[&target]
                        .iter()
                        .filter(|(_, addressed)| *addressed)
                        .count()
                        == 1;
                    (addressed && first_addressed).then_some(at)
                }
                Answers::AwakeFrom(awake) => (self.now() >= awake).then_some(at),
            };
            if let Some(at) = answer_at {
                self.replies.push((at, arp_reply(target, mac)));
            }
            Ok(())
        }
    }

    impl ResolutionLink for Segment {
        fn next_frame(&mut self) -> Option<&[u8]> {
            let now = self.elapsed();
            if let Some(ready) = self.replies.iter().position(|(at, _)| *at <= now) {
                self.reply = self.replies.remove(ready).1;
                return Some(&self.reply);
            }
            if self.real_time {
                std::thread::sleep(QUIET_READ);
            } else {
                self.clock += QUIET_READ;
            }
            None
        }

        fn now(&self) -> Instant {
            if self.real_time {
                Instant::now()
            } else {
                self.epoch + self.clock
            }
        }
    }

    /// Resolutions over nothing: a test runs them itself over a [`Segment`], and no
    /// thread is meant to open a link.
    fn undriven() -> Arc<Resolutions> {
        Arc::new(Resolutions::over(Box::new(|interface| {
            Err(format!("{interface} is driven by the test"))
        })))
    }

    /// Queues `asks` on `resolutions` as [`Resolutions::state`] would, with the link
    /// already marked driven so no thread starts for it.
    fn queue(resolutions: &Arc<Resolutions>, asks: &[Ask]) {
        for ask in asks {
            let mut state = resolutions.lock();
            state.links.entry(ask.interface.clone()).or_default().driven = true;
            drop(resolutions.begin(state, ask));
        }
    }

    /// A client that hears a broadcast only at its next DTIM beacon, later than half a
    /// second, is resolved.
    ///
    /// A phone in power save has been measured answering a broadcast ARP after 627 ms.
    #[test]
    fn a_neighbour_that_hears_a_broadcast_only_at_its_next_beacon_is_resolved() {
        let interface = "test-doze0";
        let dozing = Ipv4Addr::new(192, 0, 2, 20);
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 0x20);
        let resolutions = undriven();
        let mut segment =
            Segment::new().with(dozing, mac, Answers::After(Duration::from_millis(627)));

        queue(&resolutions, &[ask(interface, dozing)]);
        resolutions.drive(interface, &mut segment);

        assert_eq!(
            neighbor::learned_neighbor(interface, IpAddr::V4(dozing)),
            Some(mac)
        );
        assert_eq!(
            resolutions.state(&ask(interface, dozing)),
            Some(NeighborState::Resolved)
        );
    }

    /// Neighbours that never answer, asked together, cost one timeout between them, and
    /// each is asked on schedule and given up.
    ///
    /// Measured on the link's clock, so each figure is exact: a request goes out on the
    /// first read boundary at or after its share of the wait begins, and the wave ends
    /// on the first at or after the timeout.
    #[test]
    fn neighbours_that_never_answer_cost_one_timeout_together() {
        let interface = "test-dead0";
        let dead: Vec<Ipv4Addr> = (10..=209).map(|n| Ipv4Addr::new(192, 0, 2, n)).collect();
        let resolutions = undriven();
        let mut segment = Segment::new();

        let asks: Vec<Ask> = dead.iter().map(|ip| ask(interface, *ip)).collect();
        queue(&resolutions, &asks);
        resolutions.drive(interface, &mut segment);

        assert!(
            segment.clock >= ARP_TIMEOUT && segment.clock < ARP_TIMEOUT + QUIET_READ,
            "{} dead neighbours cost {:?}",
            dead.len(),
            segment.clock
        );
        let spacing = ARP_TIMEOUT / ARP_REQUESTS;
        for ip in &dead {
            let sent = &segment.asked[ip];
            assert_eq!(sent.len() as u32, ARP_REQUESTS, "{ip} asked on schedule");
            for (n, (at, _)) in sent.iter().enumerate() {
                let due = spacing * n as u32;
                assert!(
                    *at >= due && *at < due + QUIET_READ,
                    "{ip}'s request due at {due:?} went out at {at:?}"
                );
            }
            assert_eq!(
                resolutions.state(&ask(interface, *ip)),
                Some(NeighborState::Failed),
                "{ip} given up"
            );
        }
    }

    /// A neighbour whose first requests were lost is still resolved by a later one,
    /// and asked no further.
    ///
    /// With one request per resolution, a single dropped broadcast would mark a live
    /// host unanswered and turn its every port away for the next half-minute.
    #[test]
    fn a_neighbour_answering_only_a_later_request_is_resolved() {
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 0xc8);
        // At least the second, so a schedule of one request cannot pass for lack of a
        // later request to test.
        for answers in 2..=ARP_REQUESTS.max(2) {
            let interface = format!("test-lossy{answers}");
            let ip = Ipv4Addr::new(192, 0, 2, 200);
            let resolutions = undriven();
            let mut segment = Segment::new().with(ip, mac, Answers::Request(answers));

            queue(&resolutions, &[ask(&interface, ip)]);
            resolutions.drive(&interface, &mut segment);

            assert_eq!(
                neighbor::learned_neighbor(&interface, IpAddr::V4(ip)),
                Some(mac),
                "answering request {answers}"
            );
            assert_eq!(segment.requests_to(ip), answers, "and asked no further");
        }
    }

    /// A neighbour heard from before is asked at the hardware address it gave then as
    /// well as by broadcast, and one that hears only the addressed request is resolved
    /// by it.
    ///
    /// An access point holds broadcast for a client asleep on Wi-Fi until its DTIM
    /// beacon, and a frame for the client itself only until its next wake.
    #[test]
    fn a_neighbour_heard_before_is_also_asked_at_its_own_address() {
        let interface = "test-heard2";
        let ip = Ipv4Addr::new(192, 0, 2, 30);
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 0x30);
        let resolutions = undriven();
        let mut segment = Segment::new().with(ip, mac, Answers::OnlyAddressed);

        queue(&resolutions, &[ask(interface, ip)]);
        resolutions.drive(interface, &mut segment);
        assert_eq!(
            segment.asked[&ip].iter().filter(|(_, to)| *to).count(),
            0,
            "a neighbour never heard from has no address to ask at"
        );
        assert!(neighbor::learned_neighbor(interface, IpAddr::V4(ip)).is_none());

        // Heard once, long enough ago that the address is no longer framed to.
        neighbor::learn_neighbor_at(
            interface,
            IpAddr::V4(ip),
            mac,
            Instant::now() - Duration::from_secs(3600),
        );
        assert!(neighbor::learned_neighbor(interface, IpAddr::V4(ip)).is_none());
        let resolutions = undriven();
        let mut segment = Segment::new().with(ip, mac, Answers::OnlyAddressed);

        queue(&resolutions, &[ask(interface, ip)]);
        resolutions.drive(interface, &mut segment);

        assert_eq!(
            neighbor::learned_neighbor(interface, IpAddr::V4(ip)),
            Some(mac)
        );
        assert_eq!(
            segment.asked[&ip],
            vec![(Duration::ZERO, true), (Duration::ZERO, false)],
            "asked at its own address, and by broadcast beside it"
        );
    }

    /// A neighbour that went unanswered is not asked again while the record stands,
    /// and is refused at once with the resolution's verdict.
    ///
    /// Without the record, every probe to a dead address would start and wait out its
    /// own resolution: one per port, and one per retry within a port.
    #[test]
    fn a_dead_neighbour_is_asked_once_and_refused_after() {
        let interface = "test-dead1";
        let ip = Ipv4Addr::new(192, 0, 2, 40);
        let resolutions = undriven();
        let mut segment = Segment::new();

        queue(&resolutions, &[ask(interface, ip)]);
        resolutions.drive(interface, &mut segment);

        for _ in 0..5 {
            assert_eq!(
                resolutions.state(&ask(interface, ip)),
                Some(NeighborState::Failed)
            );
            assert!(matches!(
                resolutions.resolve(&ask(interface, ip)),
                Err(SendError::Unresolved(_))
            ));
        }
        assert!(
            resolutions.lock().links[interface].pending.is_empty(),
            "nothing asked again"
        );
    }

    /// A link that will not open ends its resolutions as refusals, which say nothing
    /// about the neighbours: nothing is held against them, and the next ask asks again.
    #[test]
    fn a_link_that_will_not_open_refuses_without_writing_anyone_off() {
        let interface = "test-shut0";
        let ip = Ipv4Addr::new(192, 0, 2, 50);
        let resolutions = undriven();

        assert!(matches!(
            resolutions.resolve(&ask(interface, ip)),
            Err(SendError::Refused(_))
        ));
        assert_eq!(resolutions.state(&ask(interface, ip)), None);
        assert!(
            !resolutions
                .lock()
                .unanswered
                .is_fresh(interface, IpAddr::V4(ip), Instant::now()),
            "a refusal is not an unanswered neighbour"
        );
    }

    /// A neighbour a sweep heard is framed to at once, with no resolution run and an
    /// earlier unanswered one not held against it.
    ///
    /// A Wi-Fi client in power save answers a sweep that waits seconds and can miss a
    /// later broadcast. Asking again for what the sweep already heard would write such
    /// a host off for the half-minute an unanswered resolution is remembered.
    #[test]
    fn a_neighbour_a_sweep_heard_is_not_asked_again() {
        let interface = "test-heard0";
        let ip = Ipv4Addr::new(192, 0, 2, 31);
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 0x31);
        // Resolutions that refuse any resolution they are asked to run.
        let resolutions = undriven();
        resolutions
            .lock()
            .unanswered
            .note(interface, IpAddr::V4(ip), Instant::now());
        neighbor::learn_neighbor(interface, IpAddr::V4(ip), mac);

        assert_eq!(resolutions.resolve(&ask(interface, ip)).ok(), Some(mac));
        assert_eq!(
            resolutions.state(&ask(interface, ip)),
            Some(NeighborState::Resolved)
        );
    }

    /// What one sender resolves, the next is given: every transport a scan opens
    /// builds its own sender, and each asking afresh costs a whole resolution per
    /// neighbour per pass.
    #[test]
    fn a_resolution_one_sender_ran_serves_the_next() {
        let interface = "test-heard1";
        let ip = Ipv4Addr::new(192, 0, 2, 32);
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 0x32);
        let first = undriven();
        let mut segment = Segment::new().with(ip, mac, Answers::Request(1));
        queue(&first, &[ask(interface, ip)]);
        first.drive(interface, &mut segment);

        // Resolutions that refuse any resolution they are asked to run.
        let second = undriven();
        assert_eq!(second.resolve(&ask(interface, ip)).ok(), Some(mac));
    }

    /// A link whose driver panics at its first request, as a capture binding that met
    /// something it could not handle would.
    struct Panicking;

    impl FrameSink for Panicking {
        fn send_frame(&mut self, _frame: &[u8]) -> Result<(), String> {
            panic!("the link's driver panics, as the test asks");
        }
    }

    impl ResolutionLink for Panicking {
        fn next_frame(&mut self) -> Option<&[u8]> {
            None
        }
    }

    /// A driver that panics refuses what it was running, at once, and the link
    /// resolves again on the next ask.
    ///
    /// Left marked driven, the link would start no resolution for the rest of the
    /// sender's life: every send to a neighbour on it would wait out the guard and be
    /// refused.
    #[test]
    fn a_driver_that_panics_releases_its_link() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let interface = "test-panic0";
        let ip = Ipv4Addr::new(192, 0, 2, 60);
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 0x60);
        let opened = Arc::new(AtomicUsize::new(0));
        let opens = Arc::clone(&opened);
        let resolutions = Arc::new(Resolutions::over(Box::new(move |_| {
            let link: Box<dyn ResolutionLink> = if opens.fetch_add(1, Ordering::SeqCst) == 0 {
                Box::new(Panicking)
            } else {
                Box::new(
                    Segment::new()
                        .in_real_time()
                        .with(ip, mac, Answers::Request(1)),
                )
            };
            Ok(link)
        })));

        let first = resolutions.resolve(&ask(interface, ip));
        assert!(
            matches!(&first, Err(SendError::Refused(reason)) if reason.contains("panicked")),
            "the resolution the driver was running is refused for the panic: {first:?}"
        );
        assert!(
            !resolutions
                .lock()
                .unanswered
                .is_fresh(interface, IpAddr::V4(ip), Instant::now()),
            "and not held against the neighbour"
        );
        assert_eq!(
            resolutions.resolve(&ask(interface, ip)).ok(),
            Some(mac),
            "the next ask drives the link again"
        );
        assert_eq!(opened.load(Ordering::SeqCst), 2);
    }

    /// The record is a next hop's, on its own interface, and ages out.
    #[test]
    fn a_failure_is_remembered_per_next_hop_and_link_until_it_ages_out() {
        let dead = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 201));
        let t0 = Instant::now();
        let mut unanswered = UnansweredNeighbors::default();

        assert!(!unanswered.is_fresh("en0", dead, t0), "nothing on record");
        unanswered.note("en0", dead, t0);
        assert!(unanswered.is_fresh("en0", dead, t0 + Duration::from_secs(1)));
        assert!(!unanswered.is_fresh("en0", other, t0), "another next hop");
        assert!(!unanswered.is_fresh("en1", dead, t0), "another link");
        assert!(
            !unanswered.is_fresh("en0", dead, t0 + NEIGHBOR_UNREACHABLE_TTL),
            "aged out"
        );
        unanswered.clear("en0", dead);
        assert!(
            !unanswered.is_fresh("en0", dead, t0),
            "cleared by an answer"
        );
    }

    #[test]
    fn parses_an_arp_reply_and_nothing_else() {
        let ip = Ipv4Addr::new(192, 0, 2, 200);
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 0x01);
        assert_eq!(parse_arp_reply(&arp_reply(ip, mac)), Some((ip, mac)));

        let request = arp::build_request(mac, ip, LOCAL_IP);
        assert_eq!(parse_arp_reply(&request), None, "a request");

        let mut ipv4 = vec![0u8; 42];
        MutableEthernetPacket::new(&mut ipv4)
            .unwrap()
            .set_ethertype(EtherTypes::Ipv4);
        assert_eq!(parse_arp_reply(&ipv4), None, "not ARP");
    }
}
