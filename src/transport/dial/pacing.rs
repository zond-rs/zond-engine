// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The slot every connection and datagram claims before it leaves
//!
//! A scan can keep a gap between the probes it aims at one host, and another between
//! any two it sends; see
//! [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval)
//! and [`ZondConfig::probe_interval`](crate::config::ZondConfig::probe_interval). One
//! gate on the scan's context keeps both, and the raw passes ask it before each frame.
//! Connections and datagrams the operating system sends for the engine ask the same
//! gate here: each is opened through an [`Egress`](super::Egress) the scan handed out,
//! and its socket methods require a [`Slot`]. Any pass that dials a target has to take
//! a slot, so none can run a slow scan at full speed.
//!
//! **One slot is one probe as the target sees it:** one connection attempt, whose SYN
//! is what arrives, or the first datagram of one exchange. The conversation over an
//! answered connection is not spaced, and neither is a datagram's reply. A socket this
//! machine refused before anything left gives its slot back; a target's refusal and a
//! connect that timed out keep theirs.
//!
//! **Waiting is not the target's time.** Every connection and exchange runs on its own
//! clocks (a connect budget, a collection ceiling, a detection's deadline), and a wait
//! for a slot counted against them would turn a slow preset into lost identifications
//! and false silences. A wait happens before the clocks of its connection start. The
//! clocks of a whole conversation, already running when a later connection waits,
//! pause for the wait: the async ones read [`timeout`], and the blocking ones the time
//! [`held_here`] says this thread spent waiting.
//!
//! **A wait ends with the scan.** A scan asked to stop, or past its budget, ends every
//! wait at once, and a probe still waiting when its host outlives its budget stays
//! unsent. Either way it returns [`Withheld`], which a caller files as a question not
//! asked, never as the target's silence.
//!
//! A scan that keeps no gap hands out egresses with no gate. A slot then holds nothing
//! and is taken without a lock or a clock read, and [`timeout`] behaves exactly as
//! [`tokio::time::timeout`].

use std::cell::Cell;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::system::descriptors;

/// The longest a blocking thread waiting for a slot sleeps before it looks again, and
/// the longest an async clock paused for a wait sleeps before it checks the wait again.
///
/// So a stop is noticed within this, even when the gap is minutes long. A tenth of a
/// second is below what anyone waiting on a stop notices, and costs nothing a scan
/// spaced this far apart could measure.
const SLOT_WAIT_STEP: Duration = Duration::from_millis(100);

/// What a scan answers a probe waiting for its slot: whether the slot is free, whether
/// the scan has stopped, and whether the probe's host has run out of its budget.
///
/// A trait because the scan's context lives in the layer above this one. The context is
/// the one implementation; a test may supply another.
pub(crate) trait Pacer: Send + Sync {
    /// Takes the slot of one probe to `peer`, or says when one will be free.
    fn claim(&self, peer: IpAddr) -> Result<Claim, Instant>;

    /// Gives back the slot `claim` took, for a probe that never left.
    fn refund(&self, claim: Claim);

    /// Whether `peer` has spent its budget, filing it as left early the first time
    /// it has.
    fn host_expired(&self, peer: IpAddr) -> bool;

    /// Whether the scan has been asked to stop, or has outlived its budget.
    fn should_stop(&self) -> bool;

    /// Resolves once the scan is asked to stop or outlives its budget.
    fn stopping(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// A slot a [`Pacer`] handed out: the address the probe was aimed at, and the instant
/// it was let go, which giving it back needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Claim {
    pub(crate) address: IpAddr,
    pub(crate) at: Instant,
}

/// The scan an [`Egress`](super::Egress) claims its slots from.
///
/// Built only for a scan that keeps a gap, once per destination a pass dials, and
/// shared by every connection made there.
#[derive(Clone)]
pub(crate) struct Gate(Arc<dyn Pacer>);

impl Gate {
    /// The gate `pacer` keeps.
    pub(crate) fn new(pacer: Arc<dyn Pacer>) -> Self {
        Self(pacer)
    }

    /// Waits for, and takes, the slot of one probe to `peer`.
    ///
    /// Not fair: two probes waiting on one slot both wake when it frees, and whichever
    /// claims first leaves. The gap between probes is bounded; their order is not.
    async fn wait(&self, peer: IpAddr) -> Result<Claim, Withheld> {
        let pacer = &self.0;
        loop {
            let ready = match pacer.claim(peer) {
                Ok(claim) => return Ok(claim),
                Err(ready) => ready,
            };
            if pacer.host_expired(peer) {
                return Err(Withheld::HostExpired);
            }
            let _held = Waiting::begin();
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(ready.into()) => {}
                () = pacer.stopping() => return Err(Withheld::Stopped),
            }
        }
    }

    /// [`wait`](Self::wait) for a thread that may block, as the detections do.
    ///
    /// Sleeps in steps no longer than [`SLOT_WAIT_STEP`], so a stop is noticed within
    /// one, and adds what it slept to [`held_here`].
    fn wait_blocking(&self, peer: IpAddr) -> Result<Claim, Withheld> {
        let pacer = &self.0;
        loop {
            let ready = match pacer.claim(peer) {
                Ok(claim) => return Ok(claim),
                Err(ready) => ready,
            };
            if pacer.should_stop() {
                return Err(Withheld::Stopped);
            }
            if pacer.host_expired(peer) {
                return Err(Withheld::HostExpired);
            }
            let asleep = Instant::now();
            std::thread::sleep(ready.saturating_duration_since(asleep).min(SLOT_WAIT_STEP));
            HELD_HERE.with(|held| held.set(held.get() + asleep.elapsed()));
        }
    }
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gate")
    }
}

/// Two egresses hold the same gate when they claim from the same scan.
impl PartialEq for Gate {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Gate {}

/// A gate is asked one atomic thing at a time (a slot claimed or given back), under
/// locks that are retaken past a panic, so an unwind through a probe that held one
/// leaves nothing half done. Asserted here because the scan's context behind it holds
/// maps and channels the compiler cannot see through, and without it every probe
/// carrying an egress, a detection's included, would stop being unwind-safe.
impl std::panic::UnwindSafe for Gate {}
impl std::panic::RefUnwindSafe for Gate {}

/// The slot one probe was given: what a socket towards a target is opened with, and
/// the only way to open one.
///
/// Dropping it spends the slot, as a probe that reached the wire does, whatever came
/// back. A probe this machine refused before anything left gives it back with
/// [`refund`](Self::refund), or through [`settle`](Self::settle), which decides from
/// the attempt's outcome.
///
/// Holds nothing for a scan that keeps no gap, or for a connection made outside a
/// scan.
#[must_use = "a slot is a probe the scan has let leave; one that never did gives it back"]
#[derive(Debug)]
pub(crate) struct Slot {
    claim: Option<(Gate, Claim)>,
}

impl Slot {
    /// A slot no gate gave, for a connection nothing paces.
    const UNPACED: Self = Self { claim: None };

    /// A slot no gate gave, for a test dialling a socket of its own.
    #[cfg(test)]
    pub(crate) fn unpaced() -> Self {
        Self::UNPACED
    }

    /// Gives the slot back, for a probe that never reached the wire.
    pub(crate) fn refund(self) {
        if let Some((gate, claim)) = self.claim {
            gate.0.refund(claim);
        }
    }

    /// Gives the slot back where `outcome` is a refusal this machine made before
    /// anything left, and spends it otherwise; see [`never_left`].
    pub(crate) fn settle<T>(self, outcome: &io::Result<T>) {
        if let Err(e) = outcome
            && never_left(e)
        {
            self.refund();
        }
    }

    /// Whether this is a slot for a probe to `peer`, or one nothing paces.
    pub(super) fn is_for(&self, peer: IpAddr) -> bool {
        self.claim
            .as_ref()
            .is_none_or(|(_, claim)| claim.address == peer)
    }
}

impl super::Egress {
    /// Waits for the slot of one probe to `peer`, and takes it.
    ///
    /// Taken before the clocks of its connection or exchange start, and before the
    /// process's descriptor budget is asked, so neither a connect budget nor another
    /// pass's socket waits out the gap. Free at once for an egress no scan paces.
    ///
    /// [`Withheld`] where the scan stopped, or the host ran out of its budget, first:
    /// the probe was never sent.
    pub(crate) async fn slot(&self, peer: IpAddr) -> Result<Slot, Withheld> {
        let Some(gate) = &self.gate else {
            return Ok(Slot::UNPACED);
        };
        // Boxed: the wait holds two timers and a stop notification, and every
        // connection future in the engine holds this one, which a scan keeping no gap
        // never builds.
        let claim = Box::pin(gate.wait(peer)).await?;
        Ok(Slot {
            claim: Some((gate.clone(), claim)),
        })
    }

    /// [`slot`](Self::slot) for a caller holding a blocking socket; the time it waits
    /// is added to [`held_here`].
    pub(crate) fn slot_blocking(&self, peer: IpAddr) -> Result<Slot, Withheld> {
        let Some(gate) = &self.gate else {
            return Ok(Slot::UNPACED);
        };
        let claim = gate.wait_blocking(peer)?;
        Ok(Slot {
            claim: Some((gate.clone(), claim)),
        })
    }

    /// Whether a scan's gap paces this egress's probes.
    pub(crate) fn is_paced(&self) -> bool {
        self.gate.is_some()
    }
}

/// Whether `error` is a refusal this machine made before anything left, which spends
/// no slot.
///
/// Only what no packet can cause: no descriptor, a source taken or not held here, an
/// argument or route the kernel refused outright, and a connect that met itself. A
/// missing route and a firewall's reject share their error codes on every platform,
/// and a one-step connect cannot say which half failed, so those keep their slot. That
/// risks a longer gap than asked for; giving it back could risk a shorter one.
pub(crate) fn never_left(error: &io::Error) -> bool {
    descriptors::exhausted(error)
        || super::SourcePortHeld::of(error).is_some()
        || super::met_itself(error)
        || matches!(
            error.kind(),
            io::ErrorKind::AddrInUse
                | io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::InvalidInput
                | io::ErrorKind::PermissionDenied
        )
}

/// Why a probe waiting for its slot was never sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Withheld {
    /// The scan was asked to stop, or outlived its own budget.
    Stopped,
    /// The host ran out of its budget, and the scan has filed it as left early.
    HostExpired,
}

impl std::fmt::Display for Withheld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Stopped => "the scan stopped before the probe's turn came",
            Self::HostExpired => "the host ran out of its budget before the probe's turn came",
        })
    }
}

impl std::error::Error for Withheld {}

impl From<Withheld> for io::Error {
    fn from(withheld: Withheld) -> Self {
        io::Error::other(withheld)
    }
}

thread_local! {
    /// How long this thread has waited for slots, all told.
    static HELD_HERE: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

/// How long the calling thread has spent waiting for slots, all told.
///
/// A blocking clock reads it twice and deducts the difference from what it has spent:
/// a detection's deadline, and the wait it times on a port to tell a dead one. Never
/// moves on a thread nothing paces.
pub(crate) fn held_here() -> Duration {
    HELD_HERE.with(Cell::get)
}

tokio::task_local! {
    /// The time the conversation on this task has spent waiting for slots, which
    /// [`timeout`] deducts from every clock it runs inside it. `None` inside a
    /// conversation nothing paces.
    static HELD: Option<Arc<Held>>;
}

/// Runs `conversation` with its clocks paused while any of its connections waits for a
/// slot, where `egress` is paced; see [`timeout`].
///
/// Set around a whole conversation, such as an identification, whose ceiling is
/// already running when its later connections dial. An unpaced conversation never
/// waits, so nothing is tracked and its clocks run as [`tokio::time::timeout`] does.
///
/// A plain function returning the scope's own future, with one future type either way,
/// so a caller holds one copy of the conversation's state.
pub(crate) fn holding<F: Future>(
    egress: &super::Egress,
    conversation: F,
) -> tokio::task::futures::TaskLocalFuture<Option<Arc<Held>>, F> {
    HELD.scope(egress.is_paced().then(Arc::default), conversation)
}

/// The waits of the conversation running on this task, where it is paced.
fn held() -> Option<Arc<Held>> {
    HELD.try_with(Option::clone).ok().flatten()
}

/// The waits for slots made by one conversation's connections, which may overlap.
#[derive(Debug, Default)]
pub(crate) struct Held {
    state: Mutex<HeldState>,
}

/// What [`Held`] keeps, behind its lock.
#[derive(Debug, Default)]
struct HeldState {
    /// The time covered by waits that have ended.
    total: Duration,
    /// How many waits are under way now.
    waiting: usize,
    /// When the first of those began, which is when the clocks paused.
    since: Option<tokio::time::Instant>,
}

impl Held {
    /// The time the conversation has spent with a wait under way, as of now, and
    /// whether one still is.
    fn so_far(&self) -> (Duration, bool) {
        let state = self.state.lock().unwrap_or_else(|held| held.into_inner());
        let ongoing = state.since.map_or(Duration::ZERO, |since| since.elapsed());
        (state.total + ongoing, state.waiting > 0)
    }
}

/// One wait for a slot, marked on its conversation while it lasts.
struct Waiting(Option<Arc<Held>>);

impl Waiting {
    fn begin() -> Self {
        let held = held();
        if let Some(held) = &held {
            let mut state = held.state.lock().unwrap_or_else(|held| held.into_inner());
            if state.waiting == 0 {
                state.since = Some(tokio::time::Instant::now());
            }
            state.waiting += 1;
        }
        Self(held)
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let Some(held) = &self.0 else {
            return;
        };
        let mut state = held.state.lock().unwrap_or_else(|held| held.into_inner());
        state.waiting -= 1;
        if state.waiting == 0
            && let Some(since) = state.since.take()
        {
            state.total += since.elapsed();
        }
    }
}

/// Where [`timeout`] ran out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Elapsed;

/// [`tokio::time::timeout`] for a clock inside a conversation whose later connections
/// may wait for their slots: `limit` is time the conversation had the target, and every
/// slot wait made inside it while it ran is added.
///
/// Outside a paced [`holding`] this behaves as `tokio::time::timeout`.
///
/// Takes the closure that makes the work and calls it inside, so the future holds the
/// work once: an async body keeps its arguments apart from what it awaits, and an
/// identification's collection is most of the size of every connection future that
/// carries one.
pub(crate) async fn timeout<F: Future>(
    limit: Duration,
    work: impl FnOnce() -> F,
) -> Result<F::Output, Elapsed> {
    let held = held();
    let so_far = || {
        held.as_ref()
            .map_or((Duration::ZERO, false), |held| held.so_far())
    };
    let started = tokio::time::Instant::now();
    let (before, _) = so_far();
    let work = work();
    tokio::pin!(work);
    loop {
        let (now_held, waiting) = so_far();
        let due = started + limit + (now_held - before);
        let now = tokio::time::Instant::now();
        if now >= due && !waiting {
            return Err(Elapsed);
        }
        // While a wait is under way the due time moves with it, so check again a step
        // later.
        let wake = match waiting {
            true => due.max(now + SLOT_WAIT_STEP),
            false => due,
        };
        tokio::select! {
            biased;
            done = &mut work => return Ok(done),
            () = tokio::time::sleep_until(wake) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::session::ScanSession;
    use crate::transport::dial::Egress;
    use std::net::Ipv4Addr;

    const HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    /// **A scan that keeps no gap hands out an egress with nothing to claim from**, so
    /// its connections are made without pacing.
    #[tokio::test]
    async fn a_scan_keeping_no_gap_dials_as_ever() {
        let (_session, ctx) = ScanSession::new();
        let egress = ctx.egress_toward(HOST);
        assert_eq!(egress, Egress::KERNEL);
        assert!(!egress.is_paced());
        let slot = egress.slot(HOST).await.expect("free at once");
        assert!(slot.claim.is_none(), "a slot holding a claim");
    }

    /// **A clock inside a paced conversation does not count the conversation's wait
    /// for a slot**, so a connection held for the gap keeps all of its own time; the
    /// same clock outside a paced conversation runs out as any timeout does.
    #[tokio::test]
    async fn a_held_clock_stands_still_while_a_connection_waits_for_its_slot() {
        let gap = Duration::from_millis(400);
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(gap))
            .build();
        let egress = ctx.egress_toward(HOST);
        let first = egress.slot(HOST).await.expect("the first is free");
        drop(first);

        // A limit a quarter of the gap: the second connection's slot wait is four
        // times what the clock allows.
        let limit = gap / 4;
        let dialled = holding(
            &egress,
            timeout(limit, || async {
                let slot = egress.slot(HOST).await.expect("a slot after the gap");
                drop(slot);
            }),
        )
        .await;
        assert_eq!(dialled, Ok(()), "the gap was charged to the conversation");

        let unheld = timeout(limit, || tokio::time::sleep(gap)).await;
        assert_eq!(unheld, Err(Elapsed), "a clock nothing holds ran on");
    }

    /// **A thread waiting for its slot stops waiting when the scan stops**, and its
    /// probe is withheld, however long the gap.
    #[test]
    fn a_blocking_wait_ends_with_the_scan() {
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(Duration::from_secs(3600)))
            .build();
        let egress = ctx.egress_toward(HOST);
        drop(egress.slot_blocking(HOST).expect("the first is free"));

        let handle = ctx.handle.clone();
        let stopper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            handle.abort();
        });
        let asked = Instant::now();
        let held_before = held_here();
        let waited = egress.slot_blocking(HOST);
        stopper.join().expect("the stopper joins");

        assert_eq!(waited.map(drop), Err(Withheld::Stopped));
        assert!(
            asked.elapsed() < Duration::from_secs(2),
            "the wait outlived the stop by {:?}",
            asked.elapsed()
        );
        assert!(
            held_here() - held_before >= Duration::from_millis(150),
            "the thread's held time missed the wait"
        );
    }

    /// **A probe still waiting when its host runs out of its budget is never sent**,
    /// and the host is filed as left early, as every pass files one.
    #[tokio::test]
    async fn a_wait_ends_when_the_host_runs_out_of_its_budget() {
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(Duration::from_secs(3600)))
            .host_timeout(Some(Duration::from_millis(200)))
            .build();
        assert!(!ctx.host_expired(HOST), "the host's clock starts");
        let egress = ctx.egress_toward(HOST);
        drop(egress.slot(HOST).await.expect("the first is free"));

        tokio::time::sleep(Duration::from_millis(250)).await;
        let waited = tokio::time::timeout(Duration::from_secs(5), egress.slot(HOST))
            .await
            .expect("the wait ended");
        assert_eq!(waited.map(drop), Err(Withheld::HostExpired));
        assert!(
            ctx.take_timed_out().contains(&HOST),
            "the host filed as left early"
        );
    }

    /// A slot given back leaves the next probe to the host free at once; one spent
    /// holds it for the whole gap.
    #[tokio::test]
    async fn a_refused_attempt_gives_its_slot_back() {
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(Duration::from_secs(3600)))
            .build();
        let egress = ctx.egress_toward(HOST);

        let refused = egress.slot(HOST).await.expect("the first is free");
        refused.settle::<()>(&Err(io::Error::from(io::ErrorKind::AddrNotAvailable)));
        let sent = tokio::time::timeout(Duration::from_secs(1), egress.slot(HOST))
            .await
            .expect("a refused attempt's slot came back")
            .expect("a slot");
        sent.settle::<()>(&Err(io::Error::from(io::ErrorKind::ConnectionRefused)));
        assert!(
            ctx.probe_ready_at(HOST, Instant::now()).is_some(),
            "a target's refusal gave its slot back"
        );
    }
}
