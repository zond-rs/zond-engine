// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What became of a target, and whether a resume may skip it
//!
//! The one correctness-critical distinction in the whole resume design, and the
//! one the rest of the engine deliberately does not make.
//!
//! ## The engine conflates five fates on purpose
//!
//! A raw port scan gives the same verdict — whatever
//! [`silence_means`](crate::model::technique::TcpScanTechnique::silence_means)
//! returns for the technique — to a target whose retry budget ran out, a target
//! still mid-schedule when the scan stopped, and a target sitting in the queue
//! that was never probed at all. `RawPortScan::resolve_unasked` says why, and it
//! is right:
//!
//! > *"a port reported as this scan's silence alongside a stop reason of
//! > `DeadlineExpired` is a fact somebody can act on, and an absent port is
//! > not."*
//!
//! For a **report**, that is the correct trade: a too-kind verdict beats a
//! silently truncated port list, which is the one shortfall a reader cannot see.
//!
//! ## The journal must not
//!
//! For a **resume**, the same conflation is the worst bug this feature can have.
//! A watermark that advances over a target nobody ever probed produces a second
//! sitting that skips it permanently and a merged report that claims coverage it
//! never had — a scan that silently omits targets and reports success. That is
//! strictly worse than having no resume at all, because it is invisible.
//!
//! So the fate of a target has to be recorded where the fate is *known*, which
//! is not where the verdict is written.
//!
//! ## The trap
//!
//! **Do not hook settlement onto `record_port`.** Every one of the five fates
//! below reaches it, with the same verdict, and hooking there would look correct
//! in every test that does not truncate a scan. Settlement is decided at the
//! ledger — [`ProbeLedger`](crate::scanner::pacing::retry::ProbeLedger) already
//! draws the line exactly right, and says so in its own documentation:
//!
//! | Fate | Decided at | Settled |
//! |---|---|---|
//! | [`Answered`](Fate::Answered) | `ledger.resolve(..) -> Some` | **yes** |
//! | [`Exhausted`](Fate::Exhausted) | `Due::Exhausted` — *"the moment a verdict of 'filtered' is earned rather than assumed"* | **yes** |
//! | [`Interrupted`](Fate::Interrupted) | `ledger.drain_unresolved()` — *"stopping before they could be resolved on their own"* | no |
//! | [`Unasked`](Fate::Unasked) | `resolve_unasked` — still queued, never sent | no |
//! | [`Unroutable`](Fate::Unroutable) | the composite router, or no route to the host | no |
//!
//! The ledger's own words are the specification. `Due::Exhausted` is *earned*;
//! `drain_unresolved` is *assumed*. Only what is earned may advance a watermark.
//!
//! ## Why re-probing a not-settled target is cheap
//!
//! The pessimism costs almost nothing. [`Interrupted`](Fate::Interrupted) is
//! bounded by what was in flight when the scan stopped, and
//! [`Unasked`](Fate::Unasked) by what the dispatcher had buffered — together a
//! few tens of thousands of targets against a plan of millions. Redoing seconds
//! of a six-hour scan is the correct price for never skipping one.

use std::net::IpAddr;
use std::sync::Mutex;

use crate::model::port::Protocol;

/// What became of one target in one sitting.
///
/// Ordered by how much the scan actually learned, least to most, so a target
/// that acquires two fates across a merge keeps the stronger. That ordering is
/// load-bearing rather than cosmetic: a resumed scan re-probes what the first
/// sitting left [`Interrupted`](Self::Interrupted), and the second sitting's
/// [`Answered`](Self::Answered) must win.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fate {
    /// The router had no scanner for this target's protocol, or the host had no
    /// route. Nothing was sent and nothing was learned.
    ///
    /// **Not settled**, though a resume may well reach the same conclusion: the
    /// reason is usually a missing privilege or a missing route, and both can
    /// differ between sittings. Deciding that for the target rather than
    /// re-asking would bake one run's environment into every later one.
    Unroutable,

    /// Still queued when the scan stopped. Never sent, so its verdict in the
    /// report is the scan's silence and is, in the engine's own words,
    /// "arguably too kind".
    ///
    /// **Not settled.** This is the fate that makes hooking settlement onto the
    /// verdict dangerous: it carries a verdict indistinguishable from an earned
    /// one.
    Unasked,

    /// Outstanding mid-retry-schedule when the scan stopped, and given the
    /// silence verdict by `resolve_remaining` rather than by its budget running
    /// out.
    ///
    /// **Not settled.** This is precisely the gap
    /// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort) warns
    /// about — and leaving it unsettled is how the watermark closes it.
    Interrupted,

    /// The retry budget was spent without an answer. Silence, asked for as many
    /// times as the policy allows.
    ///
    /// **Settled.** Waiting longer in this sitting could not have changed it,
    /// which is the same standard
    /// [`StopReason::AttemptsSpent`](crate::scanner::report::StopReason::AttemptsSpent)
    /// applies to a whole run.
    Exhausted,

    /// The target answered.
    ///
    /// **Settled**, and the only fate that settles positively.
    Answered,
}

impl Fate {
    /// Whether a resume may skip this target.
    ///
    /// The single predicate the cursor consults. `true` only where the sitting
    /// learned something asking again could not improve on.
    pub fn is_settled(self) -> bool {
        matches!(self, Fate::Answered | Fate::Exhausted)
    }

    /// The wire name, for the journal and for diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Fate::Unroutable => "unroutable",
            Fate::Unasked => "unasked",
            Fate::Interrupted => "interrupted",
            Fate::Exhausted => "exhausted",
            Fate::Answered => "answered",
        }
    }

    /// A wire name back into a fate, or `None` for one this build does not know.
    ///
    /// Refused rather than guessed, on the reasoning
    /// [`format`](super::format) gives: reading an unknown fate as
    /// [`Interrupted`](Self::Interrupted) would be safe and reading it as
    /// [`Answered`](Self::Answered) would skip a target, and a reader cannot
    /// tell which it is looking at.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "unroutable" => Fate::Unroutable,
            "unasked" => Fate::Unasked,
            "interrupted" => Fate::Interrupted,
            "exhausted" => Fate::Exhausted,
            "answered" => Fate::Answered,
            _ => return None,
        })
    }
}

/// One target's fate, as a strategy reports it.
///
/// Identified by address, port and transport rather than by a position in the
/// plan, because a strategy knows what it probed and not where that sat in the
/// enumeration. [`cursor`](super::cursor) supplies the other half: positions
/// come from [`TargetMap::iter`](crate::model::target::TargetMap::iter), which
/// is reproducible, so neither side has to store an ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Settlement {
    /// The address probed.
    pub ip: IpAddr,
    /// The port probed.
    pub port: u16,
    /// The transport it was probed over.
    pub protocol: Protocol,
    /// What became of it.
    pub fate: Fate,
}

impl Settlement {
    /// Records `fate` for one target.
    pub fn new(ip: IpAddr, port: u16, protocol: Protocol, fate: Fate) -> Self {
        Self {
            ip,
            port,
            protocol,
            fate,
        }
    }

    /// Whether a resume may skip this target. See [`Fate::is_settled`].
    pub fn is_settled(&self) -> bool {
        self.fate.is_settled()
    }
}

/// Where strategies report what became of their targets.
///
/// Shaped like the other sinks on
/// [`ScanContext`](crate::scanner::session::ScanContext) —
/// `record_failure`, `record_unroutable` — because it is the same kind of thing:
/// a fact about the run that the strategy is the only one who knows, written
/// once and drained by whoever assembles the outcome.
///
/// ## On identity rather than position
///
/// The cursor counts positions in the dispatcher's enumeration; this carries an
/// address, a port and a transport. Nothing has to carry an ordinal to bridge
/// them, because
/// [`TargetMap::iter`](crate::model::target::TargetMap::iter) is the *same*
/// walk the dispatcher probes by and yields the same targets in the same order
/// every time — so a position can be recovered by walking rather than stored by
/// every `Target` in a scan of millions.
///
/// ## On keeping the strongest fate
///
/// A target may be reported twice — a probe exhausted by `service_retries` and
/// then swept again by a stop path that does not know it already had a verdict.
/// The log keeps the [greatest](Fate) fate seen, so a later `Interrupted` can
/// never demote an earlier `Answered`. **Only strengthening is possible**, which
/// is the same property `Host::add_port` maintains about port states and for the
/// same reason: a merge must not be able to lose a finding.
#[derive(Debug, Default)]
pub struct SettlementLog {
    entries: Mutex<std::collections::BTreeMap<(IpAddr, u16, Protocol), Fate>>,
}

impl SettlementLog {
    /// Records one target's fate, keeping the stronger of it and anything
    /// already recorded for that target.
    pub fn record(&self, settlement: Settlement) {
        let key = (settlement.ip, settlement.port, settlement.protocol);
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .entry(key)
            .and_modify(|fate| *fate = (*fate).max(settlement.fate))
            .or_insert(settlement.fate);
    }

    /// How many targets have a fate recorded.
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.len()
    }

    /// Whether nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The fate recorded for one target, if any.
    pub fn fate_of(&self, ip: IpAddr, port: u16, protocol: Protocol) -> Option<Fate> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.get(&(ip, port, protocol)).copied()
    }

    /// Every target recorded, in address-then-port order, and what became of it.
    pub fn snapshot(&self) -> Vec<Settlement> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .iter()
            .map(|(&(ip, port, protocol), &fate)| Settlement::new(ip, port, protocol, fate))
            .collect()
    }

    /// Every target a resume may skip.
    ///
    /// The only reader the cursor needs. Everything absent from this list is
    /// re-probed, whether it was reported as not settled or never reported at
    /// all — which is what makes a strategy that forgets to report fail safe.
    pub fn settled(&self) -> Vec<Settlement> {
        self.snapshot()
            .into_iter()
            .filter(Settlement::is_settled)
            .collect()
    }

    /// Empties the log, yielding what it held.
    pub fn drain(&self) -> Vec<Settlement> {
        let taken = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *entries)
        };

        taken
            .into_iter()
            .map(|((ip, port, protocol), fate)| Settlement::new(ip, port, protocol, fate))
            .collect()
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚═╝     ╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, last])
    }

    fn log() -> SettlementLog {
        SettlementLog::default()
    }

    /// The whole rule, in one assertion. Everything else in this module exists
    /// to make sure the right fate reaches it.
    #[test]
    fn only_an_earned_verdict_settles() {
        assert!(Fate::Answered.is_settled());
        assert!(Fate::Exhausted.is_settled());

        assert!(!Fate::Interrupted.is_settled());
        assert!(!Fate::Unasked.is_settled());
        assert!(!Fate::Unroutable.is_settled());
    }

    /// A truncated run is the case this module exists for: a scan cut short
    /// gives every outstanding and unasked target the same *verdict* as an
    /// exhausted one, and must give none of them the same *fate*.
    #[test]
    fn a_truncated_run_settles_only_what_it_finished() {
        let log = log();

        // What the run actually completed before it was cut short.
        log.record(Settlement::new(ip(1), 22, Protocol::Tcp, Fate::Answered));
        log.record(Settlement::new(ip(1), 80, Protocol::Tcp, Fate::Exhausted));

        // What `resolve_remaining` swept up when the loop ended.
        log.record(Settlement::new(ip(2), 22, Protocol::Tcp, Fate::Interrupted));

        // What `resolve_unasked` drained from the queue, never probed.
        log.record(Settlement::new(ip(3), 22, Protocol::Tcp, Fate::Unasked));
        log.record(Settlement::new(ip(3), 80, Protocol::Tcp, Fate::Unasked));

        let settled = log.settled();
        assert_eq!(settled.len(), 2, "{settled:?}");
        assert!(settled.iter().all(Settlement::is_settled));

        for (ip, port) in [(ip(2), 22), (ip(3), 22), (ip(3), 80)] {
            assert!(
                !log.fate_of(ip, port, Protocol::Tcp)
                    .expect("reported")
                    .is_settled(),
                "{ip}:{port} was never asked to completion and must be re-probed"
            );
        }
    }

    /// A target reported twice keeps the stronger fate, whichever order the two
    /// reports arrive in. A stop path sweeping a target that already earned a
    /// verdict must not demote it.
    #[test]
    fn a_later_report_can_strengthen_a_fate_but_never_weaken_it() {
        for (first, second) in [
            (Fate::Answered, Fate::Interrupted),
            (Fate::Interrupted, Fate::Answered),
        ] {
            let log = log();
            log.record(Settlement::new(ip(1), 22, Protocol::Tcp, first));
            log.record(Settlement::new(ip(1), 22, Protocol::Tcp, second));

            assert_eq!(
                log.fate_of(ip(1), 22, Protocol::Tcp),
                Some(Fate::Answered),
                "{first:?} then {second:?} lost the answer"
            );
        }
    }

    /// The two transports of one number are two targets, and settling one must
    /// not settle the other. `Host::ports` keys on the pair for the same reason.
    #[test]
    fn the_two_transports_of_one_port_settle_independently() {
        let log = log();
        log.record(Settlement::new(ip(1), 53, Protocol::Tcp, Fate::Answered));
        log.record(Settlement::new(ip(1), 53, Protocol::Udp, Fate::Unasked));

        assert_eq!(log.fate_of(ip(1), 53, Protocol::Tcp), Some(Fate::Answered));
        assert_eq!(log.fate_of(ip(1), 53, Protocol::Udp), Some(Fate::Unasked));
        assert_eq!(log.settled().len(), 1);
    }

    /// A target nobody reported must be re-probed rather than assumed done, so
    /// a strategy that forgets to report costs redundant work and never
    /// coverage.
    #[test]
    fn an_unreported_target_is_not_settled() {
        let log = log();
        log.record(Settlement::new(ip(1), 22, Protocol::Tcp, Fate::Answered));

        assert_eq!(log.fate_of(ip(9), 22, Protocol::Tcp), None);
        assert!(
            !log.settled().iter().any(|s| s.ip == ip(9) && s.port == 22),
            "a target with no report must never appear as settled"
        );
    }

    /// Draining hands over what was held and leaves the log empty, so a second
    /// sitting starts with nothing inherited from the first.
    #[test]
    fn draining_empties_the_log() {
        let log = log();
        log.record(Settlement::new(ip(1), 22, Protocol::Tcp, Fate::Answered));
        log.record(Settlement::new(ip(2), 22, Protocol::Tcp, Fate::Unasked));

        assert_eq!(log.drain().len(), 2);
        assert!(log.is_empty());
        assert_eq!(log.fate_of(ip(1), 22, Protocol::Tcp), None);
    }

    /// The wire names round-trip, and an unknown one is refused rather than
    /// falling into a neighbouring fate — where the neighbours differ on whether
    /// a target is skipped.
    #[test]
    fn fate_names_round_trip_and_refuse_the_unknown() {
        for fate in [
            Fate::Unroutable,
            Fate::Unasked,
            Fate::Interrupted,
            Fate::Exhausted,
            Fate::Answered,
        ] {
            assert_eq!(Fate::from_name(fate.name()), Some(fate), "{}", fate.name());
        }

        assert_eq!(Fate::from_name("settled"), None);
        assert_eq!(Fate::from_name(""), None);
    }
}
