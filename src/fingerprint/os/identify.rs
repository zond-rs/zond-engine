// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Attributing a system to a host
//!
//! One function, and the reason it exists is that it was previously four.
//!
//! Every source that concludes something about a host's operating system has to
//! do the same three things afterwards: fold its own reading together with what
//! the host *already* implies, resolve the combination into one verdict, and
//! merge that verdict into whatever the host is already carrying. The raw TCP
//! port scanner did it, the echo prober did it, the service pass did it, and
//! each did it in its own copy of the same eighteen lines.
//!
//! That is a bad place for a copy. The rule those lines encode — **a host's own
//! hardware and name are evidence, and are consulted whatever else was seen** —
//! is a statement about how identification works, not about how a port scanner
//! works. Written once, adding a fifth source is a call; written four times, it
//! was four edits and three chances to forget one. It had already been forgotten
//! once: host discovery concluded nothing at all, on hosts whose hostname and
//! hardware vendor were sitting in the store the whole time.
//!
//! ## The passive sources are free
//!
//! [`hardware_evidence`](super::hardware_evidence) reads a vendor out of a MAC
//! address and [`hostname_evidence`](super::hostname_evidence) reads a family
//! out of a default hostname. Neither sends a packet, neither needs a port, and
//! both work on anything a discovery sweep found. That is what makes
//! [`identify`] worth calling with no observation at all.

use crate::model::host::Host;

use super::{hardware_evidence, hostname_evidence, resolve};
use crate::model::host::OsEvidence;

/// Folds `observed` together with what the host already implies, and records the
/// verdict.
///
/// `observed` is whatever the caller just read off the wire — a stack reading, an
/// echo reply, a service banner — and may be empty, which is the discovery case:
/// nothing was read, and the question is only what the host's own name and
/// hardware say.
///
/// Returns whether a fingerprint was written, so a caller can announce or count
/// what it managed to name.
///
/// # The evidence is kept, not the answer
///
/// Every reading is filed against the host and the verdict is recomputed from
/// **all** of them, rather than each source producing its own verdict and the
/// verdicts being ranked against each other.
///
/// That distinction is the difference between two sources corroborating and two
/// sources competing, and it was worth a real finding. A service banner naming
/// `Debian 12` scores 0.55 alone, under the 0.65 a stack reading scores; ranked,
/// it lost outright and the release it alone could name went with it. Resolved
/// *together* the two agree on Linux, combine to well above either, and the
/// release survives because nothing contradicted it — which is exactly what
/// [`resolve`] was built to do and what it had never been given the chance to.
///
/// So a weak source cannot displace a strong one, a strong one cannot silence a
/// weak one, and the order sources run in does not decide the answer. One item
/// is kept per source and the strongest wins, so a stack read once and a stack
/// read forty times are one piece of evidence — repeating an observation must
/// never look like corroboration.
///
/// # What it will not do
///
/// **Guess.** [`resolve`] returns nothing when there is nothing to go on, or
/// when the sources disagree badly enough that what survives is not worth
/// reporting, and this records nothing in either case. A host whose hardware is
/// a randomised address and whose name its owner chose gets no fingerprint, and
/// that is the correct answer rather than a shortfall.
pub fn identify(host: &mut Host, observed: impl IntoIterator<Item = OsEvidence>) -> bool {
    for item in observed {
        host.record_os_evidence(item);
    }

    // The host's own two sources, consulted whatever else was seen. Worth little
    // alone — a lone hit stays below the reporting threshold — and worth a great
    // deal agreeing with the wire, which is what carries a verdict past what one
    // packet supports.
    if let Some(hardware) = host.hardware().and_then(hardware_evidence) {
        host.record_os_evidence(hardware);
    }
    if let Some(name) = hostname_evidence(host.hostname()) {
        host.record_os_evidence(name);
    }

    // Everything any source has said, resolved together. Not merely what this
    // caller happens to be holding: see the note below on why that distinction
    // is the whole point.
    let evidence: Vec<OsEvidence> = host.os_evidence().cloned().collect();
    let had_evidence = !evidence.is_empty();
    let Some(resolved) = resolve(evidence) else {
        // A verdict this host's own evidence no longer supports has to go with
        // it. Evidence only accumulates, so the answer can move either way as it
        // does — a second source may contradict the first hard enough to leave
        // nothing reportable — and leaving the earlier verdict standing reported
        // a conclusion nothing on record reached. Measured, on one device
        // answering over two addresses: identical evidence sets, and the one
        // that had been named first kept a stale answer the other correctly
        // declined to give.
        //
        // Only where this host has evidence at all. A fingerprint carried in
        // from a report or a merge rests on somebody else's, and `resolve`
        // saying nothing about an empty set is not a finding about it.
        if had_evidence {
            host.clear_os();
        }
        return false;
    };

    host.set_os(resolved.to_fingerprint());
    true
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
    use crate::model::host::OsSource;
    use std::net::{IpAddr, Ipv4Addr};

    fn host() -> Host {
        Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    }

    /// Stands in for something read off the wire — a stack reading strong enough
    /// to be reported on its own, which is what the passive sources exist to
    /// agree with.
    fn observed(family: &str, confidence: f32) -> OsEvidence {
        OsEvidence {
            source: OsSource::TcpStack,
            family: Some(family.to_owned()),
            device: None,
            vendor: None,
            product: None,
            version: None,
            kernel: None,
            cpe: None,
            confidence,
            evidence: "a synthetic stack reading".to_owned(),
        }
    }

    /// The rule both passive sources state in their own documentation, pinned
    /// here because it is the whole reason they are safe to consult on every
    /// host: a lone hit sits below the floor `resolve` reports at, so neither can
    /// name a machine by itself. Hardware and software are separable, and a
    /// hostname is a label somebody may have typed.
    #[test]
    fn one_passive_source_alone_never_names_a_host() {
        let mut by_hardware = host();
        by_hardware.record_mac("b8:27:eb:00:00:01".parse().expect("a registered address"));
        assert!(!identify(&mut by_hardware, []));
        assert!(by_hardware.os().is_none());

        let mut by_name = host();
        by_name.set_hostname(Some("DESKTOP-FKV0V2O".to_owned()));
        assert!(!identify(&mut by_name, []));
        assert!(by_name.os().is_none());
    }

    /// And the other half of that rule: two independent sources agreeing carry a
    /// verdict past what either supports alone. An Apple address and a default
    /// `MacBook-Pro` name are exactly that pair, and a common one.
    #[test]
    fn two_agreeing_passive_sources_name_a_host_between_them() {
        let mut host = host();
        host.record_mac(
            "a4:83:e7:00:00:01"
                .parse()
                .expect("a registered Apple address"),
        );
        host.set_hostname(Some("MacBook-Pro".to_owned()));

        assert!(identify(&mut host, []));
        let os = host.os().expect("a fingerprint");
        assert_eq!(os.name(), "macOS");
        assert!(os.accuracy() >= 40, "below the reporting floor: {os}");
    }

    /// Evidence only accumulates, so an answer can move either way as it does —
    /// and when it moves to *nothing*, the answer on record has to go with it.
    ///
    /// Found on one device answering over two addresses: identical evidence,
    /// and the address that had been named first kept a verdict the other
    /// correctly declined to give, so one printer contradicted itself inside one
    /// report.
    #[test]
    fn a_verdict_the_evidence_no_longer_supports_is_withdrawn() {
        let mut host = host();
        assert!(identify(&mut host, [observed("Linux", 0.5)]));
        assert!(host.os().is_some());

        // A second source, as strong and naming something else. Neither survives.
        let mut contradiction = observed("Windows", 0.5);
        contradiction.source = OsSource::HardwareVendor;
        assert!(!identify(&mut host, [contradiction]));
        assert!(
            host.os().is_none(),
            "the earlier verdict rested on evidence that no longer resolves"
        );
    }

    /// A fingerprint carried in from a report or a merge rests on evidence this
    /// host never held, and `resolve` saying nothing about an empty set is not a
    /// finding about it.
    #[test]
    fn a_verdict_with_no_evidence_behind_it_is_left_alone() {
        let mut host = host();
        host.set_os(crate::model::host::OsFingerprint::new("Linux", 90));

        assert!(!identify(&mut host, []));
        assert_eq!(host.os().map(|os| os.name()), Some("Linux"));
    }

    /// Declining is the point rather than a shortfall. A randomised hardware
    /// address has no registered vendor, and a name its owner chose says nothing
    /// about the machine, so there is nothing here to be right or wrong about.
    #[test]
    fn a_host_with_nothing_to_go_on_is_left_unnamed() {
        let mut host = host();
        host.record_mac(
            "02:00:5e:00:53:04"
                .parse()
                .expect("a locally administered address"),
        );
        host.set_hostname(Some("fileserver".to_owned()));

        assert!(!identify(&mut host, []));
        assert!(host.os().is_none());
    }

    /// The rule this function exists to state once. A caller that has read
    /// something off the wire does not have to remember to ask the host what it
    /// already implies — and the agreement is worth accuracy, which is the whole
    /// point of consulting them.
    #[test]
    fn the_hosts_own_sources_are_consulted_alongside_what_was_observed() {
        let reading = observed("Linux", 0.6);

        let mut bare = host();
        assert!(identify(&mut bare, [reading.clone()]));
        let alone = bare.os().expect("a fingerprint").accuracy();

        let mut corroborated = host();
        corroborated.record_mac("b8:27:eb:00:00:01".parse().expect("a registered address"));
        assert!(identify(&mut corroborated, [reading]));
        let together = corroborated.os().expect("a fingerprint").accuracy();

        assert!(
            together > alone,
            "hardware agreeing with the wire should raise the verdict: {together} vs {alone}"
        );
    }

    /// A banner naming a release, arriving after a stack reading, must
    /// **corroborate** it rather than lose to it.
    ///
    /// The defect this replaced, measured end to end on a real host: the stack
    /// said `Linux` at 0.65, the SSH banner said `Debian 12.0` at 0.55, the
    /// banner's verdict was ranked against the stack's, lost on the number, and
    /// was discarded whole — so a scan that had read the release off the wire
    /// reported a bare family. The two agree; agreement is worth more than
    /// either, and only the banner could speak to the release.
    #[test]
    fn a_banner_arriving_after_a_stack_reading_adds_its_release() {
        let banner = OsEvidence {
            source: OsSource::ServiceBanner,
            family: Some("Linux".to_owned()),
            device: None,
            vendor: Some("Debian".to_owned()),
            product: None,
            version: Some("12.0".to_owned()),
            kernel: None,
            cpe: Some("cpe:/o:debian:debian_linux:12.0".to_owned()),
            confidence: 0.55,
            evidence: "service banner names Linux".to_owned(),
        };

        let mut host = host();
        assert!(identify(&mut host, [observed("Linux", 0.65)]));
        let from_the_wire = host.os().expect("a stack reading names it").accuracy();

        assert!(identify(&mut host, [banner]));
        let os = host.os().expect("still named");

        assert_eq!(os.family(), Some("Linux"));
        assert_eq!(
            os.generation(),
            Some("12.0"),
            "only the banner could name the release, and nothing contradicted it"
        );
        assert!(
            os.accuracy() > from_the_wire,
            "two independent sources agreeing beat either alone: {} vs {from_the_wire}",
            os.accuracy()
        );
    }

    /// Who built the hardware and who publishes the operating system are
    /// different questions, and two answers to two questions are not a
    /// disagreement.
    ///
    /// Measured, on a Raspberry Pi running Debian: the address block said
    /// `Raspberry Pi Trading Ltd`, the SSH banner said `Debian`, both were
    /// filed as the operating system's vendor, and the resolver kept neither —
    /// leaving a release with no name to attach to and reporting `Linux 12.0`,
    /// a version no Linux has ever had.
    ///
    /// An address block supports a family and nothing more. The company is still
    /// recorded, against the hardware, which is what it is about.
    #[test]
    fn a_board_maker_does_not_contradict_the_publisher_of_the_system() {
        let banner = OsEvidence {
            source: OsSource::ServiceBanner,
            family: Some("Linux".to_owned()),
            device: None,
            vendor: Some("Debian".to_owned()),
            product: Some("Linux".to_owned()),
            version: Some("12.0".to_owned()),
            kernel: None,
            cpe: None,
            confidence: 0.55,
            evidence: "service banner names Linux".to_owned(),
        };

        let mut host = host();
        // A registered Raspberry Pi address, which the corpus reads as Linux.
        host.record_mac("2c:cf:67:00:00:01".parse().expect("a registered address"));
        assert!(identify(&mut host, [observed("Linux", 0.65), banner]));

        let os = host.os().expect("a fingerprint");
        assert_eq!(os.family(), Some("Linux"));
        assert_eq!(
            os.name(),
            "Debian",
            "the publisher of the system names it, not the maker of the board: {os}"
        );
        assert_eq!(os.generation(), Some("12.0"));
        assert_eq!(
            host.vendor(),
            Some("Raspberry Pi Trading Ltd"),
            "and the board's maker is still on record, against the hardware"
        );
    }

    /// A stack read twice by two routes keeps the richer reading.
    ///
    /// The regression this replaced: the port scan reads a stack off one reply
    /// and the series probe reads the *same stack* off twelve, concluding the
    /// identical thing — same source, same family, nothing finer from either. So
    /// the second was rejected as a claim already on record, and the readings
    /// only it could produce, the ones that cost twenty-four probes, went with
    /// it. A scan reported `syn-ack hops>=64 …` where it had measured
    /// `id=`, `isn=` and `ts=` as well.
    ///
    /// The claim is not new; the working behind it is.
    #[test]
    fn a_stack_read_twice_keeps_the_reading_that_says_more() {
        let mut passive = observed("Linux", 0.65);
        passive.evidence = "syn-ack hops>=64 opts=M,S,T,N,W win=65160".to_owned();

        let mut series = observed("Linux", 0.65);
        series.evidence =
            "syn-ack hops>=64 opts=M,S,T,N,W win=65160 id=zero isn=hashed ts=ticking(1000Hz)"
                .to_owned();

        let mut host = host();
        identify(&mut host, [passive]);
        identify(&mut host, [series]);

        let evidence = host
            .os()
            .and_then(|os| os.evidence().map(str::to_owned))
            .expect("a finding with its evidence");

        assert!(
            evidence.contains("isn=hashed"),
            "the series reading is the one that cannot be got back: {evidence}"
        );
        assert!(
            !evidence.contains(" | "),
            "and the passive line it extends is not printed beside it: {evidence}"
        );
    }

    /// And the guard that makes the above safe: reading one stack repeatedly is
    /// one piece of evidence, however many ports it was read from.
    ///
    /// A host with forty open ports has its stack read forty times, and the
    /// arithmetic that combines independent sources cannot tell that apart from
    /// forty sources agreeing unless something upstream does. Left unchecked it
    /// would turn a single observation into certainty.
    #[test]
    fn one_stack_read_many_times_is_still_one_piece_of_evidence() {
        let mut once = host();
        identify(&mut once, [observed("Linux", 0.65)]);

        let mut forty = host();
        for _ in 0..40 {
            identify(&mut forty, [observed("Linux", 0.65)]);
        }

        assert_eq!(
            once.os().expect("named").accuracy(),
            forty.os().expect("named").accuracy(),
            "repeating an observation is not corroboration"
        );
    }

    /// Merged rather than assigned, so running twice cannot lose ground and the
    /// order sources happen to finish in does not decide the answer.
    #[test]
    fn identifying_twice_never_loses_what_was_already_known() {
        let mut host = host();
        host.record_mac(
            "a4:83:e7:00:00:01"
                .parse()
                .expect("a registered Apple address"),
        );
        host.set_hostname(Some("MacBook-Pro".to_owned()));

        assert!(identify(&mut host, []));
        let first = host.os().expect("a fingerprint").clone();

        assert!(identify(&mut host, []));
        let second = host.os().expect("still a fingerprint");

        assert_eq!(first.name(), second.name());
        assert!(second.accuracy() >= first.accuracy());
    }

    /// A weak source may not displace a strong one, whichever order they arrive
    /// in — which is what makes it safe to run the passive pass after a scan has
    /// already concluded something from the wire.
    #[test]
    fn a_passive_pass_cannot_weaken_a_reading_taken_from_the_wire() {
        let mut host = host();
        assert!(identify(&mut host, [observed("Linux", 0.7)]));
        let from_the_wire = host.os().expect("a fingerprint").clone();

        // Now the passive pass runs over the same host and finds nothing new.
        identify(&mut host, []);

        let after = host.os().expect("still a fingerprint");
        assert_eq!(after.name(), from_the_wire.name());
        assert!(after.accuracy() >= from_the_wire.accuracy());
    }
}
