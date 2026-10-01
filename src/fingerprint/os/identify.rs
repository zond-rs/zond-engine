// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Attributing a system to a host
//!
//! Every source that concludes something about a host's operating system (the
//! raw TCP port scanner, the echo prober, the service pass) then does the same
//! thing: folds its reading together with what the host already implies,
//! resolves the combination, and merges the verdict into the host. [`identify`]
//! does that once, and always consults the host's own **hardware and name**.
//!
//! ## The passive sources are free
//!
//! [`hardware_evidence`] reads a vendor out of a MAC address and
//! [`hostname_evidence`] a family out of a default hostname. Neither sends a
//! packet, so [`identify`] is worth calling with no observation at all.

use crate::model::host::Host;

use super::{hardware_evidence, hostname_evidence, resolve};
use crate::model::host::OsEvidence;

/// Folds `observed` together with what the host already implies, and records the
/// verdict.
///
/// `observed` is what the caller just read off the wire (a stack reading, an
/// echo reply, a service banner), and may be empty.
///
/// Returns whether a fingerprint was written, so a caller can announce or count
/// what it managed to name.
///
/// # The evidence is kept, not the answer
///
/// Every reading is filed against the host and the verdict recomputed from all
/// of them. A `Debian 12` banner at 0.55 and a Linux stack reading at 0.65 then
/// corroborate, and the release survives; ranked against each other, the
/// banner and its release would be lost.
///
/// Order does not matter. One item is kept per source, the strongest, so a
/// stack read forty times is one piece of evidence.
///
/// Where [`resolve`] returns nothing, nothing is recorded.
pub fn identify(host: &mut Host, observed: impl IntoIterator<Item = OsEvidence>) -> bool {
    for item in observed {
        host.record_os_evidence(item);
    }

    // The host's own two sources, always consulted.
    if let Some(hardware) = host.hardware().and_then(hardware_evidence) {
        host.record_os_evidence(hardware);
    }
    if let Some(name) = hostname_evidence(host.hostname()) {
        host.record_os_evidence(name);
    }

    // Everything any source has said, resolved together.
    let evidence: Vec<OsEvidence> = host.os_evidence().cloned().collect();
    let had_evidence = !evidence.is_empty();
    let Some(resolved) = resolve(evidence) else {
        // A verdict the evidence no longer supports is cleared, since a new
        // source can contradict an old one. Only where this host has evidence:
        // a fingerprint imported from a report or a merge is kept.
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

    /// A stack reading strong enough to be reported on its own.
    fn observed(family: &str, confidence: f32) -> OsEvidence {
        OsEvidence {
            source: OsSource::TcpStack,
            family: Some(family.to_owned()),
            device: None,
            vendor: None,
            product: None,
            version: None,
            kernel: None,
            arch: None,
            cpe: None,
            confidence,
            evidence: "a synthetic stack reading".to_owned(),
        }
    }

    /// Neither passive source names a host alone.
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

    /// An Apple address and a default `MacBook-Pro` name together carry a
    /// verdict.
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

    /// One Bonjour responder is one witness, however much it says.
    ///
    /// As two sources, a default name and a model identifier would fuse to 87,
    /// past the 85 at which the active probe is skipped. The same name from a
    /// resolver is a separate witness (the last assertion).
    #[test]
    fn one_bonjour_responder_is_one_witness_however_much_it_says() {
        use crate::fingerprint::SignatureDb;
        use crate::model::port::Protocol;

        // The responder's record, read as the active pass reads it.
        let record = || {
            SignatureDb::global()
                .identify(5353, Protocol::Udp, "model=Mac16,10")
                .and_then(|evidence| evidence.os)
                .expect("the corpus reads a Mac's model identifier")
        };
        assert_eq!(record().source, OsSource::MdnsResponder, "test premise");

        let mut announced = host();
        announced.set_hostname(Some("MacBook-Pro.local".to_owned()));
        assert!(identify(&mut announced, [record()]));
        let one = announced.os().expect("the record names the host");
        assert!(
            !one.is_highly_confident(),
            "one responder settled the host at {}",
            one.accuracy()
        );

        let mut resolved = host();
        resolved.set_hostname(Some("MacBook-Pro".to_owned()));
        assert!(identify(&mut resolved, [record()]));
        let two = resolved.os().expect("the record names the host");
        assert!(
            two.accuracy() > one.accuracy(),
            "a resolver's name is a second witness: {} against {}",
            two.accuracy(),
            one.accuracy()
        );
    }

    /// When the evidence resolves to nothing, the recorded verdict is cleared.
    #[test]
    fn a_verdict_the_evidence_no_longer_supports_is_withdrawn() {
        let mut host = host();
        assert!(identify(&mut host, [observed("Linux", 0.5)]));
        assert!(host.os().is_some());

        // An equally strong contradiction.
        let mut contradiction = observed("Windows", 0.5);
        contradiction.source = OsSource::HardwareVendor;
        assert!(!identify(&mut host, [contradiction]));
        assert!(
            host.os().is_none(),
            "the earlier verdict rested on evidence that no longer resolves"
        );
    }

    /// An imported fingerprint, with no evidence behind it, is kept.
    #[test]
    fn a_verdict_with_no_evidence_behind_it_is_left_alone() {
        let mut host = host();
        host.set_os(crate::model::host::OsFingerprint::new("Linux", 90));

        assert!(!identify(&mut host, []));
        assert_eq!(host.os().map(|os| os.name()), Some("Linux"));
    }

    /// A randomised address and a chosen name yield no fingerprint.
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

    /// The host's own sources are consulted alongside what was read off the wire.
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
    /// corroborate it.
    ///
    /// Stack `Linux` at 0.65 and banner `Debian 12.0` at 0.55 agree, and the
    /// release survives.
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
            arch: None,
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
    /// A Raspberry Pi running Debian: the address says `Raspberry Pi Trading Ltd`,
    /// the banner `Debian`. The address supports only a family; the company is
    /// recorded against the hardware.
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
            arch: None,
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
    /// The series probe's reading (with `id=`, `isn=`, `ts=`) replaces the port
    /// scan's single-reply reading of the same stack.
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

    /// A stack read on forty ports is one piece of evidence.
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

    /// Merged, so running twice or in another order gives the same answer.
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

    /// A weak source does not displace a strong one, in either order.
    #[test]
    fn a_passive_pass_cannot_weaken_a_reading_taken_from_the_wire() {
        let mut host = host();
        assert!(identify(&mut host, [observed("Linux", 0.7)]));
        let from_the_wire = host.os().expect("a fingerprint").clone();

        // The passive pass finds nothing new.
        identify(&mut host, []);

        let after = host.os().expect("still a fingerprint");
        assert_eq!(after.name(), from_the_wire.name());
        assert!(after.accuracy() >= from_the_wire.accuracy());
    }
}
