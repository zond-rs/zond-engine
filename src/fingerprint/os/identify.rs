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

use super::{OsEvidence, hardware_evidence, hostname_evidence, resolve};

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
/// # What it will not do
///
/// **Overwrite a better answer.** The verdict is merged rather than assigned,
/// and [`OsFingerprint::merge`](crate::model::host::os::OsFingerprint::merge)
/// ranks by accuracy and fills gaps on a tie — so a host probed several ways
/// accumulates, a weak source cannot displace a strong one, and the order
/// sources happen to run in does not decide the answer.
///
/// **Guess.** [`resolve`] returns nothing when there is nothing to go on, or
/// when the sources disagree badly enough that what survives is not worth
/// reporting, and this records nothing in either case. A host whose hardware is
/// a randomised address and whose name its owner chose gets no fingerprint, and
/// that is the correct answer rather than a shortfall.
pub fn identify(host: &mut Host, observed: impl IntoIterator<Item = OsEvidence>) -> bool {
    let mut evidence: Vec<OsEvidence> = observed.into_iter().collect();

    // The host's own two sources, consulted whatever else was seen. Worth little
    // alone — a lone hit stays below the reporting threshold — and worth a great
    // deal agreeing with the wire, which is what carries a verdict past what one
    // packet supports.
    if let Some(hardware) = host.hardware().and_then(hardware_evidence) {
        evidence.push(hardware);
    }
    if let Some(name) = hostname_evidence(host.hostname()) {
        evidence.push(name);
    }

    let Some(resolved) = resolve(evidence) else {
        return false;
    };

    let fingerprint = resolved.to_fingerprint();
    match host.os() {
        Some(existing) => {
            let mut merged = existing.clone();
            merged.merge(fingerprint);
            host.set_os(merged);
        }
        None => host.set_os(fingerprint),
    }

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
    use crate::fingerprint::os::verdict::OsSource;
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
            family: family.to_owned(),
            vendor: None,
            product: None,
            version: None,
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
