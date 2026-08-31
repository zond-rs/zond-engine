// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Combining what several sources say about one host
//!
//! A stack's shape is one way to learn what a machine runs. A banner it
//! volunteered is another, and the hardware address it answered from is a third.
//! They are read from different places, fail in different ways, and this is where
//! they are put together.
//!
//! ## The independence claim, and where it stops
//!
//! Combining evidence means assuming the pieces are independent, and that
//! assumption is *false* within a single reply: the hop counter, the window and
//! the option layout of one packet are consequences of one stack build and agree
//! with each other by construction. Scoring them separately would triple-count
//! one observation.
//!
//! So [`classify`](super::classify) already collapses a whole reply into
//! one item. What arrives here is one item per genuinely distinct source,
//! and independence is claimed only between those, a stack, a banner, a
//! hardware address, where it is close enough to true to build on.
//!
//! That is also why the arithmetic below is [noisy-OR] rather than a sum. Two
//! sources agreeing raise confidence without either being trusted more than it
//! deserves, and no amount of agreement reaches certainty.
//!
//! [noisy-OR]: https://en.wikipedia.org/wiki/Noisy-or_model
//!
//! ## Two axes, because they are two questions
//!
//! What a machine *runs* and what it *is* are independent, and a source may
//! know either without the other. A hop counter says infrastructure and never a
//! vendor; an SNMP agent names a printer down to its firmware and never its
//! kernel. So the family is one axis, the device class another, and a source
//! with nothing to say on either simply says nothing there; see
//! [`OsEvidence::family`].
//!
//! ## Disagreement lowers the answer rather than picking a winner
//!
//! When sources name different families, the leader is reduced by whatever the
//! runner-up carries. Two sources at odds are a worse position than one source
//! alone, and a resolver that took the larger and reported it at full strength
//! would be hiding the conflict at exactly the moment it matters. Below the floor
//! the result is no answer, which is the honest outcome for a host two techniques
//! disagree about.

use crate::model::host::OsEvidence;
use std::collections::BTreeMap;

use super::verdict::{MIN_REPORTABLE_ACCURACY, OsVerdict};

/// The most any combination of sources may claim.
///
/// Noisy-OR approaches certainty without reaching it, which is the right shape
/// and not enough on its own: at twenty agreeing sources the arithmetic lands
/// close enough that rounding to a percentage produces 100, and a scan reporting
/// an operating system as certain on accumulated inference would be claiming
/// something none of its sources said.
///
/// Above the 85 that marks high confidence, so agreement between genuinely
/// independent sources can still get there, that is the whole point of having
/// more than one. Below 100, which stays reserved for a host that identified
/// itself rather than one that was worked out.
pub const MAX_FUSED_ACCURACY: u8 = 95;

/// Folds every source's opinion into one answer, or none.
///
/// Returns `None` when there is nothing to go on, when the sources disagree
/// badly enough that what survives falls below [`MIN_REPORTABLE_ACCURACY`], or
/// when what survives says nothing about the software.
///
/// # Abstention is not dissent
///
/// Only the sources that [name a family](OsEvidence::family) vote on it. The
/// rest fold their finer parts into whichever family wins and never count
/// against it, which is the difference between a second opinion and a second
/// question. A hop counter of 255 says *network device*; an SNMP agent saying
/// `Brother NC-8700w` says which one. Scored as rival families those two
/// readings annihilated each other and the host was reported as nothing, on
/// real hardware, with both answers sitting in the record.
///
/// Where nobody names a family the abstentions are the whole answer, and it is
/// reported without one.
pub fn resolve(evidence: Vec<OsEvidence>) -> Option<OsVerdict> {
    // Grouped by family, because that is the level a source that has one can
    // speak to. A `BTreeMap` so two runs over the same evidence resolve the same
    // way: with scores this close together, iteration order would otherwise
    // decide ties.
    let mut by_family: BTreeMap<&str, Vec<&OsEvidence>> = BTreeMap::new();
    let mut abstained: Vec<&OsEvidence> = Vec::new();
    for item in &evidence {
        match item.family.as_deref() {
            Some(family) => by_family.entry(family).or_default().push(item),
            None => abstained.push(item),
        }
    }

    let mut scored: Vec<(&str, f32, Vec<&OsEvidence>)> = by_family
        .into_iter()
        .map(|(family, items)| {
            let score = combine(items.iter().map(|item| item.confidence));
            (family, score, items)
        })
        .collect();
    // Descending by score, and by family name where scores tie, so the answer
    // does not depend on which source happened to be added first.
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(b.0))
    });

    // Everything naming a *different* family, combined, is what the leader has to
    // survive. One dissenting source is a doubt; several agreeing with each other
    // against the leader is close to a refutation.
    let mut answer = scored.first().map(|(family, score, items)| {
        let against = combine(scored.iter().skip(1).map(|(_, score, _)| *score));
        (
            Some(*family),
            score * (1.0 - against),
            against,
            items.clone(),
        )
    });

    // A family that cannot clear the floor is not an answer, but it is also not
    // the only thing on the table. What abstained never competed for it, was
    // never reduced by the dissent that sank it, and can still be worth
    // reporting on its own, an agent naming a make and model outright while two
    // stack rules argue about what class of box it is. Dropping the whole
    // verdict there would discard the best-attested thing the scan learned
    // because of a quarrel it took no part in.
    if answer
        .as_ref()
        .is_none_or(|(_, survived, ..)| percent(*survived) < MIN_REPORTABLE_ACCURACY)
        && !abstained.is_empty()
    {
        let alone = combine(abstained.iter().map(|item| item.confidence));
        if answer
            .as_ref()
            .is_none_or(|(_, survived, ..)| alone > *survived)
        {
            answer = Some((None, alone, 0.0, Vec::new()));
        }
    }

    let (family, survived, against, mut items) = answer?;
    items.extend_from_slice(&abstained);

    let accuracy = percent(survived);
    if accuracy < MIN_REPORTABLE_ACCURACY {
        return None;
    }

    // The finer parts of the path are kept where every source that *spoke to*
    // them agrees. A source saying nothing about a version abstains rather than
    // dissenting: a stack rule can name a family and never a release, so
    // counting its silence as disagreement would mean a banner that read
    // "Ubuntu 22.04" off the wire loses it the moment a stack rule corroborates
    // the family, which is more evidence producing a less specific answer. Two
    // sources naming different values still yield nothing.
    let agreed = |part: fn(&OsEvidence) -> &Option<String>| -> Option<String> {
        let mut stated = items.iter().filter_map(|item| part(item).as_deref());
        let candidate = stated.next()?;
        stated
            .all(|other| other == candidate)
            .then(|| candidate.to_owned())
    };

    // Attributed to whichever source contributed most, since that is the one a
    // reader would want to argue with first.
    let strongest = items
        .iter()
        .max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .copied()?;

    let mut lines: Vec<&str> = items.iter().map(|item| item.evidence.as_str()).collect();
    lines.sort_unstable();
    lines.dedup();

    let (vendor, product, version, kernel, cpe, device) = (
        agreed(|item| &item.vendor),
        agreed(|item| &item.product),
        agreed(|item| &item.version),
        agreed(|item| &item.kernel),
        agreed(|item| &item.cpe),
        agreed(|item| &item.device),
    );

    // Something has to have been established. Every one of these is a real
    // answer on its own: a device class says the box is infrastructure, which is
    // the most a hop counter of 255 can support and is worth reporting about a
    // host nothing else describes.
    //
    // This guard used to exclude a device class, on the reading that a source
    // knowing only what kind of box this is has identified no software. That was
    // true while a class could only arrive beside a product, from a text rule.
    // It stopped being true when the rules that read a hop counter began stating
    // a class instead of writing one into the family field.
    if family.is_none() && device.is_none() && vendor.is_none() && product.is_none() {
        return None;
    }

    // What the finer parts are worth, as distinct from the family.
    //
    // Every source can speak to a family, and `accuracy` above is their
    // agreement about it. A release is usually named by exactly one of them, so
    // reporting it under that figure launders one weaker claim through the
    // agreement of several stronger ones, measured, on a real host: two sources
    // agreeing on Linux scored 84 while the release rested on a single banner
    // worth 55.
    //
    // Combined over the sources that actually stated something finer, and
    // reduced by the same dissent the family had to survive: a contested family
    // does not leave its release uncontested.
    let refined = vendor.is_some()
        || product.is_some()
        || version.is_some()
        || kernel.is_some()
        || cpe.is_some()
        || device.is_some();
    let detail_accuracy = refined.then(|| {
        let stated = items
            .iter()
            .filter(|item| {
                item.vendor.is_some()
                    || item.product.is_some()
                    || item.version.is_some()
                    || item.kernel.is_some()
                    || item.cpe.is_some()
                    || item.device.is_some()
            })
            .map(|item| item.confidence);

        percent(combine(stated) * (1.0 - against))
    });

    Some(OsVerdict {
        family: family.map(ToOwned::to_owned),
        device,
        vendor,
        product,
        version,
        kernel,
        cpe,
        accuracy,
        detail_accuracy,
        source: strongest.source,
        evidence: lines.join(" | "),
    })
}

/// A combined probability on the `0..=100` scale a report states, never above
/// what any amount of agreement is allowed to claim.
fn percent(probability: f32) -> u8 {
    (probability * 100.0)
        .round()
        .clamp(0.0, f32::from(MAX_FUSED_ACCURACY)) as u8
}

/// Combines independent probabilities for one hypothesis: the chance that *at
/// least one* of them is right.
///
/// `1 - Π(1 - p)`. Two sources at 0.5 give 0.75 rather than 1.0, and nothing
/// short of a certain source ever reaches 1, which is the property that
/// matters, because a stack of agreeing guesses must not become a fact.
fn combine(confidences: impl Iterator<Item = f32>) -> f32 {
    let doubt = confidences
        .map(|confidence| 1.0 - confidence.clamp(0.0, 1.0))
        .product::<f32>();
    1.0 - doubt
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

    /// The Brother print server this behaviour was found on, as its agent
    /// answered on 2026-08-26: a make, a model and a firmware, and not one word
    /// about an operating system.
    fn a_named_appliance() -> OsEvidence {
        OsEvidence {
            source: OsSource::SnmpAgent,
            family: None,
            device: Some("Printer".to_string()),
            vendor: Some("Brother".to_string()),
            product: Some("NC-8700w".to_string()),
            version: Some("ZL".to_string()),
            kernel: None,
            cpe: None,
            confidence: 0.56,
            evidence: "snmp agent names NC-8700w".to_string(),
        }
    }

    fn evidence(family: &str, confidence: f32, source: OsSource) -> OsEvidence {
        OsEvidence {
            source,
            family: Some(family.to_string()),
            device: None,
            vendor: None,
            product: None,
            version: None,
            kernel: None,
            cpe: None,
            confidence,
            evidence: format!("{source:?} says {family}"),
        }
    }

    /// The point of a second source. A stack reading alone is capped below the
    /// threshold that stops further probing, because one packet's fields are one
    /// observation; a second, genuinely independent source agreeing with it is
    /// what may legitimately carry the answer past that.
    #[test]
    fn two_agreeing_sources_are_worth_more_than_either() {
        let stack = evidence("Linux", 0.65, OsSource::TcpStack);
        let hardware = evidence("Linux", 0.30, OsSource::HardwareVendor);

        let alone = resolve(vec![stack.clone()]).expect("one source names it");
        let together = resolve(vec![stack, hardware]).expect("two sources name it");

        assert!(together.accuracy > alone.accuracy);
        assert_eq!(together.accuracy, 76, "1 - (0.35 x 0.70)");
    }

    /// Agreement must not become certainty. Noisy-OR is chosen over anything that
    /// sums precisely because a stack of agreeing guesses has to stay a stack of
    /// guesses however many of them there are.
    #[test]
    fn no_amount_of_agreement_reaches_certainty() {
        let many: Vec<OsEvidence> = (0..20)
            .map(|_| evidence("Linux", 0.6, OsSource::TcpStack))
            .collect();

        let resolved = resolve(many).expect("named");
        assert_eq!(
            resolved.accuracy, MAX_FUSED_ACCURACY,
            "twenty agreeing sources may be highly confident and must not be certain"
        );
        assert!(
            resolved.accuracy < 100,
            "certainty is reserved for a host that identified itself"
        );
    }

    /// Sources at odds are a worse position than one source alone, and the
    /// resolver has to say so rather than take the larger and report it at full
    /// strength. Hiding a conflict is worst exactly where it matters most.
    #[test]
    fn disagreement_lowers_the_answer_rather_than_picking_a_winner() {
        let uncontested = resolve(vec![evidence("Linux", 0.65, OsSource::TcpStack)])
            .expect("one source names it")
            .accuracy;

        let contested = resolve(vec![
            evidence("Linux", 0.65, OsSource::TcpStack),
            evidence("Windows", 0.30, OsSource::HardwareVendor),
        ])
        .expect("the leader survives one dissenter");

        assert_eq!(contested.family.as_deref(), Some("Linux"));
        assert!(
            contested.accuracy < uncontested,
            "a contested verdict must not score what an uncontested one does"
        );
    }

    /// And a conflict bad enough leaves nothing worth reporting. A host two
    /// techniques flatly disagree about is a host this engine cannot name, and
    /// saying so beats naming it at reduced confidence.
    #[test]
    fn an_even_conflict_names_nothing() {
        assert!(
            resolve(vec![
                evidence("Linux", 0.65, OsSource::TcpStack),
                evidence("Windows", 0.65, OsSource::HardwareVendor),
            ])
            .is_none()
        );
    }

    /// A source that says nothing about a product **abstains**; it does not
    /// dissent.
    ///
    /// A hardware vendor is read out of an address registration and has no way
    /// to hold an opinion about a distribution. Counting its silence as
    /// disagreement would mean the only source capable of naming one loses the
    /// name the moment anything else corroborates the family, which is more
    /// evidence producing a less specific answer and the wrong direction for
    /// evidence to move.
    ///
    /// This is the same rule the matcher already applies one layer down, where a
    /// predicate a rule does not state is "do not care" rather than "must be
    /// absent".
    #[test]
    fn a_source_with_nothing_to_say_about_a_product_does_not_veto_one() {
        let mut precise = evidence("Linux", 0.65, OsSource::TcpStack);
        precise.product = Some("Ubuntu".to_string());
        let vague = evidence("Linux", 0.30, OsSource::HardwareVendor);

        let resolved = resolve(vec![precise, vague]).expect("named");
        assert_eq!(resolved.family.as_deref(), Some("Linux"));
        assert_eq!(
            resolved.product.as_deref(),
            Some("Ubuntu"),
            "the only source that could name a product named one, and nothing contradicted it"
        );
    }

    /// Abstention is not agreement with anything, though. Two sources naming
    /// *different* products cannot both be right, and nothing here can say
    /// which is, so the answer keeps the family they share and drops the part
    /// they contest.
    #[test]
    fn two_sources_naming_different_products_keep_neither() {
        let mut stack = evidence("Linux", 0.65, OsSource::TcpStack);
        stack.product = Some("Ubuntu".to_string());
        let mut banner = evidence("Linux", 0.65, OsSource::ServiceBanner);
        banner.product = Some("Debian".to_string());

        let resolved = resolve(vec![stack, banner]).expect("the family is agreed");
        assert_eq!(resolved.family.as_deref(), Some("Linux"));
        assert_eq!(resolved.product, None);
    }

    /// Two runs over the same evidence must resolve the same way. With scores
    /// this close together an unordered fold would let whichever source happened
    /// to be pushed first decide a tie, and a scan would report differently on
    /// alternate runs for no reason in the data.
    #[test]
    fn the_answer_does_not_depend_on_the_order_evidence_arrived_in() {
        let a = evidence("Linux", 0.5, OsSource::TcpStack);
        let b = evidence("macOS", 0.5, OsSource::HardwareVendor);

        assert_eq!(
            resolve(vec![a.clone(), b.clone()]),
            resolve(vec![b, a]),
            "the same evidence in the other order is the same evidence"
        );
    }

    #[test]
    fn nothing_in_names_nothing_out() {
        assert!(resolve(Vec::new()).is_none());
    }

    /// The finding this file was rewritten for.
    ///
    /// A hop counter of 255 says *network device*; an SNMP agent says *Brother
    /// NC-8700w*. Those are answers to two questions and the second is by far
    /// the better one, but scored as rival families they cancelled: 0.4 reduced
    /// by 0.385 left 25, under the floor, and a printer that had answered ARP,
    /// ICMP, TCP and SNMP was reported as unidentified.
    #[test]
    fn a_source_that_names_no_family_does_not_argue_with_one_that_does() {
        let stack = evidence("Network device", 0.4, OsSource::TcpStack);
        let resolved = resolve(vec![stack.clone(), a_named_appliance()]).expect("named");

        assert_eq!(resolved.family.as_deref(), Some("Network device"));
        assert_eq!(
            resolved.accuracy,
            percent(0.4),
            "unreduced: nothing dissented"
        );
        assert_eq!(resolved.vendor.as_deref(), Some("Brother"));
        assert_eq!(resolved.product.as_deref(), Some("NC-8700w"));
        assert_eq!(resolved.device.as_deref(), Some("Printer"));
    }

    /// And the abstention carries the answer where nothing else can name a
    /// family at all, a device on a segment whose stack said nothing.
    #[test]
    fn an_abstention_alone_is_still_an_answer() {
        let resolved = resolve(vec![a_named_appliance()]).expect("named");

        assert_eq!(resolved.family, None);
        assert_eq!(resolved.product.as_deref(), Some("NC-8700w"));
        assert_eq!(resolved.accuracy, percent(0.56));
    }

    /// A family that cannot clear the floor takes only itself down. What
    /// abstained never entered the quarrel and is not reduced by it.
    #[test]
    fn a_family_too_contested_to_report_does_not_take_the_rest_with_it() {
        let one = evidence("Linux", 0.5, OsSource::TcpStack);
        let other = evidence("Windows", 0.5, OsSource::HardwareVendor);
        assert!(
            resolve(vec![one.clone(), other.clone()]).is_none(),
            "two sources this far apart name nothing between them"
        );

        let resolved = resolve(vec![one, other, a_named_appliance()]).expect("named");
        assert_eq!(
            resolved.family, None,
            "the contested family is still refused"
        );
        assert_eq!(resolved.product.as_deref(), Some("NC-8700w"));
    }

    /// A class of box on its own **is** a verdict, and this test reverses an
    /// earlier reading that said otherwise.
    ///
    /// The old rule was that something knowing only what the hardware is has
    /// identified no software, so a class alone was refused. That held while a
    /// class could only arrive beside a product, from a rule reading text. It
    /// stopped holding when the rules that read a hop counter of 255 began
    /// stating a class instead of writing one into the family field: "this host
    /// is infrastructure" is then the whole of what a real observation
    /// established, and it is the only thing anything will ever say about a
    /// switch with no port open and no name.
    #[test]
    fn a_device_class_on_its_own_is_a_verdict() {
        let class_only = OsEvidence {
            vendor: None,
            product: None,
            version: None,
            confidence: 0.5,
            ..a_named_appliance()
        };
        let resolved = resolve(vec![class_only]).expect("the class is the answer");

        assert_eq!(resolved.device.as_deref(), Some("Printer"));
        assert_eq!(
            resolved.family, None,
            "it still says nothing about software"
        );
        assert_eq!(
            resolved.label(),
            "Printer",
            "and that is what a reader sees"
        );
    }

    /// Nothing at all is still nothing.
    #[test]
    fn evidence_that_establishes_no_part_of_an_identity_is_refused() {
        let says_nothing = OsEvidence {
            family: None,
            device: None,
            vendor: None,
            product: None,
            version: None,
            ..a_named_appliance()
        };
        assert!(resolve(vec![says_nothing]).is_none());
    }
}
