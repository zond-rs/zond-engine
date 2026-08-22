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
//! So [`classify`](super::classify) already collapses a whole reply into **one**
//! item. What arrives here is one item per genuinely distinct source, and
//! independence is claimed only between those — a stack, a banner, a hardware
//! address — where it is close enough to true to build on.
//!
//! That is also why the arithmetic below is [noisy-OR] rather than a sum. Two
//! sources agreeing raise confidence without either being trusted more than it
//! deserves, and no amount of agreement reaches certainty.
//!
//! [noisy-OR]: https://en.wikipedia.org/wiki/Noisy-or_model
//!
//! ## Disagreement lowers the answer rather than picking a winner
//!
//! When sources name different families, the leader is reduced by whatever the
//! runner-up carries. Two sources at odds are a worse position than one source
//! alone, and a resolver that took the larger and reported it at full strength
//! would be hiding the conflict at exactly the moment it matters. Below the floor
//! the result is no answer, which is the honest outcome for a host two techniques
//! disagree about.

use std::collections::BTreeMap;

use super::verdict::{MIN_REPORTABLE_ACCURACY, OsSource, OsVerdict};

/// The most any combination of sources may claim.
///
/// Noisy-OR approaches certainty without reaching it, which is the right shape
/// and not enough on its own: at twenty agreeing sources the arithmetic lands
/// close enough that rounding to a percentage produces 100, and a scan reporting
/// an operating system as certain on accumulated inference would be claiming
/// something none of its sources said.
///
/// Above the 85 that marks high confidence, so agreement between genuinely
/// independent sources can still get there — that is the whole point of having
/// more than one. Below 100, which stays reserved for a host that identified
/// itself rather than one that was worked out.
pub const MAX_FUSED_ACCURACY: u8 = 95;

/// One source's opinion about one host.
///
/// The identity is a path like [`OsVerdict`]'s, and the confidence is a
/// probability rather than a percentage — the arithmetic that combines these
/// only makes sense on `0.0..=1.0`.
#[derive(Debug, Clone, PartialEq)]
pub struct OsEvidence {
    /// What produced it.
    pub source: OsSource,
    /// The broad family. The one part every source can supply.
    pub family: String,
    /// The vendor, where the source knew one.
    pub vendor: Option<String>,
    /// The product, where the source knew one.
    pub product: Option<String>,
    /// The version, where the source knew one.
    pub version: Option<String>,
    /// The kernel release, where the source read one.
    ///
    /// Beside the version rather than instead of it: a distribution release and
    /// the kernel it ships are two facts, not two answers.
    pub kernel: Option<String>,
    /// A Common Platform Enumeration identifier, where one applies exactly.
    pub cpe: Option<String>,
    /// How much this source is worth on its own, from 0 to 1.
    ///
    /// Not a percentage and not an accuracy: it is what this one source
    /// contributes before anything else is taken into account, and the value a
    /// source alone would produce is its own ceiling.
    pub confidence: f32,
    /// One line describing what was read, for the report to carry.
    pub evidence: String,
}

/// Folds every source's opinion into one answer, or none.
///
/// Returns `None` when there is nothing to go on, or when the sources disagree
/// badly enough that what survives falls below
/// [`MIN_REPORTABLE_ACCURACY`].
pub fn resolve(evidence: Vec<OsEvidence>) -> Option<OsVerdict> {
    if evidence.is_empty() {
        return None;
    }

    // Grouped by family, because that is the level every source can speak to.
    // A `BTreeMap` so two runs over the same evidence resolve the same way: with
    // scores this close together, iteration order would otherwise decide ties.
    let mut by_family: BTreeMap<&str, Vec<&OsEvidence>> = BTreeMap::new();
    for item in &evidence {
        by_family
            .entry(item.family.as_str())
            .or_default()
            .push(item);
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

    let (family, score, items) = scored.first()?;
    // Everything naming a different family, combined, is what the leader has to
    // survive. One dissenting source is a doubt; several agreeing with each other
    // against the leader is close to a refutation.
    let against = combine(scored.iter().skip(1).map(|(_, score, _)| *score));
    let survived = score * (1.0 - against);

    let accuracy = (survived * 100.0)
        .round()
        .clamp(0.0, f32::from(MAX_FUSED_ACCURACY)) as u8;
    if accuracy < MIN_REPORTABLE_ACCURACY {
        return None;
    }

    // The finer parts of the path are kept where every source that *spoke to*
    // them agrees. A source saying nothing about a version abstains rather than
    // dissenting: a stack rule can name a family and never a release, so
    // counting its silence as disagreement would mean a banner that read
    // "Ubuntu 22.04" off the wire loses it the moment a stack rule corroborates
    // the family — more evidence producing a less specific answer. Two sources
    // naming *different* values still yield nothing.
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

    let (vendor, product, version, kernel, cpe) = (
        agreed(|item| &item.vendor),
        agreed(|item| &item.product),
        agreed(|item| &item.version),
        agreed(|item| &item.kernel),
        agreed(|item| &item.cpe),
    );

    // What the finer parts are worth, as distinct from the family.
    //
    // Every source can speak to a family, and `accuracy` above is their
    // agreement about it. A release is usually named by exactly one of them, so
    // reporting it under that figure launders one weaker claim through the
    // agreement of several stronger ones — measured, on a real host: two sources
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
        || cpe.is_some();
    let detail_accuracy = refined.then(|| {
        let stated = items
            .iter()
            .filter(|item| {
                item.vendor.is_some()
                    || item.product.is_some()
                    || item.version.is_some()
                    || item.kernel.is_some()
                    || item.cpe.is_some()
            })
            .map(|item| item.confidence);

        ((combine(stated) * (1.0 - against)) * 100.0)
            .round()
            .clamp(0.0, f32::from(MAX_FUSED_ACCURACY)) as u8
    });

    Some(OsVerdict {
        family: (*family).to_string(),
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

/// Combines independent probabilities for one hypothesis: the chance that *at
/// least one* of them is right.
///
/// `1 - Π(1 - p)`. Two sources at 0.5 give 0.75 rather than 1.0, and nothing
/// short of a certain source ever reaches 1 — which is the property that matters,
/// because a stack of agreeing guesses must not become a fact.
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

    fn evidence(family: &str, confidence: f32, source: OsSource) -> OsEvidence {
        OsEvidence {
            source,
            family: family.to_string(),
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

        assert_eq!(contested.family, "Linux");
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
    /// name the moment anything else corroborates the family — more evidence
    /// producing a less specific answer, which is the wrong direction for
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
        assert_eq!(resolved.family, "Linux");
        assert_eq!(
            resolved.product.as_deref(),
            Some("Ubuntu"),
            "the only source that could name a product named one, and nothing contradicted it"
        );
    }

    /// Abstention is not agreement with anything, though. Two sources naming
    /// *different* products cannot both be right, and nothing here can say which
    /// is — so the answer keeps the family they share and drops the part they
    /// contest.
    #[test]
    fn two_sources_naming_different_products_keep_neither() {
        let mut stack = evidence("Linux", 0.65, OsSource::TcpStack);
        stack.product = Some("Ubuntu".to_string());
        let mut banner = evidence("Linux", 0.65, OsSource::ServiceBanner);
        banner.product = Some("Debian".to_string());

        let resolved = resolve(vec![stack, banner]).expect("the family is agreed");
        assert_eq!(resolved.family, "Linux");
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
}
