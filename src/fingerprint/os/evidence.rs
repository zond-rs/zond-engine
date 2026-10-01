// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Combining what several sources say about one host
//!
//! A stack's shape, a banner and a hardware address are read from different
//! places and fail in different ways. This module combines them.
//!
//! ## Independence
//!
//! Within one reply the fields are not independent, so
//! [`classify`](super::classify) collapses a reply into one item. A host files
//! one banner item per port, so [`resolve`] also counts each source once.
//! Independence is assumed only between sources (stack, banner, hardware
//! address).
//!
//! The arithmetic is [noisy-OR]: agreeing sources raise confidence, and no
//! amount of agreement reaches certainty.
//!
//! [noisy-OR]: https://en.wikipedia.org/wiki/Noisy-or_model
//!
//! ## Two axes
//!
//! What a machine *runs* (family) and what it *is* (device class) are separate.
//! A hop counter says infrastructure and never a vendor; an SNMP agent may name
//! a printer's firmware and never its kernel. See [`OsEvidence::family`].
//!
//! ## Disagreement lowers the answer
//!
//! When sources name different families, the leader is reduced by what the
//! dissenters carry. Below the floor there is no answer.

use crate::model::host::{OsEvidence, OsSource};
use std::collections::BTreeMap;

use super::verdict::{MIN_REPORTABLE_ACCURACY, OsVerdict};

/// The most any combination of sources may claim.
///
/// Noisy-OR alone rounds to 100 at enough agreeing sources. Above the 85 that
/// marks high confidence, so independent sources can reach it; 100 is left for
/// a host that identified itself.
pub const MAX_FUSED_ACCURACY: u8 = 95;

/// Folds every source's opinion into one answer, or none.
///
/// Returns `None` when there is nothing to go on, when the sources disagree
/// badly enough that what survives falls below [`MIN_REPORTABLE_ACCURACY`], or
/// when what survives says nothing about the software.
///
/// # Abstention is not dissent
///
/// Only sources that [name a family](OsEvidence::family) vote on it; the rest
/// add their finer parts to the winner and never count against it. A hop
/// counter of 255 (*network device*) and an SNMP agent (`Brother NC-8700w`)
/// would otherwise cancel each other out.
///
/// Where nobody names a family, the abstentions are the answer.
pub fn resolve(evidence: Vec<OsEvidence>) -> Option<OsVerdict> {
    // A `BTreeMap` so ties resolve the same way on every run.
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
            let score = combine_sources(&items);
            (family, score, items)
        })
        .collect();
    // By score, then family name, independent of insertion order.
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(b.0))
    });

    // The leader is reduced by every dissenting family, combined.
    let mut answer = scored.first().map(|(family, score, items)| {
        let against = combine(scored.iter().skip(1).map(|(_, score, _)| *score));
        (
            Some(*family),
            score * (1.0 - against),
            against,
            items.clone(),
        )
    });

    // A family below the floor drops only itself; the abstentions, unaffected
    // by the dissent, may still be reported.
    if answer
        .as_ref()
        .is_none_or(|(_, survived, ..)| percent(*survived) < MIN_REPORTABLE_ACCURACY)
        && !abstained.is_empty()
    {
        let alone = combine_sources(&abstained);
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

    // Finer parts are kept where every source that stated them agrees; silence
    // abstains, and differing values yield nothing.
    //
    // For product, version and kernel, a value that stops short of another
    // agrees with it (`Windows Server` and `Windows Server 2022`), and the most
    // specific stands; see `stops_short_of`. Other parts must be equal: `x86` is
    // not `x86-64` cut short.
    let stated = |part: fn(&OsEvidence) -> &Option<String>| -> Vec<&str> {
        items
            .iter()
            .filter_map(|item| part(item).as_deref())
            .collect()
    };
    let agreed = |part: fn(&OsEvidence) -> &Option<String>| -> Option<String> {
        let stated = stated(part);
        let candidate = stated.first()?;
        stated
            .iter()
            .all(|other| other == candidate)
            .then(|| (*candidate).to_owned())
    };
    let deepest = |part: fn(&OsEvidence) -> &Option<String>| -> Option<String> {
        let stated = stated(part);
        let most = stated.iter().copied().max_by_key(|value| value.len())?;
        stated
            .iter()
            .all(|other| stops_short_of(other, most))
            .then(|| most.to_owned())
    };

    // Attributed to the strongest contributing source.
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

    let (vendor, product, version, kernel, arch, device) = (
        agreed(|item| &item.vendor),
        deepest(|item| &item.product),
        deepest(|item| &item.version),
        deepest(|item| &item.kernel),
        agreed(|item| &item.arch),
        agreed(|item| &item.device),
    );

    // The CPE comes only from sources stating exactly the merged product and
    // version; a shorter reading's CPE (`windows` beside `Windows Server 2022`)
    // describes something coarser. None where those sources disagree or carry
    // none.
    let cpe = {
        let concluded: Vec<&OsEvidence> = items
            .iter()
            .copied()
            .filter(|item| item.product == product && item.version == version)
            .collect();
        let stated: Vec<&str> = concluded
            .iter()
            .filter_map(|item| item.cpe.as_deref())
            .collect();
        stated
            .first()
            .filter(|candidate| stated.iter().all(|other| other == *candidate))
            .map(|candidate| (*candidate).to_owned())
    };

    // Any one of these is an answer; a device class alone is all a hop-counter
    // rule establishes.
    if family.is_none() && device.is_none() && vendor.is_none() && product.is_none() {
        return None;
    }

    // The finer parts' own accuracy: often one source names the release while
    // several agree on the family (on one host, 84 for Linux, 55 for the
    // release). Combined over the sources that stated finer parts, reduced by
    // the same dissent as the family.
    let refined = vendor.is_some()
        || product.is_some()
        || version.is_some()
        || kernel.is_some()
        || arch.is_some()
        || cpe.is_some()
        || device.is_some();
    let detail_accuracy = refined.then(|| {
        let stated: Vec<&OsEvidence> = items
            .iter()
            .copied()
            .filter(|item| {
                item.vendor.is_some()
                    || item.product.is_some()
                    || item.version.is_some()
                    || item.kernel.is_some()
                    || item.arch.is_some()
                    || item.cpe.is_some()
                    || item.device.is_some()
            })
            .collect();

        percent(combine_sources(&stated) * (1.0 - against))
    });

    Some(OsVerdict {
        family: family.map(ToOwned::to_owned),
        device,
        vendor,
        product,
        version,
        kernel,
        arch,
        cpe,
        accuracy,
        detail_accuracy,
        source: strongest.source,
        evidence: lines.join(" | "),
    })
}

/// Whether `general` is `specific`, or `specific` cut short at a boundary
/// between words or version components: `Windows Server` of `Windows Server
/// 2022`, `10.0` of `10.0.20348`, and not `Windows Server 20` of either.
fn stops_short_of(general: &str, specific: &str) -> bool {
    specific
        .strip_prefix(general)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '.', '-']))
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
/// `1 - Π(1 - p)`. Two sources at 0.5 give 0.75; only a certain source
/// reaches 1.
fn combine(confidences: impl Iterator<Item = f32>) -> f32 {
    let doubt = confidences
        .map(|confidence| 1.0 - confidence.clamp(0.0, 1.0))
        .product::<f32>();
    1.0 - doubt
}

/// The same arithmetic over evidence, counting each source once.
///
/// A host files one [`OsSource::ServiceBanner`] item per port; counted item by
/// item, a host contradicting itself across ports would score higher than one
/// that agrees. Only the strongest reading from each source counts.
fn combine_sources(items: &[&OsEvidence]) -> f32 {
    let mut strongest: BTreeMap<OsSource, f32> = BTreeMap::new();
    for item in items {
        strongest
            .entry(item.source)
            .and_modify(|best| *best = best.max(item.confidence))
            .or_insert(item.confidence);
    }
    combine(strongest.into_values())
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

    /// A Brother print server's agent answer from 2026-08-26: make, model and
    /// firmware, no operating system.
    fn a_named_appliance() -> OsEvidence {
        OsEvidence {
            source: OsSource::SnmpAgent,
            family: None,
            device: Some("Printer".to_string()),
            vendor: Some("Brother".to_string()),
            product: Some("NC-8700w".to_string()),
            version: Some("ZL".to_string()),
            kernel: None,
            arch: None,
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
            arch: None,
            cpe: None,
            confidence,
            evidence: format!("{source:?} says {family}"),
        }
    }

    /// Every source this build knows, each at the most anything filing under it
    /// may claim.
    ///
    /// Built from one exhaustive match, so a new [`OsSource`] must get a row.
    /// Prices are read from where production sets them; where two producers
    /// share a source the higher is taken.
    fn every_source_at_its_ceiling() -> Vec<(OsSource, f32)> {
        use super::super::{MAX_STACK_ACCURACY, ceiling, hardware, hostname};

        macro_rules! rows {
            ($($source:ident => $price:expr),+ $(,)?) => {{
                let price = |source: OsSource| match source {
                    $(OsSource::$source => $price),+
                };
                vec![$((OsSource::$source, price(OsSource::$source))),+]
            }};
        }

        rows![
            TcpStack => f32::from(MAX_STACK_ACCURACY) / 100.0,
            HardwareVendor => hardware::CONFIDENCE,
            // Text kinds, priced by `ceiling`.
            ServiceBanner => ceiling(OsSource::ServiceBanner),
            SnmpAgent => ceiling(OsSource::SnmpAgent),
            // The device-info record and the announced `.local` name.
            MdnsResponder => ceiling(OsSource::MdnsResponder).max(hostname::CONFIDENCE),
            Hostname => hostname::CONFIDENCE,
        ]
    }

    /// A second independent source can carry a stack reading past the
    /// high-confidence threshold.
    #[test]
    fn two_agreeing_sources_are_worth_more_than_either() {
        let stack = evidence("Linux", 0.65, OsSource::TcpStack);
        let hardware = evidence("Linux", 0.30, OsSource::HardwareVendor);

        let alone = resolve(vec![stack.clone()]).expect("one source names it");
        let together = resolve(vec![stack, hardware]).expect("two sources name it");

        assert!(together.accuracy > alone.accuracy);
        assert_eq!(together.accuracy, 76, "1 - (0.35 x 0.70)");
    }

    /// Agreement of every source stays under [`MAX_FUSED_ACCURACY`].
    #[test]
    fn no_amount_of_agreement_reaches_certainty() {
        let many: Vec<OsEvidence> = every_source_at_its_ceiling()
            .into_iter()
            .map(|(source, _)| evidence("Linux", 0.6, source))
            .collect();

        let resolved = resolve(many).expect("named");
        assert_eq!(
            resolved.accuracy, MAX_FUSED_ACCURACY,
            "every source agreeing may be highly confident and must not be certain"
        );
        assert!(
            resolved.accuracy < 100,
            "certainty is reserved for a host that identified itself"
        );
    }

    /// No single source, however often it repeats, settles a host (the 85 the
    /// scanner reads). Every source in [`every_source_at_its_ceiling`] is run
    /// naming a family, naming only a device class, and mixing the two, down
    /// both of [`resolve`]'s routes.
    ///
    /// # What it cannot see
    ///
    /// One observation filed under two sources arrives as two witnesses. Single
    /// replies are swept by `one_reply_is_one_witness` in the fingerprint corpus
    /// tests; joins across exchanges are pinned where they are made, as in
    /// `identify`'s tests.
    #[test]
    fn no_single_source_settles_a_host() {
        for (source, ceiling) in every_source_at_its_ceiling() {
            // More claims than a host retains, all from one source.
            let naming = |nth: usize| OsEvidence {
                version: Some(nth.to_string()),
                ..evidence("Linux", ceiling, source)
            };
            let abstaining = |nth: usize| OsEvidence {
                family: None,
                device: Some("Router".to_string()),
                ..naming(nth)
            };
            let shapes: [(&str, Vec<OsEvidence>); 3] = [
                ("naming a family", (0..20).map(naming).collect()),
                ("naming only a device", (0..20).map(abstaining).collect()),
                (
                    "mixing the two",
                    (0..20)
                        .map(|nth| {
                            if nth % 2 == 0 {
                                naming(nth)
                            } else {
                                abstaining(nth)
                            }
                        })
                        .collect(),
                ),
            ];

            for (shape, many) in shapes {
                // Two sources sit under the reporting floor and name nothing alone.
                if let Some(resolved) = resolve(many) {
                    assert!(
                        !resolved.to_fingerprint().is_highly_confident(),
                        "{source:?}, {shape}, settled a host on its own at {}",
                        resolved.accuracy
                    );
                }
            }
        }
    }

    /// A host answering many ways is one witness, so it cannot pass
    /// [`BANNER_CEILING`](super::super::BANNER_CEILING) or
    /// [`MAX_STACK_ACCURACY`](super::super::MAX_STACK_ACCURACY) by repetition.
    #[test]
    fn one_source_counts_once_however_many_claims_it_files() {
        let alone = resolve(vec![evidence("Linux", 0.55, OsSource::ServiceBanner)])
            .expect("a banner names a host");

        // Three releases no machine can be at once.
        let contradicting: Vec<OsEvidence> = ["11", "12", "13"]
            .into_iter()
            .map(|release| OsEvidence {
                version: Some(release.to_string()),
                ..evidence("Linux", 0.55, OsSource::ServiceBanner)
            })
            .collect();

        let resolved = resolve(contradicting).expect("still names the family");
        assert_eq!(
            resolved.accuracy, alone.accuracy,
            "a host that contradicted itself twice is not better attested than one that spoke once"
        );
        assert!(
            resolved.version.is_none(),
            "and the release the three disagree about is not reported"
        );
    }

    /// Two different sources agreeing still beat either alone.
    #[test]
    fn distinct_sources_still_corroborate() {
        let banner = evidence("Linux", 0.55, OsSource::ServiceBanner);
        let stack = evidence("Linux", 0.65, OsSource::TcpStack);

        let alone = resolve(vec![stack.clone()]).expect("one source names it");
        let both = resolve(vec![banner, stack]).expect("two sources name it");

        assert!(
            both.accuracy > alone.accuracy,
            "a banner agreeing with the wire is worth more than the wire alone"
        );
    }

    /// Disagreeing sources lower the answer.
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

    /// A strong enough conflict leaves no answer.
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
    /// A hardware vendor from an address registration says nothing about the
    /// distribution and must not erase it.
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

    /// Two sources naming different products keep the shared family and drop the
    /// product.
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

    /// A reading that stops short of another agrees with it; the more specific
    /// stands. A domain controller's functional level says `Windows Server` and
    /// its SMB build `Windows Server 2022`.
    #[test]
    fn a_reading_cut_short_of_another_keeps_the_more_specific_one() {
        let named = |product: &str, kernel: Option<&str>| {
            let mut item = evidence("Windows", 0.6, OsSource::ServiceBanner);
            item.product = Some(product.to_string());
            item.kernel = kernel.map(str::to_string);
            item
        };
        let build = named("Windows Server 2022", Some("10.0.20348"));
        let level = named("Windows Server", None);
        let mut stack = evidence("Windows", 0.65, OsSource::TcpStack);
        stack.kernel = Some("10.0".to_string());

        for order in [
            vec![build.clone(), level.clone(), stack.clone()],
            vec![stack, level, build],
        ] {
            let resolved = resolve(order).expect("named");
            assert_eq!(resolved.product.as_deref(), Some("Windows Server 2022"));
            assert_eq!(resolved.kernel.as_deref(), Some("10.0.20348"));
        }

        // Cut mid-word, or a different release: no agreement.
        for other in ["Windows Server 20", "Windows Server 2019"] {
            let resolved = resolve(vec![named("Windows Server 2022", None), named(other, None)])
                .expect("the family is agreed");
            assert_eq!(resolved.product, None, "{other}");
        }
    }

    /// The CPE is the concluded reading's. Two sources stating the concluded
    /// release with different CPEs leave none.
    #[test]
    fn the_cpe_is_the_one_the_concluded_release_carries() {
        let named = |product: &str, version: Option<&str>, cpe: &str| {
            let mut item = evidence("Windows", 0.6, OsSource::ServiceBanner);
            item.product = Some(product.to_string());
            item.version = version.map(str::to_string);
            item.cpe = Some(cpe.to_string());
            item
        };
        let release = named(
            "Windows Server 2022",
            None,
            "cpe:/o:microsoft:windows_server_2022:-",
        );
        let family = named("Windows Server", None, "cpe:/o:microsoft:windows:-");
        let resolved = resolve(vec![family, release.clone()]).expect("named");
        assert_eq!(
            resolved.cpe.as_deref(),
            Some("cpe:/o:microsoft:windows_server_2022:-")
        );

        let patched = named(
            "Windows Server 2008",
            Some("SP2"),
            "cpe:/o:microsoft:windows_server_2008:SP2",
        );
        let unpatched = named(
            "Windows Server 2008",
            None,
            "cpe:/o:microsoft:windows_server_2008:-",
        );
        let resolved = resolve(vec![unpatched, patched]).expect("named");
        assert_eq!(resolved.version.as_deref(), Some("SP2"));
        assert_eq!(
            resolved.cpe.as_deref(),
            Some("cpe:/o:microsoft:windows_server_2008:SP2")
        );

        let mut other = release.clone();
        other.source = OsSource::SnmpAgent;
        other.cpe = Some("cpe:/o:microsoft:windows_server:2022".to_string());
        let resolved = resolve(vec![release, other]).expect("named");
        assert_eq!(resolved.product.as_deref(), Some("Windows Server 2022"));
        assert_eq!(resolved.cpe, None, "two identifiers for one release");
    }

    /// Resolution is deterministic regardless of input order.
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

    /// A hop counter of 255 (*network device*) and an SNMP agent
    /// (*Brother NC-8700w*) combine; as rival families, 0.4 reduced by 0.385
    /// would leave 25, under the floor.
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

    /// With no family named, the abstention is the answer.
    #[test]
    fn an_abstention_alone_is_still_an_answer() {
        let resolved = resolve(vec![a_named_appliance()]).expect("named");

        assert_eq!(resolved.family, None);
        assert_eq!(resolved.product.as_deref(), Some("NC-8700w"));
        assert_eq!(resolved.accuracy, percent(0.56));
    }

    /// A family below the floor takes only itself down.
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

    /// A class of box on its own **is** a verdict, although something knowing
    /// only what the hardware is has identified no software.
    ///
    /// Hop-counter rules state only a class, which may be all that is known about
    /// a switch with no open port and no name.
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
