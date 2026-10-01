// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Corpus regression tests for the operating-system rules
//!
//! Every shipped rule carries examples measured off real hosts. These run them.
//!
//! [`every_example_matches_its_own_rule`] catches a rule that stopped matching
//! what it was written for.
//!
//! [`no_example_matches_another_familys_rule`] catches the silent failure: a
//! rule with too few predicates matching hosts it was not written for. The
//! build refuses a rule with **no** predicates; only this catches one with too
//! few.

use crate::model::capture::{IpObservation, Ipv4Observation};

use super::db::RuleDb;
use super::observation::StackReply;
use super::observation::{StackObservation, TcpOptionKind};
use super::rules;
use super::series::{ClockClass, IdClass, IsnClass, SeriesClasses};
use super::signature::{Example, Provenance, ReplyKind};

/// Builds the observation an example describes.
///
/// The option layout is rebuilt from its letters, since an example records
/// values, not frames. Byte parsing is tested elsewhere.
fn observation_from(example: &Example) -> StackReply {
    // An echo example shares only the IP header with a TCP one.
    if example.reply == ReplyKind::EchoReply {
        return StackReply::Echo(super::observation::EchoObservation {
            ip: IpObservation::V4(Ipv4Observation {
                ttl: example.remaining_hops,
                identification: 0,
                dont_fragment: example.dont_fragment,
                more_fragments: false,
                dscp: 0,
                ecn: 0,
            }),
            code: example.echo_code,
            // Not an authored field; rules read only whether it came back intact.
            payload_len: 0,
            payload_intact: example.echo_payload_intact,
        });
    }

    tcp_observation_from(example)
}

fn tcp_observation_from(example: &Example) -> StackReply {
    let layout = example
        .option_layout
        .split(',')
        .filter(|letter| !letter.is_empty())
        .map(|letter| match letter {
            "E" => TcpOptionKind::EndOfList,
            "N" => TcpOptionKind::NoOp,
            "M" => TcpOptionKind::MaximumSegmentSize,
            "W" => TcpOptionKind::WindowScale,
            "S" => TcpOptionKind::SackPermitted,
            "K" => TcpOptionKind::Sack,
            "T" => TcpOptionKind::Timestamp,
            other => panic!("an example names an option letter nothing writes: {other:?}"),
        })
        .collect();

    let flags = match example.reply {
        ReplyKind::SynAck => crate::protocols::tcp::flags::SYN | crate::protocols::tcp::flags::ACK,
        ReplyKind::Reset => crate::protocols::tcp::flags::RST,
        ReplyKind::EchoReply => unreachable!("an echo example is built above"),
    };

    StackReply::Tcp(StackObservation {
        flags,
        ip: IpObservation::V4(Ipv4Observation {
            ttl: example.remaining_hops,
            identification: 0,
            dont_fragment: example.dont_fragment,
            more_fragments: false,
            dscp: 0,
            ecn: 0,
        }),
        window: example.window.unwrap_or_default(),
        option_layout: layout,
        mss: example.mss,
        window_scale: example.window_scale,
        timestamps: example
            .timestamps
            .then_some(super::observation::Timestamps { value: 1, echo: 0 }),
        sack_permitted: example.sack_permitted,
        quirks: Default::default(),
    })
}

/// What the series behind an example read, where it recorded one.
///
/// A series rule matches only through
/// [`matches_with_series`](rules::matches_with_series), so its examples run that
/// way.
///
/// A class name nothing produces panics.
fn series_from(example: &Example) -> Option<SeriesClasses> {
    if !example.records_a_series() {
        return None;
    }

    let read = |stated: &Option<String>, kind: &str, parse: &dyn Fn(&str) -> bool| {
        if let Some(name) = stated
            && !parse(name)
        {
            panic!("an example names a {kind} class nothing produces: {name:?}");
        }
    };
    read(&example.identifier_class, "identifier", &|name| {
        IdClass::from_name(name).is_some()
    });
    read(&example.sequence_class, "sequence", &|name| {
        IsnClass::from_name(name).is_some()
    });
    read(&example.clock_class, "clock", &|name| {
        ClockClass::from_name(name).is_some()
    });

    Some(SeriesClasses {
        identifiers: example
            .identifier_class
            .as_deref()
            .and_then(IdClass::from_name)
            .unwrap_or(IdClass::TooFew),
        sequences: example
            .sequence_class
            .as_deref()
            .and_then(IsnClass::from_name)
            .unwrap_or(IsnClass::TooFew),
        clock: example
            .clock_class
            .as_deref()
            .and_then(ClockClass::from_name)
            .unwrap_or(ClockClass::TooFew),
    })
}

/// Whether `rule` describes `example`, through whichever matcher the example's
/// own measurement supports.
fn rule_matches(rule: &super::signature::MatchRule, example: &Example) -> bool {
    let observed = observation_from(example);
    match series_from(example) {
        Some(series) => rules::matches_with_series(rule, &observed, &series),
        None => rules::matches(rule, &observed),
    }
}

/// Every rule matches its own examples.
#[test]
fn every_example_matches_its_own_rule() {
    let db = RuleDb::global();
    let mut failures = Vec::new();

    for rule in db.rules() {
        for example in &rule.example {
            if !rule_matches(&rule.r#match, example) {
                failures.push(format!(
                    "'{}' no longer matches its own example: {}",
                    rule.os.label(),
                    example.source
                ));
            }
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// No example matches another family's rule. Same-family matches are allowed.
///
/// [`the_cross_family_check_catches_a_rule_that_is_too_loose`] shows the
/// comparison can fail.
#[test]
fn no_example_matches_another_familys_rule() {
    let db = RuleDb::global();
    let mut failures = Vec::new();

    for owner in db.rules() {
        for example in &owner.example {
            for other in db.rules() {
                if other.os.label() == owner.os.label() {
                    continue;
                }
                if rule_matches(&other.r#match, example) {
                    failures.push(format!(
                        "'{}' matches an example belonging to '{}': {}",
                        other.os.label(),
                        owner.os.label(),
                        example.source
                    ));
                }
            }
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A rule claiming to be **measured** must ship the observation it was measured
/// from.
///
/// A published rule may have none; a measured one scores higher, so its claim
/// must be checkable.
#[test]
fn every_measured_rule_ships_what_it_measured() {
    let mut offenders = Vec::new();
    for rule in RuleDb::global().rules() {
        if rule.provenance == Provenance::Measured && rule.example.is_empty() {
            offenders.push(rule.os.label());
        }
    }

    assert!(
        offenders.is_empty(),
        "these rules claim to be measured and record no observation: {offenders:?}. \
         Either ship the values that were seen, or mark the rule `published`."
    );
}

/// A published rule must say where its values came from.
///
/// The note lets someone confirm or correct it later.
#[test]
fn every_published_rule_says_what_it_rests_on() {
    let mut offenders = Vec::new();
    for rule in RuleDb::global().rules() {
        if rule.provenance == Provenance::Published
            && rule.notes.as_deref().unwrap_or("").trim().len() < 40
        {
            offenders.push(rule.os.label());
        }
    }

    assert!(
        offenders.is_empty(),
        "these rules are unconfirmed and do not say what they rest on: {offenders:?}"
    );
}

/// The families the corpus covers, pinned so growth is a deliberate edit.
///
/// Not a claim that each is verified; see
/// [`every_measured_rule_ships_what_it_measured`].
#[test]
fn the_corpus_covers_the_families_it_says_it_does() {
    let db = RuleDb::global();
    let mut families: Vec<&str> = db.rules().iter().map(|r| r.os.label()).collect();
    families.sort_unstable();
    families.dedup();

    assert_eq!(
        families,
        vec!["FreeBSD", "Linux", "Network device", "Windows", "macOS"],
        "the set of families changed; see assets/fingerprinting/os/README.md"
    );
}

/// Every shipped rule states at least one predicate. The build enforces this
/// too, but `build.rs` does not run under `cargo test`.
#[test]
fn every_rule_tests_something() {
    for rule in RuleDb::global().rules() {
        let r#match = &rule.r#match;
        let stated = [
            r#match.initial_hops.is_some(),
            r#match.dont_fragment.is_some(),
            r#match.option_layout.is_some(),
            r#match.window.is_some(),
            r#match.window_units.is_some(),
            r#match.window_remainder.is_some(),
            r#match.window_scale.is_some(),
            r#match.mss.is_some(),
            r#match.timestamps.is_some(),
            r#match.sack_permitted.is_some(),
            r#match.identifier_class.is_some(),
            r#match.sequence_class.is_some(),
            r#match.clock_class.is_some(),
        ]
        .into_iter()
        .filter(|stated| *stated)
        .count();

        assert!(
            stated > 0,
            "'{}' states no predicates, so it matches every reply of its kind",
            rule.os.label()
        );
    }
}

/// A handshake rule is never satisfied by a reset, even one stating only
/// IP-level predicates.
#[test]
fn a_handshake_rule_is_never_satisfied_by_a_reset() {
    let db = RuleDb::global();
    let example = db
        .rules()
        .iter()
        .flat_map(|rule| &rule.example)
        .find(|example| example.reply == ReplyKind::SynAck)
        .expect("the corpus ships a handshake example");

    let mut as_reset = match observation_from(example) {
        StackReply::Tcp(observed) => observed,
        StackReply::Echo(_) => unreachable!("the example was chosen as a handshake"),
    };
    as_reset.flags = crate::protocols::tcp::flags::RST;
    let as_reset = StackReply::Tcp(as_reset);

    for rule in db.rules() {
        assert!(
            !rules::matches(&rule.r#match, &as_reset),
            "'{}' matched a reset, but it is written for a handshake",
            rule.os.label()
        );
    }
}

/// A series rule is checked against its example as the active path would run
/// it. Synthetic, since the shipped corpus holds no series rule.
#[test]
fn a_series_example_is_run_through_the_series_matcher() {
    use super::signature::{MatchRule, Predicate};

    let mut example = Example {
        source: "a synthetic measurement, for this test".to_string(),
        reply: ReplyKind::SynAck,
        remaining_hops: 64,
        dont_fragment: true,
        option_layout: "M,S,T,N,W".to_string(),
        window: Some(65_160),
        mss: Some(1460),
        window_scale: Some(7),
        timestamps: true,
        sack_permitted: true,
        echo_code: 0,
        echo_payload_intact: true,
        identifier_class: None,
        sequence_class: Some("hashed".to_string()),
        clock_class: None,
    };

    let rule = MatchRule {
        reply: ReplyKind::SynAck,
        initial_hops: Some(Predicate {
            equals: Some(64),
            any_of: None,
            range: None,
        }),
        sequence_class: Some(Predicate {
            equals: Some("hashed".to_string()),
            any_of: None,
            range: None,
        }),
        ..Default::default()
    };

    assert!(
        rule_matches(&rule, &example),
        "an example recording its series is matched through the series matcher"
    );
    assert!(
        !rules::matches(&rule, &observation_from(&example)),
        "and the single-reply matcher still refuses it, which is why the \
         distinction has to be made"
    );

    // An unexpected class: the rule no longer matches.
    example.sequence_class = Some("fixed-step".to_string());
    assert!(!rule_matches(&rule, &example));
}

/// An example naming a class nothing produces is caught as a typo.
#[test]
#[should_panic(expected = "names a sequence class nothing produces")]
fn an_example_naming_a_class_nothing_produces_is_caught() {
    let example = Example {
        source: "a typo".to_string(),
        reply: ReplyKind::SynAck,
        remaining_hops: 64,
        dont_fragment: true,
        option_layout: String::new(),
        window: Some(64_240),
        mss: None,
        window_scale: None,
        timestamps: false,
        sack_permitted: false,
        echo_code: 0,
        echo_payload_intact: true,
        identifier_class: None,
        sequence_class: Some("hashd".to_string()),
        clock_class: None,
    };
    let _ = series_from(&example);
}

/// A rule naming a different family with one weak predicate is flagged. This
/// also guards against `rules::matches` returning `false` unconditionally.
#[test]
fn the_cross_family_check_catches_a_rule_that_is_too_loose() {
    use super::signature::{MatchRule, OsDefinition, OsIdentity, Predicate};

    let observed = observation_from(
        RuleDb::global()
            .rules()
            .iter()
            .flat_map(|rule| &rule.example)
            .find(|example| example.reply == ReplyKind::SynAck)
            .expect("the corpus ships a handshake example"),
    );

    let too_loose = OsDefinition {
        os: OsIdentity {
            family: Some("Definitely Not Linux".to_string()),
            device: None,
            vendor: None,
            product: None,
            version: None,
            cpe: None,
        },
        provenance: Provenance::Published,
        notes: None,
        weight: 1.0,
        r#match: MatchRule {
            reply: ReplyKind::SynAck,
            // Nearly every on-link host satisfies it.
            initial_hops: Some(Predicate {
                equals: Some(64),
                ..Default::default()
            }),
            ..Default::default()
        },
        example: Vec::new(),
    };

    assert!(
        rules::matches(&too_loose.r#match, &observed),
        "a rule this loose must match a Linux example, or the cross-family check \
         is incapable of catching one"
    );

    // A shape no rule was written for is declined by all. The option layout is
    // changed, since the BSD and Darwin rules test no window and the
    // network-device rule keys on a hop counter of 255.
    let mut elsewhere = match observed.clone() {
        StackReply::Tcp(observed) => observed,
        StackReply::Echo(_) => unreachable!("the example was chosen as a handshake"),
    };
    elsewhere.option_layout = vec![
        TcpOptionKind::MaximumSegmentSize,
        TcpOptionKind::Sack,
        TcpOptionKind::Other(99),
    ];
    let elsewhere = StackReply::Tcp(elsewhere);
    let matched: Vec<&str> = RuleDb::global()
        .matching(&elsewhere)
        .map(|rule| rule.os.label())
        .collect();
    assert!(
        matched.is_empty(),
        "a shape nothing emits was matched by {matched:?}, so those rules are looser \
         than the families they name"
    );
}

/// `assets/` ships to crates.io, so provenance may say what *kind* of machine
/// was measured but never whose: no addresses or hostnames. Documentation
/// ranges (RFC 5737, RFC 3849) are fine.
#[test]
fn no_rule_names_a_real_address_or_host() {
    // Crude on purpose: a false positive costs a reworded line, a false
    // negative is published for good.
    let looks_like_ipv4 = |text: &str| {
        text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .any(|token| {
                let parts: Vec<&str> = token.split('.').collect();
                parts.len() == 4
                    && parts
                        .iter()
                        .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
            })
    };
    let documentation_range = |text: &str| {
        ["192.0.2.", "198.51.100.", "203.0.113."]
            .iter()
            .any(|prefix| text.contains(prefix))
    };

    let mut offenders = Vec::new();
    for rule in RuleDb::global().rules() {
        for example in &rule.example {
            let source = &example.source;
            if looks_like_ipv4(source) && !documentation_range(source) {
                offenders.push(format!("'{}': {source}", rule.os.label()));
            }
            for suffix in [".local", ".lan", ".home", ".internal"] {
                if source.contains(suffix) {
                    offenders.push(format!("'{}': {source}", rule.os.label()));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a published rule names somebody's network. Say what kind of machine was \
         measured, not which one:\n{}",
        offenders.join("\n")
    );
}

/// The echo rules reach a host the TCP rules cannot, and name it.
///
/// A stock Windows firewall drops TCP probes, so only a ping reaches it. A hop
/// counter of 128 says what the host *runs*; 255 says what it *is*.
#[test]
fn an_echo_reply_alone_can_name_a_host() {
    let windows = echo_reply(128);
    let verdict = super::verdict::classify(RuleDb::global(), &windows)
        .expect("an echo reply with a Windows hop counter names Windows");
    assert_eq!(verdict.family.as_deref(), Some("Windows"));
    assert_eq!(verdict.device, None);

    let device = echo_reply(255);
    let verdict = super::verdict::classify(RuleDb::global(), &device)
        .expect("an echo reply with an infrastructure hop counter names a class");
    assert_eq!(verdict.device.as_deref(), Some("Network device"));
    assert_eq!(
        verdict.family, None,
        "a hop counter of 255 says the box is infrastructure, not what runs on it"
    );
    assert_eq!(verdict.label(), "Network device");
}

/// A ping from a Unix-alike is not named: Linux, macOS and the BSDs all start
/// at 64, and an echo reply carries nothing else to separate them. A rule for
/// this needs a second field (the echoed code, the payload), not 64 alone.
#[test]
fn an_echo_reply_from_a_unix_hop_counter_names_nothing() {
    let unix_like = echo_reply(64);
    let matched: Vec<&str> = RuleDb::global()
        .matching(&unix_like)
        .map(|rule| rule.os.label())
        .collect();
    assert!(
        matched.is_empty(),
        "an echo reply with a hop counter of 64 was named {matched:?}, but Linux, \
         macOS and the BSDs all start there and an echo reply carries nothing \
         else to separate them"
    );
}

/// An echo-shaped reply with `hops` left, for the two tests above.
fn echo_reply(hops: u8) -> StackReply {
    StackReply::Echo(super::observation::EchoObservation {
        ip: IpObservation::V4(Ipv4Observation {
            ttl: hops,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            dscp: 0,
            ecn: 0,
        }),
        code: crate::protocols::icmp::ECHO_PROBE_CODE,
        payload_len: 28,
        payload_intact: true,
    })
}
