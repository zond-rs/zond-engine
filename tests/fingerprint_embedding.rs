// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the fingerprinting engine offers somebody embedding it.
//!
//! Every test here compiles against the published surface and nothing else,
//! which is the point: the module documents three extension seams and for a long
//! while none of them was connected. An analyzer could be written and not
//! registered, signatures could be authored and not loaded, and rules could be
//! loaded without any of the checks the build makes. Each of those was invisible
//! from inside the crate, because the crate's own consumer is the CLI and the
//! CLI needs none of it.
//!
//! These are here so the next thing that breaks one of them breaks a test.

use async_trait::async_trait;
use zond_engine::fingerprint::os::{
    MatchRule as OsMatchRule, OsDefinition, OsIdentity, Predicate, Provenance, ReplyKind, RuleDb,
    RuleError,
};
use zond_engine::fingerprint::{
    Analyzer, Collected, Evidence, MatchRule, PortContext, Probe, ResponseSet, ServiceDefinition,
    ServiceSignature, SignatureDb, SourceId, analyze_with, analyzers,
};
use zond_engine::model::confidence::Confidence;
use zond_engine::model::port::Protocol;

/// An analyzer an embedder might write: it reads the shared responses, needs no
/// probe of its own, and names something the shipped corpus never will.
struct HouseAnalyzer;

#[async_trait]
impl Analyzer for HouseAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::BannerRegex
    }

    fn interested(&self, ctx: &PortContext) -> bool {
        ctx.protocol == Protocol::Tcp
    }

    fn analyze(
        &self,
        _ctx: &PortContext,
        responses: &ResponseSet,
        _collected: &Collected,
    ) -> Vec<Evidence> {
        responses
            .banners
            .iter()
            .filter(|banner| banner.contains("ACME-Appliance"))
            .map(|_| {
                Evidence::new(SourceId::BannerRegex, Confidence::Strong)
                    .with_service("acme")
                    .with_product("ACME Appliance")
                    .with_version("4.2")
            })
            .collect()
    }
}

static HOUSE: &HouseAnalyzer = &HouseAnalyzer;

/// **An analyzer written outside the crate can be run.**
///
/// The trait was published and the registry was a private `static`, so an
/// embedder could implement the documented extension point and had nowhere to
/// put the result. Running one beside the built-in set is the whole claim.
#[tokio::test]
async fn an_analyzer_of_ones_own_runs_beside_the_built_in_set() {
    let mut set: Vec<&'static dyn Analyzer> = analyzers().to_vec();
    set.push(HOUSE);
    let set: &'static [&'static dyn Analyzer] = Box::leak(set.into_boxed_slice());

    let responses = ResponseSet::from_banners(vec!["ACME-Appliance ready".to_string()]);
    let verdict = analyze_with(PortContext::new(9000, Protocol::Tcp), responses, set)
        .await
        .expect("the house analyzer named it");

    assert_eq!(verdict.service.as_deref(), Some("acme"));
    assert_eq!(verdict.product.as_deref(), Some("ACME Appliance"));
    assert_eq!(verdict.version.as_deref(), Some("4.2"));
}

/// And the built-in set still answers on its own, so adding one changed nothing
/// about the others.
#[tokio::test]
async fn the_built_in_set_is_unchanged_by_the_seam() {
    let responses = ResponseSet::from_banners(vec!["SSH-2.0-OpenSSH_9.6p1 Debian".to_string()]);
    let verdict = analyze_with(PortContext::new(22, Protocol::Tcp), responses, analyzers())
        .await
        .expect("the banner analyzer named it");

    assert_eq!(verdict.service.as_deref(), Some("ssh"));
    assert_eq!(verdict.product.as_deref(), Some("OpenSSH"));
}

fn definition(name: &str, port: u16, pattern: &str) -> ServiceDefinition {
    ServiceDefinition {
        service: ServiceSignature {
            name: name.to_string(),
            default_ports: vec![port],
            description: None,
            attribution: None,
            speaks: None,
        },
        probe: Vec::new(),
        r#match: vec![MatchRule {
            name: None,
            pattern: pattern.to_string(),
            version_group: Some(1),
            vendor: None,
            product: Some("ACME Appliance".to_string()),
            context: None,
            example: None,
            metadata: None,
        }],
    }
}

/// **Signatures authored outside the crate can be loaded and matched.**
///
/// The authoring schema was exported so a consumer would be held to the same
/// bounds as the shipped corpus, and the constructor that would have taken what
/// they authored was private, so the export bought the types and not the thing
/// the types are for.
#[test]
fn signatures_of_ones_own_can_be_loaded_and_matched() {
    let db = SignatureDb::try_from_definitions(vec![definition(
        "acme",
        9000,
        r"^ACME-Appliance/([\d.]+)",
    )])
    .expect("a well-formed definition");

    let found = db
        .identify(9000, Protocol::Tcp, "ACME-Appliance/4.2 ready")
        .expect("the authored signature matched");

    assert_eq!(found.service.as_deref(), Some("acme"));
    assert_eq!(found.product.as_deref(), Some("ACME Appliance"));
    assert_eq!(found.version.as_deref(), Some("4.2"));
    assert!(found.port_confirmed, "matched on a port it registered");
}

/// And a definition the build would reject is rejected here, with a message
/// naming which one.
#[test]
fn a_definition_the_build_would_reject_does_not_load() {
    let refused = SignatureDb::try_from_definitions(vec![
        definition("fine", 9000, r"^OK/([\d.]+)"),
        definition("broken", 9001, "("),
    ])
    .expect_err("an unclosed group compiles on neither engine");

    let message = refused.to_string();
    assert!(message.contains("definition 1"), "{message}");
    assert!(message.contains("broken"), "{message}");
}

fn os_rule(family: &str, hops: u8) -> OsDefinition {
    OsDefinition {
        os: OsIdentity {
            family: Some(family.to_string()),
            device: None,
            vendor: None,
            product: None,
            version: None,
            cpe: None,
        },
        provenance: Provenance::Published,
        notes: Some("a rule an embedder wrote".to_string()),
        weight: 1.0,
        r#match: OsMatchRule {
            reply: ReplyKind::SynAck,
            initial_hops: Some(Predicate {
                equals: Some(hops),
                any_of: None,
                range: None,
            }),
            ..Default::default()
        },
        example: Vec::new(),
    }
}

/// **Rules of one's own are held to the checks the build makes.**
///
/// The constructor for a caller's own corpus ran none of them, so the one defect
/// the build calls worse than a build failure — a rule testing nothing, which
/// names every host that ever answers — loaded happily.
#[test]
fn rules_of_ones_own_are_checked_the_way_the_build_checks_them() {
    let loaded = RuleDb::try_from_rules(vec![os_rule("Linux", 64)]).expect("a well-formed rule");
    assert_eq!(loaded.rules().len(), 1);

    let mut untested = os_rule("Windows 3.1", 64);
    untested.r#match.initial_hops = None;
    let refused =
        RuleDb::try_from_rules(vec![untested]).expect_err("a rule testing nothing is not loadable");

    assert_eq!(refused.error, RuleError::NoPredicates);
    assert!(refused.to_string().contains("Windows 3.1"));
}

/// A probe over a transport nothing speaks is refused rather than silently
/// dropped, which is the failure mode the loader used to have.
#[test]
fn a_probe_over_an_unknown_transport_is_refused_rather_than_dropped() {
    let mut def = definition("odd", 9002, "^X");
    def.probe = vec![Probe {
        name: Some("nowhere".to_string()),
        payload: "hello".to_string(),
        protocol: "sctp".to_string(),
        rarity: 0,
        generic: false,
    }];

    assert!(SignatureDb::try_from_definitions(vec![def]).is_err());
}
