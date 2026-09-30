// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Lowering the authoring vocabulary to the model
//!
//! The [`manifest`](super::manifest) and [`authoring`](super::authoring) types
//! deserialize free of the model, which is the discipline that lets `build.rs`
//! share those files. Their conversion into the model's own vocabulary lives
//! here instead.
//!
//! Everything shared between the tiers converts in one place: the intrusiveness
//! [`Class`] a detection declares, and the [`Severity`] and [`Reference`] its
//! findings carry.
//!
//! It is also the one file that reads both vocabularies at once, which is what
//! [`SeveritySpec::into_model_at`] needs: a severity stated per exposure is
//! resolved against the model's [`Exposure`], so the
//! authoring side never has to name it and the scan path never has to translate
//! into the authoring side to ask.

use crate::model::finding::{
    DetectionClass, FindingGroup, Reference as ModelReference, Severity as ModelSeverity,
};
use crate::model::ip::Exposure;

use super::authoring::{Reference, Severity, SeveritySpec};
use super::manifest::{Class, GroupSpec};

impl Class {
    /// The model class this authoring class names.
    pub fn into_model(self) -> DetectionClass {
        match self {
            // What a finding records is the intrusiveness its detection ran at,
            // and a derived detection runs at exactly a passive one: it touches
            // nothing. Where its conclusion came from is a fact about the
            // detection, which is what `Class` is for and what a catalogue draws.
            Class::Derived | Class::Passive => DetectionClass::Passive,
            Class::ActiveBenign => DetectionClass::ActiveBenign,
            Class::ActiveMutating => DetectionClass::ActiveMutating,
            Class::Exploit => DetectionClass::Exploit,
            Class::Dos => DetectionClass::Dos,
        }
    }
}

impl Severity {
    /// The model severity this authoring severity names.
    pub fn into_model(self) -> ModelSeverity {
        match self {
            Severity::Info => ModelSeverity::Info,
            Severity::Low => ModelSeverity::Low,
            Severity::Medium => ModelSeverity::Medium,
            Severity::High => ModelSeverity::High,
            Severity::Critical => ModelSeverity::Critical,
        }
    }
}

impl SeveritySpec {
    /// The model severity this spec states for a subject at `exposure`.
    ///
    /// A [`Flat`](SeveritySpec::Flat) spec ignores the exposure, which is the
    /// whole of what "this weakness means the same thing wherever it is" comes to.
    /// A [`PerExposure`](SeveritySpec::PerExposure) one reads the rung, falling
    /// back along the table as
    /// [`SeverityByExposure`](super::authoring::SeverityByExposure) documents.
    ///
    /// The match on the exposure is exhaustive on purpose. A rung added later
    /// must be given a reading here rather than silently landing on the widest
    /// one, which is the only place in the lowering where a missing decision
    /// would change a published severity.
    pub fn into_model_at(self, exposure: Exposure) -> ModelSeverity {
        let severity = match self {
            SeveritySpec::Flat(severity) => severity,
            SeveritySpec::PerExposure(table) => match exposure {
                Exposure::Local => table.local(),
                Exposure::Internal => table.internal(),
                Exposure::Internet => table.internet,
            },
        };
        severity.into_model()
    }
}

impl GroupSpec {
    /// The model group this names, or [`None`] where either half is blank,
    /// which the model refuses and so does this. The corpus validator rejects
    /// such a detection at build, so a loaded one always converts.
    ///
    /// Borrows rather than consumes, as [`Reference::to_model`] does: a
    /// manifest's group is read once per finding the detection produces, and
    /// the manifest outlives them all.
    pub fn to_model(&self) -> Option<FindingGroup> {
        FindingGroup::new(self.id.clone(), self.summary.clone()).ok()
    }
}

impl Reference {
    /// The model reference this names, or [`None`] for a CVE identifier of the
    /// wrong shape, which the model refuses and so does this.
    ///
    /// Borrows rather than consumes: a spec's references are read once per
    /// finding it produces, and the spec outlives the finding.
    pub fn to_model(&self) -> Option<ModelReference> {
        match self {
            Reference::Cve(id) => ModelReference::cve(id),
            Reference::Cwe(number) => Some(ModelReference::cwe(*number)),
            Reference::Url(url) => Some(ModelReference::url(url)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A holder for the one field under test, since `severity` is read as part of
    /// a finding rather than as a document of its own.
    #[derive(Debug, serde::Deserialize)]
    struct Wrapper {
        severity: SeveritySpec,
    }

    /// A bare severity is the same rating at every rung: what "this means the
    /// same thing wherever it is" comes to.
    #[test]
    fn a_flat_severity_ignores_the_exposure() {
        let spec = SeveritySpec::Flat(Severity::High);
        for exposure in Exposure::ALL {
            assert_eq!(
                spec.into_model_at(*exposure),
                ModelSeverity::High,
                "{}",
                exposure.label()
            );
        }
    }

    /// A table reads the rung it was given, and an unstated rung falls back to
    /// the next wider one rather than to a default.
    #[test]
    fn a_stated_rung_is_read_and_an_unstated_one_falls_back_to_the_wider() {
        let spec: SeveritySpec =
            toml::from_str::<Wrapper>(r#"severity = { internet = "high", internal = "info" }"#)
                .expect("the table parses")
                .severity;

        assert_eq!(spec.into_model_at(Exposure::Internet), ModelSeverity::High);
        assert_eq!(spec.into_model_at(Exposure::Internal), ModelSeverity::Info);
        // `local` was not stated, so it is whatever `internal` says.
        assert_eq!(spec.into_model_at(Exposure::Local), ModelSeverity::Info);
    }

    /// The fallback is transitive: a table stating only `internet` is a flat
    /// severity written the long way, and one stating `local` reaches past an
    /// unstated `internal`.
    #[test]
    fn the_fallback_runs_the_whole_way_to_the_widest_rung() {
        let only_internet: SeveritySpec =
            toml::from_str::<Wrapper>(r#"severity = { internet = "critical" }"#)
                .expect("the table parses")
                .severity;
        for exposure in Exposure::ALL {
            assert_eq!(
                only_internet.into_model_at(*exposure),
                ModelSeverity::Critical,
                "{}",
                exposure.label()
            );
        }

        let skips_internal: SeveritySpec =
            toml::from_str::<Wrapper>(r#"severity = { internet = "high", local = "info" }"#)
                .expect("the table parses")
                .severity;
        assert_eq!(
            skips_internal.into_model_at(Exposure::Internal),
            ModelSeverity::High,
            "an unstated `internal` is the internet rating, not the local one"
        );
        assert_eq!(
            skips_internal.into_model_at(Exposure::Local),
            ModelSeverity::Info
        );
    }

    /// The bare string is the ordinary spelling, so it has to keep parsing as one
    /// after the table form was added. Every shipped detection but a handful
    /// writes it.
    #[test]
    fn the_bare_string_still_parses_as_a_severity() {
        let spec = toml::from_str::<Wrapper>(r#"severity = "medium""#)
            .expect("a bare severity parses")
            .severity;
        assert_eq!(spec, SeveritySpec::Flat(Severity::Medium));
    }

    /// A rung misspelled is a build failure rather than a severity that silently
    /// falls back, which is the whole reason the table denies unknown fields.
    #[test]
    fn a_misspelled_rung_is_refused_rather_than_ignored() {
        assert!(
            toml::from_str::<Wrapper>(r#"severity = { internet = "high", internel = "info" }"#)
                .is_err(),
            "`internel` was accepted, so the rung it meant fell back in silence"
        );
    }

    /// A table with no `internet` rung states no rating for the audience every
    /// severity is written against, and is refused.
    #[test]
    fn a_table_without_the_widest_rung_is_refused() {
        assert!(
            toml::from_str::<Wrapper>(r#"severity = { internal = "info" }"#).is_err(),
            "a table stating only the reduced rung was accepted"
        );
    }

    #[test]
    fn each_authoring_class_maps_onto_its_model_class() {
        assert_eq!(Class::Derived.into_model(), DetectionClass::Passive);
        assert_eq!(Class::Passive.into_model(), DetectionClass::Passive);
        assert_eq!(
            Class::ActiveBenign.into_model(),
            DetectionClass::ActiveBenign
        );
        assert_eq!(
            Class::ActiveMutating.into_model(),
            DetectionClass::ActiveMutating
        );
        assert_eq!(Class::Exploit.into_model(), DetectionClass::Exploit);
        assert_eq!(Class::Dos.into_model(), DetectionClass::Dos);
    }

    #[test]
    fn the_authoring_severities_map_onto_the_model_vocabulary() {
        assert_eq!(Severity::Info.into_model(), ModelSeverity::Info);
        assert_eq!(Severity::Low.into_model(), ModelSeverity::Low);
        assert_eq!(Severity::Medium.into_model(), ModelSeverity::Medium);
        assert_eq!(Severity::High.into_model(), ModelSeverity::High);
        assert_eq!(Severity::Critical.into_model(), ModelSeverity::Critical);
    }

    #[test]
    fn a_reference_carries_its_identifier_across() {
        assert_eq!(Reference::Cwe(79).to_model(), Some(ModelReference::Cwe(79)));
        assert!(Reference::Cve("CVE-2021-44228".into()).to_model().is_some());
        assert!(
            Reference::Url("https://example.invalid/a".into())
                .to_model()
                .is_some()
        );
    }

    #[test]
    fn a_malformed_cve_is_refused_exactly_as_the_model_refuses_it() {
        assert!(Reference::Cve("not-a-cve".into()).to_model().is_none());
    }

    #[test]
    fn a_group_carries_both_halves_across() {
        let group = GroupSpec {
            id: "ssh-weak-algorithms".into(),
            summary: "weak SSH algorithms offered".into(),
        }
        .to_model()
        .expect("both halves are filled");

        assert_eq!(group.id(), "ssh-weak-algorithms");
        assert_eq!(group.summary(), "weak SSH algorithms offered");
    }

    /// Half a group is no group: an id nothing prints for, or a phrase nothing
    /// gathers by. Refused here as the model refuses it, rather than lowered
    /// into a finding that claims membership of something unnameable.
    #[test]
    fn half_a_group_is_refused() {
        assert!(
            GroupSpec {
                id: "ssh-weak-algorithms".into(),
                summary: "  ".into(),
            }
            .to_model()
            .is_none()
        );
        assert!(
            GroupSpec {
                id: String::new(),
                summary: "weak SSH algorithms offered".into(),
            }
            .to_model()
            .is_none()
        );
    }
}
