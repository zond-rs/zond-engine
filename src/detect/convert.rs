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

use crate::model::finding::{
    DetectionClass, Reference as ModelReference, Severity as ModelSeverity,
};

use super::authoring::{Reference, Severity};
use super::manifest::Class;

impl Class {
    /// The model class this authoring class names.
    pub fn into_model(self) -> DetectionClass {
        match self {
            Class::Passive => DetectionClass::Passive,
            Class::ActiveBenign => DetectionClass::ActiveBenign,
            Class::ActiveMutating => DetectionClass::ActiveMutating,
            Class::Exploit => DetectionClass::Exploit,
            Class::Dos => DetectionClass::Dos,
        }
    }
}

impl Severity {
    /// The model severity this authoring severity names.
    pub(crate) fn into_model(self) -> ModelSeverity {
        match self {
            Severity::Info => ModelSeverity::Info,
            Severity::Low => ModelSeverity::Low,
            Severity::Medium => ModelSeverity::Medium,
            Severity::High => ModelSeverity::High,
            Severity::Critical => ModelSeverity::Critical,
        }
    }
}

impl Reference {
    /// The model reference this names, or [`None`] for a CVE identifier of the
    /// wrong shape, which the model refuses and so does this.
    ///
    /// Borrows rather than consumes: a spec's references are read once per
    /// finding it produces, and the spec outlives the finding.
    pub(crate) fn to_model(&self) -> Option<ModelReference> {
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

    #[test]
    fn each_authoring_class_maps_onto_its_model_class() {
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
}
