// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Lowering authoring types to the model
//!
//! A flow file deserializes into the serde-friendly authoring enums of
//! [`schema`](super::schema); when a flow produces a finding, those enums are
//! converted here into the model's own vocabulary. The conversion lives apart
//! from the schema for the reason the schema derives `Deserialize` and the model
//! does not: keeping it here leaves `schema` free of any dependency on the model,
//! which is the discipline that lets `build.rs` share that file.

use crate::model::finding::{
    DetectionClass, Reference as ModelReference, Severity as ModelSeverity,
};

use super::schema::{Class, Reference, Severity};

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

impl Reference {
    /// The model reference this names, or [`None`] for a CVE identifier of the
    /// wrong shape — the model refuses a malformed one, and so does this.
    pub fn into_model(&self) -> Option<ModelReference> {
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
    fn the_authoring_enums_map_onto_the_model_vocabulary() {
        assert_eq!(Class::Exploit.into_model(), DetectionClass::Exploit);
        assert_eq!(Severity::Critical.into_model(), ModelSeverity::Critical);
        assert_eq!(
            Reference::Cwe(79).into_model(),
            Some(ModelReference::Cwe(79))
        );
        assert!(
            Reference::Cve("CVE-2021-44228".into())
                .into_model()
                .is_some()
        );
        // A malformed CVE is refused, exactly as the model refuses it.
        assert!(Reference::Cve("not-a-cve".into()).into_model().is_none());
    }
}
