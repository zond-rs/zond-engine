// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Lowering the host authoring types to the model
//!
//! The [`schema`](super::schema) enums deserialize free of the model; their
//! conversion into the model's own vocabulary lives here, apart from them, so the
//! schema stays shareable with `build.rs`. This mirrors the flow tier's `convert`.

use crate::model::finding::{Reference as ModelReference, Severity as ModelSeverity};

use super::schema::{Reference, Severity};

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
    /// The model reference this names, or [`None`] for a CVE identifier of the wrong
    /// shape, which the model refuses and so does this.
    pub(crate) fn into_model(self) -> Option<ModelReference> {
        match self {
            Reference::Cve(id) => ModelReference::cve(id),
            Reference::Cwe(number) => Some(ModelReference::cwe(number)),
            Reference::Url(url) => Some(ModelReference::url(url)),
        }
    }
}
