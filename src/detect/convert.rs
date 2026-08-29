// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Lowering the shared manifest to the model
//!
//! The [`manifest`](super::manifest) types deserialize free of the model, so the
//! conversion into the model's own vocabulary lives here, apart from them — the
//! discipline that lets `build.rs` share the manifest file. This is the tier-
//! neutral half: the intrusiveness [`Class`] every detection declares maps onto
//! the model's [`DetectionClass`]. A flow's own authoring enums (its severity and
//! references) convert beside the flow schema, which the compute tier does not
//! share.

use crate::model::finding::DetectionClass;

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
}
