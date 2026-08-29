// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The capability envelope
//!
//! What the operator *grants* a detection, against what a detection *asks for*.
//! A [`Finding`](crate::model::finding::Finding)-producing detection declares an
//! intrusiveness [class](DetectionClass); it runs only where the envelope permits
//! that class, so intrusiveness is enforced rather than advised — a passive read
//! and an exploit are not the same permission, and the operator decides which are
//! on.
//!
//! ## An ordered ceiling, not a checklist
//!
//! The classes are ordered by how much they do to the target
//! ([`Passive`](DetectionClass::Passive) reads what the scan already gathered,
//! [`Dos`](DetectionClass::Dos) may degrade the service), so the grant is one
//! number: the most intrusive class permitted. A detection runs when its class is
//! at or below the ceiling. The default ceiling is
//! [`ActiveBenign`](DetectionClass::ActiveBenign): a flow may exchange bytes with
//! a scanned socket to decide, but a detection that mutates, exploits, or degrades
//! the target waits for an operator to raise the ceiling to it.

use crate::model::finding::DetectionClass;

/// The most intrusive class of detection an operator permits, and the gate every
/// detection is checked against before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionEnvelope {
    ceiling: DetectionClass,
}

impl DetectionEnvelope {
    /// An envelope permitting every class up to and including `ceiling`.
    pub fn up_to(ceiling: DetectionClass) -> Self {
        Self { ceiling }
    }

    /// Whether a detection of `class` is permitted to run.
    pub fn permits(&self, class: DetectionClass) -> bool {
        class <= self.ceiling
    }

    /// The most intrusive class this envelope permits.
    pub fn ceiling(&self) -> DetectionClass {
        self.ceiling
    }
}

impl Default for DetectionEnvelope {
    /// Passive and active-benign detections run; the intrusive classes need an
    /// operator to opt in by raising the ceiling.
    fn default() -> Self {
        Self {
            ceiling: DetectionClass::ActiveBenign,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_permits_benign_detection_but_not_intrusive() {
        let envelope = DetectionEnvelope::default();
        assert!(envelope.permits(DetectionClass::Passive));
        assert!(envelope.permits(DetectionClass::ActiveBenign));
        assert!(!envelope.permits(DetectionClass::ActiveMutating));
        assert!(!envelope.permits(DetectionClass::Exploit));
        assert!(!envelope.permits(DetectionClass::Dos));
    }

    #[test]
    fn raising_the_ceiling_opens_the_classes_up_to_it_and_no_further() {
        let envelope = DetectionEnvelope::up_to(DetectionClass::Exploit);
        // Everything up to exploit is now permitted.
        assert!(envelope.permits(DetectionClass::ActiveMutating));
        assert!(envelope.permits(DetectionClass::Exploit));
        // But the class above it still is not.
        assert!(!envelope.permits(DetectionClass::Dos));
    }
}
