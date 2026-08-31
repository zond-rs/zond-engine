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

use std::fmt;
use std::str::FromStr;

use crate::model::finding::DetectionClass;

/// The most intrusive class of detection an operator permits, and the gate every
/// detection is checked against before it runs.
///
/// Ordered, because one envelope being higher than another is the question a
/// caller comparing two runs is asking. Parses from a word or a number like the
/// three scales in [`config`](crate::config), so a front end offering this as a
/// flag keeps no table of its own; see [`FromStr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectionEnvelope {
    ceiling: DetectionClass,
}

impl DetectionEnvelope {
    /// An envelope permitting every class up to and including `ceiling`.
    pub const fn up_to(ceiling: DetectionClass) -> Self {
        Self { ceiling }
    }

    /// Whether a detection of `class` is permitted to run.
    pub fn permits(self, class: DetectionClass) -> bool {
        class <= self.ceiling
    }

    /// The most intrusive class this envelope permits.
    pub const fn ceiling(self) -> DetectionClass {
        self.ceiling
    }
}

impl fmt::Display for DetectionEnvelope {
    /// The ceiling's own name, which is the whole of what an envelope is.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.ceiling.label())
    }
}

/// The error parsing a [`DetectionEnvelope`] returns, carrying the classes that
/// would have worked so a front end can print it verbatim.
///
/// The list is built from [`DetectionClass::ALL`] rather than spelled here, so a
/// class added to the model is a class this message names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownDetectionEnvelope {
    /// What the caller wrote.
    pub input: String,
}

impl fmt::Display for UnknownDetectionEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = DetectionClass::ALL
            .iter()
            .map(|class| class.label())
            .collect();
        write!(
            f,
            "unknown detection envelope '{}', expected one of: {} (or 0 to {})",
            self.input,
            names.join(", "),
            DetectionClass::ALL.len() - 1
        )
    }
}

impl std::error::Error for UnknownDetectionEnvelope {}

impl FromStr for DetectionEnvelope {
    type Err = UnknownDetectionEnvelope;

    /// Reads a ceiling by name or by number.
    ///
    /// The envelope is the one thing here an *operator* decides, and it was the
    /// one scale a front end could not read from text: it had no parser, so
    /// offering it as a flag meant writing the word-to-class table again in
    /// whoever called this, which is what two front ends eventually disagree
    /// about.
    ///
    /// Names are [`DetectionClass::label`], matched without regard to case, and
    /// `-` and `_` are read alike so a command-line word and a settings key
    /// spell the same thing. The number is the class's position in
    /// [`DetectionClass::ALL`], least intrusive first.
    ///
    /// Distinct from the on-disk vocabulary in `record::wire`, which is a
    /// versioned file format rather than something a person types, and which
    /// refuses a name it does not know for its own reasons.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::config::DetectionEnvelope;
    /// use zond_engine::model::finding::DetectionClass;
    ///
    /// assert_eq!("exploit".parse(), Ok(DetectionEnvelope::up_to(DetectionClass::Exploit)));
    /// assert_eq!("active_benign".parse(), Ok(DetectionEnvelope::default()));
    /// assert_eq!("0".parse(), Ok(DetectionEnvelope::up_to(DetectionClass::Passive)));
    /// assert!("everything".parse::<DetectionEnvelope>().is_err());
    /// ```
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let written = input.trim();

        let found = if let Ok(level) = written.parse::<usize>() {
            DetectionClass::ALL.get(level).copied()
        } else {
            let wanted = written.replace('_', "-");
            DetectionClass::ALL.into_iter().find(|class| {
                class
                    .label()
                    .replace('_', "-")
                    .eq_ignore_ascii_case(&wanted)
            })
        };

        found
            .map(Self::up_to)
            .ok_or_else(|| UnknownDetectionEnvelope {
                input: input.to_string(),
            })
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

    /// The envelope was the one scale here a front end could not read from text,
    /// so offering it as a flag meant writing the word-to-class table again.
    #[test]
    fn a_ceiling_parses_by_name_and_by_number_like_every_other_scale() {
        for (index, class) in DetectionClass::ALL.into_iter().enumerate() {
            let expected = DetectionEnvelope::up_to(class);
            assert_eq!(class.label().parse(), Ok(expected), "{class:?} by name");
            assert_eq!(
                index.to_string().parse(),
                Ok(expected),
                "{class:?} by number"
            );
            assert_eq!(
                class.label().to_uppercase().parse(),
                Ok(expected),
                "case is not part of the name"
            );
        }

        // A command-line word and a settings key spell the same thing.
        assert_eq!(
            "active_benign".parse::<DetectionEnvelope>(),
            "active-benign".parse::<DetectionEnvelope>()
        );

        assert!("everything".parse::<DetectionEnvelope>().is_err());
        assert!(
            DetectionClass::ALL
                .len()
                .to_string()
                .parse::<DetectionEnvelope>()
                .is_err(),
            "a ceiling this engine does not offer is refused, not rounded down"
        );
    }

    /// The message names every class that would have worked, built from the
    /// model's own list so a class added there is a class it names.
    #[test]
    fn a_refusal_names_every_ceiling_that_would_have_worked() {
        let message = "everything"
            .parse::<DetectionEnvelope>()
            .unwrap_err()
            .to_string();

        for class in DetectionClass::ALL {
            assert!(
                message.contains(class.label()),
                "{message} omits {}",
                class.label()
            );
        }
    }

    /// An envelope renders as the ceiling it is, and reads back as itself.
    #[test]
    fn a_rendered_envelope_parses_back_to_the_same_ceiling() {
        for class in DetectionClass::ALL {
            let envelope = DetectionEnvelope::up_to(class);
            assert_eq!(envelope.to_string().parse(), Ok(envelope));
        }
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
