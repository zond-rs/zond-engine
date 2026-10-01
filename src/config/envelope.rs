// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The capability envelope
//!
//! What the operator *grants* a detection, against what a detection *asks for*. A
//! [`Finding`](crate::model::finding::Finding)-producing detection declares an
//! intrusiveness [class](DetectionClass) and runs only where the envelope permits that
//! class, so intrusiveness is enforced.
//!
//! ## An ordered ceiling
//!
//! The classes are ordered by how much they do to the target
//! ([`Passive`](DetectionClass::Passive) reads what the scan already gathered,
//! [`Dos`](DetectionClass::Dos) may degrade the service), so the grant is one value:
//! the most intrusive class permitted. A detection runs when its class is at or below
//! the ceiling. The default ceiling is [`Passive`](DetectionClass::Passive); anything
//! that opens a connection of its own waits for an operator to raise it. See
//! [`Default`] for why.

use std::fmt;
use std::str::FromStr;

use crate::model::finding::DetectionClass;

/// The most intrusive class of detection an operator permits, and the gate every
/// detection is checked against before it runs.
///
/// Ordered, so two runs' envelopes can be compared. Parses from a word or a number like
/// the scales in [`config`](crate::config); see [`FromStr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectionEnvelope {
    /// The most intrusive class permitted, or [`None`] where the operator
    /// granted nothing and the phase does not run.
    ceiling: Option<DetectionClass>,
}

impl DetectionEnvelope {
    /// An envelope permitting every class up to and including `ceiling`.
    pub const fn up_to(ceiling: DetectionClass) -> Self {
        Self {
            ceiling: Some(ceiling),
        }
    }

    /// An envelope permitting nothing, so no detection runs at all.
    ///
    /// Below [`Passive`](DetectionClass::Passive): a passive detection sends nothing
    /// but still reads the scan's responses and puts findings in the report.
    pub const fn none() -> Self {
        Self { ceiling: None }
    }

    /// Whether a detection of `class` is permitted to run.
    pub fn permits(self, class: DetectionClass) -> bool {
        matches!(self.ceiling, Some(ceiling) if class <= ceiling)
    }

    /// The most intrusive class this envelope permits, or [`None`] where it
    /// permits nothing.
    pub const fn ceiling(self) -> Option<DetectionClass> {
        self.ceiling
    }
}

impl fmt::Display for DetectionEnvelope {
    /// The ceiling's own name, or `off` where there is no ceiling because
    /// nothing is granted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ceiling {
            Some(ceiling) => f.write_str(ceiling.label()),
            None => f.write_str("off"),
        }
    }
}

/// The error parsing a [`DetectionEnvelope`] returns. Its message lists the accepted
/// values, built from [`DetectionClass::ALL`], so a front end can print it verbatim.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownDetectionEnvelope {
    /// What the caller wrote.
    pub input: String,
}

impl fmt::Display for UnknownDetectionEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `off` leads, since the class list does not name it.
        let mut names = vec!["off"];
        names.extend(DetectionClass::ALL.iter().map(|class| class.label()));
        write!(
            f,
            "unknown detection envelope '{}', expected one of: {} (or 0 to {})",
            self.input,
            names.join(", "),
            DetectionClass::ALL.len()
        )
    }
}

impl std::error::Error for UnknownDetectionEnvelope {}

impl FromStr for DetectionEnvelope {
    type Err = UnknownDetectionEnvelope;

    /// Reads a ceiling by name or by number.
    ///
    /// Names are [`DetectionClass::label`], case-insensitive, with `-` and `_` read
    /// alike so a command-line word and a settings key match, plus `off` for the
    /// envelope that grants nothing. Numbers run `0` for `off`, then the classes in
    /// [`DetectionClass::ALL`] order, least intrusive first.
    ///
    /// The on-disk vocabulary in `record::wire` is separate: it is a versioned file
    /// format.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::config::DetectionEnvelope;
    /// use zond_engine::model::finding::DetectionClass;
    ///
    /// assert_eq!("exploit".parse(), Ok(DetectionEnvelope::up_to(DetectionClass::Exploit)));
    /// assert_eq!("passive".parse(), Ok(DetectionEnvelope::default()));
    /// assert_eq!("0".parse(), Ok(DetectionEnvelope::none()));
    /// assert_eq!("off".parse(), Ok(DetectionEnvelope::none()));
    /// assert_eq!("1".parse(), Ok(DetectionEnvelope::up_to(DetectionClass::Passive)));
    /// assert!("everything".parse::<DetectionEnvelope>().is_err());
    /// ```
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let written = input.trim();
        let refused = || UnknownDetectionEnvelope {
            input: input.to_string(),
        };

        if let Ok(level) = written.parse::<usize>() {
            // Zero is off and the classes start at one.
            let Some(step) = level.checked_sub(1) else {
                return Ok(Self::none());
            };
            return DetectionClass::ALL
                .get(step)
                .copied()
                .map(Self::up_to)
                .ok_or_else(refused);
        }

        let wanted = written.replace('_', "-");
        if wanted.eq_ignore_ascii_case("off") {
            return Ok(Self::none());
        }

        DetectionClass::ALL
            .iter()
            .copied()
            .find(|class| {
                class
                    .label()
                    .replace('_', "-")
                    .eq_ignore_ascii_case(&wanted)
            })
            .map(Self::up_to)
            .ok_or_else(refused)
    }
}

impl Default for DetectionEnvelope {
    /// Only what the scan already gathered is read. Everything that opens a
    /// connection of its own, [`ActiveBenign`](DetectionClass::ActiveBenign) upward,
    /// waits for an operator to raise the ceiling.
    ///
    /// The reason is cost. An HTTP port attracts three dozen active flows, each
    /// guessing a path belonging to a particular product (`/wp-config.php.bak`,
    /// `/v1/sys/seal-status`, `/v2/_catalog`) over its own connection, and each a miss
    /// unless the target runs that product. Against a device that accepts a
    /// connection and then says nothing, which is most consumer and embedded gear,
    /// every miss costs the flow's whole time budget. Measured against four such
    /// ports, `ActiveBenign` took thirteen seconds and twenty-eight connections to
    /// reach the same findings this ceiling reaches in three and a half.
    fn default() -> Self {
        Self {
            ceiling: Some(DetectionClass::Passive),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero is off, one is the first class, and the scale runs from there.
    #[test]
    fn the_scale_runs_from_off_through_the_classes() {
        assert_eq!("off".parse(), Ok(DetectionEnvelope::none()));
        assert_eq!("OFF".parse(), Ok(DetectionEnvelope::none()));
        assert_eq!("0".parse(), Ok(DetectionEnvelope::none()));

        for (level, class) in DetectionClass::ALL.iter().copied().enumerate() {
            let asked = (level + 1).to_string();
            assert_eq!(
                asked.parse(),
                Ok(DetectionEnvelope::up_to(class)),
                "{asked} is not {}",
                class.label()
            );
        }

        assert!(
            (DetectionClass::ALL.len() + 1)
                .to_string()
                .parse::<DetectionEnvelope>()
                .is_err(),
            "a step past the top of the scale was accepted"
        );
    }

    /// An envelope granting nothing permits nothing and names no ceiling.
    #[test]
    fn off_permits_nothing_and_is_the_bottom_of_the_scale() {
        let off = DetectionEnvelope::none();

        for &class in DetectionClass::ALL {
            assert!(!off.permits(class), "{} ran under off", class.label());
        }
        assert_eq!(off.ceiling(), None);
        assert_eq!(off.to_string(), "off");
        assert!(
            off < DetectionEnvelope::up_to(DetectionClass::Passive),
            "off does not sort below the quietest class"
        );
    }

    #[test]
    fn the_default_reads_but_does_not_probe() {
        let envelope = DetectionEnvelope::default();
        assert!(envelope.permits(DetectionClass::Passive));
        assert!(
            !envelope.permits(DetectionClass::ActiveBenign),
            "a detection that opens its own connection runs without being asked for"
        );
        assert!(!envelope.permits(DetectionClass::ActiveMutating));
        assert!(!envelope.permits(DetectionClass::Exploit));
        assert!(!envelope.permits(DetectionClass::Dos));
    }

    /// A ceiling parses by name and by number, like the other scales.
    #[test]
    fn a_ceiling_parses_by_name_and_by_number_like_every_other_scale() {
        for (index, class) in DetectionClass::ALL.iter().copied().enumerate() {
            let expected = DetectionEnvelope::up_to(class);
            assert_eq!(class.label().parse(), Ok(expected), "{class:?} by name");
            // Off holds zero, so a class sits one above its own index.
            assert_eq!(
                (index + 1).to_string().parse(),
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
            (DetectionClass::ALL.len() + 1)
                .to_string()
                .parse::<DetectionEnvelope>()
                .is_err(),
            "a ceiling this engine does not offer is refused, not rounded down"
        );
    }

    /// The message names every class that would have worked.
    #[test]
    fn a_refusal_names_every_ceiling_that_would_have_worked() {
        let message = "everything"
            .parse::<DetectionEnvelope>()
            .unwrap_err()
            .to_string();

        for &class in DetectionClass::ALL {
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
        for &class in DetectionClass::ALL {
            let envelope = DetectionEnvelope::up_to(class);
            assert_eq!(envelope.to_string().parse(), Ok(envelope));
        }
    }

    #[test]
    fn raising_the_ceiling_opens_the_classes_up_to_it_and_no_further() {
        let envelope = DetectionEnvelope::up_to(DetectionClass::Exploit);
        assert!(envelope.permits(DetectionClass::ActiveMutating));
        assert!(envelope.permits(DetectionClass::Exploit));
        assert!(!envelope.permits(DetectionClass::Dos));
    }
}
