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
//! that class, so intrusiveness is enforced rather than advised: a passive read
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
//! [`Passive`](DetectionClass::Passive): a detection reads the responses the scan
//! already drew, and anything that opens a connection of its own waits for an
//! operator to raise the ceiling to it. See [`Default`] for what that costs and
//! why it is the operator's call.

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
    /// Below [`Passive`](DetectionClass::Passive) rather than equal to it. A
    /// passive detection sends nothing, but it still reads the responses a scan
    /// gathered and still puts findings in the report, and an operator who wants
    /// a port scan and nothing else is asking for neither.
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
        // `off` leads, because it is the step the class list does not name and
        // the one a reader given only the classes would not guess exists.
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
    /// The envelope is the one thing here an *operator* decides, and without a
    /// parser it would be the one scale a front end could not read from text:
    /// offering it as a flag would mean writing the word-to-class table again
    /// in whoever called this, which is what two front ends eventually disagree
    /// about.
    ///
    /// Names are [`DetectionClass::label`], matched without regard to case, and
    /// `-` and `_` are read alike so a command-line word and a settings key
    /// spell the same thing, plus `off` for the envelope that grants nothing.
    /// The number is a step along the same scale, `0` being `off` and the classes
    /// following in [`DetectionClass::ALL`] order, least intrusive first.
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
            // Zero is off and the classes start at one, so the numbers run the
            // whole scale an operator chooses along rather than starting part way
            // up it.
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
            .into_iter()
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
    /// connection of its own, [`ActiveBenign`](DetectionClass::ActiveBenign)
    /// upward, waits for an operator to raise the ceiling.
    ///
    /// The default was `ActiveBenign` and the reason it moved is what that costs
    /// against the hosts it is pointed at. An HTTP port attracts three dozen
    /// active flows, and they are not one question asked thirty-six ways: each
    /// guesses a path belonging to a particular product, `/wp-config.php.bak`,
    /// `/v1/sys/seal-status`, `/v2/_catalog`, so each opens its own connection
    /// and each is a miss unless the target happens to run that product. Against
    /// a device that accepts a connection and then says nothing, which is most
    /// consumer and embedded gear, every one of those misses costs the flow's
    /// whole time budget. Measured against four such ports: thirteen seconds and
    /// twenty-eight connections to reach the same findings this ceiling reaches
    /// in three and a half, because all of them came from reading what the
    /// service pass had already collected.
    ///
    /// So the tier that pays for itself everywhere is the default, and the tier
    /// that pays for itself against a chosen target is asked for. It is the same
    /// reasoning already applied one rung up: intrusiveness is not the only thing
    /// an operator should be the one to decide, and neither is spending a minute
    /// on a network to learn nothing.
    fn default() -> Self {
        Self {
            ceiling: Some(DetectionClass::Passive),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero is off, one is the first class, and the scale runs from there. An
    /// operator who wants a port scan and no claims about it says so with a
    /// number at the bottom of the same dial they would raise.
    #[test]
    fn the_scale_runs_from_off_through_the_classes() {
        assert_eq!("off".parse(), Ok(DetectionEnvelope::none()));
        assert_eq!("OFF".parse(), Ok(DetectionEnvelope::none()));
        assert_eq!("0".parse(), Ok(DetectionEnvelope::none()));

        for (level, class) in DetectionClass::ALL.into_iter().enumerate() {
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

    /// An envelope granting nothing permits nothing, and says so rather than
    /// naming a ceiling it does not have.
    #[test]
    fn off_permits_nothing_and_is_the_bottom_of_the_scale() {
        let off = DetectionEnvelope::none();

        for class in DetectionClass::ALL {
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

    /// The envelope was the one scale here a front end could not read from text,
    /// so offering it as a flag meant writing the word-to-class table again.
    #[test]
    fn a_ceiling_parses_by_name_and_by_number_like_every_other_scale() {
        for (index, class) in DetectionClass::ALL.into_iter().enumerate() {
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
