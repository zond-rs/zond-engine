// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # OS Fingerprinting Models
//!
//! This module provides the [`OsFingerprint`] entity, which aggregates findings
//! from multiple OS identification techniques (e.g., TCP/IP stack analysis,
//! service banner grabbing, or SNMP queries).

use std::{collections::BTreeSet, sync::Arc};

/// The absolute maximum number of CPEs we will store for a single OS fingerprint.
/// This acts as a security boundary to prevent memory exhaustion from malicious
/// targets or runaway scanning scripts.
pub const MAX_CPES_PER_OS: usize = 50;

/// A host's operating system as one technique identified it, and how sure that
/// technique was.
///
/// The accuracy is what makes several techniques combinable: a better-informed
/// finding replaces a worse one and equally-informed ones fill each other's
/// gaps. See [`merge`](Self::merge).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OsFingerprint {
    /// The operating system's name, such as `"Linux"` or `"Windows"`.
    ///
    /// Shared rather than owned because a scan of any size finds the same few
    /// names over and over, and the string is then one allocation across the
    /// whole result rather than one per host.
    name: Arc<str>,

    /// The broad family, such as `"Unix-like"` or `"Windows NT"`.
    family: Option<Arc<str>>,

    /// The version or generation, such as `"5.15.0"` or `"11"`.
    generation: Option<Arc<str>>,

    /// The vendor, such as `"Canonical"` or `"Microsoft"`.
    vendor: Option<Arc<str>>,

    /// How sure this identification is, as a percentage.
    ///
    /// Private because [`new`](Self::new) clamps it to 100 and
    /// [`merge`](Self::merge) ranks findings by it. A value above 100 would
    /// outrank a completed match and could never be displaced.
    accuracy: u8,

    /// A bounded set of Common Platform Enumeration (CPE) identifiers.
    cpe: BTreeSet<Arc<str>>,
}

impl OsFingerprint {
    /// Creates a new `OsFingerprint` with a name and a confidence score.
    ///
    /// Accuracy is strictly clamped to the range `[0, 100]`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use zond_engine::model::host::OsFingerprint;
    /// let os = OsFingerprint::new("Ubuntu Linux", 95);
    /// assert_eq!(os.accuracy(), 95);
    /// ```
    pub fn new(name: impl Into<Arc<str>>, accuracy: u8) -> Self {
        Self {
            name: name.into(),
            family: None,
            generation: None,
            vendor: None,
            accuracy: accuracy.min(100),
            cpe: BTreeSet::new(),
        }
    }

    /// The operating system's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The broad family, if one was identified.
    pub fn family(&self) -> Option<&str> {
        self.family.as_deref()
    }

    /// The version or generation, if one was identified.
    pub fn generation(&self) -> Option<&str> {
        self.generation.as_deref()
    }

    /// The vendor, if one was identified.
    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    /// How sure this identification is, from 0 to 100.
    pub fn accuracy(&self) -> u8 {
        self.accuracy
    }

    /// Builder method to set the broad family.
    pub fn with_family(mut self, family: impl Into<Arc<str>>) -> Self {
        self.family = Some(family.into());
        self
    }

    /// Builder method to set the version or generation.
    pub fn with_generation(mut self, generation: impl Into<Arc<str>>) -> Self {
        self.generation = Some(generation.into());
        self
    }

    /// Builder method to set the vendor.
    pub fn with_vendor(mut self, vendor: impl Into<Arc<str>>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Adds a CPE identifier to the fingerprint, provided the internal limit
    /// ([`MAX_CPES_PER_OS`]) has not been reached.
    pub fn add_cpe(&mut self, cpe: impl Into<Arc<str>>) {
        if self.cpe.len() < MAX_CPES_PER_OS {
            self.cpe.insert(cpe.into());
        }
    }

    /// Returns a read-only view of all identified CPEs for this host.
    pub fn cpes(&self) -> &BTreeSet<Arc<str>> {
        &self.cpe
    }

    /// Returns `true` if the identification has high certainty (>= 85%).
    ///
    /// This threshold is often used by scanning engines to decide whether
    /// to terminate OS discovery or continue with more intrusive probes.
    pub fn is_highly_confident(&self) -> bool {
        self.accuracy >= 85
    }

    /// Merges architectural findings from another OS record.
    ///
    /// - If `other` has **higher accuracy**, it replaces the current record.
    /// - If `other` has **equal accuracy**, missing fields are populated and CPEs are unioned.
    /// - If `other` has **lower accuracy**, it is ignored.
    pub fn merge(&mut self, other: OsFingerprint) {
        if other.accuracy > self.accuracy {
            *self = other;
        } else if other.accuracy == self.accuracy {
            // Fill gaps if they exist in the current record
            if self.family.is_none() {
                self.family = other.family;
            }
            if self.generation.is_none() {
                self.generation = other.generation;
            }
            if self.vendor.is_none() {
                self.vendor = other.vendor;
            }

            // Union CPEs up to the cap
            for cpe in other.cpe {
                if self.cpe.len() >= MAX_CPES_PER_OS {
                    break;
                }
                self.cpe.insert(cpe);
            }
        }
    }
}

impl std::fmt::Display for OsFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(ref generation) = self.generation {
            write!(f, " {}", generation)?;
        }
        write!(f, " [{}%]", self.accuracy)
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_accuracy_clamping() {
        let os = OsFingerprint::new("Linux", 200);
        assert_eq!(os.accuracy(), 100);
    }

    #[test]
    fn test_is_highly_confident() {
        assert!(OsFingerprint::new("Linux", 85).is_highly_confident());
        assert!(!OsFingerprint::new("Linux", 84).is_highly_confident());
    }

    #[test]
    fn os_merge_accuracy_priority() {
        let mut os1 = OsFingerprint::new("Linux", 50);
        let os2 = OsFingerprint::new("Ubuntu", 90);
        os1.merge(os2);
        assert_eq!(os1.name(), "Ubuntu");
    }

    #[test]
    fn os_merge_equal_accuracy_collision() {
        // Test deterministic "first-wins" for conflicting metadata at equal accuracy
        let mut os1 = OsFingerprint::new("Linux", 80).with_family("Old Family");

        let os2 = OsFingerprint::new("Linux", 80)
            .with_family("New Family")
            .with_generation("New Gen");

        os1.merge(os2);

        // Should keep "Old Family" (first) but adopt "New Gen" (gap filled)
        assert_eq!(os1.family(), Some("Old Family"));
        assert_eq!(os1.generation(), Some("New Gen"));
    }

    #[test]
    fn cpe_cap_enforcement() {
        let mut os = OsFingerprint::new("Windows", 100);
        for i in 0..100 {
            os.add_cpe(format!("cpe:/o:ident:{}", i));
        }
        assert_eq!(os.cpes().len(), MAX_CPES_PER_OS);
    }
}
