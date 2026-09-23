// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A stable name for what went wrong
//!
//! Every public error in this crate carries a message written for a person to
//! read. A consumer that is not Rust needs the other thing: a short name it can
//! branch on, which stays the same when the message is reworded.
//!
//! [`Coded`] is that name. A front end deciding whether to offer a retry, a
//! daemon filling in a protocol's error field, and a test asserting which
//! failure it provoked all want the code; only the person reading the screen
//! wants the message.
//!
//! ```
//! use zond_engine::{Coded, ScanError};
//!
//! let refused = ScanError::WrongPhase;
//! assert_eq!(refused.code(), "scan.wrong_phase");
//! ```
//!
//! ## The codebook lives here rather than beside each error
//!
//! A code is a contract with everything that has ever read one, so the whole set
//! is written down in one file where it can be read as a set. The alternative
//! puts each match beside its own type, where two of them can drift into the
//! same name without anybody seeing both at once.
//!
//! It also decides where the compiler points. These matches carry no wildcard
//! arm, so a variant added to any of these errors fails to compile here, and
//! here is where somebody has to come to choose its code.
//!
//! ## What a code promises
//!
//! The name is stable and the wording of the message is not. Renaming a variant
//! does not rename its code, and a code is only ever retired by being replaced
//! with one a consumer can tell apart.
//!
//! Codes read `area.what`: the area a caller was working in, and the thing that
//! stopped it. An error that wraps another reports the inner one's code, since
//! `scan.evasion` would say only that a scan refused something the caller could
//! read for themselves in `evasion.hop_limit_zero`.

use crate::detect::corpus::DetectionError;
use crate::evasion::EvasionError;
use crate::export::ExportError;
use crate::import::ImportError;
#[cfg(feature = "journal-format")]
use crate::journal::format::JournalError;
#[cfg(feature = "journal-format")]
use crate::journal::lock::LockRefused;
#[cfg(feature = "journal-format")]
use crate::journal::manifest::PlanChanged;
#[cfg(feature = "journal-format")]
use crate::journal::store::OpenError;
use crate::model::parse::ip::IpParseError;
use crate::model::parse::target::TargetParseError;
use crate::model::port::set::PortSetParseError;
use crate::scanner::ScanError;

#[cfg(feature = "import-request")]
use crate::import::request::RequestError;
#[cfg(feature = "import-settings")]
use crate::import::settings::SettingsError;

/// An error with a name a consumer outside Rust can branch on.
///
/// The module documentation states what the name promises and how the codes are
/// shaped. Implemented for every error a public entry point of this crate can
/// hand back.
pub trait Coded {
    /// A short, stable name for what went wrong.
    ///
    /// Stable across a reworded message and a renamed variant. An error that
    /// wraps another answers with the inner error's code.
    fn code(&self) -> &'static str;
}

impl Coded for ScanError {
    fn code(&self) -> &'static str {
        match self {
            ScanError::WrongPhase => "scan.wrong_phase",
            #[cfg(feature = "journal-format")]
            ScanError::PlanChanged(changed) => changed.code(),
            ScanError::Evasion(evasion) => evasion.code(),
            // A strategy that unwound is a defect in this crate, and a strategy
            // that returned an error is the network being the network. A
            // consumer that files bugs wants to tell those apart.
            ScanError::TaskFailed { panicked: true, .. } => "scan.task_panicked",
            ScanError::TaskFailed { .. } => "scan.task_failed",
        }
    }
}

#[cfg(feature = "journal-format")]
impl Coded for PlanChanged {
    fn code(&self) -> &'static str {
        "journal.plan_changed"
    }
}

impl Coded for EvasionError {
    fn code(&self) -> &'static str {
        match self {
            EvasionError::FragmentTooSmall { .. } => "evasion.fragment_too_small",
            EvasionError::HopLimitZero => "evasion.hop_limit_zero",
            EvasionError::PaddingTooLarge { .. } => "evasion.padding_too_large",
            EvasionError::SourcePortZero => "evasion.source_port_zero",
        }
    }
}

impl Coded for ExportError {
    fn code(&self) -> &'static str {
        match self {
            ExportError::Io(_) => "export.io",
            ExportError::Render { .. } => "export.render",
        }
    }
}

#[cfg(feature = "journal-format")]
impl Coded for JournalError {
    fn code(&self) -> &'static str {
        match self {
            JournalError::Io(_) => "journal.io",
            JournalError::Malformed { .. } => "journal.malformed",
            JournalError::NotAJournal => "journal.not_a_journal",
            JournalError::VersionTooNew { .. } => "journal.version_too_new",
        }
    }
}

#[cfg(feature = "journal-format")]
impl Coded for OpenError {
    fn code(&self) -> &'static str {
        match self {
            OpenError::Journal(journal) => journal.code(),
            OpenError::Locked(refused) => refused.code(),
            OpenError::PlanChanged(changed) => changed.code(),
            OpenError::VersionTooOld { .. } => "journal.version_too_old",
            OpenError::WrongPhase { .. } => "journal.wrong_phase",
        }
    }
}

#[cfg(feature = "journal-format")]
impl Coded for LockRefused {
    fn code(&self) -> &'static str {
        match self {
            LockRefused::Held(_) => "journal.locked",
            LockRefused::Io(_) => "journal.lock_io",
        }
    }
}

impl Coded for DetectionError {
    fn code(&self) -> &'static str {
        match self {
            DetectionError::Body(_) => "detection.body",
            DetectionError::Compute(_) => "detection.compute",
            DetectionError::Flow(_) => "detection.flow",
            DetectionError::Host(_) => "detection.host",
            DetectionError::InSource { cause, .. } => cause.code(),
            DetectionError::Parse(_) => "detection.parse",
            DetectionError::Pattern(_) => "detection.pattern",
            DetectionError::Tier(_) => "detection.tier",
            DetectionError::UnusedBody { .. } => "detection.unused_body",
        }
    }
}

impl Coded for TargetParseError {
    fn code(&self) -> &'static str {
        match self {
            TargetParseError::Address { source, .. } => source.code(),
            TargetParseError::Ports { source, .. } => source.code(),
            TargetParseError::Blank(..) => "target.blank",
            TargetParseError::Empty => "target.empty",
            TargetParseError::EmptyPorts(_) => "target.empty_ports",
            TargetParseError::MistypedAddress(_) => "target.mistyped_address",
            TargetParseError::NoHostLookup(_) => "target.no_host_lookup",
            TargetParseError::ResolvedToNothing(_) => "target.resolved_to_nothing",
            TargetParseError::TrailingText(_) => "target.trailing_text",
            TargetParseError::UnbalancedBracket(_) => "target.unbalanced_bracket",
            TargetParseError::UnbracketedAddress(_) => "target.unbracketed_address",
            TargetParseError::UnknownHost(_) => "target.unknown_host",
        }
    }
}

impl Coded for IpParseError {
    fn code(&self) -> &'static str {
        match self {
            IpParseError::EmptySet => "address.empty_set",
            IpParseError::InvalidPrefix(_) => "address.invalid_prefix",
            IpParseError::InvalidRange(..) => "address.invalid_range",
            IpParseError::KeywordUnresolved { .. } => "address.keyword_unresolved",
            IpParseError::Malformed(_) => "address.malformed",
            IpParseError::UnknownInterface(_) => "address.unknown_interface",
            IpParseError::ZoneOnUnscopedTarget(_) => "address.zone_on_unscoped_target",
        }
    }
}

impl Coded for PortSetParseError {
    fn code(&self) -> &'static str {
        match self {
            PortSetParseError::InvalidPort { .. } => "ports.invalid_port",
            PortSetParseError::InvalidRange { .. } => "ports.invalid_range",
            PortSetParseError::MalformedSpec(_) => "ports.malformed_spec",
        }
    }
}

impl Coded for ImportError {
    fn code(&self) -> &'static str {
        match self {
            ImportError::Io(_) => "import.io",
            ImportError::LineTooLong { .. } => "import.line_too_long",
            ImportError::InvalidUtf8 { .. } => "import.invalid_utf8",
            ImportError::DocumentTooLarge { .. } => "import.document_too_large",
            ImportError::TooManyHosts { .. } => "import.too_many_hosts",
            ImportError::TooManyTokens { .. } => "import.too_many_tokens",
            ImportError::TooManyAddresses { .. } => "import.too_many_addresses",
            ImportError::Target { source, .. } => source.code(),
            ImportError::Malformed { .. } => "import.malformed",
        }
    }
}

#[cfg(feature = "import-request")]
impl Coded for RequestError {
    fn code(&self) -> &'static str {
        match self {
            RequestError::NoTargets => "request.no_targets",
            RequestError::Ports { .. } => "request.bad_ports",
            RequestError::Targets(source) => source.code(),
        }
    }
}

#[cfg(feature = "import-settings")]
impl Coded for SettingsError {
    fn code(&self) -> &'static str {
        match self {
            SettingsError::Io { .. } => "settings.io",
            SettingsError::Malformed(_) => "settings.malformed",
            SettingsError::NoPath => "settings.no_path",
            SettingsError::TooLarge { .. } => "settings.too_large",
            SettingsError::UnknownProfile { .. } => "settings.unknown_profile",
        }
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

    /// One of each, for the assertions that hold for every code alike.
    fn sample() -> Vec<&'static str> {
        vec![
            ScanError::WrongPhase.code(),
            EvasionError::HopLimitZero.code(),
            EvasionError::FragmentTooSmall {
                mtu: 8,
                minimum: 28,
            }
            .code(),
            ExportError::Render {
                format: "html",
                message: String::new(),
            }
            .code(),
            IpParseError::EmptySet.code(),
            IpParseError::InvalidPrefix(33).code(),
            TargetParseError::Empty.code(),
            TargetParseError::UnknownHost("nowhere".into()).code(),
            PortSetParseError::InvalidRange { start: 9, end: 1 }.code(),
            PortSetParseError::MalformedSpec("x".into()).code(),
            DetectionError::Parse("bad toml".into()).code(),
        ]
    }

    /// Every code reads `area.what`, in lower case.
    ///
    /// The shape is part of the contract. A consumer grouping failures by the
    /// area they came from splits on the dot, and a code arriving in some other
    /// shape puts a whole area in the wrong bucket rather than failing loudly.
    #[test]
    fn every_code_reads_area_then_what() {
        for code in sample() {
            let (area, what) = code
                .split_once('.')
                .unwrap_or_else(|| panic!("{code} names no area"));

            assert!(!area.is_empty(), "{code} has an empty area");
            assert!(!what.is_empty(), "{code} says nothing about what happened");
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
                "{code} is not a lower-case dotted name"
            );
        }
    }

    /// An error that wraps another answers with the inner one's code.
    ///
    /// That a scan refused an evasion profile is not news to whoever wrote the
    /// profile. Which part of it was refused is.
    #[test]
    fn a_wrapping_error_reports_the_reason_rather_than_itself() {
        assert_eq!(
            ScanError::Evasion(EvasionError::HopLimitZero).code(),
            "evasion.hop_limit_zero"
        );

        assert_eq!(
            TargetParseError::Address {
                expression: "10.0.0.".into(),
                source: IpParseError::Malformed("10.0.0.".into()),
            }
            .code(),
            "address.malformed"
        );

        assert_eq!(
            TargetParseError::Ports {
                expression: "198.51.100.1:x".into(),
                source: PortSetParseError::MalformedSpec("x".into()),
            }
            .code(),
            "ports.malformed_spec"
        );
    }

    /// A panicking strategy and a failing one are told apart.
    ///
    /// One is a defect in this crate and the other is the network being the
    /// network. A consumer that files bug reports needs to know which it has.
    #[test]
    fn a_panic_and_a_failure_are_not_the_same_code() {
        let panicked = ScanError::TaskFailed {
            panicked: true,
            detail: "index out of bounds".into(),
        };
        let failed = ScanError::TaskFailed {
            panicked: false,
            detail: "cancelled".into(),
        };

        assert_eq!(panicked.code(), "scan.task_panicked");
        assert_eq!(failed.code(), "scan.task_failed");
    }

    /// The codes, written out.
    ///
    /// A golden list rather than a property, because the whole promise of a code
    /// is that it does not move, and the only way to hold one still is to have
    /// written down what it is. A failure here is either a mistake or a decision
    /// somebody has to make on purpose.
    #[test]
    fn the_codes_are_what_they_were() {
        assert_eq!(ScanError::WrongPhase.code(), "scan.wrong_phase");
        assert_eq!(
            EvasionError::SourcePortZero.code(),
            "evasion.source_port_zero"
        );
        assert_eq!(
            EvasionError::PaddingTooLarge {
                padding: 9000,
                limit: 1500
            }
            .code(),
            "evasion.padding_too_large"
        );
        assert_eq!(ExportError::Io(broken_pipe()).code(), "export.io");
        assert_eq!(IpParseError::EmptySet.code(), "address.empty_set");
        assert_eq!(
            IpParseError::UnknownInterface("en9".into()).code(),
            "address.unknown_interface"
        );
        assert_eq!(TargetParseError::Empty.code(), "target.empty");
        assert_eq!(
            TargetParseError::UnbalancedBracket("[::1".into()).code(),
            "target.unbalanced_bracket"
        );
        assert_eq!(
            PortSetParseError::InvalidRange { start: 9, end: 1 }.code(),
            "ports.invalid_range"
        );
        assert_eq!(DetectionError::Tier("4".into()).code(), "detection.tier");
    }

    /// A journal that is not one, and one written by a newer build, are
    /// different answers to "why can this not be resumed".
    #[cfg(feature = "journal-format")]
    #[test]
    fn the_journal_codes_are_what_they_were() {
        assert_eq!(JournalError::NotAJournal.code(), "journal.not_a_journal");
        assert_eq!(
            JournalError::VersionTooNew {
                found: 9,
                understood: 1
            }
            .code(),
            "journal.version_too_new"
        );
        assert_eq!(
            OpenError::VersionTooOld {
                found: 0,
                understood: 1
            }
            .code(),
            "journal.version_too_old"
        );
        assert_eq!(
            OpenError::Journal(JournalError::NotAJournal).code(),
            "journal.not_a_journal",
            "an open that failed on the format reports the format's reason"
        );
    }

    fn broken_pipe() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gone")
    }
}
