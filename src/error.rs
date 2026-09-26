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
//! Every public error type in this crate has one, the low-level ones a caller
//! assembling its own scan meets included, since a front end that has to fall
//! back on the wording for some errors cannot rely on codes for any.
//!
//! The name is stable and the wording of the message is not. Renaming a variant
//! does not rename its code, and a code is only ever retired by being replaced
//! with one a consumer can tell apart. Each names one failure, so no two arms
//! hand out the same code.
//!
//! Codes read `area.what`: the area a caller was working in, and the thing that
//! stopped it. An error that wraps another reports the inner one's code, since
//! `scan.evasion` would say only that a scan refused something the caller could
//! read for themselves in `evasion.hop_limit_zero`.

use crate::config::envelope::UnknownDetectionEnvelope;
use crate::config::{UnknownOsDetection, UnknownScanEffort, UnknownServiceDetection};
use crate::cve::CatalogueError;
use crate::detect::bundle::BundleError;
use crate::detect::compute::{CapError, LoadError, ReplayError};
use crate::detect::corpus::DetectionError;
use crate::detect::flow::ParseError as FlowParseError;
use crate::evasion::EvasionError;
use crate::export::ExportError;
use crate::fingerprint::os::{InvalidRule, RuleError};
use crate::fingerprint::{DefinitionError, InvalidDefinition};
use crate::import::ImportError;
#[cfg(feature = "import-kev")]
use crate::import::kev::KevError;
#[cfg(feature = "import-nvd")]
use crate::import::nvd::NvdError;
#[cfg(feature = "journal-format")]
use crate::journal::format::JournalError;
#[cfg(feature = "journal-format")]
use crate::journal::lock::LockRefused;
#[cfg(feature = "journal-format")]
use crate::journal::manifest::{OptionChanged, PlanChanged};
#[cfg(feature = "journal-format")]
use crate::journal::store::OpenError;
use crate::model::finding::{FindingError, VersionParseError};
use crate::model::ip::range::IpError;
use crate::model::ip::scoped::ScopedIpError;
use crate::model::ip::set::IpSetError;
use crate::model::mac::MacAddrParseError;
use crate::model::parse::ip::IpParseError;
use crate::model::parse::target::TargetParseError;
use crate::model::port::set::PortSetParseError;
use crate::model::target::TargetError;
use crate::model::technique::{UnknownSctpTechnique, UnknownTechnique};
use crate::model::tls::UnknownTlsVersion;
use crate::protocols::error::PacketError;
use crate::resolve::LinkError;
use crate::scanner::ScanError;
use crate::scanner::rdns::ResolverError;
use crate::scanner::strategy::StrategyError;
use crate::signature::SignatureError;
use crate::transport::capture::CaptureError;
use crate::transport::channel::ChannelError;
#[cfg(feature = "packet-exchange")]
use crate::transport::exchange::ExchangeError;
use crate::transport::probe::{SendError, TransportError, UnknownSendMode};
use crate::transport::raw::RawSocketError;

#[cfg(feature = "import-request")]
use crate::import::request::RequestError;
#[cfg(feature = "import-settings")]
use crate::import::settings::SettingsError;

/// An error with a name a consumer outside Rust can branch on.
///
/// The module documentation states what the name promises and how the codes are
/// shaped. Implemented for every public error type in this crate, so whatever
/// error a caller holds, it has a code to branch on.
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
            #[cfg(feature = "journal-format")]
            ScanError::OptionChanged(changed) => changed.code(),
            ScanError::Evasion(evasion) => evasion.code(),
            ScanError::TooFewDescriptors { .. } => "scan.too_few_descriptors",
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

#[cfg(feature = "journal-format")]
impl Coded for OptionChanged {
    fn code(&self) -> &'static str {
        "journal.option_changed"
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
            PortSetParseError::SpacedRange(_) => "ports.spaced_range",
            PortSetParseError::ServiceName(_) => "ports.service_name",
            PortSetParseError::NoPorts => "ports.empty",
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

/// Implements [`Coded`] for an error with one code whatever its contents: a
/// value that did not parse as the one thing it had to be.
macro_rules! one_code {
    ($($error:ty => $code:literal),+ $(,)?) => {
        $(impl Coded for $error {
            fn code(&self) -> &'static str {
                $code
            }
        })+
    };
}

one_code! {
    UnknownOsDetection => "config.unknown_os_detection",
    UnknownScanEffort => "config.unknown_scan_effort",
    UnknownServiceDetection => "config.unknown_service_detection",
    UnknownDetectionEnvelope => "config.unknown_detection_envelope",
    UnknownTechnique => "config.unknown_tcp_technique",
    UnknownSctpTechnique => "config.unknown_sctp_technique",
    UnknownSendMode => "config.unknown_send_mode",
    UnknownTlsVersion => "config.unknown_tls_version",
    MacAddrParseError => "mac.malformed",
    VersionParseError => "finding.malformed_version",
}

impl Coded for FindingError {
    fn code(&self) -> &'static str {
        match self {
            FindingError::EmptyId => "finding.empty_id",
            FindingError::EmptyTitle => "finding.empty_title",
        }
    }
}

impl Coded for IpError {
    fn code(&self) -> &'static str {
        match self {
            IpError::InvalidRange(..) => "range.backwards",
            IpError::InvalidPrefix(_) => "range.invalid_prefix",
            IpError::AddrParse(_) => "range.malformed_address",
            IpError::InvalidFormat(_) => "range.malformed",
            IpError::PrefixParse(_) => "range.malformed_prefix",
        }
    }
}

impl Coded for IpSetError {
    fn code(&self) -> &'static str {
        match self {
            IpSetError::InvalidTarget(range) => range.code(),
        }
    }
}

impl Coded for ScopedIpError {
    fn code(&self) -> &'static str {
        match self {
            ScopedIpError::NotAnAddress(_) => "scoped_address.not_an_address",
            ScopedIpError::ZoneOnUnscopedAddress(..) => "scoped_address.zone_on_unscoped",
            ScopedIpError::EmptyZone => "scoped_address.empty_zone",
        }
    }
}

impl Coded for TargetError {
    fn code(&self) -> &'static str {
        match self {
            TargetError::CapacityOverflow => "target.capacity_overflow",
        }
    }
}

impl Coded for LinkError {
    fn code(&self) -> &'static str {
        match self {
            LinkError::Empty => "link.empty",
            LinkError::Unknown { .. } => "link.unknown",
            LinkError::NoLan => "link.no_lan",
            LinkError::NoLinks => "link.no_links",
        }
    }
}

impl Coded for CatalogueError {
    fn code(&self) -> &'static str {
        match self {
            CatalogueError::Io(_) => "catalogue.io",
            CatalogueError::Malformed(_) => "catalogue.malformed",
            CatalogueError::ReservedId { .. } => "catalogue.reserved_id",
            CatalogueError::TooLarge { .. } => "catalogue.too_large",
            CatalogueError::UnreadableVersion { .. } => "catalogue.unreadable_version",
        }
    }
}

#[cfg(feature = "import-kev")]
impl Coded for KevError {
    fn code(&self) -> &'static str {
        match self {
            KevError::Io(_) => "kev.io",
            KevError::Malformed(_) => "kev.malformed",
            KevError::TooLarge { .. } => "kev.too_large",
            KevError::Rejected(catalogue) => catalogue.code(),
        }
    }
}

#[cfg(feature = "import-nvd")]
impl Coded for NvdError {
    fn code(&self) -> &'static str {
        match self {
            NvdError::Io(_) => "nvd.io",
            NvdError::Malformed(_) => "nvd.malformed",
            NvdError::TooLarge { .. } => "nvd.too_large",
            NvdError::TooManyEntries { .. } => "nvd.too_many_entries",
            NvdError::Rejected(catalogue) => catalogue.code(),
        }
    }
}

impl Coded for SignatureError {
    fn code(&self) -> &'static str {
        match self {
            SignatureError::UnreadableKey => "signature.unreadable_key",
            SignatureError::Malformed(_) => "signature.malformed",
            SignatureError::UnknownAlgorithm { .. } => "signature.unknown_algorithm",
            SignatureError::UntrustedKey => "signature.untrusted_key",
            SignatureError::Altered => "signature.altered",
            SignatureError::Invalid => "signature.invalid",
            SignatureError::Io(_) => "signature.io",
        }
    }
}

impl Coded for BundleError {
    fn code(&self) -> &'static str {
        match self {
            BundleError::Signature(signature) => signature.code(),
            BundleError::Manifest(_) => "bundle.manifest",
            BundleError::Missing { .. } => "bundle.missing",
            BundleError::Altered { .. } => "bundle.altered",
            BundleError::Unnamed { .. } => "bundle.unnamed",
            BundleError::Duplicate { .. } => "bundle.duplicate",
            BundleError::TooMany { .. } => "bundle.too_many",
        }
    }
}

impl Coded for FlowParseError {
    fn code(&self) -> &'static str {
        match self {
            FlowParseError::Empty => "flow.empty",
            FlowParseError::UnexpectedChar(_) => "flow.unexpected_char",
            FlowParseError::UnterminatedString => "flow.unterminated_string",
            FlowParseError::IntOverflow(_) => "flow.int_overflow",
            FlowParseError::Expected(_) => "flow.expected",
            FlowParseError::Trailing => "flow.trailing",
            FlowParseError::TooDeep => "flow.too_deep",
        }
    }
}

impl Coded for CapError {
    fn code(&self) -> &'static str {
        match self {
            CapError::ByteBudgetExhausted => "capability.byte_budget_exhausted",
            CapError::ConnectionBudgetExhausted => "capability.connection_budget_exhausted",
            CapError::Denied(_) => "capability.denied",
            CapError::TimedOut => "capability.timed_out",
            CapError::ConnectionRefused => "capability.connection_refused",
            CapError::Reset => "capability.reset",
        }
    }
}

impl Coded for LoadError {
    fn code(&self) -> &'static str {
        match self {
            LoadError::Compile(_) => "compute.compile",
            LoadError::UnsupportedBody => "compute.unsupported_body",
        }
    }
}

impl Coded for ReplayError {
    fn code(&self) -> &'static str {
        match self {
            ReplayError::UnknownDetection => "replay.unknown_detection",
            ReplayError::UnknownTransport(_) => "replay.unknown_transport",
            ReplayError::GrantFailed => "replay.grant_failed",
            ReplayError::Instantiate(load) => load.code(),
            ReplayError::Run(_) => "replay.run",
            ReplayError::Diverged => "replay.diverged",
        }
    }
}

impl Coded for DefinitionError {
    fn code(&self) -> &'static str {
        match self {
            DefinitionError::Pattern { .. } => "definition.pattern",
            DefinitionError::VersionGroup { .. } => "definition.version_group",
            DefinitionError::ProbeProtocol { .. } => "definition.probe_protocol",
            DefinitionError::GenericProbeNotTcp { .. } => "definition.generic_probe_not_tcp",
            DefinitionError::UdpProbeSize { .. } => "definition.udp_probe_size",
        }
    }
}

impl Coded for InvalidDefinition {
    fn code(&self) -> &'static str {
        self.error.code()
    }
}

impl Coded for RuleError {
    fn code(&self) -> &'static str {
        match self {
            RuleError::Unidentified => "rule.unidentified",
            RuleError::VersionWithoutProduct => "rule.version_without_product",
            RuleError::Weight(_) => "rule.weight",
            RuleError::Predicate { .. } => "rule.predicate",
            RuleError::NoPredicates => "rule.no_predicates",
            RuleError::ExampleWithoutSeries(_) => "rule.example_without_series",
            RuleError::ExampleWithoutWindow(_) => "rule.example_without_window",
        }
    }
}

impl Coded for InvalidRule {
    fn code(&self) -> &'static str {
        self.error.code()
    }
}

impl Coded for PacketError {
    fn code(&self) -> &'static str {
        match self {
            PacketError::TooLong { .. } => "packet.too_long",
            PacketError::FamilyMismatch { .. } => "packet.family_mismatch",
            PacketError::WrongFamily { .. } => "packet.wrong_family",
            PacketError::MtuTooSmall { .. } => "packet.mtu_too_small",
            PacketError::HeaderHasOptions { .. } => "packet.header_has_options",
            PacketError::OptionsTooLong { .. } => "packet.options_too_long",
            PacketError::OptionsMisaligned { .. } => "packet.options_misaligned",
            PacketError::UnsupportedEtherType(_) => "packet.unsupported_ether_type",
            PacketError::Unreadable { .. } => "packet.unreadable",
            PacketError::UnexpectedMessage { .. } => "packet.unexpected_message",
            PacketError::UnwritableName { .. } => "packet.unwritable_name",
            PacketError::Truncated { .. } => "packet.truncated",
        }
    }
}

impl Coded for CaptureError {
    fn code(&self) -> &'static str {
        match self {
            CaptureError::NoInterface { .. } => "capture.no_interface",
            CaptureError::NoReader { .. } => "capture.no_reader",
            CaptureError::UnsupportedLinkType { .. } => "capture.unsupported_link_type",
            CaptureError::Filter { .. } => "capture.filter",
            CaptureError::Open { .. } => "capture.open",
            CaptureError::Denied { .. } => "capture.denied",
        }
    }
}

impl Coded for RawSocketError {
    fn code(&self) -> &'static str {
        match self {
            RawSocketError::Open { .. } => "raw_socket.open",
            RawSocketError::NoSocket { .. } => "raw_socket.no_socket",
            RawSocketError::HopLimit { .. } => "raw_socket.hop_limit",
            RawSocketError::NotHeld { .. } => "raw_socket.not_held",
            RawSocketError::Pin { .. } => "raw_socket.pin",
            RawSocketError::Send { .. } => "raw_socket.send",
            RawSocketError::Poisoned => "raw_socket.poisoned",
        }
    }
}

impl Coded for TransportError {
    fn code(&self) -> &'static str {
        match self {
            TransportError::Capture(capture) => capture.code(),
            TransportError::RawSocket(_) => "transport.raw_socket",
            TransportError::NoEthernetInterface(_) => "transport.no_ethernet_interface",
        }
    }
}

impl Coded for SendError {
    fn code(&self) -> &'static str {
        match self {
            SendError::Unroutable(_) => "send.unroutable",
            SendError::Unresolved(_) => "send.unresolved",
            SendError::Refused(_) => "send.refused",
            SendError::Unsupported(_) => "send.unsupported",
        }
    }
}

impl Coded for ChannelError {
    fn code(&self) -> &'static str {
        match self {
            ChannelError::Send { .. } => "channel.send",
            ChannelError::Receive { .. } => "channel.receive",
        }
    }
}

#[cfg(feature = "packet-exchange")]
impl Coded for ExchangeError {
    fn code(&self) -> &'static str {
        match self {
            ExchangeError::Transport(transport) => transport.code(),
            ExchangeError::Build(packet) => packet.code(),
            ExchangeError::Send(send) => send.code(),
            ExchangeError::NoSource(_) => "exchange.no_source",
        }
    }
}

impl Coded for StrategyError {
    fn code(&self) -> &'static str {
        match self {
            StrategyError::Transport(transport) => transport.code(),
            StrategyError::Channel(channel) => channel.code(),
            StrategyError::Capture(capture) => capture.code(),
            StrategyError::Interface { .. } => "strategy.interface",
            StrategyError::Probe(_) => "strategy.probe",
            StrategyError::Panicked { .. } => "strategy.panicked",
        }
    }
}

impl Coded for ResolverError {
    fn code(&self) -> &'static str {
        match self {
            ResolverError::NoServer => "rdns.no_server",
            ResolverError::Transport(transport) => transport.code(),
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
            ScanError::TooFewDescriptors {
                limit: 16,
                needed: 17
            }
            .code(),
            "scan.too_few_descriptors"
        );
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

    /// Every code this file hands out, written down once.
    ///
    /// The codebook is read out of this file's own source, every quoted
    /// `area.what` outside the tests, so an arm added, renamed or dropped
    /// anywhere above fails here until the list is edited to match. That edit
    /// is the decision a code change is, made where it can be seen. Each code
    /// names one failure, so none is handed out by two arms.
    #[test]
    fn every_code_is_in_the_codebook_once() {
        const WRITTEN: &[&str] = &[
            "address.empty_set",
            "address.invalid_prefix",
            "address.invalid_range",
            "address.keyword_unresolved",
            "address.malformed",
            "address.unknown_interface",
            "address.zone_on_unscoped_target",
            "bundle.altered",
            "bundle.duplicate",
            "bundle.manifest",
            "bundle.missing",
            "bundle.too_many",
            "bundle.unnamed",
            "capability.byte_budget_exhausted",
            "capability.connection_budget_exhausted",
            "capability.connection_refused",
            "capability.denied",
            "capability.reset",
            "capability.timed_out",
            "capture.denied",
            "capture.filter",
            "capture.no_interface",
            "capture.no_reader",
            "capture.open",
            "capture.unsupported_link_type",
            "catalogue.io",
            "catalogue.malformed",
            "catalogue.reserved_id",
            "catalogue.too_large",
            "catalogue.unreadable_version",
            "channel.receive",
            "channel.send",
            "compute.compile",
            "compute.unsupported_body",
            "config.unknown_detection_envelope",
            "config.unknown_os_detection",
            "config.unknown_scan_effort",
            "config.unknown_sctp_technique",
            "config.unknown_send_mode",
            "config.unknown_service_detection",
            "config.unknown_tcp_technique",
            "config.unknown_tls_version",
            "definition.generic_probe_not_tcp",
            "definition.pattern",
            "definition.probe_protocol",
            "definition.udp_probe_size",
            "definition.version_group",
            "detection.body",
            "detection.compute",
            "detection.flow",
            "detection.host",
            "detection.parse",
            "detection.pattern",
            "detection.tier",
            "detection.unused_body",
            "evasion.fragment_too_small",
            "evasion.hop_limit_zero",
            "evasion.padding_too_large",
            "evasion.source_port_zero",
            "exchange.no_source",
            "export.io",
            "export.render",
            "finding.empty_id",
            "finding.empty_title",
            "finding.malformed_version",
            "flow.empty",
            "flow.expected",
            "flow.int_overflow",
            "flow.too_deep",
            "flow.trailing",
            "flow.unexpected_char",
            "flow.unterminated_string",
            "import.document_too_large",
            "import.io",
            "import.line_too_long",
            "import.malformed",
            "import.too_many_addresses",
            "import.too_many_hosts",
            "import.too_many_tokens",
            "journal.io",
            "journal.lock_io",
            "journal.locked",
            "journal.malformed",
            "journal.not_a_journal",
            "journal.option_changed",
            "journal.plan_changed",
            "journal.version_too_new",
            "journal.version_too_old",
            "journal.wrong_phase",
            "kev.io",
            "kev.malformed",
            "kev.too_large",
            "link.empty",
            "link.no_lan",
            "link.no_links",
            "link.unknown",
            "mac.malformed",
            "nvd.io",
            "nvd.malformed",
            "nvd.too_large",
            "nvd.too_many_entries",
            "packet.family_mismatch",
            "packet.header_has_options",
            "packet.mtu_too_small",
            "packet.options_misaligned",
            "packet.options_too_long",
            "packet.too_long",
            "packet.truncated",
            "packet.unexpected_message",
            "packet.unreadable",
            "packet.unsupported_ether_type",
            "packet.unwritable_name",
            "packet.wrong_family",
            "ports.empty",
            "ports.invalid_port",
            "ports.invalid_range",
            "ports.malformed_spec",
            "ports.service_name",
            "ports.spaced_range",
            "range.backwards",
            "range.invalid_prefix",
            "range.malformed",
            "range.malformed_address",
            "range.malformed_prefix",
            "raw_socket.hop_limit",
            "raw_socket.no_socket",
            "raw_socket.not_held",
            "raw_socket.open",
            "raw_socket.pin",
            "raw_socket.poisoned",
            "raw_socket.send",
            "rdns.no_server",
            "replay.diverged",
            "replay.grant_failed",
            "replay.run",
            "replay.unknown_detection",
            "replay.unknown_transport",
            "request.bad_ports",
            "request.no_targets",
            "rule.example_without_series",
            "rule.example_without_window",
            "rule.no_predicates",
            "rule.predicate",
            "rule.unidentified",
            "rule.version_without_product",
            "rule.weight",
            "scan.task_failed",
            "scan.task_panicked",
            "scan.too_few_descriptors",
            "scan.wrong_phase",
            "scoped_address.empty_zone",
            "scoped_address.not_an_address",
            "scoped_address.zone_on_unscoped",
            "send.refused",
            "send.unresolved",
            "send.unroutable",
            "send.unsupported",
            "settings.io",
            "settings.malformed",
            "settings.no_path",
            "settings.too_large",
            "settings.unknown_profile",
            "signature.altered",
            "signature.invalid",
            "signature.io",
            "signature.malformed",
            "signature.unknown_algorithm",
            "signature.unreadable_key",
            "signature.untrusted_key",
            "strategy.interface",
            "strategy.panicked",
            "strategy.probe",
            "target.blank",
            "target.capacity_overflow",
            "target.empty",
            "target.empty_ports",
            "target.mistyped_address",
            "target.no_host_lookup",
            "target.resolved_to_nothing",
            "target.trailing_text",
            "target.unbalanced_bracket",
            "target.unbracketed_address",
            "target.unknown_host",
            "transport.no_ethernet_interface",
            "transport.raw_socket",
        ];

        let source = include_str!("error.rs");
        let codes_end = source
            .find("#[cfg(test)]\nmod tests")
            .expect("the tests module");
        let mut handed_out: Vec<&str> = source[..codes_end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .flat_map(|line| line.split('"').skip(1).step_by(2))
            .filter(|quoted| {
                quoted.split_once('.').is_some_and(|(area, what)| {
                    !area.is_empty()
                        && !what.is_empty()
                        && quoted
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_')
                })
            })
            .collect();
        handed_out.sort_unstable();

        let mut unique = handed_out.clone();
        unique.dedup();
        assert_eq!(handed_out, unique, "a code handed out by two arms");
        assert_eq!(handed_out, WRITTEN, "the codes and the codebook differ");
    }

    fn broken_pipe() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gone")
    }
}
