// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the model's enums are called in a file
//!
//! One name and one parser for each, defined together so that they cannot drift
//! apart. [`export::schema`](crate::export::schema) writes through the names
//! here and [`journal`](crate::journal) reads through the parsers, which is why
//! neither of them defines its own.
//!
//! A name is a promise: it appears in exported reports and in journals on disk,
//! so changing one is a breaking change to both. Adding a variant means adding
//! its name and its parse case here, and `every_name_parses_back` will fail
//! until you do.
//!
//! ## An unknown name is refused, not guessed
//!
//! Every parser returns `None` for a name this build does not know, and callers
//! report it rather than substituting a neighbour. A port state read as
//! `Filtered` because the file said something newer is a scan reporting a
//! firewall that is not there.
//!
//! ## Strategy-supplied names are prefixed
//!
//! [`StatusProtocol::Custom`] and [`ScanResponse::Custom`] carry a name their
//! author chose, rendered with a `custom:` prefix so that it can never be
//! mistaken for one this engine defines. Without it, something calling itself
//! `arp` would be indistinguishable from a real ARP finding.

use std::borrow::Cow;

use crate::fingerprint::os::OsSource;
use crate::model::host::{Filtering, HostStatus, NetworkRole, StatusProtocol};
use crate::model::port::discovery::ScanResponse;
use crate::model::port::{PortSet, PortState, Protocol};
use crate::scanner::report::{AttachmentSource, PortScope, ScanKind, StopReason};
use crate::scanner::session::ScannerKind;

/// The prefix that marks a name a strategy supplied rather than one this engine
/// defines.
const CUSTOM: &str = "custom:";

/// A host's reachability.
pub fn host_status_name(status: HostStatus) -> &'static str {
    match status {
        HostStatus::Unknown => "unknown",
        HostStatus::Down => "down",
        HostStatus::Filtered => "filtered",
        HostStatus::Up => "up",
    }
}

/// [`host_status_name`] read back.
pub fn host_status(name: &str) -> Option<HostStatus> {
    Some(match name {
        "unknown" => HostStatus::Unknown,
        "down" => HostStatus::Down,
        "filtered" => HostStatus::Filtered,
        "up" => HostStatus::Up,
        _ => return None,
    })
}

/// What a probe established about a port.
pub fn port_state_name(state: PortState) -> &'static str {
    match state {
        PortState::ClosedFiltered => "closed_filtered",
        PortState::Filtered => "filtered",
        PortState::Unfiltered => "unfiltered",
        PortState::Closed => "closed",
        PortState::OpenFiltered => "open_filtered",
        PortState::Open => "open",
    }
}

/// [`port_state_name`] read back.
pub fn port_state(name: &str) -> Option<PortState> {
    Some(match name {
        "closed_filtered" => PortState::ClosedFiltered,
        "filtered" => PortState::Filtered,
        "unfiltered" => PortState::Unfiltered,
        "closed" => PortState::Closed,
        "open_filtered" => PortState::OpenFiltered,
        "open" => PortState::Open,
        _ => return None,
    })
}

/// A transport.
pub fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

/// [`protocol_name`] read back.
pub fn protocol(name: &str) -> Option<Protocol> {
    Some(match name {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => return None,
    })
}

/// A role the scan concluded about a host.
pub fn network_role_name(role: NetworkRole) -> &'static str {
    match role {
        NetworkRole::Router => "router",
        NetworkRole::DnsServer => "dns",
        NetworkRole::DhcpServer => "dhcp",
        NetworkRole::NtpServer => "ntp",
        NetworkRole::SnmpAgent => "snmp",
        NetworkRole::Switch => "switch",
        NetworkRole::Origin => "origin",
        NetworkRole::Tarpit => "tarpit",
        NetworkRole::Truncated => "truncated",
    }
}

/// [`network_role_name`] read back.
pub fn network_role(name: &str) -> Option<NetworkRole> {
    Some(match name {
        "router" => NetworkRole::Router,
        "dns" => NetworkRole::DnsServer,
        "dhcp" => NetworkRole::DhcpServer,
        "ntp" => NetworkRole::NtpServer,
        "snmp" => NetworkRole::SnmpAgent,
        "switch" => NetworkRole::Switch,
        "origin" => NetworkRole::Origin,
        "tarpit" => NetworkRole::Tarpit,
        "truncated" => NetworkRole::Truncated,
        _ => return None,
    })
}

/// A filtering conclusion the scan drew about the path to a host.
pub fn filtering_name(filtering: Filtering) -> &'static str {
    match filtering {
        Filtering::InlineMiddlebox => "inline_middlebox",
    }
}

/// [`filtering_name`] read back.
pub fn filtering(name: &str) -> Option<Filtering> {
    Some(match name {
        "inline_middlebox" => Filtering::InlineMiddlebox,
        _ => return None,
    })
}

/// The protocol behind a host's status.
pub fn status_protocol_name(protocol: &StatusProtocol) -> Cow<'_, str> {
    match protocol {
        StatusProtocol::Arp => Cow::Borrowed("arp"),
        StatusProtocol::Ndp => Cow::Borrowed("ndp"),
        StatusProtocol::IcmpEcho => Cow::Borrowed("icmp_echo"),
        StatusProtocol::IcmpUnreachable => Cow::Borrowed("icmp_unreachable"),
        StatusProtocol::TcpSyn => Cow::Borrowed("tcp_syn"),
        StatusProtocol::Tcp => Cow::Borrowed("tcp"),
        StatusProtocol::Dhcp => Cow::Borrowed("dhcp"),
        StatusProtocol::Udp => Cow::Borrowed("udp"),
        StatusProtocol::Custom(name) => Cow::Owned(format!("{CUSTOM}{name}")),
    }
}

/// [`status_protocol_name`] read back.
///
/// An empty custom name is refused: it renders as the bare prefix and would read
/// back as a finding attributed to nothing.
pub fn status_protocol(name: &str) -> Option<StatusProtocol> {
    if let Some(custom) = name.strip_prefix(CUSTOM) {
        return (!custom.is_empty()).then(|| StatusProtocol::Custom(custom.into()));
    }

    Some(match name {
        "arp" => StatusProtocol::Arp,
        "ndp" => StatusProtocol::Ndp,
        "icmp_echo" => StatusProtocol::IcmpEcho,
        "icmp_unreachable" => StatusProtocol::IcmpUnreachable,
        "tcp_syn" => StatusProtocol::TcpSyn,
        "tcp" => StatusProtocol::Tcp,
        "dhcp" => StatusProtocol::Dhcp,
        "udp" => StatusProtocol::Udp,
        _ => return None,
    })
}

/// The packet that settled a port's state.
pub fn scan_response_name(response: &ScanResponse) -> Cow<'_, str> {
    match response {
        ScanResponse::TcpSynAck => Cow::Borrowed("tcp_syn_ack"),
        ScanResponse::OverheardSynAck => Cow::Borrowed("overheard_syn_ack"),
        ScanResponse::TcpRst => Cow::Borrowed("tcp_rst"),
        ScanResponse::UdpResponse => Cow::Borrowed("udp_response"),
        ScanResponse::NoResponse => Cow::Borrowed("no_response"),
        ScanResponse::IcmpUnreachable => Cow::Borrowed("icmp_unreachable"),
        ScanResponse::IcmpProhibited => Cow::Borrowed("icmp_prohibited"),
        ScanResponse::Custom(name) => Cow::Owned(format!("{CUSTOM}{name}")),
    }
}

/// [`scan_response_name`] read back. Empty custom names are refused, as in
/// [`status_protocol`].
pub fn scan_response(name: &str) -> Option<ScanResponse> {
    if let Some(custom) = name.strip_prefix(CUSTOM) {
        return (!custom.is_empty()).then(|| ScanResponse::Custom(custom.to_string()));
    }

    Some(match name {
        "tcp_syn_ack" => ScanResponse::TcpSynAck,
        "overheard_syn_ack" => ScanResponse::OverheardSynAck,
        "tcp_rst" => ScanResponse::TcpRst,
        "udp_response" => ScanResponse::UdpResponse,
        "no_response" => ScanResponse::NoResponse,
        "icmp_unreachable" => ScanResponse::IcmpUnreachable,
        "icmp_prohibited" => ScanResponse::IcmpProhibited,
        _ => return None,
    })
}

/// Where a conclusion about an operating system came from.
pub fn os_source_name(source: OsSource) -> &'static str {
    match source {
        OsSource::TcpStack => "tcp_stack",
        OsSource::HardwareVendor => "hardware_vendor",
        OsSource::ServiceBanner => "service_banner",
        OsSource::SnmpAgent => "snmp_agent",
        OsSource::Hostname => "hostname",
    }
}

/// [`os_source_name`] read back.
pub fn os_source(name: &str) -> Option<OsSource> {
    Some(match name {
        "tcp_stack" => OsSource::TcpStack,
        "hardware_vendor" => OsSource::HardwareVendor,
        "service_banner" => OsSource::ServiceBanner,
        "snmp_agent" => OsSource::SnmpAgent,
        "hostname" => OsSource::Hostname,
        _ => return None,
    })
}

/// Which protocol an attachment was read from.
pub fn attachment_source_name(source: AttachmentSource) -> &'static str {
    match source {
        AttachmentSource::Lldp => "lldp",
        AttachmentSource::Cdp => "cdp",
    }
}

/// The [`AttachmentSource`] a wire name spells, or `None` for one this build
/// does not know.
pub fn attachment_source(name: &str) -> Option<AttachmentSource> {
    Some(match name {
        "lldp" => AttachmentSource::Lldp,
        "cdp" => AttachmentSource::Cdp,
        _ => return None,
    })
}

/// The wire name for a scan kind.
pub fn scan_kind_name(kind: ScanKind) -> &'static str {
    match kind {
        ScanKind::Discovery => "discovery",
        ScanKind::PortScan => "port_scan",
        ScanKind::Listen => "listen",
    }
}

/// [`scan_kind_name`] read back.
pub fn scan_kind(name: &str) -> Option<ScanKind> {
    Some(match name {
        "discovery" => ScanKind::Discovery,
        "port_scan" => ScanKind::PortScan,
        "listen" => ScanKind::Listen,
        _ => return None,
    })
}

/// Which strategy something is attributed to.
pub fn scanner_kind_name(kind: ScannerKind) -> &'static str {
    match kind {
        ScannerKind::Local => "local",
        ScannerKind::Passive => "passive",
        ScannerKind::Routed => "routed",
        ScannerKind::SynPort => "syn_port",
        ScannerKind::TcpPort => "tcp_port",
        ScannerKind::Connect => "connect",
        ScannerKind::ConnectUdp => "connect_udp",
        ScannerKind::UdpPort => "udp_port",
        ScannerKind::OsEcho => "os_echo",
        ScannerKind::OsSeries => "os_series",
        ScannerKind::OsSnmp => "os_snmp",
        ScannerKind::Composite => "composite",
    }
}

/// [`scanner_kind_name`] read back.
pub fn scanner_kind(name: &str) -> Option<ScannerKind> {
    Some(match name {
        "local" => ScannerKind::Local,
        "passive" => ScannerKind::Passive,
        "routed" => ScannerKind::Routed,
        "syn_port" => ScannerKind::SynPort,
        "tcp_port" => ScannerKind::TcpPort,
        "connect" => ScannerKind::Connect,
        "connect_udp" => ScannerKind::ConnectUdp,
        "udp_port" => ScannerKind::UdpPort,
        "os_echo" => ScannerKind::OsEcho,
        "os_series" => ScannerKind::OsSeries,
        "os_snmp" => ScannerKind::OsSnmp,
        "composite" => ScannerKind::Composite,
        _ => return None,
    })
}

/// Why a receive loop stopped.
pub fn stop_reason_name(reason: StopReason) -> &'static str {
    match reason {
        StopReason::Aborted => "aborted",
        StopReason::AllResponded => "all_responded",
        StopReason::AttemptsSpent => "attempts_spent",
        StopReason::DeadlineExpired => "deadline_expired",
        StopReason::StreamClosed => "stream_closed",
    }
}

/// [`stop_reason_name`] read back.
pub fn stop_reason(name: &str) -> Option<StopReason> {
    Some(match name {
        "aborted" => StopReason::Aborted,
        "all_responded" => StopReason::AllResponded,
        "attempts_spent" => StopReason::AttemptsSpent,
        "deadline_expired" => StopReason::DeadlineExpired,
        "stream_closed" => StopReason::StreamClosed,
        _ => return None,
    })
}

/// The wire name of a phase's port scope.
///
/// The set itself travels separately, as a port specification; this names which
/// of the four things that set *is*. A scope with no set has a name here all the
/// same, because "the phase walked no ports" and "the record does not say" are
/// the two that must never be read as each other.
pub fn port_scope_name(scope: &PortScope) -> &'static str {
    match scope {
        PortScope::Unstated => "unstated",
        PortScope::NoPorts => "none",
        PortScope::Every(_) => "every",
        PortScope::Mixed(_) => "mixed",
    }
}

/// [`port_scope_name`] read back, given the set that travelled with it.
///
/// A name this build does not know reads as `None`, which a caller turns into
/// [`PortScope::Unstated`] — the reading that claims nothing.
pub fn port_scope(name: &str, ports: Option<PortSet>) -> Option<PortScope> {
    Some(match (name, ports) {
        ("unstated", _) => PortScope::Unstated,
        ("none", _) => PortScope::NoPorts,
        ("every", Some(ports)) => PortScope::Every(ports),
        ("mixed", Some(ports)) => PortScope::Mixed(ports),
        // A set is what makes those two mean anything, so a name that needs one
        // and did not travel with one says nothing.
        ("every" | "mixed", None) => PortScope::Unstated,
        _ => return None,
    })
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚═╝     ╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant survives being written down and read back.
    ///
    /// Listing the variants by hand is the point: a variant added to the model
    /// without a name here will not appear in this list either, and the match
    /// arms above are what the compiler makes exhaustive. What this catches is
    /// the other mistake — a name and a parser that disagree.
    #[test]
    fn every_name_parses_back() {
        for value in [
            HostStatus::Unknown,
            HostStatus::Down,
            HostStatus::Filtered,
            HostStatus::Up,
        ] {
            assert_eq!(host_status(host_status_name(value)), Some(value));
        }

        for value in [
            PortState::ClosedFiltered,
            PortState::Filtered,
            PortState::Unfiltered,
            PortState::Closed,
            PortState::OpenFiltered,
            PortState::Open,
        ] {
            assert_eq!(port_state(port_state_name(value)), Some(value));
        }

        for value in [ScanKind::Discovery, ScanKind::PortScan, ScanKind::Listen] {
            assert_eq!(scan_kind(scan_kind_name(value)), Some(value));
        }

        for value in [AttachmentSource::Lldp, AttachmentSource::Cdp] {
            assert_eq!(
                attachment_source(attachment_source_name(value)),
                Some(value)
            );
        }

        for value in [
            ScannerKind::Local,
            ScannerKind::Passive,
            ScannerKind::Routed,
            ScannerKind::SynPort,
            ScannerKind::TcpPort,
            ScannerKind::Connect,
            ScannerKind::ConnectUdp,
            ScannerKind::UdpPort,
            ScannerKind::OsEcho,
            ScannerKind::OsSeries,
            ScannerKind::OsSnmp,
            ScannerKind::Composite,
        ] {
            assert_eq!(scanner_kind(scanner_kind_name(value)), Some(value));
        }

        for value in [
            StopReason::Aborted,
            StopReason::AllResponded,
            StopReason::AttemptsSpent,
            StopReason::DeadlineExpired,
            StopReason::StreamClosed,
        ] {
            assert_eq!(stop_reason(stop_reason_name(value)), Some(value));
        }

        for value in [Protocol::Tcp, Protocol::Udp] {
            assert_eq!(protocol(protocol_name(value)), Some(value));
        }

        for value in NetworkRole::ALL {
            assert_eq!(network_role(network_role_name(value)), Some(value));
        }

        for value in [
            OsSource::TcpStack,
            OsSource::HardwareVendor,
            OsSource::ServiceBanner,
            OsSource::Hostname,
        ] {
            assert_eq!(os_source(os_source_name(value)), Some(value));
        }

        for value in [
            StatusProtocol::Arp,
            StatusProtocol::Ndp,
            StatusProtocol::IcmpEcho,
            StatusProtocol::IcmpUnreachable,
            StatusProtocol::TcpSyn,
            StatusProtocol::Tcp,
            StatusProtocol::Dhcp,
            StatusProtocol::Udp,
            StatusProtocol::Custom("a-strategy".into()),
        ] {
            let name = status_protocol_name(&value);
            assert_eq!(status_protocol(&name), Some(value.clone()), "{name}");
        }

        for value in [
            ScanResponse::TcpSynAck,
            ScanResponse::OverheardSynAck,
            ScanResponse::TcpRst,
            ScanResponse::UdpResponse,
            ScanResponse::NoResponse,
            ScanResponse::IcmpUnreachable,
            ScanResponse::IcmpProhibited,
            ScanResponse::Custom("a-strategy".to_string()),
        ] {
            let name = scan_response_name(&value);
            assert_eq!(scan_response(&name), Some(value.clone()), "{name}");
        }
    }

    /// Every built-in protocol is spelled in all three places at once: the
    /// writer, the reader, and the report schema.
    ///
    /// The first two are exhaustive matches, so the compiler already refuses a
    /// variant that has no name. The schema is a JSON file on disk and the
    /// compiler cannot see it at all — which is the one gap, and the one that
    /// lets a finding survive a scan and disappear on the way to the report.
    ///
    /// The `match` below has no wildcard for exactly that reason: a variant
    /// added to [`StatusProtocol`] stops this test compiling until somebody has
    /// decided what the document calls it.
    #[test]
    fn every_built_in_protocol_is_named_everywhere() {
        const SCHEMA: &str = include_str!("../../assets/schema/zond-report-v1.schema.json");

        // Scoped to the one `enum` block that holds these names, because the
        // document spells some of them twice: `dhcp` is a protocol here and a
        // network role four hundred lines up, and a search of the whole file
        // finds the wrong one and passes. Anchored on the description, which
        // occurs exactly once, and running to the first `]`, which closes the
        // enum.
        let described = SCHEMA
            .find("The protocol event that produced the evidence")
            .expect("the schema describes the evidence protocol");
        let names = &SCHEMA[described..];
        let names = &names[..names.find(']').expect("the enum closes")];

        // The scoping is the part that can silently stop working, so it is
        // asserted rather than assumed: a role name has no business in here.
        assert!(
            !names.contains("\"router\""),
            "the search caught the network-role enum instead"
        );

        for protocol in [
            StatusProtocol::Arp,
            StatusProtocol::Ndp,
            StatusProtocol::IcmpEcho,
            StatusProtocol::IcmpUnreachable,
            StatusProtocol::TcpSyn,
            StatusProtocol::Tcp,
            StatusProtocol::Dhcp,
            StatusProtocol::Udp,
        ] {
            match protocol {
                StatusProtocol::Arp
                | StatusProtocol::Ndp
                | StatusProtocol::IcmpEcho
                | StatusProtocol::IcmpUnreachable
                | StatusProtocol::TcpSyn
                | StatusProtocol::Tcp
                | StatusProtocol::Dhcp
                | StatusProtocol::Udp => {}
                StatusProtocol::Custom(_) => {
                    unreachable!("the list above holds no strategy-supplied names")
                }
            }

            let name = status_protocol_name(&protocol);
            assert_eq!(status_protocol(&name), Some(protocol.clone()));
            assert!(
                names.contains(&format!("\"{name}\"")),
                "the report schema does not name '{name}'"
            );
        }
    }

    /// A name this build does not know is refused rather than falling into a
    /// neighbouring variant.
    #[test]
    fn an_unknown_name_is_refused() {
        assert_eq!(host_status("perhaps"), None);
        assert_eq!(port_state("ajar"), None);
        assert_eq!(protocol("sctp"), None);
        assert_eq!(network_role("gateway"), None);
        assert_eq!(os_source("astrology"), None);
        assert_eq!(status_protocol("igmp"), None);
        assert_eq!(scan_response("tcp_fin_ack"), None);
        assert_eq!(scan_kind("enrichment"), None);
        assert_eq!(scanner_kind("telepathy"), None);
        assert_eq!(stop_reason("bored"), None);
    }

    /// A custom name that is empty renders as the bare prefix and names nothing.
    #[test]
    fn an_empty_custom_name_is_refused() {
        assert_eq!(status_protocol(CUSTOM), None);
        assert_eq!(scan_response(CUSTOM), None);
    }
}
