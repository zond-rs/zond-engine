// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A report that exercises every corner of the exported document.
//!
//! Export tests need a report containing each shape the schema can produce -
//! a fully described host and a bare one, a port with a certificate and one
//! without, a strategy that failed, a scanner that filed counters, a script
//! value JSON cannot represent. Driving a real scan produces none of that
//! reliably, and building it inline in each test would leave every test
//! covering a slightly different document.
//!
//! So it is built once, here. Anything a test asserts about the output is
//! traceable to a value set below.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::config::ZondConfig;
use crate::model::capture::CaptureCounts;
use crate::model::host::{
    Host, HostStatus, NetworkRole, OsFingerprint, StatusProtocol, StatusReason,
};
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::port::{
    CertificateInfo, Discovery, Port, PortState, Protocol, ScanResponse, Security, Service,
};
use crate::scanner::report::{
    BUCKET_BOUNDS_MS, PhaseRecorder, ProbeStats, ScanKind, ScanReport, StopReason, TargetScope,
};
use crate::scanner::session::{ScanSession, ScannerKind};

/// An address on the fixture's network.
fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 0, last))
}

/// The gateway: everything the schema can say about a host, said about one.
fn router() -> Host {
    let mut host = Host::new(ip(1));
    host.set_hostname(Some("router.local".to_string()));
    host.set_status(HostStatus::Up);
    host.add_reason(StatusReason::new(StatusProtocol::Arp, "reply from gateway"));
    host.set_mac(MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3));

    let mut os = OsFingerprint::new("Linux", 95)
        .with_family("Unix-like")
        .with_generation("5.15.0");
    os.add_cpe("cpe:/o:linux:linux_kernel:5.15.0");
    host.set_os(os);

    host.add_rtt(Duration::from_micros(1_200));
    host.add_rtt(Duration::from_micros(1_800));
    host.add_rtt(Duration::from_micros(3_000));

    // Added out of ascending order, so the document's ordering guarantee is
    // being tested rather than inherited from how the fixture was written.
    host.add_port(https_port());
    host.add_port(ssh_port());
    host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));

    host
}

/// A port carrying a service identification, discovery telemetry, and script
/// output including a value JSON cannot express.
fn ssh_port() -> Port {
    let service = Service::new("ssh", 100)
        .with_product("OpenSSH")
        .with_vendor("OpenBSD")
        .with_version("8.9p1")
        .add_cpe("cpe:/a:openbsd:openssh:8.9p1");

    let discovery = Discovery::new(ScanResponse::TcpSynAck)
        .with_rtt(Duration::from_micros(1_450))
        .with_ttl(64)
        .with_source_ip(ip(50));

    Port::new(22, Protocol::Tcp, PortState::Open)
        .with_service(service)
        .with_discovery(discovery)
}

/// A port carrying a certificate, whose subject names a machine.
fn https_port() -> Port {
    let certificate = CertificateInfo::new(
        "router.local",
        vec!["www.router.local".to_string()],
        "Local CA",
        std::time::UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        std::time::UNIX_EPOCH + Duration::from_secs(1_798_761_600),
        "ECDSA",
        256,
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    );

    let security = Security::new()
        .with_tls_version("TLSv1.3")
        .with_cipher_suite("TLS_AES_256_GCM_SHA384")
        .add_alpn("h2")
        .add_alpn("http/1.1")
        .with_certificate(certificate);

    Port::new(443, Protocol::Tcp, PortState::Open).with_security(security)
}

/// A host that answered nothing but is known to be there.
fn filtered_host() -> Host {
    let mut host = Host::new(ip(2));
    host.set_status(HostStatus::Filtered);
    host.add_reason(StatusReason::basic(StatusProtocol::TcpSyn));
    host.add_port(Port::new(445, Protocol::Tcp, PortState::Filtered));
    host
}

/// A host with nothing on it, which is what proves the document keeps a fixed
/// shape when there is nothing to put in it.
fn bare_host() -> Host {
    let mut host = Host::new(ip(9));
    host.set_status(HostStatus::Down);
    host
}

/// The counters a routed sweep that ran out of time would file.
fn probe_stats() -> ProbeStats {
    let mut found_at = [0u64; BUCKET_BOUNDS_MS.len() + 1];
    found_at[0] = 4;
    found_at[3] = 3;
    found_at[BUCKET_BOUNDS_MS.len()] = 2;

    ProbeStats {
        scanner: ScannerKind::Routed,
        targets: 256,
        stop_reason: StopReason::DeadlineExpired,
        elapsed: Duration::from_millis(412),
        sends_attempted: 512,
        sends_failed: 0,
        segments_seen: 271,
        segments_off_target: 3,
        replies_without_rtt: 2,
        hosts_found: 9,
        answered_on: [7, 2, 0, 0, 0, 0],
        answered_unattributed: 0,
        first_reply: Some(Duration::from_micros(900)),
        last_reply: Some(Duration::from_millis(405)),
        found_at,
        capture: Some(CaptureCounts {
            received: 271,
            dropped: 0,
            if_dropped: 0,
        }),
    }
}

/// A one-phase discovery report over three hosts, a failed strategy and one
/// instrumented scanner.
pub(crate) fn report() -> ScanReport {
    let (_session, ctx) = ScanSession::new();

    let mut targets = IpSet::new();
    targets.insert_range("192.168.0.0/24".parse().expect("a valid range"));

    let recorder = PhaseRecorder::start(
        ScanKind::Discovery,
        true,
        TargetScope::from_ip_set(&mut targets),
        &ZondConfig::default(),
    );

    ctx.record_failure(ScannerKind::Local, "raw socket unavailable".to_string());
    ctx.record_probe_stats(probe_stats());

    for host in [router(), filtered_host(), bare_host()] {
        ctx.store.insert(host.primary_ip(), host);
    }

    recorder.finish(&ctx)
}

// ---------------------------------------------------------------------------
// The hostile report
// ---------------------------------------------------------------------------

/// The string every attacker-controlled field of [`hostile`] is set to.
///
/// A scanned host chooses its own banner, its own certificate subject and its
/// own script output, and all three end up in a document somebody opens. This
/// carries one payload per format the engine writes: markup and quotes for HTML
/// and XML, a leading `=` for a spreadsheet, and a right-to-left override, which
/// reverses the text after it so one address can be made to read as another.
///
/// Deliberately one string rather than one per field. A test asserting that this
/// never survives intact does not have to know which field it came from, which
/// is what lets it cover fields nobody has written yet.
pub(crate) const HOSTILE: &str = "=<script>alert(\"x\")</script>&'\u{202e}";

/// A host on the hostile fixture's network.
fn hostile_host() -> Host {
    let mut host = Host::new(ip(3));
    host.set_hostname(Some(HOSTILE.to_string()));
    host.set_status(HostStatus::Up);
    host.add_reason(StatusReason::new(StatusProtocol::Arp, HOSTILE));
    host.set_mac(MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x01));
    // The one role anything assigns, carried here so the corpus still exercises
    // a non-empty `roles` array through every exporter.
    host.add_network_role(NetworkRole::Tarpit);

    let mut os = OsFingerprint::new(HOSTILE, 90)
        .with_family(HOSTILE)
        .with_generation(HOSTILE);
    os.add_cpe(HOSTILE);
    host.set_os(os);
    host.add_rtt(Duration::from_micros(1_000));

    host.add_port(hostile_port());
    host
}

/// A port whose every describable string is hostile.
fn hostile_port() -> Port {
    let service = Service::new(HOSTILE, 100)
        .with_product(HOSTILE)
        .with_vendor(HOSTILE)
        .with_version(HOSTILE)
        .add_cpe(HOSTILE);

    let certificate = CertificateInfo::new(
        HOSTILE,
        vec![HOSTILE.to_string()],
        HOSTILE,
        std::time::UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        std::time::UNIX_EPOCH + Duration::from_secs(1_798_761_600),
        HOSTILE,
        256,
        HOSTILE,
    );

    let security = Security::new()
        .with_tls_version(HOSTILE)
        .with_cipher_suite(HOSTILE)
        .add_alpn(HOSTILE)
        .with_certificate(certificate);

    Port::new(8443, Protocol::Tcp, PortState::Open)
        .with_service(service)
        .with_security(security)
        .with_discovery(Discovery::new(ScanResponse::TcpSynAck).with_source_ip(ip(50)))
}

/// A report whose every attacker-controlled string is [`HOSTILE`].
///
/// The same shape as [`report`], so a writer that handles one handles the other.
/// What it is for is the question the per-field tests cannot answer: not "does
/// the escaper work" but "does every field go through it".
pub(crate) fn hostile() -> ScanReport {
    let (_session, ctx) = ScanSession::new();

    let mut targets = IpSet::new();
    targets.insert_range("192.168.0.0/24".parse().expect("a valid range"));

    let recorder = PhaseRecorder::start(
        ScanKind::Discovery,
        true,
        TargetScope::from_ip_set(&mut targets),
        &ZondConfig::default(),
    );

    ctx.record_failure(ScannerKind::Local, HOSTILE.to_string());
    ctx.record_probe_stats(probe_stats());
    ctx.store.insert(ip(3), hostile_host());

    recorder.finish(&ctx)
}
