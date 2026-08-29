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
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::config::{IdleScan, ZondConfig};
use crate::evasion::EvasionProfile;
use crate::model::capture::CaptureCounts;
use crate::model::confidence::Confidence;
use crate::model::exclusion::Exclusions;
use crate::model::finding::{
    DetectionClass, DetectionId, Excerpt, Finding, Reference, Severity, Version,
};
use crate::model::host::{
    Filtering, Hop, Host, HostStatus, NetworkRole, OsFingerprint, StatusProtocol, StatusReason,
};
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::port::{
    CertificateInfo, Discovery, Port, PortState, Protocol, ScanResponse, Security, Service,
};
use crate::protocols::tcp::flags;
use crate::report::ScannerKind;
use crate::report::WindowSummary;
use crate::report::{
    Attachment, AttachmentSource, BUCKET_BOUNDS_MS, ProbeStats, ScanKind, ScanReport, StopReason,
    TargetScope,
};
use crate::scanner::recorder::PhaseRecorder;
use crate::scanner::session::ScanSession;

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
    host.record_mac(MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3));

    let mut os = OsFingerprint::new("Linux", 95)
        .with_family("Unix-like")
        // Both axes populated at once, which is the case a consumer has to
        // handle and the one a fixture is most likely to leave out: a Linux
        // print server is what it runs *and* what it is.
        .with_device("Printer")
        .with_generation("5.15.0")
        // Shaped like what the stack fingerprinter renders, so the full-report
        // document exercises a populated evidence line rather than a null.
        .with_evidence("syn-ack hops>=64 opts=M,S,T,N,W win=65160=45x1448 ws=7 mss=1460");
    os.add_cpe("cpe:/o:linux:linux_kernel:5.15.0");
    host.set_os(os);

    host.add_rtt(Duration::from_micros(1_200));
    host.add_rtt(Duration::from_micros(1_800));
    host.add_rtt(Duration::from_micros(3_000));

    // Every shape a path can hold, so the document exercises all three rather
    // than the one a healthy trace produces: a measured hop, a router that
    // would not identify itself, and a hop inherited from another host's trace.
    // Recorded out of order for the same reason the ports below are.
    host.record_hop(Hop::answered(
        3,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        Some(Duration::from_micros(4_100)),
    ));
    host.record_hop(Hop::silent(2));
    host.record_hop(
        Hop::answered(1, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 254)), None).as_inferred(),
    );

    // Added out of ascending order, so the document's ordering guarantee is
    // being tested rather than inherited from how the fixture was written.
    host.add_port(https_port());
    host.add_port(ssh_port());
    host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));

    // The characterise pass drew every filtering conclusion for this host, so
    // the exported document carries them and the schema is held to each.
    host.add_filtering(Filtering::InlineMiddlebox);
    host.add_filtering(Filtering::StatefulFilter);
    host.add_filtering(Filtering::PortTrustingAcl);
    host.add_filtering(Filtering::StatelessFilter);

    host
}

/// A port carrying a service identification, discovery telemetry, and script
/// output including a value JSON cannot express.
fn ssh_port() -> Port {
    let service = Service::new("ssh", 100)
        .with_product("OpenSSH")
        .with_vendor("OpenBSD")
        .with_version("8.9p1")
        .with_cpe("cpe:/a:openbsd:openssh:8.9p1");

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
        "Local CA",
        std::time::UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        std::time::UNIX_EPOCH + Duration::from_secs(1_798_761_600),
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    )
    .with_sans([Arc::from("www.router.local")])
    .with_public_key("ECDSA", 256);

    let security = Security::new()
        .with_tls_version("TLSv1.3")
        .with_cipher_suite("TLS_AES_256_GCM_SHA384")
        .with_alpn("h2")
        .with_alpn("http/1.1")
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
        // A paced scanner, cut back twice and still short of its ceiling: what a
        // consumer has to be able to read to know the silence in this fixture is
        // a scan's limit rather than a firewall.
        window: Some(WindowSummary {
            capacity: 48,
            peak: 256,
            reductions: 2,
            adaptive: true,
            at_floor: false,
        }),
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

    // Half the range withheld by policy, so the exported scope carries an
    // exclusion that overlapped rather than one that did nothing. Every host
    // below sits in the half that was kept.
    let mut excluded = IpSet::new();
    excluded.insert_range("192.168.0.128/25".parse().expect("a valid range"));

    // This phase evaded something, so the exported document carries an evasion
    // record and every writer — and the published schema — is held to what one
    // looks like. The port-scan phase below keeps the defaults, so the fixture
    // exercises a phase that recorded evasion beside one that did not.
    let config = ZondConfig {
        evasion: EvasionProfile::default()
            .with_source_port(53)
            .with_ttl(40)
            .with_padding(24)
            .with_bad_tcp_checksum(true)
            .with_spoof_mac(MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01))
            .with_fragment(28)
            .with_decoys(vec![
                "192.0.2.61".parse().expect("a valid decoy address"),
                "192.0.2.62".parse().expect("a valid decoy address"),
            ])
            .with_flags(flags::SYN | flags::FIN),
        // For the schema rather than for plausibility: a phase carries the
        // idle-scan record beside the evasion one, so both serialized forms are
        // exercised.
        idle_scan: Some(IdleScan {
            zombie: "192.0.2.9".parse().expect("a valid zombie address"),
            zombie_port: Some(113),
        }),
        ..Default::default()
    };

    let recorder = PhaseRecorder::start(
        ScanKind::Discovery,
        true,
        TargetScope::from_ip_set(&mut targets, &Exclusions::new(excluded)),
        &config,
    );

    ctx.record_failure(ScannerKind::Local, "raw socket unavailable".to_string());
    ctx.record_probe_stats(probe_stats());
    // A sweep covers the link it ran on as well as the addresses it was handed,
    // so the exported scope carries one — otherwise every test of that field
    // compares an empty list with an empty list.
    ctx.record_sweep(Zone::new(3, "en0"));

    // A managed switch's announcement, so the exported document carries an
    // attachment and every writer — and the published schema — is held to what
    // one looks like. Recorded through the context rather than assembled into
    // the phase directly, so the path a real announcement takes is the path
    // under test.
    ctx.record_attachment(
        Attachment::new(
            Zone::new(3, "en0"),
            AttachmentSource::Lldp,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_772_000_000),
        )
        .with_device_mac(MacAddr::new(0x00, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F))
        .with_device_name("core-sw-02")
        .with_port("GigabitEthernet1/0/14")
        .with_native_vlan(40)
        .with_management_address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
    );

    for host in [router(), filtered_host(), bare_host()] {
        ctx.store.insert(host.scoped_ip(), host);
    }

    recorder.finish(&ctx)
}

// ---------------------------------------------------------------------------
// A network, and the same network later
// ---------------------------------------------------------------------------

/// The moment the earlier of the two comparison scans ran.
const BASELINE_AT: Duration = Duration::from_secs(1_780_000_000);

/// A day, for placing the fixtures apart.
const DAY: Duration = Duration::from_secs(86_400);

/// The port set both comparison scans walked, on every address.
const COMPARED_PORTS: &str = "22,80,443,8080,8443";

/// Two scans of one network, thirty-five days apart, differing in one of every
/// way a comparison can report.
///
/// Built for a schema rather than for plausibility: a host gone, a host arrived,
/// a port opened, a port shut, a service moved a version, a certificate rotated,
/// a certificate that nobody touched crossing its expiry threshold, an operating
/// system reidentified and a name resolved differently. A comparison of the two
/// therefore carries at least one change of nearly every kind, which is what
/// lets a test assert the whole document rather than the corner of it one change
/// happens to reach.
///
/// Both phases are port scans that state which ports they walked, because a
/// discovery sweep walks none — and against one of those every endpoint change
/// reads as ground nobody covered, which exercises the coverage rules rather
/// than the change vocabulary.
///
/// Times are fixed rather than taken from the clock. A certificate crossing a
/// threshold *between* two scans is only expressible if the two scans are a
/// known distance apart.
pub(crate) fn compared() -> (ScanReport, ScanReport) {
    (
        compared_phase(0, before_hosts()),
        compared_phase(35, after_hosts()),
    )
}

/// One side of [`compared`]: a port-scan phase `days` after the baseline,
/// stating the ports it walked.
fn compared_phase(days: u64, hosts: Vec<Host>) -> ScanReport {
    use crate::model::port::PortSet;
    use crate::model::target::{TargetMap, TargetSet};
    use crate::report::{PhaseParts, ScanPhase, ScanSettings};

    let mut targets = TargetMap::new();
    let mut addresses = IpSet::new();
    addresses.insert_range("192.168.0.0/25".parse().expect("a valid range"));
    targets.add_unit(TargetSet::new(
        addresses,
        PortSet::try_from(COMPARED_PORTS).expect("a valid port set"),
    ));

    let phase = ScanPhase::from_parts(PhaseParts {
        // No attachment: these two are a comparison of a network, and where the
        // machine measuring it was plugged in has nothing to do with what
        // changed between them.
        attachments: Vec::new(),
        kind: ScanKind::PortScan,
        started_at: std::time::UNIX_EPOCH + BASELINE_AT + DAY * days as u32,
        elapsed: Duration::from_secs(12),
        privileged: Some(true),
        targets: TargetScope::from_target_map(&mut targets, &Exclusions::none()),
        settings: ScanSettings::from(&ZondConfig::default()),
        failures: Vec::new(),
        unroutable: Vec::new(),
        probes: Vec::new(),
        origin: None,
    });

    ScanReport::recorded(crate::report::ENGINE_VERSION, vec![phase], hosts)
}

/// A certificate, by the two things that make one distinguishable.
fn certificate(fingerprint: &str, issuer: &str, ends: Duration) -> Security {
    Security::new()
        .with_tls_version("TLSv1.3")
        .with_cipher_suite("TLS_AES_256_GCM_SHA384")
        .with_certificate(CertificateInfo::new(
            "www.example.test",
            issuer,
            std::time::UNIX_EPOCH + BASELINE_AT - DAY * 90,
            std::time::UNIX_EPOCH + ends,
            fingerprint,
        ))
}

/// The gateway, whose every field moves between the two scans.
fn compared_router(later: bool) -> Host {
    let mut host = Host::new(ip(1));
    host.set_status(HostStatus::Up);
    host.add_reason(StatusReason::new(StatusProtocol::Arp, "reply from gateway"));
    host.record_mac(MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3));
    host.set_hostname(Some(
        if later {
            "gateway.local"
        } else {
            "router.local"
        }
        .to_string(),
    ));
    host.set_os(
        OsFingerprint::new("Linux", 95)
            .with_family("Unix-like")
            .with_generation(if later { "6.1.0" } else { "5.15.0" }),
    );

    // A finding the later scan draws and the baseline did not, so the comparison
    // carries `finding_appeared`.
    if later {
        host.add_finding(
            Finding::new(
                DetectionId::new("kev", Version::new(1, 0, 0), "seed")
                    .expect("a valid detection id"),
                "Known exploited vulnerability in the management interface",
                Severity::High,
                Confidence::Strong,
                DetectionClass::Passive,
            )
            .expect("a titled finding"),
        );
    }

    // One claim both scans make, graded higher by the later one, so the document
    // carries `finding_reassessed` as well.
    host.add_finding(
        Finding::new(
            DetectionId::new("tls-audit", Version::new(1, 0, 0), "seed")
                .expect("a valid detection id"),
            "Management interface accepts a deprecated TLS version",
            if later {
                Severity::High
            } else {
                Severity::Medium
            },
            Confidence::Strong,
            DetectionClass::Passive,
        )
        .expect("a titled finding"),
    );

    // A service that moved a version.
    host.add_port(
        Port::new(22, Protocol::Tcp, PortState::Open).with_service(
            Service::new("ssh", 100)
                .with_product("OpenSSH")
                .with_version(if later { "9.6p1" } else { "8.9p1" }),
        ),
    );

    // A port that shut.
    host.add_port(Port::new(
        80,
        Protocol::Tcp,
        if later {
            PortState::Closed
        } else {
            PortState::Open
        },
    ));

    // A certificate replaced by a different one.
    host.add_port(
        Port::new(443, Protocol::Tcp, PortState::Open).with_security(if later {
            certificate(
                "bbbb2b0b822cd15d6c15b0f00a089f86d081884c7d659a2feaa0c55ad015",
                "Public CA",
                BASELINE_AT + DAY * 400,
            )
        } else {
            certificate(
                "aaaa884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "Local CA",
                BASELINE_AT + DAY * 200,
            )
        }),
    );

    // A port that opened.
    if later {
        host.add_port(
            Port::new(8080, Protocol::Tcp, PortState::Open).with_service(
                Service::new("http-alt", 90)
                    .with_product("Caddy")
                    .with_version("2.7.6"),
            ),
        );
    }

    host
}

/// A host presenting the same certificate in both scans, which falls inside the
/// expiry threshold somewhere between them.
fn compared_expiring() -> Host {
    let mut host = Host::new(ip(4));
    host.set_status(HostStatus::Up);
    host.add_port(
        Port::new(8443, Protocol::Tcp, PortState::Open)
            // Sixty days of life at the baseline, twenty-five at the later scan:
            // outside a thirty-day threshold and then inside it, with nothing
            // about the certificate having moved.
            .with_security(certificate(
                "cccc7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "Local CA",
                BASELINE_AT + DAY * 60,
            )),
    );
    host
}

/// What the earlier scan found.
fn before_hosts() -> Vec<Host> {
    let mut gone = Host::new(ip(9));
    gone.set_status(HostStatus::Up);

    vec![compared_router(false), compared_expiring(), gone]
}

/// What the later scan found: the gateway changed, the expiring host untouched,
/// one host gone and one arrived.
fn after_hosts() -> Vec<Host> {
    let mut arrived = Host::new(ip(7));
    arrived.set_status(HostStatus::Up);
    arrived.add_reason(StatusReason::new(StatusProtocol::IcmpEcho, "echo reply"));
    arrived.add_port(Port::new(22, Protocol::Tcp, PortState::Open));

    vec![compared_router(true), compared_expiring(), arrived]
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
/// A finding whose every describable string is hostile, including a `url`
/// reference — the one reference kind that carries attacker-controlled text.
fn hostile_finding() -> Finding {
    Finding::new(
        DetectionId::new(HOSTILE, Version::new(1, 0, 0), HOSTILE).unwrap(),
        HOSTILE,
        Severity::Critical,
        Confidence::Certain,
        DetectionClass::Exploit,
    )
    .unwrap()
    .with_excerpt(Excerpt::new(HOSTILE))
    .with_reference(Reference::url(HOSTILE))
    .with_remediation(HOSTILE)
}

fn hostile_host() -> Host {
    let mut host = Host::new(ip(3));
    host.set_hostname(Some(HOSTILE.to_string()));
    host.set_status(HostStatus::Up);
    host.add_reason(StatusReason::new(StatusProtocol::Arp, HOSTILE));
    host.record_mac(MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x01));
    // The one role anything assigns, carried here so the corpus still exercises
    // a non-empty `roles` array through every exporter.
    host.add_network_role(NetworkRole::Tarpit);

    let mut os = OsFingerprint::new(HOSTILE, 90)
        .with_family(HOSTILE)
        .with_device(HOSTILE)
        .with_generation(HOSTILE)
        // Every string a report carries has to survive being written into JSON,
        // CSV, HTML and XML, and this one is no different for being meant for a
        // reader rather than a parser.
        .with_evidence(HOSTILE);
    os.add_cpe(HOSTILE);
    host.set_os(os);
    host.add_rtt(Duration::from_micros(1_000));

    host.add_finding(hostile_finding());
    host.add_port(hostile_port());
    host
}

/// A port whose every describable string is hostile.
fn hostile_port() -> Port {
    let service = Service::new(HOSTILE, 100)
        .with_product(HOSTILE)
        .with_vendor(HOSTILE)
        .with_version(HOSTILE)
        .with_cpe(HOSTILE);

    let certificate = CertificateInfo::new(
        HOSTILE,
        HOSTILE,
        std::time::UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        std::time::UNIX_EPOCH + Duration::from_secs(1_798_761_600),
        HOSTILE,
    )
    .with_sans([Arc::from(HOSTILE)])
    .with_public_key(HOSTILE, 256);

    let security = Security::new()
        .with_tls_version(HOSTILE)
        .with_cipher_suite(HOSTILE)
        .with_alpn(HOSTILE)
        .with_certificate(certificate);

    let mut port = Port::new(8443, Protocol::Tcp, PortState::Open)
        .with_service(service)
        .with_security(security)
        .with_discovery(Discovery::new(ScanResponse::TcpSynAck).with_source_ip(ip(50)));
    port.add_finding(hostile_finding());
    port
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
        TargetScope::from_ip_set(&mut targets, &Exclusions::none()),
        &ZondConfig::default(),
    );

    ctx.record_failure(ScannerKind::Local, HOSTILE.to_string());
    ctx.record_probe_stats(probe_stats());
    ctx.store.insert(
        crate::model::ip::scoped::ScopedIp::unscoped(ip(3)),
        hostile_host(),
    );

    recorder.finish(&ctx)
}
