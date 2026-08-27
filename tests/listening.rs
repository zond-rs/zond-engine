// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The listening phase, driven against a segment a test speaks on.
//!
//! Tier 2, alongside `lan_discovery`: no interface, no capture, no privileges.
//! [`PassiveListener::from_parts`] takes the receiving half of a frame stream
//! and reads whatever is pushed onto the other end as though it had been
//! captured — the listening counterpart of `EthernetHandle::from_parts`, and
//! with no sending half to supply, because a listener never transmits.
//!
//! ## What belongs here rather than beside the strategy
//!
//! The unit tests in `scanner::strategy::passive` hand frames straight to the
//! reader, one at a time, and assert on what each one proves. That is the right
//! shape for the reading rules and the wrong shape for everything around them:
//! it never runs the loop, never opens a journal, and never crosses the crate
//! boundary a consumer has to cross.
//!
//! So this covers what only a whole run can show — that the seam works from
//! outside, that the loop ends when the segment does, and that a watch resumed
//! from a record on disk is one watch rather than two.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use pnet_base::MacAddr;
use pnet_packet::ethernet::EtherTypes;
use tokio::sync::mpsc;

use zond_engine::journal::manifest::Plan;
use zond_engine::journal::store::Journal;
use zond_engine::model::ip::scoped::Zone;
use zond_engine::model::ip::set::IpSet;
use zond_engine::protocols::{craft, ethernet, tcp};
use zond_engine::scanner::report::ScanKind;
use zond_engine::scanner::session::{ScanContext, ScanSession};
use zond_engine::scanner::strategy::passive::{OnLink, PassiveListener, Recording};
use zond_engine::transport::capture::CapturedFrame;
use zond_engine::transport::frame::LinkType;
use zond_engine::transport::mac::IntoCoreMac;

/// The one machine every test here listens for, and the link it is heard on.
const MACHINE: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xAA);
const PEER: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xBB);

/// The segment being listened to, which every address below is on.
const SEGMENT: &str = "10.0.0.0/24";

fn zone() -> Zone {
    Zone::new(7, "sim0")
}

/// A listener that knows what its link carries, so an address on the segment is
/// one of its own machines rather than traffic merely crossing it.
fn on_link() -> OnLink {
    let mut ranges = IpSet::new();
    ranges.insert_range(SEGMENT.parse().expect("a valid range"));
    OnLink::of(ranges)
}

/// A TCP segment as a mirror port sees one, from `mac` at `from:sport`.
fn tcp_frame(mac: MacAddr, from: Ipv4Addr, sport: u16, dport: u16, flags: u8) -> CapturedFrame {
    let datagram = craft::Packet::new()
        .push(craft::Ipv4::new(from, Ipv4Addr::new(10, 0, 0, 9)))
        .push(craft::Tcp::new(sport, dport).with_flags(flags))
        .build()
        .expect("a test datagram");

    CapturedFrame {
        zone: zone(),
        link: LinkType::Ethernet,
        bytes: [
            ethernet::create_header(mac, PEER, EtherTypes::Ipv4),
            datagram,
        ]
        .concat(),
        observed_at: SystemTime::UNIX_EPOCH,
    }
}

/// The server's half of a handshake, which is the only thing that establishes a
/// listening port.
fn served(mac: MacAddr, from: Ipv4Addr, port: u16) -> CapturedFrame {
    tcp_frame(mac, from, port, 51234, tcp::flags::SYN | tcp::flags::ACK)
}

/// Runs a watch over `frames` to its end, and hands back what it concluded.
///
/// The segment is closed once everything has been pushed, which the loop reads
/// as the capture having ended — the run's own end rather than a fault, and
/// what makes these tests finish in microseconds without a timer or an abort.
async fn watch(ctx: &ScanContext, frames: Vec<CapturedFrame>) {
    let (tx, rx) = mpsc::channel(64);
    for frame in frames {
        tx.send(frame).await.expect("the listener is reading");
    }
    drop(tx);

    PassiveListener::from_parts(rx, on_link(), Recording::Everything, ctx.clone())
        .observe()
        .await
        .expect("the watch runs to its end");
}

/// A scratch journal root, emptied first so a re-run starts clean.
fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("zond-listening-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("a scratch root");
    root
}

/// Opens a record of a watch of one link.
fn record_of_a_watch(root: &Path, privileged: bool) -> Journal {
    Journal::create(root, &Plan::listen(vec![zone()]), privileged, "sim0")
        .expect("a journal is created")
}

/// The whole of a watch: frames arrive on a link, the loop reads them, and what
/// they prove is on the record when it stops.
///
/// The unit tests hand frames to the reader directly. This is the only thing
/// that runs the loop the reader sits inside, and the only thing that reaches
/// the listener the way a consumer of this crate has to — through
/// `from_parts`, from outside.
#[tokio::test]
async fn a_watch_reads_its_segment_and_stops_when_the_segment_does() {
    let (session, ctx) = ScanSession::new();

    watch(
        &ctx,
        vec![
            served(MACHINE, Ipv4Addr::new(10, 0, 0, 5), 443),
            served(MACHINE, Ipv4Addr::new(10, 0, 0, 5), 22),
        ],
    )
    .await;

    let hosts = ctx.hosts_snapshot();
    assert_eq!(hosts.len(), 1, "one machine spoke: {hosts:#?}");

    let mut open: Vec<u16> = hosts[0]
        .ports()
        .map(zond_engine::model::port::Port::number)
        .collect();
    open.sort_unstable();
    assert_eq!(open, vec![22, 443], "both endpoints were overheard serving");

    assert!(
        !session.handle().should_stop(),
        "the segment ended; nobody asked the watch to stop"
    );
}

/// A watch resumed from its record is one watch, not one per sitting.
///
/// This is the failure the whole feature exists to prevent, at the level it
/// actually happens: a sitting keys each machine by the first address it hears
/// it at, so a second sitting that begins knowing nothing re-keys everything it
/// hears. The laptop recorded last night under `10.0.0.5` and heard tonight
/// from `10.0.0.6` becomes a second record, and a listener left up for a week
/// across three restarts reports one machine as four — which is exactly what
/// resuming was supposed to stop.
///
/// Through a real journal on disk rather than a seeded store, because the chain
/// is the point: what one sitting wrote, what `reopen` reads back, and what the
/// next listener does with it.
#[tokio::test]
async fn a_watch_resumed_from_its_record_is_one_watch() {
    let root = scratch("resume");
    let first = Ipv4Addr::new(10, 0, 0, 5);
    let second = Ipv4Addr::new(10, 0, 0, 6);

    // Last night: the machine is heard at one of its addresses and written down.
    let mut journal = record_of_a_watch(&root, false);
    let directory = journal.directory().to_path_buf();

    let (_session, ctx) = ScanSession::new();
    watch(&ctx, vec![served(MACHINE, first, 443)]).await;
    journal
        .record_hosts(&ctx.hosts_snapshot())
        .expect("the sitting is written down");
    journal.close().expect("and the record released");

    // Tonight: the same machine, heard first at its *other* address. Which
    // address that is depends only on which frame happened to arrive first, so
    // it is the ordinary case rather than a corner.
    let (journal, _checkpoint, plan) = Journal::reopen(&directory, false).expect("it reopens");
    assert_eq!(plan.kind(), ScanKind::Listen, "the record knows its phase");
    assert_eq!(
        journal.restored().len(),
        1,
        "last night's machine came back"
    );

    let (_session, ctx) = ScanSession::new();
    ctx.restore_hosts(journal.restored());
    watch(&ctx, vec![served(MACHINE, second, 22)]).await;

    let hosts = ctx.hosts_snapshot();
    assert_eq!(
        hosts.len(),
        1,
        "one machine across two sittings, not one per sitting: {hosts:#?}"
    );
    assert!(
        hosts[0].ips().contains(&IpAddr::V4(first)) && hosts[0].ips().contains(&IpAddr::V4(second)),
        "tonight's address joined last night's record: {:?}",
        hosts[0].ips()
    );

    let mut open: Vec<u16> = hosts[0]
        .ports()
        .map(zond_engine::model::port::Port::number)
        .collect();
    open.sort_unstable();
    assert_eq!(
        open,
        vec![22, 443],
        "and both sittings' endpoints are on it rather than one being stranded"
    );
}

/// A watch resumes whether or not the second sitting runs as root.
///
/// The journal refuses a plan that moved, and privilege is part of what moves
/// it — for the two phases that probe, where a raw SYN and a connect attempt
/// ask different questions of the same port. A listener has no such pair: it
/// opened a capture or it did nothing, and it enumerated nothing either way.
///
/// This is not a corner either. Capturing without root is how most people
/// capture: `access_bpf` on macOS, `cap_net_raw` on Linux. A first sitting under
/// one and a second under `sudo` is an ordinary week, and it used to be refused
/// with a message about recorded positions a watch does not have.
#[tokio::test]
async fn a_watch_resumes_across_a_change_of_privilege() {
    let root = scratch("privilege");

    let journal = record_of_a_watch(&root, false);
    let directory = journal.directory().to_path_buf();
    journal.close().expect("the record is released");

    Journal::reopen(&directory, true)
        .expect("the same watch, this time under sudo, continues the same record");
}

/// A machine heard from off the link keeps its distance from the router that
/// forwarded it, across a resume as well as within a sitting.
///
/// The pairing a resumed watch is seeded with reads a hardware address off every
/// restored host. A host heard through a router deliberately carries none — the
/// address on that frame belonged to the last hop — so there is nothing to pair
/// it by, and inventing one would credit a machine somewhere else with the
/// router's hardware and every claim held against it.
#[tokio::test]
async fn a_restored_host_from_off_the_link_pairs_with_nothing() {
    let root = scratch("off-link");
    let elsewhere = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    let mut journal = record_of_a_watch(&root, false);
    let directory = journal.directory().to_path_buf();

    // A watch under the wide scope records what crosses the link as well, and
    // records no hardware address for it.
    let (_session, ctx) = ScanSession::new();
    watch(
        &ctx,
        vec![served(PEER, Ipv4Addr::new(93, 184, 216, 34), 443)],
    )
    .await;
    let recorded = ctx.hosts_snapshot();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].primary_ip(), elsewhere);
    assert!(
        recorded[0].mac().is_none(),
        "a frame from off the link carries the last hop's hardware, not the sender's"
    );

    journal.record_hosts(&recorded).expect("written down");
    journal.close().expect("released");

    // Reopened, and the machine on the link speaks for itself. It must get a
    // record of its own rather than joining the one from off the link.
    let (journal, _checkpoint, _plan) = Journal::reopen(&directory, false).expect("it reopens");
    let (_session, ctx) = ScanSession::new();
    ctx.restore_hosts(journal.restored());

    watch(&ctx, vec![served(MACHINE, Ipv4Addr::new(10, 0, 0, 5), 22)]).await;

    let hosts = ctx.hosts_snapshot();
    assert_eq!(
        hosts.len(),
        2,
        "two machines, one on this link and one somewhere else: {hosts:#?}"
    );
    let on_this_link = hosts
        .iter()
        .find(|host| host.primary_ip() == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
        .expect("the machine on the link has its own record");
    assert!(
        !on_this_link.ips().contains(&elsewhere),
        "and it did not absorb the one that was merely passing through"
    );
}

/// Nothing heard is not a failure, and it is not a claim about anybody either.
///
/// A watch over a silent link is the ordinary case on a segment where probing
/// is forbidden, which is what this phase is for. It has to end cleanly with an
/// empty record — never with an error, and never with a host it inferred from
/// having heard nothing, which is the one conclusion a listener may never draw.
#[tokio::test]
async fn a_silent_link_records_nobody_and_is_not_a_failure() {
    let (_session, ctx) = ScanSession::new();

    watch(&ctx, Vec::new()).await;

    assert_eq!(ctx.host_count(), 0, "silence names nobody");
    assert!(
        ctx.failures_snapshot().is_empty(),
        "and a quiet link is not a fault"
    );
}

/// A machine heard on the link is one this listener would still credit with its
/// hardware address, which is what pairs it across sittings.
///
/// Guards the seam rather than the reader: `from_parts` builds a listener with
/// the ranges a caller states, and a listener that lost them would record the
/// on-link machine as though it were off-link — no hardware address, no
/// pairing, and a fresh record every sitting.
#[tokio::test]
async fn a_listener_built_from_parts_keeps_the_link_addressing_it_was_given() {
    let (_session, ctx) = ScanSession::new();

    watch(&ctx, vec![served(MACHINE, Ipv4Addr::new(10, 0, 0, 5), 22)]).await;

    let hosts = ctx.hosts_snapshot();
    assert_eq!(
        hosts[0].mac(),
        Some(MACHINE.into_core()),
        "an address inside {SEGMENT} is one this link could have sourced itself"
    );
}
