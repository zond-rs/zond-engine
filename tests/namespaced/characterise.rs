// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What kind of filter sits in front of a host, read off a real one.
//!
//! `characterise` sends deliberately shaped probes and concludes from what
//! comes back: a segment judged by where it sits in a connection means a
//! stateful filter, one judged by the port it claims to come from means an ACL
//! trusting that claim. Both conclusions are about a firewall's behaviour, so
//! neither can be established against a simulation that was told what to
//! answer. `nftables` in the peer's namespace is a filter that was told a rule
//! and works out the rest itself.
//!
//! This is the least covered file in the crate at 18.3%, and it was not
//! reachable before this tier existed.
//!
//! Both of these were written as claims that failed, and both were failing for
//! the same reason: the diagnostic probes never left, because the engine could
//! find no interface to send from. See `netns::mount_fresh_sysfs` for why.
//! Every rule here carries a `counter`, so `nft list ruleset` in the peer's
//! namespace says what arrived if one starts failing again.

use crate::netns::{Segment, available};
use crate::support::{run_scan, target_map, test_config};
use zond_engine::model::host::Filtering;
use zond_engine::model::port::PortState;

/// The source port `characterise` tries when it asks whether an ACL trusts one.
const TRUSTED_SOURCE_PORT: u16 = 53;

/// A filter that admits an ACK where it dropped a SYN is named stateful.
#[tokio::test]
async fn a_filter_that_judges_by_connection_state_is_named_stateful() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.closed_tcp_port();
    segment.drop_new_connections_to(port);

    let mut cfg = test_config();
    cfg.characterise = true;
    let outcome = run_scan(target_map(segment.peer(), &port.to_string()), &cfg).await;

    let host = outcome.host(segment.peer()).expect("the peer answers");
    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Filtered),
        "the SYN is dropped, so the port itself reads Filtered"
    );
    assert!(
        host.filtering().contains(&Filtering::StatefulFilter),
        "an ACK admitted where a SYN was dropped is a stateful filter, but the \
         conclusions were {:?}",
        host.filtering()
    );
}

/// A filter that admits a SYN from one source port is named a port-trusting ACL.
#[tokio::test]
async fn a_filter_that_judges_by_source_port_is_named_an_acl() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.closed_tcp_port();
    segment.trust_source_port_to(port, TRUSTED_SOURCE_PORT);

    let mut cfg = test_config();
    cfg.characterise = true;
    let outcome = run_scan(target_map(segment.peer(), &port.to_string()), &cfg).await;

    let host = outcome.host(segment.peer()).expect("the peer answers");
    assert!(
        host.filtering().contains(&Filtering::PortTrustingAcl),
        "a SYN admitted only from port {TRUSTED_SOURCE_PORT} is an ACL trusting \
         that claim, but the conclusions were {:?}",
        host.filtering()
    );
}
