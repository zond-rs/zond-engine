// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Forward name resolution
//!
//! Turns the names a person writes — `example.com`, `raspberrypi.local`, `nas`
//! — into the addresses a scan can probe. This is the half of resolution that
//! runs *before* a scan, deciding what it will cover; the reverse half, which
//! attaches names to hosts a scan has already found, lives in
//! [`crate::scanner::resolver`] and answers the opposite question.
//!
//! ## Three kinds of name, one entry point
//!
//! [`Resolver::resolve`] routes a name by how it is resolved, not by asking the
//! caller to know:
//!
//! - A `.local` name is a multicast name (RFC 6762): it is resolved by asking
//!   the link over multicast DNS, not by asking a unicast server. A unicast
//!   lookup of one fails everywhere the host has no mDNS-aware resolver — which
//!   on Linux is the common case — so the engine speaks mDNS itself rather than
//!   hope the system does.
//! - Any other name goes to the system's unicast resolver, which applies the
//!   host's own search domains and returns A and AAAA records alike.
//! - A single-label name (`nas`) is tried unicast first, and if nothing answers
//!   and mDNS is enabled, again as `nas.local` — which on a home network is
//!   often what the author meant by it.
//!
//! ## Why a resolver, and not just the hook
//!
//! [`crate::model::parse`] already has the seam a name passes through: a
//! [`HostLookup`](crate::model::parse::target::HostLookup) supplied in a
//! [`TargetContext`](crate::model::parse::target::TargetContext). What it does
//! not have is anything to fill it with, because resolving a name means speaking
//! DNS and mDNS, which a target grammar must not do on its own behalf. This
//! module is what fills it, and it does so without the parse layer learning
//! anything about DNS: the engine resolves the names and hands the answers in.
//!
//! ## The synchronous seam, and the two passes
//!
//! That hook is synchronous — it is called once per name while a target
//! expression is parsed — and resolution is asynchronous and slow, mDNS
//! especially so. Blocking inside the hook would turn a file of two hundred
//! names into two hundred sequential round trips. So resolution is done in two
//! passes, and this module ships both rather than describing them:
//!
//! 1. [`resolve_names`] finds every name in a set of target expressions and
//!    resolves them concurrently into a map.
//! 2. [`to_target_map`] and [`to_set`] then build with a hook that reads the
//!    map, so the parse itself never waits on the network.
//!
//! A caller that only needs one name resolved can reach for [`Resolver::resolve`]
//! directly; a caller assembling a scan wants [`to_target_map`] or [`to_set`],
//! which do the whole of it.
//!
//! ## What it does not decide
//!
//! Whether a scan is *allowed* to resolve at all — the meaning of
//! [`ZondConfig::no_dns`](crate::config::ZondConfig::no_dns) at request time — is
//! the caller's policy, not this module's: a resolver that refused to run would
//! be a strange thing to hold. A front end that must not emit DNS supplies no
//! resolver, and the parse layer then refuses a name with
//! [`NoHostLookup`](crate::model::parse::target::TargetParseError::NoHostLookup)
//! rather than covering less than its input said.

mod mdns;
mod targets;

pub use targets::{resolve_names, to_set, to_target_map};

use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::TokioResolver;

use crate::warn;

/// The default mDNS reply window. See [`ResolveConfig::mdns_timeout`] for why it
/// is a whole second.
const DEFAULT_MDNS_TIMEOUT: Duration = Duration::from_secs(1);

/// How a [`Resolver`] behaves, independent of the host it reads its unicast
/// configuration from.
#[derive(Debug, Clone, Copy)]
pub struct ResolveConfig {
    /// Whether `.local` names are resolved over multicast, and whether a
    /// single-label name falls back to one.
    ///
    /// Off leaves a `.local` name unresolved rather than silently sending it to
    /// a unicast server that will answer NXDOMAIN for it. For an environment
    /// where multicast is filtered or unwanted, or where the only names in play
    /// are global.
    pub mdns: bool,

    /// How long to listen for mDNS replies before accepting that a `.local`
    /// name has no answer on the segment.
    ///
    /// A responder may defer a reply by up to half a second to aggregate
    /// answers (RFC 6762 §6.3), and one on a busy or sleepy device can take
    /// longer, so the default is a whole second: short enough not to stall a
    /// scan, long enough that a device answering slowly is found rather than
    /// declared absent.
    pub mdns_timeout: Duration,
}

impl Default for ResolveConfig {
    fn default() -> Self {
        Self {
            mdns: true,
            mdns_timeout: DEFAULT_MDNS_TIMEOUT,
        }
    }
}

/// Resolves names to addresses over unicast DNS and multicast DNS.
///
/// Cheap to clone — the unicast resolver it holds is reference-counted — so it
/// can be shared across the concurrent lookups [`resolve_names`] runs.
#[derive(Clone)]
pub struct Resolver {
    /// The system unicast resolver, or `None` when the host's resolver
    /// configuration could not be read. A resolver with no unicast half still
    /// answers `.local` names; it simply has nothing to ask for the rest.
    unicast: Option<TokioResolver>,
    config: ResolveConfig,
}

impl Resolver {
    /// Builds a resolver from the host's own unicast configuration, with mDNS
    /// enabled.
    ///
    /// Reading the resolver configuration can fail — a container with no
    /// `resolv.conf`, say — and that is not fatal: the resolver is returned with
    /// no unicast half, so `.local` names still resolve while global names come
    /// back empty. The failure is logged rather than raised, because a scan that
    /// resolves fewer names is still a scan.
    pub fn from_system() -> Self {
        Self::with_config(ResolveConfig::default())
    }

    /// Builds a resolver with an explicit [`ResolveConfig`].
    pub fn with_config(config: ResolveConfig) -> Self {
        Self {
            unicast: build_unicast(),
            config,
        }
    }

    /// Resolves one name to every address it stands for, in first-seen order.
    ///
    /// An empty result means nothing answered for the name — which a caller
    /// treats the same as a name that resolved to nothing, since both are a
    /// target that is simply not there. Routing is by name: see the module
    /// documentation for how `.local`, global, and single-label names differ.
    pub async fn resolve(&self, name: &str) -> Vec<IpAddr> {
        let name = name.trim_end_matches('.');

        if is_multicast_local(name) {
            return self.resolve_mdns(name).await;
        }

        let unicast = self.resolve_unicast(name).await;
        if !unicast.is_empty() || !is_single_label(name) {
            return unicast;
        }

        // A bare `nas` that unicast could not place is, on a home or office
        // segment, most often `nas.local`. Tried only after unicast so a real
        // search-domain match is never shadowed by a multicast one.
        self.resolve_mdns(&format!("{name}.local")).await
    }

    /// The unicast half: A and AAAA through the system resolver, or nothing when
    /// there is no resolver or the name has no records.
    async fn resolve_unicast(&self, name: &str) -> Vec<IpAddr> {
        let Some(resolver) = &self.unicast else {
            return Vec::new();
        };

        match resolver.lookup_ip(name).await {
            Ok(lookup) => lookup.iter().collect(),
            // A name with no records is an ordinary answer, not a failure worth
            // surfacing: it resolves to nothing, which is what an empty vector
            // says.
            Err(_) => Vec::new(),
        }
    }

    /// The multicast half, honouring the config's mDNS switch.
    async fn resolve_mdns(&self, name: &str) -> Vec<IpAddr> {
        if !self.config.mdns {
            return Vec::new();
        }
        mdns::resolve(name, self.config.mdns_timeout).await
    }
}

/// Builds the system unicast resolver, logging and swallowing the two failures
/// that leave a host unable to resolve global names.
fn build_unicast() -> Option<TokioResolver> {
    let Ok(builder) = TokioResolver::builder_tokio() else {
        warn!("no system resolver configuration found; global names will not resolve");
        return None;
    };
    let Ok(resolver) = builder.build() else {
        warn!("could not build the system resolver; global names will not resolve");
        return None;
    };
    Some(resolver)
}

/// Whether `name` is resolved over multicast: a multi-label name whose last
/// label is `local`.
///
/// A bare `local` is not one — it is a single-label name that the fallback path
/// may try as `local.local`, not a `.local` host in its own right.
fn is_multicast_local(name: &str) -> bool {
    name.contains('.')
        && name
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.eq_ignore_ascii_case("local"))
}

/// Whether `name` is a single label, and so a candidate for the `.local`
/// fallback once unicast has had its say.
fn is_single_label(name: &str) -> bool {
    !name.is_empty() && !name.contains('.')
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

    /// The routing predicate decides which protocol a name is resolved by, so a
    /// misclassification sends a `.local` host to a unicast server that cannot
    /// answer for it, or a global name to a multicast group that will not.
    #[test]
    fn only_a_dotted_local_name_is_a_multicast_name() {
        assert!(is_multicast_local("raspberrypi.local"));
        assert!(is_multicast_local("Printer.LOCAL"));
        assert!(is_multicast_local("host.sub.local"));

        assert!(!is_multicast_local("example.com"));
        assert!(!is_multicast_local("localhost"));
        // A bare `local` has no host part; it is a short name, not a `.local`
        // one.
        assert!(!is_multicast_local("local"));
    }

    #[test]
    fn a_single_label_is_a_fallback_candidate_and_a_dotted_name_is_not() {
        assert!(is_single_label("nas"));
        assert!(!is_single_label("nas.local"));
        assert!(!is_single_label("example.com"));
        assert!(!is_single_label(""));
    }
}
