// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Turning what a person wrote into links to listen on
//!
//! The counterpart to [`for_discovery`](super::for_discovery), for the phase
//! aimed at a **link**.
//!
//! A listener has no ranges, ports or hostnames, only wires this machine is on.
//! The vocabulary is small and is resolved against the interface table of the
//! machine the process runs on.
//!
//! Synchronous, unlike [`for_discovery`](super::for_discovery): nothing here
//! leaves the machine, since a link is looked up in a table the kernel already
//! holds.

use crate::system::interface::Link;

use crate::model::ip::scoped::Zone;
use crate::model::parse::ip::Keyword;
use crate::system::interface;

/// The sigil a target expression scopes an address with (`[fe80::1%en0]`),
/// accepted here so that `%en0` and `en0` name the same link.
const ZONE_SIGIL: char = '%';

/// Why a link expression named nothing to listen on.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// The expression was empty or nothing but whitespace.
    #[error("a link expression cannot be empty")]
    Empty,

    /// No interface on this machine goes by that name.
    ///
    /// Carries the interfaces this machine has, which is what a person needs to
    /// correct the expression.
    #[error("'{expression}' is not an interface on this machine (it has: {})", .available.join(", "))]
    Unknown {
        /// What the caller wrote.
        expression: String,
        /// The links that exist, by name.
        available: Vec<String>,
    },

    /// `lan` was written and this machine has no local segment to listen on.
    #[error("no local segment was found to listen on")]
    NoLan,

    /// Nothing was written and this machine has no interface that is up.
    #[error("this machine has no interface that is up, so there is nothing to listen to")]
    NoLinks,

    /// This machine's interface table could not be read, so no name could be
    /// looked up in it; see [`interfaces`](crate::system::interface::interfaces).
    #[error("this machine's interfaces could not be read: {source}")]
    Unreadable {
        /// What the read met.
        #[source]
        source: std::io::Error,
    },
}

/// Resolves link expressions into the links a listening phase reads.
///
/// The link counterpart of [`for_discovery`](super::for_discovery): it handles
/// the vocabulary, this host's interface table and the empty case in one call.
///
/// Four things may be written:
///
/// - **an interface name**, such as `en0`, `eth0` or `enp3s0`;
/// - **the same with the zone sigil**, so `%en0`, which is how an address names
///   its interface everywhere else in this engine;
/// - **`lan`**, the link a LAN scan would run on, which is the interface
///   carrying this host's default route;
/// - **nothing at all**, meaning every interface that is up.
///
/// A link named twice, or named once as `en0` and once as `%en0`, is one link.
///
/// # The empty case is every link
///
/// A listener given no links listens to every link this machine has up, which
/// is the commonest use of the phase.
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use zond_engine::{ListenScope, resolve};
///
/// // Every link that is up.
/// let scope = ListenScope::on(resolve::for_listening::<&str>(&[])?);
///
/// // Or one, by name.
/// let scope = ListenScope::on(resolve::for_listening(&["en0"])?);
/// # let _ = scope;
/// # Ok(())
/// # }
/// ```
pub fn for_listening<S: AsRef<str>>(exprs: &[S]) -> Result<Vec<Zone>, LinkError> {
    let links = crate::system::interface::interfaces()
        .map_err(|source| LinkError::Unreadable { source })?;
    for_listening_on(exprs, &links)
}

/// [`for_listening`], against a supplied interface table.
///
/// Makes the behaviour around `lan`, `%en0` and the empty case testable on a
/// machine that has none of them, as
/// [`for_discovery_with`](super::for_discovery_with) does for discovery. Every
/// branch, `lan` included, reads `interfaces` and nothing from the running
/// machine.
pub fn for_listening_on<S: AsRef<str>>(
    exprs: &[S],
    interfaces: &[Link],
) -> Result<Vec<Zone>, LinkError> {
    if exprs.is_empty() {
        let links: Vec<Zone> = interfaces
            .iter()
            .filter(|link| link.is_up())
            .map(Link::zone)
            .collect();

        return if links.is_empty() {
            Err(LinkError::NoLinks)
        } else {
            Ok(links)
        };
    }

    let mut links: Vec<Zone> = Vec::with_capacity(exprs.len());

    for expr in exprs {
        let written = expr.as_ref().trim();
        let name = written.strip_prefix(ZONE_SIGIL).unwrap_or(written);
        if name.is_empty() {
            return Err(LinkError::Empty);
        }

        let link = if Keyword::from_token(name) == Some(Keyword::Lan) {
            // `lan` is the link carrying the default route, so it is a routing
            // question, answered from the given table.
            interface::lan_link_with(interfaces.to_vec())
                .map(|lan| lan.link.zone())
                .ok_or(LinkError::NoLan)?
        } else {
            interfaces
                .iter()
                .find(|link| link.name() == name)
                .map(Link::zone)
                .ok_or_else(|| LinkError::Unknown {
                    expression: written.to_owned(),
                    available: interfaces
                        .iter()
                        .map(|link| link.name().to_owned())
                        .collect(),
                })?
        };

        // A link named twice is one link. Kept in the order written.
        if !links.contains(&link) {
            links.push(link);
        }
    }

    Ok(links)
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
    use crate::system::interface::Link;

    /// A made-up interface table, so the test does not depend on the machine.
    fn table() -> Vec<Link> {
        let up = |name: &str, index: u32, up: bool| Link::new(name, index).with_link_up(up);

        vec![
            up("en0", 4, true),
            up("en1", 5, true),
            up("awdl0", 9, false),
        ]
    }

    /// A link viable enough for `lan` to pick: up, physical, broadcast, with a
    /// MAC and a private address, and carrying the default route.
    fn lan_capable(name: &str, index: u32) -> Link {
        Link::new(name, index)
            .with_link_up(true)
            .with_physical(true)
            .with_addressing(crate::system::interface::Addressing::Broadcast)
            .with_kind(crate::system::interface::LinkKind::Wired)
            .with_mac(crate::model::mac::MacAddr::new(2, 0, 0, 0, 0, 1))
            .with_addresses(vec![crate::system::interface::LinkAddress::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 10)),
                24,
            )])
            .with_default_route(true)
    }

    /// `lan` is answered from the given table, like every other expression.
    ///
    /// A branch calling `interface::lan_link()` would read the running machine,
    /// and an empty table would still answer with the host's default-route
    /// interface.
    #[test]
    fn lan_is_answered_from_the_table_this_was_given() {
        let table = vec![lan_capable("lab0", 42)];
        let links = for_listening_on(&["lan"], &table).expect("the table has a lan");

        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0].name(),
            "lab0",
            "`lan` was answered from the machine rather than from the table"
        );
    }

    /// A table with nothing a LAN scan could run on gives `NoLan`, even on a
    /// machine that has a LAN.
    #[test]
    fn a_table_with_no_lan_refuses_rather_than_asking_the_machine() {
        assert!(matches!(
            for_listening_on(&["lan"], &table()),
            Err(LinkError::NoLan)
        ));
        assert!(matches!(
            for_listening_on(&["lan"], &[]),
            Err(LinkError::NoLan)
        ));
    }

    #[test]
    fn a_link_is_named_by_its_interface_name() {
        let links = for_listening_on(&["en1"], &table()).expect("en1 is on the machine");

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].name(), "en1");
        assert_eq!(
            links[0].index(),
            Some(5),
            "the index is what a link-local address needs to be usable"
        );
    }

    /// `%en0` is how an address names its interface elsewhere in the engine,
    /// so it is accepted here too.
    #[test]
    fn the_zone_sigil_names_the_same_link_as_the_bare_name() {
        let with = for_listening_on(&["%en0"], &table()).expect("the sigil is accepted");
        let without = for_listening_on(&["en0"], &table()).expect("so is the bare name");

        assert_eq!(with, without);
    }

    /// Naming a link twice is naming one link. A capture opened twice on one
    /// interface would report every finding twice.
    #[test]
    fn a_link_named_twice_is_one_link() {
        let links = for_listening_on(&["en0", "%en0", "en1"], &table()).expect("all are real");

        assert_eq!(
            links.iter().map(Zone::name).collect::<Vec<_>>(),
            vec!["en0", "en1"],
            "deduplicated, and in the order they were written"
        );
    }

    /// No links means every link that is up.
    #[test]
    fn nothing_written_means_every_link_that_is_up() {
        let links = for_listening_on::<&str>(&[], &table()).expect("the machine has links");

        assert_eq!(
            links.iter().map(Zone::name).collect::<Vec<_>>(),
            vec!["en0", "en1"],
            "a link that is down carries nothing to hear"
        );
    }

    /// The refusal lists the interfaces the machine has.
    #[test]
    fn an_unknown_link_names_what_the_machine_has_instead() {
        let error = for_listening_on(&["eth0"], &table()).expect_err("eth0 is not on this machine");

        let LinkError::Unknown {
            expression,
            available,
        } = &error
        else {
            panic!("expected an unknown link, got {error:?}");
        };

        assert_eq!(expression, "eth0");
        assert!(available.contains(&"en0".to_owned()));
        assert!(
            error.to_string().contains("en0"),
            "and it says so out loud: {error}"
        );
    }

    #[test]
    fn an_empty_expression_is_refused_rather_than_read_as_every_link() {
        assert!(matches!(
            for_listening_on(&["  "], &table()),
            Err(LinkError::Empty)
        ));
        assert!(matches!(
            for_listening_on(&["%"], &table()),
            Err(LinkError::Empty)
        ));
    }

    #[test]
    fn a_machine_with_nothing_up_has_nothing_to_listen_to() {
        assert!(matches!(
            for_listening_on::<&str>(&[], &[]),
            Err(LinkError::NoLinks)
        ));
    }
}
