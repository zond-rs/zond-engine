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
//! that is aimed at a **link** rather than at addresses.
//!
//! A listener has no target grammar. There are no ranges, no ports and no
//! hostnames — there is a wire, and either this machine is on it or it is not.
//! So this resolves a much smaller vocabulary than a target expression does, and
//! it resolves it against one thing: the interface table of the machine the
//! process is running on.
//!
//! ## Why this is not asynchronous
//!
//! [`for_discovery`](super::for_discovery) awaits because a target expression
//! may contain a hostname, and resolving one means speaking to a resolver
//! somebody else operates. Nothing here leaves the machine. A link is named,
//! found in a table the kernel already holds, or not found — and making the call
//! `async` to match its sibling would promise a wait that never happens.

use crate::system::interface::Link;

use crate::model::ip::scoped::Zone;
use crate::model::parse::ip::Keyword;
use crate::system::interface;

/// The sigil a target expression scopes an address with, accepted here so that
/// `%en0` and `en0` name the same link.
///
/// A person who has written `[fe80::1%en0]` once should not have to remember
/// that the sigil is wrong in the one place the whole argument *is* the
/// interface.
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
    /// Carries what this machine *does* have, because that is the whole of what
    /// a person needs to correct it and the one thing they cannot see from the
    /// message otherwise.
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
}

/// Resolves link expressions into the links a listening phase reads.
///
/// The one call a front end makes, on the same terms
/// [`for_discovery`](super::for_discovery) is: the vocabulary, this host's
/// interface table and the empty case are answered together rather than being
/// three things every consumer remembers differently.
///
/// Four things may be written:
///
/// - **an interface name** — `en0`, `eth0`, `enp3s0`;
/// - **the same with the zone sigil** — `%en0`, which is how an address names
///   its interface everywhere else in this engine;
/// - **`lan`** — the link a LAN scan would run on, which is the interface
///   carrying this host's default route;
/// - **nothing at all** — every interface that is up.
///
/// A link named twice, or named once as `en0` and once as `%en0`, is one link.
///
/// # The empty case is every link, and that is deliberate
///
/// A scan given no targets has nothing to do. A listener given no links has
/// something perfectly sensible to do — listen to everything this machine is
/// attached to — and refusing would make the commonest use of the phase the one
/// that needs an argument.
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
    for_listening_on(exprs, &crate::system::interface::interfaces())
}

/// [`for_listening`], against an interface table supplied rather than read.
///
/// The same call with its one read of the local machine handed in, which is what
/// makes the behaviour around `lan`, `%en0` and the empty case testable on a
/// machine that has none of them — the same seam
/// [`for_discovery_with`](super::for_discovery_with) exists for.
///
/// Every branch reads `interfaces` and nothing else. `lan` used to reach past it
/// to the running machine, so this function handed an empty table still answered
/// with whichever interface held the default route, and the one case the seam is
/// named for was the one it did not cover.
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
            // Asked of the table rather than matched by name: `lan` means the
            // link carrying the default route, which is a routing question and
            // not a naming one. Asked of the *table* rather than of the machine,
            // because the table is what this function was given and the whole
            // point of taking one.
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

        // A link named twice is one link. Kept in the order written rather than
        // sorted, since that is the order a person reads their own arguments in.
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

    /// An interface table that exists nowhere, so the behaviour under test is
    /// this function's rather than the machine's.
    fn table() -> Vec<Link> {
        let up = |name: &str, index: u32, up: bool| Link::new(name, index).up(up);

        // A link says whether it is up rather than carrying a flags word the
        // reader has to know the bit positions of — which is the whole of what
        // was wrong on Windows, where nobody filled that word in.
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
            .up(true)
            .physical(true)
            .addressing(crate::system::interface::Addressing::Broadcast)
            .of_kind(crate::system::interface::LinkKind::Wired)
            .with_mac(crate::model::mac::MacAddr::new(2, 0, 0, 0, 0, 1))
            .with_addresses(vec![crate::system::interface::LinkAddress::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 10)),
                24,
            )])
            .carrying_the_default_route(true)
    }

    /// `lan` is answered from the table this was handed, like every other
    /// expression it takes.
    ///
    /// **This test could not be written before.** The branch called
    /// `interface::lan_link()`, which reads the running machine, so the seam
    /// this function exists to provide covered `%en0` and the empty case and not
    /// the one its own documentation names first. An empty table still answered
    /// with whichever interface held the host's default route.
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

    /// And a table with nothing a LAN scan could run on says so, rather than
    /// reaching past the caller to a machine that has one.
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

    /// `%en0` is how an address names its interface everywhere else in this
    /// engine, and a person who has written it once should not have to remember
    /// that it is wrong in the one place the argument *is* the interface.
    #[test]
    fn the_zone_sigil_names_the_same_link_as_the_bare_name() {
        let with = for_listening_on(&["%en0"], &table()).expect("the sigil is accepted");
        let without = for_listening_on(&["en0"], &table()).expect("so is the bare name");

        assert_eq!(with, without);
    }

    /// Naming a link twice is naming one link. A capture opened twice on one
    /// interface would read every frame twice, and every finding would arrive
    /// in duplicate.
    #[test]
    fn a_link_named_twice_is_one_link() {
        let links = for_listening_on(&["en0", "%en0", "en1"], &table()).expect("all are real");

        assert_eq!(
            links.iter().map(Zone::name).collect::<Vec<_>>(),
            vec!["en0", "en1"],
            "deduplicated, and in the order they were written"
        );
    }

    /// A listener given no links has something sensible to do, unlike a scan
    /// given no targets. Refusing would make the commonest use of the phase the
    /// one that needs an argument.
    #[test]
    fn nothing_written_means_every_link_that_is_up() {
        let links = for_listening_on::<&str>(&[], &table()).expect("the machine has links");

        assert_eq!(
            links.iter().map(Zone::name).collect::<Vec<_>>(),
            vec!["en0", "en1"],
            "a link that is down carries nothing to hear"
        );
    }

    /// The refusal carries what the machine does have, which is the whole of
    /// what a person needs to correct it and the one thing the message would
    /// otherwise leave them to guess.
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
