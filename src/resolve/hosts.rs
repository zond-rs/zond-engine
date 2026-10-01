// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The hosts file
//!
//! The static table every system consults first: `/etc/hosts` on Unix,
//! `System32\drivers\etc\hosts` on Windows. It is where a lab box with no DNS
//! of its own gets a name, so a name listed there is answered from the file,
//! whatever its suffix, and asked of no server.
//!
//! The engine reads the file itself, not through the unicast client, because:
//!
//! - The file is authoritative for a name it lists. A client that consults it
//!   per record type still asks upstream for the family the file does not
//!   list, which leaks the name to a resolver somebody else operates and, where
//!   that resolver is unreachable, stalls the lookup for its whole timeout.
//! - It answers `.local` names too, which never reach the unicast client.
//! - It is read at every resolution pass, so a long-lived front end sees a line
//!   added after the box came up.

use std::collections::HashMap;
use std::net::IpAddr;

/// The names a hosts file lists, each with its addresses in file order, and
/// the name each address is known by.
#[derive(Debug, Default)]
pub(crate) struct HostsTable {
    /// Keyed by the folded name, so `Box.HTB` and `box.htb.` find one entry.
    by_name: HashMap<String, Vec<IpAddr>>,
    /// The first name on the first line listing each address, as written.
    by_address: HashMap<IpAddr, String>,
}

/// What the file says about one name.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HostsAnswer {
    /// The addresses to use: the first line's address in each family.
    pub(crate) addresses: Vec<IpAddr>,
    /// Addresses later lines give the same name in a family already answered,
    /// which nothing uses.
    pub(crate) shadowed: Vec<IpAddr>,
}

impl HostsTable {
    /// Reads the system's hosts file. A missing or unreadable file gives an
    /// empty table.
    pub(crate) fn read_system() -> Self {
        match std::fs::read_to_string(hosts_path()) {
            Ok(text) => Self::parse(&text),
            Err(e) => {
                crate::info!(verbosity = 1, "hosts file not read ({e})");
                Self::default()
            }
        }
    }

    /// Parses hosts-file text: an address, then the names it answers for, with
    /// `#` starting a comment.
    ///
    /// A line whose address does not parse is skipped, as the system's own
    /// reader skips it. That includes an address with a zone (`fe80::1%lo0`),
    /// which a name cannot carry into a target.
    pub(crate) fn parse(text: &str) -> Self {
        let mut table = Self::default();
        for line in text.lines() {
            let line = line.split_once('#').map_or(line, |(kept, _)| kept);
            let mut fields = line.split_whitespace().peekable();
            let Some(Ok(address)) = fields.next().map(str::parse::<IpAddr>) else {
                continue;
            };
            if let Some(canonical) = fields.peek() {
                table
                    .by_address
                    .entry(address)
                    .or_insert_with(|| canonical.trim_end_matches('.').to_owned());
            }
            for name in fields {
                let listed = table.by_name.entry(fold(name)).or_default();
                if !listed.contains(&address) {
                    listed.push(address);
                }
            }
        }
        table
    }

    /// What the file says `name` stands for, or `None` when it does not list it.
    ///
    /// The first line naming a host answers for its family; a later line giving
    /// the same name another address of that family is returned in
    /// [`HostsAnswer::shadowed`]. Two lines for one name are almost always an
    /// old box and its replacement, and the first is what the system's own
    /// single-answer lookups return, so it is what `ping` and `ssh` reach too.
    /// A name listed once per family, like `localhost` at `127.0.0.1` and
    /// `::1`, answers with both, as DNS does for a name with A and AAAA
    /// records.
    pub(crate) fn lookup(&self, name: &str) -> Option<HostsAnswer> {
        let listed = self.by_name.get(&fold(name))?;
        let mut answer = HostsAnswer {
            addresses: Vec::new(),
            shadowed: Vec::new(),
        };
        for &address in listed {
            let answered = answer
                .addresses
                .iter()
                .any(|kept| kept.is_ipv4() == address.is_ipv4());
            if answered {
                answer.shadowed.push(address);
            } else {
                answer.addresses.push(address);
            }
        }
        Some(answer)
    }

    /// The name the file gives `address`, or `None` when no line lists it.
    ///
    /// The first name on the first line listing the address: the line's
    /// canonical name, and what `getnameinfo` reports, so a scan names the host
    /// as the rest of the system does.
    pub(crate) fn name_of(&self, address: IpAddr) -> Option<&str> {
        self.by_address.get(&address).map(String::as_str)
    }
}

/// A name as the table keys it: case-folded, without a trailing root dot.
fn fold(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Where the system keeps its hosts file.
#[cfg(unix)]
fn hosts_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/etc/hosts")
}

/// Where the system keeps its hosts file: under the Windows directory, which
/// is not always `C:\Windows`.
#[cfg(windows)]
fn hosts_path() -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    std::path::Path::new(&root).join("System32\\drivers\\etc\\hosts")
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

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("a test address parses")
    }

    /// Every name on a line answers with its address, whatever case or root
    /// dot it is asked with. A lab's hosts line often names a box and its
    /// domain together.
    #[test]
    fn every_name_on_a_line_answers_in_any_case() {
        let table = HostsTable::parse(
            "# a comment line\n\
             198.51.100.7\tforest.corp.local corp.local   # the lab's domain controller\n\
             \n\
             not-an-address ignored.example\n\
             fe80::1%lo0 zoned.example\n",
        );

        for name in ["forest.corp.local", "CORP.LOCAL", "corp.local."] {
            assert_eq!(
                table.lookup(name).map(|a| a.addresses),
                Some(vec![ip("198.51.100.7")]),
                "{name}"
            );
        }
        assert_eq!(table.lookup("ignored.example"), None);
        assert_eq!(table.lookup("zoned.example"), None);
        assert_eq!(table.lookup("a.comment"), None);
    }

    /// A second line for a name in the same family is reported and not
    /// scanned; the first is the one the system's own tools reach.
    #[test]
    fn a_later_line_for_a_name_is_shadowed_by_the_first_in_its_family() {
        let table = HostsTable::parse(
            "198.51.100.23 box.example\n\
             2001:db8::23 box.example\n\
             198.51.100.99 box.example\n\
             198.51.100.23 box.example\n",
        );

        assert_eq!(
            table.lookup("box.example"),
            Some(HostsAnswer {
                addresses: vec![ip("198.51.100.23"), ip("2001:db8::23")],
                shadowed: vec![ip("198.51.100.99")],
            }),
            "one address per family, and the repeat of the first is no conflict"
        );
    }

    /// An address takes the canonical name of the first line listing it, as
    /// the system's reverse lookup gives it.
    #[test]
    fn an_address_is_named_by_the_first_line_listing_it() {
        let table = HostsTable::parse(
            "198.51.100.23 old-box.example old-box\n\
             198.51.100.23 new-box.example\n\
             2001:db8::23 Box6.Example.\n",
        );

        assert_eq!(table.name_of(ip("198.51.100.23")), Some("old-box.example"));
        assert_eq!(table.name_of(ip("2001:db8::23")), Some("Box6.Example"));
        assert_eq!(table.name_of(ip("198.51.100.24")), None);
    }
}
