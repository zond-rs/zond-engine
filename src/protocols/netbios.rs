// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # NetBIOS Name Service
//!
//! Reads the name table a node-status response carries.
//!
//! The corpus registers the query in `assets/fingerprinting/network/netbios-ns.toml`:
//! a NBSTAT question for the wildcard name, which is what `nbtscan` sends and
//! what makes a Windows or Samba host list every name it has registered. The
//! answer went unread until this module: a scan counted it as evidence the port
//! was open, which it already knew from the datagram arriving.
//!
//! ## What is in a name table, and what is not
//!
//! Each entry is a sixteen-byte name whose last byte is a suffix saying which
//! service registered it, and a flags word whose top bit says whether the name is
//! a group rather than one machine's own. The names themselves are site-specific,
//! a machine and a workgroup somebody chose, so there is nothing here for a
//! signature to match, which is why this produces no corpus text. The suffixes
//! are not site-specific at all, and they are what
//! [`NameTable::domain_controller`] reads.
//!
//! ## Which suffix means a domain controller
//!
//! `<1C>` is registered as a group by every domain controller in a domain and by
//! nothing else, so its presence names the machine's role outright. `<1B>` is the
//! domain master browser, held by exactly one controller, and it is a unique name
//! rather than a group.
//!
//! Not `<20>`, which is the server service and means only that the host shares
//! something, and not `<00>`, which every NetBIOS host registers.

/// The suffix a domain controller registers as a group name.
const SUFFIX_DOMAIN_CONTROLLERS: u8 = 0x1C;

/// The suffix the domain master browser registers, as a unique name. One
/// controller in a domain holds it.
const SUFFIX_DOMAIN_MASTER_BROWSER: u8 = 0x1B;

/// The bit in a name's flags word marking it a group name rather than a
/// machine's own.
const FLAG_GROUP: u16 = 0x8000;

/// Bytes of the fixed header: transaction ID, flags, and four section counts.
const HEADER_BYTES: usize = 12;

/// Bytes of an encoded name in a question or an answer: a length byte, the
/// thirty-two bytes of first-level encoding, and a terminator.
const ENCODED_NAME_BYTES: usize = 34;

/// Bytes of the type, class, TTL and RDLENGTH that follow an answer's name.
const ANSWER_FIXED_BYTES: usize = 2 + 2 + 4 + 2;

/// Bytes of one name-table entry: fifteen of name, one of suffix, two of flags.
const ENTRY_BYTES: usize = 18;

/// The flags bit set on a response.
const FLAG_RESPONSE: u16 = 0x8000;

/// One registered name, as the table spells it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredName {
    /// The fifteen-character name with its padding removed. May be empty, and
    /// may hold anything a person typed, so nothing here treats it as a
    /// hostname without deciding to.
    pub name: String,
    /// The service byte: `0x00` for the workstation, `0x20` for the server
    /// service, `0x1C` for the domain controllers group.
    pub suffix: u8,
    /// Whether the name belongs to a group rather than to this machine.
    pub group: bool,
}

/// Every name a node-status response listed, and the adapter that answered.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameTable {
    /// The registered names, in the order the responder listed them.
    pub names: Vec<RegisteredName>,
    /// The adapter's hardware address, from the first six bytes of the
    /// statistics block. All zeroes on a responder that reports none, which
    /// Samba does by default, so it is offered as read rather than as a fact
    /// about hardware.
    pub unit_id: [u8; 6],
}

impl NameTable {
    /// Whether this table was answered by a domain controller.
    ///
    /// Reads the two suffixes only a controller registers, and reads each in the
    /// form it is registered in: `<1C>` as a group, `<1B>` as a unique name. A
    /// check that ignored the group bit would take a machine that merely holds a
    /// name resembling one of these for a controller.
    #[must_use]
    pub fn domain_controller(&self) -> bool {
        self.names.iter().any(|entry| {
            (entry.suffix == SUFFIX_DOMAIN_CONTROLLERS && entry.group)
                || (entry.suffix == SUFFIX_DOMAIN_MASTER_BROWSER && !entry.group)
        })
    }

    /// The name this machine registered for itself, if it named one.
    ///
    /// The `<00>` unique name is the workstation service, which every NetBIOS
    /// host registers under its own computer name. The same suffix on a group
    /// name is the workgroup or domain instead, which is why the group bit is part of
    /// the question rather than an afterthought.
    #[must_use]
    pub fn workstation(&self) -> Option<&str> {
        self.names
            .iter()
            .find(|entry| entry.suffix == 0x00 && !entry.group && !entry.name.is_empty())
            .map(|entry| entry.name.as_str())
    }

    /// The domain or workgroup the machine says it belongs to.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.names
            .iter()
            .find(|entry| entry.suffix == 0x00 && entry.group && !entry.name.is_empty())
            .map(|entry| entry.name.as_str())
    }
}

/// Reads the name table out of a node-status response.
///
/// [`None`] for anything that is not one: a datagram too short to hold a header,
/// a message that is a query rather than a response, an answer that claims more
/// names than the bytes after it can hold. Every length is checked against what
/// actually arrived rather than trusted, because this parses a datagram from an
/// unauthenticated stranger and a claimed count is the stranger's to choose.
///
/// The statistics block is truncated on some responders, so a table whose names
/// parse is returned with a zero unit ID rather than refused: the names are the
/// part anything here reads, and losing them to a missing trailer would be
/// discarding an answer over a field nobody asked for.
#[must_use]
pub fn node_status(datagram: &[u8]) -> Option<NameTable> {
    let flags = u16::from_be_bytes([*datagram.get(2)?, *datagram.get(3)?]);
    if flags & FLAG_RESPONSE == 0 {
        return None;
    }

    let answers = u16::from_be_bytes([*datagram.get(6)?, *datagram.get(7)?]);
    if answers == 0 {
        return None;
    }

    // The answer's own name repeats the question's, in the same encoding and at
    // the same fixed width, so the record body sits at a known offset. No
    // compression pointer can appear here: the name service uses none.
    let rdata = datagram.get(HEADER_BYTES + ENCODED_NAME_BYTES + ANSWER_FIXED_BYTES..)?;

    let count = *rdata.first()? as usize;
    let mut names = Vec::with_capacity(count.min(rdata.len() / ENTRY_BYTES));
    for index in 0..count {
        let at = 1 + index * ENTRY_BYTES;
        let entry = rdata.get(at..at + ENTRY_BYTES)?;
        let flags = u16::from_be_bytes([entry[16], entry[17]]);
        names.push(RegisteredName {
            // Trailing spaces are the padding to fifteen characters; a leading
            // one is padding too on the browser names that start with a control
            // byte, so both ends are trimmed.
            name: String::from_utf8_lossy(&entry[..15]).trim().to_string(),
            suffix: entry[15],
            group: flags & FLAG_GROUP != 0,
        });
    }

    let statistics = 1 + count * ENTRY_BYTES;
    let unit_id = rdata
        .get(statistics..statistics + 6)
        .and_then(|bytes| <[u8; 6]>::try_from(bytes).ok())
        .unwrap_or([0; 6]);

    Some(NameTable { names, unit_id })
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

    /// Builds a node-status response carrying `entries`, in the layout a
    /// responder writes: header, the question's name echoed back, the fixed
    /// record fields, then the table and the statistics block.
    fn response(entries: &[(&str, u8, bool)]) -> Vec<u8> {
        let mut out = vec![0x80, 0xf0]; // transaction ID
        out.extend_from_slice(&0x8400u16.to_be_bytes()); // response, authoritative
        out.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        out.push(0x20);
        out.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        out.push(0x00);

        out.extend_from_slice(&0x0021u16.to_be_bytes()); // NBSTAT
        out.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
        out.extend_from_slice(&0u32.to_be_bytes()); // TTL
        let rdlength = 1 + entries.len() * ENTRY_BYTES + 46;
        out.extend_from_slice(&(rdlength as u16).to_be_bytes());

        out.push(entries.len() as u8);
        for (name, suffix, group) in entries {
            let mut padded = format!("{name:<15}").into_bytes();
            padded.truncate(15);
            out.extend_from_slice(&padded);
            out.push(*suffix);
            out.extend_from_slice(&(if *group { FLAG_GROUP } else { 0 }).to_be_bytes());
        }
        out.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]); // unit ID
        out.extend_from_slice(&[0u8; 40]); // the rest of the statistics block
        out
    }

    /// The ordinary case: a member server lists its own name, the server
    /// service, and the workgroup it joined.
    #[test]
    fn a_table_yields_the_names_and_the_adapter() {
        let table = node_status(&response(&[
            ("FILESERVER", 0x00, false),
            ("FILESERVER", 0x20, false),
            ("WORKGROUP", 0x00, true),
        ]))
        .expect("a well-formed response parses");

        assert_eq!(table.names.len(), 3);
        assert_eq!(table.workstation(), Some("FILESERVER"));
        assert_eq!(table.domain(), Some("WORKGROUP"));
        assert_eq!(table.unit_id, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    }

    /// The suffix a controller registers, in the form it registers it.
    #[test]
    fn the_domain_controllers_group_names_a_controller() {
        let table = node_status(&response(&[
            ("DC01", 0x00, false),
            ("CORP", 0x00, true),
            ("CORP", SUFFIX_DOMAIN_CONTROLLERS, true),
        ]))
        .expect("parses");
        assert!(table.domain_controller());
        assert_eq!(table.domain(), Some("CORP"));
    }

    /// And the master browser's, which a controller holds as a unique name.
    #[test]
    fn the_domain_master_browser_names_one_too() {
        let table = node_status(&response(&[
            ("DC01", 0x00, false),
            ("CORP", SUFFIX_DOMAIN_MASTER_BROWSER, false),
        ]))
        .expect("parses");
        assert!(table.domain_controller());
    }

    /// The group bit is half of each claim. `<1C>` as a unique name and `<1B>`
    /// as a group are both the wrong form, and a host registering either has not
    /// said it is a controller.
    #[test]
    fn a_suffix_in_the_wrong_form_names_nothing() {
        let unique_1c =
            node_status(&response(&[("CORP", SUFFIX_DOMAIN_CONTROLLERS, false)])).expect("parses");
        assert!(!unique_1c.domain_controller());

        let group_1b = node_status(&response(&[("CORP", SUFFIX_DOMAIN_MASTER_BROWSER, true)]))
            .expect("parses");
        assert!(!group_1b.domain_controller());
    }

    /// An ordinary workstation is not a controller, which is the case that has
    /// to stay false for the role to mean anything.
    #[test]
    fn a_workstation_is_not_a_controller() {
        let table = node_status(&response(&[
            ("LAPTOP", 0x00, false),
            ("LAPTOP", 0x20, false),
            ("WORKGROUP", 0x00, true),
            ("WORKGROUP", 0x1E, true),
        ]))
        .expect("parses");
        assert!(!table.domain_controller());
    }

    /// A query is not an answer. Our own probe echoed back by a reflector must
    /// not be read as a name table.
    #[test]
    fn a_query_is_refused() {
        let mut query = response(&[("HOST", 0x00, false)]);
        query[2] = 0x00; // clear the response bit
        query[3] = 0x10;
        assert!(node_status(&query).is_none());
    }

    /// A count larger than the bytes behind it is the stranger choosing a
    /// number, and is refused rather than read past.
    #[test]
    fn a_count_the_datagram_cannot_back_is_refused() {
        let mut lying = response(&[("HOST", 0x00, false)]);
        let table_at = HEADER_BYTES + ENCODED_NAME_BYTES + ANSWER_FIXED_BYTES;
        lying[table_at] = 200;
        lying.truncate(table_at + 1 + ENTRY_BYTES);
        assert!(node_status(&lying).is_none());
    }

    /// A responder that sends no statistics block still has its names read.
    #[test]
    fn a_truncated_statistics_block_costs_only_the_adapter() {
        let full = response(&[("HOST", 0x00, false)]);
        let table_at = HEADER_BYTES + ENCODED_NAME_BYTES + ANSWER_FIXED_BYTES;
        let table = node_status(&full[..table_at + 1 + ENTRY_BYTES]).expect("the names parse");
        assert_eq!(table.workstation(), Some("HOST"));
        assert_eq!(table.unit_id, [0; 6]);
    }

    /// Anything at all, without panicking and without inventing a table.
    #[test]
    fn arbitrary_bytes_are_refused_rather_than_read() {
        for bytes in [
            &b""[..],
            &b"\x00"[..],
            &b"\x80\xf0\x84\x00"[..],
            &[0xff; 64][..],
        ] {
            let _ = node_status(bytes);
        }
        assert!(node_status(b"").is_none());
        assert!(node_status(&[0u8; 12]).is_none());
    }
}
