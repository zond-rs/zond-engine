// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading what an SNMP agent says it is
//!
//! One value out of one reply: `sysDescr.0`, the string an agent returns when
//! asked what it runs.
//!
//! ## Why this one field is worth a decoder
//!
//! On a Unix host `sysDescr` is the output of `uname -a`:
//!
//! ```text
//! Linux pi 6.1.0-rpi7-rpi-v8 #1 SMP PREEMPT Debian 1:6.1.63-1+rpt1 aarch64
//! ```
//!
//! That is the **exact kernel version**, stated by the machine itself. Nothing
//! else this engine can reach comes close: a TCP stack's shape identifies a
//! family and cannot separate two kernels eleven releases apart — measured, on
//! two labelled hosts — and a service banner names a distribution release at
//! best. An agent that answers this question answers it outright.
//!
//! ## What is parsed, and what is refused
//!
//! Every byte here was chosen by a remote host, so the walk asserts rather than
//! assumes: each tag is checked, each length is checked against the bytes that
//! actually follow it, and the returned identifier has to be the one that was
//! asked for. A reply that disagrees anywhere yields nothing.
//!
//! It parses **only the shape this engine's own probe draws** — an SNMPv1
//! `GetResponse` carrying a single variable binding whose value is an octet
//! string. That is a deliberate limit rather than an unfinished job: a general
//! ASN.1 decoder is a large piece of attack surface for a scanner to carry, and
//! every construct beyond this one is a construct the probe cannot elicit.
//!
//! ## The value is a field, not a response
//!
//! The corpus writes its rules against the decoded string — `context =
//! "snmp.sys_description"`, patterns anchored on the text itself. Feeding it the
//! datagram would match nothing, for the same reason feeding a whole SSH
//! identification line to rules anchored on the software identifier matched
//! nothing. See [`extract`](super::extract).

/// The identifier this engine's probe asks for: `1.3.6.1.2.1.1.1.0`, sysDescr
/// instance zero, as BER packs it — the first two arcs into one byte,
/// `1 * 40 + 3 = 0x2b`.
///
/// Checked against what came back rather than assumed. An agent is free to
/// answer with a binding for something else entirely, and reading that as a
/// system description would attribute one field's text to another field's name.
const SYS_DESCR_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

/// BER tags, by the names the encoding gives them.
mod tag {
    /// A constructed sequence: the message, the variable-binding list, and each
    /// binding.
    pub const SEQUENCE: u8 = 0x30;
    /// An object identifier, naming what a binding is about.
    pub const OID: u8 = 0x06;
    /// An octet string, which is what a system description is carried as.
    pub const OCTET_STRING: u8 = 0x04;
    /// The response to a `GetRequest`. Context-specific, constructed, tag 2.
    pub const GET_RESPONSE: u8 = 0xa2;
}

/// The longest `sysDescr` accepted.
///
/// RFC 1213 bounds the object at 255 octets. A longer one is a peer that is not
/// following the definition it is answering under, and the value is refused
/// rather than truncated: half a description matched against a corpus of whole
/// ones is a match nobody can reproduce.
const MAX_SYS_DESCR: usize = 255;

/// A cursor over BER tag/length/value triples.
///
/// Every read is bounds-checked and returns `None` rather than panicking, which
/// is the property that matters: the bytes come from an unauthenticated peer on
/// a port anyone can send to.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Reads one triple, returning its tag and its value, and advances past it.
    ///
    /// The length is checked against what actually follows: a header claiming
    /// more bytes than the datagram holds is the commonest malformed input
    /// there is, and honouring it would read past the buffer.
    fn read(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.bytes.split_first()?;
        let (&first, rest) = rest.split_first()?;

        let (length, rest) = if first < 0x80 {
            // Short form: the byte is the length.
            (usize::from(first), rest)
        } else {
            // Long form: the low seven bits count the length's own bytes.
            // Refused past four, which is past any datagram: a peer claiming a
            // length that needs more than 32 bits to write is not describing
            // this reply.
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return None;
            }
            let (digits, rest) = rest.split_at_checked(count)?;
            let length = digits
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            (length, rest)
        };

        let (value, remainder) = rest.split_at_checked(length)?;
        self.bytes = remainder;
        Some((tag, value))
    }

    /// Reads one triple and requires it to carry `expected`.
    fn expect(&mut self, expected: u8) -> Option<&'a [u8]> {
        let (tag, value) = self.read()?;
        (tag == expected).then_some(value)
    }

    /// Reads one triple and discards it, failing only where none could be read.
    fn skip(&mut self) -> Option<()> {
        self.read().map(|_| ())
    }
}

/// The `sysDescr.0` string out of an SNMPv1 `GetResponse`, or `None` if this
/// datagram is not one.
///
/// # What has to hold
///
/// The message must be a sequence carrying a version, a community and a
/// `GetResponse`; the response must carry exactly the three integers a PDU
/// begins with and then its bindings; the first binding must name
/// [`SYS_DESCR_OID`] and carry an octet string. Anything else — an error PDU
/// from a wrong community, a trap, a binding for another object, a value of
/// another type — is not a system description and is refused as one.
///
/// The string must also be valid UTF-8. `sysDescr` is defined as
/// `DisplayString`, which is ASCII, so bytes that are not are a peer sending
/// something other than what it claims.
pub(crate) fn sys_descr(datagram: &[u8]) -> Option<&str> {
    let mut message = Reader::new(Reader::new(datagram).expect(tag::SEQUENCE)?);
    message.skip()?; // version
    message.skip()?; // community

    let mut response = Reader::new(message.expect(tag::GET_RESPONSE)?);
    response.skip()?; // request identifier
    response.skip()?; // error status
    response.skip()?; // error index

    let mut bindings = Reader::new(response.expect(tag::SEQUENCE)?);
    let mut binding = Reader::new(bindings.expect(tag::SEQUENCE)?);

    // The identifier is checked, not skipped. An agent may answer with a
    // binding for something this probe never asked about, and reading that
    // value as a system description would file one field's text under another
    // field's name.
    if binding.expect(tag::OID)? != SYS_DESCR_OID {
        return None;
    }

    let value = binding.expect(tag::OCTET_STRING)?;
    (value.len() <= MAX_SYS_DESCR)
        .then(|| std::str::from_utf8(value).ok())
        .flatten()
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

    /// One BER triple: tag, length, value. Short-form length only, which is all
    /// these fixtures need.
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, value.len() as u8];
        out.extend_from_slice(value);
        out
    }

    /// The reply an agent sends to this engine's probe, assembled from RFC 1157
    /// §4.1 rather than through anything in this module — so a misreading here
    /// cannot write the fixture that confirms it.
    fn get_response(oid: &[u8], value_tag: u8, value: &[u8]) -> Vec<u8> {
        let mut binding = tlv(tag::OID, oid);
        binding.extend(tlv(value_tag, value));
        let bindings = tlv(tag::SEQUENCE, &tlv(tag::SEQUENCE, &binding));

        let mut pdu = tlv(0x02, b"zond"); // request identifier
        pdu.extend(tlv(0x02, &[0])); // error status
        pdu.extend(tlv(0x02, &[0])); // error index
        pdu.extend(bindings);

        let mut message = tlv(0x02, &[0]); // version: SNMPv1
        message.extend(tlv(tag::OCTET_STRING, b"public"));
        message.extend(tlv(tag::GET_RESPONSE, &pdu));
        tlv(tag::SEQUENCE, &message)
    }

    fn sys_descr_reply(description: &str) -> Vec<u8> {
        get_response(SYS_DESCR_OID, tag::OCTET_STRING, description.as_bytes())
    }

    /// The whole reason this decoder exists: an agent's own account of its
    /// kernel, which no other channel this engine has can reach.
    #[test]
    fn a_unix_agent_yields_the_kernel_it_is_running() {
        let uname = "Linux pi 6.1.0-rpi7-rpi-v8 #1 SMP PREEMPT Debian 1:6.1.63-1+rpt1 aarch64";
        assert_eq!(sys_descr(&sys_descr_reply(uname)), Some(uname));
    }

    /// A binding for something else is not a system description, however
    /// well-formed. An agent may answer with an object this probe never asked
    /// about, and reading it here would file one field's text under another
    /// field's name.
    #[test]
    fn a_binding_for_another_object_is_refused() {
        // sysUpTime.0 rather than sysDescr.0.
        let other = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00];
        let reply = get_response(other, tag::OCTET_STRING, b"Linux something");
        assert_eq!(sys_descr(&reply), None);
    }

    /// A value of another type is not one either. An integer where a string was
    /// defined is a peer answering under a different definition than the one it
    /// claims.
    #[test]
    fn a_value_that_is_not_a_string_is_refused() {
        let reply = get_response(SYS_DESCR_OID, 0x02, &[0x01, 0x02]);
        assert_eq!(sys_descr(&reply), None);
    }

    /// Every byte is chosen by an unauthenticated peer on a port anyone can send
    /// to, so the walk has to survive anything — a length claiming more than
    /// arrived, a truncation at every offset, a tag that belongs to another
    /// message.
    #[test]
    fn nothing_a_peer_can_send_makes_this_panic() {
        let whole = sys_descr_reply("Linux test 6.1.0 aarch64");

        // Truncated at every possible offset.
        for cut in 0..whole.len() {
            let _ = sys_descr(&whole[..cut]);
        }

        // Every single-byte corruption, at every offset. This walks the tag and
        // length bytes as well as the payload, so it covers a length inflated
        // past the buffer's end at any depth of the nesting.
        for offset in 0..whole.len() {
            for byte in [0x00u8, 0x01, 0x30, 0x7f, 0x80, 0x84, 0xa2, 0xff] {
                let mut mutated = whole.clone();
                mutated[offset] = byte;
                let _ = sys_descr(&mutated);
            }
        }

        // And things that are not this message at all.
        for junk in [
            &b""[..],
            &[0x30][..],
            &[0x30, 0xff][..],
            &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff][..],
            b"SSH-2.0-OpenSSH_9.2p1",
        ] {
            let _ = sys_descr(junk);
        }
    }

    /// A length header that claims more than the datagram holds is the
    /// commonest malformed input there is. Honouring it would read past the
    /// buffer; refusing it is the whole job.
    #[test]
    fn a_length_running_past_the_datagram_yields_nothing() {
        let mut reply = sys_descr_reply("Linux test");
        reply[1] = 0x7f; // the outer sequence now claims far more than follows
        assert_eq!(sys_descr(&reply), None);
    }

    /// RFC 1213 bounds `sysDescr` at 255 octets. A longer one is refused rather
    /// than truncated: half a description matched against a corpus of whole ones
    /// is a match nobody can reproduce.
    #[test]
    fn a_description_past_the_defined_bound_is_refused() {
        // Built by hand: `tlv` writes a short-form length, which stops at 255.
        let value = vec![b'A'; 300];
        let mut binding = tlv(tag::OID, SYS_DESCR_OID);
        binding.push(tag::OCTET_STRING);
        binding.extend_from_slice(&[0x82, 0x01, 0x2c]); // long form: 300
        binding.extend_from_slice(&value);

        let bindings = tlv(tag::SEQUENCE, &tlv(tag::SEQUENCE, &binding));
        let mut pdu = tlv(0x02, b"zond");
        pdu.extend(tlv(0x02, &[0]));
        pdu.extend(tlv(0x02, &[0]));
        pdu.extend(bindings);

        let mut message = tlv(0x02, &[0]);
        message.extend(tlv(tag::OCTET_STRING, b"public"));
        message.extend(tlv(tag::GET_RESPONSE, &pdu));

        // The outer sequence needs a long-form length too.
        let mut reply = vec![tag::SEQUENCE, 0x82];
        reply.extend_from_slice(&(message.len() as u16).to_be_bytes());
        reply.extend_from_slice(&message);

        assert_eq!(sys_descr(&reply), None);
    }

    /// A request is not a response. The probe this engine sends is a
    /// `GetRequest`, and reading one back — from a reflection, or from a scan of
    /// this host's own traffic — must not be mistaken for an answer.
    #[test]
    fn a_request_is_not_an_answer() {
        let mut reply = sys_descr_reply("Linux test");
        // Find the PDU tag and turn the response back into a request.
        let pdu = reply
            .iter()
            .position(|&b| b == tag::GET_RESPONSE)
            .expect("the fixture carries a response PDU");
        reply[pdu] = 0xa0; // GetRequest
        assert_eq!(sys_descr(&reply), None);
    }
}
