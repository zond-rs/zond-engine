// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading what an SNMP agent says it is
//!
//! Two values out of one reply: `sysDescr.0`, the string an agent returns when
//! asked what it runs, and `sysObjectID.0`, the vendor's own identifier for
//! the box, which the same request asks for beside it.
//!
//! ## Why the description is worth a decoder
//!
//! On a Unix host `sysDescr` is the output of `uname -a`:
//!
//! ```text
//! Linux pi 6.1.0-rpi7-rpi-v8 #1 SMP PREEMPT Debian 1:6.1.63-1+rpt1 aarch64
//! ```
//!
//! That is the **exact kernel version**, stated by the machine itself. Nothing
//! else this engine can reach comes close: a TCP stack's shape identifies a
//! family and cannot separate two kernels eleven releases apart, measured, on
//! two labelled hosts, and a service banner names a distribution release at
//! best. An agent that answers this question answers it outright.
//!
//! ## What is parsed, and what is refused
//!
//! Every byte here was chosen by a remote host, so the walk asserts rather than
//! assumes: each tag is checked, each length is checked against the bytes that
//! actually follow it, and the returned identifier has to be the one that was
//! asked for. A reply that disagrees anywhere yields nothing.
//!
//! It parses **only the shape this engine's own probe draws**, an SNMPv1
//! `GetResponse` whose bindings answer the two questions the probe asks: a
//! description carried as an octet string, and an identifier carried as an
//! object identifier, in either order. That is a deliberate limit rather than
//! an unfinished job: a general ASN.1 decoder is a large piece of attack
//! surface for a scanner to carry, and every construct beyond this one is a
//! construct the probe cannot elicit.
//!
//! ## The value is a field, not a response
//!
//! The corpus writes its rules against the decoded string, with `context =
//! "snmp.sys_description"` and patterns anchored on the text itself. Feeding it
//! the
//! datagram would match nothing, for the same reason feeding a whole SSH
//! identification line to rules anchored on the software identifier matched
//! nothing. See [`extract`](super::extract).

/// The identifier this engine's probe asks for: `1.3.6.1.2.1.1.1.0`, sysDescr
/// instance zero, as BER packs it, the first two arcs into one byte, `1 * 40 +
/// 3 = 0x2b`.
///
/// Checked against what came back rather than assumed. An agent is free to
/// answer with a binding for something else entirely, and reading that as a
/// system description would attribute one field's text to another field's name.
const SYS_DESCR_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

/// `sysObjectID.0`, `1.3.6.1.2.1.1.2.0`, encoded the same way.
///
/// RFC 1213 defines it as the vendor's own identifier for the box, which makes
/// it the one field that names a model outright rather than describing it.
const SYS_OBJECT_ID_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00];

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

/// The value of `sysObjectID.0` in a GetResponse, as dotted decimal.
///
/// The agent's own name for what it is, which the corpus matches both alone and
/// joined to the description. Walks every binding rather than reading the first,
/// because an agent orders its answers as it likes and the probe asks two
/// questions.
///
/// [`None`] when the message is not a GetResponse, carries no such binding, or
/// carries one whose value is not an object identifier.
pub(crate) fn sys_object_id(datagram: &[u8]) -> Option<String> {
    let mut bindings = bindings_of(datagram)?;

    while let Some((tag::SEQUENCE, binding)) = bindings.read() {
        let mut binding = Reader::new(binding);
        let Some(name) = binding.expect(tag::OID) else {
            continue;
        };
        if name != SYS_OBJECT_ID_OID {
            continue;
        }
        return binding.expect(tag::OID).and_then(object_identifier);
    }
    None
}

/// Renders a BER object identifier as the dotted decimal a rule is written
/// against.
///
/// The first byte packs the first two arcs as `40 * x + y`, and every arc after
/// it is base-128 with the top bit set on all but the last byte. An arc whose
/// continuation never ends is a truncated identifier and yields nothing.
fn object_identifier(encoded: &[u8]) -> Option<String> {
    let (first, rest) = encoded.split_first()?;
    let mut arcs = vec![(first / 40).to_string(), (first % 40).to_string()];

    let mut arc: u64 = 0;
    let mut open = false;
    for byte in rest {
        // A value this long is not an arc anybody assigned; refusing it keeps
        // the shift below from wrapping.
        arc = arc.checked_mul(128)?.checked_add(u64::from(byte & 0x7f))?;
        open = byte & 0x80 != 0;
        if !open {
            arcs.push(arc.to_string());
            arc = 0;
        }
    }

    (!open).then(|| arcs.join("."))
}

/// The variable-binding list of a GetResponse, as a cursor over its bindings.
fn bindings_of(datagram: &[u8]) -> Option<Reader<'_>> {
    let mut message = Reader::new(Reader::new(datagram).expect(tag::SEQUENCE)?);
    message.skip()?; // version
    message.skip()?; // community

    let mut response = Reader::new(message.expect(tag::GET_RESPONSE)?);
    response.skip()?; // request identifier
    response.skip()?; // error status
    response.skip()?; // error index

    Some(Reader::new(response.expect(tag::SEQUENCE)?))
}

/// The `sysDescr.0` string out of an SNMPv1 `GetResponse`, or `None` if this
/// datagram is not one.
///
/// # What has to hold
///
/// The message must be a sequence carrying a version, a community and a
/// `GetResponse`; the response must carry exactly the three integers a PDU
/// begins with and then its bindings; and one of those bindings must name
/// [`SYS_DESCR_OID`] and carry an octet string. Anything else, an error PDU
/// from a wrong community, a trap, a reply that answers only the other
/// question, a value of another type, is not a system description and is
/// refused as one.
///
/// Every binding is examined rather than the first, because the request carries
/// two questions and an agent answers them in whatever order it likes.
///
/// The string must also be valid UTF-8. `sysDescr` is defined as
/// `DisplayString`, which is ASCII, so bytes that are not are a peer sending
/// something other than what it claims.
pub(crate) fn sys_descr(datagram: &[u8]) -> Option<&str> {
    let mut bindings = bindings_of(datagram)?;

    while let Some((tag::SEQUENCE, binding)) = bindings.read() {
        let mut binding = Reader::new(binding);
        // The identifier is checked, not skipped. An agent may answer with a
        // binding for something this probe never asked about, and reading that
        // value as a system description would file one field's text under
        // another field's name.
        let Some(name) = binding.expect(tag::OID) else {
            continue;
        };
        if name != SYS_DESCR_OID {
            continue;
        }
        let value = binding.expect(tag::OCTET_STRING)?;
        return (value.len() <= MAX_SYS_DESCR)
            .then(|| std::str::from_utf8(value).ok())
            .flatten();
    }
    None
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

    /// A reply carrying one binding, which is all most of these need.
    fn get_response(oid: &[u8], value_tag: u8, value: &[u8]) -> Vec<u8> {
        response(&[(oid, value_tag, value)])
    }

    /// The reply an agent sends to this engine's probe, carrying `bindings` in
    /// the order given, each a name, a value tag and a value. Assembled from
    /// RFC 1157 §4.1 rather than through anything in this module, so a
    /// misreading here cannot write the fixture that confirms it.
    fn response(bindings: &[(&[u8], u8, &[u8])]) -> Vec<u8> {
        let list: Vec<u8> = bindings
            .iter()
            .flat_map(|(oid, value_tag, value)| {
                let mut binding = tlv(tag::OID, oid);
                binding.extend(tlv(*value_tag, value));
                tlv(tag::SEQUENCE, &binding)
            })
            .collect();
        let bindings = tlv(tag::SEQUENCE, &list);

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

    /// `1.3.6.1.4.1.8072.3.2.10`, Net-SNMP's identifier for an agent on Linux.
    /// The 8072 arc takes two base-128 bytes, which is the case a renderer
    /// reading bytes as arcs gets wrong.
    const NET_SNMP_LINUX: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xbf, 0x08, 0x03, 0x02, 0x0a];

    /// What an agent answering both of the probe's questions sends back, in the
    /// order it chose.
    fn both_answers(identifier_first: bool) -> Vec<u8> {
        let description = (
            SYS_DESCR_OID,
            tag::OCTET_STRING,
            &b"Linux zond 6.1.0 x86_64"[..],
        );
        let identifier = (SYS_OBJECT_ID_OID, tag::OID, NET_SNMP_LINUX);
        if identifier_first {
            response(&[identifier, description])
        } else {
            response(&[description, identifier])
        }
    }

    /// Whether `rendered` is what [`object_identifier`] promises: two or more
    /// arcs of decimal digits, joined by dots.
    fn is_dotted_decimal(rendered: &str) -> bool {
        let arcs: Vec<&str> = rendered.split('.').collect();
        arcs.len() >= 2
            && arcs
                .iter()
                .all(|arc| !arc.is_empty() && arc.bytes().all(|b| b.is_ascii_digit()))
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

    /// The reply the probe draws answers two questions, in whatever order the
    /// agent likes, and each reader finds its own answer in either.
    #[test]
    fn both_answers_are_read_in_either_order() {
        for identifier_first in [false, true] {
            let reply = both_answers(identifier_first);
            assert_eq!(sys_descr(&reply), Some("Linux zond 6.1.0 x86_64"));
            assert_eq!(
                sys_object_id(&reply).as_deref(),
                Some("1.3.6.1.4.1.8072.3.2.10")
            );
        }
    }

    /// The pin below, over the reply the probe actually draws and through both
    /// readers.
    ///
    /// A second binding is a second walk through the list, and the identifier
    /// has an encoding of its own to be parsed behind it. Neither may panic on
    /// a mangled reply, and whatever either still hands back has the shape it
    /// promises: a description within the defined bound, an identifier in
    /// dotted decimal. `0x06` joins the corrupting bytes because it is the tag
    /// an identifier is recognised by.
    #[test]
    fn nothing_a_peer_can_send_breaks_either_reader_of_the_probes_reply() {
        for identifier_first in [false, true] {
            let whole = both_answers(identifier_first);

            let mut mangled: Vec<Vec<u8>> =
                (0..whole.len()).map(|cut| whole[..cut].to_vec()).collect();
            for offset in 0..whole.len() {
                for byte in [0x00u8, 0x01, 0x06, 0x30, 0x7f, 0x80, 0x84, 0xa2, 0xff] {
                    let mut mutated = whole.clone();
                    mutated[offset] = byte;
                    mangled.push(mutated);
                }
            }

            for datagram in &mangled {
                if let Some(description) = sys_descr(datagram) {
                    assert!(description.len() <= MAX_SYS_DESCR);
                }
                if let Some(identifier) = sys_object_id(datagram) {
                    assert!(
                        is_dotted_decimal(&identifier),
                        "{identifier:?} read out of {datagram:02x?}"
                    );
                }
            }
        }
    }

    /// The renderer is handed whatever bytes a binding carried, so it is held
    /// to what the walk around it is: any input renders as nothing or as dotted
    /// decimal, and never panics. Deterministic, for the reason
    /// `arbitrary_datagrams_are_refused_rather_than_read` gives.
    #[test]
    fn any_encoded_identifier_renders_as_nothing_or_as_dotted_decimal() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..20_000 {
            let len = (next() % 24) as usize;
            let encoded: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
            if let Some(rendered) = object_identifier(&encoded) {
                assert!(
                    is_dotted_decimal(&rendered),
                    "{rendered:?} rendered from {encoded:02x?}"
                );
            }
        }
    }

    /// An arc ends at the first byte without the continuation bit, so an
    /// identifier cut inside one is truncated and yields nothing, at every
    /// place it can be cut. One longer than any arc anybody assigned is
    /// refused rather than wrapped.
    #[test]
    fn an_identifier_cut_inside_an_arc_or_past_any_arc_yields_nothing() {
        for cut in 1..NET_SNMP_LINUX.len() {
            let prefix = &NET_SNMP_LINUX[..cut];
            let inside_an_arc = prefix.last().is_some_and(|byte| byte & 0x80 != 0);
            assert_eq!(
                object_identifier(prefix).is_none(),
                inside_an_arc,
                "cut after {prefix:02x?}"
            );
        }

        // Ten continuation bytes are seventy bits, past what an arc is held in.
        let mut endless = vec![0x2b];
        endless.extend([0xff; 10]);
        endless.push(0x7f);
        assert_eq!(object_identifier(&endless), None);
    }

    /// Every byte is chosen by an unauthenticated peer on a port anyone can
    /// send to, so the walk has to survive anything, a length claiming more
    /// than arrived, a truncation at every offset, a tag that belongs to
    /// another message.
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
    /// `GetRequest`, and reading one back, from a reflection, or from a scan of
    /// this host's own traffic, must not be mistaken for an answer.
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

    /// **Every way a length can lie, refused rather than believed.**
    ///
    /// The length encoding is where a hand-rolled BER reader goes wrong, and
    /// this one is read from an unauthenticated peer on a port anyone can send
    /// to. Each row is a shape that has broken a real ASN.1 parser somewhere:
    /// the indefinite form, a long form claiming more bytes than a length needs,
    /// a length past the end of the datagram, and a header cut off in the middle.
    #[test]
    fn no_length_encoding_reads_past_the_datagram() {
        let cases: &[(&str, &[u8])] = &[
            // 0x80 is the indefinite form, which BER allows and DER does not,
            // and which a reader that treats it as a length of zero will loop on.
            ("indefinite length", &[0x30, 0x80, 0x02, 0x01, 0x00]),
            // The low seven bits count the length's own bytes; five is more than
            // a length this side of a 32-bit datagram needs.
            ("long form over four bytes", &[0x30, 0x85, 1, 1, 1, 1, 1]),
            // Four bytes of 0xFF is a length of four gigabytes.
            (
                "long form naming four gigabytes",
                &[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
            ),
            ("length past the buffer", &[0x30, 0x7F, 0x02]),
            ("truncated after the tag", &[0x30]),
            ("truncated inside the long form", &[0x30, 0x82, 0x01]),
            ("empty", &[]),
            ("zero length", &[0x30, 0x00]),
        ];

        for (name, datagram) in cases {
            assert_eq!(sys_descr(datagram), None, "{name} was not refused");
            assert_eq!(sys_object_id(datagram), None, "{name} was not refused");
        }
    }

    /// Nesting costs bytes, so a datagram cannot nest its way to a stack
    /// overflow — but the walk has to actually terminate on one that tries.
    #[test]
    fn a_deeply_nested_datagram_terminates() {
        let mut datagram = Vec::new();
        for _ in 0..512 {
            datagram.push(0x30);
            datagram.push(0x02);
        }
        assert_eq!(sys_descr(&datagram), None);
        assert_eq!(sys_object_id(&datagram), None);
    }

    /// **Arbitrary bytes settle nothing and break nothing.**
    ///
    /// The port answers to anyone, so the reader's whole job is to come back
    /// with `None` rather than a panic or a claim. Deterministic, so a failure
    /// is reproducible from the seed rather than from a saved corpus — `snmp`
    /// is reached through a `pub(crate)` entry and so cannot be driven from
    /// `fuzz/`, which is why this lives here.
    #[test]
    fn arbitrary_datagrams_are_refused_rather_than_read() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..20_000 {
            let len = (next() % 96) as usize;
            let datagram: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
            assert!(
                sys_descr(&datagram).is_none(),
                "random bytes were read as a system description: {datagram:02x?}"
            );
            assert!(
                sys_object_id(&datagram).is_none(),
                "random bytes were read as an object identifier: {datagram:02x?}"
            );
        }
    }

    /// And a message that is nearly a GetResponse stays safe under every
    /// single-byte change, which is where a reader that trusts one field after
    /// checking another comes apart.
    #[test]
    fn a_near_miss_response_survives_every_single_byte_mutation() {
        let mut real: Vec<u8> = vec![0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06];
        real.extend_from_slice(b"public");
        real.extend_from_slice(&[
            0xA2, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
        ]);
        real.extend_from_slice(&[0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08]);
        real.extend_from_slice(&[0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
        real.extend_from_slice(&[0x04, 0x00]);

        for at in 0..real.len() {
            for value in [0x00u8, 0x01, 0x30, 0x7F, 0x80, 0x84, 0xA2, 0xFF] {
                let mut datagram = real.clone();
                datagram[at] = value;
                let _ = sys_descr(&datagram);
                let _ = sys_object_id(&datagram);
            }
        }
    }
}
