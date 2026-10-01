// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading what an SNMP agent says it is
//!
//! Two values out of one reply: `sysDescr.0`, the agent's description of what it
//! runs, and `sysObjectID.0`, the vendor's identifier for the box.
//!
//! ## Why the description matters
//!
//! On a Unix host `sysDescr` is the output of `uname -a`:
//!
//! ```text
//! Linux pi 6.1.0-rpi7-rpi-v8 #1 SMP PREEMPT Debian 1:6.1.63-1+rpt1 aarch64
//! ```
//!
//! That is the **exact kernel version**. A TCP stack's shape identifies only a
//! family (it could not separate two kernels eleven releases apart on two
//! labelled hosts), and a service banner names a distribution release at best.
//!
//! ## What is parsed
//!
//! Every byte comes from a remote host: each tag is checked, each length is
//! checked against the bytes that follow, and the returned identifier must be
//! the one asked for. A reply that disagrees anywhere yields nothing.
//!
//! **Only the shape this engine's probe draws** is parsed: an SNMPv1
//! `GetResponse` whose bindings carry the description as an octet string and the
//! identifier as an object identifier, in either order. A general ASN.1 decoder
//! would be attack surface for constructs the probe cannot elicit.
//!
//! ## The value is a field
//!
//! The corpus writes rules against the decoded string, with
//! `context = "snmp.sys_description"` and patterns anchored on the text. See
//! [`extract`](super::extract).

/// The identifier this engine's probe asks for: `1.3.6.1.2.1.1.1.0`, sysDescr
/// instance zero, as BER packs it, the first two arcs into one byte, `1 * 40 +
/// 3 = 0x2b`.
///
/// Checked against the reply, since an agent may answer with a binding for
/// something else.
const SYS_DESCR_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

/// `sysObjectID.0`, `1.3.6.1.2.1.1.2.0`, encoded the same way.
///
/// RFC 1213 defines it as the vendor's own identifier for the box, so it names
/// a model outright.
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
/// RFC 1213 bounds the object at 255 octets. A longer value is refused, since a
/// truncated description would match unpredictably.
const MAX_SYS_DESCR: usize = 255;

/// A cursor over BER tag/length/value triples.
///
/// Every read is bounds-checked and returns `None` on malformed input; the bytes
/// come from an unauthenticated peer.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Reads one triple, returning its tag and its value, and advances past it.
    ///
    /// The length is checked against what actually follows.
    fn read(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.bytes.split_first()?;
        let (&first, rest) = rest.split_first()?;

        let (length, rest) = if first < 0x80 {
            // Short form.
            (usize::from(first), rest)
        } else {
            // Long form: the low seven bits count the length's own bytes. More
            // than four is past any datagram.
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
/// The corpus matches it alone and joined to the description. Every binding is
/// walked, since an agent orders its answers as it likes.
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
/// Every subidentifier is base-128 with the top bit set on all but its last
/// byte; one whose continuation never ends is truncated and yields nothing. The
/// first packs two arcs as `40 * x + y` (X.690 §8.19.4), where `y` is below
/// forty under roots 0 and 1 and unbounded under 2. It is read as a full
/// subidentifier and unpacked by range, since under 2 it can exceed a byte.
fn object_identifier(encoded: &[u8]) -> Option<String> {
    let mut subidentifiers: Vec<u64> = Vec::new();
    let mut value: u64 = 0;
    let mut open = false;
    for byte in encoded {
        // Refused before the shift can wrap; no assigned arc is this long.
        value = value
            .checked_mul(128)?
            .checked_add(u64::from(byte & 0x7f))?;
        open = byte & 0x80 != 0;
        if !open {
            subidentifiers.push(value);
            value = 0;
        }
    }
    if open {
        return None;
    }

    let (&packed, rest) = subidentifiers.split_first()?;
    let (root, second) = match packed {
        0..40 => (0, packed),
        40..80 => (1, packed - 40),
        _ => (2, packed - 80),
    };
    let arcs: Vec<String> = [root, second]
        .into_iter()
        .chain(rest.iter().copied())
        .map(|arc| arc.to_string())
        .collect();
    Some(arcs.join("."))
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
/// `GetResponse`; the response must carry the three integers a PDU begins with
/// and then its bindings; and one binding must name [`SYS_DESCR_OID`] and carry
/// an octet string. Error PDUs, traps, and values of another type are refused.
///
/// Every binding is examined, since an agent orders its answers as it likes.
///
/// The string must be valid UTF-8; `sysDescr` is a `DisplayString`, which is
/// ASCII.
pub(crate) fn sys_descr(datagram: &[u8]) -> Option<&str> {
    let mut bindings = bindings_of(datagram)?;

    while let Some((tag::SEQUENCE, binding)) = bindings.read() {
        let mut binding = Reader::new(binding);
        // An agent may answer with a binding for something not asked about.
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

    /// One BER triple with a short-form length.
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, value.len() as u8];
        out.extend_from_slice(value);
        out
    }

    /// A reply carrying one binding.
    fn get_response(oid: &[u8], value_tag: u8, value: &[u8]) -> Vec<u8> {
        response(&[(oid, value_tag, value)])
    }

    /// The reply an agent sends to this engine's probe, carrying `bindings` in
    /// the order given. Assembled from RFC 1157 §4.1 independently of this
    /// module, so a misreading here cannot shape the fixture.
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
    /// The 8072 arc takes two base-128 bytes.
    const NET_SNMP_LINUX: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xbf, 0x08, 0x03, 0x02, 0x0a];

    /// A reply answering both of the probe's questions, in either order.
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

    /// An agent's own account of its kernel.
    #[test]
    fn a_unix_agent_yields_the_kernel_it_is_running() {
        let uname = "Linux pi 6.1.0-rpi7-rpi-v8 #1 SMP PREEMPT Debian 1:6.1.63-1+rpt1 aarch64";
        assert_eq!(sys_descr(&sys_descr_reply(uname)), Some(uname));
    }

    /// A well-formed binding for another object is not a system description.
    #[test]
    fn a_binding_for_another_object_is_refused() {
        // sysUpTime.0
        let other = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00];
        let reply = get_response(other, tag::OCTET_STRING, b"Linux something");
        assert_eq!(sys_descr(&reply), None);
    }

    /// A value of another type is refused.
    #[test]
    fn a_value_that_is_not_a_string_is_refused() {
        let reply = get_response(SYS_DESCR_OID, 0x02, &[0x01, 0x02]);
        assert_eq!(sys_descr(&reply), None);
    }

    /// Each reader finds its answer in either binding order.
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
    /// Neither reader panics on a mangled reply, and what either returns has the
    /// promised shape: a description within the bound, an identifier in dotted
    /// decimal. `0x06` is among the corrupting bytes because it is the OID tag.
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

    /// Any input renders as nothing or as dotted decimal, without panicking.
    /// Deterministic, for the reason
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

    /// An identifier renders as the arcs it was encoded from, whatever they
    /// are.
    ///
    /// X.690 §8.19.4 packs the first two arcs as `40 * x + y`, bounding `y` only
    /// under roots 0 and 1. Split naively by forty, `2.45` would render as `3.5`
    /// and `2.999` as `3.16.55`. Hand-encoded cases plus a deterministic random
    /// run.
    #[test]
    fn an_identifier_renders_as_the_arcs_it_was_encoded_from() {
        /// X.690 §8.19: base 128, most significant group first, the top bit set
        /// on every byte of a subidentifier but its last.
        fn encode(arcs: &[u64]) -> Vec<u8> {
            let packed = std::iter::once(40 * arcs[0] + arcs[1]).chain(arcs[2..].iter().copied());
            let mut encoded = Vec::new();
            for subidentifier in packed {
                let mut groups = vec![(subidentifier & 0x7f) as u8];
                let mut rest = subidentifier >> 7;
                while rest > 0 {
                    groups.push((rest & 0x7f) as u8 | 0x80);
                    rest >>= 7;
                }
                encoded.extend(groups.iter().rev());
            }
            encoded
        }

        let dotted = |arcs: &[u64]| {
            arcs.iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(".")
        };

        let mut cases: Vec<Vec<u64>> = vec![
            vec![0, 0],
            vec![0, 39],
            vec![1, 3, 6, 1, 4, 1, 8072, 3, 2, 10],
            vec![1, 39, 1],
            vec![2, 0],
            vec![2, 39],
            vec![2, 40],
            vec![2, 45],
            vec![2, 47],
            vec![2, 48],
            vec![2, 999, 1],
            vec![2, 16, 840, 1, 113_883],
        ];

        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2_000 {
            let root = next() % 3;
            // Under the first two roots the second arc stays below forty.
            let second = if root < 2 {
                next() % 40
            } else {
                next() % 1_000_000
            };
            let mut arcs = vec![root, second];
            arcs.extend((0..next() % 6).map(|_| next() >> (next() % 64)));
            cases.push(arcs);
        }

        for arcs in cases {
            let encoded = encode(&arcs);
            assert_eq!(
                object_identifier(&encoded).as_deref(),
                Some(dotted(&arcs).as_str()),
                "encoded as {encoded:02x?}"
            );
        }
    }

    /// An identifier cut inside an arc yields nothing, wherever it is cut. An arc
    /// too long to hold is refused.
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

        // Ten continuation bytes are seventy bits.
        let mut endless = vec![0x2b];
        endless.extend([0xff; 10]);
        endless.push(0x7f);
        assert_eq!(object_identifier(&endless), None);
    }

    /// The walk survives truncation at every offset, every single-byte
    /// corruption, and unrelated messages.
    #[test]
    fn nothing_a_peer_can_send_makes_this_panic() {
        let whole = sys_descr_reply("Linux test 6.1.0 aarch64");

        // Truncated at every possible offset.
        for cut in 0..whole.len() {
            let _ = sys_descr(&whole[..cut]);
        }

        // Every single-byte corruption, at every offset, including tag and length
        // bytes at every nesting depth.
        for offset in 0..whole.len() {
            for byte in [0x00u8, 0x01, 0x30, 0x7f, 0x80, 0x84, 0xa2, 0xff] {
                let mut mutated = whole.clone();
                mutated[offset] = byte;
                let _ = sys_descr(&mutated);
            }
        }

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

    /// A length header claiming more than the datagram holds is refused.
    #[test]
    fn a_length_running_past_the_datagram_yields_nothing() {
        let mut reply = sys_descr_reply("Linux test");
        reply[1] = 0x7f; // the outer sequence now claims far more than follows
        assert_eq!(sys_descr(&reply), None);
    }

    /// RFC 1213 bounds `sysDescr` at 255 octets; a longer one is refused.
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

    /// A `GetRequest` (this engine's own probe, reflected back) is not an answer.
    #[test]
    fn a_request_is_not_an_answer() {
        let mut reply = sys_descr_reply("Linux test");
        let pdu = reply
            .iter()
            .position(|&b| b == tag::GET_RESPONSE)
            .expect("the fixture carries a response PDU");
        reply[pdu] = 0xa0; // GetRequest
        assert_eq!(sys_descr(&reply), None);
    }

    /// **Every way a length can lie, refused rather than believed.**
    ///
    /// Each row is a shape that has broken real ASN.1 parsers: the indefinite
    /// form, an oversized long form, a length past the end of the datagram, and
    /// a header cut off in the middle.
    #[test]
    fn no_length_encoding_reads_past_the_datagram() {
        let cases: &[(&str, &[u8])] = &[
            // 0x80 is the indefinite form; read as length zero, a reader loops.
            ("indefinite length", &[0x30, 0x80, 0x02, 0x01, 0x00]),
            // Five length bytes is more than any datagram needs.
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

    /// The walk terminates on deeply nested input.
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
    /// Deterministic, so a failure is reproducible from the seed. It lives here
    /// because `snmp` is `pub(crate)` and cannot be driven from `fuzz/`.
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

    /// A message that is nearly a GetResponse stays safe under every single-byte
    /// change.
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
