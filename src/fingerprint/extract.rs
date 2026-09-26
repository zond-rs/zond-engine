// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Turning a response into the text the corpus is written against
//!
//! A signature matches a field, not a reply. Every rule declares the
//! `context` it reads, `ssh.banner`, `snmp.sys_description`,
//! `http.server_header`, and anchors its pattern on that field's text alone.
//! Something has to produce that field from what actually arrived, and this is
//! where that happens.
//!
//! ## The mistake this module exists to stop repeating
//!
//! It has been made twice, silently, and cost a working corpus both times.
//!
//! RFC 4253 §4.2 gives an SSH identification line as
//! `SSH-protoversion-softwareversion SP comments`, and the corpus anchors on
//! the software identifier: `^OpenSSH_(9\.2p1) (Debian-\d\d?\+deb12u\d+)$`. Fed
//! the whole line, that `^` can never match, so **every release-naming SSH rule
//! was unreachable**, and a host announcing `SSH-2.0-OpenSSH_9.2p1
//! Debian-2+deb12u10` was reported as `Linux` while the corpus held a rule
//! mapping that exact string to Debian 12.
//!
//! SNMP is the same shape one protocol over: `sysDescr` is a BER-encoded octet
//! string inside a `GetResponse`, and the rules match the decoded text. A
//! datagram handed to them matches nothing.
//!
//! Both failures look identical from outside, a scan that names a family and
//! stops, and neither shows up as a broken test, because a test that feeds the
//! matcher a field directly passes while the engine feeds it a whole response.
//!
//! ## Keyed on the port, because that is what is known
//!
//! [`from_datagram`] selects a decoder by destination port, exactly as
//! [`payload`](crate::scanner::payload) selects a probe by one. It is the only
//! thing known about a UDP target before anything answers, which is the whole
//! difficulty of UDP scanning, and pairing the two on the same key keeps the
//! probe and the reading of its answer from drifting apart.

use std::borrow::Cow;

use crate::model::host::HostName;
use crate::model::port::Protocol;

/// A reply as the text the corpus matches, every byte of it kept.
///
/// UTF-8 wherever the bytes are UTF-8, and every other byte as the code point
/// of the same value, which is how Latin-1 reads it. So a pattern's `\x82`
/// means the byte 0x82, as it does in the corpora the rules were written for,
/// and a page that names itself in UTF-8 still reads as the words it wrote.
///
/// Both halves are needed. A binary protocol is identified by its bytes, and
/// the answers that carry one high byte in a fixed place are exactly the ones
/// a byte pattern is for: a NetBIOS session reply is one byte of type, a telnet
/// negotiation opens on 0xFF, an Active Directory message states its length in
/// four bytes behind 0x84. A decoder that replaces what is not UTF-8 turns
/// every one of those into the same replacement character, and each rule
/// written for them matches nothing. A decoder that read everything as Latin-1
/// would keep them and garble every UTF-8 title and version string instead.
///
/// What this cannot do is tell a binary reply whose high bytes happen to form
/// a UTF-8 sequence from text. Such a pair reads as one character where a byte
/// pattern expects two. The rules here are written so they never meet that
/// case: a high byte with a byte below 0x80 on either side of it belongs to no
/// sequence, since a sequence needs a lead byte from 0xC2 up before a
/// continuation and a continuation from 0x80 up after a lead, and the bytes
/// 0xC0, 0xC1 and 0xF5 to 0xFF belong to none anywhere. A type or length field
/// in a binary header is a high byte between low ones.
pub(crate) fn reply_text(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        text.extend(chunk.invalid().iter().map(|&byte| char::from(byte)));
    }
    text
}

/// The bytes [`reply_text`] read `text` from, for a reader that decodes a
/// reply as structure after it has become text.
///
/// Exact wherever the text says how it was read. A character from U+0100 up
/// can only have been a UTF-8 sequence, and one below U+0080 only its own
/// byte. What is ambiguous is U+0080 to U+00FF, which is either a byte that
/// belonged to no sequence or a two-byte sequence led by 0xC2 or 0xC3, and it
/// is read back as the single byte. That is right for every high byte a binary
/// header carries, for the reason [`reply_text`] gives, and wrong only for text
/// inside the reply that spells a Latin-1 letter in UTF-8. A decoder handed
/// such a reply finds a length one short of what it states and stops there,
/// which is the answer it gives any reply it cannot read.
pub(crate) fn reply_bytes(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(text.len());
    for character in text.chars() {
        match u8::try_from(u32::from(character)) {
            Ok(byte) => bytes.push(byte),
            Err(_) => {
                let mut buffer = [0; 4];
                bytes.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    bytes
}

/// The texts one banner should be matched against, most complete first.
///
/// Usually just the banner. A structured one also yields the fields the corpus
/// anchors on, and both are offered rather than the field replacing the line: a
/// rule may legitimately be written against either, and which is more specific
/// is a question for the matcher's own ranking rather than for this.
///
/// Borrowed wherever a field is a slice of the banner. The one exception is an
/// HTML title, whose whitespace is normalised before it can be matched.
pub(crate) fn texts(banner: &str) -> Vec<Cow<'_, str>> {
    let mut texts = vec![Cow::Borrowed(banner)];
    texts.extend(super::ssh::software_version(banner).map(Cow::Borrowed));
    texts.extend(super::http::corpus_fields(banner));
    texts.extend(
        super::sip::corpus_fields(banner)
            .into_iter()
            .map(Cow::Borrowed),
    );
    texts
}

/// The texts a UDP reply carries, where this engine knows how to read one.
///
/// Empty for a port whose replies it cannot decode, which is most of them: a
/// datagram nothing can read is still proof the port is open, and that is what
/// the scan already took from it.
///
/// More than one where a reply answers more than one question. An SNMP agent is
/// asked for its description and its object identifier in a single datagram, and
/// the corpus has rules against each alone and against the two joined, so all
/// three are offered and the matcher ranks them. They are separate texts rather
/// than one, because 570 of the 579 description rules anchor at the start and a
/// joined string would reach none of them.
///
/// Owned because decoding is not always a borrow: a value lifted out of a binary
/// encoding has no text in the datagram to point at.
pub(crate) fn from_datagram(port: u16, datagram: &[u8]) -> Vec<String> {
    match port {
        // On a Unix host `sysDescr` is the output of `uname -a`, which names the
        // exact kernel, and `sysObjectID` is the vendor's own name for the box.
        // See [`snmp`](super::snmp).
        161 => {
            let description = super::snmp::sys_descr(datagram);
            let object_id = super::snmp::sys_object_id(datagram);

            let mut texts = Vec::new();
            texts.extend(description.map(ToOwned::to_owned));
            if let Some(object_id) = object_id {
                if let Some(description) = description {
                    texts.push(format!("{object_id} {description}"));
                }
                texts.push(object_id);
            }
            texts
        }
        // The `version.bind` probe the corpus registers for this port draws a
        // TXT answer holding the nameserver's own account of its build.
        53 => crate::protocols::dns::first_text_answer(datagram)
            .into_iter()
            .collect(),
        // A device-info answer carries one `key=value` per character-string, and
        // a rule reads one of them: `model=Mac16,10` and `osxvers=25` are two
        // separate claims about the same machine.
        5353 => crate::protocols::mdns::text_records(datagram).unwrap_or_default(),
        // An M-SEARCH answer is HTTP-shaped, and the UPnP Device Architecture
        // fixes what its `SERVER` value holds: the operating system, the UPnP
        // version, and the product, each with its own version.
        //
        //   SERVER: Linux/3.14.0 UPnP/1.0 MiniUPnPd/1.9
        //           └─ OS ────┘  └─ UPnP ┘ └─ product ┘
        //
        // The value alone rather than the response it came in. Handing back the
        // whole thing would make it a banner beginning `HTTP/`, which is what
        // [`HttpHeadersAnalyzer`](super::http) gates on, and a UPnP responder
        // would be reported as a web server on 1900. The header is the half that
        // identifies anything.
        //
        // `ST` is not offered with it. The probe asks `ssdp:all` and a device
        // answers it with one datagram per service it exposes; this exchange
        // reads one, so the `ST` in hand is whichever the device happened to
        // send first, and that is `upnp:rootdevice` on nearly everything.
        // Reading a device type out of it would be reading the order the
        // datagrams left in.
        1900 => match std::str::from_utf8(datagram) {
            Ok(text) => super::http::server_value(text)
                .map(ToOwned::to_owned)
                .into_iter()
                .collect(),
            Err(_) => Vec::new(),
        },
        // A KRB-ERROR is proof of a KDC. The realm it names is not text for
        // the corpus but one of the host's names; see `names_from_datagram`.
        88 => super::framed::kerberos_error(datagram)
            .into_iter()
            .collect(),
        // What a concentrator calls itself, and what it calls the machine.
        1701 => super::framed::l2tp_control(datagram).into_iter().collect(),
        // The corpus registers two probes here. The client request proves the
        // port is open and carries nothing to read; the mode 6 control message
        // draws the variables the daemon describes itself with.
        123 => super::framed::ntp_control_variables(datagram)
            .into_iter()
            .collect(),
        // The gateway's own vendor ids, which is what separates one IPsec
        // implementation from another.
        500 | 4500 => super::framed::ike_response(datagram).into_iter().collect(),
        // What a STUN server calls itself, where it says.
        3478 => super::framed::stun_binding(datagram).into_iter().collect(),
        // Every program the host has registered, with the port each is on.
        111 => super::framed::rpc_program_dump(datagram)
            .into_iter()
            .collect(),
        // The probe asks for a version nothing implements, so the mismatch that
        // comes back names the versions the server does support.
        2049 => super::framed::rpc_version_range(datagram)
            .into_iter()
            .collect(),
        // What a management controller says about how it may be logged into,
        // before anything has logged into it.
        623 => super::framed::ipmi_auth_capabilities(datagram)
            .into_iter()
            .collect(),
        // A display manager that answers this accepts remote X logins from the
        // network, whatever the software behind it turns out to be.
        177 => super::framed::xdmcp_willing(datagram).into_iter().collect(),
        // Either the information a game server publishes, or the challenge it
        // now asks for instead. Both say what is listening.
        27015 => super::framed::source_engine(datagram).into_iter().collect(),
        // A master answers with a page of other hosts' servers, which says what
        // it is and nothing about itself.
        27010..=27014 => super::framed::steam_master_list(datagram)
            .map(ToOwned::to_owned)
            .into_iter()
            .collect(),
        // The status line a Bedrock server builds from its own configuration,
        // once the reply's magic has confirmed it is RakNet at all.
        19132 => super::framed::raknet_pong(datagram)
            .map(ToOwned::to_owned)
            .into_iter()
            .collect(),
        // A device with no version string anywhere still lists the resources it
        // exposes, which is what says what it is for.
        5683 => super::framed::coap_payload(datagram)
            .map(ToOwned::to_owned)
            .into_iter()
            .collect(),
        // The Browser's whole answer is a list of the instances on the host,
        // each with its build number and the TCP port it listens on.
        1434 => super::framed::sql_server_browser(datagram)
            .map(ToOwned::to_owned)
            .into_iter()
            .collect(),
        // Behind the frame is the same `VERSION` line the TCP probe draws, so
        // the rule written for that banner reads this one too.
        11211 => super::framed::memcached_udp(datagram)
            .map(ToOwned::to_owned)
            .into_iter()
            .collect(),
        // A ProbeMatches names what kind of thing answered, and the prefixes are
        // stripped on the way out because no two responders agree on them.
        3702 => super::framed::wsd_types(datagram).into_iter().collect(),
        // A SIP endpoint answers OPTIONS over UDP far more often than over TCP,
        // and names itself in the same two headers either way.
        5060 | 5061 => match std::str::from_utf8(datagram) {
            Ok(text) => super::sip::corpus_fields(text)
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            Err(_) => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// The texts a TCP reply carries, where this engine knows how to read one.
///
/// The counterpart to [`from_datagram`], keyed the same way and for the same
/// reason. Almost every TCP service answers in text a banner grab can hand
/// straight to the matcher, so this is empty for nearly all of them and the
/// [`reply_text`] beside it does the work.
///
/// It exists for the ones that do not. An RPC, Kerberos or DNS reply over TCP
/// hides the message a datagram would carry behind framing of its own, a TDS
/// pre-login states its version in binary, and an RTSP response is declined
/// by the HTTP reader, so each wants reading as what it is.
///
/// Offered *beside* the whole reply rather than instead of it, so nothing that
/// already matched stops matching.
pub(crate) fn from_stream(port: u16, bytes: &[u8]) -> Vec<String> {
    match port {
        // An RTSP status line is not an HTTP one, so the HTTP reader declines
        // the response and the `Server` value would go unread.
        554 | 8554 => super::framed::rtsp_server(bytes).into_iter().collect(),
        // The dump a datagram would carry, behind the record marks TCP adds.
        111 => super::framed::rpc_record(bytes)
            .and_then(|record| super::framed::rpc_program_dump(&record))
            .into_iter()
            .collect(),
        // The mismatch a datagram would carry, behind the same marks.
        2049 => super::framed::rpc_record(bytes)
            .and_then(|record| super::framed::rpc_version_range(&record))
            .into_iter()
            .collect(),
        // The KRB-ERROR a datagram would carry, behind the four-byte length
        // RFC 4120 §7.2.2 puts in front of a message over TCP.
        88 => bytes
            .get(4..)
            .and_then(super::framed::kerberos_error)
            .into_iter()
            .collect(),
        // The answer a datagram would carry, behind the two-byte length RFC
        // 1035 §4.2.2 puts in front of a message over TCP.
        53 => bytes
            .get(2..)
            .and_then(crate::protocols::dns::first_text_answer)
            .into_iter()
            .collect(),
        // What the server says its build is, before any login.
        1433 => super::framed::tds_version(bytes).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// The names a UDP reply from `port` gives for the machine that sent it, read
/// from the reply's structure.
///
/// Apart from [`from_datagram`] because what it returns is not matched. A rule
/// that captures part of a text writes the capture into a service's
/// description, and a description reaches every report unmasked, so a name
/// that travelled as text would leak from a report redacted to hide it. A
/// [`HostName`] is masked wherever a hostname is.
pub(crate) fn names_from_datagram(port: u16, datagram: &[u8]) -> Vec<HostName> {
    match port {
        88 => super::framed::kerberos_realm(datagram)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// The names a TCP reply from `port` gives for the machine that sent it: the
/// counterpart to [`names_from_datagram`], as [`from_stream`] is to
/// [`from_datagram`].
pub(crate) fn names_from_stream(port: u16, bytes: &[u8]) -> Vec<HostName> {
    match port {
        // Behind the four-byte length RFC 4120 §7.2.2 puts in front of a
        // message over TCP.
        88 => bytes
            .get(4..)
            .and_then(super::framed::kerberos_realm)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether this engine can read a reply from `port` over `protocol` at all.
///
/// What decides whether a UDP port is worth a second datagram: there is no
/// point dialling one whose answer nothing here could turn into text. A TCP
/// port always qualifies, every one of them can be read for a banner.
pub(crate) fn reads(port: u16, protocol: Protocol) -> bool {
    match protocol {
        Protocol::Tcp => true,
        Protocol::Udp => DECODED_UDP_PORTS.contains(&port),
        // An INIT scan learns that a port answers and nothing about what is
        // behind it, and there is no client here to ask it a second time.
        Protocol::Sctp => false,
    }
}

/// What kind of text a reply from `port` over `protocol` is, for weighing what a
/// rule matched against it says about the *host*.
///
/// Almost everything a scan reads is a banner: a string a daemon carries from
/// its own build, which is why [`ceiling`](super::os::ceiling) holds it below a
/// stack reading. SNMP is the exception this exists for, `sysDescr` is the
/// machine's management agent describing the machine, and it is keyed on the
/// same port [`from_datagram`] decodes, so the decoder and the weight put on
/// what it decodes cannot drift apart.
pub(crate) fn attested_by(port: u16, protocol: Protocol) -> crate::model::host::OsSource {
    match (protocol, port) {
        (Protocol::Udp, 161) => crate::model::host::OsSource::SnmpAgent,
        (Protocol::Udp, 5353) => crate::model::host::OsSource::MdnsResponder,
        _ => crate::model::host::OsSource::ServiceBanner,
    }
}

/// The UDP ports [`from_datagram`] has a decoder for.
///
/// Stated rather than derived, because a decoder cannot be asked whether it
/// would succeed without a datagram to try it on, and this question is asked
/// before one has been drawn.
const DECODED_UDP_PORTS: &[u16] = &[
    53, 88, 111, 123, 161, 177, 500, 623, 1434, 1701, 1900, 2049, 3478, 3702, 4500, 5060, 5061,
    5353, 5683, 11211, 19132, 27010, 27011, 27012, 27013, 27014, 27015,
];

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

    /// The whole line and the field, both offered, because a rule may be
    /// written against either and only the matcher can say which fits better.
    #[test]
    fn a_structured_banner_offers_its_field_as_well_as_itself() {
        let texts = texts("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10");
        assert_eq!(
            texts,
            [
                "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10",
                "OpenSSH_9.2p1 Debian-2+deb12u10",
            ]
        );
    }

    /// An unstructured one offers itself and nothing else, rather than a second
    /// text that would only cost the matcher a pass.
    #[test]
    fn an_ordinary_banner_offers_only_itself() {
        assert_eq!(
            texts("220 mail.example ESMTP Postfix"),
            ["220 mail.example ESMTP Postfix"]
        );
    }

    /// A byte that is not part of any UTF-8 sequence reaches the matcher as
    /// the code point of its own value, which is what a pattern's `\x82`
    /// names.
    #[test]
    fn a_byte_outside_utf8_reads_as_its_own_code_point() {
        assert_eq!(reply_text(b"\x82\x00\x00\x00"), "\u{82}\0\0\0");
        assert_eq!(reply_text(b"\xff\xfd\x18"), "\u{ff}\u{fd}\u{18}");
    }

    /// Text that is UTF-8 reads as the words it wrote, beside a byte that is
    /// not, so a page titled in UTF-8 is not garbled for the sake of a binary
    /// protocol.
    #[test]
    fn utf8_text_reads_as_written_beside_a_byte_that_is_not() {
        assert_eq!(reply_text("Überblick".as_bytes()), "Überblick");
        assert_eq!(reply_text(b"caf\xe9 \xc3\xa9t\xc3\xa9"), "café été");
    }

    /// A port with no decoder yields nothing rather than the datagram as text.
    /// A reply nothing can read is still proof the port is open, which is what
    /// the scan already took from it.
    #[test]
    fn a_datagram_from_an_unreadable_port_yields_nothing() {
        assert!(from_datagram(9_999, b"anything at all").is_empty());
        assert!(!reads(9_999, Protocol::Udp));
    }

    /// Every port the corpus sends a UDP probe to has a decoder for the answer,
    /// or is named here as one that does not.
    ///
    /// The two lists are authored in different places for different reasons.
    /// `assets/fingerprinting` says what to send, [`DECODED_UDP_PORTS`] says what
    /// can be read back, and nothing but this connects them: a UDP probe
    /// authored for a port with no decoder draws a reply the fingerprinter
    /// throws away, and the only symptom is a service that is never identified.
    ///
    /// The sibling test on the service side
    /// (`every_port_with_a_signature_is_a_port_the_default_scan_reaches`) holds
    /// the same kind of join and is what this is modelled on.
    #[test]
    fn a_udp_probe_either_has_a_decoder_or_is_listed_as_having_none() {
        use crate::fingerprint::SignatureDb;

        /// Ports the corpus probes over UDP for *liveness* rather than for
        /// identification. A UDP probe is what establishes the port is open at
        /// all, since UDP offers no handshake to infer it from, so a probe here
        /// earns its place without a decoder. Each entry is a decoder somebody
        /// could write.
        // 162 is the trap receiver. snmp.toml claims both numbers, so the probe
        // reaches it, and a receiver does not answer a get.
        const PROBED_BUT_NOT_DECODED: &[u16] = &[137, 162];

        let db = SignatureDb::global();
        let probed: Vec<u16> = (0..=u16::MAX)
            .filter(|port| !db.udp_probe_payloads(*port).is_empty())
            .collect();

        for port in &probed {
            assert!(
                DECODED_UDP_PORTS.contains(port) || PROBED_BUT_NOT_DECODED.contains(port),
                "the corpus sends a UDP probe to {port} and nothing here reads the \
                 answer. Write a decoder in `from_datagram`, or list the port in \
                 PROBED_BUT_NOT_DECODED to say the probe is for liveness alone."
            );
        }

        for port in DECODED_UDP_PORTS {
            assert!(
                probed.contains(port),
                "there is a decoder for {port} and the corpus sends it nothing, so \
                 the decoder can never run"
            );
        }
        for port in PROBED_BUT_NOT_DECODED {
            assert!(
                probed.contains(port),
                "{port} is listed as probed without a decoder and is not probed"
            );
        }
    }

    /// And a port that has one is worth the second datagram it costs.
    #[test]
    fn a_port_with_a_decoder_is_worth_dialling() {
        assert!(reads(161, Protocol::Udp));
        assert!(reads(53, Protocol::Udp));
        assert!(
            reads(22, Protocol::Tcp),
            "every TCP port can be read for a banner"
        );
        assert!(
            reads(123, Protocol::Udp),
            "a mode 6 control response is read for the variables a daemon reports"
        );
        assert!(
            !reads(137, Protocol::Udp),
            "a NetBIOS name table is read as a host role rather than as service text"
        );
    }
}

#[cfg(test)]
mod http_fields {
    use crate::fingerprint::SignatureDb;
    use crate::model::port::Protocol;

    /// The whole point of offering a field separately: a corpus rule anchors on
    /// one header value at both ends, so it can never match the response that
    /// carried it.
    fn identify(response: &str) -> Option<String> {
        SignatureDb::global()
            .identify(80, Protocol::Tcp, response)
            .and_then(|evidence| evidence.product)
    }

    #[test]
    fn a_www_authenticate_realm_names_the_product_behind_it() {
        let response = "HTTP/1.1 401 Unauthorized\r\n\
                        WWW-Authenticate: Basic realm=\"Transmission\"\r\n\
                        \r\n";
        assert_eq!(identify(response).as_deref(), Some("Transmission"));
    }

    #[test]
    fn a_set_cookie_name_names_the_product_that_set_it() {
        let response = "HTTP/1.1 200 OK\r\n\
                        Set-Cookie: __cfuid=1337; path=/\r\n\
                        \r\n";
        assert_eq!(
            identify(response).as_deref(),
            Some("CloudFlare Load Balancer")
        );
    }

    #[test]
    fn a_document_title_names_the_product_serving_it() {
        let response = "HTTP/1.1 403 Forbidden\r\n\
                        Content-Type: text/html\r\n\
                        \r\n\
                        <html><head><title>ERROR: The request could not be satisfied</title></head></html>";
        assert_eq!(
            identify(response).as_deref(),
            Some("CloudFront Load Balancer")
        );
    }

    /// A title runs across lines in real markup, and the corpus rules are
    /// written against one normalised line.
    #[test]
    fn a_title_broken_across_lines_still_matches_a_rule_written_on_one() {
        let response = "HTTP/1.1 403 Forbidden\r\n\r\n\
                        <html><head><title>ERROR: The request\n   could not be satisfied</title></head>";
        assert_eq!(
            identify(response).as_deref(),
            Some("CloudFront Load Balancer")
        );
    }

    /// Every other banner pays one prefix comparison and nothing else.
    #[test]
    fn a_banner_that_is_not_http_yields_no_fields() {
        assert!(super::texts("220 ProFTPD 1.3.5 Server ready").len() == 1);
    }
}

#[cfg(test)]
mod version_bind {
    use crate::fingerprint::SignatureDb;
    use crate::model::port::Protocol;

    /// A CHAOS TXT response to `version.bind`, built the way a nameserver
    /// answers one: the question echoed back, then one TXT answer whose single
    /// character-string is the build.
    fn response(version: &str) -> Vec<u8> {
        let mut packet = vec![
            0x00, 0x00, // id
            0x84, 0x00, // response, authoritative
            0x00, 0x01, // one question
            0x00, 0x01, // one answer
            0x00, 0x00, 0x00, 0x00,
        ];
        // QNAME version.bind, CHAOS TXT
        packet.extend_from_slice(b"\x07version\x04bind\x00");
        packet.extend_from_slice(&[0x00, 0x10, 0x00, 0x03]);
        // The answer, its owner name a pointer back to the question.
        packet.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let rdata_len = (version.len() + 1) as u16;
        packet.extend_from_slice(&rdata_len.to_be_bytes());
        packet.push(version.len() as u8);
        packet.extend_from_slice(version.as_bytes());
        packet
    }

    #[test]
    fn the_txt_answer_is_read_out_of_the_datagram() {
        let decoded = super::from_datagram(53, &response("9.9.5-11ubuntu1.1-Ubuntu"));
        assert_eq!(decoded, vec!["9.9.5-11ubuntu1.1-Ubuntu".to_string()]);
    }

    /// The probe already went out over both transports and the answer was
    /// discarded. This is the rule it now reaches.
    #[test]
    fn a_bind_build_string_names_the_product_and_its_version() {
        let texts = super::from_datagram(53, &response("9.9.5-11ubuntu1.1-Ubuntu"));
        let banner = texts.first().expect("the TXT answer decodes");
        let evidence = SignatureDb::global()
            .identify(53, Protocol::Udp, banner)
            .expect("the corpus names it");
        assert_eq!(evidence.product.as_deref(), Some("BIND"));
    }

    #[test]
    fn a_datagram_that_is_not_a_dns_response_decodes_to_nothing() {
        assert!(super::from_datagram(53, b"not a dns message at all").is_empty());
        // A query rather than a response, which is what a sniffed packet is.
        let mut query = response("9.1.1");
        query[2] = 0x00;
        assert!(super::from_datagram(53, &query).is_empty());
    }

    #[test]
    fn port_53_is_now_worth_a_second_datagram() {
        assert!(super::reads(53, Protocol::Udp));
    }
}

#[cfg(test)]
mod sys_object_id {
    use crate::fingerprint::SignatureDb;
    use crate::model::port::Protocol;

    /// A GetResponse carrying both bindings the probe now asks for, in the order
    /// an agent would answer them.
    fn response(object_id: &[u8], description: &str) -> Vec<u8> {
        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = vec![tag, value.len() as u8];
            out.extend_from_slice(value);
            out
        }

        let descr_oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        let objid_oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00];

        let mut first = tlv(0x06, &descr_oid);
        first.extend(tlv(0x04, description.as_bytes()));
        let mut second = tlv(0x06, &objid_oid);
        second.extend(tlv(0x06, object_id));

        let mut bindings = tlv(0x30, &first);
        bindings.extend(tlv(0x30, &second));

        let mut pdu = tlv(0x02, b"zond");
        pdu.extend(tlv(0x02, &[0x00]));
        pdu.extend(tlv(0x02, &[0x00]));
        pdu.extend(tlv(0x30, &bindings));

        let mut message = tlv(0x02, &[0x00]);
        message.extend(tlv(0x04, b"public"));
        message.extend(tlv(0xa2, &pdu));
        tlv(0x30, &message)
    }

    /// `1.3.6.1.4.1.8072.3.2.1`. The 8072 arc is two base-128 bytes, which is
    /// the case a naive renderer gets wrong.
    const NET_SNMP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xbf, 0x08, 0x03, 0x02, 0x01];

    #[test]
    fn the_object_identifier_renders_as_dotted_decimal() {
        let texts = super::from_datagram(161, &response(NET_SNMP, "Linux zond 6.1.0"));
        assert!(
            texts.contains(&"1.3.6.1.4.1.8072.3.2.1".to_string()),
            "got {texts:?}"
        );
    }

    /// Three texts, because the corpus has rules against each shape. The
    /// description stays a text of its own: 570 of the 579 rules written against
    /// it anchor at the start, so a joined string reaches none of them.
    #[test]
    fn the_description_is_offered_whole_beside_the_joined_form() {
        let texts = super::from_datagram(161, &response(NET_SNMP, "Linux zond 6.1.0"));
        assert_eq!(
            texts,
            vec![
                "Linux zond 6.1.0".to_string(),
                "1.3.6.1.4.1.8072.3.2.1 Linux zond 6.1.0".to_string(),
                "1.3.6.1.4.1.8072.3.2.1".to_string(),
            ]
        );
    }

    /// The reason the identifier is offered as a text of its own: sixteen of the
    /// forty-two rules written against it match the bare OID and nothing else.
    #[test]
    fn a_bare_object_identifier_names_the_agent_behind_it() {
        let texts = super::from_datagram(161, &response(NET_SNMP, "an agent that says little"));
        let bare = texts.last().expect("the identifier is offered last");

        let evidence = SignatureDb::global()
            .identify(161, Protocol::Udp, bare)
            .expect("the corpus names it");
        assert_eq!(evidence.product.as_deref(), Some("SNMP Agent"));
    }

    /// An agent answering only the first question is the ordinary case for one
    /// that does not implement the second.
    #[test]
    fn a_reply_without_the_second_binding_still_yields_the_description() {
        let mut only_descr = super::from_datagram(161, &response(NET_SNMP, "Linux zond"));
        only_descr.truncate(1);
        assert_eq!(only_descr, vec!["Linux zond".to_string()]);
    }
}

#[cfg(test)]
mod device_info {
    use crate::fingerprint::SignatureDb;
    use crate::model::port::Protocol;

    /// The answer a Mac's own responder gave on 2026-09-05, asked over unicast.
    const REPLY: &[u8] = &[
        0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x6d, 0x61,
        0x63, 0x0c, 0x5f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x69, 0x6e, 0x66, 0x6f, 0x04,
        0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x10, 0x80, 0x01,
        0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x23, 0x0e, 0x6d, 0x6f,
        0x64, 0x65, 0x6c, 0x3d, 0x4d, 0x61, 0x63, 0x31, 0x36, 0x2c, 0x31, 0x30, 0x0a, 0x6f, 0x73,
        0x78, 0x76, 0x65, 0x72, 0x73, 0x3d, 0x32, 0x35, 0x08, 0x69, 0x63, 0x6f, 0x6c, 0x6f, 0x72,
        0x3d, 0x30,
    ];

    #[test]
    fn the_reply_yields_one_text_per_field() {
        assert_eq!(
            super::from_datagram(5353, REPLY),
            vec!["model=Mac16,10", "osxvers=25", "icolor=0"]
        );
    }

    /// The model this Mac reports postdates every one the imported corpus
    /// enumerates, which is what the generative rules are for.
    #[test]
    fn a_model_newer_than_the_enumerated_ones_still_names_apple() {
        let evidence = SignatureDb::global()
            .identify(5353, Protocol::Udp, "model=Mac16,10")
            .expect("the shape is recognised");
        let os = evidence.os.expect("it says something about the machine");

        assert_eq!(os.vendor.as_deref(), Some("Apple"));
        assert_eq!(os.family.as_deref(), Some("macOS"));
    }

    /// And the Darwin release, captured rather than looked up, so it does not
    /// stop at the 22 the imported rules stop at.
    #[test]
    fn a_darwin_release_past_the_enumerated_ones_is_still_read() {
        let evidence = SignatureDb::global()
            .identify(5353, Protocol::Udp, "osxvers=25")
            .expect("the shape is recognised");
        let os = evidence.os.expect("it says something about the machine");

        assert_eq!(os.vendor.as_deref(), Some("Apple"));
        assert_eq!(os.kernel.as_deref(), Some("25"));
    }

    /// A model the imported corpus does name is still named by it, in full.
    #[test]
    fn an_enumerated_model_keeps_the_more_specific_reading() {
        let evidence = SignatureDb::global()
            .identify(5353, Protocol::Udp, "model=MacBookPro18,3")
            .expect("the corpus names it");
        let os = evidence.os.expect("it says something about the machine");
        assert_eq!(os.vendor.as_deref(), Some("Apple"));
    }

    #[test]
    fn port_5353_is_now_worth_a_second_datagram() {
        assert!(super::reads(5353, Protocol::Udp));
    }
}

#[cfg(test)]
mod sip_headers {
    use crate::fingerprint::SignatureDb;
    use crate::model::port::Protocol;

    /// What a Cisco gateway answers OPTIONS with, in the shape RFC 3261 gives a
    /// response and the corpus has rules for.
    const GATEWAY: &str = "SIP/2.0 200 OK\r\n\
         Via: SIP/2.0/UDP nm;branch=zond\r\n\
         Server: Cisco-SIPGateway/IOS-12.x\r\n\
         Content-Length: 0\r\n\r\n";

    /// Over UDP, which is where most SIP is, through the port-keyed decoder.
    #[test]
    fn a_datagram_yields_the_header_the_corpus_reads() {
        assert_eq!(
            super::from_datagram(5060, GATEWAY.as_bytes()),
            vec!["Cisco-SIPGateway/IOS-12.x"]
        );
    }

    /// And over TCP, where the response arrives as a banner. The whole reply is
    /// still offered beside the field, as it is for every other banner.
    #[test]
    fn a_banner_offers_the_header_beside_itself() {
        let texts = super::texts(GATEWAY);
        assert!(
            texts.iter().any(|text| text == "Cisco-SIPGateway/IOS-12.x"),
            "got {texts:?}"
        );
    }

    /// The whole point: a rule is anchored on the header value, so it can never
    /// match the response that carried it.
    #[test]
    fn the_header_names_the_gateway_behind_it() {
        let evidence = SignatureDb::global()
            .identify(5060, Protocol::Udp, "Cisco-SIPGateway/IOS-12.x")
            .expect("the corpus names it");
        assert_eq!(evidence.product.as_deref(), Some("IOS"));
    }

    #[test]
    fn port_5060_is_now_worth_a_second_datagram() {
        assert!(super::reads(5060, Protocol::Udp));
        assert!(super::reads(5061, Protocol::Udp));
    }

    /// A datagram that is not SIP decodes to nothing rather than to noise.
    #[test]
    fn a_datagram_that_is_not_sip_yields_nothing() {
        assert!(super::from_datagram(5060, b"\x00\x01\x02 not sip").is_empty());
        assert!(super::from_datagram(5060, b"HTTP/1.1 200 OK\r\n\r\n").is_empty());
    }
}

#[cfg(test)]
mod ldap_root_dse {
    use crate::fingerprint::SignatureDb;
    use crate::model::port::Protocol;

    /// The opening of a real root DSE search result, captured from OpenLDAP
    /// 2.6 on 2026-09-06. The corpus matches these bytes as text rather than a
    /// parse of them, which is why nothing here decodes BER.
    const ROOT_DSE: &[u8] = &[
        0x30, 0x82, 0x03, 0x5a, 0x02, 0x01, 0x02, 0x64, 0x82, 0x03, 0x53, 0x04, 0x00, 0x30, 0x82,
        0x03, 0x4d, 0x30, 0x25, 0x04, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61,
        0x73, 0x73, 0x31, 0x16, 0x04, 0x03, 0x74, 0x6f, 0x70, 0x04, 0x0f, 0x4f, 0x70, 0x65, 0x6e,
        0x4c, 0x44, 0x41, 0x50, 0x72, 0x6f, 0x6f, 0x74, 0x44, 0x53, 0x45, 0x30,
    ];

    /// The whole point of the search: an anonymous bind establishes only that
    /// something speaks LDAP, while the entry at the empty DN names the
    /// directory.
    #[test]
    fn a_root_dse_result_names_the_directory() {
        let text = super::reply_text(ROOT_DSE);
        let evidence = SignatureDb::global()
            .identify(389, Protocol::Tcp, &text)
            .expect("the corpus names it");

        assert_eq!(evidence.product.as_deref(), Some("OpenLDAP"));
        assert_eq!(evidence.vendor.as_deref(), Some("OpenLDAP"));
    }

    /// The response carries bytes that are not UTF-8, and the rules are written
    /// against them: each reaches the matcher as the code point of its own
    /// value, and the text between them as it was written.
    #[test]
    fn bytes_that_are_not_utf8_reach_the_rules_as_themselves() {
        let text = super::reply_text(ROOT_DSE);
        assert!(text.contains("OpenLDAProotDSE"));
        assert!(text.starts_with("0\u{82}\u{3}Z\u{2}\u{1}\u{2}"));
        assert!(!text.contains(char::REPLACEMENT_CHARACTER));
    }
}

#[cfg(test)]
mod ssdp_server {
    use crate::fingerprint::SignatureDb;
    use crate::model::port::Protocol;

    /// What a consumer router answers M-SEARCH with: an HTTP-shaped message
    /// whose `SERVER` value carries the three tokens UPnP specifies.
    const ROUTER: &str = "HTTP/1.1 200 OK\r\n\
         CACHE-CONTROL: max-age=120\r\n\
         ST: upnp:rootdevice\r\n\
         USN: uuid:11111111-2222-3333-4444-555555555555::upnp:rootdevice\r\n\
         EXT:\r\n\
         SERVER: Linux/3.14.0, UPnP/1.0, MiniUPnPd/1.9\r\n\
         LOCATION: http://192.0.2.1:5000/rootDesc.xml\r\n\r\n";

    #[test]
    fn a_datagram_yields_the_header_the_corpus_reads() {
        assert_eq!(
            super::from_datagram(1900, ROUTER.as_bytes()),
            vec!["Linux/3.14.0, UPnP/1.0, MiniUPnPd/1.9"]
        );
    }

    /// The header and not the message. A banner beginning `HTTP/` is what the
    /// HTTP analyzer gates on, so handing the reply back whole would have a UPnP
    /// responder reported as a web server running on 1900.
    #[test]
    fn the_reply_itself_is_not_offered_as_a_banner() {
        assert!(
            !super::from_datagram(1900, ROUTER.as_bytes())
                .iter()
                .any(|text| text.starts_with("HTTP/")),
            "the message would be read as an HTTP response"
        );
    }

    #[test]
    fn the_header_names_the_daemon_behind_it() {
        let evidence = SignatureDb::global()
            .identify(1900, Protocol::Udp, "Linux/3.14.0, UPnP/1.0, MiniUPnPd/1.9")
            .expect("the corpus names it");
        assert_eq!(evidence.product.as_deref(), Some("MiniUPnPd"));
        assert_eq!(evidence.version.as_deref(), Some("1.9"));
    }

    /// A device that names no product still resolves to UPnP rather than to
    /// nothing, which is the baseline rule's whole job.
    #[test]
    fn a_stack_the_corpus_cannot_name_is_still_upnp() {
        let evidence = SignatureDb::global()
            .identify(1900, Protocol::Udp, "SomeRTOS/1.0 UPnP/1.0 Widget/2.3")
            .expect("the baseline rule fires");
        assert_eq!(evidence.product.as_deref(), Some("upnp"));
    }

    #[test]
    fn port_1900_is_now_worth_a_second_datagram() {
        assert!(super::reads(1900, Protocol::Udp));
    }

    /// A reply carrying no such header, and one that is not a message at all,
    /// both decode to nothing rather than to noise.
    #[test]
    fn a_datagram_with_nothing_to_read_yields_nothing() {
        assert!(super::from_datagram(1900, b"\x00\x01\x02 not ssdp").is_empty());
        assert!(super::from_datagram(1900, b"HTTP/1.1 200 OK\r\nST: x\r\n\r\n").is_empty());
    }
}

#[cfg(test)]
mod framed_replies {
    use crate::fingerprint::SignatureDb;
    use crate::model::port::Protocol;

    /// What the corpus makes of one decoded reply, port-scoped as a scan would
    /// match it.
    fn identify(port: u16, text: &str) -> Option<(String, Option<String>)> {
        SignatureDb::global()
            .identify(port, Protocol::Udp, text)
            .map(|found| (found.product.unwrap_or_default(), found.version))
    }

    /// The Browser's answer names the release and the instance behind it.
    #[test]
    fn a_browser_response_names_the_instance_and_its_build() {
        let reply = {
            let body = b"ServerName;WIN-DB01;InstanceName;SQLEXPRESS;IsClustered;No;\
                         Version;15.0.2000.5;tcp;1433;;";
            let mut out = vec![0x05];
            out.extend_from_slice(&(body.len() as u16).to_le_bytes());
            out.extend_from_slice(body);
            out
        };

        let texts = super::from_datagram(1434, &reply);
        assert_eq!(texts.len(), 1, "got {texts:?}");
        assert!(texts[0].starts_with("ServerName;WIN-DB01"));

        assert_eq!(
            identify(1434, &texts[0]),
            Some((
                "Microsoft SQL Server".to_string(),
                Some("15.0.2000.5".to_string())
            ))
        );
    }

    /// The reason this port is worth asking at all: a named instance says which
    /// TCP port it listens on, which a port scan would otherwise have to find.
    #[test]
    fn the_instance_list_carries_the_port_the_engine_listens_on() {
        let body = b"ServerName;WIN-DB01;InstanceName;SQLEXPRESS;IsClustered;No;\
                     Version;15.0.2000.5;tcp;49812;;";
        let mut reply = vec![0x05];
        reply.extend_from_slice(&(body.len() as u16).to_le_bytes());
        reply.extend_from_slice(body);

        let texts = super::from_datagram(1434, &reply);
        assert!(texts[0].contains("tcp;49812"), "got {texts:?}");
    }

    /// The UDP probe draws the same line the TCP one does, and the rule written
    /// for that banner reads it unchanged.
    #[test]
    fn memcached_over_udp_reuses_the_rule_written_for_tcp() {
        let reply = b"\x00\x01\x00\x00\x00\x01\x00\x00VERSION 1.6.21\r\n";
        let texts = super::from_datagram(11211, reply);
        assert_eq!(texts, vec!["VERSION 1.6.21"]);

        assert_eq!(
            identify(11211, &texts[0]),
            Some(("memcached".to_string(), Some("1.6.21".to_string())))
        );
    }

    #[test]
    fn a_wsd_probe_match_names_what_answered() {
        let windows = br#"<s:Envelope><s:Body><d:ProbeMatches><d:ProbeMatch>
            <d:Types>wsdp:Device pub:Computer</d:Types>
            </d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"#;
        let texts = super::from_datagram(3702, windows);
        assert_eq!(texts, vec!["Device Computer"]);
        assert_eq!(
            identify(3702, &texts[0]).map(|found| found.0),
            Some("WS-Discovery host".to_string())
        );

        let printer = b"<d:ProbeMatches><d:Types>print:PrintDeviceType</d:Types></d:ProbeMatches>";
        let texts = super::from_datagram(3702, printer);
        assert_eq!(
            identify(3702, &texts[0]).map(|found| found.0),
            Some("WSD print service".to_string())
        );
    }

    /// Each of these fields is also matched against text belonging to no port,
    /// through `identify_field`, so a rule loose enough to fire there would put
    /// a WS-Discovery device behind a certificate subject. This is what caught
    /// that when these rules were first written.
    #[test]
    fn the_new_rules_do_not_fire_on_text_that_is_not_theirs() {
        let db = SignatureDb::global();
        for text in [
            "CN=example.invalid,O=Nobody,C=ZZ",
            "Apache/2.4.62 (Debian)",
            "220 mail.example ESMTP Postfix",
            "SSH-2.0-OpenSSH_9.6p1 Debian-3",
            "Error: could not open file",
            "Computer Associates License Server",
            "Willing to help with your display",
            "</usr/share>;rw",
            "MCPE Gaming Ltd",
            "challenge-response authentication",
            "nfs shares are exported read-only",
            "supports versions 3-4 of the specification",
            "IPMI 2.0 compliant baseboard controller",
            "stunning performance",
            "notify the administrator",
            "krb-error handling is disabled",
            "vendor=example, host unreachable",
            "Device Manager Print Spooler",
            "Network Video Recorder",
            "ServerName Corp",
            "Scanner Ready",
        ] {
            let named = db.identify_field(text).and_then(|found| found.product);
            assert!(
                !matches!(
                    named.as_deref(),
                    Some("WS-Discovery host" | "WSD print service" | "WSD scan service")
                        | Some("ONVIF device" | "Microsoft SQL Server Browser")
                        | Some("GDM" | "XDM" | "xdmcp" | "coap")
                        | Some("Source engine server" | "Minecraft Bedrock Server")
                        | Some("NFS" | "IPMI" | "rpcbind")
                        | Some("coturn" | "stunserver" | "isakmp" | "FortiGate")
                        | Some("MIT Kerberos" | "Kerberos KDC" | "xl2tpd" | "Windows RRAS")
                ),
                "{text:?} was named {named:?}"
            );
        }
    }

    /// A display manager willing to manage a session for a stranger, which is
    /// the finding whatever the software behind it is.
    #[test]
    fn an_xdmcp_manager_is_named_from_what_it_says_about_itself() {
        let mut reply = vec![0x00, 0x01, 0x00, 0x05, 0x00, 0x00];
        for field in ["", "workstation", "Linux 6.1 gdm"] {
            reply.extend_from_slice(&(field.len() as u16).to_be_bytes());
            reply.extend_from_slice(field.as_bytes());
        }

        let texts = super::from_datagram(177, &reply);
        assert_eq!(texts, vec!["workstation: Linux 6.1 gdm"]);
        assert_eq!(
            identify(177, &texts[0]).map(|found| found.0),
            Some("GDM".to_string())
        );
    }

    #[test]
    fn a_source_server_names_the_game_it_runs() {
        let mut reply = vec![0xFF, 0xFF, 0xFF, 0xFF, b'I', 17];
        for field in ["Zond Test Server", "de_dust2", "csgo", "Counter-Strike"] {
            reply.extend_from_slice(field.as_bytes());
            reply.push(0);
        }

        let texts = super::from_datagram(27015, &reply);
        assert_eq!(texts, vec!["Zond Test Server;de_dust2;csgo;Counter-Strike"]);
        assert_eq!(
            identify(27015, &texts[0]).map(|found| found.0),
            Some("Counter-Strike".to_string())
        );
    }

    /// A server that asked for a challenge instead of answering is still named,
    /// because nothing else sends that reply.
    #[test]
    fn a_source_challenge_still_names_the_service() {
        let reply = [0xFF, 0xFF, 0xFF, 0xFF, b'A', 0x11, 0x22, 0x33, 0x44];
        let texts = super::from_datagram(27015, &reply);
        assert_eq!(texts, vec!["challenge"]);
        assert_eq!(
            identify(27015, &texts[0]).map(|found| found.0),
            Some("Source engine server".to_string())
        );
    }

    #[test]
    fn a_bedrock_server_names_its_version_and_its_players() {
        const STATUS: &str =
            "MCPE;Dedicated Server;390;1.14.60;3;10;13253860892328930865;Bedrock level";
        let mut reply = vec![0x1C];
        reply.extend_from_slice(&[0u8; 16]);
        reply.extend_from_slice(&[
            0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34,
            0x56, 0x78,
        ]);
        reply.extend_from_slice(&(STATUS.len() as u16).to_be_bytes());
        reply.extend_from_slice(STATUS.as_bytes());

        let texts = super::from_datagram(19132, &reply);
        assert_eq!(texts, vec![STATUS]);
        assert_eq!(
            identify(19132, &texts[0]),
            Some((
                "Minecraft Bedrock Server".to_string(),
                Some("1.14.60".to_string())
            ))
        );
    }

    #[test]
    fn a_coap_endpoint_lists_the_resources_it_exposes() {
        let mut reply = vec![0x60, 0x45, 0x7a, 0x6e, 0xC1, 0x28, 0xFF];
        reply.extend_from_slice(br#"</sensors/temp>;rt="temperature";if="sensor""#);

        let texts = super::from_datagram(5683, &reply);
        assert_eq!(texts.len(), 1);
        assert!(texts[0].starts_with("</sensors/temp>"), "got {texts:?}");
        assert_eq!(
            identify(5683, &texts[0]).map(|found| found.0),
            Some("coap".to_string())
        );
    }

    /// A Steam master is asked its server list over UDP, the only transport it
    /// answers on, and is named from the list it returns. A query sent over TCP
    /// draws nothing from a master and costs a connection per port.
    #[test]
    fn a_steam_master_is_asked_over_udp_and_named_from_its_list() {
        let query = b"1\xff0.0.0.0:0\x00\x00";
        let db = SignatureDb::global();
        for port in 27010..=27014 {
            assert!(
                db.tcp_probe_payloads(port).is_empty(),
                "tcp probe on {port}"
            );
            assert_eq!(db.udp_probe_payloads(port), [query.to_vec()], "on {port}");
        }

        let mut reply = vec![0xFF, 0xFF, 0xFF, 0xFF, b'f', b'\n'];
        reply.extend_from_slice(&[198, 51, 100, 4, 0x69, 0x87, 0, 0, 0, 0, 0, 0]);
        let texts = super::from_datagram(27011, &reply);
        assert_eq!(texts, ["server list"]);
        assert_eq!(
            identify(27011, &texts[0]).map(|found| found.0),
            Some("Steam master server".to_string())
        );
    }

    /// The exact bytes the `zond-refresh.sh` fixtures answer with, captured off
    /// the wire.
    ///
    /// The tests above build a reply from the same understanding of the format
    /// that wrote the reader, so they agree with it by construction. These came
    /// from a separate implementation, which is the one place a fixture and a
    /// parser can be caught disagreeing before a VM run does it.
    #[test]
    fn the_fixtures_answer_with_bytes_these_readers_accept() {
        fn hex(text: &str) -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits"))
                .collect()
        }

        const BEDROCK: &str = "1c0000000000000000000000000000000000ffff00fefefefefdfdfdfd1234567800514d4350453b5a6f6e642054657374205265616c6d3b3339303b312e32302e31353b323b31303b31333235333836303839323332383933303836353b426564726f636b206c6576656c3b537572766976616c";
        assert_eq!(
            super::from_datagram(19132, &hex(BEDROCK)),
            vec![
                "MCPE;Zond Test Realm;390;1.20.15;2;10;13253860892328930865;Bedrock level;Survival"
            ]
        );

        const A2S: &str = "ffffffff49115a6f6e642054657374205365727665720064655f6475737432006373676f00436f756e7465722d537472696b6500da02041000";
        assert_eq!(
            super::from_datagram(27015, &hex(A2S)),
            vec!["Zond Test Server;de_dust2;csgo;Counter-Strike"]
        );

        const COAP: &str = "60457a6eff3c2f73656e736f72732f74656d703e3b72743d2274656d7065726174757265223b69663d2273656e736f72222c3c2f6163747561746f72732f6c65643e3b72743d226c69676874223b69663d22636f72652e6122";
        let texts = super::from_datagram(5683, &hex(COAP));
        assert!(texts[0].starts_with("</sensors/temp>"), "got {texts:?}");
        assert_eq!(
            identify(5683, &texts[0]).map(|found| found.0),
            Some("coap".to_string())
        );
    }

    /// An RPC reply header with an empty verifier, then `body`.
    fn rpc_reply(accept_status: u32, body: &[u8]) -> Vec<u8> {
        let mut out = 0x7a6f6e64u32.to_be_bytes().to_vec();
        for word in [1u32, 0, 0, 0, accept_status] {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    /// The portmapper is worth asking because it says where things are, not
    /// only what they are: `mountd` on 20048 is a port nothing would have
    /// guessed.
    #[test]
    fn a_portmapper_names_the_services_and_where_they_are() {
        let mut body = Vec::new();
        for entry in [
            (100000u32, 2u32, 17u32, 111u32),
            (100003, 3, 6, 2049),
            (100005, 3, 17, 20048),
        ] {
            body.extend_from_slice(&1u32.to_be_bytes());
            for field in [entry.0, entry.1, entry.2, entry.3] {
                body.extend_from_slice(&field.to_be_bytes());
            }
        }
        body.extend_from_slice(&0u32.to_be_bytes());

        let texts = super::from_datagram(111, &rpc_reply(0, &body));
        assert_eq!(
            texts,
            vec!["portmapper 2 udp 111, nfs 3 tcp 2049, mountd 3 udp 20048"]
        );
        // No version: the dump lists one record per version per transport, so a
        // capture here would name whichever the server wrote first. The probe
        // on 2049 answers that with the range.
        assert_eq!(identify(111, &texts[0]), Some(("NFS".to_string(), None)));
    }

    /// The order a real portmapper lists in, captured from `rpcbind` and
    /// `nfs-kernel-server` on Debian 12.
    ///
    /// Every mountd version comes before the first nfs one, and `nfs_acl` is
    /// registered beside `nfs` on the same port. The first version of the NFS
    /// rule read `nfs ... mountd` in sequence and matched neither this nor any
    /// other real server, which nothing but a scan of one would have shown.
    #[test]
    fn the_order_a_real_portmapper_lists_in_is_not_the_order_a_rule_may_assume() {
        const REAL: &str = "portmapper 4 tcp 111, portmapper 3 tcp 111, portmapper 2 tcp 111, \
             portmapper 4 udp 111, portmapper 3 udp 111, portmapper 2 udp 111, \
             status 1 udp 32818, status 1 tcp 37525, mountd 1 udp 44481, \
             mountd 1 tcp 43111, mountd 2 udp 33385, mountd 2 tcp 60869, \
             mountd 3 udp 43738, mountd 3 tcp 33227, nfs 3 tcp 2049, nfs 4 tcp 2049, \
             nfs_acl 3 tcp 2049, nfs 3 udp 2049, nfs_acl 3 udp 2049, \
             nlockmgr 1 udp 51523, nlockmgr 3 udp 51523, nlockmgr 4 udp 51523";

        assert_eq!(
            identify(111, REAL).map(|found| found.0),
            Some("NFS".to_string())
        );
    }

    /// And `nfs_acl` alone does not stand in for `nfs`, which the space after
    /// the program name is what enforces.
    #[test]
    fn a_host_registering_only_part_of_the_pair_is_not_a_file_server() {
        for dump in [
            "portmapper 4 tcp 111, mountd 3 udp 43738",
            "mountd 3 udp 111, nfs_acl 3 tcp 2049",
            "portmapper 2 udp 111",
        ] {
            assert_ne!(
                identify(111, dump).map(|found| found.0),
                Some("NFS".to_string()),
                "{dump:?} was read as a file server"
            );
        }
    }

    #[test]
    fn an_nfs_server_states_the_versions_it_supports() {
        let mut body = 3u32.to_be_bytes().to_vec();
        body.extend_from_slice(&4u32.to_be_bytes());

        let texts = super::from_datagram(2049, &rpc_reply(2, &body));
        assert_eq!(texts, vec!["versions 3-4"]);
        assert_eq!(
            identify(2049, &texts[0]),
            Some(("NFS".to_string(), Some("4".to_string())))
        );
    }

    /// The finding a scan of a management network is looking for.
    #[test]
    fn a_bmc_that_authenticates_nobody_says_so() {
        let mut reply = vec![0x06, 0x00, 0xFF, 0x07];
        reply.extend_from_slice(&[0u8; 9]);
        reply.push(8);
        reply.extend_from_slice(&[0x81, 0x1C, 0x00, 0x20, 0x00, 0x38]);
        reply.extend_from_slice(&[0x00, 0x01, 0b1000_0000, 0b0000_0011]);

        let texts = super::from_datagram(623, &reply);
        assert_eq!(texts, vec!["IPMI-2.0 anonymous-login null-user"]);
        assert_eq!(
            identify(623, &texts[0]),
            Some(("IPMI".to_string(), Some("2.0".to_string())))
        );
    }

    /// The point of the mode 6 probe: an imported rule that could not fire
    /// before now reads a real daemon's answer.
    ///
    /// Seventy-five rules were written against `ntp.readvar` and none of them
    /// had ever matched anything, because the only probe this port carried was
    /// an ordinary client request and its reply is timestamps. Nothing about
    /// them was wrong; the engine was asking the wrong question.
    #[test]
    fn the_ntp_rules_that_never_fired_now_read_a_daemon_that_answers() {
        const VARS: &str = "version=\"ntpd 4.2.8p15@1.3728-o Wed May 12 08:30:00 UTC 2021 (1)\", \
             processor=\"x86_64\", system=\"Linux/6.1.0-18-arm64\", leap=00, stratum=3";

        let mut reply = vec![0x16, 0x82];
        reply.extend_from_slice(&1u16.to_be_bytes());
        reply.extend_from_slice(&[0u8; 6]);
        reply.extend_from_slice(&(VARS.len() as u16).to_be_bytes());
        reply.extend_from_slice(VARS.as_bytes());

        let texts = super::from_datagram(123, &reply);
        assert_eq!(texts.len(), 1, "got {texts:?}");
        assert!(texts[0].starts_with("version=\"ntpd"), "got {texts:?}");

        // The version is what the imported rule captures, build suffix included:
        // its pattern takes everything up to the first space. That is Recog's
        // reading and not this engine's, and the point here is that the rule now
        // gets a string to read at all.
        let found = identify(123, &texts[0]).expect("the corpus names it");
        assert_eq!(found.1.as_deref(), Some("4.2.8p15@1.3728-o"));
    }

    /// The client probe's own reply is still not read, which is why the control
    /// probe had to be added rather than the rules rewritten.
    #[test]
    fn the_client_reply_this_port_used_to_draw_still_says_nothing() {
        let mut timestamps = vec![0x24, 0x03, 0x06, 0xec];
        timestamps.extend_from_slice(&[0u8; 44]);
        assert!(super::from_datagram(123, &timestamps).is_empty());
    }

    #[test]
    fn a_stun_server_is_named_by_the_software_it_reports() {
        let name = b"Coturn-4.5.2 'dan Eider'";
        let mut reply = 0x0101u16.to_be_bytes().to_vec();
        reply.extend_from_slice(&((4 + name.len()) as u16).to_be_bytes());
        reply.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        reply.extend_from_slice(b"zond-scan-01");
        reply.extend_from_slice(&0x8022u16.to_be_bytes());
        reply.extend_from_slice(&(name.len() as u16).to_be_bytes());
        reply.extend_from_slice(name);

        let texts = super::from_datagram(3478, &reply);
        assert_eq!(texts, vec!["Coturn-4.5.2 'dan Eider'"]);
        assert_eq!(
            identify(3478, &texts[0]),
            Some(("coturn".to_string(), Some("4.5.2".to_string())))
        );
    }

    /// A gateway is named by the vendor ids it announces, and both IKE ports
    /// read the same way.
    #[test]
    fn an_ike_gateway_is_named_by_its_vendor_ids() {
        let mut reply = b"initiat0responde".to_vec();
        reply.push(13); // first payload: vendor id
        reply.extend_from_slice(&[0x10, 0x02, 0x00]);
        reply.extend_from_slice(&[0u8; 8]); // message id and length
        let vendor = [
            0x82u8, 0x99, 0x03, 0x17, 0x57, 0xa3, 0x60, 0x82, 0xc6, 0xa6, 0x21, 0xde, 0x00, 0x00,
            0x00, 0x00,
        ];
        reply.extend_from_slice(&[0, 0]);
        reply.extend_from_slice(&((4 + vendor.len()) as u16).to_be_bytes());
        reply.extend_from_slice(&vendor);

        for port in [500u16, 4500] {
            let texts = super::from_datagram(port, &reply);
            assert_eq!(
                texts,
                vec!["8299031757a36082c6a621de00000000"],
                "port {port}"
            );
            assert_eq!(
                identify(port, &texts[0]).map(|found| found.0),
                Some("FortiGate".to_string()),
                "port {port}"
            );
        }
    }

    /// The bytes the `zond-refresh.sh` fixtures put on the wire, captured from
    /// them rather than rebuilt here.
    ///
    /// The tests above construct a reply from the same reading of each format
    /// that wrote the reader, so they agree with it by construction. These came
    /// from the other implementation, which is where a fixture and a parser are
    /// caught disagreeing before a VM run does it.
    #[test]
    fn the_phase_three_fixtures_answer_with_bytes_these_readers_accept() {
        fn hex(text: &str) -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits"))
                .collect()
        }

        // ntpsec 1.2.2 on the VM, answering the corpus probe. It sorts its reply
        // alphabetically, which is the ordering the imported rules do not expect
        // and `ntpsec_version` exists to cover.
        const NTPSEC: &str = r#"processor="aarch64", system="Linux/6.1.0-50-cloud-arm64", version="ntpd ntpsec-1.2.2""#;
        let mut reply = vec![0x16, 0x82];
        reply.extend_from_slice(&1u16.to_be_bytes());
        reply.extend_from_slice(&[0u8; 6]);
        reply.extend_from_slice(&(NTPSEC.len() as u16).to_be_bytes());
        reply.extend_from_slice(NTPSEC.as_bytes());
        assert_eq!(
            identify(123, &super::from_datagram(123, &reply)[0]),
            Some(("NTPsec".to_string(), Some("1.2.2".to_string())))
        );

        const STUN: &str = "0101001c2112a4427a6f6e642d7363616e2d303180220018436f7475726e2d342e352e32202764616e20456964657227";
        let texts = super::from_datagram(3478, &hex(STUN));
        assert_eq!(texts, vec!["Coturn-4.5.2 'dan Eider'"]);
        assert_eq!(
            identify(3478, &texts[0]).map(|found| found.0),
            Some("coturn".to_string())
        );

        const IKE_500: &str = "7a6f6e647363616e726573706f6e64650d1002200000000000000030000000148299031757a36082c6a621de00000000";
        let texts = super::from_datagram(500, &hex(IKE_500));
        assert_eq!(texts, vec!["8299031757a36082c6a621de00000000"]);
        assert_eq!(
            identify(500, &texts[0]).map(|found| found.0),
            Some("FortiGate".to_string())
        );

        const IKE_4500: &str = "7a6f6e647363616e726573706f6e64650d1002200000000000000034000000181e2b516905991c7d7c96fcbfb587e46100000009";
        let texts = super::from_datagram(4500, &hex(IKE_4500));
        assert_eq!(
            identify(4500, &texts[0]).map(|found| found.0),
            Some("Windows IKE".to_string())
        );
    }

    /// What MIT krb5 1.20 on Debian 12 actually answered the corpus probe with,
    /// captured off the wire.
    ///
    /// The realm is absent from the reading on purpose. This reply carries
    /// `ZOND-SCAN` in both realm fields, which is the realm the probe invented
    /// coming back: a KDC repeats what it was asked about. Reporting it would
    /// print this engine's own guess as though it were a discovered domain.
    #[test]
    fn a_kdc_is_named_and_its_echo_of_our_realm_is_not_reported() {
        fn hex(text: &str) -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits"))
                .collect()
        }
        const MIT: &str = "7e8198308195a003020105a10302011ea411180f32303236303930383133313432325aa50502030f13baa603020106a70b1b095a4f4e442d5343414ea81c301aa003020101a11330111b0f7a6f6e642d7363616e2d70726f6265a90b1b095a4f4e442d5343414eaa1e301ca003020102a11530131b066b72627467741b095a4f4e442d5343414eab121b10434c49454e545f4e4f545f464f554e44";

        let texts = super::from_datagram(88, &hex(MIT));
        assert_eq!(texts, vec!["krb-error 6 CLIENT_NOT_FOUND"]);
        assert!(
            !texts[0].contains("ZOND-SCAN"),
            "the probe's own realm came back as though it were the KDC's: {texts:?}"
        );
        assert_eq!(
            identify(88, &texts[0]).map(|found| found.0),
            Some("MIT Kerberos".to_string())
        );
        assert!(
            super::names_from_datagram(88, &hex(MIT)).is_empty(),
            "the probe's own realm was recorded as the host's"
        );
    }

    /// A realm the probe did not supply is read as the domain the KDC serves,
    /// which is the case the whole probe is for: on a domain controller it
    /// names the Active Directory domain. It is a name of the host's and not
    /// text for the corpus, since a rule's capture would carry it into the
    /// service's description, which a redacted report does not mask.
    #[test]
    fn a_realm_this_engine_did_not_ask_about_is_a_name_and_never_text() {
        use crate::model::host::{HostName, NameKind, NameSource};

        // A KRB-ERROR carrying error 68 and a realm of its own.
        let realm = b"CORP.EXAMPLE";
        let mut fields = vec![0xA6, 0x03, 0x02, 0x01, 68];
        fields.push(0xA9);
        fields.push((realm.len() + 2) as u8);
        fields.push(0x1B);
        fields.push(realm.len() as u8);
        fields.extend_from_slice(realm);

        let mut sequence = vec![0x30, fields.len() as u8];
        sequence.extend_from_slice(&fields);
        let mut reply = vec![0x7E, sequence.len() as u8];
        reply.extend_from_slice(&sequence);

        let texts = super::from_datagram(88, &reply);
        assert_eq!(texts, vec!["krb-error 68"]);
        let found = SignatureDb::global()
            .identify(88, Protocol::Udp, &texts[0])
            .expect("a KDC");
        assert_eq!(found.product.as_deref(), Some("Kerberos KDC"));

        let named = [
            HostName::new(NameKind::Domain, NameSource::Kerberos, "CORP.EXAMPLE").expect("a name"),
        ];
        assert_eq!(super::names_from_datagram(88, &reply), named);

        // Over TCP the same message sits behind its four-byte length.
        let mut stream = (reply.len() as u32).to_be_bytes().to_vec();
        stream.extend_from_slice(&reply);
        assert_eq!(super::from_stream(88, &stream), vec!["krb-error 68"]);
        assert_eq!(super::names_from_stream(88, &stream), named);
    }

    /// What xl2tpd 1.3.16 on Debian 12 actually answered, captured off the wire.
    /// The host name in it is the VM's own.
    #[test]
    fn a_concentrator_names_itself_and_the_machine() {
        fn hex(text: &str) -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits"))
                .collect()
        }
        const SCCRP: &str = "c802006b7a6f00000000000180080000000000028008000000020100800a0000000300000003800a000000040000000000080000000606908010000000076c696d612d646562313200130000000878656c6572616e63652e636f6d800800000009503180080000000a0004";

        let texts = super::from_datagram(1701, &hex(SCCRP));
        assert_eq!(texts, vec!["vendor=xelerance.com host=lima-deb12"]);
        assert_eq!(
            identify(1701, &texts[0]).map(|found| found.0),
            Some("xl2tpd".to_string())
        );
    }

    /// What Samba 4.17.12 on Debian 12 answered the SMB1 session the SMB
    /// analyzer asks for, captured off the wire: a negotiate response and a
    /// session setup, back to back.
    ///
    /// Eighty-five imported rules were written against these two fields, and a
    /// negotiate response carries neither.
    #[test]
    fn a_session_setup_yields_the_fields_eighty_five_rules_were_written_against() {
        fn hex(text: &str) -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits"))
                .collect()
        }
        const SAMBA: &str = "0000009fff534d4272000000008801c80000000000000000000000000000fffe000001001100000332000100044100000000010088220000fdf3808039dcb70b9d3fdd0188ff005a007a6f6e64736d62000000000000000000604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f72650000007cff534d4273000000008803880000000000000000000000000000fffe85e4010003ff0000000000530000570069006e0064006f0077007300200036002e0031000000530061006d0062006100200034002e00310037002e00310032002d00440065006200690061006e0000005a004f004e0044004c00410042000000";

        let texts = crate::fingerprint::framed::smb_session_setup(&hex(SAMBA));
        assert_eq!(
            texts,
            vec!["Windows 6.1", "Samba 4.17.12-Debian"],
            "each field on its own, since the rules anchor at both ends of one"
        );
        // The workgroup is the host's name, and never text a rule could
        // capture into a service's description.
        let names = crate::fingerprint::framed::smb_session_names(&hex(SAMBA));
        assert_eq!(
            names
                .iter()
                .map(|name| (name.kind(), name.source(), name.name()))
                .collect::<Vec<_>>(),
            [(
                crate::model::host::NameKind::NetbiosDomain,
                crate::model::host::NameSource::Smb,
                "ZONDLAB"
            )]
        );

        // The imported rule reads the release and stops at the packager's
        // suffix: its capture is `(\d\.\d+.\d+\w*)`, and `\w` does not cross
        // the hyphen. That is Recog's reading, and the point here is that the
        // rule has a field to read at all.
        assert_eq!(
            SignatureDb::global()
                .identify(445, Protocol::Tcp, &texts[1])
                .and_then(|found| found.version),
            Some("4.17.12".to_string())
        );

        // And the operating-system field reaches its own rule, anchored whole.
        assert!(
            SignatureDb::global()
                .identify(445, Protocol::Tcp, &texts[0])
                .is_some(),
            "the native OS field matched nothing"
        );
    }

    /// An RTSP `Server` value reaches the rules written for it.
    ///
    /// The status line is what makes this a reader of its own: `RTSP/1.0` is not
    /// `HTTP/1.1`, so the HTTP reader declines the response and the header would
    /// go unread whatever the rules said.
    #[test]
    fn an_rtsp_options_reply_yields_the_server_that_sent_it() {
        const REPLY: &[u8] = b"RTSP/1.0 200 OK\r\n\
            CSeq: 1\r\n\
            Public: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n\
            Server: GStreamer RTSP server\r\n\r\n";

        let texts = super::from_stream(554, REPLY);
        assert_eq!(texts, vec!["GStreamer RTSP server"]);
        assert_eq!(
            identify(554, &texts[0]).map(|found| found.0),
            Some("GStreamer RTSP Server".to_string())
        );
    }

    /// A camera that names a version has it read, and an HTTP response on the
    /// same port is not mistaken for one.
    #[test]
    fn an_rtsp_reader_declines_what_is_not_rtsp() {
        const CAMERA: &[u8] =
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: AvigilonOnvifNvt/2.6.0.130\r\n\r\n";
        let texts = super::from_stream(554, CAMERA);
        assert_eq!(texts, vec!["AvigilonOnvifNvt/2.6.0.130"]);

        assert!(super::from_stream(554, b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n").is_empty());
        assert!(super::from_stream(554, b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n").is_empty());
        assert!(super::from_stream(554, b"").is_empty());
    }

    /// A negotiate response on its own carries none of it, which is why the
    /// probe had to grow a second message rather than the rules a new pattern.
    #[test]
    fn a_negotiate_response_alone_yields_nothing() {
        let mut negotiate = vec![0x00, 0x00, 0x00, 0x23];
        negotiate.extend_from_slice(b"\xffSMBr");
        negotiate.extend_from_slice(&[0u8; 31]);
        assert!(super::from_stream(445, &negotiate).is_empty());
        assert!(super::from_stream(445, b"").is_empty());
        assert!(super::from_stream(80, b"HTTP/1.1 200 OK").is_empty());
    }

    #[test]
    fn every_new_port_is_worth_a_second_datagram() {
        for port in [
            111, 123, 177, 500, 623, 1434, 2049, 3478, 3702, 4500, 5683, 11211, 19132, 27015,
        ] {
            assert!(super::reads(port, Protocol::Udp), "port {port}");
        }
    }
}
