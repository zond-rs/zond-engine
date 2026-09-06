// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a SIP endpoint says about itself
//!
//! RFC 3261 gives a response the same shape HTTP has: a status line, then
//! headers. Two of them name the software, and the signature corpus is written
//! against their values rather than against the response carrying them, so a
//! rule reads `Cisco-SIPGateway/IOS-12.x` and never matches the reply it arrived
//! in.
//!
//! Most of what answers here is embedded: the corpus names TP-Link, D-Link,
//! Technicolor and a long tail of consumer gateways, which is hardware that
//! identifies itself nowhere else a scan can reach.

/// The header values the corpus is written against.
///
/// `Server` and `User-Agent` both name the software, and RFC 3261 §20 gives
/// neither precedence: a gateway sets one, a phone the other, and a few set
/// both with different strings. So both are offered and the matcher ranks them.
///
/// Empty for anything that is not a SIP response, which costs one prefix
/// comparison.
pub(crate) fn corpus_fields(response: &str) -> Vec<&str> {
    if !response.starts_with("SIP/2.0") {
        return Vec::new();
    }

    ["server", "user-agent"]
        .iter()
        .filter_map(|name| header(response, name))
        .collect()
}

/// The value of the first header named `name`, which must be lowercase.
///
/// Stops at the blank line, so a body that happens to contain a header-shaped
/// line is not read as one. A continuation line is not joined: RFC 3261 §7.3
/// permits folding, no deployed endpoint folds these two, and a value spliced
/// across lines would match no rule in the corpus either way.
fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response
        .lines()
        .skip(1)
        .take_while(|line| !line.trim_end_matches('\r').is_empty())
        .find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header
                .trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim_end_matches('\r').trim())
        })
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gateway naming itself in `Server`, which is the commonest shape and the
    /// one the Cisco rules are written against.
    #[test]
    fn a_server_header_is_offered_as_its_own_text() {
        let response = "SIP/2.0 200 OK\r\n\
             Via: SIP/2.0/UDP nm;branch=zond\r\n\
             Server: Cisco-SIPGateway/IOS-12.x\r\n\
             Content-Length: 0\r\n\r\n";
        assert_eq!(corpus_fields(response), vec!["Cisco-SIPGateway/IOS-12.x"]);
    }

    /// A phone naming itself in `User-Agent` instead. Neither header has
    /// precedence, so a rule may be written against either.
    #[test]
    fn a_user_agent_header_is_offered_too() {
        let response = "SIP/2.0 200 OK\r\n\
             User-Agent: TP-Link SIP Stack V1.0.0\r\n\r\n";
        assert_eq!(corpus_fields(response), vec!["TP-Link SIP Stack V1.0.0"]);
    }

    /// Both, where an endpoint sets both, and in the order they are asked for
    /// rather than the order they arrived.
    #[test]
    fn both_are_offered_where_both_are_present() {
        let response = "SIP/2.0 200 OK\r\n\
             User-Agent: Grandstream HT802 1.0.29.8\r\n\
             Server: Asterisk PBX 18.10.0\r\n\r\n";
        assert_eq!(
            corpus_fields(response),
            vec!["Asterisk PBX 18.10.0", "Grandstream HT802 1.0.29.8"]
        );
    }

    /// The header name is case-insensitive, which deployed endpoints are not
    /// consistent about.
    #[test]
    fn the_header_name_is_matched_whatever_case_it_arrived_in() {
        let response = "SIP/2.0 200 OK\r\nSERVER: Vendor/1.0\r\n\r\n";
        assert_eq!(corpus_fields(response), vec!["Vendor/1.0"]);
    }

    /// A body is not headers. Reading past the blank line would let a message
    /// body state whatever it liked about the machine serving it.
    #[test]
    fn a_header_shaped_line_in_the_body_is_not_read() {
        let response = "SIP/2.0 200 OK\r\n\
             Content-Length: 22\r\n\r\n\
             Server: Not A Real One\r\n";
        assert!(corpus_fields(response).is_empty());
    }

    #[test]
    fn a_reply_that_is_not_sip_yields_nothing() {
        assert!(corpus_fields("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n").is_empty());
        assert!(corpus_fields("220 ProFTPD Server ready").is_empty());
        assert!(corpus_fields("").is_empty());
    }

    /// An endpoint that answers without naming itself is the ordinary case, and
    /// an empty value says no more than an absent one.
    #[test]
    fn an_empty_value_is_not_offered() {
        let response = "SIP/2.0 200 OK\r\nServer: \r\nUser-Agent:\r\n\r\n";
        assert!(corpus_fields(response).is_empty());
    }
}
