// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # JARM
//!
//! A fingerprint of how a TLS server answers, rather than of what it serves.
//!
//! Ten `ClientHello` messages go out, each deliberately unusual in a different
//! way: the cipher list reversed, halved, or dealt from the middle outwards,
//! GREASE values salted in, the protocol list reordered, a 1.3 hello carrying
//! nothing 1.3 can negotiate. What a stack picks out of each is a property of
//! the stack and of how it was configured, not of the certificate it presents,
//! so two hosts running the same software answer alike however differently they
//! are dressed.
//!
//! That is what makes it worth having. A Tor bridge and a Metasploit listener
//! both present a certificate designed to look like nothing in particular, and
//! both answer these ten questions distinctively.
//!
//! ## The algorithm is not this crate's to choose
//!
//! JARM's value is entirely in matching hashes other people published, so every
//! detail here follows the reference implementation exactly: the cipher lists
//! and their order, the extension order, where GREASE goes, which fields are
//! read back, and the shape of the hash. A change that looks like a tidy-up
//! produces hashes that match nothing, and nothing about the result says so.
//! The corpus carries nineteen rules written against published hashes.
//! `every_hello_matches_the_reference_implementation` holds the ten hellos to
//! the reference byte for byte, the tests beside it pin how each answer is
//! coded into the hash, and `a_published_hash_reaches_the_corpus` holds the
//! lookup to those rules.
//!
//! ## What the hash is
//!
//! Sixty-two characters. The first thirty are three per probe: two naming the
//! cipher the server chose, one naming the version. The last thirty-two are a
//! SHA-256 of the ALPN protocol and extension list from all ten answers, joined.
//!
//! A server that answered nothing hashes to sixty-two zeros, which is reported
//! as no fingerprint at all rather than as a fingerprint of silence.

use std::net::SocketAddr;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::analyzer::{Analyzer, PortContext};
use super::model::{Evidence, SourceId};
use super::response::{Collected, ResponseSet};
use crate::config::ServiceDetection;
use crate::model::port::Protocol;
use crate::protocols::tls;

/// How long one probe may take, connection included.
///
/// Ten of these run for every port that speaks TLS, so the budget is per probe
/// and deliberately short: a server that has not answered a hello in this long
/// is not going to, on a path that costs nothing. A scan allows for the path it
/// measured on top (see [`on_path`](super::on_path)).
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// How long all ten probes may take between them: three of them running out
/// their [`PROBE_TIMEOUT`].
///
/// A server answers or refuses a hello in a round trip, so ten of them from
/// one that answers take ten round trips and come nowhere near this. What
/// reaches it is a peer letting hellos go unanswered, which a tarpit or a
/// filter in front of the server does and a TLS stack does not, and each one it
/// lets go costs the whole of a probe's wait. Without a bound on the ten, that
/// is forty seconds a port, which is more than the rest of the port's
/// identification together may take; see
/// [`COLLECTION_BUDGET`](super::COLLECTION_BUDGET).
///
/// A fingerprint that runs out of it is abandoned rather than finished with
/// the rest of its answers empty. A hash is matched whole against published
/// ones, and one whose last answers are missing because this scan stopped
/// asking is not the server's, however like a published one it looks. A scan
/// allows for the path once for each probe on top.
const BUDGET: Duration = Duration::from_secs(12);

/// The most of a `ServerHello` worth reading. A record may be far larger, and
/// nothing past the extension list is part of the fingerprint.
const MAX_REPLY_BYTES: usize = 8192;

/// The hash a server that answered nothing produces.
const EMPTY_HASH: &str = "00000000000000000000000000000000000000000000000000000000000000";

/// Every cipher suite a probe offers, in the order the algorithm fixes.
///
/// The order is the fingerprint. Five of the ten probes send this list rearranged,
/// and what a server picks out of each arrangement is what separates one stack
/// from another.
const SUITES_ALL: &[[u8; 2]] = &[
    [0x00, 0x16],
    [0x00, 0x33],
    [0x00, 0x67],
    [0xc0, 0x9e],
    [0xc0, 0xa2],
    [0x00, 0x9e],
    [0x00, 0x39],
    [0x00, 0x6b],
    [0xc0, 0x9f],
    [0xc0, 0xa3],
    [0x00, 0x9f],
    [0x00, 0x45],
    [0x00, 0xbe],
    [0x00, 0x88],
    [0x00, 0xc4],
    [0x00, 0x9a],
    [0xc0, 0x08],
    [0xc0, 0x09],
    [0xc0, 0x23],
    [0xc0, 0xac],
    [0xc0, 0xae],
    [0xc0, 0x2b],
    [0xc0, 0x0a],
    [0xc0, 0x24],
    [0xc0, 0xad],
    [0xc0, 0xaf],
    [0xc0, 0x2c],
    [0xc0, 0x72],
    [0xc0, 0x73],
    [0xcc, 0xa9],
    [0x13, 0x02],
    [0x13, 0x01],
    [0xcc, 0x14],
    [0xc0, 0x07],
    [0xc0, 0x12],
    [0xc0, 0x13],
    [0xc0, 0x27],
    [0xc0, 0x2f],
    [0xc0, 0x14],
    [0xc0, 0x28],
    [0xc0, 0x30],
    [0xc0, 0x60],
    [0xc0, 0x61],
    [0xc0, 0x76],
    [0xc0, 0x77],
    [0xcc, 0xa8],
    [0x13, 0x05],
    [0x13, 0x04],
    [0x13, 0x03],
    [0xcc, 0x13],
    [0xc0, 0x11],
    [0x00, 0x0a],
    [0x00, 0x2f],
    [0x00, 0x3c],
    [0xc0, 0x9c],
    [0xc0, 0xa0],
    [0x00, 0x9c],
    [0x00, 0x35],
    [0x00, 0x3d],
    [0xc0, 0x9d],
    [0xc0, 0xa1],
    [0x00, 0x9d],
    [0x00, 0x41],
    [0x00, 0xba],
    [0x00, 0x84],
    [0x00, 0xc0],
    [0x00, 0x07],
    [0x00, 0x04],
    [0x00, 0x05],
];

/// The same list without the TLS 1.3 suites, for the probe that offers a 1.3
/// hello and nothing 1.3 can negotiate.
const SUITES_NO_TLS13: &[[u8; 2]] = &[
    [0x00, 0x16],
    [0x00, 0x33],
    [0x00, 0x67],
    [0xc0, 0x9e],
    [0xc0, 0xa2],
    [0x00, 0x9e],
    [0x00, 0x39],
    [0x00, 0x6b],
    [0xc0, 0x9f],
    [0xc0, 0xa3],
    [0x00, 0x9f],
    [0x00, 0x45],
    [0x00, 0xbe],
    [0x00, 0x88],
    [0x00, 0xc4],
    [0x00, 0x9a],
    [0xc0, 0x08],
    [0xc0, 0x09],
    [0xc0, 0x23],
    [0xc0, 0xac],
    [0xc0, 0xae],
    [0xc0, 0x2b],
    [0xc0, 0x0a],
    [0xc0, 0x24],
    [0xc0, 0xad],
    [0xc0, 0xaf],
    [0xc0, 0x2c],
    [0xc0, 0x72],
    [0xc0, 0x73],
    [0xcc, 0xa9],
    [0xcc, 0x14],
    [0xc0, 0x07],
    [0xc0, 0x12],
    [0xc0, 0x13],
    [0xc0, 0x27],
    [0xc0, 0x2f],
    [0xc0, 0x14],
    [0xc0, 0x28],
    [0xc0, 0x30],
    [0xc0, 0x60],
    [0xc0, 0x61],
    [0xc0, 0x76],
    [0xc0, 0x77],
    [0xcc, 0xa8],
    [0xcc, 0x13],
    [0xc0, 0x11],
    [0x00, 0x0a],
    [0x00, 0x2f],
    [0x00, 0x3c],
    [0xc0, 0x9c],
    [0xc0, 0xa0],
    [0x00, 0x9c],
    [0x00, 0x35],
    [0x00, 0x3d],
    [0xc0, 0x9d],
    [0xc0, 0xa1],
    [0x00, 0x9d],
    [0x00, 0x41],
    [0x00, 0xba],
    [0x00, 0x84],
    [0x00, 0xc0],
    [0x00, 0x07],
    [0x00, 0x04],
    [0x00, 0x05],
];

/// The suites a hash has a code for, in the order that assigns it.
///
/// A suite's code is its one-based index in this list, written as two hex digits,
/// and a suite absent from it, or no suite at all, is `00`. Sorted differently
/// from the offer lists above, and deliberately: this is the hash's own ordering
/// and changing it would change every hash ever published.
const CODED_SUITES: &[[u8; 2]] = &[
    [0x00, 0x04],
    [0x00, 0x05],
    [0x00, 0x07],
    [0x00, 0x0a],
    [0x00, 0x16],
    [0x00, 0x2f],
    [0x00, 0x33],
    [0x00, 0x35],
    [0x00, 0x39],
    [0x00, 0x3c],
    [0x00, 0x3d],
    [0x00, 0x41],
    [0x00, 0x45],
    [0x00, 0x67],
    [0x00, 0x6b],
    [0x00, 0x84],
    [0x00, 0x88],
    [0x00, 0x9a],
    [0x00, 0x9c],
    [0x00, 0x9d],
    [0x00, 0x9e],
    [0x00, 0x9f],
    [0x00, 0xba],
    [0x00, 0xbe],
    [0x00, 0xc0],
    [0x00, 0xc4],
    [0xc0, 0x07],
    [0xc0, 0x08],
    [0xc0, 0x09],
    [0xc0, 0x0a],
    [0xc0, 0x11],
    [0xc0, 0x12],
    [0xc0, 0x13],
    [0xc0, 0x14],
    [0xc0, 0x23],
    [0xc0, 0x24],
    [0xc0, 0x27],
    [0xc0, 0x28],
    [0xc0, 0x2b],
    [0xc0, 0x2c],
    [0xc0, 0x2f],
    [0xc0, 0x30],
    [0xc0, 0x60],
    [0xc0, 0x61],
    [0xc0, 0x72],
    [0xc0, 0x73],
    [0xc0, 0x76],
    [0xc0, 0x77],
    [0xc0, 0x9c],
    [0xc0, 0x9d],
    [0xc0, 0x9e],
    [0xc0, 0x9f],
    [0xc0, 0xa0],
    [0xc0, 0xa1],
    [0xc0, 0xa2],
    [0xc0, 0xa3],
    [0xc0, 0xac],
    [0xc0, 0xad],
    [0xc0, 0xae],
    [0xc0, 0xaf],
    [0xcc, 0x13],
    [0xcc, 0x14],
    [0xcc, 0xa8],
    [0xcc, 0xa9],
    [0x13, 0x01],
    [0x13, 0x02],
    [0x13, 0x03],
    [0x13, 0x04],
    [0x13, 0x05],
];

/// How one probe's hello differs from the others.
///
/// The ten values below are the algorithm's own, and the fingerprint is what a
/// server makes of the differences between them.
#[derive(Debug, Clone, Copy)]
struct Probe {
    /// The version the record and the hello announce.
    version: Version,
    /// Whether the offer includes the TLS 1.3 suites.
    suites: Suites,
    /// How the cipher list is rearranged before it is sent.
    order: Order,
    /// Whether GREASE values are salted into the offer.
    grease: bool,
    /// Whether the protocol list drops the two every browser sends.
    alpn: Alpn,
    /// What the `supported_versions` extension says, where it is sent at all.
    supported: Supported,
    /// How the protocol and version lists inside the extensions are ordered.
    extension_order: Order,
}

/// The version a probe announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    Tls11,
    Tls12,
    Tls13,
}

/// Which cipher list a probe offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suites {
    All,
    NoTls13,
}

/// How a list is rearranged before it goes on the wire.
///
/// The rearrangements are the point: a server with a preference of its own
/// answers all of them the same way, and one that takes the client's first
/// acceptable offer answers each differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Order {
    Forward,
    Reverse,
    TopHalf,
    BottomHalf,
    MiddleOut,
}

/// Which protocols the ALPN extension offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Alpn {
    /// Everything, weakest first.
    All,
    /// The same without `http/1.1` and `h2`, so a server that insists on one of
    /// them has nothing to choose.
    Rare,
}

/// What the `supported_versions` extension carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Supported {
    /// Not sent.
    None,
    /// Up to 1.2, so a 1.3 server has to decline.
    Tls12,
    /// Up to 1.3.
    Tls13,
}

/// The ten probes, in the order their answers are hashed.
///
/// Reordering them changes every hash, so this list is fixed by the algorithm
/// rather than by taste.
const PROBES: [Probe; 10] = [
    Probe {
        version: Version::Tls12,
        suites: Suites::All,
        order: Order::Forward,
        grease: false,
        alpn: Alpn::All,
        supported: Supported::Tls12,
        extension_order: Order::Reverse,
    },
    Probe {
        version: Version::Tls12,
        suites: Suites::All,
        order: Order::Reverse,
        grease: false,
        alpn: Alpn::All,
        supported: Supported::Tls12,
        extension_order: Order::Forward,
    },
    Probe {
        version: Version::Tls12,
        suites: Suites::All,
        order: Order::TopHalf,
        grease: false,
        alpn: Alpn::All,
        supported: Supported::None,
        extension_order: Order::Forward,
    },
    Probe {
        version: Version::Tls12,
        suites: Suites::All,
        order: Order::BottomHalf,
        grease: false,
        alpn: Alpn::Rare,
        supported: Supported::None,
        extension_order: Order::Forward,
    },
    Probe {
        version: Version::Tls12,
        suites: Suites::All,
        order: Order::MiddleOut,
        grease: true,
        alpn: Alpn::Rare,
        supported: Supported::None,
        extension_order: Order::Reverse,
    },
    Probe {
        version: Version::Tls11,
        suites: Suites::All,
        order: Order::Forward,
        grease: false,
        alpn: Alpn::All,
        supported: Supported::None,
        extension_order: Order::Forward,
    },
    Probe {
        version: Version::Tls13,
        suites: Suites::All,
        order: Order::Forward,
        grease: false,
        alpn: Alpn::All,
        supported: Supported::Tls13,
        extension_order: Order::Reverse,
    },
    Probe {
        version: Version::Tls13,
        suites: Suites::All,
        order: Order::Reverse,
        grease: false,
        alpn: Alpn::All,
        supported: Supported::Tls13,
        extension_order: Order::Forward,
    },
    Probe {
        version: Version::Tls13,
        suites: Suites::NoTls13,
        order: Order::Forward,
        grease: false,
        alpn: Alpn::All,
        supported: Supported::Tls13,
        extension_order: Order::Forward,
    },
    Probe {
        version: Version::Tls13,
        suites: Suites::All,
        order: Order::MiddleOut,
        grease: true,
        alpn: Alpn::All,
        supported: Supported::Tls13,
        extension_order: Order::Reverse,
    },
];

/// Rearranges `items` as `order` says.
///
/// `TopHalf` and `MiddleOut` are the two that need reading twice. The top half
/// is the list reversed and then halved, which is not the same as the first
/// half reversed, and an odd-length list gives its middle element to the top
/// half. `MiddleOut` deals outwards from the centre, taking the later of each
/// pair first.
fn rearrange<T: Copy>(items: &[T], order: Order) -> Vec<T> {
    let len = items.len();
    match order {
        Order::Forward => items.to_vec(),
        Order::Reverse => items.iter().rev().copied().collect(),
        Order::BottomHalf => match len % 2 {
            1 => items[len / 2 + 1..].to_vec(),
            _ => items[len / 2..].to_vec(),
        },
        Order::TopHalf => {
            let mut out = Vec::with_capacity(len.div_ceil(2));
            if len % 2 == 1 {
                out.push(items[len / 2]);
            }
            out.extend(rearrange(
                &rearrange(items, Order::Reverse),
                Order::BottomHalf,
            ));
            out
        }
        Order::MiddleOut => {
            let middle = len / 2;
            let mut out = Vec::with_capacity(len);
            if len % 2 == 1 {
                out.push(items[middle]);
                for step in 1..=middle {
                    out.push(items[middle + step]);
                    out.push(items[middle - step]);
                }
            } else {
                for step in 1..=middle {
                    out.push(items[middle - 1 + step]);
                    out.push(items[middle - step]);
                }
            }
            out
        }
    }
}

/// One of the sixteen values reserved to look like a cipher suite nobody
/// implements.
///
/// A server that negotiates one is broken, and one that chokes on the sight of
/// one is distinctive, which is why two of the ten probes send them. Chosen at
/// random per hello, as the reference does: the value is not part of the
/// fingerprint and a fixed one would be a signature of this scanner.
fn grease() -> [u8; 2] {
    const VALUES: [u8; 16] = [
        0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a, 0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea,
        0xfa,
    ];
    let pick = VALUES[rand::random_range(0..VALUES.len())];
    [pick, pick]
}

/// Where a hello's unpredictable parts come from.
///
/// Four of them: the client random, the session id, the key share, and the
/// GREASE value two of the ten probes salt in. None reaches the fingerprint,
/// which reads only what comes back, so the choice is free.
///
/// It is a parameter rather than a call to [`grease`] and [`rand`] in place so
/// a test can fix it and compare a hello to the reference implementation's byte
/// for byte. That comparison is the only offline way to hold these ten
/// questions to the ten JARM actually asks; everything else needs a server.
enum Entropy {
    /// What a scan sends.
    Live,
    /// One byte repeated for every random field, and one GREASE value, so a
    /// hello is reproducible. Only a test has a reason to send one.
    #[cfg(test)]
    Fixed { fill: u8, grease: u8 },
}

impl Entropy {
    /// A random field's worth.
    fn fill(&self) -> [u8; 32] {
        match self {
            Entropy::Live => rand::random(),
            #[cfg(test)]
            Entropy::Fixed { fill, .. } => [*fill; 32],
        }
    }

    /// A GREASE value, which is always a byte repeated.
    fn grease(&self) -> [u8; 2] {
        match self {
            Entropy::Live => grease(),
            #[cfg(test)]
            Entropy::Fixed { grease, .. } => [*grease; 2],
        }
    }
}

/// The `ClientHello` record one probe sends.
///
/// Assembled by hand rather than through
/// [`protocols::tls::client_hello`](crate::protocols::tls::client_hello),
/// which builds an ordinary hello and offers no way to say any of what makes
/// these ten different. Bending it to would make a general-purpose function
/// answer to this one caller.
fn hello(probe: &Probe, host: &str, entropy: &Entropy) -> Vec<u8> {
    // A 1.3 hello announces 1.2 in the record and the body, and says 1.3 in the
    // extension. The others announce themselves.
    let (record_version, body_version): ([u8; 2], [u8; 2]) = match probe.version {
        Version::Tls11 => ([0x03, 0x02], [0x03, 0x02]),
        Version::Tls12 => ([0x03, 0x03], [0x03, 0x03]),
        Version::Tls13 => ([0x03, 0x01], [0x03, 0x03]),
    };

    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&body_version);
    body.extend_from_slice(&entropy.fill());

    // A session id is sent, and a random one, which an ordinary hello opening a
    // fresh connection would leave empty.
    body.push(32);
    body.extend_from_slice(&entropy.fill());

    let offered = suites(probe, entropy);
    body.extend_from_slice(&(offered.len() as u16).to_be_bytes());
    body.extend_from_slice(&offered);

    // One compression method, null.
    body.push(0x01);
    body.push(0x00);

    body.extend_from_slice(&extensions(probe, host, entropy));

    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01);
    handshake.push(0x00);
    handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(0x16);
    record.extend_from_slice(&record_version);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// The cipher suites one probe offers, rearranged and salted as it says.
fn suites(probe: &Probe, entropy: &Entropy) -> Vec<u8> {
    let list = match probe.suites {
        Suites::All => SUITES_ALL,
        Suites::NoTls13 => SUITES_NO_TLS13,
    };
    let mut ordered = rearrange(list, probe.order);
    if probe.grease {
        ordered.insert(0, entropy.grease());
    }
    ordered.concat()
}

/// The extension block, in the order the algorithm fixes.
///
/// The order is part of the fingerprint. A stack that reads extensions in the
/// order they arrive answers differently from one that indexes them, and the
/// reference sends them exactly like this.
fn extensions(probe: &Probe, host: &str, entropy: &Entropy) -> Vec<u8> {
    let mut all = Vec::with_capacity(256);

    if probe.grease {
        all.extend_from_slice(&entropy.grease());
        all.extend_from_slice(&[0x00, 0x00]);
    }

    all.extend_from_slice(&server_name(host));
    all.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // extended master secret
    all.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x01]); // max fragment length
    all.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]); // renegotiation info
    all.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
    ]); // supported groups
    all.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]); // ec point formats
    all.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]); // session ticket
    all.extend_from_slice(&alpn(probe));
    all.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08,
        0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
    ]); // signature algorithms
    all.extend_from_slice(&key_share(probe.grease, entropy));
    all.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]); // psk key exchange modes

    if probe.version == Version::Tls13 || probe.supported == Supported::Tls12 {
        all.extend_from_slice(&supported_versions(probe, entropy));
    }

    let mut out = Vec::with_capacity(all.len() + 2);
    out.extend_from_slice(&(all.len() as u16).to_be_bytes());
    out.extend_from_slice(&all);
    out
}

/// The `server_name` extension naming the host as it was addressed.
fn server_name(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut out = vec![0x00, 0x00];
    out.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
    out.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    out.push(0x00);
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name);
    out
}

/// The protocol list, weakest first, rearranged as the probe says.
fn alpn(probe: &Probe) -> Vec<u8> {
    const HTTP_0_9: &[u8] = b"\x08http/0.9";
    const HTTP_1_0: &[u8] = b"\x08http/1.0";
    const HTTP_1_1: &[u8] = b"\x08http/1.1";
    const SPDY_1: &[u8] = b"\x06spdy/1";
    const SPDY_2: &[u8] = b"\x06spdy/2";
    const SPDY_3: &[u8] = b"\x06spdy/3";
    const H2: &[u8] = b"\x02h2";
    const H2C: &[u8] = b"\x03h2c";
    const HQ: &[u8] = b"\x02hq";

    let list: Vec<&[u8]> = match probe.alpn {
        Alpn::All => vec![
            HTTP_0_9, HTTP_1_0, HTTP_1_1, SPDY_1, SPDY_2, SPDY_3, H2, H2C, HQ,
        ],
        // Without the two a browser sends, so a server that will speak only one
        // of them has nothing to choose and has to say so.
        Alpn::Rare => vec![HTTP_0_9, HTTP_1_0, SPDY_1, SPDY_2, SPDY_3, H2C, HQ],
    };

    let protocols: Vec<u8> = rearrange(&list, probe.extension_order).concat();
    let mut out = vec![0x00, 0x10];
    out.extend_from_slice(&((protocols.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&(protocols.len() as u16).to_be_bytes());
    out.extend_from_slice(&protocols);
    out
}

/// The `key_share` extension, offering x25519 and nothing else.
fn key_share(with_grease: bool, entropy: &Entropy) -> Vec<u8> {
    let mut shares = Vec::with_capacity(64);
    if with_grease {
        shares.extend_from_slice(&entropy.grease());
        shares.extend_from_slice(&[0x00, 0x01, 0x00]);
    }
    shares.extend_from_slice(&[0x00, 0x1d]); // x25519
    shares.extend_from_slice(&[0x00, 0x20]);
    shares.extend_from_slice(&entropy.fill());

    let mut out = vec![0x00, 0x33];
    out.extend_from_slice(&((shares.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&(shares.len() as u16).to_be_bytes());
    out.extend_from_slice(&shares);
    out
}

/// The `supported_versions` extension, oldest first before any rearrangement.
fn supported_versions(probe: &Probe, entropy: &Entropy) -> Vec<u8> {
    let list: Vec<[u8; 2]> = match probe.supported {
        // Stopping at 1.2 is a question rather than an omission: a 1.3 server
        // asked this has to come down, and what it comes down to is the answer.
        Supported::Tls12 => vec![[0x03, 0x01], [0x03, 0x02], [0x03, 0x03]],
        _ => vec![[0x03, 0x01], [0x03, 0x02], [0x03, 0x03], [0x03, 0x04]],
    };

    let mut versions = Vec::with_capacity(16);
    if probe.grease {
        versions.extend_from_slice(&entropy.grease());
    }
    versions.extend_from_slice(&rearrange(&list, probe.extension_order).concat());

    let mut out = vec![0x00, 0x2b];
    out.extend_from_slice(&((versions.len() + 1) as u16).to_be_bytes());
    out.push(versions.len() as u8);
    out.extend_from_slice(&versions);
    out
}

/// What one probe's answer contributes to the hash.
///
/// Four parts, the shape the reference reads them in: the cipher chosen, the
/// version chosen, the protocol agreed by ALPN, and the extension types in the
/// order the server listed them. A probe that drew an alert, a refusal or
/// nothing at all contributes all four empty, which is not the same as nothing:
/// silence in answer to one hello and not the others is itself distinguishing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Answer {
    cipher: String,
    version: String,
    alpn: String,
    extensions: String,
}

/// Reads one `ServerHello`.
///
/// Offsets are the reference's, counted from the record header, and the session
/// id's length at byte 43 is what shifts everything after it. Nothing here
/// trusts a length: a hello that did not all arrive, or whose extensions claim
/// more than it holds, returns an empty answer, which is what a refusal returns
/// too.
fn read_answer(reply: &[u8]) -> Answer {
    // An alert rather than a handshake: the server declined this hello.
    if reply.first() != Some(&0x16) || reply.get(5) != Some(&0x02) {
        return Answer::default();
    }

    // All of the hello or none of it. Part of one has its cipher and version
    // right and its extension list wrong, which hashes to something nobody
    // published; every hello a published hash was taken from arrived whole.
    let Some(end) = tls::server_hello_end(reply) else {
        return Answer::default();
    };

    let Some(&session_id_len) = reply.get(43) else {
        return Answer::default();
    };
    let counter = session_id_len as usize;

    let (Some(cipher), Some(version)) = (reply.get(counter + 44..counter + 46), reply.get(9..11))
    else {
        return Answer::default();
    };

    let hello_length = match reply.get(3..5) {
        Some(bytes) => u16::from_be_bytes([bytes[0], bytes[1]]) as usize,
        None => return Answer::default(),
    };

    let Some((alpn, extensions)) = read_extensions(reply, counter, hello_length, end) else {
        return Answer::default();
    };
    Answer {
        cipher: hex(cipher),
        version: hex(version),
        alpn,
        extensions,
    }
}

/// The ALPN protocol a server agreed and the extension types it sent, in order,
/// or `None` where the extension list runs past the hello's end at `end`.
///
/// Returns both empty where the hello carries no usable extension block. The
/// three refusals checked for first are the reference's, and they are shapes
/// rather than lengths: a handshake failure alert inside the record, and two
/// byte sequences that mark a server answering something other than this
/// question. They read the reply as it arrived, past the hello included,
/// because that is what the reference reads them against.
///
/// A list running past the hello is refused rather than read as far as it
/// goes. The reference abandons the whole answer when its walk runs out of
/// bytes, and a list read part way is a hash nobody published rather than a
/// missing one.
fn read_extensions(
    reply: &[u8],
    counter: usize,
    hello_length: usize,
    end: usize,
) -> Option<(String, String)> {
    let empty = Some((String::new(), String::new()));

    if reply.get(counter + 47) == Some(&11)
        || reply.get(counter + 50..counter + 53) == Some(&[0x0e, 0xac, 0x0b][..])
        || reply.get(82..85) == Some(&[0x0f, 0xf0, 0x0b][..])
        || counter + 42 >= hello_length
    {
        return empty;
    }

    let Some(stated) = reply.get(counter + 47..counter + 49) else {
        return empty;
    };
    let length = u16::from_be_bytes([stated[0], stated[1]]) as usize;

    let mut at = counter + 49;
    if at + length > end {
        return None;
    }
    // Walked within the hello, since what follows it is another message.
    let hello = reply.get(..end)?;
    let maximum = length + at - 1;
    let mut types = Vec::new();
    let mut alpn = String::new();

    while at < maximum {
        let kind = hello.get(at..at + 2)?;
        let size = hello.get(at + 2..at + 4)?;
        let size = u16::from_be_bytes([size[0], size[1]]) as usize;

        // The ALPN extension's value is a list, and the protocol agreed sits
        // behind three bytes of framing.
        if kind == [0x00, 0x10]
            && let Some(value) = hello.get(at + 4 + 3..at + 4 + size)
        {
            alpn = String::from_utf8_lossy(value).into_owned();
        }

        types.push(hex(kind));
        at += size + 4;
    }

    Some((alpn, types.join("-")))
}

/// The sixty-two character hash of ten answers.
///
/// Three characters per probe naming what it drew, then a SHA-256 of everything
/// the ten said about protocols and extensions, truncated. The truncation is the
/// algorithm's, not a shortening chosen here.
fn hash(answers: &[Answer]) -> String {
    // Ten answers that said nothing hash to zeros rather than to the digest of
    // the empty string. The reference special-cases it the same way, and it is
    // load-bearing: without it every unreachable host would share one perfectly
    // ordinary-looking fingerprint, and `fingerprint` would hand it back as a
    // finding.
    if answers.iter().all(|answer| answer == &Answer::default()) {
        return EMPTY_HASH.to_string();
    }

    let mut fuzzy = String::with_capacity(62);
    let mut spelled = String::new();

    for answer in answers {
        fuzzy.push_str(&cipher_code(&answer.cipher));
        fuzzy.push(version_code(&answer.version));
        spelled.push_str(&answer.alpn);
        spelled.push_str(&answer.extensions);
    }

    let digest = Sha256::digest(spelled.as_bytes());
    fuzzy.push_str(&hex(&digest)[..32]);
    fuzzy
}

/// A cipher's two-character code: its one-based place in [`CODED_SUITES`].
///
/// A suite the list does not carry takes the code one past its end, which is
/// what the reference's loop leaves behind when it finds no match, and no suite
/// at all is `00`.
fn cipher_code(cipher: &str) -> String {
    if cipher.is_empty() {
        return "00".to_string();
    }
    let place = CODED_SUITES
        .iter()
        .position(|suite| hex(suite) == cipher)
        .map_or(CODED_SUITES.len() + 1, |index| index + 1);

    format!("{place:02x}")
}

/// A version's single character: `a` for SSL 3.0 through `f` for TLS 1.3.
fn version_code(version: &str) -> char {
    const LETTERS: [char; 6] = ['a', 'b', 'c', 'd', 'e', 'f'];
    version
        .chars()
        .nth(3)
        .and_then(|digit| digit.to_digit(16))
        .and_then(|index| LETTERS.get(index as usize).copied())
        .unwrap_or('0')
}

/// Lowercase hex, which is the only spelling any of this compares against.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The JARM fingerprint of the TLS service at `addr`, or [`None`] where it
/// answered none of the ten probes.
///
/// Ten connections, one per probe, made in turn rather than at once: they are
/// the same conversation asked ten ways, and a server that rate-limits or
/// tarpits should meet a scanner behaving like one client rather than ten.
///
/// `host` is what the `server_name` extension carries. A growing number of
/// servers answer a nameless hello differently, or not at all, so the name a
/// target was reached by is part of the question and the address stands in
/// where there is no name.
///
/// All ten are asked within [`BUDGET`], each within [`PROBE_TIMEOUT`], both
/// allowing for the path; a fingerprint the budget cuts short is [`None`].
pub async fn fingerprint(addr: SocketAddr, host: &str) -> Option<String> {
    let waits = u32::try_from(PROBES.len()).unwrap_or(u32::MAX);
    let limits = Limits {
        probe: super::on_path(PROBE_TIMEOUT),
        all: super::on_path_each(BUDGET, waits),
    };
    fingerprint_within(addr, host, limits).await
}

/// How long a fingerprint may wait, set apart from [`fingerprint`] so a test
/// can shorten both.
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// One probe, connection included.
    probe: Duration,
    /// All ten.
    all: Duration,
}

/// [`fingerprint`], within `limits`.
async fn fingerprint_within(addr: SocketAddr, host: &str, limits: Limits) -> Option<String> {
    let asked = async {
        let mut answers = Vec::with_capacity(PROBES.len());
        for probe in &PROBES {
            answers.push(
                match timeout(limits.probe, exchange(addr, probe, host)).await {
                    Ok(Some(reply)) => read_answer(&reply),
                    Ok(None) | Err(_) => Answer::default(),
                },
            );
        }
        answers
    };
    let answers = timeout(limits.all, asked).await.ok()?;

    let found = hash(&answers);
    (found != EMPTY_HASH).then_some(found)
}

/// Sends one hello and reads back as much of the answer as the fingerprint
/// reads. [`None`] on any failure, which the caller treats as an empty answer.
///
/// Read until the hello is whole rather than for one read: TCP delivers a
/// record in as many pieces as it likes, and the first piece taken for the
/// whole answer is a hello the reader has to refuse. Where the first read
/// holds the whole hello, which is nearly always, this is the one read the
/// reference makes. What has arrived when the peer stops is handed on, and the
/// reader refuses it if it is short of a hello.
///
/// Unbounded in itself: the caller gives it [`PROBE_TIMEOUT`] for the whole,
/// connection, hello and answer together, and what has arrived when that runs
/// out is lost with it. That loses no answer, since the reader would refuse a
/// hello still arriving then as short.
async fn exchange(addr: SocketAddr, probe: &Probe, host: &str) -> Option<Vec<u8>> {
    let mut stream = super::analyzer_connect(addr).await.ok()?;
    let hello = hello(probe, host, &Entropy::Live);

    stream.write_all(&hello).await.ok()?;

    let mut reply = vec![0u8; MAX_REPLY_BYTES];
    let mut filled = 0;
    while filled < reply.len() && wants_more(&reply[..filled]) {
        match stream.read(&mut reply[filled..]).await {
            Ok(0) | Err(_) => break,
            Ok(read) => filled += read,
        }
    }
    reply.truncate(filled);

    (!reply.is_empty()).then_some(reply)
}

/// Whether `reply` is still short of what the fingerprint reads.
///
/// Reading stops at the end of the ServerHello, since nothing past it is part
/// of the answer, and at the end of the first record where that comes first: a
/// hello its record does not complete is split across records, which the
/// reference does not read either, and a server that has said all it will
/// until the client speaks would otherwise hold the probe to its budget.
fn wants_more(reply: &[u8]) -> bool {
    if tls::server_hello_end(reply).is_some() {
        return false;
    }
    match tls::record_length(reply) {
        Some(total) => reply.len() < total,
        // Either the header has not all arrived, or it announced a record no
        // peer may send.
        None => reply.len() < tls::RECORD_HEADER_LEN,
    }
}

/// Identifies a TLS stack, and often the product behind it, by how it answers
/// ten deliberately awkward hellos.
///
/// Active, and the most expensive analyzer here: ten connections where the
/// favicon costs one. Three things keep that in proportion.
///
/// The first is the level. This runs only at
/// [`ServiceDetection::Thorough`],
/// the level whose whole meaning is that the caller has asked for every question
/// the corpus has. Ten hellos, half of them malformed on purpose, is also a
/// shape an IDS is written to notice, and a default scan should not wear it.
///
/// The second is the gate on TLS. [`interested`](Analyzer::interested) is handed
/// no responses, so the level and the transport are all it can read;
/// [`collect`](Analyzer::collect) sees the responses and asks the only question
/// that matters, which is whether a handshake happened at all. `responses.tls`
/// rather than the tunnel: a server too old for this engine's TLS client still
/// records a version there, and those are exactly the devices the corpus names.
///
/// The third is where the hash goes. A JARM rule is registered under no port —
/// a Chromecast and a Cobalt Strike listener are not on one — so it is matched
/// by `SignatureDb::identify_jarm`, against the
/// rules written for a hash and nothing else. Not the whole corpus: sixty-two
/// hex characters also satisfies an ISAKMP baseline written for a vendor-id
/// list, which would name every unrecognised TLS stack an IKE gateway.
pub struct JarmAnalyzer;

#[async_trait::async_trait]
impl Analyzer for JarmAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::Jarm
    }

    fn interested(&self, ctx: &PortContext) -> bool {
        // TCP with a peer to dial, and only where the caller asked for the
        // thorough level. Whether the port speaks TLS is `collect`'s question:
        // nothing here has seen a response yet.
        ctx.protocol == Protocol::Tcp
            && ctx.addr.is_some()
            && ctx.detection >= ServiceDetection::Thorough
    }

    async fn collect(&self, ctx: &PortContext, responses: &ResponseSet) -> Collected {
        // No handshake, no fingerprint. Ten hellos to a plaintext port would
        // read ten protocol errors and hash them into something meaningless.
        if responses.tls.is_none() {
            return Collected::default();
        }
        let Some(addr) = ctx.addr else {
            return Collected::default();
        };

        // The address as SNI, because it is the only name this engine has: a
        // scan addresses a host by number, and the published hashes this is
        // matched against were harvested the same way.
        let host = addr.ip().to_string();
        match fingerprint(addr, &host).await {
            Some(found) => Collected::from_frames(vec![found.into_bytes()]),
            None => Collected::default(),
        }
    }

    fn analyze(
        &self,
        _ctx: &PortContext,
        _responses: &ResponseSet,
        collected: &Collected,
    ) -> Vec<Evidence> {
        let Some(frame) = collected.frames.first() else {
            return Vec::new();
        };
        let Ok(found) = std::str::from_utf8(frame) else {
            return Vec::new();
        };

        super::db::SignatureDb::global()
            .identify_jarm(found)
            .map(|evidence| vec![as_handshake_reading(evidence)])
            .unwrap_or_default()
    }
}

/// Marks a corpus match as this analyzer's, and says so in the port table.
///
/// The note matters more here than anywhere else. A JARM rule very often names
/// a product nothing else on the port named — a Cobalt Strike listener presents
/// a plausible certificate and no banner at all — so without a word about where
/// the name came from, a reader sees `Cobalt Strike Listener` appear beside a
/// blank-looking web server and has nothing to weigh it against.
///
/// Only where the rule states no detail of its own, which stays the more
/// specific thing to say.
fn as_handshake_reading(mut evidence: Evidence) -> Evidence {
    evidence.source = SourceId::Jarm;
    if evidence.extrainfo.is_none() {
        evidence = evidence.with_extrainfo("TLS fingerprint".to_string());
    }
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::loopback::accept_from_this_process;

    /// The entropy the golden vectors below were generated with: the reference
    /// implementation run with `os.urandom` returning `0xab` and `choose_grease`
    /// returning `\x5a\x5a`.
    const FIXED: Entropy = Entropy::Fixed {
        fill: 0xab,
        grease: 0x5a,
    };

    /// The host the vectors were generated against. It reaches the wire in the
    /// `server_name` extension, so it is part of what they pin.
    const VECTOR_HOST: &str = "192.168.64.4";

    fn sha256_hex(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }

    /// Every probe's `ClientHello`, byte for byte, as the reference builds it.
    ///
    /// The length and the digest of each of the ten records, taken from
    /// `jarm.py` with its two sources of randomness pinned. This is the test
    /// that matters: a JARM hash is worth nothing unless the questions are the
    /// ones everybody else asked, and a wrong byte anywhere — a cipher out of
    /// order, an extension moved, GREASE in the wrong place — produces hashes
    /// that match no published rule and says nothing about it.
    ///
    /// Regenerating these against a modified reference is not a fix. The
    /// algorithm is frozen by everyone who has already published a hash.
    #[test]
    fn every_hello_matches_the_reference_implementation() {
        const VECTORS: [(&str, usize, &str); 10] = [
            (
                "tls1_2_forward",
                426,
                "5000b1706a88d1009fb1247de87295804dba8099e8d72d61beea912c5a84ec29",
            ),
            (
                "tls1_2_reverse",
                426,
                "a62c054d4aff4afa6895fb1744f7cef2c5c343c2ac9ad5f50ca28349ef9cc886",
            ),
            (
                "tls1_2_top_half",
                347,
                "88d7cf577b0e938c221e0a1257984502a645165e2c8067e4204821167f8ce9bd",
            ),
            (
                "tls1_2_bottom_half",
                333,
                "210d2b8b1276ba0225bfee3bcb4d8fac834a00171bd7b679ca439e4313abe9be",
            ),
            (
                "tls1_2_middle_out",
                414,
                "2cb29950f961ba34ce7cd61e18ee03c915946415be76598a890b15a0e1db6941",
            ),
            (
                "tls1_1_middle_out",
                415,
                "19da4c2c0142b37772088d23a78883f7e436311c7c6431c08622e4256e8c97c2",
            ),
            (
                "tls1_3_forward",
                428,
                "6bc238b720a46538d34944da9995ba8532d93ace35dcb68726ad05380ec752f9",
            ),
            (
                "tls1_3_reverse",
                428,
                "4faef2f68ec0f294509f5780f87b329208e3618c32d32a27a676b9f617db6e40",
            ),
            (
                "tls1_3_invalid",
                418,
                "9c627ca140aa5f451720c3b7bca51cc20caa5c588f169131d0f0abfea9959914",
            ),
            (
                "tls1_3_middle_out",
                441,
                "ce7e02b6e208db87617b4254d55d05b9f3d58f75269c02c61be547f50efbc492",
            ),
        ];

        assert_eq!(
            PROBES.len(),
            VECTORS.len(),
            "the ten probes and the ten vectors are the same list"
        );

        for (probe, (name, length, digest)) in PROBES.iter().zip(VECTORS) {
            let built = hello(probe, VECTOR_HOST, &FIXED);
            assert_eq!(built.len(), length, "{name}: record length");
            assert_eq!(sha256_hex(&built), digest, "{name}: record bytes");
        }
    }

    /// The five arrangements, which are what five of the probes differ by.
    #[test]
    fn rearrange_deals_the_list_five_ways() {
        let list = [1, 2, 3, 4, 5, 6, 7, 8];

        assert_eq!(rearrange(&list, Order::Forward), list);
        assert_eq!(rearrange(&list, Order::Reverse), [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(rearrange(&list, Order::MiddleOut), [5, 4, 6, 3, 7, 2, 8, 1]);

        // The two whose names read backwards. The reference's top half is the
        // list reversed and *then* halved, so it is the first four counting
        // down; its bottom half is the second four counting up. Naming them the
        // other way round is the obvious mistake and produces a hash that
        // matches nothing.
        assert_eq!(rearrange(&list, Order::TopHalf), [4, 3, 2, 1]);
        assert_eq!(rearrange(&list, Order::BottomHalf), [5, 6, 7, 8]);

        // An odd count, where the middle element goes to the top half and the
        // deal starts on it.
        let odd = [1, 2, 3, 4, 5];
        assert_eq!(rearrange(&odd, Order::TopHalf), [3, 2, 1]);
        assert_eq!(rearrange(&odd, Order::BottomHalf), [4, 5]);
        assert_eq!(rearrange(&odd, Order::MiddleOut), [3, 4, 2, 5, 1]);

        // Nothing to deal, rather than a panic on the halving.
        let empty: [u8; 0] = [];
        for order in [
            Order::Forward,
            Order::Reverse,
            Order::TopHalf,
            Order::BottomHalf,
            Order::MiddleOut,
        ] {
            assert!(rearrange(&empty, order).is_empty());
        }
    }

    /// The shape of the hash: sixty-two characters, three per probe and then a
    /// truncated digest.
    #[test]
    fn the_hash_is_thirty_cipher_characters_and_thirty_two_digest_characters() {
        let answered = Answer {
            cipher: "c02f".into(),
            version: "0303".into(),
            alpn: "h2".into(),
            extensions: "002b-0033".into(),
        };
        let answers: Vec<Answer> = (0..10).map(|_| answered.clone()).collect();

        let found = hash(&answers);
        assert_eq!(found.len(), 62);
        assert!(found.is_char_boundary(30));
        assert!(
            found.chars().all(|c| c.is_ascii_hexdigit()),
            "the whole hash is hex: {found}"
        );
    }

    /// A host that answered nothing hashes to zeros, and `fingerprint` reports
    /// that as no fingerprint rather than as a fingerprint every silent host
    /// shares.
    #[test]
    fn silence_is_not_a_fingerprint() {
        let silent: Vec<Answer> = (0..10).map(|_| Answer::default()).collect();
        assert_eq!(hash(&silent), EMPTY_HASH);
        assert_eq!(EMPTY_HASH.len(), 62);
    }

    /// The three characters a probe contributes, and the zeros a probe that drew
    /// nothing contributes instead.
    #[test]
    fn a_probe_contributes_two_cipher_characters_and_one_version_character() {
        assert_eq!(cipher_code(""), "00");
        assert_eq!(version_code(""), '0');

        // A suite the coded list holds: its one-based place, in hex.
        assert_eq!(cipher_code("0016"), "05");
        assert_eq!(cipher_code("c02f"), "29");
        assert_eq!(cipher_code("c030"), "2a");

        // One it does not. The code is one past the end rather than `00`, which
        // is reserved for a probe that drew no answer at all: a server that
        // chose something unlisted said more than a server that said nothing.
        assert_eq!(cipher_code("dead"), "46");

        // The version's last nibble, lettered from `a` for SSL 3.0.
        assert_eq!(version_code("0301"), 'b');
        assert_eq!(version_code("0302"), 'c');
        assert_eq!(version_code("0303"), 'd');
        assert_eq!(version_code("0304"), 'e');
    }

    /// A `ServerHello` this engine sent a hello to, read back into the four
    /// parts the hash is built from.
    ///
    /// The bytes are nginx answering the first probe with TLS 1.2 and
    /// `ECDHE-RSA-AES128-GCM-SHA256`, trimmed after the extension list.
    #[test]
    fn a_server_hello_reads_back_as_its_four_parts() {
        let read = read_answer(&server_hello(false));
        assert_eq!(read.cipher, "c02f");
        assert_eq!(read.version, "0303");
        assert_eq!(read.alpn, "", "the server agreed no protocol");
        assert_eq!(read.extensions, "ff01-0017");
    }

    /// A hello that did not all arrive is no answer, rather than part of one.
    ///
    /// Every cut of a real answer reads as the whole of it or as nothing. Half
    /// an answer is worse than none: its cipher and version are right and its
    /// extension list is not, so the probe's three characters agree with a
    /// published hash while the digest over all ten extension lists does not,
    /// and a product the corpus lists goes unnamed with nothing to say why.
    #[test]
    fn a_server_hello_reads_whole_or_not_at_all() {
        let whole = server_hello(false);
        assert_ne!(read_answer(&whole), Answer::default());

        for cut in 0..whole.len() {
            assert_eq!(
                read_answer(&whole[..cut]),
                Answer::default(),
                "the first {cut} of {} bytes",
                whole.len()
            );
        }
    }

    /// A refusal is not a hello. An alert record, and anything too short to hold
    /// a hello, contribute an empty answer rather than reading past their end.
    #[test]
    fn a_refusal_reads_back_empty() {
        // Alert, fatal, handshake failure.
        let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert_eq!(read_answer(&alert), Answer::default());

        assert_eq!(read_answer(&[]), Answer::default());
        assert_eq!(read_answer(&[0x16, 0x03, 0x03]), Answer::default());

        // A handshake record that claims a hello and then stops.
        let truncated = [0x16, 0x03, 0x03, 0x00, 0x40, 0x02, 0x00, 0x00, 0x3c];
        assert_eq!(read_answer(&truncated), Answer::default());
    }

    /// The nineteen corpus rules are reached, and only they are. This is what
    /// proves the analyzer's output lands where it was written to.
    #[test]
    fn a_published_hash_reaches_the_corpus() {
        let db = super::super::db::SignatureDb::global();

        // Cobalt Strike's, from `tls_jarm.toml`.
        let found = db
            .identify_jarm("07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1")
            .expect("a published hash names a product");
        assert_eq!(found.product.as_deref(), Some("Cobalt Strike Listener"));

        // And it says where the name came from, since nothing else on the port
        // will have said it.
        let reported = as_handshake_reading(found);
        assert_eq!(reported.source, SourceId::Jarm);
        assert_eq!(reported.extrainfo.as_deref(), Some("TLS fingerprint"));

        // A hash nobody published names nothing. Through the whole corpus it
        // would name `isakmp`: sixty-two hex characters satisfies the baseline
        // rule for an IKE responder's vendor-id list, and that is why these
        // rules are consulted in an index of their own.
        let unpublished = "00112233445566778899aabbccddeeff00112233445566778899aabbccddee";
        assert!(db.identify_jarm(unpublished).is_none());
        assert_eq!(
            db.identify_field(unpublished)
                .and_then(|stray| stray.service),
            Some("isakmp".to_string()),
            "the whole corpus does answer, which is the reason for the index"
        );
    }

    /// The gate. Ten connections are worth making only where the caller asked
    /// for the thorough level and there is a TCP peer to make them to.
    #[test]
    fn the_analyzer_asks_only_at_the_thorough_level() {
        let addr: std::net::SocketAddr = "127.0.0.1:443".parse().expect("an address");
        let at = |level, protocol| {
            PortContext::new(443, protocol)
                .with_addr(Some(addr))
                .with_detection(level)
        };

        assert!(JarmAnalyzer.interested(&at(ServiceDetection::Thorough, Protocol::Tcp)));

        assert!(!JarmAnalyzer.interested(&at(ServiceDetection::Probe, Protocol::Tcp)));
        assert!(!JarmAnalyzer.interested(&at(ServiceDetection::Banner, Protocol::Tcp)));
        assert!(!JarmAnalyzer.interested(&at(ServiceDetection::Off, Protocol::Tcp)));

        // Nothing here speaks DTLS, and a UDP port scanned at 443 is not a TLS
        // listener to dial.
        assert!(!JarmAnalyzer.interested(&at(ServiceDetection::Thorough, Protocol::Udp)));

        // No peer, nowhere to send ten hellos.
        assert!(!JarmAnalyzer.interested(
            &PortContext::new(443, Protocol::Tcp).with_detection(ServiceDetection::Thorough)
        ));
    }

    /// A port that never completed a handshake is not dialled at all.
    ///
    /// Counted rather than inferred from the empty result: an analyzer that
    /// probed and then discarded what it read would pass a test that only looked
    /// at the frames, and ten connections to a plaintext port is exactly the
    /// cost this gate exists to avoid.
    #[tokio::test]
    async fn a_plaintext_port_is_not_dialled() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        let dialled = Arc::new(AtomicUsize::new(0));

        let counted = Arc::clone(&dialled);
        tokio::spawn(async move {
            while accept_from_this_process(&listener).await.is_ok() {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        });

        let ctx = PortContext::new(80, Protocol::Tcp)
            .with_addr(Some(addr))
            .with_detection(ServiceDetection::Thorough);
        let plaintext = ResponseSet::from_banners(vec!["HTTP/1.1 200 OK".to_string()]);

        assert!(
            JarmAnalyzer
                .collect(&ctx, &plaintext)
                .await
                .frames
                .is_empty()
        );
        assert_eq!(dialled.load(Ordering::SeqCst), 0, "no handshake, no probes");

        // And the same port once a handshake is on record, to show the gate is
        // the TLS reading and not something else about the context.
        let handshaken = ResponseSet::default().with_tls(super::super::TlsInfo::new(Vec::new()));
        let _ = JarmAnalyzer.collect(&ctx, &handshaken).await;
        assert_eq!(dialled.load(Ordering::SeqCst), PROBES.len(), "ten hellos");
    }

    /// A listener that answers every hello the same way, with
    /// [`server_hello`]. `refuse` makes it send a fatal alert instead, which is
    /// what a server that liked none of the terms sends.
    async fn stub_server(refuse: bool) -> SocketAddr {
        answering(server_hello(refuse), None).await
    }

    /// A listener that answers every hello with `reply`, in two writes a
    /// moment apart where `split_at` says where to cut it.
    async fn answering(reply: Vec<u8>, split_at: Option<usize>) -> SocketAddr {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");

        tokio::spawn(async move {
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
                let mut hello = vec![0u8; 4096];
                if stream.read(&mut hello).await.is_err() {
                    continue;
                }
                let (head, tail) = reply.split_at(split_at.unwrap_or(reply.len()));
                let _ = stream.write_all(head).await;
                if !tail.is_empty() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    let _ = stream.write_all(tail).await;
                }
            }
        });

        addr
    }

    /// The record the stub sends: TLS 1.2, `ECDHE-RSA-AES128-GCM-SHA256`, and
    /// two extensions. The same bytes the reading tests walk.
    fn server_hello(refuse: bool) -> Vec<u8> {
        if refuse {
            return vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        }

        let mut record = vec![
            0x16, 0x03, 0x03, 0x00, 0x55, // record: handshake, TLS 1.2, 85 bytes
            0x02, 0x00, 0x00, 0x51, // server hello, 81 bytes
            0x03, 0x03, // the version it chose
        ];
        record.extend_from_slice(&[0x11; 32]); // server random
        record.push(0x20);
        record.extend_from_slice(&[0x22; 32]); // session id
        record.extend_from_slice(&[0xc0, 0x2f]); // the suite it chose
        record.push(0x00); // null compression
        record.extend_from_slice(&[0x00, 0x09]); // nine bytes of extensions
        record.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]); // renegotiation info
        record.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // extended master secret
        record
    }

    /// Ten probes against a server whose answer never varies, assembled into the
    /// hash it implies.
    ///
    /// Every stage in one test: ten connections made, ten answers read, and the
    /// sixty-two characters they add up to. The value is pinned rather than
    /// merely shaped, so a change anywhere in the assembly — an answer dropped,
    /// the order of the ten disturbed, the digest taken over the wrong text —
    /// shows up here.
    ///
    /// `29` is the suite's place and `d` is TLS 1.2, ten times over, because
    /// this server gives every probe the same answer. A real one does not, which
    /// is the entire point of asking ten times.
    #[tokio::test]
    async fn ten_answers_assemble_into_a_hash() {
        let addr = stub_server(false).await;

        let found = fingerprint(addr, "127.0.0.1")
            .await
            .expect("a server that answered has a fingerprint");

        assert_eq!(&found[..30], "29d29d29d29d29d29d29d29d29d29d");
        assert_eq!(found.len(), 62);

        // Twice, to state that the ten questions are fixed rather than sampled:
        // the parts that vary between two runs — the client random, the session
        // id, the key share, the GREASE value — are the parts no answer carries
        // back.
        assert_eq!(
            fingerprint(addr, "127.0.0.1").await.as_deref(),
            Some(found.as_str()),
            "the same server answers the same way twice"
        );
    }

    /// A hello that arrives in two segments is read whole, and hashes as it
    /// does in one.
    ///
    /// TCP delivers a record in as many pieces as it likes, and a single read
    /// takes the first for the whole answer. Cut inside the extension list, as
    /// here, that is the worst kind of wrong: a hash whose first thirty
    /// characters are right and whose digest matches nothing anyone published.
    #[tokio::test]
    async fn a_server_hello_arriving_in_pieces_hashes_as_it_does_whole() {
        let whole = stub_server(false).await;
        let expected = fingerprint(whole, "127.0.0.1")
            .await
            .expect("a server that answered has a fingerprint");

        // Four bytes into the nine of extensions.
        let pieces = answering(server_hello(false), Some(85)).await;
        assert_eq!(
            fingerprint(pieces, "127.0.0.1").await.as_deref(),
            Some(expected.as_str())
        );
    }

    /// A server that refuses every hello reads as no fingerprint, the same as
    /// one that said nothing.
    ///
    /// It is tempting to want those told apart — refusing ten times is a
    /// distinctive thing to do — but an alert carries no cipher, no version and
    /// no extension list, so there is nothing to hash. The reference implements
    /// it this way and its published hashes are what the corpus holds.
    #[tokio::test]
    async fn a_server_that_refuses_everything_has_no_fingerprint() {
        let addr = stub_server(true).await;
        assert_eq!(fingerprint(addr, "127.0.0.1").await, None);
    }

    /// A server that stops answering part-way through costs the fingerprint
    /// its budget and no more, and yields no fingerprint rather than one with
    /// the unasked answers left empty.
    ///
    /// Each hello it lets go costs a probe's whole wait, so ten of them would
    /// cost the port ten, more than the rest of its identification together.
    /// And the two answers it gave are real, so a hash finished with the rest
    /// empty would be a hash, one this server does not have. Shortened limits
    /// stand in for the real ones, which are the same arithmetic in seconds.
    #[tokio::test]
    async fn a_server_that_stops_answering_costs_the_budget_and_yields_nothing() {
        use crate::testing::loopback::accept_from_this_process;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        tokio::spawn(async move {
            let mut taken = 0;
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
                taken += 1;
                let answers = taken <= 2;
                tokio::spawn(async move {
                    let mut hello = vec![0u8; 4096];
                    let _ = stream.read(&mut hello).await;
                    if answers {
                        let _ = stream.write_all(&server_hello(false)).await;
                    }
                    while stream.read(&mut hello).await.is_ok_and(|read| read > 0) {}
                });
            }
        });

        let limits = Limits {
            probe: Duration::from_secs(1),
            all: Duration::from_millis(1_500),
        };
        let started = std::time::Instant::now();
        let found = fingerprint_within(addr, "127.0.0.1", limits).await;
        let took = started.elapsed();

        assert_eq!(found, None, "a fingerprint cut short was finished");
        assert!(
            took < Duration::from_secs(5),
            "the eight hellos it let go took {took:?}, a probe's wait each"
        );
    }

    /// The registry runs it. `interested` and `collect` are exercised above on
    /// their own; this is the assertion that the set a scan actually consults
    /// contains this analyzer.
    #[test]
    fn the_registry_carries_the_analyzer() {
        assert!(
            super::super::analyzers()
                .iter()
                .any(|analyzer| analyzer.id() == SourceId::Jarm),
            "a scan consults the set, not this module"
        );
    }

    /// Nothing collected is nothing claimed, and a frame that is not a hash
    /// names nothing rather than being matched as text.
    #[test]
    fn nothing_collected_is_nothing_claimed() {
        let ctx = PortContext::new(443, Protocol::Tcp);
        let responses = ResponseSet::default();

        assert!(
            JarmAnalyzer
                .analyze(&ctx, &responses, &Collected::default())
                .is_empty()
        );

        let invalid = Collected::from_frames(vec![vec![0xff, 0xfe]]);
        assert!(JarmAnalyzer.analyze(&ctx, &responses, &invalid).is_empty());
    }
}
