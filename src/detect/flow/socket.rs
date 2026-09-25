// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Running a flow against a real port
//!
//! [`run`](super::run) takes a [`Probe`], and this is the one that opens
//! sockets. A scan builds it for every flow it runs; a caller driving a single
//! detection outside a scan builds it the same way.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::detect::compute::Budget;
use crate::detect::exchange;
use crate::fingerprint::Tunnel;
use crate::model::port::Protocol;
use crate::transport::dial::Egress;

use super::{Probe, ProbeRefusal};

/// A blocking [`Probe`] over a fresh connection to one port, holding a budget
/// and debiting it as it goes.
///
/// Each [`speak`](Probe::speak) is one request and its reply, which is what the
/// corpus's stateless exchanges need. It is bound to the address it was built
/// for and reaches nothing else.
///
/// The budget is enforced here, which is what makes a detection's declaration
/// mean something: an exchange the budget cannot pay for is refused before a
/// packet leaves, and a reply is capped at the bytes still available.
///
/// ```no_run
/// use std::time::Duration;
/// use zond_engine::detect::compute::Budget;
/// use zond_engine::detect::flow::{self, FlowSeed, SocketProbe};
/// use zond_engine::model::port::Protocol;
///
/// # fn example(detection: &zond_engine::detect::flow::schema::FlowDetection) {
/// let addr = "192.0.2.10:6379".parse().expect("a socket address");
/// let budget = Budget::new(0, Duration::from_secs(5));
/// let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget);
///
/// let seed = FlowSeed::new("192.0.2.10", 6379);
/// let findings = flow::run(detection, "redis", &seed, &mut probe);
/// # let _ = findings;
/// # }
/// ```
pub struct SocketProbe {
    addr: SocketAddr,
    protocol: Protocol,
    /// The tunnel the port answered inside, if any: a flow speaks TLS to an
    /// `ssl/*` service and plaintext to the rest, over the same exchange.
    tunnel: Option<Tunnel>,
    /// Where each of the flow's connections leaves from.
    egress: Egress,
    /// Bytes still available across this flow's remaining sends and replies.
    bytes_left: u64,
    /// When the flow's time budget runs out.
    deadline: Instant,
    /// Connections still available to this flow.
    connections_left: u32,
    /// Why the last `speak` refused, if a budget did rather than the port going
    /// silent.
    last_refusal: Option<ProbeRefusal>,
    /// Whether the last `speak` read its reply to a self-terminating end: the
    /// peer closing, or an HTTP message reaching the length it declared. False
    /// after a `speak` that returned nothing, which left no reply to be whole.
    last_complete: bool,
    /// The exchanges the flow may still make, this probe's own included, once
    /// the flow has said how many it plans. See [`Probe::plan`].
    exchanges_left: Option<u32>,
    /// Where the coming `speak`'s reply ends, its source kept beside the
    /// compiled form so a `for_each` sending the same step does not recompile
    /// it. See [`Probe::reads_until`].
    reply_end: Option<(String, exchange::ReplyEnd)>,
}

/// The least a datagram is waited on for its reply, however many the flow
/// still plans to send.
///
/// Sharing the flow's time among its datagrams could otherwise leave each too
/// little for any reply to arrive, and a guess given no time to be answered is
/// a guess silently not tried. Half a second holds an intercontinental round
/// trip and an agent's work on the request with room to spare. A flow planning
/// more datagrams than its budget holds at this pace is refused the rest on its
/// deadline, which its report then shows, rather than trying every one too
/// briefly to hear any.
const DATAGRAM_WAIT_FLOOR: Duration = Duration::from_millis(500);

impl SocketProbe {
    /// A probe bound to `addr`, held to `budget`.
    ///
    /// `tunnel` is the transport the port answered inside, so a flow reaches an
    /// `ssl/*` service through a handshake and every other port in the clear.
    /// The clock starts here rather than at the first exchange, so time spent
    /// waiting to build one does not come out of the flow's budget.
    ///
    /// Of the five ceilings a [`Budget`] carries, a flow spends the three that
    /// reach the network: bytes, wall clock, and connections. `fuel` and
    /// `max_memory` bound a compute module's execution and a flow executes
    /// nothing, so they are ignored here as they are in
    /// [`LiveCapabilities`](crate::detect::compute::LiveCapabilities).
    ///
    /// Its connections go where the routing table sends them. A scan forced to
    /// a source builds its own with every connection pinned there.
    pub fn new(
        addr: SocketAddr,
        protocol: Protocol,
        tunnel: Option<Tunnel>,
        budget: &Budget,
    ) -> Self {
        Self {
            addr,
            protocol,
            tunnel,
            egress: Egress::KERNEL,
            bytes_left: budget.max_bytes,
            deadline: Instant::now() + budget.deadline,
            connections_left: budget.max_connections,
            last_refusal: None,
            last_complete: false,
            exchanges_left: None,
            reply_end: None,
        }
    }

    /// The same probe, with every connection leaving by `egress`: the way the
    /// scan reached the port, so a detection speaks to it from where the probe
    /// did.
    pub(crate) fn via(mut self, egress: Egress) -> Self {
        self.egress = egress;
        self
    }

    /// How long to wait for this datagram's reply: its share of the flow's time
    /// left, split evenly among the exchanges the flow still plans, and never
    /// less than [`DATAGRAM_WAIT_FLOOR`] or past the flow's deadline.
    ///
    /// Silence is an ordinary answer over UDP, and every datagram of a flow may
    /// draw one. Given the whole of what is left, the first unanswered one
    /// would spend it and the rest would never be sent; given an even share,
    /// each is heard out and the last still has its turn. A caller speaking
    /// without a plan has told this probe nothing of what follows, so its
    /// datagram gets all the time there is, and silence at the deadline is a
    /// question the clock closed rather than one heard out.
    fn datagram_wait(&self, left: Duration) -> DatagramWait {
        let Some(planned) = self.exchanges_left else {
            return DatagramWait {
                until: self.deadline,
                full_share: false,
            };
        };
        let share = (left / planned.max(1)).max(DATAGRAM_WAIT_FLOOR);
        DatagramWait {
            until: (Instant::now() + share).min(self.deadline),
            full_share: share <= left,
        }
    }
}

/// The wait one datagram's reply is given.
struct DatagramWait {
    /// When it ends.
    until: Instant,
    /// Whether it is the datagram's whole share, so silence at its end is the
    /// port's answer even if the flow's deadline falls there too.
    full_share: bool,
}

impl Probe for SocketProbe {
    fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        // Refuse the exchange the budget cannot pay for, before any packet leaves,
        // recording which budget so a silent port and a spent one stay distinct.
        self.last_refusal = None;
        self.last_complete = false;
        if self.connections_left == 0 {
            self.last_refusal = Some(ProbeRefusal::Connections);
            return None;
        }
        let Some(left) = exchange::remaining(self.deadline) else {
            self.last_refusal = Some(ProbeRefusal::Deadline);
            return None;
        };
        let sent = bytes.len() as u64;
        if sent > self.bytes_left {
            self.last_refusal = Some(ProbeRefusal::Bytes);
            return None;
        }
        self.bytes_left -= sent;
        self.connections_left -= 1;
        let datagram = self.datagram_wait(left);
        self.exchanges_left = self.exchanges_left.map(|planned| planned.saturating_sub(1));

        // The reply may consume at most what the byte budget has left. A silent or
        // unreachable port is not a refusal, so `last_refusal` stays clear, unless
        // it was the flow's clock that ended the wait, or the process that had
        // no socket to make the exchange with.
        let reply = match self.protocol {
            Protocol::Tcp => exchange::tcp(
                self.addr,
                self.egress,
                self.tunnel,
                bytes,
                self.deadline,
                self.bytes_left,
                self.reply_end.as_ref().map(|(_, end)| end),
            ),
            Protocol::Udp => exchange::udp(
                self.addr,
                self.egress,
                bytes,
                datagram.until,
                self.bytes_left,
            ),
            // An SCTP port is scanned without a client stack, so there is
            // nothing here for a detection to hold a conversation over.
            Protocol::Sctp => return None,
        };
        if matches!(reply, Err(exchange::ExchangeError::Starved)) {
            self.last_refusal = Some(ProbeRefusal::Descriptors);
            return None;
        }
        let reply = reply.ok().filter(|reply| !reply.bytes.is_empty());

        let Some(reply) = reply else {
            // Every wait in an exchange is drawn from what is left of the flow's
            // time, so one that came back empty with none of it left was ended
            // by the budget, not by the port: the question was still open when
            // the clock stopped it. Refused, so the flow's report says a budget
            // left it unanswered rather than that the port had nothing to say.
            // A port that refused the connection or reset it did so with time
            // to spare, and stays silence. So does a datagram that was waited
            // on for its whole share: its silence was heard out, and is the
            // answer, even when that share was the last of the flow's time.
            let heard_out = self.protocol == Protocol::Udp && datagram.full_share;
            if exchange::remaining(self.deadline).is_none() && !heard_out {
                self.last_refusal = Some(ProbeRefusal::Deadline);
            }
            return None;
        };

        self.bytes_left -= reply.bytes.len() as u64;
        self.last_complete = reply.complete;
        Some(reply.bytes)
    }

    fn last_refusal(&self) -> Option<ProbeRefusal> {
        self.last_refusal
    }

    fn reply_complete(&self) -> bool {
        self.last_complete
    }

    fn plan(&mut self, exchanges: u32) {
        self.exchanges_left = Some(exchanges);
    }

    fn reads_until(&mut self, pattern: Option<&str>) {
        // Kept compiled across a `for_each` that sends the same step: recompile
        // only when the pattern changes, and clear it when a step names none.
        match pattern {
            Some(source)
                if self
                    .reply_end
                    .as_ref()
                    .is_some_and(|(kept, _)| kept == source) => {}
            Some(source) => {
                self.reply_end = exchange::ReplyEnd::compile(source)
                    .map(|compiled| (source.to_string(), compiled));
            }
            None => self.reply_end = None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A budget with the ceilings this file is about, and nothing spent on the
    /// two a flow never touches.
    fn budget(max_bytes: u64, millis: u64, max_connections: u32) -> Budget {
        Budget::new(0, Duration::from_millis(millis))
            .with_max_bytes(max_bytes)
            .with_max_connections(max_connections)
    }

    /// An exchange the process had no socket for is refused on the process's
    /// account, once the flow's own time has gone on waiting for one, rather
    /// than coming back as a port that said nothing: a flow reads silence as
    /// an answer and clears the port, and the finding a reply would have drawn
    /// is lost with nothing said.
    #[cfg(unix)]
    #[test]
    fn an_exchange_with_no_socket_to_give_is_refused_rather_than_read_as_silence() {
        use crate::system::descriptors::testing::{exhaust, in_a_process_of_its_own};

        if !in_a_process_of_its_own(
            module_path!(),
            "an_exchange_with_no_socket_to_give_is_refused_rather_than_read_as_silence",
        ) {
            return;
        }
        // Bound before the table fills; nothing will reach it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let addr = listener.local_addr().expect("its address");
        let held = exhaust(64);

        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4_096, 300, 8));
        let reply = probe.speak(b"GET / HTTP/1.1\r\n\r\n");
        drop(held);

        assert_eq!(reply, None, "a reply with no socket to carry it");
        assert_eq!(
            probe.last_refusal(),
            Some(ProbeRefusal::Descriptors),
            "the process's shortfall was not told apart from the port's silence"
        );
    }

    #[test]
    fn a_reply_is_capped_at_the_flows_byte_budget() {
        use std::io::{Read as _, Write as _};

        // A loopback that floods the probe with far more than the budget allows.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.read(&mut [0u8; 64]);
                let _ = sock.write_all(&vec![b'A'; 4096]);
            }
        });

        // 20-byte budget, one of which the `x` send spends: the reply gets 19.
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(20, 5_000, 8));
        let reply = probe.speak(b"x").expect("a reply within budget");
        assert!(
            reply.len() <= 19,
            "reply was not capped, got {}",
            reply.len()
        );
    }

    #[test]
    fn a_flow_cannot_open_more_connections_than_its_budget() {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // Answer the one connection the budget permits, and no more.
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.write_all(b"ok");
            }
        });

        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 5_000, 1));
        assert!(
            probe.speak(b"a").is_some(),
            "the one permitted exchange failed"
        );
        assert!(
            probe.speak(b"b").is_none(),
            "a second connection was opened past the budget"
        );
        assert_eq!(probe.last_refusal(), Some(ProbeRefusal::Connections));
    }

    #[test]
    fn an_expired_time_budget_refuses_the_exchange() {
        // A zero-millisecond budget is spent the instant it is granted, so no
        // packet leaves; the unreachable address is never dialed.
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 0, 8));

        assert!(probe.speak(b"anything").is_none());
        assert_eq!(probe.last_refusal(), Some(ProbeRefusal::Deadline));
    }

    /// A send larger than what is left is refused rather than truncated, and the
    /// refusal says which budget stopped it.
    #[test]
    fn a_send_past_the_byte_budget_is_refused_and_names_the_budget() {
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4, 5_000, 8));

        assert!(probe.speak(b"far too long").is_none());
        assert_eq!(probe.last_refusal(), Some(ProbeRefusal::Bytes));
    }

    /// A web server that keeps the connection open after its reply, whatever
    /// `Connection: close` asked, as some embedded servers do. The reply says
    /// how long it is, so the exchange is over when that much has arrived: a
    /// flow asking three questions of such a server gets three whole answers
    /// inside a budget one idle connection would otherwise have spent.
    #[test]
    fn a_reply_that_says_how_long_it_is_ends_there_rather_than_when_the_server_hangs_up() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for sock in listener.incoming().take(3) {
                let Ok(mut sock) = sock else { return };
                std::thread::spawn(move || {
                    let _ = sock.read(&mut [0u8; 512]);
                    let _ = sock
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found");
                    // Held until the client lets go, which is what a server
                    // ignoring `Connection: close` looks like from this side.
                    let _ = sock.read(&mut [0u8; 1]);
                });
            }
        });

        let budget_ms = 1_500;
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, budget_ms, 3));
        let started = Instant::now();
        for path in ["/a", "/b", "/c"] {
            let request = format!("GET {path} HTTP/1.1\r\nConnection: close\r\n\r\n");
            let reply = probe.speak(request.as_bytes());
            assert!(
                reply
                    .as_deref()
                    .is_some_and(|reply| reply.ends_with(b"not found")),
                "{path} went unanswered: {reply:?}, refused on {:?}",
                probe.last_refusal()
            );
            assert!(
                probe.reply_complete(),
                "{path}'s reply was whole but not taken as such"
            );
        }
        assert!(
            started.elapsed() < Duration::from_millis(budget_ms / 2),
            "three exchanges with an idle server took {:?}",
            started.elapsed()
        );
    }

    /// A service that answers and then keeps the connection open for the next
    /// command, as redis and memcached do, and whose replies carry no length a
    /// generic reader could follow. Each exchange ends once the reply has
    /// arrived and the port has gone quiet, so a flow's second question is
    /// asked inside the budget the first would otherwise have spent waiting for
    /// a close that never comes.
    #[test]
    fn a_reply_the_service_holds_the_connection_open_after_ends_once_the_port_goes_quiet() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for sock in listener.incoming().take(2) {
                let Ok(mut sock) = sock else { return };
                std::thread::spawn(move || {
                    let _ = sock.read(&mut [0u8; 512]);
                    let _ = sock.write_all(b"+PONG\r\n");
                    // Held for the next command until the client lets go.
                    let _ = sock.read(&mut [0u8; 1]);
                });
            }
        });

        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 3_000, 2));
        for command in ["PING\r\n", "PING\r\n"] {
            let reply = probe.speak(command.as_bytes());
            assert_eq!(
                reply.as_deref(),
                Some(&b"+PONG\r\n"[..]),
                "a question went unanswered, refused on {:?}",
                probe.last_refusal()
            );
        }
        assert!(
            !probe.reply_complete(),
            "a reply ended by the port going quiet was taken as whole"
        );
    }

    /// A service that greets on connect and then pauses, longer than the idle
    /// gap, before answering the pipelined command. Without a stated end the
    /// read takes the pause for the end and keeps only the greeting; told where
    /// the reply ends, it waits through the pause and reads the answer whole.
    #[test]
    fn a_reply_named_end_waits_through_a_pause_the_idle_gap_would_end_it_at() {
        use std::io::{Read as _, Write as _};

        // Two connections: one probe told where its reply ends, one not. Each
        // gets a fresh listener slot so the pause is the port's, not a queue.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for sock in listener.incoming().take(2) {
                let Ok(mut sock) = sock else { return };
                std::thread::spawn(move || {
                    // Greet at once, as an FTP server does.
                    let _ = sock.write_all(b"220 service ready\r\n");
                    let _ = sock.read(&mut [0u8; 512]);
                    // Hold the verdict past the idle gap, as a failed login is
                    // held, then answer and close.
                    std::thread::sleep(Duration::from_millis(1_100));
                    let _ = sock.write_all(b"230 logged in\r\n");
                });
            }
        });

        // Told where the reply ends: the read waits through the pause and the
        // verdict line arrives.
        let mut told = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 3_000, 1));
        told.reads_until(Some("(?m)^230[ -]"));
        let reply = told.speak(b"USER anonymous\r\n").unwrap_or_default();
        assert!(
            String::from_utf8_lossy(&reply).contains("230"),
            "the named end did not wait through the pause: {:?}",
            String::from_utf8_lossy(&reply)
        );

        // Not told: the idle gap ends the reply at the greeting, before the
        // verdict, which is the shortfall the named end exists to close.
        let mut untold = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 3_000, 1));
        let greeting = untold.speak(b"USER anonymous\r\n").unwrap_or_default();
        assert!(
            !String::from_utf8_lossy(&greeting).contains("230"),
            "the idle gap was expected to end the reply before the verdict"
        );
    }

    /// A flow that guesses over UDP, one datagram per guess, where a wrong
    /// guess draws no reply at all, as an SNMP agent treats a community it does
    /// not know. Silence is the answer to each wrong guess, so each may wait
    /// only its share of the flow's time: an agent that accepts only the second
    /// guess is found, rather than the first guess's silence spending the whole
    /// budget and leaving the rest untried, and the last guess heard out to the
    /// end of the budget is answered by its silence rather than cut short.
    #[test]
    fn a_udp_flow_tries_every_guess_when_the_first_goes_unanswered() {
        use crate::detect::flow::{FlowSeed, run, schema::FlowDetection};

        let agent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = agent.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 512];
            while let Ok((read, from)) = agent.recv_from(&mut buffer) {
                if &buffer[..read] == b"second" {
                    let _ = agent.send_to(b"accepted", from);
                }
            }
        });

        let flow: FlowDetection = toml::from_str(
            r#"
            [detection]
            id      = "guesses"
            version = "1.0.0"
            title   = "Guesses"
            [detection.when]
            protocol = "udp"
            [detection.capabilities]
            class      = "active-benign"
            max_millis = 1500
            [[step]]
            for_each    = { var = "guess", in = ["first", "second", "third"] }
            on_no_match = "continue"
            send        = "{guess}"
            expect      = "accepted"
              [[step.finding]]
              when    = "matched"
              severity = "high"
              summary = "the agent accepted {guess}"
            "#,
        )
        .expect("a valid flow");

        let mut probe = SocketProbe::new(addr, Protocol::Udp, None, &budget(4096, 1_500, 8));
        let findings = run(
            &flow,
            "0",
            &FlowSeed::new("127.0.0.1", addr.port()),
            &mut probe,
        );

        let summaries: Vec<&str> = findings.iter().map(|finding| finding.title()).collect();
        assert_eq!(
            summaries,
            vec!["the agent accepted second"],
            "the accepted guess was never tried; last refusal {:?}",
            probe.last_refusal()
        );
        // The last guess's silence was heard out for its whole share, so it is
        // the agent's answer, not a question the budget left open.
        assert_eq!(probe.last_refusal(), None);
    }

    /// What the probe says about a reply's completeness describes its last
    /// exchange, and an exchange that drew nothing has no whole reply to
    /// describe, whatever the one before it read.
    #[test]
    fn an_exchange_that_drew_nothing_is_not_reported_whole() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            // Answers the one connection and closes it, then stops listening.
            // The request is read first, so the close is a clean one rather
            // than a reset over unread bytes.
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.read(&mut [0u8; 16]);
                let _ = sock.write_all(b"ok");
            }
        });

        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 5_000, 8));
        assert!(probe.speak(b"a").is_some());
        assert!(
            probe.reply_complete(),
            "a reply read to the close was not whole"
        );
        server.join().unwrap();

        assert!(probe.speak(b"b").is_none(), "a closed port answered");
        assert!(
            !probe.reply_complete(),
            "the unanswered exchange was described by the one before it"
        );
    }

    /// An exchange the flow's clock ran out on is a question the budget left
    /// unanswered, and says so: a flow whose last request was still waiting
    /// when its time was up must not read the same as one the port declined.
    #[test]
    fn an_exchange_its_time_budget_ran_out_on_is_refused_rather_than_unanswered() {
        use std::io::Read as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                // Takes the request and answers nothing until the client leaves.
                let _ = sock.read(&mut [0u8; 512]);
                let _ = sock.read(&mut [0u8; 1]);
            }
        });

        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 300, 8));
        assert!(probe.speak(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert_eq!(probe.last_refusal(), Some(ProbeRefusal::Deadline));
    }

    /// A port that turns the connection away has answered, with a refusal of
    /// its own, before the budget had any say: that is silence, not a cut.
    #[test]
    fn a_port_that_refuses_the_connection_is_unanswered_rather_than_refused() {
        // Bound and dropped, so the port is closed and the kernel resets.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 5_000, 8));

        assert!(probe.speak(b"anything").is_none());
        assert_eq!(probe.last_refusal(), None);
    }

    /// An SCTP port has no client stack behind it here, so a flow aimed at one
    /// goes unanswered rather than refused: nothing about the budget stopped it.
    #[test]
    fn an_sctp_port_is_unanswered_rather_than_refused() {
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let mut probe = SocketProbe::new(addr, Protocol::Sctp, None, &budget(4096, 5_000, 8));

        assert!(probe.speak(b"anything").is_none());
        assert_eq!(probe.last_refusal(), None);
    }
}
