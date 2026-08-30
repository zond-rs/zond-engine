# Tests

The engine is tested in layers, because the things worth testing have very
different costs. Parsing a packet is cheap to check and can be done thousands of
times a second. Watching a scanner decide that a port is filtered takes as long
as the scan's deadline, and doing it against a real firewall takes root and a
Linux kernel. Mixing all of that into one suite would mean either running the
slow parts constantly or skipping the interesting parts entirely.

So the suite is split into tiers. Each one answers a different question, and each
one runs somewhere different.

## Unit tests, inside the crate

Anything that is a pure function of bytes lives next to the code it covers, in a
`mod tests` at the bottom of the file. Packet builders, classification tables,
IP set arithmetic, the fingerprint corpus, and the adaptive deadline are all
tested this way, some of them with `proptest` where the invariant matters more
than any particular input.

These are the fastest tests and there should be a lot of them. If a behaviour can
be expressed as "given these bytes, produce this verdict", it belongs here rather
than in any of the tiers below.

## Tier 1: portable integration tests

Files: `discovery.rs`, `lifecycle.rs`, `port_states.rs`, `service_fingerprint.rs`,
`detections.rs`, `import.rs`, with shared helpers in `common/mod.rs`.

`import.rs` is the odd one: it binds no socket at all, because the surface it
covers reads files. It sits here because it needs nothing but a temporary
directory, which is the property this tier is defined by.

These drive the public API, `scanner::scan` and `scanner::discover`, end to end
against real servers on loopback. Nothing is faked: a real TCP listener is bound,
a real connection is made, and a real banner comes back. That is what makes them
convincing, and it is also what limits them. A cooperative kernel will only ever
produce two outcomes on loopback, open and closed, so that is all this tier can
assert.

They need no privileges and no network setup, so they run identically on Linux
and macOS. When the process happens to be running as root, `scan` takes its raw
socket path instead of the connect fallback, and the assertions that depend on
the fallback call `is_privileged()` and skip rather than flake.

## The wire parsers, against bytes nobody wrote

File: `wire_parsers.rs`.

Sits beside Tier 1 and needs even less: no socket, no temporary directory,
nothing but the crate. It drives every public parser that reads bytes off a wire
over `proptest`-generated input and asserts that each one returns.

It belongs here rather than beside each parser because the interesting inputs are
whole frames, and building one means reaching across `protocols::craft`,
`protocols::ethernet` and the reader under test at once.

**The generators are shaped, and their shape is checked.** Uniform random bytes
are refused at the first length check, so most of these build a well-formed
frame and vary what the reader actually walks: LLDP TLVs with their seven-bit
type and nine-bit length, CDP records whose length counts its own header, an
ICMPv6 message behind a real IPv6 header, BOOTP options behind a real magic
cookie. `the_generators_reach_the_parsers_they_are_written_for` measures how
often each one gets through and fails if it stops, because a property that says
"the parser returns" is satisfied perfectly by input the parser never reads. The
first draft of the file was in exactly that state.

## Tier 2: the simulated network

Harnesses: `common/fake_net.rs` simulates a Layer 4 network, `common/fake_lan.rs`
simulates an Ethernet segment, and the fixtures at the bottom of `common/mod.rs`
stand up the host they are probed from.

Files: `probe_classification.rs`, `lan_discovery.rs`, `retransmission.rs`,
`listening.rs`, `evasion.rs`, `comparison.rs`.

This is where the behaviour that actually distinguishes a scanner gets tested:
what it does when probes are lost, answered late, answered twice, answered by a
router instead of the host, or never answered at all.

`FakeNet` plugs into `ProbeTransport::from_parts`. It receives the Layer 4
segments a scanner emits, decides per target how to answer, and pushes
synthesized replies back onto the scanner's receive stream exactly as a live
capture would. There are no sockets, no privileges and no interfaces involved, so
these tests run on every platform CI covers, in milliseconds, without depending
on the machine's network.

All three Layer 4 scanners can be driven this way through their `with_transport`
constructors: `TcpPortScanner`, `UdpPortScanner`, and `RoutedScanner` for
discovery. `TcpPortScanner` takes the `TcpScanTechnique` to probe with, and
`FakeNet::stack` chooses how the virtual hosts answer it — conformant,
BSD-derived, or one of the stacks that reset every flag probe whatever the port
state. `LocalScanner` takes an `EthernetHandle` instead of a probe transport,
because it identifies a neighbour by the Ethernet source MAC that a segment-fed
transport has already stripped, so it gets `FakeLan` and
`LocalScanner::with_handle`.

An `EthernetHandle` carries `CapturedFrame`s rather than bare bytes: each frame
arrives with the link it came off, how it is framed, and when it was seen. A
fixture building frames by hand wraps them the way `FakeLan::capture` does —
which is also the reason a fixture and `common::scanner_interface` have to agree
on which interface they are pretending to be.

`listening.rs` needs no harness at all, because a listener has no probes to
answer. `PassiveListener::from_parts` takes the receiving half of a frame stream
and nothing else — there is no sending half to supply, a listener never
transmits — so a test pushes the frames it wants read and closes the channel,
which the loop reads as the capture having ended. That is what makes those tests
finish without a timer, an abort, or a deadline to wait out.

They cover what only a whole run can show and the unit tests beside the strategy
cannot: that the seam works from outside the crate, and that a watch resumed from
a journal on disk goes on being one watch. That second one is not hypothetical —
a listener keys each machine by the first address it hears it at, so a sitting
that begins knowing nothing re-keys every machine it hears, and a watch resumed
three times reported one laptop as four.

### Tests that are meant to fail

An `#[ignore]`d test here is a claim about something the engine does not do yet,
not a test that is switched off. It runs, it fails for the reason it says, and
removing the attribute is the definition of done.

`retransmission.rs` was written this way against a feature the engine did not
have, and every test in it now runs. So does the one claim `detections.rs`
carried, that a whole scan hands a passive detection the responses it already
drew: the connect path now keeps what its inline fingerprint read instead of
discarding it. No live claim stands under the convention today.

The three `#[ignore]`d tests in the crate are a different thing entirely. They
are gated on an environment rather than on a missing feature, each says so in its
attribute, and **Tier 3 below is the job that runs them**: two UDP scan tests
need libpcap capture access, and one nmap importer test needs a document nmap
itself wrote. They are not claims about unfinished work, and removing the
attribute is not the definition of done for any of them.

There were four. `dump_for_external_validation` asserted nothing, printing a
document for `xmllint` to judge, so it was never a test at all. It is
`examples/nmap_dump.rs` now, which compiles under `cargo check --all-targets` and
runs without a harness flag.

`retransmission.rs` is also the one place in Tier 2 that takes seconds rather
than milliseconds, because a bounded retry schedule is exactly what it is
asserting on: a probe that is meant to go unanswered has to actually wait out
every attempt before the verdict it produces means anything.

An ignored test that *is* a claim should still fail for the reason it says, so
when one exists, check it:

```sh
cargo test -- --ignored
```

### Writing one

Describe the hosts, hand the scanner a transport, run it, then assert on the
results and on the probes the network saw:

```rust
let net = FakeNet::new(Layer4::Tcp)
    .host(target, 80, Policy::open())
    .host(target, 81, Policy::silent())
    .host(target, 82, Policy::open().drop_first(1));

let (session, ctx) = ScanSession::new();
let mut scanner =
    TcpPortScanner::with_transport(resolver, ctx, TcpScanTechnique::Syn, net.transport(), 3);
scanner.scan(targets).await?;

assert_eq!(net.probe_count(target, 82), 2, "the lost probe should be retried");
```

The second half of that matters as much as the first. Retransmission is only
visible in the probe log, since a scan that retries and one that got lucky the
first time produce the same result.

Each `Probe` in that log carries more than the target it was aimed at. It also
holds the Layer 4 segment as it went out, the source address and source port it
left from, its TCP flags, and the `Emission` the sender was handed. That is what
lets a test assert on the packet a scanner emitted rather than only on how many
it sent, which is what `evasion.rs` needed: every knob on an `EvasionProfile`
changes a probe and nothing outside the crate was reading one.

Policies start from the reply and layer conditions on top: `Policy::open()`,
`closed()`, `silent()`, `admin_prohibited()` and `truncated()`, combined with
`drop_first(n)`, `loss_rate(p)`, `delay(d)` and `duplicated()`. Any target with
no policy of its own is silent, which is both what most of the address space
really does and a safe default, since a test that forgets to declare a host gets
a plausible answer rather than an accidental open port.

### Determinism

Probabilistic policies draw from a generator owned by the net and seeded per
test, so the same seed always drops the same packets. A failure found in CI
reproduces locally from the seed alone, which is the only thing that makes a
loss based test worth having. Print `net.seed()` when one fails.

The generator is implemented in the harness rather than taken from `rand`, whose
output is explicitly not stable between versions. Borrowing it would mean a
routine dependency bump could quietly change which packets a "reproducible" test
drops, and a test whose seed no longer reproduces its failure is worse than no
test at all.

### What this tier cannot model

The seam sits above IP. A scanner hands down a finished Layer 4 segment and gets
Layer 4 segments back, with the IP header already stripped by the capture. So
anything whose behaviour lives at or below IP is invisible here and cannot be
faked honestly: path MTU, fragmentation and reassembly, real queueing delay, ARP
and NDP. Those belong to Tier 3.

`Policy::truncated()` is the one gesture in that direction, and it only checks
that a scanner survives a reply it cannot parse.

One qualification, and it is what `evasion.rs` runs on. A scanner does not only
hand down a segment: it also names the source address the segment was built
against and passes an `Emission`, which is what it wants the IP header to say.
Both reach `Probe`, so a test can assert that a scan asked for a hop limit, a
spoofed hardware address, a fragment size or a decoy source, on every probe it
sent. What it still cannot see is the packet that would have come out, because
none is built here. Asserting the instruction is honest at this tier; asserting
the result is Tier 3's.

One more gap worth knowing about: `LocalScanner`, which does ARP and NDP
discovery on the local segment, does not use `ProbeTransport` at all. It holds an
`EthernetHandle` and sends Layer 2 frames, so `FakeNet` cannot reach it yet.

### The `test-support` feature

`test-support` gates the **fake** transports and nothing else:
`ProbeTransport::from_parts` and `EthernetHandle::from_parts`, which build a
transport over a caller-supplied sender and reply stream instead of a socket and
a capture. That is what lets a test outside this crate drive a real scanner
against a synthetic network.

The scanners themselves need no feature. `scanner::strategy` and every
`with_transport` constructor in it are ordinary public API, because building a
strategy by hand against a real transport is a supported way to use the engine
rather than a test hatch — see the three altitudes in the `scanner` module docs.

The tests get the feature through a dev dependency on the crate itself, declared
in `Cargo.toml`, which Cargo unifies with the library target. Nothing is
compiled twice, and the feature stays off for every downstream consumer. A
synthetic transport has no use in a shipped binary, so enable it for tests only.

## Tier 3: privileged Linux tests

**The job exists; the namespace does not yet.**

`test.yml`'s `privileged` job installs libpcap and nmap on a Linux runner, has
nmap write a document against the runner's own loopback, and runs the crate's
three `#[ignore]`d tests as root. That is what cashes them.

Before it they were reachable only through a `continue-on-error` step, and what
that step reported is worth naming, because it is the failure mode a non-gating
job has. It ran them without the environment any of them asks for, so it came
back part green: on an unprivileged macOS runner one of the two capture tests
passes anyway and the other two fail. A step that is always partly red and never
blocks is one everybody learns to scroll past, which is the same place the four
`#[ignore]`d tests were before ZA-6-006 was written.

**The nmap document is generated on every run rather than committed**, and that
is the point of the test reading it. Every other nmap test here parses a document
somebody typed into a source file carrying their beliefs about nmap's output,
which is the trap this project keeps finding; a committed fixture would be the
same trap with a longer shelf life.

What is still missing is the network itself. Tier 2 simulates it, which means it
cannot catch a bug in the real path below the seam: a wrong BPF filter, a bad
checksum, or a mistake in interface selection passes Tier 2 happily and then
fails in the field. The answer to that is a veth pair into a network namespace,
with `netem` for loss and latency, `tbf` for congestion, a lowered MTU for
fragmentation, and `nftables` for the difference between a silent drop and a
reject. The job above is where it goes when it is written.

It should stay small. A handful of end to end cases confirming that real packets
survive a real degraded link is the point, and duplicating the Tier 2 matrix here
would only produce flaky tests, since `netem` is statistical and will not honour
a precise assertion.

## Running them

```sh
cargo test              # unit tests, Tier 1 and Tier 2
cargo test --lib        # unit tests only
cargo test --test port_states
```

Tiers 1 and 2 are what CI runs today, on Linux and macOS. Neither needs any
special setup, so `cargo test` is the whole story. Tier 3 will need its own job,
running as root on a Linux runner, once it exists.
