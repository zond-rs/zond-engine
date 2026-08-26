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
with shared helpers in `common/mod.rs`.

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

## Tier 2: the simulated network

Harnesses: `common/fake_net.rs` simulates a Layer 4 network, `common/fake_lan.rs`
simulates an Ethernet segment, and the fixtures at the bottom of `common/mod.rs`
stand up the host they are probed from.

Files: `probe_classification.rs`, `lan_discovery.rs`, `retransmission.rs`.

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

### Tests that are meant to fail

An `#[ignore]`d test here is a claim about something the engine does not do yet,
not a test that is switched off. It runs, it fails for the reason it says, and
removing the attribute is the definition of done.

`retransmission.rs` was written this way against a feature the engine did not
have, and every test in it now runs. **Nothing in `tests/` is currently ignored**,
so the convention has no live claim under it right now.

The four `#[ignore]`d tests in the crate are a different thing entirely — they
are gated on an environment rather than on a missing feature, and each says so in
its attribute: two UDP scan tests need libpcap capture access, one nmap importer
test needs a real document named by `ZOND_NMAP_XML`, and one nmap exporter test
prints a document for external validation instead of asserting. They are not
claims about unfinished work and removing the attribute is not the definition of
done for any of them.

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

Not written yet.

Tier 2 simulates the network, which means it cannot catch a bug in the real path
below the seam. A wrong BPF filter, a bad checksum, or a mistake in interface
selection passes Tier 2 happily and then fails in the field. Tier 3 is the
answer to that: a veth pair into a network namespace, with `netem` for loss and
latency, `tbf` for congestion, a lowered MTU for fragmentation, and `nftables`
for the difference between a silent drop and a reject.

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
