# Tests

The engine is tested in layers, because the things worth testing have very
different costs. Parsing a packet is cheap to check and can be done thousands of
times a second. Watching a scanner decide that a port is filtered takes as long
as the scan's deadline, and doing it against a real firewall takes root and a
Linux kernel. Mixing all of that into one suite would mean either running the
slow parts constantly or skipping the interesting parts entirely.

So the suite is split into tiers. Each one answers a different question, and each
one runs somewhere different.

A tier is one test binary, and its directory is what it contains:

```text
tests/
  support/       the shared harness: fixtures, fake_net, fake_lan
  hygiene/       checks on the repository rather than on the engine
  portable/      Tier 1, loopback and files
  simulated/     Tier 2, fake_net and fake_lan
  namespaced/    Tier 3, a real kernel over a veth pair
  containers/    Tier 4, real software from pinned images
  data/          manifests the tiers read
```

Each directory's `main.rs` carries the tier's doc header and its `mod`
declarations, so what a tier is and what is in it are one file. `cargo test
--test simulated` runs a whole tier, and `--test simulated probe_classification::`
runs one module of it.

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

Binary: `portable/`, with shared helpers in `tests/support/mod.rs`.

`import` is the odd one: it binds no socket at all, because the surface it
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

Module: `portable/wire_parsers.rs`.

Sits inside Tier 1's binary and needs even less: no socket, no temporary directory,
nothing but the crate. It drives every public parser that reads bytes off a wire
over `proptest`-generated input and asserts that each one returns.

It belongs here rather than beside each parser because the interesting inputs are
whole frames, and building one means reaching across `protocols::craft`,
`protocols::ethernet` and the reader under test at once.

Coverage-guided fuzzing over the same parsers lives in `fuzz/`, which has its
own README. This tier is what runs on every commit; that one is what runs for
hours.

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

Harnesses: `tests/support/fake_net.rs` simulates a Layer 4 network,
`tests/support/fake_lan.rs` simulates an Ethernet segment, and the fixtures at
the bottom of `tests/support/mod.rs` stand up the host they are probed from.

Binary: `simulated/`, holding `probe_classification`, `lan_discovery`,
`retransmission`, `listening`, `evasion`, `comparison`, `settlement` and
`pacing`.

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
which is also the reason a fixture and `support::scanner_interface` have to agree
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
discarding it.

One live claim stands under the convention, and it is in Tier 3:
`an_administratively_prohibited_port_is_filtered_rather_than_closed`. A real
ICMP prohibition comes back as `Unasked` rather than `Filtered`, because Linux
delivers the error to the socket and the next send reports it, which reads as a
probe the operating system refused to send. `Unasked` is documented to mean
exactly that, so nothing is behaving unexpectedly; what is open is which
evidence should win, an error the target really sent or the local send failure
that error caused. Removing the attribute is the definition of done.

One `#[ignore]`d test in the crate is a different thing entirely. It is gated on
an environment rather than on a missing feature and says so in its attribute:
the nmap importer test needs a document nmap itself wrote. It is not a claim
about unfinished work, and removing the attribute is not the definition of done
for it.

There were three. The other two drove a `libpcap` capture on loopback to prove
that a real kernel's ICMP error names the probe that caused it, and that a real
reply gets through the capture filter. Neither could run where it was, since the
lib tests have no namespace to borrow capture access from, and Tier 3 now asks
both questions of the whole scanner rather than of a hand-driven capture:
`a_udp_port_nothing_is_bound_to_is_reported_closed` and
`a_udp_reply_reaches_the_scan_and_opens_the_port`. The loop they closed is
closed further out, so they were removed rather than left switched off.

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

## Tier 3: the namespace

Binary: `namespaced/`, with the harness in `namespaced/netns.rs`.

Tier 2 simulates the network, which means it cannot catch a defect in the real
path below the seam: a wrong BPF filter, a bad checksum, or a mistake in
interface selection passes it happily and then fails in the field. This tier
gives the engine a network instead of a simulation. Packets are built here, put
on a wire by the kernel, answered by another kernel, and read back through
libpcap.

**It needs no root.** An unprivileged user namespace carries the full capability
set inside itself, `CAP_NET_ADMIN` and `CAP_NET_RAW` among them, over devices
that exist only in that namespace. So `cargo test` runs this tier like any
other, and it can gate a pull request rather than waiting on a privileged host
somebody has to remember to use.

### /sys has to be replaced, or the tier tests nothing

The namespace also gets a mount namespace and a fresh `sysfs` over `/sys`, and
without it this tier quietly stops being Tier 3. `netdev` reads a link's RFC
2863 operational state from `/sys/class/net/<link>/operstate`; an inherited
`/sys` is the host's, where a veth living only in here has no entry, so
`is_oper_up` answers false for every link and `Link::is_up` requires it beside
the `IFF_UP` flag that is set. `PortScanPlan` then finds no source address,
abandons the raw path, and runs a `connect` scan instead.

That is not a hypothetical. It is what this tier did for its first two phases,
reporting the same verdicts over a path that never builds an IP header, while a
guard asserting only privilege passed. `the_engine_takes_its_raw_path_here` now
asserts the planner's whole condition, privilege and a resolvable source, which
is what makes the tier's name true.

### How the process gets there

`netns.rs` registers an `.init_array` entry, so the move happens before `main`
and before any thread exists. Both halves of that matter. A network namespace is
a property of a task, and the engine reads its interfaces through a rayon pool
and reads frames on threads `transport::capture` spawns, so a process that moved
late would send from one network and listen on another. `CLONE_NEWUSER` also
refuses a process that is already threaded.

A machine with unprivileged user namespaces switched off reports the reason and
skips, which is a policy this tier cannot argue with rather than a defect in it.

### The segment

```text
  this process                      peer process
  10.99.N.1  zvNa <=============> zvNb  10.99.N.2
             (this netns)         (its own netns)
```

Both ends in one namespace would be short-circuited: traffic to a local address
never reaches the wire and a capture sees nothing. So the far end is moved into a
namespace of its own, held open by a parked child process, and the far side is
configured through `nsenter`. Each `Segment` numbers its own links and subnet, so
tests that build one at the same time do not collide, and dropping it kills the
peer, which takes the namespace and both ends of the pair with it. Nothing is
named in `/var/run/netns`, so a panicking test leaves nothing behind.

### What is in it

`classification` for the verdicts a real answer produces, including the two a
firewall gives and the two that need an ICMP error; `segment` for finding the
right neighbour on the right link, over both address families; `degraded` for
what survives loss and delay; `techniques` for all seven TCP techniques against
a kernel rather than a model of one; `characterise` for what kind of filter sits
in front of a host; `resuming` for what a resumed sitting of a raw scan sends,
since the sweeps beside a port scan never ask about a loopback target.

`listening` for the watch entry point over a real capture, and `resolving` for
a `.local` name a responder on the segment really answers, including the scope
that names one. The tests in `resolving` hold a mutex for their whole length and
cannot be made to run beside each other: a responder lives in its own namespace,
but the socket the engine queries from is in this process's, bound to 5353 with
`SO_REUSEPORT`, and two of those means the kernel hands an arriving answer to
whichever it likes. Both cover surfaces
whose tests stopped at a seam: Tier 2 hands `PassiveListener::from_parts` frames
a test built and never opens a link, and multicast cannot be faked on loopback,
the query going to a group whose membership decides whether it arrives at all.

`techniques` and `characterise` are where this tier pays for itself. Tier 2
covers the techniques more thoroughly than this ever will, and cannot disagree
with whoever wrote its stacks; Linux can. `characterise` was the least covered
file in the crate at 18.3%, because every conclusion it draws is about a
firewall's behaviour and there was no firewall to put in front of it.

A `Segment` can also firewall a port in the peer's namespace, with `drop` for
silence and `reject` for an ICMP error, and shape the near end of the pair with
`tc netem`. The nft rules carry a `counter`, so a failing test can be asked how
many probes actually arrived, which is usually the first thing worth knowing.

### Testing the tier itself

A scan that quietly fell back to the connect path would report the same two
verdicts over a path that never builds an IP header, and the tier would go on
passing while testing nothing the tiers above it do not.
`the_engine_takes_its_raw_path_here` is the guard against that.

It was also checked the other way, by severing the near end of the pair mid-test
and confirming the open-port case fails. Worth repeating after any change to the
harness: a green tier that has stopped reading the wire looks exactly like a
green tier.

### What belongs here

Only what cannot be asked anywhere else. It should stay small. Tier 2 can
describe a thousand answers a network might give and does; repeating that matrix
against a real link would buy nothing and cost a flake every time `netem`
rounded a probability the wrong way.

## Tier 4: real software, in containers

Binary: `containers/`, with its manifest in `tests/data/containers.toml` and the
runtime driver in `containers/runtime.rs`.

### Which runtime, and what rootless costs

Podman first, then Docker. The reason is not preference: Docker's socket is
owned by the `docker` group, and membership in it is root on the machine, since
anything that can reach the daemon can start a container with the host
filesystem mounted. Asking whoever tests a security tool to grant themselves
that in order to run one tier is a poor trade. Rootless podman needs no daemon
and no group, and the two command lines are close enough that one driver serves
both.

What rootless costs is a host port below 1024, which
`net.ipv4.ip_unprivileged_port_start` puts out of reach at its default of 1024.
Only `openldap` needs one, and it needs it because the corpus keys the root DSE
search on 389; published anywhere else the scan asks a directory for a web page
and it says nothing. So either lower the floor,

```sh
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=389
```

which is what this machine does, or install Docker and let the daemon bind it.
The failure says so when it happens rather than leaving a reader to guess.

Every tier above proves the engine is consistent with itself. A signature matches
the example recorded beside it; a parser returns on any bytes; a simulated
network answers the way a stack would. None of it ever asks a real application
what it serves, so all of it can be green while the engine identifies nothing.

This tier starts the real thing from a pinned image, scans it through
`scanner::scan`, and holds the verdict to the manifest. Going through the public
API is deliberate: reaching into the analyzers would test the parts and leave the
wiring between them unexamined, and the wiring is where these defects live.

The `report` pass asserts nothing. It prints what each target yields together
with the digest of the icon it serves and whether the corpus holds that digest,
which is how an expectation is written for a new target and how a stale corpus
entry is found.

`the_manifest_is_well_formed` runs with the ordinary suite and needs nothing, so
a mistake in the data does not read as a defect in the engine.

## Running them

```sh
cargo test                        # unit tests, hygiene, Tier 1, Tier 2, Tier 3
cargo test --lib                  # unit tests only
cargo test --test namespaced      # one tier
cargo test --test portable port_states::   # one module of one tier

# Tier 4, one target at a time so a memory-hungry image is not run beside four others
cargo test --test containers -- --ignored --test-threads=1
cargo test --test containers -- --ignored --test-threads=1 --nocapture report
```

Tiers 1 and 2 run on Linux and macOS. Tier 3 is Linux only and skips elsewhere,
and skips on a Linux machine whose policy forbids unprivileged user namespaces.
None of the three needs any setup, so `cargo test` is the whole story.

## What CI runs

`test.yml` runs the suite on both platforms, and gives Tier 3 a job of its own so
the tier has a status in the checks list rather than a share of a broader green.
That job lifts the AppArmor restriction Ubuntu ships, installs `nftables`, and
sets `ZOND_REQUIRE_NETNS`, which turns a skip into a failure. The reason is that
a skipped tier and a passing one report the same thing: run the binary with no
namespace available and it says `11 passed` in no time at all.

Tier 4 is deliberately not a CI job. It pulls gigabytes and its failures are
usually somebody else's release, which is a bad reason to redden a pull request.

One thing worth knowing about the other workflow, because it dominates the cost
of verifying a change: `lint.yml` checks the feature surface in two pieces. Each
feature on its own stays on the pull request path. Every pair of them, which is
121 combinations and between forty minutes and two hours, runs nightly against
`main` and on `workflow_dispatch`. Almost no pair in this crate can interact, so
the pairs are worth running regularly and not worth waiting for.
