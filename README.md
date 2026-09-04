# Zond Engine

![Test Status](https://github.com/zond-rs/zond-engine/actions/workflows/test.yml/badge.svg)
![Lint Status](https://github.com/zond-rs/zond-engine/actions/workflows/lint.yml/badge.svg)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![Rust Version](https://img.shields.io/badge/rustc-1.93+-blue.svg)

**Zond Engine** is the core library powering the [Zond](https://github.com/zond-rs/zond) network mapping and discovery tool. It provides a lightweight, fast, and highly concurrent networking backend for packet crafting, protocol fingerprinting, and host discovery on Linux and macOS.

## Features

* **Host discovery:** ARP and ICMPv6 on the local segment, raw TCP SYN for anything
  through a gateway, and an unprivileged TCP connect fallback when the process is
  not root. Hosts arrive live on an event stream as they are found.
* **Port scanning:** seven TCP techniques (see below), raw UDP, and SCTP by INIT
  chunk, with retransmission, an adaptive deadline, and a verdict per port that
  says what the evidence actually supports.
* **Service fingerprinting:** identify the service, product and version behind an
  open port using an embedded signature database.
* **IP protocol scanning:** which protocols a host's stack takes delivery of, one
  layer below the ports — GRE, ESP, AH, OSPF and the rest, which have no ports to
  enumerate and so make a tunnel endpoint or a router look like an empty host. It
  reads a firewall's *protocol* policy rather than its port policy, which on a
  perimeter review is often the more revealing of the two.
* **TLS cipher and protocol enumeration:** what a TLS endpoint *accepts*, not
  only what one handshake negotiated. Offers each version in turn and narrows the
  cipher list until the server stops answering, so a report can say whether an
  endpoint still takes TLS 1.0, RC4, 3DES or an export cipher. Every accepted
  suite is graded from its own parts, and the withdrawn versions and broken
  ciphers become findings with the RFC that withdrew them attached.
* **Path measurement:** the routers between this machine and each host that
  answered, traced with whatever probe already reached it — a SYN to an open port
  where the scan found one, an echo otherwise. Paths shared between hosts are
  measured once, and a hop inherited that way is marked as inherited.
* **Scope exclusion:** addresses a scan may not probe or record, honoured before
  the first packet and again at every finding — so a segment sweep cannot report
  a neighbour it was forbidden to look at. The report carries the excluded ranges
  and what they cost, which is what makes it evidence that a scope was kept to.
* **Plan-wide target randomization:** the order a scan asks about its targets is
  a keyed rearrangement of the whole plan rather than a shuffle inside a window,
  so a `/16` is not walked in address order at any grain. The order is a function
  of a seed the journal records, so a resumed scan continues in the order it
  started in rather than changing shape halfway through.
* **Wall-clock bounds:** a budget per host and a budget for the whole run, so a
  scheduled scan finishes whether or not the network cooperates. A host left
  early is named in the report rather than reported quiet, and a run that spent
  its budget says so rather than reading as one somebody interrupted.
* **Comparing two scans:** what appeared, what went away, and what changed about
  what stayed — paired by address across scans that keyed the same machine
  differently, and read against what each scan says it walked, so a narrowed scan
  does not read as a network that emptied out. Every host and endpoint is graded
  routine, notable or urgent, so a nightly comparison of a live network says which
  three lines of it somebody has to read.
* **Folding several scans into one:** a `/16` scanned in eight chunks, one range
  seen from inside the perimeter and from outside, or a year of archived nmap
  files against tonight's run. A later source overrides only where it made a
  claim, so a host missing from tonight's scan is not a host that went away and an
  endpoint nothing listed is not a port that closed. Each phase of the result says
  which document it came from.
* **Resume and replay:** a scan is journalled as it runs, so one that was
  interrupted continues from where it stopped and one that finished can be read
  back without the network.
* **Known-exploited correlation:** the CVE correlator takes its dataset as a
  parameter rather than compiling one in, and `import::kev` converts CISA's
  Known Exploited Vulnerabilities catalogue into it. KEV carries no version
  data, so those findings say so: they match on the software and report at a
  lower confidence than a version match, with an excerpt stating that the
  version was never checked.
* **ICMP timestamp probing:** every host the OS pass pings over IPv4 is also
  asked for a timestamp (RFC 792 type 13). Filters written against ping
  routinely pass it, so a host that answers no echo is still found, and the
  reply carries the target's own clock, which no other probe here obtains. An
  offset of hours says a machine is in another timezone or has never had its
  clock set. IPv4 only: RFC 4443 defines no timestamp message.
* **Signing a report:** a detached Ed25519 signature over the exact bytes an
  export wrote, to keep beside it. It establishes that the holder of a key
  produced that document and that not a byte has changed since, which is what a
  compliance artifact needs and is all it claims: whoever holds the key can sign
  anything, so it attests to the document and never to the honesty of the run.
  Keys are the caller's, and verification takes the trusted public key as an
  argument rather than reading one out of the file being checked.
* **Detections from somebody else, safely:** a detection reaches the network only
  through the verbs its class grants, which is a sandbox nmap cannot retrofit onto
  an NSE script. That is worth nothing unless a stranger's detection can go into
  it, so a published set is signed as one manifest naming every detection and the
  hash of its source — binding the membership, not just the bytes, so an attacker
  serving the files cannot drop the one that would have found them. The only way
  to load one is to name the key you trust; there is no flag to leave unset.
* **Reports in and out:** export a finished scan as JSON, JSONL, CSV, a
  self-contained HTML page, or nmap-compatible XML; read targets back from a list,
  CSV, this engine's own JSON, or an nmap XML file somebody else produced.
  Each format sits behind a cargo feature.

There is no dynamic plugin system, deliberately — loading code into a process
holding raw-socket privileges is a liability, and it buys nothing a trait does
not. `Exporter` and the import traits are public, so a consumer who wants their
own format writes it in their own crate, type-checked at compile time and costing
this crate no dependency.

## Getting Started

Add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
zond-engine = "0.14.0"
```

A scan runs in two phases. `discover` establishes which hosts exist; `scan`
classifies the ports of hosts already known. They are separate calls because
they cost very different amounts — sweeping a `/24` is a few hundred packets,
port-scanning all of it is a few hundred thousand — so run the cheap one first
and spend the expensive one only on what answered.

Each returns a pair: a `ScanSession` you can watch while the scan runs, and a
task that resolves to the `ScanReport` describing it afterwards.

```rust
use zond_engine::{Resolver, ScanEvent, ZondConfig, discover, resolve};

// One call: the address grammar, this host's interface table for `lan` and
// `%en0`, any hostnames, and whether a segment sweep was asked for.
let resolver = Resolver::from_system();
let targets = resolve::for_discovery(&["192.168.1.0/24"], Some(&resolver)).await?;

let mut cfg = ZondConfig::default();
targets.apply_to(&mut cfg);

let (mut session, task) = discover(targets.into_ips(), &cfg).await?;

// Hosts arrive as they are found.
while let Some(event) = session.events().recv().await {
    if let ScanEvent::HostUpdated(address) = event
        && let Some(host) = session.hosts().get(&address)
    {
        println!("{host}");
    }
}

// And the record of the sweep once it is over.
let report = task.join().await?;
println!("{} hosts up", report.summary().hosts_alive);
```

Both phases work without root — they fall back to ordinary TCP connect
attempts — and the report records which it was, so a result can be read for what
it is worth.

## Modules

* `model`: the domain model — hosts, ports, IP sets, targets, and the addresses
  and exclusions they are expressed in. `config` is the scan configuration beside
  it.
* `scanner`: the two entry points — `discover` for which hosts are alive, `scan`
  for which of their ports are open — the strategies behind them, the live
  session and the finished report.
* `fingerprint`: service and operating-system identification over an open port.
* `detect`: what to conclude beyond a service name. Declarative flows, a
  capability-sandboxed compute tier, and the signed bundles that let a
  stranger's detections run under both. `cve` correlates a finished report
  against a vulnerability dataset.
* `diff`: what changed between two scans, whoever ran them, judged by what each
  says it walked, and graded by how much it is worth acting on.
* `merge`: any number of scans folded into one report — a `/16` scanned in
  chunks, two vantage points on one range, a year of archived nmap files against
  tonight's run.
* `journal`: a scan written down as it runs, so one that stopped can be resumed
  and one that finished can be replayed.
* `export` / `import`: reports out, targets and settings in. `format` is what a
  reader and a writer of the same document have to agree on; `record` is the
  model as data, and the one place the wire vocabulary lives.
* `protocols`: protocol parsers and packet crafting (TCP, UDP, ICMP, ARP, NDP,
  DNS, mDNS).
* `transport`: raw send and capture transports, beneath the protocol layer.
  `resolve` turns names into addresses above it.
* `system`: interfaces, routing and privilege checks — the only place the engine
  asks the host about itself.

## TCP scan techniques

A port scan asks a target one question, and the flags on the probe decide which
question that is. Set `ZondConfig::tcp_technique` to choose; the default is
`Syn`. All but the default need raw sockets, and asking for one without them is
reported as a failed strategy rather than silently answered with a connect scan.

| Technique | Probe | What a RST means | What silence means |
| --------- | ----- | ---------------- | ------------------ |
| `syn`     | `SYN` | closed (a SYN+ACK means **open**) | filtered |
| `fin`     | `FIN` | closed | open or filtered |
| `null`    | no flags | closed | open or filtered |
| `xmas`    | `FIN PSH URG` | closed | open or filtered |
| `maimon`  | `FIN ACK` | closed | open or filtered |
| `ack`     | `ACK` | **unfiltered** — the probe arrived | filtered |
| `window`  | `ACK` | **open** where it announces a window, closed where it announces zero | filtered |

`TcpScanTechnique` parses from a string, renders back to it, and carries a
one-line summary per variant, so a front end can offer the choice without a
mapping table of its own.

**None of them answers the whole question alone.** Only `syn` identifies a
listener from the reply itself. The flag probes report an open port and a
filtered one identically, since both are silent. An `ack` scan separates those
two and never says which is open, and `window` is that same probe read one field
further. They are complementary instruments, not alternatives.

**Three limits worth knowing before trusting a result.** Windows, many Cisco
devices, BSDI and IBM OS/400 answer every flag probe with a RST whatever the
port state, so `fin`, `null`, `xmas` and `maimon` report every port closed
against them — a run that finds no open-or-filtered port at all has probably met
one. `maimon` only distinguishes anything on BSD-derived stacks: elsewhere an
open port answers exactly as a closed one does and is reported closed, which is a
wrong answer rather than a missing one. And `window` depends on a stack leaving
the listening socket's window on a reset, which BSD derivatives and a lot of
network hardware do and current Linux and Windows do not: against those it
reports the whole range closed. A range that comes back almost entirely open is
the same failure from the other side. Read either against a `syn` scan.

## Scanning SCTP

SCTP carries Diameter, S1AP and M3UA, so a mobile core scanned for TCP and UDP
alone comes back looking empty. Ask about it in the port specification, with the
`s:` prefix beside the `u:` one UDP uses:

```text
80,443,u:53,s:2905,s:3868
```

`PortSet::top_sctp` is the engine's own list of which ports those are: twenty-five
of them, a mobile core first, short enough that the order is a claim all the way
down. It is the one port list that is never a default, since nothing probes SCTP
unless a scan asked for it.

The default probe is an INIT chunk, and both answers it can draw are decisive:
an INIT-ACK is an endpoint accepting the association, so the port is open, and an
ABORT is a reachable stack refusing it, so the port is closed. Neither completes
an association, so no port is left half-open. Silence is `filtered` rather than
`open|filtered`, because a live endpoint answers either way.

The other technique is the COOKIE-ECHO, set with `sctp_technique`. It carries a
cookie no endpoint minted, and RFC 4960 sends that down two paths: a listener
authenticates it, fails, and discards the packet without a word, while a port
with nothing behind it answers with an ABORT. So an ABORT is still a closed port
and everything else is `open|filtered`, with no way to tell an open port from a
filtered one. What it buys is passage. A filter written against SCTP scanning
blocks the INIT, because that is the chunk a scan is expected to send; rules
written for the first often say nothing about the second. Reach for it when an
INIT scan came back entirely filtered and the question is whether the filter is
aimed at SCTP or only at the chunk everybody sends.

Discovery follows the ports, and always with an INIT whichever technique the
port scan was asked for, since a COOKIE-ECHO draws nothing from the open port a
sweep is hoping to hear from. A scan that names an SCTP port sweeps for hosts
with an INIT as well as with a SYN, because the port phase probes what discovery
found: a host behind a filter that passes SCTP and drops everything
else would otherwise be reported down with its ports never looked at. The sweep
asks on the likeliest of the ports you named.

Two things worth knowing. Neither technique has an unprivileged form and both
need raw sockets, so
an unprivileged scan that named SCTP ports is told they went unprobed rather than
being handed a different question's answer. And a host with no SCTP stack at all
answers ICMP protocol unreachable, so a range that comes back entirely filtered
may be a machine that does not speak SCTP rather than a firewall in front of one.

There is no service pass behind an SCTP port: identifying what is listening needs
an association, and this engine holds none.

## Measuring the route to a host

`ZondConfig::traceroute` turns on path measurement. It runs last, after the
ports are known, and only against hosts that answered something:

```rust
use zond_engine::ZondConfig;

let mut cfg = ZondConfig::default();
cfg.traceroute = true;
```

**A router is made to identify itself by giving it something to discard.** A
router forwarding a packet need not say so; a router whose hop limit reached zero
is required to (RFC 792, RFC 4443 §3.3). So a probe built to expire a chosen
number of hops away makes exactly that router announce itself.

**The probe matches the scan.** A host with an open TCP port is traced with SYNs
to that port, and any other host with ICMP echoes. That is not a detail: the
probe that reached a host is the probe its network permits, and a trace made of
something else measures the path to wherever that something else is dropped. A
SYN to :443 crosses filters that discard every ping.

**Traces are measured backwards and share their prefixes.** A trace starts at the
target and walks inward, so the first router it recognises from an earlier trace
is the point at which the rest can be taken from that trace instead of measured
again — which on a scan of many hosts behind one gateway is nearly all of it.
That splice assumes two paths meeting one router at one distance agreed before
it; every hop adopted that way is marked `inferred`, so a reader can tell a
measurement from an inheritance.

A router that will not answer is recorded as a hop with no address rather than
omitted, because dropping it would renumber every router beyond it. Only hosts
that answered are traced: a path is measured from its far end, and the far end's
distance is read out of a reply.

Paths appear in the JSON report as `path` on each host, and in the nmap-XML
export as `<trace>` and `<distance>` — the one finding this engine produces that
nmap's format already has a first-class place for.

## Asking what a TLS port accepts

A handshake tells you what an endpoint negotiated with the client that turned
up. An audit asks something else: what would it negotiate with a client that
asked for something worse? Set `tls_enumeration` and the scan finds out.

```rust
let mut cfg = ZondConfig::default();
cfg.tls_enumeration = true;
cfg.host_timeout = Some(Duration::from_secs(120));
```

It runs after service detection, against the ports a handshake already completed
against, and it offers each version from SSL 3.0 to TLS 1.3 in turn. Each answer
names one cipher suite, which is removed from the offer before the next
question, so the walk ends when the server stops answering. What comes out is
every version accepted and every suite under it, in the order the server chose
them.

None of this goes through `rustls`, which the certificate path uses. That
library implements TLS 1.2 and 1.3 and the nine AEAD suites of its ring
provider, and declines by design to speak SSL 3.0, RC4, 3DES or an export
cipher, which are exactly the configurations a report is asked about. So the
ClientHello is built by hand and the ServerHello read by hand, and no handshake
is ever completed: the connection is torn down once the answer is read, so
nothing is negotiated and no application-level session exists.

Each accepted suite is graded from its own parts rather than from a table beside
them. `TLS_RSA_WITH_3DES_EDE_CBC_SHA` says it exchanges keys with static RSA,
encrypts with 3DES in CBC mode and authenticates with SHA-1, and the report
names all four faults that follow: no forward secrecy, a SHA-1 MAC, CBC mode,
and a 64-bit block. A suite added to the registry is graded by the same rule, so
nothing can arrive ungraded.

Findings are grouped by fault rather than by suite. An endpoint accepting nine
RC4 suites has one problem and one line of configuration to fix, so it produces
one finding with the suites in its excerpt. A withdrawn version is its own
finding, separately from whatever ciphers sit under it, and cites the RFC that
withdrew it.

Two things worth knowing. It costs connections: about a dozen against a current
server, a few dozen against one that accepts everything under three versions,
and the target's connection log sees all of them. And it sends no SNI, because
the name a target was resolved from is not recorded by the time this runs, so an
endpoint that refuses a nameless hello reads as one that accepted nothing. Both
are why the pass is opt-in and why `host_timeout` is worth setting beside it.

## Writing a detection

Fingerprinting names a service. A detection says what is wrong with it, and
anybody can write one. There are two tiers and the choice between them is
usually obvious.

A **flow** is a detection authored as data: a bounded sequence of probe-and-match
steps ending in a typed finding. It carries no code, cannot loop and cannot
exceed the budget it declares, so most detections should be one.

```toml
[detection]
id      = "acme-metrics-pprof"
version = "1.0.0"
title   = "Internal metrics daemon exposes pprof"

# The gate. `speaks` asks the fingerprint corpus which services are carried over
# HTTP, so a gate written this way covers a product the corpus can name as well
# as a plain web server.
[detection.when]
speaks = "http"
ports  = [9110, 9111]

# What it asks to be handed, and the bounds it runs under.
[detection.capabilities]
class      = "active-benign"
speak      = "target"
max_bytes  = 8192
max_millis = 2000

[[step]]
send   = "GET /debug/pprof/ HTTP/1.0\r\n\r\n"
expect = "Types of profiles available"
bind   = { build = "X-Acme-Build: (?<build>[0-9a-f]{7,40})" }

  [[step.finding]]
  when       = "matched"
  severity   = "high"
  summary    = "pprof is reachable on the metrics port"
  detail     = "Build {build} serves /debug/pprof to anyone who can reach the port."
  references = [{ cwe = 200 }]
```

A **compute module** is for what a flow cannot express: real parsing, a stateful
exchange, a verdict computed from behaviour. It is code, written in Rhai with
`fn analyze(ctx, responses)` as its entry point, and it reaches the world only
through the verbs its class is granted. Write the body inline under `[compute]`,
or keep it in a sibling file and name it with `body = "check.rhai"`.

The `class` a detection declares is a request, never a grant. `passive` sends
nothing, `active-benign` exchanges bytes with the one scanned socket, and
`active-mutating`, `exploit` and `dos` each do more to the target than the one
before. The operator's `ZondConfig::detection` envelope decides which are served,
and it stops at `active-benign` unless somebody raises it, so a detection above
that ships inert.

Load them by handing the builder what the files hold. The engine opens nothing:

```rust
use zond_engine::detect::Detections;

let detections = Detections::builder()
    .sources(&sources)?   // name to contents, from wherever they came
    .build();

let (session, task) = scan(targets, &cfg, detections).await?;
```

Detections from somebody else arrive as a signed bundle instead. `Bundle::verified`
takes the key the caller trusts, checks the signature before the manifest is
parsed and each source against the hash the manifest records before anything is
compiled. Because the signature covers the membership rather than only the bytes,
an attacker serving the files cannot drop the one that would have found them.

`examples/detections.rs` walks the whole of it, publisher and recipient. The
official CLI puts it behind `zond detections`.

## Excluding addresses from a scan

`ZondConfig::exclusions` names addresses the scan may not touch, in the same
grammar targets are written in:

```rust
use zond_engine::{Resolver, ZondConfig, resolve};

let mut cfg = ZondConfig::default();
// ... a settings document has already contributed its own ...

let resolver = Resolver::from_system();
let from_arguments = resolve::for_exclusion(&["10.0.5.0/24"], Some(&resolver)).await?;
cfg.exclusions.extend(&from_arguments);
```

It is enforced twice. The target list is narrowed before anything is opened, so
no probe is addressed at an excluded host; and every finding is checked again on
its way into the store, so a segment sweep cannot record a neighbour it learned
about from an ARP reply or the host's own neighbour table. The second is the one
that makes this a guarantee rather than a filter — a sweep does not confine
itself to the addresses it was given.

**What it cannot promise is that an excluded machine never receives a packet.**
An ARP request goes to the broadcast address and the IPv6 all-nodes echo to
`ff02::1`; every machine on the link sees them. The reply is dropped, and a
caller who needs the stronger property should not sweep the segment.

The report records the excluded ranges and how many addresses they withheld, so
a finished scan can be checked against the scope it was run under: no host in it
falls inside a range it names.

A settings file may set `exclude` too — the one key in that document that
accumulates across layers rather than being overridden, since a range an
administrator wrote into `/etc/zond/engine.toml` should not be droppable by a
file below it.

## Compatibility

* **Supported Platforms:** Linux, macOS
* **Unsupported:** Windows is not currently supported.

### Address families

|                                   | IPv4                | IPv6                                                                             |
| --------------------------------- | ------------------- | -------------------------------------------------------------------------------- |
| Local-segment discovery           | ARP sweep           | all-nodes echo, neighbor discovery, the host's own neighbour cache, mDNS records |
| TCP port scanning (SYN, connect)  | yes                 | yes                                                                              |
| UDP port scanning                 | yes                 | yes                                                                              |
| Sweeping a whole network by range | yes                 | no — see below                                                                   |

An IPv6 network is **searched, not enumerated.** A `/64` holds 2^64 addresses,
so there is no equivalent of walking a `/24`: `zond d lan` finds IPv6 neighbours
through multicast probes and the addresses the host already knows, and a routed
IPv6 prefix too large to probe one address at a time is refused rather than
silently sampled. Results found on a local segment carry the interface they were
found on, since a link-local address names a different machine on every link.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first — it
covers what the AGPL asks of you and the Contributor License Agreement you will be
asked to sign on your first pull request.

## License

This project is licensed under the **GNU Affero General Public License, version 3
or later** (AGPL-3.0-or-later). See the [LICENSE](LICENSE) file for the full text.

In short: you may use, study, modify and redistribute this software, but if you
distribute it — or run a modified version as a network service that users interact
with — you must offer those users the corresponding source under the same terms.

If the AGPL does not suit your deployment, a separate commercial license is
available; contact **licensing@zond.rs** to discuss terms.

The fingerprint signatures under `assets/fingerprinting/imported/rapid7/` are
derived from the [Rapid7 Recog](https://github.com/rapid7/recog) project and remain
under their original BSD-2-Clause license.

Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors.
