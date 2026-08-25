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
* **Port scanning:** six TCP techniques (see below) and raw UDP, with
  retransmission, an adaptive deadline, and a verdict per port that says what the
  evidence actually supports.
* **Service fingerprinting:** identify the service, product and version behind an
  open port using an embedded signature database.
* **Path measurement:** the routers between this machine and each host that
  answered, traced with whatever probe already reached it — a SYN to an open port
  where the scan found one, an echo otherwise. Paths shared between hosts are
  measured once, and a hop inherited that way is marked as inherited.
* **Scope exclusion:** addresses a scan may not probe or record, honoured before
  the first packet and again at every finding — so a segment sweep cannot report
  a neighbour it was forbidden to look at. The report carries the excluded ranges
  and what they cost, which is what makes it evidence that a scope was kept to.
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
zond-engine = "0.13.0"
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

// Hosts arrive as they are found, rather than all at the end.
while let Some(event) = session.events().recv().await {
    if let ScanEvent::HostUpdated(ip) = event
        && let Some(host) = session.hosts().get(&ip)
    {
        println!("{host}");
    }
}

let report = task.join().await?;
println!("{} hosts up", report.summary().hosts_alive);
```

Both phases work without root — they fall back to ordinary TCP connect
attempts — and the report records which it was, so a result can be read for what
it is worth.

## Modules

* `core`: the domain model (hosts, ports, IP sets, targets), scan configuration,
  the live session and the finished report.
* `scanner`: the two entry points — `discover` for which hosts are alive, `scan`
  for which of their ports are open — and the strategies behind them.
* `fingerprinting`: service identification over an open port.
* `export` / `import`: reports out, targets and settings in.
* `protocols`: protocol parsers and packet crafting (TCP, UDP, ICMP, ARP, NDP,
  DNS, mDNS).
* `network`: raw send and capture transports, beneath the protocol layer.
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

`TcpScanTechnique` parses from a string, renders back to it, and carries a
one-line summary per variant, so a front end can offer the choice without a
mapping table of its own.

**None of them answers the whole question alone.** Only `syn` identifies a
listener. The flag probes report an open port and a filtered one identically,
since both are silent. An `ack` scan separates those two and never says which is
open. They are complementary instruments, not alternatives.

**Two limits worth knowing before trusting a result.** Windows, many Cisco
devices, BSDI and IBM OS/400 answer every flag probe with a RST whatever the
port state, so `fin`, `null`, `xmas` and `maimon` report every port closed
against them — a run that finds no open-or-filtered port at all has probably met
one. And `maimon` only distinguishes anything on BSD-derived stacks: elsewhere an
open port answers exactly as a closed one does and is reported closed, which is a
wrong answer rather than a missing one.

## Measuring the route to a host

`ZondConfig::traceroute` turns on path measurement. It runs last, after the
ports are known, and only against hosts that answered something:

```rust
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

## Excluding addresses from a scan

`ZondConfig::exclusions` names addresses the scan may not touch, in the same
grammar targets are written in:

```rust
use zond_engine::{Resolver, ZondConfig, resolve};

let resolver = Resolver::from_system();
let mut cfg = ZondConfig::default();

// Layered, never assigned: a settings file may already have contributed its own.
cfg.exclusions
    .extend(&resolve::for_exclusion(&["10.0.5.0/24"], Some(&resolver)).await?);
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
