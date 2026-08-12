# Zond Engine

![Build Status](https://github.com/zond-rs/zond-engine/actions/workflows/build.yml/badge.svg)
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
zond-engine = "0.10.0"
```

A scan runs in two phases. `discover` establishes which hosts exist; `scan`
classifies the ports of hosts already known. They are separate calls because
they cost very different amounts — sweeping a `/24` is a few hundred packets,
port-scanning all of it is a few hundred thousand — so run the cheap one first
and spend the expensive one only on what answered.

Each returns a pair: a `ScanSession` you can watch while the scan runs, and a
task that resolves to the `ScanReport` describing it afterwards.

```rust
use zond_engine::{ScanEvent, ZondConfig, discover};
use zond_engine::core::parse::ip::to_set;

let targets = to_set(&["192.168.1.0/24"], None)?;
let (mut session, task) = discover(targets, &ZondConfig::default()).await?;

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
* `system`: interfaces, routing and privilege checks.
* `host_sys`: local sockets and firewall status for the host itself.

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
