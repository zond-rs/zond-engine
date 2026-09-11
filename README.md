# Zond Engine

![Test Status](https://github.com/zond-rs/zond-engine/actions/workflows/test.yml/badge.svg)
![Lint Status](https://github.com/zond-rs/zond-engine/actions/workflows/lint.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/zond-engine.svg)](https://crates.io/crates/zond-engine)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![Rust Version](https://img.shields.io/badge/rustc-1.93+-blue.svg)

A network scanner, as a library. Addresses in, and it reports which hosts are
alive; hosts and ports in, and it reports which of those are open and what is
listening behind them. The scanning, the domain model, the report and the file
formats are all here.

[Zond](https://github.com/zond-rs/zond) is the official command-line front end,
and one consumer of this crate among others.

```toml
[dependencies]
zond-engine = "0.15"
```

## Two phases

`discover` establishes which hosts exist. `scan` classifies the ports of hosts
already known. Separate calls, because sweeping a `/24` is a few hundred packets
and port-scanning all of it is a few hundred thousand.

```rust
use zond_engine::{Resolver, ScanEvent, ZondConfig, discover, resolve};

// One call handles the address grammar, this host's interface table for `lan`
// and `%en0`, any hostnames, and whether a segment sweep was asked for.
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

Both run without root, falling back to TCP connect attempts, and the report
records which it was.

A third entry point, `listen`, sends nothing and reads what a link already
carries: which switch port this machine is on, which VLANs it carries, what a
device says about itself while asking for an address.

## What it can do

**Finding hosts.** ARP and ICMPv6 on the local segment, raw TCP SYN through a
gateway, an unprivileged connect fallback, and an ICMP timestamp beside every
echo.

**Classifying ports.** Seven TCP techniques, raw UDP, SCTP by INIT chunk or
COOKIE-ECHO, with retransmission and an adaptive deadline. A separate pass asks
which IP protocols the stack takes delivery of, one layer below the ports.

**Naming what is listening.** Service, product and version from an embedded
signature corpus, the operating system from the shape of a reply. A TLS port can
be asked what it *accepts* rather than what one handshake negotiated: every
version and suite offered in turn, each graded from its own parts.

**Saying what is wrong with it.** A detection corpus that turns a service name
into a finding. Detections are TOML: a bounded sequence of probes and matches,
or a sandboxed module that reaches the network only through the verbs its class
grants. The operator sets the ceiling, so anything above `active-benign` ships
inert. A finished report correlates against a vulnerability dataset the caller
supplies.

**Keeping the result.** Every scan is journalled as it runs, so one that stopped
continues and one that finished replays without the network. Reports export as
JSON, JSONL, CSV, a self-contained HTML page or nmap XML; targets import from a
list, CSV, this engine's JSON or somebody else's nmap XML. Two reports compare,
any number fold into one.

**Staying inside a scope.** Excluded addresses are enforced before the first
packet and again at every finding, and the report carries the ranges and what
they withheld.

## Modules

| | |
|---|---|
| `model` | Hosts, ports, IP sets, targets, and the addresses and exclusions they are expressed in. `config` sits beside it. |
| `scanner` | `discover`, `scan` and `listen`, the strategies behind them, the live session and the finished report. |
| `fingerprint` | Service and operating-system identification over an open port. |
| `detect` | What to conclude beyond a service name. Flows, the sandboxed compute tier, signed bundles, and `cve` correlation. |
| `diff` / `merge` | What changed between two scans, and any number of scans folded into one. |
| `journal` | A scan written down as it runs, so it can be resumed or replayed. |
| `export` / `import` | Reports out, targets and settings in. `record` is the model as data. |
| `protocols` | Parsing and packet crafting: TCP, UDP, ICMP, ARP, NDP, DNS, mDNS. |
| `transport` | Raw send and capture, beneath the protocol layer. `resolve` turns names into addresses above it. |
| `system` | Interfaces, routing and privilege checks. The only place the engine asks the host about itself. |

Each import and export format sits behind a cargo feature. The reference on
[docs.rs](https://docs.rs/zond-engine) is built with all of them on.

## Compatibility

Linux and macOS. Windows is not supported.

|                                | IPv4       | IPv6                                                                |
| ------------------------------ | ---------- | ------------------------------------------------------------------- |
| Local-segment discovery        | ARP sweep  | all-nodes echo, neighbour discovery, the host's own cache, mDNS      |
| TCP port scanning              | yes        | yes                                                                 |
| UDP port scanning              | yes        | yes                                                                 |
| Sweeping a network by range    | yes        | no, an IPv6 network is searched rather than enumerated               |

A `/64` holds 2^64 addresses, so there is no equivalent of walking a `/24`.
Multicast probes and the neighbour table find what is on the link, and a prefix
too large to probe one address at a time is refused rather than sampled.

## Contributing

Contributions are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers what the
AGPL asks of you and the Contributor License Agreement you will be asked to sign
on your first pull request.

## License

GNU Affero General Public License, version 3 or later. See
[LICENSE](LICENSE).

You may use, study, modify and redistribute this software. If you distribute it,
or run a modified version as a network service, you must offer your users the
corresponding source under the same terms. If that does not suit your
deployment, a commercial license is available: **licensing@zond.rs**.

The fingerprint signatures under `assets/fingerprinting/imported/rapid7/` are
derived from [Rapid7 Recog](https://github.com/rapid7/recog) and remain under
their original BSD-2-Clause license.

Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors.
