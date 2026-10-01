# zond-engine

[![Crates.io](https://img.shields.io/crates/v/zond-engine.svg)](https://crates.io/crates/zond-engine)
[![Docs](https://docs.rs/zond-engine/badge.svg)](https://docs.rs/zond-engine)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

A network scanner as a Rust library: host discovery, port scanning, service
and OS identification, vulnerability matching, and the reports that come out
of it. [zond](https://github.com/zond-rs/zond) is the command-line tool built on
it; anything else you build gets the same scans and the same report format.

```toml
[dependencies]
zond-engine = "0.19"
tokio = { version = "1", features = ["full"] }
```

## Example

Find the live hosts in a range, printing each as it turns up:

```rust
use zond_engine::{Resolver, ScanEvent, ZondConfig, discover, resolve};

let resolver = Resolver::from_system();
let targets = resolve::for_discovery(&["192.0.2.0/24"], Some(&resolver)).await?;

let mut cfg = ZondConfig::default();
targets.apply_to(&mut cfg);

let (mut session, task) = discover(targets.into_ips(), &cfg).await?;

while let Some(event) = session.events().recv().await {
    if let ScanEvent::HostUpdated(address) = event
        && let Some(host) = session.hosts().get(&address)
    {
        println!("{host}");
    }
}

let report = task.join().await?;
println!("{} hosts up", report.summary().hosts_alive);
```

`scan` works the same way for ports, and `listen` records what a link carries
without sending anything. Every call gives you a live session to watch and a
report at the end that says what was asked, what came back, and what failed.

## What's in it

- **Discovery**: ARP and ICMPv6 on the local segment, TCP SYN beyond it, a TCP
  connect fallback when there are no raw sockets.
- **Port scanning**: TCP (SYN and six other techniques), UDP and SCTP, with
  retransmission and adaptive timing.
- **Identification**: services, versions and operating systems from an
  embedded signature set, and a full TLS enumeration of what an endpoint
  accepts.
- **Findings**: a sandboxed detection language, and CVE matching that checks a
  distribution's build against its own fix data (Ubuntu, Debian) instead of
  trusting the version number. Findings citing a CVE that CISA lists as
  exploited are marked.
- **Records**: scans are journalled as they run, so they can be resumed.
  Reports export as JSON, JSONL, CSV, HTML or nmap XML, and can be diffed and
  merged, nmap's included.
- **Scope**: no packet is addressed to an excluded address, and none appears
  in the report. A local sweep's broadcasts (ARP, the all-nodes echo, one
  router solicitation and one DHCPINFORM) still reach every machine on the
  segment. Excluded ports are never probed; name lookups and the IP-protocol
  pass do not consult them.

The [docs](https://docs.rs/zond-engine) walk through all of it; the crate-level
page is the place to start. File formats and optional pieces sit behind cargo
features, listed in `Cargo.toml`.

## Platforms and privileges

Linux, macOS and Windows. Building needs libpcap: `libpcap-dev` on Debian and
Ubuntu, `libpcap-devel` on Fedora, nothing extra on macOS, and
[Npcap](https://npcap.com) on Windows.

Raw sockets (root, `CAP_NET_RAW`, or BPF access on macOS) give you ARP, ICMPv6
and SYN. Without them everything still runs over plain TCP connections, and the
report says so.

IPv6 is supported throughout, with one difference: an IPv6 network is searched
(multicast, neighbour discovery, mDNS) rather than swept address by address,
since a /64 is too big to walk.

## Contributing

Issues and pull requests are welcome. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) first; your first pull request will ask you
to sign a Contributor License Agreement. Report security problems privately, as
described in [SECURITY.md](SECURITY.md).

## License

AGPL-3.0-or-later, see [LICENSE](LICENSE). If you distribute it, or run a
modified version as a network service, you have to offer your users the source.
If that doesn't work for you, a commercial license is available:
licensing@zond.rs.

The signatures under `assets/fingerprinting/imported/rapid7/` come from
[Rapid7 Recog](https://github.com/rapid7/recog) and stay under BSD-2-Clause.
CISA's list of exploited vulnerabilities in `assets/cve/kev.toml` is public
domain (CC0).

Copyright (c) 2026 Erik Lening (hollowpointer) and contributors.
