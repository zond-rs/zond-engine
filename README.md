# Zond Engine

![Build Status](https://github.com/zond-rs/zond-engine/actions/workflows/build.yml/badge.svg)
![Lint Status](https://github.com/zond-rs/zond-engine/actions/workflows/lint.yml/badge.svg)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![Rust Version](https://img.shields.io/badge/rustc-1.93+-blue.svg)

**Zond Engine** is the core library powering the [Zond](https://github.com/zond-rs/zond) network mapping and discovery tool. It provides a lightweight, fast, and highly concurrent networking backend for packet crafting, protocol fingerprinting, and host discovery on Linux and macOS.

## Features

* **Network Discovery:** Fast, asynchronous host scanning using raw sockets or TCP connect fallbacks.
* **Protocol Fingerprinting:** Identify services, databases, and network devices using an embedded signature database.
* **System Profiling:** Gather detailed local network interface and system information.
* **Pluggable Architecture:** Easy to extend with custom packet parsers or discovery modules.

## Getting Started

To use the `zond-engine` in your own Rust project, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
zond-engine = "0.10.0"
```

## Modules

This crate contains the following core modules:

* `core`: Shared data structures, constants, and utilities.
* `protocols`: Network protocol parsers and packet crafting (TCP, UDP, ICMP, DNS, MDNS, etc.).
* `plugins`: Extendable modules for specific application-layer interactions or advanced enumeration.
* `system`: OS-level utilities (interfaces, firewall status, local processes) for Linux and macOS.
* `scanner`: The main asynchronous scanner, host resolution, and core orchestration logic.

## Compatibility

* **Supported Platforms:** Linux, macOS
* **Unsupported:** Windows is not currently supported.

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
