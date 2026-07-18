# Zond Engine

![Build Status](https://github.com/zond-rs/zond-engine/actions/workflows/build.yml/badge.svg)
![Lint Status](https://github.com/zond-rs/zond-engine/actions/workflows/lint.yml/badge.svg)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
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
zond-engine = "0.4.0"
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

## License

This project is licensed under the **Mozilla Public License 2.0** (MPL-2.0).
See the [LICENSE](LICENSE) file for more details.

Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors.
