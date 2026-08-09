# Contributing to Zond Engine

Thanks for wanting to help. Zond Engine is the networking core behind Zond, and it
is the kind of code where a subtle mistake shows up as a wrong answer about
somebody's network rather than as a crash — so this guide is a little more
particular than most.

## Before you start

For anything larger than a bug fix, **open an issue or a discussion first**. A
scanner has a lot of load-bearing detail in it — timing, retransmission, privilege
boundaries — and it is much cheaper to agree on an approach than to rework a
finished pull request.

## License and the CLA

Zond Engine is licensed under the **GNU Affero General Public License, version 3 or
later**. Two things follow from that, and both matter before you write code.

**Your contribution ships under the AGPL.** If you distribute the engine, or run a
modified version as a network service, your users are entitled to the corresponding
source. See [LICENSE](LICENSE).

**You will be asked to sign a Contributor License Agreement.** On your first pull
request the CLA Assistant bot will post a comment; reply to it with:

```
I have read the CLA Document and I hereby sign the CLA
```

That is the whole process, and you only do it once. The agreements are
[CLA.md](CLA.md) for individuals and [CLA-ENTITY.md](CLA-ENTITY.md) for
organisations.

**Why a CLA?** You keep the copyright in your work. The agreement gives the
maintainer permission to relicense it, which is what makes it possible to offer
Zond commercially to organisations that cannot accept the AGPL, and to fix the
license later if the AGPL turns out to be the wrong choice. In exchange, the CLA
commits the project to always keeping a version available under an OSI-approved
open source license. If you contribute code you wrote for an employer, check that
they are happy for you to do so — clause 5 of the CLA covers this.

## New license headers

Every source file carries this header. New files need it too:

```rust
// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
```

Leave the copyright line as it is — "and Contributors" covers you, and the commit
history is the authoritative record of who wrote what.

## Third-party code

Do not paste in code or data you did not write without saying so. If a fingerprint
signature or an algorithm comes from somewhere else, say where in the pull request
and name the license. Permissively licensed material (MIT, BSD, Apache-2.0, ISC)
can generally be included with its attribution preserved — the Rapid7 Recog
signatures under `assets/fingerprinting/imported/rapid7/` are an example of how
that is recorded. Code under a copyleft license other than the AGPL usually cannot
be included at all.

## Working on the code

```bash
cargo test --all-features
```

```bash
cargo clippy --all-features --all-targets -- -D warnings
```

```bash
cargo fmt --check
```

Some tests exercise raw sockets and need elevated privileges; those are gated and
will skip rather than fail when run unprivileged.

A few expectations specific to this codebase:

- **Measure before and after.** Claims about performance or discovery coverage
  should come with numbers from a real run, not reasoning about what ought to be
  faster.
- **Comments explain what a value is for**, not how it came to be that way. Avoid
  changelog-style comments describing what you changed.
- **Tests should earn their place.** A test that restates the implementation is
  worse than no test; a test that pins down a real behavioural boundary is worth a
  lot.

## Pull requests

Keep them focused — one concern per pull request. Fill in the template, explain
what you verified and how, and note anything you deliberately left out. If your
change affects scan behaviour, say what you observed on a real network.

## Reporting security issues

Please do not open a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
