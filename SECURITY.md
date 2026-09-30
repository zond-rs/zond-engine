# Security policy

## Supported versions

Zond is in early development. Fixes land on `main` and go out in the next
release; older releases are not patched.

## Reporting a vulnerability

Please don't open a public issue. Email **security@zond.rs** with:

- what the vulnerability is,
- how to reproduce it (code, input files, or the `zond` command you ran),
- what an attacker could do with it.

You'll get a reply within 7 days, and a timeline once the problem is
confirmed. If you'd like, you'll be credited in the release notes. There's no
bug bounty; this is a small project without a security team, but reports are
taken seriously and appreciated.

## Scope

This repository is the engine: the scanners, the protocol parsers, the file
formats it reads and writes, the journal, and the detection sandbox. The ones
people most often ask about:

- **Anything reachable from bytes off the wire.** `listen` reads whatever
  crosses a segment, and every parser behind it is in scope.
- **Anything reachable from a file the engine reads.** Reports, nmap XML,
  settings, target lists, journals and detection modules all come from
  outside.

Problems in the `zond` command itself (output, argument parsing, redaction,
its settings files) belong to [zond-rs/zond](https://github.com/zond-rs/zond).
If you're unsure which side something falls on, report it here; a misrouted
report is better than none.
