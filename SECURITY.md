# Security Policy

## Supported Versions

Zond is in early development and the version number moves faster than any support
window would. There is one supported version and it is the tip of `main`; a fix
lands there and is released from there. Nothing older is patched in place, and
pinning an older release means carrying its defects.

| Version | Supported          |
| ------- | ------------------ |
| tip of `main` | :white_check_mark: |
| anything else | :x:          |

## Reporting a Vulnerability

We take the security of Zond seriously. If you believe you have found a security vulnerability, please report it privately to us.

**Please do not open a public GitHub issue for security reports.**

Instead, send a detailed report to: **security@zond.rs**

### What to include:
- A description of the vulnerability.
- Steps to reproduce the issue (including any relevant `zond` commands).
- Potential impact if exploited.

### Our Commitment:
Zond is currently a **best-effort hobby project**. While we do not have a formal full-time security team, we commit to:
- Acknowledging your report within **7 days**.
- Providing a timeline for a fix once the vulnerability is confirmed.
- Crediting you for the discovery (if desired) in our release notes/hall of fame.

## Scope

This policy covers `zond-engine`, which is the whole of this repository: the
scanning engine, the protocol readers and writers, the file formats it imports
and exports, the journal, and the detection sandbox.

The `zond` CLI is a separate repository with its own release, and reports about
it belong there. Report it here if you are unsure which side of the line it falls
on. A misrouted report is better than an unsent one.

Two things are worth naming as in scope, because they are the ones people ask
about:

- **Anything reachable from bytes off the wire.** The listening phase reads
  whatever crosses a segment, and every protocol reader behind it is in scope.
- **Anything reachable from a document the engine reads.** Reports, nmap XML,
  settings, target lists, journals and detection modules are all parsed from
  files this project did not write.

We currently do not offer financial bounties, but we deeply appreciate the time and effort researchers put into making Zond more secure.
