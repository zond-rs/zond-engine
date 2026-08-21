# Rapid7 Recog Fingerprints

The signatures in this directory have been imported from the [Rapid7 Recog](https://github.com/rapid7/recog) project.

## Attribution
These fingerprints are the property of Rapid7 and are used here under the terms of their open-source license. We gratefully acknowledge their contributions to the security community.

- **Source**: [github.com/rapid7/recog](https://github.com/rapid7/recog)
- **License**: BSD-2-Clause

## Local corrections

The converted files are edited in place where the imported metadata asserts more
than its own pattern can establish. **Re-importing overwrites these**, so they are
recorded here to be re-applied.

### Linux major releases (2026-08-21, 57 rules)

`os.version` was `"12.0"` on every Debian rule, `"11.0"` on every Raspbian one,
and so on. Those rules match a banner carrying only the *major* release —
`OpenSSH_9.2p1 Debian-2+deb12u10` names `deb12`, and the `u10` is a package
revision rather than a point release — so nothing in the evidence distinguishes
Debian 12.0 from 12.7. Asserting `12.0` was correct only on hosts that had never
been updated, and wrong on every other one.

Corrected to the bare major: `"12"`, `"11"`. That is also what the corpus already
did elsewhere — Red Hat, Fedora and Synology rules were bare majors all along, so
this makes the Linux rules agree with each other.

`os.cpe23` was **left alone**. `cpe:/o:debian:debian_linux:12.0` is the
registered form for that platform, and a CPE is a name in somebody else's
namespace rather than a claim of this engine's.

Scope: `os.family = "Linux"` with an `os.version` of exactly `<major>.0`. Rules
where `.0` is a real version — Windows NT 4.0, iOS 13.0 — are a different family
and were not touched.

## Integration
These fingerprints are automatically converted from the original XML format into Zond-compatible TOML. They include extended metadata such as:
- CPE (Common Platform Enumeration)
- OS Family/Version
- Hardware Device Type
- Version Capture Groups
