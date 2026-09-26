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

### CPEs naming products the vulnerability data does not have (2026-09-09, 29 rules)

Three identifiers were spelled in a way NVD has never used, so every finding
carrying one correlated against nothing:

| emitted | rows in NVD | corrected to |
|---|---|---|
| `microsoft:iis` | 0 | `internet_information_server` at 6.0 and below, `internet_information_services` above |
| `aiohttp_project:aiohttp` | 0 | `aiohttp:aiohttp`, 46 |
| `zed_shaw:mongrel` | 0 | `mongrel:mongrel`, 1 |

IIS is the largest single CPE in this corpus, 27 rules across six files, and NVD
splits it by era: 111 records under `internet_information_server`, 93 under
`internet_information_services`. The version each rule states decides which it
gets, and a rule that captures the version from a banner takes the modern name,
since that is what a live server answers with.

Counts are `totalResults` from the NVD 2.0 API on 2026-09-09, per
`cpe:2.3:a:<vendor>:<product>`.

Two more are wrong and are left alone, because no spelling has any rows behind
it: `zaphoyd:websocketpp` and `darkhttpd_project:darkhttpd`. A third,
`treck:tcp%2fip`, carries a URL-encoded separator that is an import artifact; the
product is the Ripple20 stack and nothing a scan meets runs it.

### Linux named as its own vendor (2026-09-10, 1 rule)

`Linux catch-all` in `operating/operating_system.toml` stated
`os.vendor = "Linux"`. Linux has no vendor, and the pattern it is attached to,
which matches any string ending in the word, cannot establish one.

It is the canonical reading for the name `Linux`, so `canonicalise` filled that
vendor into every reading whose product is `Linux`, which is nearly all of them.
Measured on a Debian 13 host answering both an SSH banner and an SNMP agent: the
banner stated `Debian`, the agent's reading was canonically filled with `Linux`,
the two disagreed, and `resolve`'s `agreed` dropped the vendor entirely. `label`
then fell back to the product and the host was reported as **`Linux 13`**, a
release number no Linux has ever had, attached to the wrong noun. It is the same
defect the comment on `label` records, arriving one stage earlier.

The key is removed. Nothing else in the rule changes, and a host that really has
nothing but the word `Linux` to go on still reports the family, the release the
pattern captured, and the kernel CPE.

### A distribution read as an instruction set (2026-09-08, 1 rule)

`Linux x86_64 Generic - hostname variant` took `os.arch` from its third capture,
which its own example puts the architecture in:

```
Linux hostname 2.6.9 #2 SMP Tue Jun 26 16:10:49 EDT 2012 x86_64
                                                  └─ EDT ─┘ └ capture 3 ┘
```

The capture is a position rather than a meaning. The marker before it is
`(?:[0-9]{4}|[A-Z][A-Z][A-Z]{1,2}|...)`, and on a current Debian banner `SMP`
satisfies it, so the capture takes the next word:

```
Linux zond 6.1.0-18-arm64 #1 SMP Debian 6.1.76-1 (2024-02-01) x86_64
                             └─┘ └ capture 3 ┘
```

giving `os.arch = "Debian"`. Anchoring the capture at the end loses the banner
entirely, and requiring it to look like an architecture does too: the rule's
shape does not fit a banner with a parenthesised date, so this cannot be
corrected in the capture.

The `os.arch` claim is dropped instead. The corpus carries seven rules whose
whole job is naming an instruction set, they read `x86_64` out of the same
banner, and `SignatureDb::architecture_of` asks them first. A rule identifying
Linux no longer guesses at the silicon.

### A kernel version that kept its separator (2026-09-07, 1 rule)

`ntpd running on linux` captured the kernel straight after the word, with no
allowance for the `/` that separates them:

```
system="Linux/6.1.0-50-cloud-arm64"
           └┬──────────────────┘
            └─ captured, slash and all
```

Its own example is `system="Linux2.6.10"`, which is how old ntpd wrote it and why
the pattern was written that way. Every current daemon writes the separator, so
the rule produced `os.version = "/6.1.0-50-cloud-arm64"`, rendered as
`Linux /6.1.0-50-cloud-arm64`, and fed a malformed
`cpe:/o:linux:linux_kernel:/6.1.0-50-cloud-arm64`.

Corrected to the form its own sibling two hundred lines above already uses, which
keeps the separatorless form matching:

```
system="Linux/?([^ ]+)"
```

Found by scanning ntpsec 1.2.2, which answers a mode 6 query with the fields in
alphabetical order and so reaches this rule rather than the version-first one.

### The Python runtime, onto the key that reaches a report (2026-09-06, 5 rules)

Five HTTP rules recorded the interpreter version under `python.version`, a key
nothing reads:

```
SimpleHTTP/0.6 Python/3.13.5
                      └┬───┘
                       └─ captured, stored under `python.version`, dropped
```

The corpus's own key for the runtime a service runs on is
`service.component.*`, which 347 rules already use and which the matcher turns
into a service's extra info. Corrected to it, with the vendor and product spelled
out beside the capture:

```
"service.component.vendor" = "Python Software Foundation"
"service.component.product" = "Python"
"service.component.version" = "{capture:2}"
```

A `SimpleHTTP` server is not the interesting half of that banner. The interpreter
under it is, and it was the half being thrown away.

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

### Package revisions read as point releases (2026-08-21, 6 rules)

The same error one field over. `os.version` was `"10.2"` on a rule matching
`OpenSSH_7.9p1 Debian-10+deb10u2`, reading the `u2` — the *package's* security
update number — as Debian 10.2. It is not: Debian 10 had point releases 10.0
through 10.13, and no package's revision number tracks them.

Corrected to the release the stamp actually names: `"10"`.

Scope: `os.vendor = "Debian"` with an `os.version` of `<major>.<n>` **whose rule
pattern reads that same `debNuN`**. Six matched. Six others state a version some
other way — Debian 3.1 and 7.8 were real releases, named as such — and were not
touched. The pattern is what separates them, which is why this was not a
search-and-replace.

## Integration
These fingerprints are automatically converted from the original XML format into Zond-compatible TOML. They include extended metadata such as:
- CPE (Common Platform Enumeration)
- OS Family/Version
- Hardware Device Type
- Version Capture Groups

### Functional level 7 named as Windows Server 2016 (2026-09-26, 3 rules)

`Active Directory Controller on Windows Server 2016`, `Microsoft LDS on Windows
Server Server 2016` and `Windows Server Server 2016` read
`domainControllerFunctionality` 7 and named the release 2016 with its CPE. Level
7 is the highest a domain controller on Server 2016, 2019 or 2022 reports
(MS-ADTS, `DS_BEHAVIOR_WIN2016`); no later level existed until Server
2025, which reports 10. So the value proves one of three releases, and the 2016
CPE sent every 2019 and 2022 controller to the wrong vulnerability records.

The three now name `Windows Server` with no release and no operating-system
CPE, and the two that identify a directory state the level and the releases it
covers in `service.extrainfo`. Their names are left as imported, since a rule's
name is its identifier. Level 10 is read by `network/ldap.toml`, which is
authored here.
