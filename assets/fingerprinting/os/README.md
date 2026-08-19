# Operating-system rules

Rules matched against a `StackObservation` — a typed feature vector read off one
TCP reply — rather than against text. The schema is
`src/fingerprinting/os/signature.rs`, shared verbatim with `build.rs`.

## Two kinds of rule, and why both belong

Every rule declares its `provenance`:

- **`measured`** — read off a real host by this engine, through this engine's own
  probe, with the machine's operating system known independently. Must ship the
  observation it was measured from.
- **`published`** — taken from the documented defaults a stack family is known to
  have. Must say in `notes` what it rests on. Scores lower until somebody
  confirms it here.

The difference is not reliability. A stack's initial hop counter, the order it
writes its TCP options in, and whether it offers timestamps by default are stable,
well-known properties. The difference is that a `published` rule has not been seen
**through this engine's own probe**, and that gap has a specific technical cause
worth understanding before authoring anything.

**Option negotiation is reciprocal.** RFC 7323 §2.2 permits a window scale in a
SYN+ACK only if the SYN carried one; §3.2 says the same of timestamps, and
RFC 2018 §2 of SACK-permitted. So a peer names the options it was *asked* about,
and any recorded layout is a joint fact about that peer and the probe that drew
it. A layout recorded against one probe describes nothing when a different probe
is sent — it matches no host at all, from every stack at once, while looking
perfectly correct.

Every rule here is written against the option set `tcp::create_probe` sends. A
rule taken from elsewhere has to be checked against that, not assumed onto it,
which is what `published` records and what confirming one promotes.

## Coverage

| family | provenance | notes |
|---|---|---|
| Linux | measured | two shapes across four labelled hosts, one with a known kernel |
| macOS | measured | confirmed on a Mac; covers iOS and iPadOS, which share the kernel and are indistinguishable at this layer |
| Windows | published | NT-family defaults; a stock firewall drops, so this needs a host with something listening |
| FreeBSD | published | distinguished from Darwin by option order |
| Network device | published | the hop counter alone; deliberately states no option predicate |

## This directory is published

`assets/` is deliberately **not** excluded from the packaged crate — `build.rs`
compiles the rules out of it, so a package without it does not build. Every word
written here goes to crates.io and stays there.

A rule's provenance has to say what *kind* of machine was measured, because that
is what makes the rule attributable and re-measurable. It must not say *whose*.
An address, a hostname, or a cross-reference between two of them describes
somebody's network, is of no use to anyone reading the rule, and cannot be taken
back once published. This engine ships a redaction policy for exactly this class
of detail in its reports; its own corpus should not be the leak.

`no_rule_names_a_real_address_or_host` in `src/fingerprinting/os/corpus.rs`
fails the build on anything address-shaped outside the documentation ranges.

## Before adding a rule: check what already exists

Rules that name an operating system live in **three** places, because they read
three different things, and one of the files holding them is over two thousand
lines long. Searching by hand is not realistic, so there is a query:

```
cargo bench --no-run --bench os_rules
target/release/deps/os_rules-<hash> windows
```

It reads every corpus at once and reports what already names a match, grouped by
which kind of rule it is and which file it is in. With no argument it lists every
family the corpora know — 2239 rules across roughly forty families — which is the
other question worth asking before deciding something is missing. No privileges
and no network; it reads the asset tree.

The three kinds, and why they are not one directory:

| kind | reads | lives in |
|---|---|---|
| stack rule | the shape of a TCP reply | `assets/fingerprinting/os/` |
| operating-system name rule | an OS string a service reported (SMB, SNMP) | the imported corpus |
| service rule | a service banner, naming an OS as a side effect | the imported corpus, per protocol |

The third is the largest — over half the shipped signatures carry `os.*`
metadata — and it cannot move here: those files **are** the service corpus, matched
by the service pipeline, and the operating system is something they mention rather
than what they are for. Moving them would mean either duplicating them or breaking
service detection, and would separate the imported files from the attribution that
belongs with them.

## Authoring

A predicate sets exactly one of `equals`, `any_of` or `range`. A field the rule
does not name is not tested, so a rule with too few predicates matches hosts it
should not — which is the failure that does *not* show up as a broken test, and
why every rule ships examples that the corpus test also runs against every other
family's rules.

Two fields are not what they look like, and both are documented on the schema:
`option_layout` is a joint fact about the peer *and* the probe, and
`window_units` exists because an MSS-derived window moves when the probe changes.

**Pick the right window predicate**, because a stack chooses its window in one of
two ways and the wrong one fails on a different network rather than on this one:

- `window_units` — for a stack that counts its window in segments. Linux does:
  the same host answers `20 x 1460` to a bare probe and `20 x 1448` to one that
  negotiates a timestamp, and the twenty is the part that belongs to the sender.
- `window` — for a stack that announces a number. Darwin does: 65535 whatever the
  path, so the derived figures shift with the path MSS (`45 x 1448 + 375` here,
  `48 x 1348 + 831` elsewhere) and describe the network rather than the host.

Predicate on what the stack chose, and leave the rest unstated. A measured rule
records everything observed in its `example`; it does not have to *test*
everything it recorded, and pinning a value that varies by release over-fits the
rule to the one machine that confirmed it.
