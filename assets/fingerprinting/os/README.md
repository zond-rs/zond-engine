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

Every rule here is written against the option set `tcp::build_probe` sends. A
rule taken from elsewhere has to be checked against that, not assumed onto it,
which is what `published` records and what confirming one promotes.

## Coverage

| family | provenance | notes |
|---|---|---|
| Linux | measured | one rule, five labelled hosts, three kernels known exactly; states no window predicate, and the reason is worth reading |
| macOS | measured | confirmed on a Mac; covers iOS and iPadOS, which share the kernel and are indistinguishable at this layer |
| Windows | published | NT-family defaults; a stock firewall drops, so this needs a host with something listening |
| FreeBSD | published | distinguished from Darwin by option order |
| Network device | published | the hop counter alone; deliberately states no option predicate |

## Naming a release rather than a family

Everything above is read off **one** reply, and one reply cannot separate two
builds of the same stack. The option layout, the initial hop counter and the
window multiplier are the parts a stack's authors settled years ago and have not
touched since — which is exactly why they identify a family so well and a release
not at all.

Three features *do* move between releases, and none of them is in a single
packet:

| predicate | what it reads | names |
|---|---|---|
| `identifier_class` | the IP identification field across replies | `zero`, `constant`, `counting`, `scattered` |
| `sequence_class` | how initial sequence numbers are generated | `zero`, `fixed-step`, `multiples`, `hashed` |
| `clock_class` | the TCP timestamp clock | `none`, `zero`, `ticking`, `randomised`, `slower` |

A rule naming any of them is matched only against a host that was **asked more
than once** — the active series probe, at `OsDetection::Active` or above. Against
the passive path it fails by the ordinary "the peer did not say" rule, which is
what stops a claim about a generator ever being satisfied by one number.

```toml
provenance = "measured"

[os]
family = "Linux"
version = "6.x"

[match]
reply = "syn_ack"
initial_hops = { equals = 64 }
option_layout = { equals = "M,S,T,N,W" }
window_scale = { equals = 7 }
sequence_class = { equals = "hashed" }
clock_class = { equals = "ticking" }
```

### A finer rule does not have to restate the broader one

The family rule above it will match the same host, every time — a release rule is
by construction narrower than the family rule describing the same stack. That is
handled: a rule that says nothing about a version **abstains** rather than
dissenting, so the version survives. Two rules naming *different* versions is
still a contradiction and still yields neither.

So write the release rule as the family rule plus what separates it, and do not
duplicate the family rule's job.

### Which series a predicate reads

Whichever the rule's own `reply` names. A stack's reset path and its handshake
path are different code that disagrees about the same field — measured, on one
host: identifier zero on the SYN+ACK path, a global counter on the reset path.
The two are collected and classified as separate series, and a rule sees the one
belonging to the segment it declares.

That matters most for `identifier_class`, and it is the reason the probe follows
two ports per host. Ask a `reply = "syn_ack"` rule about the identifier and the
answer is usually `zero`, because RFC 6864 §4.1 releases a sender from writing
anything meaningful into a datagram that cannot be fragmented. The policy lives
on the reset path — `reply = "reset"` — where it separated three of five measured
hosts three ways. Meanwhile `sequence_class` and `clock_class` are readable only
from a `syn_ack`: a reset opens no connection to number and carries no options to
timestamp.

### Measuring one before authoring it

`benches/os_sample.rs` is the instrument. It takes the samples, prints the class
each series was read as with the raw values beside it, and — in its last block —
says whether the extra samples actually split hosts that a single reply reported
as identical. A feature that never refines that partition cannot change a
verdict, whatever else it reveals.

```
cargo bench --no-run --bench os_sample
sudo -E <binary> <target> [ports] [samples] [spacing_ms] [rate]
```

The other half is simply the CLI, which runs the same phases through the same
entry point:

```
sudo zond scan 192.168.64.0/24 -p 22,80,443 --os-detection aggressive -v
```

`-v` puts the working under each finding — the `read:` line carrying the stack
shape and the `id=` / `isn=` / `ts=` classes. That readout **is** what a rule
predicates on, so what you see there is what you write into `[match]`.

Use `aggressive` when the machine's operating system is already known from
outside: it takes twice the samples and follows hosts even once they are named,
which is the case authoring a rule always is. `benches/os_detect.rs` shows the
whole `Host` record instead, for when a field is missing and the question is
whether nothing found it or nothing carried it through.

**Label the hosts from outside.** Two machines running one operating system can
differ here for reasons that are not the stack: uptime moves a clock's offset
though not its rate, and load moves an identifier counter's step. A split that
falls *inside* a family is a warning, not a rule.

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

**Think twice before stating a window predicate at all**, and read
`linux.toml` first. Measured 2026-08-21: one `sysctl -w net.ipv4.tcp_rmem=...`
on an otherwise untouched kernel moved a host's window *and* window scale far
enough that the Linux rule stopped matching, and the machine went from
`Linux [65%]` to unidentified. A window predicate is a claim about somebody's
receive buffers, and it takes the whole verdict down with it when they have
tuned them. Predicate on it where the shape genuinely identifies the family;
leave it to the examples where it identifies a configuration.

**If you do state one, pick the right form**, because a stack chooses its window
in one of two ways and the wrong one fails on a different network rather than on
this one:

- `window_units` — for a stack that counts its window in segments. Linux does:
  the same host answers `20 x 1460` to a bare probe and `20 x 1448` to one that
  negotiates a timestamp, and the twenty is the part that belongs to the sender.
  Note that the twenty is still `tcp_rmem` rather than the kernel.
- `window` — for a stack that announces a number. Darwin does: 65535 whatever the
  path, so the derived figures shift with the path MSS (`45 x 1448 + 375` here,
  `48 x 1348 + 831` elsewhere) and describe the network rather than the host.

Predicate on what the stack chose, and leave the rest unstated. A measured rule
records everything observed in its `example`; it does not have to *test*
everything it recorded, and pinning a value that varies by release over-fits the
rule to the one machine that confirmed it.
