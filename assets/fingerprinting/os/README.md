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
| Windows | published | NT-family defaults; a stock firewall drops, so this needs a host with something listening |
| macOS | published | Darwin defaults; covers iOS and iPadOS, which are indistinguishable at this layer |
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

## Authoring

A predicate sets exactly one of `equals`, `any_of` or `range`. A field the rule
does not name is not tested, so a rule with too few predicates matches hosts it
should not — which is the failure that does *not* show up as a broken test, and
why every rule ships examples that the corpus test also runs against every other
family's rules.

Two fields are not what they look like, and both are documented on the schema:
`option_layout` is a joint fact about the peer *and* the probe, and
`window_units` exists because the raw window moves when the probe changes.
