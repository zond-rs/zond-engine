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

The published rules are not a compromise. A stack's initial hop counter, the
order it writes its TCP options in, and whether it offers timestamps by default
are ordinary engineering facts, stable across releases and documented for
decades; re-deriving them by measurement would be re-deriving p0f from scratch to
reach the same table.

What the distinction records is a specific, earned caution. **Option negotiation
is reciprocal**: a layout the literature gives is the layout a peer sends *to a
probe that asked for those options*. This engine's SYN offered only a maximum
segment size until it was changed to offer the full set, and against that probe
every host on a real segment answered `M` — so a rule transcribed as `M,S,T,N,W`
would have matched nothing, from every stack at once, while looking perfectly
correct. The measurement is what made the published values usable, not what
replaced them.

So: use the literature, mark it as such, score it below what has been seen here,
and promote it when somebody confirms it.

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
