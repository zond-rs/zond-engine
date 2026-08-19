# Operating-system rules

Rules matched against a `StackObservation` — a typed feature vector read off one
TCP reply — rather than against text. The schema is
`src/fingerprinting/os/signature.rs`, shared verbatim with `build.rs`.

## What is here, and what is deliberately not

Only what has been measured. Every value in every rule was read off a real host
and labelled from outside the engine; nothing is transcribed from published
defaults, because a rule authored from the literature and then tested against the
literature only proves both were copied from the same place.

That leaves the corpus honestly incomplete:

- **Linux** — two shapes across four labelled hosts, one with a known kernel.
- **Apple** — six labelled devices, none with an open port. A reset carries no
  TCP options at all, so there is nothing to write a rule against, and the one
  reset feature that looked promising was retracted after the same devices
  answered two scanners on one segment with opposite values.
- **Windows** — two labelled hosts, both of which emitted **nothing** on any of
  fourteen ports from two vantage points. A stock firewall drops rather than
  refuses. There is no packet to read and therefore no rule to write; naming one
  is phase 5's job, from a name, a banner or a hardware address.
- **macOS** — not yet measured with an open port.

Adding a family means measuring it, not describing it.

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
