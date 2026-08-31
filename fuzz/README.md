# Fuzzing

Coverage-guided fuzzing over the code that reads bytes somebody else wrote, and
over the code that writes bytes somebody else opens. Eight targets, each an
entry point a hostile network or a hostile file reaches directly.

```
cargo +nightly fuzz list
cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target>
```

**Both directories, in that order.** libFuzzer writes what it discovers into the
*first* one and reads the rest, so passing the seeds alone buries the curated
files under a few hundred generated ones. `fuzz/corpus/` is gitignored and is
where the growing corpus belongs.

Needs a nightly toolchain and a sanitizer, which is why this is a crate of its
own with its own `[workspace]`: nothing here is built by a `cargo build` at the
repository root, and `Cargo.toml` excludes it from the published crate.

## Layout

```
fuzz_targets/<surface>/<what>.rs      →  target named <surface>_<what>
seeds/<surface>_<what>/               →  what that target starts from
```

Four surfaces, because a target is defined by the boundary it attacks rather
than by the module it happens to call: `wire` is bytes off a segment, `import` is
a file an operator was handed, `export` is a document this engine produces, and
`format` is the contract the two directions share. `export_report` reaches the
writers by way of a reader and is still an export target, because a writer is
what it asserts about.

A new target goes in the directory for its surface, takes the matching name, and
brings a seed. Nothing else is arranged around any of them.

## The targets

| target | what it reads | why |
|---|---|---|
| `wire_ethernet_frame` | `ethernet::parse` and every reader behind it | a listening phase reads whatever crosses the segment |
| `wire_buffer` | TCP, SCTP, ICMP, DNS and mDNS from a bare buffer | reached without a frame in front of them |
| `import_targets` | the list, CSV, JSON, JSON Lines and nmap readers behind `ImportFormat`, and the sniff that picks between them | these decide what gets probed; a reader that mangles one produces a scan of something else |
| `import_report` | this engine's own report, both JSON shapes | a document it wrote is still a document somebody can edit, and `diff` takes one from wherever it was kept |
| `import_nmap` | nmap's XML, through the hand-rolled subset reader | `Cargo.toml` calls that reader defensible only because it refuses more than it accepts |
| `import_settings` | `engine.toml`, and what applying one does to a `ZondConfig` | a file synced out of a team repository, which nobody reads before it takes effect |
| `export_report` | every writer, over a report built by a reader | a device names itself, so every string a writer escapes is one the network chose |
| `format_timestamp` | `parse_rfc3339` and `rfc3339` | the one parser both directions depend on, and the only one whose output is also its input |

`wire_ethernet_frame` also asserts the shape of what `parse` hands out: a frame
lending a payload wider than the buffer it came from is a defect every reader
behind it would inherit, and it would not crash on its own.

`export_report` asserts one property per format — that the JSON writers emit
JSON, that no CSV field opens with a character a spreadsheet evaluates, that no
script tag or direction override reaches the page, that no character XML cannot
carry reaches the document — and that a report survives the round trip through
the canonical format unchanged. Its own documentation says what it deliberately
does not assert and why.

### `import_targets` takes a selector byte

Its first byte chooses which reader gets the rest, so that the CSV and list
readers are reachable with content that would not sniff as either. The seeds
carry the byte their format needs; `(byte >> 1) % 5` indexes `ImportFormat::all()`
and `byte & 1` picks the refusal policy. The sniffing arm runs on every input
regardless, which is where the two answers get compared.

## Pass the seeds

**A fuzzer starting from nothing barely gets past the first length check.**
Measured on this repository, edges reached in thirty seconds from an empty
corpus against the same from `fuzz/seeds/`:

| target | from nothing | from seeds |
|---|---|---|
| `export_report` | 861 | 9670 |
| `import_report` | 2081 | 6703 |
| `import_nmap` | 439 | 2054 |
| `wire_ethernet_frame` | 143 | 441 |
| `format_timestamp` | 188 | 269 |
| `import_targets` | 3312 | 3949 |
| `import_settings` | 3004 | 3866 |
| `wire_buffer` | 520 | 497 |

The table is in two halves and the split is worth reading. A structured document
has a header a fuzzer will not stumble into, so `export_report` reaches eleven
times as much code from one seed as from none — it cannot reach a *writer* at all
until something parses as a report. A target list and a TOML file are text a
fuzzer finds on its own, and `wire_buffer` does slightly better from nothing,
because its readers take a bare buffer and a seed only narrows where it looks.
Seeds are not a ritual; they are what gets past a header.

So `fuzz/seeds/` is tracked. Each file is a valid message built by this crate's
own `protocols::craft` builders or, for the documents, written by its own
exporters: an LLDP advertisement with its mandatory TLVs, a CDP announcement
behind its LLC/SNAP header, a neighbour advertisement, a DHCP acknowledgement, a
VLAN-tagged frame, a report in each format this engine writes, and an nmap
document. Two seeds are there to be *refused* rather than read —
`import_nmap/entity.xml` and `format_timestamp/impossible-date` — which keeps the
fuzzer near the refusal rather than away from it.

The corpus a run *produces* is not tracked. It is a machine-local artifact of one
run, and one checked in goes stale the moment a parser's framing changes.

## What has been found

`import_nmap`, thirty seconds into the first run it was ever given seeds for:
`start="16847805878974283974"` in an `<nmaprun>` element panicked the process
with `overflow when adding duration to SystemTime`. Nmap writes every time as
seconds since the epoch, a `u64` of those reaches five hundred billion years, and
`SystemTime + Duration` panics rather than saturating — so a document with twenty
digits in one attribute took down whatever had embedded the engine. `epoch` now
uses `checked_add`, and
`a_time_past_what_a_clock_can_hold_is_dropped_rather_than_fatal` pins it.

Since: two minutes per target from the seeds, no crashes.

| target | executions | edges |
|---|---|---|
| `format_timestamp` | 2 657 544 | 259 |
| `wire_ethernet_frame` | 2 646 136 | 463 |
| `import_settings` | 1 895 414 | 4 307 |
| `import_nmap` | 1 584 948 | 2 337 |
| `wire_buffer` | 1 532 371 | 587 |
| `import_report` | 881 756 | 7 648 |
| `import_targets` | 848 650 | 4 869 |
| `export_report` | 774 891 | 10 259 |

That is a smoke run rather than a campaign, and the two columns say why the
distinction matters: `export_report` does a third of `format_timestamp`'s
executions because each one drives ten writers, and it is still nowhere near
exhausting forty times the code. A target left running overnight is the point of
having one, and the seeds are what make those hours count.

## In CI

`.github/workflows/fuzz.yml` builds every target on a change under `fuzz/` or
`src/`, which is what catches the common rot: a target that stops compiling
because the API it drives moved. It does not fuzz on a pull request — a
sixty-second run finds nothing a longer one would not, and it would make every
pull request wait on a nightly toolchain.

The weekly run is the one that does the work: each target from its seeds, long
enough to be worth the machine, with a crashing input uploaded as an artifact so
it can be reproduced from the repository rather than from a log.
