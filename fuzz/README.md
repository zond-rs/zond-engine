# Fuzzing

Coverage-guided fuzzing over the code that reads bytes somebody else wrote, the
code that writes bytes somebody else opens, and the code that decides what a
scan already found means. Fourteen targets, each an entry point a hostile
network, a hostile file or an edited state directory reaches directly.

```
cargo +nightly fuzz list
cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target> \
  -- -dict=fuzz/dictionaries/<target>.dict -rss_limit_mb=4096 -timeout=25
```

**Both directories, in that order.** libFuzzer writes what it discovers into the
*first* one and reads the rest, so passing the seeds alone buries the curated
files under a few hundred generated ones. `fuzz/corpus/` is gitignored and is
where the growing corpus belongs — and where a campaign's real value
accumulates, so it is the thing to keep between sessions.

`-rss_limit_mb` and `-timeout` are not optional extras. Without them an
allocation that runs away takes the run down with it and an input that never
returns hangs it, and neither is reported as the finding it is.

Needs a nightly toolchain and a sanitizer, which is why this is a crate of its
own with its own `[workspace]`: nothing here is built by a `cargo build` at the
repository root, and `Cargo.toml` excludes it from the published crate.

## Watching a run

libFuzzer has no status screen. Its only output controls are `verbosity` and a
set of `print_*` flags that fire at exit, so the scroll is the interface —
thousands of lines a minute, and the numbers that matter buried in them.

`watch.py` renders the same stream in place:

```
cargo +nightly fuzz run import_nmap fuzz/corpus/import_nmap fuzz/seeds/import_nmap \
  -- -dict=fuzz/dictionaries/import_nmap.dict -rss_limit_mb=4096 -timeout=25 \
  2>&1 | python3 fuzz/watch.py import_nmap
```

It exists for one line of its output. **libFuzzer never says how long it has
been since it last found anything**, and that is what a campaign is steered by:
a target an hour into silence is a target to stop and swap out. Everything else
on the screen is already in the scroll somewhere.

A crash is never rendered. On the first sign of one it drops out of the way and
passes the raw stream through, because a status screen that swallowed the report
would be worse than the scroll it replaced.

AFL++ has the status screen this imitates, and `cargo-afl` brings it to Rust —
but it is a different fuzzer with its own instrumentation, harness macro and
corpus format, and macOS on ARM is its weakest platform. Worth it for what AFL++
finds; not worth it for the screen.

## Layout

```
fuzz_targets/<surface>/<what>.rs      →  target named <surface>_<what>
seeds/<surface>_<what>/               →  what that target starts from
dictionaries/<surface>_<what>.dict    →  the tokens its format is made of
src/lib.rs                            →  the oracles more than one target asks
watch.py                              →  a libFuzzer run as a status screen
```

Eight surfaces, because a target is defined by the boundary it attacks rather
than by the module it happens to call: `wire` is bytes off a segment, `import` is
a file an operator was handed, `export` is a document this engine produces,
`format` is the contract the two directions share, `record` is where a type with
invariants becomes something a file can hold, `journal` is what a scan writes
down as it runs, and `diff` and `merge` are what two scans and several scans
respectively add up to. `export_report` reaches the writers by way of a reader
and is still an export target, because a writer is what it asserts about; the
same arrangement gets `diff` and `merge` their reports.

**The last four surfaces are not parsers, and that is why they are here.** A
reader is fuzzed because it takes bytes from somebody hostile. `journal::cursor`
takes no bytes from anyone: it takes a number a scan produced and decides whether
a resumed scan may skip a target, and a wrong answer is a second sitting that
skips work, finds nothing, and reports success. Nothing downstream detects that,
and there is no document to hold up against it — so the assertions are the whole
of the instrument, and the input is a fuzzer's only way of reaching enough of
them. The same is true of a merge that quietly drops a field.

A new target goes in the directory for its surface, takes the matching name, and
brings a seed. Nothing else is arranged around any of them.

## An oracle is worth more than an hour

**A target that only calls and discards finds a panic and nothing else.** It will
not notice a reader that drops a host, or one that reads a port as the wrong
number, however long it runs — those return `Ok` and the harness is satisfied. So
each target says what it holds true, in its own documentation, and the
assertions are where the value is rather than in the machine time.

Two rules for writing one:

- **It has to hold for every input the target can reach.** A property that is
  merely usually true stops the run on something that was never wrong, and the
  night is spent on the harness rather than the engine. Prove it from the code
  before asserting it — `import_nmap` deliberately does not assert a round trip,
  and says why.
- **Prefer an oracle that covers what has not been written yet.** `ScanDiff`
  comparing a report against itself catches a field added in six months; a list
  of field names checks the ones that exist today.

[`src/lib.rs`](src/lib.rs) holds the ones more than one target asks.

## Dictionaries, and what they are actually for

`-dict=` gives libFuzzer the tokens a format is built from. Every dictionary here
is generated from the thing it describes — the report's from the published JSON
schema, the nmap one from the element names the reader looks for, the settings
one from `KNOWN_KEYS` — so the tokens are the real ones rather than a
transcription that can drift. They carry what a parser **refuses** as well as
what it accepts: `<!ENTITY`, a `DOCTYPE` with an internal subset, `2026-02-31`, a
bare `+2026`. A refusal nothing ever spells is a refusal nothing ever tests.

**A dictionary substitutes for seeds. It does not add to them.** That is the
opposite of the folklore, and it is measured, sixty seconds each way:

| target | cold | cold + dict | seeded | seeded + dict |
|---|---|---|---|---|
| `import_nmap` | 495 | 1 222 | 3 674 | 3 848 |
| `export_report` | 876 | 1 663 | 9 851 | 9 911 |
| `import_report` | 2 159 | 2 844 | 10 133 | 10 105 |
| `import_settings` | 2 980 | 3 170 | 4 045 | 4 109 |
| `record_host`* | 987 | 2 079 | 4 532 | 4 490 |
| `journal_manifest`* | 1 026 | 1 634 | 2 443 | 2 512 |

\* forty-five seconds each way rather than sixty, which is why they are not
comparable with the rows above. They are comparable across their own row, which
is what the table is for.

From nothing a dictionary is worth 6% to 150%, and it is worth most exactly where
a seed is: a format with a header a fuzzer will not stumble into. Beside the
seeds it is worth 0% to 5%, and for `import_report` it measured slightly
negative — noise, which is the point. The seeds already contain every token, and
splicing between corpus entries reproduces them without being told. The two rows
added later reproduce the same shape: 111% and 59% from nothing, and -1% and 3%
beside the seeds.

Six of the fourteen have no dictionary. `journal_cursor` takes numbers rather
than a format, and `diff_reports` and `merge_reports` take whole documents whose
tokens are already `import_report`'s — a dictionary of them would be the same
file under another name, and the seeds carry every one.

So: pass the dictionary, because it costs nothing and the tail of a long run is
not what sixty seconds measures. But do not expect it to be the lever. **It is
insurance for the cold start** — a corpus thrown away, a format whose framing
moved, or OSS-Fuzz beginning with nothing — and that is when it earns its place.

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

Two, both in `import_nmap`, both within minutes of it being given seeds and an
oracle.

A **panic**, thirty seconds into the first seeded run:
`start="16847805878974283974"` in an `<nmaprun>` element panicked the process
with `overflow when adding duration to SystemTime`. Nmap writes every time as
seconds since the epoch, a `u64` of those reaches five hundred billion years, and
`SystemTime + Duration` panics rather than saturating — so a document with twenty
digits in one attribute took down whatever had embedded the engine. `epoch` now
uses `checked_add`, and
`a_time_past_what_a_clock_can_hold_is_dropped_rather_than_fatal` pins it.

A **round trip that re-keyed a host**, three minutes after the target was given
an oracle. Nmap has no attribute saying which of a host's addresses it is filed
under, so the reader takes the first `<address>` in the document — and the writer
was emitting them in the set's own ascending order. A multi-homed host exported
to this format and read back came out keyed by whichever address sorted lowest,
so a scan compared against its own source reported one host gone and one
arrived. That is the false alarm `diff` is arranged to prevent, reintroduced at
the last step. The writer now leads with the address the host is keyed by, which
invents no attribute and costs the document nothing.

That one is worth noting for what found it: no panic, no sanitizer report,
nothing that would have surfaced without an assertion saying what the round trip
owed. Machine time alone would have run past it forever.

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
