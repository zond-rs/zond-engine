# Fuzzing

Coverage-guided fuzzing over the parsers that read bytes somebody else wrote.
Four targets, all of them entry points a hostile network or a hostile file
reaches directly.

Four, not all of them. The target-side readers behind `ImportFormat::read` have
none: the list grammar, the CSV record reader with its quoting and its carriage
returns, and the record-per-line reader. Neither does `settings::parse`, which
reads a TOML file synced from a team repository, nor
`format::time::parse_rfc3339`. The XML parser is covered through
`nmap_document`, which is the one both nmap readers share.

```
cargo +nightly fuzz list
cargo +nightly fuzz run ethernet_frame fuzz/corpus/ethernet_frame fuzz/seeds/ethernet_frame
```

**Both directories, in that order.** libFuzzer writes what it discovers into the
*first* one and reads the rest, so passing the seeds alone buries the five
curated files under a few hundred generated ones. `fuzz/corpus/` is gitignored
and is where the growing corpus belongs.

Needs a nightly toolchain and a sanitizer, which is why this is a crate of its
own with its own `[workspace]`: nothing here is built by a `cargo build` at the
repository root, and `Cargo.toml` excludes it from the published crate.

## The targets

| target | what it reads | why |
|---|---|---|
| `ethernet_frame` | `ethernet::parse` and every reader behind it | a listening phase reads whatever crosses the segment |
| `wire_buffer` | TCP, SCTP, ICMP, DNS and mDNS from a bare buffer | reached without a frame in front of them |
| `nmap_document` | nmap's XML, through the hand-rolled subset reader | `Cargo.toml` calls that reader defensible only because it refuses more than it accepts |
| `report_document` | this engine's own report, read back | a document it wrote is still a document somebody can edit |

`ethernet_frame` also asserts the shape of what `parse` hands out: a frame
lending a payload wider than the buffer it came from is a defect every reader
behind it would inherit, and it would not crash on its own.

## Pass the seeds

**A fuzzer starting from nothing barely gets past the first length check.**
Measured, on this repository: `ethernet_frame` from an empty corpus reaches 142
edges, and from `fuzz/seeds/ethernet_frame` it reaches 389. The same shape of
mistake `tests/wire_parsers.rs` was written against, in a different tool.

So `fuzz/seeds/` is tracked, and it is the argument to pass. Each file is a valid
message built by this crate's own `protocols::craft` builders or, for the
documents, written by a real run: an LLDP advertisement with its mandatory TLVs,
a CDP announcement behind its LLC/SNAP header, a neighbour advertisement, a DHCP
acknowledgement, a VLAN-tagged frame, a report this engine exported, and an nmap
document. `nmap_document` also carries `entity.xml`, which is refused and is
there to keep the fuzzer near the refusal rather than away from it.

The corpus a run *produces* is not tracked. It is a machine-local artifact of one
run, and one checked in goes stale the moment a parser's framing changes.

## What has been run

Four targets, 150k to 200k executions each, no crashes. That is a smoke run
rather than a campaign: a target left running overnight is the point of having
one, and the seeds are what make those hours count.
