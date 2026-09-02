# Defect register

The `ZA-` identifiers this repository's comments cite, and what each one was.

## Why this file exists

Eight comments in `src/` and `tests/`, plus one in `deny.toml`, cite a defect by
identifier. Four are load-bearing — they are given as *the reason a test exists*
or as the reason a dependency advisory is ignored. Until this file, none of them
resolved to anything in the repository: the register they name lived in working
notes that were never tracked.

`tests/citations.rs` was written against exactly this failure one step to the
side. Its module documentation states the principle — *an unkeepable citation is
worse than none, because a reader spends time looking* — and it enforces it for
backticked paths. A bare identifier is not a path, so the gate could not see
these. It can now: `every_cited_defect_resolves` reads every `ZA-n-nnn` in the
trees `citations.rs` already walks and fails on one that has no heading here.

## What this file is, and is not

**It is the index the gate checks.** One heading per identifier, so a citation
resolves and a reader stops looking.

**It is not the working notes.** Each entry below was reconstructed from the
sentence the citing comment already carries, because that sentence is what
survives in the repository. Where the original notes said more — the measurement,
the rejected fixes, the argument — that is not here and this file does not
pretend otherwise. An entry that is one line is one line because that is what
was recoverable, not because that was all there was.

Numbering is not contiguous. The identifiers below are the ones something cites;
the gaps are defects that were filed and never referenced from code, and nothing
here can reconstruct those.

---

## ZA-0-009 — bincode 1.x is unmaintained, with no upgrade inside the 1.x line

Cited by `deny.toml`, as the reason `RUSTSEC-2025-0141` is ignored.

`bincode` is a direct dependency in both the runtime and the build dependency
sets: `build.rs` serialises the signature and detection corpora into blobs the
runtime deserialises with `include_bytes!`. Every byte bincode decodes on that
path was produced by this crate's own build from files in `assets/`, so no input
reaching it is chosen by anyone outside the build. That bounds the exposure to a
bug reachable from data this project generates.

Moving to bincode 2.x means both the encode and the decode side and a format
change to the embedded blobs. Open.

## ZA-4-005 — a re-entrant capability implementation would alias `&mut`

Cited by `src/detect/compute/rhai.rs`, on the test that holds the invariant.

The Rhai runtime erases the borrow to its `Capabilities` into a raw pointer for
the span of one run, so a thread-local can hold it. If a `Capabilities`
implementation re-entered the runtime, two runs would hold live `&mut` to one
value. `Capabilities` is implementable outside this crate, so the rule is one
somebody else's code has to keep.

`ActiveRun::new` refuses a second run on a thread that already has one, which is
what makes the rule hold in a release build rather than only under an assertion.
Fixed, and held by
`detect::compute::rhai::tests::a_second_run_on_one_thread_is_refused_before_it_can_alias`.

## ZA-4-008 — a finding that appeared was not reported as a change

Cited by `src/diff/host.rs` and `src/diff/port.rs`, on the two tests that hold
the property.

A comparison between two scans reported hosts, ports and services that moved, and
said nothing when a finding arrived on one that had not — so a host that gained a
critical vulnerability between two runs compared as unchanged. Fixed on both
halves: a finding appearing or resolving is a change, at the host level and at
the port level.

## ZA-4-009 — a link-local address's zone did not survive the report

Cited by `src/export/conformance.rs`, in the list of fields the journal and the
report spell the same way.

A link-local range is only meaningful with the interface it is valid on, and
`zone` is where that is carried. It is named in the conformance list because the
journal and the report have to agree on the spelling; a field either of them
dropped would make a resumed scan disagree with the report of the scan it
resumed.

## ZA-4-012 — a detection gated on a service nothing produces never runs

Cited by `build.rs`, on the check that warns about it.

A detection's gate names the services it applies to. A gate naming a service no
analyzer and no corpus entry can produce fits no port, ever — so the detection
ships in the binary, appears in the corpus listing, and never fires. Nothing said
so, because a detection that never matches looks exactly like a detection whose
condition was never met.

`warn_unknown_gate_services` in `build.rs` reports it at build. A warning rather
than a refusal: the corpus is not the only place a service name is minted — three
analyzers state one in Rust, and a tunnelled service is labelled with its scheme
— so the accounting is a list kept in `build.rs` rather than derived, and a
fourth name added elsewhere would make a refusal reject a valid detection.

## ZA-4-013 — an unprivileged scan dropped what a banner said about the machine

Cited by `tests/service_fingerprint.rs`, on the test that holds it.

`SSH-2.0-OpenSSH_9.6p1 Debian-3` names an operating system as plainly as it names
a product, and both come out of the one handshake the scanner makes. The connect
prober drew that evidence and dropped it, so a scan without root disagreed with a
scan with root about what it had just been told. Fixed: the unprivileged path
files the machine-level evidence the privileged path does.

## ZA-4-015 — the HTTP detection gate named a service, not a protocol

Cited by `tests/detections.rs`, on the test that holds it.

The generic HTTP detection's gate named `http`, so it reached a web server the
corpus could not put a name to and skipped every web *application* it could —
Grafana, Kibana, Prometheus and the rest, which the fingerprint corpus gives
their own service names. Fixed by gating on `speaks = "http"`, which asks the
corpus which of its services are carried over HTTP. The `http` case is kept as
the control: both must fire, or the gate has only moved which half it misses.

## ZA-4-016 — a tunnelled label was read as one fact rather than two

Cited by `src/detect/gate.rs`, on the test that holds it.

A service identified through TLS carries a composed label — `ssl/http`,
`ssl/grafana` — and a gate matching the label whole saw neither half. A web
server inside TLS still speaks HTTP, and a detection gated on HTTP has to reach
it. Fixed: the gate reads a tunnelled label as the tunnel and the service it
carries.

## ZA-6-006 — the privileged tests were reachable only through a non-gating step

Cited by `tests/README.md`, in the section on the privileged tier.

The `#[ignore]`d tests — two needing capture access, one needing a document nmap
wrote — ran under a `continue-on-error` step, without the environment any of them
asks for. It came back part green: on an unprivileged macOS runner one of the two
capture tests passes anyway and the other two fail. A step that is always partly
red and never blocks is one everybody learns to scroll past, which left the tier
exactly where it had been before anybody wrote a job for it.

Fixed by the `privileged` job in `.github/workflows/test.yml`, which installs
nmap, has it write a document against the runner's own loopback, builds
unprivileged and runs the ignored tests under `sudo`. It gates.
