# Service Fingerprinting Redesign

**Status:** Draft / RFC
**Branch:** `feat/fingerprinting`
**Scope:** Service & version fingerprinting subsystem (`src/plugins/fingerprint.rs` +
`assets/fingerprinting/`).
**Audience:** zond-engine maintainers.

> **Scope & naming.** This subsystem answers *"what is running on this open port?"* — the
> service, product, and version behind it. That is distinct from `discover`, which answers
> *"which hosts and ports are alive?"*. We keep the community-standard name **fingerprinting**
> (as in service/OS fingerprinting) precisely because it is unambiguous against discovery. The
> module should be consolidated under `src/fingerprinting/` and exposed as
> `zond_engine::fingerprinting`. "Evidence pipeline" below refers to the *internal
> architecture* of that subsystem, not a new user-facing name.

---

## 1. Context

`zond s <host>` classifies TCP ports (open/closed/filtered) and attaches a service label.
During that work we found the fingerprinting layer is the single most fragile and least
scalable part of the engine. Three concrete defects, all in `src/plugins/fingerprint.rs`,
motivated this redesign:

1. **Eager, all-at-once regex compilation on the async reactor.** `get_engine()` is a
   `OnceLock` that, on first use, deserializes the full signature blob and calls
   `Regex::new()` on **every** pattern (4,732 of them across 123 services). Measured cost:
   **~1.0 s in release, ~7.4 s in a debug build.** Because it runs synchronously inside
   `record_port()` on a Tokio worker, it froze the SYN scan loop for ~9 s, blew the 202 ms
   scan deadline, and caused every reply that arrived during the freeze to be misreported as
   `filtered`. Scan results were non-deterministic run-to-run as a result.

2. **Per-connection recompilation.** `fingerprint_tcp()` ignores the precompiled set and calls
   `Regex::new(&m.pattern)` *inside the match loop* (`fingerprint.rs:225`) — recompiling
   regexes for every response on every connection.

3. **Silent pattern drops.** Both paths use `Regex::new(...).ok()`. Any pattern the `regex`
   crate cannot compile (e.g. backreferences/lookaround) is **silently discarded**. For a
   commercial product this is the worst kind of bug: undetectable coverage gaps shipped to
   customers.

These are symptoms of an architecture that treats fingerprinting as "a global regex table"
rather than as a pipeline that gathers and resolves evidence. This document proposes a
redesign.

---

## 2. Goals & non-goals

### Goals

- **Reliability first.** Deterministic results. Linear-time matching (no ReDoS on hostile
  banners). No silent coverage loss. Safe handling of malformed/adversarial responses.
- **High performance at scale.** Near-zero startup cost. Fast matching. Bounded memory.
  Suitable for large sweeps (10⁴–10⁶ hosts) without per-host CPU cliffs.
- **Easy to expand.** Adding a service signature is a data change. Adding a *new kind* of
  detector (TLS, HTTP, JARM, …) is a small, isolated code change behind one trait.
- **Clean async hygiene.** CPU-bound work never runs on the Tokio reactor.
- **Commercially shippable.** Clear signature-data ownership/licensing. Updatable signature
  database without recompiling the binary.

### Non-goals (for this pass)

- OS fingerprinting (separate subsystem; the evidence model below should not preclude it).
- Rewriting the port-scan/transport layer.
- Building a full nmap-service-probes importer on day one (a bootstrap importer is enough).

---

## 3. Design principles

1. **Fingerprinting is an evidence pipeline, not a single regex match.** Regex-on-banner is one
   evidence source among many.
2. **Separate authoring, compilation, and runtime.** Humans author signatures (TOML). A build
   step validates and compiles them into a versioned artifact. Runtime loads that artifact
   with zero compilation.
3. **Linear-time matching by default.** Prefer the `regex`/`regex-automata` engines for their
   guaranteed linear-time execution. Attacker-controlled input must never be able to make the
   matcher hang.
4. **Fail loud at build, degrade gracefully at runtime.** Unsupported patterns fail the build,
   not the scan. A missing/old database is a clear error, not a silent no-op.
5. **I/O on Tokio, CPU on rayon/blocking. Never mix.**

---

## 4. Architecture

```
                    ┌────────────────────────────────────────────────┐
                    │             Fingerprinting engine               │
                    │                                                  │
  open port  ─────▶ │  ProbePlanner ──▶ transport (async I/O) ──▶ raw │
  (+ hints:         │      ▲              per-probe timeout,       resp│
   port, tls?)      │      │              size caps                 │  │
                    │      │                                        ▼  │
                    │      │        ┌───────── Analyzer set ───────────┤
                    │      │        │ BannerRegex  TlsCert  HttpHeaders │
                    │      │        │ Jarm/Ja3s   Ssh   Snmp   Favicon  │
                    │      │        └───────────────┬──────────────────┤
                    │      │                        ▼                   │
                    │      │              Vec<Evidence>                 │
                    │      │                        ▼                   │
                    │  (re-probe e.g.        Resolver (confidence       │
                    │   through TLS)          merge) ──▶ ServiceVerdict │
                    └────────────────────────────────────────────────┘
```

### 4.1 Core data model

```rust
/// One independent observation about what a port is running.
pub struct Evidence {
    pub service: Option<String>,       // "http", "ssh", ...
    pub product: Option<String>,       // "nginx", "OpenSSH"
    pub version: Option<String>,       // "1.25.3"
    pub vendor:  Option<String>,
    pub cpe:     Option<Cpe>,          // structured CPE for downstream (CVE, inventory)
    pub tunnel:  Option<Tunnel>,       // e.g. Tls -> caller should re-probe inside it
    pub confidence: Confidence,        // see §4.3
    pub source: SourceId,              // which analyzer produced this
    pub extra: Metadata,               // typed side-channel (headers, cert SANs, JA3S hash…)
}

pub enum Confidence { Weak, Probable, Strong, Certain }  // ordered

/// The merged, final answer for a port.
pub struct ServiceVerdict {
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub cpe: Option<Cpe>,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,       // full provenance retained for audit/debug
}
```

Retaining all `Evidence` (not just the winner) is deliberate: provenance is a feature for a
commercial scanner (explainability, tuning, customer trust).

### 4.2 The `Analyzer` trait — the extension point

```rust
#[async_trait]
pub trait Analyzer: Send + Sync {
    fn id(&self) -> SourceId;

    /// Cheap gate: should this analyzer run for this port at all?
    /// (e.g. TlsCert only when the tunnel is TLS; HttpHeaders only on web-ish ports)
    fn interested(&self, ctx: &PortContext) -> bool;

    /// Produce evidence from already-collected response data. Pure/CPU-bound analyzers
    /// (regex, cert parsing) run on the blocking pool; I/O-driven ones may await.
    async fn analyze(&self, ctx: &PortContext, resp: &ResponseSet) -> Vec<Evidence>;
}
```

Adding TLS/HTTP/JARM/SNMP/favicon detection = implement `Analyzer`, register it. The regex
matcher becomes `BannerRegexAnalyzer`, a peer — not the center of the universe.

### 4.3 Resolver

Merges `Vec<Evidence>` into one `ServiceVerdict`:

- Highest-confidence evidence wins the `service` field; ties broken by analyzer priority.
- Fields merge independently (a `TlsCert` analyzer may supply `product`/`vendor` while
  `BannerRegex` supplies `version`).
- Conflicts at equal confidence are recorded (and optionally surfaced) rather than hidden.

Start with a simple ordered-confidence + priority scheme. The trait boundary lets us evolve to
a weighted/scored model later without touching analyzers.

---

## 5. The matching engine (BannerRegex analyzer internals)

This is where the current pain lives. Recommended design:

### 5.1 Compile at build time, not run time

Use **`regex-automata`** to build dense DFAs and **serialize them into the compiled artifact**
(`regex-automata` supports zero-copy deserialization of serialized DFAs). Runtime "compilation"
becomes *mmap + validate header*: microseconds, deterministic, and **impossible to stall the
reactor**. This is strictly better than both the current eager compile and the lazy-per-port
stopgap.

Measured build/compile costs for the current 4,732-pattern set, for reference:

| Strategy                         | release | debug  |
|----------------------------------|---------|--------|
| sequential `Regex::new` (today)  | 959 ms  | 6.6 s  |
| `rayon` parallel `Regex::new`    | 150 ms  | 1.08 s |
| `RegexSet::new(all)`             | 78 ms   | 428 ms |
| build-time serialized DFA        | ~0 (runtime) | ~0 |
| lazy per-port (1–4 patterns)     | ~0      | ~0     |

### 5.2 Two-stage matching for throughput

1. **Prefilter:** one multi-pattern pass to select candidate signatures. Options, in order of
   preference: `aho-corasick` over literal anchors extracted from each pattern; or a
   `RegexSet`. This turns "run 4,732 regexes" into "run the 1–4 that could possibly match".
2. **Capture stage:** run only the candidate patterns to extract version/product capture
   groups.

Keep this behind a `Matcher` trait so a **vectorscan/hyperscan** backend can be dropped in
later for DPI-grade throughput without changing callers. Do **not** start with hyperscan — it
is a heavier (C) dependency; earn it with profiling.

### 5.3 Linear-time guarantee & the backreference problem

The `regex` crate cannot express backreferences/lookaround. Some real-world signatures use
them. Handle this **explicitly at build time**, never with a silent `.ok()`:

- Normalize patterns where a lookaround/backref can be rewritten to an equivalent linear form.
- Route the irreducible residue to a **sandboxed `fancy-regex`** path (supports backrefs) that
  is always run **with a hard wall-clock timeout** and on the blocking pool, because it is *not*
  linear-time and is a ReDoS surface.
- Anything that compiles in neither engine **fails the build** with a pointer to the offending
  `assets/fingerprinting/…/service.toml`. Coverage gaps become visible in CI, not in production.

---

## 6. Execution model

The 9 s bug was fundamentally an async-hygiene failure. Establish and enforce:

- **Network I/O** (probe send, response read) runs on Tokio, with per-probe read timeouts and a
  **hard cap on bytes read** (never read an unbounded banner into a `String`).
- **CPU-bound analysis** (regex matching, cert parsing, hashing) runs on a dedicated **rayon**
  pool or via `spawn_blocking`, never inline on a reactor worker.
- **Bounded concurrency** across hosts/ports with backpressure.
- No `.unwrap()`/`.expect()` on network-derived data.

---

## 7. Signature database & the `assets/` question

**Question posed:** keep `assets/` in the zond-engine repo with its current structure, or move
it out / adopt a superior format?

### 7.1 What exists today

- `assets/fingerprinting/<category>/<service>.toml` — 123 hand-authored TOML files (~2 MB),
  grouped by category (`database/`, `web/`, `remote/`, `network/`, …). Schema: one
  `[service]` + N `[[probe]]` + N `[[match]]` per file.
- `build.rs` walks the tree, `toml::from_str` each file, `bincode::serialize` the `Vec` into
  `$OUT_DIR/fingerprints.bin`.
- Runtime `include_bytes!`es that blob into the binary.

### 7.2 Recommendation — keep the source, change the contract

**Keep the TOML source directory. It is a genuine strength, not a liability.** One file per
service, grouped by category, is:

- **reviewable** — a signature change is a small, self-contained diff;
- **mergeable** — contributors touch one file, few conflicts;
- **toolable** — easy to lint, validate, and machine-generate/append.

Do **not** move to a single monolithic file (nmap-service-probes' one-giant-file model is a
maintenance regression), and do **not** hand-author the binary.

What *should* change is everything downstream of the TOML:

1. **Evolve the schema (versioned).** Add a top-level `schema_version`. Add fields the pipeline
   needs: `cpe`, `confidence`, `rarity`/`intensity` (probe selection), `softmatch` (narrow
   service without full ID), `tunnel`/`ssl` (re-probe through TLS), `fallback`, and per-probe
   `ports`/`exclude`. Consider renaming the awkward `[[match]]` (`r#match` in Rust) to
   `[[signature]]`.

2. **Validate and compile at build, and fail loud.** The build step must: verify every regex
   compiles in the chosen engine (or is explicitly marked `engine = "fancy"`); verify every
   `version_group` exists in its pattern; reject duplicate service names; check `cpe` syntax.
   Today `build.rs` only parses TOML — bad patterns slip through to a runtime `.ok()` drop.

3. **Stop `include_bytes!`-ing the database; load it from disk (mmap).** Baking the blob into
   the binary means every signature update requires a recompile and a new library release, and
   forecloses proprietary/per-customer signature packs and out-of-band updates. Instead:
   - Ship a compiled artifact (`zond-fingerprints.bin` or a small directory) alongside the
     binary.
   - Load via `mmap` at startup; validate a header `{ schema_version, engine_version, build
     time, content hash/signature }`.
   - Keep an **embedded fallback** copy for zero-config single-binary use, but make disk
     override the primary path.

4. **Artifact format.** `bincode` is fine for the *metadata* (compact, fast). For the redesign
   the artifact should be a small container with:
   - a versioned header (+ integrity hash, optionally signed),
   - the service metadata table (bincode or `rkyv` — `rkyv` enables true zero-copy mmap access
     if we want to skip even deserialization),
   - the **serialized `regex-automata` DFAs / prefilter tables** (§5.1), so runtime does zero
     regex compilation.
   Prefer `rkyv` for the parts we want to mmap zero-copy; keep `bincode` if simplicity wins and
   deserialize cost stays in the low-ms range. Decide with a benchmark, not taste.

### 7.3 Where should the database live? (repo/package placement)

Signatures change on a *different cadence* than engine code and, for a commercial product, may
be **licensed or proprietary** separately. Recommendation:

- **Short term:** keep the TOML source in-repo under `assets/fingerprinting/`, but decouple it
  via the disk-loading contract above so the engine is not *forced* to embed it.
- **Medium term:** split the signature set into its own versioned package/repo (e.g.
  `zond-fingerprints`) that produces the compiled artifact as a release. The engine depends on
  a *format/ABI*, not on the data. This enables independent signature releases, customer-specific
  packs, and clean licensing boundaries.

### 7.4 Licensing — a commercial blocker to decide early

`assets/fingerprinting/imported/` and any nmap-derived patterns need scrutiny.
**nmap-service-probes is not permissively licensed** (Nmap Public Source License); Nmap
Software LLC sells OEM licenses specifically for embedding its data in commercial products.
Shipping nmap-derived signatures in a closed commercial binary is a legal risk. Decide:

- author/own the signature set (a strategic asset and the recommended path),
- and/or license a set properly,
- and keep provenance metadata per signature (`source`, `license`) so the build can *exclude*
  anything that isn't cleared for the shipped edition.

Track this as a hard gate before the first commercial release.

---

## 8. Reliability scaffolding (build this early)

- **Recorded-response test corpus.** A directory of real captured service responses paired with
  expected `ServiceVerdict`s, run as regression tests. A signature DB that evolves without this
  *will* silently regress. This is the highest-leverage investment in the whole redesign.
- **Per-analyzer metrics.** Hit rate, latency, top-N services — so signatures are tuned with
  data.
- **Determinism tests.** Same input ⇒ same verdict, including probe ordering.
- **Fuzz the matchers** against random/adversarial banners (assert: no panic, bounded time).

---

## 9. Proposed module layout

```
src/fingerprinting/
  mod.rs                // public API: fingerprint(port, ctx) -> ServiceVerdict
  model.rs              // Evidence, ServiceVerdict, Confidence, Cpe, Tunnel
  plan.rs               // ProbePlanner: which probes, order, rarity/intensity
  transport.rs          // async probe I/O: timeouts, byte caps, TLS wrap/re-probe
  resolve.rs            // Evidence -> ServiceVerdict (confidence merge)
  db/
    mod.rs              // load/mmap compiled artifact, header/version/integrity checks
    schema.rs           // authoring schema (serde) + schema_version
    artifact.rs         // compiled artifact format (metadata + serialized DFAs)
  matcher/
    mod.rs              // Matcher trait (prefilter + capture)
    regex_automata.rs   // default backend
    fancy.rs            // sandboxed backref backend (timeout-guarded)
    // hyperscan.rs      // future, behind a feature flag
  analyzers/
    mod.rs              // Analyzer trait + registry
    banner_regex.rs
    tls_cert.rs
    http_headers.rs
    jarm.rs
    ssh.rs
    // ...

build/ (build.rs helpers)
  compile_signatures.rs // TOML -> validate -> compile DFAs -> artifact; fail loud

assets/fingerprinting/<category>/<service>.toml   // authoring source (unchanged layout)
tests/fingerprinting/corpus/                       // recorded responses + expected verdicts
```

---

## 10. Phased migration

Each phase ships value and is independently reviewable; no big-bang rewrite.

- **Phase 0 — stop the bleeding (small, do now).** Split the cheap `port → service name` index
  out of `get_engine()` so port labelling needs zero regex; move any compilation off the
  reactor (`spawn_blocking`) and compile once; delete the per-connection `Regex::new` in
  `fingerprint_tcp`. This alone fixes the 9 s stall and the non-deterministic results on `main`.
- **Phase 1 — pipeline abstraction.** Introduce `model.rs`, `Analyzer`, `Resolver`; port the
  existing regex matcher in as `BannerRegexAnalyzer`. Behaviour-preserving. Consolidate
  `src/plugins/fingerprint.rs` into `src/fingerprinting/`.
- **Phase 2 — database contract.** Versioned schema, build-time validation (fail loud on bad
  patterns), disk/mmap loading with embedded fallback, provenance/license metadata.
- **Phase 3 — matcher upgrade.** Prefilter + build-time serialized DFAs; explicit
  backref/fancy handling; fuzzing.
- **Phase 4 — expand analyzers.** TLS cert, HTTP headers, JARM/JA3S, SSH, SNMP, favicon.
- **Phase 5 — scale/perf.** Recorded-response corpus in CI, per-analyzer metrics; evaluate
  hyperscan/vectorscan backend and `zond-fingerprints` package split.

---

## 11. Open decisions

1. **Artifact serialization:** `rkyv` (zero-copy mmap) vs `bincode` (simple) for the metadata
   table — benchmark before choosing.
2. **Embedded fallback vs disk-only** for the default distribution.
3. **`zond-fingerprints` split** timing — Phase 2 or later.
4. **Confidence model** — ordered enum now; weighted score later? Define when the second
   analyzer lands.
5. **Licensing edition strategy** — one clean-authored set, or a shippable subset gated by
   `license` metadata at build time.
6. **Probe intensity/rarity model** — adopt nmap-like intensity levels, or a simpler
   "always/on-demand" split to start?
