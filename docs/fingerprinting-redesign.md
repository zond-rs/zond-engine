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
| `RegexSet::new(all)`             | **infeasible** — see §5.2 | |
| build-time serialized DFA        | ~0 (runtime) | ~0 |
| lazy per-port (1–4 patterns)     | ~0      | ~0     |

> **Correction (measured during Phase 3).** An earlier draft listed `RegexSet::new(all)` at
> ~78 ms; that number was a *fast failure*, not a build. A single `RegexSet` over all 4,732
> patterns exceeds the compiled-size limit even at **256 MB**, and 64-pattern chunks already
> blow 32 MB. `RegexSet` — chunked or not — is not a viable global prefilter for this set. See
> §5.2 for what replaced it.

### 5.2 Two-stage matching for throughput

The original plan — a `RegexSet` prefilter over the whole set — does not survive contact with
the data (see the correction above). Two things were true instead:

1. **A global automaton is the wrong primitive here.** The only prefilter that scales is
   `aho-corasick` over *extracted literal anchors* (compact, millions-of-patterns friendly).
   But extracting a *required* literal from an arbitrary regex is subtle, and a wrong extraction
   silently drops matches — the very failure mode this redesign exists to kill. It needs the
   recorded-response corpus (§8) in place first.
2. **Most of the perceived need was reachability, not throughput.** The bulk of the signature
   set (imported banner sets) is port-less. Analysis showed the high-value port-less services
   (http, ssh, smtp, mysql, ftp, telnet, smb, sip, dns, ldap, imap, pop3, nntp) all have a
   ported sibling, so **linking signatures by service name** makes them reachable through their
   service's port — bounded, safe, no global automaton.

**Phase 3 therefore shipped three things:**

- **Service-name linking** — the DB's port index is the union, per port, of every definition of
  every service reachable on that port; compilation is lazy, parallelised with `rayon`, cached.
- **A signature model that is flat and index-addressed** — the port index and the prefilter both
  hand back signature indices, matched uniformly.
- **An Aho-Corasick literal prefilter** (`prefilter.rs`) for global matching on *non-standard*
  ports. For each signature it extracts a set of **required literals** — from the pattern's
  prefix (handling alternations), its longest guaranteed inner run, or its suffix — and indexes
  them in one Aho-Corasick automaton. A response's candidates are the signatures whose literal
  appears, plus a small always-run bucket.

**Why the prefilter, and why it is safe.** An earlier iteration used a "compile-all/run-all"
fallback and I justified it with "enough at this scale". That was wrong for a database we plan to
grow a lot: run-all is O(N) in signature count. The prefilter is **sublinear** — measured on the
current set: **0.76% always-run** (36 of 4,732 — binary protocols, pure-structural
version/UUID/IP patterns, `(?i)` folded ones, a *bounded* category), **~64 candidates per
response** (vs 4,732), **72 ms one-time build**. Only *required* literals are used, so a match is
never wrongly excluded, and this is **proved against the corpus**: `corpus.rs`'s
`prefilter_never_drops_a_matching_signature` asserts every matching example selects its signature
(zero violations). The prefilter sits behind a `Prefilter` trait, so a `hyperscan`/`vectorscan`
backend can replace it for DPI-grade throughput without touching callers.

**Known limitation — global-match disambiguation.** On a non-standard port, an ambiguous banner
(e.g. the shared `220` greeting) can match a different service's signature than intended (SMTP
seen as FTP), because global matching has no port context and takes the first matching candidate.
On the correct port, linking resolves it. Fix is a resolution-quality follow-up (confidence-
downgrade global matches so port-confirmed always wins; prefer more-specific matches) — tracked,
not a prefilter defect.

The remaining port-less-and-siblingless categories (favicon hashes, x509/TLS, SNMP, mDNS, NTP)
are not TCP-banner signatures at all; the prefilter does not help them — they belong to dedicated
analyzers (§4.2) fed by their own data (a TLS handshake, a favicon fetch, an SNMP get).

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

- **Recorded-response test corpus. _(done — `src/fingerprinting/corpus.rs`)_** Two layers:
  (1) *self-consistency* — 95% of signature rules ship a recorded `example` banner; every one is
  run through the real compiled matcher and the count of non-matching examples is pinned to a
  baseline, so a signature edit that breaks (or fixes) one fails the test; (2) *golden
  end-to-end* — real banners of well-known services driven through the whole pipeline
  (port-linked selection → matching → resolution) with the exact service/product/version pinned.
  - **Finding — lost recog case flags.** 218 of 4,477 examples do not match their own pattern,
    overwhelmingly because of **case** (`"MIPS"` vs `mips`, `"FTP server"` vs `FTP Server`). The
    imported rapid7/recog signatures carry a per-pattern case-insensitivity flag (`REG_ICASE`)
    that was dropped on import. The fix is a **re-import that preserves per-pattern flags**, not
    a blanket case-fold (recog defaults to case-sensitive; folding everything would add false
    positives). The baseline is pinned at 218 so the number cannot silently grow; ratchet it down
    as the flags are restored. Tracked as a signature-data follow-up.
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
- **Phase 1 — pipeline abstraction. _(done)_** `model.rs`, `Analyzer`, `Resolver`; the regex
  matcher ported in as `BannerRegexAnalyzer`; `src/plugins/fingerprint.rs` consolidated into
  `src/fingerprinting/`. Fixed the 9 s stall and the non-deterministic results (Phase 0 was
  folded in here — the cheap `port → name` index and off-reactor matching).
- **Phase 2 — build-time validation. _(done)_** Every pattern and `version_group` validated in
  `build.rs`; defects fail the build with a file pointer instead of shipping as silent coverage
  gaps. Schema de-duplicated (build `include!`s the canonical types); deterministic artifact.
  Recovered two signatures the 10 MiB regex size cap was silently dropping. _Deferred to a later
  stage:_ versioned/disk-mmap artifact + provenance/license metadata (carries open decision #2).
- **Phase 3 — matcher: linking + prefilter. _(done)_** Flat, index-addressed signatures. The
  port index is service-linked, so port-less supplementary signatures are matched through their
  service's port. An Aho-Corasick required-literal prefilter (§5.2) makes global matching on
  non-standard ports sublinear (0.76% always-run, ~64 candidates/response, corpus-proven sound),
  behind a `Prefilter` trait. Compilation is lazy and `rayon`-parallel. _Deferred:_ global-match
  disambiguation (confidence-downgrade); build-time serialized DFAs; backref/`fancy-regex`
  handling; fuzzing; a `hyperscan` prefilter backend if profiling demands it.
- **Phase 4 — expand analyzers.** TLS cert, HTTP headers, JARM/JA3S, SSH, SNMP, favicon — these
  also absorb the port-less-and-siblingless signature categories (x509/TLS, favicon, SNMP, …).
  - **Phase 4a — TLS certificate analyzer. _(done)_** The first non-regex analyzer, proving the
    extension point on structured binary rather than a text banner. The `Vec<String>` analyzer
    input became a typed `ResponseSet { banners, tls }` (`response.rs`) so non-banner evidence has
    a home (TLS now, raw binary frames for the nerva ports later). `tls.rs` completes a real
    handshake and captures the presented chain as raw DER; `tls_cert.rs` parses the leaf and emits
    `service = "ssl"` (Probable), plus `vendor` from the subject `O=` **only when the cert is
    self-signed** (subject == issuer), where `O=` reliably names the operator/appliance vendor. The
    transport goes straight to a handshake on implicit-TLS ports and opportunistically on any
    silent, un-probed port (non-standard-port TLS). Verified end-to-end against live expired/
    self-signed/wrong-host hosts and a recorded self-signed DER fixture in `corpus.rs`.
    - **Empirical findings.** (1) The handshake *must* complete — TLS 1.3 encrypts the server
      `Certificate` message, so raw-record scraping cannot see modern certs; we run a real rustls
      client with an accept-any verifier (a scanner wants the presented chain, not a trust
      decision). (2) Crypto provider pinned to pure-Rust **ring**, not rustls's default `aws-lc-rs`,
      which needs cmake/NASM and is a Windows-build friction point for a cross-platform product.
    - **Decision — `ssl` is the only truthful label; no port→name map.** The analyzer observed one
      thing (a handshake completed), not the application protocol inside the tunnel, so it reports
      exactly that: `ssl` at Probable. A `443→https` map would be port-number *guessing* wearing a
      Probable badge — conflating an observed fact with a heuristic, the anti-pattern this pipeline
      exists to kill (and it can't reuse the DB index, which maps `443→http`, `8443→kubernetes`).
      **Phase 4b's tunnel re-probe supersedes `ssl` with the specific protocol (https, imaps) at
      Strong, backed by real evidence.** The interim cost is cosmetic (users expect 443 to say
      `https`) and is accepted for correctness now.
    - **Decision — split TLS handshake timeouts by prior.** Expected-TLS (implicit-TLS) ports keep
      the patient 3 s `TLS_HANDSHAKE_TIMEOUT`; a *speculative* handshake on a silent, un-probed
      non-standard port uses a tighter `SPECULATIVE_TLS_TIMEOUT` (1.5 s), since a real TLS server on
      a reachable port completes sub-second and this cost is paid on every silent port.
    - **Known gap.** The extracted `vendor` (and cert host attribution: CN/SAN) lives on
      `Evidence`/`ServiceVerdict` but is **dropped by `to_service()`** — the crate `Service` model
      has no `vendor` field, so it is not yet user-visible. Surface it (and SAN host attribution)
      as a follow-up.
  - **Phase 4b — re-probe through the TLS tunnel. _(done)_** The handshake now returns the live
    `TlsStream`; a transport-generic `collect_responses<S: AsyncRead + AsyncWrite>` runs the banner
    grab + active probes over either the raw socket or the tunnel, so the protocol carried inside
    TLS is fingerprinted by the same `BannerRegexAnalyzer`. A `Tunnel` (`Tls`) signal rides on
    `Evidence` (stamped from `PortContext`) and on `ServiceVerdict`, and `to_service()` labels a
    tunnelled service `<scheme>/<name>`.
    - **Decision — label `ssl/http`, not `https`.** Both facts are now *observed* (the protocol
      from the decrypted banner, TLS from the handshake), so the label shows both explicitly,
      nmap-style, with no per-protocol rename map. `Evidence::service` stays the bare protocol
      (`http`) for downstream CPE/CVE; the `ssl/` prefix is applied only at the `Service`
      projection. The tunnel's own bare `ssl` verdict (no inner protocol matched) is *not*
      re-prefixed. Verified end-to-end: badssl/google/github :443 now resolve `ssl/http` where 4a
      gave bare `ssl`.
    - **Prerequisite fixed — probe payloads were not unescaped.** Payloads are authored as TOML
      *literal* strings (`'GET / HTTP/1.1\r\n\r\n'`), so `\r\n` reached the wire as literal
      backslashes — HTTP active-probing was malformed on the plaintext path too, not just in the
      tunnel. Now decoded at load (`\r \n \t \0 \xHH \\`) and stored as `Vec<u8>` so binary probes
      are representable. (`db.rs::unescape`.)
    - **Known limitation — first-match, not best-match.** Inside TLS on 443 the result is
      `ssl/http` at Probable, not `ssl/http nginx <ver>`: `BannerRegexAnalyzer` takes the *first*
      matching signature, and a generic HTTP signature shadows the specific `Server: …` ones. This
      is a pre-existing matcher-quality issue (same family as global-match disambiguation), not a
      4b regression; best-match selection is a separate follow-up.
- **Phase 5 — scale/perf.** Recorded-response corpus landed (§8) and now guards regressions and
  unblocks the prefilter; remaining: per-analyzer metrics, hyperscan/vectorscan evaluation, and
  the `zond-fingerprints` split. Signature-data follow-up: re-import recog per-pattern case flags
  to clear the 218 pinned example mismatches.

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
