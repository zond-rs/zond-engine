# Service Fingerprinting — Road to 1.0

**Scope:** the service/version fingerprinting subsystem (`src/fingerprinting/`,
`assets/fingerprinting/`). This is *"what is running on this open port?"* — not
discovery (*"which hosts/ports are alive?"*).

**Status:** the engine foundations are shipped and solid; this doc tracks what
remains for a **1.0** release. The full design rationale and phase-by-phase
history previously lived in `fingerprinting-redesign.md` (removed — recoverable
from git history). The load-bearing decisions are preserved below; everything
else is a forward checklist.

---

## What "1.0" means (the bar)

Five properties. Every checklist item below serves one of them.

- **Correct** — no silent coverage drops, fuzz-hardened, deterministic.
- **Broad** — enough analyzers + an owned corpus (incl. binary/ICS via nerva) +
  UDP to be credible against nmap on coverage.
- **Fast at scale** — intensity/softmatch so 10⁴–10⁶-host sweeps don't pay for
  every probe on every port.
- **Commercial** — owned/clean signature data, an updatable artifact, and CPEs
  for downstream CVE/inventory.
- **Explainable** — provenance retained; vendor/host attribution surfaced.

---

## Done — foundations (don't re-litigate)

- [x] Evidence pipeline: `Analyzer` / `Evidence` / `ServiceVerdict` / resolver
      (`model.rs`, `analyzer.rs`).
- [x] Build-time validation, fail-loud (`build.rs`): a bad pattern or
      `version_group` aborts the build instead of shipping a silent gap.
- [x] Service-name linking + Aho-Corasick required-literal prefilter — sublinear
      global match, corpus-proven sound (`db.rs`, `prefilter.rs`).
- [x] Best-match selection by `(confidence, detail)` (`matcher.rs`,
      `analyzer.rs`): specific signatures no longer shadowed by generic ones.
- [x] TLS: real rustls handshake (ring), cert analyzer, and re-probe *through*
      the tunnel → `ssl/<proto>` (`tls.rs`, `tls_cert.rs`).
- [x] Recorded-response corpus: self-consistency + golden end-to-end
      (`corpus.rs`).
- [x] Probe `rarity` field reserved for intensity (`fingerprint.rs`; build
      validates `0..=9`).
- [x] **Two-phase `Analyzer` trait** (`analyzer.rs`): `async collect` (I/O, on
      the reactor) → `sync analyze` (CPU, off it), with a raw-bytes `Collected`
      channel (`response.rs`) for an analyzer's own probe frames. This is the
      extension point every *active* analyzer (JARM, SSH, SNMP, …) and every
      nerva binary handler drops into — they override `collect`, parse in
      `analyze`. Passive analyzers keep the default no-op `collect`.

## Durable decisions (keep)

- Keep the TOML source (one file per service); validate+compile at build; never
  hand-author the binary; never move to one monolithic file.
- **TLS labels are observed-only:** bare `ssl` when nothing inner matches,
  `ssl/<proto>` when it does. No port→name or protocol→secure-name rename map.
  `Evidence::service` stays the bare protocol (for CPE); the `ssl/` prefix is
  applied only in `to_service()`.
- Crypto provider = pure-Rust **ring**, not aws-lc-rs (Windows build friction).
- Split TLS handshake timeouts: implicit-TLS 3 s; speculative-on-silent-ports
  1.5 s.
- Best-match ranking: confidence dominates (version → Strong), then explicit
  product/vendor count; ties keep the lowest index (deterministic).
- Prefilter uses only *required* literals, so a match is never wrongly excluded;
  soundness is asserted against the corpus, not assumed.
- **Backtracking bound is a step limit, not a wall clock.** The fancy-regex
  fallback is bounded by a backtrack-step ceiling, chosen over a wall-clock
  timeout deliberately: a synchronous match can't be interrupted mid-flight (a
  watchdog thread would leave the runaway match burning a core anyway), and a
  step ceiling is deterministic — same pattern + input resolves identically on
  every machine, keeping the corpus tests reproducible. A limit hit is reported
  as "no match", never a hang.

---

## Checklist to 1.0

### A. Data & corpus — the mountain

- [ ] **nerva integration** (see [nerva](#nerva-integration-praetorian-incnerva--rust))
      — the primary data-growth lever for binary/ICS/database-wire protocols.
- [ ] Grow the **owned** signature corpus toward nmap-class density (~12k+ match
      lines vs ~4.7k today); keep `source`/`license` provenance per signature.
- [ ] **Licensing gate:** ship only clean-authored / properly-licensed data — no
      nmap-service-probes (NPSL) in the commercial edition. Hard gate before 1.0.
- [ ] Re-import recog with per-pattern case flags (`REG_ICASE`) → clear the 218
      pinned `KNOWN_EXAMPLE_MISMATCHES`; ratchet the baseline down as they land.
- [ ] Author CPEs in signatures and populate `Evidence.cpe` (downstream
      CVE/inventory; currently always `None`).

### B. Analyzers — 4 of ~8 today

The two-phase trait now hosts active analyzers: each overrides `collect` (its own
probe/handshake) and parses in `analyze`. The three that need UDP (SNMP, DNS,
NTP) also depend on §D UDP; the rest are TCP-only and can land now.

The active `collect→analyze` path is proven end-to-end with real network I/O by
the SSH analyzer (below) — the reference every future active analyzer (JARM, the
nerva binary/ICS handlers) follows. Enabling it required threading the peer
address into `PortContext` (`addr`), since an active analyzer opens its own
connection; that is the "grows as analyzers need more context" the trait
anticipated.

- [x] HTTP headers (structured, not regex-on-banner) — `http.rs`. Parses the
      captured response and lifts product/version out of the `Server` header for
      *any* server (`gunicorn`, `Microsoft-IIS/10.0`, `openresty`, …), covering
      the long tail the curated `Server:` regexes miss. Passive (reads the
      shared `get_root` response, no double-probe). Scope today is the `Server`
      header + a baseline `http` label; `X-Powered-By`/`Set-Cookie`/
      `X-AspNet-Version` are deferred until the `Service` model gains an
      `extrainfo`/technologies slot (see §E) — emitting them now would clobber
      the real server in the single `product` field. The parser already exposes
      every header, so that is a small follow-up. **Active HTTP probing on
      non-standard ports** (a `GET` from `collect` where no probe is configured)
      is the other open follow-up.
- [ ] JARM / JA3S TLS-stack fingerprinting (identifies servers silent in-band).
- [x] SSH (KEX / host-key algorithms) — `ssh.rs`. The first **active** analyzer:
      `collect` opens its own connection, does the identification-string exchange,
      and reads the server's `SSH_MSG_KEXINIT`; `analyze` bounds-checks and parses
      the algorithm name-lists. Adds protocol confirmation (`ssh` at Strong — a
      completed handshake, not just a banner starting `SSH-`) and the server's
      host-key algorithm list as `extrainfo` (a basis for later HASSH-style ID).
      Active probing is gated to ports 22/2222 (a fresh connection is not free);
      SSH on non-standard ports still resolves from its banner, and driving the
      probe from an accumulating service guess is the ProbePlanner's job (§D).
- [ ] SNMP (`sysDescr`), favicon hash, DNS `version.bind`, NTP.
- [ ] Binary / ICS analyzers arrive via nerva (see below).

### C. Matcher completeness

- [x] **Backref/lookaround path** (`pattern.rs`, new): a two-tier matcher. The
      linear `regex` (RE2) engine stays the primary; a bounded `fancy-regex`
      backtracking engine is the fallback, reached *only* for patterns the linear
      engine can't express (backrefs, lookaround). `build.rs` and the runtime
      share the exact selection logic (`#[path]`-included), so the build accepts
      precisely what the engine can match instead of aborting — the import
      ceiling is lifted. Bound is a deterministic **backtrack-step limit**, not a
      wall clock (see durable decision below); analysis already runs off the
      reactor, so a bounded match can't stall the scheduler.

### D. Probing strategy

- [ ] **Intensity cap:** consume `rarity` — send a probe only when
      `rarity <= intensity`. Requires threading an intensity level from the
      scanner into `gather()` (no config plumbing exists yet). Boundary-safe
      (still batchable). Near-zero wall-clock win today (≤1 probe/service), pays
      off as probe density grows.
- [ ] **Softmatch feedback loop:** match between sends, narrow candidates,
      continue; stop at a **port-confirmed** Strong. Interleaves I/O and CPU —
      revisits the "gather-then-analyze in one batch" boundary. Do after the
      intensity cap is proven.
- [ ] **ProbePlanner** (`plan.rs`, new): probe selection keyed on the
      accumulating service guess, not just the port. The DB already holds
      `service → probes` internally; expose it. Prerequisite for softmatch.
- [ ] **UDP fingerprinting:** the *sending* half now exists. The corpus carries
      `protocol = "udp"` probes (dns, mdns, ntp, snmp, netbios-ns, ssdp),
      `SignatureDb::udp_probe_payloads` indexes them by port, and the scanner
      sends them and interprets ICMP port-unreachable — see
      [udp-scanning.md](udp-scanning.md). What is missing is the *reading* half:
      the replies those probes draw are counted as evidence a port is open and
      then discarded, though they carry exactly what a fingerprint wants (a
      `version.bind` answer is the BIND version string; an SNMP reply is
      `sysDescr`). Needs a UDP analyzer path feeding `Collected`, plus `[[match]]`
      rules on the new definitions — which now sit in the same files as the
      probes that provoke the responses they would match.
- [x] **Raw-bytes response channel:** an analyzer's own probe frames flow as raw
      `Vec<u8>` through `Collected` (`response.rs`), so binary analyzers parse
      bytes directly. (The shared first-contact `ResponseSet.banners` stays
      `String` — text-oriented; binary analyzers read their own `Collected`
      frames, not the shared banners.) The nerva prerequisite is met.

### E. Resolver quality

- [x] **Port-confirmation downgrade:** `Evidence` now carries `port_confirmed`
      (set by `BannerRegexAnalyzer` — true for a port-linked-tier match, false
      for a global-fallback one), and `resolve` ranks by `(confidence,
      port_confirmed)`. Confidence still dominates (a weak port match never
      buries a strong global identification); within a level the port-confirmed
      match wins, so a coincidental cross-protocol banner match (bare-`220`
      FTP-vs-SMTP) loses to the service expected on the port. This closes the
      port-context half at equal confidence; making port-confirmation override a
      *higher*-confidence global match is intentionally deferred — it needs the
      cross-probe context of the softmatch stop rule to be safe.
- [x] **Surface vendor + extrainfo attribution:** the `Service` model now carries
      `vendor`, and `extrainfo` is threaded through `Evidence`/`ServiceVerdict` →
      `to_service()`. Fixes the silent data loss where `TlsCertAnalyzer` extracted
      a vendor that `to_service()` then dropped, and unblocks the HTTP analyzer's
      `X-Powered-By` (now emitted as `extrainfo`, so a framework never displaces
      the server in the single `product` slot). Composes cleanly: a curated
      Apache signature supplies product+vendor while the HTTP analyzer supplies
      extrainfo, all merging onto one `Service`.
- [ ] **Cert CN/SAN host attribution:** the subject CN / SAN hostnames describe
      the *host*, not the service, so they belong on the `Host` model, not
      `Evidence`. Separate follow-up at that layer.

### F. Artifact & ops — commercial-necessary

- [ ] **Serialized-DFA / mmap artifact:** versioned header + integrity hash,
      disk-loadable, out-of-band + per-customer signature packs. Today it's
      `include_bytes!` + lazy runtime compile — functional, but forecloses the
      update/licensing story. Decide `rkyv` vs `bincode` by benchmark.
- [ ] **Per-analyzer metrics:** hit rate, latency, top-N services — so tuning is
      data-driven.
- [x] **Fuzz the matchers/parsers** against random/adversarial input (`proptest`,
      colocated per module): the full banner pipeline against the real signature
      set (prefilter → fast/fancy regex → best-match → resolve), the SSH `KEXINIT`
      binary parser (arbitrary bytes — no panic, no OOB, no hostile-length alloc),
      the HTTP response + `Server` parsers, the fancy-regex path (terminates on
      any input — the backtrack-step limit is the guarantee), and the prefilter.
      No panics found; the properties stand as regression guards. Deeper coverage
      (a `cargo-fuzz` target with a corpus) can layer on later, but the untrusted
      surfaces are covered.

---

## nerva integration (praetorian-inc/nerva → Rust)

**Why.** nerva is **Apache-2.0** (commercially clean to derive from, with
attribution — unlike NPSL), 170+ protocols, and strong exactly where
regex-on-banner is weak: **binary / ICS-SCADA (Modbus, S7comm, BACnet) /
database-wire / telecom**. Complementary coverage, not text-banner overlap.

**How it slots in (no schema change).** nerva fingerprints are *procedural Go*
(byte-offset parsing, multi-step handshakes, branching) — they **cannot** become
declarative TOML (that schema only holds send-string → regex → capture). Instead,
each nerva protocol becomes a Rust **`Analyzer`** (`analyzer.rs`): it sends its
own probe, parses raw bytes, and emits `Evidence` — a peer of
`BannerRegexAnalyzer`, resolved by the same resolver. The extension point already
exists; nerva is what proves it out at scale.

**Anti-hallucination oracle.** Translation is done by many small AI agents,
incrementally. Validate every translated analyzer against nerva's own
`testdata/` fixtures (recorded protocol responses + expected results), mirroring
`corpus.rs`. **No translation is trusted without fixture validation.**

**Checklist:**

- [x] Raw-bytes response channel via `Collected` (§D) — done; the prerequisite
      is met.
- [ ] Define the binary-`Analyzer` pattern with **one** reference protocol
      end-to-end (probe → parse → `Evidence` → resolver) + its nerva `testdata`
      fixture wired into the corpus harness.
- [ ] Port **2–3 high-value** ICS/binary protocols (e.g. Modbus, S7comm) against
      fixtures — not all 170 at once.
- [ ] Scale the Go→Rust translation with fixture-gated agents; track ported vs
      remaining protocols.
