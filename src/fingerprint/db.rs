// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Signature database
//!
//! The compiled signature set and the access layer over it.
//!
//! Signatures are stored flat and addressed by index. Three access patterns,
//! by cost:
//!
//! * **Name lookup** ([`SignatureDb::service_name`]): a `port -> name` index
//!   built once at load, with no regex compilation. Called for every classified
//!   port.
//! * **Port matching** ([`SignatureDb::signatures_for_port`]): the
//!   service-linked signatures for a port. Their regexes compile lazily, once
//!   each; [`SignatureDb::warm`] can compile a set in parallel.
//! * **Global matching** ([`SignatureDb::prefilter`]): for services on
//!   non-standard ports, an Aho-Corasick prefilter narrows the whole set to a
//!   small candidate list.
//!
//! The set is a `bincode` blob embedded at build time from
//! `assets/fingerprinting/` and loaded by [`SignatureDb::global`].

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use rayon::prelude::*;

use crate::fingerprint::signature::{DefinitionError, ServiceDefinition, unescape};
use crate::model::port::Protocol;

/// The field a rule reads when it takes an operating system's own name rather
/// than something a service said. See
/// [`canonical_os_name`](SignatureDb::canonical_os_name).
const OS_NAME_CONTEXT: &str = "operating_system.name";

/// The field a rule reads when its whole job is to name an instruction set.
/// See [`architecture_of`](SignatureDb::architecture_of).
const ARCHITECTURE_CONTEXT: &str = "architecture";

/// The `vendor:product` a rule's CPE template names, where the template carries
/// a version to fill and names an application.
///
/// [`None`] for a rule with no CPE, one whose CPE is literal (nothing to fill,
/// so the version is whatever was written, usually `-`), and one naming an
/// operating system, whose CPE version is a release family rather than anything
/// a banner states.
fn versioned_product(rule: &super::signature::MatchRule) -> Option<String> {
    const VERSION: &str = "{service.version}";

    let template = rule.metadata.as_ref()?.get("service.cpe23")?;
    let rest = template.strip_prefix("cpe:/a:")?;
    if !rest.contains(VERSION) {
        return None;
    }

    let mut parts = rest.split(':');
    let vendor = parts.next().filter(|part| !part.is_empty())?;
    let product = parts.next().filter(|part| !part.is_empty())?;
    Some(format!("{vendor}:{product}"))
}

/// The context whose rules read a JARM hash, held in an index of their own.
const JARM_CONTEXT: &str = "tls.jarm";

use super::model::{Evidence, Tunnel};
use super::on_the_matching_thread;
use crate::model::host::OsEvidence;

use super::matcher::Signature;
use super::prefilter::{LiteralPrefilter, Prefilter};

/// The signature set compiled from `assets/fingerprinting/` by `build.rs`.
const EMBEDDED_DB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fingerprints.bin"));

/// The decoded corpus, built on first use and shared after. Decoding is not
/// cheap and the result never changes, so it is done once per process.
static DB: OnceLock<SignatureDb> = OnceLock::new();

/// A definition [`SignatureDb::try_from_definitions`] refused, and why.
///
/// Carries the definition's position and service, to find it in a large corpus.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidDefinition {
    /// Where the definition sat in the list handed over.
    pub index: usize,
    /// The service it was about.
    pub service: String,
    /// What is wrong with it.
    pub error: DefinitionError,
}

impl std::fmt::Display for InvalidDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            index,
            service,
            error,
        } = self;
        write!(f, "definition {index} (service '{service}') {error}")
    }
}

impl std::error::Error for InvalidDefinition {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Runtime view over the service-signature database.
#[derive(Debug)]
pub struct SignatureDb {
    /// All signatures, flat, addressed by index.
    signatures: Vec<Signature>,
    /// `port -> primary service name` (first definition to claim the port).
    name_index: HashMap<u16, Arc<str>>,
    /// The signatures whose rules read `operating_system.name`: an operating
    /// system's own name, normalised.
    ///
    /// These say what a bare operating-system name canonically is:
    /// `Windows Server 2008 R2 Standard` is the Windows family, the 2008 R2
    /// product, the Standard edition.
    ///
    /// Kept apart because [`identify_field`](Self::identify_field) over the whole
    /// corpus would hit loose banner rules: four FTP rules read
    /// `Windows Server 2008` as just `Windows`. See
    /// [`canonical_os_name`](Self::canonical_os_name).
    os_name_signatures: Vec<usize>,
    /// The signatures whose rules read `architecture`: seven patterns that name
    /// nothing but an instruction set.
    ///
    /// Kept apart like [`os_name_signatures`](Self::os_name_signatures). They state
    /// no product, family or vendor, so
    /// [`evidence_from`](super::os::banner_evidence) declines them; they are
    /// consulted for one field and never vote.
    architecture_signatures: Vec<usize>,
    /// The signatures whose rules read a JARM hash.
    ///
    /// Kept apart because a baseline rule matches any run of hex as an ISAKMP
    /// vendor-id list, so through [`identify_field`](Self::identify_field) every
    /// unpublished hash would be named `isakmp`. See
    /// [`identify_jarm`](Self::identify_jarm).
    jarm_signatures: Vec<usize>,
    /// Every `vendor:product` the corpus can name *with a version*, as a CPE
    /// spells them.
    ///
    /// A vulnerability catalogue entry for software this corpus cannot version
    /// can never match, as [`Reach::Unproduced`](super::Reach) describes. 269
    /// products are named by some rule but never with a version.
    ///
    /// A product counts when its `service.cpe23` template carries
    /// `{service.version}`. Applications only: an operating-system CPE's version
    /// is a family name such as `windows_server_2016`.
    versioned_products: BTreeSet<String>,
    /// `port -> signature indices` matchable on that port.
    ///
    /// The union of the signatures of every service reachable on the port,
    /// including each service's port-less ones.
    by_port: HashMap<u16, Vec<usize>>,
    /// `port -> TCP active-probe payloads` of the services reachable on it,
    /// grouped by the service that registered them; see [`Conversations`].
    /// Payloads are decoded bytes (escapes resolved, see [`unescape`]), ready to
    /// go on the wire as they are, non-UTF-8 binary probes included.
    tcp_probes: HashMap<u16, Conversations>,
    /// The TCP probes worth sending to a port that registered none of its own,
    /// decoded to wire bytes.
    ///
    /// Authored with `generic = true`; see
    /// [`Probe::generic`](crate::fingerprint::signature::Probe::generic).
    generic_tcp_probes: Vec<Vec<u8>>,
    /// The TCP probes that may be put to a port their own service never
    /// registered, each with the intensity that unlocks it.
    ///
    /// Ordered by rarity, likeliest first. Holds only probes authored with a
    /// rarity of 1 or more; see
    /// [`Probe::rarity`](crate::fingerprint::signature::Probe::rarity).
    universal_tcp_probes: Vec<(u8, Vec<u8>)>,
    /// `port -> UDP probe payloads`, indexed like [`Self::tcp_probes`].
    ///
    /// A TCP probe makes a known-open service identify itself; a UDP probe also
    /// establishes that the port is open, since UDP has no handshake.
    udp_probes: HashMap<u16, Vec<Vec<u8>>>,
    /// `service name -> the application protocol it is carried over`, for the
    /// services that declare one. See
    /// [`ServiceSignature::speaks`](crate::fingerprint::ServiceSignature::speaks).
    speaks: HashMap<Arc<str>, Arc<str>>,
    /// The services a scan can meet on a port: those that register one or send
    /// a probe. The rest are names the corpus files rules under without any
    /// port speaking them, `x509` and `favicons.xml` among them; see
    /// [`agree`](Self::agree).
    protocols: HashSet<Arc<str>>,
    /// The ports every service reachable on which speaks HTTP; see
    /// [`asked_first`](Self::asked_first).
    asked_first: HashSet<u16>,
    /// The global-match prefilter, built on first use.
    prefilter: OnceLock<LiteralPrefilter>,
}

/// One port's TCP probes, in the order they are asked, grouped by the service
/// that registered them.
///
/// Each service's probes go on their own connection, since a question in one
/// protocol often ends the conversation in another: an Aerospike info request
/// draws a `400` and a close from the web server that usually holds 3000.
///
/// Services that name the port come first, then those that share it, so the
/// likeliest service is asked first on the connection the scan already opened.
#[derive(Debug, Default)]
struct Conversations {
    /// Every probe, flat, in the order they are asked.
    payloads: Vec<Vec<u8>>,
    /// Where each service's run of [`payloads`](Self::payloads) ends.
    ends: Vec<usize>,
}

impl Conversations {
    /// Appends one service's probes as a conversation of its own, or nothing
    /// where it registered none.
    fn push(&mut self, probes: &[Vec<u8>]) {
        if probes.is_empty() {
            return;
        }
        self.payloads.extend_from_slice(probes);
        self.ends.push(self.payloads.len());
    }

    /// Each service's probes, in the order they are asked.
    fn each(&self) -> impl Iterator<Item = &[Vec<u8>]> {
        let starts = std::iter::once(0).chain(self.ends.iter().copied());
        starts
            .zip(&self.ends)
            .map(|(start, &end)| &self.payloads[start..end])
    }
}

impl SignatureDb {
    /// The process-wide database. The first call deserializes the embedded set
    /// and builds the name and port indices; it compiles no regexes and builds
    /// no prefilter. Subsequent calls are a pointer read.
    pub fn global() -> &'static SignatureDb {
        DB.get_or_init(|| {
            let defs: Vec<ServiceDefinition> = bincode::deserialize(EMBEDDED_DB)
                .expect("embedded fingerprint database failed to deserialize");
            SignatureDb::from_defs(defs)
        })
    }

    /// Builds a database from definitions given directly, refusing any the build
    /// would refuse.
    ///
    /// How a caller supplies signatures of their own. The checks are
    /// [`ServiceDefinition::validate`], which `build.rs` also runs over the
    /// shipped corpus.
    ///
    /// Every pattern is compiled to check it, which is the expensive part;
    /// [`global`](Self::global) skips it.
    ///
    /// # Errors
    ///
    /// [`InvalidDefinition`] names which definition was refused and why.
    pub fn try_from_definitions(defs: Vec<ServiceDefinition>) -> Result<Self, InvalidDefinition> {
        for (index, def) in defs.iter().enumerate() {
            def.validate().map_err(|error| InvalidDefinition {
                index,
                service: def.service.name.clone(),
                error,
            })?;
        }
        Ok(Self::from_defs(defs))
    }

    /// Builds the flat signature list and its indices from raw definitions.
    /// Involves no regex compilation.
    fn from_defs(defs: Vec<ServiceDefinition>) -> Self {
        let mut signatures = Vec::new();
        // service name -> its signature indices (across every definition).
        let mut service_sigs: HashMap<String, Vec<usize>> = HashMap::new();
        // service name -> its active-probe payloads (decoded), per transport.
        let mut service_tcp_probes: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        let mut service_udp_probes: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        // Probes for ports nobody registered, across every definition.
        let mut generic_tcp_probes: Vec<Vec<u8>> = Vec::new();
        // Probes with a rarity, across every definition.
        let mut universal_tcp_probes: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut os_name_signatures: Vec<usize> = Vec::new();
        let mut architecture_signatures: Vec<usize> = Vec::new();
        let mut jarm_signatures: Vec<usize> = Vec::new();
        let mut versioned_products: BTreeSet<String> = BTreeSet::new();
        for def in &defs {
            for rule in &def.r#match {
                let idx = signatures.len();
                match rule.context.as_deref() {
                    Some(OS_NAME_CONTEXT) => os_name_signatures.push(idx),
                    Some(ARCHITECTURE_CONTEXT) => architecture_signatures.push(idx),
                    Some(JARM_CONTEXT) => jarm_signatures.push(idx),
                    _ => {}
                }
                if let Some(product) = versioned_product(rule) {
                    versioned_products.insert(product);
                }
                signatures.push(Signature::new(&def.service.name, rule));
                service_sigs
                    .entry(def.service.name.clone())
                    .or_default()
                    .push(idx);
            }
            for probe in &def.probe {
                let by_protocol = match probe.protocol.as_str() {
                    "tcp" => &mut service_tcp_probes,
                    "udp" => &mut service_udp_probes,
                    // An unknown protocol is already a build warning.
                    _ => continue,
                };
                let payload = unescape(&probe.payload);
                if probe.generic && probe.protocol == "tcp" {
                    generic_tcp_probes.push(payload.clone());
                }
                if probe.rarity > 0 && probe.protocol == "tcp" {
                    universal_tcp_probes.push((probe.rarity, payload.clone()));
                }
                by_protocol
                    .entry(def.service.name.clone())
                    .or_default()
                    .push(payload);
            }
        }

        // Keyed by service name: a service may span files (`http` spans six).
        let mut speaks: HashMap<Arc<str>, Arc<str>> = HashMap::new();
        for def in &defs {
            if let Some(protocol) = &def.service.speaks {
                speaks
                    .entry(Arc::from(def.service.name.as_str()))
                    .or_insert_with(|| Arc::from(protocol.as_str()));
            }
        }

        let protocols = defs
            .iter()
            .filter(|def| {
                let service = &def.service;
                !(service.default_ports.is_empty()
                    && service.shared_ports.is_empty()
                    && def.probe.is_empty())
            })
            .map(|def| Arc::from(def.service.name.as_str()))
            .collect();

        // Primary name and reachable-service set per port. Both lists reach a
        // port; only `default_ports` names it. Every service naming a port
        // is collected before any that only shares it, so a port's services
        // are listed in the order its probes are asked; see `Conversations`.
        let mut name_index: HashMap<u16, Arc<str>> = HashMap::new();
        let mut port_services: HashMap<u16, Vec<String>> = HashMap::new();
        for def in &defs {
            for &port in &def.service.default_ports {
                name_index
                    .entry(port)
                    .or_insert_with(|| Arc::from(def.service.name.as_str()));
            }
        }
        let naming = defs.iter().map(|def| &def.service.default_ports);
        let sharing = defs.iter().map(|def| &def.service.shared_ports);
        for (def, ports) in defs.iter().zip(naming).chain(defs.iter().zip(sharing)) {
            for &port in ports {
                let names = port_services.entry(port).or_default();
                if !names.contains(&def.service.name) {
                    names.push(def.service.name.clone());
                }
            }
        }

        // Link: a port's signatures (and probes) are those of every service
        // reachable on it.
        let mut by_port: HashMap<u16, Vec<usize>> = HashMap::new();
        let mut tcp_probes: HashMap<u16, Conversations> = HashMap::new();
        let mut udp_probes: HashMap<u16, Vec<Vec<u8>>> = HashMap::new();
        for (port, names) in &port_services {
            let mut indices: Vec<usize> = names
                .iter()
                .filter_map(|name| service_sigs.get(name))
                .flatten()
                .copied()
                .collect();
            indices.sort_unstable();
            indices.dedup();
            by_port.insert(*port, indices);

            let mut conversations = Conversations::default();
            for probes in names.iter().filter_map(|name| service_tcp_probes.get(name)) {
                conversations.push(probes);
            }
            if !conversations.payloads.is_empty() {
                tcp_probes.insert(*port, conversations);
            }

            let payloads: Vec<Vec<u8>> = names
                .iter()
                .filter_map(|name| service_udp_probes.get(name))
                .flatten()
                .cloned()
                .collect();
            if !payloads.is_empty() {
                udp_probes.insert(*port, payloads);
            }
        }

        universal_tcp_probes.sort_by_key(|(rarity, _)| *rarity);

        let asked_first = port_services
            .iter()
            .filter(|(_, names)| {
                names
                    .iter()
                    .all(|name| speaks.get(name.as_str()).is_some_and(|p| &**p == "http"))
            })
            .map(|(port, _)| *port)
            .collect();

        Self {
            signatures,
            name_index,
            os_name_signatures,
            architecture_signatures,
            jarm_signatures,
            versioned_products,
            by_port,
            tcp_probes,
            generic_tcp_probes,
            universal_tcp_probes,
            udp_probes,
            speaks,
            protocols,
            asked_first,
            prefilter: OnceLock::new(),
        }
    }

    /// What this signature set makes of one `response` read from `port`.
    ///
    /// Text extraction, both matching tiers, and the separate choice of a
    /// service reading and an operating-system reading. Signatures loaded
    /// through [`try_from_definitions`](Self::try_from_definitions) are matched
    /// through here, and
    /// [`BannerRegexAnalyzer`](crate::fingerprint::BannerRegexAnalyzer) is a loop
    /// around it.
    ///
    /// # Two tiers
    ///
    /// The response is checked first against the signatures registered for its
    /// port, narrowed by the prefilter. The global set, narrowed the same way and
    /// compiled on demand, is consulted when the port set identified nothing,
    /// **and also when it named a service but said nothing about the machine**,
    /// since operating-system readings often live only in the global set.
    ///
    /// [`Evidence::port_confirmed`](crate::fingerprint::Evidence::port_confirmed)
    /// records which tier named the service. The tunnel is not set here.
    ///
    /// # Where the match runs
    ///
    /// On the engine's identification thread; the caller waits. A compiled
    /// signature keeps a search cache per thread that matches with it, so one
    /// thread keeps one cache.
    pub fn identify(&self, port: u16, protocol: Protocol, response: &str) -> Option<Evidence> {
        on_the_matching_thread(|| {
            let port_signatures = self.signatures_for_port(port);
            let attested_by = super::extract::attested_by(port, protocol);
            identify_within(self, port_signatures, response, attested_by)
        })
    }

    /// What the corpus makes of one extracted field, matched against the whole
    /// set rather than a port's.
    ///
    /// For text that belongs to no port: a certificate name, a hash, a record a
    /// rule reads directly. Such rules are registered under their own service,
    /// not a port. The prefilter keeps this cheap.
    ///
    /// Matched on the identification thread, as [`identify`](Self::identify) is.
    pub(crate) fn identify_field(&self, text: &str) -> Option<Evidence> {
        let mut candidates = self.prefilter().candidates(text);
        candidates.sort_unstable();
        candidates.dedup();
        self.warm(&candidates);
        on_the_matching_thread(|| {
            best_match(
                self,
                &candidates,
                &[text],
                crate::model::host::OsSource::ServiceBanner,
            )
        })
    }

    /// What the corpus canonically calls the operating system `name`.
    ///
    /// A second stage over a match's reading. A service rule often names the
    /// operating system as the service reported it (`Windows Server 2008 R2
    /// Standard` from an SMB session setup), and 59 corpus rules say what such a
    /// string canonically is.
    ///
    /// Only those rules are consulted: through the whole corpus,
    /// `Windows Server 2008` comes back as just `Windows` from an FTP rule.
    ///
    /// [`None`] where nothing recognises the name.
    ///
    /// Matched on the identification thread, as [`identify`](Self::identify) is.
    pub(crate) fn canonical_os_name(&self, name: &str) -> Option<OsEvidence> {
        self.warm(&self.os_name_signatures);
        on_the_matching_thread(|| {
            best_match_within(
                self,
                &self.os_name_signatures,
                &[name],
                crate::model::host::OsSource::ServiceBanner,
            )
        })?
        .os
    }

    /// Every `vendor:product` the corpus can name with a version.
    ///
    /// A vulnerability catalogue is filtered against this. See the
    /// `versioned_products` field for the test applied.
    pub fn versioned_products(&self) -> &BTreeSet<String> {
        &self.versioned_products
    }

    /// What the corpus makes of a JARM hash.
    ///
    /// Matched against the JARM rules only; the whole corpus would match the
    /// ISAKMP baseline on any hash.
    ///
    /// [`None`] where nothing published this hash, the ordinary outcome.
    ///
    /// Matched on the identification thread, as [`identify`](Self::identify) is.
    pub(crate) fn identify_jarm(&self, found: &str) -> Option<Evidence> {
        self.warm(&self.jarm_signatures);
        on_the_matching_thread(|| {
            best_match_within(
                self,
                &self.jarm_signatures,
                &[found],
                crate::model::host::OsSource::ServiceBanner,
            )
        })
    }

    /// The instruction set the corpus reads out of `text`, where it reads one.
    ///
    /// Seven rules exist for this (`x64|amd64|x86_64` against a `uname` banner).
    /// They state no product, family or vendor, so they are asked directly.
    ///
    /// The most specific match wins, so `x86_64` beats the `x86` rule inside it.
    ///
    /// [`None`] where the text names no architecture.
    ///
    /// Matched on the identification thread, as [`identify`](Self::identify) is.
    pub(crate) fn architecture_of(&self, text: &str) -> Option<String> {
        self.warm(&self.architecture_signatures);

        on_the_matching_thread(|| {
            self.architecture_signatures
                .iter()
                .filter_map(|&idx| {
                    self.signature(idx)?
                        .identify(text, crate::model::host::OsSource::ServiceBanner)
                })
                .reduce(|best, m| {
                    if m.quality.specificity() > best.quality.specificity() {
                        m
                    } else {
                        best
                    }
                })
        })?
        .arch
    }

    /// The primary service name registered for `port`, if any. No compilation.
    pub fn service_name(&self, port: u16) -> Option<Arc<str>> {
        self.name_index.get(&port).cloned()
    }

    /// Every port some service registers, in no particular order.
    ///
    /// What this engine can name, which differs from what a scan asks about.
    /// Exposed so the two can be checked against each other.
    pub fn indexed_ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.name_index.keys().copied()
    }

    /// The application protocol `service` is carried over, where the corpus
    /// says it is carried over one.
    ///
    /// A tunnel scheme (`ssl/http`) is stripped before the lookup.
    pub fn speaks(&self, service: &str) -> Option<&str> {
        let (_, bare) = Tunnel::split_label(service);
        self.speaks.get(bare).map(|protocol| &**protocol)
    }

    /// Whether an observation filed under `other` can describe the software
    /// behind `service`.
    ///
    /// Two names agree when they are the same, when one is carried over the other
    /// (Grafana over HTTP), or when either is not a protocol any port is
    /// registered or probed for. The last covers rules filed under the text they
    /// read: a certificate subject under `x509`, an icon digest under
    /// `favicons.xml`, a `Server` header's modules under `apache`.
    ///
    /// Two protocols carried over the same third do not agree: an Elasticsearch
    /// rule firing on a Grafana port disagrees.
    pub(crate) fn agree(&self, service: &str, other: &str) -> bool {
        let carried_over = |inner: &str, outer: &str| {
            self.speaks
                .get(inner)
                .is_some_and(|protocol| &**protocol == outer)
        };
        service == other
            || !self.protocols.contains(service)
            || !self.protocols.contains(other)
            || carried_over(service, other)
            || carried_over(other, service)
    }

    /// The TCP probes to send to a port that registers none of its own.
    ///
    /// See [`Probe::generic`](crate::fingerprint::signature::Probe::generic).
    pub fn generic_tcp_probe_payloads(&self) -> &[Vec<u8>] {
        &self.generic_tcp_probes
    }

    /// The TCP probes worth putting to `port` that no service registered for
    /// it, within `intensity`, likeliest first.
    ///
    /// What a scan asks a port that stayed silent. The port's own probes are
    /// excluded, since they were already sent.
    ///
    /// Empty at intensity 0, which is every level below
    /// [`ServiceDetection::Probe`](crate::config::ServiceDetection::Probe).
    pub fn universal_tcp_probe_payloads(&self, port: u16, intensity: u8) -> Vec<&[u8]> {
        if intensity == 0 {
            return Vec::new();
        }

        let registered = self.tcp_probe_payloads(port);
        self.universal_tcp_probes
            .iter()
            .filter(|(rarity, _)| *rarity <= intensity)
            .map(|(_, payload)| payload.as_slice())
            .filter(|payload| !registered.iter().any(|sent| sent.as_slice() == *payload))
            .collect()
    }

    /// The signature indices matchable on `port` (service-linked). Empty if no
    /// service registers the port.
    pub fn signatures_for_port(&self, port: u16) -> &[usize] {
        self.by_port.get(&port).map_or(&[], Vec::as_slice)
    }

    /// The signature at `idx`, or `None` past the end of the set.
    ///
    /// Crate-visible: [`Signature`] is not public; callers use
    /// [`identify`](Self::identify).
    pub(crate) fn signature(&self, idx: usize) -> Option<&Signature> {
        self.signatures.get(idx)
    }

    /// The TCP active-probe payloads registered for `port` (service-linked), as
    /// decoded bytes ready to send, in the order they are asked: the services
    /// that name the port first, then those that share it.
    pub fn tcp_probe_payloads(&self, port: u16) -> &[Vec<u8>] {
        self.tcp_probes
            .get(&port)
            .map_or(&[], |conversations| conversations.payloads.as_slice())
    }

    /// [`tcp_probe_payloads`](Self::tcp_probe_payloads), one run per service, each
    /// to be sent on its own connection; see [`Conversations`].
    pub(crate) fn tcp_probe_conversations(&self, port: u16) -> impl Iterator<Item = &[Vec<u8>]> {
        self.tcp_probes
            .get(&port)
            .into_iter()
            .flat_map(Conversations::each)
    }

    /// Whether every service reachable on `port` waits to be asked, so its
    /// probes go out without first listening for a greeting.
    ///
    /// Normally a port is listened to first, since some services drop a client
    /// that speaks before their greeting. HTTP never greets, so a port where
    /// every service speaks HTTP is asked at once. A port shared with any other
    /// service is listened to first.
    pub(crate) fn asked_first(&self, port: u16) -> bool {
        self.asked_first.contains(&port)
    }

    /// The UDP probe payloads registered for `port` (service-linked), as decoded
    /// bytes ready to send.
    ///
    /// Empty where no service registers a UDP probe; a scanner then sends an
    /// empty datagram, which draws an ICMP error from a closed port but rarely a
    /// reply from an open one.
    pub fn udp_probe_payloads(&self, port: u16) -> &[Vec<u8>] {
        self.udp_probes.get(&port).map_or(&[], Vec::as_slice)
    }

    /// The global-match prefilter, built (over the whole set) on first use and
    /// cached. Building parses each pattern for literals; it compiles no
    /// regexes.
    ///
    /// Crate-visible: the prefilter type is private.
    pub(crate) fn prefilter(&self) -> &LiteralPrefilter {
        self.prefilter
            .get_or_init(|| LiteralPrefilter::build(&self.signatures))
    }

    /// Forces the regexes of `indices` to compile, in parallel. Idempotent, since
    /// already-compiled signatures are untouched, so a candidate set can be warmed
    /// before matching to spread compilation across cores.
    ///
    /// Crate-visible: [`identify`](Self::identify) already warms what it matches.
    pub(crate) fn warm(&self, indices: &[usize]) {
        indices
            .par_iter()
            .for_each(|&idx| self.signatures[idx].compile());
    }

    /// Deserializes the embedded definitions afresh. Used by the corpus tests to
    /// reach the recorded `example` banners the runtime signatures drop.
    #[cfg(test)]
    pub(crate) fn embedded_definitions() -> Vec<ServiceDefinition> {
        bincode::deserialize(EMBEDDED_DB)
            .expect("embedded fingerprint database failed to deserialize")
    }
}

/// Evidence from the **most specific** signature in `indices` that identifies any
/// of `texts`, by [`MatchQuality`](super::matcher::MatchQuality).
///
/// Every candidate is evaluated, so a generic signature listed earlier (a bare
/// `HTTP/1.1`) cannot shadow a more specific one. Ties keep the earliest text
/// and the lowest index. Candidate sets are bounded.
///
/// For the same reason all `texts` are tried: the whole line may match a loose
/// family rule while the extracted field matches the release rule.
fn best_match(
    db: &SignatureDb,
    indices: &[usize],
    texts: &[&str],
    attested_by: crate::model::host::OsSource,
) -> Option<Evidence> {
    let found = best_match_within(db, indices, texts, attested_by)?;

    // Fill in what `canonical_os_name` knows about the winner's OS name
    // (usually the family); the merge only adds. See `os::canonicalise`.
    let os = found.os.map(|evidence| {
        let canonical = evidence
            .product
            .as_deref()
            .and_then(|product| db.canonical_os_name(product));
        match canonical {
            Some(canonical) => super::os::canonicalise(evidence, &canonical),
            None => evidence,
        }
    });

    Some(Evidence { os, ..found })
}

/// [`best_match`] without the canonical-name stage, which is what that stage
/// itself runs on.
///
/// Split out so the canonical-name stage, which matches its own output, cannot
/// recurse.
fn best_match_within(
    db: &SignatureDb,
    indices: &[usize],
    texts: &[&str],
    attested_by: crate::model::host::OsSource,
) -> Option<Evidence> {
    let matched: Vec<super::matcher::Match> = texts
        .iter()
        .flat_map(|text| {
            indices
                .iter()
                .filter_map(move |&idx| db.signature(idx)?.identify(text, attested_by))
        })
        .collect();

    // Replace only on a strictly better match, so the earliest text and the
    // lowest index win ties.
    let service = matched
        .iter()
        .reduce(|best, m| if m.quality > best.quality { m } else { best })?;

    // See `resolved_service_name`.
    let service_name = super::matcher::resolved_service_name(service, &matched);

    // Chosen separately from the service: a rule pinning `OpenSSH_9.2p1` exactly
    // outranks one that also names Debian 12, so the OS reading comes from the
    // most complete match instead.
    let os = matched
        .iter()
        .filter_map(|m| m.os.as_ref())
        .reduce(|best, os| {
            if os_detail(os) > os_detail(best) {
                os
            } else {
                best
            }
        })
        .cloned();

    // See `Match::arch`. The dedicated rules are asked first; a service rule's
    // captured architecture is less reliable (one read the distribution out of a
    // Debian `uname`).
    let arch = texts
        .iter()
        .find_map(|text| db.architecture_of(text))
        .or_else(|| {
            matched
                .iter()
                .filter(|m| m.arch.is_some())
                .reduce(|best, m| {
                    if m.quality.specificity() > best.quality.specificity() {
                        m
                    } else {
                        best
                    }
                })
                .and_then(|m| m.arch.clone())
        });
    let os = os.map(|evidence| OsEvidence {
        arch: evidence.arch.or(arch),
        ..evidence
    });

    // Merged: two rules may each name a different part of the box.
    let hardware = matched
        .iter()
        .filter_map(|m| m.hardware.as_ref())
        .cloned()
        .reduce(|mut best, other| {
            best.merge(other);
            best
        });

    // Merged across matches of the winner's product: a generic rule reads the
    // revision from an OpenSSH comment, a specific rule knows the release.
    let winner_product = service.evidence.product.as_deref();
    let mut build = matched
        .iter()
        .filter(|m| {
            m.evidence.product.as_deref().is_none()
                || m.evidence
                    .product
                    .as_deref()
                    .zip(winner_product)
                    .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
        })
        .filter_map(|m| m.evidence.build.clone())
        .reduce(|mut best, other| {
            best.merge(other);
            best
        });

    // The OS reading's release completes a build of the same distributor that
    // lacks one: a rule mapping `OpenSSH_6.6.1p1 Ubuntu-2` to Ubuntu 14.04 names
    // the release that shipped the package.
    if let (Some(held), Some(os)) = (build.as_mut(), os.as_ref())
        && held.release().is_none()
        && let Some(release) = os
            .vendor
            .as_deref()
            .and_then(crate::model::port::Distributor::from_name)
            .filter(|&vendor| vendor == held.distributor())
            .zip(os.version.as_deref())
            .and_then(|(vendor, version)| {
                crate::model::port::build::normalised_release(vendor, version)
            })
    {
        *held = held.clone().with_release(crate::model::port::Release::new(
            release,
            crate::model::port::ReleaseBasis::Banner,
        ));
    }

    Some(Evidence {
        os,
        hardware,
        build,
        service: service_name,
        ..service.evidence.clone()
    })
}

/// How much of the identity path an operating-system reading fills in.
///
/// Ranks readings against each other only. Where two say the same amount the
/// first stands.
///
/// Count every field, including new ones; an uncounted field cannot win its
/// rule the ranking.
pub(super) fn os_detail(os: &crate::model::host::OsEvidence) -> u8 {
    u8::from(os.version.is_some())
        + u8::from(os.kernel.is_some())
        + u8::from(os.product.is_some())
        + u8::from(os.vendor.is_some())
        + u8::from(os.cpe.is_some())
}

/// Everything one banner yields: the evidence, and whether the signature that
/// named the service was registered for this port.
///
/// Text extraction, both tiers, and the separate choice of service and
/// operating-system readings. `analyze` loops around it, and tests call it
/// directly so they exercise the real path.
fn identify_within(
    db: &SignatureDb,
    port_signatures: &[usize],
    banner: &str,
    attested_by: crate::model::host::OsSource,
) -> Option<Evidence> {
    // Owned: a field is not always a slice of the banner.
    let extracted = super::extract::texts(banner);
    let texts: Vec<&str> = extracted.iter().map(AsRef::as_ref).collect();

    // The prefilter's candidates for each text, unioned.
    let mut candidates: Vec<usize> = texts
        .iter()
        .flat_map(|text| db.prefilter().candidates(text))
        .collect();
    candidates.sort_unstable();
    candidates.dedup();

    // The port's signatures, port-confirmed, limited to the prefilter's
    // candidates so a busy port (every web product on 80) does not compile most
    // of the corpus. Port order is kept for tie-breaking.
    let port_candidates: Vec<usize> = port_signatures
        .iter()
        .copied()
        .filter(|index| candidates.binary_search(index).is_ok())
        .collect();
    db.warm(&port_candidates);
    let mut found = best_match(db, &port_candidates, &texts, attested_by);
    let mut port_confirmed = found.is_some();

    // The global set, when the port set identified nothing or said nothing
    // about the machine. Compilation is cached per signature.
    if found.as_ref().is_none_or(|found| found.os.is_none()) {
        db.warm(&candidates);
        if let Some(global) = best_match(db, &candidates, &texts, attested_by) {
            match found.as_mut() {
                // Keep the port-confirmed service; take only the OS reading.
                Some(found) => found.os = global.os,
                None => {
                    found = Some(global);
                    port_confirmed = false;
                }
            }
        }
    }

    found.map(|mut found| {
        found.port_confirmed = port_confirmed;
        found
    })
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::signature::{DefinitionError, MatchRule, Probe, ServiceSignature};
    use crate::model::host::OsSource;
    use std::collections::BTreeMap;

    fn def(name: &str, ports: Vec<u16>, patterns: &[&str]) -> ServiceDefinition {
        speaking(name, ports, patterns, None)
    }

    /// A definition carrying one TCP probe at a given rarity.
    fn probed(name: &str, ports: Vec<u16>, payload: &str, rarity: u8) -> ServiceDefinition {
        let mut definition = def(name, ports, &["^X"]);
        definition.probe = vec![Probe {
            name: None,
            payload: payload.to_string(),
            protocol: "tcp".into(),
            rarity,
            generic: false,
        }];
        definition
    }

    /// A definition that declares what it is carried over.
    fn speaking(
        name: &str,
        ports: Vec<u16>,
        patterns: &[&str],
        speaks: Option<&str>,
    ) -> ServiceDefinition {
        ServiceDefinition {
            service: ServiceSignature {
                name: name.to_string(),
                default_ports: ports,
                shared_ports: Vec::new(),
                description: None,
                attribution: None,
                speaks: speaks.map(str::to_owned),
            },
            probe: Vec::new(),
            r#match: patterns
                .iter()
                .map(|p| MatchRule {
                    name: None,
                    pattern: p.to_string(),
                    version_group: None,
                    vendor: None,
                    product: None,
                    context: None,
                    example: None,
                    metadata: None,
                })
                .collect(),
        }
    }

    fn db() -> SignatureDb {
        SignatureDb::from_defs(vec![
            def("http", vec![80, 8080], &["^HTTP/1", "^Server:"]),
            def("https", vec![443], &["^TLS"]),
            def("http-alt", vec![80], &["^HTX"]),
        ])
    }

    /// The tunnel scheme is stripped before the lookup.
    #[test]
    fn a_tunnelled_label_speaks_what_the_service_inside_it_speaks() {
        let db = SignatureDb::from_defs(vec![
            speaking("http", vec![80], &["^HTTP/1"], Some("http")),
            speaking("redis", vec![6379], &["^-ERR"], None),
        ]);

        assert_eq!(db.speaks("http"), Some("http"));
        assert_eq!(db.speaks("ssl/http"), Some("http"));
        assert_eq!(db.speaks("redis"), None);
        assert_eq!(db.speaks("ssl/redis"), None);
        assert_eq!(db.speaks("nothing-here"), None);
    }

    /// An application agrees with its carrier protocol, two applications over
    /// the same protocol do not agree, and a name no port speaks agrees with
    /// everything.
    #[test]
    fn services_agree_through_what_carries_them_and_not_through_a_sibling() {
        let db = SignatureDb::global();
        assert!(db.agree("grafana", "http"));
        assert!(db.agree("http", "grafana"));
        assert!(!db.agree("grafana", "elasticsearch"));
        assert!(!db.agree("kerberos", "lpd"));
        assert!(!db.agree("ftp", "smtp"));
        assert!(db.agree("http", "x509"));
        assert!(db.agree("http", "favicons.xml"));
        assert!(db.agree("http", "apache"));
    }

    #[test]
    fn name_index_is_first_claimant() {
        let db = db();
        assert_eq!(db.service_name(80).as_deref(), Some("http"));
        assert_eq!(db.service_name(443).as_deref(), Some("https"));
        assert!(db.service_name(22).is_none());
    }

    /// A rarity of zero (the default) keeps a probe on its own ports.
    #[test]
    fn only_an_authored_rarity_reaches_a_port_that_did_not_register_it() {
        let db = SignatureDb::from_defs(vec![
            probed("redis", vec![6379], "PING\r\n", 1),
            probed("oracle", vec![1521], "\x00\x1a", 7),
            probed("mysql", vec![3306], "\x0a", 0),
        ]);

        let at_default: Vec<&[u8]> = db.universal_tcp_probe_payloads(8443, 1);
        assert_eq!(at_default, vec![b"PING\r\n".as_slice()]);

        // Higher intensity reaches rarer probes, never zero-rarity ones.
        let thorough = db.universal_tcp_probe_payloads(8443, 9);
        assert_eq!(thorough.len(), 2, "{thorough:?}");
        assert!(!thorough.contains(&b"\x0a".as_slice()));

        assert!(db.universal_tcp_probe_payloads(8443, 0).is_empty());
    }

    /// A port's own probe is not asked twice.
    #[test]
    fn a_ports_own_probe_is_not_offered_back_to_it() {
        let db = SignatureDb::from_defs(vec![probed("redis", vec![6379], "PING\r\n", 1)]);

        assert!(db.universal_tcp_probe_payloads(6379, 9).is_empty());
        assert_eq!(db.universal_tcp_probe_payloads(6380, 9).len(), 1);
    }

    /// A port's own service is asked before one that only shares it, however
    /// the corpus happens to be laid out, and each is asked apart.
    ///
    /// 1080 in the shipped corpus: SOCKS5 names it, SOCKS4 shares it, and the
    /// SOCKS4 file sorts first.
    #[test]
    fn a_ports_own_service_is_asked_before_one_that_shares_it() {
        let mut sharer = probed("socks4", Vec::new(), "four", 0);
        sharer.service.shared_ports = vec![1080];
        let owner = probed("socks5", vec![1080], "five", 0);
        let db = SignatureDb::from_defs(vec![sharer, owner]);

        let asked: Vec<&[Vec<u8>]> = db.tcp_probe_conversations(1080).collect();
        assert_eq!(asked, [&[b"five".to_vec()][..], &[b"four".to_vec()][..]]);
        assert_eq!(
            db.tcp_probe_payloads(1080),
            [b"five".to_vec(), b"four".to_vec()]
        );
    }

    #[test]
    fn port_index_is_service_linked() {
        let db = SignatureDb::from_defs(vec![
            def("ssh", vec![22], &["^SSH-2", "^SSH-1"]), // 2 signatures, ported
            def("ssh", vec![], &["^SSH banner"]),        // port-less supplementary
            def("http", vec![80], &["^HTTP/1"]),
        ]);
        // Port 22 links both `ssh` definitions: 2 + 1 = 3 signatures.
        assert_eq!(db.signatures_for_port(22).len(), 3);
        assert_eq!(db.signatures_for_port(80).len(), 1);
        assert!(db.signatures_for_port(9999).is_empty());
    }

    #[test]
    fn signatures_identify_through_the_index() {
        let db = db();
        let hit = db.signatures_for_port(80).iter().find_map(|&i| {
            db.signature(i)?
                .identify("HTTP/1.1 200 OK", OsSource::ServiceBanner)
        });
        assert_eq!(
            hit.and_then(|m| m.evidence.service),
            Some("http".to_string())
        );
    }

    /// Every port this engine can name a service on is a port it asks about by
    /// default.
    ///
    /// `assets/fingerprinting/` says what can be identified and
    /// [`catalog`](crate::model::port::catalog) what gets probed; a signature on a
    /// port outside the catalogue never matches. Both transports' halves are
    /// taken together, since a definition's ports carry no transport.
    #[test]
    fn every_port_with_a_signature_is_a_port_the_default_scan_reaches() {
        use crate::model::port::catalog::{
            SCTP_BY_PREVALENCE, TCP_BY_PREVALENCE, UDP_BY_PREVALENCE,
        };

        let probed: std::collections::HashSet<u16> = TCP_BY_PREVALENCE
            .iter()
            .chain(UDP_BY_PREVALENCE.iter())
            .chain(SCTP_BY_PREVALENCE.iter())
            .copied()
            .collect();

        let unreachable: Vec<u16> = SignatureDb::global()
            .indexed_ports()
            .filter(|port| !probed.contains(port))
            .collect();

        assert!(
            unreachable.is_empty(),
            "these ports have signatures but no default scan reaches them, so the \
             signatures can never match: {unreachable:?}. Add them to the catalogue, \
             or drop the signature."
        );
    }

    /// The shipped database has a generic probe, whichever file holds it.
    #[test]
    fn the_shipped_database_carries_a_generic_probe() {
        let generic = SignatureDb::global().generic_tcp_probe_payloads();

        assert!(
            !generic.is_empty(),
            "no probe is marked generic, so every unrecognised port is asked nothing"
        );
        assert!(
            generic.len() <= 2,
            "a generic probe is sent to every unrecognised port of every scan; \
             {} of them is a cost that wants an argument",
            generic.len()
        );
        assert!(
            generic
                .iter()
                .any(|payload| payload.starts_with(b"GET / HTTP/")),
            "the one question worth asking of an unknown port is an HTTP request"
        );
    }

    /// Generic probes are TCP only, as the build enforces.
    #[test]
    fn a_generic_udp_probe_is_not_indexed_as_generic() {
        let mut def = def("weird", vec![9999], &["^X"]);
        def.probe = vec![Probe {
            name: Some("nope".into()),
            payload: "ping".into(),
            protocol: "udp".into(),
            rarity: 0,
            generic: true,
        }];

        assert!(
            SignatureDb::from_defs(vec![def])
                .generic_tcp_probe_payloads()
                .is_empty()
        );
    }

    /// Caller-authored definitions load and match.
    #[test]
    fn a_caller_can_load_signatures_of_their_own() {
        let db =
            SignatureDb::try_from_definitions(vec![def("acme", vec![9999], &[r"^ACME/([\d.]+)"])])
                .expect("a well-formed definition");

        assert_eq!(db.service_name(9999).as_deref(), Some("acme"));
        let hit = db.signatures_for_port(9999).iter().find_map(|&i| {
            db.signature(i)?
                .identify("ACME/2.1", OsSource::ServiceBanner)
        });
        assert_eq!(
            hit.and_then(|m| m.evidence.service),
            Some("acme".to_string())
        );
    }

    /// **A port's signatures are compiled only where the response could match
    /// them, and the port still answers as it did.**
    ///
    /// Compiled rules and their caches live for the process, so a busy port must
    /// not compile its whole list.
    #[test]
    fn a_ports_signatures_are_compiled_only_where_the_response_could_match() {
        let db = SignatureDb::try_from_definitions(vec![
            def("acme", vec![9999], &[r"^ACME/([\d.]+)"]),
            def("zenith", vec![9999], &[r"^ZENITH/([\d.]+)"]),
        ])
        .expect("well-formed definitions");

        let found = db
            .identify(9999, Protocol::Tcp, "ACME/2.1")
            .expect("the port names it");
        assert_eq!(found.service.as_deref(), Some("acme"));
        assert!(found.port_confirmed, "by the port's own signature");

        let compiled: Vec<bool> = db
            .signatures_for_port(9999)
            .iter()
            .map(|&index| db.signature(index).expect("a signature").is_compiled())
            .collect();
        assert_eq!(compiled, [true, false], "ZENITH is nowhere in the response");
    }

    /// A definition that would fail the build fails here.
    #[test]
    fn the_checks_are_the_ones_the_build_makes() {
        // A pattern neither engine compiles.
        let refused = SignatureDb::try_from_definitions(vec![def("broken", vec![1], &["("])])
            .expect_err("an unclosed group is a syntax error in both engines");
        assert!(
            matches!(refused.error, DefinitionError::Pattern { rule: 0, .. }),
            "{:?}",
            refused.error
        );
        assert_eq!(refused.service, "broken");

        // A version group the pattern has no group for.
        let mut d = def("versioned", vec![2], &["^HELLO"]);
        d.r#match[0].version_group = Some(1);
        let refused =
            SignatureDb::try_from_definitions(vec![d]).expect_err("the pattern captures nothing");
        assert_eq!(
            refused.error,
            DefinitionError::VersionGroup {
                rule: 0,
                group: 1,
                available: 0
            }
        );

        // A transport nothing speaks.
        let mut d = def("odd", vec![3], &["^X"]);
        d.probe = vec![Probe {
            name: None,
            payload: "hello".into(),
            protocol: "sctp".into(),
            rarity: 0,
            generic: false,
        }];
        let refused =
            SignatureDb::try_from_definitions(vec![d]).expect_err("sctp is not a transport here");
        assert_eq!(
            refused.error,
            DefinitionError::ProbeProtocol {
                probe: 0,
                protocol: "sctp".into()
            }
        );

        // A generic probe over UDP.
        let mut d = def("weird", vec![4], &["^X"]);
        d.probe = vec![Probe {
            name: None,
            payload: "ping".into(),
            protocol: "udp".into(),
            rarity: 0,
            generic: true,
        }];
        let refused = SignatureDb::try_from_definitions(vec![d])
            .expect_err("generic only means anything over TCP");
        assert_eq!(
            refused.error,
            DefinitionError::GenericProbeNotTcp {
                probe: 0,
                protocol: "udp".into()
            }
        );

        // An empty UDP payload cannot elicit a reply.
        let mut d = def("silent", vec![5], &["^X"]);
        d.probe = vec![Probe {
            name: None,
            payload: String::new(),
            protocol: "udp".into(),
            rarity: 0,
            generic: false,
        }];
        let refused = SignatureDb::try_from_definitions(vec![d])
            .expect_err("an empty datagram draws nothing");
        assert_eq!(
            refused.error,
            DefinitionError::UdpProbeSize { probe: 0, bytes: 0 }
        );
    }

    /// The canonical stage fills in the family a service rule could not state,
    /// and leaves the release it did state alone.
    ///
    /// The rule reading `Windows Server 2008 R2 Standard 7601 Service Pack 1`
    /// names no family; the canonical stage supplies `Windows`.
    #[test]
    fn a_canonical_name_supplies_the_family_and_keeps_the_release() {
        let found = SignatureDb::global()
            .identify(
                445,
                Protocol::Tcp,
                "Windows Server 2008 R2 Standard 7601 Service Pack 1",
            )
            .expect("the corpus names it");
        let os = found.os.expect("it says something about the machine");

        assert_eq!(os.family.as_deref(), Some("Windows"));
        assert_eq!(
            os.product.as_deref(),
            Some("Windows Server 2008 R2"),
            "the release the service reported must survive the stage"
        );
    }

    /// The family is what the stage is consulted for, and it is the same one for
    /// every release in a line.
    ///
    /// So two Windows machines on different releases agree on the family.
    #[test]
    fn every_windows_release_canonicalises_to_one_family() {
        let db = SignatureDb::global();
        for name in [
            "Windows Server 2008",
            "Windows Server 2012 R2",
            "Windows 7",
            "Windows XP",
            "Windows 10",
        ] {
            let canonical = db
                .canonical_os_name(name)
                .unwrap_or_else(|| panic!("{name} is not recognised"));
            assert_eq!(
                canonical.family.as_deref(),
                Some("Windows"),
                "{name} canonicalised to a different family"
            );
        }
    }

    /// A product that is not an operating system is left alone.
    #[test]
    fn a_product_that_is_not_an_operating_system_is_not_canonicalised() {
        let db = SignatureDb::global();
        for product in ["nginx", "OpenSSH", "Grafana", "NC-8700w"] {
            assert!(
                db.canonical_os_name(product).is_none(),
                "{product} was read as an operating system"
            );
        }
    }

    /// An architecture reaches the reading even though the rule that named it
    /// named nothing else.
    ///
    /// It is collected and filled into whichever reading won.
    #[test]
    fn an_architecture_is_collected_from_a_rule_that_named_nothing_else() {
        let found = SignatureDb::global()
            .identify(
                161,
                Protocol::Udp,
                "Linux zond 6.1.0-18-arm64 #1 SMP Debian 6.1.76-1 (2024-02-01) x86_64",
            )
            .expect("the corpus names it");
        let os = found.os.expect("it says something about the machine");

        assert_eq!(
            os.family.as_deref(),
            Some("Linux"),
            "the reading is unchanged"
        );
        assert_eq!(
            os.arch.as_deref(),
            Some("x86_64"),
            "and carries the architecture a separate rule named"
        );
    }

    /// A version is what a pattern captured, without the line ending or the
    /// padding a greeting carried around it.
    ///
    /// A group running to the end of the line captures the CR; one stopping at a
    /// parenthesis captures the space before it.
    #[test]
    fn a_captured_version_keeps_no_surrounding_whitespace() {
        let db = SignatureDb::global();
        for (port, banner, expected) in [
            (25, "220 mail.example ESMTP MailSrv 2.1\r\n", "MailSrv 2.1"),
            (
                21,
                "220 ProFTPD 1.3.5e Server (Debian) [192.0.2.1]\r\n",
                "1.3.5e",
            ),
        ] {
            let found = db
                .identify(port, Protocol::Tcp, banner)
                .expect("the corpus names it");
            assert_eq!(found.version.as_deref(), Some(expected), "for {banner:?}");
        }
    }

    /// ProFTPD's greeting yields product and release separately. A server hiding
    /// its release is still named, with no version.
    #[test]
    fn a_proftpd_greeting_names_the_product_and_its_release() {
        let db = SignatureDb::global();
        for (banner, version, cpe) in [
            (
                "220 ProFTPD 1.3.5e Server (Debian) [192.0.2.1]\r\n",
                Some("1.3.5e"),
                Some("cpe:/a:proftpd:proftpd:1.3.5e"),
            ),
            (
                "220 ProFTPD Server (Debian) [192.0.2.1]\r\n",
                None,
                Some("cpe:/a:proftpd:proftpd:-"),
            ),
        ] {
            let found = db
                .identify(21, Protocol::Tcp, banner)
                .expect("the corpus names it");
            assert_eq!(found.product.as_deref(), Some("ProFTPD"), "for {banner:?}");
            assert_eq!(found.version.as_deref(), version, "for {banner:?}");
            assert_eq!(found.cpe.as_deref(), cpe, "for {banner:?}");
        }
    }

    /// **A file-transfer or mail greeting names its daemon, and its release
    /// apart from it, for every common daemon**, from the greeting as it
    /// arrives.
    #[test]
    fn a_file_transfer_or_mail_greeting_names_its_daemon_and_its_release() {
        let db = SignatureDb::global();
        for (port, banner, product, version, cpe) in [
            (
                21,
                "220 (vsFTPd 3.0.5)\r\n",
                "vsFTPd",
                Some("3.0.5"),
                Some("cpe:/a:vsftpd_project:vsftpd:3.0.5"),
            ),
            (
                21,
                "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n\
                 220-You are user number 1 of 50 allowed.\r\n\
                 220 This is a private system - No anonymous login\r\n",
                "Pure-FTPd",
                None,
                Some("cpe:/a:pureftpd:pure-ftpd:-"),
            ),
            (
                21,
                "220-FileZilla Server 1.8.0\r\n\
                 220 Please visit https://filezilla-project.org/\r\n",
                "FileZilla Server",
                Some("1.8.0"),
                Some("cpe:/a:filezilla-project:filezilla_server:1.8.0"),
            ),
            (
                21,
                "220 Microsoft FTP Service\r\n",
                "IIS",
                None,
                Some("cpe:/a:microsoft:internet_information_services:-"),
            ),
            (
                25,
                "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n",
                "Postfix",
                None,
                Some("cpe:/a:postfix:postfix:-"),
            ),
            (
                25,
                "220 mail.example.com ESMTP Exim 4.96 Mon, 01 Jan 2024 00:00:00 +0000\r\n",
                "exim",
                Some("4.96"),
                Some("cpe:/a:exim:exim:4.96"),
            ),
            (
                25,
                "220 mail.example.com ESMTP Sendmail 8.15.2/8.15.2; \
                 Mon, 1 Jan 2024 00:00:00 +0000\r\n",
                "Sendmail",
                Some("8.15.2"),
                Some("cpe:/a:sendmail:sendmail:8.15.2"),
            ),
        ] {
            let found = db
                .identify(port, Protocol::Tcp, banner)
                .expect("the corpus names it");
            let named = (
                found.product.as_deref(),
                found.version.as_deref(),
                found.cpe.as_deref(),
            );
            assert_eq!(named, (Some(product), version, cpe), "for {banner:?}");
        }
    }

    /// `x86` matches inside `x86_64`; the longer read wins.
    #[test]
    fn the_more_specific_architecture_wins() {
        let db = SignatureDb::global();
        for (banner, expected) in [
            ("Linux host 6.1.0 x86_64", "x86_64"),
            ("Linux host 2.6.32 i686", "x86"),
        ] {
            let arch = db
                .identify(161, Protocol::Udp, banner)
                .and_then(|found| found.os)
                .and_then(|os| os.arch);
            assert_eq!(arch.as_deref(), Some(expected), "for {banner:?}");
        }
    }

    /// A rule stating family and product as the same word (Linux, AIX) is
    /// untouched.
    #[test]
    fn a_family_that_is_honestly_the_product_is_left_alone() {
        let canonical = SignatureDb::global()
            .canonical_os_name("Linux")
            .expect("the os-name rules recognise it");
        assert_eq!(canonical.family.as_deref(), Some("Linux"));
        assert_eq!(canonical.product.as_deref(), Some("Linux"));
    }

    /// The canonical stage does not recurse.
    #[test]
    fn the_canonical_stage_does_not_call_itself() {
        for name in [
            "Windows Server 2008",
            "Linux",
            "Mac OS X",
            "not an os at all",
        ] {
            let _ = SignatureDb::global().canonical_os_name(name);
        }
    }

    /// No port number is owned twice across the shipped corpus.
    ///
    /// The index keeps the first claim in sorted-path order, so a second claim
    /// would lose silently. Any number of `shared_ports` claims are allowed.
    #[test]
    fn no_two_services_own_the_same_port() {
        let definitions = SignatureDb::embedded_definitions();
        let mut owners: BTreeMap<u16, BTreeSet<&str>> = BTreeMap::new();
        for def in &definitions {
            for &port in &def.service.default_ports {
                owners
                    .entry(port)
                    .or_default()
                    .insert(def.service.name.as_str());
            }
        }

        let contested: Vec<String> = owners
            .iter()
            .filter(|(_, names)| names.len() > 1)
            .map(|(port, names)| {
                format!(
                    "{port} claimed by {}",
                    names.iter().copied().collect::<Vec<_>>().join(", ")
                )
            })
            .collect();

        assert!(
            contested.is_empty(),
            "a port may be owned by one service: {}. Move it to shared_ports in \
             every definition that does not own the number.",
            contested.join("; ")
        );
    }

    /// A shared port reaches the service's rules and probes without taking its
    /// name.
    #[test]
    fn a_shared_port_is_matched_but_not_named() {
        let db = SignatureDb::global();

        assert_eq!(db.service_name(8080).as_deref(), Some("http"));
        assert!(
            db.signatures_for_port(8080).len()
                > db.signatures_for_port(3128).len().saturating_sub(1),
            "8080 carries Squid's rules as well as HTTP's"
        );
        assert!(
            !db.tcp_probe_payloads(8080)
                .iter()
                .any(|p| p.starts_with(b"GET http://")),
            "no probe asks a proxy to fetch a third-party URL"
        );

        assert_eq!(db.service_name(3000).as_deref(), None);
        assert_eq!(db.tcp_probe_payloads(3000).len(), 2);
    }

    /// Everything the build compiled passes the build's own check.
    #[test]
    fn every_shipped_definition_satisfies_the_shared_check() {
        for (index, def) in SignatureDb::embedded_definitions().iter().enumerate() {
            assert!(
                def.validate().is_ok(),
                "shipped definition {index} ('{}') would be refused: {:?}",
                def.service.name,
                def.validate()
            );
        }
    }

    /// The message names the definition.
    #[test]
    fn the_refusal_names_which_definition_and_why() {
        let refused = SignatureDb::try_from_definitions(vec![
            def("fine", vec![1], &["^OK"]),
            def("broken", vec![2], &["("]),
        ])
        .expect_err("the second definition is unusable");

        let message = refused.to_string();
        assert!(message.contains("definition 1"), "{message}");
        assert!(message.contains("broken"), "{message}");
        assert!(message.contains("unusable pattern"), "{message}");
    }

    #[test]
    fn unescape_decodes_common_sequences() {
        assert_eq!(unescape(r"GET /\r\n"), b"GET /\r\n");
        assert_eq!(unescape(r"a\tb\0c"), b"a\tb\0c");
        assert_eq!(unescape(r"\x00\xff\x1b"), &[0x00, 0xff, 0x1b]);
        assert_eq!(unescape(r"c:\path"), br"c:\path"); // unknown escape kept literal
        assert_eq!(unescape(r"\\n"), br"\n"); // escaped backslash, then literal n
    }

    #[test]
    fn probe_payloads_are_decoded_to_wire_bytes() {
        let mut d = def("http", vec![80], &["^HTTP/1"]);
        d.probe = vec![Probe {
            name: None,
            payload: r"GET / HTTP/1.1\r\n\r\n".to_string(),
            protocol: "tcp".to_string(),
            rarity: 0,
            generic: false,
        }];
        let db = SignatureDb::from_defs(vec![d]);
        // The authored `\r\n` reaches the wire as CRLF.
        assert_eq!(
            db.tcp_probe_payloads(80),
            &[b"GET / HTTP/1.1\r\n\r\n".to_vec()]
        );
    }
}
