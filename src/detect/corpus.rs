// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The detections a scan runs
//!
//! A [`Detections`] is the corpus the detection phase draws on: the Tier-1
//! [flows](super::flow), the Tier-2 [compute modules](super::compute), and the
//! host correlations, compiled and ready to run. The default is the corpus this
//! build ships, embedded from `assets/detect/`; a caller adds their own with a
//! [builder](DetectionsBuilder) and passes the result to
//! [`scan`](crate::scanner::scan).
//!
//! A compute module reaches the world only through the capability verbs its
//! class grants (see [`ComputeRuntime`](super::compute::ComputeRuntime)), and a
//! flow carries no code. A caller's detection is held to the same gate and
//! budgets as a shipped one, and is validated as it is added.
//!
//! ## A caller's own, and somebody else's
//!
//! The three source calls take bytes the caller chooses to run.
//! [`bundle`](DetectionsBuilder::bundle) takes a [`Bundle`], which can only be
//! obtained by checking a signature against a key, so a stranger's detections
//! enter only under a named key.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, OnceLock};

use super::bundle::{Bundle, Tier};
use super::compute::db::{ComputeDb, compile_compute_source, load_embedded};
use super::compute::{LoadedDetection, RhaiModule, RhaiRuntime};
use super::flow::db::{CompiledFlow, FlowDb, embedded_flows};
use super::flow::schema::FlowDetection;
use super::flow::{ValidationError, check, check_patterns};
use super::host::db::{HostDb, compile_host_source, embedded_hosts};
use super::host::stage::LoadedHostDetection;
use super::manifest::{Class, Rule};
use super::source;

/// The compiled corpus a scan's detection phase runs.
///
/// Cheap to clone: the three tiers sit behind [`Arc`]s. [`Default`] and
/// [`embedded`](Self::embedded) both give the corpus this build ships.
#[derive(Clone)]
pub struct Detections {
    flows: Arc<FlowDb>,
    modules: Arc<ComputeDb>,
    hosts: Arc<HostDb>,
    /// The distributors' own data a scan judges a distribution's build
    /// against when it correlates. See [`with_advisories`](Self::with_advisories).
    advisories: Arc<[crate::cve::Advisories]>,
    /// The list of exploited vulnerabilities a scan marks what it reports by,
    /// where a caller supplied one in place of the list this crate ships. See
    /// [`with_exploited`](Self::with_exploited).
    exploited: Option<Arc<crate::cve::KnownExploited>>,
}

/// The shipped corpus, compiled once and shared by every [`Detections::embedded`].
static EMBEDDED: OnceLock<Detections> = OnceLock::new();

impl Detections {
    /// The detections this build ships, compiled from `assets/detect/`. Compiled
    /// once on the first call and shared by every caller after.
    ///
    /// The first call takes tens of milliseconds in a debug build. Make it before
    /// a runtime starts, or on its blocking pool: on a worker it delays every
    /// connection in flight, and a running scan would time them as that much
    /// slower.
    pub fn embedded() -> Self {
        EMBEDDED
            .get_or_init(|| Detections {
                flows: Arc::new(FlowDb::from_embedded()),
                modules: Arc::new(ComputeDb::from_embedded()),
                hosts: Arc::new(HostDb::from_embedded()),
                advisories: Arc::from([]),
                exploited: None,
            })
            .clone()
    }

    /// Judges a distribution's build against its distributor's data when the
    /// scan correlates its services with known vulnerabilities.
    ///
    /// Without it a service naming its distribution's build
    /// (`OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13`) is reported for its upstream
    /// release's vulnerabilities, at a confidence saying the build was not
    /// checked. See [`cve::Correlator`](crate::cve::Correlator). One dataset per
    /// distributor; shared between clones.
    pub fn with_advisories(
        mut self,
        advisories: impl IntoIterator<Item = crate::cve::Advisories>,
    ) -> Self {
        self.advisories = advisories.into_iter().collect();
        self
    }

    /// The distributors' data a scan's correlation uses.
    pub(crate) fn advisories(&self) -> &[crate::cve::Advisories] {
        &self.advisories
    }

    /// Marks the vulnerabilities a scan's correlation reports by `exploited`
    /// in place of the list this crate ships: a newer copy of CISA's catalogue,
    /// or anybody else's. Marking only; see
    /// [`Correlator::with_exploited`](crate::cve::Correlator::with_exploited).
    pub fn with_exploited(mut self, exploited: crate::cve::KnownExploited) -> Self {
        self.exploited = Some(Arc::new(exploited));
        self
    }

    /// The list of exploited vulnerabilities a scan's correlation marks by.
    pub(crate) fn exploited(&self) -> &crate::cve::KnownExploited {
        match &self.exploited {
            Some(exploited) => exploited,
            None => crate::cve::KnownExploited::embedded(),
        }
    }

    /// A builder for a corpus that adds a caller's own detections, on top of the
    /// shipped ones unless [`without_embedded`](DetectionsBuilder::without_embedded)
    /// is set.
    pub fn builder() -> DetectionsBuilder {
        DetectionsBuilder::new()
    }

    pub(crate) fn flows(&self) -> &FlowDb {
        &self.flows
    }

    pub(crate) fn modules(&self) -> &ComputeDb {
        &self.modules
    }

    pub(crate) fn hosts(&self) -> &HostDb {
        &self.hosts
    }

    /// Every detection in the corpus, in the order the tiers run: flows, then
    /// compute modules, then the host correlations.
    ///
    /// For a front end listing what a scan would run.
    ///
    /// Whether a listed detection actually runs is decided by its
    /// [`class`](DetectionSummary::class) against the operator's
    /// [envelope](crate::config::envelope::DetectionEnvelope), and then by its
    /// gate against each port.
    #[must_use]
    pub fn listing(&self) -> Vec<DetectionSummary> {
        let flows = self.flows.flows().map(|compiled| {
            let manifest = &compiled.flow().detection;
            DetectionSummary {
                id: manifest.id.clone(),
                title: manifest.title.clone(),
                version: manifest.version.clone(),
                tier: Tier::Flow,
                class: manifest.capabilities.class,
                gate: Gate::Port(manifest.when.clone()),
                content_hash: compiled.content_hash().to_string(),
            }
        });

        let modules = self.modules.detections().iter().map(|loaded| {
            let manifest = loaded.manifest();
            DetectionSummary {
                id: manifest.id.clone(),
                title: manifest.title.clone(),
                version: manifest.version.clone(),
                tier: Tier::Compute,
                class: manifest.capabilities.class,
                gate: Gate::Port(manifest.when.clone()),
                content_hash: loaded.content_hash().to_string(),
            }
        });

        let hosts = self
            .hosts
            .detections()
            .iter()
            .map(|loaded| DetectionSummary {
                id: loaded.id().to_string(),
                title: loaded.title().to_string(),
                version: loaded.version().to_string(),
                tier: Tier::Host,
                class: Class::Derived,
                gate: Gate::Host {
                    ports_open: loaded.ports_open().to_vec(),
                    services: loaded.services().to_vec(),
                },
                content_hash: loaded.content_hash().to_string(),
            });

        flows.chain(modules).chain(hosts).collect()
    }
}

/// One detection in a corpus, as a listing describes it.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DetectionSummary {
    /// The author-chosen id, stamped on every finding it produces.
    pub id: String,
    /// The one-line human name a report prints for it.
    pub title: String,
    /// Its own version, as the detection declares it.
    pub version: String,
    /// Which tier runs it.
    pub tier: Tier,
    /// The intrusiveness it asks for, and the value an envelope permits or
    /// refuses it on.
    ///
    /// [`Derived`](Class::Derived) for a host detection, which sends nothing of
    /// its own.
    pub class: Class,
    /// What decides whether it fires.
    pub gate: Gate,
    /// The SHA-256 of the bytes that decide its behaviour, its provenance.
    pub content_hash: String,
}

/// What decides whether a detection fires.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Gate {
    /// The port rule a flow or a compute module fires on. An empty rule fits any
    /// open port the envelope offers it.
    Port(Rule),
    /// The aggregate a host detection looks for. Every port must be open and
    /// every service present.
    Host {
        /// Ports that must all be open.
        ports_open: Vec<u16>,
        /// Services that must all have been identified.
        services: Vec<String>,
    },
}

impl Default for Detections {
    fn default() -> Self {
        Self::embedded()
    }
}

impl fmt::Debug for Detections {
    /// The counts only; the compiled bodies have no useful debug form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Detections")
            .field("flows", &self.flows.flows().count())
            .field("modules", &self.modules.detections().len())
            .field("hosts", &self.hosts.detections().len())
            .field("advisories", &self.advisories.len())
            .field("exploited", &self.exploited().len())
            .finish()
    }
}

/// Why a caller's detection source could not be added to a [`Detections`].
///
/// The same objections the build raises against the shipped corpus.
#[non_exhaustive]
#[derive(Debug)]
pub enum DetectionError {
    /// The source did not parse as TOML.
    Parse(String),
    /// A flow was structurally ill-formed. Carries every objection the validator
    /// raised, not the first.
    Flow(Vec<ValidationError>),
    /// A flow carried a pattern that will not compile, which the runtime would
    /// read as a clean negative.
    Pattern(String),
    /// A compute module would not compile, or declared no inline source.
    Compute(String),
    /// A host detection was ill-formed.
    Host(String),
    /// A document in a source set did not say which tier runs it, or said two
    /// things at once.
    Tier(String),
    /// A compute document names a body file the source set did not carry.
    Body(String),
    /// A source set carried a body no detection references.
    ///
    /// Refused, as [`BundleError::Unnamed`](super::bundle::BundleError::Unnamed)
    /// is: its author would believe it is running.
    UnusedBody {
        /// The name it arrived under.
        name: String,
    },
    /// Which document in a source set drew one of the objections above.
    InSource {
        /// The name the document arrived under.
        name: String,
        /// What was wrong with it.
        cause: Box<DetectionError>,
    },
}

impl fmt::Display for DetectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectionError::Parse(reason) => {
                write!(f, "the detection source did not parse: {reason}")
            }
            DetectionError::Flow(errors) => {
                write!(f, "the flow is ill-formed:")?;
                for error in errors {
                    write!(f, "\n  - the detection {error}")?;
                }
                Ok(())
            }
            DetectionError::Pattern(reason) => {
                write!(
                    f,
                    "the flow carries a pattern that will not compile: {reason}"
                )
            }
            DetectionError::Compute(reason) => {
                write!(f, "the compute module could not be compiled: {reason}")
            }
            DetectionError::Host(reason) => write!(f, "the host detection is ill-formed: {reason}"),
            DetectionError::Tier(reason) => write!(f, "the tier is not decidable: {reason}"),
            DetectionError::Body(reason) => {
                write!(f, "the compute body is not available: {reason}")
            }
            DetectionError::UnusedBody { name } => {
                write!(f, "'{name}' is a body no detection references")
            }
            DetectionError::InSource { name, cause } => write!(f, "in '{name}': {cause}"),
        }
    }
}

impl From<source::PreparationError> for DetectionError {
    /// A file-level objection, named against the file that drew it.
    fn from(error: source::PreparationError) -> Self {
        match error.cause {
            source::PreparationCause::Unused => DetectionError::UnusedBody { name: error.name },
            source::PreparationCause::Tier(reason) => DetectionError::InSource {
                name: error.name,
                cause: Box::new(DetectionError::Tier(reason)),
            },
            source::PreparationCause::Body(reason) => DetectionError::InSource {
                name: error.name,
                cause: Box::new(DetectionError::Body(reason)),
            },
        }
    }
}

impl std::error::Error for DetectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DetectionError::InSource { cause, .. } => Some(cause.as_ref()),
            _ => None,
        }
    }
}

/// Builds a [`Detections`] corpus from the shipped detections plus a caller's own.
///
/// Each `flow`/`compute`/`host` call validates and compiles the source as it is
/// added, as the build does. The `content_hash` is stamped on findings as
/// provenance; it may be empty during development.
pub struct DetectionsBuilder {
    include_embedded: bool,
    runtime: RhaiRuntime,
    flows: Vec<CompiledFlow>,
    modules: Vec<LoadedDetection<RhaiModule>>,
    hosts: Vec<LoadedHostDetection>,
}

impl DetectionsBuilder {
    fn new() -> Self {
        Self {
            include_embedded: true,
            runtime: RhaiRuntime::new(),
            flows: Vec::new(),
            modules: Vec::new(),
            hosts: Vec::new(),
        }
    }

    /// Leaves the shipped corpus out, so the scan runs only what is added here.
    #[must_use]
    pub fn without_embedded(mut self) -> Self {
        self.include_embedded = false;
        self
    }

    /// Adds a Tier-1 flow from its TOML source, validated as the build validates
    /// the shipped flows.
    pub fn flow(mut self, source: &str, content_hash: &str) -> Result<Self, DetectionError> {
        let flow: FlowDetection =
            toml::from_str(source).map_err(|error| DetectionError::Parse(error.to_string()))?;
        let errors = check(&flow);
        if !errors.is_empty() {
            return Err(DetectionError::Flow(errors));
        }
        // `check` does not compile patterns, and a bad one would read as a clean
        // negative at scan time.
        check_patterns(&flow).map_err(DetectionError::Pattern)?;
        self.flows
            .push(CompiledFlow::from_parts(flow, content_hash.to_string()));
        Ok(self)
    }

    /// Adds a Tier-2 compute module from its TOML source, compiling its body now.
    pub fn compute(mut self, source: &str, content_hash: &str) -> Result<Self, DetectionError> {
        let loaded = compile_compute_source(&self.runtime, source, content_hash)
            .map_err(DetectionError::Compute)?;
        self.modules.push(loaded);
        Ok(self)
    }

    /// Adds a host-level detection from its TOML source.
    pub fn host(mut self, source: &str, content_hash: &str) -> Result<Self, DetectionError> {
        let loaded = compile_host_source(source, content_hash).map_err(DetectionError::Host)?;
        self.hosts.push(loaded);
        Ok(self)
    }

    /// Adds a whole set of detection sources, working out for each one which tier
    /// runs it and where its code lives.
    ///
    /// `sources` is name to contents, as [`Bundle::verified`](Bundle::verified)
    /// also takes them. A name ending `.toml` is a detection document; the rest
    /// are bodies a `[compute]` section may reference.
    ///
    /// The tier comes from the document: `[[step]]` for a flow, `[compute]` for
    /// a module, `[detection.host]` for a host correlation. (A [`Bundle`] takes
    /// its tiers from the signed manifest; see [`bundle`](Self::bundle).)
    ///
    /// Each detection is stamped with the
    /// [content hash](super::bundle::content_hash) of what decides its
    /// behaviour (the document, or a compute module's code), matching the hashes
    /// the build records under `assets/detect/`.
    ///
    /// # Errors
    ///
    /// [`DetectionError::InSource`] naming the document, wrapping the objection
    /// the tier's own call raised, or [`DetectionError::UnusedBody`] for a body
    /// no document referenced. A source set is added whole or not at all.
    pub fn sources(mut self, sources: &BTreeMap<String, String>) -> Result<Self, DetectionError> {
        for detection in source::prepare(sources).map_err(DetectionError::from)? {
            let in_source = |cause: DetectionError| DetectionError::InSource {
                name: detection.name.clone(),
                cause: Box::new(cause),
            };
            let hash = &detection.content_hash;

            self = match detection.tier {
                Tier::Flow => self.flow(&detection.document, hash).map_err(in_source)?,
                Tier::Host => self.host(&detection.document, hash).map_err(in_source)?,
                Tier::Compute => self.compute(&detection.document, hash).map_err(in_source)?,
            };
        }

        Ok(self)
    }

    /// Adds every detection a verified [`Bundle`] carries.
    ///
    /// The tier and the `content_hash` come from the signed manifest, so whoever
    /// served the sources cannot change how a detection runs, and a finding names
    /// signed bytes.
    ///
    /// Each source is still validated and compiled as a hand-written one is: a
    /// signature says who published a detection, not that it is well-formed.
    ///
    /// # Errors
    ///
    /// The same objections the three calls above raise, for the first source in
    /// the bundle that draws one. A bundle is added whole or not at all.
    pub fn bundle(mut self, bundle: Bundle) -> Result<Self, DetectionError> {
        for entry in bundle.entries() {
            self = match entry.tier() {
                Tier::Flow => self.flow(entry.source(), entry.sha256())?,
                Tier::Compute => self.compute(entry.source(), entry.sha256())?,
                Tier::Host => self.host(entry.source(), entry.sha256())?,
            };
        }
        Ok(self)
    }

    /// Assembles the corpus. The shipped detections come first unless
    /// [`without_embedded`](Self::without_embedded) was set; the caller's follow.
    #[must_use]
    pub fn build(mut self) -> Detections {
        let mut flows = if self.include_embedded {
            embedded_flows()
        } else {
            Vec::new()
        };
        flows.append(&mut self.flows);

        let mut modules = if self.include_embedded {
            load_embedded(&self.runtime)
        } else {
            Vec::new()
        };
        modules.append(&mut self.modules);

        let mut hosts = if self.include_embedded {
            embedded_hosts()
        } else {
            Vec::new()
        };
        hosts.append(&mut self.hosts);

        Detections {
            flows: Arc::new(FlowDb::from_flows(flows)),
            modules: Arc::new(ComputeDb::from_parts(self.runtime, modules)),
            hosts: Arc::new(HostDb::from_detections(hosts)),
            advisories: Arc::from([]),
            exploited: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, sound flow the positive tests add.
    const SOUND_FLOW: &str = r#"
        [detection]
        id      = "corpus-test"
        version = "1.0.0"
        title   = "Corpus test"
        [detection.when]
        service = "http"
        [detection.capabilities]
        class = "active-benign"
        speak = "target"
        [[step]]
        send        = "PING\r\n"
        expect      = "PONG"
        on_no_match = "continue"
        [[step.finding]]
        when     = "matched"
        severity = "low"
        summary  = "the corpus test fired"
    "#;

    /// A verified bundle's detections run, stamped with the manifest's hash.
    #[test]
    fn a_verified_bundle_reaches_the_corpus_stamped_with_the_hash_that_was_signed() {
        use crate::detect::bundle::{Bundle, Tier};
        use crate::signature::{Domain, Signing, SigningKey};
        use std::collections::BTreeMap;
        use std::io::Write;

        let mut sources = BTreeMap::new();
        sources.insert(
            "sound.toml".to_string(),
            (Tier::Flow, SOUND_FLOW.to_string()),
        );

        let manifest = Bundle::manifest("acme", "1", &sources);
        let (_, key) = SigningKey::generate().expect("a key");
        let mut sink = Vec::new();
        let mut writer = Signing::new(&mut sink);
        writer
            .write_all(manifest.as_bytes())
            .expect("the manifest is written");
        let signature = writer.finish(&key, Domain::DETECTIONS);

        let plain: BTreeMap<String, String> = sources
            .iter()
            .map(|(name, (_, source))| (name.clone(), source.clone()))
            .collect();
        let bundle = Bundle::verified(&manifest, &signature, &key.public_key(), plain)
            .expect("the bundle verifies");
        let signed_hash = bundle.entries()[0].sha256().to_string();

        let corpus = Detections::builder()
            .without_embedded()
            .bundle(bundle)
            .expect("a sound bundle is added")
            .build();

        let hashes: Vec<&str> = corpus
            .flows()
            .flows()
            .map(|flow| flow.content_hash())
            .collect();
        assert_eq!(hashes, vec![signed_hash.as_str()]);
    }

    /// A trusted bundle is validated as a hand-written source is.
    #[test]
    fn a_bundle_from_a_trusted_key_is_still_validated() {
        use crate::detect::bundle::{Bundle, Tier};
        use crate::signature::{Domain, Signing, SigningKey};
        use std::collections::BTreeMap;
        use std::io::Write;

        // A flow that declares no finding, which the validator refuses.
        let dead = r#"
            [detection]
            id = "x"
            version = "1.0.0"
            title = "x"
            [detection.when]
            [detection.capabilities]
            class = "passive"
            [[step]]
            send = "x"
            expect = "y"
            on_no_match = "continue"
        "#;

        let mut sources = BTreeMap::new();
        sources.insert("dead.toml".to_string(), (Tier::Flow, dead.to_string()));

        let manifest = Bundle::manifest("acme", "1", &sources);
        let (_, key) = SigningKey::generate().expect("a key");
        let mut sink = Vec::new();
        let mut writer = Signing::new(&mut sink);
        writer
            .write_all(manifest.as_bytes())
            .expect("the manifest is written");
        let signature = writer.finish(&key, Domain::DETECTIONS);

        let plain: BTreeMap<String, String> = sources
            .iter()
            .map(|(name, (_, source))| (name.clone(), source.clone()))
            .collect();
        let bundle = Bundle::verified(&manifest, &signature, &key.public_key(), plain)
            .expect("the signature is good, which is a separate question");

        assert!(
            matches!(
                Detections::builder().bundle(bundle),
                Err(DetectionError::Flow(_))
            ),
            "a signed detection skipped the validation an unsigned one gets"
        );
    }

    #[test]
    fn the_builder_rejects_an_ill_formed_flow() {
        // A flow that declares no finding; the validator's reasons are carried
        // out.
        let dead = r#"
            [detection]
            id = "x"
            version = "1.0.0"
            title = "x"
            [detection.when]
            [detection.capabilities]
            class = "passive"
            [[step]]
            expect = "x"
            on_no_match = "continue"
        "#;
        let Err(error) = Detections::builder().flow(dead, "") else {
            panic!("an ill-formed flow was accepted");
        };
        assert!(
            matches!(error, DetectionError::Flow(_)),
            "wrong error for a dead flow: {error}"
        );
    }

    #[test]
    fn the_builder_rejects_unparseable_toml() {
        let Err(error) = Detections::builder().compute("this is not toml {", "") else {
            panic!("unparseable compute source was accepted");
        };
        assert!(matches!(error, DetectionError::Compute(_)), "{error}");
    }

    #[test]
    fn the_builder_refuses_a_host_detection_with_a_non_triple_version() {
        // Only the version is not major.minor.patch.
        let host = r#"
            [detection]
            id      = "caller-host"
            version = "1.0"
            title   = "Caller host"
            [detection.host]
            ports_open = [88, 389]
            [[finding]]
            severity = "info"
            summary  = "a caller host detection"
        "#;
        let Err(error) = Detections::builder().host(host, "") else {
            panic!("a host detection with a two-part version was accepted");
        };
        assert!(matches!(error, DetectionError::Host(_)), "{error}");
    }

    #[test]
    fn the_builder_refuses_a_detection_claiming_the_reserved_namespace() {
        // The `zond:` prefix is reserved for first-party detections.
        let compute = r#"
            [detection]
            id      = "zond:caller"
            version = "1.0.0"
            title   = "Caller compute"
            [detection.when]
            service = "http"
            [detection.capabilities]
            class = "passive"
            [compute]
            source = "fn detect() {}"
        "#;
        let Err(error) = Detections::builder().compute(compute, "") else {
            panic!("a detection claiming the reserved namespace was accepted");
        };
        assert!(matches!(error, DetectionError::Compute(_)), "{error}");
    }

    #[test]
    fn the_builder_refuses_a_flow_whose_pattern_will_not_compile() {
        // The `expect` pattern is an unclosed character class.
        let flow = r#"
            [detection]
            id      = "bad-pattern"
            version = "1.0.0"
            title   = "Bad pattern"
            [detection.when]
            service = "http"
            [detection.capabilities]
            class = "active-benign"
            speak = "target"
            [[step]]
            send        = "PING\r\n"
            expect      = "[unclosed"
            on_no_match = "continue"
            [[step.finding]]
            when     = "matched"
            severity = "low"
            summary  = "x"
        "#;
        let Err(error) = Detections::builder().flow(flow, "") else {
            panic!("a flow with an uncompilable pattern was accepted");
        };
        assert!(matches!(error, DetectionError::Pattern(_)), "{error}");
    }

    #[test]
    fn a_caller_flow_joins_the_embedded_corpus() {
        let detections = Detections::builder()
            .flow(SOUND_FLOW, "caller-hash")
            .expect("a sound flow is accepted")
            .build();

        let ids: Vec<&str> = detections
            .flows()
            .flows()
            .map(|flow| flow.flow().detection.id.as_str())
            .collect();
        assert!(ids.contains(&"corpus-test"), "the caller flow is missing");
        assert!(
            ids.contains(&"redis-unauth-access"),
            "the embedded corpus was dropped: {ids:?}"
        );
    }

    #[test]
    fn without_embedded_leaves_only_the_caller_detections() {
        let detections = Detections::builder()
            .without_embedded()
            .flow(SOUND_FLOW, "caller-hash")
            .expect("a sound flow is accepted")
            .build();

        let ids: Vec<&str> = detections
            .flows()
            .flows()
            .map(|flow| flow.flow().detection.id.as_str())
            .collect();
        assert_eq!(ids, vec!["corpus-test"], "the corpus is not caller-only");
    }

    /// A set of files: each document's tier is read and every detection loads.
    #[test]
    fn a_source_set_is_read_by_the_tier_each_document_declares() {
        let host = r#"
            [detection]
            id      = "source-set-host"
            version = "1.0.0"
            title   = "Source set host"
            [detection.host]
            ports_open = [88, 389]
            [[finding]]
            severity = "info"
            summary  = "a host detection from a source set"
        "#;

        let mut sources = BTreeMap::new();
        sources.insert("flow.toml".to_string(), SOUND_FLOW.to_string());
        sources.insert("host.toml".to_string(), host.to_string());

        let corpus = Detections::builder()
            .without_embedded()
            .sources(&sources)
            .expect("both documents are sound")
            .build();

        assert_eq!(corpus.flows().flows().count(), 1);
        assert_eq!(corpus.hosts().detections().len(), 1);
    }

    /// A module with its code in a sibling file is stamped with that code's hash.
    #[test]
    fn a_compute_body_in_a_sibling_file_is_resolved_and_hashed() {
        let document = r#"
            [detection]
            id      = "source-set-compute"
            version = "1.0.0"
            title   = "Source set compute"
            [detection.when]
            service = "http"
            [detection.capabilities]
            class = "passive"
            [compute]
            language = "rhai"
            body     = "module.rhai"
        "#;
        let body = "fn analyze(ctx, responses) { [] }";

        let mut sources = BTreeMap::new();
        sources.insert("module.toml".to_string(), document.to_string());
        sources.insert("module.rhai".to_string(), body.to_string());

        let corpus = Detections::builder()
            .without_embedded()
            .sources(&sources)
            .expect("the body resolves and compiles")
            .build();

        let hashes: Vec<&str> = corpus
            .modules()
            .detections()
            .iter()
            .map(|loaded| loaded.content_hash())
            .collect();
        assert_eq!(
            hashes,
            vec![crate::detect::bundle::content_hash(body).as_str()]
        );
    }

    /// A body no document referenced is refused.
    #[test]
    fn a_body_nothing_references_is_refused() {
        let mut sources = BTreeMap::new();
        sources.insert("flow.toml".to_string(), SOUND_FLOW.to_string());
        sources.insert("orphan.rhai".to_string(), "fn analyze() { [] }".to_string());

        let Err(error) = Detections::builder().without_embedded().sources(&sources) else {
            panic!("an unreferenced body was accepted");
        };
        assert!(
            matches!(&error, DetectionError::UnusedBody { name } if name == "orphan.rhai"),
            "{error}"
        );
    }

    /// An objection to one document names that document.
    #[test]
    fn an_objection_names_the_document_that_drew_it() {
        let dead = r#"
            [detection]
            id = "dead"
            version = "1.0.0"
            title = "Dead"
            [detection.when]
            [detection.capabilities]
            class = "passive"
            [[step]]
            send = "x"
            expect = "y"
            on_no_match = "continue"
        "#;

        let mut sources = BTreeMap::new();
        sources.insert("dead.toml".to_string(), dead.to_string());

        let Err(error) = Detections::builder().without_embedded().sources(&sources) else {
            panic!("a flow that concludes nothing was accepted");
        };
        assert!(error.to_string().starts_with("in 'dead.toml':"), "{error}");
    }

    /// A shipped detection read as a loose file gets the hash the build recorded.
    #[test]
    fn a_shipped_flow_loaded_loose_keeps_the_hash_the_build_gave_it() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/assets/detect/database/redis-unauth.toml"
        );
        let shipped = std::fs::read_to_string(path).expect("the shipped flow is readable");

        let mut sources = BTreeMap::new();
        sources.insert("redis-unauth.toml".to_string(), shipped.clone());

        let loose = Detections::builder()
            .without_embedded()
            .sources(&sources)
            .expect("a shipped flow is a sound flow")
            .build();
        let loose_hash = loose
            .flows()
            .flows()
            .next()
            .expect("the flow is in the corpus")
            .content_hash()
            .to_string();

        let embedded_hash = Detections::embedded()
            .flows()
            .flows()
            .find(|flow| flow.flow().detection.id == "redis-unauth-access")
            .expect("the shipped corpus carries it")
            .content_hash()
            .to_string();

        assert_eq!(loose_hash, embedded_hash);
    }

    /// The whole publisher-to-recipient round trip, for a module whose code sat in
    /// a sibling file.
    ///
    /// `publishable` folds the `.rhai` into its document; what it returns is both
    /// what the manifest covers and what the publisher writes out.
    #[test]
    fn a_module_with_a_sibling_body_survives_being_published_and_loaded() {
        use crate::signature::{Domain, Signing, SigningKey};
        use std::io::Write;

        let document = r#"
            [detection]
            id      = "bundled-compute"
            version = "1.0.0"
            title   = "Bundled compute"
            [detection.when]
            service = "http"
            [detection.capabilities]
            class = "passive"
            [compute]
            language = "rhai"
            body     = "module.rhai"
        "#;
        let body = "fn analyze(ctx, responses) { [] }";

        let mut authored = BTreeMap::new();
        authored.insert("module.toml".to_string(), document.to_string());
        authored.insert("module.rhai".to_string(), body.to_string());

        // The publisher's side: the body is folded into its document.
        let published = Bundle::publishable(&authored).expect("the body resolves");
        assert_eq!(published.len(), 1);
        assert!(published.contains_key("module.toml"));

        let manifest = Bundle::manifest("acme", "1", &published);
        let (_, key) = SigningKey::generate().expect("a key");
        let mut sink = Vec::new();
        let mut writer = Signing::new(&mut sink);
        writer
            .write_all(manifest.as_bytes())
            .expect("the manifest is written");
        let signature = writer.finish(&key, Domain::DETECTIONS);

        // The recipient's side.
        let delivered: BTreeMap<String, String> = published
            .iter()
            .map(|(name, (_, document))| (name.clone(), document.clone()))
            .collect();

        let bundle = Bundle::verified(&manifest, &signature, &key.public_key(), delivered)
            .expect("what was published is what was signed");
        let corpus = Detections::builder()
            .without_embedded()
            .bundle(bundle)
            .expect("the module compiles")
            .build();

        assert_eq!(corpus.modules().detections().len(), 1);
    }
}
