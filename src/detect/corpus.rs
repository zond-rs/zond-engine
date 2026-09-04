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
//! host correlations, compiled and ready to run. The default is the
//! corpus this build ships, embedded from `assets/detect/`; a caller who embeds the
//! engine and wants detections about their own software adds them with a
//! [builder](DetectionsBuilder) and passes the result to
//! [`scan`](crate::scanner::scan).
//!
//! Accepting a detection from a caller is safe for the reason the
//! [runtime](super::compute::ComputeRuntime) documents: a compute module reaches
//! the world only through the capability verbs its class grants, and a flow carries
//! no code at all. A caller's detection is held to the same gate and the same
//! budgets as a shipped one, and it is validated as it is added, so the corpus a
//! scan runs is never one the build would have refused.
//!
//! ## A caller's own, and somebody else's
//!
//! The three source calls take bytes the caller holds and is choosing to run,
//! which is their own act. [`bundle`](DetectionsBuilder::bundle) is the other
//! door, and it takes a [`Bundle`] rather than bytes: the
//! only way to hold one is to have checked a signature against a key, so a
//! stranger's detections cannot enter this corpus without somebody having named
//! whose they are. There is no setting that changes that in either direction.

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
/// Cheap to clone and to pass to a [`scan`](crate::scanner::scan): the three tiers
/// sit behind [`Arc`]s, so a clone shares the compiled modules rather than
/// recompiling them. [`Default`] and [`embedded`](Self::embedded) both give the
/// corpus this build ships.
#[derive(Clone)]
pub struct Detections {
    flows: Arc<FlowDb>,
    modules: Arc<ComputeDb>,
    hosts: Arc<HostDb>,
}

/// The shipped corpus, compiled once and shared by every [`Detections::embedded`].
static EMBEDDED: OnceLock<Detections> = OnceLock::new();

impl Detections {
    /// The detections this build ships, compiled from `assets/detect/`. Compiled
    /// once on the first call and shared by every caller after.
    pub fn embedded() -> Self {
        EMBEDDED
            .get_or_init(|| Detections {
                flows: Arc::new(FlowDb::from_embedded()),
                modules: Arc::new(ComputeDb::from_embedded()),
                hosts: Arc::new(HostDb::from_embedded()),
            })
            .clone()
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
    /// What a front end lists for an operator asking what a scan would run, and
    /// what an author checks a file against before pointing it at a network. A
    /// summary is a copy rather than a borrow, since a listing is asked for once
    /// and a corpus is shared behind an [`Arc`].
    ///
    /// A detection appearing here is one the corpus compiled, which is not the
    /// same as one a scan will run: whether it runs is decided by its
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
                class: Some(manifest.capabilities.class),
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
                class: Some(manifest.capabilities.class),
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
                class: None,
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
    /// [`None`] for a host detection, which declares none: it correlates ports
    /// the scan already settled and sends nothing of its own.
    pub class: Option<Class>,
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
    /// The counts, not the compiled bodies: the module ASTs behind them have no
    /// useful debug form and a great deal of noise.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Detections")
            .field("flows", &self.flows.flows().count())
            .field("modules", &self.modules.detections().len())
            .field("hosts", &self.hosts.detections().len())
            .finish()
    }
}

/// Why a caller's detection source could not be added to a [`Detections`].
///
/// Each is the same objection the build raises against the shipped corpus, brought
/// to a caller adding a detection at runtime rather than at build.
#[non_exhaustive]
#[derive(Debug)]
pub enum DetectionError {
    /// The source did not parse as TOML.
    Parse(String),
    /// A flow was structurally ill-formed. Carries every objection the validator
    /// raised, not the first.
    Flow(Vec<ValidationError>),
    /// A flow was structurally sound but carried a pattern that will not compile,
    /// which the runtime would read as a clean negative rather than an error.
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
    /// Refused rather than skipped, on the reasoning
    /// [`BundleError::Unnamed`](super::bundle::BundleError::Unnamed) is refused
    /// on: a file nothing loaded is a file whose author believes it is running.
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
/// added, so a source the build would have refused is refused here too. The
/// `content_hash` a caller passes is stamped on the findings a detection produces as
/// provenance; it may be empty for a detection under development.
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

    /// Adds a Tier-1 flow from its TOML source, validated exactly as the build
    /// validates the shipped flows.
    pub fn flow(mut self, source: &str, content_hash: &str) -> Result<Self, DetectionError> {
        let flow: FlowDetection =
            toml::from_str(source).map_err(|error| DetectionError::Parse(error.to_string()))?;
        let errors = check(&flow);
        if !errors.is_empty() {
            return Err(DetectionError::Flow(errors));
        }
        // `check` is structural and holds no pattern engine, so it cannot tell a
        // pattern that will not compile from one that will. The build compiles the
        // shipped corpus's patterns; do the same for a caller's, or a bad one reads
        // as a clean negative at scan time rather than an error here.
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
    /// `sources` is name to contents, the shape a directory read hands over and
    /// the shape [`Bundle::verified`](Bundle::verified) takes its sources in.
    /// Where they came from is the caller's business: a directory, an archive, a
    /// database, a text box in a browser. A name ending `.toml` is a detection
    /// document and the rest is a body a `[compute]` section may reference.
    ///
    /// This is the door for detections the caller wrote or chose, so the tier
    /// comes from the document: `[[step]]` for a flow, `[compute]` for a module,
    /// `[detection.host]` for a host correlation. A bundle from somebody else
    /// takes its tiers from the signed manifest instead, and
    /// [`bundle`](Self::bundle) is the only way one gets in.
    ///
    /// Each detection is stamped with the [content
    /// hash](super::bundle::content_hash) of what decides its behaviour: the
    /// document for a flow or a host detection, the code for a compute module.
    /// Those are the hashes the build records for the same files under
    /// `assets/detect/`, so a detection keeps its provenance when it moves
    /// between a working directory and a shipped corpus.
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
    /// The tier comes from the bundle's manifest, which is the document the
    /// signature covers, so an attacker who served the sources cannot have a
    /// compute module compiled as a flow or a flow run with a module's
    /// capabilities. The `content_hash` each detection is stamped with is the one
    /// the manifest recorded and the signature covered, so a finding names bytes
    /// somebody signed rather than bytes that happened to be on disk.
    ///
    /// Each source is still validated and compiled exactly as one a caller wrote
    /// by hand: a signature says who published a detection, never that it is
    /// well-formed, and this refuses an ill-formed one from a trusted publisher as
    /// readily as from anybody.
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

    /// A verified bundle reaches the corpus and its detections run, stamped with
    /// the hash the manifest recorded rather than one the loader computed.
    ///
    /// The provenance is the point: a finding names the exact bytes somebody
    /// signed, so a reader who doubts it can go and check that signature against
    /// those bytes.
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

    /// A signature says who published a detection and never that it is
    /// well-formed. A bundle from a key the caller trusts is held to exactly the
    /// validation a hand-written source is.
    #[test]
    fn a_bundle_from_a_trusted_key_is_still_validated() {
        use crate::detect::bundle::{Bundle, Tier};
        use crate::signature::{Domain, Signing, SigningKey};
        use std::collections::BTreeMap;
        use std::io::Write;

        // Structurally sound TOML that declares no finding, which the validator
        // refuses: a flow that can conclude nothing is dead code in a scan.
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
        // A flow that declares no finding is dead; the validator refuses it and so
        // must the builder, with the validator's reasons carried out.
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
        // Everything else is well-formed; only the version is not major.minor.patch.
        // The build refuses this for a shipped detection, so the builder must for a
        // caller's, or a finding's provenance would silently record 0.0.0.
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
        // The `zond:` prefix is the engine's own; a caller must not stamp it on a
        // finding's provenance and pass their detection off as first-party.
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
        // Structurally sound, but the `expect` pattern is an unclosed character
        // class. The runtime reads an uncompilable pattern as a clean negative, so
        // the builder compiles it now and refuses, as the build does for the corpus.
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

    /// A directory of files, as a front end hands one over: the tier comes out of
    /// each document and every detection reaches the corpus.
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

    /// A module whose code sits in a sibling file arrives compiled, and is stamped
    /// with the hash of that code rather than of the document naming it.
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

    /// A body no document referenced is refused. Skipping it would leave whoever
    /// put it there believing a detection is running that was never compiled.
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

    /// An objection to one document in a set names that document. A set is read
    /// whole, so an error that said only "the flow is ill-formed" would leave a
    /// caller with thirty files and no idea which.
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

    /// A shipped detection read as a loose file gets the hash the build recorded
    /// for it. Provenance follows the bytes, so a detection lifted out of
    /// `assets/detect/` to be edited is recognisably the same one until it changes.
    #[test]
    fn a_shipped_flow_loaded_loose_keeps_the_hash_the_build_gave_it() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/assets/detect/redis-unauth.toml"
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
    /// This is the case a bundle gets wrong if it carries an author's files
    /// rather than the detections they describe: a `.rhai` is not a document, and
    /// signing one as though it were produces a bundle that verifies and then
    /// will not compile. `publishable` is what resolves that, and what it returns
    /// is both what the manifest covers and what the publisher writes out.
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

        // The publisher's side. The body is gone from what is published, having
        // been resolved into the one document that carries it.
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

        // The recipient's side, reading the files the publisher wrote out.
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
