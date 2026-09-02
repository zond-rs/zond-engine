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

use std::fmt;
use std::sync::{Arc, OnceLock};

use super::compute::db::{ComputeDb, compile_compute_source, load_embedded};
use super::compute::{LoadedDetection, RhaiModule, RhaiRuntime};
use super::flow::db::{CompiledFlow, FlowDb, embedded_flows};
use super::flow::schema::FlowDetection;
use super::flow::{ValidationError, check};
use super::host::db::{HostDb, compile_host_source, embedded_hosts};
use super::host::stage::LoadedHostDetection;

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
    /// A compute module would not compile, or declared no inline source.
    Compute(String),
    /// A host detection was ill-formed.
    Host(String),
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
            DetectionError::Compute(reason) => {
                write!(f, "the compute module could not be compiled: {reason}")
            }
            DetectionError::Host(reason) => write!(f, "the host detection is ill-formed: {reason}"),
        }
    }
}

impl std::error::Error for DetectionError {}

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
}
