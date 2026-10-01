// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Signed detection bundles
//!
//! The [compute](super::compute) sandbox gives a module only `Speak`, `Resolve`
//! and `Now`, metered by byte and connection, and a [flow](super::flow) carries
//! no code. That makes it safe to run a stranger's detections: a [`Bundle`] is a
//! signed set of them, loaded by naming the key the caller trusts.
//!
//! ## The manifest is what is signed
//!
//! One document lists every detection by name, tier and the SHA-256 of its
//! source. The signature covers it, and each source is held to its recorded
//! hash. Signing sources separately would leave the set unsigned, so an attacker
//! serving files could drop a detection or replay an older one.
//!
//! ## Loading is the guarantee
//!
//! A caller's own source enters through
//! [`DetectionsBuilder::flow`](super::DetectionsBuilder::flow) and its siblings.
//! A stranger's enters only through
//! [`DetectionsBuilder::bundle`](super::DetectionsBuilder::bundle), which takes a
//! [`Bundle`], obtainable only from [`Bundle::verified`] with a key. No setting
//! changes that.
//!
//! ## Out of scope
//!
//! Fetching, trust stores, updates and revocation. A bundle needs bytes and a
//! key, and the caller supplies both, as with [`signature`](crate::signature).
//!
//! ```no_run
//! use std::collections::BTreeMap;
//! use zond_engine::detect::{Detections, bundle::Bundle};
//! use zond_engine::signature::Signature;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let trusted_key: Vec<u8> = Vec::new();
//! let manifest = std::fs::read_to_string("detections.toml")?;
//! let signature = Signature::read(&mut std::io::BufReader::new(
//!     std::fs::File::open("detections.toml.sig")?,
//! ))?;
//!
//! let mut sources = BTreeMap::new();
//! sources.insert(
//!     "redis-unauth.toml".to_string(),
//!     std::fs::read_to_string("redis-unauth.toml")?,
//! );
//!
//! let bundle = Bundle::verified(&manifest, &signature, &trusted_key, sources)?;
//! let detections = Detections::builder().bundle(bundle)?.build();
//! # let _ = detections;
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

use crate::signature::{Domain, Signature, SignatureError};

use super::corpus::DetectionError;

/// How many detections one bundle may carry.
///
/// Bounds what an untrusted manifest can ask this process to compile: far above
/// any hand-authored corpus, far below a memory problem.
pub const MAX_DETECTIONS: usize = 4_096;

/// A verified set of detections, ready to add to a corpus.
///
/// Only [`verified`](Self::verified) builds one, so holding a `Bundle` means a
/// signature was checked against a key the caller named.
#[derive(Debug, Clone)]
pub struct Bundle {
    name: String,
    version: String,
    entries: Vec<Entry>,
}

/// One detection in a verified bundle: which tier runs it, its source, and the
/// hash that was signed.
#[derive(Debug, Clone)]
pub struct Entry {
    name: String,
    tier: Tier,
    source: String,
    sha256: String,
}

impl Entry {
    /// The name the manifest gave it, which is the key its source arrived under.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Which tier runs it.
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// Its source, as the bundle carried it.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The SHA-256 of that source, hex-encoded.
    ///
    /// The value the manifest recorded and the signature covered, stamped on
    /// every finding this detection produces.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Which tier runs a detection.
///
/// Named in the manifest, so an attacker cannot influence it through the
/// source's shape.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    /// A declarative [flow](super::flow): steps and matches, carrying no code.
    Flow,
    /// A [compute module](super::compute): code, run in the capability sandbox.
    Compute,
    /// A host-level correlation.
    Host,
}

impl Tier {
    /// Every tier this build knows.
    ///
    /// As [`Class::ALL`](crate::detect::manifest::Class::ALL): the enum is
    /// non-exhaustive, and a front end needs the full list.
    pub const ALL: &'static [Self] = &[Self::Flow, Self::Compute, Self::Host];
}

/// Why a bundle could not be verified.
///
/// Every variant is a refusal to load. A caller can still add the sources
/// individually through the builder.
#[non_exhaustive]
#[derive(Debug)]
pub enum BundleError {
    /// The signature did not check out against the key the caller named.
    Signature(SignatureError),
    /// The manifest did not parse.
    Manifest(String),
    /// The manifest names a detection whose source the caller did not supply.
    Missing {
        /// The name the manifest gave it.
        name: String,
    },
    /// A source does not hash to what the manifest recorded, so it is not the
    /// source that was signed.
    Altered {
        /// The name the manifest gave it.
        name: String,
    },
    /// The caller supplied a source the manifest does not name.
    ///
    /// Refused, since dropping it silently would leave the caller believing it
    /// ran.
    Unnamed {
        /// The name it arrived under.
        name: String,
    },
    /// The manifest names the same detection twice, so which source the hash
    /// covers is not decidable.
    Duplicate {
        /// The name given twice.
        name: String,
    },
    /// The manifest names more detections than [`MAX_DETECTIONS`].
    TooMany {
        /// How many it named.
        named: usize,
    },
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleError::Signature(error) => {
                write!(f, "the bundle's signature did not verify: {error}")
            }
            BundleError::Manifest(reason) => {
                write!(f, "the bundle manifest is malformed: {reason}")
            }
            BundleError::Missing { name } => {
                write!(
                    f,
                    "the manifest names '{name}' and no source was supplied for it"
                )
            }
            BundleError::Altered { name } => write!(
                f,
                "'{name}' does not hash to what the manifest recorded, so it is not what was signed"
            ),
            BundleError::Unnamed { name } => write!(
                f,
                "a source was supplied for '{name}', which the manifest does not name and the \
                 signature says nothing about"
            ),
            BundleError::Duplicate { name } => {
                write!(f, "the manifest names '{name}' more than once")
            }
            BundleError::TooMany { named } => write!(
                f,
                "the manifest names {named} detections, above the {MAX_DETECTIONS} a bundle may \
                 carry"
            ),
        }
    }
}

impl std::error::Error for BundleError {}

impl From<SignatureError> for BundleError {
    fn from(error: SignatureError) -> Self {
        BundleError::Signature(error)
    }
}

impl Bundle {
    /// Checks `signature` over `manifest` under `trusted_key`, then holds every
    /// source in `sources` to the hash the manifest recorded for it.
    ///
    /// `sources` is keyed by the names the manifest uses.
    ///
    /// The signature is checked before the manifest is parsed, and the hashes
    /// before anything is compiled.
    ///
    /// # Errors
    ///
    /// [`BundleError::Signature`] where the signature does not verify under the
    /// named key, and one of the others where the manifest and the sources do not
    /// agree. Nothing is loaded on error.
    pub fn verified(
        manifest: &str,
        signature: &Signature,
        trusted_key: &[u8],
        mut sources: BTreeMap<String, String>,
    ) -> Result<Self, BundleError> {
        // First, on the raw bytes, before any parsing.
        signature.verify(manifest.as_bytes(), trusted_key, Domain::DETECTIONS)?;

        let document: ManifestDocument =
            toml::from_str(manifest).map_err(|error| BundleError::Manifest(error.to_string()))?;

        if document.detection.len() > MAX_DETECTIONS {
            return Err(BundleError::TooMany {
                named: document.detection.len(),
            });
        }

        let mut entries = Vec::with_capacity(document.detection.len());
        let mut seen: BTreeMap<&str, ()> = BTreeMap::new();

        for named in &document.detection {
            if seen.insert(named.name.as_str(), ()).is_some() {
                return Err(BundleError::Duplicate {
                    name: named.name.clone(),
                });
            }

            // Taken, so what remains is what the manifest did not name.
            let source = sources
                .remove(&named.name)
                .ok_or_else(|| BundleError::Missing {
                    name: named.name.clone(),
                })?;

            if !hash_matches(&source, &named.sha256) {
                return Err(BundleError::Altered {
                    name: named.name.clone(),
                });
            }

            entries.push(Entry {
                name: named.name.clone(),
                tier: named.tier,
                source,
                sha256: named.sha256.clone(),
            });
        }

        if let Some((name, _)) = sources.into_iter().next() {
            return Err(BundleError::Unnamed { name });
        }

        Ok(Self {
            name: document.bundle.name,
            version: document.bundle.version,
            entries,
        })
    }

    /// The name the bundle gives itself.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The version it gives itself.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Every detection it carries, in the order the manifest listed them.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The documents a set of loose detection files should be published as.
    ///
    /// A module whose code sits in a sibling `.rhai` is folded into its document,
    /// so the signature covers the code. The result is ready for
    /// [`manifest`](Self::manifest) and for writing out; write these documents,
    /// not the originals, since a recipient hashes the files it receives.
    ///
    /// The tier is read from each document, which is safe on a publisher's own
    /// files; [`verified`](Self::verified) takes tiers from the manifest.
    ///
    /// # Errors
    ///
    /// [`DetectionError::InSource`] naming the document that would not resolve,
    /// or [`DetectionError::UnusedBody`] for a body no document references.
    pub fn publishable(
        sources: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, (Tier, String)>, DetectionError> {
        let prepared = super::source::prepare(sources).map_err(DetectionError::from)?;
        Ok(prepared
            .into_iter()
            .map(|detection| (detection.name, (detection.tier, detection.document)))
            .collect())
    }

    /// The manifest document for a set of sources, for a publisher building a
    /// bundle.
    ///
    /// Hashes each source and writes the document that
    /// [`verified`](Self::verified) will check them against. What comes back is
    /// signed with [`Signing`](crate::signature::Signing) under
    /// [`Domain::DETECTIONS`], and the signature published beside it.
    ///
    /// Shipped here so both ends agree exactly on what is hashed.
    #[must_use]
    pub fn manifest(
        name: &str,
        version: &str,
        sources: &BTreeMap<String, (Tier, String)>,
    ) -> String {
        let mut document = format!(
            "# A zond detection bundle. The signature beside this file covers these\n\
             # bytes; each source is held to the hash recorded here.\n\
             [bundle]\n\
             name = \"{name}\"\n\
             version = \"{version}\"\n"
        );

        // Ordered by name, so the document is deterministic.
        for (source_name, (tier, source)) in sources {
            document.push_str(&format!(
                "\n[[detection]]\n\
                 name = \"{source_name}\"\n\
                 tier = \"{}\"\n\
                 sha256 = \"{}\"\n",
                tier.name(),
                sha256_hex(source),
            ));
        }

        document
    }
}

impl Tier {
    /// The name the manifest spells this tier with.
    pub const fn name(self) -> &'static str {
        match self {
            Tier::Flow => "flow",
            Tier::Compute => "compute",
            Tier::Host => "host",
        }
    }
}

/// The manifest as TOML holds it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDocument {
    bundle: BundleHeader,
    /// Absent for an empty bundle, which is valid: a publisher may withdraw
    /// everything.
    #[serde(default)]
    detection: Vec<NamedDetection>,
}

/// `[bundle]`: what the set calls itself.
///
/// Informational, and signed so a publisher's name cannot be put on somebody
/// else's detections.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleHeader {
    /// The publisher's name for the set.
    name: String,
    /// The publisher's version for it.
    version: String,
}

/// One `[[detection]]`: which source, run by which tier, and the bytes it must
/// be.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedDetection {
    /// The name the source is supplied under.
    name: String,
    /// Which tier runs it.
    tier: Tier,
    /// The SHA-256 the source is held to, lowercase hex.
    sha256: String,
}

/// Whether `source` hashes to `expected`, which is lowercase hex.
///
/// Compared exactly: an upper-case digest or stray whitespace is a mismatch.
fn hash_matches(source: &str, expected: &str) -> bool {
    sha256_hex(source) == expected
}

/// The SHA-256 of a detection source, lowercase hex, as a manifest records it.
///
/// The provenance stamped on every finding. [`Bundle::manifest`] computes it for
/// a whole set; this is for one source, for a caller of
/// [`flow`](super::corpus::DetectionsBuilder::flow) and its siblings, which take
/// the hash as an argument.
#[must_use]
pub fn content_hash(source: &str) -> String {
    sha256_hex(source)
}

/// The SHA-256 of `source`, lowercase hex.
fn sha256_hex(source: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, source.as_bytes());
    digest.as_ref().iter().fold(String::new(), |mut hex, byte| {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
        hex
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
    /// Every tier is listed, once each.
    ///
    /// `place` is an exhaustive match, so a new tier must be listed.
    #[test]
    fn the_list_of_tiers_holds_every_one_of_them_once() {
        fn place(tier: super::Tier) -> usize {
            match tier {
                super::Tier::Flow => 0,
                super::Tier::Compute => 1,
                super::Tier::Host => 2,
            }
        }

        let places: Vec<usize> = super::Tier::ALL.iter().copied().map(place).collect();

        assert_eq!(
            places,
            (0..super::Tier::ALL.len()).collect::<Vec<_>>(),
            "every tier, once"
        );
    }

    use super::*;
    use crate::signature::{Signing, SigningKey};
    use std::io::Write;

    /// A minimal flow the corpus compiles.
    const FLOW: &str = r#"
        [detection]
        id      = "bundle-test"
        version = "1.0.0"
        title   = "Bundle test"
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
        summary  = "the bundle test fired"
    "#;

    fn sources() -> BTreeMap<String, (Tier, String)> {
        let mut sources = BTreeMap::new();
        sources.insert("flow.toml".to_string(), (Tier::Flow, FLOW.to_string()));
        sources
    }

    fn plain(sources: &BTreeMap<String, (Tier, String)>) -> BTreeMap<String, String> {
        sources
            .iter()
            .map(|(name, (_, source))| (name.clone(), source.clone()))
            .collect()
    }

    /// Signs `manifest` and returns the key that did, with the signature.
    fn signed(manifest: &str) -> (SigningKey, Signature) {
        let (_, key) = SigningKey::generate().expect("a key");
        let mut sink = Vec::new();
        let mut writer = Signing::new(&mut sink);
        writer
            .write_all(manifest.as_bytes())
            .expect("the manifest is written");
        let signature = writer.finish(&key, Domain::DETECTIONS);
        (key, signature)
    }

    /// A manifest this crate wrote is one it accepts.
    #[test]
    fn a_bundle_this_crate_wrote_is_one_it_verifies() {
        let sources = sources();
        let manifest = Bundle::manifest("acme", "2026.09.1", &sources);
        let (key, signature) = signed(&manifest);

        let bundle = Bundle::verified(&manifest, &signature, &key.public_key(), plain(&sources))
            .expect("the bundle verifies");

        assert_eq!(bundle.name(), "acme");
        assert_eq!(bundle.version(), "2026.09.1");
        assert_eq!(bundle.entries().len(), 1);
        assert_eq!(bundle.entries()[0].name(), "flow.toml");
        assert_eq!(bundle.entries()[0].tier(), Tier::Flow);
        assert_eq!(bundle.entries()[0].source(), FLOW);
        assert_eq!(bundle.entries()[0].sha256().len(), 64, "a hex sha256");
    }

    /// A bundle signed with another key is refused.
    #[test]
    fn a_bundle_signed_by_another_key_is_refused() {
        let sources = sources();
        let manifest = Bundle::manifest("acme", "2026.09.1", &sources);
        let (_, signature) = signed(&manifest);

        let (_, recipient) = SigningKey::generate().expect("a key");

        assert!(matches!(
            Bundle::verified(
                &manifest,
                &signature,
                &recipient.public_key(),
                plain(&sources)
            ),
            Err(BundleError::Signature(_))
        ));
    }

    /// A source swapped after signing fails its hash.
    #[test]
    fn a_source_that_is_not_what_was_signed_is_refused() {
        let sources = sources();
        let manifest = Bundle::manifest("acme", "2026.09.1", &sources);
        let (key, signature) = signed(&manifest);

        let mut swapped = plain(&sources);
        swapped.insert(
            "flow.toml".to_string(),
            FLOW.replace("active-benign", "exploit"),
        );

        assert!(matches!(
            Bundle::verified(&manifest, &signature, &key.public_key(), swapped),
            Err(BundleError::Altered { name }) if name == "flow.toml"
        ));
    }

    /// A missing source is refused.
    #[test]
    fn a_detection_withheld_from_a_signed_set_is_refused() {
        let sources = sources();
        let manifest = Bundle::manifest("acme", "2026.09.1", &sources);
        let (key, signature) = signed(&manifest);

        assert!(matches!(
            Bundle::verified(&manifest, &signature, &key.public_key(), BTreeMap::new()),
            Err(BundleError::Missing { name }) if name == "flow.toml"
        ));
    }

    /// An unsigned extra source is refused.
    #[test]
    fn a_source_the_manifest_does_not_name_is_refused() {
        let sources = sources();
        let manifest = Bundle::manifest("acme", "2026.09.1", &sources);
        let (key, signature) = signed(&manifest);

        let mut extra = plain(&sources);
        extra.insert("smuggled.toml".to_string(), FLOW.to_string());

        assert!(matches!(
            Bundle::verified(&manifest, &signature, &key.public_key(), extra),
            Err(BundleError::Unnamed { name }) if name == "smuggled.toml"
        ));
    }

    /// A manifest edited after signing does not verify, whatever it now says.
    #[test]
    fn a_manifest_altered_after_signing_is_refused() {
        let sources = sources();
        let manifest = Bundle::manifest("acme", "2026.09.1", &sources);
        let (key, signature) = signed(&manifest);

        let edited = manifest.replace("2026.09.1", "2026.09.2");

        assert!(matches!(
            Bundle::verified(&edited, &signature, &key.public_key(), plain(&sources)),
            Err(BundleError::Signature(_))
        ));
    }

    /// The tier comes from the signed manifest, not the source.
    #[test]
    fn the_tier_is_the_manifests_and_not_the_sources() {
        let mut sources = BTreeMap::new();
        // A flow's source, declared as a compute module.
        sources.insert("thing.toml".to_string(), (Tier::Compute, FLOW.to_string()));

        let manifest = Bundle::manifest("acme", "1", &sources);
        let (key, signature) = signed(&manifest);

        let bundle = Bundle::verified(&manifest, &signature, &key.public_key(), plain(&sources))
            .expect("the bundle verifies");

        assert_eq!(bundle.entries()[0].tier(), Tier::Compute);
    }

    /// A manifest naming one detection twice is refused.
    #[test]
    fn a_manifest_naming_one_detection_twice_is_refused() {
        let sources = sources();
        let manifest = Bundle::manifest("acme", "1", &sources);
        let doubled = format!(
            "{manifest}\n[[detection]]\nname = \"flow.toml\"\ntier = \"flow\"\nsha256 = \"{}\"\n",
            sha256_hex(FLOW)
        );
        let (key, signature) = signed(&doubled);

        assert!(matches!(
            Bundle::verified(&doubled, &signature, &key.public_key(), plain(&sources)),
            Err(BundleError::Duplicate { name }) if name == "flow.toml"
        ));
    }

    /// An empty bundle is valid.
    #[test]
    fn a_bundle_carrying_nothing_verifies_and_carries_nothing() {
        let manifest = Bundle::manifest("acme", "2026.09.2", &BTreeMap::new());
        let (key, signature) = signed(&manifest);

        let bundle = Bundle::verified(&manifest, &signature, &key.public_key(), BTreeMap::new())
            .expect("an empty bundle is a bundle");

        assert!(bundle.entries().is_empty());
    }
}
