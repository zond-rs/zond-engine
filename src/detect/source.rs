// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Loose detection files, as a caller holds them
//!
//! A [bundle](super::bundle) arrives with a manifest naming every detection and
//! the tier that runs it. A directory of files a caller wrote arrives with
//! neither, so this module supplies the two things the manifest would have said:
//! which tier a document belongs to, and where a `[compute]` body lives.
//!
//! Both answers come from the document itself. Reading a tier out of a stranger's
//! bytes is the thing [`Tier`] exists to prevent, and it stays prevented: nothing
//! here is reachable from [`Bundle::verified`](super::bundle::Bundle::verified),
//! and the door this serves,
//! [`sources`](super::corpus::DetectionsBuilder::sources), is the one a caller
//! walks through with bytes they chose.

use std::collections::BTreeMap;

use super::bundle::Tier;
use super::compute::schema::ComputeDetection;

/// The extension a detection document carries. Anything else in a source set is
/// a body a `[compute]` section may name.
pub(crate) const DOCUMENT_EXTENSION: &str = ".toml";

/// Whether `name` is a detection document rather than a body.
pub(crate) fn is_document(name: &str) -> bool {
    name.ends_with(DOCUMENT_EXTENSION)
}

/// One detection out of a set of loose files: self-contained, with its tier read
/// from the document and its content hash computed.
#[derive(Debug)]
pub(crate) struct Prepared {
    /// The name it arrived under.
    pub(crate) name: String,
    /// Which tier runs it.
    pub(crate) tier: Tier,
    /// The document, carrying any code inline.
    pub(crate) document: String,
    /// The SHA-256 of what decides its behaviour: the document for a flow or a
    /// host detection, the code for a compute module.
    pub(crate) content_hash: String,
}

/// Reads a set of named files into the detections it describes.
///
/// A name ending [`DOCUMENT_EXTENSION`] is a detection and everything else is a
/// body a `[compute]` section may reference. Each document comes back
/// self-contained, so what this returns is what both a corpus and a bundle carry.
///
/// The one implementation behind
/// [`DetectionsBuilder::sources`](super::corpus::DetectionsBuilder::sources) and
/// [`Bundle::publishable`](super::bundle::Bundle::publishable), which is what
/// makes a detection hash the same whether it is loaded or published.
pub(crate) fn prepare(
    sources: &BTreeMap<String, String>,
) -> Result<Vec<Prepared>, PreparationError> {
    let (documents, mut bodies): (BTreeMap<_, _>, BTreeMap<_, _>) = sources
        .iter()
        .map(|(name, contents)| (name.clone(), contents.clone()))
        .partition(|(name, _)| is_document(name));

    let mut prepared = Vec::with_capacity(documents.len());

    for (name, contents) in &documents {
        let named = |reason: PreparationCause| PreparationError {
            name: name.clone(),
            cause: reason,
        };

        let tier = tier_of(contents).map_err(|reason| named(PreparationCause::Tier(reason)))?;

        let (document, hashed) = match tier {
            Tier::Flow | Tier::Host => (contents.clone(), contents.clone()),
            Tier::Compute => {
                let resolved = resolve_compute(contents, &bodies)
                    .map_err(|reason| named(PreparationCause::Body(reason)))?;
                if let Some(referenced) = &resolved.referenced {
                    bodies.remove(referenced);
                }
                (resolved.document, resolved.body)
            }
        };

        prepared.push(Prepared {
            name: name.clone(),
            tier,
            document,
            content_hash: super::bundle::content_hash(&hashed),
        });
    }

    if let Some((name, _)) = bodies.into_iter().next() {
        return Err(PreparationError {
            name,
            cause: PreparationCause::Unused,
        });
    }

    Ok(prepared)
}

/// Why a set of loose files does not describe the detections it should.
#[derive(Debug)]
pub(crate) struct PreparationError {
    /// The file that drew the objection.
    pub(crate) name: String,
    /// What was wrong with it.
    pub(crate) cause: PreparationCause,
}

/// What was wrong with one file in a set.
#[derive(Debug)]
pub(crate) enum PreparationCause {
    /// The document did not say which tier runs it, or said two things at once.
    Tier(String),
    /// A compute document's body was not among the files supplied.
    Body(String),
    /// The file is a body no document references.
    Unused,
}

/// Which tier runs the detection `source` describes.
///
/// The tables a document carries decide it: `[compute]` for a module, `[[step]]`
/// for a flow, `[detection.host]` for a host correlation. A document carrying
/// more than one of them is refused rather than resolved by precedence, since
/// which tier a detection runs at decides what it is handed.
pub(crate) fn tier_of(source: &str) -> Result<Tier, String> {
    let document: toml::Table =
        toml::from_str(source).map_err(|error| format!("it did not parse as TOML: {error}"))?;

    let mut found = Vec::new();
    if document.contains_key("compute") {
        found.push((Tier::Compute, "a [compute] section"));
    }
    if document.contains_key("step") {
        found.push((Tier::Flow, "a [[step]] array"));
    }
    if document
        .get("detection")
        .and_then(toml::Value::as_table)
        .is_some_and(|detection| detection.contains_key("host"))
    {
        found.push((Tier::Host, "a [detection.host] gate"));
    }

    match found.as_slice() {
        [(tier, _)] => Ok(*tier),
        [] => Err(
            "it names no tier: a flow carries [[step]], a compute module a [compute] \
             section, and a host detection a [detection.host] gate"
                .to_string(),
        ),
        several => {
            let named: Vec<&str> = several.iter().map(|(_, what)| *what).collect();
            Err(format!(
                "it carries {}, so which tier runs it is not decidable",
                named.join(" and ")
            ))
        }
    }
}

/// A compute detection with its body resolved to the inline form, and the source
/// of that body.
///
/// The document a caller wrote may keep its code in a sibling file, which is the
/// form the shipped corpus uses and the only form a binary body could take. The
/// runtime reads inline source alone, so the reference is resolved here exactly
/// as the build resolves it for `assets/detect/`: the body is spliced into
/// `compute.source`, the reference removed, and the document re-serialized.
#[derive(Debug)]
pub(crate) struct ResolvedCompute {
    /// The document, normalised to carry its code inline.
    pub(crate) document: String,
    /// The code, which is what the content hash covers.
    pub(crate) body: String,
    /// The body file this drew the code from, where it was out of line.
    pub(crate) referenced: Option<String>,
}

/// Resolves the body of the compute detection `source`, drawing an out-of-line
/// one from `bodies` by the name the `[compute]` section gives it.
///
/// A document that already carries `source` comes back unchanged apart from the
/// body being reported alongside it.
pub(crate) fn resolve_compute(
    source: &str,
    bodies: &BTreeMap<String, String>,
) -> Result<ResolvedCompute, String> {
    let detection: ComputeDetection = toml::from_str(source)
        .map_err(|error| format!("it is not a valid compute detection: {error}"))?;

    if let Some(inline) = detection.compute.source {
        return Ok(ResolvedCompute {
            document: source.to_string(),
            body: inline,
            referenced: None,
        });
    }

    let name = detection
        .compute
        .body
        .ok_or_else(|| "its [compute] section declares neither `source` nor `body`".to_string())?;

    let body = bodies
        .get(&name)
        .ok_or_else(|| format!("its body '{name}' is not among the sources supplied"))?
        .clone();

    let mut value: toml::Value =
        toml::from_str(source).map_err(|error| format!("it did not parse as TOML: {error}"))?;
    let compute = value
        .get_mut("compute")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| "its [compute] section is not a table".to_string())?;
    compute.insert("source".to_string(), toml::Value::String(body.clone()));
    compute.remove("body");

    let document = toml::to_string(&value)
        .map_err(|error| format!("its body could not be inlined: {error}"))?;

    Ok(ResolvedCompute {
        document,
        body,
        referenced: Some(name),
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

    const MANIFEST: &str = r#"
        [detection]
        id = "example"
        version = "1.0.0"
        title = "Example"
        [detection.when]
        service = "http"
        [detection.capabilities]
        class = "passive"
    "#;

    #[test]
    fn a_step_array_is_a_flow() {
        let source = format!("{MANIFEST}\n[[step]]\nsend = \"x\"\nexpect = \"y\"\n");
        assert_eq!(tier_of(&source), Ok(Tier::Flow));
    }

    #[test]
    fn a_compute_section_is_a_module() {
        let source = format!("{MANIFEST}\n[compute]\nlanguage = \"rhai\"\nbody = \"x.rhai\"\n");
        assert_eq!(tier_of(&source), Ok(Tier::Compute));
    }

    #[test]
    fn a_host_gate_is_a_host_detection() {
        let source = "\
            [detection]\n\
            id = \"example\"\n\
            version = \"1.0.0\"\n\
            title = \"Example\"\n\
            [detection.host]\n\
            ports_open = [88, 389]\n";
        assert_eq!(tier_of(source), Ok(Tier::Host));
    }

    /// Two tiers in one document is refused rather than resolved by precedence.
    /// Which tier runs a detection decides what it is handed, so a document that
    /// asks for both has to be corrected by whoever wrote it.
    #[test]
    fn a_document_naming_two_tiers_is_refused() {
        let source = format!(
            "{MANIFEST}\n[[step]]\nsend = \"x\"\nexpect = \"y\"\n\
             [compute]\nlanguage = \"rhai\"\nbody = \"x.rhai\"\n"
        );
        let error = tier_of(&source).expect_err("two tiers are not decidable");
        assert!(error.contains("not decidable"), "{error}");
    }

    #[test]
    fn a_document_naming_no_tier_is_refused() {
        let error = tier_of(MANIFEST).expect_err("a manifest alone is no detection");
        assert!(error.contains("names no tier"), "{error}");
    }

    /// An out-of-line body arrives inline, and the hash covers the code rather
    /// than the document that referenced it, which is what the build records for
    /// the same detection in `assets/detect/`.
    #[test]
    fn an_out_of_line_body_is_inlined() {
        let source = format!("{MANIFEST}\n[compute]\nlanguage = \"rhai\"\nbody = \"x.rhai\"\n");
        let mut bodies = BTreeMap::new();
        bodies.insert(
            "x.rhai".to_string(),
            "fn analyze(ctx, responses) { [] }".to_string(),
        );

        let resolved = resolve_compute(&source, &bodies).expect("the body resolves");
        assert_eq!(resolved.body, "fn analyze(ctx, responses) { [] }");
        assert!(resolved.document.contains("fn analyze"));
        assert!(!resolved.document.contains("x.rhai"));
    }

    #[test]
    fn an_inline_body_is_left_as_it_was_written() {
        let source = format!(
            "{MANIFEST}\n[compute]\nlanguage = \"rhai\"\nsource = \"fn analyze() {{ }}\"\n"
        );
        let resolved =
            resolve_compute(&source, &BTreeMap::new()).expect("an inline body needs no resolving");
        assert_eq!(resolved.body, "fn analyze() { }");
        assert_eq!(resolved.document, source);
    }

    /// A body nothing supplied is an error naming it. The alternative is a
    /// detection that compiles to nothing and reports nothing, which reads in a
    /// report exactly like one that ran and found the host clean.
    #[test]
    fn a_missing_body_names_what_was_missing() {
        let source = format!("{MANIFEST}\n[compute]\nlanguage = \"rhai\"\nbody = \"gone.rhai\"\n");
        let error =
            resolve_compute(&source, &BTreeMap::new()).expect_err("the body is not supplied");
        assert!(error.contains("gone.rhai"), "{error}");
    }
}
