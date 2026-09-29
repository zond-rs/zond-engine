// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Fetching data the engine does not ship
//!
//! Some of what the engine reasons with changes faster than it is released:
//! which distribution build fixed which vulnerability, above all, and later
//! the detections somebody else publishes. This module downloads such data on
//! request and keeps it in a directory the caller names, so that a command
//! line, a web front end and a scheduled job all fetch it the same way and
//! read the same copy back.
//!
//! It is a small general layer rather than a downloader for one feed. A
//! [`Resource`] says what to fetch, how large it may be and how it is checked;
//! a [`Store`] says where it is kept; a [`Client`] does the fetching. The
//! feeds the engine knows today are declared in [`advisory`], and
//! [`registry`] lists every resource there is, so a caller that means
//! "update everything" does not need to know what that is.
//!
//! ## Nothing happens unless asked
//!
//! The whole module is behind the `fetch` feature, and nothing in it runs
//! except when a caller calls it: no scan fetches anything, and nothing here
//! picks a directory on its own. [`default_cache_dir`] says where the
//! conventional one is, and creates nothing.
//!
//! ## What is checked, and by what
//!
//! Every fetch is over HTTPS, redirects included, verified against the
//! operating system's trust store, so a corporate network that inspects TLS
//! and installs its own authority there works as every other program on the
//! machine does. A resource can ask for more, a pinned SHA-256 or a detached
//! Ed25519 signature by a key the caller trusts; see [`Verify`]. Whatever
//! fails a check is discarded and the copy already stored is kept.
//!
//! ## The TLS stack
//!
//! The HTTP client is `reqwest`, built without its default TLS provider,
//! because that provider is `aws-lc-rs` and needs a C toolchain with CMake
//! that the Windows cross-build and some users lack. The engine already
//! carries `rustls` with the `ring` provider for its own TLS probes, so the
//! client is handed a `rustls` configuration built on that provider and on
//! `rustls-platform-verifier`, the verifier `reqwest` itself would have
//! chosen. The configuration is passed whole rather than by installing `ring`
//! as the process's default provider, since a library that installs a
//! process-wide default makes the choice for every other crate in the
//! program. A configuration `reqwest` cannot take, which a mismatch of
//! `rustls` versions would produce, fails [`Client::new`] rather than a
//! download.

use std::path::PathBuf;

use crate::signature::Domain;

pub mod advisory;
mod client;
mod store;

pub use client::{
    Client, DownloadProgress, FetchError, NetworkFailure, Outcome, VerificationFailure,
};
pub use store::{Metadata, Store, Stored};

/// Every resource the engine knows how to fetch.
///
/// What a caller walks to bring every copy up to date. Today that is the
/// distribution advisory feeds; see [`advisory::Feed`].
pub fn registry() -> Vec<Resource> {
    advisory::Feed::ALL
        .iter()
        .map(|feed| feed.resource())
        .collect()
}

/// Where fetched data lives by convention, for whoever this run is on behalf
/// of.
///
/// | | Cache root |
/// |---|---|
/// | Unix (incl. macOS) | `$XDG_CACHE_HOME/zond`, else `$HOME/.cache/zond` |
/// | Windows | `%LOCALAPPDATA%\zond\cache` |
///
/// The cache directory rather than the state one the journal uses: what is
/// here can be fetched again at any time, and a user clearing caches to free
/// space should be free to remove it. Under `sudo` it is the invoking user's
/// directory, by the same rule the journal and the settings follow, so an
/// update run as the user and a scan run with `sudo` read one copy; see
/// [`journal::paths`](crate::journal::paths).
///
/// `None` when the environment names no home at all. Nothing is created.
#[cfg(not(windows))]
pub fn default_cache_dir() -> Option<PathBuf> {
    crate::journal::paths::base_directory("XDG_CACHE_HOME", std::path::Path::new(".cache"))
        .map(|root| root.join(VENDOR))
}

/// Where fetched data lives by convention on Windows: `%LOCALAPPDATA%`, which
/// does not roam between machines, beside the journals.
#[cfg(windows)]
pub fn default_cache_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|root| root.join(VENDOR).join("cache"))
}

/// The one vendor directory every root this crate uses is joined with.
const VENDOR: &str = "zond";

/// Something to fetch: where it comes from, where it is kept, how large it may
/// be, and how it is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    id: String,
    url: String,
    max_bytes: u64,
    verify: Verify,
}

impl Resource {
    /// The resource `id`, fetched from `url`, refused beyond `max_bytes` and
    /// checked as `verify` says.
    ///
    /// The id names the resource in a [`Store`] and is kept stable across
    /// releases, since a copy is found by it: one or more segments of lowercase
    /// letters, digits, `-`, `_` and `.`, joined by `/`, such as
    /// `advisories/ubuntu-osv`. A segment is never `.` or `..` and never
    /// starts with a dot, so an id is always a path inside the store.
    ///
    /// # Errors
    ///
    /// [`InvalidResource`] for an id outside that shape, and for a URL, the
    /// resource's or a signature's, that is not an absolute `http` or `https`
    /// URL. Whether plain `http` may be fetched is the [`Client`]'s to decide.
    pub fn new(
        id: impl Into<String>,
        url: impl Into<String>,
        max_bytes: u64,
        verify: Verify,
    ) -> Result<Self, InvalidResource> {
        let id = id.into();
        let url = url.into();
        if !is_valid_id(&id) {
            return Err(InvalidResource::Id(id));
        }
        check_url(&url)?;
        if let Verify::Ed25519 { signature_url, .. } = &verify {
            check_url(signature_url)?;
        }
        Ok(Self {
            id,
            url,
            max_bytes,
            verify,
        })
    }

    /// The name it is kept under in a [`Store`].
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Where it is fetched from.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The most it may be. A download that passes this is abandoned as the
    /// byte past it arrives, and nothing of it is kept.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// How what arrives is checked before it is kept.
    pub fn verify(&self) -> &Verify {
        &self.verify
    }
}

/// How a download is checked before it replaces the stored copy.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verify {
    /// Only by the transport: HTTPS to the named host, verified against the
    /// system's trust store. What the distributions' own security feeds
    /// offer, since they publish neither a digest nor a signature beside the
    /// file.
    Transport,

    /// The download must hash to this SHA-256, for a resource whose exact
    /// content the caller knows in advance.
    Sha256([u8; 32]),

    /// The download must carry a detached signature, fetched from
    /// `signature_url`, by `public_key` under `domain`.
    ///
    /// The signature is the document [`signature`](crate::signature) writes
    /// and reads, so something published here is signed with the same tool
    /// that signs a report or a detection bundle. The key is the caller's to
    /// trust and never read from the signature; see
    /// [`Signature::verify`](crate::signature::Signature::verify).
    Ed25519 {
        /// The raw 32-byte Ed25519 public key the signature must be by.
        public_key: [u8; 32],
        /// Where the detached signature document is published.
        signature_url: String,
        /// What kind of document the signature must have been made over.
        domain: Domain,
    },
}

/// Why a [`Resource`] could not be described.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidResource {
    /// The id is not a path-safe name; see [`Resource::new`].
    #[error("'{0}' is not a resource id (lowercase segments joined by '/')")]
    Id(String),

    /// A URL is not an absolute `http` or `https` URL.
    #[error("'{0}' is not an http or https URL")]
    Url(String),
}

/// Whether `id` is one or more safe segments joined by `/`.
fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.split('/').all(|segment| {
            !segment.is_empty()
                && !segment.starts_with('.')
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
        })
}

/// Refuses a URL that is not absolute `http` or `https` with a host.
///
/// A check of the shape only: the client parses it again when it fetches, and
/// that parse is the one that decides. What this saves is a resource that
/// could never be fetched being described without complaint.
fn check_url(url: &str) -> Result<(), InvalidResource> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    let host = rest.and_then(|rest| rest.split(['/', '?', '#']).next());
    match host {
        Some(host) if !host.is_empty() && !url.contains(char::is_whitespace) => Ok(()),
        _ => Err(InvalidResource::Url(url.to_string())),
    }
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

    /// An id is joined onto the store's directory, so one that could climb out
    /// of it, name a hidden file or carry a separator of another platform
    /// would let a resource description write somewhere nobody chose.
    #[test]
    fn an_id_is_refused_unless_it_is_a_path_inside_the_store() {
        for good in ["advisories/ubuntu-osv", "a", "detections/bundle-1.2_x"] {
            assert!(is_valid_id(good), "{good} was refused");
        }
        for bad in [
            "",
            "/abs",
            "trailing/",
            "a//b",
            "..",
            "a/../b",
            ".hidden",
            "a/.b",
            "Upper",
            "back\\slash",
            "sp ace",
            "c:",
        ] {
            assert!(!is_valid_id(bad), "{bad:?} was accepted");
        }
    }

    /// A resource that could never be fetched is refused when it is described,
    /// rather than when somebody runs an update and finds out.
    #[test]
    fn a_url_that_is_not_http_is_refused_when_the_resource_is_described() {
        for bad in [
            "ftp://example.com/x",
            "https://",
            "example.com/x",
            "https:// x",
        ] {
            assert_eq!(
                Resource::new("a", bad, 1, Verify::Transport),
                Err(InvalidResource::Url(bad.to_string()))
            );
        }
        let unsigned = Verify::Ed25519 {
            public_key: [0; 32],
            signature_url: "file:///etc/passwd".into(),
            domain: Domain::DETECTIONS,
        };
        assert!(
            Resource::new("a", "https://example.com/x", 1, unsigned).is_err(),
            "a signature URL is held to the same rule"
        );
    }

    /// Every resource the engine registers is one that can be described, and
    /// no two share an id, since the second would overwrite the first's copy.
    #[test]
    fn the_registry_holds_distinct_ids() {
        let resources = registry();
        let mut ids: Vec<&str> = resources.iter().map(Resource::id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), resources.len(), "{ids:?}");
        assert!(!resources.is_empty());
    }

    /// The conventional directory ends in the vendor directory, so it is one a
    /// user can find and remove, and asking for it creates nothing.
    #[cfg(not(windows))]
    #[test]
    fn the_default_cache_directory_is_under_the_vendor_directory() {
        if let Some(path) = default_cache_dir() {
            assert!(path.is_absolute(), "{path:?}");
            assert!(path.ends_with(VENDOR), "{path:?}");
            let existed = path.exists();
            let _ = default_cache_dir();
            assert_eq!(existed, path.exists(), "asking for the directory made it");
        }
    }
}
