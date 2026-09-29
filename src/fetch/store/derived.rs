// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Data made from fetched data
//!
//! A fetched feed is rarely what the engine reads: tens of megabytes of
//! archive or JSON are converted once into the compact dataset a scan loads,
//! and a signed bundle's sources are checked and compiled before they run.
//! What is made is kept beside what it was made from, and has to answer the
//! question a reader asks of it: is this still what those sources say?
//!
//! ## One call that decides, converts and stores
//!
//! [`Store::derive`] takes a description of the derived data, a [`Derived`]
//! naming its sources and the version of the conversion, and a closure that
//! makes it. It opens each source's stored copy, and when the derived copy
//! already on disk was made by the same version from exactly those copies it
//! returns without running the closure; otherwise it runs it and puts what it
//! returned in place. An update can therefore call it after every fetch and
//! pay for a conversion only when a source changed or the converter did.
//!
//! A closure rather than a call that takes finished bytes, because the check
//! that makes skipping safe has to see the same source copies the conversion
//! reads. Handed bytes, the store could only record whatever the caller said
//! they were made from, and a caller that read a source, lost a race to an
//! update and then recorded the newer copy's digest would store a dataset
//! that claims to be current and is not. Here the sources are opened files,
//! which stay the copies their metadata describes whatever an update does
//! meanwhile, and their digests are what is recorded.
//!
//! ## Locking
//!
//! The derived entry has the two locks every entry has. Its update lock is
//! held from before the sources are opened until the result is in place, so
//! two derivations of one entry run one after the other and the second finds
//! the first's result current. The sources' own update locks are not taken:
//! an update of a source may replace it during a long conversion, and the
//! conversion carries on with the copy it opened and records that copy, which
//! the next derivation then finds stale. A fetch never waits on a conversion,
//! and a conversion never waits on a download.
//!
//! ## Where it is kept
//!
//! Under `<root>/derived/<id>/`, with the same `data`, `metadata.toml` and
//! locks as a fetched resource, written the same way: staged, on disk, and
//! renamed into place, with every name reached under `sudo` as a journal's
//! are. No resource id may start with `derived`, so the two never share a
//! directory.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::super::{InvalidResource, Resource, is_valid_id};
use super::{
    DERIVED, FetchError, Metadata, Store, Stored, hex, lock_directory, open_data, read_locked,
    read_metadata_as, storage, unhex,
};

/// The version of the derived metadata layout.
const FORMAT: u32 = 1;

/// Data a caller makes from stored resources: what it is called, which
/// resources it is made from, and which version of the conversion makes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derived {
    id: String,
    version: String,
    sources: Vec<Resource>,
}

impl Derived {
    /// The derived data `id`, made by `version` of its conversion from
    /// `sources`.
    ///
    /// The id follows the rule for a resource's, and is its own namespace:
    /// `advisories/ubuntu` names derived data and a resource alike without
    /// the two meeting. The version is whatever tells one conversion from the
    /// next, such as the dataset's format version: a copy made by another
    /// version is never current, so changing the converter rebuilds every copy
    /// the old one made.
    ///
    /// # Errors
    ///
    /// [`InvalidResource::Id`] for an id outside the resource id rule, and
    /// [`InvalidResource::NoSources`] where there is nothing to derive from.
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
        sources: Vec<Resource>,
    ) -> Result<Self, InvalidResource> {
        let id = id.into();
        if !is_valid_id(&id) {
            return Err(InvalidResource::Id(id));
        }
        if sources.is_empty() {
            return Err(InvalidResource::NoSources(id));
        }
        Ok(Self {
            id,
            version: version.into(),
            sources,
        })
    }

    /// The name it is kept under.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The version of the conversion that makes it.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The resources it is made from, in the order the conversion is handed
    /// them.
    pub fn sources(&self) -> &[Resource] {
        &self.sources
    }
}

/// What is known about a derived copy.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedMetadata {
    /// The version of the conversion that made it.
    pub version: String,
    /// When it was made.
    pub derived_at: SystemTime,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256.
    pub sha256: [u8; 32],
    /// The copy of each source it was made from, in the order the
    /// conversion was handed them.
    pub sources: Vec<Source>,
}

/// One stored copy a derived copy was made from.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The resource's id.
    pub id: String,
    /// That copy's SHA-256, which is what identifies it.
    pub sha256: [u8; 32],
    /// When that copy was downloaded, for saying how old the data behind the
    /// derived copy is.
    pub fetched_at: SystemTime,
}

impl Source {
    /// The copy `metadata` describes, of the resource `id`.
    fn of(id: &str, metadata: &Metadata) -> Self {
        Self {
            id: id.to_string(),
            sha256: metadata.sha256,
            fetched_at: metadata.fetched_at,
        }
    }

    /// Whether this names the same copy as `other`. Times are left out: a
    /// copy is its bytes, and a download of identical bytes keeps its time.
    fn same_copy(&self, other: &Source) -> bool {
        self.id == other.id && self.sha256 == other.sha256
    }
}

impl DerivedMetadata {
    /// Whether this copy was made by `derived`'s version from exactly the
    /// source copies in `sources`.
    fn made_from(&self, derived: &Derived, sources: &[Source]) -> bool {
        self.version == derived.version
            && self.sources.len() == sources.len()
            && self
                .sources
                .iter()
                .zip(sources)
                .all(|(made, now)| made.same_copy(now))
    }
}

/// What [`Store::derive`] did.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Derivation {
    /// The conversion ran, and its result replaced the stored copy.
    Built(DerivedMetadata),
    /// The stored copy was made by this version from the source copies
    /// stored now, so the conversion did not run.
    Current(DerivedMetadata),
}

impl Derivation {
    /// What is now known about the stored copy.
    pub fn metadata(&self) -> &DerivedMetadata {
        match self {
            Derivation::Built(metadata) | Derivation::Current(metadata) => metadata,
        }
    }
}

/// Why a derivation stopped. The stored derived copy is as it was.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum DeriveError<E: std::error::Error + 'static> {
    /// The store could not be read or written.
    #[error("{0}")]
    Store(#[from] FetchError),

    /// A source has never been stored, so there is nothing to derive from.
    #[error("{id} is not stored")]
    NotStored {
        /// The source's id.
        id: String,
    },

    /// The conversion failed.
    #[error("conversion failed: {0}")]
    Convert(#[source] E),
}

/// A derived copy, open for reading.
#[derive(Debug)]
pub struct DerivedCopy {
    path: PathBuf,
    file: File,
    metadata: DerivedMetadata,
    current: bool,
}

impl DerivedCopy {
    /// Where the data is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What is known about it: how it was made, and from what.
    pub fn metadata(&self) -> &DerivedMetadata {
        &self.metadata
    }

    /// Whether, when it was opened, it was made by the version asked for from
    /// the source copies stored then.
    ///
    /// A copy that is not is still what the last conversion made, and a
    /// reader may well use it rather than nothing, saying it is behind its
    /// sources; [`Store::derive`] is what brings it up to date.
    pub fn is_current(&self) -> bool {
        self.current
    }

    /// The copy, as the file opened alongside its metadata.
    pub fn into_file(self) -> File {
        self.file
    }

    /// The copy's bytes.
    ///
    /// # Errors
    ///
    /// Whatever reading the file fails with.
    pub fn read(mut self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(usize::try_from(self.metadata.size).unwrap_or(0));
        self.file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

impl Store {
    /// The directory `derived` is kept in.
    pub fn derived_directory(&self, derived: &Derived) -> PathBuf {
        self.under(&format!("{DERIVED}/{}", derived.id()))
    }

    /// Brings `derived` up to date with its sources, running `convert` only
    /// when the stored copy was not made by this version from the source
    /// copies stored now.
    ///
    /// `convert` is handed the sources' stored copies, in the order
    /// [`Derived::sources`] lists them, and returns the derived data. What it
    /// returns is written beside the stored copy and renamed over it; a
    /// conversion that fails, or a write that does, leaves the stored copy as
    /// it was. Two derivations of one entry, from this process or another,
    /// run one after the other.
    ///
    /// A closure rather than finished bytes, so that what is recorded as the
    /// sources is the copies the conversion actually read: they are opened
    /// files, which stay those copies whatever an update does meanwhile. The
    /// sources' own update locks are not taken, so a fetch never waits on a
    /// conversion; a source replaced during one leaves the result recording
    /// the copy it was made from, and the next derivation rebuilds it.
    ///
    /// It blocks, on the lock and on the conversion, so an async caller runs
    /// it with `spawn_blocking`.
    ///
    /// ```no_run
    /// use zond_engine::fetch::{Derived, Store, advisory::Feed};
    ///
    /// # fn convert(_: &[u8]) -> Result<Vec<u8>, std::io::Error> { Ok(Vec::new()) }
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let store = Store::new("/var/cache/zond");
    /// let ubuntu = Derived::new("advisories/ubuntu", "1", vec![Feed::UbuntuOsv.resource()])?;
    /// let made = store.derive(&ubuntu, |sources| {
    ///     let osv = sources.into_iter().next().expect("one source").read()?;
    ///     convert(&osv)
    /// })?;
    /// println!("{} bytes", made.metadata().size);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`DeriveError::NotStored`] for a source never fetched,
    /// [`DeriveError::Convert`] with what the conversion failed with, and
    /// [`DeriveError::Store`] where the store could not be read or written.
    pub fn derive<E: std::error::Error + 'static>(
        &self,
        derived: &Derived,
        convert: impl FnOnce(Vec<Stored>) -> Result<Vec<u8>, E>,
    ) -> Result<Derivation, DeriveError<E>> {
        let update = lock_directory(self.derived_directory(derived))?;

        let mut opened = Vec::with_capacity(derived.sources.len());
        for resource in &derived.sources {
            let stored = self.open(resource)?.ok_or_else(|| DeriveError::NotStored {
                id: resource.id().to_string(),
            })?;
            opened.push(stored);
        }
        let sources: Vec<Source> = derived
            .sources
            .iter()
            .zip(&opened)
            .map(|(resource, stored)| Source::of(resource.id(), stored.metadata()))
            .collect();

        if let Some(stored) = read_metadata_as(&update.directory, decode)?
            && stored.made_from(derived, &sources)
            && open_data(&update.directory, stored.size).is_ok()
        {
            return Ok(Derivation::Current(stored));
        }

        let bytes = convert(opened).map_err(DeriveError::Convert)?;
        let metadata = DerivedMetadata {
            version: derived.version.clone(),
            derived_at: SystemTime::now(),
            size: bytes.len() as u64,
            sha256: ring::digest::digest(&ring::digest::SHA256, &bytes)
                .as_ref()
                .try_into()
                .expect("SHA-256 is thirty-two bytes"),
            sources,
        };

        let written = update.stage().and_then(|(mut file, path)| {
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| storage(&path, e))
        });
        if let Err(e) = written.and_then(|()| update.replace(&encode(&metadata), None)) {
            update.discard();
            return Err(e.into());
        }
        Ok(Derivation::Built(metadata))
    }

    /// The stored copy of `derived`, opened, with what is known about it and
    /// whether it is current; `None` when none has been made.
    ///
    /// # Errors
    ///
    /// [`FetchError::Storage`] where a file is there and cannot be read.
    pub fn open_derived(&self, derived: &Derived) -> Result<Option<DerivedCopy>, FetchError> {
        let directory = self.derived_directory(derived);
        let (path, file, metadata) = {
            let Some(_lock) = read_locked(&directory)? else {
                return Ok(None);
            };
            let Some(metadata) = read_metadata_as(&directory, decode)? else {
                return Ok(None);
            };
            let (path, file) = open_data(&directory, metadata.size)?;
            (path, file, metadata)
        };

        // Asked after the derived copy's read lock is let go, so a reader
        // never holds two entries' locks at once.
        let mut sources = Vec::with_capacity(derived.sources.len());
        for resource in &derived.sources {
            match self.current_metadata(resource)? {
                Some(stored) => sources.push(Source::of(resource.id(), &stored)),
                None => break,
            }
        }
        let current =
            sources.len() == derived.sources.len() && metadata.made_from(derived, &sources);
        Ok(Some(DerivedCopy {
            path,
            file,
            metadata,
            current,
        }))
    }
}

/// The derived metadata file, as it is written and read.
#[derive(serde::Serialize, serde::Deserialize)]
struct DerivedFile {
    format: u32,
    version: String,
    derived_at: u64,
    size: u64,
    sha256: String,
    sources: Vec<SourceFile>,
}

/// One source, as the derived metadata file holds it.
#[derive(serde::Serialize, serde::Deserialize)]
struct SourceFile {
    id: String,
    sha256: String,
    fetched_at: u64,
}

/// Whole seconds since the Unix epoch, as the metadata keeps times.
fn seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// `metadata` as the file holds it.
fn encode(metadata: &DerivedMetadata) -> String {
    let file = DerivedFile {
        format: FORMAT,
        version: metadata.version.clone(),
        derived_at: seconds(metadata.derived_at),
        size: metadata.size,
        sha256: hex(&metadata.sha256),
        sources: metadata
            .sources
            .iter()
            .map(|source| SourceFile {
                id: source.id.clone(),
                sha256: hex(&source.sha256),
                fetched_at: seconds(source.fetched_at),
            })
            .collect(),
    };
    toml::to_string(&file).expect("the metadata is plain strings and integers")
}

/// The derived metadata a file holds, or why it is not metadata this wrote.
fn decode(text: &str) -> Result<DerivedMetadata, String> {
    let file: DerivedFile = toml::from_str(text).map_err(|e| e.message().to_string())?;
    if file.format != FORMAT {
        return Err(format!("metadata format {} is not {FORMAT}", file.format));
    }
    let time = |seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
    let digest =
        |text: &str| unhex(text).ok_or_else(|| format!("'{text}' is not a 32-byte hex digest"));
    let sources = file
        .sources
        .into_iter()
        .map(|source| {
            Ok(Source {
                sha256: digest(&source.sha256)?,
                id: source.id,
                fetched_at: time(source.fetched_at),
            })
        })
        .collect::<Result<_, String>>()?;
    Ok(DerivedMetadata {
        version: file.version,
        derived_at: time(file.derived_at),
        size: file.size,
        sha256: digest(&file.sha256)?,
        sources,
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
    use super::super::Verified;
    use super::*;
    use crate::fetch::Verify;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A store in a directory of its own, removed when the test is done.
    struct Scratch(Store);

    impl Scratch {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("zond-derive-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            Self(Store::new(root))
        }
    }

    impl std::ops::Deref for Scratch {
        type Target = Store;
        fn deref(&self) -> &Store {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0.root());
        }
    }

    fn resource(id: &str) -> Resource {
        Resource::new(
            id,
            format!("https://example.com/{id}"),
            1024,
            Verify::Transport,
        )
        .unwrap()
    }

    /// Stores `bytes` as `resource`'s copy, as a fetch would.
    fn put(store: &Store, resource: &Resource, bytes: &[u8]) {
        let update = store.lock_for_update(resource).unwrap();
        let (mut file, _) = update.stage().unwrap();
        file.write_all(bytes).unwrap();
        let sha256 = ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .try_into()
            .unwrap();
        let metadata = Metadata::new(
            resource.url().to_string(),
            bytes.len() as u64,
            sha256,
            Verified::Transport,
        );
        update.commit(&metadata, None).unwrap();
    }

    /// The conversion these tests run: the sources joined, upper-cased, and
    /// counted so a test can tell whether it ran.
    fn upper(runs: &AtomicUsize) -> impl FnOnce(Vec<Stored>) -> Result<Vec<u8>, io::Error> + '_ {
        move |sources| {
            runs.fetch_add(1, Ordering::SeqCst);
            let mut joined = Vec::new();
            for stored in sources {
                joined.extend(stored.read()?.to_ascii_uppercase());
            }
            Ok(joined)
        }
    }

    /// What a conversion made is kept with the copies it was made from, and
    /// read back as current while those copies are the ones stored.
    #[test]
    fn a_derived_copy_records_its_sources_and_reads_back_current() {
        let store = Scratch::new("records");
        let (a, b) = (resource("feeds/a"), resource("feeds/b"));
        put(&store, &a, b"one ");
        put(&store, &b, b"two");
        let derived = Derived::new("made/ab", "1", vec![a.clone(), b.clone()]).unwrap();

        let runs = AtomicUsize::new(0);
        let made = store.derive(&derived, upper(&runs)).unwrap();
        assert!(matches!(made, Derivation::Built(_)), "{made:?}");

        let copy = store
            .open_derived(&derived)
            .unwrap()
            .expect("a derived copy");
        assert!(copy.is_current());
        let recorded: Vec<(&str, [u8; 32])> = copy
            .metadata()
            .sources
            .iter()
            .map(|source| (source.id.as_str(), source.sha256))
            .collect();
        let a_sha = store.open(&a).unwrap().unwrap().metadata().sha256;
        let b_sha = store.open(&b).unwrap().unwrap().metadata().sha256;
        assert_eq!(recorded, [("feeds/a", a_sha), ("feeds/b", b_sha)]);
        assert_eq!(copy.read().unwrap(), b"ONE TWO");
        assert!(
            store.root().join("derived/made/ab/data").exists(),
            "derived data is kept under derived/"
        );
    }

    /// An update calls the derivation after every fetch, so one whose sources
    /// have not changed must not pay for the conversion again.
    #[test]
    fn a_derivation_whose_sources_have_not_changed_does_not_convert_again() {
        let store = Scratch::new("current");
        let a = resource("feeds/a");
        put(&store, &a, b"one");
        let derived = Derived::new("made/a", "1", vec![a.clone()]).unwrap();

        let runs = AtomicUsize::new(0);
        let _ = store.derive(&derived, upper(&runs)).unwrap();
        let again = store.derive(&derived, upper(&runs)).unwrap();
        assert!(matches!(again, Derivation::Current(_)), "{again:?}");
        assert_eq!(runs.load(Ordering::SeqCst), 1, "the conversion ran twice");
    }

    /// A source replaced since the conversion makes the derived copy stale to
    /// a reader, and the next derivation rebuilds it; so does a new version
    /// of the conversion, with the sources unchanged.
    #[test]
    fn a_changed_source_or_version_makes_the_derived_copy_stale() {
        let store = Scratch::new("stale");
        let a = resource("feeds/a");
        put(&store, &a, b"one");
        let derived = Derived::new("made/a", "1", vec![a.clone()]).unwrap();
        let runs = AtomicUsize::new(0);
        let _ = store.derive(&derived, upper(&runs)).unwrap();

        put(&store, &a, b"uno");
        let copy = store.open_derived(&derived).unwrap().unwrap();
        assert!(
            !copy.is_current(),
            "a copy made from a replaced source read as current"
        );
        assert_eq!(
            copy.read().unwrap(),
            b"ONE",
            "the stale copy is still readable"
        );

        let rebuilt = store.derive(&derived, upper(&runs)).unwrap();
        assert!(matches!(rebuilt, Derivation::Built(_)), "{rebuilt:?}");
        assert!(store.open_derived(&derived).unwrap().unwrap().is_current());

        let next = Derived::new("made/a", "2", vec![a]).unwrap();
        assert!(!store.open_derived(&next).unwrap().unwrap().is_current());
        let rebuilt = store.derive(&next, upper(&runs)).unwrap();
        assert!(matches!(rebuilt, Derivation::Built(_)), "{rebuilt:?}");
        assert_eq!(runs.load(Ordering::SeqCst), 3);
    }

    /// A conversion that fails leaves the copy it would have replaced, and
    /// nothing of its own behind.
    #[test]
    fn a_failed_conversion_keeps_the_old_copy() {
        let store = Scratch::new("failed");
        let a = resource("feeds/a");
        put(&store, &a, b"one");
        let derived = Derived::new("made/a", "1", vec![a.clone()]).unwrap();
        let runs = AtomicUsize::new(0);
        let _ = store.derive(&derived, upper(&runs)).unwrap();

        put(&store, &a, b"two");
        let failed = store.derive(&derived, |_| Err(io::Error::other("malformed feed")));
        assert!(matches!(failed, Err(DeriveError::Convert(_))), "{failed:?}");
        assert_eq!(
            store
                .open_derived(&derived)
                .unwrap()
                .unwrap()
                .read()
                .unwrap(),
            b"ONE"
        );
    }

    /// Nothing is derived from a source that was never fetched.
    #[test]
    fn a_missing_source_is_named() {
        let store = Scratch::new("missing");
        let derived = Derived::new("made/a", "1", vec![resource("feeds/a")]).unwrap();
        let runs = AtomicUsize::new(0);
        let missing = store.derive(&derived, upper(&runs));
        assert!(
            matches!(&missing, Err(DeriveError::NotStored { id }) if id == "feeds/a"),
            "{missing:?}"
        );
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        assert!(store.open_derived(&derived).unwrap().is_none());
    }

    /// Two derivations of one entry at once run one after the other, so the
    /// second finds the first's result current rather than converting again
    /// and racing it to the rename.
    #[test]
    fn two_derivations_of_one_entry_do_not_interleave() {
        let store = Scratch::new("concurrent");
        let a = resource("feeds/a");
        put(&store, &a, b"one");
        let derived = Derived::new("made/a", "1", vec![a]).unwrap();
        let runs = AtomicUsize::new(0);

        let slow = |sources: Vec<Stored>| {
            std::thread::sleep(Duration::from_millis(200));
            upper(&runs)(sources)
        };
        let outcomes: Vec<Derivation> = std::thread::scope(|scope| {
            let one = scope.spawn(|| store.derive(&derived, slow).unwrap());
            let two = scope.spawn(|| store.derive(&derived, slow).unwrap());
            vec![one.join().unwrap(), two.join().unwrap()]
        });
        assert_eq!(runs.load(Ordering::SeqCst), 1, "{outcomes:?}");
    }

    /// A derived id follows the resource id rule, and derived data needs
    /// something to be derived from.
    #[test]
    fn a_derived_entry_is_described_as_a_resource_is() {
        assert_eq!(
            Derived::new("../x", "1", vec![resource("feeds/a")]),
            Err(InvalidResource::Id("../x".into()))
        );
        assert_eq!(
            Derived::new("made/a", "1", Vec::new()),
            Err(InvalidResource::NoSources("made/a".into()))
        );
    }

    /// The file keeps everything a staleness check and a reader need.
    #[test]
    fn derived_metadata_reads_back_as_it_was_written() {
        let metadata = DerivedMetadata {
            version: "advisories 3".into(),
            derived_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
            size: 42,
            sha256: [1; 32],
            sources: vec![Source {
                id: "feeds/a".into(),
                sha256: [2; 32],
                fetched_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_789_000_000),
            }],
        };
        assert_eq!(decode(&encode(&metadata)), Ok(metadata));
    }
}
