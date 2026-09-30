// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Where fetched data is kept
//!
//! One directory per resource, named by its id, under a root the caller
//! chooses:
//!
//! | Name | What it is |
//! |---|---|
//! | `data` | The resource's bytes, exactly as they arrived and were checked. |
//! | `metadata.toml` | Where they came from, when, and what they hash to; see [`Metadata`]. |
//! | `signature` | The detached signature they were checked against, for a resource checked by one. |
//! | `update.lock` | Held by an update for as long as it runs. |
//! | `read.lock` | Held by a reader while it opens the pair, and by an update while it replaces it. |
//! | `*.partial` | What an update is writing, before it is renamed into place. |
//!
//! ## A reader sees one whole copy or none
//!
//! A download is written beside `data` and renamed over it only once it has
//! arrived whole and passed its checks, so a crash, a refused download or a
//! full disk leaves the previous copy where it was. The metadata is removed
//! before the renames and written after them, so whenever `metadata.toml`
//! exists it describes the `data` and the `signature` beside it; an update that dies between the two
//! leaves no metadata, which reads as nothing stored and costs one full
//! download on the next update, never a copy described by another copy's
//! metadata.
//!
//! ## Two locks, so a long download does not stall a reader
//!
//! An update holds `update.lock` from before it asks the server until it is
//! done, so two updaters never interleave: the second waits, then asks with
//! what the first stored and is told nothing changed. The swap itself takes
//! `read.lock` exclusively for the few calls it lasts, and a reader takes it
//! shared while it opens the metadata and the data, so a reader never pairs
//! one copy's metadata with another's data and never waits for a download.
//! Both are advisory locks on the files' descriptors, released when the
//! holder exits however it exits.
//!
//! ## Data made from fetched data
//!
//! What a caller makes out of stored resources, a converted dataset say, is
//! kept in the same store by the same rules, under `derived/`; see
//! [`Store::derive`].
//!
//! ## Under `sudo`
//!
//! What an elevated run creates in the invoking user's home is given back to
//! them, and every name there is reached without following a link out of the
//! home, exactly as a journal's files are; see
//! [`ownership`]. An update run as the user and a
//! scan run with `sudo` then share one copy that both can read and replace.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::journal::ownership::{self, Place};
use crate::signature::Signature;

use super::{FetchError, Resource, Verify, is_valid_id};

/// The downloaded bytes.
const DATA: &str = "data";
/// What is known about them.
const METADATA: &str = "metadata.toml";
/// Held for as long as an update runs.
const UPDATE_LOCK: &str = "update.lock";
/// Held while the pair is opened or replaced.
const READ_LOCK: &str = "read.lock";
/// A download on its way to being `data`.
const DATA_PARTIAL: &str = "data.partial";
/// Metadata on its way to being `metadata.toml`.
const METADATA_PARTIAL: &str = "metadata.partial";
/// The detached signature the data was checked against.
const SIGNATURE: &str = "signature";
/// A signature on its way to being `signature`.
const SIGNATURE_PARTIAL: &str = "signature.partial";

/// The largest metadata file read back. One this writes is a dozen short
/// lines; the ceiling is for a file somebody else put there.
const MAX_METADATA_BYTES: u64 = 64 * 1024;

/// The version of the metadata layout, so a later one can be told apart.
const FORMAT: u32 = 1;

/// The first segment every derived file's directory is under, which no
/// resource id may start with, so a fetch and a derivation never share one;
/// see [`derived`].
pub(super) const DERIVED: &str = "derived";

/// The directory a caller's notes are kept in, which no resource id may start
/// with either; see [`Store::note`].
pub(super) const NOTES: &str = "notes";

/// The longest note kept: a word or a line, never a document.
const MAX_NOTE_BYTES: u64 = 4096;

mod derived;

pub use derived::{Derivation, DeriveError, Derived, DerivedCopy, DerivedMetadata, Source};

/// A directory holding fetched resources, one subdirectory each.
///
/// Naming a store touches nothing on disk. A store's directories are created
/// by the first update that needs them, and reading a resource never
/// creates anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// The store rooted at `root`, which the caller chooses; see
    /// [`default_cache_dir`](super::default_cache_dir) for the conventional
    /// one.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory the store was named with.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory one resource is kept in.
    pub fn directory(&self, resource: &Resource) -> PathBuf {
        self.under(resource.id())
    }

    /// The note the caller left under `name`, where there is one.
    ///
    /// For a front end's own small records about what it fetches, such as a
    /// person having declined a dataset when asked, so they are not asked
    /// again. Kept in the store beside the data it is about, so clearing the
    /// cache clears the choice with it, and written as the store's files are:
    /// never through a link, and under `sudo` for the invoking user.
    ///
    /// # Errors
    ///
    /// [`FetchError::Storage`] for a name that is not one lowercase path
    /// segment, and where a note is there and cannot be read.
    pub fn note(&self, name: &str) -> Result<Option<String>, FetchError> {
        let path = self.note_path(name)?;
        let file = match open(&path, Access::Read) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(storage(&path, e)),
        };
        let mut text = String::new();
        file.take(MAX_NOTE_BYTES)
            .read_to_string(&mut text)
            .map_err(|e| storage(&path, e))?;
        Ok(Some(text))
    }

    /// Leaves `text` under `name`, replacing a note already there. See
    /// [`note`](Self::note).
    ///
    /// # Errors
    ///
    /// [`FetchError::Storage`] for a name that is not one lowercase path
    /// segment, and where the note cannot be written.
    pub fn set_note(&self, name: &str, text: &str) -> Result<(), FetchError> {
        let path = self.note_path(name)?;
        let directory = self.root.join(NOTES);
        let created =
            ownership::create_missing(&directory, None).map_err(|e| storage(&directory, e))?;
        ownership::hand_over(&directory, &created);
        let mut file = create(&path).map_err(|e| storage(&path, e))?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| storage(&path, e))
    }

    /// Where the note `name` is kept, refusing a name that is not one path
    /// segment of a resource id's shape.
    fn note_path(&self, name: &str) -> Result<PathBuf, FetchError> {
        if name.contains('/') || !is_valid_id(name) {
            let invalid = io::Error::new(io::ErrorKind::InvalidInput, "not a note name");
            return Err(storage(&self.root.join(NOTES).join(name), invalid));
        }
        Ok(self.root.join(NOTES).join(name))
    }

    /// The directory an id names, one path component per segment.
    fn under(&self, id: &str) -> PathBuf {
        id.split('/')
            .fold(self.root.clone(), |path, segment| path.join(segment))
    }

    /// The stored copy of `resource`, opened, with what is known about it;
    /// `None` when nothing has been stored.
    ///
    /// The file is opened before this returns, so it stays the copy the
    /// metadata describes even if an update replaces the resource while the
    /// caller is still reading it.
    ///
    /// # Errors
    ///
    /// [`FetchError::Storage`] where a file is there and cannot be read, or
    /// where the data does not have the size its metadata records.
    pub fn open(&self, resource: &Resource) -> Result<Option<Stored>, FetchError> {
        let directory = self.directory(resource);
        let Some(_lock) = read_locked(&directory)? else {
            return Ok(None);
        };
        let Some(metadata) = read_metadata(&directory)? else {
            return Ok(None);
        };
        let (path, file) = open_data(&directory, metadata.size)?;
        let signature = match metadata.verified {
            Verified::Transport => None,
            Verified::Ed25519(_) => Some(read_signature(&directory)?),
        };
        Ok(Some(Stored {
            path,
            file,
            metadata,
            signature,
        }))
    }

    /// Takes `resource`'s update lock, creating its directory, and returns
    /// once no other update holds it.
    ///
    /// Blocks while another update runs, so an async caller takes it off the
    /// runtime's workers.
    pub(super) fn lock_for_update(&self, resource: &Resource) -> Result<Update, FetchError> {
        lock_directory(self.directory(resource))
    }

    /// What is known about the copy of `resource` stored now, without
    /// opening its data; `None` when nothing is stored.
    fn current_metadata(&self, resource: &Resource) -> Result<Option<Metadata>, FetchError> {
        let directory = self.directory(resource);
        let Some(_lock) = read_locked(&directory)? else {
            return Ok(None);
        };
        read_metadata(&directory)
    }
}

/// Takes the update lock of the entry at `directory`, creating it, and
/// returns once no other update holds it. Blocks while another does.
fn lock_directory(directory: PathBuf) -> Result<Update, FetchError> {
    let created =
        ownership::create_missing(&directory, None).map_err(|e| storage(&directory, e))?;
    ownership::hand_over(&directory, &created);

    let lock_path = directory.join(UPDATE_LOCK);
    let lock = open(&lock_path, Access::CreateOrOpen).map_err(|e| storage(&lock_path, e))?;
    lock.lock().map_err(|e| storage(&lock_path, e))?;
    Ok(Update {
        directory,
        _lock: lock,
    })
}

/// The read lock of the entry at `directory`, held shared; `None` where the
/// entry has never been written.
fn read_locked(directory: &Path) -> Result<Option<File>, FetchError> {
    let path = directory.join(READ_LOCK);
    let lock = match open(&path, Access::Read) {
        Ok(lock) => lock,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(storage(&path, e)),
    };
    lock.lock_shared().map_err(|e| storage(&path, e))?;
    Ok(Some(lock))
}

/// The data of the entry at `directory`, opened, refused unless it is the
/// `size` its metadata records.
fn open_data(directory: &Path, size: u64) -> Result<(PathBuf, File), FetchError> {
    let path = directory.join(DATA);
    let file = open(&path, Access::Read).map_err(|e| storage(&path, e))?;
    let held = file.metadata().map_err(|e| storage(&path, e))?.len();
    if held != size {
        return Err(storage(
            &path,
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("holds {held} bytes, and its metadata records {size}"),
            ),
        ));
    }
    Ok((path, file))
}

/// A stored copy of a resource, open for reading.
#[derive(Debug)]
pub struct Stored {
    path: PathBuf,
    file: File,
    metadata: Metadata,
    signature: Option<Signature>,
}

impl Stored {
    /// Where the data is.
    ///
    /// For showing a person, or for a tool that takes a path. Opened by that
    /// path again later, it may name a newer copy than [`Stored::metadata`]
    /// describes; [`Stored::into_file`] is the copy that was opened.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What is known about the copy: where it came from, when, and what it
    /// hashes to.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// The detached signature the copy was checked against when it arrived,
    /// for a resource checked by one.
    ///
    /// Kept so a consumer that checks again when it loads the data, as
    /// [`Bundle::verified`](crate::detect::bundle::Bundle::verified) does
    /// with a bundle's manifest, has the very document the fetch accepted,
    /// replaced with the data and never apart from it.
    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
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
        // A hint, never a bound: the size was checked against the metadata when
        // the file was opened.
        let mut bytes = Vec::with_capacity(usize::try_from(self.metadata.size).unwrap_or(0));
        self.file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

/// What is known about a stored copy.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// Where it was fetched from.
    pub url: String,
    /// The entity tag the server sent with it, which the next update asks
    /// with.
    pub etag: Option<String>,
    /// The modification time the server sent with it, as sent, which the next
    /// update asks with where there is no entity tag.
    pub last_modified: Option<String>,
    /// When this copy was downloaded.
    pub fetched_at: SystemTime,
    /// When the server last confirmed this copy is current: its download, or
    /// a later update that found nothing new. How old the data is, as far as
    /// anyone can tell.
    pub checked_at: SystemTime,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256.
    pub sha256: [u8; 32],
    /// What it was checked by when it arrived.
    pub(super) verified: Verified,
}

impl Metadata {
    /// A copy of `size` bytes hashing to `sha256`, fetched from `url` now.
    pub(super) fn new(url: String, size: u64, sha256: [u8; 32], verified: Verified) -> Self {
        let now = SystemTime::now();
        Self {
            url,
            etag: None,
            last_modified: None,
            fetched_at: now,
            checked_at: now,
            size,
            sha256,
            verified,
        }
    }

    /// Whether a copy checked as this one was is enough for `verify`.
    ///
    /// A copy is only kept as current, and only asked about conditionally,
    /// while it satisfies what the resource asks today: a digest pinned
    /// afresh, or a key rotated, makes the stored copy one that has to be
    /// fetched and checked again, whatever the server would say about it.
    pub(super) fn satisfies(&self, verify: &Verify) -> bool {
        match verify {
            Verify::Transport => true,
            Verify::Sha256(digest) => self.sha256 == *digest,
            Verify::Ed25519 { public_key, .. } => self.verified == Verified::Ed25519(*public_key),
        }
    }
}

/// What a stored copy was checked by, recorded so a later update can tell
/// whether it still meets what the resource asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verified {
    /// The transport alone, or a pinned digest, which the recorded SHA-256
    /// answers for itself.
    Transport,
    /// A signature by this key.
    Ed25519([u8; 32]),
}

/// An update in progress: the resource's update lock, held until this is
/// dropped.
#[derive(Debug)]
pub(super) struct Update {
    directory: PathBuf,
    _lock: File,
}

impl Update {
    /// The copy stored now, if there is one and its data is there at the
    /// size the metadata records. What a conditional request is made with.
    pub(super) fn current(&self) -> Result<Option<Metadata>, FetchError> {
        let Some(metadata) = read_metadata(&self.directory)? else {
            return Ok(None);
        };
        let path = self.directory.join(DATA);
        let size = open(&path, Access::Read).and_then(|file| file.metadata());
        Ok(match size {
            Ok(held) if held.len() == metadata.size => Some(metadata),
            _ => None,
        })
    }

    /// The file a download is written to, empty. Where an earlier update
    /// left one behind, it is discarded first.
    pub(super) fn stage(&self) -> Result<(File, PathBuf), FetchError> {
        let path = self.directory.join(DATA_PARTIAL);
        let file = create(&path).map_err(|e| storage(&path, e))?;
        Ok((file, path))
    }

    /// Removes what an update staged and is not to be kept.
    pub(super) fn discard(&self) {
        let _ = remove(&self.directory.join(DATA_PARTIAL));
        let _ = remove(&self.directory.join(SIGNATURE_PARTIAL));
    }

    /// Replaces the stored copy with the staged download, described by
    /// `metadata` and checked against `signature` where it was checked by
    /// one.
    pub(super) fn commit(
        &self,
        metadata: &Metadata,
        signature: Option<&[u8]>,
    ) -> Result<(), FetchError> {
        self.replace(&encode(metadata), signature)
    }

    /// [`commit`](Self::commit) with the metadata already written out, for
    /// whatever kind of entry this update is of.
    fn replace(&self, metadata: &str, signature: Option<&[u8]>) -> Result<(), FetchError> {
        let signature_path = self.directory.join(SIGNATURE);
        let staged_signature = signature
            .map(|document| self.stage_file(SIGNATURE_PARTIAL, document))
            .transpose()?;
        let staged = self.stage_file(METADATA_PARTIAL, metadata.as_bytes())?;
        self.swapping(|| {
            let data = self.directory.join(DATA);
            let metadata_path = self.directory.join(METADATA);
            remove_if_there(&metadata_path)?;
            rename(&self.directory.join(DATA_PARTIAL), &data).map_err(|e| storage(&data, e))?;
            match &staged_signature {
                Some(staged) => {
                    rename(staged, &signature_path).map_err(|e| storage(&signature_path, e))?
                }
                // A signature left from when the resource was checked by one
                // describes nothing any more.
                None => remove_if_there(&signature_path)?,
            }
            rename(&staged, &metadata_path).map_err(|e| storage(&metadata_path, e))
        })
    }

    /// Rewrites the metadata of the copy already stored, which the server has
    /// just confirmed is current.
    pub(super) fn confirm(&self, metadata: &Metadata) -> Result<(), FetchError> {
        let staged = self.stage_file(METADATA_PARTIAL, encode(metadata).as_bytes())?;
        let destination = self.directory.join(METADATA);
        self.swapping(|| rename(&staged, &destination).map_err(|e| storage(&destination, e)))
    }

    /// Writes `contents` to `name` in the resource's directory, on disk
    /// before this returns, ready to be renamed into place.
    fn stage_file(&self, name: &str, contents: &[u8]) -> Result<PathBuf, FetchError> {
        use std::io::Write as _;

        let path = self.directory.join(name);
        let written = create(&path).and_then(|mut file| {
            file.write_all(contents)?;
            file.sync_all()
        });
        match written {
            Ok(()) => Ok(path),
            Err(e) => {
                let _ = remove(&path);
                Err(storage(&path, e))
            }
        }
    }

    /// Runs `swap` holding the read lock exclusively, so no reader opens the
    /// pair half replaced.
    fn swapping(&self, swap: impl FnOnce() -> Result<(), FetchError>) -> Result<(), FetchError> {
        let path = self.directory.join(READ_LOCK);
        let lock = open(&path, Access::CreateOrOpen).map_err(|e| storage(&path, e))?;
        lock.lock().map_err(|e| storage(&path, e))?;
        swap()
    }
}

/// Removes `path`, which may already be gone.
fn remove_if_there(path: &Path) -> Result<(), FetchError> {
    match remove(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(storage(path, e)),
        _ => Ok(()),
    }
}

/// The signature stored in `directory`, which its metadata says is there.
fn read_signature(directory: &Path) -> Result<Signature, FetchError> {
    let path = directory.join(SIGNATURE);
    let file = open(&path, Access::Read).map_err(|e| storage(&path, e))?;
    Signature::read(&mut io::BufReader::new(file)).map_err(|e| {
        storage(
            &path,
            io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
        )
    })
}

/// The metadata stored in `directory`, or `None` where there is none.
fn read_metadata(directory: &Path) -> Result<Option<Metadata>, FetchError> {
    read_metadata_as(directory, decode)
}

/// The metadata stored in `directory`, read by `decode`, or `None` where
/// there is none.
fn read_metadata_as<M>(
    directory: &Path,
    decode: impl FnOnce(&str) -> Result<M, String>,
) -> Result<Option<M>, FetchError> {
    let path = directory.join(METADATA);
    let file = match open(&path, Access::Read) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(storage(&path, e)),
    };
    let mut text = String::new();
    let read = file
        .take(MAX_METADATA_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| storage(&path, e))?;
    if read as u64 > MAX_METADATA_BYTES {
        return Err(storage(
            &path,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "larger than any metadata written",
            ),
        ));
    }
    decode(&text)
        .map(Some)
        .map_err(|reason| storage(&path, io::Error::new(io::ErrorKind::InvalidData, reason)))
}

/// The metadata file, as it is written and read.
///
/// Its own type rather than a derive on [`Metadata`], so the file's layout
/// is not whatever the public struct's fields happen to be. Times are whole
/// seconds since the Unix epoch, and the digest and key lowercase hex.
#[derive(serde::Serialize, serde::Deserialize)]
struct MetadataFile {
    format: u32,
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_modified: Option<String>,
    fetched_at: u64,
    checked_at: u64,
    size: u64,
    sha256: String,
    /// `transport`, or `ed25519:` and the key's hex.
    verified: String,
}

/// `metadata` as the file holds it.
fn encode(metadata: &Metadata) -> String {
    let seconds = |time: SystemTime| {
        time.duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    };
    let file = MetadataFile {
        format: FORMAT,
        url: metadata.url.clone(),
        etag: metadata.etag.clone(),
        last_modified: metadata.last_modified.clone(),
        fetched_at: seconds(metadata.fetched_at),
        checked_at: seconds(metadata.checked_at),
        size: metadata.size,
        sha256: hex(&metadata.sha256),
        verified: match metadata.verified {
            Verified::Transport => "transport".to_string(),
            Verified::Ed25519(key) => format!("ed25519:{}", hex(&key)),
        },
    };
    toml::to_string(&file).expect("the metadata is plain strings and integers")
}

/// The metadata a file holds, or why it is not metadata this wrote.
fn decode(text: &str) -> Result<Metadata, String> {
    let file: MetadataFile = toml::from_str(text).map_err(|e| e.message().to_string())?;
    if file.format != FORMAT {
        return Err(format!("metadata format {} is not {FORMAT}", file.format));
    }
    let time = |seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
    let digest = |text: &str| {
        unhex(text).ok_or_else(|| format!("'{text}' is not a 32-byte hex digest or key"))
    };
    let verified = match file.verified.split_once(':') {
        None if file.verified == "transport" => Verified::Transport,
        Some(("ed25519", key)) => Verified::Ed25519(digest(key)?),
        _ => return Err(format!("'{}' is not a verification", file.verified)),
    };
    Ok(Metadata {
        url: file.url,
        etag: file.etag,
        last_modified: file.last_modified,
        fetched_at: time(file.fetched_at),
        checked_at: time(file.checked_at),
        size: file.size,
        sha256: digest(&file.sha256)?,
        verified,
    })
}

/// `bytes` as lowercase hex.
fn hex(bytes: &[u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

/// Thirty-two bytes from lowercase hex.
fn unhex(text: &str) -> Option<[u8; 32]> {
    data_encoding::HEXLOWER
        .decode(text.as_bytes())
        .ok()?
        .try_into()
        .ok()
}

/// A storage failure at `path`.
fn storage(path: &Path, source: io::Error) -> FetchError {
    FetchError::Storage {
        path: path.to_path_buf(),
        source,
    }
}

/// The ways a file in the store is opened.
#[derive(Clone, Copy)]
enum Access {
    /// For reading, never creating.
    Read,
    /// For reading and writing, created if missing and never truncated: a
    /// lock, which every contender must end up holding on one file.
    CreateOrOpen,
}

/// Opens `path` as `how` says, never following a link at it and, under
/// `sudo`, never through one leading out of the invoking user's home; a file
/// this creates there is given to them.
#[cfg(unix)]
fn open(path: &Path, how: Access) -> io::Result<File> {
    let flags = match how {
        Access::Read => libc::O_RDONLY,
        Access::CreateOrOpen => libc::O_RDWR | libc::O_CREAT,
    };
    let file = Place::of(path)?.open(flags, 0o644)?;
    if matches!(how, Access::CreateOrOpen) {
        ownership::give_open(&file, path);
    }
    Ok(file)
}

/// Opens `path` as `how` says, where there is no `sudo` to guard against.
#[cfg(not(unix))]
fn open(path: &Path, how: Access) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    match how {
        Access::Read => options.read(true),
        Access::CreateOrOpen => options.read(true).write(true).create(true),
    };
    options.open(Place::of(path)?.path())
}

/// Creates `path` empty for writing, removing a file an earlier run left
/// there first, and refusing one that appears between the two.
///
/// Removed rather than truncated, so a link at the name loses the link and
/// never the file it points to.
fn create(path: &Path) -> io::Result<File> {
    match remove(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    create_new(path)
}

/// Creates `path`, refusing a name that exists.
#[cfg(unix)]
fn create_new(path: &Path) -> io::Result<File> {
    let file = Place::of(path)?.open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o644)?;
    ownership::give_open(&file, path);
    Ok(file)
}

/// Creates `path`, refusing a name that exists.
#[cfg(not(unix))]
fn create_new(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Place::of(path)?.path())
}

/// Removes the name `path`, a link at it rather than what it points to.
fn remove(path: &Path) -> io::Result<()> {
    Place::of(path)?.remove()
}

/// Renames `from` over `to`, two names in one directory reached through one
/// walk, so nothing rearranged above them between the two lookups can send
/// the rename elsewhere.
fn rename(from: &Path, to: &Path) -> io::Result<()> {
    let destination = Place::of(to)?;
    let name = from
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "a file name"))?;
    destination.beside(name)?.rename_over(&destination)
}

/// Filling a store without a network, for tests anywhere in the crate.
#[cfg(test)]
pub(crate) mod testing {
    use std::io::Write as _;

    use super::{Metadata, Store, Verified};
    use crate::fetch::Resource;

    /// Stores `bytes` as `resource`'s copy, as a fetch would.
    pub(crate) fn put(store: &Store, resource: &Resource, bytes: &[u8]) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What an update writes is what the next one reads, every field of it,
    /// or a conditional request would be made with a validator the server
    /// never sent.
    /// A note is the one thing a front end keeps in the store about its own
    /// choices, so it has to read back as written, be absent until written,
    /// and never reach outside the notes directory by its name.
    #[test]
    fn a_note_reads_back_and_its_name_stays_inside_the_store() {
        let root = std::env::temp_dir().join(format!("zond-notes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::new(&root);

        assert_eq!(store.note("debian-declined").unwrap(), None);
        store
            .set_note("debian-declined", "declined 2026-09-30")
            .unwrap();
        assert_eq!(
            store.note("debian-declined").unwrap().as_deref(),
            Some("declined 2026-09-30")
        );
        store.set_note("debian-declined", "again").unwrap();
        assert_eq!(
            store.note("debian-declined").unwrap().as_deref(),
            Some("again")
        );

        for name in ["../escape", "a/b", "", ".hidden", "UPPER"] {
            assert!(store.set_note(name, "x").is_err(), "{name:?} was accepted");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn metadata_reads_back_as_it_was_written() {
        let mut metadata = Metadata::new(
            "https://example.com/feed".into(),
            1234,
            [7; 32],
            Verified::Ed25519([9; 32]),
        );
        metadata.etag = Some("\"abc\"".into());
        metadata.last_modified = Some("Tue, 29 Sep 2026 10:00:00 GMT".into());
        // Whole seconds, which is what the file keeps.
        metadata.fetched_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        metadata.checked_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_100);

        assert_eq!(decode(&encode(&metadata)), Ok(metadata));
    }

    /// A file this did not write is refused rather than half read, so a
    /// damaged one costs a download rather than a copy described wrongly.
    #[test]
    fn metadata_this_did_not_write_is_refused() {
        let written = encode(&Metadata::new(
            "https://example.com/feed".into(),
            1,
            [0; 32],
            Verified::Transport,
        ));
        assert!(decode(&written.replace("format = 1", "format = 2")).is_err());
        assert!(decode(&written.replace("transport", "trust me")).is_err());
        assert!(decode("url = 3").is_err());
    }
}
