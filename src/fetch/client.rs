// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Downloading a resource into a store
//!
//! One [`Client`] per program, one [`Client::fetch`] per resource. A fetch sends a
//! conditional request based on the stored copy, so an unchanged feed costs one request
//! and no download. A new body is streamed to disk, abandoned as soon as it passes the
//! resource's size ceiling, checked, and only then put in place of the old copy.

use std::error::Error as StdError;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use reqwest::header::{ETAG, HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use reqwest::{StatusCode, Url};
use tokio::io::AsyncWriteExt;

use crate::signature::{Signature, SignatureError};

use super::store::{Metadata, Update, Verified};
use super::{Resource, Store, Verify};

/// How long a connection may take to open: enough for a slow proxy and a distant mirror,
/// short enough that a machine with no route out reports it within a minute.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a transfer may go without a byte arriving.
///
/// A limit on silence, since an eighty-megabyte feed over a slow link can take many
/// minutes in total. Five minutes because some publishers build the document as they
/// send it: the Debian security tracker sends its headers and then goes silent for more
/// than a minute at a time.
const READ_TIMEOUT: Duration = Duration::from_secs(300);

/// How many redirects a fetch follows. Mirrors and CDNs use one or two.
const MAX_REDIRECTS: usize = 5;

/// The largest detached signature a fetch will take. One the
/// [`signature`](crate::signature) module writes is a few hundred bytes.
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;

/// Downloads resources over HTTPS.
///
/// Build one and share it: it holds a connection pool and the TLS configuration, and
/// cloning is cheap. Requests carry the user agent `zond-engine/<version>` and honour the
/// system's proxy settings and the `HTTPS_PROXY` family of variables.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    plain_http: bool,
}

impl Client {
    /// A client that fetches over HTTPS alone, verified against the operating
    /// system's trust store.
    ///
    /// # Errors
    ///
    /// [`FetchError::Setup`] if the TLS configuration cannot be built, which on a
    /// supported platform is a defect in this build.
    pub fn new() -> Result<Self, FetchError> {
        Self::build(false)
    }

    /// A client that also fetches plain `http` and ignores any proxy, for a test server
    /// on loopback.
    #[cfg(test)]
    pub(crate) fn plain_http_for_tests() -> Result<Self, FetchError> {
        Self::build(true)
    }

    fn build(plain_http: bool) -> Result<Self, FetchError> {
        let setup = |e: &dyn std::fmt::Display| FetchError::Setup(e.to_string());

        // Passed in, not installed as the process default; see the module documentation.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            rustls_platform_verifier::Verifier::new(provider.clone()).map_err(|e| setup(&e))?;
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| setup(&e))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        // The client is built for HTTP/1.1 only, so offer only that.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];

        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .user_agent(concat!("zond-engine/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .https_only(!plain_http)
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                let followed = attempt.previous().len();
                match judge_redirect(followed, attempt.url().scheme(), plain_http) {
                    Ok(()) => attempt.follow(),
                    Err(refused) => attempt.error(refused),
                }
            }));
        if plain_http {
            builder = builder.no_proxy();
        }
        let http = builder.build().map_err(|e| setup(&e))?;
        Ok(Self { http, plain_http })
    }

    /// Brings `resource`'s copy in `store` up to date.
    ///
    /// Sends the stored copy's entity tag and modification time, if the copy still meets
    /// the resource's checks, so an unchanged resource downloads nothing. A new body is
    /// written beside the stored copy, abandoned once it passes
    /// [`max_bytes`](Resource::max_bytes), checked as [`verify`](Resource::verify) says,
    /// and only then renamed over it; any failure leaves the stored copy as it was. Two
    /// fetches of one resource into one store, from this process or another, run one after
    /// the other.
    ///
    /// `progress` is called for every chunk written; pass `()` to ignore it.
    ///
    /// # Errors
    ///
    /// A [`FetchError`] naming the one thing that stopped it.
    pub async fn fetch(
        &self,
        resource: &Resource,
        store: &Store,
        mut progress: impl DownloadProgress,
    ) -> Result<Outcome, FetchError> {
        let url = self.url(resource.url())?;

        let update = {
            let store = store.clone();
            let resource = resource.clone();
            blocking(move || store.lock_for_update(&resource)).await?
        };
        let current = update
            .current()?
            .filter(|stored| stored.url == resource.url() && stored.satisfies(resource.verify()));

        let mut request = self.http.get(url);
        if let Some(stored) = &current {
            if let Some(etag) = &stored.etag {
                request = request.header(IF_NONE_MATCH, etag);
            }
            if let Some(modified) = &stored.last_modified {
                request = request.header(IF_MODIFIED_SINCE, modified);
            }
        }
        let mut response = request.send().await.map_err(network)?;

        let status = response.status();
        if status == StatusCode::NOT_MODIFIED
            && let Some(mut stored) = current
        {
            // A 304 may carry fresh validators; keep them for next time.
            let (etag, modified) = validators(response.headers());
            stored.etag = etag.or(stored.etag);
            stored.last_modified = modified.or(stored.last_modified);
            stored.checked_at = SystemTime::now();
            update.confirm(&stored)?;
            return Ok(Outcome::NotModified(stored));
        }
        if !status.is_success() {
            return Err(FetchError::Status {
                status: status.as_u16(),
            });
        }

        let limit = resource.max_bytes();
        let total = response.content_length();
        if total.is_some_and(|total| total > limit) {
            return Err(FetchError::TooLarge { limit });
        }
        let (etag, modified) = validators(response.headers());

        let downloaded = download(&update, &mut response, limit, total, &mut progress).await;
        let (size, sha256) = match downloaded {
            Ok(downloaded) => downloaded,
            Err(e) => {
                update.discard();
                return Err(e);
            }
        };
        let (verified, signature) = match self.check(resource.verify(), &sha256).await {
            Ok(checked) => checked,
            Err(e) => {
                update.discard();
                return Err(e);
            }
        };

        let mut metadata = Metadata::new(resource.url().to_string(), size, sha256, verified);
        metadata.etag = etag;
        metadata.last_modified = modified;

        // Same bytes from a server that ignored the conditional request: keep the copy,
        // update its metadata.
        if let Some(stored) = current.filter(|stored| stored.sha256 == sha256) {
            update.discard();
            metadata.fetched_at = stored.fetched_at;
            update.confirm(&metadata)?;
            return Ok(Outcome::Unchanged(metadata));
        }

        if let Err(e) = update.commit(&metadata, signature.as_deref()) {
            update.discard();
            return Err(e);
        }
        Ok(Outcome::Updated(metadata))
    }

    /// `text` as a URL this client may fetch.
    fn url(&self, text: &str) -> Result<Url, FetchError> {
        let url = Url::parse(text).map_err(|e| FetchError::Network {
            failure: NetworkFailure::Url,
            source: Box::new(e),
        })?;
        match url.scheme() {
            "https" => Ok(url),
            "http" if self.plain_http => Ok(url),
            _ => Err(FetchError::Insecure),
        }
    }

    /// Checks a download that hashed to `sha256` as `verify` says, and returns what it was
    /// checked by, with the signature document if there was one.
    async fn check(
        &self,
        verify: &Verify,
        sha256: &[u8; 32],
    ) -> Result<(Verified, Option<Vec<u8>>), FetchError> {
        match verify {
            Verify::Transport => Ok((Verified::Transport, None)),
            Verify::Sha256(pinned) if pinned == sha256 => Ok((Verified::Transport, None)),
            Verify::Sha256(_) => Err(FetchError::Verification(
                VerificationFailure::DigestMismatch,
            )),
            Verify::Ed25519 {
                public_key,
                signature_url,
                domain,
            } => {
                let document = self.signature(signature_url).await.map_err(|e| {
                    FetchError::Verification(VerificationFailure::NoSignature(Box::new(e)))
                })?;
                let signature = Signature::read(&mut document.as_slice())
                    .map_err(|e| FetchError::Verification(VerificationFailure::Signature(e)))?;
                signature
                    .verify_digest(sha256, public_key, *domain)
                    .map_err(|e| FetchError::Verification(VerificationFailure::Signature(e)))?;
                Ok((Verified::Ed25519(*public_key), Some(document)))
            }
        }
    }

    /// The detached signature document at `url`, bounded.
    async fn signature(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        let mut response = self
            .http
            .get(self.url(url)?)
            .send()
            .await
            .map_err(network)?;
        if !response.status().is_success() {
            return Err(FetchError::Status {
                status: response.status().as_u16(),
            });
        }
        let mut document = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(network)? {
            document.extend_from_slice(&chunk);
            if document.len() as u64 > MAX_SIGNATURE_BYTES {
                return Err(FetchError::TooLarge {
                    limit: MAX_SIGNATURE_BYTES,
                });
            }
        }
        Ok(document)
    }
}

/// Streams `response` into the update's staged file, and returns its size and
/// SHA-256.
///
/// The ceiling is checked before each chunk is written, so an oversized download leaves
/// no more than the ceiling on disk, however much the server meant to send.
async fn download(
    update: &Update,
    response: &mut reqwest::Response,
    limit: u64,
    total: Option<u64>,
    progress: &mut impl DownloadProgress,
) -> Result<(u64, [u8; 32]), FetchError> {
    let (staged, path) = update.stage()?;
    let storage = |source| FetchError::Storage {
        path: path.clone(),
        source,
    };
    let mut file = tokio::fs::File::from_std(staged);
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut received: u64 = 0;

    while let Some(chunk) = response.chunk().await.map_err(network)? {
        received += chunk.len() as u64;
        if received > limit {
            return Err(FetchError::TooLarge { limit });
        }
        digest.update(&chunk);
        file.write_all(&chunk).await.map_err(storage)?;
        progress.advanced(received, total);
    }
    // Synced before the rename, so a crash cannot leave a copy shorter than its metadata.
    file.sync_all().await.map_err(storage)?;

    let sha256 = digest
        .finish()
        .as_ref()
        .try_into()
        .expect("SHA-256 is thirty-two bytes");
    Ok((received, sha256))
}

/// The entity tag and modification time a response carries, as sent.
fn validators(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let text = |name| {
        headers
            .get(name)
            .and_then(|value: &reqwest::header::HeaderValue| value.to_str().ok())
            .map(str::to_string)
    };
    (text(ETAG), text(LAST_MODIFIED))
}

/// Runs `work` where it may block, and hands back what it returned.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, FetchError> + Send + 'static,
) -> Result<T, FetchError> {
    joined(tokio::task::spawn_blocking(work).await)
}

/// What a task that ran blocking work hands back, as the fetch's own result.
///
/// A panic in the work resumes unwinding here. A task that never finished was cancelled,
/// which for blocking work only happens as the runtime shuts down; that is reported as
/// [`FetchError::Cancelled`], since the store was never reached.
fn joined<T>(
    result: Result<Result<T, FetchError>, tokio::task::JoinError>,
) -> Result<T, FetchError> {
    match result {
        Ok(result) => result,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(_) => Err(FetchError::Cancelled),
    }
}

/// Whether a redirect to a URL of `scheme`, after `followed` URLs, may be
/// followed.
fn judge_redirect(followed: usize, scheme: &str, plain_http: bool) -> Result<(), RedirectRefused> {
    if followed > MAX_REDIRECTS {
        Err(RedirectRefused::TooMany)
    } else if scheme == "https" || (plain_http && scheme == "http") {
        Ok(())
    } else {
        Err(RedirectRefused::OffHttps)
    }
}

/// Why a redirect was not followed, carried through the HTTP client's error
/// so the fetch can say which.
#[derive(Debug, thiserror::Error)]
enum RedirectRefused {
    #[error("too many redirects")]
    TooMany,
    #[error("redirected off https")]
    OffHttps,
}

/// A request that failed below HTTP, said as the one thing that went wrong.
fn network(error: reqwest::Error) -> FetchError {
    let mut cause: Option<&(dyn StdError + 'static)> = Some(&error);
    while let Some(current) = cause {
        match current.downcast_ref::<RedirectRefused>() {
            Some(RedirectRefused::OffHttps) => return FetchError::Insecure,
            Some(RedirectRefused::TooMany) => {
                return FetchError::Network {
                    failure: NetworkFailure::Redirects,
                    source: Box::new(error),
                };
            }
            None => cause = current.source(),
        }
    }

    let failure = if error.is_timeout() {
        NetworkFailure::TimedOut
    } else if let Some(tls) = tls_failure(&error) {
        tls
    } else if error.is_connect() {
        NetworkFailure::Connect
    } else if error.is_body() || error.is_decode() {
        NetworkFailure::Interrupted
    } else {
        NetworkFailure::Other
    };
    FetchError::Network {
        failure,
        source: Box::new(error),
    }
}

/// Whether TLS is why `error` happened, and whether because of the
/// certificate.
///
/// The TLS error arrives wrapped in an I/O error whose `source` skips the wrapped error
/// and returns that error's own source, so each I/O error on the way is opened too.
fn tls_failure(error: &(dyn StdError + 'static)) -> Option<NetworkFailure> {
    let mut cause = Some(error);
    while let Some(current) = cause {
        let tls = current.downcast_ref::<rustls::Error>().or_else(|| {
            current
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::get_ref)
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        });
        if let Some(tls) = tls {
            return Some(match tls {
                rustls::Error::InvalidCertificate(_) => NetworkFailure::Certificate,
                _ => NetworkFailure::Tls,
            });
        }
        cause = current.source();
    }
    None
}

/// Told how a download is going, for a caller drawing a progress bar.
pub trait DownloadProgress: Send {
    /// `received` bytes have arrived so far, of `total` where the server said.
    fn advanced(&mut self, received: u64, total: Option<u64>);
}

/// Nothing to tell.
impl DownloadProgress for () {
    fn advanced(&mut self, _received: u64, _total: Option<u64>) {}
}

impl<F: FnMut(u64, Option<u64>) + Send> DownloadProgress for F {
    fn advanced(&mut self, received: u64, total: Option<u64>) {
        self(received, total);
    }
}

/// What a fetch did.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A new copy arrived, passed its checks and replaced the stored one.
    Updated(Metadata),
    /// The server sent the resource again, and it is byte for byte the copy
    /// already stored, which stays.
    Unchanged(Metadata),
    /// The server said the stored copy is current, and nothing was
    /// downloaded.
    NotModified(Metadata),
}

impl Outcome {
    /// What is now known about the stored copy.
    pub fn metadata(&self) -> &Metadata {
        match self {
            Outcome::Updated(metadata)
            | Outcome::Unchanged(metadata)
            | Outcome::NotModified(metadata) => metadata,
        }
    }

    /// How many bytes this fetch downloaded.
    pub fn downloaded(&self) -> u64 {
        match self {
            Outcome::Updated(metadata) | Outcome::Unchanged(metadata) => metadata.size,
            Outcome::NotModified(_) => 0,
        }
    }
}

/// Why a fetch stopped.
///
/// Each message is a few words without the resource's name or URL; the caller knows which
/// resource it asked for and prefixes it.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The HTTP client could not be built.
    #[error("no HTTP client: {0}")]
    Setup(String),

    /// The fetch was abandoned before it finished, because the runtime it ran
    /// on is shutting down. The stored copy is as it was.
    #[error("cancelled (shutting down)")]
    Cancelled,

    /// The request failed below HTTP.
    #[error("{failure}")]
    Network {
        /// What went wrong, in a few words.
        failure: NetworkFailure,
        /// The underlying error, for a caller that wants the whole chain.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },

    /// The URL, or a redirect, was not HTTPS.
    #[error("not https (refused)")]
    Insecure,

    /// The server answered with a status other than success.
    #[error("HTTP {status}")]
    Status {
        /// The status code.
        status: u16,
    },

    /// The resource is larger than its ceiling, and was abandoned.
    #[error("over {limit} bytes (refused)")]
    TooLarge {
        /// The ceiling it passed.
        limit: u64,
    },

    /// The download arrived and failed its check, and was discarded.
    #[error("{0}")]
    Verification(VerificationFailure),

    /// The store could not be read or written.
    #[error("{}: {source}", path.display())]
    Storage {
        /// The file or directory that failed.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
}

/// What went wrong below HTTP, in a few words.
///
/// Carried by [`FetchError::Network`] alongside the underlying cause.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkFailure {
    /// The URL could not be parsed.
    Url,
    /// No connection could be made: no route, no name, or refused.
    Connect,
    /// The server's certificate is not trusted by this system.
    Certificate,
    /// The TLS handshake failed for another reason.
    Tls,
    /// The server went silent for longer than a transfer may.
    TimedOut,
    /// The connection broke during the transfer.
    Interrupted,
    /// Redirects went on for longer than a fetch follows them.
    Redirects,
    /// Anything else.
    Other,
}

impl std::fmt::Display for NetworkFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            NetworkFailure::Url => "not a valid URL",
            NetworkFailure::Connect => "could not connect",
            NetworkFailure::Certificate => "certificate not trusted",
            NetworkFailure::Tls => "TLS handshake failed",
            NetworkFailure::TimedOut => "timed out",
            NetworkFailure::Interrupted => "connection lost",
            NetworkFailure::Redirects => "too many redirects",
            NetworkFailure::Other => "request failed",
        })
    }
}

/// Why a download failed its check.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum VerificationFailure {
    /// It does not hash to the pinned SHA-256.
    #[error("digest mismatch")]
    DigestMismatch,
    /// Its detached signature could not be fetched.
    #[error("no signature: {0}")]
    NoSignature(Box<FetchError>),
    /// Its detached signature does not hold for it under the trusted key.
    #[error("signature: {0}")]
    Signature(SignatureError),
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
    use crate::signature::{Domain, Signing, SigningKey};
    use std::collections::HashMap;
    use std::io::Write as _;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;

    /// How long any one fetch in these tests may take before it counts as hung: far beyond
    /// what a loopback transfer of a few hundred kilobytes needs on the slowest runner. A
    /// size check made only after the transfer would hit this against a server that never
    /// finishes.
    const HUNG: Duration = Duration::from_secs(60);

    /// What the test server sends for one path.
    #[derive(Clone)]
    struct Reply {
        body: Arc<Vec<u8>>,
        etag: Option<String>,
        /// Whether to say how long the body is up front.
        length: bool,
        /// A pause between chunks, so a transfer lasts long enough to overlap.
        trickle: Option<Duration>,
        /// Whether to hold the connection open after the body, as a server
        /// sending an endless body would.
        endless: bool,
    }

    impl Reply {
        fn of(body: &[u8], etag: &str) -> Self {
            Self {
                body: Arc::new(body.to_vec()),
                etag: Some(format!("\"{etag}\"")),
                length: true,
                trickle: None,
                endless: false,
            }
        }
    }

    /// A minimal HTTP/1.1 server on loopback: one request per connection,
    /// answering a matching `If-None-Match` with 304 and counting the full
    /// bodies it sends.
    struct Server {
        address: SocketAddr,
        routes: Arc<Mutex<HashMap<String, Reply>>>,
        bodies: Arc<AtomicUsize>,
        conditional: Arc<AtomicUsize>,
    }

    impl Server {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let routes: Arc<Mutex<HashMap<String, Reply>>> = Arc::default();
            let bodies = Arc::new(AtomicUsize::new(0));
            let conditional = Arc::new(AtomicUsize::new(0));
            let server = Self {
                address,
                routes: routes.clone(),
                bodies: bodies.clone(),
                conditional: conditional.clone(),
            };
            tokio::spawn(async move {
                while let Ok(socket) =
                    crate::testing::loopback::accept_from_this_process(&listener).await
                {
                    let (routes, bodies, conditional) =
                        (routes.clone(), bodies.clone(), conditional.clone());
                    tokio::spawn(answer(socket, routes, bodies, conditional));
                }
            });
            server
        }

        fn route(&self, path: &str, reply: Reply) {
            self.routes.lock().unwrap().insert(path.to_string(), reply);
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{path}", self.address)
        }

        fn bodies(&self) -> usize {
            self.bodies.load(Ordering::SeqCst)
        }
    }

    async fn answer(
        mut socket: tokio::net::TcpStream,
        routes: Arc<Mutex<HashMap<String, Reply>>>,
        bodies: Arc<AtomicUsize>,
        conditional: Arc<AtomicUsize>,
    ) {
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(n) => request.extend_from_slice(&buffer[..n]),
            }
        }
        let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
        let path = request.split(' ').nth(1).unwrap_or("/").to_string();
        let asked = request
            .lines()
            .find_map(|line| line.strip_prefix("if-none-match: "))
            .map(|tag| tag.trim().to_string());
        if asked.is_some() {
            conditional.fetch_add(1, Ordering::SeqCst);
        }

        let reply = routes.lock().unwrap().get(&path).cloned();
        let Some(reply) = reply else {
            let _ = socket
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return;
        };
        if asked.is_some() && asked == reply.etag.as_deref().map(str::to_ascii_lowercase) {
            let head = format!(
                "HTTP/1.1 304 Not Modified\r\nETag: {}\r\nConnection: close\r\n\r\n",
                reply.etag.as_deref().unwrap_or_default()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            return;
        }

        bodies.fetch_add(1, Ordering::SeqCst);
        let mut head = String::from("HTTP/1.1 200 OK\r\nConnection: close\r\n");
        head.push_str("Last-Modified: Tue, 29 Sep 2026 10:00:00 GMT\r\n");
        if let Some(etag) = &reply.etag {
            head.push_str(&format!("ETag: {etag}\r\n"));
        }
        if reply.length {
            head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
        }
        head.push_str("\r\n");
        if socket.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        for chunk in reply.body.chunks(16 * 1024) {
            if socket.write_all(chunk).await.is_err() {
                return;
            }
            if let Some(pause) = reply.trickle {
                tokio::time::sleep(pause).await;
            }
        }
        if reply.endless {
            // Never finishes, so a client that checks the size only at the end hangs here.
            let _ = socket.flush().await;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }

    /// A store in its own directory, removed before and after the test.
    fn store(name: &str) -> Scratch {
        let root = std::env::temp_dir().join(format!("zond-fetch-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        Scratch(Store::new(root))
    }

    struct Scratch(Store);

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

    fn resource(server: &Server, verify: Verify, max_bytes: u64) -> Resource {
        Resource::new("test/feed", server.url("/feed"), max_bytes, verify).unwrap()
    }

    async fn fetch(resource: &Resource, store: &Store) -> Result<Outcome, FetchError> {
        let client = Client::plain_http_for_tests().unwrap();
        tokio::time::timeout(HUNG, client.fetch(resource, store, ()))
            .await
            .expect("the fetch hung")
    }

    fn stored(store: &Store, resource: &Resource) -> Vec<u8> {
        store
            .open(resource)
            .unwrap()
            .expect("a copy is stored")
            .read()
            .unwrap()
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .try_into()
            .unwrap()
    }

    /// Updating an unchanged feed costs one request and no download; the feeds are tens of
    /// megabytes.
    #[tokio::test]
    async fn a_resource_that_has_not_changed_is_not_downloaded_again() {
        let server = Server::start().await;
        server.route("/feed", Reply::of(b"version one", "v1"));
        let store = store("unchanged");
        let resource = resource(&server, Verify::Transport, 1024);

        let mut heard = Vec::new();
        let client = Client::plain_http_for_tests().unwrap();
        let first = client
            .fetch(&resource, &store, |received, total| {
                heard.push((received, total))
            })
            .await
            .unwrap();
        assert!(matches!(first, Outcome::Updated(_)), "{first:?}");
        assert_eq!(
            heard.last(),
            Some(&(11, Some(11))),
            "progress reached the end"
        );

        let second = fetch(&resource, &store).await.unwrap();
        assert!(matches!(second, Outcome::NotModified(_)), "{second:?}");
        assert_eq!(second.downloaded(), 0);
        assert_eq!(
            server.bodies(),
            1,
            "the second update downloaded the body again"
        );
        assert_eq!(stored(&store, &resource), b"version one");

        let metadata = store.open(&resource).unwrap().unwrap().metadata().clone();
        assert_eq!(metadata.etag.as_deref(), Some("\"v1\""));
        assert_eq!(metadata.sha256, sha256(b"version one"));
        assert!(metadata.checked_at >= metadata.fetched_at);
    }

    /// A body past the ceiling is refused as the byte past it arrives, and the stored copy
    /// is untouched. The server never finishes, so a check made at the end would never
    /// run.
    #[tokio::test]
    async fn a_download_past_its_ceiling_is_refused_as_it_streams_and_the_old_copy_survives() {
        let server = Server::start().await;
        server.route("/feed", Reply::of(b"small", "v1"));
        let store = store("oversize");
        let resource = resource(&server, Verify::Transport, 64 * 1024);
        let first = fetch(&resource, &store).await;
        assert!(matches!(first, Ok(Outcome::Updated(_))), "{first:?}");

        let mut endless = Reply::of(&vec![b'x'; 256 * 1024], "v2");
        endless.length = false;
        endless.endless = true;
        server.route("/feed", endless);
        let refused = fetch(&resource, &store).await;
        assert!(
            matches!(refused, Err(FetchError::TooLarge { limit: 65536 })),
            "{refused:?}"
        );
        assert_eq!(stored(&store, &resource), b"small");
        assert!(
            !store.directory(&resource).join("data.partial").exists(),
            "the refused download was left on disk"
        );

        // Declared too large up front, it is refused before a byte is read.
        server.route("/feed", Reply::of(&vec![b'y'; 128 * 1024], "v3"));
        let refused = fetch(&resource, &store).await;
        assert!(
            matches!(refused, Err(FetchError::TooLarge { .. })),
            "{refused:?}"
        );
        assert_eq!(stored(&store, &resource), b"small");
    }

    /// A download that does not hash to the pinned digest is not kept, and
    /// the copy that did is.
    #[tokio::test]
    async fn a_digest_mismatch_is_refused_and_the_old_copy_survives() {
        let server = Server::start().await;
        server.route("/feed", Reply::of(b"pinned content", "v1"));
        let store = store("digest");
        let resource = resource(&server, Verify::Sha256(sha256(b"pinned content")), 1024);
        let first = fetch(&resource, &store).await;
        assert!(matches!(first, Ok(Outcome::Updated(_))), "{first:?}");

        server.route("/feed", Reply::of(b"something else", "v2"));
        let refused = fetch(&resource, &store).await;
        assert!(
            matches!(
                refused,
                Err(FetchError::Verification(
                    VerificationFailure::DigestMismatch
                ))
            ),
            "{refused:?}"
        );
        assert_eq!(stored(&store, &resource), b"pinned content");
    }

    /// A download whose detached signature does not hold, because the content
    /// changed or because another key made it, is not kept.
    #[tokio::test]
    async fn a_signature_that_does_not_hold_is_refused_and_the_old_copy_survives() {
        let sign = |key: &SigningKey, body: &[u8]| {
            let mut sink = Vec::new();
            let mut writer = Signing::new(&mut sink);
            writer.write_all(body).unwrap();
            writer
                .finish(key, Domain::DETECTIONS)
                .to_document()
                .into_bytes()
        };
        let (_, trusted) = SigningKey::generate().unwrap();
        let (_, stranger) = SigningKey::generate().unwrap();

        let server = Server::start().await;
        server.route("/feed", Reply::of(b"signed content", "v1"));
        server.route(
            "/feed.sig",
            Reply::of(&sign(&trusted, b"signed content"), "s1"),
        );
        let store = store("signature");
        let verify = Verify::Ed25519 {
            public_key: trusted.public_key().try_into().unwrap(),
            signature_url: server.url("/feed.sig"),
            domain: Domain::DETECTIONS,
        };
        let resource = resource(&server, verify, 1024);
        let first = fetch(&resource, &store).await.unwrap();
        assert!(matches!(first, Outcome::Updated(_)), "{first:?}");
        let kept = store.open(&resource).unwrap().unwrap();
        kept.signature()
            .expect("the signature is kept with the data")
            .verify(b"signed content", &trusted.public_key(), Domain::DETECTIONS)
            .expect("the kept signature checks the kept data");

        // New content under the old signature.
        server.route("/feed", Reply::of(b"altered content", "v2"));
        let refused = fetch(&resource, &store).await;
        assert!(
            matches!(
                refused,
                Err(FetchError::Verification(VerificationFailure::Signature(
                    SignatureError::Altered
                )))
            ),
            "{refused:?}"
        );

        // New content, signed, by somebody else.
        server.route(
            "/feed.sig",
            Reply::of(&sign(&stranger, b"altered content"), "s2"),
        );
        let refused = fetch(&resource, &store).await;
        assert!(
            matches!(
                refused,
                Err(FetchError::Verification(VerificationFailure::Signature(
                    SignatureError::UntrustedKey
                )))
            ),
            "{refused:?}"
        );
        assert_eq!(stored(&store, &resource), b"signed content");
        let kept = store.open(&resource).unwrap().unwrap();
        assert!(
            kept.signature()
                .unwrap()
                .verify(b"signed content", &trusted.public_key(), Domain::DETECTIONS)
                .is_ok(),
            "a refused download replaced the kept signature"
        );
    }

    /// Two concurrent updates of one resource run one after the other: the second asks
    /// with what the first stored and downloads nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_fetches_of_one_resource_do_not_interleave() {
        let server = Server::start().await;
        let body: Vec<u8> = (0..=255u8).cycle().take(256 * 1024).collect();
        let mut slow = Reply::of(&body, "v1");
        slow.trickle = Some(Duration::from_millis(20));
        server.route("/feed", slow);
        let store = store("concurrent");
        let resource = resource(&server, Verify::Transport, 1024 * 1024);

        let (one, two) = tokio::join!(fetch(&resource, &store), fetch(&resource, &store));
        let mut outcomes = [one.unwrap(), two.unwrap()];
        outcomes.sort_by_key(Outcome::downloaded);
        assert!(
            matches!(outcomes[0], Outcome::NotModified(_)),
            "{outcomes:?}"
        );
        assert!(matches!(outcomes[1], Outcome::Updated(_)), "{outcomes:?}");
        assert_eq!(server.bodies(), 1, "both fetches downloaded the body");
        assert_eq!(stored(&store, &resource), body);
    }

    /// The same bytes sent again by a server that ignored the conditional request are
    /// recognised, and the stored copy is not rewritten.
    #[tokio::test]
    async fn the_same_bytes_sent_again_are_reported_unchanged() {
        let server = Server::start().await;
        server.route("/feed", Reply::of(b"same", "v1"));
        let store = store("same");
        let resource = resource(&server, Verify::Transport, 1024);
        let first = fetch(&resource, &store).await;
        assert!(matches!(first, Ok(Outcome::Updated(_))), "{first:?}");

        // A new tag on the same content, so the server answers in full.
        server.route("/feed", Reply::of(b"same", "v2"));
        let again = fetch(&resource, &store).await.unwrap();
        assert!(matches!(again, Outcome::Unchanged(_)), "{again:?}");
        assert_eq!(again.metadata().etag.as_deref(), Some("\"v2\""));
        assert_eq!(server.conditional.load(Ordering::SeqCst), 1);
    }

    /// A client built for real use fetches nothing over plain HTTP, and says
    /// so before it opens a connection.
    #[tokio::test]
    async fn a_real_client_refuses_plain_http() {
        let client = Client::new().expect("a client builds with the ring provider");
        let resource =
            Resource::new("test/feed", "http://127.0.0.1:9/feed", 1, Verify::Transport).unwrap();
        let refused = client.fetch(&resource, &store("plain"), ()).await;
        assert!(matches!(refused, Err(FetchError::Insecure)), "{refused:?}");
    }

    /// Blocking work whose task was cancelled by a runtime shutting down is reported as
    /// cancelled, not as a storage failure at no path.
    #[tokio::test]
    async fn a_cancelled_task_is_reported_as_cancelled() {
        let task = tokio::spawn(std::future::pending::<Result<(), FetchError>>());
        task.abort();
        let cancelled = task.await;
        assert!(
            cancelled
                .as_ref()
                .is_err_and(tokio::task::JoinError::is_cancelled)
        );
        let reported = joined(cancelled);
        assert!(
            matches!(reported, Err(FetchError::Cancelled)),
            "{reported:?}"
        );
    }

    /// Redirects stay on HTTPS and stop after a handful.
    #[test]
    fn a_redirect_off_https_or_past_the_limit_is_refused() {
        assert!(judge_redirect(1, "https", false).is_ok());
        assert!(matches!(
            judge_redirect(1, "http", false),
            Err(RedirectRefused::OffHttps)
        ));
        assert!(matches!(
            judge_redirect(1, "ftp", true),
            Err(RedirectRefused::OffHttps)
        ));
        assert!(judge_redirect(MAX_REDIRECTS, "https", false).is_ok());
        assert!(matches!(
            judge_redirect(MAX_REDIRECTS + 1, "https", false),
            Err(RedirectRefused::TooMany)
        ));
    }

    /// An untrusted certificate, as a TLS-inspecting network produces, is reported as such
    /// and not as a failure to connect: the fix is the trust store, not the network.
    #[test]
    fn an_untrusted_certificate_is_told_apart_from_other_failures() {
        let wrapped = std::io::Error::other(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ));
        assert_eq!(tls_failure(&wrapped), Some(NetworkFailure::Certificate));
        let handshake = std::io::Error::other(rustls::Error::HandshakeNotComplete);
        assert_eq!(tls_failure(&handshake), Some(NetworkFailure::Tls));
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert_eq!(tls_failure(&refused), None);
    }
}
