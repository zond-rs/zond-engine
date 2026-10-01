// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Signing a document, and checking one
//!
//! Two things in this crate are worth signing, and they are signed the same way.
//!
//! A **report** records scope, exclusions and coverage, which makes it evidence (an ASV
//! report, a SOC 2 artifact, a pentest appendix), but a file anyone can edit.
//!
//! A **detection bundle** is bytes from a stranger that this process will compile and
//! run; see [`detect::bundle`](crate::detect::bundle).
//!
//! The caller supplies a key, writes the document through [`Signing`], and keeps the
//! returned [`Signature`] beside it.
//!
//! Unrelated to the match rules [`fingerprint`](crate::fingerprint) calls signatures.
//!
//! ```no_run
//! use zond_engine::export::{ExportFormat, ExportOptions};
//! use zond_engine::signature::{Domain, SigningKey, Signing};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let report = zond_engine::report::ScanReport::recorded("0.0.0", vec![], []);
//! # let pkcs8 = std::fs::read("signing-key.pk8")?;
//! let key = SigningKey::from_pkcs8(&pkcs8)?;
//! let mut file = std::fs::File::create("scan.json")?;
//!
//! let mut writer = Signing::new(&mut file);
//! ExportFormat::Json
//!     .exporter(ExportOptions::new())
//!     .export(&report, &mut writer)?;
//! let signature = writer.finish(&key, Domain::REPORT);
//!
//! std::fs::write("scan.json.sig", signature.to_document())?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Detached
//!
//! An embedded signature needs rules for which bytes to exclude and how to canonicalise
//! the rest, a common source of verification bypasses. This signs the exact bytes
//! written and keeps the signature in its own file; verification hashes the document as
//! it sits on disk.
//!
//! ## What a signature establishes
//!
//! That the key holder produced this document and not a byte has changed since.
//!
//! It does not make a *scan* tamper-evident: the key holder can sign a report they
//! edited first.
//!
//! ## Keys belong to the caller
//!
//! Nothing here stores, loads or rotates keys. [`SigningKey`] takes a PKCS#8 document
//! the caller has, and [`Signature::verify`] takes the public key the caller trusts.

use std::io::{BufRead, Write};

use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

/// The largest signature document [`Signature::read`] will take.
///
/// One this crate writes is five short lines; the ceiling is for files from elsewhere.
const MAX_DOCUMENT_BYTES: u64 = 64 * 1024;

/// The one signature algorithm, named so a document says which produced it.
///
/// Ed25519 (RFC 8032). One algorithm, so a document cannot talk a verifier down to a
/// weaker one.
pub const ALGORITHM: &str = "ed25519";

/// What the signed bytes are a signature *of*.
///
/// Prefixed to the digest before signing, so a signature over one kind of document
/// cannot be presented as one over another kind the same key signed.
///
/// The caller states the domain at both ends, like the trusted key, so a document cannot
/// pick it. Only the domains defined here exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Domain(&'static [u8]);

impl Domain {
    /// An exported [`ScanReport`](crate::report::ScanReport), in any format.
    pub const REPORT: Self = Self(b"zond.report.signature.v1\0");

    /// A [detection bundle](crate::detect::bundle)'s manifest.
    pub const DETECTIONS: Self = Self(b"zond.detections.signature.v1\0");
}

/// The digest the signature covers, named in the document beside it.
pub const DIGEST: &str = "sha256";

/// Why a document could not be signed or a signature could not be checked.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// The PKCS#8 document is not an Ed25519 private key.
    #[error("the signing key could not be read: not a PKCS#8 Ed25519 key")]
    UnreadableKey,

    /// The signature document is not one this wrote.
    #[error("the signature document is malformed: {0}")]
    Malformed(String),

    /// The document names an algorithm or digest this build does not implement.
    #[error("the signature names '{named}', and this build implements '{implemented}'")]
    UnknownAlgorithm {
        /// What the document asked for.
        named: String,
        /// What is available.
        implemented: &'static str,
    },

    /// The signature is by a key other than the one the caller trusts.
    ///
    /// See [`Signature::verify`].
    #[error("the signature is by a key the caller did not name as trusted")]
    UntrustedKey,

    /// The document does not hash to what the signature covers, so it changed
    /// after it was signed.
    #[error("the document does not match the signature: it has been altered")]
    Altered,

    /// The signature does not verify under the key that made it.
    #[error("the signature is not valid for this document and key")]
    Invalid,

    /// The signature document could not be read.
    #[error("the signature could not be read: {0}")]
    Io(#[from] std::io::Error),
}

/// A key that signs exported documents.
///
/// Built from a PKCS#8 v2 document, as `ring` and `openssl genpkey -algorithm ed25519`
/// emit for an Ed25519 private key.
pub struct SigningKey {
    pair: Ed25519KeyPair,
}

impl SigningKey {
    /// Reads a signing key from a PKCS#8 document.
    ///
    /// # Errors
    ///
    /// [`SignatureError::UnreadableKey`] where the bytes are not an Ed25519 private key
    /// in that encoding. The error does not say how parsing failed, so it reveals
    /// nothing about key material.
    pub fn from_pkcs8(document: &[u8]) -> Result<Self, SignatureError> {
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(document)
            .map(|pair| Self { pair })
            .map_err(|_| SignatureError::UnreadableKey)
    }

    /// Generates a key, returning the PKCS#8 document to keep and the key to
    /// sign with.
    ///
    /// For tests and simple callers. The document is returned, not stored; keeping it
    /// safe is the caller's responsibility.
    ///
    /// # Errors
    ///
    /// [`SignatureError::UnreadableKey`] where the system random source failed,
    /// which is the same thing to a caller: no key came back.
    pub fn generate() -> Result<(Vec<u8>, Self), SignatureError> {
        let random = SystemRandom::new();
        let document =
            Ed25519KeyPair::generate_pkcs8(&random).map_err(|_| SignatureError::UnreadableKey)?;
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(document.as_ref())
            .map_err(|_| SignatureError::UnreadableKey)?;
        Ok((document.as_ref().to_vec(), Self { pair }))
    }

    /// The public half, as the raw thirty-two bytes.
    ///
    /// A recipient must obtain this from somewhere other than the signature.
    pub fn public_key(&self) -> Vec<u8> {
        self.pair.public_key().as_ref().to_vec()
    }
}

impl std::fmt::Debug for SigningKey {
    /// Prints nothing about the key.
    ///
    /// So a key cannot leak into a log through `{:?}`. Use
    /// [`public_key`](SigningKey::public_key) to print the public half.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

/// A detached signature over an exported document.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    algorithm: String,
    digest_algorithm: String,
    public_key: String,
    digest: String,
    signature: String,
}

impl Signature {
    /// The signature algorithm this document names.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The public key that made it, hex-encoded.
    ///
    /// Says *which* key to look up; never verify against it. See
    /// [`verify`](Self::verify).
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// The digest of the document this covers, hex-encoded.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Checks `document` against this signature, under a key the caller trusts.
    ///
    /// `trusted_key` is the raw public key. It is a parameter because trusting the key
    /// printed in the document would accept anything an attacker re-signed with their
    /// own key.
    ///
    /// # Errors
    ///
    /// [`SignatureError::UntrustedKey`] where the signature is by another key,
    /// [`SignatureError::Altered`] where the document no longer hashes to what
    /// was signed, [`SignatureError::Invalid`] where the signature does not
    /// verify, and [`SignatureError::UnknownAlgorithm`] for a document naming
    /// something this build does not implement.
    pub fn verify(
        &self,
        document: &[u8],
        trusted_key: &[u8],
        domain: Domain,
    ) -> Result<(), SignatureError> {
        self.verify_digest(&sha256(document), trusted_key, domain)
    }

    /// [`verify`](Self::verify) for a document already hashed, as SHA-256.
    ///
    /// For a document hashed as it streamed past, such as a download.
    pub(crate) fn verify_digest(
        &self,
        digest: &[u8],
        trusted_key: &[u8],
        domain: Domain,
    ) -> Result<(), SignatureError> {
        if self.algorithm != ALGORITHM {
            return Err(SignatureError::UnknownAlgorithm {
                named: self.algorithm.clone(),
                implemented: ALGORITHM,
            });
        }
        if self.digest_algorithm != DIGEST {
            return Err(SignatureError::UnknownAlgorithm {
                named: self.digest_algorithm.clone(),
                implemented: DIGEST,
            });
        }

        let named_key = decode_hex(&self.public_key)
            .ok_or_else(|| SignatureError::Malformed("the public key is not hex".to_string()))?;
        // Checked first: an untrusted key ends the matter.
        if named_key != trusted_key {
            return Err(SignatureError::UntrustedKey);
        }

        let recorded = decode_hex(&self.digest)
            .ok_or_else(|| SignatureError::Malformed("the digest is not hex".to_string()))?;
        if digest != recorded {
            return Err(SignatureError::Altered);
        }

        let signature = decode_hex(&self.signature)
            .ok_or_else(|| SignatureError::Malformed("the signature is not hex".to_string()))?;

        UnparsedPublicKey::new(&ED25519, trusted_key)
            .verify(&signed_payload(domain, digest), &signature)
            .map_err(|_| SignatureError::Invalid)
    }

    /// The document to write beside the report, conventionally under the
    /// report's own name with `.sig` appended.
    ///
    /// TOML, so a build without the JSON exporter can write it and a person can read
    /// it.
    pub fn to_document(&self) -> String {
        format!(
            "# A detached signature over the report beside this file.\n\
             # Verify against a public key obtained from somewhere other than this document.\n\
             algorithm = \"{}\"\n\
             digest_algorithm = \"{}\"\n\
             public_key = \"{}\"\n\
             digest = \"{}\"\n\
             signature = \"{}\"\n",
            self.algorithm, self.digest_algorithm, self.public_key, self.digest, self.signature
        )
    }

    /// Reads a signature document back.
    ///
    /// # Errors
    ///
    /// [`SignatureError::Malformed`] for anything this did not write.
    pub fn read(input: &mut dyn BufRead) -> Result<Self, SignatureError> {
        use std::io::Read as _;

        // Bounded, since the file arrives from elsewhere (as `journal::store`
        // bounds its manifest).
        let mut source = String::new();
        let read = (&mut *input)
            .take(MAX_DOCUMENT_BYTES + 1)
            .read_to_string(&mut source)?;
        if read as u64 > MAX_DOCUMENT_BYTES {
            return Err(SignatureError::Malformed(format!(
                "the signature document is larger than {MAX_DOCUMENT_BYTES} bytes"
            )));
        }

        let document: SignatureDocument = toml::from_str(&source)
            .map_err(|error| SignatureError::Malformed(error.to_string()))?;

        Ok(Self {
            algorithm: document.algorithm,
            digest_algorithm: document.digest_algorithm,
            public_key: document.public_key,
            digest: document.digest,
            signature: document.signature,
        })
    }
}

/// The signature document, as it is read back.
#[derive(Debug, serde::Deserialize)]
struct SignatureDocument {
    algorithm: String,
    digest_algorithm: String,
    public_key: String,
    digest: String,
    signature: String,
}

/// A writer that signs everything written through it.
///
/// Wraps the export's writer and hashes bytes as they stream, buffering nothing.
pub struct Signing<'a> {
    inner: &'a mut dyn Write,
    digest: ring::digest::Context,
}

impl<'a> Signing<'a> {
    /// Wraps `inner`, hashing what passes through on the way.
    pub fn new(inner: &'a mut dyn Write) -> Self {
        Self {
            inner,
            digest: ring::digest::Context::new(&ring::digest::SHA256),
        }
    }

    /// Signs what was written and returns the detached signature.
    ///
    /// Consumes the wrapper, so no bytes can follow the signature.
    pub fn finish(self, key: &SigningKey, domain: Domain) -> Signature {
        let digest = self.digest.finish().as_ref().to_vec();
        let signature = key.pair.sign(&signed_payload(domain, &digest));

        Signature {
            algorithm: ALGORITHM.to_string(),
            digest_algorithm: DIGEST.to_string(),
            public_key: encode_hex(&key.public_key()),
            digest: encode_hex(&digest),
            signature: encode_hex(signature.as_ref()),
        }
    }
}

impl Write for Signing<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Hash only what the inner writer took; a short write takes less than
        // `buf`.
        let written = self.inner.write(buf)?;
        self.digest.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl std::fmt::Debug for Signing<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signing(..)")
    }
}

/// What is actually signed: the context, then the digest.
///
/// The digest alone could be lifted and presented as a signature over something else
/// this key signed.
fn signed_payload(domain: Domain, digest: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(domain.0.len() + digest.len());
    payload.extend_from_slice(domain.0);
    payload.extend_from_slice(digest);
    payload
}

/// The SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

/// Lowercase hex, which is how every field of a signature document is written.
fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// [`encode_hex`] read back, or `None` for anything that is not an even run of
/// lowercase hex digits.
///
/// Exactly `[0-9a-f]`. `u8::from_str_radix(_, 16)` accepts a leading `+`, which would
/// give each field many spellings. Not a bypass, since [`Signature::verify`] decides on
/// decoded bytes, but [`Signature::public_key`] is what a recipient looks a key up by,
/// so encoding and decoding are kept one-to-one.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            Some(digit(pair[0])? << 4 | digit(pair[1])?)
        })
        .collect()
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

    /// A key, and a document signed with it.
    fn signed(document: &[u8]) -> (SigningKey, Signature) {
        let (_, key) = SigningKey::generate().expect("a key");
        let mut sink = Vec::new();
        let mut writer = Signing::new(&mut sink);
        writer.write_all(document).expect("writes");
        let signature = writer.finish(&key, Domain::REPORT);
        (key, signature)
    }

    /// A document verifies against the key that signed it.
    #[test]
    fn a_signed_document_verifies_under_the_key_that_signed_it() {
        let document = b"{\"schema_version\":1}";
        let (key, signature) = signed(document);

        assert_eq!(signature.algorithm(), ALGORITHM);
        assert!(
            signature
                .verify(document, &key.public_key(), Domain::REPORT)
                .is_ok()
        );
    }

    /// One changed byte and the document no longer matches.
    #[test]
    fn a_document_altered_by_one_byte_does_not_verify() {
        let document = b"{\"open_ports\":1}".to_vec();
        let (key, signature) = signed(&document);

        let mut altered = document.clone();
        let last = altered.len() - 2;
        altered[last] = b'9';

        assert!(matches!(
            signature.verify(&altered, &key.public_key(), Domain::REPORT),
            Err(SignatureError::Altered)
        ));
    }

    /// A document re-signed with another key is internally consistent, and only the
    /// caller's trusted key catches it.
    #[test]
    fn a_document_resigned_by_another_key_is_refused() {
        let original = b"nine hosts, no findings".to_vec();
        let (trusted, _) = signed(&original);

        // Edited and re-signed with another key.
        let forged = b"nine hosts, one finding removed".to_vec();
        let (attacker, forged_signature) = signed(&forged);
        assert!(
            forged_signature
                .verify(&forged, &attacker.public_key(), Domain::REPORT)
                .is_ok(),
            "the forgery is internally consistent, which is the point"
        );

        // Refused against the trusted key.
        assert!(matches!(
            forged_signature.verify(&forged, &trusted.public_key(), Domain::REPORT),
            Err(SignatureError::UntrustedKey)
        ));
    }

    /// A signature in one domain does not verify in the other, under the same key.
    #[test]
    fn a_signature_in_one_domain_does_not_verify_in_the_other() {
        let document = b"the same bytes either way".to_vec();

        let (_, key) = SigningKey::generate().expect("a key");
        let mut sink = Vec::new();
        let mut writer = Signing::new(&mut sink);
        writer
            .write_all(&document)
            .expect("the document is written");
        let over_a_report = writer.finish(&key, Domain::REPORT);

        assert!(
            over_a_report
                .verify(&document, &key.public_key(), Domain::REPORT)
                .is_ok(),
            "the signature is good in its own domain"
        );
        assert!(
            matches!(
                over_a_report.verify(&document, &key.public_key(), Domain::DETECTIONS),
                Err(SignatureError::Invalid)
            ),
            "a report's signature was accepted as a bundle's"
        );
    }

    /// A signature over one document does not verify another, even under the
    /// right key.
    #[test]
    fn a_signature_does_not_carry_across_documents() {
        let (key, signature) = signed(b"the first report");
        assert!(matches!(
            signature.verify(b"the second report", &key.public_key(), Domain::REPORT),
            Err(SignatureError::Altered)
        ));
    }

    /// The signature document round-trips.
    #[test]
    fn a_signature_document_round_trips() {
        let document = b"a report".to_vec();
        let (key, signature) = signed(&document);

        let text = signature.to_document();
        let read = Signature::read(&mut text.as_bytes()).expect("reads back");

        assert_eq!(read, signature);
        assert!(
            read.verify(&document, &key.public_key(), Domain::REPORT)
                .is_ok()
        );
    }

    /// A signature whose recorded digest was edited to match a doctored document
    /// still fails, because the digest is signed and not merely recorded.
    #[test]
    fn editing_the_recorded_digest_does_not_help_an_attacker() {
        let document = b"the original".to_vec();
        let (key, signature) = signed(&document);

        let doctored = b"the replacement".to_vec();
        let mut forged = signature.clone();
        forged.digest = encode_hex(&sha256(&doctored));

        // The digest matches the document, but the signature covers the old one.
        assert!(matches!(
            forged.verify(&doctored, &key.public_key(), Domain::REPORT),
            Err(SignatureError::Invalid)
        ));
    }

    /// An unknown algorithm is refused by name.
    #[test]
    fn an_algorithm_this_build_does_not_implement_is_refused() {
        let (key, signature) = signed(b"a report");

        let mut downgraded = signature.clone();
        downgraded.algorithm = "none".to_string();
        assert!(matches!(
            downgraded.verify(b"a report", &key.public_key(), Domain::REPORT),
            Err(SignatureError::UnknownAlgorithm { .. })
        ));

        let mut weakened = signature.clone();
        weakened.digest_algorithm = "md5".to_string();
        assert!(matches!(
            weakened.verify(b"a report", &key.public_key(), Domain::REPORT),
            Err(SignatureError::UnknownAlgorithm { .. })
        ));
    }

    /// The wrapper signs what the writer accepted, not what it was offered.
    #[test]
    fn a_short_write_signs_only_what_was_written() {
        /// A writer that takes four bytes at a time, as a pipe or a socket will.
        struct Trickle(Vec<u8>);
        impl Write for Trickle {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let take = buf.len().min(4);
                self.0.extend_from_slice(&buf[..take]);
                Ok(take)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (_, key) = SigningKey::generate().expect("a key");
        let document = b"a report long enough to need several writes".to_vec();

        let mut trickle = Trickle(Vec::new());
        {
            let mut writer = Signing::new(&mut trickle);
            // `write_all` loops on the short writes.
            writer.write_all(&document).expect("writes");
            let signature = writer.finish(&key, Domain::REPORT);
            assert!(
                signature
                    .verify(&document, &key.public_key(), Domain::REPORT)
                    .is_ok()
            );
        }
        assert_eq!(trickle.0, document, "every byte reached the inner writer");
    }

    /// A real report through the exporter: the signature covers exactly the file on
    /// disk, however the exporter streams it.
    #[test]
    fn a_real_exported_report_signs_and_verifies_as_written() {
        use crate::export::{ExportFormat, ExportOptions};

        let report = crate::export::fixture::report();
        let (_, key) = SigningKey::generate().expect("a key");

        let mut document = Vec::new();
        let signature = {
            let mut writer = Signing::new(&mut document);
            ExportFormat::Json
                .exporter(ExportOptions::new())
                .export(&report, &mut writer)
                .expect("the report exports");
            writer.finish(&key, Domain::REPORT)
        };

        assert!(!document.is_empty(), "something was written");
        assert_eq!(
            signature.digest(),
            encode_hex(&sha256(&document)),
            "the signature covers the bytes that were written and no others"
        );
        assert!(
            signature
                .verify(&document, &key.public_key(), Domain::REPORT)
                .is_ok()
        );

        // The sidecar document verifies the same file.
        let sidecar = Signature::read(&mut signature.to_document().as_bytes()).expect("reads");
        assert!(
            sidecar
                .verify(&document, &key.public_key(), Domain::REPORT)
                .is_ok()
        );

        // A re-export with a different policy is a different document.
        let mut redacted = Vec::new();
        ExportFormat::Json
            .exporter(ExportOptions::new().with_redaction(crate::export::Redaction::Standard))
            .export(&report, &mut redacted)
            .expect("the report exports");
        assert!(matches!(
            signature.verify(&redacted, &key.public_key(), Domain::REPORT),
            Err(SignatureError::Altered)
        ));
    }

    /// Anything that is not a signature document is refused.
    #[test]
    fn what_is_not_a_signature_document_is_refused() {
        for text in ["", "not toml", "algorithm = \"ed25519\""] {
            assert!(
                Signature::read(&mut text.as_bytes()).is_err(),
                "'{text}' read as a signature"
            );
        }
    }

    /// A malformed field is refused, not treated as absent.
    #[test]
    fn a_field_that_is_not_hex_is_refused() {
        let (key, signature) = signed(b"a report");

        let mut broken = signature.clone();
        broken.public_key = "not hex".to_string();
        assert!(matches!(
            broken.verify(b"a report", &key.public_key(), Domain::REPORT),
            Err(SignatureError::Malformed(_))
        ));

        let mut odd = signature.clone();
        odd.signature = "abc".to_string();
        assert!(
            odd.verify(b"a report", &key.public_key(), Domain::REPORT)
                .is_err()
        );
    }

    /// Bytes that are not a key are refused, and the error says no more than
    /// that.
    #[test]
    fn what_is_not_a_key_is_refused() {
        assert!(matches!(
            SigningKey::from_pkcs8(b"not a key"),
            Err(SignatureError::UnreadableKey)
        ));
    }

    /// A key does not print itself.
    #[test]
    fn a_signing_key_prints_nothing_about_itself() {
        let (document, key) = SigningKey::generate().expect("a key");
        let printed = format!("{key:?}");

        assert_eq!(printed, "SigningKey(..)");
        assert!(!printed.contains(&encode_hex(&document)));
        assert!(!printed.contains(&encode_hex(&key.public_key())));
    }

    /// Hex round-trips, and non-hex reads as nothing.
    #[test]
    fn hex_round_trips_and_refuses_what_is_not_hex() {
        let bytes = vec![0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(encode_hex(&bytes), "000fa5ff");
        assert_eq!(decode_hex("000fa5ff"), Some(bytes));

        assert_eq!(decode_hex("abc"), None, "an odd length is not hex");
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex(""), Some(Vec::new()));
    }

    /// **A signature document has one spelling.**
    ///
    /// A leading `+` is refused, so each hex field has one encoding.
    #[test]
    fn only_lowercase_hex_decodes() {
        assert_eq!(decode_hex("0f"), Some(vec![0x0f]));
        assert_eq!(decode_hex("00ff"), Some(vec![0x00, 0xff]));

        for refused in [
            "+f", "+0", "+f+f", " f", "0X", "0x", "-1", "FF", "0F", "f", "g0",
        ] {
            assert_eq!(
                decode_hex(refused),
                None,
                "{refused:?} is not what encode_hex emits"
            );
        }
    }

    /// Everything this crate writes still reads back.
    #[test]
    fn every_byte_survives_the_round_trip() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode_hex(&encode_hex(&all)), Some(all));
    }

    /// A re-spelled public key does not verify, because it does not decode.
    #[test]
    fn a_respelled_key_is_refused_rather_than_accepted() {
        let document = b"a signed report";
        let (key, signature) = signed(document);
        let trusted = key.public_key();
        assert!(signature.verify(document, &trusted, Domain::REPORT).is_ok());

        let respelled = signature.public_key().replacen("0", "+", 1);
        if respelled == signature.public_key() {
            return; // no leading-zero nibble in this key; nothing to re-spell
        }
        let forged = Signature {
            algorithm: signature.algorithm().to_string(),
            digest_algorithm: DIGEST.to_string(),
            public_key: respelled,
            digest: signature.digest().to_string(),
            signature: encode_hex(&decode_hex(&signature.signature).expect("hex")),
        };
        assert!(matches!(
            forged.verify(document, &trusted, Domain::REPORT),
            Err(SignatureError::Malformed(_))
        ));
    }

    /// A document larger than the ceiling is refused.
    #[test]
    fn an_oversized_document_is_refused() {
        let padding = "#".repeat(MAX_DOCUMENT_BYTES as usize + 1);
        let document = format!(
            "algorithm = \"ed25519\"\ndigest_algorithm = \"sha256\"\n\
             public_key = \"00\"\ndigest = \"00\"\nsignature = \"00\"\n{padding}\n"
        );
        let mut input = std::io::Cursor::new(document.as_bytes());
        assert!(matches!(
            Signature::read(&mut input),
            Err(SignatureError::Malformed(_))
        ));
    }
}
