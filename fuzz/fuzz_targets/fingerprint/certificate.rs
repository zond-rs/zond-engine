// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The certificate a peer presents, through both readers that look at one.
//!
//! This is the only place in the crate where fully attacker-chosen bytes go into
//! third-party parsing code. A scanner completes a TLS handshake with a verifier
//! that accepts anything — deliberately, because expired, self-signed and
//! wrong-host certificates are the ones worth reporting — so whatever the peer
//! sends arrives here unfiltered and is handed to `x509-parser`.
//!
//! Both readers are driven, because they read the same bytes to answer different
//! questions and each has its own walk over the structure. `TlsCertAnalyzer`
//! asks what the service is; `tls_summary::security` asks what the handshake
//! established, and it is the one that reaches the extensions, the public key
//! and the validity window.
//!
//! ## The oracles
//!
//! **Neither reader panics on any input.** That is most of it, and it is not a
//! low bar: the summary walks a subject alternative name extension, renders IP
//! addresses out of raw octets, parses a public key and converts two ASN.1 times
//! into `SystemTime`, and every one of those is arithmetic over remote values.
//!
//! **A record is produced for every completed handshake, readable chain or
//! not.** A certificate this cannot parse is a finding rather than a reason to
//! report nothing, so the negotiated parameters must survive a chain that does
//! not parse.
//!
//! **Nothing a certificate says reaches a report unbounded.** A subject common
//! name is remote text on its way into an exported document.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zond_engine::fingerprint::{
    Analyzer, Collected, PortContext, ResponseSet, TlsCertAnalyzer, TlsInfo,
};
use zond_engine::model::port::Protocol;

fuzz_target!(|data: &[u8]| {
    // The chain as the handshake would hand it over: the leaf is what both
    // readers take, and a second entry proves neither reaches past it.
    let chain = vec![data.to_vec(), data.to_vec()];
    let info = TlsInfo::new(chain)
        .with_version("TLSv1.3")
        .with_cipher_suite("TLS13_AES_256_GCM_SHA384");
    let responses = ResponseSet::from_banners(Vec::new()).with_tls(info);

    // What the handshake established. Always produced, whatever the chain is.
    let tls = responses.tls.as_ref().expect("just set");
    let security = zond_engine::fingerprint::tls_security(tls);
    assert_eq!(
        security.tls_version(),
        Some("TLSv1.3"),
        "a chain that does not parse must not lose what was negotiated"
    );

    if let Some(certificate) = security.certificate() {
        // Remote text on its way into an exported document.
        assert!(
            certificate.common_name().len() <= 4096,
            "a subject common name reached a report unbounded"
        );
        assert!(certificate.issuer().len() <= 4096);
        assert_eq!(
            certificate.fingerprint_sha256().len(),
            64,
            "a fingerprint is a SHA-256 in hex, whatever the certificate was"
        );
        // The window is two instants and must be orderable, whatever the
        // certificate claimed.
        let _ = certificate.validity_end() >= certificate.validity_start();
    }

    // What the service is. Reads the same leaf and asks a different question.
    let ctx = PortContext::new(443, Protocol::Tcp);
    let evidence = TlsCertAnalyzer.analyze(&ctx, &responses, &Collected::default());
    assert_eq!(
        evidence.len(),
        1,
        "a completed handshake establishes TLS whether or not its chain parses"
    );
    if let Some(vendor) = evidence[0].vendor.as_deref() {
        assert!(!vendor.is_empty(), "an empty vendor is not an attribution");
    }
});
