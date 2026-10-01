// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Folding several scans into one report
//!
//! Scan a `/16` in eight chunks and you have eight documents. Scan a range from
//! inside the perimeter and again from outside and you have two. Inherit an
//! engagement repository and you have a year of nmap XML. [`Merge`] turns any
//! number of them into one [`ScanReport`].
//!
//! ```no_run
//! use zond_engine::merge::{Merge, MergeOptions};
//! # use zond_engine::report::ScanReport;
//! # fn example(tonight: ScanReport, archived: ScanReport, chunk: ScanReport) {
//! let mut merge = Merge::new(MergeOptions::default());
//! merge.add(tonight);                       // a scan this process ran
//! merge.add_from("q1.xml", archived);       // a document, named by the caller
//! merge.add_from("chunk3.json", chunk);
//!
//! let report = merge.finish();
//! # }
//! ```
//!
//! ## What a merge answers
//!
//! What is out there given everything known: the network as of the newest source that
//! looked at it. What changed is [`diff`](crate::diff)'s question; history stays in the
//! input documents.
//!
//! So a merge is lossy in one way: where two sources disagree, one answer wins and the
//! other remains only in its input file. What accumulates does accumulate: addresses,
//! endpoints, hardware addresses, roles and status reasons. A service's CPEs do not;
//! each names a product version, so it goes with the identification it was read from.
//!
//! ## The rule: a later source overrides only where it made a claim
//!
//! Sources are folded oldest to newest. Where a newer source states something,
//! it wins. Where a newer source says nothing, the older answer stands.
//!
//! Absence is never a claim: a host missing from tonight's scan has not gone away, an
//! unlisted endpoint has not closed, and a field a document has no word for (nmap has
//! none for a service vendor) is not retracted.
//!
//! [`Unknown`](crate::model::host::HostStatus::Unknown) means nothing was received, so a
//! newer `Unknown` never overrides an older verdict.
//!
//! What a TLS endpoint [accepts](crate::model::tls::TlsSupport) folds version by
//! version. A walk cut short records what it reached and is silent about the rest, so
//! where a newer cut-short walk found nothing the older account lacks, the older stands
//! if it went further. A newer walk that found a new suite, or finished, is the newer
//! answer.
//!
//! ### A finding goes with the evidence it was drawn from
//!
//! Findings accumulate, since a finding missing from a newer scan is a detection that
//! did not fire. The exception is a finding refuted by evidence the report holds beside
//! it. Three derivations draw from such evidence: TLS acceptance (resting on the versions
//! whose walk drew them), certificate posture (resting on the certificate), and
//! vulnerability correlation (resting on the platform identifiers it names). Where the
//! folded record settled what a claim rests on and does not draw it (a newer finished
//! walk found TLS 1.0 refused, a different certificate, another service version), the
//! claim is dropped. Where it left that unsettled, the claim stands.
//!
//! A claim that stands has its excerpt restated from the folded record wherever the
//! evidence under it moved, so it never names a suite under a version the merged report
//! says is refused. The verdict is the scan's own.
//!
//! Every other finding is kept, since the report holds nothing it rests on.
//!
//! ### Exclusions
//!
//! [`Exclusions`](crate::model::exclusion::Exclusions) is not a parameter here. The
//! exclusion promise is enforced by a *scan*, before anything is opened and at
//! [`write_host`](crate::scanner::session::ScanContext::write_host); a merge probes
//! nothing and folds what other scans recorded. A source that walked an address the
//! caller now excludes contributes it.
//!
//! Every source's phase is kept with its scope and withheld ranges, so an address can be
//! traced to its source and checked against that source's scope.
//!
//! ### Coverage
//!
//! A merge never explains an absence, so it needs no
//! [`Coverage`](crate::diff::Coverage). The merged report holds every source's phases,
//! which carry coverage.
//!
//! ## Which record is which host
//!
//! [`HostIdentity`] decides, as for a comparison; see [`pairing`]. The default follows
//! a dual-stack machine keyed under IPv4 by one scanner and IPv6 by another.
//!
//! ## Provenance
//!
//! Every phase folded in carries a [`PhaseOrigin`]: what the caller called the document
//! and what produced it. An origin already on a phase is kept, so merging a merged
//! report keeps its sources' labels.
//!
//! ## What comes back
//!
//! A [`ScanReport`], so a merged report exports through every writer, compares through
//! a diff, and merges again.
//!
//! ## Redaction
//!
//! A name the fold does not keep (a renamed machine's old name) can still appear in the
//! older source's findings and banners. The merged record sets such names aside, and
//! [redaction](crate::export::Redaction) masks them in that text. They are not written
//! into documents, so this works only when the merged report is redacted as it is
//! written.
//!
//! ## Fold every source at once
//!
//! A merged report cannot be taken apart into its inputs, so merging in rounds differs
//! from merging at once: `merge(merge(a, c), b)` folds `b` against `c`'s clock, so a
//! verdict `b` should have overturned survives, and readings the first round discarded
//! cannot enrich `b`'s findings. Pass all N documents to one [`Merge`]. Merging a merged
//! report is supported and gives a coherent report, just not the one a single fold
//! would have given.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use crate::diff::HostIdentity;
use crate::diff::pairing;
use crate::model::finding::{Finding, Standing};
use crate::model::host::hardware::HardwareInfo;
use crate::model::host::os::OsFingerprint;
use crate::model::host::{Host, HostStatus};
use crate::model::port::{Port, PortState, Protocol, Security, Service};
use crate::report::{PhaseOrigin, ScanPhase, ScanReport};

/// What a merge is allowed to assume.
///
/// The default suits scans of one network, by whatever tools, in whatever order.
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeOptions {
    identity: HostIdentity,
}

impl MergeOptions {
    /// The defaults: records are the same host when they share any address.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets what makes two records the same host.
    pub fn with_identity(mut self, identity: HostIdentity) -> Self {
        self.identity = identity;
        self
    }

    /// What makes two records the same host.
    pub fn identity(&self) -> HostIdentity {
        self.identity
    }
}

/// One report waiting to be folded, and what the caller called it.
#[derive(Debug)]
struct Source {
    label: Option<Arc<str>>,
    report: ScanReport,
}

/// Several scans, folded into one report.
///
/// Reports accumulate and [`finish`](Self::finish) folds them in clock order, whatever
/// order they were added in. See the module documentation.
#[derive(Debug)]
pub struct Merge {
    options: MergeOptions,
    sources: Vec<Source>,
}

impl Merge {
    /// A merge that will fold under `options`.
    pub fn new(options: MergeOptions) -> Self {
        Self {
            options,
            sources: Vec::new(),
        }
    }

    /// Adds a report with no name.
    ///
    /// For a scan this process ran. Its phases are still attributed by engine version.
    pub fn add(&mut self, report: ScanReport) -> &mut Self {
        self.sources.push(Source {
            label: None,
            report,
        });
        self
    }

    /// Adds a report, naming the document it was read from.
    ///
    /// The label is the caller's: a path, a record id, a bucket key.
    ///
    /// A phase that already carries a [`PhaseOrigin`] keeps it.
    pub fn add_from(&mut self, label: impl Into<Arc<str>>, report: ScanReport) -> &mut Self {
        self.sources.push(Source {
            label: Some(label.into()),
            report,
        });
        self
    }

    /// How many reports are waiting to be folded.
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether nothing has been added.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Folds every source added into one report.
    ///
    /// Records are ordered by when each was observed. A merge of nothing is an empty
    /// report attributed to this build.
    pub fn finish(self) -> ScanReport {
        let Self { options, sources } = self;

        if sources.is_empty() {
            return ScanReport::from_phases(Vec::new(), Vec::new());
        }

        // Read once per source; it walks every phase.
        let mut sources: Vec<(SystemTime, Source)> = sources
            .into_iter()
            .map(|source| (source.report.observed_at(), source))
            .collect();

        // Stable, so ties keep the order added.
        sources.sort_by_key(|(stopped, _)| *stopped);

        // Every record, dated by when it was observed.
        let mut dated: Vec<(SystemTime, &Host)> = sources
            .iter()
            .flat_map(|(stopped, source)| {
                let stopped = *stopped;
                source
                    .report
                    .hosts()
                    .map(move |record| (observed_at(record, stopped), record))
            })
            .collect();

        // Stable, so ties keep source order.
        dated.sort_by_key(|(at, _)| *at);

        // Oldest first, so "the last account" below means the newest.
        let records: Vec<&Host> = dated.into_iter().map(|(_, record)| record).collect();

        let hosts: Vec<Host> = pairing::groups(&records, options.identity)
            .into_iter()
            .map(|group| {
                let accounts: Vec<&Host> = group.into_iter().map(|i| records[i]).collect();
                fold_host(&accounts)
            })
            .collect();

        // The newest source's; each phase carries its own.
        let engine_version = sources
            .last()
            .expect("a non-empty source list")
            .1
            .report
            .engine_version()
            .to_owned();

        let mut phases = Vec::new();
        for (_, source) in sources {
            let attribution = PhaseOrigin::new(source.report.engine_version());
            let attribution = match &source.label {
                Some(label) => attribution.with_label(Arc::clone(label)),
                None => attribution,
            };

            for mut phase in source.report.into_phases() {
                if phase.origin().is_none() {
                    phase.attribute(attribution.clone());
                }
                phases.push(phase);
            }
        }

        // Chronological and stable.
        phases.sort_by_key(ScanPhase::started_at);

        ScanReport::recorded(engine_version, phases, hosts)
    }
}

/// When one record's account was taken, for ordering it against every other.
///
/// The earlier of the record's `last_seen` and the document's stop time. The record's
/// time places hosts correctly within a source that spans time (a resumed job, a merged
/// baseline); the document's bounds a hand-assembled record whose `last_seen` is just
/// when it was built.
fn observed_at(record: &Host, stopped: SystemTime) -> SystemTime {
    record.last_seen().min(stopped)
}

/// Folds every record of one host into one, oldest account first.
///
/// Built through the model's constructors, not [`Host::merge`], which folds probes of
/// one scan where state only promotes; across scans a port can close.
fn fold_host(accounts: &[&Host]) -> Host {
    let newest = accounts.last().expect("a group holds at least one record");

    // `consider_primary_ip` ranks the union of addresses.
    let mut host = Host::new(newest.primary_ip());
    for account in accounts {
        host.extend_ips(account.ips().iter().copied());
        host.consider_primary_ip(account.primary_ip());
    }

    if let Some(hostname) = newest_claim(accounts, |account| account.hostname()) {
        host.set_hostname(Some(hostname.to_owned()));
    }

    // Per protocol, from the newest account that heard names in it: a renamed
    // machine states only its new name, and an account that did not ask a
    // protocol cannot displace one that did.
    let mut heard = std::collections::BTreeSet::new();
    for account in accounts.iter().rev() {
        let sources: std::collections::BTreeSet<_> =
            account.names().map(|name| name.source()).collect();
        for name in account.names() {
            if !heard.contains(&name.source()) {
                host.record_name(name.clone());
            }
        }
        heard.extend(sources);
    }

    // Names not kept may still appear in older text, so set them aside for
    // redaction.
    for account in accounts {
        host.set_aside_names_of(account);
    }

    // `Unknown` is the absence of evidence and never overrides.
    if let Some(status) = accounts
        .iter()
        .rev()
        .map(|account| account.status())
        .find(|status| *status != HostStatus::Unknown)
    {
        host.set_status(status);
    }

    for account in accounts {
        for reason in account.reasons() {
            host.add_reason(reason.clone());
        }
        for role in account.network_roles() {
            host.add_network_role(*role);
        }
        // At most one source runs the comparative probe, so all are kept.
        for filtering in account.filtering() {
            host.add_filtering(*filtering);
        }
    }

    // Newest first: the evidence map is capped and turns away what arrives once
    // full, and many scans can fill it, so the newest readings must arrive first.
    for account in accounts.iter().rev() {
        for evidence in account.os_evidence() {
            host.record_os_evidence(evidence.clone());
        }
    }

    if let Some(os) = fold_os(accounts) {
        host.set_os(os);
    }

    // `HardwareInfo::merge` keeps the incumbent vendor and newest sightings, so
    // folding newest first gives this module's rule.
    let mut hardware = None;
    for found in accounts
        .iter()
        .rev()
        .filter_map(|account| account.hardware())
    {
        match hardware {
            Some(ref mut existing) => HardwareInfo::merge(existing, found.clone()),
            None => hardware = Some(found.clone()),
        }
    }
    if let Some(hardware) = hardware {
        host.set_hardware(hardware);
    }

    if let Some(zone) = newest_claim(accounts, |account| account.zone()) {
        host.set_zone(zone.clone());
    }

    // Taken whole from one account: `HostTelemetry::merge` sorts by `Instant`,
    // which means nothing across documents.
    if let Some(telemetry) = newest_claim(accounts, |account| {
        let telemetry = account.telemetry();
        (!telemetry.history().is_empty() || telemetry.hop_counter().is_some()).then_some(telemetry)
    }) {
        host.add_rtts(telemetry.history().iter().map(|sample| sample.rtt));
        if let Some(arrived) = telemetry.hop_counter() {
            host.record_hop_counter(arrived);
        }
    }

    // Whole: folding two different routes hop by hop makes a path nothing
    // travelled.
    if let Some(path) = newest_claim(accounts, |account| {
        let path = account.path();
        (!path.is_empty()).then_some(path)
    }) {
        for hop in path.hops() {
            host.record_hop(*hop);
        }
    }

    for port in fold_ports(accounts) {
        host.add_port(port);
    }

    // Oldest first, since `Finding::corroborate` lets the last account applied
    // set the verdict.
    for account in accounts {
        for finding in account.findings() {
            host.add_finding(finding.clone());
        }
    }

    // Last, since the mutators above stamp `last_seen`.
    let first_seen = accounts
        .iter()
        .map(|account| account.first_seen())
        .min()
        .expect("a group holds at least one record");
    let last_seen = accounts
        .iter()
        .map(|account| account.last_seen())
        .max()
        .expect("a group holds at least one record");
    host.restore_seen(first_seen, last_seen);

    host
}

/// The newest account that states something, or `None` where none does.
fn newest_claim<'a, T>(accounts: &[&'a Host], claim: impl Fn(&'a Host) -> Option<T>) -> Option<T> {
    accounts.iter().rev().find_map(|account| claim(account))
}

/// Every endpoint any account holds, each folded from every account of it.
///
/// Ordered by number and transport, as a host stores them.
fn fold_ports(accounts: &[&Host]) -> Vec<Port> {
    let mut by_endpoint: BTreeMap<(u16, Protocol), Vec<&Port>> = BTreeMap::new();

    for account in accounts {
        for port in account.ports() {
            by_endpoint
                .entry((port.number(), port.protocol()))
                .or_default()
                .push(port);
        }
    }

    by_endpoint.into_values().map(|of| fold_port(&of)).collect()
}

/// Folds every account of one endpoint into one, oldest first.
fn fold_port(accounts: &[&Port]) -> Port {
    let newest = accounts
        .last()
        .expect("an endpoint has at least one account");

    // The state is taken from the newest account, not promoted, so a merge can
    // record a port closing. `PortState::Unasked` is absence recorded as a state,
    // so it is skipped, as `HostStatus::Unknown` is; a new `PortState` needs the
    // same question asked here.
    let state = newest_claim_port(accounts, |account| {
        (account.state() != PortState::Unasked).then_some(account.state())
    })
    .unwrap_or(newest.state());
    let mut port = Port::new(newest.number(), newest.protocol(), state);

    // From the newest account that reached the same verdict: nmap's XML records
    // no packet, which would otherwise discard every zond scan's discovery.
    if let Some(discovery) = newest_claim_port(accounts, |account| {
        (account.state() == state)
            .then(|| account.discovery())
            .flatten()
    }) {
        port = port.with_discovery(discovery.clone());
    }

    if let Some(service) = fold_service(accounts) {
        port.set_service(service);
    }

    // Each older account is folded into the next newer one. Oldest first, so a
    // finished TLS walk retires every older account; newest first, an old walk
    // could outlive one that had overturned it.
    let mut security: Option<Security> = None;
    for found in accounts.iter().filter_map(|account| account.security()) {
        let mut newer = found.clone();
        if let Some(older) = security.take() {
            newer.merge(older);
        }
        security = Some(newer);
    }
    if let Some(security) = security {
        port.set_security(security);
    }

    // As on the host, less claims the folded record overturned, and with kept
    // claims reworded from it.
    for account in accounts {
        for finding in account.findings() {
            if !overturned(finding, account, &port) {
                port.add_finding(worded(finding, account, &port));
            }
        }
    }
    port.retire_superseded_correlations();

    port
}

/// Whether the folded record of an endpoint overturned a finding one account
/// of it carried.
///
/// Compares the account's record (the finding's evidence) with the folded one, so a
/// claim is overturned only by a newer account that settled what it rests on.
///
/// A correlation is overturned where the account's service carried one of its
/// identifiers and the folded service carries none. A claim resting only on
/// identifiers the account's service did not carry is left alone.
fn overturned(finding: &Finding, account: &Port, folded: &Port) -> bool {
    if finding.is_correlation() {
        let carries = |port: &Port| {
            port.service()
                .is_some_and(|service| finding.cpes().any(|cpe| service.cpes().contains(cpe)))
        };
        // The build too: a distribution's fix moves only the build. A claim
        // judged against one build, or none, is overturned by a folded record
        // carrying a different one.
        let judged = |port: &Port| {
            port.service().and_then(Service::build).map(same_build_key)
                == finding.build().map(same_build_key)
        };
        return (carries(account) && !carries(folded)) || (judged(account) && !judged(folded));
    }
    match (folded.security(), account.security()) {
        (Some(folded), Some(basis)) => {
            folded.standing(finding, basis) == Some(Standing::Overturned)
        }
        _ => false,
    }
}

/// What identifies a build: distributor, revision and release, without the basis.
fn same_build_key(
    build: &crate::model::port::Build,
) -> (crate::model::port::Distributor, Option<&str>, Option<&str>) {
    (
        build.distributor(),
        build.revision(),
        build.release().map(crate::model::port::Release::name),
    )
}

/// A finding one account of an endpoint carried, worded for the folded record
/// it will be carried beside.
///
/// Only the excerpt can change; see [`Security::restate`].
fn worded(finding: &Finding, account: &Port, folded: &Port) -> Finding {
    let restated = match (folded.security(), account.security()) {
        (Some(folded), Some(basis)) => folded.restate(finding, basis),
        _ => None,
    };
    match restated {
        Some(excerpt) => finding.clone().with_excerpt(excerpt),
        None => finding.clone(),
    }
}

/// The service one endpoint is running, from every account of it.
///
/// The identity (name, product, vendor, version, extra info, confidence) comes whole
/// from the newest account that *identified* a service, so an older `Apache` and a newer
/// `nginx` cannot splice into `nginx 2.4`. A label [inferred](Service::is_inferred) from
/// the port number counts only where nothing was identified, so a quick scan cannot
/// replace `Apache httpd 2.4.49` with a bare `http`.
///
/// An older account naming the same service (name and product) may fill in version
/// and extra info.
///
/// CPEs follow the identification. An older account's CPEs are kept only where it
/// names the same service and no other version, since the correlation joins on them and
/// a stale one would match vulnerabilities of software no longer running. Unlike
/// [`Service::merge`], which folds probes of one scan.
fn fold_service(accounts: &[&Port]) -> Option<Service> {
    fn identified(port: &Port) -> Option<&Service> {
        port.service().filter(|service| !service.is_inferred())
    }
    let newest = newest_claim_port(accounts, identified)
        .or_else(|| newest_claim_port(accounts, Port::service))?;

    // Every other identification, newest first, excluding the fold's own by
    // identity.
    let others = || {
        accounts
            .iter()
            .rev()
            .filter_map(|account| identified(account))
            .filter(|other| !std::ptr::eq(*other, newest))
    };

    let mut folded = Service::new(newest.name(), newest.confidence());
    if let Some(product) = newest.product() {
        folded = folded.with_product(product);
    }
    if let Some(vendor) = newest.vendor() {
        folded = folded.with_vendor(vendor);
    }
    if let Some(version) = newest.version() {
        folded = folded.with_version(version);
    }
    if let Some(extrainfo) = newest.extrainfo() {
        folded = folded.with_extrainfo(extrainfo);
    }
    if let Some(build) = newest.build() {
        folded = folded.with_build(build.clone());
    }

    for older in others().filter(|older| same_service(newest, older)) {
        if folded.vendor().is_none()
            && let Some(vendor) = older.vendor()
        {
            folded = folded.with_vendor(vendor);
        }
        if folded.version().is_none()
            && let Some(version) = older.version()
        {
            folded = folded.with_version(version);
        }
        if folded.extrainfo().is_none()
            && let Some(extrainfo) = older.extrainfo()
        {
            folded = folded.with_extrainfo(extrainfo);
        }
        // An older build completes the fold only for the same version.
        if folded.build().is_none()
            && folded.version() == older.version()
            && let Some(build) = older.build()
        {
            folded = folded.with_build(build.clone());
        }
    }

    // Newest first, so the cap keeps the reported identification's identifiers.
    let version = folded.version().map(str::to_owned);
    let agreeing = others().filter(|older| {
        same_service(newest, older)
            && older
                .version()
                .is_none_or(|stated| version.as_deref() == Some(stated))
    });
    for cpe in newest.cpes().iter().chain(agreeing.flat_map(Service::cpes)) {
        folded.add_cpe(Arc::clone(cpe));
    }

    Some(folded)
}

/// Whether two accounts name the same service, so that the older one's detail
/// belongs on the newer one's finding.
///
/// By name and product; the version is what is being decided.
fn same_service(newest: &Service, older: &Service) -> bool {
    newest.name() == older.name() && newest.product() == older.product()
}

/// The operating system, from every account of one host.
///
/// Like [`fold_service`]: the verdict (name, family, generation, vendor, accuracy) comes
/// from the newest account that named a system, and an older account naming the same
/// system fills kernel, architecture, device class, detail accuracy and evidence. Every
/// account contributes CPEs, since nothing correlates on an operating system's.
///
/// Identity is name, family, generation and vendor. [`diff::host`](crate::diff::host)'s
/// `same_system` also compares kernel, architecture and CPEs, since it asks whether
/// anything changed.
fn fold_os(accounts: &[&Host]) -> Option<OsFingerprint> {
    let newest = newest_claim(accounts, |account| account.os())?;

    let mut folded = OsFingerprint::new(newest.name(), newest.accuracy());
    if let Some(family) = newest.family() {
        folded = folded.with_family(family);
    }
    if let Some(generation) = newest.generation() {
        folded = folded.with_generation(generation);
    }
    if let Some(vendor) = newest.vendor() {
        folded = folded.with_vendor(vendor);
    }
    if let Some(kernel) = newest.kernel() {
        folded = folded.with_kernel(kernel);
    }
    if let Some(arch) = newest.arch() {
        folded = folded.with_arch(arch);
    }
    if let Some(device) = newest.device() {
        folded = folded.with_device(device);
    }
    if let Some(accuracy) = newest.detail_accuracy() {
        folded = folded.with_detail_accuracy(accuracy);
    }
    if let Some(evidence) = newest.evidence() {
        folded = folded.with_evidence(evidence);
    }

    for older in accounts
        .iter()
        .rev()
        .filter_map(|account| account.os())
        .skip(1)
        .filter(|older| names_the_same_system(newest, older))
    {
        if folded.kernel().is_none()
            && let Some(kernel) = older.kernel()
        {
            folded = folded.with_kernel(kernel);
        }
        if folded.arch().is_none()
            && let Some(arch) = older.arch()
        {
            folded = folded.with_arch(arch);
        }
        if folded.device().is_none()
            && let Some(device) = older.device()
        {
            folded = folded.with_device(device);
        }
        if folded.detail_accuracy().is_none()
            && let Some(accuracy) = older.detail_accuracy()
        {
            folded = folded.with_detail_accuracy(accuracy);
        }
        if folded.evidence().is_none()
            && let Some(evidence) = older.evidence()
        {
            folded = folded.with_evidence(evidence);
        }
    }

    for cpe in accounts
        .iter()
        .filter_map(|account| account.os())
        .flat_map(OsFingerprint::cpes)
    {
        folded.add_cpe(Arc::clone(cpe));
    }

    Some(folded)
}

/// Whether two readings name the same system, by the fields that identify one.
fn names_the_same_system(newest: &OsFingerprint, older: &OsFingerprint) -> bool {
    newest.name() == older.name()
        && newest.family() == older.family()
        && newest.generation() == older.generation()
        && newest.vendor() == older.vendor()
}

/// The newest account of an endpoint that states something.
fn newest_claim_port<'a, T>(
    accounts: &[&'a Port],
    claim: impl Fn(&'a Port) -> Option<T>,
) -> Option<T> {
    accounts.iter().rev().find_map(|account| claim(account))
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
    use crate::system::privilege::Privilege;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, SystemTime};

    use crate::config::ZondConfig;
    use crate::diff::ScanDiff;
    use crate::model::exclusion::Exclusions;
    use crate::model::host::path::Hop;
    use crate::model::host::{OsEvidence, OsSource};
    use crate::model::ip::scoped::Zone;
    use crate::model::ip::set::IpSet;
    use crate::model::port::discovery::{Discovery, ScanResponse};
    use crate::model::tls::{
        CipherSuite, Interruption, TlsSupport, TlsVersion, UnfinishedVersion, VersionSupport,
    };
    use crate::report::{PhaseParts, ScanKind, ScanSettings, TargetScope};

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);
    const TCP: Protocol = Protocol::Tcp;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn day(n: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + DAY * n as u32
    }

    /// A host that answered, at `192.0.2.<last>`.
    fn host(last: u8) -> Host {
        let mut host = Host::new(ip(last));
        host.set_status(HostStatus::Up);
        host
    }

    /// A report of one phase that ran on `at`, attributed to `engine`.
    fn report(engine: &str, at: SystemTime, hosts: Vec<Host>) -> ScanReport {
        let phase = ScanPhase::from_parts(PhaseParts {
            open: false,
            attachments: Vec::new(),
            kind: ScanKind::PortScan,
            started_at: at,
            elapsed: Duration::from_secs(60),
            privilege: Some(Privilege::Raw),
            targets: TargetScope::from_ip_set(&mut IpSet::new(), &Exclusions::none()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            refusals: Vec::new(),
            unroutable: Vec::new(),
            refused_by_route: Vec::new(),
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided: Vec::new(),
            liveness_skipped: None,
            silent: Vec::new(),
            stopped: None,
            passes_cut: Vec::new(),
            unreached: 0,
            unheard_probes: 0,
            probes: Vec::new(),
            origin: None,
        });

        ScanReport::recorded(engine, vec![phase], hosts)
    }

    /// A folded report can be told from a measured one. Its `elapsed` sums every
    /// source's working time and is not a duration anything took.
    #[test]
    fn a_folded_report_says_it_was_folded_and_a_measured_one_does_not() {
        let one = report("0.13.0", day(1), vec![host(1)]);
        let two = report("0.13.0", day(2), vec![host(2)]);

        assert!(!one.is_merged(), "a report of one scan was not folded");

        let folded = merged(vec![one, two]);
        assert!(folded.is_merged());

        // Two minutes of scanning a day apart: a span of a day and two minutes.
        assert_eq!(folded.elapsed(), Duration::from_secs(120));
        assert_eq!(
            folded
                .finished_at()
                .duration_since(folded.started_at())
                .expect("a report ends after it begins"),
            DAY + Duration::from_secs(60)
        );
    }

    /// A name is the newest account's in each protocol: a rename replaces the old
    /// name, and a newer scan that asked no directory leaves the older LDAP names.
    #[test]
    fn a_name_is_the_newest_account_s_in_each_protocol() {
        use crate::model::host::{HostName, NameKind, NameSource};

        let name = |source, text| HostName::new(NameKind::Host, source, text).expect("a name");
        let mut old = host(1);
        old.record_name(name(NameSource::Ntlm, "old.corp.example"));
        old.record_name(name(NameSource::Ldap, "dc.corp.example"));
        let mut new = host(1);
        new.record_name(name(NameSource::Ntlm, "new.corp.example"));

        let folded = merged(vec![
            report("0.18.0", day(1), vec![old]),
            report("0.18.0", day(2), vec![new]),
        ]);
        let names: Vec<&str> = folded
            .hosts()
            .next()
            .expect("the host")
            .names()
            .map(HostName::name)
            .collect();
        assert_eq!(names, ["new.corp.example", "dc.corp.example"]);
    }

    /// Folding a merged report keeps the origins its sources were given.
    #[test]
    fn folding_a_folded_report_leaves_it_folded() {
        let once = merged(vec![
            report("0.13.0", day(1), vec![host(1)]),
            report("0.13.0", day(2), vec![host(2)]),
        ]);

        let twice = merged(vec![once, report("0.13.0", day(3), vec![host(3)])]);
        assert!(twice.is_merged());
    }

    /// Folds `sources` under the defaults, oldest first however they are given.
    fn merged(sources: Vec<ScanReport>) -> ScanReport {
        let mut merge = Merge::new(MergeOptions::default());
        for source in sources {
            merge.add(source);
        }
        merge.finish()
    }

    /// What the merged report says one endpoint's state is.
    fn state_of(report: &ScanReport, last: u8, number: u16) -> Option<PortState> {
        report
            .hosts()
            .find(|host| host.ips().contains(&ip(last)))?
            .ports()
            .find(|port| port.number() == number)
            .map(Port::state)
    }

    /// What the merged report says settled one endpoint's state.
    fn discovery_on(report: &ScanReport, last: u8, number: u16) -> Option<Discovery> {
        report
            .hosts()
            .find(|host| host.ips().contains(&ip(last)))?
            .ports()
            .find(|port| port.number() == number)?
            .discovery()
            .cloned()
    }

    /// What the merged report says is listening on one endpoint.
    fn service_on(report: &ScanReport, last: u8, number: u16) -> Option<Service> {
        report
            .hosts()
            .find(|host| host.ips().contains(&ip(last)))?
            .ports()
            .find(|port| port.number() == number)?
            .service()
            .cloned()
    }

    /// A finding, so that a fold asserted through [`ScanDiff`] has one to lose.
    fn finding(id: &str, title: &str) -> crate::model::finding::Finding {
        use crate::model::confidence::Confidence;
        use crate::model::finding::{DetectionClass, DetectionId, Finding, Severity, Version};

        Finding::new(
            DetectionId::new(id, Version::new(1, 0, 0), "hash").expect("a valid detection id"),
            title,
            Severity::Medium,
            Confidence::Certain,
            DetectionClass::Passive,
        )
        .expect("a titled finding")
    }

    fn with_port(mut host: Host, port: Port) -> Host {
        host.add_port(port);
        host
    }

    // -----------------------------------------------------------------------
    // The rule
    // -----------------------------------------------------------------------

    /// A newer `Closed` replaces an older `Open`. `Port::merge` takes the maximum,
    /// which across scans would never let a port close.
    #[test]
    fn a_port_that_closed_since_the_older_scan_reads_as_closed() {
        let january = with_port(host(1), Port::new(3389, Protocol::Tcp, PortState::Open));
        let august = with_port(host(1), Port::new(3389, Protocol::Tcp, PortState::Closed));

        let merged = merged(vec![
            report("older", day(0), vec![january]),
            report("newer", day(200), vec![august]),
        ]);

        assert_eq!(
            state_of(&merged, 1, 3389),
            Some(PortState::Closed),
            "the newest source that probed it said closed"
        );
    }

    /// An endpoint missing from a later document keeps its verdict. Unprivileged
    /// scans file no closed ports and nmap summarises them in `<extraports>`, so
    /// absence is routine.
    #[test]
    fn an_endpoint_a_later_scan_never_recorded_keeps_its_verdict() {
        let january = with_port(host(1), Port::new(22, TCP, PortState::Open));
        let august = host(1);

        let merged = merged(vec![
            report("older", day(0), vec![january]),
            report("newer", day(200), vec![august]),
        ]);

        assert_eq!(
            state_of(&merged, 1, 22),
            Some(PortState::Open),
            "silence about an endpoint is not a verdict about it"
        );
    }

    /// A newer `HostStatus::Unknown` does not override an older verdict, or a host
    /// would vanish the first time one sweep missed it.
    #[test]
    fn silence_in_a_later_scan_does_not_unseat_a_host_that_answered() {
        let january = host(1);
        let august = Host::new(ip(1));
        assert_eq!(august.status(), HostStatus::Unknown, "the premise");

        let merged = merged(vec![
            report("older", day(0), vec![january]),
            report("newer", day(200), vec![august]),
        ]);

        assert_eq!(
            merged.hosts().next().map(Host::status),
            Some(HostStatus::Up)
        );
    }

    /// A newer `Down` or `Blocked` does override an older `Up`; each is backed by a
    /// packet.
    ///
    /// The fold calls [`Host::set_status`], which only promotes, on a host still
    /// `Unknown`, so it acts as a replacement.
    #[test]
    fn a_newer_unreachable_verdict_unseats_an_older_answer() {
        let january = host(1);
        let mut august = Host::new(ip(1));
        august.set_status(HostStatus::Down);

        let merged = merged(vec![
            report("older", day(0), vec![january]),
            report("newer", day(200), vec![august]),
        ]);

        assert_eq!(
            merged.hosts().next().map(Host::status),
            Some(HostStatus::Down),
            "an intermediary's unreachable is a later word than an answer"
        );
    }

    /// The discovery comes from the newest account that reached the same verdict,
    /// since nmap's XML records no packet behind a port state.
    #[test]
    fn an_older_probe_of_the_state_that_won_still_explains_it() {
        let probed = with_port(
            host(1),
            Port::new(443, TCP, PortState::Open)
                .with_discovery(Discovery::new(ScanResponse::TcpSynAck)),
        );
        let imported = with_port(host(1), Port::new(443, TCP, PortState::Open));

        let merged = merged(vec![
            report("zond", day(0), vec![probed]),
            report("nmap 7.94", day(200), vec![imported]),
        ]);

        assert_eq!(
            discovery_on(&merged, 1, 443).map(|found| found.reason().clone()),
            Some(ScanResponse::TcpSynAck),
            "the packet that settled the verdict being reported"
        );
    }

    /// A packet that settled a different state is not kept: last quarter's SYN/ACK
    /// does not explain tonight's `Closed`.
    #[test]
    fn evidence_never_comes_from_an_account_that_reached_another_verdict() {
        let january = with_port(
            host(1),
            Port::new(443, TCP, PortState::Open)
                .with_discovery(Discovery::new(ScanResponse::TcpSynAck)),
        );
        let august = with_port(host(1), Port::new(443, TCP, PortState::Closed));

        let merged = merged(vec![
            report("older", day(0), vec![january]),
            report("newer", day(200), vec![august]),
        ]);

        assert_eq!(
            state_of(&merged, 1, 443),
            Some(PortState::Closed),
            "the premise"
        );
        assert_eq!(
            discovery_on(&merged, 1, 443),
            None,
            "a packet explaining an open port is not evidence the port is closed"
        );
    }

    /// The capped evidence map keeps a host's newest readings when a dozen scans
    /// each read a different kernel release.
    #[test]
    fn the_newest_readings_are_the_ones_the_evidence_cap_keeps() {
        fn read(release: &str) -> OsEvidence {
            OsEvidence {
                source: OsSource::TcpStack,
                family: Some("Linux".to_owned()),
                device: None,
                vendor: None,
                product: None,
                version: Some(release.to_owned()),
                kernel: None,
                arch: None,
                cpe: None,
                confidence: 0.8,
                evidence: format!("a stack reading of {release}"),
            }
        }

        // Well past the cap.
        let nightly: Vec<ScanReport> = (0..12)
            .map(|night| {
                let mut host = host(1);
                host.record_os_evidence(read(&format!("6.1.{night}")));
                report("nightly", day(night), vec![host])
            })
            .collect();

        let merged = merged(nightly);
        let kept: Vec<&str> = merged
            .hosts()
            .next()
            .expect("a host")
            .os_evidence()
            .filter_map(|reading| reading.version.as_deref())
            .collect();

        assert!(
            kept.contains(&"6.1.11"),
            "the newest reading of the host, and the one a report is about: {kept:?}"
        );
        assert!(
            !kept.contains(&"6.1.0"),
            "and not the first reading of a year ago: {kept:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Identity blocks
    // -----------------------------------------------------------------------

    /// An older `Apache httpd 2.4.1` and a newer `nginx` do not splice into
    /// `nginx 2.4.1`.
    #[test]
    fn a_service_that_changed_product_does_not_inherit_the_old_version() {
        let older = with_port(
            host(1),
            Port::new(80, TCP, PortState::Open).with_service(
                Service::new("http", 90)
                    .with_product("Apache httpd")
                    .with_version("2.4.1"),
            ),
        );
        let newer = with_port(
            host(1),
            Port::new(80, TCP, PortState::Open)
                .with_service(Service::new("http", 90).with_product("nginx")),
        );

        let merged = merged(vec![
            report("older", day(0), vec![older]),
            report("newer", day(200), vec![newer]),
        ]);

        let service = service_on(&merged, 1, 80).expect("a service");
        assert_eq!(service.product(), Some("nginx"));
        assert_eq!(
            service.version(),
            None,
            "a version belongs to the product it was read from"
        );
    }

    /// An older reading of the same service fills in what the newer one lacks.
    #[test]
    fn an_older_reading_of_the_same_service_supplies_the_version_the_newer_one_missed() {
        let older = with_port(
            host(1),
            Port::new(80, TCP, PortState::Open).with_service(
                Service::new("http", 90)
                    .with_product("Apache httpd")
                    .with_version("2.4.1"),
            ),
        );
        let newer = with_port(
            host(1),
            Port::new(80, TCP, PortState::Open)
                .with_service(Service::new("http", 90).with_product("Apache httpd")),
        );

        let merged = merged(vec![
            report("older", day(0), vec![older]),
            report("newer", day(200), vec![newer]),
        ]);

        assert_eq!(
            service_on(&merged, 1, 80).and_then(|s| s.version().map(str::to_owned)),
            Some("2.4.1".to_owned()),
            "the same product, so the older detail is more of one finding"
        );
    }

    /// The CPEs host 1's port 80 carries in `report`, ascending.
    fn cpes_on(report: &ScanReport) -> Vec<String> {
        service_on(report, 1, 80)
            .map(|service| service.cpes().iter().map(|cpe| cpe.to_string()).collect())
            .unwrap_or_default()
    }

    /// A CPE read off a replaced identification goes with it, so Apache's is not
    /// correlated beside `nginx`.
    #[test]
    fn a_cpe_goes_with_the_identification_it_was_read_from() {
        let older = with_port(
            host(1),
            Port::new(80, TCP, PortState::Open).with_service(
                Service::new("http", 90)
                    .with_product("Apache httpd")
                    .with_cpe("cpe:/a:apache:http_server"),
            ),
        );
        let newer = with_port(
            host(1),
            Port::new(80, TCP, PortState::Open).with_service(
                Service::new("http", 90)
                    .with_product("nginx")
                    .with_cpe("cpe:/a:nginx:nginx"),
            ),
        );

        let merged = merged(vec![
            report("older", day(0), vec![older]),
            report("newer", day(200), vec![newer]),
        ]);

        assert_eq!(cpes_on(&merged), ["cpe:/a:nginx:nginx"]);
    }

    /// An older reading of the same service with no other version keeps its CPEs,
    /// as does one whose version the fold took.
    #[test]
    fn an_older_identifier_of_the_same_service_at_no_other_version_stands() {
        let apache = |version: Option<&str>, cpe: Option<&str>| {
            let mut service = Service::new("http", 90).with_product("Apache httpd");
            if let Some(version) = version {
                service = service.with_version(version);
            }
            if let Some(cpe) = cpe {
                service = service.with_cpe(cpe);
            }
            with_port(
                host(1),
                Port::new(80, TCP, PortState::Open).with_service(service),
            )
        };

        let versionless_then = merged(vec![
            report(
                "older",
                day(0),
                vec![apache(None, Some("cpe:/a:apache:http_server"))],
            ),
            report(
                "newer",
                day(200),
                vec![apache(
                    Some("2.4.58"),
                    Some("cpe:/a:apache:http_server:2.4.58"),
                )],
            ),
        ]);
        assert_eq!(
            cpes_on(&versionless_then),
            [
                "cpe:/a:apache:http_server",
                "cpe:/a:apache:http_server:2.4.58"
            ]
        );

        let versionless_now = merged(vec![
            report(
                "older",
                day(0),
                vec![apache(
                    Some("2.4.1"),
                    Some("cpe:/a:apache:http_server:2.4.1"),
                )],
            ),
            report("newer", day(200), vec![apache(None, None)]),
        ]);
        assert_eq!(
            service_on(&versionless_now, 1, 80).and_then(|s| s.version().map(str::to_owned)),
            Some("2.4.1".to_owned())
        );
        assert_eq!(
            cpes_on(&versionless_now),
            ["cpe:/a:apache:http_server:2.4.1"],
            "the version the fold reports brings the identifier read with it"
        );
    }

    // -----------------------------------------------------------------------
    // Identity, and the fold's own properties
    // -----------------------------------------------------------------------

    /// Two scanners that key one dual-stack machine under different addresses
    /// produce one host.
    #[test]
    fn two_documents_keying_one_machine_differently_fold_to_one_host() {
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        let mut keyed_v4 = host(5);
        keyed_v4.add_ip(v6);

        let mut keyed_v6 = Host::new(v6);
        keyed_v6.set_status(HostStatus::Up);

        let merged = merged(vec![
            report("nmap 7.94", day(0), vec![keyed_v4]),
            report("zond", day(1), vec![keyed_v6]),
        ]);

        assert_eq!(merged.host_count(), 1, "one machine, two documents");
        assert_eq!(
            merged.hosts().next().expect("a host").ips().len(),
            2,
            "and it holds both addresses"
        );
    }

    /// Merging one report, or a report with itself, gives back what went in.
    /// Asserted through the differ, which compares every finding.
    #[test]
    fn folding_a_report_leaves_its_findings_alone() {
        let mut port = Port::new(443, TCP, PortState::Open).with_service(
            Service::new("https", 90)
                .with_product("nginx")
                .with_version("1.24.0"),
        );
        port.add_finding(finding("tls-weak-cipher", "a weak cipher is offered"));

        let mut carrier = host(1);
        carrier.add_finding(finding("ssh-old", "an outdated SSH server"));

        let source = report("test", day(0), vec![with_port(carrier, port)]);

        let once = merged(vec![source.clone()]);
        assert!(
            ScanDiff::between(&source, &once).is_empty(),
            "a merge of one source is that source"
        );

        let twice = merged(vec![source.clone(), source.clone()]);
        assert!(
            ScanDiff::between(&source, &twice).is_empty(),
            "and folding it into itself adds nothing"
        );
    }

    /// Different findings about one host are both kept; the same claim is kept
    /// once, graded as the later scan graded it ([`Host::add_finding`]'s rule).
    #[test]
    fn two_accounts_of_one_host_keep_every_claim_and_grade_it_as_the_newer_did() {
        use crate::model::confidence::Confidence;
        use crate::model::finding::{DetectionClass, DetectionId, Finding, Severity, Version};

        let graded = |severity| {
            Finding::new(
                DetectionId::new("tls-weak-cipher", Version::new(1, 0, 0), "hash")
                    .expect("a valid detection id"),
                "a weak cipher is offered",
                severity,
                Confidence::Certain,
                DetectionClass::Passive,
            )
            .expect("a titled finding")
        };

        let mut january = host(1);
        january.add_finding(graded(Severity::Low));
        january.add_finding(finding("ssh-old", "an outdated SSH server"));

        let mut june = host(1);
        june.add_finding(graded(Severity::Critical));

        let folded = merged(vec![
            report("older", day(0), vec![january]),
            report("newer", day(30), vec![june]),
        ]);

        let host = folded.hosts().next().expect("the one host");
        let findings: Vec<_> = host.findings().collect();

        assert_eq!(
            findings.len(),
            2,
            "the claim only the older scan made is still a claim"
        );

        let cipher = findings
            .iter()
            .find(|finding| finding.detection().id() == "tls-weak-cipher")
            .expect("the claim both scans made");
        assert_eq!(
            cipher.severity(),
            Severity::Critical,
            "the later scan graded it, so the later grade stands"
        );
    }

    /// The order sources are added in does not matter; their clocks decide.
    #[test]
    fn the_order_sources_are_added_in_does_not_decide_the_outcome() {
        let january = report(
            "older",
            day(0),
            vec![with_port(host(1), Port::new(3389, TCP, PortState::Open))],
        );
        let august = report(
            "newer",
            day(200),
            vec![with_port(host(1), Port::new(3389, TCP, PortState::Closed))],
        );

        let forwards = merged(vec![january.clone(), august.clone()]);
        let backwards = merged(vec![august, january]);

        assert_eq!(state_of(&forwards, 1, 3389), Some(PortState::Closed));
        assert_eq!(state_of(&backwards, 1, 3389), Some(PortState::Closed));
    }

    /// `fe80::1` on two interfaces is two hosts, as
    /// [`pairing`](crate::diff::pairing) scopes link-local tokens by interface.
    #[test]
    fn two_link_locals_on_different_segments_stay_two_hosts() {
        let shared = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));

        let mut near = Host::new(shared);
        near.set_status(HostStatus::Up);
        near.set_zone(Zone::new(1, "en0"));

        let mut far = Host::new(shared);
        far.set_status(HostStatus::Up);
        far.set_zone(Zone::new(2, "en1"));

        let merged = merged(vec![
            report("en0", day(0), vec![near]),
            report("en1", day(1), vec![far]),
        ]);

        assert_eq!(merged.host_count(), 2, "two segments, two machines");
        let zones: Vec<&str> = merged
            .hosts()
            .filter_map(|host| host.zone().map(Zone::name))
            .collect();
        assert_eq!(zones, ["en0", "en1"], "and each says which link it is on");
    }

    /// Merging is not associative: `merge(merge(a, c), b)` folds `b` against
    /// `c`'s clock, so `a`'s verdict survives although `b` overturned it.
    #[test]
    fn folding_in_rounds_is_not_folding_at_once() {
        let january = report(
            "january",
            day(0),
            vec![with_port(host(1), Port::new(3389, TCP, PortState::Open))],
        );
        let march = report(
            "march",
            day(60),
            vec![with_port(host(1), Port::new(3389, TCP, PortState::Closed))],
        );
        // Silent about the endpoint, which leaves March's verdict standing.
        let august = report("august", day(200), vec![host(1)]);

        let at_once = merged(vec![january.clone(), march.clone(), august.clone()]);
        assert_eq!(
            state_of(&at_once, 1, 3389),
            Some(PortState::Closed),
            "the newest source that probed the endpoint said closed"
        );

        let mut round = Merge::new(MergeOptions::default());
        round.add(january).add(august);
        let in_rounds = merged(vec![round.finish(), march]);

        assert_eq!(
            state_of(&in_rounds, 1, 3389),
            Some(PortState::Open),
            "January's verdict, carried into a document March cannot outrank"
        );
    }

    /// An outer merge keeps the labels of an inner one's sources.
    #[test]
    fn merging_a_merge_keeps_the_labels_its_own_sources_were_given() {
        let mut inner = Merge::new(MergeOptions::default());
        inner.add_from("q1.xml", report("nmap 7.94", day(0), vec![host(1)]));
        inner.add_from("q2.xml", report("nmap 7.94", day(90), vec![host(2)]));

        let mut outer = Merge::new(MergeOptions::default());
        outer.add_from("combined.json", inner.finish());
        outer.add_from("q3.xml", report("nmap 7.95", day(180), vec![host(3)]));

        let merged = outer.finish();
        let labels: Vec<&str> = merged
            .phases()
            .iter()
            .filter_map(|phase| phase.origin().and_then(PhaseOrigin::label))
            .collect();

        assert_eq!(labels, ["q1.xml", "q2.xml", "q3.xml"]);
    }

    /// What a source's phase never decided stays with that phase, so a later
    /// comparison does not read undecided hosts as gone.
    #[test]
    fn a_merged_report_keeps_what_each_phase_left_undecided() {
        let source = crate::export::fixture::report();
        let expected: Vec<Vec<crate::model::ip::range::IpRange>> = source
            .phases()
            .iter()
            .map(|phase| phase.undecided().to_vec())
            .collect();
        assert!(
            expected.iter().any(|undecided| !undecided.is_empty()),
            "the fixture leaves something undecided, or this proves nothing"
        );

        let merged = merged(vec![source]);
        let kept: Vec<Vec<crate::model::ip::range::IpRange>> = merged
            .phases()
            .iter()
            .map(|phase| phase.undecided().to_vec())
            .collect();
        assert_eq!(kept, expected);
    }

    // -----------------------------------------------------------------------
    // What a merged report is judged against
    // -----------------------------------------------------------------------

    /// A merged report is dated by when it last looked, so a comparison judges
    /// tonight's certificates against tonight.
    #[test]
    fn a_merged_report_is_placed_by_when_it_last_looked() {
        let merged = merged(vec![
            report("older", day(0), vec![host(1)]),
            report("newer", day(200), vec![host(2)]),
        ]);

        let last_looked = day(200) + Duration::from_secs(60);
        assert_eq!(merged.finished_at(), last_looked);

        let diff = ScanDiff::between(&report("baseline", day(0), vec![host(1)]), &merged);
        assert_eq!(
            diff.current().at(),
            last_looked,
            "and that is the clock the comparison judges it at"
        );
    }

    /// A source that spans time places each host at its own `last_seen`, so a
    /// baseline stopped in August does not outrank last month's scan about a host
    /// it last heard from in January. See [`observed_at`].
    #[test]
    fn a_record_is_placed_by_when_it_was_seen_not_by_when_its_document_stopped() {
        // A baseline that stopped looking in August, holding a host it last
        // heard from in January.
        let mut stale = with_port(host(1), Port::new(3389, TCP, PortState::Open));
        stale.restore_seen(day(0), day(0));
        let baseline = report("baseline", day(200), vec![stale]);

        let march = report(
            "march",
            day(60),
            vec![with_port(host(1), Port::new(3389, TCP, PortState::Closed))],
        );

        let merged = merged(vec![baseline, march]);

        assert_eq!(
            state_of(&merged, 1, 3389),
            Some(PortState::Closed),
            "March saw the endpoint after January did, whatever their documents say"
        );
    }

    /// Filtering conclusions survive a fold; only the scan that ran the
    /// comparative probe has one.
    #[test]
    fn a_conclusion_about_the_filter_in_front_of_a_host_survives_a_fold() {
        use crate::model::host::Filtering;

        let mut characterised = host(1);
        characterised.add_filtering(Filtering::StatefulFilter);
        characterised.add_filtering(Filtering::StatelessFilter);

        let folded = merged(vec![
            report("a", day(1), vec![characterised]),
            report("b", day(2), vec![host(1)]),
        ]);

        let host = folded.hosts().next().expect("one host");
        assert!(host.filtering().contains(&Filtering::StatefulFilter));
        assert!(host.filtering().contains(&Filtering::StatelessFilter));
    }

    /// A record stamped later than its document is placed at the document's
    /// clock, so an undated archive read tonight does not outrank tonight's scan.
    #[test]
    fn a_record_stamped_later_than_its_document_is_placed_by_the_document() {
        let mut archived = with_port(host(1), Port::new(3389, TCP, PortState::Open));
        archived.restore_seen(day(300), day(300));
        let january = report("archive.xml", day(0), vec![archived]);

        let mut probed = with_port(host(1), Port::new(3389, TCP, PortState::Closed));
        probed.restore_seen(day(200), day(200));
        let august = report("august", day(200), vec![probed]);

        let merged = merged(vec![january, august]);

        assert_eq!(
            state_of(&merged, 1, 3389),
            Some(PortState::Closed),
            "an archive is as old as it says it is, not as old as its records were stamped"
        );
    }

    /// A route is taken whole from one account, not folded hop by hop.
    #[test]
    fn two_measured_routes_do_not_splice_into_one_that_was_never_travelled() {
        let mut january = host(1);
        january.record_hop(Hop::answered(1, ip(200), None));
        january.record_hop(Hop::answered(2, ip(201), None));

        let mut august = host(1);
        august.record_hop(Hop::answered(1, ip(210), None));

        let merged = merged(vec![
            report("older", day(0), vec![january]),
            report("newer", day(200), vec![august]),
        ]);

        let path = merged.hosts().next().expect("a host").path().clone();
        assert_eq!(path.at(1), Some(ip(210)), "the route measured last");
        assert_ne!(
            path.at(2),
            Some(ip(201)),
            "and not a second hop from a different route"
        );
    }

    /// A newer `Unasked` does not erase an older verdict. `Unasked` is written
    /// when a scan ran out of time or could not send, and establishes nothing.
    #[test]
    fn a_later_scan_that_never_asked_does_not_erase_what_an_earlier_one_found() {
        for found in [PortState::Open, PortState::Closed, PortState::NoReply] {
            let wide = with_port(host(1), Port::new(3389, Protocol::Tcp, found));
            let narrow = with_port(host(1), Port::new(3389, Protocol::Tcp, PortState::Unasked));

            let mut merge = Merge::new(MergeOptions::default());
            merge.add(report("wide", day(1), vec![wide]));
            merge.add(report("narrow", day(2), vec![narrow]));

            let merged = merge.finish();
            let state = merged
                .hosts()
                .next()
                .and_then(|host| host.ports().find(|port| port.number() == 3389))
                .map(|port| port.state());

            assert_eq!(
                state,
                Some(found),
                "a scan that ran out of budget erased a {found:?} port"
            );
        }
    }

    /// A newer real verdict still wins in both directions, unlike `Port::merge`,
    /// which promotes.
    #[test]
    fn a_later_scan_that_did_ask_still_overrides() {
        let january = with_port(host(1), Port::new(3389, Protocol::Tcp, PortState::Open));
        let august = with_port(host(1), Port::new(3389, Protocol::Tcp, PortState::Closed));

        let mut merge = Merge::new(MergeOptions::default());
        merge.add(report("january", day(1), vec![january]));
        merge.add(report("august", day(2), vec![august]));

        assert_eq!(
            merge
                .finish()
                .hosts()
                .next()
                .and_then(|host| host.ports().find(|port| port.number() == 3389))
                .map(|port| port.state()),
            Some(PortState::Closed),
            "a later scan that looked is allowed to close a port"
        );
    }

    // -----------------------------------------------------------------------
    // What an endpoint accepts
    // -----------------------------------------------------------------------

    fn suite(code: u16) -> CipherSuite {
        CipherSuite::from_code(code).expect("a suite in the registry")
    }

    /// Host 1, with 443 carrying `support`.
    fn enumerated(support: TlsSupport) -> Host {
        with_port(
            host(1),
            Port::new(443, TCP, PortState::Open)
                .with_security(Security::new().with_support(support)),
        )
    }

    /// What the merged report says host 1's 443 accepts.
    fn support_on(report: &ScanReport) -> TlsSupport {
        report
            .hosts()
            .next()
            .and_then(|host| host.ports().find(|port| port.number() == 443))
            .and_then(Port::security)
            .map(|security| security.support().clone())
            .expect("443 carries an enumeration")
    }

    /// A walk cut short is a floor: the newer scan stopped part way through
    /// TLS 1.2, so the older tail stands there. It finished TLS 1.3, which takes
    /// its answer.
    #[test]
    fn a_cut_short_walk_does_not_replace_a_complete_one() {
        use TlsVersion::{Tls12, Tls13};

        let complete = TlsSupport::new()
            .accepting(VersionSupport::new(
                Tls12,
                vec![suite(0xC030), suite(0xC02F), suite(0x000A)],
                vec![],
            ))
            .accepting(VersionSupport::new(Tls13, vec![suite(0x1302)], vec![]));
        let cut_short = TlsSupport::new()
            .accepting(VersionSupport::new(Tls12, vec![suite(0xC030)], vec![]))
            .leaving_unfinished(UnfinishedVersion::new(Tls12, Interruption::Stopped))
            .accepting(VersionSupport::new(Tls13, vec![suite(0x1301)], vec![]));

        let merged = merged(vec![
            report("older", day(1), vec![enumerated(complete.clone())]),
            report("newer", day(2), vec![enumerated(cut_short)]),
        ]);

        let support = support_on(&merged);
        assert_eq!(
            support.versions()[0],
            complete.versions()[0],
            "the older walk of TLS 1.2 finished, and the newer found nothing it lacks"
        );
        assert!(support.is_complete(), "and so it is the whole answer there");
        assert_eq!(
            support.versions()[1].suites(),
            &[suite(0x1301)],
            "the newer walk of TLS 1.3 finished, and a finished walk is the newer answer"
        );
    }

    /// A finished walk retires every older answer. January accepted two suites,
    /// February finished finding one, March was cut short finding the other;
    /// January must not return.
    #[test]
    fn a_finished_walk_retires_every_older_answer() {
        use TlsVersion::Tls12;

        let finished = |suites: Vec<CipherSuite>| {
            TlsSupport::new().accepting(VersionSupport::new(Tls12, suites, vec![]))
        };
        let january = finished(vec![suite(0xC030), suite(0xC02F)]);
        let february = finished(vec![suite(0xC02F)]);
        let march = TlsSupport::new()
            .accepting(VersionSupport::new(Tls12, vec![suite(0xC030)], vec![]))
            .leaving_unfinished(UnfinishedVersion::new(Tls12, Interruption::Unanswered));

        let merged = merged(vec![
            report("january", day(1), vec![enumerated(january)]),
            report("february", day(2), vec![enumerated(february)]),
            report("march", day(3), vec![enumerated(march.clone())]),
        ]);

        assert_eq!(support_on(&merged), march);
    }

    /// Host 1, with 443 carrying `support` and the findings drawn from it.
    fn audited(support: TlsSupport) -> Host {
        let findings = support.findings();
        let mut port = Port::new(443, TCP, PortState::Open)
            .with_security(Security::new().with_support(support));
        for finding in findings {
            port.add_finding(finding);
        }
        with_port(host(1), port)
    }

    /// The titles of the findings host 1's 443 carries in `report`.
    fn findings_on(report: &ScanReport) -> Vec<String> {
        report
            .hosts()
            .next()
            .and_then(|host| host.ports().find(|port| port.number() == 443))
            .map(|port| port.findings().map(|f| f.title().to_owned()).collect())
            .unwrap_or_default()
    }

    /// A finding goes with its evidence: January found TLS 1.0 accepted,
    /// February finished and found it refused, so January's findings are dropped.
    #[test]
    fn a_finding_a_newer_finished_walk_overturned_is_not_carried() {
        use TlsVersion::{Tls10, Tls12};

        let january = TlsSupport::new()
            .accepting(VersionSupport::new(Tls10, vec![suite(0x002F)], vec![]))
            .accepting(VersionSupport::new(Tls12, vec![suite(0xC02F)], vec![]));
        let february =
            TlsSupport::new().accepting(VersionSupport::new(Tls12, vec![suite(0xC02F)], vec![]));

        let merged = merged(vec![
            report("january", day(1), vec![audited(january)]),
            report("february", day(2), vec![audited(february.clone())]),
        ]);

        assert_eq!(support_on(&merged), february, "February's walk stands");
        // Every claim January drew rests on TLS 1.0 alone, and February's
        // strong TLS 1.2 suite draws none of its own.
        let titles = findings_on(&merged);
        assert!(
            titles.is_empty(),
            "the merged port carries findings its own record refutes: {titles:?}"
        );
    }

    /// A claim resting on what lies past where a newer walk stopped stands.
    /// February's TLS 1.0 walk stopped after a suite January does not list, so the
    /// fold takes February's list, but January's static-RSA claim stands.
    #[test]
    fn a_finding_a_newer_walk_never_got_back_to_is_kept() {
        use TlsVersion::Tls10;

        let january =
            TlsSupport::new().accepting(VersionSupport::new(Tls10, vec![suite(0x002F)], vec![]));
        let february = TlsSupport::new()
            .accepting(VersionSupport::new(Tls10, vec![suite(0xC013)], vec![]))
            .leaving_unfinished(UnfinishedVersion::new(Tls10, Interruption::Stopped));

        let merged = merged(vec![
            report("january", day(1), vec![audited(january.clone())]),
            report("february", day(2), vec![audited(february.clone())]),
        ]);
        assert_eq!(support_on(&merged), february, "February's walk stands");

        let static_rsa = january
            .findings()
            .into_iter()
            .map(|finding| finding.title().to_owned())
            .find(|title| title.contains("long-term key"))
            .expect("January draws a claim from the static-RSA suite");
        assert!(
            findings_on(&merged).contains(&static_rsa),
            "a claim the newer walk never got back to was dropped"
        );
    }

    /// Certificate posture claims go when a newer scan sees another certificate
    /// and stay while the same one is presented.
    #[test]
    fn a_posture_finding_goes_with_the_certificate_it_was_drawn_from() {
        use crate::model::port::security::CertificateInfo;

        let presenting = |fingerprint: &str, issuer: &str| {
            let certificate =
                CertificateInfo::new("www.example.test", issuer, day(0), day(365), fingerprint);
            let findings = certificate.findings(day(1));
            let mut port = Port::new(443, TCP, PortState::Open)
                .with_security(Security::new().with_certificate(certificate));
            for finding in findings {
                port.add_finding(finding);
            }
            with_port(host(1), port)
        };
        let self_signed = "TLS certificate is self-signed".to_owned();

        let rotated = merged(vec![
            report(
                "older",
                day(1),
                vec![presenting("aaaa", "www.example.test")],
            ),
            report("newer", day(2), vec![presenting("bbbb", "Example CA")]),
        ]);
        assert!(
            !findings_on(&rotated).contains(&self_signed),
            "a claim about a certificate the endpoint no longer presents"
        );

        let kept = merged(vec![
            report(
                "older",
                day(1),
                vec![presenting("aaaa", "www.example.test")],
            ),
            report(
                "newer",
                day(2),
                vec![presenting("aaaa", "www.example.test")],
            ),
        ]);
        assert!(findings_on(&kept).contains(&self_signed));
    }

    /// The finding host 1's 443 carries under `title` in `report`.
    fn finding_on(report: &ScanReport, title: &str) -> Option<crate::model::finding::Finding> {
        report
            .hosts()
            .next()
            .and_then(|host| host.ports().find(|port| port.number() == 443))
            .and_then(|port| port.findings().find(|f| f.title() == title).cloned())
    }

    /// January accepted an RC4 suite under TLS 1.0 and another under TLS 1.2,
    /// each walk finished.
    fn rc4_under_ten_and_twelve() -> TlsSupport {
        TlsSupport::new()
            .accepting(VersionSupport::new(
                TlsVersion::Tls10,
                vec![suite(0x0005)],
                vec![],
            ))
            .accepting(VersionSupport::new(
                TlsVersion::Tls12,
                vec![suite(0xC011)],
                vec![],
            ))
    }

    const RC4: &str = "cipher suites accepted with RC4, prohibited by RFC 7465";

    /// A kept finding is reworded for the folded record. February refused TLS 1.0
    /// and was cut short in TLS 1.2, so the RC4 claim stands on TLS 1.2 and its
    /// excerpt no longer names the TLS 1.0 suite.
    #[test]
    fn a_carried_fault_names_only_the_suites_the_folded_record_accepts() {
        use TlsVersion::{Tls12, Tls13};

        let february = TlsSupport::new()
            .accepting(VersionSupport::new(Tls13, vec![suite(0x1301)], vec![]))
            .leaving_unfinished(UnfinishedVersion::new(Tls12, Interruption::Unanswered));
        let january = rc4_under_ten_and_twelve();
        assert!(
            finding_on(
                &merged(vec![report(
                    "january",
                    day(1),
                    vec![audited(january.clone())]
                )]),
                RC4
            )
            .is_some_and(|f| f.excerpt().as_str().contains("TLS_RSA_WITH_RC4_128_SHA")),
            "test premise: January's own text names the TLS 1.0 suite"
        );

        let merged = merged(vec![
            report("january", day(1), vec![audited(january)]),
            report("february", day(2), vec![audited(february)]),
        ]);

        let support = support_on(&merged);
        assert!(!support.accepts(TlsVersion::Tls10), "February's TLS 1.0");
        assert!(support.accepts(Tls12), "January's TLS 1.2");

        let carried = finding_on(&merged, RC4).expect("the claim stands on TLS 1.2");
        assert_eq!(
            carried.excerpt().as_str(),
            "1 of the accepted suites carry this: TLS_ECDHE_RSA_WITH_RC4_128_SHA",
            "the text names a suite the merged record does not accept"
        );
    }

    /// The same where the claim stands only because the fold left it unsettled:
    /// the excerpt keeps January's TLS 1.2 suite and drops its refused TLS 1.0 one.
    #[test]
    fn an_unsettled_fault_names_only_the_suites_nothing_newer_refused() {
        use TlsVersion::{Tls12, Tls13};

        let february = TlsSupport::new()
            .accepting(VersionSupport::new(Tls12, vec![suite(0xC02F)], vec![]))
            .leaving_unfinished(UnfinishedVersion::new(Tls12, Interruption::Stopped))
            .accepting(VersionSupport::new(Tls13, vec![suite(0x1301)], vec![]));

        let merged = merged(vec![
            report("january", day(1), vec![audited(rc4_under_ten_and_twelve())]),
            report("february", day(2), vec![audited(february.clone())]),
        ]);

        assert_eq!(support_on(&merged), february, "February's walk stands");
        let carried = finding_on(&merged, RC4).expect("the claim is unsettled, so it stands");
        assert_eq!(
            carried.excerpt().as_str(),
            "1 of the accepted suites carry this: TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        );
    }

    /// Where nothing moved under a claim, the finding is carried as written.
    #[test]
    fn a_fault_whose_evidence_did_not_move_is_carried_as_written() {
        let support = rc4_under_ten_and_twelve();
        let written = support
            .findings()
            .into_iter()
            .find(|finding| finding.title() == RC4)
            .expect("the RC4 claim")
            .with_excerpt(crate::model::finding::Excerpt::new(
                "RC4 is negotiated under TLS 1.0 and TLS 1.2",
            ));
        let mut port = Port::new(443, TCP, PortState::Open)
            .with_security(Security::new().with_support(support));
        port.add_finding(written.clone());
        let account = with_port(host(1), port);

        let merged = merged(vec![
            report("january", day(1), vec![account.clone()]),
            report("february", day(2), vec![account]),
        ]);

        assert_eq!(finding_on(&merged, RC4), Some(written));
    }

    /// Port 80 of host 1 serving Apache httpd `version`, correlated against the
    /// shipped catalogue.
    fn serving_apache(version: &str) -> Host {
        let service = Service::new("http", 90)
            .with_product("Apache httpd")
            .with_version(version)
            .with_cpe(format!("cpe:/a:apache:http_server:{version}"));
        let mut host = with_port(
            host(1),
            Port::new(80, TCP, PortState::Open).with_service(service),
        );
        crate::cve::correlate(&mut host);
        host
    }

    fn claims_on_80(report_or_host: impl IntoIterator<Item = Host>) -> Vec<String> {
        let mut claims: Vec<String> = report_or_host
            .into_iter()
            .flat_map(|host| {
                host.ports()
                    .filter(|port| port.number() == 80)
                    .flat_map(|port| port.findings().map(|f| f.title().to_owned()))
                    .collect::<Vec<_>>()
            })
            .collect();
        claims.sort();
        claims
    }

    /// A correlation goes with its identification: January's 2.4.49
    /// vulnerabilities are dropped once June reads 2.4.58.
    #[test]
    fn a_correlation_an_older_identification_drew_is_not_carried_past_a_newer_one() {
        let january = serving_apache("2.4.49");
        let june = serving_apache("2.4.58");
        assert!(
            claims_on_80([january.clone()])
                .iter()
                .any(|title| title.starts_with("Apache httpd 2.4.49")),
            "test premise: the catalogue draws a finding from 2.4.49: {:?}",
            claims_on_80([january.clone()])
        );

        let merged = merged(vec![
            report("january", day(1), vec![january]),
            report("june", day(150), vec![june.clone()]),
        ]);

        let service = service_on(&merged, 1, 80).expect("a service");
        assert_eq!(service.version(), Some("2.4.58"));
        assert_eq!(
            service
                .cpes()
                .iter()
                .map(|cpe| cpe.to_string())
                .collect::<Vec<_>>(),
            ["cpe:/a:apache:http_server:2.4.58"],
            "the merged service carries the identifier its own version backs"
        );
        assert_eq!(
            claims_on_80(merged.hosts().cloned()),
            claims_on_80([june]),
            "the merged port carries what 2.4.58 draws and nothing 2.4.49 did"
        );
    }

    /// Port 22 of host 1 serving OpenSSH 6.6.1p1 as Ubuntu 14.04 built it at
    /// `revision`, correlated as a scan's correlation step does.
    fn serving_ubuntu_openssh(revision: &str) -> Host {
        use crate::model::port::{Build, Distributor, Release, ReleaseBasis};
        let service = Service::new("ssh", 100)
            .with_product("OpenSSH")
            .with_version("6.6.1p1")
            .with_cpe("cpe:/a:openbsd:openssh:6.6.1p1")
            .with_build(
                Build::new(Distributor::Ubuntu)
                    .with_revision(revision)
                    .with_release(Release::new("14.04", ReleaseBasis::Banner)),
            );
        let mut host = with_port(
            host(1),
            Port::new(22, TCP, PortState::Open).with_service(service),
        );
        crate::cve::correlate(&mut host);
        host
    }

    fn claims_on_22(report_or_host: impl IntoIterator<Item = Host>) -> Vec<String> {
        let mut claims: Vec<String> = report_or_host
            .into_iter()
            .flat_map(|host| {
                host.ports()
                    .filter(|port| port.number() == 22)
                    .flat_map(|port| port.findings().map(|f| f.claim_id().subject().to_owned()))
                    .collect::<Vec<_>>()
            })
            .collect();
        claims.sort();
        claims
    }

    /// A correlator's claims give way to a newer correlator's on the same port,
    /// even when keyed differently (a distribution build summarised as the
    /// upstream release, keyed on its lowest identifier).
    #[test]
    fn an_earlier_correlators_claims_are_retired_by_a_later_ones() {
        use crate::model::finding::{DetectionClass, DetectionId, Finding, Reference, Version};

        let june = serving_ubuntu_openssh("2ubuntu2.13");
        assert!(
            !claims_on_22([june.clone()]).is_empty(),
            "test premise: the catalogue draws a claim on the build"
        );

        let mut january = june.clone();
        let earlier = Finding::new(
            DetectionId::new("zond:cve-kev", Version::new(0, 2, 0), "earlier").expect("an id"),
            "openssh 6.6.1p1 has 44 known vulnerabilities",
            crate::model::finding::Severity::Critical,
            crate::model::confidence::Confidence::Probable,
            DetectionClass::Passive,
        )
        .expect("a finding")
        .with_cpe("cpe:/a:openbsd:openssh:6.6.1p1")
        .with_reference(Reference::cve("CVE-2016-1908").expect("an id"));
        let mut port = january
            .ports()
            .find(|p| p.number() == 22)
            .expect("the port")
            .clone();
        port.add_finding(earlier);
        january.add_port(port);
        assert!(
            claims_on_22([january.clone()]).contains(&"CVE-2016-1908".to_string()),
            "test premise: January carries the earlier correlator's claim"
        );

        let merged = merged(vec![
            report("january", day(1), vec![january]),
            report("june", day(150), vec![june.clone()]),
        ]);
        assert_eq!(claims_on_22(merged.hosts().cloned()), claims_on_22([june]));
    }

    /// A claim judged against an old build does not survive a newer one: OpenSSH
    /// 6.6.1p1 at Ubuntu `2ubuntu2.7`, then at `2ubuntu2.13`.
    #[test]
    fn a_claim_judged_against_an_older_build_is_not_carried_past_an_upgrade() {
        let january = serving_ubuntu_openssh("2ubuntu2.7");
        // The upgraded build carries every fix, so no correlation.
        let mut june = serving_ubuntu_openssh("2ubuntu2.13");
        june.replace_port_correlations(22, TCP, "zond:cve-kev", Vec::new());
        assert!(claims_on_22([june.clone()]).is_empty(), "test premise");
        assert!(!claims_on_22([january.clone()]).is_empty(), "test premise");

        let merged = merged(vec![
            report("january", day(1), vec![january]),
            report("june", day(150), vec![june]),
        ]);
        assert_eq!(
            claims_on_22(merged.hosts().cloned()),
            Vec::<String>::new(),
            "January's claim described the build June no longer runs"
        );
    }

    /// A claim stands while any identifier it was drawn from is backed: one
    /// release named in both URI and 2.3 form, with a newer scan backing only one.
    #[test]
    fn a_claim_is_carried_while_any_identifier_it_was_drawn_from_is_backed() {
        const URI: &str = "cpe:/a:apache:http_server:2.4.49";
        const FORMATTED: &str = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*";
        let claim = |cpe: &str| {
            finding(
                "zond:cve-kev",
                "http_server 2.4.49 has 1 known vulnerability",
            )
            .with_reference(crate::model::finding::Reference::cve("CVE-2021-41773").unwrap())
            .with_cpe(cpe)
        };

        let mut imported = Port::new(80, TCP, PortState::Open).with_service(
            Service::new("http", 90)
                .with_product("Apache httpd")
                .with_version("2.4.49")
                .with_cpe(URI)
                .with_cpe(FORMATTED),
        );
        imported.add_finding(claim(URI));
        imported.add_finding(claim(FORMATTED));

        let rescanned = Port::new(80, TCP, PortState::Open).with_service(
            Service::new("http", 90)
                .with_product("Apache httpd")
                .with_version("2.4.49 (Unix)")
                .with_cpe(URI),
        );

        let merged = merged(vec![
            report("nmap 7.94", day(1), vec![with_port(host(1), imported)]),
            report("zond", day(2), vec![with_port(host(1), rescanned)]),
        ]);

        assert_eq!(
            claims_on_80(merged.hosts().cloned()),
            ["http_server 2.4.49 has 1 known vulnerability"],
            "the newer identification still carries {URI}"
        );
    }

    /// A discovery phase over `walked` begun on `at`, that reached no verdict on
    /// `open`.
    fn swept(at: SystemTime, walked: &str, open: Option<&str>) -> ScanReport {
        use crate::model::ip::range::IpRange;

        let mut targets: IpSet = walked.parse().expect("a range");
        let undecided = open.map_or_else(Vec::new, |open| {
            let open: IpSet = open.parse().expect("a range");
            open.v4().iter().copied().map(IpRange::V4).collect()
        });
        let phase = ScanPhase::from_parts(PhaseParts {
            open: false,
            attachments: Vec::new(),
            kind: ScanKind::Discovery,
            started_at: at,
            elapsed: Duration::from_secs(60),
            privilege: Some(Privilege::Raw),
            targets: TargetScope::from_ip_set(&mut targets, &Exclusions::none()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            refusals: Vec::new(),
            unroutable: Vec::new(),
            refused_by_route: Vec::new(),
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided,
            liveness_skipped: None,
            silent: Vec::new(),
            stopped: None,
            passes_cut: Vec::new(),
            unreached: 0,
            unheard_probes: 0,
            probes: Vec::new(),
            origin: None,
        });
        ScanReport::recorded("zond", vec![phase], Vec::new())
    }

    /// A stopped sweep merged with a later complete one is not partial.
    #[test]
    fn a_stopped_sweep_merged_with_a_later_complete_one_is_not_partial() {
        let stopped = swept(day(1), "192.0.2.0/28", Some("192.0.2.4-192.0.2.15"));
        assert!(stopped.is_partial(), "test premise: the stopped sweep is");

        let merged = merged(vec![stopped, swept(day(2), "192.0.2.0/28", None)]);

        assert!(
            merged
                .phases()
                .iter()
                .any(|phase| !phase.undecided().is_empty()),
            "the stopped phase keeps its own record"
        );
        assert!(!merged.is_partial());
    }

    /// A newer label inferred from the port number does not replace an older
    /// identification or its correlation.
    #[test]
    fn a_service_named_from_its_port_number_does_not_unseat_an_identification() {
        let january = serving_apache("2.4.49");
        let tonight = with_port(
            host(1),
            Port::new(80, TCP, PortState::Open).with_service(Service::new("http", 0)),
        );

        let merged = merged(vec![
            report("january", day(1), vec![january.clone()]),
            report("tonight", day(150), vec![tonight]),
        ]);

        assert_eq!(
            service_on(&merged, 1, 80),
            january.ports().next().and_then(Port::service).cloned(),
            "January's identification stands"
        );
        assert_eq!(
            claims_on_80(merged.hosts().cloned()),
            claims_on_80([january])
        );
    }

    /// A port only ever recorded unasked stays unasked.
    #[test]
    fn a_port_nobody_ever_asked_about_stays_unasked() {
        let first = with_port(host(1), Port::new(3389, Protocol::Tcp, PortState::Unasked));
        let second = with_port(host(1), Port::new(3389, Protocol::Tcp, PortState::Unasked));

        let mut merge = Merge::new(MergeOptions::default());
        merge.add(report("first", day(1), vec![first]));
        merge.add(report("second", day(2), vec![second]));

        assert_eq!(
            merge
                .finish()
                .hosts()
                .next()
                .and_then(|host| host.ports().find(|port| port.number() == 3389))
                .map(|port| port.state()),
            Some(PortState::Unasked)
        );
    }
}
