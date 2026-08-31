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
//! ## What a merge answers, and what it does not
//!
//! **A merge answers "what is out there, given everything I know."** It produces
//! the network as of the newest source that looked at it.
//!
//! **[`diff`](crate::diff) answers "what changed."** A merge that also tried to
//! be a history — recording that 3389 was open in March and closed in August —
//! would be a worse differ built inside a document format. The historical answer
//! stays where it already lives: in the input documents, and in a comparison run
//! over them.
//!
//! So a merge is lossy in exactly one way, stated once. Where two sources give
//! different answers to the same question, one answer wins and the other is only
//! in the input file. Everything that *accumulates* — addresses, endpoints,
//! hardware addresses, CPEs, roles, status reasons — accumulates, and none of
//! that is lost.
//!
//! ## The rule: a later source overrides only where it made a claim
//!
//! Sources are folded oldest to newest. Where a newer source states something,
//! it wins. Where a newer source says nothing, the older answer stands.
//!
//! **Absence is never a claim.** A host missing from tonight's scan is not
//! evidence the host went away. An endpoint not listed is not evidence the port
//! closed. A field the document has no word for — nmap records no service vendor
//! — is not a retraction of one.
//!
//! One carve-out follows from the model's own words.
//! [`Unknown`](crate::model::host::HostStatus::Unknown) is documented as nothing
//! having been received that says anything about the host, and every other
//! status is backed by a packet. So `Unknown` is silence wearing a variant, and
//! a newer source's `Unknown` never overrides an older verdict.
//!
//! ### What a merge does not need, and a comparison does
//!
//! A comparison needs [`Coverage`](crate::diff::Coverage), because a host in one
//! report and not the other has two explanations and telling them apart is most
//! of that feature's value.
//!
//! **A merge never asks what a scan covered, because it never has to explain an
//! absence.** It reports nothing. It folds what each source claimed and leaves
//! what nothing claimed alone. The merged report's own scope needs no work
//! either: it holds every source's phases, and coverage is already a property of
//! the phase list.
//!
//! ## Which record is which host
//!
//! [`HostIdentity`] decides, exactly as it does for a comparison, and
//! [`pairing`] carries the whole argument for how. The
//! default follows a dual-stack machine keyed under IPv4 by one scanner and
//! under IPv6 by another.
//!
//! ## Where a merged report says its findings came from
//!
//! Every phase folded in carries a [`PhaseOrigin`]: what the caller called the
//! document, and what produced it as that scanner attributed itself. A merged
//! report therefore states what each of its sources covered, when, and on whose
//! word.
//!
//! An origin already on a phase is left alone, so merging a merged report keeps
//! the labels its own sources were given.
//!
//! ## What comes back
//!
//! A [`ScanReport`], which is the same kind of thing that went in. Every
//! exporter takes one, so a merged report writes as JSON, JSONL, CSV, HTML or
//! nmap XML with nothing added; every reader produces one, so a journal, an
//! exported document, an nmap file and a live scan are the same input; and a
//! merged report is a legal input to the next merge and to a comparison.
//!
//! ## Fold every source at once, not in rounds
//!
//! A merged report is a report and not a transcript of one. Where two sources
//! disagreed the losing answer is only in the input file, so nothing can take a
//! merged report apart again into what went into it.
//!
//! That is what makes merging in rounds different from merging at once.
//! `merge(merge(a, c), b)` folds `b` against a document whose clock is `c`'s, so
//! a verdict `b` should have overturned survives it — and a reading that
//! `merge(a, c)` already discarded is no longer there to enrich `b`'s finding.
//! Both are the lossiness above, applied one round earlier than the caller
//! meant. Equality of the two would need every field to carry the moment it was
//! established, which is a claim about the domain rather than about this fold.
//!
//! So N documents go into one [`Merge`]. Merging a merged report is supported
//! and often right — a baseline folded last quarter, tonight's scan folded into
//! it — and gives a coherent report; it is not the report all N sources folded
//! together would have given.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use crate::diff::HostIdentity;
use crate::diff::pairing;
use crate::model::host::hardware::HardwareInfo;
use crate::model::host::os::OsFingerprint;
use crate::model::host::{Host, HostStatus};
use crate::model::port::{Port, Protocol, Security, Service};
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
/// Reports accumulate and [`finish`](Self::finish) folds them, because the order
/// they are added in is nobody's to control and the order they are folded in is
/// decided by their clocks. See the module documentation for the rule that
/// decides every field.
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
    /// For a scan this process ran, which has no document to name. Its phases
    /// are still attributed, by the engine version the report carries, so a
    /// merged report can be counted in sources.
    pub fn add(&mut self, report: ScanReport) -> &mut Self {
        self.sources.push(Source {
            label: None,
            report,
        });
        self
    }

    /// Adds a report, naming the document it was read from.
    ///
    /// The label is whatever the caller calls it — a path, a record id, a bucket
    /// key. The engine opens nothing and has no word for one.
    ///
    /// A phase that already carries a [`PhaseOrigin`] keeps it, so merging a report
    /// that is itself a merge keeps the names its own sources were given rather
    /// than relabelling them all with this one.
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
    /// Records are ordered by when each was observed, so the result does not
    /// depend on the order a caller added their documents. A merge of nothing is
    /// an empty report attributed to this build.
    pub fn finish(self) -> ScanReport {
        let Self { options, sources } = self;

        if sources.is_empty() {
            return ScanReport::from_phases(Vec::new(), Vec::new());
        }

        // Read once per source, because it walks every phase of a report and
        // both the sort below and every record in it want the answer.
        let mut sources: Vec<(SystemTime, Source)> = sources
            .into_iter()
            .map(|source| (source.report.observed_at(), source))
            .collect();

        // Stable, so two sources that stopped at the same instant stay in the
        // order they were added and the fold has one answer rather than two.
        sources.sort_by_key(|(stopped, _)| *stopped);

        // Every record, each carrying when it was observed rather than when its
        // document was.
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

        // Stable, so records observed at the same moment keep the order their
        // sources were folded in.
        dated.sort_by_key(|(at, _)| *at);

        // Oldest first, which is what makes "the last account of this endpoint"
        // mean "the newest account that recorded one" further down.
        let records: Vec<&Host> = dated.into_iter().map(|(_, record)| record).collect();

        let hosts: Vec<Host> = pairing::groups(&records, options.identity)
            .into_iter()
            .map(|group| {
                let accounts: Vec<&Host> = group.into_iter().map(|i| records[i]).collect();
                fold_host(&accounts)
            })
            .collect();

        // The newest source's, because it produced the findings that survived
        // arbitration. Which build produced each phase is on the phase.
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

        // Chronological, and stable so that two phases of one job that began
        // together keep the order they ran in.
        phases.sort_by_key(ScanPhase::started_at);

        ScanReport::recorded(engine_version, phases, hosts)
    }
}

/// When one record's account was taken, for ordering it against every other.
///
/// A document states when it stopped looking, and every record in it states when
/// the scan last heard from that host. The second is the better answer and the
/// first is the bound on it: nothing in a document was observed after the
/// document stopped, so a record is placed at the earlier of the two.
///
/// **Both halves earn their place.** Taking the document's clock alone puts
/// every host in a report at one moment, which is wrong for any source that
/// spans time — a resumed job, and every merged report. A quarterly baseline
/// merged with a scan from last month would then outrank it about hosts the
/// baseline last saw in January.
///
/// Taking the record's alone trusts a field that is only meaningful when
/// something restored it. Every mutator on [`Host`] stamps `last_seen` with the
/// moment it ran, and the readers put back what was recorded — but a record
/// assembled by hand carries the moment it was assembled, which would place a
/// document read today at today whatever it says. Bounding by the document's
/// clock is what makes that case degrade to the document's own answer instead of
/// to the wrong one.
fn observed_at(record: &Host, stopped: SystemTime) -> SystemTime {
    record.last_seen().min(stopped)
}

/// Folds every record of one host into one, oldest account first.
///
/// Built through the model's own constructors rather than by folding with
/// [`Host::merge`] and correcting afterwards. `Host::merge` is right about the
/// job it documents — two probes of one scan, where a state only ever promotes
/// — and a merge across scans has to be able to record that a port closed. Two
/// policies, and the domain keeps the one it was written with.
fn fold_host(accounts: &[&Host]) -> Host {
    let newest = accounts.last().expect("a group holds at least one record");

    // The model's ranking over the union, rather than whichever record happened
    // to be newest: which address a report keys a host under is the report's
    // business, and `consider_primary_ip` is the rule that decides between them.
    let mut host = Host::new(newest.primary_ip());
    for account in accounts {
        host.extend_ips(account.ips().iter().copied());
        host.consider_primary_ip(account.primary_ip());
    }

    if let Some(hostname) = newest_claim(accounts, |account| account.hostname()) {
        host.set_hostname(Some(hostname.to_owned()));
    }

    // `Unknown` is the absence of evidence, by the model's own documentation, so
    // it never overrides. A host every source was silent about keeps the
    // `Unknown` that `Host::new` put there.
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
        // A conclusion about the filter in front of a host is drawn by a
        // comparative probe, so at most one source will have run it and every
        // account that reached one is the only account of it there is.
        for filtering in account.filtering() {
            host.add_filtering(*filtering);
        }
    }

    // **Newest first, which is the one place in this fold that order decides
    // what survives rather than what wins.**
    //
    // Keying is per source and per claim, which is exactly the deduplication a
    // fold across documents wants: one stack read by four scanners is four
    // readings of it, and the same scanner's reading twice is one. But the map
    // is capped — a host with many identifiable services can otherwise offer one
    // claim each until enough of them agree to a certainty none of them stated —
    // and once it is full it turns away what arrives next.
    //
    // A fold across documents is the one caller that can fill it: eight scans
    // that each read a different kernel release are eight distinct claims. Given
    // oldest first, the cap would keep the eight oldest readings of a host and
    // discard every newer one, which inverts the rule the rest of this module is
    // built on.
    for account in accounts.iter().rev() {
        for evidence in account.os_evidence() {
            host.record_os_evidence(evidence.clone());
        }
    }

    if let Some(os) = fold_os(accounts) {
        host.set_os(os);
    }

    // `HardwareInfo::merge` keeps the incumbent vendor and the newest sighting
    // of each address, so folding newest first is already the rule this module
    // wants and the model's is reused rather than restated.
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

    // Taken whole from one account rather than interleaved.
    // `HostTelemetry::merge` sorts two histories together by a sample's
    // `Instant`, and states the precondition: the two records were filled by
    // probes running at the same time. Across two documents that is false, and
    // an `Instant` from another process orders against nothing.
    if let Some(telemetry) = newest_claim(accounts, |account| {
        let telemetry = account.telemetry();
        (!telemetry.history().is_empty() || telemetry.hop_counter().is_some()).then_some(telemetry)
    }) {
        host.add_rtts(telemetry.history().iter().map(|sample| sample.rtt));
        if let Some(arrived) = telemetry.hop_counter() {
            host.record_hop_counter(arrived);
        }
    }

    // Whole, for the same reason. `NetworkPath::record`'s per-hop rule is
    // written for two accounts of one route; two genuinely different routes
    // folded hop by hop make a path nothing travelled.
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

    // Oldest account first, because `Finding::corroborate` takes the incoming
    // severity, title and class, so the last one applied is the one that
    // stands. `add_finding` is what decides whether two accounts of a claim are
    // one finding, and it is the same rule a single scan reaching a claim twice
    // goes through.
    for account in accounts {
        for finding in account.findings() {
            host.add_finding(finding.clone());
        }
    }

    // Last, because every mutator above stamps `last_seen` with the moment it
    // ran. A fold is not a sighting.
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
/// Ordered by number and transport, which is the order a host stores them in, so
/// the ports of a merged host arrive in the same order they would have if one
/// scan had found them all.
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

    // The newest account of this endpoint *is* the newest source that recorded
    // a verdict for it, since a source that recorded none contributed nothing to
    // the list. So the state is taken rather than promoted, which is what lets a
    // merge record that a port closed.
    let mut port = Port::new(newest.number(), newest.protocol(), newest.state());

    // The evidence follows the verdict it explains — from the newest account
    // that reached the *same* verdict, rather than from the newest account.
    //
    // The same shape as `fold_service` below, and the same reason. A packet is
    // an account of the state it settled, so one that settled a different state
    // does not explain this one; but where an older account reached the verdict
    // that won, its packet is evidence for the finding being reported. Nmap's
    // XML records no packet at all, so taking the newest account's blindly
    // discards the discovery of every zond scan an imported document is folded
    // with.
    if let Some(discovery) = newest_claim_port(accounts, |account| {
        (account.state() == newest.state())
            .then(|| account.discovery())
            .flatten()
    }) {
        port = port.with_discovery(discovery.clone());
    }

    if let Some(service) = fold_service(accounts) {
        port.set_service(service);
    }

    // `Security::merge` keeps the incumbent version, cipher and certificate and
    // unions the ALPN list, so folding newest first is this module's rule
    // already. A certificate is identified by its fingerprint, so a rotation is
    // a different certificate and the current one is the newest.
    let mut security = None;
    for found in accounts
        .iter()
        .rev()
        .filter_map(|account| account.security())
    {
        match security {
            Some(ref mut existing) => Security::merge(existing, found.clone()),
            None => security = Some(found.clone()),
        }
    }
    if let Some(security) = security {
        port.set_security(security);
    }

    // As on the host, and for the same reason.
    for account in accounts {
        for finding in account.findings() {
            port.add_finding(finding.clone());
        }
    }

    port
}

/// The service one endpoint is running, from every account of it.
///
/// **The identity moves as a unit.** "Newest wins, but fill in what it left
/// blank" would splice an older `Apache` with a newer `nginx` and produce
/// `nginx 2.4`, a finding nobody made. So name, product, vendor, version, extra
/// info and confidence all come from the newest account that named a service.
///
/// An older account may still enrich it, on one condition: it has to be talking
/// about the same service. Where the name and the product agree, its version and
/// extra info are more detail about one finding and belong.
///
/// CPEs come from every account whatever it named, which is
/// [`Service::merge`]'s rule kept: a CPE is not a claim about which service this
/// is, it is a claim that an identifier applies.
fn fold_service(accounts: &[&Port]) -> Option<Service> {
    let newest = newest_claim_port(accounts, |port| port.service())?;

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

    for older in accounts
        .iter()
        .rev()
        .filter_map(|account| account.service())
        .skip(1)
        .filter(|older| same_service(newest, older))
    {
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
    }

    for cpe in accounts
        .iter()
        .filter_map(|account| account.service())
        .flat_map(Service::cpes)
    {
        folded.add_cpe(Arc::clone(cpe));
    }

    Some(folded)
}

/// Whether two accounts name the same service, so that the older one's detail
/// belongs on the newer one's finding.
///
/// The name and the product, which are what identify it. The version is the
/// thing being decided and cannot be part of the test.
fn same_service(newest: &Service, older: &Service) -> bool {
    newest.name() == older.name() && newest.product() == older.product()
}

/// The operating system, from every account of one host.
///
/// The same shape as [`fold_service`], one field list along. The verdict —
/// name, family, generation, vendor and the accuracy behind it — comes from the
/// newest account that named a system. An older account naming the same system
/// contributes the kernel, the device class, the detail accuracy and the
/// evidence line where the newer one carried none, and every account contributes
/// CPEs.
///
/// Identity here is name, family, generation and vendor.
/// [`diff::host`](crate::diff::host) has a `same_system` of its own that also
/// compares the kernel and the CPEs, and it answers a different question:
/// whether anything about the reading changed, which is what a comparison
/// reports. Reusing it would refuse to enrich exactly the readings worth
/// enriching.
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
    use crate::model::port::PortState;
    use crate::model::port::discovery::{Discovery, ScanResponse};
    use crate::report::{PhaseParts, ScanKind, ScanSettings, TargetScope};

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);
    const TCP: Protocol = Protocol::Tcp;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn day(n: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + DAY * n as u32
    }

    /// A host that answered, at `10.0.0.<last>`.
    fn host(last: u8) -> Host {
        let mut host = Host::new(ip(last));
        host.set_status(HostStatus::Up);
        host
    }

    /// A report of one phase that ran on `at`, attributed to `engine`.
    fn report(engine: &str, at: SystemTime, hosts: Vec<Host>) -> ScanReport {
        let phase = ScanPhase::from_parts(PhaseParts {
            attachments: Vec::new(),
            kind: ScanKind::PortScan,
            started_at: at,
            elapsed: Duration::from_secs(60),
            privilege: Some(Privilege::Raw),
            targets: TargetScope::from_ip_set(&mut IpSet::new(), &Exclusions::none()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            unroutable: Vec::new(),
            probes: Vec::new(),
            origin: None,
        });

        ScanReport::recorded(engine, vec![phase], hosts)
    }

    /// A folded report can be told from a measured one, which is what anything
    /// reading a report as an account of one job has to know.
    ///
    /// `elapsed` is a sum over the phases, so a merged report's is the working
    /// time of every source added together — a real quantity, and not a length
    /// of time anything took. A caller presenting it as a duration would
    /// describe a scan that never ran, and this is the flag that stops it.
    #[test]
    fn a_folded_report_says_it_was_folded_and_a_measured_one_does_not() {
        let one = report("0.13.0", day(1), vec![host(1)]);
        let two = report("0.13.0", day(2), vec![host(2)]);

        assert!(!one.is_merged(), "a report of one scan was not folded");

        let folded = merged(vec![one, two]);
        assert!(folded.is_merged());

        // And the two numbers it has to keep apart: two minutes of scanning a
        // day apart is a day and two minutes of span, not two minutes.
        assert_eq!(folded.elapsed(), Duration::from_secs(120));
        assert_eq!(
            folded
                .finished_at()
                .duration_since(folded.started_at())
                .expect("a report ends after it begins"),
            DAY + Duration::from_secs(60)
        );
    }

    /// Folding a merged report keeps it merged: the origins its own sources were
    /// given are left alone, so nothing about it reverts to reading as one job.
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

    /// The decision the whole module turns on, and the reason it does not fold
    /// with `Port::merge`.
    ///
    /// `PortState`'s ordering ranks `Open` above `Closed` so that two probes of
    /// one scan settle on the stronger verdict, and `Port::merge` takes the
    /// maximum for exactly that reason. Applied across scans it means a merge can
    /// never record that a port closed, and a year of nightly merges reads as a
    /// network that is wide open.
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

    /// The other half of the same rule, and the one that stops it becoming
    /// "whatever the last scan said".
    ///
    /// An unprivileged scan files no closed ports and nmap summarises them in
    /// `<extraports>`, so an endpoint missing from a later document is routine
    /// and says nothing. Only a source that recorded a verdict may overturn one.
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

    /// `HostStatus::Unknown` is documented as nothing having been received, and
    /// every other status is backed by a packet. So it is an absence wearing a
    /// variant, and letting it win would have a host vanish from a merged report
    /// the first time one source's sweep missed it.
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

    /// The other half of the carve-out, and what makes it a carve-out rather
    /// than a rule. `Unknown` is silence; `Down` and `Filtered` are each backed
    /// by a packet, so a router calling an address unreachable tonight is a
    /// later word about it than an ARP reply last quarter.
    ///
    /// Worth holding because the fold expresses "replace" through
    /// [`Host::set_status`], which promotes and never lowers. It reads as a
    /// replacement only because the host it is called on is still `Unknown`,
    /// the bottom of that ordering — so the rule holds by where the call sits,
    /// and until now nothing said so.
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

    /// A verdict a merged report cannot explain is a verdict its reader cannot
    /// check. Nmap's XML records no packet behind a port state, so taking the
    /// newest account's discovery unconditionally drops the evidence of every
    /// zond scan an imported document is folded with — while both accounts agree
    /// on what the state is.
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

    /// The guard on the rule above, and the reason it is written on the state
    /// rather than on the endpoint. A packet is an account of the state it
    /// settled, so the SYN/ACK from the quarter this port was open explains
    /// nothing about tonight's `Closed`.
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

    /// The evidence map is capped, because a host running many identifiable
    /// services can otherwise offer one claim each until enough of them agree to
    /// a certainty none of them stated. A fold across documents is the one caller
    /// that can fill it: a dozen scans that each read a different kernel release
    /// are a dozen distinct claims.
    ///
    /// Replayed oldest first the cap keeps a host's oldest readings and turns
    /// away every newer one, which is this module's rule exactly inverted.
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
                cpe: None,
                confidence: 0.8,
                evidence: format!("a stack reading of {release}"),
            }
        }

        // Comfortably past the cap, so the test states the rule rather than the
        // number.
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

    /// "Newest wins, then fill in the blanks" is the obvious rule and it invents
    /// findings: an older `Apache httpd 2.4.1` and a newer `nginx` splice into
    /// `nginx 2.4.1`, which nothing observed.
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

    /// The positive half, and the reason the guard above is written on identity
    /// rather than on everything. A guard too strict — one that also compared the
    /// version, or the CPEs — would refuse to enrich exactly the readings worth
    /// enriching, and a merge would keep only whatever the last scan happened to
    /// extract.
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

    /// A CPE is not a claim about which service this is, it is a claim that an
    /// identifier applies, so a reading that lost the identity vote can still
    /// have extracted a valid one. `Service::merge` and `OsFingerprint::merge`
    /// both make this exception and both record that dropping them cost findings.
    #[test]
    fn a_cpe_from_a_reading_that_lost_the_vote_is_still_recorded() {
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

        let service = service_on(&merged, 1, 80).expect("a service");
        assert_eq!(service.cpes().len(), 2, "both identifiers apply");
    }

    // -----------------------------------------------------------------------
    // Identity, and the fold's own properties
    // -----------------------------------------------------------------------

    /// Which address a report keys a host under is the report's business rather
    /// than the network's. Two scanners that key one dual-stack machine
    /// differently must not produce two hosts, which is what folding by primary
    /// address alone would do.
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

    /// A fold is not a change. Merging one report, and merging it with itself,
    /// both have to give back what went in — which is the assertion that catches
    /// a field any of the fold rules quietly drops, whichever field it was.
    ///
    /// Asserted through the differ rather than field by field, on the same
    /// reasoning as `import::report::json`'s round-trip test: the comparison
    /// already knows every finding worth comparing.
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

    /// Two sources that found different things about one host hold both, and two
    /// that reached the same claim hold one, graded as the later scan graded it.
    ///
    /// Which is [`Host::add_finding`]'s rule, not a second one written here: a
    /// merge reaching a claim twice and a single scan reaching it twice are the
    /// same question.
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

    /// The order a caller adds sources in is argv order, which is nobody's
    /// statement about which scan is the later word. Only the clocks decide.
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

    /// `fe80::1` names a different machine on every segment, which is why
    /// [`pairing`](crate::diff::pairing) scopes a link-local token by the
    /// interface it was read on. A fold that correctly separates two of them
    /// then needs a report that can hold both: keyed by the bare address the
    /// second replaced the first, and a scanner watching two segments published
    /// a report holding fewer hosts than it found.
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

    /// **Merging in rounds is not merging at once, and this is what pins it.**
    ///
    /// `merge(merge(a, c), b)` folds `b` against a document whose clock is `c`'s,
    /// so `a`'s verdict — which `b` overturned and `c` never spoke to — survives
    /// a round it should not have. Equality of the two would need every field to
    /// carry the moment it was established, which the record does not offer and
    /// a fold cannot invent.
    ///
    /// Asserted rather than left alone, because the tempting claim is that a
    /// merge is associative: it reads true, the API gives no hint otherwise, and
    /// three separate places in this crate once said it was.
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
        // Silent about the endpoint, which by §3 leaves March's verdict standing.
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

    /// Merges compose, and the labels are what say so. Re-stamping every phase
    /// with the outer merge's name would lose which of five documents a finding
    /// came from the moment somebody merged in two rounds instead of one.
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

    // -----------------------------------------------------------------------
    // What a merged report is judged against
    // -----------------------------------------------------------------------

    /// A merged report's findings are as of when it last looked, not when its
    /// oldest source started. Placed by the earliest instead, a comparison judges
    /// tonight's certificates against last quarter and the crossing rule the diff
    /// design's §6 argues for stops working for the whole side.
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

    /// A source that spans time does not place all of its hosts at one moment.
    ///
    /// A document's clock is when it stopped looking, which for a merged baseline
    /// or a resumed job is months after some of its records were taken. Placed
    /// there, a quarterly baseline outranks last month's scan about a host the
    /// baseline last heard from in January, and the newer reading loses to the
    /// older one.
    ///
    /// The document's clock still bounds each record, which is what makes the
    /// rule safe where `last_seen` means nothing: see [`observed_at`].
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

    /// What the filter in front of a host was shown to be doing survives a fold.
    ///
    /// Every other field here is folded by an argument about which account wins.
    /// This one has no contest to lose: a conclusion is drawn by a comparative
    /// probe only a scan that asked for it runs, so the account that reached one
    /// is the only account of it there is, and a fold that did not name the field
    /// discarded every one of them.
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

    /// The other half of [`observed_at`], and the case the bound exists for.
    ///
    /// A reader puts back the times a document recorded. A document that recorded
    /// none leaves its records carrying the moment they were assembled, because
    /// every mutator on a host stamps the current time — so a record can be
    /// stamped later than the document holding it is dated. Taken at its word,
    /// an undated archive read tonight outranks tonight's scan.
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

    /// A route is measured end to end, and two of them folded hop by hop make a
    /// path nothing travelled. `NetworkPath::record`'s promoting rule is written
    /// for two accounts of one route, which two scans months apart are not.
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
}
