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
//! A merge answers what is out there given everything known, producing the
//! network as of the newest source that looked at it.
//! [`diff`](crate::diff) answers what changed. A merge that also tried to be a
//! history, recording that 3389 was open in March and closed in August, would be
//! a worse differ built inside a document format. The historical answer stays in
//! the input documents and in a comparison run over them.
//!
//! So a merge is lossy in one way, stated once. Where two sources give different
//! answers to the same question, one answer wins and the other is only in the
//! input file. Everything that accumulates does accumulate: addresses, endpoints,
//! hardware addresses, roles and status reasons. A service's CPEs are not on
//! that list. Each one names a version of a product, so it is an answer to
//! what is running, and it goes with the identification it was read from.
//!
//! ## The rule: a later source overrides only where it made a claim
//!
//! Sources are folded oldest to newest. Where a newer source states something,
//! it wins. Where a newer source says nothing, the older answer stands.
//!
//! Absence is never a claim. A host missing from tonight's scan is not evidence
//! the host went away, an endpoint not listed is not evidence the port closed,
//! and a field the document has no word for, as nmap has none for a service
//! vendor, is not a retraction of one.
//!
//! One carve-out follows from the model's own words.
//! [`Unknown`](crate::model::host::HostStatus::Unknown) is documented as nothing
//! having been received that says anything about the host, and every other
//! status is backed by a packet. So `Unknown` is silence wearing a variant, and
//! a newer source's `Unknown` never overrides an older verdict.
//!
//! What a TLS endpoint [accepts](crate::model::tls::TlsSupport) is read the same
//! way, version by version. A walk cut short, by an endpoint that stopped
//! answering or by the scan's budget, records the suites it reached and says it
//! did not finish, which is a claim about what it found and silence about the
//! rest. So where a newer walk was cut short having found nothing the older
//! account lacks, the older one stands if it went further: a finished walk over
//! one cut short, or of two cut short, the one that got further. A newer walk
//! that found a suite the older account does not list saw a configuration that
//! changed, and one that finished made a claim about all of it; either is the
//! newer answer.
//!
//! ### A finding goes with the evidence it was drawn from
//!
//! Findings accumulate, since a finding a newer scan does not carry is a
//! detection that did not fire rather than a claim that the subject is clean.
//! The exception is a finding the newer scan's own evidence refutes, and that
//! can be seen only where the evidence a finding rests on is in the report
//! beside it. Three derivations draw from such evidence: what a TLS endpoint
//! accepts, whose claims rest on the versions whose walk drew them; the
//! certificate an endpoint presents, whose posture claims rest on that
//! certificate; and a vulnerability correlation, whose claims rest on the
//! platform identifier each names. Where the folded record settled what such a
//! claim rests on and does not draw it, as where a newer walk finished and
//! found TLS 1.0 refused, a newer scan was shown a different certificate, or a
//! newer scan identified another version of the service, the claim is dropped.
//! Where the folded record left it unsettled, as where the newer walk was cut
//! short before it got there, the claim stands.
//!
//! A claim that stands is worded from the folded record. A fault's excerpt
//! names the suites that carry it, and the folded record may hold one version
//! from one scan and the next from another, so the words an older scan wrote
//! can name a suite under a version the merged report says is refused. The
//! verdict stays the scan's own; the excerpt is restated wherever the evidence
//! under the claim moved, and nowhere else.
//!
//! Every other finding is kept whatever a newer scan found, because nothing in
//! the report says what it rests on. A detection's finding rests on an exchange
//! the report keeps no account of.
//!
//! ### What a merge does not enforce, and a scan does
//!
//! [`Exclusions`](crate::model::exclusion::Exclusions) is not a parameter here,
//! and that is worth saying rather than leaving to be discovered. The exclusion
//! promise — no packet addressed to an excluded address, and no excluded address
//! in the report — is enforced at the two points a *scan* has: before anything is
//! opened, and at
//! [`write_host`](crate::scanner::session::ScanContext::write_host) on every
//! finding. A merge is not a scan. It probes nothing, so the first point does not
//! apply, and it folds documents somebody else's scans produced, so the second
//! has nothing to gate.
//!
//! So a source that walked an address this caller now excludes contributes that
//! address, and the merged report carries it. That is the honest outcome — the
//! document really does record what that scan found — and it is a caller's to
//! act on: an engagement whose scope narrowed between one scan and the next has
//! a policy question that no fold can answer for it.
//!
//! What the merged report does give them is the means to see it. Every source's
//! phase is kept, each with the scope it walked and the ranges it withheld, so
//! an address can be traced to the source that claimed it and checked against
//! that source's own scope. The exclusion module's point that the promise is
//! *checkable from the report* holds per phase, which is where a merged report
//! keeps it.
//!
//! ### What a merge does not need, and a comparison does
//!
//! A comparison needs [`Coverage`](crate::diff::Coverage), because a host in one
//! report and not the other has two explanations and telling them apart is most
//! of that feature's value.
//!
//! A merge never asks what a scan covered, since it never has to explain an
//! absence. It reports nothing, folds what each source claimed, and leaves what
//! nothing claimed alone. The merged report's own scope needs no work either: it
//! holds every source's phases, and coverage is already a property of the phase
//! list.
//!
//! ## Which record is which host
//!
//! [`HostIdentity`] decides, as it does for a comparison, and [`pairing`] carries
//! the argument for how. The default follows a dual-stack machine keyed under
//! IPv4 by one scanner and under IPv6 by another.
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
//! a verdict `b` should have overturned survives it, and a reading that
//! `merge(a, c)` already discarded is no longer there to enrich `b`'s finding.
//! Both are the lossiness above applied one round earlier than the caller meant.
//! Making the two equal would need every field to carry the moment it was
//! established, which is a claim about the domain rather than about this fold.
//!
//! So N documents go into one [`Merge`]. Merging a merged report is supported and
//! often right, as when a baseline folded last quarter takes tonight's scan, and
//! gives a coherent report. It is not the report all N sources folded together
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
    /// The label is whatever the caller calls it: a path, a record id, a bucket
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
/// Both halves earn their place. Taking the document's clock alone puts every
/// host in a report at one moment, which is wrong for any source that spans time,
/// such as a resumed job or a merged report. A quarterly baseline merged with a
/// scan from last month would then outrank it about hosts the baseline last saw
/// in January.
///
/// Taking the record's alone trusts a field that is only meaningful when
/// something restored it. Every mutator on [`Host`] stamps `last_seen` with the
/// moment it ran and the readers put back what was recorded, but a record
/// assembled by hand carries the moment it was assembled, which would place a
/// document read today at today whatever it says. Bounding by the document's
/// clock makes that case degrade to the document's own answer.
fn observed_at(record: &Host, stopped: SystemTime) -> SystemTime {
    record.last_seen().min(stopped)
}

/// Folds every record of one host into one, oldest account first.
///
/// Built through the model's own constructors rather than by folding with
/// [`Host::merge`] and correcting afterwards. `Host::merge` is right about the
/// job it documents, two probes of one scan where a state only promotes, and a
/// merge across scans has to be able to record that a port closed. Two policies,
/// and the domain keeps the one it was written with.
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
    // is capped, since a host with many identifiable services could otherwise
    // offer one claim each until enough of them agree to a certainty none of
    // them stated, and once full it turns away what arrives next.
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

    // The newest account of this endpoint is *almost* the newest source that
    // recorded a verdict for it, since a source that recorded none contributed
    // nothing to the list. So the state is taken rather than promoted, which is
    // what lets a merge record that a port closed.
    //
    // Almost, because of one state. That premise reads "recorded none" as "is
    // absent from the list", and [`PortState::Unasked`] is the case where it is
    // not: a scan that ran out of wall clock, or could not send, writes the port
    // down as one nobody asked about. It is absence that made it into the list.
    // Taking it would let a later, narrower scan erase what an earlier, wider
    // one found — an open port becoming `Unasked` — which is the thing this
    // module's own rule promises does not happen: *an endpoint nothing listed is
    // not evidence the port closed*. It is the same carve-out
    // [`HostStatus::Unknown`](crate::model::host::HostStatus::Unknown) gets a
    // few lines up, for the same reason, and a state added to `PortState` has
    // to be asked the same question here.
    //
    // So the state is the newest one that says anything, and `Unasked` only
    // where nothing ever did.
    let state = newest_claim_port(accounts, |account| {
        (account.state() != PortState::Unasked).then_some(account.state())
    })
    .unwrap_or(newest.state());
    let mut port = Port::new(newest.number(), newest.protocol(), state);

    // The evidence follows the verdict it explains, taken from the newest
    // account that reached the same verdict rather than the newest account.
    //
    // The same shape as `fold_service` below, and the same reason. A packet is
    // an account of the state it settled, so one that settled a different state
    // does not explain this one; but where an older account reached the verdict
    // that won, its packet is evidence for the finding being reported. Nmap's
    // XML records no packet at all, so taking the newest account's blindly
    // discards the discovery of every zond scan an imported document is folded
    // with.
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

    // `Security::merge` keeps the incumbent version, cipher and certificate and
    // unions the ALPN list, so folding the older accounts into each newer one in
    // turn is this module's rule already. A certificate is identified by its
    // fingerprint, so a rotation is a different certificate and the current one
    // is the newest.
    //
    // Oldest first rather than newest first, because of what the endpoint
    // accepts. That folds version by version, and the incumbent gives way to an
    // account that went further and found everything it did. Folded newest
    // first, an old finished walk would be weighed against whichever newer
    // account had survived so far, and could outlive a finished walk between
    // the two that had already overturned it. Oldest first, a walk that
    // finished retires every account older than itself.
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

    // As on the host, and for the same reason, less every claim the folded
    // record overturned. That record is what the report will say the endpoint
    // runs, accepts and presents, and a finding it refutes carried beside it
    // would have the one port say both. A claim it keeps is worded from it,
    // for the same reason: an excerpt listing what an older account accepted
    // would name suites the folded record says are refused.
    for account in accounts {
        for finding in account.findings() {
            if !overturned(finding, account, &port) {
                port.add_finding(worded(finding, account, &port));
            }
        }
    }

    port
}

/// Whether the folded record of an endpoint overturned a finding one account
/// of it carried.
///
/// Asked of the account's own record, which is the evidence the finding was
/// drawn from, against the folded one. The fold takes each part of that record
/// from the newest account that settled it, so what overturns a claim here is
/// always a newer account that settled what the claim rests on.
///
/// A correlation rests on the platform identifiers it names, and is
/// overturned where the account's service carried one of them and the folded
/// one carries none: [`fold_service`] keeps an identifier only while the
/// identification it was read from stands, and the claim stands while any
/// identifier it was drawn from does. Identifiers the account's own service
/// does not carry are not evidence the report holds, and a claim resting on
/// no other is left alone.
fn overturned(finding: &Finding, account: &Port, folded: &Port) -> bool {
    if finding.is_correlation() {
        let carries = |port: &Port| {
            port.service()
                .is_some_and(|service| finding.cpes().any(|cpe| service.cpes().contains(cpe)))
        };
        return carries(account) && !carries(folded);
    }
    match (folded.security(), account.security()) {
        (Some(folded), Some(basis)) => {
            folded.standing(finding, basis) == Some(Standing::Overturned)
        }
        _ => false,
    }
}

/// A finding one account of an endpoint carried, worded for the folded record
/// it will be carried beside.
///
/// The verdict, the provenance and the references are the account's. Only the
/// excerpt can move, where it lists evidence the folded record holds other
/// accounts of; [`Security::restate`] says when.
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
/// The identity moves as a unit. Letting the newest win and filling in what it
/// left blank would splice an older `Apache` with a newer `nginx` and produce
/// `nginx 2.4`, a finding nobody made. So name, product, vendor, version, extra
/// info and confidence all come from the newest account that identified a
/// service.
///
/// Identified, rather than named. A service
/// [inferred](Service::is_inferred) from the port number is the label every
/// scan path seeds a classified port with, and one run without service
/// detection leaves it there: silence wearing a variant, as `Unknown` is for a
/// host's status, and it names the endpoint only where no account identified
/// anything. Taken as the newest word, a quick port scan folded over a
/// thorough one would replace `Apache httpd 2.4.49` with a bare `http` and
/// retire every correlation drawn from it.
///
/// An older account may still enrich it, on one condition: it has to be talking
/// about the same service. Where the name and the product agree, its version and
/// extra info are more detail about one finding and belong.
///
/// CPEs follow the identification, and from an older account only where it
/// names the same service and no other version than the folded one. A CPE is
/// a whole identity, vendor and product and version in one string, and the
/// correlation joins on it, so one read off an identification the newer scan
/// replaced would have the port matched against the vulnerabilities of
/// software it no longer runs: Apache's beside `nginx`, or 2.4.49's beside
/// 2.4.58. That is the false finding the service verdict already refuses to
/// make within one scan, where a CPE travels only with the product that won.
/// An older account that stated no version contradicts none, and its
/// identifiers stand beside the newer ones.
///
/// [`Service::merge`] unions every identifier, and that is its rule rather than
/// this one's. It folds the probes of one scan, which read one listener at one
/// time; here the accounts are months apart, and the newer is the one that says
/// what is running.
fn fold_service(accounts: &[&Port]) -> Option<Service> {
    fn identified(port: &Port) -> Option<&Service> {
        port.service().filter(|service| !service.is_inferred())
    }
    let newest = newest_claim_port(accounts, identified)
        .or_else(|| newest_claim_port(accounts, Port::service))?;

    // Every other identification, newest first. The fold's own is left out by
    // identity rather than by position, since a newer account may hold a label
    // the fold passed over.
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
    }

    // Newest first, so the cap, if a banner ever fills it, keeps the
    // identifiers of the identification the fold reports.
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
/// The name and the product, which are what identify it. The version is the
/// thing being decided and cannot be part of the test.
fn same_service(newest: &Service, older: &Service) -> bool {
    newest.name() == older.name() && newest.product() == older.product()
}

/// The operating system, from every account of one host.
///
/// The same shape as [`fold_service`], one field list along. The verdict, meaning
/// name and family and generation and vendor and the accuracy behind them, comes
/// from the newest account that named a system. An older account naming the same
/// system contributes the kernel, the architecture, the device class, the detail
/// accuracy and the evidence line where the newer one carried none, and every
/// account contributes CPEs. That last part is where the two differ: the
/// service fold keeps only the identifiers of the identification it reports,
/// because the vulnerability correlation joins on them, and nothing joins on
/// an operating system's.
///
/// Identity here is name, family, generation and vendor.
/// [`diff::host`](crate::diff::host) has a `same_system` of its own that also
/// compares the kernel, the architecture and the CPEs, and it answers a
/// different question:
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
            timed_out: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided: Vec::new(),
            liveness_skipped: None,
            probes: Vec::new(),
            origin: None,
        });

        ScanReport::recorded(engine, vec![phase], hosts)
    }

    /// A folded report can be told from a measured one, which is what anything
    /// reading a report as an account of one job has to know.
    ///
    /// `elapsed` is a sum over the phases, so a merged report's is the working
    /// time of every source added together, which is a real quantity and not a
    /// length of time anything took. A caller presenting it as a duration would
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
    /// Worth holding because the fold expresses replacement through
    /// [`Host::set_status`], which promotes and never lowers. It reads as a
    /// replacement only because the host it is called on is still `Unknown`, the
    /// bottom of that ordering, so the rule holds by where the call sits.
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
    /// zond scan an imported document is folded with, while both accounts agree
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
                arch: None,
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

    /// The positive half, and why the guard above is written on identity rather
    /// than on everything. A guard that also compared the version or the CPEs
    /// would refuse to enrich the readings most worth enriching, and a merge
    /// would keep only whatever the last scan happened to extract.
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

    /// A CPE is a whole identity, and one read off an identification a newer
    /// scan replaced goes with it.
    ///
    /// Kept beside `nginx`, Apache's identifier would have the correlation
    /// match the port against Apache's vulnerabilities while the report names
    /// something else, which the service verdict refuses to do within one scan
    /// and a merge must not do across two.
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

    /// The positive half. An older reading of the same service that states no
    /// other version contradicts nothing, so its identifiers stand, and one
    /// whose version the fold took because the newer reading had none is the
    /// identification the fold reports.
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
    /// both have to give back what went in, which catches a field any of the fold
    /// rules drops whichever field it was.
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
    /// second would replace the first, and a scanner watching two segments would
    /// publish a report holding fewer hosts than it found.
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

    /// Merging in rounds is not merging at once, and this is what pins it.
    ///
    /// `merge(merge(a, c), b)` folds `b` against a document whose clock is `c`'s,
    /// so `a`'s verdict survives a round it should not have, having been
    /// overturned by `b` and never spoken to by `c`. Making the two equal would
    /// need every field to carry the moment it was established, which the record
    /// does not offer and a fold cannot invent.
    ///
    /// Asserted rather than left alone, since the tempting claim is that a merge
    /// is associative: it reads true, and the API gives no hint otherwise.
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

    /// What a source's phase never decided stays with that phase. The merged
    /// report's coverage is a property of its phase list, so a gap dropped
    /// here would have a later comparison read every host past a stopped
    /// sweep's last answer as one that went away.
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
    /// none leaves its records carrying the moment they were assembled, since
    /// every mutator on a host stamps the current time, so a record can be
    /// stamped later than the document holding it is dated. Taken at its word, an
    /// undated archive read tonight outranks tonight's scan.
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

    /// **A port nobody asked about does not erase one somebody found.**
    ///
    /// `Unasked` is what a scan writes down when it ran out of wall clock, or
    /// could not send: the port is on the record so the count still adds up, and
    /// nothing was established either way. Its own documentation says it "never
    /// overrides anything", and `Port::merge` honours that with a `max`.
    ///
    /// A fold that took the newest account's state outright would not, on the
    /// reasoning that a source recording no verdict contributes nothing to the
    /// list — true of every state but this one, which is absence that made it
    /// into the list. A later, narrower scan would erase what an earlier, wider
    /// one found, which is exactly what this module's rule promises does not
    /// happen.
    #[test]
    fn a_later_scan_that_never_asked_does_not_erase_what_an_earlier_one_found() {
        for found in [PortState::Open, PortState::Closed, PortState::Filtered] {
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

    /// And a real verdict still wins, in both directions, which is what makes
    /// the carve-out a carve-out rather than a promotion rule.
    ///
    /// `Port::merge` promotes, because it folds two readings of one live scan.
    /// A merge is not that: it folds two scans, and the later one is entitled to
    /// say a port closed. Only silence is not.
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

    /// **A walk cut short is a floor, not a newer answer.**
    ///
    /// The newer scan ran out of budget part way through TLS 1.2 and said so.
    /// What it reached is the head of the server's own preference order, and
    /// nothing in it says the server stopped accepting the rest; taken as the
    /// newer answer, it would erase the older scan's tail, which is where a
    /// legacy configuration keeps the suites worth reporting. Judged per
    /// version rather than per endpoint: the same scan finished TLS 1.3 and
    /// found it changed, and there it is the answer.
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

    /// Oldest first, so a finished walk retires every older answer for good.
    ///
    /// January accepted two suites, February finished a walk that found one of
    /// them, and March was cut short having found the other. Each change is the
    /// server's, and March's floor is all that is known of it now. Weighed
    /// newest first, January would be read against March alone, found to hold
    /// everything March found, and stand as the finished answer that February
    /// had already overturned.
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

    /// Host 1, with 443 carrying `support` and the findings drawn from it, as
    /// a scan records an enumeration.
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

    /// **A finding goes with the evidence it was drawn from.**
    ///
    /// January found TLS 1.0 accepted, and February walked every version to
    /// the end and found it refused. The fold already takes February's word for
    /// TLS 1.0, so a January finding carried beside it would have the merged
    /// report say the endpoint accepts a version its own record says it
    /// refuses, which is the finding a remediation ticket is opened from.
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

    /// A newer walk cut short settled nothing past where it stopped, so a
    /// claim resting on what lies there stands, which is the rule's other
    /// half: a later source overrides only where it made a claim.
    ///
    /// February's TLS 1.0 walk stopped having found a suite January does not
    /// list, so the fold takes it as the configuration now and no longer lists
    /// January's static-RSA suite. Whether the server still accepts that suite
    /// is in the part of the walk February never reached, and January's claim
    /// about it is the only word there is.
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

    /// A certificate's posture is a property of that certificate, so a claim
    /// about the one an older scan was shown goes when a newer scan is shown
    /// another, and stays while the same one is presented.
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

    /// **A finding carried beside a folded record says what that record
    /// holds.**
    ///
    /// February finished TLS 1.0 and found it refused, and was cut short in
    /// TLS 1.2 having found nothing, so the fold takes February's TLS 1.0 and
    /// January's TLS 1.2. The RC4 claim still stands on TLS 1.2. January's
    /// text for it lists the suite it accepted under TLS 1.0 as well, and
    /// carried as it was written, the merged port would name a suite under a
    /// version its own record says is refused.
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

    /// The same where the claim stands only because the fold left it
    /// unsettled: the text keeps the part of the older account nothing newer
    /// contradicts.
    ///
    /// February was cut short in TLS 1.2 having found a suite January does not
    /// list, so its walk stands there as the configuration now, and nothing
    /// in the folded record draws the RC4 claim. It stands because what
    /// January found under TLS 1.2 lies past where February stopped. Under
    /// TLS 1.0 February finished and was refused, so January's suite there is
    /// not part of what keeps the claim.
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

    /// Where nothing moved under a claim, the finding is carried as it was
    /// written, in the words of whatever build wrote it. A merge of one report
    /// is that report, and a merge that reworded every finding it carried
    /// would rewrite a document it had no newer evidence about.
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

    /// Port 80 of host 1 serving Apache httpd `version`, identified the way
    /// the service pass names it and correlated against the shipped catalogue
    /// the way a scan's correlation step does.
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

    /// **A correlation goes with the identification it was drawn from.**
    ///
    /// January read Apache httpd 2.4.49, the path-traversal release, and the
    /// correlation drew its vulnerabilities from that identifier. June read
    /// 2.4.58 on the same port. The merged service is June's, and a January
    /// identifier kept beside it would have the one port say it runs two
    /// versions at once and carry the vulnerabilities of the one it no longer
    /// runs, which is a remediation ticket for a patch that already landed.
    #[test]
    fn a_correlation_an_older_identification_drew_is_not_carried_past_a_newer_one() {
        let january = serving_apache("2.4.49");
        let june = serving_apache("2.4.58");
        assert!(
            claims_on_80([january.clone()])
                .iter()
                .any(|title| title.starts_with("http_server 2.4.49")),
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

    /// **A claim is carried while any identifier it was drawn from is still
    /// backed.** An imported document can name one release twice, in the URI
    /// form and the 2.3 form, and each draws the same vulnerability. A newer
    /// scan that backs only the first, identifying the release under a
    /// version string of its own, still backs the claim, and dropping it
    /// because the second went unbacked would retire a vulnerability the
    /// newer scan's own identification carries.
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
            timed_out: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided,
            liveness_skipped: None,
            probes: Vec::new(),
            origin: None,
        });
        ScanReport::recorded("zond", vec![phase], Vec::new())
    }

    /// **A merge of a stopped sweep with a later complete one is complete.**
    /// The stopped sweep's phase keeps its own record of what it never
    /// decided, and the later one decided all of it, so the merged report has
    /// nothing left undecided and is not partial. Read phase by phase it
    /// would stay partial for ever, however many sweeps finished the job.
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

    /// A newer scan that named the port from its number identified nothing,
    /// and carries neither the older identification nor the correlation drawn
    /// from it away.
    ///
    /// Every scan path seeds a classified port with the label its number is
    /// registered under, at a confidence of zero, and a scan run without
    /// service detection leaves it there. Read as the newest identification,
    /// that label would replace Apache httpd 2.4.49 with a bare `http` and
    /// retire every vulnerability the older scan correlated, on the word of a
    /// scan that never asked what was listening.
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

    /// A port only ever recorded unasked stays unasked, rather than vanishing or
    /// acquiring a verdict nothing established.
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
