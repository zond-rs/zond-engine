// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How many sockets a scan's connections may hold at once
//!
//! Every socket is a file descriptor, and a Unix process may hold only so many:
//! its soft `RLIMIT_NOFILE`, 256 in a macOS Terminal and 1,024 in most Linux
//! shells. Past it, opening a socket fails with `EMFILE` before anything is
//! sent, and a connect sweep keeping thousands in flight reaches it at once.
//!
//! The limit belongs to the process, so the budget here does too: one gate,
//! [`gate`], that a connection takes a permit from before it opens a socket
//! and keeps for as long as the socket lives. Sized per scan, two scans
//! in one process would each take what fits and together take twice that, and
//! an application running several at once, or a test harness running them in
//! parallel, would find its own files refused.
//!
//! Every connection a scan opens to a target draws from it: a connect probe
//! and the identification it goes on to over the same socket, the service
//! pass's, each offer a TLS enumeration puts, each detection's. Each takes its
//! permit before its first socket and gives it back when its last one closes.
//! A pass whose one unit of work opens its sockets one after another holds one
//! permit for the unit; one that opens several at once takes one for each.
//!
//! The gate holds what is left of the soft limit once a reserve is set aside
//! for the rest of the process: the standard streams, the runtime's own
//! descriptors, capture handles, the journal, a second socket a unit briefly
//! holds beside its first, and whatever the application embedding the engine
//! has open. The reserve is half the limit, and never fewer than [`RESERVE`],
//! since what the rest of the process holds does not shrink with the limit: a
//! command-line scanner holds ten before its first connection. A table that
//! fills anyway, from any of those, is not the engine's to prevent, and a
//! connection refused a socket waits for one rather than reading the refusal
//! as an answer; see [`exhausted`] and [`patiently`].
//!
//! A limit that leaves nothing once the reserve is set aside is too small for
//! a scan to keep both its connections and its journal, and so is a table
//! already too full, when the scan starts, to hold a socket beside what is
//! open and what the scan opens as it runs: a scan is refused under either
//! before anything is sent; see [`too_few`].
//!
//! What is open is counted for that refusal and not for the gate's size. The
//! gate is sized once for the life of the process, and what is open at that
//! moment is a snapshot of an application that goes on opening and closing its
//! own files: sized from it, a gate would keep for good a shortfall that
//! passed, or a room that did not last. The refusal is asked afresh by each
//! scan, of the table as it stands then, which is the moment a scan either
//! fits or does not. A scan that fits in a table fuller than the reserve
//! allows for holds back, for its own duration, the permits that table has no
//! socket for; see [`hold_back`].
//!
//! The limit is read and never raised. Raising it is a decision about the
//! whole process, which a library does not own: the soft limit is inherited by
//! every child the application starts, and a program still built on `select`
//! cannot watch a descriptor numbered past 1,024, which is why shells default
//! to that number in the first place. An application that wants a faster sweep
//! raises its own limit before its first scan, and the gate is sized from what
//! it finds then.

use std::future::Future;
use std::io;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tokio::sync::{Semaphore, SemaphorePermit};

/// One socket's share of the gate, held for as long as the socket is.
pub(crate) type Descriptor = SemaphorePermit<'static>;

/// The gate every connection a scan opens takes a [`Descriptor`] from.
///
/// Sized once, from the soft limit in force when the first connection asks, so
/// a limit an application raises before its first scan is the one that counts.
pub(crate) fn gate() -> &'static Semaphore {
    static GATE: OnceLock<Semaphore> = OnceLock::new();
    GATE.get_or_init(|| Semaphore::new(budget()))
}

/// Takes a [`Descriptor`] from the gate, for a caller holding blocking
/// sockets, waiting on `runtime` for one to come free.
///
/// What a detection holds for as long as it runs, since its exchanges are made
/// by blocking sockets on threads outside the runtime's workers. The runtime
/// is handed in rather than found, because a detection's flows run on threads
/// of their own that carry no runtime context to find.
pub(crate) fn descriptor_blocking(runtime: &tokio::runtime::Handle) -> Descriptor {
    runtime
        .block_on(gate().acquire())
        .expect("the descriptor gate is never closed")
}

/// How long a connection keeps asking for a socket while the process has none
/// to give, before it is given up.
///
/// A connection refused a socket has sent nothing, so waiting costs time and
/// never a verdict. The engine's own connections take at most half the table,
/// and a sweep gives each socket back within a
/// [`CONNECT_PROBE_TIMEOUT`](crate::config::limits::CONNECT_PROBE_TIMEOUT), so
/// a table that stays full for several of those is held by the rest of the
/// process, and nothing the scan finishes will free it. Past this a connect
/// probe's target is filed unasked, and a resume asks again; any other
/// connection is reported as the process having run out of descriptors.
pub(crate) const PATIENCE: Duration = Duration::from_secs(10);

/// How long a connection that waits out a full table on the engine's own
/// account keeps asking: [`PATIENCE`].
///
/// A test that fills its own process's table to see a connection given up
/// sets it shorter through `testing::wait_out_a_full_table_for`, since what
/// it checks is that the wait ends and how, which a wait of ten seconds
/// shows no better than one of a tenth of one.
pub(crate) fn patience() -> Duration {
    #[cfg(all(test, unix))]
    if let Some(patience) = testing::patience() {
        return patience;
    }
    PATIENCE
}

/// The first pause before an attempt refused a socket asks for one again.
/// Short, because the descriptor it waits for is freed by whichever connection
/// finishes next, which on a busy scan is a matter of milliseconds.
pub(crate) const FIRST_PAUSE: Duration = Duration::from_millis(10);

/// The longest pause between two asks, so an attempt notices a freed
/// descriptor within a fraction of a connect's own budget however long it has
/// waited.
pub(crate) const LONGEST_PAUSE: Duration = Duration::from_millis(250);

/// Makes `attempt` until it is not refused a socket, or until `patience` has
/// passed since the first refusal.
///
/// A refusal is raised before anything is sent, so it says nothing about the
/// target, and passed on it reads as one: a port that would not answer, an
/// identification that found nothing. Returned as it is only once `patience`
/// is spent, and then [`exhausted`] still names it for what it is.
///
/// Each attempt is made afresh, so a time budget inside `attempt` is spent on
/// the connection and never on the wait: a refusal comes back before the
/// attempt's clock has run at all.
pub(crate) async fn patiently<T, F, Fut>(patience: Duration, mut attempt: F) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut refused_since: Option<Instant> = None;
    let mut pause = FIRST_PAUSE;
    loop {
        match attempt().await {
            Err(e) if exhausted(&e) => {
                if refused_since.get_or_insert_with(Instant::now).elapsed() >= patience {
                    return Err(e);
                }
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(LONGEST_PAUSE);
            }
            result => return result,
        }
    }
}

/// [`patiently`], for a caller holding a blocking socket.
pub(crate) fn patiently_blocking<T>(
    patience: Duration,
    mut attempt: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let mut refused_since: Option<Instant> = None;
    let mut pause = FIRST_PAUSE;
    loop {
        match attempt() {
            Err(e) if exhausted(&e) => {
                if refused_since.get_or_insert_with(Instant::now).elapsed() >= patience {
                    return Err(e);
                }
                std::thread::sleep(pause);
                pause = (pause * 2).min(LONGEST_PAUSE);
            }
            result => return result,
        }
    }
}

/// Why a connection was never made, when the process had no socket to give
/// it for as long as it would wait: `patience`.
///
/// Said the one way wherever it is filed, since the remedy is the caller's
/// and the same everywhere: the engine reads the file limit and does not raise
/// it.
pub(crate) fn starved(patience: Duration) -> String {
    starved_while(&format!("within {patience:?}"))
}

/// [`starved`], for a connection whose wait was bounded by a clock of its own
/// rather than by [`PATIENCE`], named by `wait` as it finishes the sentence
/// "no socket came free ...".
pub(crate) fn starved_while(wait: &str) -> String {
    let limit = soft_limit()
        .map(|limit| format!(" of {limit}"))
        .unwrap_or_default();
    format!("file descriptor limit{limit} reached, no socket free {wait}")
}

/// [`starved`] in the few words a console line has room for: the limit and
/// its size, which is what the reader raises. The report's entry says the
/// rest.
pub(crate) fn starved_briefly() -> String {
    match soft_limit() {
        Some(limit) => format!("file limit {limit}"),
        None => String::from("file limit"),
    }
}

/// The fewest descriptors the gate leaves to the rest of the process, however
/// small its limit.
///
/// What a process running a scan holds besides the scan's connections does
/// not shrink with the limit. A command-line scanner holds ten before its
/// first connection: the three standard streams, the runtime's event queues
/// and a few sockets the platform's own libraries keep, and then it opens its
/// journal and its report beside them. Sixteen covers those with room for the
/// second socket a unit briefly holds beside its first. Half the limit is the
/// larger share from 32 up, which leaves an application that holds many files
/// of its own room in proportion to them.
pub(crate) const RESERVE: usize = 16;

/// What a scan opens once it is running, beside its connections' sockets and
/// its captures: the sockets it asks the routing table through, a transport's
/// send sockets, a journal entry being written, a system library's brief read
/// of its configuration, and the second socket a unit holds for a moment
/// beside its first.
///
/// The part of the [`RESERVE`] still to come when a scan starts. The rest of
/// it is open by then: the standard streams, the runtime's event queues, the
/// sockets the platform's libraries keep, and a command-line scanner's report
/// files, which it creates before the scan so a destination it cannot write
/// is refused before anything is sent. [`too_few`] and [`hold_back`] read the
/// table as it stands, where those are counted already, and add only this
/// beside it: charged the whole reserve on top, a process is charged its own
/// descriptors twice, and a table twenty-four short of its limit leaves a
/// scan one connection at a time rather than eight.
pub(crate) const OPENED_WHILE_RUNNING: usize = 8;

/// How many sockets the connections of this process's scans may hold at once.
pub(crate) fn budget() -> usize {
    budget_within(soft_limit())
}

/// The budget a process with a soft descriptor limit of `soft` gives its
/// scans' connections: what is left once the reserve is set aside, and no
/// bound at all where there is no limit to read.
///
/// Never below one, since a gate of none would hold every connection waiting
/// for ever. A limit that leaves none is refused a scan before it starts; see
/// [`too_few`].
fn budget_within(soft: Option<usize>) -> usize {
    soft.map_or(Semaphore::MAX_PERMITS, |soft| {
        soft.saturating_sub(reserve_within(soft))
            .clamp(1, Semaphore::MAX_PERMITS)
    })
}

/// What a process with a soft limit of `soft` keeps back from its scans'
/// connections: half of it, and never fewer than [`RESERVE`].
fn reserve_within(soft: usize) -> usize {
    (soft / 2).max(RESERVE)
}

/// The descriptor limit this process has and the least a scan needs, when the
/// first is below the second.
///
/// A scan needs a socket for its connections beside whatever the process
/// holds open when the scan starts, its own descriptors and the rest: a table
/// a parent filled before handing it over, or an application's own files. It
/// needs them beside what it opens as it runs, too, which is what is left of
/// the [`RESERVE`] once the process has started; see
/// [`OPENED_WHILE_RUNNING`]. Below that the budget would have to come out of
/// the reserve, and the journal and the application around the scan would
/// find their files refused somewhere in the middle of it, where
/// the failure says nothing about why; or the connections would find none
/// free and wait out their [`PATIENCE`] to be filed unasked. Refused before
/// anything is sent, the scan is not half run, and the reason names its
/// remedy: a limit that holds what is open and the scan.
///
/// Where what is open cannot be counted, the whole reserve is needed, since
/// none of what it stands for was counted either.
///
/// `captures` is the capture devices the scan will hold beside all of that:
/// one for each link a scan taking the raw path listens on, which is the links
/// replies to its targets arrive by and every link, thirty on a laptop with a
/// VPN and a hypervisor, where those cannot be told; none for a scan by
/// connect. They
/// are counted apart from the reserve because their number is the host's and
/// not the scan's. Left out, a table with room for the rest alone lets the
/// scan start and refuses its captures one link at a time, and what that
/// leaves reads as a network that did not answer.
pub(crate) fn too_few(captures: usize) -> Option<(usize, usize)> {
    let soft = soft_limit();
    too_few_within(soft, soft.and_then(open_descriptors), captures)
}

/// Takes out of the gate, for as long as the scan holds what this returns,
/// every permit the table as it stands has no socket for.
///
/// The gate is sized from the limit alone, and a process that holds more
/// than the reserve when a scan starts, a table a parent filled or an
/// application's own files, has fewer sockets to give than the gate has
/// permits. A scan passing [`too_few`] then runs connections the gate lets
/// through into a full table, where each waits out its [`PATIENCE`] beside
/// the ones holding the sockets and is filed unasked, and what the reserve
/// keeps for the journal is spent on connections. Held back, the connections
/// take what the table holds beside what the scan opens as it runs, and no
/// more; see [`OPENED_WHILE_RUNNING`].
///
/// Counted as permits the gate still has against sockets the table still
/// has, so a scan already running in the process is counted once: each of
/// its connections holds a permit and a descriptor alike, and what the
/// difference measures is the descriptors held outside the gate. Held until
/// the scan ends rather than handed back as the table empties, since the gate
/// has no way to learn the rest of the process closed a file.
pub(crate) fn hold_back() -> Option<Descriptor> {
    let soft = soft_limit()?;
    let open = open_descriptors(soft)?;
    let gate = gate();
    let excess = held_back_within(gate.available_permits(), soft, open);
    if excess == 0 {
        return None;
    }
    gate.try_acquire_many(u32::try_from(excess).ok()?).ok()
}

/// How many of `available` permits [`hold_back`] takes out of the gate in a
/// process whose soft limit is `soft` and which holds `open` descriptors:
/// every one past the sockets the table has room for beside
/// [`OPENED_WHILE_RUNNING`], and never the last one, so a scan let through
/// still runs.
fn held_back_within(available: usize, soft: usize, open: usize) -> usize {
    let room = soft.saturating_sub(open + OPENED_WHILE_RUNNING).max(1);
    available.saturating_sub(room)
}

/// [`too_few`], for a process whose soft limit is `soft` and which holds
/// `open` descriptors, where that could be counted.
fn too_few_within(
    soft: Option<usize>,
    open: Option<usize>,
    captures: usize,
) -> Option<(usize, usize)> {
    let beside = open.map_or(RESERVE, |open| open + OPENED_WHILE_RUNNING);
    let needed = beside + captures + 1;
    soft.filter(|&soft| soft < needed)
        .map(|soft| (soft, needed))
}

/// How many descriptors this process holds open, where it can say: every one
/// of `soft` when the table is too full to open the listing.
///
/// Read from the directory the system lists a process's open descriptors
/// in, which Linux and macOS both keep at `/dev/fd`, less the one the listing
/// itself holds while it is read. Elsewhere, and wherever the listing will
/// not open for another reason, nothing is counted and the limit alone
/// decides.
fn open_descriptors(soft: usize) -> Option<usize> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        match std::fs::read_dir("/dev/fd") {
            Ok(listing) => Some(listing.count().saturating_sub(1)),
            Err(error) if exhausted(&error) => Some(soft),
            Err(_) => None,
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = soft;
        None
    }
}

/// The number of descriptors this process may hold, where it has such a limit
/// and it is finite.
///
/// Windows has none of this kind: a socket there is a kernel handle, bounded by
/// memory and ports rather than by a count the process could read.
pub(crate) fn soft_limit() -> Option<usize> {
    #[cfg(unix)]
    {
        let mut bounds = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes one `rlimit` through a pointer to a live
        // local of that type and reads nothing else.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut bounds) } != 0 {
            return None;
        }
        if bounds.rlim_cur == libc::RLIM_INFINITY {
            return None;
        }
        usize::try_from(bounds.rlim_cur).ok()
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Whether `error` is this machine running out of sockets to give, rather than
/// anything a target did.
///
/// Raised when the socket is opened, before anything is sent, so the target
/// has been asked nothing and the attempt can be made again once a descriptor
/// comes free. `EMFILE` is this process's table full and `ENFILE` the whole
/// system's; Windows reports its own two, a handle table full and no buffer
/// space for another socket, under their Winsock names.
pub(crate) fn exhausted(error: &io::Error) -> bool {
    let Some(code) = error.raw_os_error() else {
        return false;
    };
    #[cfg(unix)]
    {
        code == libc::EMFILE || code == libc::ENFILE
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
        code == WSAEMFILE || code == WSAENOBUFS
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = code;
        false
    }
}

/// Running a test out of descriptors without taking every other test down
/// with it.
///
/// A test that fills this process's descriptor table would take every test
/// running beside it down too, so it runs its body in a process of its own:
/// [`in_a_process_of_its_own`](testing::in_a_process_of_its_own) re-runs the
/// test binary on that one test, and the re-run fills its own table with
/// [`exhaust`](testing::exhaust), where how many descriptors are free is what
/// it tests, or refuses every descriptor with
/// [`refuse_every_descriptor`](testing::refuse_every_descriptor), where a
/// refusal is: a socket some thread of the test closes after a fill frees
/// room the next ask takes, and under a refusal it frees none.
#[cfg(all(test, unix))]
pub(crate) mod testing {
    pub(crate) use crate::testing::own_process::in_a_process_of_its_own;

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// The [`patience`](super::patience) a test set, in milliseconds, or zero
    /// where it set none.
    static PATIENCE_MS: AtomicU64 = AtomicU64::new(0);

    /// Has every connection that waits out a full table on
    /// [`patience`](super::patience) wait `patience` instead, for the rest of
    /// this process. For a test running in a process of its own, which is the
    /// only kind that fills its table.
    pub(crate) fn wait_out_a_full_table_for(patience: Duration) {
        let millis = u64::try_from(patience.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        PATIENCE_MS.store(millis, Ordering::Relaxed);
    }

    /// What [`wait_out_a_full_table_for`] set, if anything.
    pub(super) fn patience() -> Option<Duration> {
        match PATIENCE_MS.load(Ordering::Relaxed) {
            0 => None,
            millis => Some(Duration::from_millis(millis)),
        }
    }

    /// Every descriptor this process asks for refused, for as long as it is
    /// held, whatever it closes meanwhile.
    pub(crate) struct Refusing(libc::rlimit);

    /// Lowers this process's descriptor limit below every descriptor it
    /// holds, so the next one anything asks for is refused, and so is every
    /// one after it until what this returns is dropped: a descriptor closed
    /// meanwhile frees no room under a limit of none.
    pub(crate) fn refuse_every_descriptor() -> Refusing {
        let mut bounds = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: as in `exhaust`.
        unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut bounds), 0);
            let was = bounds;
            bounds.rlim_cur = 0;
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &bounds), 0);
            Refusing(was)
        }
    }

    impl Drop for Refusing {
        fn drop(&mut self) {
            // SAFETY: as in `exhaust`.
            unsafe {
                libc::setrlimit(libc::RLIMIT_NOFILE, &self.0);
            }
        }
    }

    /// Lowers this process's descriptor limit to `limit` and opens files until
    /// it is reached, so the next socket anything asks for is refused. The
    /// files are handed back, and dropping them is what frees the table.
    pub(crate) fn exhaust(limit: libc::rlim_t) -> Vec<std::fs::File> {
        let mut bounds = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes one `rlimit` through a pointer to a live
        // local of that type, and `setrlimit` reads one the same way.
        unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut bounds), 0);
            bounds.rlim_cur = limit;
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &bounds), 0);
        }
        let mut held = Vec::new();
        loop {
            match std::fs::File::open("/dev/null") {
                Ok(file) => held.push(file),
                Err(e) if e.raw_os_error() == Some(libc::EMFILE) => return held,
                Err(e) => panic!("filling the descriptor table: {e}"),
            }
        }
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

    /// The two shells a user is most likely to start a scan from leave the
    /// engine half of what they allow, and the rest of the process the other
    /// half. A process with no limit to read is not held to one.
    #[test]
    fn the_connect_paths_take_half_of_what_the_process_may_hold() {
        assert_eq!(budget_within(Some(256)), 128, "a macOS Terminal");
        assert_eq!(budget_within(Some(1024)), 512, "a Linux shell");
        assert_eq!(budget_within(None), Semaphore::MAX_PERMITS);
        assert_eq!(budget_within(Some(usize::MAX)), Semaphore::MAX_PERMITS);
    }

    /// Under a small limit the rest of the process keeps what it needs
    /// whatever the scan wants, rather than half of a table too small to hold
    /// its standard streams, runtime and journal. A command-line scan holds
    /// ten before its first connection, so half of a limit of 24 would leave
    /// it two for its journal and report, and the journal would be refused
    /// its file in the middle of the scan.
    #[test]
    fn a_small_limit_keeps_the_reserve_and_gives_the_scan_the_rest() {
        assert_eq!(
            budget_within(Some(48)),
            24,
            "half, which is above the reserve"
        );
        assert_eq!(budget_within(Some(24)), 24 - RESERVE);
        assert_eq!(budget_within(Some(RESERVE + 1)), 1);
        assert_eq!(
            budget_within(Some(RESERVE)),
            1,
            "a gate is never empty, so a connection past the refusal still runs"
        );
    }

    /// A scan is refused only where the limit leaves its connections nothing
    /// beside the reserve, and the refusal carries both numbers so it can say
    /// what to raise the limit to.
    #[test]
    fn a_limit_that_leaves_no_socket_beside_the_reserve_refuses_the_scan() {
        assert_eq!(too_few_within(Some(16), None, 0), Some((16, RESERVE + 1)));
        assert_eq!(too_few_within(Some(0), None, 0), Some((0, RESERVE + 1)));
        assert_eq!(too_few_within(Some(RESERVE + 1), None, 0), None);
        assert_eq!(too_few_within(Some(256), None, 0), None);
        assert_eq!(
            too_few_within(None, None, 0),
            None,
            "no limit to fall short of"
        );
    }

    /// What is open when the scan starts is held beside what the scan opens
    /// as it runs and the socket, and the limit named is one that would hold
    /// all three.
    #[test]
    fn what_is_open_already_is_needed_beside_what_the_scan_opens() {
        assert_eq!(
            too_few_within(Some(64), Some(57), 0),
            Some((64, 57 + OPENED_WHILE_RUNNING + 1))
        );
        assert_eq!(too_few_within(Some(64), Some(10), 0), None);
        assert_eq!(too_few_within(Some(256), Some(64), 0), None);
        assert_eq!(too_few_within(None, Some(57), 0), None);
    }

    /// A scan taking the raw path holds a capture device on every link it
    /// listens on, and a table with room for what is open and the rest of
    /// the scan alone is refused it: let through, the scan's captures are
    /// refused one link at a time and the replies those links carry are
    /// never heard.
    ///
    /// Thirty open and twenty-eight links, as a laptop with a VPN and a
    /// hypervisor has them, under a limit of 64: room for what the scan opens
    /// as it runs and a socket, and not for the captures beside them.
    #[test]
    fn a_raw_scan_needs_a_descriptor_for_every_link_it_captures_on() {
        assert_eq!(too_few_within(Some(64), Some(30), 0), None, "by connect");
        assert_eq!(
            too_few_within(Some(64), Some(30), 28),
            Some((64, 30 + OPENED_WHILE_RUNNING + 28 + 1))
        );
        assert_eq!(too_few_within(Some(256), Some(30), 28), None);
    }

    /// A process whose table is nearly full before the scan starts, held by
    /// whatever started it, is refused the scan up front, and told what limit
    /// would hold it. Let through because its limit alone is wide enough, the
    /// scan's connections would wait out their patience for sockets nothing
    /// frees and be filed unasked, every one of them.
    #[cfg(unix)]
    #[test]
    fn a_table_already_nearly_full_refuses_the_scan_whatever_the_limit() {
        if !testing::in_a_process_of_its_own(
            module_path!(),
            "a_table_already_nearly_full_refuses_the_scan_whatever_the_limit",
        ) {
            return;
        }
        let mut held = testing::exhaust(64);
        // Seven free, as a parent that filled the table leaves them.
        held.truncate(held.len() - 7);

        let refused = too_few(0);
        drop(held);

        let (limit, needed) = refused.expect("a scan with seven descriptors free");
        assert_eq!(limit, 64);
        assert!(
            needed > 64 - 7 + OPENED_WHILE_RUNNING,
            "{needed} names no limit that would hold what is open and the scan"
        );
    }

    /// A scan let through into a table fuller than the reserve allows for is
    /// left as many permits as the table has sockets, beside what the scan
    /// opens as it runs, and no more. Promised the gate's whole budget, its connections past what
    /// the table holds would wait out their patience for sockets the ones
    /// before them hold, and be filed unasked.
    #[test]
    fn a_gate_is_held_to_the_sockets_the_table_has_room_for() {
        // A limit of 64 with 40 open passes the refusal, and leaves sixteen.
        assert_eq!(too_few_within(Some(64), Some(40), 0), None);
        assert_eq!(held_back_within(budget_within(Some(64)), 64, 40), 32 - 16);
        // A table the reserve covers holds nothing back.
        assert_eq!(held_back_within(budget_within(Some(256)), 256, 10), 0);
        // What another scan's connections hold is counted once: its permits
        // are gone from the gate and its sockets from the table alike.
        assert_eq!(held_back_within(32 - 5, 64, 40 + 5), 32 - 16);
        // The last permit is never taken.
        assert_eq!(held_back_within(32, 64, 64), 31);
    }

    /// What a process holds of its own when its scan starts is counted once,
    /// as part of what is open, and not a second time as the reserve it is
    /// part of. Charged twice, a command-line scan in a table twenty-four
    /// short of its limit of 64 was left one connection at a time: its sixty
    /// silent ports took 333 s to identify, against 11 s in an open table,
    /// though the table had room for nine at once.
    #[test]
    fn what_the_process_holds_of_its_own_is_counted_once() {
        // Twenty-four free when the command line starts, and seven of those
        // its own by the time its scan does: three event queues, a socket
        // pair and its duplicate, and a network policy handle.
        let open = 64 - 24 + 7;
        let gate = budget_within(Some(64));
        let left = gate - held_back_within(gate, 64, open);
        assert_eq!(
            left,
            64 - open - OPENED_WHILE_RUNNING,
            "every socket the table has beside what the scan opens as it runs"
        );
        assert!(left > 1, "{left} connection at a time");
    }

    /// Held back in a process whose table is fuller than the reserve allows
    /// for, the gate hands out no more permits than the table has sockets
    /// for, and gives them back when the scan lets go.
    #[cfg(unix)]
    #[test]
    fn a_scan_in_a_crowded_table_holds_back_what_it_has_no_socket_for() {
        if !testing::in_a_process_of_its_own(
            module_path!(),
            "a_scan_in_a_crowded_table_holds_back_what_it_has_no_socket_for",
        ) {
            return;
        }
        let mut held = testing::exhaust(64);
        let free = 24;
        held.truncate(held.len() - free);
        assert_eq!(
            too_few(0),
            None,
            "a table with {free} free passes the refusal"
        );

        let whole = gate().available_permits();
        let held_back = hold_back();
        let left = gate().available_permits();
        drop(held_back);
        let returned = gate().available_permits();
        drop(held);

        assert_eq!(whole, 32);
        assert_eq!(
            left,
            free - OPENED_WHILE_RUNNING,
            "permits left for {free} free descriptors, {OPENED_WHILE_RUNNING} of them \
             what the scan opens as it runs"
        );
        assert_eq!(returned, whole);
    }

    /// A socket refused because the table is full is asked for again rather
    /// than handed back as the connection's outcome, and the attempt that
    /// finally gets one is what the caller sees.
    ///
    /// The refusal is raised before anything is sent, so passed on it is a
    /// port read as closed or an identification that found nothing, from a
    /// target nobody asked.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_full_table_is_waited_out_rather_than_passed_on() {
        let mut refusals = 3;
        let outcome = patiently(Duration::from_secs(10), || {
            let refused = refusals > 0;
            refusals -= 1;
            async move {
                match refused {
                    true => Err(io::Error::from_raw_os_error(libc::EMFILE)),
                    false => Ok("connected"),
                }
            }
        })
        .await;
        assert_eq!(
            outcome.expect("the fourth attempt had a socket"),
            "connected"
        );

        let mut refusals = 3;
        let outcome = patiently_blocking(Duration::from_secs(10), || {
            refusals -= 1;
            match refusals {
                0.. => Err(io::Error::from_raw_os_error(libc::ENFILE)),
                _ => Ok("connected"),
            }
        });
        assert_eq!(outcome.expect("a later attempt had a socket"), "connected");
    }

    /// The wait is bounded, and what it ends on still says what it was: a
    /// table that never frees is the process's shortfall and is reported as
    /// one, not as a target that did not answer. Anything else an attempt
    /// comes to, a refusal by the target among them, is passed on at once.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_wait_ends_on_its_patience_and_nothing_else_is_waited_on() {
        let outcome: io::Result<()> = patiently(Duration::from_millis(30), || async {
            Err(io::Error::from_raw_os_error(libc::EMFILE))
        })
        .await;
        assert!(
            outcome.is_err_and(|e| exhausted(&e)),
            "the refusal is named"
        );

        let mut attempts = 0;
        let outcome: io::Result<()> = patiently(Duration::from_secs(10), || {
            attempts += 1;
            async { Err(io::Error::from_raw_os_error(libc::ECONNREFUSED)) }
        })
        .await;
        assert!(outcome.is_err_and(|e| !exhausted(&e)));
        assert_eq!(attempts, 1, "a target's answer was asked again");
    }

    /// The table filling is told apart from everything a target can do to a
    /// connect, which is what keeps a refused socket from being read as an
    /// answer.
    #[cfg(unix)]
    #[test]
    fn a_full_descriptor_table_is_told_apart_from_a_target_s_answer() {
        assert!(exhausted(&io::Error::from_raw_os_error(libc::EMFILE)));
        assert!(exhausted(&io::Error::from_raw_os_error(libc::ENFILE)));
        assert!(!exhausted(&io::Error::from_raw_os_error(
            libc::ECONNREFUSED
        )));
        assert!(!exhausted(&io::Error::from_raw_os_error(libc::ETIMEDOUT)));
        assert!(!exhausted(&io::ErrorKind::TimedOut.into()));
    }
}
