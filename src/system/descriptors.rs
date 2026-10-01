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
//! The limit belongs to the process, so there is one process-wide [`gate`]. A
//! connection takes a permit before it opens a socket and keeps it while the
//! socket lives, so several scans in one process share the budget.
//!
//! Every connection a scan opens to a target draws from it: a connect probe and
//! the identification it goes on to over the same socket, the service pass, each
//! TLS enumeration offer, each detection. A unit of work that opens its sockets
//! one after another holds one permit; one that opens several at once takes one
//! for each.
//!
//! The gate holds what is left of the soft limit once a reserve is set aside for
//! the rest of the process: the standard streams, the runtime's descriptors,
//! capture handles, the journal, a second socket a unit briefly holds, and
//! whatever the embedding application has open. The reserve is half the limit and
//! at least [`RESERVE`]. A connection refused a socket anyway waits for one; see
//! [`exhausted`] and [`patiently`].
//!
//! A scan is refused before anything is sent when the limit leaves nothing past
//! the reserve, or when the table is already too full to hold a socket beside
//! what is open and what the scan opens as it runs; see [`too_few`].
//!
//! The gate is sized once, from the limit alone, because what is open changes
//! over the process's life. Each scan checks the table as it stands when it
//! starts, and a scan in a table fuller than the reserve allows for holds back
//! the permits that table has no socket for; see [`hold_back`].
//!
//! The limit is read and never raised: the soft limit is inherited by every child
//! the application starts, and programs built on `select` cannot watch a
//! descriptor numbered past 1,024. An application that wants a faster sweep raises
//! its own limit before its first scan.

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
/// A detection holds one for as long as it runs. Its flows run on their own
/// threads, which carry no runtime context, so the runtime is passed in.
pub(crate) fn descriptor_blocking(runtime: &tokio::runtime::Handle) -> Descriptor {
    runtime
        .block_on(gate().acquire())
        .expect("the descriptor gate is never closed")
}

/// How long a connection keeps asking for a socket while the process has none
/// to give, before it is given up.
///
/// A connection refused a socket has sent nothing, so waiting costs time and
/// never a verdict. The engine's connections take at most half the table and
/// each gives its socket back within a
/// [`CONNECT_PROBE_TIMEOUT`](crate::config::limits::CONNECT_PROBE_TIMEOUT), so a
/// table full for several of those is held by the rest of the process. Past this
/// a connect probe's target is filed unasked, for a resume to ask again; any
/// other connection is reported as the process having run out of descriptors.
pub(crate) const PATIENCE: Duration = Duration::from_secs(10);

/// How long a connection that waits out a full table on the engine's own
/// account keeps asking: [`PATIENCE`].
///
/// Tests shorten it through `testing::wait_out_a_full_table_for`.
pub(crate) fn patience() -> Duration {
    #[cfg(all(test, unix))]
    if let Some(patience) = testing::patience() {
        return patience;
    }
    PATIENCE
}

/// The first pause before an attempt refused a socket asks again. Short, because
/// on a busy scan the next connection to finish frees one within milliseconds.
pub(crate) const FIRST_PAUSE: Duration = Duration::from_millis(10);

/// The longest pause between two asks, so an attempt notices a freed
/// descriptor within a fraction of a connect's own budget however long it has
/// waited.
pub(crate) const LONGEST_PAUSE: Duration = Duration::from_millis(250);

/// Makes `attempt` until it is not refused a socket, or until `patience` has
/// passed since the first refusal.
///
/// A refusal is raised before anything is sent, so it says nothing about the
/// target, but passed on it would read as an answer. It is returned only once
/// `patience` is spent, and [`exhausted`] still recognises it.
///
/// Each attempt is made afresh, so a time budget inside `attempt` is spent on the
/// connection and never on the wait.
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
/// Worded the same wherever it is filed, since the remedy is always the caller's:
/// raise the file limit.
pub(crate) fn starved(patience: Duration) -> String {
    let limit = soft_limit()
        .map(|limit| format!(" of {limit}"))
        .unwrap_or_default();
    format!("file descriptor limit{limit} reached, no socket free within {patience:?}")
}

/// [`starved`] shortened for a console line: the limit and its size.
pub(crate) fn starved_briefly() -> String {
    match soft_limit() {
        Some(limit) => format!("file limit {limit}"),
        None => String::from("file limit"),
    }
}

/// The fewest descriptors the gate leaves to the rest of the process, however
/// small its limit.
///
/// What the rest of the process holds does not shrink with the limit. A
/// command-line scanner holds ten before its first connection (the standard
/// streams, the runtime's event queues, sockets the platform libraries keep) and
/// then opens its journal and report. Sixteen covers those plus the second socket
/// a unit briefly holds. From a limit of 32 up, half the limit is larger.
pub(crate) const RESERVE: usize = 16;

/// What a scan opens once it is running, beside its connections' sockets and
/// its captures: the sockets it asks the routing table through, a transport's
/// send sockets, a journal entry being written, a system library's brief read
/// of its configuration, and the second socket a unit holds for a moment
/// beside its first.
///
/// The part of the [`RESERVE`] still to come when a scan starts; the rest is
/// already open by then. [`too_few`] and [`hold_back`] read the table as it
/// stands and add only this, so the process's own descriptors are not counted
/// twice.
pub(crate) const OPENED_WHILE_RUNNING: usize = 8;

/// How many sockets the connections of this process's scans may hold at once.
pub(crate) fn budget() -> usize {
    budget_within(soft_limit())
}

/// The budget a process with a soft descriptor limit of `soft` gives its
/// scans' connections: what is left once the reserve is set aside, and no
/// bound at all where there is no limit to read.
///
/// At least one, since a gate of none would block every connection forever. A
/// limit that leaves none is refused a scan before it starts; see [`too_few`].
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
/// A scan needs a socket for its connections beside what the process holds open
/// when it starts and what it opens as it runs ([`OPENED_WHILE_RUNNING`]).
/// Short of that, the journal or the embedding application would have files
/// refused mid-scan, or connections would wait out their [`PATIENCE`] and be
/// filed unasked. Refused up front, the scan is not half run and the error names
/// a limit that would hold it.
///
/// Where what is open cannot be counted, the whole reserve is needed.
///
/// `captures` is the capture devices the scan will hold: one per link a raw-path
/// scan listens on (every link, which can be thirty on a laptop with a VPN and a
/// hypervisor, where the reply links cannot be told), none for a connect scan.
/// Their number depends on the host, so they are counted apart from the reserve.
/// Left out, the scan would start and have its captures refused one link at a
/// time, which reads as a network that did not answer.
pub(crate) fn too_few(captures: usize) -> Option<(usize, usize)> {
    let soft = soft_limit();
    too_few_within(soft, soft.and_then(open_descriptors), captures)
}

/// Takes out of the gate, for as long as the scan holds what this returns,
/// every permit the table as it stands has no socket for.
///
/// The gate is sized from the limit alone, so a process holding more than the
/// reserve when a scan starts has fewer sockets than the gate has permits.
/// Without this, connections would run into a full table, wait out their
/// [`PATIENCE`] and be filed unasked, and the journal's reserve would be spent on
/// connections. Held back, connections get what the table holds beside
/// [`OPENED_WHILE_RUNNING`], and no more.
///
/// Counted as permits the gate has against sockets the table has, so a scan
/// already running is counted once: each of its connections holds both. Held
/// until the scan ends, since the gate cannot learn that the rest of the process
/// closed a file.
///
/// Taken when a scan starts, and again when a capture has opened its links (held
/// while the capture is open), since a capture opens after the scan's holdback
/// was read; see [`CaptureGuard`](crate::transport::capture::CaptureGuard).
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

/// How many of the `soft` descriptors this process's table has room for are
/// taken, where it can say: every one when the table is too full to open the
/// listing.
///
/// Read from `/dev/fd` (Linux and macOS), less the descriptor the listing itself
/// holds. Only descriptors numbered below `soft` are counted: both systems give a
/// new descriptor the lowest free number and refuse one at the limit or above, so
/// a descriptor above the limit (passed down by a parent before the limit was
/// lowered) takes no room. Elsewhere, or where the listing will not open for
/// another reason, nothing is counted and the limit alone decides.
fn open_descriptors(soft: usize) -> Option<usize> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let below_the_limit = |entry: std::io::Result<std::fs::DirEntry>| {
            entry.ok().and_then(|entry| {
                let number = entry.file_name().to_str()?.parse::<usize>().ok()?;
                (number < soft).then_some(())
            })
        };
        match std::fs::read_dir("/dev/fd") {
            Ok(listing) => Some(
                listing
                    .filter_map(below_the_limit)
                    .count()
                    .saturating_sub(1),
            ),
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
/// `None` on Windows, where a socket is a kernel handle bounded by memory and
/// ports.
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

/// Whether `error` is this machine running out of sockets, as opposed to
/// anything a target did.
///
/// Raised when the socket is opened, before anything is sent, so the attempt can
/// be made again once a descriptor comes free. `EMFILE` is this process's table
/// full and `ENFILE` the whole system's; on Windows, the Winsock equivalents (handle
/// table full, no buffer space).
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
/// [`in_a_process_of_its_own`](testing::in_a_process_of_its_own) re-runs the test
/// binary on one test, which then fills its own table with
/// [`exhaust`](testing::exhaust) (when the number of free descriptors matters) or
/// [`refuse_every_descriptor`](testing::refuse_every_descriptor) (when every ask
/// must be refused, even after another thread closes a socket).
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
    /// this process. For a test running in a process of its own.
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

    /// The common shell limits leave the engine half. A process with no limit
    /// to read is not held to one.
    #[test]
    fn the_connect_paths_take_half_of_what_the_process_may_hold() {
        assert_eq!(budget_within(Some(256)), 128, "a macOS Terminal");
        assert_eq!(budget_within(Some(1024)), 512, "a Linux shell");
        assert_eq!(budget_within(None), Semaphore::MAX_PERMITS);
        assert_eq!(budget_within(Some(usize::MAX)), Semaphore::MAX_PERMITS);
    }

    /// Under a small limit the rest of the process keeps [`RESERVE`]. Half of
    /// 24 would leave a command-line scan (ten open before its first
    /// connection) two for its journal and report.
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

    /// A raw-path scan holds a capture device on every link it listens on, and
    /// a table without room for them is refused.
    ///
    /// Thirty open and twenty-eight links (a laptop with a VPN and a
    /// hypervisor) under a limit of 64: room for the rest of the scan, not for
    /// the captures.
    #[test]
    fn a_raw_scan_needs_a_descriptor_for_every_link_it_captures_on() {
        assert_eq!(too_few_within(Some(64), Some(30), 0), None, "by connect");
        assert_eq!(
            too_few_within(Some(64), Some(30), 28),
            Some((64, 30 + OPENED_WHILE_RUNNING + 28 + 1))
        );
        assert_eq!(too_few_within(Some(256), Some(30), 28), None);
    }

    /// A process whose table is nearly full before the scan starts is refused
    /// up front and told what limit would hold it, even when the limit alone is
    /// wide enough.
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
    /// opens as it runs, and no more.
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

    /// What a process holds of its own when its scan starts is counted once, as
    /// part of what is open, and not again as part of the reserve. Counted
    /// twice, a table twenty-four short of a limit of 64 leaves one connection
    /// at a time where it has room for nine.
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

    /// In a table fuller than the reserve allows for, the gate hands out no
    /// more permits than the table has sockets, and gives them back when the
    /// scan lets go.
    ///
    /// A descriptor numbered above the limit takes none of that room. A test
    /// runner can leave a few such open.
    #[cfg(unix)]
    #[test]
    fn a_scan_in_a_crowded_table_holds_back_what_it_has_no_socket_for() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        if !testing::in_a_process_of_its_own(
            module_path!(),
            "a_scan_in_a_crowded_table_holds_back_what_it_has_no_socket_for",
        ) {
            return;
        }
        let null = std::fs::File::open("/dev/null").expect("a descriptor to copy");
        // SAFETY: `fcntl` copies a live descriptor this function owns to the
        // lowest free number from 100 up, and the copy is owned by nothing
        // else once it is handed to `OwnedFd`.
        let above = unsafe {
            let copy = libc::fcntl(null.as_raw_fd(), libc::F_DUPFD, 100);
            assert!(copy >= 100, "a descriptor above the limit");
            OwnedFd::from_raw_fd(copy)
        };
        drop(null);
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
        drop((held, above));

        assert_eq!(whole, 32);
        assert_eq!(
            left,
            free - OPENED_WHILE_RUNNING,
            "permits left for {free} free descriptors, {OPENED_WHILE_RUNNING} of them \
             what the scan opens as it runs"
        );
        assert_eq!(returned, whole);
    }

    /// A socket refused because the table is full is asked for again, and the
    /// attempt that finally gets one is what the caller sees.
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

    /// The wait is bounded, and a table that never frees is reported as the
    /// process's shortfall. Anything else, a refusal by the target among them,
    /// is passed on at once.
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
    /// connect.
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
