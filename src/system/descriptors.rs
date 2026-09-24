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
//! a scan to keep both its connections and its journal, and a scan is refused
//! under it before anything is sent; see [`too_few`].
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
    format!(
        "the process reached its file descriptor limit{limit} and no socket came \
         free {wait}; raise the limit and scan again"
    )
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
/// A scan needs a socket for its connections beside the [`RESERVE`] the rest
/// of the process keeps. Below that the budget would have to come out of the
/// reserve, and the journal, the report, and the application around the scan
/// would find their files refused somewhere in the middle of it, where the
/// failure says nothing about why. Refused before anything is sent, the scan
/// is not half run, and the reason names its remedy.
pub(crate) fn too_few() -> Option<(usize, usize)> {
    too_few_within(soft_limit())
}

/// [`too_few`], for a process whose soft limit is `soft`.
fn too_few_within(soft: Option<usize>) -> Option<(usize, usize)> {
    let needed = RESERVE + 1;
    soft.filter(|&soft| soft < needed)
        .map(|soft| (soft, needed))
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
/// [`exhaust`](testing::exhaust).
#[cfg(all(test, unix))]
pub(crate) mod testing {
    /// The variable a re-run finds itself under, naming the test it is.
    const OWN_PROCESS: &str = "ZOND_TEST_IN_OWN_PROCESS";

    /// Whether this is the process the test `name`, in the module
    /// `module` (its `module_path!()`), should run its body in.
    ///
    /// The first call re-runs this binary on that one test and fails if the
    /// re-run does, and the re-run is the call that answers `true`.
    pub(crate) fn in_a_process_of_its_own(module: &str, name: &str) -> bool {
        if std::env::var(OWN_PROCESS).is_ok_and(|running| running == name) {
            return true;
        }
        let path = format!(
            "{}::{name}",
            module.split_once("::").expect("a crate path").1
        );
        let run = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([path.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(OWN_PROCESS, name)
            .output()
            .expect("re-running the test in a process of its own");
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            run.status.success(),
            "{name} failed in its own process:\n{stdout}{}",
            String::from_utf8_lossy(&run.stderr),
        );
        // A filter that matched nothing exits cleanly too.
        assert!(
            stdout.contains("1 passed"),
            "{name} did not run in its own process:\n{stdout}"
        );
        false
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
        assert_eq!(too_few_within(Some(16)), Some((16, RESERVE + 1)));
        assert_eq!(too_few_within(Some(0)), Some((0, RESERVE + 1)));
        assert_eq!(too_few_within(Some(RESERVE + 1)), None);
        assert_eq!(too_few_within(Some(256)), None);
        assert_eq!(too_few_within(None), None, "no limit to fall short of");
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
