// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How many sockets the connect paths may hold at once
//!
//! Every socket is a file descriptor, and a Unix process may hold only so many:
//! its soft `RLIMIT_NOFILE`, 256 in a macOS Terminal and 1,024 in most Linux
//! shells. Past it, opening a socket fails with `EMFILE` before anything is
//! sent, and a connect sweep keeping thousands in flight reaches it at once.
//!
//! The limit belongs to the process, so the budget here does too: one gate,
//! [`gate`], that every connect probe takes a permit from before it opens a
//! socket and keeps for as long as the socket lives. Sized per scan, two scans
//! in one process would each take what fits and together take twice that, and
//! an application running several at once, or a test harness running them in
//! parallel, would find its own files refused.
//!
//! The gate holds half the soft limit. The other half is the rest of the
//! process's: the runtime's own descriptors, capture handles, the journal, the
//! connections a detection makes beside the probe that found the port, and
//! whatever the application embedding the engine has open. A table that fills
//! anyway, from any of those, is not the engine's to prevent, and a connect
//! probe that is refused a socket waits for one rather than reading the refusal
//! as an answer; see [`exhausted`].
//!
//! The limit is read and never raised. Raising it is a decision about the
//! whole process, which a library does not own: the soft limit is inherited by
//! every child the application starts, and a program still built on `select`
//! cannot watch a descriptor numbered past 1,024, which is why shells default
//! to that number in the first place. An application that wants a faster sweep
//! raises its own limit before its first scan, and the gate is sized from what
//! it finds then.

use std::io;
use std::sync::OnceLock;

use tokio::sync::{Semaphore, SemaphorePermit};

/// One socket's share of the gate, held for as long as the socket is.
pub(crate) type Descriptor = SemaphorePermit<'static>;

/// The gate every connect probe in this process takes a [`Descriptor`] from.
///
/// Sized once, from the soft limit in force when the first probe asks, so a
/// limit an application raises before its first scan is the one that counts.
pub(crate) fn gate() -> &'static Semaphore {
    static GATE: OnceLock<Semaphore> = OnceLock::new();
    GATE.get_or_init(|| Semaphore::new(budget()))
}

/// How many sockets the connect probes of this process may hold at once.
pub(crate) fn budget() -> usize {
    budget_within(soft_limit())
}

/// The budget a process with a soft descriptor limit of `soft` gives its
/// connect probes: half of it, and no bound at all where there is no limit to
/// read.
fn budget_within(soft: Option<usize>) -> usize {
    soft.map_or(Semaphore::MAX_PERMITS, |soft| {
        (soft / 2).clamp(1, Semaphore::MAX_PERMITS)
    })
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
        assert_eq!(budget_within(Some(1)), 1, "a probe always has one socket");
        assert_eq!(budget_within(None), Semaphore::MAX_PERMITS);
        assert_eq!(budget_within(Some(usize::MAX)), Semaphore::MAX_PERMITS);
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
