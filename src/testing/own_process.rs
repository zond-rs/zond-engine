// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Running one test in a process of its own
//!
//! A test binary runs its tests side by side in one process, and some tests
//! reach past their own share of it. One that fills the process's descriptor
//! table takes every test beside it down with it. One that scans all of
//! loopback's ports reaches every service the tests beside it stand up, and
//! its connections are this process's, which is the one thing those services
//! tell their own test's pass by; see [`loopback`](super::loopback). Such a
//! test re-runs its binary on itself alone and runs its body there.

/// The variable a re-run finds itself under, naming the test it is.
const OWN_PROCESS: &str = "ZOND_TEST_IN_OWN_PROCESS";

/// Whether this is the process the test `name`, in the module `module` (its
/// `module_path!()`), should run its body in.
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
