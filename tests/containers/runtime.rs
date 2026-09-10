// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which container runtime starts the targets.
//!
//! Podman first, and the reason is not preference. Docker's socket is owned by
//! the `docker` group, and membership in it is root on the machine: anything
//! that can talk to the daemon can start a container with the host filesystem
//! mounted. Asking whoever tests a security tool to grant themselves that in
//! order to run one tier is a poor trade. Rootless podman needs no daemon and no
//! group, and its command line is close enough that one driver serves both.
//!
//! # What rootless costs
//!
//! A host port below 1024. `net.ipv4.ip_unprivileged_port_start` is 1024 by
//! default, so a target published on its registered number is refused before any
//! container starts. Only `openldap` in the manifest needs one, and it needs it
//! because the corpus keys the root DSE search on 389; published anywhere else
//! the scan asks a directory for a web page and it says nothing.
//!
//! Two ways out, and neither is this file's to choose: lower the sysctl, or
//! install Docker and let the daemon bind it. [`Runtime::privileged_port_hint`]
//! is what says so when it happens.
//!
//! # Image names
//!
//! Podman refuses a name with no registry in it. Docker resolves one silently
//! against Docker Hub, which is the same answer arrived at by a search order
//! that lives in a configuration file rather than in the manifest.
//! [`Runtime::qualify`] settles it for both by naming the registry, so what the
//! manifest pins is an image and where it came from.

#![allow(dead_code)]

use std::process::Command;
use std::sync::OnceLock;

/// A container runtime this machine has, and can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    Podman,
    Docker,
}

impl Runtime {
    /// The runtime to use, or `None` when neither is installed and answering.
    ///
    /// Answering rather than merely present: a Docker binary with no daemon
    /// behind it is the common case on a workstation, and it fails at `run`
    /// with a message about the socket rather than at detection.
    pub fn detect() -> Option<Self> {
        static FOUND: OnceLock<Option<Runtime>> = OnceLock::new();
        *FOUND.get_or_init(|| {
            [Runtime::Podman, Runtime::Docker]
                .into_iter()
                .find(|runtime| runtime.answers())
        })
    }

    /// The binary this runtime is driven through.
    pub fn binary(self) -> &'static str {
        match self {
            Runtime::Podman => "podman",
            Runtime::Docker => "docker",
        }
    }

    /// A command against this runtime.
    pub fn command(self) -> Command {
        Command::new(self.binary())
    }

    /// An image reference with its registry named.
    ///
    /// A first component carrying a dot or a colon is already a host, so it is
    /// left alone; a bare single name is an official image and lives under
    /// `library/`. Applied for both runtimes rather than only the one that
    /// insists, because a scanner's own test suite should say where it is
    /// pulling software from.
    pub fn qualify(image: &str) -> String {
        let host = image.split('/').next().unwrap_or_default();
        match image.contains('/') {
            true if host.contains('.') || host.contains(':') || host == "localhost" => {
                image.to_string()
            }
            true => format!("docker.io/{image}"),
            false => format!("docker.io/library/{image}"),
        }
    }

    /// Whether it is installed and its backend is up.
    fn answers(self) -> bool {
        self.command()
            .arg("info")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// What to say when a host port below 1024 is refused.
    ///
    /// Empty for anything else, so a caller can append it to a failure without
    /// deciding whether it applies.
    pub fn privileged_port_hint(self, host_port: u16, stderr: &str) -> String {
        let refused = stderr.contains("Permission denied") || stderr.contains("permission denied");
        if self != Runtime::Podman || host_port >= 1024 || !refused {
            return String::new();
        }
        format!(
            "\n\nRootless podman cannot bind host port {host_port}, and this target has to have \
             that number. Either raise the limit with\n    \
             sudo sysctl -w net.ipv4.ip_unprivileged_port_start={host_port}\n\
             or install Docker, whose daemon binds it."
        )
    }
}
