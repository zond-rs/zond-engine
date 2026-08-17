// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end check for forward name resolution.
//!
//! Resolution is the one part of the engine a unit test cannot fully exercise:
//! `.local` names are answered by whatever responders share the segment, and a
//! global name by whatever the host's resolver returns, neither of which a test
//! can stand in for without becoming a test of its own fake. This puts real
//! names on the real network and prints what came back, so the two paths can be
//! seen working against a machine that actually has an `example.com` and a
//! `raspberrypi.local` on it.
//!
//! It needs a network but **no privileges**: resolution is ordinary UDP, unicast
//! to the system resolver and multicast to the mDNS group, so nothing here opens
//! a raw socket.
//!
//! Each argument is resolved on its own, so the routing is visible — which name
//! went to unicast, which to multicast, which single-label name fell back to
//! `.local`. Then every argument is resolved together through
//! [`resolve::to_set`], the two-pass path a discovery front end uses, to show the
//! whole list folded into one address set.
//!
//! ```text
//! cargo bench --no-run --bench resolve
//! target/release/deps/resolve-<hash> example.com raspberrypi.local nas
//! ```
//!
//! Built as a bench rather than an example because it takes a network and reads
//! arguments, which the crate's examples deliberately never do. Run the binary
//! directly rather than through `cargo bench`, which would pass its own
//! arguments to this `harness = false` target.

use std::time::Instant;

use zond_engine::resolve::{self, Resolver};

#[tokio::main]
async fn main() {
    // The engine reports a missing resolver configuration and a failed mDNS
    // send at WARN, and installs no subscriber of its own. Without one here,
    // this instrument would resolve names while discarding the one record of
    // why a name that should have resolved did not.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .without_time()
        .init();

    let names: Vec<String> = std::env::args().skip(1).collect();
    if names.is_empty() {
        eprintln!("usage: resolve <name>...\n  e.g. resolve example.com raspberrypi.local nas");
        std::process::exit(2);
    }

    let resolver = Resolver::from_system();

    println!("Resolving {} name(s), one at a time:", names.len());
    for name in &names {
        let started = Instant::now();
        let addresses = resolver.resolve(name).await;
        let elapsed = started.elapsed();

        if addresses.is_empty() {
            println!("  {name:<28} -> (nothing answered)   {elapsed:.0?}");
        } else {
            let rendered = addresses
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!("  {name:<28} -> {rendered}   {elapsed:.0?}");
        }
    }

    // The path a discovery front end takes: parse a whole list, resolve every
    // name in it concurrently, and fold the results into one address set. No
    // keyword or zone resolver is supplied, so `lan` or a `%interface` suffix in
    // the arguments would be refused here rather than resolved.
    println!("\nThe same list through resolve::to_set (the discovery path):");
    match resolve::to_set(&names, None, None, &resolver).await {
        Ok(set) => {
            println!("  {} address(es):", set.len());
            for ip in set.iter() {
                println!("    {ip}");
            }
        }
        Err(e) => println!("  refused: {e}"),
    }
}
