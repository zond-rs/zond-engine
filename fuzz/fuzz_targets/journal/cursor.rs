// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! How far a scan got, which is the number a resumed scan trusts.
//!
//! A cursor is a watermark and the settled positions above it, and everything a
//! resume skips is decided by it. The failure it exists to prevent is a
//! watermark that advanced over a position nobody probed: a second sitting that
//! skips those targets, finds nothing there, and reports success. Nothing
//! downstream can detect that, which is why the arithmetic is worth attacking
//! directly rather than through a scan.
//!
//! ## The positions are crowded on purpose
//!
//! **Eight random bytes are a position no other position is ever adjacent to**,
//! and a cursor over those never advances its watermark past zero, never fills a
//! gap, and never runs `catch_up` at all — so a target that fed the input
//! straight in would exercise a `BTreeSet` insert and call it fuzzing. This is
//! the shape the crate's own notes name: a generator perfectly satisfying "it
//! returns" with input the code never reads.
//!
//! So positions are read as `u16` and folded into a window the first byte
//! chooses, between 64 and 4096 wide. Inside a window that small a few hundred
//! settlements collide, fill each other's gaps, and drive the watermark across
//! the set — which is the code this is aimed at.
//!
//! ## What is asserted
//!
//! - **The cursor agrees with the set of positions it was given**, at every
//!   position in the window and not only the ones settled. A position it claims
//!   is settled and never was is the silent-skip failure itself.
//! - **The watermark only ever moves forward**, and never past a position that
//!   was not settled.
//! - **A checkpoint answers what the cursor it came from answers**, since it is
//!   what a resume actually reads, and it binary-searches a list where the
//!   cursor searches a set.
//! - **A checkpoint resumed from is the same checkpoint**, which is what makes a
//!   scan resumed twice count what a scan resumed once does.
//! - **`Checkpoint::new` normalises**, because the fields are public and a
//!   caller keeping journals somewhere other than a directory comes through it.
//! - **`remaining` yields the unsettled positions and no others**, in order.
//!   That is the whole of what a second sitting scans.

#![no_main]

use std::collections::BTreeSet;
use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use zond_engine::journal::cursor::{Checkpoint, Cursor};
use zond_engine::model::port::Protocol;
use zond_engine::model::target::Target;

fuzz_target!(|data: &[u8]| {
    let Some((&choice, positions)) = data.split_first() else {
        return;
    };

    // 64 to 4096, so a few hundred settlements are dense enough to fill each
    // other's gaps. See the module documentation.
    let window = 1u64 << (6 + u32::from(choice % 7));

    let mut cursor = Cursor::new();
    let mut settled: BTreeSet<u64> = BTreeSet::new();
    let mut watermark = 0;

    for pair in positions.as_chunks::<2>().0 {
        let position = u64::from(u16::from_be_bytes(*pair)) % window;

        cursor.settle(position);
        settled.insert(position);

        assert!(
            cursor.watermark() >= watermark,
            "the watermark went backwards, from {watermark} to {}",
            cursor.watermark()
        );
        watermark = cursor.watermark();

        assert!(
            (0..watermark).all(|below| settled.contains(&below)),
            "the watermark reached {watermark} over a position nothing settled"
        );
    }

    for position in 0..window {
        assert_eq!(
            cursor.is_settled(position),
            settled.contains(&position),
            "the cursor and the settlements disagree about position {position}"
        );
    }
    assert_eq!(cursor.settled_count(), settled.len() as u64);
    assert_eq!(cursor.pending_count(), cursor.settled_above().count());

    let checkpoint = cursor.checkpoint();
    for position in 0..window {
        assert_eq!(
            checkpoint.is_settled(position),
            cursor.is_settled(position),
            "a checkpoint and the cursor it came from disagree about {position}"
        );
    }

    assert_eq!(
        Cursor::from_checkpoint(&checkpoint).checkpoint(),
        checkpoint,
        "a checkpoint resumed from is not the checkpoint that was written"
    );

    // The fields are public, so this is the constructor that cannot be built
    // wrong; what it establishes is what `is_settled` binary-searches on.
    let rebuilt = Checkpoint::new(
        checkpoint.watermark,
        checkpoint.settled_above.iter().copied(),
    );
    assert_eq!(rebuilt, checkpoint, "a normalised checkpoint moved");
    assert!(
        rebuilt
            .settled_above
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "the settled list is not ascending and deduplicated"
    );
    assert!(
        rebuilt
            .settled_above
            .iter()
            .all(|position| *position >= rebuilt.watermark),
        "a position below the watermark is being carried above it"
    );

    // What the second sitting walks. `remaining` numbers the *original* plan, so
    // the positions have to come back as they were, minus what settled.
    let ip: IpAddr = "192.0.2.1".parse().expect("an address");
    let plan: Vec<Target> = (0..window)
        .map(|position| Target {
            ip,
            port: position as u16,
            protocol: Protocol::Tcp,
        })
        .collect();

    let left: Vec<u64> = checkpoint
        .remaining(plan)
        .map(|target| target.position)
        .collect();
    let expected: Vec<u64> = (0..window).filter(|p| !settled.contains(p)).collect();
    assert_eq!(
        left, expected,
        "a resumed sitting would walk something other than what is left"
    );
});
