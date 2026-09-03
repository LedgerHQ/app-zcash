//! Measurement of the heap space the allocator can still serve.
//!
//! The PCZT parser keeps one signing record per action alive for a whole session, so how many
//! actions a transaction may carry is settled by what the heap still holds once the bundles are
//! parsed. Nothing reports that today: the SDK's debug instruction measures the call stack, and the
//! allocator keeps its accounting to itself. Asking it for blocks is what yields the figure without
//! reaching into it.
//!
//! Built only under the `heap_probe` feature, which a released application never enables. The
//! figure moves with how many shielded outputs decrypted under the user's viewing key and how much
//! memo text the review kept — both of which the wire format withholds from the host on purpose, so
//! answering this over APDU is acceptable on a measurement build and on no other.

use alloc::vec::Vec;

/// Whether the allocator can currently serve one block of `bytes`.
///
/// The block is released before returning, so a sequence of calls samples one heap state instead of
/// consuming it. Releasing is not the same as leaving the allocator untouched, though: a
/// measurement taken while a session still has allocations to make can move where the next of them
/// lands, which is why one is taken once a session has made them all.
fn is_available(bytes: usize) -> bool {
    let mut block = Vec::<u8>::new();
    block.try_reserve_exact(bytes).is_ok()
}

/// One past the largest heap the SDK accepts, `HEAP_SIZE` being capped at 24576 bytes. No block can
/// exceed the heap holding it, so the search starts already knowing it is refused, and never asks
/// the allocator for a size no device could serve.
const HEAP_CEILING: usize = 24577;

/// Size in bytes of the largest single block the allocator can still serve.
///
/// Narrows the interval between a size known to be served and one known to be refused by halving.
///
/// A contiguous block is the figure that governs the parser, not the sum of the free space: a `Vec`
/// outgrowing its capacity must be handed one contiguous block, so a heap holding twice as much in
/// scattered fragments does not serve it.
pub fn largest_available_block() -> usize {
    if !is_available(1) {
        return 0;
    }

    // Held from here on: `fits` is available, `beyond` is not.
    let mut fits = 1usize;
    let mut beyond = HEAP_CEILING;

    while beyond - fits > 1 {
        let midpoint = fits + (beyond - fits) / 2;
        if is_available(midpoint) {
            fits = midpoint;
        } else {
            beyond = midpoint;
        }
    }

    fits
}
