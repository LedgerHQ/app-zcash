/*****************************************************************************
 *   Ledger App Boilerplate Rust.
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/
use crate::{
    AppSW,
    app_ui::load_glyph,
    consts::{ZCASH_DECIMALS_DIV, ZCASH_TICKER},
};

use alloc::{string::String, vec::Vec};
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{Field, NbglReview, nbgl_tag_value::TagValue};

use crate::tx::{TransferType, TxOutput};
use crate::utils::ensure_heap_headroom;
use alloc::boxed::Box;
use core::fmt;
use ledger_device_sdk::sys::nbgl_contentTagValue_t;

/// Heap the review builder takes for its three titles and their empty C strings, with margin.
const REVIEW_TITLES_HEAP: usize = 160;

/// Like `format!`, but fails instead of exiting the app when the heap cannot serve it.
pub(super) fn try_format(args: fmt::Arguments<'_>) -> Result<String, AppSW> {
    struct Length(usize);
    impl fmt::Write for Length {
        fn write_str(&mut self, text: &str) -> fmt::Result {
            self.0 += text.len();
            Ok(())
        }
    }

    let mut length = Length(0);
    fmt::write(&mut length, args).map_err(|_| AppSW::TechnicalProblem)?;
    let mut text = String::new();
    text.try_reserve_exact(length.0)
        .map_err(|_| AppSW::NotEnoughMemorySpace)?;
    fmt::write(&mut text, args).map_err(|_| AppSW::TechnicalProblem)?;
    Ok(text)
}

fn format_zec_amount(amount: u64) -> Result<String, AppSW> {
    // ZEC has 8 decimal places
    let whole = amount / ZCASH_DECIMALS_DIV;
    let fractional = amount % ZCASH_DECIMALS_DIV;
    try_format(format_args!("{}.{:08} {}", whole, fractional, ZCASH_TICKER))
}

/// A request rounded up to the allocator's 8-byte granularity.
const fn heap_block(bytes: usize) -> usize {
    bytes.next_multiple_of(8)
}

/// Heap `NbglReview::show` takes for `fields`; it exits the app on allocation failure.
/// The heap is first-fit with no block header, so one free block this large serves the whole build.
fn review_build_heap(fields: &[Field]) -> usize {
    let count = fields.len();
    let strings: usize = fields
        .iter()
        .map(|field| heap_block(field.name.len() + 1) + heap_block(field.value.len() + 1))
        .sum();

    heap_block(count * size_of::<TagValue>())
        // The SDK's `CField`: name and value C strings.
        + heap_block(count * size_of::<(Box<[u8]>, Box<[u8]>)>())
        + strings
        + 2 * heap_block(count * size_of::<Option<usize>>())
        + heap_block(count * size_of::<nbgl_contentTagValue_t>())
}

/// Display transaction outputs, fees and validity window for user confirmation.
///
/// `transfer_type` classifies the flow (public, shielding, deshielding, private
/// or mixed) and is shown as the review subtitle so the user can tell apart the
/// involved value pools.
///
/// `expiry_height` is always shown, including when it is zero: zero means the
/// transaction never expires, which is the widest possible window for it to be
/// broadcast and therefore the case the user most needs to see. `locktime` is
/// shown only when set, since zero constrains nothing.
pub fn ui_display_tx(
    comm: &mut Comm,
    outputs: &[TxOutput],
    fees: u64,
    transfer_type: TransferType,
    locktime: u32,
    expiry_height: u32,
) -> Result<bool, AppSW> {
    // Allocations here are fallible or pre-bounded: the host controls the review's size.
    let fees_str = format_zec_amount(fees)?;
    let locktime_str = try_format(format_args!("{locktime}"))?;
    let expiry_str = if expiry_height == 0 {
        try_format(format_args!("Never expires"))?
    } else {
        try_format(format_args!("{expiry_height}"))?
    };

    let displayed = outputs.iter().filter(|output| !output.is_change).count();
    let memos = outputs
        .iter()
        .filter(|output| !output.is_change && output.memo.is_some())
        .count();

    // Build name and value strings
    let mut name_strs = Vec::new();
    name_strs
        .try_reserve_exact(displayed)
        .map_err(|_| AppSW::NotEnoughMemorySpace)?;
    let mut value_strs = Vec::new();
    value_strs
        .try_reserve_exact(displayed)
        .map_err(|_| AppSW::NotEnoughMemorySpace)?;

    // Only display non-change outputs
    for (idx, output) in outputs
        .iter()
        .filter(|output| !output.is_change)
        .enumerate()
    {
        // Make it 1-based for display
        let idx = idx + 1;
        name_strs.push((
            try_format(format_args!("Output #{idx} amount"))?,
            // An own-account output shows its ZIP 32 account index instead of an address.
            if output.own_account.is_some() {
                try_format(format_args!("Output #{idx} account"))?
            } else {
                try_format(format_args!("Output #{idx} address"))?
            },
            // The memo carries the index of its output, and is shown right after it below. Grouped
            // at the end under a label naming only the kind, a memo could not be traced back to a
            // recipient — an output without one contributes no field, so position identifies
            // nothing, and two memos exchanged between two outputs would draw the same screen.
            output
                .memo
                .as_ref()
                .map(|memo| try_format(format_args!("Output #{idx} {}", memo.label)))
                .transpose()?,
        ));

        value_strs.push((
            format_zec_amount(output.amount)?,
            output
                .own_account
                .map(|account| try_format(format_args!("Account index {account}")))
                .transpose()?,
        ));
    }

    // Two per output, its memo, then fees, lock time and expiry.
    let mut my_fields = Vec::new();
    my_fields
        .try_reserve_exact(2 * displayed + memos + 3)
        .map_err(|_| AppSW::NotEnoughMemorySpace)?;

    // Only display non-change outputs
    for (idx, output) in outputs
        .iter()
        .filter(|output| !output.is_change)
        .enumerate()
    {
        my_fields.push(Field {
            name: name_strs[idx].0.as_str(),
            value: value_strs[idx].0.as_str(),
        });
        my_fields.push(Field {
            name: name_strs[idx].1.as_str(),
            value: value_strs[idx]
                .1
                .as_deref()
                .unwrap_or(output.address.as_str()),
        });

        if let (Some(label), Some(memo)) = (name_strs[idx].2.as_ref(), output.memo.as_ref()) {
            my_fields.push(Field {
                name: label.as_str(),
                value: memo.value.as_str(),
            });
        }
    }

    my_fields.push(Field {
        name: "Fees",
        value: fees_str.as_str(),
    });

    if locktime != 0 {
        my_fields.push(Field {
            name: "Lock time",
            value: locktime_str.as_str(),
        });
    }

    my_fields.push(Field {
        name: "Expiry height",
        value: expiry_str.as_str(),
    });

    ensure_heap_headroom(REVIEW_TITLES_HEAP)?;
    let review: NbglReview = NbglReview::new()
        .titles(
            "Review transaction to send ZEC",
            transfer_type.subtitle(),
            "Sign transaction",
        )
        .glyph(load_glyph());

    ensure_heap_headroom(review_build_heap(&my_fields))?;
    Ok(review.show(comm, &my_fields))
}
