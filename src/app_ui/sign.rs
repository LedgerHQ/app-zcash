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
use ledger_device_sdk::nbgl::{Field, NbglReview};

use crate::tx::{TransferType, TxOutput};
use crate::utils::ensure_heap_headroom;
use alloc::boxed::Box;
use core::fmt;
use ledger_device_sdk::sys::nbgl_contentTagValue_t;

/// Heap the review builder takes before any field is copied: an empty C string for each of its three
/// titles, then the three titles themselves. Each block is a few dozen bytes once rounded to the
/// allocator's granularity; this covers the longest subtitle with room to spare.
const REVIEW_TITLES_HEAP: usize = 160;

/// Format `args` into a string whose one allocation is fallible.
///
/// `format!` exits the application when the heap cannot serve it. Measuring the text first lets that
/// allocation be reserved exactly, so writing the text never grows the string.
fn try_format(args: fmt::Arguments<'_>) -> Result<String, AppSW> {
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

/// A heap block the size of the C string `CString::new(text)` allocates: the text and its nul.
fn c_string_block(text: &str) -> Result<Box<[u8]>, AppSW> {
    let mut block = Vec::new();
    block
        .try_reserve_exact(text.len() + 1)
        .map_err(|_| AppSW::NotEnoughMemorySpace)?;
    block.resize(text.len() + 1, 0);
    Ok(block.into_boxed_slice())
}

/// Make, fallibly and in the same order, the allocations `NbglReview::show` is about to make
/// infallibly, then release them.
///
/// The review copies every field into a pair of C strings gathered in one list, then grows a list of
/// pointers to them one field at a time, and a failed allocation there exits the application. How
/// much that takes depends on where the heap is fragmented, not only on the text, so no estimate
/// bounds it. The heap is a first-fit list that merges what is freed: releasing the rehearsal
/// restores it, and the same requests are then served the same way, so the rehearsal succeeding is
/// what proves the review will.
fn rehearse_review_allocations(fields: &[Field]) -> Result<(), AppSW> {
    // The SDK's `CField`: a field's name and value as C strings, side by side.
    type CFieldBlocks = (Box<[u8]>, Box<[u8]>);

    let mut strings: Vec<CFieldBlocks> = Vec::new();
    strings
        .try_reserve_exact(fields.len())
        .map_err(|_| AppSW::NotEnoughMemorySpace)?;
    for field in fields {
        strings.push((c_string_block(field.name)?, c_string_block(field.value)?));
    }

    let mut pairs: Vec<nbgl_contentTagValue_t> = Vec::new();
    for _ in fields {
        pairs
            .try_reserve(1)
            .map_err(|_| AppSW::NotEnoughMemorySpace)?;
        pairs.push(nbgl_contentTagValue_t::default());
    }
    Ok(())
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
    // Every allocation the review makes is fallible or rehearsed: the review is the last step before
    // signing, and the host chooses how much it holds.
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
            try_format(format_args!("Output #{idx} address"))?,
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

        value_strs.push(format_zec_amount(output.amount)?);
    }

    // Define transaction review fields: two per output, its memo, then fees, lock time and expiry.
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
            value: value_strs[idx].as_str(),
        });
        my_fields.push(Field {
            name: name_strs[idx].1.as_str(),
            value: &output.address,
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

    rehearse_review_allocations(&my_fields)?;
    Ok(review.show(comm, &my_fields))
}
