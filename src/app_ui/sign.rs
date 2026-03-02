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

use alloc::{format, string::String, vec::Vec};
use ledger_device_sdk::nbgl::{Field, NbglReview};

use crate::tx::TxOutput;

fn format_zec_amount(amount: u64) -> String {
    // ZEC has 8 decimal places
    let whole = amount / ZCASH_DECIMALS_DIV;
    let fractional = amount % ZCASH_DECIMALS_DIV;
    format!("{}.{:08} {}", whole, fractional, ZCASH_TICKER)
}

/// Display transaction outputs and fees for user confirmation.
pub fn ui_display_tx(outputs: &[TxOutput], fees: u64) -> Result<bool, AppSW> {
    let fees_str = format_zec_amount(fees);

    // Build name and value strings
    let mut name_strs = Vec::new();
    let mut value_strs = Vec::new();

    // Only display non-change outputs
    for (idx, output) in outputs
        .iter()
        .filter(|output| !output.is_change)
        .enumerate()
    {
        // Make it 1-based for display
        let idx = idx + 1;
        name_strs.push((
            format!("Output #{idx} amount"),
            format!("Output #{idx} address"),
        ));

        value_strs.push(format_zec_amount(output.amount));
    }

    // Define transaction review fields
    let mut my_fields = Vec::new();

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
    }

    my_fields.push(Field {
        name: "Fees",
        value: fees_str.as_str(),
    });

    // Create NBGL review. Maximum number of fields and string buffer length can be customized
    // with constant generic parameters of NbglReview. Default values are 32 and 1024 respectively.
    let review: NbglReview = NbglReview::new()
        .titles("Review transaction", "", "Sign transaction")
        .glyph(load_glyph());

    Ok(review.show(&my_fields))
}
