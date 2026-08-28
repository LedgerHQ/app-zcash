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

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::String;

use ledger_device_sdk::nbgl::{Field, NbglAddressReview};

use crate::{AppSW, app_ui::load_glyph};

fn display_address(review_title: &str, addr: &str) -> Result<bool, AppSW> {
    // Display the address confirmation screen.
    Ok(NbglAddressReview::new()
        .glyph(load_glyph())
        .review_title(review_title)
        .show(addr))
}

pub fn ui_display_pk(addr: &str) -> Result<bool, AppSW> {
    // Display the address confirmation screen.
    display_address("Verify address", addr)
}

pub fn ui_display_shielded_address(
    shielded_addr: &str,
    transparent_addr: &str,
) -> Result<bool, AppSW> {
    let public_address = [Field {
        name: "Public Address",
        value: transparent_addr,
    }];

    Ok(NbglAddressReview::new()
        .glyph(load_glyph())
        .review_title("Verify Zcash addresses")
        .review_subtitle("Private address")
        .set_tag_value_list(&public_address)
        .show(shielded_addr))
}

// Viewing keys can be long, shorten them for better display.
fn shorten_fvk_to_display<'s>(
    viewing_key: &'s str,
    shortened_len: usize,
    prefix_len: usize,
    ellipsis: &str,
) -> Cow<'s, str> {
    if viewing_key.len() <= shortened_len {
        return Cow::Borrowed(viewing_key);
    }

    let suffix_len = shortened_len - prefix_len;

    let mut shortened = String::with_capacity(shortened_len);
    shortened.push_str(&viewing_key[..prefix_len]);
    shortened.push_str(ellipsis);
    shortened.push_str(&viewing_key[viewing_key.len() - suffix_len..]);

    Cow::Owned(shortened)
}

/// Confirm the export of a viewing key, naming the account it opens.
///
/// The key itself is opaque and shortened for the screen, so on its own it tells the holder
/// nothing about what is leaving the device: a host asking for a different account than the one
/// the user opened in their wallet drew exactly the same prompt. The account number is the whole
/// of what varies — validation pins the purpose and the coin type, both trees put the account at
/// the same depth, and the two paths of a unified key must agree on it — so naming it states the
/// full scope of the export.
fn ui_display_fvk(review_title: &str, fvk: &str, account: u32) -> Result<bool, AppSW> {
    let viewing_key = if cfg!(any(target_os = "nanosplus", target_os = "nanox")) {
        const ELLIPSIS: &str = "\n ... \n";
        const ROW_LEN: usize = 18;
        const SHORTENED_DISPLAY_LEN: usize = ROW_LEN * 3 * 3 - ROW_LEN;
        const PREFIX_LEN: usize = ROW_LEN * 4;

        shorten_fvk_to_display(fvk, SHORTENED_DISPLAY_LEN, PREFIX_LEN, ELLIPSIS)
    } else {
        const ELLIPSIS: &str = " ... ";
        const SHORTENED_DISPLAY_LEN: usize = if cfg!(target_os = "apex_p") { 125 } else { 132 };
        const PREFIX_LEN: usize = (SHORTENED_DISPLAY_LEN - ELLIPSIS.len()) / 2;

        shorten_fvk_to_display(fvk, SHORTENED_DISPLAY_LEN, PREFIX_LEN, ELLIPSIS)
    };

    let account_str = format!("#{account}");
    let account_field = [Field {
        name: "Account",
        value: account_str.as_str(),
    }];

    // Display the viewing key export confirmation screen.
    #[allow(unused_mut)]
    let mut review = NbglAddressReview::new()
        .glyph(load_glyph())
        .review_title(review_title)
        .set_tag_value_list(&account_field);

    #[cfg(not(any(target_os = "nanosplus", target_os = "nanox")))]
    {
        review = review.review_subtitle("This lets the connected wallet access your accounts info");
    }

    Ok(review.show(viewing_key.as_ref()))
}

pub fn ui_display_ufvk(ufvk: &str, account: u32) -> Result<bool, AppSW> {
    ui_display_fvk("Share Zcash Unified Full Viewing Key?", ufvk, account)
}

pub fn ui_display_orchard_fvk(orchard_fvk: &str, account: u32) -> Result<bool, AppSW> {
    ui_display_fvk(
        "Share Zcash Orchard Full Viewing Key?",
        orchard_fvk,
        account,
    )
}
