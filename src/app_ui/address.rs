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
use alloc::string::String;

use ledger_device_sdk::nbgl::NbglAddressReview;

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

pub fn ui_display_unified_address(addr: &str) -> Result<bool, AppSW> {
    // Display the unified address confirmation screen.
    display_address("Verify Orchard UAddress", addr)
}

// UFVK can be 300-400 chars long, shorten it for better display
fn shorten_ufvk_to_display<'s>(
    ufvk: &'s str,
    shortened_len: usize,
    prefix_len: usize,
    ellipsis: &str,
) -> Cow<'s, str> {
    if ufvk.len() <= shortened_len {
        return Cow::Borrowed(ufvk);
    }

    let suffix_len = shortened_len - prefix_len;

    let mut shortened = String::with_capacity(shortened_len);
    shortened.push_str(&ufvk[..prefix_len]);
    shortened.push_str(ellipsis);
    shortened.push_str(&ufvk[ufvk.len() - suffix_len..]);

    Cow::Owned(shortened)
}

pub fn ui_display_ufvk(ufvk: &str) -> Result<bool, AppSW> {
    let ufvk = if cfg!(any(target_os = "nanosplus", target_os = "nanox")) {
        const ELLIPSIS: &str = "\n ... \n";
        const ROW_LEN: usize = 18;
        const SHORTENED_DISPLAY_LEN: usize = ROW_LEN * 3 * 3 - ROW_LEN;
        const PREFIX_LEN: usize = ROW_LEN * 4;

        shorten_ufvk_to_display(ufvk, SHORTENED_DISPLAY_LEN, PREFIX_LEN, ELLIPSIS)
    } else {
        const ELLIPSIS: &str = " ... ";
        const SHORTENED_DISPLAY_LEN: usize = if cfg!(target_os = "apex_p") { 125 } else { 132 };
        const PREFIX_LEN: usize = (SHORTENED_DISPLAY_LEN - ELLIPSIS.len()) / 2;

        shorten_ufvk_to_display(ufvk, SHORTENED_DISPLAY_LEN, PREFIX_LEN, ELLIPSIS)
    };

    // Display the UFVK export confirmation screen.
    #[allow(unused_mut)]
    let mut review = NbglAddressReview::new()
        .glyph(load_glyph())
        .review_title("Share Zcash Unified Full Viewing Key?");

    #[cfg(not(any(target_os = "nanosplus", target_os = "nanox")))]
    {
        review = review.review_subtitle("This lets the connected wallet access your accounts info");
    }

    Ok(review.show(ufvk.as_ref()))
}
