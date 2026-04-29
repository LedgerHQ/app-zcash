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
