/*****************************************************************************
 *   Ledger App Boilerplate Rust - Swap Feature
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

//! Swap Feature Implementation
//!
//! This module implements the "swap" feature, which allows the Ledger Exchange app
//! to call this coin app as a library to validate addresses and amounts before
//! signing swap transactions.
//!
//! ## Important Constraints
//!
//! When called as a library by the Exchange app (via `os_lib_call`), this code runs
//! under special constraints:
//!
//! - **No heap allocation** in `check_address` and `get_printable_amount`:
//!   The Exchange app shares BSS memory with the coin app. Writing to BSS (which
//!   includes heap allocations via `Vec`, `String`, etc.) will trigger integrity
//!   check failures and crash the device. Use stack-allocated types like arrays
//!   and `ArrayString` instead.
//!
//! - **BSS is reset** only before `sign_transaction`: The SDK calls `c_reset_bss()`
//!   before the signing phase, making heap allocation safe at that point.
//!
//! ## Swap Flow
//!
//! 1. **CHECK_ADDRESS**: Verify the destination address belongs to this device
//! 2. **GET_PRINTABLE_AMOUNT**: Format amounts for display (fees, totals)
//! 3. **SIGN_TRANSACTION**: Sign the transaction (UI bypass - already validated by Exchange)

use alloc::vec::Vec;
use arrayvec::ArrayString;
use core::fmt::Write;
use core::str;
use ledger_device_sdk::libcall::LibCallCommand;
use ledger_device_sdk::libcall::{
    self, SwapAppErrorCodeTrait,
    string::uint256_to_float,
    swap::{
        self, CheckAddressParams, CreateTxParams, PrintableAmountParams, SwapError,
        SwapErrorCommonCode, SwapResult,
    },
};
use ledger_device_sdk::log::{debug, error, info};

pub(crate) mod panic_handler;

#[cfg(feature = "legacy_path")]
mod legacy;

#[cfg(feature = "legacy_path")]
pub use legacy::get_check_address_params;

#[cfg(not(feature = "legacy_path"))]
pub use swap::get_check_address_params;

use crate::swap::panic_handler::{set_swap_panic_handler, swap_panic_handler};
use crate::tx::TxOutput;
use crate::utils::bip32_path::BIP32_BYTES_PER_SEGMENT;
use crate::utils::{Bip44CheckMode, check_bip44_compliance};
use crate::{
    consts::{ZCASH_DECIMALS, ZCASH_TICKER},
    utils::{
        base58_address::{Base58Address, ToBase58Address},
        bip32_path::Bip32Path,
        extended_public_key::ExtendedPublicKey,
    },
};
use alloc::{format, string::ToString};

/// Lower byte of the 2-byte swap error code; the upper byte is a
/// [`ledger_device_sdk::libcall::swap::SwapErrorCommonCode`]. Exchange maps every app error to
/// `IncorrectData` on the wire, so these codes serve this app's logs rather than the host.
/// Specification: the C SDK's `swap_error_code_helpers.h`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapAppErrorCode {
    /// The common code carries the whole message.
    Default = 0x00,
    /// Other error codes, don't hesitate to add your own for more granularity.
    AmountCastFail = 0x01,
    DestinationDecodeFail = 0x02,

    FailedToSerializeAddress = 0x04,
    FailedToDeriveAddress = 0x05,
    UnexpectedExternalOutputCount = 0x06,
    BufferOverflow = 0x07,
    UnsupportedDestinationExtraId = 0x08,
}

impl SwapAppErrorCodeTrait for SwapAppErrorCode {
    // Cast is safe as enum is #[repr(u8)]
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Validates the transaction to be signed against the Exchange's reference parameters: the amount and
/// the fee must match exactly, and the single external output must pay the swap destination. Only one
/// transaction type exists, so the type check is implicit.
pub fn check_swap_params(
    params: &CreateTxParams,
    outputs: &[TxOutput],
    fees: u64,
) -> Result<(), SwapError<SwapAppErrorCode>> {
    debug!("Swap mode detected");

    // The extra ID is where chains that need one carry the routing or deposit information their
    // destination address does not hold. Zcash has such a place — the encrypted memo of a shielded
    // output — but nothing here reads the field, and the swap path signs transparent outputs, which
    // have no memo at all. Approving a trade that asks for one and signing a transaction that
    // cannot carry it would send funds the provider has no way to attribute.
    if params.dest_address_extra_id_len != 0 {
        error!(
            "Swap destination carries an extra ID of {} bytes",
            params.dest_address_extra_id_len
        );
        return Err(SwapError::with_message(
            SwapErrorCommonCode::ErrorWrongDestination,
            SwapAppErrorCode::UnsupportedDestinationExtraId,
            "Destination extra ID is not supported".to_string(),
        ));
    }

    // In swap operation we can only have 1 "external" output
    let external_outputs: Vec<&TxOutput> = outputs.iter().filter(|out| !out.is_change).collect();
    if external_outputs.len() != 1 {
        error!(
            "Unexpected number of external outputs: {}",
            external_outputs.len()
        );
        return Err(SwapError::with_message(
            SwapErrorCommonCode::ErrorGeneric,
            SwapAppErrorCode::UnexpectedExternalOutputCount,
            format!(
                "Expected exactly 1 external output, found {}",
                external_outputs.len()
            ),
        ));
    }

    let output = external_outputs[0];

    // Validate amount
    // Parse amount (u64 from big-endian bytes, right aligned in 16-byte buffer)
    // Amount is stored in AMOUNT_BUF_SIZE (16 bytes) buffer, right-aligned big-endian
    let start = params.amount.len() - 8;

    // The eight low bytes hold every amount Zcash can express — the whole supply is four orders of
    // magnitude below `u64::MAX` — so anything above them is not an amount this transaction could
    // ever carry. Reading past them and keeping only the low half would compare the approved value
    // modulo 2^64, letting a swap approved for an unrepresentable amount be settled by whatever
    // small amount shares its low bytes.
    if params.amount[..start].iter().any(|byte| *byte != 0) {
        error!("Swap amount is not representable: {:?}", params.amount);
        return Err(SwapError::without_message(
            SwapErrorCommonCode::ErrorWrongAmount,
            SwapAppErrorCode::AmountCastFail,
        ));
    }

    let amount_bytes: [u8; 8] = params.amount[start..].try_into().map_err(|_| {
        SwapError::without_message(
            SwapErrorCommonCode::ErrorWrongAmount,
            SwapAppErrorCode::AmountCastFail,
        )
    })?;
    let swap_amount = u64::from_be_bytes(amount_bytes);

    if output.amount != swap_amount {
        error!(
            "Swap amount mismatch\n Tx: {:?}, Swap: {:?}",
            output.amount, swap_amount
        );
        // Error detected, we return the error with detailed message in common SDK defined format
        return Err(SwapError::with_message(
            SwapErrorCommonCode::ErrorWrongAmount,
            SwapAppErrorCode::Default,
            format!("Amount tx {} != swap {}", output.amount, swap_amount),
        ));
    }

    // Validate fees
    // Parse fee (u64 from big-endian bytes, right aligned in 16-byte buffer)
    let start = params.fee_amount.len() - 8;

    if params.fee_amount[..start].iter().any(|byte| *byte != 0) {
        error!("Swap fee is not representable: {:?}", params.fee_amount);
        return Err(SwapError::without_message(
            SwapErrorCommonCode::ErrorWrongFees,
            SwapAppErrorCode::AmountCastFail,
        ));
    }

    let fee_bytes: [u8; 8] = params.fee_amount[start..].try_into().map_err(|_| {
        SwapError::without_message(
            SwapErrorCommonCode::ErrorWrongFees,
            SwapAppErrorCode::AmountCastFail,
        )
    })?;
    let swap_fee = u64::from_be_bytes(fee_bytes);

    if fees != swap_fee {
        error!("Swap fee mismatch\n Tx: {:?}, Swap: {:?}", fees, swap_fee);
        // Error detected, we return the error with detailed message in common SDK defined format
        return Err(SwapError::with_message(
            SwapErrorCommonCode::ErrorWrongFees,
            SwapAppErrorCode::Default,
            format!("Fees tx {} != swap {}", fees, swap_fee),
        ));
    }

    // Validate destination
    let swap_dest =
        str::from_utf8(&params.dest_address[..params.dest_address_len]).map_err(|_| {
            SwapError::with_message(
                SwapErrorCommonCode::ErrorWrongDestination,
                SwapAppErrorCode::DestinationDecodeFail,
                "Failed to UTF-8 decode destination str".to_string(),
            )
        })?;

    if output.address != swap_dest {
        error!(
            "Swap destination mismatch\n Tx: {:?}. Swap {:?}",
            &output.address, &swap_dest
        );
        return Err(SwapError::with_message(
            SwapErrorCommonCode::ErrorWrongDestination,
            SwapAppErrorCode::Default,
            format!(
                "Destination mismatch: tx {:?} != swap {:?}",
                output.address, swap_dest
            ),
        ));
    }

    info!("Swap validation success, bypassing UI\n");

    Ok(())
}

// --8<-- [start:swap_main]
/// Library-mode entry point, called by the Exchange app through `os_lib_call` with one of
/// `SwapCheckAddress`, `SwapGetPrintableAmount` or `SwapSignTransaction`.
pub fn swap_main(arg0: u32) {
    debug!("swap_main called\n");
    let cmd = libcall::get_command(arg0);

    match cmd {
        LibCallCommand::SwapCheckAddress => {
            debug!("Received SwapCheckAddress command\n");
            let mut params = get_check_address_params(arg0);
            let res = check_address(&params).unwrap_or_else(|e| {
                debug!("Swap error: {:?}", e);
                false
            });
            swap::swap_return(SwapResult::CheckAddressResult(&mut params, res as i32));
        }
        LibCallCommand::SwapGetPrintableAmount => {
            debug!("Received SwapGetPrintableAmount command\n");
            let mut params = swap::get_printable_amount_params(arg0);
            let amount_str = get_printable_amount(&params).unwrap_or_else(|e| {
                debug!("Swap error: {:?}", e);
                ArrayString::new()
            });
            swap::swap_return(SwapResult::PrintableAmountResult(
                &mut params,
                amount_str.as_str(),
            ))
        }
        LibCallCommand::SwapSignTransaction => {
            debug!("Received SwapSignTransaction command\n");
            let mut params = swap::sign_tx_params(arg0);

            // SAFETY: at this point, the app is initialized,
            // so we can safely set the panic handler
            unsafe {
                set_swap_panic_handler(swap_panic_handler);
            }

            // Call normal_main with Swap parameter set to enter the special Swap flow
            let success = crate::normal_main(Some(&params));
            if success {
                swap::swap_return(SwapResult::CreateTxResult(&mut params, 1));
            } else {
                swap::swap_return(SwapResult::CreateTxResult(&mut params, 0));
            }
        }
    }
}
// --8<-- [end:swap_main]

// --8<-- [start:check_address]
/// Verifies that the swap destination belongs to this device, so the Exchange app can rule out a
/// destination the user does not own.
///
/// Stack arrays only: BSS is shared with the Exchange app. Exchange sends the reference address as a
/// hex string over the C API, so the derived address is hex-encoded before comparison.
fn check_address(params: &CheckAddressParams) -> Result<bool, SwapAppErrorCode> {
    // `dpath_len` counts path components, not bytes; each is a big-endian u32.
    debug!("ENTERED_CHECK_ADDRESS\n");

    let bip32_path = Bip32Path::from_dpath(
        params.dpath_len,
        &params.dpath[..params.dpath_len * BIP32_BYTES_PER_SEGMENT],
    )
    .map_err(|_e| SwapAppErrorCode::FailedToDeriveAddress)?;

    // Same prefix restriction the APDU key-export path applies. Exchange is a trusted caller, so
    // this is defense in depth — but the path it forwards originates with the host, and refusing an
    // out-of-prefix one here costs nothing.
    if !check_bip44_compliance(&bip32_path, Bip44CheckMode::PrefixOnly) {
        error!("Swap check_address path outside the app's derivation prefixes");
        return Err(SwapAppErrorCode::FailedToDeriveAddress);
    }

    let extended_public_key = ExtendedPublicKey::try_from(&bip32_path)
        .map_err(|_e| SwapAppErrorCode::FailedToDeriveAddress)?;

    let compressed_key_hash = &extended_public_key
        .compressed_public_key_hash160()
        .map_err(|_e| SwapAppErrorCode::FailedToDeriveAddress)?;
    let base58_address = Base58Address::from_public_key_hash(compressed_key_hash)
        .map_err(|_e: crate::AppSW| SwapAppErrorCode::FailedToDeriveAddress)?;

    let received_address = core::str::from_utf8(&params.ref_address[..params.ref_address_len])
        .map_err(|_| SwapAppErrorCode::FailedToSerializeAddress)?;

    // Compare addresses
    let derived_address = base58_address.as_str();
    if derived_address == received_address {
        info!("Check address successful, derived and received addresses match\n");
        Ok(true) // Success
    } else {
        error!(
            "Derived and received addresses do NOT match!\n Derived address: {:?}. Reference (hex): {:?} \n",
            derived_address, received_address
        );

        Ok(false) // Failure
    }
}

// --8<-- [end:check_address]

// --8<-- [start:get_printable_amount]
/// Formats an amount as `"ZEC {value}"` for the Exchange app's display.
///
/// `params.amount` is big-endian, right-aligned in a 16-byte buffer with the significant length in
/// `params.amount_len`. The result is an `ArrayString`: this runs under the BSS restrictions of
/// library mode, so no heap. `coin_config` is unused, the ticker being fixed.
fn get_printable_amount(
    params: &PrintableAmountParams,
) -> Result<ArrayString<40>, SwapAppErrorCode> {
    // The SDK formatting helpers take a right-aligned uint256.
    let mut amount_u256: [u8; 32] = [0; 32];
    let src_start = params.amount.len() - params.amount_len;
    let dst_start = 32 - params.amount_len;
    amount_u256[dst_start..].copy_from_slice(&params.amount[src_start..]);

    debug!("Amount bytes (u256): {:?} ", &amount_u256);

    // Use SDK helper to format amount with decimals
    let amount_str = uint256_to_float(&amount_u256, ZCASH_DECIMALS as usize);

    // Format as "{value} ZEC " using stack-allocated ArrayString
    let mut printable: ArrayString<40> = ArrayString::<40>::new();
    write!(&mut printable, "{} {}", amount_str.as_str(), ZCASH_TICKER)
        .map_err(|_| SwapAppErrorCode::BufferOverflow)?;

    debug!("Formatted amount: {:?} ", printable.as_str());

    Ok(printable)
}
