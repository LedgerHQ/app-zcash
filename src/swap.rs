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
    self,
    string::uint256_to_float,
    swap::{
        self, CheckAddressParams, CreateTxParams, PrintableAmountParams, SwapError,
        SwapErrorCommonCode, SwapResult,
    },
    SwapAppErrorCodeTrait,
};

pub(crate) mod panic_handler;

#[cfg(feature = "legacy_path")]
mod legacy;

#[cfg(feature = "legacy_path")]
pub use legacy::get_check_address_params;

#[cfg(not(feature = "legacy_path"))]
pub use swap::get_check_address_params;

use crate::swap::panic_handler::{set_swap_panic_handler, swap_panic_handler};
use crate::tx::TxOutput;
use crate::{
    consts::{ZCASH_DECIMALS, ZCASH_TICKER},
    log::{debug, error, info},
    utils::{
        base58_address::{Base58Address, ToBase58Address},
        bip32_path::Bip32Path,
        extended_public_key::ExtendedPublicKey,
    },
};
use alloc::{format, string::ToString};

/// Application-specific swap error codes.
///
/// This enum defines the lower byte of the 2-byte error code used in swap error responses.
/// It provides additional context and refinement to the common error codes defined in
/// [`ledger_device_sdk::libcall::swap::SwapErrorCommonCode`].
///
/// # Error Code Structure
///
/// The complete 2-byte error code is structured as:
/// - **Upper byte**: Common error code from `SwapErrorCommonCode` (e.g., `ErrorWrongAmount`)
/// - **Lower byte**: Application-specific code from this enum (for additional context)
///
/// # Usage
///
/// When returning a swap error, combine a common code with an app-specific code:
///
/// ```rust,ignore
/// use ledger_device_sdk::libcall::swap::SwapErrorCommonCode;
///
/// // Example: Amount validation failed, no app-specific refinement needed
/// comm.append(&[
///     SwapErrorCommonCode::ErrorWrongAmount as u8,
///     SwapAppErrorCode::Default as u8
/// ]);
/// comm.append(b"Amount mismatch: tx=1000, swap=2000");
/// ```
///
/// # Template Note
///
/// This is a template/placeholder enum. In a production application, you may want to add
/// specific error codes to provide more granular error information. For example:
///
/// ```rust,ignore
/// pub enum SwapAppErrorCode {
///     Default = 0x00,
///     AmountOverflow = 0x01,
///     AmountUnderflow = 0x02,
///     InvalidAddressChecksum = 0x03,
///     // ... add your application-specific codes
/// }
/// ```
///
/// Refer to the C SDK's `swap_error_code_helpers.h` for the specification.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapAppErrorCode {
    /// Default application error code (no specific refinement).
    ///
    /// Use this when the common error code from `SwapErrorCommonCode` is sufficient
    /// and no additional application-specific context is needed.
    Default = 0x00,
    /// Other error codes, don't hesitate to add your own for more granularity.
    AmountCastFail = 0x01,
    DestinationDecodeFail = 0x02,

    FailedToSerializeAddress = 0x04,
    FailedToDeriveAddress = 0x05,
    UnexpectedExternalOutputCount = 0x06,
    BufferOverflow = 0x07,
}

impl SwapAppErrorCodeTrait for SwapAppErrorCode {
    // Cast is safe as enum is #[repr(u8)]
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// This function performs a strict validation of the transaction to be signed
/// against the reference transaction parameters provided by the Exchange app.
/// It checks that:
/// 1. The transaction type matches the expected one (Only one type of Tx implemented so auto true).
/// 2. The transaction amount matches the swap amount exactly.
/// 3. The transaction fees matches the swap fees exactly. (fees are not implemented so auto true).
/// 4. The destination address matches the swap destination address exactly.
///
/// # Errors
///
/// Returns error if:
/// - Amount parsing fails (AmountCastFail)
/// - Amount doesn't match between tx and swap params (ErrorWrongAmount)
/// - Destination address has invalid UTF-8 (DestinationDecodeFail)
/// - Destination address hex decode fails (DestinationDecodeFail)
/// - Destination address doesn't match (ErrorWrongDestination)
pub fn check_swap_params(
    params: &CreateTxParams,
    outputs: &[TxOutput],
    fees: u64,
) -> Result<(), SwapError<SwapAppErrorCode>> {
    debug!("Swap mode detected");

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
/// Main entry point when app is called as a library by the Exchange app.
///
/// # Arguments
///
/// * `arg0` - Parameter passed by `os_lib_call` containing command and data pointers
///
/// The Exchange app calls this function with different commands during a swap:
/// - `SwapCheckAddress`: Validate that an address belongs to this device
/// - `SwapGetPrintableAmount`: Format amounts/fees for display
/// - `SwapSignTransaction`: Sign the final transaction
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
            // Return to Exchange, forwarding the result
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
/// Verify that a given address belongs to this device.
///
/// The Exchange app calls this to ensure the user owns the destination address
/// before proceeding with the swap. This prevents sending funds to wrong addresses.
///
/// # Flow
///
/// 1. Parse BIP32 derivation path from params
/// 2. Derive public key from the path
/// 3. Compute address from public key (Keccak256 hash)
/// 4. Compare with reference address from Exchange
///
/// # Important Notes
///
/// - **No heap allocation**: Uses stack arrays only (BSS memory is shared with Exchange)
/// - **Hex string comparison**: Exchange sends address as hex string via C API,
///   so we convert our computed address to hex for comparison
/// - **Address format**: This app uses Ethereum-style addresses (last 20 bytes of
///   Keccak256 hash of pubkey). Adapt this for your blockchain's address format.
///
/// # Arguments
///
/// * `params` - Contains BIP32 path and reference address from Exchange
///
/// # Returns
///
/// * `true` if addresses match (valid)
/// * `false` if addresses don't match or error occurred
fn check_address(params: &CheckAddressParams) -> Result<bool, SwapAppErrorCode> {
    // Parse BIP32 derivation path
    // Note: params.dpath_len is the NUMBER of u32 path components (e.g., 5 for m/44'/133'/0'/0/0),
    // not the byte length. Each component is 4 bytes (big-endian u32).
    debug!("ENTERED_CHECK_ADDRESS\n");

    let bip32_path = Bip32Path::from_dpath(params.dpath_len, &params.dpath[..params.dpath_len * 4])
        .map_err(|_e| SwapAppErrorCode::FailedToDeriveAddress)?;

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
/// Format an amount for display in the Exchange app UI.
///
/// The Exchange app calls this to get human-readable strings for amounts and fees.
/// This is used during swap transactions to show the user what amounts they're
/// exchanging.
///
/// # Amount Format
///
/// The amount is provided as big-endian bytes in `params.amount`:
/// - Right-aligned in a 16-byte buffer (AMOUNT_BUF_SIZE)
/// - Actual length is in `params.amount_len`
/// - Padded to 32 bytes (uint256) for SDK formatting helpers
///
/// # Arguments
///
/// * `params` - Contains:
///   - `amount`: Big-endian encoded amount bytes (right-aligned in 16-byte buffer)
///   - `amount_len`: Actual number of significant bytes
///   - `coin_config`: Coin configuration (unused - hardcoded to CRAB in this template)
///   - `is_fee`: Whether this is a fee amount
///
/// # Returns
///
/// Stack-allocated string formatted as "CRAB {value}" (e.g., "CRAB 1.5")
///
/// # Memory Safety
///
/// Uses `ArrayString` (stack-allocated) to avoid heap allocation, as this function
/// runs under BSS memory restrictions.
///
/// # Production Notes
///
/// For a production app, you should:
/// - Parse `coin_config` to extract ticker and decimals dynamically
/// - Handle different coin types
/// - Support both u64 and u128 amounts
fn get_printable_amount(
    params: &PrintableAmountParams,
) -> Result<ArrayString<40>, SwapAppErrorCode> {
    // Convert amount from 16-byte buffer to 32-byte buffer (uint256 format)
    // The amount is right-aligned in params.amount, we need to copy it to a
    // 32-byte buffer that's also right-aligned (big-endian)
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
