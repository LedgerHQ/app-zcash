/*****************************************************************************
 *   Ledger App Zcash Rust.
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

use crate::utils::HexSlice;
use crate::{
    app_ui::address::ui_display_pk,
    utils::{
        base58_address::{Base58Address, ToBase58Address},
        extended_public_key::ExtendedPublicKey,
    },
};

use crate::AppSW;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::log::debug;

/// Handler for GET_PUBLIC_KEY APDU command.
///
/// Derives and returns the public key for a given BIP32 path, optionally
/// displaying the corresponding address on the device for user verification.
///
/// # Flow
///
/// 1. Parse BIP32 path from APDU data
/// 2. Derive public key using shared helper `get_pubkey_from_path()`
/// 3. If display requested, compute and show address on device
/// 4. Return public key and chaincode to client
///
/// # Note
///
/// This handler uses the same address derivation logic as `swap::check_address()`
/// via the shared `get_address_hash_from_pubkey()` helper, ensuring consistency.
pub fn handler_get_public_key(comm: &mut Comm, display: bool) -> Result<(), AppSW> {
    debug!("Called get public key handler");

    let bip32_path = comm
        .get_data()
        .map_err(|_| AppSW::WrongApduLength)?
        .try_into()?;
    debug!("path {:?}", bip32_path);

    let extended_public_key = ExtendedPublicKey::try_from(&bip32_path)?;

    let compressed_key_hash = &extended_public_key.compressed_public_key_hash160()?;
    let base58_address = Base58Address::from_public_key_hash(compressed_key_hash)?;
    debug!("bytes collected{:?}", &base58_address.len());

    let address_str = base58_address.as_str();
    debug!("address_str {:?}", address_str);

    // Display address on device if requested
    if display && !ui_display_pk(address_str)? {
        return Err(AppSW::Deny);
    }

    let public_key = extended_public_key.public_key_slice();
    comm.append(&[extended_public_key.public_key_len as u8]);
    comm.append(extended_public_key.public_key_slice());
    debug!("Public Key: {:02X?}", public_key);

    let addr_len = address_str.len() as u8;
    comm.append(&[addr_len]);
    comm.append(address_str.as_bytes());

    debug!("Address: {}", address_str);

    // Don't encode chain code length, it's always 32 bytes
    debug!("Chain Code: {}", HexSlice(&extended_public_key.chain_code));
    comm.append(&extended_public_key.chain_code);

    Ok(())
}
