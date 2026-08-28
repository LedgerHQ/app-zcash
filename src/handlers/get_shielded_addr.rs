use orchard::keys::Scope;
use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};

use ledger_device_sdk::io::Comm;
use ledger_device_sdk::log::{error, info};

use crate::consts::UNHARDENED_MASK;

use crate::app_ui::address::ui_display_shielded_address;
use crate::utils::base58_address::{Base58Address, ToBase58Address};
use crate::utils::bip32_path::Bip32Path;
use crate::utils::hashers::ToHash160;
use crate::utils::{Bip44CheckMode, HexSlice, check_bip44_compliance, encode_string_response};
use crate::zip32::{derive_transparent_account_pubkey, map_ledger_crypto_error, orchard_network};
use crate::{AppSW, P2ShieldedAddrMode, zip32::derive_orchard_fvk};

const TRANSPARENT_ACCOUNT_CHAIN_CODE_LEN: usize = 32;

fn transparent_account_address(path: &Bip32Path) -> Result<Base58Address, AppSW> {
    let transparent_bytes = derive_transparent_account_pubkey(path)?;
    let compressed_key_hash = &transparent_bytes[TRANSPARENT_ACCOUNT_CHAIN_CODE_LEN..].hash160()?;

    Base58Address::from_public_key_hash(compressed_key_hash)
}

fn parse_shielded_paths(
    data: &[u8],
    mode: P2ShieldedAddrMode,
) -> Result<(Bip32Path, Option<Bip32Path>), AppSW> {
    match mode {
        P2ShieldedAddrMode::OrchardAddress => Ok((Bip32Path::try_from(data)?, None)),
        P2ShieldedAddrMode::UAddress => {
            let (orchard_path, remaining) = Bip32Path::from_prefixed_bytes(data)?;
            let (transparent_path, remaining) = Bip32Path::from_prefixed_bytes(remaining)?;
            if !remaining.is_empty() {
                return Err(AppSW::WrongApduLength);
            }

            Ok((orchard_path, Some(transparent_path)))
        }
    }
}

pub fn handler_get_shielded_addr(
    comm: &mut Comm,
    mode: P2ShieldedAddrMode,
    display: bool,
) -> Result<(), AppSW> {
    // A raw Orchard receiver is thirty-odd bytes with no encoding the user could read back against
    // their wallet, so this mode has no screen to show. The dispatcher accepts the display P1 for
    // it all the same, and the handler used to answer by returning the receiver with no review at
    // all — a request for the user's confirmation served without asking for it. Refused here,
    // ahead of the derivation, so it also costs nothing on the Secure Element.
    if display && matches!(mode, P2ShieldedAddrMode::OrchardAddress) {
        error!("Raw Orchard receiver cannot be displayed for verification");
        return Err(AppSW::WrongP1P2);
    }

    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    let (path, transparent_path) = parse_shielded_paths(data, mode)?;

    if !check_bip44_compliance(&path, Bip44CheckMode::Zip32Only) {
        error!("Orchard address path not ZIP32 compliant");
        return Err(AppSW::IncorrectData);
    }

    if let P2ShieldedAddrMode::UAddress = mode {
        let transparent_path = transparent_path.as_ref().ok_or(AppSW::WrongApduLength)?;
        if !check_bip44_compliance(
            transparent_path,
            Bip44CheckMode::Full {
                is_change_path: false,
            },
        ) {
            error!("Transparent address path not BIP44 compliant");
            return Err(AppSW::IncorrectData);
        }
        if (path.as_slice()[2] & UNHARDENED_MASK)
            != (transparent_path.as_slice()[2] & UNHARDENED_MASK)
        {
            error!("Orchard and transparent address paths must have matching accounts");
            return Err(AppSW::IncorrectData);
        }
    }

    let orchard_fvk = derive_orchard_fvk(&path)?;

    let resp = match mode {
        P2ShieldedAddrMode::OrchardAddress => {
            let ivk = orchard_fvk
                .to_ivk_ledger(Scope::External)
                .map_err(map_ledger_crypto_error)?;

            let orchard_address = ivk
                .address_at_ledger(0u32)
                .map_err(map_ledger_crypto_error)?;
            info!(
                "Orchard raw address: {}",
                HexSlice(&orchard_address.to_raw_address_bytes())
            );

            orchard_address.to_raw_address_bytes().to_vec()
        }
        P2ShieldedAddrMode::UAddress => {
            let transparent_path = transparent_path.as_ref().ok_or(AppSW::WrongApduLength)?;

            let ivk = orchard_fvk
                .to_ivk_ledger(Scope::External)
                .map_err(map_ledger_crypto_error)?;

            let orchard_address = ivk
                .address_at_ledger(0u32)
                .map_err(map_ledger_crypto_error)?;

            let network = orchard_network(&path);

            let orchard_address = UnifiedAddress::try_from_items(alloc::vec![Receiver::Orchard(
                orchard_address.to_raw_address_bytes(),
            )])
            .map_err(|_| AppSW::TechnicalProblem)?;

            let orchard_address_str = orchard_address.encode(&network);
            info!("Orchard UAddress: {}", orchard_address_str);

            // Display address on device if requested
            if display {
                let transparent_address = transparent_account_address(transparent_path)?;
                info!("Transparent address: {}", transparent_address);

                if !ui_display_shielded_address(&orchard_address_str, &transparent_address)? {
                    return Err(AppSW::Deny);
                }
            }

            encode_string_response(&orchard_address_str)?
        }
    };

    comm.append(&resp);

    Ok(())
}
