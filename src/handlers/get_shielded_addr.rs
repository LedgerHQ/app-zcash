use orchard::keys::Scope;
use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};

use ledger_device_sdk::info;
use ledger_device_sdk::io::Comm;

use crate::utils::bip32_path::Bip32Path;
use crate::utils::{HexSlice, encode_string_response};
use crate::zip32::{map_ledger_crypto_error, orchard_network};
use crate::{AppSW, GetShieldedAddrMode, zip32::derive_orchard_fvk};

pub fn handler_get_shielded_addr(
    comm: &mut Comm,
    mode: GetShieldedAddrMode,
    _display: bool,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    let path = Bip32Path::try_from(data)?;

    let orchard_fvk = derive_orchard_fvk(&path)?;

    let resp = match mode {
        GetShieldedAddrMode::OrchardAddress => {
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
        GetShieldedAddrMode::UAddress => {
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

            encode_string_response(&orchard_address_str)
        }
    };

    comm.append(&resp);

    Ok(())
}
