use orchard::keys::{SpendAuthorizingKey as OrchardAsk, SpendingKey as OrchardSk};
use zcash_protocol::consensus::NetworkType;

use ledger_device_sdk::ecc::Pallas;
use ledger_device_sdk::ecc::{ChainCode, Secret};
use ledger_device_sdk::info;

use crate::utils::HexSlice;
use crate::utils::extended_public_key::ExtendedPublicKey;
use crate::{AppSW, utils::bip32_path::Bip32Path};

pub use orchard::keys::FullViewingKey as OrchardFvk;

pub fn map_ledger_crypto_error(err: ledger_zcash_crypto::Error) -> AppSW {
    match err {
        ledger_zcash_crypto::Error::InvalidKeyDiscarded => AppSW::Deny,
        _ => AppSW::TechnicalProblem,
    }
}

pub fn orchard_network(path: &Bip32Path) -> NetworkType {
    // m_Orchard / 32' / 1' / account'
    if let Some(coin_type) = path.as_slice().get(1)
        && *coin_type == 1 + 0x8000_0000
    {
        return NetworkType::Test;
    }
    NetworkType::Main
}

pub fn convert_orchard_path_to_transparent_path(path: &Bip32Path) -> Result<Bip32Path, AppSW> {
    // Convert from m/32'/<coin_type>'/<account>' to m/44'/<coin_type>'/<account>'
    let mut path = path.as_slice().to_vec();
    if let Some(path0) = path.get_mut(0) {
        *path0 = 44 + 0x8000_0000;
    }

    Bip32Path::try_from(path.as_slice())
}

// Derives the Orchard FullViewingKey bytes for the given coin type and account.
pub fn derive_orchard_fvk_bytes(sk: Secret<32>) -> Result<OrchardFvk, AppSW> {
    let sk = OrchardSk::ledger_from_bytes(sk.as_ref().try_into().unwrap())
        .map_err(map_ledger_crypto_error)?;

    OrchardFvk::ledger_try_from(&sk).map_err(map_ledger_crypto_error)
}

pub fn derive_orchard_ask(path: &Bip32Path) -> Result<OrchardAsk, AppSW> {
    let sk = derive_orchard_sk(path)?;
    OrchardAsk::ledger_try_from(&sk).map_err(map_ledger_crypto_error)
}

// Derives the transparent account public key bytes for the BIP44 path
// `m/44'/<coin_type>'/<account>'`.
//
// Returns 65 bytes: [chain_code (32 bytes) | compressed_pubkey (33 bytes)]
pub fn derive_transparent_account_pubkey(path: &Bip32Path) -> Result<[u8; 65], AppSW> {
    let extended_public_key = ExtendedPublicKey::try_from(path)?;
    let compressed_public_key = extended_public_key.compressed_public_key()?;

    let mut result = [0u8; 65];
    result[..32].copy_from_slice(&extended_public_key.chain_code);
    result[32..].copy_from_slice(&compressed_public_key);

    Ok(result)
}

fn derive_orchard_sk_bytes(path: &Bip32Path) -> Result<Secret<32>, AppSW> {
    let path_slice = path.as_slice();
    let mut cc = ChainCode::default();

    let sk = Pallas::zip32_orchard_derive(path_slice, (&mut cc).into(), None)
        .map_err(|_| AppSW::TechnicalProblem)?;

    Ok(sk)
}

fn derive_orchard_sk(path: &Bip32Path) -> Result<OrchardSk, AppSW> {
    let sk = derive_orchard_sk_bytes(path)?;
    OrchardSk::ledger_from_bytes(sk.as_ref().try_into().unwrap()).map_err(map_ledger_crypto_error)
}

pub fn derive_orchard_fvk(path: &Bip32Path) -> Result<OrchardFvk, AppSW> {
    let sk = derive_orchard_sk_bytes(path)?;
    let orchard_fvk = derive_orchard_fvk_bytes(sk)?;
    info!("Orchard FVK: {}", HexSlice(&orchard_fvk.to_bytes()));

    Ok(orchard_fvk)
}
