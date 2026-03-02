use ledger_device_sdk::info;
use orchard::keys::{FullViewingKey as OrchardFvk, SpendingKey as OrchardSk};

use ledger_device_sdk::ecc::{ChainCode, Secret};
use ledger_device_sdk::io::Comm;

#[cfg(not(feature = "test_zip32_stub"))]
use ledger_device_sdk::ecc::Pallas;

use crate::utils::HexSlice;
use crate::{AppSW, GetUfvkMode, utils::bip32_path::Bip32Path};

fn map_ledger_crypto_error(err: ledger_zcash_crypto::Error) -> AppSW {
    match err {
        ledger_zcash_crypto::Error::InvalidKeyDiscarded => AppSW::Deny,
        _ => AppSW::TechnicalProblem,
    }
}

// Derives the Orchard FullViewingKey bytes for the given coin type and account.
fn derive_orchard_fvk_bytes(sk: Secret<32>) -> Result<[u8; 96], AppSW> {
    let sk = OrchardSk::ledger_from_bytes(sk.as_ref().try_into().unwrap())
        .map_err(map_ledger_crypto_error)?;
    let fvk = OrchardFvk::ledger_try_from(&sk).map_err(map_ledger_crypto_error)?;

    Ok(fvk.to_bytes())
}

#[cfg(feature = "test_zip32_stub")]
/// Stub implementation for testing with Speculos without ZIP32 key derivation.
fn derive_orchard_child_keys(path: &[u32], cc: &mut ChainCode) -> Result<Secret<32>, AppSW> {
    // -----------------------  Default speculos seed ---------------------------------
    // * glory promote mansion idle axis finger extra february uncover one trip
    // * resource lawn turtle enact monster seven myth punch hobby comfort wild raise
    // * skin
    // --------------------------------------------------------------------------------
    let sk_cc = [
        (
            // Exported keys from ledger device using the above seed and the path m/32'/133'/0':
            // Child sk: b9880c68c59436419fe615ef7e05d26ffb6de0ef36f151c764bd80c259254a1e
            [
                0xb9, 0x88, 0x0c, 0x68, 0xc5, 0x94, 0x36, 0x41, 0x9f, 0xe6, 0x15, 0xef, 0x7e, 0x05,
                0xd2, 0x6f, 0xfb, 0x6d, 0xe0, 0xef, 0x36, 0xf1, 0x51, 0xc7, 0x64, 0xbd, 0x80, 0xc2,
                0x59, 0x25, 0x4a, 0x1e,
            ],
            // Child chain code: 5cc85343f688608f94d5548f4dfc4086d708b13eb34c47be06c966f5e739427e
            [
                0x5c, 0xc8, 0x53, 0x43, 0xf6, 0x88, 0x60, 0x8f, 0x94, 0xd5, 0x54, 0x8f, 0x4d, 0xfc,
                0xc4, 0x08, 0x6d, 0x70, 0x8b, 0x13, 0xeb, 0x34, 0xc4, 0x7b, 0xe0, 0x6c, 0x96, 0xf5,
                0xe7, 0x39, 0x42, 0x7e,
            ],
        ),
        // Exported keys from ledger device using the above seed and the path m/32'/133'/1':
        // Child sk: 2e34ba81595227a2394e352ebdcad030db3872c820ada7ef2d6157351244a5ac
        (
            [
                0x2e, 0x34, 0xba, 0x81, 0x59, 0x52, 0x27, 0xa2, 0x39, 0x4e, 0x35, 0x2e, 0xbd, 0xca,
                0xd0, 0x30, 0xdb, 0x38, 0x72, 0xc8, 0x20, 0xad, 0xa7, 0xef, 0x2d, 0x61, 0x57, 0x35,
                0x12, 0x44, 0xa5, 0xac,
            ],
            // Child chain code: f7c8f3956e2f8bcb71da50639b1b0431e6627334bd00797f3e0ca2b739f273b3
            [
                0xf7, 0xc8, 0xf3, 0x95, 0x6e, 0x2f, 0x8b, 0xcb, 0x71, 0xda, 0x50, 0x63, 0x9b, 0x1b,
                0x04, 0x31, 0xe6, 0x62, 0x73, 0x34, 0xbd, 0x00, 0x79, 0x7f, 0x3e, 0x0c, 0xa2, 0xb7,
                0x39, 0xf2, 0x73, 0xb3,
            ],
        ),
    ];

    let account_idx: u32 = if path.len() >= 3 {
        path[2] & 0x7FFF_FFFF
    } else if !path.is_empty() {
        path[path.len() - 1] & 0x7FFF_FFFF
    } else {
        0
    };

    if account_idx > 1 {
        panic!("Test stub only supports account indices 0 and 1");
    }

    let account_idx = account_idx as usize;
    let mut sk = Secret::default();

    sk.as_mut().copy_from_slice(&sk_cc[account_idx].0);
    cc.value.copy_from_slice(&sk_cc[account_idx].1);

    Ok(sk)
}

pub fn handler_get_ufvk(comm: &mut Comm, _display: bool, mode: GetUfvkMode) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    let path = Bip32Path::try_from(data)?;
    let path_slice = path.as_slice();

    let mut _cc = ChainCode::default();

    #[cfg(feature = "test_zip32_stub")]
    let sk = derive_orchard_child_keys(path_slice, &mut _cc)?;

    #[cfg(not(feature = "test_zip32_stub"))]
    let sk = Pallas::zip32_orchard_derive(path_slice, (&mut _cc).into(), None);

    let orchard_fvk = derive_orchard_fvk_bytes(sk)?;
    info!("Orchard FVK: {}", HexSlice(&orchard_fvk));

    match mode {
        GetUfvkMode::OrchardFvk => comm.append(&orchard_fvk),
        _ => unimplemented!("Going to be implemented in the next PRs"),
    }

    Ok(())
}
