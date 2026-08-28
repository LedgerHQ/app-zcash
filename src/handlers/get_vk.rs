use zcash_address::unified::{Encoding, Fvk, Ufvk};

use alloc::format;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::log::{error, info};

use crate::app_ui::address::{ui_display_orchard_fvk, ui_display_ufvk};
use crate::consts::{UNHARDENED_MASK, ZCASH_BIP44_COIN_TYPE};
use crate::utils::{
    Bip44CheckMode, HexSlice, check_bip44_compliance, derivation_account, encode_string_response,
};
use crate::zip32::{derive_orchard_fvk, derive_transparent_account_pubkey, orchard_network};
use crate::{
    AppSW, P2VkMode,
    tx::{PendingVkResponse, TxContext},
    utils::bip32_path::Bip32Path,
};

const VK_RESPONSE_CHUNK_LEN: usize = 255;

fn check_transparent_vk_path(path: &Bip32Path) -> bool {
    const HARDENED: u32 = 0x8000_0000;
    const BIP44_PURPOSE: u32 = 44;
    let p = path.as_slice();
    p.len() == 3
        && (p[0] & UNHARDENED_MASK) == BIP44_PURPOSE
        && (p[1] & UNHARDENED_MASK) == ZCASH_BIP44_COIN_TYPE
        && p[2] & HARDENED != 0
}

fn parse_vk_paths(data: &[u8], mode: P2VkMode) -> Result<(Bip32Path, Option<Bip32Path>), AppSW> {
    match mode {
        P2VkMode::OrchardFvk => Ok((Bip32Path::try_from(data)?, None)),
        P2VkMode::Ufvk => {
            let (orchard_path, remaining) = Bip32Path::from_prefixed_bytes(data)?;
            let (transparent_path, remaining) = Bip32Path::from_prefixed_bytes(remaining)?;
            if !remaining.is_empty() {
                return Err(AppSW::WrongApduLength);
            }

            Ok((orchard_path, Some(transparent_path)))
        }
    }
}

fn append_pending_vk_chunk(comm: &mut Comm, ctx: &mut TxContext) -> Result<(), AppSW> {
    let pending = ctx.vk_response.as_mut().ok_or(AppSW::BadState)?;
    let end = core::cmp::min(pending.offset + VK_RESPONSE_CHUNK_LEN, pending.bytes.len());
    comm.append(&pending.bytes[pending.offset..end]);
    pending.offset = end;

    if pending.offset == pending.bytes.len() {
        ctx.is_vk_display_finished = true;
        ctx.vk_response = None;
    }

    Ok(())
}

pub fn handler_get_vk(
    comm: &mut Comm,
    ctx: &mut TxContext,
    mode: P2VkMode,
    continue_response: bool,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if continue_response {
        if !data.is_empty() {
            return Err(AppSW::WrongApduLength);
        }

        return append_pending_vk_chunk(comm, ctx);
    }

    ctx.vk_response = None;

    let (path, transparent_path) = parse_vk_paths(data, mode)?;

    // Both modes derive a viewing key from this path, which exposes the account's shielded history.
    if !check_bip44_compliance(&path, Bip44CheckMode::Zip32Only) {
        error!("Orchard VK path is not a valid ZIP32 path");
        return Err(AppSW::IncorrectData);
    }

    if let P2VkMode::Ufvk = mode {
        let t_path = transparent_path.as_ref().ok_or(AppSW::WrongApduLength)?;
        if !check_transparent_vk_path(t_path) {
            error!("Transparent VK path is not a valid account-level BIP44 path");
            return Err(AppSW::IncorrectData);
        }
        if (path.as_slice()[2] & UNHARDENED_MASK) != (t_path.as_slice()[2] & UNHARDENED_MASK) {
            error!("Orchard and transparent VK paths must have matching accounts");
            return Err(AppSW::IncorrectData);
        }
    }

    // Validation above pins every component but this one, so it is the whole of what the review
    // has to name. Unhardening it is for the screen only; the derivation used the raw value.
    let account = derivation_account(&path).ok_or(AppSW::IncorrectData)? & UNHARDENED_MASK;

    let orchard_fvk = derive_orchard_fvk(&path)?;

    let response_bytes = match mode {
        P2VkMode::OrchardFvk => {
            let orchard_fvk_bytes = orchard_fvk.to_bytes();
            let orchard_fvk_str = format!("{}", HexSlice(&orchard_fvk_bytes));

            if !ui_display_orchard_fvk(&orchard_fvk_str, account)? {
                ctx.is_vk_display_finished = true;
                return Err(AppSW::Deny);
            }

            orchard_fvk_bytes.to_vec()
        }
        P2VkMode::Ufvk => {
            let transparent_path = transparent_path.as_ref().ok_or(AppSW::WrongApduLength)?;
            let transparent_bytes = derive_transparent_account_pubkey(transparent_path)?;
            info!("Transparent PK: {}", HexSlice(&transparent_bytes));

            let network = orchard_network(&path);

            let ufvk = Ufvk::try_from_items(alloc::vec![
                Fvk::Orchard(orchard_fvk.to_bytes()),
                Fvk::P2pkh(transparent_bytes),
            ])
            .map_err(|_| AppSW::TechnicalProblem)?;

            let ufvk_str = ufvk.encode(&network);

            if !ui_display_ufvk(&ufvk_str, account)? {
                ctx.is_vk_display_finished = true;
                return Err(AppSW::Deny);
            }

            encode_string_response(&ufvk_str)?
        }
    };

    ctx.vk_response = Some(PendingVkResponse {
        bytes: response_bytes,
        offset: 0,
    });

    append_pending_vk_chunk(comm, ctx)?;

    Ok(())
}
