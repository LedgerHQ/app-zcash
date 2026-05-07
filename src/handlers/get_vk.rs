use zcash_address::unified::{Encoding, Fvk, Ufvk};

use ledger_device_sdk::info;
use ledger_device_sdk::io::Comm;

use crate::app_ui::address::ui_display_ufvk;
use crate::utils::{HexSlice, encode_string_response};
use crate::zip32::{
    convert_orchard_path_to_transparent_path, derive_orchard_fvk,
    derive_transparent_account_pubkey, orchard_network,
};
use crate::{
    AppSW, P2VkMode,
    tx::{PendingVkResponse, TxContext},
    utils::bip32_path::Bip32Path,
};

const VK_RESPONSE_CHUNK_LEN: usize = 255;

fn append_pending_vk_chunk(comm: &mut Comm, ctx: &mut TxContext) -> Result<(), AppSW> {
    let pending = ctx.vk_response.as_mut().ok_or(AppSW::BadState)?;
    let end = core::cmp::min(pending.offset + VK_RESPONSE_CHUNK_LEN, pending.bytes.len());
    comm.append(&pending.bytes[pending.offset..end]);
    pending.offset = end;

    if pending.offset == pending.bytes.len() {
        ctx.vk_response = None;
    }

    Ok(())
}

fn display_ufvk_on_last_chunk(ctx: &mut TxContext) -> Result<(), AppSW> {
    let should_display = {
        let pending = ctx.vk_response.as_ref().ok_or(AppSW::BadState)?;
        let end = core::cmp::min(pending.offset + VK_RESPONSE_CHUNK_LEN, pending.bytes.len());
        pending.display_ufvk.is_some() && end == pending.bytes.len()
    };

    if should_display {
        let approved = {
            let pending = ctx.vk_response.as_ref().ok_or(AppSW::BadState)?;
            let ufvk = pending.display_ufvk.as_deref().ok_or(AppSW::BadState)?;
            ui_display_ufvk(ufvk)?
        };

        ctx.vk_display_status = true;

        if !approved {
            ctx.vk_response = None;
            return Err(AppSW::Deny);
        }
    }

    Ok(())
}

pub fn handler_get_vk(
    comm: &mut Comm,
    ctx: &mut TxContext,
    mode: P2VkMode,
    continue_response: bool,
    display: bool,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if continue_response {
        if !data.is_empty() {
            return Err(AppSW::WrongApduLength);
        }

        display_ufvk_on_last_chunk(ctx)?;
        return append_pending_vk_chunk(comm, ctx);
    }

    ctx.vk_response = None;

    let path = Bip32Path::try_from(data)?;
    let orchard_fvk = derive_orchard_fvk(&path)?;

    let (response_bytes, display_ufvk) = match mode {
        P2VkMode::OrchardFvk => (orchard_fvk.to_bytes().to_vec(), None),
        P2VkMode::Ufvk => {
            let transparent_bytes = derive_transparent_account_pubkey(
                &convert_orchard_path_to_transparent_path(&path)?,
            )?;
            info!("Transparent PK: {}", HexSlice(&transparent_bytes));

            let network = orchard_network(&path);

            let ufvk = Ufvk::try_from_items(alloc::vec![
                Fvk::Orchard(orchard_fvk.to_bytes()),
                Fvk::P2pkh(transparent_bytes),
            ])
            .map_err(|_| AppSW::TechnicalProblem)?;

            let ufvk_str = ufvk.encode(&network);

            let response_bytes = encode_string_response(&ufvk_str);
            let display_ufvk = display.then_some(ufvk_str);

            (response_bytes, display_ufvk)
        }
    };

    ctx.vk_response = Some(PendingVkResponse {
        bytes: response_bytes,
        offset: 0,
        display_ufvk,
    });

    display_ufvk_on_last_chunk(ctx)?;
    append_pending_vk_chunk(comm, ctx)?;

    Ok(())
}
