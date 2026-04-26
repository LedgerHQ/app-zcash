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
use ledger_device_sdk::ecc::{Secp256k1, SeedDerive as _};
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::log::{debug, error, info};

use crate::AppSW;
use crate::parser::{OutputParserCtx, Parser, ParserCtx, ParserMode, ParserSourceError};
use crate::tx::TxContext;
use crate::utils::{Bip44CheckMode, HexSlice, check_bip44_compliance};
use crate::utils::{bip32_path::Bip32Path, extended_public_key::ExtendedPublicKey};

pub fn handler_hash_input_start(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    continue_hashing: bool,
) -> Result<(), AppSW> {
    if continue_hashing {
        info!("Reset parser");
        ctx.parser = Parser::new(ParserMode::Signature);
        // Extract transparent output count from output parser on final state
        ctx.parser
            .set_transparent_output_count(ctx.output_parser.transparent_output_count());
    } else if first {
        info!("Reset TX context");
        ctx.reset(ParserMode::Signature);
    }

    // Try to get data from comm
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    ctx.parser
        .parse(
            &mut ParserCtx {
                tx_state: &mut ctx.tx_signing_state,
                tx_info: &mut ctx.tx_info,
                trusted_input_info: &mut ctx.trusted_input_info,
                hashers: &mut ctx.hashers,
            },
            data,
        )
        .map_err(|e| {
            error!("Error parsing/hashing TX: {:#?}", e);
            match e.source {
                ParserSourceError::Hash(_) => AppSW::TechnicalProblem,
                _ => AppSW::IncorrectData,
            }
        })?;

    Ok(())
}

pub fn handler_hash_input_finalize_full(
    comm: &mut Comm,
    ctx: &mut TxContext,
    is_change_info: bool,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if data.is_empty() {
        return Err(AppSW::WrongApduLength);
    }

    // Check processing states
    if !ctx.parser.is_presign_ready() || ctx.output_parser.is_finished() {
        error!("Bad processing state");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    if is_change_info {
        let path: Bip32Path = data.try_into()?;

        let public_key_with_cc = ExtendedPublicKey::try_from(&path)?;

        ctx.tx_info.change_pk_hash = public_key_with_cc.compressed_public_key_hash160()?;

        info!("Change pk hash: {}", HexSlice(&ctx.tx_info.change_pk_hash));

        if !check_bip44_compliance(
            &path,
            Bip44CheckMode::Full {
                is_change_path: true,
            },
        ) {
            error!("Change address path not Bip44 compliant");
            return Err(AppSW::ConditionsOfUseNotSatisfied);
        }

        return Ok(());
    }

    ctx.output_parser
        .parse(
            &mut OutputParserCtx {
                tx_info: &mut ctx.tx_info,
                hashers: &mut ctx.hashers,
                swap_params: ctx.swap_params,
            },
            data,
        )
        .map_err(|e| {
            error!("Error parsing TX output: {:#?}", e);
            match e.source {
                ParserSourceError::Hash(_) => AppSW::TechnicalProblem,
                ParserSourceError::AppSW(sw) => sw,
                ParserSourceError::UserDenied => {
                    // User rejected output after review, mark transaction as finished
                    ctx.set_finished();
                    AppSW::Deny
                }
                ParserSourceError::SwapError {
                    common_code,
                    app_code,
                    message,
                } => {
                    error!(
                        "Swap error with common code {}, app code {}, message {:?}",
                        common_code, app_code, message
                    );

                    // Original app sends IncorrectData for any swap error, so we do the same
                    AppSW::IncorrectData
                }
                _ => AppSW::IncorrectData,
            }
        })?;

    if ctx.output_parser.is_finished() && !ctx.tx_signing_state.is_tx_parsed_once {
        info!("Set TX parsed once flag");
        ctx.tx_signing_state.is_tx_parsed_once = true;
    }

    Ok(())
}

fn parse_extra_data(buf: &[u8]) -> Result<(u32, u8, u32), AppSW> {
    if buf.len() < 9 {
        error!("Not enough data for extra header data");
        return Err(AppSW::WrongApduLength);
    }

    // NOTE: for some reason big endian is used here
    let locktime: u32 = u32::from_be_bytes(buf[..4].try_into().unwrap());
    let sighash_type: u8 = buf[4];
    let expiry_height: u32 = u32::from_be_bytes(buf[5..9].try_into().unwrap());

    info!("Extra TX data received:");
    info!("locktime: {}", locktime);
    info!("sighash_type: {}", sighash_type);
    info!("expiry_height: {}", expiry_height);

    Ok((locktime, sighash_type, expiry_height))
}

pub fn handler_hash_sign(
    comm: &mut Comm,
    ctx: &mut TxContext,
    sign_digest: bool,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if data.is_empty() {
        error!("Not enough data for derivation path length");
        return Err(AppSW::WrongApduLength);
    }

    if ctx.tx_signing_state.is_tx_parsed_once && !ctx.is_extra_header_data_set() {
        // not used path size 1 + not used auth len 1 + locktime 4 + sighhash ty 1 +  expiry height 4
        const EXTRA_HEADER_DATA_LEN: usize = 11;
        if data.len() != EXTRA_HEADER_DATA_LEN {
            error!("Not enough data for extra header data");
            return Err(AppSW::WrongApduLength);
        }

        // Skip unused bytes
        let data = &data[2..];

        // Extract extra TX data
        let (locktime, sighash_type, expiry_height) = parse_extra_data(data)?;

        ctx.tx_info.locktime = locktime;
        ctx.tx_info.sighash_type = sighash_type;
        ctx.tx_info.expiry_height = expiry_height;

        ctx.set_extra_header_data();

        return Ok(());
    }

    if !ctx.parser.is_ready_to_sign() {
        error!("Bad processing state for signing");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    let path_len = data[0] as usize * 4 + 1; // Path segment 4 bytes + 1 byte length

    if data.len() < path_len {
        error!("Not enough data for derivation path");
        return Err(AppSW::WrongApduLength);
    }

    let path_data = &data[..path_len];
    let path: Bip32Path = path_data.try_into()?;

    if !check_bip44_compliance(&path, Bip44CheckMode::OnlyCoinType) {
        error!("Output address path not Bip44 compliant");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    if sign_digest {
        debug!("Returning signature digest only");
        comm.append(&ctx.tx_info.signature_digest);
        return Ok(());
    }

    append_signature(
        comm,
        &ctx.tx_info.signature_digest,
        &path,
        ctx.tx_info.sighash_type,
        true,
    )?;

    ctx.tx_signing_state.already_signed_input_count = ctx
        .tx_signing_state
        .already_signed_input_count
        .saturating_add(1);

    let expected_signatures = core::cmp::max(ctx.tx_signing_state.total_input_count, 1);

    info!(
        "Signed input {}/{}",
        ctx.tx_signing_state.already_signed_input_count, expected_signatures
    );

    if ctx.tx_signing_state.already_signed_input_count == expected_signatures {
        info!("All inputs have been signed, TX signing is finished");
        ctx.set_finished();
    }

    Ok(())
}

fn append_signature(
    comm: &mut Comm,
    sig_hash: &[u8; 32],
    path: &Bip32Path,
    sighash_type: u8,
    deterministic_sign: bool,
) -> Result<(), AppSW> {
    debug!("Final TX hash: {}", HexSlice(sig_hash));

    let (p, _chain_code) = Secp256k1::derive_from(path.as_slice());

    let (mut sig, sig_len, info) = if deterministic_sign {
        p.deterministic_sign(sig_hash)
    } else {
        p.sign(sig_hash)
    }
    .map_err(|_| AppSW::TechnicalProblem)?;

    // Store information about the parity of the 'y' coordinate
    if info != 0 {
        sig[0] |= 0x01;
    }

    debug!("Signature: {}", HexSlice(&sig[..sig_len as usize]));

    comm.append(&sig[..sig_len as usize]);
    comm.append(&[sighash_type]);

    Ok(())
}
