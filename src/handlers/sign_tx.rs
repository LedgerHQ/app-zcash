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
use ledger_device_sdk::random::{LedgerRng, rand_bytes};

use crate::AppSW;
use crate::consts::P1HashSignMode;
use crate::parser::{OutputParserCtx, Parser, ParserCtx, ParserMode, ParserSourceError};
use crate::tx::TxContext;
use crate::utils::{Bip44CheckMode, HexSlice, check_bip44_compliance};
use crate::utils::{bip32_path::Bip32Path, extended_public_key::ExtendedPublicKey};
use crate::zip32::{derive_orchard_ask, map_ledger_crypto_error};

const ORCHARD_BINDING_SIGNING_KEY_LEN: usize = 32;

fn map_redpallas_error(err: ledger_zcash_crypto::redpallas::Error) -> AppSW {
    match err {
        ledger_zcash_crypto::redpallas::Error::MalformedSigningKey
        | ledger_zcash_crypto::redpallas::Error::MalformedVerificationKey => AppSW::IncorrectData,
        _ => map_ledger_crypto_error(ledger_zcash_crypto::Error::from(err)),
    }
}

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
    mode: P1HashSignMode,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if data.is_empty() {
        error!("Not enough data for hash sign");
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

    if let P1HashSignMode::BindingSig = mode {
        debug!("Returning orchard binding signature");

        let binding_sig = orchard_binding_signature(data, &ctx.tx_info.signature_digest)?;
        comm.append(&binding_sig);

        return Ok(());
    }

    let path_len = data[0] as usize * 4 + 1; // Path segment 4 bytes + 1 byte length

    if data.len() < path_len {
        error!("Not enough data for derivation path");
        return Err(AppSW::WrongApduLength);
    }

    let path_data = &data[..path_len];
    let path: Bip32Path = path_data.try_into()?;

    if !check_bip44_compliance(&path, Bip44CheckMode::OnlyCoinType) {
        error!("Signing path not compliant");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    if let P1HashSignMode::Digest = mode {
        debug!("Returning signature digest only");
        comm.append(&ctx.tx_info.signature_digest);

        return Ok(());
    } else if let P1HashSignMode::SpendAuthSig = mode {
        debug!("Returning spend auth signature for an orchard action");

        let (auth_sig, alpha) = orchard_spend_auth_signature(&path, &ctx.tx_info.signature_digest)?;
        comm.append(&auth_sig);
        comm.append(&alpha);

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

// Returns a 64-byte Orchard binding signature. The APDU data must be the
// canonical little-endian binding signing key scalar.
fn orchard_binding_signature(data: &[u8], sig_hash: &[u8; 32]) -> Result<[u8; 64], AppSW> {
    if data.len() != ORCHARD_BINDING_SIGNING_KEY_LEN {
        error!("Invalid binding signing key length: {}", data.len());
        return Err(AppSW::WrongApduLength);
    }

    let mut bsk_bytes = [0u8; ORCHARD_BINDING_SIGNING_KEY_LEN];
    bsk_bytes.copy_from_slice(data);

    let bsk = ledger_zcash_crypto::redpallas::binding_signing_key(bsk_bytes)
        .map_err(map_redpallas_error)?;

    let mut random_bytes = [0u8; 80];
    rand_bytes(&mut random_bytes);

    let binding_sig = ledger_zcash_crypto::redpallas::binding_sign(&bsk, &random_bytes, sig_hash)
        .map_err(map_redpallas_error)?;

    debug!("Orchard binding signature: {}", HexSlice(&binding_sig));

    Ok(binding_sig)
}

// Returns a 64-byte spend auth signature and alpha bytes
fn orchard_spend_auth_signature(
    bip32_path: &Bip32Path,
    sig_hash: &[u8; 32],
) -> Result<([u8; 64], [u8; 32]), AppSW> {
    // This number of attempts gives negligible failure probability
    const ALPHA_GENERATION_ATTEMPTS: usize = 350;

    let ask = derive_orchard_ask(bip32_path)?;

    let mut alpha = None;
    for _ in 0..ALPHA_GENERATION_ATTEMPTS {
        let mut alpha_bytes = [0u8; 32];
        rand_bytes(&mut alpha_bytes);

        match ledger_zcash_crypto::pallas_scalar_from_repr(alpha_bytes) {
            Ok(alpha_scalar) => {
                alpha = Some((alpha_scalar, alpha_bytes));
                break;
            }
            Err(ledger_zcash_crypto::Error::MalformedPallasScalar) => {}
            Err(_) => return Err(AppSW::TechnicalProblem),
        }
    }

    let (alpha, alpha_bytes) = alpha.ok_or_else(|| {
        error!(
            "Failed to generate a valid alpha scalar after {} attempts",
            ALPHA_GENERATION_ATTEMPTS
        );
        AppSW::MaxValueReached
    })?;

    let randomized_ask = ask
        .randomize_ledger(&alpha)
        .map_err(map_ledger_crypto_error)?;

    debug!(
        "randomized_ask: {}",
        HexSlice(&{
            let randomized_ask_bytes: [u8; 32] = (&randomized_ask).into();
            randomized_ask_bytes
        })
    );

    let auth_sig = randomized_ask
        .sign_ledger(LedgerRng, sig_hash)
        .map_err(map_ledger_crypto_error)?;
    let auth_sig: [u8; 64] = (&auth_sig).into();

    debug!("Orchard spend auth signature: {}", HexSlice(&auth_sig));
    debug!("Orchard alpha: {}", HexSlice(&alpha_bytes));

    Ok((auth_sig, alpha_bytes))
}
