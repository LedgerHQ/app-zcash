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
use ledger_device_sdk::ecc::{Secp256k1, Secret, SeedDerive as _};
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::log::{debug, error, info};
use zeroize::Zeroizing;

use crate::AppSW;
use crate::app_ui::sign::ui_display_tx;
use crate::consts::SIGHASH_ALL;
use crate::parser::{
    LegacyOutputParserCtx, LegacyParser, LegacyParserCtx, LegacyParserMode, ParserSourceError,
};
use crate::rng;
use crate::tx::{TransferType, TxContext};
use crate::utils::{Bip44CheckMode, HexSlice, check_bip44_compliance, derivation_account};
use crate::utils::{bip32_path::Bip32Path, extended_public_key::ExtendedPublicKey};
use crate::zip32::{derive_orchard_ask_from_sk, map_ledger_crypto_error};

pub fn handler_hash_input_start(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    continue_hashing: bool,
) -> Result<(), AppSW> {
    // Any shape that does not reset the context reuses the transaction state already there, which is
    // sound only after a legacy round that is still in progress.
    let resets_context = first && !continue_hashing;
    if !resets_context {
        if ctx.pczt_parser.is_session_active() {
            error!("Legacy round during a PCZT session");
            return Err(AppSW::BadState);
        }

        // A transaction that is finished — fully signed, or refused at its review — keeps its
        // outputs, hashers and parsers until the next reset, and a PCZT that ran to completion is
        // no longer reported as an active session. Resuming that state would append this round's
        // outputs to the previous transaction's, so the review would list outputs the signature
        // does not cover, and would spend an approval that is already spent.
        if ctx.is_finished() {
            error!("Legacy round resuming a finished transaction");
            return Err(AppSW::BadState);
        }
    }

    if continue_hashing {
        // A continuation keeps the transaction state of the previous round, so it may
        // only follow a legacy round. `is_v6` is reachable here through a V6 trusted-input
        // round, and continuing would parse legacy fields under a V6 transaction version.
        if ctx.tx_info.is_v6 {
            error!("Legacy continuation after a V6 transaction header");
            return Err(AppSW::BadState);
        }

        // A continuation is the signing round, so it may only resume a transaction the user has
        // already reviewed. It preserves the output amounts and the change classification the
        // review round accumulated, yet `parse_header` re-initialises the V5 hashers while
        // `is_tx_parsed_once` is false. Accepting it mid-review would therefore let a host park an
        // output in the displayed fee computation while dropping it from the signed outputs
        // digest, so the value of that output would silently go to the miner instead.
        if !ctx.tx_signing_state.is_tx_parsed_once {
            error!("Legacy continuation before the transaction was reviewed");
            return Err(AppSW::BadState);
        }

        info!("Reset parser");
        ctx.legacy_parser = LegacyParser::new(LegacyParserMode::Signature);
        // Extract transparent output count from output parser on final state
        ctx.legacy_parser
            .set_transparent_output_count(ctx.legacy_output_parser.transparent_output_count());
    } else if first {
        info!("Reset TX context");
        ctx.reset_for_new_transaction(LegacyParserMode::Signature)?;
    }

    // Try to get data from comm
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    ctx.legacy_parser
        .parse(
            &mut LegacyParserCtx {
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
    if !ctx.legacy_parser.is_presign_ready() || ctx.legacy_output_parser.is_finished() {
        error!("Bad processing state");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    if is_change_info {
        let path: Bip32Path = data.try_into()?;

        // A change hash removes an output from the review screen, so it is installed only from a
        // path that passed the check.
        if !check_bip44_compliance(
            &path,
            Bip44CheckMode::Full {
                is_change_path: true,
            },
        ) {
            error!("Change address path not Bip44 compliant");
            return Err(AppSW::ConditionsOfUseNotSatisfied);
        }

        let public_key_with_cc = ExtendedPublicKey::try_from(&path)?;
        let change_pk_hash = public_key_with_cc.compressed_public_key_hash160()?;
        ctx.tx_info.change_pk_hash = Some(change_pk_hash);
        // Remembered for the signing step, which is the first point where the account being spent
        // from is known too.
        ctx.tx_info.change_account = derivation_account(&path);

        info!("Change pk hash: {}", HexSlice(&change_pk_hash));

        return Ok(());
    }

    ctx.legacy_output_parser
        .parse(
            &mut LegacyOutputParserCtx {
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

    if sighash_type != SIGHASH_ALL {
        error!("Unsupported sighash_type: {}", sighash_type);
        return Err(AppSW::IncorrectData);
    }

    info!("Extra TX data received:");
    info!("locktime: {}", locktime);
    info!("sighash_type: {}", sighash_type);
    info!("expiry_height: {}", expiry_height);

    Ok((locktime, sighash_type, expiry_height))
}

pub fn handler_hash_sign(comm: &mut Comm, ctx: &mut TxContext) -> Result<(), AppSW> {
    // Legacy signing reads the transaction state a legacy round built; during a PCZT session that
    // state belongs to the PCZT.
    if ctx.pczt_parser.is_session_active() {
        error!("Legacy signing during a PCZT session");
        return Err(AppSW::BadState);
    }

    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if data.is_empty() {
        error!("Not enough data for hash sign");
        return Err(AppSW::WrongApduLength);
    }

    // This APDU carries the header of a transaction whose outputs are already in. It is the point
    // at which the transaction is fully known, so it is also where the user reviews it: the
    // validity window arrives here and nowhere earlier, and reviewing before it would leave the
    // host free to pick a locktime and an expiry the approval never covered.
    if ctx.legacy_output_parser.is_finished() && !ctx.is_extra_header_data_set() {
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

        // Under swap the Exchange approval stands in for the review, and the output parser has
        // already cross-checked the transaction against it.
        if ctx.swap_params.is_none() {
            let transfer_type = TransferType::classify(true, false, &ctx.tx_info.outputs);
            if !ui_display_tx(
                &ctx.tx_info.outputs,
                ctx.tx_info.fees,
                transfer_type,
                locktime,
                expiry_height,
            )? {
                info!("Transaction refused at review");
                ctx.set_finished();
                return Err(AppSW::Deny);
            }
            info!("Transaction reviewed");
        }

        ctx.tx_signing_state.is_tx_parsed_once = true;

        return Ok(());
    }

    if !ctx.legacy_parser.is_ready_to_sign() {
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
        error!("Signing path not compliant");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    // A change output is removed from the review, so nothing on screen tells the user where it
    // goes. That is only acceptable while it returns to the account the transaction spends from:
    // otherwise the host names a change path in another account, and the value leaves the account
    // the user is spending with no destination and no amount displayed. Both accounts are known
    // only here, so this is where the transaction is refused — before any signature exists, since
    // a released signature cannot be recalled.
    if let Some(change_account) = ctx.tx_info.change_account
        && derivation_account(&path) != Some(change_account)
    {
        error!("Change path account differs from the signing account");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    append_signature(
        comm,
        &ctx.tx_info.signature_digest,
        &path,
        ctx.tx_info.sighash_type,
        true,
    )?;
    ctx.note_signature_released();

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

pub(crate) fn append_signature(
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

pub(crate) fn orchard_spend_auth_signature_with_sk(
    sk_bytes: &Secret<32>,
    sig_hash: &[u8; 32],
    alpha_bytes: [u8; 32],
) -> Result<[u8; 64], AppSW> {
    let ask = derive_orchard_ask_from_sk(sk_bytes)?;
    orchard_spend_auth_signature_with_ask(&ask, sig_hash, alpha_bytes)
}

fn orchard_spend_auth_signature_with_ask(
    ask: &::orchard::keys::SpendAuthorizingKey,
    sig_hash: &[u8; 32],
    alpha_bytes: [u8; 32],
) -> Result<[u8; 64], AppSW> {
    let alpha =
        ledger_zcash_crypto::pallas_scalar_from_repr(alpha_bytes).map_err(|err| match err {
            ledger_zcash_crypto::Error::MalformedPallasScalar => AppSW::IncorrectData,
            _ => AppSW::TechnicalProblem,
        })?;

    // Never logged: the randomized spend authorizing key is a device-only secret, and printing it
    // would disclose the signing key outright.
    let randomized_ask = ask
        .randomize_ledger(&alpha)
        .map_err(map_ledger_crypto_error)?;

    // Drawn here, and checked, so that an RNG failure aborts the signature instead of producing one
    // with an all-zero nonce seed, which would disclose the randomized signing key.
    let mut random_bytes = Zeroizing::new([0u8; 80]);
    rng::fill_bytes(&mut random_bytes[..])?;

    let auth_sig = randomized_ask
        .sign_ledger(&random_bytes, sig_hash)
        .map_err(map_ledger_crypto_error)?;
    let auth_sig: [u8; 64] = (&auth_sig).into();

    // Only the signature is logged: it goes on chain. The randomizer is not, even though the host
    // supplied it and already knows it — a build with logging enabled would otherwise put scalar
    // material next to the signature it randomizes, and the pair is what turns a second leak into a
    // key recovery.
    debug!("Orchard spend auth signature: {}", HexSlice(&auth_sig));

    Ok(auth_sig)
}
