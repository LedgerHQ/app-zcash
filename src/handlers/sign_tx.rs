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
use alloc::string::String;
use alloc::vec::Vec;
use ledger_device_sdk::ecc::{Secp256k1, SeedDerive as _};
use ledger_device_sdk::hash::blake2::Blake2b_256;
use ledger_device_sdk::hash::sha2::Sha2_256;
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::io::Comm;

use ledger_device_sdk::libcall::swap::CreateTxParams;
use ledger_device_sdk::nbgl::NbglHomeAndSettings;

use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::BranchId;

use crate::log::{debug, error, info};
use crate::parser::{OutputParser, Parser, ParserCtx, ParserMode, ParserSourceError};
use crate::utils::{bip32_path::Bip32Path, extended_public_key::ExtendedPublicKey};
use crate::utils::{check_bip44_compliance, Bip44CheckMode, HexSlice};
use crate::AppSW;

#[derive(Default)]
pub struct Hashers {
    // Transparent transaction hashers
    pub prevouts_hasher: Blake2b_256,
    pub sequence_hasher: Blake2b_256,
    pub outputs_hasher: Blake2b_256,
    pub amounts_hasher: Blake2b_256,
    pub scripts_hasher: Blake2b_256,

    pub orchard_hasher: Blake2b_256,
    pub sapling_hasher: Blake2b_256,

    pub tx_memo_hasher: Blake2b_256,
    pub tx_compact_hasher: Blake2b_256,
    pub tx_non_compact_hasher: Blake2b_256,

    pub tx_full_hasher: Blake2b_256,

    // Legacy V4 txid is SHA256d over the V4-encoded transaction bytes.
    pub v4_tx_hasher: Sha2_256,
}

#[derive(Default)]
pub struct TxOutput {
    pub amount: u64,
    pub address: String,
    pub is_change: bool,
}

#[derive(Default)]
pub struct TxInfo {
    pub tx_version: Option<TxVersion>,
    pub branch_id: Option<BranchId>,
    pub locktime: u32,
    pub sighash_type: u8,
    pub expiry_height: u32,
    pub total_amount: u64,

    pub outputs: Vec<TxOutput>,
    pub is_change_found: bool,
    pub change_pk_hash: [u8; 20],

    pub prevouts_hash: [u8; 32],
    pub sequence_hash: [u8; 32],
    pub outputs_hash: [u8; 32],
    pub amounts_hash: [u8; 32],
    pub scripts_hash: [u8; 32],

    pub header_digest: [u8; 32],
}

#[derive(Default)]
pub struct TrustedInputInfo {
    // Transaction input to catch for a Trusted Input lookup
    pub input_idx: Option<u32>,
    pub is_input_processed: bool,
    pub amount: u64,
    pub tx_id: [u8; 32],
}

#[derive(Default)]
pub struct TxSigningState {
    pub is_tx_parsed_once: bool,
}

/// Transaction context holding state between APDU chunks.
pub struct TxContext<'a> {
    is_review_finished: bool,

    is_extra_header_data_set: bool,
    is_signing_finished: bool,
    pub tx_signing_state: TxSigningState,

    pub tx_info: TxInfo,
    pub trusted_input_info: TrustedInputInfo,
    pub hashers: Hashers,

    pub home: NbglHomeAndSettings,
    pub parser: Parser,
    pub output_parser: OutputParser,
    /// Swap parameters if running in swap mode.
    /// Used to validate the transaction against the Exchange's request.
    pub swap_params: Option<&'a CreateTxParams>,
}

// Implement constructor for TxInfo with default values
impl<'s> TxContext<'s> {
    pub fn new(swap_params: Option<&'s CreateTxParams>, mode: ParserMode) -> TxContext<'s> {
        TxContext {
            is_review_finished: false,

            is_extra_header_data_set: false,
            is_signing_finished: false,
            tx_signing_state: Default::default(),

            tx_info: Default::default(),
            trusted_input_info: Default::default(),
            hashers: Default::default(),

            home: Default::default(),
            parser: Parser::new(mode),
            output_parser: OutputParser::new(),
            swap_params,
        }
    }

    #[inline(always)]
    pub fn reset(&mut self, mode: ParserMode) {
        let swap_params = self.swap_params;
        *self = TxContext::new(swap_params, mode);
    }

    pub fn set_transaction_trusted_input_idx(&mut self, idx: u32) {
        self.trusted_input_info.input_idx = idx.into();
    }

    // Get review status
    pub fn is_review_finished(&self) -> bool {
        self.is_review_finished
    }

    // Get signing finished or rejected by user status
    pub fn is_signing_finished(&self) -> bool {
        self.is_signing_finished
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
            &mut crate::parser::OutputParserCtx {
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
                    ctx.is_signing_finished = true;
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
                    ctx.is_signing_finished = true;

                    // Original app sends IncorrectData for any swap error, so we do the same
                    AppSW::IncorrectData
                }
                _ => AppSW::IncorrectData,
            }
        })?;

    if ctx.output_parser.is_finished() {
        ctx.is_review_finished = true;
        if !ctx.tx_signing_state.is_tx_parsed_once {
            info!("Set TX parsed once flag");
            ctx.tx_signing_state.is_tx_parsed_once = true;
        }
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

pub fn handler_hash_sign(comm: &mut Comm, ctx: &mut TxContext) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if data.is_empty() {
        error!("Not enough data for derivation path length");
        return Err(AppSW::WrongApduLength);
    }

    if ctx.tx_signing_state.is_tx_parsed_once && !ctx.is_extra_header_data_set {
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

        ctx.is_extra_header_data_set = true;

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

    // Finalize hash
    compute_signature_and_append(
        comm,
        &mut ctx.hashers.tx_full_hasher,
        &path,
        ctx.tx_info.sighash_type,
        true,
    )?;

    ctx.is_signing_finished = true;

    Ok(())
}

fn compute_signature_and_append(
    comm: &mut Comm,
    tx_full_hasher: &mut Blake2b_256,
    path: &Bip32Path,
    sighash_type: u8,
    deterministic_sign: bool,
) -> Result<(), AppSW> {
    let mut hash = [0u8; 32];
    tx_full_hasher
        .finalize(&mut hash)
        .map_err(|_| AppSW::TechnicalProblem)?;

    debug!("Final TX hash: {}", HexSlice(&hash));

    let (p, _chain_code) = Secp256k1::derive_from(path.as_slice());

    let (mut sig, sig_len, info) = if deterministic_sign {
        p.deterministic_sign(&hash)
    } else {
        p.sign(&hash)
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
