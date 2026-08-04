use ::orchard::bundle::commitments::{
    ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION, ZCASH_ORCHARD_HASH_PERSONALIZATION,
};
use alloc::{string::ToString, vec::Vec};
use core::{iter, mem};
use ledger_device_sdk::hash::sha2::Sha2_256;
use ledger_device_sdk::libcall::swap::CreateTxParams;
use zcash_primitives::transaction::sighash_v5::{
    ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION, ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION,
    ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION,
};

use corez::io::Read;
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::hash::blake2::Blake2b_256;
use ledger_device_sdk::hmac::{HMACInit, sha2::Sha2_256 as HmacSha256};
use num_enum::TryFromPrimitive;
use zcash_encoding::CompactSize;
use zcash_primitives::encoding::ReadBytesExt;
use zcash_primitives::transaction::TxVersion;
use zcash_primitives::transaction::txid::{
    ZCASH_HEADERS_HASH_PERSONALIZATION, ZCASH_OUTPUTS_HASH_PERSONALIZATION,
    ZCASH_PREVOUTS_HASH_PERSONALIZATION, ZCASH_SAPLING_HASH_PERSONALIZATION,
    ZCASH_SEQUENCE_HASH_PERSONALIZATION,
};
use zcash_protocol::consensus::BranchId;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::OutPoint;

use crate::parser::compute::{finalize_signature_hash, finalize_signature_input_hash};
use crate::parser::personalization::{
    ZCASH_IRONWOOD_HASH_PERSONALIZATION, ZCASH_ORCHARD_HASH_PERSONALIZATION_V6,
};
use crate::parser::reader::ByteReader;
use crate::settings::Settings;
use crate::tx::{Hashers, SupportedTxVersion, TrustedInputInfo, TxInfo, TxOutput, TxSigningState};
use crate::utils::blake2b_256_pers::{AsWriter, AsWriterB as _, Blake2b256Personalization};
use crate::utils::{CheckDispOutput, HexSlice, check_output_displayable, secure_memcmp};
use crate::{AppSW, swap};
use crate::{app_ui::sign::ui_display_tx, utils::base58_address::Base58Address};
use crate::{
    consts::{
        MAX_OUTPUTS_NUMBER, MAX_SCRIPT_SIZE, TRUSTED_INPUT_TOTAL_SIZE, V6_TX_HEADER,
        V6_VERSION_GROUP_ID,
    },
    utils::base58_address::ToBase58Address,
};
use error::ok;
use ledger_device_sdk::log::{debug, error, info};

pub use error::{ParserError, ParserSourceError};
pub use orchard::ActionBundle;
pub use output_parser::{OutputParser, OutputParserCtx};

mod compute;
mod error;
mod orchard;
mod output_parser;
mod personalization;
mod reader;
mod sapling;
mod transparent;

const HASH_SIZE: usize = 32;
const UINT32_SIZE: usize = 4;

pub(super) fn hash_reader_chunk(
    reader: &mut ByteReader<'_>,
    hasher: &mut Blake2b_256,
    remaining_size: usize,
) -> Result<usize, ParserError> {
    let to_read = core::cmp::min(remaining_size, reader.remaining_len());
    ok!(hasher.update(&reader.remaining_slice()[..to_read]));
    ok!(reader.advance(to_read));
    Ok(remaining_size - to_read)
}

pub(super) fn hash_reader_exact(
    reader: &mut ByteReader<'_>,
    hasher: &mut Blake2b_256,
    size: usize,
    err_msg: &'static str,
) -> Result<(), ParserError> {
    if reader.remaining_len() < size {
        return Err(ParserError::from_str(err_msg));
    }

    ok!(hasher.update(&reader.remaining_slice()[..size]));
    ok!(reader.advance(size));
    Ok(())
}

pub(super) fn finalize_and_log_hash(
    hasher: &mut Blake2b_256,
    label: &str,
) -> Result<[u8; HASH_SIZE], ParserError> {
    let mut hash = [0u8; HASH_SIZE];
    ok!(hasher.finalize(&mut hash));
    debug!("{}: {}", label, HexSlice(&hash));
    Ok(hash)
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u8)]
enum TrustedInputMode {
    Trusted = 0x01,
    Untrusted = 0x02,
}

impl TrustedInputMode {
    fn read(reader: &mut ByteReader<'_>) -> Result<Self, ParserError> {
        let value = ok!(reader.read_u8());
        value
            .try_into()
            .map_err(|_| ParserError::from_str("Unsupported trusted input mode"))
    }
}

#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum ParserMode {
    #[default]
    TrustedInput,
    Signature,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum ParserState {
    #[default]
    None,
    WaitInput,
    ProcessInputScript {
        size: usize,
        remaining_size: usize,
    },
    InputHashingDone,
    WaitOutput,
    ProcessOutputScript {
        size: usize,
        remaining_size: usize,
    },
    OutputHashingDone,

    ProcessSapling,
    ProcessSaplingSpends {
        /// `None` for a v6 transaction, whose spends non-compact digest omits the
        /// anchor (ZIP-229), so the host streams none.
        anchor: Option<[u8; 32]>,
    },
    ProcessSaplingSpendsHashing,
    ProcessSaplingOutputsCompact,
    ProcessSaplingOutputsMemo {
        size: usize,
        remaining_size: usize,
    },
    ProcessSaplingOutputsNonCompact,
    ProcessSaplingOutputHashing,

    ProcessActionsCompact {
        bundle: ActionBundle,
    },
    ProcessActionsMemo {
        bundle: ActionBundle,
        size: usize,
        remaining_size: usize,
    },
    ProcessActionsNonCompact {
        bundle: ActionBundle,
    },
    ProcessActionsHashing {
        bundle: ActionBundle,
    },

    ProcessExtra,
    TransactionParsed,
    TransactionPresignReady,
    TransactionReadyToSign,
}

pub struct ParserCtx<'ctx> {
    pub tx_state: &'ctx mut TxSigningState,
    pub tx_info: &'ctx mut TxInfo,
    pub trusted_input_info: &'ctx mut TrustedInputInfo,
    pub hashers: &'ctx mut Hashers,
}

pub struct Parser {
    mode: ParserMode,

    state: ParserState,

    input_count: usize,
    input_parsed_count: usize,
    output_count: usize,
    output_parsed_count: usize,

    sapling_spend_count: usize,
    sapling_spend_parsed_count: usize,
    sapling_output_count: usize,
    sapling_output_parsed_count: usize,
    orchard_action_count: usize,
    ironwood_action_count: usize,
    /// Shared by both action bundles, which are streamed one after the other.
    action_parsed_count: usize,

    sapling_balance: i64,

    script_bytes: Vec<u8>,
}

impl Parser {
    pub fn new(mode: ParserMode) -> Self {
        Parser {
            mode,
            state: ParserState::None,

            input_count: 0,
            input_parsed_count: 0,
            output_count: 0,
            output_parsed_count: 0,
            sapling_spend_count: 0,
            sapling_spend_parsed_count: 0,
            sapling_output_count: 0,
            sapling_output_parsed_count: 0,
            orchard_action_count: 0,
            ironwood_action_count: 0,
            action_parsed_count: 0,

            sapling_balance: 0,
            script_bytes: Vec::new(),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.state == ParserState::TransactionParsed
    }

    pub fn is_presign_ready(&self) -> bool {
        self.state == ParserState::TransactionPresignReady
    }

    pub fn is_ready_to_sign(&self) -> bool {
        self.state == ParserState::TransactionReadyToSign
    }

    pub fn parse(&mut self, ctx: &mut ParserCtx<'_>, data: &[u8]) -> Result<(), ParserError> {
        let mut reader = ByteReader::new(data);

        while reader.remaining_len() > 0 {
            let prev_state = self.state;

            match self.state {
                ParserState::None => self.parse_header(ctx, &mut reader)?,
                ParserState::WaitInput if self.mode == ParserMode::Signature => {
                    self.parse_input_signature_mode(ctx, &mut reader)?
                }
                ParserState::WaitInput => self.parse_input(ctx, &mut reader)?,
                ParserState::ProcessInputScript {
                    size,
                    remaining_size,
                } => self.parse_input_script(ctx, &mut reader, size, remaining_size)?,
                ParserState::InputHashingDone => {
                    self.parse_input_hashing_done(ctx, &mut reader)?;
                }
                ParserState::WaitOutput => self.parse_output(ctx, &mut reader)?,
                ParserState::ProcessOutputScript {
                    size,
                    remaining_size,
                } => self.parse_output_script(ctx, &mut reader, size, remaining_size)?,
                ParserState::OutputHashingDone => {
                    self.parse_output_hashing_done(ctx, &mut reader)?;
                }
                ParserState::ProcessSapling => self.parse_sapling(ctx, &mut reader)?,
                ParserState::ProcessSaplingSpends { anchor } => {
                    self.parse_sapling_spends(ctx, &mut reader, anchor)?
                }
                ParserState::ProcessSaplingSpendsHashing => {
                    self.parse_sapling_spends_hashing(ctx, &mut reader)?
                }
                ParserState::ProcessSaplingOutputsCompact => {
                    self.parse_sapling_outputs_compact(ctx, &mut reader)?
                }
                ParserState::ProcessSaplingOutputsMemo {
                    size,
                    remaining_size,
                } => self.parse_sapling_outputs_memo(ctx, &mut reader, size, remaining_size)?,
                ParserState::ProcessSaplingOutputsNonCompact => {
                    self.parse_sapling_outputs_non_compact(ctx, &mut reader)?
                }
                ParserState::ProcessSaplingOutputHashing => {
                    self.parse_sapling_output_hashing(ctx, &mut reader)?
                }
                ParserState::ProcessActionsCompact { bundle } => {
                    self.parse_actions_compact(ctx, &mut reader, bundle)?
                }
                ParserState::ProcessActionsMemo {
                    bundle,
                    size,
                    remaining_size,
                } => self.parse_actions_memo(ctx, &mut reader, bundle, size, remaining_size)?,
                ParserState::ProcessActionsNonCompact { bundle } => {
                    self.parse_actions_noncompact(ctx, &mut reader, bundle)?
                }
                ParserState::ProcessActionsHashing { bundle } => {
                    self.parse_actions_hashing(ctx, &mut reader, bundle)?
                }
                ParserState::ProcessExtra => self.parse_process_extra(ctx, &mut reader)?,
                ParserState::TransactionParsed
                | ParserState::TransactionPresignReady
                | ParserState::TransactionReadyToSign => {
                    break;
                }
            }

            if self.state != prev_state {
                info!("Parser state changed: {:?} -> {:?}", prev_state, self.state);
            }
        }

        Ok(())
    }

    /// Consumes the 8-byte version prefix when it announces a v6 transaction (ZIP-229),
    /// and leaves the reader untouched otherwise so that `TxVersion` can read it.
    ///
    /// ZIP-229 states as a non-requirement that v6 carries `zip233Amount`, so this prefix
    /// is fixed at 8 bytes; a later format that grows it would need a new version number.
    fn take_v6_header(reader: &mut ByteReader<'_>) -> Result<bool, ParserError> {
        const PREFIX_SIZE: usize = 2 * UINT32_SIZE;

        let prefix = reader.remaining_slice();
        if prefix.len() < PREFIX_SIZE {
            return Ok(false);
        }

        let mut word = [0u8; UINT32_SIZE];
        word.copy_from_slice(&prefix[..UINT32_SIZE]);
        let version = u32::from_le_bytes(word);
        word.copy_from_slice(&prefix[UINT32_SIZE..PREFIX_SIZE]);
        let version_group_id = u32::from_le_bytes(word);

        if version != V6_TX_HEADER || version_group_id != V6_VERSION_GROUP_ID {
            return Ok(false);
        }

        ok!(reader.advance(PREFIX_SIZE));
        Ok(true)
    }

    /// Initializes the per-component hashers feeding the ZIP-244 transaction ID. Only the
    /// Orchard bundle personalization changes between v5 and v6.
    fn init_txid_hashers(
        ctx: &mut ParserCtx<'_>,
        orchard_personalization: &[u8; 16],
    ) -> Result<(), ParserError> {
        ok!(ctx
            .hashers
            .prevouts_hasher
            .init_with_perso(ZCASH_PREVOUTS_HASH_PERSONALIZATION));
        ok!(ctx
            .hashers
            .sequence_hasher
            .init_with_perso(ZCASH_SEQUENCE_HASH_PERSONALIZATION));
        ok!(ctx
            .hashers
            .outputs_hasher
            .init_with_perso(ZCASH_OUTPUTS_HASH_PERSONALIZATION));
        ok!(ctx
            .hashers
            .amounts_hasher
            .init_with_perso(ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION));
        ok!(ctx
            .hashers
            .scripts_hasher
            .init_with_perso(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION));
        ok!(ctx
            .hashers
            .sapling_hasher
            .init_with_perso(ZCASH_SAPLING_HASH_PERSONALIZATION));
        ok!(ctx
            .hashers
            .orchard_hasher
            .init_with_perso(orchard_personalization));

        Ok(())
    }

    pub fn parse_header(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let is_v6 = Self::take_v6_header(reader)?;
        let version = if is_v6 {
            None
        } else {
            Some(ok!(TxVersion::read(&mut *reader)))
        };

        let value = ok!(reader.read_u32_le());
        let consensus_branch_id = ok!(BranchId::try_from(value));

        info!(
            "Transaction version: {:?} (v6: {}), consensus branch id: {:?}",
            version, is_v6, consensus_branch_id
        );
        ctx.tx_info.tx_version = version;
        ctx.tx_info.is_v6 = is_v6;
        ctx.tx_info.branch_id = Some(consensus_branch_id);

        let input_count: usize = ok!(CompactSize::read_t(&mut *reader));
        info!("Input count: {}", input_count);

        match (self.mode, version, ctx.tx_state.is_tx_parsed_once) {
            // A v6 transaction only ever reaches this parser as the previous transaction of
            // an input, to recompute its txid; signing one goes through the PCZT path. Its
            // `version` is None because `TxVersion` cannot represent v6 on this branch.
            (ParserMode::TrustedInput, None, _) => {
                debug!("Init V6 tx hashers");
                Self::init_txid_hashers(ctx, ZCASH_ORCHARD_HASH_PERSONALIZATION_V6)?;
                ok!(ctx
                    .hashers
                    .ironwood_hasher
                    .init_with_perso(ZCASH_IRONWOOD_HASH_PERSONALIZATION));
            }
            // Normal flow for TrustedInput and Signature modes
            (ParserMode::TrustedInput, Some(TxVersion::V5), _)
            | (ParserMode::Signature, Some(TxVersion::V5), false) => {
                debug!("Init V5 tx hashers");
                Self::init_txid_hashers(ctx, ZCASH_ORCHARD_HASH_PERSONALIZATION)?;
            }
            // In case of Signature mode, continue computing Tx hash from previous state
            (ParserMode::Signature, Some(version @ TxVersion::V5), true) => {
                info!("Resume TX hashing for signing");
                info!("TX Version {:X?}", version);
                info!("TX prevout hash {}", HexSlice(&ctx.tx_info.prevouts_hash));
                info!("TX sequence hash {}", HexSlice(&ctx.tx_info.sequence_hash));

                info!("Compute headers hash");

                let full_hasher = &mut ctx.hashers.tx_full_hasher;
                ok!(full_hasher.init_with_perso(ZCASH_HEADERS_HASH_PERSONALIZATION));

                ok!(version.write(&mut full_hasher.as_writer()));
                ok!(full_hasher.update(&u32::from(consensus_branch_id).to_le_bytes()));
                ok!(full_hasher.update(&ctx.tx_info.locktime.to_le_bytes()));
                ok!(full_hasher.update(&ctx.tx_info.expiry_height.to_le_bytes()));

                // Save header_digest
                ok!(full_hasher.finalize(&mut ctx.tx_info.header_digest));

                info!("V5 header digest {}", HexSlice(&ctx.tx_info.header_digest));

                ok!(ctx
                    .hashers
                    .prevouts_hasher
                    .init_with_perso(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION));
            }
            // Support V4 in trusted input mode (Transaction ID computation)
            (ParserMode::TrustedInput, Some(version @ TxVersion::V4), _) => {
                debug!("Init V4 txid hasher");
                ctx.hashers.v4_tx_hasher = Sha2_256::new();
                version
                    .write(&mut ctx.hashers.v4_tx_hasher.as_writer())
                    .expect("cannot fail");
                CompactSize::write(&mut ctx.hashers.v4_tx_hasher.as_writer(), input_count)
                    .expect("cannot fail");
            }
            _ => {
                error!(
                    "Unsupported transaction version: {:?} in mode {:?} with is_tx_parsed_once={}",
                    version, self.mode, ctx.tx_state.is_tx_parsed_once
                );
                return Err(ParserError::from_str("Unsupported transaction version"));
            }
        }

        ctx.tx_info.total_amount = 0;
        self.input_count = input_count;

        // Set total_input_count for signing
        if let ParserMode::Signature = self.mode
            && !ctx.tx_state.is_tx_parsed_once
        {
            ctx.tx_state.total_input_count = self.input_count;
        }

        self.state = if self.input_count == 0 {
            ParserState::InputHashingDone
        } else {
            ParserState::WaitInput
        };

        Ok(())
    }

    pub fn parse_process_extra(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Processing extra data...");

        ctx.tx_info.locktime = ok!(reader.read_u32_le());

        info!("Locktime: {:X?}", ctx.tx_info.locktime);

        let extra_data_len: usize = ok!(CompactSize::read_t(&mut *reader));
        info!("Extra data length: {}", extra_data_len);

        if extra_data_len != reader.remaining_len() {
            error!(
                "Expected extra data length to be {}, got {}",
                reader.remaining_len(),
                extra_data_len
            );
            return Err(ParserError::from_str("Invalid extra data length"));
        }

        info!(
            "Extra data {}",
            HexSlice(&reader.remaining_slice()[..extra_data_len])
        );

        ctx.tx_info.expiry_height = ok!(reader.read_u32_le());
        info!("Expiry height: {:X?}", ctx.tx_info.expiry_height);

        if let SupportedTxVersion::V4 = ctx.tx_info.tx_version() {
            ok!(ctx
                .hashers
                .v4_tx_hasher
                .update(&ctx.tx_info.locktime.to_le_bytes()));

            ok!(ctx
                .hashers
                .v4_tx_hasher
                .update(&ctx.tx_info.expiry_height.to_le_bytes()));

            ok!(ctx.hashers.v4_tx_hasher.update(reader.remaining_slice()));
        }

        ctx.trusted_input_info.is_input_processed = true;
        self.state = ParserState::TransactionParsed;

        compute::tx_id(ctx)?;

        Ok(())
    }
}
