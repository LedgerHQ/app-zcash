use alloc::{string::ToString, vec::Vec};
use core::{iter, mem};
use ledger_device_sdk::hash::sha2::Sha2_256;
use ledger_device_sdk::libcall::swap::CreateTxParams;

use super::personalization::ZCASH_ORCHARD_HASH_PERSONALIZATION_V6;
use super::personalization::{
    ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION, ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION,
};
use super::reader::ReadBytesExt;
use corez::io::Read;
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::hash::blake2::Blake2b_256;
use ledger_device_sdk::hmac::{HMACInit, sha2::Sha2_256 as HmacSha256};
use num_enum::TryFromPrimitive;
use zcash_encoding::CompactSize;
use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::BranchId;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::OutPoint;

use crate::parser::compute::{
    compute_no_transparent_input_signature_digest, compute_transparent_input_signature_digest,
    finalize_signature_input_hash,
};
use crate::parser::{
    HASH_SIZE, ORCHARD_MEMO_SIZE, ParserError, finalize_and_log_hash, hash_reader_chunk,
    hash_reader_exact, ok,
};
use crate::parser::{compute, reader::ByteReader};
use crate::settings::Settings;
use crate::swap;
use crate::tx::{
    Hashers, SupportedTxVersion, TransferType, TrustedInputInfo, TxInfo, TxOutput, TxPool,
    TxSigningState,
};
use crate::utils::blake2b_256_pers::{AsWriter, AsWriterB as _, Blake2b256Personalization};
use crate::utils::{CheckDispOutput, HexSlice, check_output_displayable, secure_memcmp};
use crate::{app_ui::sign::ui_display_tx, utils::base58_address::Base58Address};
use crate::{
    consts::{MAX_OUTPUTS_NUMBER, MAX_SCRIPT_SIZE, TRUSTED_INPUT_TOTAL_SIZE},
    utils::base58_address::ToBase58Address,
};
use ledger_device_sdk::log::{debug, error, info};

pub use output_parser::{LegacyOutputParser, LegacyOutputParserCtx};

mod orchard;
mod output_parser;
mod sapling;
mod transparent;

/// One of the shielded action bundles carried by a transaction.
///
/// Orchard and Ironwood share the same on-wire action layout and the same ZIP-244
/// three-part digest structure; they differ only by personalization and by which bundle
/// hasher they feed. Whether the anchor belongs to the txid digest depends on the
/// transaction version, not on the bundle.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ActionBundle {
    Orchard,
    Ironwood,
}

#[derive(Debug, PartialEq, TryFromPrimitive)]
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
pub enum LegacyParserMode {
    #[default]
    TrustedInput,
    Signature,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum LegacyParserState {
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

pub struct LegacyParserCtx<'ctx> {
    pub tx_state: &'ctx mut TxSigningState,
    pub tx_info: &'ctx mut TxInfo,
    pub trusted_input_info: &'ctx mut TrustedInputInfo,
    pub hashers: &'ctx mut Hashers,
}

pub struct LegacyParser {
    mode: LegacyParserMode,

    state: LegacyParserState,

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

impl LegacyParser {
    pub fn set_transparent_output_count(&mut self, cnt: usize) {
        self.output_count = cnt;
    }

    pub fn new(mode: LegacyParserMode) -> Self {
        LegacyParser {
            mode,
            state: LegacyParserState::None,

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
        self.state == LegacyParserState::TransactionParsed
    }

    pub fn is_presign_ready(&self) -> bool {
        self.state == LegacyParserState::TransactionPresignReady
    }

    pub fn is_ready_to_sign(&self) -> bool {
        self.state == LegacyParserState::TransactionReadyToSign
    }

    pub fn parse(&mut self, ctx: &mut LegacyParserCtx<'_>, data: &[u8]) -> Result<(), ParserError> {
        let mut reader = ByteReader::new(data);

        while reader.remaining_len() > 0 {
            let prev_state = self.state;

            match self.state {
                LegacyParserState::None => self.parse_header(ctx, &mut reader)?,
                LegacyParserState::WaitInput if self.mode == LegacyParserMode::Signature => {
                    self.parse_input_signature_mode(ctx, &mut reader)?
                }
                LegacyParserState::WaitInput => self.parse_input(ctx, &mut reader)?,
                LegacyParserState::ProcessInputScript {
                    size,
                    remaining_size,
                } => self.parse_input_script(ctx, &mut reader, size, remaining_size)?,
                LegacyParserState::InputHashingDone => {
                    self.parse_input_hashing_done(ctx, &mut reader)?;
                }
                LegacyParserState::WaitOutput => self.parse_output(ctx, &mut reader)?,
                LegacyParserState::ProcessOutputScript {
                    size,
                    remaining_size,
                } => self.parse_output_script(ctx, &mut reader, size, remaining_size)?,
                LegacyParserState::OutputHashingDone => {
                    self.parse_output_hashing_done(ctx, &mut reader)?;
                }
                LegacyParserState::ProcessSapling => self.parse_sapling(ctx, &mut reader)?,
                LegacyParserState::ProcessSaplingSpends { anchor } => {
                    self.parse_sapling_spends(ctx, &mut reader, anchor)?
                }
                LegacyParserState::ProcessSaplingSpendsHashing => {
                    self.parse_sapling_spends_hashing(ctx, &mut reader)?
                }
                LegacyParserState::ProcessSaplingOutputsCompact => {
                    self.parse_sapling_outputs_compact(ctx, &mut reader)?
                }
                LegacyParserState::ProcessSaplingOutputsMemo {
                    size,
                    remaining_size,
                } => self.parse_sapling_outputs_memo(ctx, &mut reader, size, remaining_size)?,
                LegacyParserState::ProcessSaplingOutputsNonCompact => {
                    self.parse_sapling_outputs_non_compact(ctx, &mut reader)?
                }
                LegacyParserState::ProcessSaplingOutputHashing => {
                    self.parse_sapling_output_hashing(ctx, &mut reader)?
                }
                LegacyParserState::ProcessActionsCompact { bundle } => {
                    self.parse_actions_compact(ctx, &mut reader, bundle)?
                }
                LegacyParserState::ProcessActionsMemo {
                    bundle,
                    size,
                    remaining_size,
                } => self.parse_actions_memo(ctx, &mut reader, bundle, size, remaining_size)?,
                LegacyParserState::ProcessActionsNonCompact { bundle } => {
                    self.parse_actions_noncompact(ctx, &mut reader, bundle)?
                }
                LegacyParserState::ProcessActionsHashing { bundle } => {
                    self.parse_actions_hashing(ctx, &mut reader, bundle)?
                }
                LegacyParserState::ProcessExtra => self.parse_process_extra(ctx, &mut reader)?,
                LegacyParserState::TransactionParsed
                | LegacyParserState::TransactionPresignReady
                | LegacyParserState::TransactionReadyToSign => {
                    break;
                }
            }

            if self.state != prev_state {
                info!(
                    "LegacyParser state changed: {:?} -> {:?}",
                    prev_state, self.state
                );
            }
        }

        Ok(())
    }

    pub fn parse_header(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let version = ok!(TxVersion::read(&mut *reader));

        let value = ok!(reader.read_u32_le());
        let consensus_branch_id = ok!(BranchId::try_from(value));

        info!(
            "Transaction version: {:?}, consensus branch id: {:?}",
            version, consensus_branch_id
        );
        ctx.tx_info.tx_version = Some(version);
        ctx.tx_info.branch_id = Some(consensus_branch_id);

        let input_count: usize = ok!(CompactSize::read_t(&mut *reader));
        info!("Input count: {}", input_count);

        match (self.mode, version, ctx.tx_state.is_tx_parsed_once) {
            // V6 (ZIP-229) is only reachable in TrustedInput mode: the app never signs
            // a v6 transaction on the legacy path; signing goes through the PCZT path.
            (LegacyParserMode::TrustedInput, TxVersion::V6, _) => {
                debug!("Init V6 tx hashers");
                // Re-use the V5 transparent/sapling hasher initialisation, then override
                // the Orchard bundle personalization for V6 and set the is_v6 flag so
                // that tx_version() returns SupportedTxVersion::V6 throughout.
                ok!(ctx.hashers.init_v5_tx_hashers());
                ok!(ctx
                    .hashers
                    .orchard_hasher
                    .init_with_perso(ZCASH_ORCHARD_HASH_PERSONALIZATION_V6));
                ctx.tx_info.is_v6 = true;
            }
            // Normal flow for TrustedInput and Signature modes
            (LegacyParserMode::TrustedInput, TxVersion::V5, _)
            | (LegacyParserMode::Signature, TxVersion::V5, false) => {
                debug!("Init V5 tx hashers");
                ok!(ctx.hashers.init_v5_tx_hashers());
            }
            // In case of Signature mode, continue computing Tx hash from previous state
            (LegacyParserMode::Signature, TxVersion::V5, true) => {
                info!("Resume TX hashing for signing");
                info!("TX Version {:X?}", version);
                info!("TX prevout hash {}", HexSlice(&ctx.tx_info.prevouts_hash));
                info!("TX sequence hash {}", HexSlice(&ctx.tx_info.sequence_hash));

                if input_count != 0 {
                    ok!(ctx
                        .hashers
                        .prevouts_hasher
                        .init_with_perso(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION));

                    ok!(ctx
                        .hashers
                        .scripts_hasher
                        .init_with_perso(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION));
                }
            }
            // Support V4 in trusted input mode (Transaction ID computation)
            (LegacyParserMode::TrustedInput, TxVersion::V4, _) => {
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
        if let LegacyParserMode::Signature = self.mode
            && !ctx.tx_state.is_tx_parsed_once
        {
            ctx.tx_state.total_input_count = self.input_count;
        }

        self.state = if self.input_count == 0 {
            match (self.mode, ctx.tx_state.is_tx_parsed_once) {
                (LegacyParserMode::Signature, false) => {
                    finalize_signature_input_hash(ctx)?;
                    LegacyParserState::TransactionPresignReady
                }
                (LegacyParserMode::Signature, true) => {
                    compute_no_transparent_input_signature_digest(
                        ctx.tx_info,
                        self.output_count,
                        ctx.tx_info.sighash_type,
                    )?;
                    LegacyParserState::TransactionReadyToSign
                }
                _ => LegacyParserState::InputHashingDone,
            }
        } else {
            LegacyParserState::WaitInput
        };

        Ok(())
    }

    pub fn parse_process_extra(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
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

        self.state = LegacyParserState::TransactionParsed;

        compute::tx_id(ctx)?;

        Ok(())
    }
}
