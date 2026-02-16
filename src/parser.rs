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

use core2::io::Read;
use ledger_device_sdk::hash::blake2::Blake2b_256;
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::hmac::{sha2::Sha2_256 as HmacSha256, HMACInit};
use num_enum::TryFromPrimitive;
use zcash_encoding::CompactSize;
use zcash_primitives::encoding::ReadBytesExt;
use zcash_primitives::transaction::txid::{
    ZCASH_HEADERS_HASH_PERSONALIZATION, ZCASH_OUTPUTS_HASH_PERSONALIZATION,
    ZCASH_PREVOUTS_HASH_PERSONALIZATION, ZCASH_SAPLING_HASH_PERSONALIZATION,
    ZCASH_SEQUENCE_HASH_PERSONALIZATION,
};
use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::BranchId;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::OutPoint;

use crate::handlers::sign_tx::{Hashers, TrustedInputInfo, TxInfo, TxOutput, TxSigningState};
use crate::log::{debug, error, info};
use crate::parser::compute::{finalize_signature_hash, finalize_signature_input_hash};
use crate::parser::reader::ByteReader;
use crate::settings::Settings;
use crate::utils::blake2b_256_pers::{AsWriter, AsWriterB as _, Blake2b256Personalization};
use crate::utils::{check_output_displayable, secure_memcmp, CheckDispOutput, HexSlice};
use crate::{app_ui::sign::ui_display_tx, utils::base58_address::Base58Address};
use crate::{
    consts::{MAX_OUTPUTS_NUMBER, MAX_SCRIPT_SIZE, TRUSTED_INPUT_TOTAL_SIZE},
    utils::base58_address::ToBase58Address,
};
use crate::{swap, AppSW};
use error::ok;

pub use error::{ParserError, ParserSourceError};

mod compute;
mod error;
mod orchard;
mod reader;
mod sapling;

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
        anchor: [u8; 32],
    },
    ProcessSaplingSpendsHashing,
    ProcessSaplingOutputsCompact,
    ProcessSaplingOutputsMemo {
        size: usize,
        remaining_size: usize,
    },
    ProcessSaplingOutputsNonCompact,
    ProcessSaplingOutputHashing,

    ProcessOrchardCompact,
    ProcessOrchardMemo {
        size: usize,
        remaining_size: usize,
    },
    ProcessOrchardNonCompact,
    ProcessOrchardHashing,

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
    orchard_action_parsed_count: usize,

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
            orchard_action_parsed_count: 0,

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
                ParserState::ProcessOrchardCompact => {
                    self.parse_orchard_compact(ctx, &mut reader)?
                }
                ParserState::ProcessOrchardMemo {
                    size,
                    remaining_size,
                } => self.parse_orchard_memo(ctx, &mut reader, size, remaining_size)?,
                ParserState::ProcessOrchardNonCompact => {
                    self.parse_orchard_noncompact(ctx, &mut reader)?
                }
                ParserState::ProcessOrchardHashing => {
                    self.parse_orchard_hashing(ctx, &mut reader)?
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

    fn parse_header(
        &mut self,
        ctx: &mut ParserCtx<'_>,
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

        match (self.mode, ctx.tx_state.is_tx_parsed_once) {
            // Normal flow for TrustedInput and Signature modes
            (ParserMode::TrustedInput, _) | (ParserMode::Signature, false) => {
                match version {
                    TxVersion::V5 => {
                        debug!("Init V5 tx hashers");
                        ctx.hashers
                            .prevouts_hasher
                            .init_with_perso(ZCASH_PREVOUTS_HASH_PERSONALIZATION);
                        ctx.hashers
                            .sequence_hasher
                            .init_with_perso(ZCASH_SEQUENCE_HASH_PERSONALIZATION);
                        ctx.hashers
                            .outputs_hasher
                            .init_with_perso(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
                        ctx.hashers
                            .amounts_hasher
                            .init_with_perso(ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION);
                        ctx.hashers
                            .scripts_hasher
                            .init_with_perso(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
                        ctx.hashers
                            .sapling_hasher
                            .init_with_perso(ZCASH_SAPLING_HASH_PERSONALIZATION);
                        ctx.hashers
                            .orchard_hasher
                            .init_with_perso(ZCASH_ORCHARD_HASH_PERSONALIZATION);
                    }
                    // Support V4 in trusted input mode (Transaction ID computation)
                    TxVersion::V4 if ParserMode::TrustedInput == self.mode => {
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
                            "Unsupported transaction version: {:?} in mode {:?}",
                            version, self.mode
                        );
                        return Err(ParserError::from_str("Unsupported transaction version"));
                    }
                }
            }
            // In case of Signature mode, continue computing Tx hash from previous state
            (ParserMode::Signature, true) => {
                info!("Resume TX hashing for signing");
                info!("TX Version {:X?}", version);
                info!("TX prevout hash {}", HexSlice(&ctx.tx_info.prevouts_hash));
                info!("TX sequence hash {}", HexSlice(&ctx.tx_info.sequence_hash));

                info!("Compute headers hash");

                let full_hasher = &mut ctx.hashers.tx_full_hasher;
                full_hasher.init_with_perso(ZCASH_HEADERS_HASH_PERSONALIZATION);

                ok!(version.write(&mut full_hasher.as_writer()));
                ok!(full_hasher.update(&u32::from(consensus_branch_id).to_le_bytes()));
                ok!(full_hasher.update(&ctx.tx_info.locktime.to_le_bytes()));
                ok!(full_hasher.update(&ctx.tx_info.expiry_height.to_le_bytes()));

                // Save header_digest
                ok!(full_hasher.finalize(&mut ctx.tx_info.header_digest));

                info!("NU5 header digest {}", HexSlice(&ctx.tx_info.header_digest));

                ctx.hashers
                    .prevouts_hasher
                    .init_with_perso(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION);
            }
        }

        ctx.tx_info.total_amount = 0;
        self.input_count = input_count;
        self.state = if self.input_count == 0 {
            ParserState::InputHashingDone
        } else {
            ParserState::WaitInput
        };

        Ok(())
    }

    fn parse_input(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let prevout = ok!(OutPoint::read(&mut *reader));

        // TODO: use match
        match ctx.tx_info.tx_version.expect("should be set at this point") {
            TxVersion::V5 => {
                ok!(prevout.write(ctx.hashers.prevouts_hasher.as_writer()));
            }
            TxVersion::V4 => {
                ok!(prevout.write(ctx.hashers.v4_tx_hasher.as_writer()));
            }
            _ => unreachable!("we should only support V4 and V5 at this point"),
        }

        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));

        if script_size > MAX_SCRIPT_SIZE {
            return Err(ParserError::from_str("Bad input script size"));
        }

        info!("Previous outpoint: {:?}", prevout);
        info!("Script size: {}", script_size);

        self.state = ParserState::ProcessInputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.script_bytes.clear();
        // Allocate script bytes buffer
        self.script_bytes.extend(iter::repeat_n(0, script_size));

        Ok(())
    }

    fn parse_input_signature_mode(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        debug!("Parsing input for signature mode...");

        let trusted_input_mode = TrustedInputMode::read(reader)?;

        let TrustedInputMode::Trusted = trusted_input_mode else {
            error!("Untrusted input mode is not supported for signing");
            return Err(ParserError::from_str(
                "Untrusted input mode is not supported for signing",
            ));
        };

        let trusted_input_len = ok!(reader.read_u8()) as usize;
        if trusted_input_len != TRUSTED_INPUT_TOTAL_SIZE {
            return Err(ParserError::from_str("Invalid trusted input size"));
        }

        if reader.remaining_len() < trusted_input_len {
            return Err(ParserError::from_str("Not enough data for trusted input"));
        }

        let trusted_input = &reader.remaining_slice()[..trusted_input_len];
        let trusted_input_hmac = &trusted_input[trusted_input_len - 8..][..8];
        let mut computed_hmac = [0x00u8; 8];

        // Compute HMAC-SHA256 signature over the trusted input
        let mut hmac_sha256_signer = HmacSha256::new(
            &Settings
                .trusted_input_key()
                .ok_or_else(|| ParserError::from_str("Trusted input key not set"))?,
        );

        ok!(hmac_sha256_signer.update(&trusted_input[0..trusted_input_len - 8]));
        ok!(hmac_sha256_signer.finalize(&mut computed_hmac));

        info!(
            "=====> Computed trusted input HMAC: {}",
            HexSlice(&computed_hmac)
        );
        info!(
            "=====> Provided trusted input HMAC: {}",
            HexSlice(trusted_input_hmac)
        );
        if !secure_memcmp(&computed_hmac, trusted_input_hmac) {
            error!("Trusted input HMAC mismatch");
            return Err(ParserError::from_str("Trusted input HMAC mismatch"));
        }
        info!("HMACs matched");

        // Advance reader position
        ok!({
            let mut _magic = [0u8; 2];
            reader.read_exact(&mut _magic)
        });

        ok!({
            let mut _rand_bytes = [0u8; 2];
            reader.read_exact(&mut _rand_bytes)
        });

        let prevout = ok!(OutPoint::read(&mut *reader));
        info!("Previous outpoint: {:?}", prevout);
        ok!(prevout.write(ctx.hashers.prevouts_hasher.as_writer()));

        let amount = ok!({
            let mut tmp = [0u8; 8];
            ok!(reader.read_exact(&mut tmp));
            // Hash amount
            ok!(ctx.hashers.amounts_hasher.update(&tmp));
            Zatoshis::from_nonnegative_i64_le_bytes(tmp)
        });
        ctx.tx_info.total_amount = ctx.tx_info.total_amount.saturating_add(amount.into_u64());
        info!("Input amount: {:?}", amount);
        info!("New amount: {}", ctx.tx_info.total_amount);

        ok!({
            let mut _hmac = [0u8; 8];
            reader.read_exact(&mut _hmac)
        });

        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));
        info!("Script size: {}", script_size);

        if ctx.tx_state.is_tx_parsed_once {
            ok!(ctx
                .hashers
                .prevouts_hasher
                .update(&amount.to_i64_le_bytes()));
        }

        self.state = ParserState::ProcessInputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.script_bytes.clear();
        // Allocate script bytes buffer
        self.script_bytes.extend(iter::repeat_n(0, script_size));

        Ok(())
    }

    fn parse_input_script(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        let new_remaining_size = {
            let offset = size - remaining_size;
            let len = ok!(reader.read(&mut self.script_bytes[offset..][..remaining_size]));

            remaining_size.saturating_sub(len)
        };

        if new_remaining_size != 0 {
            self.state = ParserState::ProcessInputScript {
                size,
                remaining_size: new_remaining_size,
            };
            debug!(
                "Need more script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        if size != self.script_bytes.len() {
            return Err(ParserError::from_str("Bad input script len"));
        }

        let mut script_sig = Script::default();
        // NOTE: take/deallocate self.script_bytes here
        script_sig.0 .0 = mem::take(&mut self.script_bytes);

        match ctx.tx_info.tx_version.expect("should be set at this point") {
            TxVersion::V5 => {
                ok!(script_sig.write(ctx.hashers.scripts_hasher.as_writer()));
            }
            TxVersion::V4 => {
                ok!(script_sig.write(ctx.hashers.v4_tx_hasher.as_writer()));
            }
            _ => unreachable!("we should only support V4 and V5 at this point"),
        }

        info!("Script sig: {:?}", script_sig);

        let sequence = {
            let mut sequence = [0; 4];
            ok!(reader.read_exact(&mut sequence));
            u32::from_le_bytes(sequence)
        };
        info!("Sequence: {:X?}", sequence);

        match ctx.tx_info.tx_version.expect("should be set at this point") {
            TxVersion::V5 => {
                ok!(ctx.hashers.sequence_hasher.update(&sequence.to_le_bytes()));
            }
            TxVersion::V4 => {
                //ok!(ctx.hashers.v4_tx_hasher.update(&sequence.to_le_bytes()));
                ok!(ctx
                    .hashers
                    .v4_tx_hasher
                    .as_writer()
                    .dbg_update(&sequence.to_le_bytes()));
            }
            _ => unreachable!("we should only support V4 and V5 at this point"),
        }

        if ctx.tx_state.is_tx_parsed_once {
            ok!(script_sig.write(ctx.hashers.prevouts_hasher.as_writer()));
            ok!(ctx.hashers.prevouts_hasher.update(&sequence.to_le_bytes()));
        }

        self.input_parsed_count = self.input_parsed_count.saturating_add(1);

        if self.input_count == self.input_parsed_count {
            info!("All inputs parsed");

            if self.mode == ParserMode::Signature {
                if ctx.tx_state.is_tx_parsed_once {
                    finalize_signature_hash(ctx)?;

                    self.state = ParserState::TransactionReadyToSign;
                } else {
                    finalize_signature_input_hash(ctx)?;

                    self.state = ParserState::TransactionPresignReady;

                    // Skip trailing bytes if any
                    ok!(reader.advance(reader.remaining_len()));
                }

                return Ok(());
            }

            info!("Input hashing done");

            self.state = ParserState::InputHashingDone;
        } else {
            self.state = ParserState::WaitInput;
        }

        Ok(())
    }

    fn parse_input_hashing_done(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let output_count: usize = ok!(CompactSize::read_t(&mut *reader));
        info!("Output count: {}", output_count);

        if ctx.tx_info.tx_version.expect("should be set at this point") == TxVersion::V4 {
            ok!(CompactSize::write(
                &mut ctx.hashers.v4_tx_hasher.as_writer(),
                output_count
            ));
        }

        self.output_count = output_count;
        self.state = ParserState::WaitOutput;

        Ok(())
    }

    fn parse_output(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let amount = ok!({
            let mut tmp = [0u8; 8];
            ok!(reader.read_exact(&mut tmp));
            Zatoshis::from_nonnegative_i64_le_bytes(tmp)
        });

        if ctx
            .trusted_input_info
            .input_idx
            .expect("should be set at this point")
            == self.output_parsed_count as u32
        {
            ctx.trusted_input_info.amount = amount.into_u64();
            info!(
                "Found amount for trusted input: {}",
                ctx.trusted_input_info.amount
            );
        }

        match ctx.tx_info.tx_version.expect("should be set at this point") {
            TxVersion::V5 => {
                ok!(ctx.hashers.outputs_hasher.update(&amount.to_i64_le_bytes()));
            }
            TxVersion::V4 => {
                //ok!(ctx.hashers.v4_tx_hasher.update(&amount.to_i64_le_bytes()));
                ok!(ctx
                    .hashers
                    .v4_tx_hasher
                    .as_writer()
                    .dbg_update(&amount.to_i64_le_bytes()));
            }
            _ => unreachable!("we should only support V4 and V5 at this point"),
        }

        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));

        if script_size > MAX_SCRIPT_SIZE {
            return Err(ParserError::from_str("Bad output script size"));
        }

        info!("Output amount: {:?}", amount);
        info!("Output script size: {}", script_size);

        self.state = ParserState::ProcessOutputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.script_bytes.clear();
        self.script_bytes.extend(iter::repeat_n(0, script_size));

        Ok(())
    }

    fn parse_output_script(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        let new_remaining_size = {
            let offset = size - remaining_size;
            let len = ok!(reader.read(&mut self.script_bytes[offset..][..remaining_size]));

            remaining_size.saturating_sub(len)
        };

        if new_remaining_size != 0 {
            self.state = ParserState::ProcessOutputScript {
                size,
                remaining_size: new_remaining_size,
            };
            info!(
                "Need more output script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        if size != self.script_bytes.len() {
            return Err(ParserError::from_str("Bad output script len"));
        }

        let mut script_pubkey = Script::default();
        // NOTE: take/deallocate self.script_bytes here
        script_pubkey.0 .0 = mem::take(&mut self.script_bytes);

        match ctx.tx_info.tx_version.expect("should be set at this point") {
            TxVersion::V5 => {
                ok!(script_pubkey.write(&mut ctx.hashers.outputs_hasher.as_writer()));
            }
            TxVersion::V4 => {
                ok!(script_pubkey.write(&mut ctx.hashers.v4_tx_hasher.as_writer()));
            }
            _ => unreachable!("we should only support V4 and V5 at this point"),
        }

        info!("Output script pubkey: {:?}", script_pubkey);

        self.output_parsed_count = self.output_parsed_count.saturating_add(1);

        if self.output_count == self.output_parsed_count {
            info!("All outputs parsed");
            self.state = ParserState::OutputHashingDone;
        } else {
            self.state = ParserState::WaitOutput;
        }

        Ok(())
    }

    fn parse_output_hashing_done(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Output hashing done");

        self.sapling_spend_count = ok!(CompactSize::read_t(&mut *reader));
        self.sapling_output_count = ok!(CompactSize::read_t(&mut *reader));
        self.orchard_action_count = ok!(CompactSize::read_t(&mut *reader));

        info!("Sapling spend remaining: {}", self.sapling_spend_count);
        info!("Sapling output count: {}", self.sapling_output_count);
        info!("Orchard action count: {}", self.orchard_action_count);

        self.state = if self.sapling_spend_count > 0 || self.sapling_output_count > 0 {
            ParserState::ProcessSapling
        } else if self.orchard_action_count > 0 {
            ctx.hashers
                .tx_compact_hasher
                .init_with_perso(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
            ParserState::ProcessOrchardCompact
        } else {
            ParserState::ProcessExtra
        };

        Ok(())
    }

    fn parse_process_extra(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Processing extra data...");

        ctx.tx_info.locktime = ok!(reader.read_u32_le());

        info!("Locktime: {:X?}", ctx.tx_info.locktime);

        let extra_data_len: usize = ok!(CompactSize::read_t(&mut *reader));
        info!("Extra data length: {}", extra_data_len);
        info!(
            "Extra data {}",
            HexSlice(&reader.remaining_slice()[..extra_data_len])
        );

        if let Some(TxVersion::V5) = ctx.tx_info.tx_version {
            if extra_data_len != 4 {
                error!(
                    "Expected extra data length to be 4 for expiry height, got {}",
                    extra_data_len
                );
                return Err(ParserError::from_str(
                    "Invalid extra data length for expiry height",
                ));
            }
        } else if extra_data_len != reader.remaining_len() {
            error!(
                "Expected extra data length to be {}, got {}",
                reader.remaining_len(),
                extra_data_len
            );
            return Err(ParserError::from_str("Invalid extra data length"));
        }

        ctx.tx_info.expiry_height = ok!(reader.read_u32_le());
        info!("Expiry height: {:X?}", ctx.tx_info.expiry_height);

        if let Some(TxVersion::V4) = ctx.tx_info.tx_version {
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

pub struct OutputParserCtx<'ctx> {
    pub tx_info: &'ctx mut TxInfo,
    pub hashers: &'ctx mut Hashers,
    pub swap_params: Option<&'ctx CreateTxParams>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum OutputParseState {
    ParsingNumberOfOutputs,
    ParsingOutput,
    ProcessOutputScript { size: usize, remaining_size: usize },
    OutputProcessingDone,
}

pub struct OutputParser {
    state: OutputParseState,
    output_count: usize,
    pub total_output_amount: u64,
    output_parsed_count: usize,
    current_output_amount: u64,
    script_bytes: Vec<u8>,
}

impl OutputParser {
    pub fn new() -> Self {
        OutputParser {
            state: OutputParseState::ParsingNumberOfOutputs,
            output_count: 0,
            output_parsed_count: 0,
            total_output_amount: 0,
            current_output_amount: 0,
            script_bytes: Vec::new(),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.state == OutputParseState::OutputProcessingDone
    }

    pub fn parse(&mut self, ctx: &mut OutputParserCtx<'_>, data: &[u8]) -> Result<(), ParserError> {
        let mut reader = ByteReader::new(data);

        while reader.remaining_len() > 0 {
            let prev_state = self.state;

            match &self.state {
                OutputParseState::ParsingNumberOfOutputs => {
                    let output_count: usize = ok!(CompactSize::read_t(&mut reader));
                    info!("Output count: {}", output_count);

                    if output_count > MAX_OUTPUTS_NUMBER {
                        return Err(ParserError::from_str("Too many outputs"));
                    }

                    ctx.hashers
                        .outputs_hasher
                        .init_with_perso(ZCASH_OUTPUTS_HASH_PERSONALIZATION);

                    self.output_count = output_count;
                    self.state = OutputParseState::ParsingOutput;
                }
                OutputParseState::ParsingOutput => {
                    let amount: Zatoshis = ok!({
                        let mut tmp = [0u8; 8];
                        ok!(reader.read_exact(&mut tmp));
                        Zatoshis::from_nonnegative_i64_le_bytes(tmp)
                    });

                    info!("Output amount: {:?}", amount);

                    ok!(ctx.hashers.outputs_hasher.update(&amount.to_i64_le_bytes()));

                    self.current_output_amount = amount.into_u64();
                    self.total_output_amount = self
                        .total_output_amount
                        .saturating_add(self.current_output_amount);

                    let script_size: usize = ok!(CompactSize::read_t(&mut reader));

                    if script_size > MAX_SCRIPT_SIZE {
                        return Err(ParserError::from_str("Bad output script size"));
                    }

                    info!("Output script size: {}", script_size);

                    self.script_bytes.clear();
                    self.script_bytes.extend(iter::repeat_n(0, script_size));

                    self.state = OutputParseState::ProcessOutputScript {
                        size: script_size,
                        remaining_size: script_size,
                    };
                }

                OutputParseState::ProcessOutputScript {
                    size,
                    remaining_size,
                } => {
                    let new_remaining_size = {
                        let offset = size - remaining_size;
                        let len =
                            ok!(reader.read(&mut self.script_bytes[offset..][..*remaining_size]));

                        remaining_size.saturating_sub(len)
                    };

                    if new_remaining_size != 0 {
                        self.state = OutputParseState::ProcessOutputScript {
                            size: *size,
                            remaining_size: new_remaining_size,
                        };
                        info!(
                            "Need more output script bytes, remaining size: {}",
                            new_remaining_size
                        );
                        continue;
                    }

                    let mut script = Script::default();
                    // NOTE: take/deallocate self.script_bytes here
                    script.0 .0 = mem::take(&mut self.script_bytes);
                    ok!(script.write(ctx.hashers.outputs_hasher.as_writer()));

                    if let output @ (CheckDispOutput::Change | CheckDispOutput::Displayable) =
                        check_output_displayable(
                            &script.0 .0,
                            self.current_output_amount,
                            &ctx.tx_info.change_pk_hash,
                        )
                    {
                        let is_change = output == CheckDispOutput::Change;

                        if is_change && ctx.tx_info.is_change_found {
                            error!("Multiple change outputs detected");
                            return Err(ParserError::from_str("Multiple change outputs detected"));
                        }

                        let address =
                            ok!(Base58Address::from_output_script(&script.0 .0)).to_string();
                        debug!("address_string: {}", &address);

                        ctx.tx_info.outputs.push(TxOutput {
                            amount: self.current_output_amount,
                            address,
                            is_change,
                        });

                        if is_change {
                            ctx.tx_info.is_change_found = true;
                        }
                    }

                    self.output_parsed_count = self.output_parsed_count.saturating_add(1);

                    if self.output_count == self.output_parsed_count {
                        info!("All outputs parsed");

                        let fees = ok!(ctx
                            .tx_info
                            .total_amount
                            .checked_sub(self.total_output_amount)
                            .ok_or(AppSW::IncorrectData)
                            .inspect_err(|_| error!("Failed to calculate fees")));

                        if let Some(swap_params) = ctx.swap_params {
                            ok!(swap::check_swap_params(
                                swap_params,
                                &ctx.tx_info.outputs,
                                fees
                            ));
                        } else {
                            if !ok!(ui_display_tx(&ctx.tx_info.outputs, fees)) {
                                return Err(ParserError::user());
                            }
                            info!("All outputs reviewed");
                        }

                        ok!(ctx
                            .hashers
                            .outputs_hasher
                            .finalize(&mut ctx.tx_info.outputs_hash));

                        info!("Outputs hash: {}", HexSlice(&ctx.tx_info.outputs_hash));

                        self.state = OutputParseState::OutputProcessingDone;
                    } else {
                        self.state = OutputParseState::ParsingOutput;
                    }
                }

                OutputParseState::OutputProcessingDone => {
                    break;
                }
            }

            if self.state != prev_state {
                info!(
                    "Output parser state changed: {:?} -> {:?}",
                    prev_state, self.state
                );
            }
        }

        Ok(())
    }
}
