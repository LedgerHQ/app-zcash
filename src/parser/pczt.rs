use alloc::{string::ToString, vec::Vec};
use core::{cmp, mem};

use core2::io::Read;
use ledger_device_sdk::hash::{HashInit as _, blake2::Blake2b_256};
use ledger_device_sdk::libcall::swap::CreateTxParams;
use ledger_device_sdk::log::{debug, info};
use zcash_encoding::CompactSize;
use zcash_primitives::encoding::ReadBytesExt;
use zcash_primitives::transaction::TxVersion;
use zcash_primitives::transaction::sighash_v5::ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION;
use zcash_protocol::consensus::BranchId;
use zcash_protocol::constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::OutPoint;

use crate::AppSW;
use crate::app_ui::sign::ui_display_tx;
use crate::consts::{MAX_OUTPUTS_NUMBER, MAX_SCRIPT_SIZE, MAX_TRANSPARENT_INPUTS_NUMBER};
use crate::parser::compute::finalize_signature_hash_from_txin_digest;
use crate::swap;
use crate::tx::{Hashers, TxInfo, TxOutput, TxSigningState};
use crate::utils::blake2b_256_pers::{AsWriter as _, Blake2b256Personalization as _};
use crate::utils::check_output_displayable;
use crate::utils::{
    Bip44CheckMode, CheckDispOutput, HexSlice,
    base58_address::{Base58Address, ToBase58Address},
    bip32_path::{Bip32Path, MAX_ZCASH_BIP32_PATH},
    check_bip44_compliance,
};

use super::reader::ByteReader;
use super::{ParserError, ok};

const MAGIC_BYTES: &[u8; 4] = b"PCZT";
const PCZT_VERSION_1: u32 = 1;
const DEFAULT_SEQUENCE: u32 = 0xFFFF_FFFF;
const PREVOUT_SIZE: usize = 32 + 4;
const SIGHASH_ALL: u8 = 0x01;
const COMPRESSED_PUBKEY_SIZE: usize = 33;
const ZIP32_SEED_FINGERPRINT_SIZE: usize = 32;
const ZIP32_DERIVATION_PATH_COUNT_OFFSET: usize =
    COMPRESSED_PUBKEY_SIZE + ZIP32_SEED_FINGERPRINT_SIZE;
const ZIP32_DERIVATION_MIN_SIZE: usize = ZIP32_DERIVATION_PATH_COUNT_OFFSET + 1;

enum PathCountParse {
    NeedMore(usize),
    Ready {
        path_count: usize,
        path_offset: usize,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum PcztParserState {
    #[default]
    None,
    WaitTransparentInput,
    ProcessTransparentInputScript {
        size: usize,
        remaining_size: usize,
    },
    WaitTransparentInputSighashType,
    WaitTransparentInputBip32Derivation,
    ProcessTransparentInputBip32Derivation {
        expected_size: Option<usize>,
    },
    TransparentInputsDone,
    WaitTransparentOutput,
    ProcessTransparentOutputScript {
        size: usize,
        remaining_size: usize,
    },
    TransparentOutputsDone,
}

struct PcztTransparentInputRecord {
    prevout: [u8; PREVOUT_SIZE],
    sequence: u32,
    amount: [u8; 8],
    script_pubkey: Vec<u8>,
    sighash_type: u8,
    path: Bip32Path,
}

pub struct PcztParserCtx<'ctx> {
    pub tx_state: &'ctx mut TxSigningState,
    pub tx_info: &'ctx mut TxInfo,
    pub hashers: &'ctx mut Hashers,
    pub swap_params: Option<&'ctx CreateTxParams>,
}

pub struct PcztParser {
    state: PcztParserState,
    transparent_input_count: usize,
    transparent_input_parsed_count: usize,
    transparent_inputs: Vec<PcztTransparentInputRecord>,
    transparent_output_count: usize,
    transparent_output_parsed_count: usize,
    current_input_prevout: [u8; PREVOUT_SIZE],
    current_input_sequence: u32,
    current_input_amount: [u8; 8],
    current_input_script_pubkey: Vec<u8>,
    current_input_sighash_type: u8,
    current_output_amount: u64,
    total_output_amount: u64,
    script_bytes: Vec<u8>,
    bip32_derivation_bytes: Vec<u8>,
}

impl PcztParser {
    // APDU payload formats for this PCZT transparent parser.
    //
    // This is a compact APDU subset whose field order mirrors the pczt crate structs
    // we consume: `Pczt`, `common::Global`, then `transparent::Input` or
    // `transparent::Output`.
    //
    // Primitive encoding:
    //   u8/u32/u64        little-endian, except u8
    //   Option<T>         0x00 for None, 0x01 followed by T for Some
    //   Vec<T>            CompactSize byte count, followed by bytes
    //
    // PCZT header fields:
    //   magic                  "PCZT"
    //   version                u32, must be 1
    //
    // common::Global fields, in order:
    //   tx_version             u32
    //   version_group_id       u32
    //   consensus_branch_id    u32
    //   fallback_lock_time     Option<u32>
    //   expiry_height          u32
    //   coin_type              u32
    //   tx_modifiable          u8
    //
    // transparent::Bundle subset:
    //   `Pczt` header and `common::Global` are sent exactly once at the
    //   beginning of `PCZT_TRANSPARENT_INPUT`; `PCZT_TRANSPARENT_OUTPUT` starts
    //   from its own bundle fields.
    //   inputs                 Vec<Input> as CompactSize count, followed by inputs
    //   outputs                Vec<Output> as CompactSize count, followed by outputs
    //
    // transparent::Input fields, in order:
    //   prevout_txid           [u8; 32]
    //   prevout_index          u32
    //   sequence               Option<u32>
    //   required_time_lock_time SKIPPED
    //   required_height_lock_time SKIPPED
    //   script_sig             SKIPPED
    //   value                  u64
    //   script_pubkey          Vec<u8>
    //   redeem_script          SKIPPED
    //   partial_signatures     SKIPPED
    //   sighash_type           u8
    //   bip32_derivation       BTreeMap<[u8; 33], Zip32Derivation> as:
    //                            CompactSize entry count, followed by entries:
    //                              key compressed_pubkey [u8; 33]
    //                              seed_fingerprint [u8; 32]
    //                              derivation_path Vec<u32> as CompactSize count
    //                                followed by LE u32 path segments
    //                            exactly one entry is currently used
    //   ripemd160_preimages    SKIPPED
    //   sha256_preimages       SKIPPED
    //   hash160_preimages      SKIPPED
    //   hash256_preimages      SKIPPED
    //   proprietary            SKIPPED
    //
    // transparent::Output fields, in order:
    //   value                  u64
    //   script_pubkey          Vec<u8>
    //   redeem_script          SKIPPED
    //   bip32_derivation       SKIPPED
    //   user_address           SKIPPED
    //   proprietary            SKIPPED
    //
    pub fn new() -> Self {
        Self {
            state: PcztParserState::None,
            transparent_input_count: 0,
            transparent_input_parsed_count: 0,
            transparent_inputs: Vec::new(),
            transparent_output_count: 0,
            transparent_output_parsed_count: 0,
            current_input_prevout: [0; PREVOUT_SIZE],
            current_input_sequence: 0,
            current_input_amount: [0; 8],
            current_input_script_pubkey: Vec::new(),
            current_input_sighash_type: SIGHASH_ALL,
            current_output_amount: 0,
            total_output_amount: 0,
            script_bytes: Vec::new(),
            bip32_derivation_bytes: Vec::new(),
        }
    }

    pub fn is_transparent_inputs_finished(&self) -> bool {
        matches!(
            self.state,
            PcztParserState::TransparentInputsDone
                | PcztParserState::WaitTransparentOutput
                | PcztParserState::ProcessTransparentOutputScript { .. }
                | PcztParserState::TransparentOutputsDone
        )
    }

    pub fn is_finished(&self) -> bool {
        self.state == PcztParserState::TransparentOutputsDone
    }

    pub fn parse_transparent_inputs(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        data: &[u8],
    ) -> Result<(), ParserError> {
        let mut reader = ByteReader::new(data);

        while reader.remaining_len() > 0 {
            let prev_state = self.state;

            match self.state {
                PcztParserState::None => self.parse_transparent_inputs_start(ctx, &mut reader)?,
                PcztParserState::WaitTransparentInput => {
                    self.parse_transparent_input(ctx, &mut reader)?
                }
                PcztParserState::ProcessTransparentInputScript {
                    size,
                    remaining_size,
                } => self.parse_transparent_input_script(ctx, &mut reader, size, remaining_size)?,
                PcztParserState::WaitTransparentInputSighashType => {
                    self.parse_transparent_input_sighash_type(ctx, &mut reader)?
                }
                PcztParserState::WaitTransparentInputBip32Derivation => {
                    self.parse_transparent_input_bip32_derivation(ctx, &mut reader)?
                }
                PcztParserState::ProcessTransparentInputBip32Derivation { expected_size } => self
                    .parse_transparent_input_bip32_derivation_bytes(
                    ctx,
                    &mut reader,
                    expected_size,
                )?,
                PcztParserState::TransparentInputsDone
                | PcztParserState::WaitTransparentOutput
                | PcztParserState::ProcessTransparentOutputScript { .. }
                | PcztParserState::TransparentOutputsDone => {
                    return Err(ParserError::from_sw(AppSW::BadState));
                }
            }

            if self.state != prev_state {
                info!(
                    "PCZT parser state changed: {:?} -> {:?}",
                    prev_state, self.state
                );
            }
        }

        Ok(())
    }

    pub fn parse_transparent_outputs(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        data: &[u8],
    ) -> Result<(), ParserError> {
        let mut reader = ByteReader::new(data);

        while reader.remaining_len() > 0 {
            let prev_state = self.state;

            match self.state {
                PcztParserState::TransparentInputsDone => {
                    self.parse_transparent_outputs_start(ctx, &mut reader)?
                }
                PcztParserState::WaitTransparentOutput => {
                    self.parse_transparent_output(ctx, &mut reader)?
                }
                PcztParserState::ProcessTransparentOutputScript {
                    size,
                    remaining_size,
                } => {
                    self.parse_transparent_output_script(ctx, &mut reader, size, remaining_size)?
                }
                PcztParserState::None
                | PcztParserState::WaitTransparentInput
                | PcztParserState::WaitTransparentInputSighashType
                | PcztParserState::WaitTransparentInputBip32Derivation
                | PcztParserState::ProcessTransparentInputBip32Derivation { .. }
                | PcztParserState::ProcessTransparentInputScript { .. }
                | PcztParserState::TransparentOutputsDone => {
                    return Err(ParserError::from_sw(AppSW::BadState));
                }
            }

            if self.state != prev_state {
                info!(
                    "PCZT parser state changed: {:?} -> {:?}",
                    prev_state, self.state
                );
            }
        }

        Ok(())
    }

    fn parse_transparent_inputs_start(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT transparent inputs start");

        ok!(ctx.hashers.init_v5_tx_hashers());
        ctx.tx_info.tx_version = Some(TxVersion::V5);
        ctx.tx_info.total_amount = 0;

        self.parse_pczt_header(reader)?;
        self.parse_global(ctx, reader)?;

        let input_count: usize = ok!(CompactSize::read_t(&mut *reader));
        if input_count > MAX_TRANSPARENT_INPUTS_NUMBER {
            return Err(ParserError::from_str("Too many PCZT transparent inputs"));
        }

        debug!("PCZT transparent input count: {}", input_count);

        self.transparent_input_count = input_count;
        self.transparent_input_parsed_count = 0;
        self.transparent_inputs.clear();
        self.current_input_script_pubkey.clear();
        self.current_input_sighash_type = SIGHASH_ALL;
        self.bip32_derivation_bytes.clear();
        ctx.tx_state.total_input_count = input_count;

        if input_count == 0 {
            self.finalize_transparent_inputs(ctx)?;
        } else {
            self.state = PcztParserState::WaitTransparentInput;
        }

        Ok(())
    }

    fn parse_transparent_outputs_start(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT transparent outputs start");

        let output_count: usize = ok!(CompactSize::read_t(&mut *reader));
        if output_count > MAX_OUTPUTS_NUMBER {
            return Err(ParserError::from_str("Too many PCZT transparent outputs"));
        }

        debug!("PCZT transparent output count: {}", output_count);

        self.transparent_output_count = output_count;
        self.transparent_output_parsed_count = 0;
        self.current_output_amount = 0;
        self.total_output_amount = 0;
        ctx.tx_info.outputs.clear();
        ctx.tx_info.is_change_found = false;

        if output_count == 0 {
            self.finalize_transparent_outputs(ctx)?;
        } else {
            self.state = PcztParserState::WaitTransparentOutput;
        }

        Ok(())
    }

    fn parse_pczt_header(&mut self, reader: &mut ByteReader<'_>) -> Result<(), ParserError> {
        let mut magic = [0u8; 4];
        ok!(reader.read_exact(&mut magic));

        if &magic != MAGIC_BYTES {
            return Err(ParserError::from_str("Bad PCZT magic bytes"));
        }

        let version = ok!(reader.read_u32_le());
        if version != PCZT_VERSION_1 {
            return Err(ParserError::from_str("Unsupported PCZT version"));
        }

        debug!("PCZT header: magic {:?}, version {}", magic, version);

        Ok(())
    }

    fn parse_global(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let tx_version = ok!(reader.read_u32_le());
        let version_group_id = ok!(reader.read_u32_le());

        if tx_version != V5_TX_VERSION || version_group_id != V5_VERSION_GROUP_ID {
            return Err(ParserError::from_str(
                "Unsupported PCZT transaction version",
            ));
        }

        let consensus_branch_id = ok!(BranchId::try_from(ok!(reader.read_u32_le())));
        let fallback_lock_time = self.read_optional_u32(reader)?;
        let expiry_height = ok!(reader.read_u32_le());
        let coin_type = ok!(reader.read_u32_le());
        let tx_modifiable = ok!(reader.read_u8());

        debug!(
            "PCZT global: version {}, version_group_id {:08x}, branch {:?}, fallback_lock_time {:?}, expiry_height {}, coin_type {}, tx_modifiable {:02x}",
            tx_version,
            version_group_id,
            consensus_branch_id,
            fallback_lock_time,
            expiry_height,
            coin_type,
            tx_modifiable
        );

        ctx.tx_info.tx_version = Some(TxVersion::V5);
        ctx.tx_info.branch_id = Some(consensus_branch_id);
        ctx.tx_info.locktime = fallback_lock_time.unwrap_or_default();
        ctx.tx_info.expiry_height = expiry_height;

        Ok(())
    }

    fn parse_transparent_input(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        if self.transparent_input_parsed_count >= self.transparent_input_count {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        if reader.remaining_len() < PREVOUT_SIZE {
            return Err(ParserError::from_str(
                "Not enough PCZT transparent input prevout bytes",
            ));
        }

        self.current_input_prevout
            .copy_from_slice(&reader.remaining_slice()[..PREVOUT_SIZE]);

        let prevout = ok!(OutPoint::read(&mut *reader));
        ok!(prevout.write(ctx.hashers.prevouts_hasher.as_writer()));
        debug!(
            "PCZT transparent input #{} prevout: {:?}",
            self.transparent_input_parsed_count, prevout
        );

        self.current_input_sequence = self.read_optional_u32(reader)?.unwrap_or(DEFAULT_SEQUENCE);
        ok!(ctx
            .hashers
            .sequence_hasher
            .update(&self.current_input_sequence.to_le_bytes()));
        debug!(
            "PCZT transparent input #{} sequence: {:08x}",
            self.transparent_input_parsed_count, self.current_input_sequence
        );

        let amount = ok!({
            ok!(reader.read_exact(&mut self.current_input_amount));
            ok!(ctx
                .hashers
                .amounts_hasher
                .update(&self.current_input_amount));
            Zatoshis::from_nonnegative_i64_le_bytes(self.current_input_amount)
        });
        ctx.tx_info.total_amount = ctx.tx_info.total_amount.saturating_add(amount.into_u64());
        debug!(
            "PCZT transparent input #{} amount: {}",
            self.transparent_input_parsed_count,
            amount.into_u64()
        );

        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));
        if script_size > MAX_SCRIPT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT transparent input script size",
            ));
        }

        debug!(
            "PCZT transparent input #{} scriptPubKey size: {}",
            self.transparent_input_parsed_count, script_size
        );

        self.script_bytes.clear();
        self.script_bytes.resize(script_size, 0);

        if script_size == 0 {
            self.finish_transparent_input_script(ctx, script_size)?;
        } else {
            self.state = PcztParserState::ProcessTransparentInputScript {
                size: script_size,
                remaining_size: script_size,
            };
        }

        Ok(())
    }

    fn parse_transparent_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        if self.transparent_output_parsed_count >= self.transparent_output_count {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        let amount = ok!({
            let mut amount_bytes = [0u8; 8];
            ok!(reader.read_exact(&mut amount_bytes));
            ok!(ctx.hashers.outputs_hasher.update(&amount_bytes));
            Zatoshis::from_nonnegative_i64_le_bytes(amount_bytes)
        });

        self.current_output_amount = amount.into_u64();
        self.total_output_amount = self
            .total_output_amount
            .saturating_add(self.current_output_amount);

        debug!(
            "PCZT transparent output #{} amount: {}",
            self.transparent_output_parsed_count, self.current_output_amount
        );

        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));
        if script_size > MAX_SCRIPT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT transparent output script size",
            ));
        }

        debug!(
            "PCZT transparent output #{} scriptPubKey size: {}",
            self.transparent_output_parsed_count, script_size
        );

        self.script_bytes.clear();
        self.script_bytes.resize(script_size, 0);

        if script_size == 0 {
            self.finish_transparent_output_script(ctx, script_size)?;
        } else {
            self.state = PcztParserState::ProcessTransparentOutputScript {
                size: script_size,
                remaining_size: script_size,
            };
        }

        Ok(())
    }

    fn parse_transparent_input_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        let offset = size - remaining_size;
        let len = ok!(reader.read(&mut self.script_bytes[offset..][..remaining_size]));
        let new_remaining_size = remaining_size.saturating_sub(len);

        if new_remaining_size != 0 {
            self.state = PcztParserState::ProcessTransparentInputScript {
                size,
                remaining_size: new_remaining_size,
            };
            debug!(
                "Need more PCZT transparent input script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        self.finish_transparent_input_script(ctx, size)
    }

    fn parse_transparent_input_sighash_type(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let sighash_type = ok!(reader.read_u8());
        if sighash_type != SIGHASH_ALL {
            return Err(ParserError::from_str(
                "Unsupported PCZT transparent sighash type",
            ));
        }

        debug!(
            "PCZT transparent input #{} sighash_type: {:02x}",
            self.transparent_input_parsed_count, sighash_type
        );

        self.current_input_sighash_type = sighash_type;
        self.state = PcztParserState::WaitTransparentInputBip32Derivation;

        Ok(())
    }

    fn parse_transparent_input_bip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let derivation_count: usize = ok!(CompactSize::read_t(&mut *reader));
        if derivation_count != 1 {
            return Err(ParserError::from_str(
                "Expected exactly one PCZT input bip32 derivation",
            ));
        }

        debug!(
            "PCZT transparent input #{} bip32 derivation count: {}",
            self.transparent_input_parsed_count, derivation_count
        );

        self.bip32_derivation_bytes.clear();
        self.state = PcztParserState::ProcessTransparentInputBip32Derivation {
            expected_size: None,
        };
        self.parse_transparent_input_bip32_derivation_bytes(ctx, reader, None)
    }

    fn parse_transparent_input_bip32_derivation_bytes(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        mut expected_size: Option<usize>,
    ) -> Result<(), ParserError> {
        loop {
            let (target_size, is_header_target) = if let Some(size) = expected_size {
                (size, false)
            } else {
                match Self::parse_derivation_path_count(&self.bip32_derivation_bytes)? {
                    PathCountParse::NeedMore(size) => (size, true),
                    PathCountParse::Ready {
                        path_count,
                        path_offset,
                    } => {
                        let size = path_offset + path_count * 4;
                        debug!(
                            "PCZT transparent input #{} bip32 derivation path len: {}",
                            self.transparent_input_parsed_count, path_count
                        );
                        (size, false)
                    }
                }
            };

            let missing = target_size.saturating_sub(self.bip32_derivation_bytes.len());

            if missing > 0 {
                let to_read = cmp::min(missing, reader.remaining_len());
                if to_read == 0 {
                    let expected_size = if is_header_target {
                        None
                    } else {
                        Some(target_size)
                    };
                    self.state =
                        PcztParserState::ProcessTransparentInputBip32Derivation { expected_size };
                    debug!(
                        "Need more PCZT transparent input bip32 derivation bytes, currently read: {}",
                        self.bip32_derivation_bytes.len()
                    );
                    return Ok(());
                }

                let offset = self.bip32_derivation_bytes.len();
                self.bip32_derivation_bytes.resize(offset + to_read, 0);
                ok!(reader.read_exact(&mut self.bip32_derivation_bytes[offset..]));
            }

            if self.bip32_derivation_bytes.len() == target_size {
                if is_header_target {
                    expected_size = None;
                    continue;
                }

                return self.finish_transparent_input_bip32_derivation(ctx);
            }
        }
    }

    fn parse_derivation_path_count(data: &[u8]) -> Result<PathCountParse, ParserError> {
        if data.len() < ZIP32_DERIVATION_MIN_SIZE {
            return Ok(PathCountParse::NeedMore(ZIP32_DERIVATION_MIN_SIZE));
        }

        let count_offset = ZIP32_DERIVATION_PATH_COUNT_OFFSET;
        let first = data[count_offset];
        let (path_count, compact_size_len) = match first {
            0x00..=0xfc => (first as usize, 1),
            0xfd => {
                let size = count_offset + 3;
                if data.len() < size {
                    return Ok(PathCountParse::NeedMore(size));
                }

                (
                    u16::from_le_bytes(data[count_offset + 1..count_offset + 3].try_into().unwrap())
                        as usize,
                    3,
                )
            }
            0xfe => {
                let size = count_offset + 5;
                if data.len() < size {
                    return Ok(PathCountParse::NeedMore(size));
                }

                (
                    u32::from_le_bytes(data[count_offset + 1..count_offset + 5].try_into().unwrap())
                        as usize,
                    5,
                )
            }
            0xff => {
                let size = count_offset + 9;
                if data.len() < size {
                    return Ok(PathCountParse::NeedMore(size));
                }

                let path_count = u64::from_le_bytes(
                    data[count_offset + 1..count_offset + 9].try_into().unwrap(),
                );
                if path_count > usize::MAX as u64 {
                    return Err(ParserError::from_str(
                        "Bad PCZT input bip32 derivation path length",
                    ));
                }

                (path_count as usize, 9)
            }
        };

        if path_count > MAX_ZCASH_BIP32_PATH {
            return Err(ParserError::from_str(
                "Bad PCZT input bip32 derivation path length",
            ));
        }

        Ok(PathCountParse::Ready {
            path_count,
            path_offset: count_offset + compact_size_len,
        })
    }

    fn finish_transparent_input_bip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        let derivation = mem::take(&mut self.bip32_derivation_bytes);
        let pubkey = &derivation[..COMPRESSED_PUBKEY_SIZE];
        let _seed_fingerprint =
            &derivation[COMPRESSED_PUBKEY_SIZE..ZIP32_DERIVATION_PATH_COUNT_OFFSET];
        let (path_count, path_offset) = match Self::parse_derivation_path_count(&derivation)? {
            PathCountParse::Ready {
                path_count,
                path_offset,
            } => (path_count, path_offset),
            PathCountParse::NeedMore(_) => {
                return Err(ParserError::from_str(
                    "Incomplete PCZT input bip32 derivation",
                ));
            }
        };

        let mut derivation_path = Vec::new();
        for chunk in derivation[path_offset..path_offset + path_count * 4].chunks_exact(4) {
            derivation_path.push(u32::from_le_bytes(chunk.try_into().unwrap()));
        }

        let path = ok!(Bip32Path::try_from(derivation_path.as_slice()));

        if !check_bip44_compliance(&path, Bip44CheckMode::OnlyCoinType) {
            return Err(ParserError::from_str(
                "PCZT transparent signing path not compliant",
            ));
        }

        debug!(
            "PCZT transparent input #{} bip32 derivation pubkey: {}",
            self.transparent_input_parsed_count,
            HexSlice(pubkey)
        );
        debug!(
            "PCZT transparent input #{} seed fingerprint: {}",
            self.transparent_input_parsed_count,
            HexSlice(_seed_fingerprint)
        );
        debug!(
            "PCZT transparent input #{} signing path: {:?}",
            self.transparent_input_parsed_count, path
        );

        self.transparent_inputs.push(PcztTransparentInputRecord {
            prevout: self.current_input_prevout,
            sequence: self.current_input_sequence,
            amount: self.current_input_amount,
            script_pubkey: mem::take(&mut self.current_input_script_pubkey),
            sighash_type: self.current_input_sighash_type,
            path,
        });

        self.transparent_input_parsed_count = self.transparent_input_parsed_count.saturating_add(1);

        if self.transparent_input_count == self.transparent_input_parsed_count {
            self.finalize_transparent_inputs(ctx)?;
        } else {
            self.state = PcztParserState::WaitTransparentInput;
        }

        Ok(())
    }

    fn parse_transparent_output_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        let offset = size - remaining_size;
        let len = ok!(reader.read(&mut self.script_bytes[offset..][..remaining_size]));
        let new_remaining_size = remaining_size.saturating_sub(len);

        if new_remaining_size != 0 {
            self.state = PcztParserState::ProcessTransparentOutputScript {
                size,
                remaining_size: new_remaining_size,
            };
            debug!(
                "Need more PCZT transparent output script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        self.finish_transparent_output_script(ctx, size)
    }

    fn finish_transparent_input_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        size: usize,
    ) -> Result<(), ParserError> {
        if size != self.script_bytes.len() {
            return Err(ParserError::from_str(
                "Bad PCZT transparent input script length",
            ));
        }

        let script_bytes = mem::take(&mut self.script_bytes);
        let mut script_pubkey = Script::default();
        script_pubkey.0.0 = script_bytes.clone();
        ok!(script_pubkey.write(ctx.hashers.scripts_hasher.as_writer()));
        debug!(
            "PCZT transparent input #{} scriptPubKey: {:?}",
            self.transparent_input_parsed_count, script_pubkey
        );

        self.current_input_script_pubkey = script_bytes;
        self.state = PcztParserState::WaitTransparentInputSighashType;

        Ok(())
    }

    pub fn compute_transparent_signature_digest(
        &self,
        tx_info: &mut TxInfo,
        input_index: usize,
    ) -> Result<u8, ParserError> {
        if !self.is_finished() {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        let input = self
            .transparent_inputs
            .get(input_index)
            .ok_or_else(|| ParserError::from_str("Bad PCZT transparent input index"))?;

        let mut txin_sig_digest = [0u8; 32];
        let mut hasher = Blake2b_256::default();
        ok!(hasher.init_with_perso(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION));
        ok!(hasher.update(&input.prevout));
        ok!(hasher.update(&input.amount));

        let mut script_pubkey = Script::default();
        script_pubkey.0.0 = input.script_pubkey.clone();
        ok!(script_pubkey.write(hasher.as_writer()));

        ok!(hasher.update(&input.sequence.to_le_bytes()));
        ok!(hasher.finalize(&mut txin_sig_digest));
        debug!(
            "PCZT transparent input #{} txin sig digest: {}",
            input_index,
            HexSlice(&txin_sig_digest)
        );

        tx_info.sighash_type = input.sighash_type;
        finalize_signature_hash_from_txin_digest(tx_info, &txin_sig_digest, input.sighash_type)?;

        Ok(input.sighash_type)
    }

    pub fn transparent_input_signing_path(
        &self,
        input_index: usize,
    ) -> Result<&Bip32Path, ParserError> {
        if !self.is_finished() {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        self.transparent_inputs
            .get(input_index)
            .map(|input| &input.path)
            .ok_or_else(|| ParserError::from_str("Bad PCZT transparent input index"))
    }

    fn finish_transparent_output_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        size: usize,
    ) -> Result<(), ParserError> {
        if size != self.script_bytes.len() {
            return Err(ParserError::from_str(
                "Bad PCZT transparent output script length",
            ));
        }

        let mut script_pubkey = Script::default();
        script_pubkey.0.0 = mem::take(&mut self.script_bytes);
        ok!(script_pubkey.write(ctx.hashers.outputs_hasher.as_writer()));
        debug!(
            "PCZT transparent output #{} scriptPubKey: {:?}",
            self.transparent_output_parsed_count, script_pubkey
        );

        if let output @ (CheckDispOutput::Change | CheckDispOutput::Displayable) =
            check_output_displayable(
                &script_pubkey.0.0,
                self.current_output_amount,
                &ctx.tx_info.change_pk_hash,
            )
        {
            let is_change = output == CheckDispOutput::Change;

            if is_change && ctx.tx_info.is_change_found {
                return Err(ParserError::from_str("Multiple change outputs detected"));
            }

            let address = ok!(Base58Address::from_output_script(&script_pubkey.0.0)).to_string();
            debug!("PCZT transparent output address: {}", &address);

            ctx.tx_info.outputs.push(TxOutput {
                amount: self.current_output_amount,
                address,
                is_change,
            });

            if is_change {
                ctx.tx_info.is_change_found = true;
            }
        }

        self.transparent_output_parsed_count =
            self.transparent_output_parsed_count.saturating_add(1);

        if self.transparent_output_count == self.transparent_output_parsed_count {
            self.finalize_transparent_outputs(ctx)?;
        } else {
            self.state = PcztParserState::WaitTransparentOutput;
        }

        Ok(())
    }

    fn read_optional_u32(
        &mut self,
        reader: &mut ByteReader<'_>,
    ) -> Result<Option<u32>, ParserError> {
        match ok!(reader.read_u8()) {
            0 => Ok(None),
            1 => Ok(Some(ok!(reader.read_u32_le()))),
            _ => Err(ParserError::from_str("Bad PCZT Option<u32> tag")),
        }
    }

    fn finalize_transparent_inputs(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT transparent inputs hashing done");

        ok!(ctx
            .hashers
            .prevouts_hasher
            .finalize(&mut ctx.tx_info.prevouts_hash));
        debug!(
            "PCZT prevouts hash: {}",
            HexSlice(&ctx.tx_info.prevouts_hash)
        );

        ok!(ctx
            .hashers
            .sequence_hasher
            .finalize(&mut ctx.tx_info.sequence_hash));
        debug!(
            "PCZT sequence hash: {}",
            HexSlice(&ctx.tx_info.sequence_hash)
        );

        ok!(ctx
            .hashers
            .amounts_hasher
            .finalize(&mut ctx.tx_info.amounts_hash));
        debug!("PCZT amounts hash: {}", HexSlice(&ctx.tx_info.amounts_hash));

        ok!(ctx
            .hashers
            .scripts_hasher
            .finalize(&mut ctx.tx_info.scripts_hash));
        debug!("PCZT scripts hash: {}", HexSlice(&ctx.tx_info.scripts_hash));

        self.state = PcztParserState::TransparentInputsDone;

        Ok(())
    }

    fn finalize_transparent_outputs(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT transparent outputs hashing done");

        if ctx.tx_info.outputs.is_empty() {
            return Err(ParserError::from_str(
                "No displayable PCZT transparent outputs detected",
            ));
        }

        let fees_i128 = i128::from(ctx.tx_info.total_amount) - i128::from(self.total_output_amount);

        if fees_i128 < 0 {
            return Err(ParserError::from_str("Failed to calculate PCZT fees"));
        }

        let fees = u64::try_from(fees_i128)
            .map_err(|_| ParserError::from_str("PCZT fee value out of range"))?;

        if let Some(swap_params) = ctx.swap_params {
            ok!(swap::check_swap_params(
                swap_params,
                &ctx.tx_info.outputs,
                fees
            ));
        } else if !ok!(ui_display_tx(&ctx.tx_info.outputs, fees)) {
            return Err(ParserError::user());
        }

        ok!(ctx
            .hashers
            .outputs_hasher
            .finalize(&mut ctx.tx_info.outputs_hash));
        debug!("PCZT outputs hash: {}", HexSlice(&ctx.tx_info.outputs_hash));

        self.state = PcztParserState::TransparentOutputsDone;

        Ok(())
    }
}
