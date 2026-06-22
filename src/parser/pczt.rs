use alloc::vec::Vec;
use core::mem;

use corez::io::Read;
use ledger_device_sdk::hash::HashInit as _;
use ledger_device_sdk::log::{debug, info};
use zcash_encoding::CompactSize;
use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::BranchId;
use zcash_protocol::constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::OutPoint;

use crate::AppSW;
use crate::consts::MAX_SCRIPT_SIZE;
use crate::tx::{Hashers, TxInfo, TxSigningState};
use crate::utils::HexSlice;
use crate::utils::blake2b_256_pers::AsWriter as _;

use super::reader::{ByteReader, ReadBytesExt};
use super::{ParserError, ok};

const MAGIC_BYTES: &[u8; 4] = b"PCZT";
const PCZT_VERSION_1: u32 = 1;
const DEFAULT_SEQUENCE: u32 = 0xFFFF_FFFF;

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum PcztParserState {
    #[default]
    None,
    WaitTransparentInput,
    ProcessTransparentInputScript {
        size: usize,
        remaining_size: usize,
    },
    TransparentInputsDone,
}

pub struct PcztParserCtx<'ctx> {
    pub tx_state: &'ctx mut TxSigningState,
    pub tx_info: &'ctx mut TxInfo,
    pub hashers: &'ctx mut Hashers,
}

pub struct PcztParser {
    state: PcztParserState,
    transparent_input_count: usize,
    transparent_input_parsed_count: usize,
    script_bytes: Vec<u8>,
}

impl PcztParser {
    // APDU payload format for this PCZT transparent-input parser.
    //
    // This is a compact APDU subset whose field order mirrors the pczt crate structs
    // we consume: `Pczt`, `common::Global`, then `transparent::Input`.
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
    //   inputs                 Vec<Input> as CompactSize count, followed by inputs
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
    //   sighash_type           SKIPPED
    //   bip32_derivation       SKIPPED
    //   ripemd160_preimages    SKIPPED
    //   sha256_preimages       SKIPPED
    //   hash160_preimages      SKIPPED
    //   hash256_preimages      SKIPPED
    //   proprietary            SKIPPED
    //
    pub fn new() -> Self {
        Self {
            state: PcztParserState::None,
            transparent_input_count: 0,
            transparent_input_parsed_count: 0,
            script_bytes: Vec::new(),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.state == PcztParserState::TransparentInputsDone
    }

    pub fn parse(&mut self, ctx: &mut PcztParserCtx<'_>, data: &[u8]) -> Result<(), ParserError> {
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
                PcztParserState::TransparentInputsDone => {
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
        debug!("PCZT transparent input count: {}", input_count);

        self.transparent_input_count = input_count;
        ctx.tx_state.total_input_count = input_count;

        if input_count == 0 {
            self.finalize_transparent_inputs(ctx)?;
        } else {
            self.state = PcztParserState::WaitTransparentInput;
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

        let prevout = ok!(OutPoint::read(&mut *reader));
        ok!(prevout.write(ctx.hashers.prevouts_hasher.as_writer()));
        debug!(
            "PCZT transparent input #{} prevout: {:?}",
            self.transparent_input_parsed_count, prevout
        );

        let sequence = self.read_optional_u32(reader)?.unwrap_or(DEFAULT_SEQUENCE);
        ok!(ctx.hashers.sequence_hasher.update(&sequence.to_le_bytes()));
        debug!(
            "PCZT transparent input #{} sequence: {:08x}",
            self.transparent_input_parsed_count, sequence
        );

        let amount = ok!({
            let mut amount_bytes = [0u8; 8];
            ok!(reader.read_exact(&mut amount_bytes));
            ok!(ctx.hashers.amounts_hasher.update(&amount_bytes));
            Zatoshis::from_nonnegative_i64_le_bytes(amount_bytes)
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

        let mut script_pubkey = Script::default();
        script_pubkey.0.0 = mem::take(&mut self.script_bytes);
        ok!(script_pubkey.write(ctx.hashers.scripts_hasher.as_writer()));
        debug!(
            "PCZT transparent input #{} scriptPubKey: {:?}",
            self.transparent_input_parsed_count, script_pubkey
        );

        self.transparent_input_parsed_count = self.transparent_input_parsed_count.saturating_add(1);

        if self.transparent_input_count == self.transparent_input_parsed_count {
            self.finalize_transparent_inputs(ctx)?;
        } else {
            self.state = PcztParserState::WaitTransparentInput;
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
}
