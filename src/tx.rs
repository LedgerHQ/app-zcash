use alloc::string::String;
use alloc::vec::Vec;
use ledger_device_sdk::hash::blake2::Blake2b_256;
use ledger_device_sdk::hash::sha2::Sha2_256;
use ledger_device_sdk::libcall::swap::CreateTxParams;
use ledger_device_sdk::nbgl::NbglHomeAndSettings;

use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::BranchId;

use crate::parser::{OutputParser, Parser, ParserMode};

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

pub enum SupportedTxVersion {
    V4,
    V5,
}

impl TxInfo {
    // Call only after header parsing is finished, otherwise it may panic if tx_version or branch_id is not set yet.
    pub fn tx_version(&self) -> SupportedTxVersion {
        match self
            .tx_version
            .expect("TX version should be set at this point of the parsing")
        {
            TxVersion::V4 => SupportedTxVersion::V4,
            TxVersion::V5 => SupportedTxVersion::V5,
            _ => unreachable!(
                "Unsupported transaction version, should have been rejected at version parsing"
            ),
        }
    }
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
    pub already_signed_input_count: usize,
    pub total_input_count: usize,
}

/// Transaction context holding state between APDU chunks.
pub struct TxContext<'a> {
    is_extra_header_data_set: bool,
    is_finished: bool,
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

impl<'s> TxContext<'s> {
    pub fn new(swap_params: Option<&'s CreateTxParams>, mode: ParserMode) -> TxContext<'s> {
        TxContext {
            is_extra_header_data_set: false,
            is_finished: false,
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

    pub fn reset(&mut self, mode: ParserMode) {
        // Don't reset home and swap params, they're not part of TX state
        self.is_extra_header_data_set = false;
        self.is_finished = false;
        self.tx_signing_state = TxSigningState::default();
        self.tx_info = TxInfo::default();
        self.trusted_input_info = TrustedInputInfo::default();
        self.hashers = Hashers::default();
        self.parser = Parser::new(mode);
        self.output_parser = OutputParser::new();
    }

    pub fn set_transaction_trusted_input_idx(&mut self, idx: u32) {
        self.trusted_input_info.input_idx = idx.into();
    }

    // Get signing finished or rejected by user status
    pub fn is_finished(&self) -> bool {
        self.is_finished
    }

    pub fn set_finished(&mut self) {
        self.is_finished = true;
    }

    pub fn is_extra_header_data_set(&self) -> bool {
        self.is_extra_header_data_set
    }

    pub fn set_extra_header_data(&mut self) {
        self.is_extra_header_data_set = true;
    }
}
