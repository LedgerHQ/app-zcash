use core::ptr::addr_of_mut;

use alloc::string::String;
use alloc::vec::Vec;
use ledger_device_sdk::hash::HashError;
use ledger_device_sdk::hash::blake2::Blake2b_256;
use ledger_device_sdk::hash::sha2::Sha2_256;
use ledger_device_sdk::libcall::swap::CreateTxParams;
use ledger_device_sdk::nbgl::NbglHomeAndSettings;
use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::BranchId;

use crate::parser::orchard_decipher::OrchardDecipherKeys;
use crate::parser::personalization::{
    ZCASH_OUTPUTS_HASH_PERSONALIZATION, ZCASH_PREVOUTS_HASH_PERSONALIZATION,
    ZCASH_SAPLING_HASH_PERSONALIZATION, ZCASH_SEQUENCE_HASH_PERSONALIZATION,
    ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION, ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION,
};
use crate::parser::{OutputParser, Parser, ParserMode, PcztParser};
use crate::utils::blake2b_256_pers::Blake2b256Personalization as _;
use orchard::bundle::commitments::ZCASH_ORCHARD_HASH_PERSONALIZATION;

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

    // Legacy V4 txid is SHA256d over the V4-encoded transaction bytes.
    pub v4_tx_hasher: Sha2_256,
}

impl Hashers {
    pub fn init_v5_tx_hashers(&mut self) -> Result<(), HashError> {
        self.prevouts_hasher
            .init_with_perso(ZCASH_PREVOUTS_HASH_PERSONALIZATION)?;
        self.sequence_hasher
            .init_with_perso(ZCASH_SEQUENCE_HASH_PERSONALIZATION)?;
        self.outputs_hasher
            .init_with_perso(ZCASH_OUTPUTS_HASH_PERSONALIZATION)?;
        self.amounts_hasher
            .init_with_perso(ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION)?;
        self.scripts_hasher
            .init_with_perso(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION)?;
        self.sapling_hasher
            .init_with_perso(ZCASH_SAPLING_HASH_PERSONALIZATION)?;
        self.orchard_hasher
            .init_with_perso(ZCASH_ORCHARD_HASH_PERSONALIZATION)?;

        Ok(())
    }
}

#[derive(Default)]
pub struct TxOutputMemo {
    pub label: &'static str,
    pub value: String,
}

impl TxOutputMemo {
    pub fn text(value: String) -> Self {
        Self {
            label: "Memo",
            value,
        }
    }

    pub fn hash(value: String) -> Self {
        Self {
            label: "Memo hash",
            value,
        }
    }
}

// Value pool an output belongs to. Used to classify the transfer type for the
// clear-signing review subtitle.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum TxPool {
    // Transparent (public) output.
    #[default]
    Transparent,
    // Orchard (shielded/private) output.
    Orchard,
}

#[derive(Default)]
pub struct TxOutput {
    pub amount: u64,
    pub address: String,
    pub is_change: bool,
    pub memo: Option<TxOutputMemo>,
    pub pool: TxPool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransferType {
    // Transparent inputs spent to transparent recipients.
    PublicToPublic,
    // Transparent inputs shielded into Orchard recipients.
    PublicToPrivate,
    // Orchard notes spent to transparent recipients.
    PrivateToPublic,
    // Orchard notes spent to Orchard recipients.
    PrivateToPrivate,
}

impl TransferType {
    // Classifies the transfer from the source pool and the displayed outputs.
    pub fn classify(from_private: bool, outputs: &[TxOutput]) -> Self {
        let to_private = outputs
            .iter()
            .any(|output| !output.is_change && output.pool == TxPool::Orchard);

        match (from_private, to_private) {
            (false, false) => TransferType::PublicToPublic,
            (false, true) => TransferType::PublicToPrivate,
            (true, false) => TransferType::PrivateToPublic,
            (true, true) => TransferType::PrivateToPrivate,
        }
    }

    // Human-readable subtitle shown under the review title.
    pub fn subtitle(self) -> &'static str {
        match self {
            TransferType::PublicToPublic => "Public transfer",
            TransferType::PublicToPrivate => "Transfer from public to private address",
            TransferType::PrivateToPublic => "Transfer from private to public address",
            TransferType::PrivateToPrivate => "Private transfer",
        }
    }
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
    pub change_pk_hash: Option<[u8; 20]>,

    pub prevouts_hash: [u8; 32],
    pub sequence_hash: [u8; 32],
    pub outputs_hash: [u8; 32],
    pub amounts_hash: [u8; 32],
    pub scripts_hash: [u8; 32],

    pub header_digest: [u8; 32],
    pub orchard_digest: [u8; 32],
    pub signature_digest: [u8; 32],

    pub orchard_decipher_keys: Option<OrchardDecipherKeys>,
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

#[derive(Default)]
pub struct PendingVkResponse {
    pub bytes: Vec<u8>,
    pub offset: usize,
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
    pub pczt_parser: PcztParser,
    pub output_parser: OutputParser,
    pub vk_response: Option<PendingVkResponse>,
    pub is_vk_display_finished: bool,
    /// Swap parameters if running in swap mode.
    /// Used to validate the transaction against the Exchange's request.
    pub swap_params: Option<&'a CreateTxParams>,
}

impl<'s> TxContext<'s> {
    #[inline(never)]
    pub unsafe fn init_in_place(
        ptr: *mut TxContext<'s>,
        swap_params: Option<&'s CreateTxParams>,
        mode: ParserMode,
    ) {
        unsafe {
            addr_of_mut!((*ptr).is_extra_header_data_set).write(false);
            addr_of_mut!((*ptr).is_finished).write(false);
            addr_of_mut!((*ptr).tx_signing_state).write(TxSigningState::default());
            addr_of_mut!((*ptr).tx_info).write(TxInfo::default());
            addr_of_mut!((*ptr).trusted_input_info).write(TrustedInputInfo::default());
            // NOTE: We don't need to init hashers here because they will initialized before first use in parser.
            addr_of_mut!((*ptr).home).write(NbglHomeAndSettings::default());
            addr_of_mut!((*ptr).parser).write(Parser::new(mode));
            addr_of_mut!((*ptr).pczt_parser).write(PcztParser::new());
            addr_of_mut!((*ptr).output_parser).write(OutputParser::new());
            addr_of_mut!((*ptr).vk_response).write(None);
            addr_of_mut!((*ptr).is_vk_display_finished).write(false);
            addr_of_mut!((*ptr).swap_params).write(swap_params);
        }
    }

    #[inline(never)]
    pub fn reset(&mut self, mode: ParserMode) {
        // Don't reset home and swap params, they're not part of TX state
        self.is_extra_header_data_set = false;
        self.is_finished = false;
        self.tx_signing_state = TxSigningState::default();
        self.tx_info = TxInfo::default();
        self.trusted_input_info = TrustedInputInfo::default();
        self.hashers = Hashers::default();
        self.parser = Parser::new(mode);
        self.pczt_parser = PcztParser::new();
        self.output_parser = OutputParser::new();
        self.vk_response = None;
        self.is_vk_display_finished = false;
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
