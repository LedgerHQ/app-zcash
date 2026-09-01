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

use ledger_device_sdk::log::error;

use crate::AppSW;
use crate::parser::orchard_decipher::OrchardDecipherKeys;
use crate::parser::personalization::ZCASH_IRONWOOD_HASH_PERSONALIZATION;
use crate::parser::personalization::{
    ZCASH_OUTPUTS_HASH_PERSONALIZATION, ZCASH_PREVOUTS_HASH_PERSONALIZATION,
    ZCASH_SAPLING_HASH_PERSONALIZATION, ZCASH_SEQUENCE_HASH_PERSONALIZATION,
    ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION, ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION,
};
use crate::parser::{LegacyOutputParser, LegacyParser, LegacyParserMode, PcztParser};
use crate::utils::blake2b_256_pers::Blake2b256Personalization as _;
use crate::utils::{bip32_path::Bip32Path, derivation_account};
use orchard::bundle::commitments::ZCASH_ORCHARD_V5_HASH_PERSONALIZATION;

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

    pub ironwood_hasher: Blake2b_256,
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
            .init_with_perso(ZCASH_ORCHARD_V5_HASH_PERSONALIZATION)?;
        self.ironwood_hasher
            .init_with_perso(ZCASH_IRONWOOD_HASH_PERSONALIZATION)?;

        Ok(())
    }
}

#[derive(Default)]
pub struct TxOutputMemo {
    /// Names the kind of memo. Composed with the index of the output at display time, since that
    /// index is the only thing tying a memo to its recipient: an output without a memo contributes
    /// no field, so a label naming the kind alone leaves the position of a memo among the memo
    /// fields unable to identify which output it came with.
    pub label: &'static str,
    pub value: String,
}

impl TxOutputMemo {
    pub fn text(value: String) -> Self {
        Self {
            label: "memo",
            value,
        }
    }

    pub fn hash(value: String) -> Self {
        Self {
            label: "memo hash",
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
    // Transfer with both public and private source or recipient pools.
    Mixed,
}

impl TransferType {
    // Classifies the transfer from the source pool and the displayed outputs.
    pub fn classify(from_public: bool, from_private: bool, outputs: &[TxOutput]) -> Self {
        let to_public = outputs
            .iter()
            .any(|output| !output.is_change && output.pool == TxPool::Transparent);
        let to_private = outputs
            .iter()
            .any(|output| !output.is_change && output.pool == TxPool::Orchard);

        if (from_public && from_private) || (to_public && to_private) {
            return TransferType::Mixed;
        }

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
            TransferType::Mixed => "Mixed pool transfer",
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
    /// Fee derived from the parsed amounts, kept for the review that runs after the outputs.
    pub fees: u64,

    pub outputs: Vec<TxOutput>,
    /// Bytes of memo text already kept for the review of this transaction.
    ///
    /// Bounds what the shielded outputs can claim on the heap: the host decides how many memos
    /// there are and how long each one is, and the review holds them all at once.
    pub retained_memo_bytes: usize,
    pub is_change_found: bool,
    pub change_pk_hash: Option<[u8; 20]>,
    /// Account component of the change path the host declared, hardening bit included.
    ///
    /// Kept so the signature can be refused when it would spend from a different account than the
    /// one the hidden change returns to.
    pub change_account: Option<u32>,

    pub prevouts_hash: [u8; 32],
    pub sequence_hash: [u8; 32],
    pub outputs_hash: [u8; 32],
    pub amounts_hash: [u8; 32],
    pub scripts_hash: [u8; 32],

    pub header_digest: [u8; 32],
    pub orchard_digest: [u8; 32],
    pub signature_digest: [u8; 32],

    pub ironwood_digest: [u8; 32],
    pub is_v6: bool,
    pub has_ironwood_bundle: bool,
    pub branch_id_raw: u32,

    pub orchard_decipher_keys: Option<OrchardDecipherKeys>,
}

/// Refuse a signature that would spend from an account other than the one the change returns to.
///
/// A transparent change output is dropped from the review, so nothing on screen says where its
/// value goes. That is only acceptable while it comes back to the account being spent. Checked at
/// signing rather than while parsing because the transparent outputs are parsed before the shielded
/// bundles, so a shielded spend paying transparent change has no account to compare against yet.
///
/// Every signing path is accepted: BIP-44 for a transparent input, ZIP-32 for an Orchard or an
/// Ironwood action. **Every path that releases a signature must call this** — legacy `HASH_SIGN` and
/// the three PCZT signing handlers alike — since any one of them signs the same approved digest, and
/// a single unchecked path is enough to redirect the whole change amount. It lives here, beside the
/// account it reads, so that a new signing path has one rule to adopt rather than one to copy.
///
/// The shielded outputs need no equivalent check — a note counts as change only when it decrypts
/// under the viewing key derived from the very spending key that signs the action, and the parser
/// already refuses a second shielded action declaring another path.
pub fn check_change_returns_to_signing_account(
    tx_info: &TxInfo,
    path: &Bip32Path,
) -> Result<(), AppSW> {
    let Some(change_account) = tx_info.change_account else {
        return Ok(());
    };

    if derivation_account(path) != Some(change_account) {
        error!("Change account differs from the signing account");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    Ok(())
}

pub enum SupportedTxVersion {
    V4,
    V5,
    V6,
}

impl TxInfo {
    // Call only after header parsing is finished, otherwise it may panic if tx_version or branch_id is not set yet.
    pub fn tx_version(&self) -> SupportedTxVersion {
        if self.is_v6 {
            return SupportedTxVersion::V6;
        }
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
    pub legacy_parser: LegacyParser,
    pub pczt_parser: PcztParser,
    pub legacy_output_parser: LegacyOutputParser,
    pub vk_response: Option<PendingVkResponse>,
    pub is_vk_display_finished: bool,
    /// Swap parameters if running in swap mode.
    /// Used to validate the transaction against the Exchange's request.
    pub swap_params: Option<&'a CreateTxParams>,
    /// Whether a signature has already left the device during this run of the app.
    ///
    /// Deliberately outside the scope of [`TxContext::reset`]: a signature cannot be recalled, so
    /// this has to outlive the transaction state a host can reset at will.
    has_released_signature: bool,
}

impl<'s> TxContext<'s> {
    // Initializes `TxContext` directly at `ptr` without materializing the whole
    // context on the stack during a reset.
    //
    // # Safety
    //
    // `ptr` must be valid for writes, properly aligned, and point to storage
    // for a `TxContext<'s>`.
    #[inline(never)]
    pub unsafe fn init_in_place(
        ptr: *mut TxContext<'s>,
        swap_params: Option<&'s CreateTxParams>,
        mode: LegacyParserMode,
    ) {
        unsafe {
            addr_of_mut!((*ptr).is_extra_header_data_set).write(false);
            addr_of_mut!((*ptr).is_finished).write(false);
            addr_of_mut!((*ptr).tx_signing_state).write(TxSigningState::default());
            addr_of_mut!((*ptr).tx_info).write(TxInfo::default());
            addr_of_mut!((*ptr).trusted_input_info).write(TrustedInputInfo::default());
            addr_of_mut!((*ptr).hashers).write(Hashers::default());
            addr_of_mut!((*ptr).home).write(NbglHomeAndSettings::default());
            addr_of_mut!((*ptr).legacy_parser).write(LegacyParser::new(mode));
            addr_of_mut!((*ptr).pczt_parser).write(PcztParser::new());
            addr_of_mut!((*ptr).legacy_output_parser).write(LegacyOutputParser::new());
            addr_of_mut!((*ptr).vk_response).write(None);
            addr_of_mut!((*ptr).is_vk_display_finished).write(false);
            addr_of_mut!((*ptr).swap_params).write(swap_params);
            addr_of_mut!((*ptr).has_released_signature).write(false);
        }
    }

    #[inline(never)]
    pub fn reset(&mut self, mode: LegacyParserMode) {
        // Don't reset home, swap params and has_released_signature, they're not part of TX state
        self.is_extra_header_data_set = false;
        self.is_finished = false;
        self.tx_signing_state = TxSigningState::default();
        self.tx_info = TxInfo::default();
        self.trusted_input_info = TrustedInputInfo::default();
        self.hashers = Hashers::default();
        self.legacy_parser = LegacyParser::new(mode);
        self.pczt_parser = PcztParser::new();
        self.legacy_output_parser = LegacyOutputParser::new();
        self.vk_response = None;
        self.is_vk_display_finished = false;
    }

    /// Resets the context to start a new transaction, refusing when that would reuse an approval
    /// already spent on a signature.
    ///
    /// Outside swap mode every transaction carries its own on-device review, so signing several in
    /// a row is legitimate. Under swap, the single Exchange approval covers one transaction: the
    /// app validates against `swap_params` instead of displaying anything, and `reset` keeps those
    /// params. A host that stops mid-way through a multi-input transaction, once it holds a
    /// signature, could otherwise start a second transaction against the same approval and have
    /// the user pay twice.
    pub fn reset_for_new_transaction(&mut self, mode: LegacyParserMode) -> Result<(), AppSW> {
        if self.swap_params.is_some() && self.has_released_signature {
            error!("New transaction after a signature was released under a swap approval");
            return Err(AppSW::BadState);
        }

        self.reset(mode);
        Ok(())
    }

    /// Records that a signature has been returned to the host.
    pub fn note_signature_released(&mut self) {
        self.has_released_signature = true;
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
