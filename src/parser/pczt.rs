use ::orchard::bundle::commitments::{
    ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION,
    ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
    ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
};
use alloc::{format, string::ToString, vec::Vec};
use core::{cmp, mem};

use crate::consts::{V6_TX_VERSION, V6_VERSION_GROUP_ID};
use crate::parser::personalization::ZCASH_ORCHARD_HASH_PERSONALIZATION_V6;
use ::orchard::keys::Scope as OrchardScope;
use corez::io::Read;
use ledger_device_sdk::ecc::Secret;
use ledger_device_sdk::hash::HashInit as _;
use ledger_device_sdk::libcall::swap::CreateTxParams;
use ledger_device_sdk::log::{debug, info};
use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
use zcash_encoding::CompactSize;
use zcash_primitives::transaction::TxVersion;
use zcash_primitives::transaction::components::orchard as orchard_component;
use zcash_protocol::consensus::{BranchId, NetworkType};
use zcash_protocol::constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::bundle::OutPoint;

use crate::AppSW;
use crate::app_ui::sign::ui_display_tx;
use crate::consts::MAX_PCZT_IRONWOOD_ACTIONS_NUMBER;
use crate::consts::{
    MAX_PCZT_ORCHARD_ACTIONS_NUMBER, MAX_PCZT_SCRIPT_SIZE, MAX_PCZT_TRANSPARENT_INPUTS_NUMBER,
    MAX_PCZT_TRANSPARENT_OUTPUTS_NUMBER, SIGHASH_ALL, ZCASH_BIP44_COIN_TYPE,
};
use crate::parser::ORCHARD_MEMO_SIZE;
use crate::parser::compute::{
    compute_shielded_signature_digest, compute_transparent_input_signature_digest,
    transparent_input_txin_signature_digest, write_transparent_script,
};
use crate::parser::orchard_decipher::{
    DecipheredOrchardOutput, ORCHARD_ENC_CIPHERTEXT_SIZE, ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE,
    ORCHARD_OUT_CIPHERTEXT_SIZE, ORCHARD_RAW_ADDRESS_SIZE, OrchardActionCiphertext,
    OrchardCompactAction, OrchardDecipherKeys, decipher_compact_value, decipher_value_with_ovk,
};
use crate::tx::{Hashers, TransferType, TxInfo, TxOutput, TxPool, TxSigningState};
use crate::utils::blake2b_256_pers::{AsWriter as _, Blake2b256Personalization as _};
use crate::utils::check_output_displayable;
use crate::utils::{
    Bip44CheckMode, CheckDispOutput, HexSlice,
    base58_address::{Base58Address, ToBase58Address},
    bip32_path::Bip32Path,
    check_bip44_compliance,
    extended_public_key::ExtendedPublicKey,
    hashers::ToHash160,
};
use crate::zip32::{
    OrchardAsk, OrchardFvk, derive_orchard_fvk_and_ask_from_sk, derive_orchard_fvk_from_sk,
    derive_orchard_sk_bytes, orchard_network,
};

use super::reader::{ByteReader, ReadBytesExt};
use super::{ParserError, finalize_and_log_hash, ok};

mod common;
mod ironwood;
mod orchard;
mod transparent;

const MAGIC_BYTES: &[u8; 4] = b"PCZT";
const PCZT_VERSION_1: u32 = 1;
const PCZT_VERSION_2: u32 = 2;
const NOTE_VERSION_ORCHARD: u8 = 0x02;
const NOTE_VERSION_IRONWOOD: u8 = 0x03;
const DEFAULT_SEQUENCE: u32 = 0xFFFF_FFFF;
const PREVOUT_SIZE: usize = 32 + 4;
const COMPRESSED_PUBKEY_SIZE: usize = 33;
const ZIP32_SEED_FINGERPRINT_SIZE: usize = 32;
const ZIP32_DERIVATION_PATH_COUNT_OFFSET: usize =
    COMPRESSED_PUBKEY_SIZE + ZIP32_SEED_FINGERPRINT_SIZE;
const ORCHARD_ENC_CIPHERTEXT_TAG_OFFSET: usize =
    ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE + ORCHARD_MEMO_SIZE;

#[derive(Debug, Default, Clone, Copy, PartialEq)]
enum PcztParserState {
    #[default]
    WaitHeaderAndGlobal,
    WaitTransparentInputsCount,
    WaitTransparentInput,
    WaitTransparentInputScript,
    ProcessTransparentInputScript {
        size: usize,
        remaining_size: usize,
    },
    WaitTransparentInputSighashType,
    WaitTransparentInputBip32Derivation,
    TransparentInputsDone,
    WaitTransparentOutput,
    WaitTransparentOutputScript,
    ProcessTransparentOutputScript {
        size: usize,
        remaining_size: usize,
    },
    WaitTransparentOutputBip32Derivation,
    TransparentOutputsDone,
    WaitOrchardAction,
    WaitOrchardZip32Derivation,
    WaitOrchardOutput,
    WaitOrchardEncCiphertextLen,
    ProcessOrchardEncCiphertext,
    WaitOrchardOutCiphertextLen,
    ProcessOrchardOutCiphertext,
    WaitOrchardOutputMetadata,
    WaitOrchardTrailer,
    OrchardActionsDone,
    WaitIronwoodAction,
    WaitIronwoodZip32Derivation,
    WaitIronwoodOutput,
    WaitIronwoodEncCiphertextLen,
    ProcessIronwoodEncCiphertext,
    WaitIronwoodOutCiphertextLen,
    ProcessIronwoodOutCiphertext,
    WaitIronwoodOutputMetadata,
    WaitIronwoodTrailer,
    IronwoodActionsDone,
}

impl PcztParserState {
    fn is_orchard_state(self) -> bool {
        matches!(
            self,
            PcztParserState::WaitOrchardAction
                | PcztParserState::WaitOrchardZip32Derivation
                | PcztParserState::WaitOrchardOutput
                | PcztParserState::WaitOrchardEncCiphertextLen
                | PcztParserState::ProcessOrchardEncCiphertext
                | PcztParserState::WaitOrchardOutCiphertextLen
                | PcztParserState::ProcessOrchardOutCiphertext
                | PcztParserState::WaitOrchardOutputMetadata
                | PcztParserState::WaitOrchardTrailer
                | PcztParserState::OrchardActionsDone
        )
    }

    fn is_ironwood_state(self) -> bool {
        matches!(
            self,
            PcztParserState::WaitIronwoodAction
                | PcztParserState::WaitIronwoodZip32Derivation
                | PcztParserState::WaitIronwoodOutput
                | PcztParserState::WaitIronwoodEncCiphertextLen
                | PcztParserState::ProcessIronwoodEncCiphertext
                | PcztParserState::WaitIronwoodOutCiphertextLen
                | PcztParserState::ProcessIronwoodOutCiphertext
                | PcztParserState::WaitIronwoodOutputMetadata
                | PcztParserState::WaitIronwoodTrailer
                | PcztParserState::IronwoodActionsDone
        )
    }
}

struct PcztTransparentInputRecord {
    prevout: [u8; PREVOUT_SIZE],
    sequence: u32,
    amount: [u8; 8],
    script_pubkey: Vec<u8>,
    path: Bip32Path,
    signed: bool,
}

struct PcztOrchardActionSigningRecord {
    alpha: [u8; 32],
    path: Bip32Path,
    // Whether the action carries a real spend (spend value != 0) rather than a
    // dummy padding spend. Dummy actions are deliberately parsed *without* the
    // rk and nullifier checks (their rk derives from the host's throwaway key,
    // so those checks cannot pass), which is only sound as long as the device
    // never signs them: signing authorizes an action whose spend side it did
    // not verify. The signing path therefore refuses a dummy index instead of
    // trusting the host to skip it.
    is_real_spend: bool,
    signed: bool,
}

pub struct PcztParserCtx<'ctx> {
    pub tx_state: &'ctx mut TxSigningState,
    pub tx_info: &'ctx mut TxInfo,
    pub hashers: &'ctx mut Hashers,
    /// Present only when the Exchange app drove this app into swap mode, in which case the
    /// transaction is validated against the Exchange's request instead of being shown to the user.
    pub swap_params: Option<&'ctx CreateTxParams>,
}

/// Ironwood signing records share the same layout as Orchard — alias for correct naming.
type PcztIronwoodActionSigningRecord = PcztOrchardActionSigningRecord;

/// Scratch state for the single action being parsed, shared by the Orchard and
/// Ironwood bundles.
///
/// Sharing is safe because a bundle is parsed to completion before the next one
/// starts and every field is rewritten when an action begins; nothing an action
/// leaves behind is read once it is finished, since what outlives it is copied
/// into the bundle's signing records. Giving each pool its own copy costs about a
/// kilobyte of static RAM, which on Nano X is taken straight out of the stack the
/// action-finalisation path needs.
struct PcztCurrentActionState {
    flags: u8,
    value_sum_magnitude: u64,
    cv_net: [u8; 32],
    nullifier: [u8; 32],
    rk: [u8; 32],
    spend_value: u64,
    spend_recipient: [u8; ORCHARD_RAW_ADDRESS_SIZE],
    spend_rho: [u8; 32],
    spend_rseed: [u8; 32],
    rcv: Option<[u8; 32]>,
    output_rseed: Option<[u8; 32]>,
    cmx: [u8; 32],
    ephemeral_key: [u8; 32],
    out_ciphertext: Option<[u8; ORCHARD_OUT_CIPHERTEXT_SIZE]>,
    output_recipient: [u8; ORCHARD_RAW_ADDRESS_SIZE],
    output_value: u64,
    enc_ciphertext: Vec<u8>,
    alpha: Option<[u8; 32]>,
    path: Option<Bip32Path>,
    fvk: Option<OrchardFvk>,
    note_plaintext_version: u8,
}

impl PcztCurrentActionState {
    const fn new() -> Self {
        Self {
            flags: 0,
            value_sum_magnitude: 0,
            cv_net: [0; 32],
            nullifier: [0; 32],
            rk: [0; 32],
            spend_value: 0,
            spend_recipient: [0; ORCHARD_RAW_ADDRESS_SIZE],
            spend_rho: [0; 32],
            spend_rseed: [0; 32],
            rcv: None,
            output_rseed: None,
            cmx: [0; 32],
            ephemeral_key: [0; 32],
            out_ciphertext: None,
            output_recipient: [0; ORCHARD_RAW_ADDRESS_SIZE],
            output_value: 0,
            enc_ciphertext: Vec::new(),
            alpha: None,
            path: None,
            fvk: None,
            note_plaintext_version: NOTE_VERSION_ORCHARD,
        }
    }
}

pub struct PcztParser {
    state: PcztParserState,
    transparent_input_count: usize,
    transparent_input_parsed_count: usize,
    transparent_inputs: Vec<PcztTransparentInputRecord>,
    transparent_output_count: usize,
    transparent_output_parsed_count: usize,
    outputs_reviewed: bool,
    pczt_finished: bool,
    pczt_version: u32,
    current_input_prevout: [u8; PREVOUT_SIZE],
    current_input_sequence: u32,
    current_input_amount: [u8; 8],
    current_input_script_pubkey: Vec<u8>,
    current_output_amount: u64,
    total_output_amount: u64,
    orchard_action_count: usize,
    orchard_action_parsed_count: usize,
    orchard_signing_records: Vec<PcztOrchardActionSigningRecord>,
    orchard_signed_action_count: usize,
    // Number of Orchard actions the device must sign: real spends (spend value
    // != 0) only. Dummy padding spends (value 0) are self-signed host-side by
    // the PCZT IoFinalizer and are never sent to the device for signing, so the
    // signing loop completes when the real spends are signed — not when every
    // action is. Using the total action count here would leave a transparent→
    // shielded transaction (0 real spends) forever "unfinished", stranding the
    // device on the signing screen.
    orchard_real_spend_count: usize,
    orchard_signature_digest: Option<[u8; 32]>,
    orchard_value_balance: i64,
    orchard_spend_value_sum: u64,
    orchard_output_value_sum: u64,
    current_action: PcztCurrentActionState,
    // Account Orchard spending key, derived once per PCZT session and reused for
    // every action's FVK/ASK derivation and spend-auth signature. `zip32_orchard_derive`
    // (the SE key-derivation syscall) does not reclaim its resources between calls,
    // so a few consecutive derivations exhaust them and the next fails with 6f00;
    // caching keeps the session to a single derivation. A PCZT is signed by one
    // account (one UFVK), so every Orchard action derives from the same path — the
    // key is cached under the first action's path and any divergent path is
    // rejected. Zeroized on `reset` and once the last Orchard action has been
    // signed (or once the parse shows none will be).
    orchard_spending_key: Option<Secret<32>>,
    // Derivation path the cached spending key belongs to, used to reject a
    // second Orchard action declaring a different path.
    orchard_spending_key_path: Option<Bip32Path>,
    is_v6_tx: bool,
    has_orchard_bundle: bool,
    has_ironwood_bundle: bool,
    ironwood_action_count: usize,
    ironwood_action_parsed_count: usize,
    // Ironwood actions carrying a real spend, i.e. the ones the device will sign.
    ironwood_real_spend_count: usize,
    ironwood_signing_records: Vec<PcztIronwoodActionSigningRecord>,
    ironwood_signed_action_count: usize,
    ironwood_signature_digest: Option<[u8; 32]>,
    ironwood_value_balance: i64,
    ironwood_spend_value_sum: u64,
    ironwood_output_value_sum: u64,
    script_bytes: Vec<u8>,
    pool_field_bytes: Vec<u8>,
}

impl PcztParser {
    // The APDU field layout, the per-bundle order and the version rules are specified in
    // docs/PCZT_APDU.md, which is the contract the host is written against.
    pub fn new() -> Self {
        Self {
            state: PcztParserState::WaitHeaderAndGlobal,
            transparent_input_count: 0,
            transparent_input_parsed_count: 0,
            transparent_inputs: Vec::new(),
            transparent_output_count: 0,
            transparent_output_parsed_count: 0,
            outputs_reviewed: false,
            pczt_finished: false,
            pczt_version: 0,
            current_input_prevout: [0; PREVOUT_SIZE],
            current_input_sequence: 0,
            current_input_amount: [0; 8],
            current_input_script_pubkey: Vec::new(),
            current_output_amount: 0,
            total_output_amount: 0,
            orchard_action_count: 0,
            orchard_real_spend_count: 0,
            orchard_action_parsed_count: 0,
            orchard_signing_records: Vec::new(),
            orchard_signed_action_count: 0,
            orchard_signature_digest: None,
            orchard_value_balance: 0,
            orchard_spend_value_sum: 0,
            orchard_output_value_sum: 0,
            current_action: PcztCurrentActionState::new(),
            orchard_spending_key: None,
            orchard_spending_key_path: None,
            is_v6_tx: false,
            has_orchard_bundle: false,
            has_ironwood_bundle: false,
            ironwood_action_count: 0,
            ironwood_action_parsed_count: 0,
            ironwood_real_spend_count: 0,
            ironwood_signing_records: Vec::new(),
            ironwood_signed_action_count: 0,
            ironwood_signature_digest: None,
            ironwood_value_balance: 0,
            ironwood_spend_value_sum: 0,
            ironwood_output_value_sum: 0,
            script_bytes: Vec::new(),
            pool_field_bytes: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Whether a PCZT session owns the transaction state: a header has been accepted and the
    /// session has not been reset.
    ///
    /// The legacy and PCZT paths write the same `TxContext`. A legacy round entered inside this
    /// window would hash its own fields into the state a PCZT review approved, and would reach
    /// the legacy signing state without a review of its own.
    pub fn is_session_active(&self) -> bool {
        self.state != PcztParserState::WaitHeaderAndGlobal || self.pczt_finished
    }

    // Returns the account Orchard spending key, deriving it via
    // `zip32_orchard_derive` exactly once per PCZT session and caching it for
    // reuse. Reusing the cached key is mandatory, not an optimization: the
    // syscall's SE resources are not reclaimed between successive calls, so
    // re-deriving per action exhausts them and the derivation eventually fails
    // with 6f00.
    //
    // All Orchard actions of a PCZT share one account key (one UFVK), so the
    // first action's `path` fixes the key for the whole transaction. A later
    // action declaring a different path is rejected rather than served the
    // cached key: the caller would otherwise derive an FVK from one path while
    // deciding the network (`orchard_network`) from another, and sign with a key
    // the declared path does not produce.
    pub fn orchard_spending_key(&mut self, path: &Bip32Path) -> Result<&Secret<32>, AppSW> {
        match self.orchard_spending_key_path {
            Some(cached_path) if cached_path != *path => return Err(AppSW::BadState),
            Some(_) => {}
            None => {
                self.orchard_spending_key = Some(derive_orchard_sk_bytes(path)?);
                self.orchard_spending_key_path = Some(*path);
            }
        }

        self.orchard_spending_key
            .as_ref()
            .ok_or(AppSW::TechnicalProblem)
    }

    // Zeroizes the cached account spending key (dropping the `Secret`) once it
    // is no longer needed: after the last Orchard action is signed, or as soon
    // as the parse establishes that no action will be signed at all.
    //
    // The path is cleared with the key so a later action cannot be compared
    // against a path whose key no longer exists; a fresh derivation for that
    // path is then the correct behaviour.
    fn clear_orchard_spending_key(&mut self) {
        self.orchard_spending_key = None;
        self.orchard_spending_key_path = None;
    }

    fn reset_on_error<T>(&mut self, result: Result<T, ParserError>) -> Result<T, ParserError> {
        if result.is_err() {
            self.reset();
            debug!("PCZT parser state reset after error");
        }

        result
    }

    pub fn is_transparent_inputs_finished(&self) -> bool {
        matches!(
            self.state,
            PcztParserState::TransparentInputsDone
                | PcztParserState::WaitTransparentOutput
                | PcztParserState::ProcessTransparentOutputScript { .. }
                | PcztParserState::WaitTransparentOutputBip32Derivation
                | PcztParserState::TransparentOutputsDone
        ) || self.state.is_orchard_state()
            || self.state.is_ironwood_state()
    }

    pub fn is_transparent_outputs_finished(&self) -> bool {
        matches!(self.state, PcztParserState::TransparentOutputsDone)
            || self.state.is_orchard_state()
            || self.state.is_ironwood_state()
    }

    pub fn is_orchard_actions_finished(&self) -> bool {
        if matches!(self.state, PcztParserState::OrchardActionsDone) {
            return true;
        }
        if self.state.is_ironwood_state() {
            return true;
        }
        false
    }

    pub fn is_ironwood_actions_finished(&self) -> bool {
        matches!(self.state, PcztParserState::IronwoodActionsDone)
    }

    pub fn is_ready_to_sign(&self) -> bool {
        let orchard_done = !self.has_orchard_bundle || self.is_orchard_actions_finished();
        let ironwood_done =
            !self.is_v6_tx || !self.has_ironwood_bundle || self.is_ironwood_actions_finished();
        orchard_done && ironwood_done && self.outputs_reviewed
    }

    pub fn is_finished(&self) -> bool {
        self.pczt_finished && self.is_ready_to_sign()
    }

    pub fn parse_header(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        data: &[u8],
    ) -> Result<(), ParserError> {
        let result = (|| {
            if self.state != PcztParserState::WaitHeaderAndGlobal {
                return Err(ParserError::from_sw(AppSW::BadState));
            }

            let mut reader = ByteReader::new(data);

            *ctx.tx_info = TxInfo::default();

            ok!(ctx.hashers.init_v5_tx_hashers());
            ctx.tx_info.tx_version = Some(TxVersion::V5);
            ctx.tx_info.total_amount = 0;

            self.parse_pczt_header(&mut reader)?;
            self.parse_global(ctx, &mut reader)?;

            if reader.remaining_len() != 0 {
                return Err(ParserError::from_str(
                    "Unexpected PCZT header data after global fields",
                ));
            }

            let prev_state = self.state;
            self.state = PcztParserState::WaitTransparentInputsCount;
            info!(
                "PCZT parser state changed: {:?} -> {:?}",
                prev_state, self.state
            );

            Ok(())
        })();

        self.reset_on_error(result)
    }

    pub fn parse_transparent_inputs(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        data: &[u8],
    ) -> Result<(), ParserError> {
        let result = (|| {
            let mut reader = ByteReader::new(data);

            while reader.remaining_len() > 0 {
                let prev_state = self.state;

                match self.state {
                    PcztParserState::WaitTransparentInputsCount => {
                        self.parse_transparent_inputs_start(ctx, &mut reader)?
                    }
                    PcztParserState::WaitTransparentInput => {
                        self.parse_transparent_input(ctx, &mut reader)?
                    }
                    PcztParserState::WaitTransparentInputScript => {
                        self.parse_transparent_input_script_start(ctx, &mut reader)?
                    }
                    PcztParserState::ProcessTransparentInputScript {
                        size,
                        remaining_size,
                    } => {
                        self.parse_transparent_input_script(ctx, &mut reader, size, remaining_size)?
                    }
                    PcztParserState::WaitTransparentInputSighashType => {
                        self.parse_transparent_input_sighash_type(ctx, &mut reader)?
                    }
                    PcztParserState::WaitTransparentInputBip32Derivation => {
                        self.parse_transparent_input_bip32_derivation(ctx, &mut reader)?
                    }
                    _ => {
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
        })();

        self.reset_on_error(result)
    }

    pub fn parse_transparent_outputs(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        data: &[u8],
    ) -> Result<(), ParserError> {
        let result = (|| {
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
                    PcztParserState::WaitTransparentOutputScript => {
                        self.parse_transparent_output_script_start(ctx, &mut reader)?
                    }
                    PcztParserState::ProcessTransparentOutputScript {
                        size,
                        remaining_size,
                    } => self.parse_transparent_output_script(
                        ctx,
                        &mut reader,
                        size,
                        remaining_size,
                    )?,
                    PcztParserState::WaitTransparentOutputBip32Derivation => {
                        self.parse_transparent_output_bip32_derivation(ctx, &mut reader)?
                    }
                    _ => {
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
        })();

        self.reset_on_error(result)
    }

    pub fn parse_orchard_actions(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        data: &[u8],
    ) -> Result<(), ParserError> {
        let result = (|| {
            let mut reader = ByteReader::new(data);

            while reader.remaining_len() > 0 {
                let prev_state = self.state;

                match self.state {
                    PcztParserState::TransparentOutputsDone => {
                        self.parse_orchard_actions_start(ctx, &mut reader)?
                    }
                    PcztParserState::WaitOrchardAction => {
                        self.parse_orchard_action(ctx, &mut reader)?
                    }
                    PcztParserState::WaitOrchardZip32Derivation => {
                        self.parse_orchard_zip32_derivation(ctx, &mut reader)?
                    }
                    PcztParserState::WaitOrchardOutput => {
                        self.parse_orchard_output(ctx, &mut reader)?
                    }
                    PcztParserState::WaitOrchardEncCiphertextLen => {
                        self.parse_orchard_enc_ciphertext_len(ctx, &mut reader)?
                    }
                    PcztParserState::ProcessOrchardEncCiphertext => {
                        self.parse_orchard_enc_ciphertext(ctx, &mut reader)?
                    }
                    PcztParserState::WaitOrchardOutCiphertextLen => {
                        self.parse_orchard_out_ciphertext_len(ctx, &mut reader)?
                    }
                    PcztParserState::ProcessOrchardOutCiphertext => {
                        self.parse_orchard_out_ciphertext(ctx, &mut reader)?
                    }
                    PcztParserState::WaitOrchardOutputMetadata => {
                        self.parse_orchard_output_metadata(ctx, &mut reader)?
                    }
                    PcztParserState::WaitOrchardTrailer => {
                        self.parse_orchard_trailer(ctx, &mut reader)?
                    }
                    _ => {
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
        })();

        self.reset_on_error(result)
    }

    pub fn parse_ironwood_actions(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        data: &[u8],
    ) -> Result<(), ParserError> {
        let result = (|| {
            let mut reader = ByteReader::new(data);

            while reader.remaining_len() > 0 {
                let prev_state = self.state;

                match self.state {
                    PcztParserState::OrchardActionsDone => {
                        self.parse_ironwood_actions_start(ctx, &mut reader)?
                    }
                    PcztParserState::WaitIronwoodAction => {
                        self.parse_ironwood_action(ctx, &mut reader)?
                    }
                    PcztParserState::WaitIronwoodZip32Derivation => {
                        self.parse_ironwood_zip32_derivation(ctx, &mut reader)?
                    }
                    PcztParserState::WaitIronwoodOutput => {
                        self.parse_ironwood_output(ctx, &mut reader)?
                    }
                    PcztParserState::WaitIronwoodEncCiphertextLen => {
                        self.parse_ironwood_enc_ciphertext_len(ctx, &mut reader)?
                    }
                    PcztParserState::ProcessIronwoodEncCiphertext => {
                        self.parse_ironwood_enc_ciphertext(ctx, &mut reader)?
                    }
                    PcztParserState::WaitIronwoodOutCiphertextLen => {
                        self.parse_ironwood_out_ciphertext_len(ctx, &mut reader)?
                    }
                    PcztParserState::ProcessIronwoodOutCiphertext => {
                        self.parse_ironwood_out_ciphertext(ctx, &mut reader)?
                    }
                    PcztParserState::WaitIronwoodOutputMetadata => {
                        self.parse_ironwood_output_metadata(ctx, &mut reader)?
                    }
                    PcztParserState::WaitIronwoodTrailer => {
                        self.parse_ironwood_trailer(ctx, &mut reader)?
                    }
                    _ => {
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
        })();

        self.reset_on_error(result)
    }

    pub fn finish_pczt(&mut self) -> Result<(), ParserError> {
        let result = (|| {
            if !self.is_ready_to_sign() {
                return Err(ParserError::from_sw(AppSW::BadState));
            }

            self.pczt_finished = true;

            debug!("PCZT finished and ready to sign");

            Ok(())
        })();

        self.reset_on_error(result)
    }
}
