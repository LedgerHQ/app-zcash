use ::orchard::bundle::commitments::{
    ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION,
    ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
    ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
};
use alloc::{format, string::ToString, vec::Vec};
use core::{cmp, mem};

use ::orchard::note::TransmittedNoteCiphertext;
use core2::io::Read;
use ledger_device_sdk::hash::HashInit as _;
use ledger_device_sdk::libcall::swap::CreateTxParams;
use ledger_device_sdk::log::{debug, info};
use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
use zcash_encoding::CompactSize;
use zcash_primitives::encoding::ReadBytesExt;
use zcash_primitives::transaction::TxVersion;
use zcash_primitives::transaction::components::orchard as orchard_component;
use zcash_protocol::consensus::{BranchId, NetworkType};
use zcash_protocol::constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::OutPoint;

use crate::AppSW;
use crate::app_ui::sign::ui_display_tx;
use crate::consts::{
    MAX_ORCHARD_ACTIONS, MAX_OUTPUTS_NUMBER, MAX_SCRIPT_SIZE, MAX_TRANSPARENT_INPUTS_NUMBER,
    SIGHASH_ALL,
};
use crate::parser::compute::{
    compute_shielded_signature_digest, compute_transparent_input_signature_digest,
    transparent_input_txin_signature_digest,
};
use crate::parser::orchard::ORCHARD_MEMO_SIZE;
use crate::parser::orchard_decipher::{
    DecipheredOrchardOutput, ORCHARD_ENC_CIPHERTEXT_SIZE, ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE,
    ORCHARD_OUT_CIPHERTEXT_SIZE, OrchardActionCiphertext, OrchardCompactAction,
    OrchardDecipherKeys, decipher_compact_value, decipher_value_with_ovk,
};
use crate::swap;
use crate::tx::{Hashers, TxInfo, TxOutput, TxSigningState};
use crate::utils::blake2b_256_pers::{AsWriter as _, Blake2b256Personalization as _};
use crate::utils::check_output_displayable;
use crate::utils::{
    Bip44CheckMode, CheckDispOutput, HexSlice,
    base58_address::{Base58Address, ToBase58Address},
    bip32_path::{Bip32Path, MAX_ZCASH_BIP32_PATH},
    check_bip44_compliance,
    extended_public_key::ExtendedPublicKey,
};
use crate::zip32::{derive_orchard_fvk, orchard_network};

use super::reader::ByteReader;
use super::{ParserError, finalize_and_log_hash, ok};

mod common;
mod orchard;
mod transparent;

const MAGIC_BYTES: &[u8; 4] = b"PCZT";
const PCZT_VERSION_1: u32 = 1;
const DEFAULT_SEQUENCE: u32 = 0xFFFF_FFFF;
const PREVOUT_SIZE: usize = 32 + 4;
const COMPRESSED_PUBKEY_SIZE: usize = 33;
const ZIP32_SEED_FINGERPRINT_SIZE: usize = 32;
const ZIP32_DERIVATION_PATH_COUNT_OFFSET: usize =
    COMPRESSED_PUBKEY_SIZE + ZIP32_SEED_FINGERPRINT_SIZE;
const ORCHARD_ENC_CIPHERTEXT_TAG_OFFSET: usize =
    ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE + ORCHARD_MEMO_SIZE;

enum PathCountParse {
    NeedMore(usize),
    Ready {
        path_count: usize,
        path_offset: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PcztOrchardField {
    CvNet,
    Nullifier,
    Rk,
    Alpha,
    Zip32Derivation { expected_size: Option<usize> },
    Cmx,
    EphemeralKey,
    EncCiphertextLen,
    EncCiphertext,
    OutCiphertextLen,
    OutCiphertext,
    Flags,
    ValueSumMagnitude,
    ValueSumSign,
    Anchor,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
enum PcztParserState {
    #[default]
    WaitHeaderAndGlobal,
    WaitTransparentInput,
    WaitTransparentInputScript,
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
    WaitTransparentOutputScript,
    ProcessTransparentOutputScript {
        size: usize,
        remaining_size: usize,
    },
    WaitTransparentOutputBip32Derivation,
    ProcessTransparentOutputBip32Derivation {
        expected_size: Option<usize>,
    },
    TransparentOutputsDone,
    ProcessOrchardField {
        field: PcztOrchardField,
    },
    OrchardActionsDone,
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
    signed: bool,
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
    outputs_reviewed: bool,
    pczt_finished: bool,
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
    orchard_value_balance: i64,
    orchard_decrypted_output_count: usize,
    current_orchard_flags: u8,
    current_orchard_value_sum_magnitude: u64,
    current_orchard_cv_net: [u8; 32],
    current_orchard_nullifier: [u8; 32],
    current_orchard_rk: [u8; 32],
    current_orchard_cmx: [u8; 32],
    current_orchard_ephemeral_key: [u8; 32],
    current_orchard_enc_ciphertext: Vec<u8>,
    current_orchard_alpha: Option<[u8; 32]>,
    current_orchard_path: Option<Bip32Path>,
    script_bytes: Vec<u8>,
    bip32_derivation_bytes: Vec<u8>,
    orchard_field_bytes: Vec<u8>,
}

impl PcztParser {
    // APDU payload formats for this PCZT parser.
    //
    // This is a compact APDU subset whose field order mirrors the pczt crate structs
    // we consume. The APDU order is fixed: `Pczt` header and `common::Global`,
    // transparent inputs, transparent outputs, then Orchard actions. `Pczt` header
    // and `common::Global` are sent exactly once at the beginning of
    // `PCZT_TRANSPARENT_INPUT`; following bundle commands start from their own
    // bundle fields. `PCZT_ORCHARD_ACTION` is still sent with action count 0 when no
    // Orchard actions are present.
    //
    // Primitive encoding:
    //   u8/u32/u64        little-endian, except u8
    //   bool              0x00 for false, 0x01 for true
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
    //   proprietary            SKIPPED
    //
    // transparent::Bundle subset:
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
    //   sighash_type           u8, must be SIGHASH_ALL
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
    //   bip32_derivation       BTreeMap<[u8; 33], Zip32Derivation> as:
    //                            CompactSize entry count, followed by entries:
    //                              key compressed_pubkey [u8; 33]
    //                              seed_fingerprint [u8; 32]
    //                              derivation_path Vec<u32> as CompactSize count
    //                                followed by LE u32 path segments
    //                            at most one entry is currently used for change
    //   user_address           SKIPPED
    //   proprietary            SKIPPED
    //
    // orchard::Bundle subset:
    //   actions                Vec<Action> as CompactSize count, followed by actions
    //   flags                  u8
    //   value_sum              (u64, bool) as magnitude followed by negative-sign flag
    //   anchor                 [u8; 32]
    //   zkproof                SKIPPED
    //   bsk                    SKIPPED
    //
    // orchard::Action fields, in order:
    //   cv_net                 [u8; 32]
    //   spend                  Spend subset
    //   output                 Output subset
    //   rcv                    SKIPPED
    //
    // orchard::Spend fields, in order:
    //   nullifier              [u8; 32]
    //   rk                     [u8; 32]
    //   spend_auth_sig         SKIPPED
    //   recipient              SKIPPED
    //   value                  SKIPPED
    //   rho                    SKIPPED
    //   rseed                  SKIPPED
    //   fvk                    SKIPPED
    //   witness                SKIPPED
    //   alpha                  [u8; 32]
    //                            REQUIRED by this parser for every action; unlike
    //                            the pczt crate Option field, no option tag is sent.
    //   zip32_derivation       Zip32Derivation as:
    //                            REQUIRED by this parser for every action; unlike
    //                            the pczt crate Option field, no option tag is sent.
    //                            seed_fingerprint [u8; 32]
    //                            derivation_path Vec<u32> as CompactSize count
    //                              followed by LE u32 path segments
    //   dummy_sk               SKIPPED
    //   proprietary            SKIPPED
    //
    // orchard::Output fields, in order:
    //   cmx                    [u8; 32]
    //   ephemeral_key          [u8; 32]
    //   enc_ciphertext         Vec<u8>, currently must be 580 bytes
    //   out_ciphertext         Vec<u8>, currently must be 80 bytes
    //   recipient              SKIPPED
    //   value                  SKIPPED
    //   rseed                  SKIPPED
    //   ock                    SKIPPED
    //   zip32_derivation       SKIPPED
    //   user_address           SKIPPED
    //   proprietary            SKIPPED
    //
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
            current_input_prevout: [0; PREVOUT_SIZE],
            current_input_sequence: 0,
            current_input_amount: [0; 8],
            current_input_script_pubkey: Vec::new(),
            current_output_amount: 0,
            total_output_amount: 0,
            orchard_action_count: 0,
            orchard_action_parsed_count: 0,
            orchard_signing_records: Vec::new(),
            orchard_signed_action_count: 0,
            orchard_value_balance: 0,
            orchard_decrypted_output_count: 0,
            current_orchard_flags: 0,
            current_orchard_value_sum_magnitude: 0,
            current_orchard_cv_net: [0; 32],
            current_orchard_nullifier: [0; 32],
            current_orchard_rk: [0; 32],
            current_orchard_cmx: [0; 32],
            current_orchard_ephemeral_key: [0; 32],
            current_orchard_enc_ciphertext: Vec::new(),
            current_orchard_alpha: None,
            current_orchard_path: None,
            script_bytes: Vec::new(),
            bip32_derivation_bytes: Vec::new(),
            orchard_field_bytes: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
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
                | PcztParserState::ProcessTransparentOutputBip32Derivation { .. }
                | PcztParserState::TransparentOutputsDone
                | PcztParserState::ProcessOrchardField { .. }
                | PcztParserState::OrchardActionsDone
        )
    }

    pub fn is_transparent_outputs_finished(&self) -> bool {
        matches!(
            self.state,
            PcztParserState::TransparentOutputsDone
                | PcztParserState::ProcessOrchardField { .. }
                | PcztParserState::OrchardActionsDone
        )
    }

    pub fn is_orchard_actions_finished(&self) -> bool {
        matches!(self.state, PcztParserState::OrchardActionsDone)
    }

    pub fn is_ready_to_sign(&self) -> bool {
        self.is_orchard_actions_finished() && self.outputs_reviewed
    }

    pub fn is_finished(&self) -> bool {
        self.pczt_finished && self.is_ready_to_sign()
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
                    PcztParserState::WaitHeaderAndGlobal => {
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
                    PcztParserState::ProcessTransparentInputBip32Derivation { expected_size } => {
                        self.parse_transparent_input_bip32_derivation_bytes(
                            ctx,
                            &mut reader,
                            expected_size,
                        )?
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
                    PcztParserState::ProcessTransparentOutputBip32Derivation { expected_size } => {
                        self.parse_transparent_output_bip32_derivation_bytes(
                            ctx,
                            &mut reader,
                            expected_size,
                        )?
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
                    PcztParserState::ProcessOrchardField { field } => {
                        self.parse_orchard_field(ctx, &mut reader, field)?
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
