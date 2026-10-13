use ::orchard::bundle::commitments::{
    ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION,
    ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
    ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
};
use alloc::{string::String, string::ToString, vec::Vec};
use core::fmt::Write as _;
use core::{cmp, mem};

use crate::consts::{
    MAX_PCZT_OWN_ACCOUNTS, PCZT_OUTPUT_EXTENSION_ACCOUNT, UNHARDENED_MASK, V6_TX_VERSION,
    V6_VERSION_GROUP_ID,
};
use crate::parser::personalization::ZCASH_ORCHARD_HASH_PERSONALIZATION_V6;
use ::orchard::keys::Scope as OrchardScope;
use corez::io::Read;
use ledger_device_sdk::ecc::Secret;
use ledger_device_sdk::hash::HashInit as _;
use ledger_device_sdk::hash::blake2::{Blake2b_256, Blake2bWithPerso as _};
use ledger_device_sdk::libcall::swap::CreateTxParams;
use ledger_device_sdk::log::{debug, error, info};
use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver, Revision, Uitem};
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
use crate::consts::SHIELDED_ACTIONS_HEAP_HEADROOM;
use crate::consts::{
    MAX_PCZT_ORCHARD_ACTIONS_NUMBER, MAX_PCZT_SCRIPT_SIZE,
    MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER, MAX_PCZT_SHIELDED_RETAINED_OUTPUTS_NUMBER,
    MAX_PCZT_TRANSPARENT_INPUTS_NUMBER, MAX_PCZT_TRANSPARENT_OUTPUTS_NUMBER, SIGHASH_ALL,
    ZCASH_BIP44_COIN_TYPE,
};
use crate::parser::compute::{
    compute_shielded_signature_digest, compute_transparent_input_signature_digest,
    transparent_input_txin_signature_digest, write_transparent_script,
};
use crate::parser::orchard_decipher::{
    DecipheredOrchardOutput, ORCHARD_ENC_CIPHERTEXT_SIZE, ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE,
    ORCHARD_OUT_CIPHERTEXT_SIZE, ORCHARD_RAW_ADDRESS_SIZE, OrchardActionCiphertext,
    OrchardCompactAction, OrchardDecipherKeys, OwnAccountKeys, decipher_compact_value,
    decipher_value_with_ivk, decipher_value_with_ovk,
};
use crate::parser::{HASH_SIZE, ORCHARD_MEMO_SIZE};
use crate::tx::{Hashers, TransferType, TxInfo, TxOutput, TxOutputMemo, TxPool, TxSigningState};
use crate::utils::blake2b_256_pers::{AsWriter as _, Blake2b256Personalization as _};
use crate::utils::ensure_heap_headroom;
use crate::utils::{
    Bip44CheckMode, CheckDispOutput, HexSlice,
    base58_address::{Base58Address, ToBase58Address},
    bip32_path::Bip32Path,
    check_bip44_compliance, check_output_displayable, derivation_account,
    extended_public_key::ExtendedPublicKey,
    hashers::ToHash160,
    output_script_is_regular,
};
use crate::zip32::{
    OrchardFvk, OrchardValidationKey, RetainedOrchardFvk, derive_orchard_ask_from_sk,
    derive_orchard_fvk, derive_orchard_fvk_and_ask_from_sk, derive_orchard_fvk_from_sk,
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

const ZCASH_MEMO_TEXT_MAX_TAG: u8 = 0xF4;
const ZCASH_MEMO_EMPTY_TAG: u8 = 0xF6;

/// Hexadecimal length of a memo hash, the fixed-size rendering used when the text is not kept.
const MEMO_HASH_DISPLAY_LEN: usize = 2 * HASH_SIZE;

/// Bytes of memo text one transaction may keep for its review, across both shielded pools.
///
/// Every recoverable, non-change shielded output may carry a 512-byte memo, and the host decides
/// how many such outputs there are: kept verbatim, a few of them claim more than the whole heap,
/// next to the addresses, the output records and the note ciphertext. The allocation that cannot be
/// served does not surface as a parse error — the allocator panics and the panic handler exits the
/// app, so the host takes down the transaction in progress at will.
///
/// The budget is what makes the review's footprint independent of what the host sends: past it a
/// memo is rendered as its hash, and past even that the parser refuses with a status word instead
/// of walking into the allocator. It is set to hold two maximum-length memos verbatim, well above
/// what a transaction built by a wallet carries and well below where the heap gives out.
const MAX_RETAINED_MEMO_BYTES: usize = 2 * ORCHARD_MEMO_SIZE;

/// Bind a hidden shielded change output to the account the transaction spends from.
///
/// A shielded output that decrypts under the internal IVK is kept off the review, and that IVK is
/// derived from the path the host declared for the action — so on its own, nothing stops the host
/// from naming an account of its choosing and having the value land there unseen. Recording the
/// account is what arms [`check_change_returns_to_signing_account`], which every path that releases
/// a signature calls: the hidden change has to belong to the account being spent, or no signature
/// leaves the device.
///
/// Shares `TxInfo::change_account` with the transparent change output, and carries the same conflict
/// rule for the same reason: two change outputs naming different accounts are refused outright,
/// since whichever one the signing check matched, the other would stay hidden.
fn record_hidden_shielded_change_account(
    tx_info: &mut TxInfo,
    path: &Bip32Path,
) -> Result<(), ParserError> {
    let Some(account) = derivation_account(path) else {
        error!("Shielded change path carries no account");
        return Err(ParserError::from_str(
            "Shielded change path carries no account",
        ));
    };

    match tx_info.change_account {
        Some(previous) if previous != account => Err(ParserError::from_str(
            "PCZT change outputs declare different accounts",
        )),
        _ => {
            tx_info.change_account = Some(account);
            Ok(())
        }
    }
}

/// Claim room for one more shielded output of either kind, displayed or change, refusing once the
/// budget is spent. Called before [`claim_displayed_shielded_output`] and for the same reason.
fn claim_retained_shielded_output(tx_info: &mut TxInfo) -> Result<(), ParserError> {
    if tx_info.retained_shielded_outputs >= MAX_PCZT_SHIELDED_RETAINED_OUTPUTS_NUMBER {
        error!("Shielded retained-output budget exhausted");
        return Err(ParserError::from_sw(AppSW::NotEnoughMemorySpace));
    }

    tx_info.retained_shielded_outputs += 1;

    Ok(())
}

/// Claim room for one more shielded output on the review, refusing once the budget is spent.
///
/// Call this before anything is allocated for the output — the address encoding included — since
/// refusing after the allocation would leave the parser holding what the budget exists to prevent.
///
/// Shared by both shielded pools for the same reason the memo rendering is: Ironwood repeats
/// Orchard's note format, so a per-pool copy of a budget is a budget that comes apart.
fn claim_displayed_shielded_output(tx_info: &mut TxInfo) -> Result<(), ParserError> {
    if tx_info.displayed_shielded_outputs >= MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER {
        error!("Shielded displayed-output budget exhausted");
        return Err(ParserError::from_sw(AppSW::NotEnoughMemorySpace));
    }

    tx_info.displayed_shielded_outputs += 1;

    Ok(())
}

/// Render a shielded output's memo for the review, within the transaction's retention budget.
///
/// Shared by both shielded pools: Ironwood repeats Orchard's note format, and a divergence here
/// would leave one of them with the unbounded behaviour the other lost.
fn memo_display(tx_info: &mut TxInfo, memo: &[u8]) -> Result<Option<TxOutputMemo>, ParserError> {
    if memo.len() != ORCHARD_MEMO_SIZE {
        return Err(ParserError::from_sw(AppSW::TechnicalProblem));
    }

    if memo[0] == ZCASH_MEMO_EMPTY_TAG && memo[1..].iter().all(|byte| *byte == 0) {
        return Ok(None);
    }

    let Some(memo_len) = memo
        .iter()
        .rposition(|byte| *byte != 0)
        .map(|index| index + 1)
    else {
        return Ok(None);
    };

    let budget = MAX_RETAINED_MEMO_BYTES.saturating_sub(tx_info.retained_memo_bytes);

    if memo[0] <= ZCASH_MEMO_TEXT_MAX_TAG
        && memo_len <= budget
        && let Ok(text) = core::str::from_utf8(&memo[..memo_len])
        && is_displayable_memo_text(text)
    {
        let retained = try_retain(text)?;
        tx_info.retained_memo_bytes += memo_len;
        return Ok(Some(TxOutputMemo::text(retained)));
    }

    if MEMO_HASH_DISPLAY_LEN > budget {
        error!("Memo retention budget exhausted");
        return Err(ParserError::from_sw(AppSW::NotEnoughMemorySpace));
    }

    // `Blake2b_256::default()` leaves the cx_blake2b_t zeroed, so `update` would dereference a
    // null cx_hash_info_t. Built here rather than through `HashInit::new`, which discards the
    // initialization error and would hand back that same unusable context: no salt and no
    // personalization yields the plain BLAKE2b-256 the review field is meant to show.
    let mut hasher = ok!(Blake2b_256::new_with_salt_and_perso(None, None));
    ok!(hasher.update(memo));
    let mut hash = [0u8; HASH_SIZE];
    ok!(hasher.finalize(&mut hash));

    let mut retained = String::new();
    retained
        .try_reserve_exact(MEMO_HASH_DISPLAY_LEN)
        .map_err(|_| ParserError::from_sw(AppSW::NotEnoughMemorySpace))?;
    for byte in hash {
        // Writes into the capacity reserved just above, so it cannot reach the allocator again.
        let _ = write!(&mut retained, "{byte:02x}");
    }
    tx_info.retained_memo_bytes += MEMO_HASH_DISPLAY_LEN;

    Ok(Some(TxOutputMemo::hash(retained)))
}

/// Whether a memo can be shown as text rather than hashed.
///
/// Printable ASCII only. This is also what keeps a NUL byte out of the retained text: the review
/// hands each value to the C layer as a NUL-terminated string, and an interior NUL panics the
/// build of it — an app exit the host would choose. Widening this to non-ASCII UTF-8 would have to
/// keep excluding it.
fn is_displayable_memo_text(text: &str) -> bool {
    text.bytes().all(|byte| matches!(byte, 0x20..=0x7E))
}

/// Copy a string onto the heap without the infallible path's panic on exhaustion.
fn try_retain(text: &str) -> Result<String, ParserError> {
    let mut retained = String::new();
    retained
        .try_reserve_exact(text.len())
        .map_err(|_| ParserError::from_sw(AppSW::NotEnoughMemorySpace))?;
    retained.push_str(text);
    Ok(retained)
}

/// Length of the account index carried by a [`PCZT_OUTPUT_EXTENSION_ACCOUNT`] extension.
const OUTPUT_EXTENSION_ACCOUNT_LEN: usize = 4;

/// Parse an output-metadata extension block: `tag u8 · len u8 · value[len]` entries up to the end
/// of the packet, returning the destination account it declares.
///
/// Strict on purpose: an extension this parser does not understand may change what the output
/// means, so skipping it would show the user something the host did not describe. An unknown or
/// repeated tag, a length that does not match its tag and a truncated value are all refused.
fn parse_output_extensions(reader: &mut ByteReader<'_>) -> Result<Option<u32>, ParserError> {
    let mut account = None;

    while reader.remaining_len() > 0 {
        let tag = reader
            .read_u8()
            .map_err(|_| ParserError::from_str("Truncated PCZT output extension"))?;
        let len = usize::from(
            reader
                .read_u8()
                .map_err(|_| ParserError::from_str("Truncated PCZT output extension"))?,
        );

        match tag {
            PCZT_OUTPUT_EXTENSION_ACCOUNT => {
                if len != OUTPUT_EXTENSION_ACCOUNT_LEN {
                    return Err(ParserError::from_str(
                        "Bad PCZT output account extension length",
                    ));
                }
                if account.is_some() {
                    return Err(ParserError::from_str("Repeated PCZT output extension"));
                }
                let mut value = [0u8; OUTPUT_EXTENSION_ACCOUNT_LEN];
                reader
                    .read_exact(&mut value)
                    .map_err(|_| ParserError::from_str("Truncated PCZT output extension"))?;
                let index = u32::from_le_bytes(value);
                // The device hardens the index itself; a host passing it hardened already is
                // describing some other path than the one this field names.
                if index & !UNHARDENED_MASK != 0 {
                    return Err(ParserError::from_str("Hardened PCZT output account index"));
                }
                account = Some(index);
            }
            _ => return Err(ParserError::from_str("Unknown PCZT output extension")),
        }
    }

    Ok(account)
}

/// The ZIP 32 account path of another account of the seed, built from the path being spent.
///
/// Purpose and coin type are taken from the source path rather than from a default, so a
/// transaction on one network cannot reach a key of the other. The source account itself is
/// refused: its outputs are change or payments the device already recognizes, and naming it here
/// would let a declaration relabel them.
fn own_account_path(source: &Bip32Path, account: u32) -> Result<Bip32Path, ParserError> {
    const HARDENED: u32 = 0x8000_0000;

    let source = source.as_slice();
    if source.len() != crate::consts::ZIP32_PATH_LEN {
        return Err(ParserError::from_sw(AppSW::BadState));
    }
    let hardened_account = account | HARDENED;
    if source[2] == hardened_account {
        return Err(ParserError::from_str(
            "PCZT output declares the account being spent",
        ));
    }

    let mut encoded = [0u8; 4 * crate::consts::ZIP32_PATH_LEN];
    for (chunk, component) in
        encoded
            .chunks_exact_mut(4)
            .zip([source[0], source[1], hardened_account])
    {
        chunk.copy_from_slice(&component.to_be_bytes());
    }
    let path = Bip32Path::from_dpath(crate::consts::ZIP32_PATH_LEN, &encoded)
        .map_err(ParserError::from_sw)?;

    if !check_bip44_compliance(&path, Bip44CheckMode::OnlyCoinType) {
        return Err(ParserError::from_str(
            "PCZT output account path not compliant",
        ));
    }

    Ok(path)
}

/// Record an output proven to pay another account of the seed.
///
/// It is a payment like any other for every rule but its rendering: never change, never hidden,
/// counted against both output budgets before anything is allocated for it, and shown with its
/// memo. No address is encoded — the account is what the user recognizes, and an internal address
/// is one no wallet shows.
fn push_own_account_output(
    tx_info: &mut TxInfo,
    output: DecipheredOrchardOutput,
    account: u32,
) -> Result<(), ParserError> {
    claim_retained_shielded_output(tx_info)?;
    claim_displayed_shielded_output(tx_info)?;

    tx_info
        .outputs
        .try_reserve(1)
        .map_err(|_| ParserError::from_sw(AppSW::NotEnoughMemorySpace))?;
    let memo = match output.memo.as_ref() {
        Some(memo) => memo_display(tx_info, memo)?,
        None => None,
    };

    debug!(
        "PCZT own-account output: account {}, amount {}",
        account, output.value
    );

    tx_info.outputs.push(TxOutput {
        amount: output.value,
        address: String::new(),
        is_change: false,
        memo,
        pool: TxPool::Orchard,
        own_account: Some(account),
    });

    Ok(())
}

/// Drop the viewing keys of the other accounts, wiping them, and release their storage.
fn discard_own_account_keys(tx_info: &mut TxInfo) {
    tx_info.own_account_keys = Vec::new();
}

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
    pub comm: &'ctx mut ledger_device_sdk::io::Comm,
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
    note_plaintext_version: u8,
    /// Account the host declared the output pays, through the output-metadata extension block.
    output_account: Option<u32>,
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
            note_plaintext_version: NOTE_VERSION_ORCHARD,
            output_account: None,
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
    // Shared by both pools under orchard_spending_key_path; wiped before review or on reset.
    orchard_fvk: Option<RetainedOrchardFvk>,
    // Normalized scalar under the same account path. Wiped before review or on reset.
    orchard_validation_key: Option<OrchardValidationKey>,
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
            orchard_fvk: None,
            orchard_validation_key: None,
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

    /// Whether a PCZT session owns the transaction state, which the legacy path shares.
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
        self.orchard_fvk = None;
        self.orchard_validation_key = None;
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

        if result.is_err() {
            discard_own_account_keys(ctx.tx_info);
        }
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

        if result.is_err() {
            discard_own_account_keys(ctx.tx_info);
        }
        self.reset_on_error(result)
    }

    /// Derive, once per transaction, the viewing keys of another account an output declares.
    ///
    /// Runs while the output metadata is parsed, at the shallowest point that knows the account,
    /// rather than inside the output's validation where the derivation would stack on top of note
    /// decryption. The derivation draws on the per-run budget like any other, and the full viewing
    /// key is dropped as soon as its two IVKs are taken.
    #[inline(never)]
    fn prepare_own_account_keys(
        &self,
        tx_info: &mut TxInfo,
        account: u32,
    ) -> Result<(), ParserError> {
        if tx_info
            .own_account_keys
            .iter()
            .any(|keys| keys.account == account)
        {
            return Ok(());
        }

        let source = self
            .orchard_spending_key_path
            .as_ref()
            .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?;
        let path = own_account_path(source, account)?;

        if tx_info.own_account_keys.len() >= MAX_PCZT_OWN_ACCOUNTS {
            error!("Own-account budget exhausted");
            return Err(ParserError::from_sw(AppSW::NotEnoughMemorySpace));
        }
        // Reserved whole on first use, so a later account never regrows the vector mid-parse.
        let missing = MAX_PCZT_OWN_ACCOUNTS - tx_info.own_account_keys.len();
        tx_info
            .own_account_keys
            .try_reserve_exact(missing)
            .map_err(|_| ParserError::from_sw(AppSW::NotEnoughMemorySpace))?;
        ensure_heap_headroom(SHIELDED_ACTIONS_HEAP_HEADROOM).map_err(ParserError::from_sw)?;

        let keys = {
            let fvk =
                RetainedOrchardFvk::new(derive_orchard_fvk(&path).map_err(ParserError::from_sw)?);
            OwnAccountKeys::from_fvk(account, &fvk).map_err(ParserError::from_sw)?
        };
        tx_info.own_account_keys.push(keys);

        Ok(())
    }

    /// Recognize the current action's output as a note of the account it declares.
    ///
    /// The declaration is a claim, and this is the only way it is accepted: the note has to decrypt
    /// under that account's internal or external IVK and pass the full note validation. Any other
    /// outcome refuses the action — falling back to the undeclared paths would let a declaration
    /// that fails to prove itself still reach the review.
    #[inline(never)]
    fn recognize_own_account_output(
        &self,
        tx_info: &TxInfo,
        account: u32,
        enc_ciphertext: &[u8],
        out_ciphertext: &[u8; ORCHARD_OUT_CIPHERTEXT_SIZE],
        note_version: u8,
        refusal: &'static str,
    ) -> Result<DecipheredOrchardOutput, ParserError> {
        let keys = tx_info
            .own_account_keys
            .iter()
            .find(|keys| keys.account == account)
            .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?;

        let mut enc_ciphertext_prefix = [0u8; ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE];
        enc_ciphertext_prefix.copy_from_slice(
            enc_ciphertext
                .get(..ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE)
                .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?,
        );
        let action = OrchardActionCiphertext {
            compact: OrchardCompactAction {
                nullifier: self.current_action.nullifier,
                cmx: self.current_action.cmx,
                ephemeral_key: self.current_action.ephemeral_key,
                enc_ciphertext_prefix,
            },
            rk: self.current_action.rk,
            cv_net: self.current_action.cv_net,
            enc_ciphertext,
            out_ciphertext: *out_ciphertext,
        };

        for ivk in [&keys.internal_ivk, &keys.external_ivk] {
            match decipher_value_with_ivk(ivk, &action, note_version) {
                Ok(Some(output)) => return Ok(output),
                Ok(None) => {}
                Err(ledger_zcash_crypto::Error::OutOfMemory) => {
                    return Err(ParserError::from_sw(AppSW::NotEnoughMemorySpace));
                }
                Err(err) => debug!("PCZT own-account decryption failed: {:?}", err),
            }
        }

        Err(ParserError::from_str(refusal))
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

#[cfg(test)]
mod tests {
    use super::{
        Bip32Path, ByteReader, MAX_RETAINED_MEMO_BYTES, memo_display, own_account_path,
        parse_output_extensions,
    };
    use crate::parser::{HASH_SIZE, ORCHARD_MEMO_SIZE};
    use crate::tx::TxInfo;
    use ledger_device_sdk::testing::TestType;

    /// Build the 512-byte memo field a shielded note carries, zero-padded like the real one.
    fn memo_field(content: &[u8]) -> [u8; ORCHARD_MEMO_SIZE] {
        let mut memo = [0u8; ORCHARD_MEMO_SIZE];
        memo[..content.len()].copy_from_slice(content);
        memo
    }

    /// Run `memo_display` on a fresh transaction and return the rendered value's bytes.
    ///
    /// The returned `String` is heap-allocated, so comparing it needs no relocation of a
    /// `&'static` pointer — unlike the memo's `label`, which is left alone here.
    fn rendered(content: &[u8]) -> Result<alloc::string::String, ()> {
        let mut tx_info = TxInfo::default();
        match memo_display(&mut tx_info, &memo_field(content)) {
            Ok(Some(memo)) => Ok(memo.value),
            _ => Err(()),
        }
    }

    /// Baseline: a printable-ASCII memo takes the text branch and is shown verbatim.
    ///
    /// Listed first so a run proves the harness itself works before reaching the hash branch.
    #[test_case]
    const PRINTABLE_ASCII_MEMO_IS_SHOWN_AS_TEXT: TestType = TestType {
        modname: module_path!(),
        name: "printable_ascii_memo_is_shown_as_text",
        f: || {
            let value = rendered(b"Vizor memo probe")?;
            if value.as_bytes() != b"Vizor memo probe" {
                return Err(());
            }
            Ok(())
        },
    };

    /// A memo holding one line break is not printable ASCII, so it takes the hash branch.
    ///
    /// These five bytes are what wiped the reporter's device. The expected digest is
    /// BLAKE2b-256, unkeyed and unpersonalized, over the whole 512-byte memo field.
    #[test_case]
    const LINE_BREAK_MEMO_IS_HASHED: TestType = TestType {
        modname: module_path!(),
        name: "line_break_memo_is_hashed",
        f: || {
            let value = rendered(b"test\n")?;
            if value.as_bytes()
                != b"158c40577ec4159f67aa9488a866d5dcfcf4008447de0ce44eff3f563de116ae"
            {
                return Err(());
            }
            Ok(())
        },
    };

    /// Non-ASCII UTF-8 takes the hash branch: one Korean word is enough.
    #[test_case]
    const NON_ASCII_MEMO_IS_HASHED: TestType = TestType {
        modname: module_path!(),
        name: "non_ascii_memo_is_hashed",
        f: || {
            let value = rendered("안녕하세요".as_bytes())?;
            if value.as_bytes()
                != b"503a4fed723a38f764c4b284257c5f17294cca985a41566d1b688a3a476249e1"
            {
                return Err(());
            }
            Ok(())
        },
    };

    /// A tab is a control character, so it too leaves the printable-ASCII range.
    #[test_case]
    const TAB_MEMO_IS_HASHED: TestType = TestType {
        modname: module_path!(),
        name: "tab_memo_is_hashed",
        f: || {
            let value = rendered(b"first\tsecond")?;
            if value.as_bytes()
                != b"1f3cf29aa6495cf63fb12682af2a1a5af3d77da328b6e22680a3d609899081e3"
            {
                return Err(());
            }
            Ok(())
        },
    };

    /// An emoji is multi-byte UTF-8, which the text branch also refuses.
    #[test_case]
    const EMOJI_MEMO_IS_HASHED: TestType = TestType {
        modname: module_path!(),
        name: "emoji_memo_is_hashed",
        f: || {
            let value = rendered("gg 🎉".as_bytes())?;
            if value.as_bytes()
                != b"68dcb3e8e0b501eca765f4d918931f6ccf9f55f2b3e506156e5bbf8ef99256f7"
            {
                return Err(());
            }
            Ok(())
        },
    };

    /// A lead byte above the text tag marks a non-text memo, which is hashed whatever follows.
    #[test_case]
    const NON_TEXT_TAG_MEMO_IS_HASHED: TestType = TestType {
        modname: module_path!(),
        name: "non_text_tag_memo_is_hashed",
        f: || {
            let value = rendered(b"\xff abc")?;
            if value.as_bytes()
                != b"1ae0dd79905b7a4e3b4d335810901c84052cbfaa3f11d9477f05223d3fce483a"
            {
                return Err(());
            }
            Ok(())
        },
    };

    /// Length alone never reaches the hash branch: a full-length ASCII memo stays text.
    ///
    /// Pins the separation between the retention budget and the character-set rule, so a
    /// later change to one of them cannot be mistaken for the other.
    #[test_case]
    const MAX_LENGTH_ASCII_MEMO_IS_SHOWN_AS_TEXT: TestType = TestType {
        modname: module_path!(),
        name: "max_length_ascii_memo_is_shown_as_text",
        f: || {
            let value = rendered(&[b'x'; ORCHARD_MEMO_SIZE])?;
            if value.len() != ORCHARD_MEMO_SIZE || value.bytes().any(|byte| byte != b'x') {
                return Err(());
            }
            Ok(())
        },
    };

    /// Exhausting the retention budget sends an otherwise displayable memo to the hash branch.
    ///
    /// Earlier memos leave 100 bytes of budget: too little for this memo's 512 bytes of text,
    /// enough for the 64-character digest. That is the one way the hash branch is reached
    /// without any non-printable byte.
    #[test_case]
    const MEMO_OVER_THE_RETENTION_BUDGET_IS_HASHED: TestType = TestType {
        modname: module_path!(),
        name: "memo_over_the_retention_budget_is_hashed",
        f: || {
            let memo = memo_field(&[b'x'; ORCHARD_MEMO_SIZE]);
            let mut tx_info = TxInfo {
                retained_memo_bytes: MAX_RETAINED_MEMO_BYTES - 100,
                ..Default::default()
            };

            let Ok(Some(rendered)) = memo_display(&mut tx_info, &memo) else {
                return Err(());
            };
            if rendered.value.len() != 2 * HASH_SIZE {
                return Err(());
            }
            Ok(())
        },
    };

    fn extensions(block: &[u8]) -> Result<Option<u32>, ()> {
        parse_output_extensions(&mut ByteReader::new(block)).map_err(|_| ())
    }

    /// An empty block declares nothing; one well-formed entry declares its account.
    #[test_case]
    const OUTPUT_EXTENSIONS_ACCEPT_THE_ACCOUNT_TAG: TestType = TestType {
        modname: module_path!(),
        name: "output_extensions_accept_the_account_tag",
        f: || {
            if extensions(&[])? != None
                || extensions(&[0x01, 4, 7, 0, 0, 0])? != Some(7)
                || extensions(&[0x01, 4, 0xff, 0xff, 0xff, 0x7f])? != Some(0x7fff_ffff)
            {
                return Err(());
            }
            Ok(())
        },
    };

    /// Unknown, repeated, mis-sized, truncated and hardened entries are all refused.
    #[test_case]
    const OUTPUT_EXTENSIONS_REFUSE_MALFORMED_BLOCKS: TestType = TestType {
        modname: module_path!(),
        name: "output_extensions_refuse_malformed_blocks",
        f: || {
            let malformed: [&[u8]; 7] = [
                &[0x02, 4, 1, 0, 0, 0],
                &[0x01, 4, 1, 0, 0, 0, 0x01, 4, 1, 0, 0, 0],
                &[0x01, 3, 1, 0, 0],
                &[0x01, 5, 1, 0, 0, 0, 0],
                &[0x01, 4, 1, 0],
                &[0x01, 4, 1, 0, 0, 0x80],
                &[0x01],
            ];
            if malformed.iter().any(|block| extensions(block).is_ok()) {
                return Err(());
            }
            Ok(())
        },
    };

    fn zip32_path(account: u32) -> Bip32Path {
        zip32_path_for_coin(crate::consts::ZCASH_BIP44_COIN_TYPE, account)
    }

    fn zip32_path_for_coin(coin_type: u32, account: u32) -> Bip32Path {
        let mut encoded = [0u8; 12];
        for (chunk, component) in
            encoded
                .chunks_exact_mut(4)
                .zip([0x8000_0020, 0x8000_0000 | coin_type, account])
        {
            chunk.copy_from_slice(&component.to_be_bytes());
        }
        Bip32Path::from_dpath(3, &encoded).unwrap_or_default()
    }

    /// The destination path keeps the source's prefix, hardens the index, and never names the
    /// account being spent.
    #[test_case]
    const OWN_ACCOUNT_PATH_IS_BUILT_FROM_THE_SOURCE: TestType = TestType {
        modname: module_path!(),
        name: "own_account_path_is_built_from_the_source",
        f: || {
            let source = zip32_path(0x8000_0000);
            if own_account_path(&source, 1).map_err(|_| ())? != zip32_path(0x8000_0001)
                || own_account_path(&source, 0).is_ok()
                || own_account_path(&zip32_path(0x8000_0002), 2).is_ok()
            {
                return Err(());
            }
            Ok(())
        },
    };

    /// A source path on the other network's coin type builds no destination: a mainnet build
    /// never reaches a testnet account's keys, nor the reverse.
    #[test_case]
    const OWN_ACCOUNT_PATH_STAYS_ON_THE_BUILD_NETWORK: TestType = TestType {
        modname: module_path!(),
        name: "own_account_path_stays_on_the_build_network",
        f: || {
            let other_coin_type = if crate::consts::ZCASH_BIP44_COIN_TYPE == 133 {
                1
            } else {
                133
            };
            if own_account_path(&zip32_path_for_coin(other_coin_type, 0x8000_0000), 1).is_ok() {
                return Err(());
            }
            Ok(())
        },
    };
}
