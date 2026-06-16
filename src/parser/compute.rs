use ledger_device_sdk::hash::{HashInit as _, blake2::Blake2b_256, sha2::Sha2_256};
use ledger_device_sdk::log::{debug, info};
use zcash_primitives::transaction::sighash_v5::ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION;
use zcash_primitives::transaction::txid::{
    ZCASH_HEADERS_HASH_PERSONALIZATION, ZCASH_SAPLING_HASH_PERSONALIZATION,
    ZCASH_TRANSPARENT_HASH_PERSONALIZATION, ZCASH_TX_PERSONALIZATION_PREFIX,
};

use crate::{
    parser::{
        ParserCtx, ParserError, ZCASH_ORCHARD_HASH_PERSONALIZATION, finalize_and_log_hash, ok,
    },
    tx::{SupportedTxVersion, TxInfo},
    utils::{
        HexSlice,
        blake2b_256_pers::{AsWriter as _, Blake2b256Personalization as _},
    },
};

pub fn tx_id(ctx: &mut ParserCtx<'_>) -> Result<(), ParserError> {
    let tx_version = ctx
        .tx_info
        .tx_version
        .expect("tx_version should be set at this point");

    let branch_id = ctx
        .tx_info
        .branch_id
        .expect("branch_id should be set at this point");

    match ctx.tx_info.tx_version() {
        SupportedTxVersion::V5 => {
            let prevouts_hash =
                finalize_and_log_hash(&mut ctx.hashers.prevouts_hasher, "Prevouts hash")?;

            let sequence_hash =
                finalize_and_log_hash(&mut ctx.hashers.sequence_hasher, "Sequence hash")?;

            let outputs_hash =
                finalize_and_log_hash(&mut ctx.hashers.outputs_hasher, "Outputs hash")?;

            let header_hash = {
                let mut hash = [0u8; 32];

                let mut hasher = Blake2b_256::default();
                ok!(hasher.init_with_perso(ZCASH_HEADERS_HASH_PERSONALIZATION));

                ok!(tx_version.write(&mut hasher.as_writer()));

                ok!(hasher.update(&u32::from(branch_id).to_le_bytes()));

                ok!(hasher.update(&ctx.tx_info.locktime.to_le_bytes()));
                ok!(hasher.update(&ctx.tx_info.expiry_height.to_le_bytes()));

                ok!(hasher.finalize(&mut hash));
                hash
            };
            debug!("Header hash: {}", HexSlice(&header_hash));

            let transparent_hash = {
                let mut hash = [0u8; 32];

                let mut hasher = Blake2b_256::default();
                ok!(hasher.init_with_perso(ZCASH_TRANSPARENT_HASH_PERSONALIZATION));

                ok!(hasher.update(&prevouts_hash));
                ok!(hasher.update(&sequence_hash));
                ok!(hasher.update(&outputs_hash));

                ok!(hasher.finalize(&mut hash));
                hash
            };
            debug!("Transparent hash: {}", HexSlice(&transparent_hash));

            let sapling_hash =
                finalize_and_log_hash(&mut ctx.hashers.sapling_hasher, "Sapling hash")?;

            let orchard_hash =
                finalize_and_log_hash(&mut ctx.hashers.orchard_hasher, "Orchard hash")?;

            let mut personalization = [0u8; 16];
            personalization[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
            personalization[12..].copy_from_slice(&u32::from(branch_id).to_le_bytes());

            let mut hasher = Blake2b_256::default();
            ok!(hasher.init_with_perso(&personalization));

            ok!(hasher.update(&header_hash));
            ok!(hasher.update(&transparent_hash));
            ok!(hasher.update(&sapling_hash));
            ok!(hasher.update(&orchard_hash));

            ok!(hasher.finalize(&mut ctx.trusted_input_info.tx_id));

            debug!(
                "Transaction ID hash: {}",
                HexSlice(&ctx.trusted_input_info.tx_id)
            );
        }
        SupportedTxVersion::V4 => {
            let mut first_round_hash = [0u8; 32];
            ok!(ctx.hashers.v4_tx_hasher.finalize(&mut first_round_hash));

            let mut second_round_hasher = Sha2_256::new();
            ok!(second_round_hasher.hash(&first_round_hash, &mut ctx.trusted_input_info.tx_id));

            debug!(
                "V4 transaction ID hash: {}",
                HexSlice(&ctx.trusted_input_info.tx_id)
            );
        }
    }

    Ok(())
}

pub fn finalize_signature_input_hash(ctx: &mut ParserCtx<'_>) -> Result<(), ParserError> {
    ok!(ctx
        .hashers
        .prevouts_hasher
        .finalize(&mut ctx.tx_info.prevouts_hash));
    info!("prevout hash {}", HexSlice(&ctx.tx_info.prevouts_hash));

    ok!(ctx
        .hashers
        .sequence_hasher
        .finalize(&mut ctx.tx_info.sequence_hash));
    info!("sequence hash {}", HexSlice(&ctx.tx_info.sequence_hash));

    ok!(ctx
        .hashers
        .amounts_hasher
        .finalize(&mut ctx.tx_info.amounts_hash));
    info!("amounts hash {}", HexSlice(&ctx.tx_info.amounts_hash));

    ok!(ctx
        .hashers
        .scripts_hasher
        .finalize(&mut ctx.tx_info.scripts_hash));
    info!("scripts hash {}", HexSlice(&ctx.tx_info.scripts_hash));

    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub enum SighHashComputeMode {
    NoTransparentInputsOrOutputs,
    NoTransparentInputs,
    SomeTransparentInputs,
}

#[derive(Debug, Clone, Copy)]
pub enum TxInSignatureDigest<'a> {
    Absent,
    Provided(&'a [u8; 32]),
}

pub fn empty_txin_signature_digest() -> Result<[u8; 32], ParserError> {
    let mut txin_sig_digest = [0u8; 32];
    let mut hasher = Blake2b_256::default();
    ok!(hasher.init_with_perso(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION));
    ok!(hasher.finalize(&mut txin_sig_digest));
    debug!("Shielded txin sig digest: {}", HexSlice(&txin_sig_digest));

    Ok(txin_sig_digest)
}

pub fn finalize_signature_hash(
    ctx: &mut ParserCtx<'_>,
    mode: SighHashComputeMode,
) -> Result<(), ParserError> {
    let mut txin_sig_digest = [0u8; 32];
    ok!(ctx.hashers.prevouts_hasher.finalize(&mut txin_sig_digest));
    info!("txin sig digest {}", HexSlice(&txin_sig_digest));
    info!("sighash compute mode {:X?}", mode);

    let transparent_digest = transparent_signature_digest(
        ctx.tx_info,
        mode,
        ctx.tx_info.sighash_type,
        Some(&txin_sig_digest),
    )?;
    finalize_signature_hash_from_transparent_digest(ctx.tx_info, &transparent_digest)
}

pub fn finalize_signature_hash_from_txin_digest(
    tx_info: &mut TxInfo,
    mode: SighHashComputeMode,
    sighash_type: u8,
    txin_sig_digest: TxInSignatureDigest<'_>,
) -> Result<(), ParserError> {
    compute_header_digest(tx_info)?;

    let txin_sig_digest = match txin_sig_digest {
        TxInSignatureDigest::Absent => None,
        TxInSignatureDigest::Provided(digest) => Some(digest),
    };

    let transparent_digest =
        transparent_signature_digest(tx_info, mode, sighash_type, txin_sig_digest)?;

    finalize_signature_hash_from_transparent_digest(tx_info, &transparent_digest)
}

fn compute_header_digest(tx_info: &mut TxInfo) -> Result<(), ParserError> {
    let tx_version = tx_info
        .tx_version
        .expect("tx_version should be set at this point");
    let branch_id = tx_info
        .branch_id
        .expect("branch_id should be set at this point");

    let mut hasher = Blake2b_256::default();
    ok!(hasher.init_with_perso(ZCASH_HEADERS_HASH_PERSONALIZATION));
    ok!(tx_version.write(&mut hasher.as_writer()));
    ok!(hasher.update(&u32::from(branch_id).to_le_bytes()));
    ok!(hasher.update(&tx_info.locktime.to_le_bytes()));
    ok!(hasher.update(&tx_info.expiry_height.to_le_bytes()));
    ok!(hasher.finalize(&mut tx_info.header_digest));
    debug!("Header hash: {}", HexSlice(&tx_info.header_digest));

    Ok(())
}

fn transparent_signature_digest(
    tx_info: &TxInfo,
    mode: SighHashComputeMode,
    sighash_type: u8,
    txin_sig_digest: Option<&[u8; 32]>,
) -> Result<[u8; 32], ParserError> {
    let mut hash = [0u8; 32];
    let mut hasher = Blake2b_256::default();
    ok!(hasher.init_with_perso(ZCASH_TRANSPARENT_HASH_PERSONALIZATION));

    match mode {
        SighHashComputeMode::NoTransparentInputsOrOutputs => {}
        SighHashComputeMode::NoTransparentInputs => {
            ok!(hasher.update(&tx_info.prevouts_hash));
            ok!(hasher.update(&tx_info.sequence_hash));
            ok!(hasher.update(&tx_info.outputs_hash));
        }
        SighHashComputeMode::SomeTransparentInputs => {
            let txin_sig_digest = txin_sig_digest.ok_or_else(|| {
                ParserError::from_str("Missing transparent input signature digest")
            })?;

            ok!(hasher.update(&[sighash_type]));
            ok!(hasher.update(&tx_info.prevouts_hash));
            ok!(hasher.update(&tx_info.amounts_hash));
            ok!(hasher.update(&tx_info.scripts_hash));
            ok!(hasher.update(&tx_info.sequence_hash));
            ok!(hasher.update(&tx_info.outputs_hash));
            ok!(hasher.update(txin_sig_digest));
        }
    }

    ok!(hasher.finalize(&mut hash));
    debug!("Transparent hash: {}", HexSlice(&hash));

    Ok(hash)
}

fn finalize_signature_hash_from_transparent_digest(
    tx_info: &mut TxInfo,
    transparent_digest: &[u8; 32],
) -> Result<(), ParserError> {
    let branch_id = tx_info
        .branch_id
        .expect("branch_id should be set at this point");

    let sapling_digest = empty_digest(ZCASH_SAPLING_HASH_PERSONALIZATION)?;
    let orchard_digest = if tx_info.orchard_digest == [0; 32] {
        empty_digest(ZCASH_ORCHARD_HASH_PERSONALIZATION)?
    } else {
        tx_info.orchard_digest
    };
    debug!("Orchard hash: {}", HexSlice(&orchard_digest));

    let mut personalization = [0u8; 16];
    personalization[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    personalization[12..].copy_from_slice(&u32::from(branch_id).to_le_bytes());

    let mut hasher = Blake2b_256::default();
    ok!(hasher.init_with_perso(&personalization));
    ok!(hasher.update(&tx_info.header_digest));
    ok!(hasher.update(transparent_digest));
    ok!(hasher.update(&sapling_digest));
    ok!(hasher.update(&orchard_digest));
    ok!(hasher.finalize(&mut tx_info.signature_digest));

    debug!("Signature hash: {}", HexSlice(&tx_info.signature_digest));

    Ok(())
}

fn empty_digest(personalization: &[u8; 16]) -> Result<[u8; 32], ParserError> {
    let mut hash = [0u8; 32];
    let mut hasher = Blake2b_256::default();
    ok!(hasher.init_with_perso(personalization));
    ok!(hasher.finalize(&mut hash));
    Ok(hash)
}
