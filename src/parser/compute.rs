use crate::parser::personalization::{
    ZCASH_HEADERS_HASH_PERSONALIZATION, ZCASH_SAPLING_HASH_PERSONALIZATION,
    ZCASH_TRANSPARENT_HASH_PERSONALIZATION, ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION,
    ZCASH_TX_PERSONALIZATION_PREFIX,
};
use corez::io::Write;
use ledger_device_sdk::hash::{HashInit as _, blake2::Blake2b_256, sha2::Sha2_256};
use ledger_device_sdk::log::{debug, info};
use zcash_encoding::CompactSize;
#[cfg(feature = "zcash_unstable")]
use crate::consts::{V6_TX_VERSION, V6_VERSION_GROUP_ID};

use crate::{
    consts::SIGHASH_ALL,
    parser::{
        LegacyParserCtx, ParserError, ZCASH_ORCHARD_V5_HASH_PERSONALIZATION, finalize_and_log_hash,
        ok,
    },
    tx::{SupportedTxVersion, TxInfo},
    utils::{
        HexSlice,
        blake2b_256_pers::{AsWriter as _, Blake2b256Personalization as _},
    },
};

pub fn tx_id(ctx: &mut LegacyParserCtx<'_>) -> Result<(), ParserError> {
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
        #[cfg(feature = "zcash_unstable")]
        SupportedTxVersion::V6 => unreachable!("V6 transactions use the PCZT path"),
    }

    Ok(())
}

pub fn finalize_signature_input_hash(ctx: &mut LegacyParserCtx<'_>) -> Result<(), ParserError> {
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
enum SighHashComputeMode<'a> {
    NoTransparentInputsOrOutputs,
    NoTransparentInputs,
    SomeTransparentInputs { txin_sig_digest: &'a [u8; 32] },
}

fn empty_txin_signature_digest() -> Result<[u8; 32], ParserError> {
    let txin_sig_digest = empty_digest(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION)?;
    debug!("Shielded txin sig digest: {}", HexSlice(&txin_sig_digest));

    Ok(txin_sig_digest)
}

pub fn compute_shielded_signature_digest(
    tx_info: &mut TxInfo,
    transparent_input_count: usize,
    transparent_output_count: usize,
) -> Result<(), ParserError> {
    // Implements ZIP 244 S.2g for Sapling Spend and Orchard Action signatures:
    // when transparent inputs exist, txin_sig_digest is Zcash___TxInHash over empty input data.
    if transparent_input_count == 0 {
        compute_no_transparent_input_signature_digest(
            tx_info,
            transparent_output_count,
            SIGHASH_ALL,
        )
    } else {
        let txin_sig_digest = empty_txin_signature_digest()?;
        compute_transparent_input_signature_digest(tx_info, &txin_sig_digest, SIGHASH_ALL)
    }
}

pub fn compute_no_transparent_input_signature_digest(
    tx_info: &mut TxInfo,
    transparent_output_count: usize,
    sighash_type: u8,
) -> Result<(), ParserError> {
    tx_info.sighash_type = sighash_type;

    let mode = if transparent_output_count == 0 {
        SighHashComputeMode::NoTransparentInputsOrOutputs
    } else {
        SighHashComputeMode::NoTransparentInputs
    };

    finalize_signature_hash(tx_info, mode, sighash_type)
}

pub fn compute_transparent_input_signature_digest(
    tx_info: &mut TxInfo,
    txin_sig_digest: &[u8; 32],
    sighash_type: u8,
) -> Result<(), ParserError> {
    tx_info.sighash_type = sighash_type;

    finalize_signature_hash(
        tx_info,
        SighHashComputeMode::SomeTransparentInputs { txin_sig_digest },
        sighash_type,
    )
}

pub fn write_transparent_script<W: Write>(
    mut writer: W,
    script_pubkey: &[u8],
) -> Result<(), ParserError> {
    ok!(CompactSize::write(&mut writer, script_pubkey.len()));
    ok!(writer.write_all(script_pubkey));

    Ok(())
}

pub fn transparent_input_txin_signature_digest(
    prevout: &[u8],
    amount: &[u8; 8],
    script_pubkey: &[u8],
    sequence: u32,
) -> Result<[u8; 32], ParserError> {
    let mut txin_sig_digest = [0u8; 32];
    let mut hasher = Blake2b_256::default();
    ok!(hasher.init_with_perso(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION));
    ok!(hasher.update(prevout));
    ok!(hasher.update(amount));
    write_transparent_script(hasher.as_writer(), script_pubkey)?;
    ok!(hasher.update(&sequence.to_le_bytes()));
    ok!(hasher.finalize(&mut txin_sig_digest));

    Ok(txin_sig_digest)
}

fn finalize_signature_hash(
    tx_info: &mut TxInfo,
    mode: SighHashComputeMode<'_>,
    sighash_type: u8,
) -> Result<(), ParserError> {
    compute_header_digest(tx_info)?;

    let transparent_digest = transparent_signature_digest(tx_info, mode, sighash_type)?;

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
    #[cfg(feature = "zcash_unstable")]
    if tx_info.is_v6 {
        ok!(hasher.update(&(V6_TX_VERSION | 0x80000000u32).to_le_bytes()));
        ok!(hasher.update(&V6_VERSION_GROUP_ID.to_le_bytes()));
        ok!(hasher.update(&tx_info.branch_id_raw.to_le_bytes()));
    } else {
        ok!(tx_version.write(&mut hasher.as_writer()));
        ok!(hasher.update(&u32::from(branch_id).to_le_bytes()));
    }
    #[cfg(not(feature = "zcash_unstable"))]
    {
        ok!(tx_version.write(&mut hasher.as_writer()));
        ok!(hasher.update(&u32::from(branch_id).to_le_bytes()));
    }
    ok!(hasher.update(&tx_info.locktime.to_le_bytes()));
    ok!(hasher.update(&tx_info.expiry_height.to_le_bytes()));
    ok!(hasher.finalize(&mut tx_info.header_digest));
    debug!("Header hash: {}", HexSlice(&tx_info.header_digest));

    Ok(())
}

fn transparent_signature_digest(
    tx_info: &TxInfo,
    mode: SighHashComputeMode<'_>,
    sighash_type: u8,
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
        SighHashComputeMode::SomeTransparentInputs { txin_sig_digest } => {
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
        empty_digest(ZCASH_ORCHARD_V5_HASH_PERSONALIZATION)?
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
    #[cfg(feature = "zcash_unstable")]
    if tx_info.has_ironwood_bundle {
        ok!(hasher.update(&tx_info.ironwood_digest));
    }
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
