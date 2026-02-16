use ledger_device_sdk::hash::{blake2::Blake2b_256, sha2::Sha2_256, HashInit as _};
use zcash_primitives::transaction::{
    txid::{
        ZCASH_HEADERS_HASH_PERSONALIZATION, ZCASH_SAPLING_HASH_PERSONALIZATION,
        ZCASH_TRANSPARENT_HASH_PERSONALIZATION, ZCASH_TX_PERSONALIZATION_PREFIX,
    },
    TxVersion,
};

use crate::{
    log::{debug, error, info},
    parser::{ok, ParserCtx, ParserError, ZCASH_ORCHARD_HASH_PERSONALIZATION},
    utils::{
        blake2b_256_pers::{AsWriter as _, Blake2b256Personalization as _},
        HexSlice,
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

    if let Some(TxVersion::V5) = ctx.tx_info.tx_version {
        let prevouts_hash = {
            let mut hash = [0u8; 32];
            ok!(ctx.hashers.prevouts_hasher.finalize(&mut hash));
            hash
        };
        debug!("Prevouts hash: {}", HexSlice(&prevouts_hash));

        let sequence_hash = {
            let mut hash = [0u8; 32];
            ok!(ctx.hashers.sequence_hasher.finalize(&mut hash));
            hash
        };
        debug!("Sequence hash: {}", HexSlice(&sequence_hash));

        let outputs_hash = {
            let mut hash = [0u8; 32];
            ok!(ctx.hashers.outputs_hasher.finalize(&mut hash));
            hash
        };
        debug!("Outputs hash: {}", HexSlice(&outputs_hash));

        let header_hash = {
            let mut hash = [0u8; 32];

            let mut hasher = Blake2b_256::default();
            hasher.init_with_perso(ZCASH_HEADERS_HASH_PERSONALIZATION);

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
            hasher.init_with_perso(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);

            ok!(hasher.update(&prevouts_hash));
            ok!(hasher.update(&sequence_hash));
            ok!(hasher.update(&outputs_hash));

            ok!(hasher.finalize(&mut hash));
            hash
        };
        debug!("Transparent hash: {}", HexSlice(&transparent_hash));

        let sapling_hash = {
            let mut hash = [0u8; 32];
            ok!(ctx.hashers.sapling_hasher.finalize(&mut hash));
            hash
        };
        debug!("Sapling hash: {}", HexSlice(&sapling_hash));

        let orchard_hash = {
            let mut hash = [0u8; 32];
            ok!(ctx.hashers.orchard_hasher.finalize(&mut hash));
            hash
        };
        debug!("Orchard hash: {}", HexSlice(&orchard_hash));

        let mut personalization = [0u8; 16];
        personalization[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
        personalization[12..].copy_from_slice(&u32::from(branch_id).to_le_bytes());

        let mut hasher = Blake2b_256::default();
        hasher.init_with_perso(&personalization);

        ok!(hasher.update(&header_hash));
        ok!(hasher.update(&transparent_hash));
        ok!(hasher.update(&sapling_hash));
        ok!(hasher.update(&orchard_hash));

        ok!(hasher.finalize(&mut ctx.trusted_input_info.tx_id));

        debug!(
            "Transaction ID hash: {}",
            HexSlice(&ctx.trusted_input_info.tx_id)
        );
    } else if let Some(TxVersion::V4) = ctx.tx_info.tx_version {
        let mut first_round_hash = [0u8; 32];
        ok!(ctx.hashers.v4_tx_hasher.finalize(&mut first_round_hash));

        let mut second_round_hasher = Sha2_256::new();
        ok!(second_round_hasher.hash(&first_round_hash, &mut ctx.trusted_input_info.tx_id));

        debug!(
            "V4 transaction ID hash: {}",
            HexSlice(&ctx.trusted_input_info.tx_id)
        );
    } else {
        error!(
            "TX ID computation for versions other than V4, V5 is not implemented {:?}",
            tx_version
        );
        return Err(ParserError::from_str(
            "TX ID computation for versions other than V4, V5 is not implemented",
        ));
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

pub fn finalize_signature_hash(ctx: &mut ParserCtx<'_>) -> Result<(), ParserError> {
    let mut txin_sig_digest = [0u8; 32];
    ok!(ctx.hashers.prevouts_hasher.finalize(&mut txin_sig_digest));
    info!("txin sig digest {}", HexSlice(&txin_sig_digest));

    // Compute transparent_sig_digest
    let transparent_digest = {
        let mut hash = [0u8; 32];

        let mut hasher = Blake2b_256::default();
        hasher.init_with_perso(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);

        ok!(hasher.update(&[ctx.tx_info.sighash_type]));
        ok!(hasher.update(&ctx.tx_info.prevouts_hash));
        ok!(hasher.update(&ctx.tx_info.amounts_hash));
        ok!(hasher.update(&ctx.tx_info.scripts_hash));
        ok!(hasher.update(&ctx.tx_info.sequence_hash));
        ok!(hasher.update(&ctx.tx_info.outputs_hash));
        ok!(hasher.update(&txin_sig_digest));

        ok!(hasher.finalize(&mut hash));
        hash
    };
    debug!("Transparent hash: {}", HexSlice(&transparent_digest));

    // Compute sapling_digest. Assume no Sapling spends or outputs are present
    let sapling_digest = {
        let mut sapling_digest = [0u8; 32];
        ctx.hashers
            .sapling_hasher
            .init_with_perso(ZCASH_SAPLING_HASH_PERSONALIZATION);
        ok!(ctx.hashers.sapling_hasher.finalize(&mut sapling_digest));
        sapling_digest
    };

    // Compute orchard_digest. Assume there are no Orchard actions
    let orchard_digest = {
        let mut orchard_digest = [0u8; 32];
        ctx.hashers
            .orchard_hasher
            .init_with_perso(ZCASH_ORCHARD_HASH_PERSONALIZATION);
        ok!(ctx.hashers.orchard_hasher.finalize(&mut orchard_digest));
        orchard_digest
    };

    let branch_id = ctx.tx_info.branch_id.expect("should be set at this point");

    // Start to compute signature_digest
    let mut personalization = [0u8; 16];
    personalization[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    personalization[12..].copy_from_slice(&u32::from(branch_id).to_le_bytes());

    let hasher = &mut ctx.hashers.tx_full_hasher;
    hasher.init_with_perso(&personalization);

    ok!(hasher.update(&ctx.tx_info.header_digest));
    ok!(hasher.update(&transparent_digest));
    ok!(hasher.update(&sapling_digest));
    ok!(hasher.update(&orchard_digest));

    Ok(())
}
