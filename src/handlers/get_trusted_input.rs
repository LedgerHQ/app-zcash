use crate::{
    AppSW,
    consts::TRUSTED_INPUT_SIZE,
    parser::{LegacyParserCtx, LegacyParserMode, ParserSourceError},
    rng,
    settings::Settings,
    tx::TxContext,
    utils::{Endianness, HexSlice, read_u32},
};
use ledger_device_sdk::{
    hmac::{HMACInit, sha2::Sha2_256 as HmacSha256},
    io::{Command, CommandResponse},
    log::{debug, error, info},
};

const MAGIC_TRUSTED_INPUT: u8 = 0x32;

pub fn handler_get_trusted_input<'a>(
    command: Command<'a>,
    ctx: &mut TxContext,
    first: bool,
    _next: bool,
) -> Result<CommandResponse<'a>, AppSW> {
    let mut data = command.get_data();

    // Only the first packet resets the context; a continuation parses into the transaction state
    // already there. During a PCZT session that state is the one the review approved, and the
    // hashers a continuation re-initialises are the ones its signature digest is built from.
    if !first && ctx.pczt_parser.is_session_active() {
        error!("Trusted-input continuation during a PCZT session");
        return Err(AppSW::BadState);
    }

    // Likewise once a transaction is finished: its outputs and hashers stay in place, and a
    // completed PCZT no longer reports an active session, so a continuation would build on the
    // previous transaction's state instead of a fresh one.
    if !first && ctx.is_finished() {
        error!("Trusted-input continuation resuming a finished transaction");
        return Err(AppSW::BadState);
    }

    if first {
        info!("Reset TX context");
        ctx.reset_for_new_transaction(LegacyParserMode::TrustedInput)?;

        let transaction_trusted_input_idx = read_u32(data, Endianness::Big, false)?;
        data = &data[4..];

        ctx.set_transaction_trusted_input_idx(transaction_trusted_input_idx);
        info!("Trusted input idx: {}", transaction_trusted_input_idx);
    }

    ctx.legacy_parser
        .parse(
            &mut LegacyParserCtx {
                tx_state: &mut ctx.tx_signing_state,
                tx_info: &mut ctx.tx_info,
                trusted_input_info: &mut ctx.trusted_input_info,
                hashers: &mut ctx.hashers,
            },
            data,
        )
        .map_err(|e| {
            error!("Error parsing trusted input: {:#?}", e);
            match e.source {
                ParserSourceError::Hash(_) => AppSW::TechnicalProblem,
                _ => AppSW::IncorrectData,
            }
        })?;

    let mut response = command.into_response();
    if ctx.legacy_parser.is_finished() {
        if !ctx.trusted_input_info.is_input_processed {
            error!("Trusted input index was not processed");
            return Err(AppSW::IncorrectData);
        }

        let mut nonce = [0u8; 4];
        rng::fill_bytes(&mut nonce)?;

        let mut trusted_input = [0u8; TRUSTED_INPUT_SIZE];
        trusted_input[..2].copy_from_slice(&[MAGIC_TRUSTED_INPUT, 0x00]);
        trusted_input[2..4].copy_from_slice(&nonce[2..]);
        trusted_input[4..36].copy_from_slice(&ctx.trusted_input_info.tx_id);
        trusted_input[36..40].copy_from_slice(
            &ctx.trusted_input_info
                .input_idx
                .expect("should be set at init parser state (see above)")
                .to_le_bytes(),
        );
        trusted_input[40..].copy_from_slice(&ctx.trusted_input_info.amount.to_le_bytes());

        // Compute HMAC-SHA256 signature over the trusted input
        let mut signature = [0u8; 8];
        let trusted_input_key = Settings
            .trusted_input_key()
            .ok_or(AppSW::TechnicalProblem)?;
        let mut hmac_sha256_signer = HmacSha256::new(trusted_input_key.as_ref());
        debug!("HMAC input: {}", HexSlice(&trusted_input));

        hmac_sha256_signer.update(&trusted_input).map_err(|err| {
            error!("HMAC update error {:?}", err);
            AppSW::TechnicalProblem
        })?;
        hmac_sha256_signer.finalize(&mut signature).map_err(|err| {
            error!("HMAC finalize error {:?}", err);
            AppSW::TechnicalProblem
        })?;

        response.append(&trusted_input)?;
        response.append(&signature)?;
    }

    Ok(response)
}
