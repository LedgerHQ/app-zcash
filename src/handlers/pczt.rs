use ledger_device_sdk::io::Comm;
use ledger_device_sdk::log::{debug, error, info};

use crate::AppSW;
use crate::handlers::sign_tx::append_signature;
use crate::parser::{ParserMode, ParserSourceError, PcztParserCtx};
use crate::tx::TxContext;

pub fn handler_pczt_transparent_input(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    last: bool,
) -> Result<(), AppSW> {
    if first {
        info!("Reset TX context for PCZT transparent input parsing");
        ctx.reset(ParserMode::Signature);
    }

    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    ctx.pczt_parser
        .parse_transparent_inputs(
            &mut PcztParserCtx {
                tx_state: &mut ctx.tx_signing_state,
                tx_info: &mut ctx.tx_info,
                hashers: &mut ctx.hashers,
                swap_params: ctx.swap_params,
            },
            data,
        )
        .map_err(|e| {
            error!("Error parsing PCZT transparent input data: {:#?}", e);
            match e.source {
                ParserSourceError::Hash(_) => AppSW::TechnicalProblem,
                ParserSourceError::AppSW(sw) => sw,
                _ => AppSW::IncorrectData,
            }
        })?;

    if last && !ctx.pczt_parser.is_transparent_inputs_finished() {
        error!("PCZT transparent input data ended before all inputs were parsed");
        return Err(AppSW::WrongApduLength);
    }

    Ok(())
}

pub fn handler_pczt_transparent_output(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    last: bool,
) -> Result<(), AppSW> {
    if first {
        debug!("Start PCZT transparent output parsing");
    }

    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    ctx.pczt_parser
        .parse_transparent_outputs(
            &mut PcztParserCtx {
                tx_state: &mut ctx.tx_signing_state,
                tx_info: &mut ctx.tx_info,
                hashers: &mut ctx.hashers,
                swap_params: ctx.swap_params,
            },
            data,
        )
        .map_err(|e| {
            error!("Error parsing PCZT transparent output data: {:#?}", e);
            match e.source {
                ParserSourceError::Hash(_) => AppSW::TechnicalProblem,
                ParserSourceError::AppSW(sw) => sw,
                ParserSourceError::UserDenied => {
                    ctx.set_finished();
                    AppSW::Deny
                }
                ParserSourceError::SwapError {
                    common_code,
                    app_code,
                    message,
                } => {
                    error!(
                        "Swap error with common code {}, app code {}, message {:?}",
                        common_code, app_code, message
                    );
                    AppSW::IncorrectData
                }
                _ => AppSW::IncorrectData,
            }
        })?;

    if last && !ctx.pczt_parser.is_finished() {
        error!("PCZT transparent output data ended before all outputs were parsed");
        return Err(AppSW::WrongApduLength);
    }

    if ctx.pczt_parser.is_finished() && !ctx.tx_signing_state.is_tx_parsed_once {
        info!("Set TX parsed once flag after PCZT transparent outputs");
        ctx.tx_signing_state.is_tx_parsed_once = true;
    }

    Ok(())
}

pub fn handler_pczt_sign_transparent(
    comm: &mut Comm,
    ctx: &mut TxContext,
    input_index: usize,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if !data.is_empty() {
        error!("Unexpected data for PCZT transparent signing");
        return Err(AppSW::WrongApduLength);
    }

    if !ctx.pczt_parser.is_finished() {
        error!("PCZT transparent inputs and outputs are not ready for signing");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    let sighash_type = ctx
        .pczt_parser
        .compute_transparent_signature_digest(&mut ctx.tx_info, input_index)
        .map_err(|e| {
            error!(
                "Error computing PCZT transparent signature digest: {:#?}",
                e
            );
            match e.source {
                ParserSourceError::Hash(_) => AppSW::TechnicalProblem,
                ParserSourceError::AppSW(sw) => sw,
                _ => AppSW::IncorrectData,
            }
        })?;

    let path = ctx
        .pczt_parser
        .transparent_input_signing_path(input_index)
        .map_err(|e| {
            error!("Error reading PCZT transparent signing path: {:#?}", e);
            match e.source {
                ParserSourceError::AppSW(sw) => sw,
                _ => AppSW::IncorrectData,
            }
        })?;

    append_signature(
        comm,
        &ctx.tx_info.signature_digest,
        path,
        sighash_type,
        true,
    )?;

    ctx.tx_signing_state.already_signed_input_count = ctx
        .tx_signing_state
        .already_signed_input_count
        .saturating_add(1);

    let expected_signatures = core::cmp::max(ctx.tx_signing_state.total_input_count, 1);
    info!(
        "Signed PCZT transparent input {}/{}",
        ctx.tx_signing_state.already_signed_input_count, expected_signatures
    );

    if ctx.tx_signing_state.already_signed_input_count == expected_signatures {
        info!("All PCZT transparent inputs have been signed");
        ctx.set_finished();
    }

    Ok(())
}
