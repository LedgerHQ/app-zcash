use ledger_device_sdk::io::Comm;
use ledger_device_sdk::log::{debug, error, info};

use crate::AppSW;
use crate::handlers::sign_tx::{append_signature, orchard_spend_auth_signature_with_sk};
use crate::parser::{LegacyParserMode, ParserError, ParserSourceError, PcztParserCtx};
use crate::tx::TxContext;

fn are_pczt_transparent_signatures_done(ctx: &TxContext) -> bool {
    ctx.tx_signing_state.total_input_count == 0
        || ctx.tx_signing_state.already_signed_input_count >= ctx.tx_signing_state.total_input_count
}

fn are_pczt_signatures_done(ctx: &TxContext) -> bool {
    #[cfg(feature = "zcash_unstable")]
    let ironwood_done = ctx.pczt_parser.are_ironwood_signatures_done();
    #[cfg(not(feature = "zcash_unstable"))]
    let ironwood_done = true;
    are_pczt_transparent_signatures_done(ctx)
        && ctx.pczt_parser.are_orchard_signatures_done()
        && ironwood_done
}

fn reset_pczt_parser_after_error(ctx: &mut TxContext) {
    ctx.pczt_parser.reset();
    debug!("PCZT parser state reset after error");
}

fn reset_pczt_parser_with_sw(ctx: &mut TxContext, sw: AppSW) -> AppSW {
    reset_pczt_parser_after_error(ctx);
    sw
}

fn map_pczt_parser_error(ctx: &mut TxContext, error: ParserError) -> AppSW {
    let sw = match error.source {
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
    };

    reset_pczt_parser_after_error(ctx);
    sw
}

fn finish_pczt_if_requested(ctx: &mut TxContext, requested: bool) -> Result<(), AppSW> {
    if !requested {
        return Ok(());
    }

    if let Err(e) = ctx.pczt_parser.finish_pczt() {
        error!("Error finishing PCZT: {:#?}", e);
        return Err(map_pczt_parser_error(ctx, e));
    }

    info!("PCZT is finished and ready to sign");
    ctx.tx_signing_state.is_tx_parsed_once = true;

    Ok(())
}

pub fn handler_pczt_header(comm: &mut Comm, ctx: &mut TxContext) -> Result<(), AppSW> {
    info!("Reset TX context for PCZT header parsing");
    ctx.reset(LegacyParserMode::Signature);

    let data = match comm.get_data() {
        Ok(data) => data,
        Err(_) => return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength)),
    };

    if let Err(e) = ctx.pczt_parser.parse_header(
        &mut PcztParserCtx {
            tx_state: &mut ctx.tx_signing_state,
            tx_info: &mut ctx.tx_info,
            hashers: &mut ctx.hashers,
        },
        data,
    ) {
        error!("Error parsing PCZT header data: {:#?}", e);
        return Err(map_pczt_parser_error(ctx, e));
    }

    Ok(())
}

pub fn handler_pczt_transparent_input(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    last: bool,
) -> Result<(), AppSW> {
    if first {
        debug!("Start PCZT transparent input parsing");
    }

    let data = match comm.get_data() {
        Ok(data) => data,
        Err(_) => return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength)),
    };

    if let Err(e) = ctx.pczt_parser.parse_transparent_inputs(
        &mut PcztParserCtx {
            tx_state: &mut ctx.tx_signing_state,
            tx_info: &mut ctx.tx_info,
            hashers: &mut ctx.hashers,
        },
        data,
    ) {
        error!("Error parsing PCZT transparent input data: {:#?}", e);
        return Err(map_pczt_parser_error(ctx, e));
    }

    if last && !ctx.pczt_parser.is_transparent_inputs_finished() {
        error!("PCZT transparent input data ended before all inputs were parsed");
        return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength));
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

    let data = match comm.get_data() {
        Ok(data) => data,
        Err(_) => return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength)),
    };

    if let Err(e) = ctx.pczt_parser.parse_transparent_outputs(
        &mut PcztParserCtx {
            tx_state: &mut ctx.tx_signing_state,
            tx_info: &mut ctx.tx_info,
            hashers: &mut ctx.hashers,
        },
        data,
    ) {
        error!("Error parsing PCZT transparent output data: {:#?}", e);
        return Err(map_pczt_parser_error(ctx, e));
    }

    if last && !ctx.pczt_parser.is_transparent_outputs_finished() {
        error!("PCZT transparent output data ended before all outputs were parsed");
        return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength));
    }

    Ok(())
}

pub fn handler_pczt_orchard_action(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    last: bool,
    finished: bool,
) -> Result<(), AppSW> {
    if first {
        debug!("Start PCZT orchard action parsing");
    }

    let data = match comm.get_data() {
        Ok(data) => data,
        Err(_) => return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength)),
    };

    if let Err(e) = ctx.pczt_parser.parse_orchard_actions(
        &mut PcztParserCtx {
            tx_state: &mut ctx.tx_signing_state,
            tx_info: &mut ctx.tx_info,
            hashers: &mut ctx.hashers,
        },
        data,
    ) {
        error!("Error parsing PCZT orchard action data: {:#?}", e);
        return Err(map_pczt_parser_error(ctx, e));
    }

    if last && !ctx.pczt_parser.is_orchard_actions_finished() {
        error!("PCZT orchard action data ended before all actions were parsed");
        return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength));
    }

    finish_pczt_if_requested(ctx, finished)?;

    Ok(())
}

#[cfg(feature = "zcash_unstable")]
pub fn handler_pczt_ironwood_action(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    last: bool,
    finished: bool,
) -> Result<(), AppSW> {
    if first {
        debug!("Start PCZT ironwood action parsing");
    }

    let data = match comm.get_data() {
        Ok(data) => data,
        Err(_) => return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength)),
    };

    if let Err(e) = ctx.pczt_parser.parse_ironwood_actions(
        &mut PcztParserCtx {
            tx_state: &mut ctx.tx_signing_state,
            tx_info: &mut ctx.tx_info,
            hashers: &mut ctx.hashers,
        },
        data,
    ) {
        error!("Error parsing PCZT ironwood action data: {:#?}", e);
        return Err(map_pczt_parser_error(ctx, e));
    }

    if last && !ctx.pczt_parser.is_ironwood_actions_finished() {
        error!("PCZT ironwood action data ended before all actions were parsed");
        return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength));
    }

    finish_pczt_if_requested(ctx, finished)?;

    Ok(())
}

pub fn handler_pczt_sign_transparent(
    comm: &mut Comm,
    ctx: &mut TxContext,
    input_index: usize,
) -> Result<(), AppSW> {
    let data = match comm.get_data() {
        Ok(data) => data,
        Err(_) => return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength)),
    };

    if !data.is_empty() {
        error!("Unexpected data for PCZT transparent signing");
        return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength));
    }

    if !ctx.pczt_parser.is_finished() {
        error!("PCZT is not finished and ready for transparent signing");
        return Err(reset_pczt_parser_with_sw(
            ctx,
            AppSW::ConditionsOfUseNotSatisfied,
        ));
    }

    // Reject a second signature for the same input
    if let Err(e) = ctx.pczt_parser.mark_transparent_input_signed(input_index) {
        error!(
            "PCZT transparent input {} cannot be signed: {:#?}",
            input_index, e
        );
        return Err(map_pczt_parser_error(ctx, e));
    }

    let sighash_type = match ctx
        .pczt_parser
        .use_transparent_signature_digest(&mut ctx.tx_info, input_index)
    {
        Ok(sighash_type) => sighash_type,
        Err(e) => {
            error!(
                "Error selecting PCZT transparent signature digest: {:#?}",
                e
            );
            return Err(map_pczt_parser_error(ctx, e));
        }
    };

    let path = match ctx.pczt_parser.transparent_input_signing_path(input_index) {
        Ok(path) => path,
        Err(e) => {
            error!("Error reading PCZT transparent signing path: {:#?}", e);
            return Err(map_pczt_parser_error(ctx, e));
        }
    };

    if let Err(sw) = append_signature(
        comm,
        &ctx.tx_info.signature_digest,
        path,
        sighash_type,
        true,
    ) {
        return Err(reset_pczt_parser_with_sw(ctx, sw));
    }

    ctx.tx_signing_state.already_signed_input_count = ctx
        .tx_signing_state
        .already_signed_input_count
        .saturating_add(1);

    let expected_signatures = core::cmp::max(ctx.tx_signing_state.total_input_count, 1);
    info!(
        "Signed PCZT transparent input {}/{}",
        ctx.tx_signing_state.already_signed_input_count, expected_signatures
    );

    if are_pczt_signatures_done(ctx) {
        info!("All PCZT signatures have been produced");
        ctx.set_finished();
        ctx.pczt_parser.reset();
    }

    Ok(())
}

pub fn handler_pczt_sign_orchard(
    comm: &mut Comm,
    ctx: &mut TxContext,
    action_index: usize,
) -> Result<(), AppSW> {
    let data = match comm.get_data() {
        Ok(data) => data,
        Err(_) => return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength)),
    };

    if !data.is_empty() {
        error!("Unexpected data for PCZT orchard signing");
        return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength));
    }

    if !ctx.pczt_parser.is_finished() {
        error!("PCZT is not finished and ready for Orchard signing");
        return Err(reset_pczt_parser_with_sw(
            ctx,
            AppSW::ConditionsOfUseNotSatisfied,
        ));
    }

    if let Err(e) = ctx
        .pczt_parser
        .ensure_signature_digest_for_orchard(&mut ctx.tx_info, action_index)
    {
        error!(
            "Error preparing PCZT signature digest for Orchard signing: {:#?}",
            e
        );
        return Err(map_pczt_parser_error(ctx, e));
    }

    let (path, alpha) = match ctx.pczt_parser.orchard_action_signing_data(action_index) {
        Ok((path, alpha)) => (*path, alpha),
        Err(e) => {
            error!("Error reading PCZT orchard signing data: {:#?}", e);
            return Err(map_pczt_parser_error(ctx, e));
        }
    };

    // Reuse the session-cached account spending key rather than re-deriving it
    // per action (repeated zip32_orchard_derive exhausts the SE and fails 6f00).
    let sk = match ctx.pczt_parser.orchard_spending_key(&path) {
        Ok(sk) => sk,
        Err(sw) => return Err(reset_pczt_parser_with_sw(ctx, sw)),
    };

    let auth_sig =
        match orchard_spend_auth_signature_with_sk(sk, &ctx.tx_info.signature_digest, alpha) {
            Ok(auth_sig) => auth_sig,
            Err(sw) => return Err(reset_pczt_parser_with_sw(ctx, sw)),
        };
    comm.append(&auth_sig);

    let signed_orchard_count = match ctx.pczt_parser.mark_orchard_action_signed(action_index) {
        Ok(signed_orchard_count) => signed_orchard_count,
        Err(e) => {
            error!("Error marking PCZT orchard action as signed: {:#?}", e);
            return Err(map_pczt_parser_error(ctx, e));
        }
    };
    let orchard_signature_count = ctx.pczt_parser.orchard_signature_count();

    info!(
        "Signed PCZT orchard action {} ({}/{})",
        action_index, signed_orchard_count, orchard_signature_count
    );

    if are_pczt_signatures_done(ctx) {
        info!("All PCZT signatures have been produced");
        ctx.set_finished();
        ctx.pczt_parser.reset();
    }

    Ok(())
}

#[cfg(feature = "zcash_unstable")]
pub fn handler_pczt_sign_ironwood(
    comm: &mut Comm,
    ctx: &mut TxContext,
    action_index: usize,
) -> Result<(), AppSW> {
    let data = match comm.get_data() {
        Ok(data) => data,
        Err(_) => return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength)),
    };

    if !data.is_empty() {
        error!("Unexpected data for PCZT ironwood signing");
        return Err(reset_pczt_parser_with_sw(ctx, AppSW::WrongApduLength));
    }

    if !ctx.pczt_parser.is_finished() {
        error!("PCZT is not finished and ready for Ironwood signing");
        return Err(reset_pczt_parser_with_sw(
            ctx,
            AppSW::ConditionsOfUseNotSatisfied,
        ));
    }

    if let Err(e) = ctx
        .pczt_parser
        .ensure_signature_digest_for_ironwood(&mut ctx.tx_info, action_index)
    {
        error!(
            "Error preparing PCZT signature digest for Ironwood signing: {:#?}",
            e
        );
        return Err(map_pczt_parser_error(ctx, e));
    }

    let (path, alpha) = match ctx.pczt_parser.ironwood_action_signing_data(action_index) {
        Ok(signing_data) => signing_data,
        Err(e) => {
            error!("Error reading PCZT ironwood signing data: {:#?}", e);
            return Err(map_pczt_parser_error(ctx, e));
        }
    };

    let auth_sig =
        match orchard_spend_auth_signature_with_alpha(path, &ctx.tx_info.signature_digest, alpha) {
            Ok(auth_sig) => auth_sig,
            Err(sw) => return Err(reset_pczt_parser_with_sw(ctx, sw)),
        };
    comm.append(&auth_sig);

    let signed_ironwood_count = match ctx.pczt_parser.mark_ironwood_action_signed(action_index) {
        Ok(signed_ironwood_count) => signed_ironwood_count,
        Err(e) => {
            error!("Error marking PCZT ironwood action as signed: {:#?}", e);
            return Err(map_pczt_parser_error(ctx, e));
        }
    };
    let ironwood_signature_count = ctx.pczt_parser.ironwood_signature_count();

    info!(
        "Signed PCZT ironwood action {} ({}/{})",
        action_index, signed_ironwood_count, ironwood_signature_count
    );

    if are_pczt_signatures_done(ctx) {
        info!("All PCZT signatures have been produced");
        ctx.set_finished();
        ctx.pczt_parser.reset();
    }

    Ok(())
}
