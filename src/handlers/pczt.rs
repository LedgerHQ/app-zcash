use ledger_device_sdk::io::Comm;
use ledger_device_sdk::log::{error, info};

use crate::AppSW;
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
        .parse(
            &mut PcztParserCtx {
                tx_state: &mut ctx.tx_signing_state,
                tx_info: &mut ctx.tx_info,
                hashers: &mut ctx.hashers,
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

    if last && !ctx.pczt_parser.is_finished() {
        error!("PCZT transparent input data ended before all inputs were parsed");
        return Err(AppSW::WrongApduLength);
    }

    Ok(())
}
