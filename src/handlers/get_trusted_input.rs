use crate::{
    consts::TRUSTED_INPUT_SIZE,
    handlers::sign_tx::TxContext,
    log::{debug, error, info},
    parser::{ParserCtx, ParserMode, ParserSourceError},
    settings::Settings,
    utils::{read_u32, Endianness, HexSlice},
    AppSW,
};
use ledger_device_sdk::{
    hmac::{sha2::Sha2_256 as HmacSha256, HMACInit},
    io::Comm,
    random::rand_bytes,
};

const MAGIC_TRUSTED_INPUT: u8 = 0x32;

pub fn handler_get_trusted_input(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    _next: bool,
) -> Result<(), AppSW> {
    let mut data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if first {
        info!("Reset TX context");
        ctx.reset(ParserMode::TrustedInput);

        let transaction_trusted_input_idx = read_u32(data, Endianness::Big, false)?;
        data = &data[4..];

        ctx.set_transaction_trusted_input_idx(transaction_trusted_input_idx);
        info!("Trusted input idx: {}", transaction_trusted_input_idx);
    }

    ctx.parser
        .parse(
            &mut ParserCtx {
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

    if ctx.parser.is_finished() {
        if !ctx.trusted_input_info.is_input_processed {
            error!("Trusted input index was not processed");
            return Err(AppSW::IncorrectData);
        }

        let mut rng = [0u8; 4];
        rand_bytes(&mut rng);

        comm.append(&[MAGIC_TRUSTED_INPUT, 0x00]);
        comm.append(&rng[2..]);
        comm.append(&ctx.trusted_input_info.tx_id);
        comm.append(
            ctx.trusted_input_info
                .input_idx
                .expect("should be set at init parser state (see above)")
                .to_le_bytes()
                .as_ref(),
        );
        comm.append(ctx.trusted_input_info.amount.to_le_bytes().as_ref());

        // Compute HMAC-SHA256 signature over the trusted input
        let mut signature = [0u8; 8];
        let mut hmac_sha256_signer = HmacSha256::new(
            &Settings
                .trusted_input_key()
                .ok_or(AppSW::TechnicalProblem)?,
        );
        debug!("HMAC input: {}", HexSlice(comm.get(0, TRUSTED_INPUT_SIZE)));

        hmac_sha256_signer
            .update(comm.get(0, TRUSTED_INPUT_SIZE))
            .map_err(|err| {
                error!("HMAC update error {:?}", err);
                AppSW::TechnicalProblem
            })?;
        hmac_sha256_signer.finalize(&mut signature).map_err(|err| {
            error!("HMAC finalize error {:?}", err);
            AppSW::TechnicalProblem
        })?;

        comm.append(&signature);
    }

    Ok(())
}
