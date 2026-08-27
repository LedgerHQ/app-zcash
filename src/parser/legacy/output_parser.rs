use crate::parser::personalization::ZCASH_OUTPUTS_HASH_PERSONALIZATION;

use super::*;

pub struct LegacyOutputParserCtx<'ctx> {
    pub tx_info: &'ctx mut TxInfo,
    pub hashers: &'ctx mut Hashers,
    pub swap_params: Option<&'ctx CreateTxParams>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum LegacyOutputParserState {
    ParsingNumberOfOutputs,
    ParsingOutput,
    ProcessOutputScript { size: usize, remaining_size: usize },
    OutputProcessingDone,
}

pub struct LegacyOutputParser {
    state: LegacyOutputParserState,
    output_count: usize,
    pub total_output_amount: u64,
    output_parsed_count: usize,
    current_output_amount: u64,
    script_bytes: Vec<u8>,
}

impl LegacyOutputParser {
    pub fn new() -> Self {
        LegacyOutputParser {
            state: LegacyOutputParserState::ParsingNumberOfOutputs,
            output_count: 0,
            total_output_amount: 0,
            output_parsed_count: 0,
            current_output_amount: 0,
            script_bytes: Vec::new(),
        }
    }

    pub fn transparent_output_count(&self) -> usize {
        self.output_count
    }

    pub fn is_finished(&self) -> bool {
        self.state == LegacyOutputParserState::OutputProcessingDone
    }

    /// Completes the output side: derives the fee, cross-checks it under swap, and closes the
    /// outputs hash. The user-facing review is run later, by `handler_hash_sign`.
    fn finalize_outputs(&mut self, ctx: &mut LegacyOutputParserCtx<'_>) -> Result<(), ParserError> {
        if ctx.tx_info.outputs.is_empty() {
            return Err(ParserError::from_str("No transparent outputs to display"));
        }

        let fees = ctx
            .tx_info
            .total_amount
            .checked_sub(self.total_output_amount)
            .ok_or_else(|| {
                error!(
                    "Failed to calculate fees: total_amount={}, total_output_amount={}",
                    ctx.tx_info.total_amount, self.total_output_amount
                );
                ParserError::from_str("Failed to calculate fees")
            })?;

        if let Some(swap_params) = ctx.swap_params {
            ok!(swap::check_swap_params(
                swap_params,
                &ctx.tx_info.outputs,
                fees
            ));
        } else {
            // The review is deliberately not run here. On this path `locktime` and
            // `expiry_height` only reach the device with the HASH_SIGN header that follows, so
            // reviewing now would ask the user to approve a transaction whose validity window is
            // still unknown, and the host could then pick any. `handler_hash_sign` runs it once
            // the header is in.
            ctx.tx_info.fees = fees;
        }

        ok!(ctx
            .hashers
            .outputs_hasher
            .finalize(&mut ctx.tx_info.outputs_hash));

        info!("Outputs hash: {}", HexSlice(&ctx.tx_info.outputs_hash));

        Ok(())
    }

    pub fn parse(
        &mut self,
        ctx: &mut LegacyOutputParserCtx<'_>,
        data: &[u8],
    ) -> Result<(), ParserError> {
        let mut reader = ByteReader::new(data);

        while reader.remaining_len() > 0 {
            let prev_state = self.state;

            match &self.state {
                LegacyOutputParserState::ParsingNumberOfOutputs => {
                    let output_count: usize = ok!(CompactSize::read_t(&mut reader));
                    info!("Output count: {}", output_count);

                    if output_count > MAX_OUTPUTS_NUMBER {
                        return Err(ParserError::from_str("Too many outputs"));
                    }

                    ok!(ctx
                        .hashers
                        .outputs_hasher
                        .init_with_perso(ZCASH_OUTPUTS_HASH_PERSONALIZATION));

                    self.output_count = output_count;
                    self.state = LegacyOutputParserState::ParsingOutput;
                }
                LegacyOutputParserState::ParsingOutput => {
                    let amount: Zatoshis = ok!({
                        let mut tmp = [0u8; 8];
                        ok!(reader.read_exact(&mut tmp));
                        Zatoshis::from_nonnegative_i64_le_bytes(tmp)
                    });

                    info!("Output amount: {:?}", amount);

                    ok!(ctx.hashers.outputs_hasher.update(&amount.to_i64_le_bytes()));

                    self.current_output_amount = amount.into_u64();
                    self.total_output_amount = self
                        .total_output_amount
                        .saturating_add(self.current_output_amount);

                    let script_size: usize = ok!(CompactSize::read_t(&mut reader));

                    if script_size > MAX_SCRIPT_SIZE {
                        return Err(ParserError::from_str("Bad output script size"));
                    }

                    info!("Output script size: {}", script_size);

                    self.script_bytes.clear();
                    self.script_bytes.extend(iter::repeat_n(0, script_size));

                    self.state = LegacyOutputParserState::ProcessOutputScript {
                        size: script_size,
                        remaining_size: script_size,
                    };
                }

                LegacyOutputParserState::ProcessOutputScript {
                    size,
                    remaining_size,
                } => {
                    let new_remaining_size = {
                        let offset = size - remaining_size;
                        let len =
                            ok!(reader.read(&mut self.script_bytes[offset..][..*remaining_size]));

                        remaining_size.saturating_sub(len)
                    };

                    if new_remaining_size != 0 {
                        self.state = LegacyOutputParserState::ProcessOutputScript {
                            size: *size,
                            remaining_size: new_remaining_size,
                        };
                        info!(
                            "Need more output script bytes, remaining size: {}",
                            new_remaining_size
                        );
                        continue;
                    }

                    let mut script = Script::default();
                    // NOTE: take/deallocate self.script_bytes here
                    script.0.0 = mem::take(&mut self.script_bytes);
                    ok!(script.write(ctx.hashers.outputs_hasher.as_writer()));

                    match check_output_displayable(
                        &script.0.0,
                        self.current_output_amount,
                        ctx.tx_info.change_pk_hash.as_ref(),
                    ) {
                        output @ (CheckDispOutput::Change | CheckDispOutput::Displayable) => {
                            let is_change = output == CheckDispOutput::Change;

                            if is_change && ctx.tx_info.is_change_found {
                                error!("Multiple change outputs detected");
                                return Err(ParserError::from_str(
                                    "Multiple change outputs detected",
                                ));
                            }

                            let address =
                                ok!(Base58Address::from_output_script(&script.0.0)).to_string();
                            debug!("address_string: {}", &address);

                            ctx.tx_info.outputs.push(TxOutput {
                                amount: self.current_output_amount,
                                address,
                                is_change,
                                memo: None,
                                pool: TxPool::Transparent,
                            });

                            if is_change {
                                ctx.tx_info.is_change_found = true;
                            }
                        }
                        CheckDispOutput::None => {
                            return Err(ParserError::from_str(
                                "Unsupported transparent output script cannot be safely reviewed",
                            ));
                        }
                    }

                    self.output_parsed_count = self.output_parsed_count.saturating_add(1);

                    if self.output_count == self.output_parsed_count {
                        info!("All outputs parsed");

                        self.finalize_outputs(ctx)?;
                        self.state = LegacyOutputParserState::OutputProcessingDone;
                    } else {
                        self.state = LegacyOutputParserState::ParsingOutput;
                    }
                }

                LegacyOutputParserState::OutputProcessingDone => {
                    break;
                }
            }

            if self.state != prev_state {
                info!(
                    "Output parser state changed: {:?} -> {:?}",
                    prev_state, self.state
                );
            }
        }

        Ok(())
    }
}
