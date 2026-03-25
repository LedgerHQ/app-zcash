use super::*;

pub struct OutputParserCtx<'ctx> {
    pub tx_info: &'ctx mut TxInfo,
    pub hashers: &'ctx mut Hashers,
    pub swap_params: Option<&'ctx CreateTxParams>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum OutputParseState {
    ParsingNumberOfOutputs,
    ParsingOutput,
    ProcessOutputScript { size: usize, remaining_size: usize },
    OutputProcessingDone,
}

pub struct OutputParser {
    state: OutputParseState,
    output_count: usize,
    pub total_output_amount: u64,
    output_parsed_count: usize,
    current_output_amount: u64,
    script_bytes: Vec<u8>,
}

impl OutputParser {
    pub fn new() -> Self {
        OutputParser {
            state: OutputParseState::ParsingNumberOfOutputs,
            output_count: 0,
            output_parsed_count: 0,
            total_output_amount: 0,
            current_output_amount: 0,
            script_bytes: Vec::new(),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.state == OutputParseState::OutputProcessingDone
    }

    pub fn parse(&mut self, ctx: &mut OutputParserCtx<'_>, data: &[u8]) -> Result<(), ParserError> {
        let mut reader = ByteReader::new(data);

        while reader.remaining_len() > 0 {
            let prev_state = self.state;

            match &self.state {
                OutputParseState::ParsingNumberOfOutputs => {
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
                    self.state = OutputParseState::ParsingOutput;
                }
                OutputParseState::ParsingOutput => {
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

                    self.state = OutputParseState::ProcessOutputScript {
                        size: script_size,
                        remaining_size: script_size,
                    };
                }

                OutputParseState::ProcessOutputScript {
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
                        self.state = OutputParseState::ProcessOutputScript {
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

                    if let output @ (CheckDispOutput::Change | CheckDispOutput::Displayable) =
                        check_output_displayable(
                            &script.0.0,
                            self.current_output_amount,
                            &ctx.tx_info.change_pk_hash,
                        )
                    {
                        let is_change = output == CheckDispOutput::Change;

                        if is_change && ctx.tx_info.is_change_found {
                            error!("Multiple change outputs detected");
                            return Err(ParserError::from_str("Multiple change outputs detected"));
                        }

                        let address =
                            ok!(Base58Address::from_output_script(&script.0.0)).to_string();
                        debug!("address_string: {}", &address);

                        ctx.tx_info.outputs.push(TxOutput {
                            amount: self.current_output_amount,
                            address,
                            is_change,
                        });

                        if is_change {
                            ctx.tx_info.is_change_found = true;
                        }
                    }

                    self.output_parsed_count = self.output_parsed_count.saturating_add(1);

                    if self.output_count == self.output_parsed_count {
                        info!("All outputs parsed");

                        let fees = ok!(ctx
                            .tx_info
                            .total_amount
                            .checked_sub(self.total_output_amount)
                            .ok_or(AppSW::IncorrectData)
                            .inspect_err(|_| error!("Failed to calculate fees")));

                        if let Some(swap_params) = ctx.swap_params {
                            ok!(swap::check_swap_params(
                                swap_params,
                                &ctx.tx_info.outputs,
                                fees
                            ));
                        } else {
                            if !ok!(ui_display_tx(&ctx.tx_info.outputs, fees)) {
                                return Err(ParserError::user());
                            }
                            info!("All outputs reviewed");
                        }

                        ok!(ctx
                            .hashers
                            .outputs_hasher
                            .finalize(&mut ctx.tx_info.outputs_hash));

                        info!("Outputs hash: {}", HexSlice(&ctx.tx_info.outputs_hash));

                        self.state = OutputParseState::OutputProcessingDone;
                    } else {
                        self.state = OutputParseState::ParsingOutput;
                    }
                }

                OutputParseState::OutputProcessingDone => {
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
