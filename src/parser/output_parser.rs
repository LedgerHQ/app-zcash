use ::orchard::bundle::commitments::{
    ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
    ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
};
use alloc::format;
use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
use zcash_protocol::consensus::NetworkType;

use crate::parser::orchard::{
    ORCHARD_ACTIONS_COMPACT_SIZE, ORCHARD_ACTIONS_NONCOMPACT_SIZE, ORCHARD_BALANCE_SIZE,
    ORCHARD_DIGEST_DATA_SIZE, ORCHARD_MEMO_SIZE,
};
use crate::parser::orchard_decipher::{
    DecipheredOrchardOutput, ORCHARD_ENC_CIPHERTEXT_SIZE, ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE,
    ORCHARD_OUT_CIPHERTEXT_SIZE, OrchardActionCiphertext, OrchardCompactAction,
    decipher_compact_value, decipher_value_with_ovk,
};
use crate::parser::personalization::ZCASH_OUTPUTS_HASH_PERSONALIZATION;

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
    ParsingShieldedCounts,
    ParsingOrchardCompact,
    ParsingOrchardMemo { size: usize, remaining_size: usize },
    ParsingOrchardNonCompact,
    ParsingOrchardDigestData,
    OutputProcessingDone,
}

#[derive(Clone)]
struct PendingOrchardAction {
    compact: OrchardCompactAction,
    memo: [u8; ORCHARD_MEMO_SIZE],
}

pub struct OutputParser {
    state: OutputParseState,
    output_count: usize,
    pub total_output_amount: u64,
    output_parsed_count: usize,
    current_output_amount: u64,
    orchard_value_balance: i64,
    orchard_action_count: usize,
    orchard_action_parsed_count: usize,
    orchard_actions: Vec<PendingOrchardAction>,
    orchard_decrypted_output_count: usize,
    script_bytes: Vec<u8>,
}

impl OutputParser {
    pub fn new() -> Self {
        OutputParser {
            state: OutputParseState::ParsingNumberOfOutputs,
            output_count: 0,
            total_output_amount: 0,
            output_parsed_count: 0,
            current_output_amount: 0,
            orchard_value_balance: 0,
            orchard_action_count: 0,
            orchard_action_parsed_count: 0,
            orchard_actions: Vec::new(),
            orchard_decrypted_output_count: 0,
            script_bytes: Vec::new(),
        }
    }

    pub fn transparent_output_count(&self) -> usize {
        self.output_count
    }

    pub fn is_finished(&self) -> bool {
        self.state == OutputParseState::OutputProcessingDone
    }

    fn finalize_outputs_review(
        &mut self,
        ctx: &mut OutputParserCtx<'_>,
    ) -> Result<(), ParserError> {
        if self.orchard_decrypted_output_count == 0 && ctx.tx_info.outputs.is_empty() {
            return Err(ParserError::from_str(
                "No outputs to display (no transparent outputs, and no Orchard outputs could be decrypted)",
            ));
        }

        let fees_i128 = i128::from(ctx.tx_info.total_amount)
            + i128::from(self.orchard_value_balance)
            - i128::from(self.total_output_amount);

        if fees_i128 < 0 {
            error!(
                "Failed to calculate fees: total_amount={}, orchard_balance={}, total_output_amount={}",
                ctx.tx_info.total_amount, self.orchard_value_balance, self.total_output_amount
            );
            return Err(ParserError::from_str("Failed to calculate fees"));
        }

        let fees = u64::try_from(fees_i128)
            .map_err(|_| ParserError::from_str("Fee value out of range"))?;

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

        Ok(())
    }

    fn parse_orchard_compact_action(&mut self, bytes: &[u8]) -> Result<(), ParserError> {
        if bytes.len() != ORCHARD_ACTIONS_COMPACT_SIZE {
            return Err(ParserError::from_str("Bad orchard compact action size"));
        }

        let mut nullifier = [0u8; HASH_SIZE];
        let mut cmx = [0u8; HASH_SIZE];
        let mut ephemeral_key = [0u8; HASH_SIZE];
        let mut enc_ciphertext_prefix = [0u8; ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE];

        nullifier.copy_from_slice(&bytes[..HASH_SIZE]);
        cmx.copy_from_slice(&bytes[HASH_SIZE..HASH_SIZE * 2]);
        ephemeral_key.copy_from_slice(&bytes[HASH_SIZE * 2..HASH_SIZE * 3]);
        enc_ciphertext_prefix.copy_from_slice(
            &bytes[HASH_SIZE * 3..HASH_SIZE * 3 + ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE],
        );

        self.orchard_actions.push(PendingOrchardAction {
            compact: OrchardCompactAction {
                nullifier,
                cmx,
                ephemeral_key,
                enc_ciphertext_prefix,
            },
            memo: [0u8; ORCHARD_MEMO_SIZE],
        });

        Ok(())
    }

    fn store_orchard_memo_chunk(
        &mut self,
        mut offset: usize,
        mut bytes: &[u8],
    ) -> Result<(), ParserError> {
        while !bytes.is_empty() {
            let action_index = offset / ORCHARD_MEMO_SIZE;
            let action_offset = offset % ORCHARD_MEMO_SIZE;

            let action = self
                .orchard_actions
                .get_mut(action_index)
                .ok_or_else(|| ParserError::from_str("Bad orchard memo action index"))?;

            let to_copy = core::cmp::min(bytes.len(), ORCHARD_MEMO_SIZE - action_offset);
            action.memo[action_offset..action_offset + to_copy].copy_from_slice(&bytes[..to_copy]);
            offset += to_copy;
            bytes = &bytes[to_copy..];
        }

        Ok(())
    }

    fn push_deciphered_orchard_output(
        &mut self,
        ctx: &mut OutputParserCtx<'_>,
        output: DecipheredOrchardOutput,
        network: NetworkType,
        is_change: bool,
    ) -> Result<(), ParserError> {
        if is_change && ctx.tx_info.is_change_found {
            error!("Multiple change outputs detected");
            return Err(ParserError::from_str("Multiple change outputs detected"));
        }

        let address =
            UnifiedAddress::try_from_items(alloc::vec![Receiver::Orchard(output.raw_address,)])
                .map(|address| address.encode(&network))
                .unwrap_or_else(|_| format!("orchard:{}", HexSlice(&output.raw_address)));

        ctx.tx_info.outputs.push(TxOutput {
            amount: output.value,
            address,
            is_change,
        });

        if is_change {
            ctx.tx_info.is_change_found = true;
        }

        self.orchard_decrypted_output_count = self.orchard_decrypted_output_count.saturating_add(1);
        Ok(())
    }

    fn parse_orchard_noncompact_action(
        &mut self,
        ctx: &mut OutputParserCtx<'_>,
        bytes: &[u8],
    ) -> Result<(), ParserError> {
        if bytes.len() != ORCHARD_ACTIONS_NONCOMPACT_SIZE {
            return Err(ParserError::from_str("Bad orchard non-compact action size"));
        }

        let Some(pending) = self
            .orchard_actions
            .get(self.orchard_action_parsed_count)
            .cloned()
        else {
            return Err(ParserError::from_str("Bad orchard action index"));
        };

        let Some(keys) = ctx.tx_info.orchard_decipher_keys.as_ref() else {
            debug!("No orchard decipher keys available");
            return Ok(());
        };
        let network = keys.network;

        match decipher_compact_value(&keys.internal_ivk, &pending.compact) {
            Ok(Some(output)) => {
                self.push_deciphered_orchard_output(ctx, output, network, true)?;
                return Ok(());
            }
            Ok(None) => debug!("Orchard internal IVK decryption did not match this action"),
            Err(err) => debug!("Orchard compact decryption failed: {:?}", err),
        }

        let mut cv_net = [0u8; HASH_SIZE];
        let mut rk = [0u8; HASH_SIZE];
        let mut out_ciphertext = [0u8; ORCHARD_OUT_CIPHERTEXT_SIZE];

        cv_net.copy_from_slice(&bytes[..HASH_SIZE]);
        rk.copy_from_slice(&bytes[HASH_SIZE..HASH_SIZE * 2]);
        out_ciphertext.copy_from_slice(
            &bytes[HASH_SIZE * 2 + 16..HASH_SIZE * 2 + 16 + ORCHARD_OUT_CIPHERTEXT_SIZE],
        );

        let mut enc_ciphertext = Vec::with_capacity(ORCHARD_ENC_CIPHERTEXT_SIZE);
        enc_ciphertext.extend_from_slice(&pending.compact.enc_ciphertext_prefix);
        enc_ciphertext.extend_from_slice(&pending.memo);
        enc_ciphertext.extend_from_slice(&bytes[HASH_SIZE * 2..HASH_SIZE * 2 + 16]);

        let action = OrchardActionCiphertext {
            compact: pending.compact,
            rk,
            cv_net,
            enc_ciphertext: &enc_ciphertext,
            out_ciphertext,
        };

        match decipher_value_with_ovk(&keys.external_ovk, &action) {
            Ok(Some(output)) => {
                self.push_deciphered_orchard_output(ctx, output, network, false)?;
                return Ok(());
            }
            Ok(None) => debug!("Orchard external OVK recovery did not match this action"),
            Err(err) => debug!("Orchard OVK recovery failed: {:?}", err),
        }

        Ok(())
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
                    self.orchard_value_balance = 0;
                    self.orchard_action_count = 0;
                    self.orchard_action_parsed_count = 0;
                    self.orchard_actions.clear();
                    self.orchard_decrypted_output_count = 0;
                    self.state = if output_count == 0 {
                        if reader.remaining_len() == 0 {
                            self.finalize_outputs_review(ctx)?;
                            OutputParseState::OutputProcessingDone
                        } else {
                            OutputParseState::ParsingShieldedCounts
                        }
                    } else {
                        OutputParseState::ParsingOutput
                    };
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

                        self.state = if reader.remaining_len() == 0 {
                            self.finalize_outputs_review(ctx)?;
                            OutputParseState::OutputProcessingDone
                        } else {
                            OutputParseState::ParsingShieldedCounts
                        };
                    } else {
                        self.state = OutputParseState::ParsingOutput;
                    }
                }

                OutputParseState::ParsingShieldedCounts => {
                    let sapling_spends: usize = ok!(CompactSize::read_t(&mut reader));
                    let sapling_outputs: usize = ok!(CompactSize::read_t(&mut reader));
                    let orchard_actions: usize = ok!(CompactSize::read_t(&mut reader));

                    info!(
                        "Shielded counts: sapling_spends={}, sapling_outputs={}, orchard_actions={}",
                        sapling_spends, sapling_outputs, orchard_actions
                    );

                    if sapling_spends != 0 || sapling_outputs != 0 {
                        return Err(ParserError::from_str(
                            "Sapling shielded data is not supported in sign flow",
                        ));
                    }

                    self.orchard_action_count = orchard_actions;
                    self.orchard_action_parsed_count = 0;
                    self.orchard_actions.clear();
                    self.orchard_decrypted_output_count = 0;

                    if orchard_actions == 0 {
                        self.finalize_outputs_review(ctx)?;
                        self.state = OutputParseState::OutputProcessingDone;
                    } else {
                        ok!(ctx
                            .hashers
                            .tx_compact_hasher
                            .init_with_perso(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION));
                        self.state = OutputParseState::ParsingOrchardCompact;
                    }
                }

                OutputParseState::ParsingOrchardCompact => {
                    if reader.remaining_len() < ORCHARD_ACTIONS_COMPACT_SIZE {
                        return Err(ParserError::from_str(
                            "Not enough data for orchard compact output",
                        ));
                    }

                    let bytes = &reader.remaining_slice()[..ORCHARD_ACTIONS_COMPACT_SIZE];
                    ok!(ctx.hashers.tx_compact_hasher.update(bytes));
                    self.parse_orchard_compact_action(bytes)?;
                    ok!(reader.advance(ORCHARD_ACTIONS_COMPACT_SIZE));

                    self.orchard_action_parsed_count += 1;

                    if self.orchard_action_parsed_count == self.orchard_action_count {
                        ok!(ctx
                            .hashers
                            .tx_memo_hasher
                            .init_with_perso(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION));
                        self.state = OutputParseState::ParsingOrchardMemo {
                            size: self.orchard_action_count * ORCHARD_MEMO_SIZE,
                            remaining_size: self.orchard_action_count * ORCHARD_MEMO_SIZE,
                        };
                    }
                }

                OutputParseState::ParsingOrchardMemo {
                    size,
                    remaining_size,
                } => {
                    let memo_size = *size;
                    let memo_remaining_size = *remaining_size;
                    let to_read = core::cmp::min(memo_remaining_size, reader.remaining_len());
                    let memo_offset = memo_size - memo_remaining_size;
                    let bytes = &reader.remaining_slice()[..to_read];
                    ok!(ctx.hashers.tx_memo_hasher.update(bytes));
                    self.store_orchard_memo_chunk(memo_offset, bytes)?;
                    ok!(reader.advance(to_read));
                    let new_remaining_size = memo_remaining_size.saturating_sub(to_read);

                    if new_remaining_size == 0 {
                        ok!(ctx.hashers.tx_non_compact_hasher.init_with_perso(
                            ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION
                        ));
                        self.orchard_action_parsed_count = 0;
                        self.state = OutputParseState::ParsingOrchardNonCompact;
                    } else {
                        self.state = OutputParseState::ParsingOrchardMemo {
                            size: memo_size,
                            remaining_size: new_remaining_size,
                        };
                    }
                }

                OutputParseState::ParsingOrchardNonCompact => {
                    if reader.remaining_len() < ORCHARD_ACTIONS_NONCOMPACT_SIZE {
                        return Err(ParserError::from_str(
                            "Not enough data for orchard non-compact output",
                        ));
                    }

                    let bytes = &reader.remaining_slice()[..ORCHARD_ACTIONS_NONCOMPACT_SIZE];
                    ok!(ctx.hashers.tx_non_compact_hasher.update(bytes));
                    self.parse_orchard_noncompact_action(ctx, bytes)?;
                    ok!(reader.advance(ORCHARD_ACTIONS_NONCOMPACT_SIZE));

                    self.orchard_action_parsed_count += 1;

                    if self.orchard_action_parsed_count == self.orchard_action_count {
                        self.state = OutputParseState::ParsingOrchardDigestData;
                    }
                }

                OutputParseState::ParsingOrchardDigestData => {
                    let orchard_compact_digest = finalize_and_log_hash(
                        &mut ctx.hashers.tx_compact_hasher,
                        "Orchard compact digest",
                    )?;
                    let orchard_memo_digest = finalize_and_log_hash(
                        &mut ctx.hashers.tx_memo_hasher,
                        "Orchard memo digest",
                    )?;
                    let orchard_non_compact_digest = finalize_and_log_hash(
                        &mut ctx.hashers.tx_non_compact_hasher,
                        "Orchard non compact digest",
                    )?;

                    ok!(ctx.hashers.orchard_hasher.update(&orchard_compact_digest));
                    ok!(ctx.hashers.orchard_hasher.update(&orchard_memo_digest));
                    ok!(ctx
                        .hashers
                        .orchard_hasher
                        .update(&orchard_non_compact_digest));

                    let mut digest_data = [0u8; ORCHARD_DIGEST_DATA_SIZE];
                    ok!(reader.read_exact(&mut digest_data));
                    self.orchard_value_balance = i64::from_le_bytes(
                        digest_data[1..1 + ORCHARD_BALANCE_SIZE].try_into().unwrap(),
                    );
                    ok!(ctx.hashers.orchard_hasher.update(&digest_data));

                    ok!(ctx
                        .hashers
                        .orchard_hasher
                        .finalize(&mut ctx.tx_info.orchard_digest));

                    info!("Orchard digest: {}", HexSlice(&ctx.tx_info.orchard_digest));
                    info!("Orchard value balance: {}", self.orchard_value_balance);

                    self.finalize_outputs_review(ctx)?;

                    self.state = OutputParseState::OutputProcessingDone;
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
