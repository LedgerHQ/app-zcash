use super::*;

#[derive(Debug, Clone, Copy)]
enum TransparentScriptKind {
    Input,
    Output,
}

impl PcztParser {
    pub(super) fn parse_transparent_inputs_start(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT transparent inputs start");

        let input_count: usize = ok!(CompactSize::read_t(&mut *reader));
        if input_count > MAX_PCZT_TRANSPARENT_INPUTS_NUMBER {
            return Err(ParserError::from_str("Too many PCZT transparent inputs"));
        }

        debug!("PCZT transparent input count: {}", input_count);

        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected PCZT transparent input data after input count",
            ));
        }

        self.transparent_input_count = input_count;
        self.transparent_input_parsed_count = 0;
        self.transparent_inputs.clear();

        // Reserved before the per-input allocations begin, for the reason the shielded bundles
        // reserve theirs: growing by doubling mid-parse asks for a contiguous block twice the size
        // of the one it replaces, at the point the parse has fragmented the heap most. It also makes
        // a count the device cannot hold a status word here rather than an allocator panic, which
        // exits the application instead of reporting anything.
        self.transparent_inputs
            .try_reserve_exact(input_count)
            .map_err(|_| ParserError::from_sw(AppSW::NotEnoughMemorySpace))?;
        self.current_input_script_pubkey.clear();
        self.outputs_reviewed = false;
        self.pczt_finished = false;
        self.reset_orchard_bundle_state(0);
        ctx.tx_state.total_input_count = input_count;

        if input_count == 0 {
            self.finalize_transparent_inputs(ctx)?;
        } else {
            self.state = PcztParserState::WaitTransparentInput;
        }

        Ok(())
    }

    pub(super) fn parse_transparent_outputs_start(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT transparent outputs start");

        let output_count: usize = ok!(CompactSize::read_t(&mut *reader));
        if output_count > MAX_PCZT_TRANSPARENT_OUTPUTS_NUMBER {
            return Err(ParserError::from_str("Too many PCZT transparent outputs"));
        }

        debug!("PCZT transparent output count: {}", output_count);

        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected PCZT transparent output data after output count",
            ));
        }

        self.transparent_output_count = output_count;
        self.transparent_output_parsed_count = 0;
        self.current_output_amount = 0;
        self.total_output_amount = 0;
        self.outputs_reviewed = false;
        self.pczt_finished = false;
        ctx.tx_info.outputs.clear();
        ctx.tx_info.is_change_found = false;

        if output_count == 0 {
            self.finalize_transparent_outputs(ctx)?;
        } else {
            self.state = PcztParserState::WaitTransparentOutput;
        }

        Ok(())
    }

    pub(super) fn parse_transparent_input(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        if self.transparent_input_parsed_count >= self.transparent_input_count {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        if reader.remaining_len() < PREVOUT_SIZE {
            return Err(ParserError::from_str(
                "Not enough PCZT transparent input prevout bytes",
            ));
        }

        self.current_input_prevout
            .copy_from_slice(&reader.remaining_slice()[..PREVOUT_SIZE]);

        let prevout = ok!(OutPoint::read(&mut *reader));
        ok!(prevout.write(ctx.hashers.prevouts_hasher.as_writer()));
        debug!(
            "PCZT transparent input #{} prevout: {:?}",
            self.transparent_input_parsed_count, prevout
        );

        self.current_input_sequence = self.read_optional_u32(reader)?.unwrap_or(DEFAULT_SEQUENCE);
        ok!(ctx
            .hashers
            .sequence_hasher
            .update(&self.current_input_sequence.to_le_bytes()));
        debug!(
            "PCZT transparent input #{} sequence: {:08x}",
            self.transparent_input_parsed_count, self.current_input_sequence
        );

        let amount = ok!({
            ok!(reader.read_exact(&mut self.current_input_amount));
            ok!(ctx
                .hashers
                .amounts_hasher
                .update(&self.current_input_amount));
            Zatoshis::from_nonnegative_i64_le_bytes(self.current_input_amount)
        });
        ctx.tx_info.total_amount = ctx.tx_info.total_amount.saturating_add(amount.into_u64());
        debug!(
            "PCZT transparent input #{} amount: {}",
            self.transparent_input_parsed_count,
            amount.into_u64()
        );

        self.state = PcztParserState::WaitTransparentInputScript;
        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "PCZT transparent input scriptPubKey must start in a separate APDU",
            ));
        }

        Ok(())
    }

    pub(super) fn parse_transparent_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        if self.transparent_output_parsed_count >= self.transparent_output_count {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        let amount = ok!({
            let mut amount_bytes = [0u8; 8];
            ok!(reader.read_exact(&mut amount_bytes));
            ok!(ctx.hashers.outputs_hasher.update(&amount_bytes));
            Zatoshis::from_nonnegative_i64_le_bytes(amount_bytes)
        });

        self.current_output_amount = amount.into_u64();
        self.total_output_amount = self
            .total_output_amount
            .saturating_add(self.current_output_amount);

        debug!(
            "PCZT transparent output #{} amount: {}",
            self.transparent_output_parsed_count, self.current_output_amount
        );

        self.state = PcztParserState::WaitTransparentOutputScript;
        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "PCZT transparent output scriptPubKey must start in a separate APDU",
            ));
        }

        Ok(())
    }

    pub(super) fn parse_transparent_input_script_start(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        self.parse_transparent_script_start(ctx, reader, TransparentScriptKind::Input)
    }

    pub(super) fn parse_transparent_input_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        self.parse_transparent_script(
            ctx,
            reader,
            TransparentScriptKind::Input,
            size,
            remaining_size,
        )
    }

    fn parse_transparent_script_start(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        kind: TransparentScriptKind,
    ) -> Result<(), ParserError> {
        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));
        if script_size > MAX_PCZT_SCRIPT_SIZE {
            return Err(ParserError::from_str("Bad PCZT transparent script size"));
        }

        debug!(
            "PCZT transparent {:?} #{} scriptPubKey size: {}",
            kind,
            self.transparent_script_index(kind),
            script_size
        );

        self.script_bytes.clear();
        self.script_bytes.resize(script_size, 0);

        if script_size == 0 {
            self.finish_transparent_script(ctx, kind, script_size)?;
            if reader.remaining_len() != 0 {
                return Err(ParserError::from_str(
                    "Unexpected data after empty PCZT transparent scriptPubKey",
                ));
            }
            return Ok(());
        }

        if reader.remaining_len() == 0 {
            return Err(ParserError::from_str(
                "Missing PCZT transparent scriptPubKey bytes",
            ));
        }

        self.set_transparent_script_process_state(kind, script_size, script_size);
        self.parse_transparent_script(ctx, reader, kind, script_size, script_size)
    }

    fn parse_transparent_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        kind: TransparentScriptKind,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        let offset = size - remaining_size;
        let len = ok!(reader.read(&mut self.script_bytes[offset..][..remaining_size]));
        let new_remaining_size = remaining_size.saturating_sub(len);

        if new_remaining_size != 0 {
            self.set_transparent_script_process_state(kind, size, new_remaining_size);
            debug!(
                "Need more PCZT transparent {:?} script bytes, remaining size: {}",
                kind, new_remaining_size,
            );
            return Ok(());
        }

        self.finish_transparent_script(ctx, kind, size)?;

        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected data after PCZT transparent scriptPubKey",
            ));
        }

        Ok(())
    }

    fn transparent_script_index(&self, kind: TransparentScriptKind) -> usize {
        match kind {
            TransparentScriptKind::Input => self.transparent_input_parsed_count,
            TransparentScriptKind::Output => self.transparent_output_parsed_count,
        }
    }

    fn set_transparent_script_process_state(
        &mut self,
        kind: TransparentScriptKind,
        size: usize,
        remaining_size: usize,
    ) {
        self.state = match kind {
            TransparentScriptKind::Input => PcztParserState::ProcessTransparentInputScript {
                size,
                remaining_size,
            },
            TransparentScriptKind::Output => PcztParserState::ProcessTransparentOutputScript {
                size,
                remaining_size,
            },
        };
    }

    fn finish_transparent_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        kind: TransparentScriptKind,
        size: usize,
    ) -> Result<(), ParserError> {
        match kind {
            TransparentScriptKind::Input => self.finish_transparent_input_script(ctx, size),
            TransparentScriptKind::Output => self.finish_transparent_output_script(ctx, size),
        }
    }

    pub(super) fn parse_transparent_input_sighash_type(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let sighash_type = ok!(reader.read_u8());
        if sighash_type != SIGHASH_ALL {
            return Err(ParserError::from_str(
                "Unsupported PCZT transparent sighash type",
            ));
        }

        debug!(
            "PCZT transparent input #{} sighash_type: {:02x}",
            self.transparent_input_parsed_count, sighash_type
        );

        self.state = PcztParserState::WaitTransparentInputBip32Derivation;
        if reader.remaining_len() == 0 {
            return Err(ParserError::from_str(
                "Missing PCZT transparent input bip32 derivation",
            ));
        }

        Ok(())
    }

    pub(super) fn parse_transparent_input_bip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let derivation_count: usize = ok!(CompactSize::read_t(&mut *reader));
        if derivation_count != 1 {
            return Err(ParserError::from_str(
                "Expected exactly one PCZT input bip32 derivation",
            ));
        }

        debug!(
            "PCZT transparent input #{} bip32 derivation count: {}",
            self.transparent_input_parsed_count, derivation_count
        );

        let derivation_len = {
            let derivation = reader.remaining_slice();
            if derivation.is_empty() {
                return Err(ParserError::from_str(
                    "Missing PCZT transparent input bip32 derivation bytes",
                ));
            }

            let derivation_len = derivation.len();
            self.finish_transparent_input_bip32_derivation(ctx, derivation)?;
            derivation_len
        };
        ok!(reader.advance(derivation_len));

        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected data after PCZT transparent input bip32 derivation",
            ));
        }

        Ok(())
    }

    fn finish_transparent_input_bip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        derivation: &[u8],
    ) -> Result<(), ParserError> {
        let path = Bip32Path::try_from(
            derivation
                .get(ZIP32_DERIVATION_PATH_COUNT_OFFSET..)
                .unwrap_or(&[]),
        )
        .map_err(|_| ParserError::from_str("Bad PCZT input bip32 derivation path"))?;
        let pubkey = &derivation[..COMPRESSED_PUBKEY_SIZE];
        let _seed_fingerprint =
            &derivation[COMPRESSED_PUBKEY_SIZE..ZIP32_DERIVATION_PATH_COUNT_OFFSET];

        if !check_bip44_compliance(&path, Bip44CheckMode::OnlyCoinType) {
            return Err(ParserError::from_str(
                "PCZT transparent signing path not compliant",
            ));
        }

        debug!(
            "PCZT transparent input #{} bip32 derivation pubkey: {}",
            self.transparent_input_parsed_count,
            HexSlice(pubkey)
        );
        debug!(
            "PCZT transparent input #{} seed fingerprint: {}",
            self.transparent_input_parsed_count,
            HexSlice(_seed_fingerprint)
        );
        debug!(
            "PCZT transparent input #{} signing path: {:?}",
            self.transparent_input_parsed_count, path
        );

        self.transparent_inputs.push(PcztTransparentInputRecord {
            prevout: self.current_input_prevout,
            sequence: self.current_input_sequence,
            amount: self.current_input_amount,
            script_pubkey: mem::take(&mut self.current_input_script_pubkey),
            path,
            signed: false,
        });

        self.transparent_input_parsed_count = self.transparent_input_parsed_count.saturating_add(1);

        if self.transparent_input_count == self.transparent_input_parsed_count {
            self.finalize_transparent_inputs(ctx)?;
        } else {
            self.state = PcztParserState::WaitTransparentInput;
        }

        Ok(())
    }

    pub(super) fn parse_transparent_output_script_start(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        // Change detection is established per-output by that output's own change
        // bip32_derivation. Clear any hash carried over from a previous output so an
        // output without its own derivation can never be matched against a stale
        // change hash and silently classified as change (and hidden from the user).
        ctx.tx_info.change_pk_hash = None;

        self.parse_transparent_script_start(ctx, reader, TransparentScriptKind::Output)
    }

    pub(super) fn parse_transparent_output_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        self.parse_transparent_script(
            ctx,
            reader,
            TransparentScriptKind::Output,
            size,
            remaining_size,
        )
    }

    fn finish_transparent_input_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        size: usize,
    ) -> Result<(), ParserError> {
        if size != self.script_bytes.len() {
            return Err(ParserError::from_str(
                "Bad PCZT transparent input script length",
            ));
        }

        let script_bytes = mem::take(&mut self.script_bytes);

        // An input is spent by a signature over its own scriptPubKey, and the only key this app
        // derives on the transparent tree pays to a P2PKH hash. Any other shape is one it cannot
        // produce a valid signature for — a P2SH input would need a redeem script the wire format
        // does not carry — so accepting it would sign something unspendable.
        //
        // Refusing here is also what keeps the input bound affordable: the script is retained for
        // the whole session, because the per-input signature digest consumes it. Pinned to the
        // 25-byte P2PKH shape, the retained cost per input is fixed; left at MAX_PCZT_SCRIPT_SIZE it
        // is ten times that, and the bound has to shrink to pay for a shape no account can spend.
        if !output_script_is_regular(&script_bytes) {
            error!("PCZT transparent input scriptPubKey is not P2PKH");
            return Err(ParserError::from_sw(AppSW::IncorrectData));
        }

        write_transparent_script(ctx.hashers.scripts_hasher.as_writer(), &script_bytes)?;
        debug!(
            "PCZT transparent input #{} scriptPubKey: {}",
            self.transparent_input_parsed_count,
            HexSlice(&script_bytes)
        );

        self.current_input_script_pubkey = script_bytes;
        self.state = PcztParserState::WaitTransparentInputSighashType;

        Ok(())
    }

    pub fn compute_transparent_signature_digest(
        &mut self,
        tx_info: &mut TxInfo,
        input_index: usize,
    ) -> Result<u8, ParserError> {
        if !self.is_finished() {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        let input = self
            .transparent_inputs
            .get(input_index)
            .ok_or_else(|| ParserError::from_str("Bad PCZT transparent input index"))?;

        let txin_sig_digest = transparent_input_txin_signature_digest(
            &input.prevout,
            &input.amount,
            &input.script_pubkey,
            input.sequence,
        )?;
        debug!(
            "PCZT transparent input #{} txin sig digest: {}",
            input_index,
            HexSlice(&txin_sig_digest)
        );

        compute_transparent_input_signature_digest(tx_info, &txin_sig_digest, SIGHASH_ALL)?;

        Ok(SIGHASH_ALL)
    }

    pub fn use_transparent_signature_digest(
        &mut self,
        tx_info: &mut TxInfo,
        input_index: usize,
    ) -> Result<u8, ParserError> {
        let sighash_type = self.compute_transparent_signature_digest(tx_info, input_index)?;

        debug!(
            "Computed PCZT transparent input #{} signature digest for signing: {}",
            input_index,
            HexSlice(&tx_info.signature_digest)
        );

        Ok(sighash_type)
    }

    pub fn transparent_input_signing_path(
        &self,
        input_index: usize,
    ) -> Result<&Bip32Path, ParserError> {
        if !self.is_ready_to_sign() {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        self.transparent_inputs
            .get(input_index)
            .map(|input| &input.path)
            .ok_or_else(|| ParserError::from_str("Bad PCZT transparent input index"))
    }

    pub fn mark_transparent_input_signed(&mut self, input_index: usize) -> Result<(), ParserError> {
        let input = self
            .transparent_inputs
            .get_mut(input_index)
            .ok_or_else(|| ParserError::from_str("Bad PCZT transparent input index"))?;

        if input.signed {
            return Err(ParserError::from_str(
                "PCZT transparent input already signed",
            ));
        }

        input.signed = true;

        Ok(())
    }

    fn finish_transparent_output_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        size: usize,
    ) -> Result<(), ParserError> {
        if size != self.script_bytes.len() {
            return Err(ParserError::from_str(
                "Bad PCZT transparent output script length",
            ));
        }

        write_transparent_script(ctx.hashers.outputs_hasher.as_writer(), &self.script_bytes)?;
        debug!(
            "PCZT transparent output #{} scriptPubKey: {}",
            self.transparent_output_parsed_count,
            HexSlice(&self.script_bytes)
        );

        self.state = PcztParserState::WaitTransparentOutputBip32Derivation;

        Ok(())
    }

    pub(super) fn parse_transparent_output_bip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let derivation_count: usize = ok!(CompactSize::read_t(&mut *reader));
        if derivation_count > 1 {
            return Err(ParserError::from_str(
                "Expected at most one PCZT output bip32 derivation",
            ));
        }

        debug!(
            "PCZT transparent output #{} bip32 derivation count: {}",
            self.transparent_output_parsed_count, derivation_count
        );

        if derivation_count == 0 {
            if reader.remaining_len() != 0 {
                return Err(ParserError::from_str(
                    "Unexpected data after empty PCZT output bip32 derivation",
                ));
            }

            return self.finish_transparent_output(ctx);
        }

        let derivation_len = {
            let derivation = reader.remaining_slice();
            if derivation.is_empty() {
                return Err(ParserError::from_str(
                    "Missing PCZT transparent output bip32 derivation bytes",
                ));
            }

            let derivation_len = derivation.len();
            self.finish_transparent_output_bip32_derivation(ctx, derivation)?;
            derivation_len
        };
        ok!(reader.advance(derivation_len));

        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected data after PCZT transparent output bip32 derivation",
            ));
        }

        Ok(())
    }

    fn finish_transparent_output_bip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        derivation: &[u8],
    ) -> Result<(), ParserError> {
        let path = Bip32Path::try_from(
            derivation
                .get(ZIP32_DERIVATION_PATH_COUNT_OFFSET..)
                .unwrap_or(&[]),
        )
        .map_err(|_| ParserError::from_str("Bad PCZT output bip32 derivation path"))?;
        let pubkey = &derivation[..COMPRESSED_PUBKEY_SIZE];
        let _seed_fingerprint =
            &derivation[COMPRESSED_PUBKEY_SIZE..ZIP32_DERIVATION_PATH_COUNT_OFFSET];
        if !check_bip44_compliance(
            &path,
            Bip44CheckMode::Full {
                is_change_path: true,
            },
        ) {
            return Err(ParserError::from_str(
                "PCZT output change path not compliant",
            ));
        }

        let expected_public_key =
            ok!(ok!(ExtendedPublicKey::try_from(&path)).compressed_public_key());
        if pubkey != expected_public_key.as_slice() {
            return Err(ParserError::from_str(
                "PCZT output bip32 derivation pubkey mismatch",
            ));
        }

        let change_pk_hash: [u8; 20] = ok!(pubkey.hash160());
        ctx.tx_info.change_pk_hash = Some(change_pk_hash);

        // Kept for the signing step, which is where it meets the account actually being spent. Two
        // change outputs naming different accounts are refused outright: whichever one the signing
        // check then matched, the other would still be hidden from the review.
        let change_account = derivation_account(&path);
        match ctx.tx_info.change_account {
            Some(previous) if Some(previous) != change_account => {
                return Err(ParserError::from_str(
                    "PCZT change outputs declare different accounts",
                ));
            }
            _ => ctx.tx_info.change_account = change_account,
        }

        debug!(
            "PCZT transparent output #{} bip32 derivation pubkey: {}",
            self.transparent_output_parsed_count,
            HexSlice(pubkey)
        );
        debug!(
            "PCZT transparent output #{} change path: {:?}",
            self.transparent_output_parsed_count, path
        );
        debug!(
            "PCZT transparent output #{} change pk hash: {}",
            self.transparent_output_parsed_count,
            HexSlice(&change_pk_hash)
        );

        self.finish_transparent_output(ctx)
    }

    fn finish_transparent_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        match check_output_displayable(
            &self.script_bytes,
            self.current_output_amount,
            ctx.tx_info.change_pk_hash.as_ref(),
        ) {
            output @ (CheckDispOutput::Change | CheckDispOutput::Displayable) => {
                let is_change = output == CheckDispOutput::Change;

                if is_change && ctx.tx_info.is_change_found {
                    return Err(ParserError::from_str("Multiple change outputs detected"));
                }

                let address =
                    ok!(Base58Address::from_output_script(&self.script_bytes)).to_string();
                debug!("PCZT transparent output address: {}", &address);

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

        self.transparent_output_parsed_count =
            self.transparent_output_parsed_count.saturating_add(1);
        self.script_bytes.clear();

        if self.transparent_output_count == self.transparent_output_parsed_count {
            self.finalize_transparent_outputs(ctx)?;
        } else {
            self.state = PcztParserState::WaitTransparentOutput;
        }

        Ok(())
    }

    fn finalize_transparent_inputs(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT transparent inputs hashing done");

        ok!(ctx
            .hashers
            .prevouts_hasher
            .finalize(&mut ctx.tx_info.prevouts_hash));
        debug!(
            "PCZT prevouts hash: {}",
            HexSlice(&ctx.tx_info.prevouts_hash)
        );

        ok!(ctx
            .hashers
            .sequence_hasher
            .finalize(&mut ctx.tx_info.sequence_hash));
        debug!(
            "PCZT sequence hash: {}",
            HexSlice(&ctx.tx_info.sequence_hash)
        );

        ok!(ctx
            .hashers
            .amounts_hasher
            .finalize(&mut ctx.tx_info.amounts_hash));
        debug!("PCZT amounts hash: {}", HexSlice(&ctx.tx_info.amounts_hash));

        ok!(ctx
            .hashers
            .scripts_hasher
            .finalize(&mut ctx.tx_info.scripts_hash));
        debug!("PCZT scripts hash: {}", HexSlice(&ctx.tx_info.scripts_hash));

        self.state = PcztParserState::TransparentInputsDone;

        Ok(())
    }

    fn finalize_transparent_outputs(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT transparent outputs hashing done");

        ok!(ctx
            .hashers
            .outputs_hasher
            .finalize(&mut ctx.tx_info.outputs_hash));
        debug!("PCZT outputs hash: {}", HexSlice(&ctx.tx_info.outputs_hash));

        self.state = PcztParserState::TransparentOutputsDone;

        Ok(())
    }
}
