use super::*;

impl PcztParser {
    pub(super) fn parse_transparent_inputs_start(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT transparent inputs start");

        ok!(ctx.hashers.init_v5_tx_hashers());
        ctx.tx_info.tx_version = Some(TxVersion::V5);
        ctx.tx_info.total_amount = 0;

        self.parse_pczt_header(reader)?;
        self.parse_global(ctx, reader)?;

        let input_count: usize = ok!(CompactSize::read_t(&mut *reader));
        if input_count > MAX_TRANSPARENT_INPUTS_NUMBER {
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
        self.current_input_script_pubkey.clear();
        self.bip32_derivation_bytes.clear();
        self.outputs_reviewed = false;
        self.pczt_finished = false;
        self.orchard_action_count = 0;
        self.orchard_action_parsed_count = 0;
        self.orchard_signing_records.clear();
        self.orchard_signed_action_count = 0;
        self.orchard_value_balance = 0;
        self.orchard_decrypted_output_count = 0;
        self.current_orchard_flags = 0;
        self.current_orchard_value_sum_magnitude = 0;
        self.reset_current_orchard_action();
        self.orchard_field_bytes.clear();
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
        if output_count > MAX_OUTPUTS_NUMBER {
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
        self.orchard_decrypted_output_count = 0;

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
        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));
        if script_size > MAX_SCRIPT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT transparent input script size",
            ));
        }

        debug!(
            "PCZT transparent input #{} scriptPubKey size: {}",
            self.transparent_input_parsed_count, script_size
        );

        self.script_bytes.clear();
        self.script_bytes.resize(script_size, 0);

        if script_size == 0 {
            self.finish_transparent_input_script(ctx, script_size)?;
            if reader.remaining_len() != 0 {
                return Err(ParserError::from_str(
                    "Unexpected data after empty PCZT transparent input scriptPubKey",
                ));
            }
            return Ok(());
        }

        if reader.remaining_len() == 0 {
            return Err(ParserError::from_str(
                "Missing PCZT transparent input scriptPubKey bytes",
            ));
        }

        self.state = PcztParserState::ProcessTransparentInputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.parse_transparent_input_script(ctx, reader, script_size, script_size)
    }

    pub(super) fn parse_transparent_input_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        let offset = size - remaining_size;
        let len = ok!(reader.read(&mut self.script_bytes[offset..][..remaining_size]));
        let new_remaining_size = remaining_size.saturating_sub(len);

        if new_remaining_size != 0 {
            self.state = PcztParserState::ProcessTransparentInputScript {
                size,
                remaining_size: new_remaining_size,
            };
            debug!(
                "Need more PCZT transparent input script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        self.finish_transparent_input_script(ctx, size)?;

        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected data after PCZT transparent input scriptPubKey",
            ));
        }

        Ok(())
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

        self.bip32_derivation_bytes.clear();
        self.state = PcztParserState::ProcessTransparentInputBip32Derivation {
            expected_size: None,
        };
        self.parse_transparent_input_bip32_derivation_bytes(ctx, reader, None)
    }

    pub(super) fn parse_transparent_input_bip32_derivation_bytes(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        mut expected_size: Option<usize>,
    ) -> Result<(), ParserError> {
        loop {
            let (target_size, is_header_target) = if let Some(size) = expected_size {
                (size, false)
            } else {
                match Self::parse_derivation_path_count(
                    &self.bip32_derivation_bytes,
                    ZIP32_DERIVATION_PATH_COUNT_OFFSET,
                    "PCZT input bip32 derivation",
                )? {
                    PathCountParse::NeedMore(size) => (size, true),
                    PathCountParse::Ready {
                        path_count,
                        path_offset,
                    } => {
                        let size = path_offset + path_count * 4;
                        debug!(
                            "PCZT transparent input #{} bip32 derivation path len: {}",
                            self.transparent_input_parsed_count, path_count
                        );
                        (size, false)
                    }
                }
            };

            let missing = target_size.saturating_sub(self.bip32_derivation_bytes.len());

            if missing > 0 {
                let to_read = cmp::min(missing, reader.remaining_len());
                if to_read == 0 {
                    return Err(ParserError::from_str(
                        "Incomplete PCZT transparent input bip32 derivation APDU",
                    ));
                }

                let offset = self.bip32_derivation_bytes.len();
                self.bip32_derivation_bytes.resize(offset + to_read, 0);
                ok!(reader.read_exact(&mut self.bip32_derivation_bytes[offset..]));
            }

            if self.bip32_derivation_bytes.len() == target_size {
                if is_header_target {
                    expected_size = None;
                    continue;
                }

                self.finish_transparent_input_bip32_derivation(ctx)?;

                if reader.remaining_len() != 0 {
                    return Err(ParserError::from_str(
                        "Unexpected data after PCZT transparent input bip32 derivation",
                    ));
                }

                return Ok(());
            }
        }
    }

    fn finish_transparent_input_bip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        let derivation = mem::take(&mut self.bip32_derivation_bytes);
        let pubkey = &derivation[..COMPRESSED_PUBKEY_SIZE];
        let _seed_fingerprint =
            &derivation[COMPRESSED_PUBKEY_SIZE..ZIP32_DERIVATION_PATH_COUNT_OFFSET];
        let (path_count, path_offset) = match Self::parse_derivation_path_count(
            &derivation,
            ZIP32_DERIVATION_PATH_COUNT_OFFSET,
            "Bad PCZT input bip32 derivation path length",
        )? {
            PathCountParse::Ready {
                path_count,
                path_offset,
            } => (path_count, path_offset),
            PathCountParse::NeedMore(_) => {
                return Err(ParserError::from_str(
                    "Incomplete PCZT input bip32 derivation",
                ));
            }
        };

        let mut derivation_path = Vec::new();
        for chunk in derivation[path_offset..path_offset + path_count * 4].chunks_exact(4) {
            derivation_path.push(u32::from_le_bytes(chunk.try_into().unwrap()));
        }

        let path = ok!(Bip32Path::try_from(derivation_path.as_slice()));

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
        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));
        if script_size > MAX_SCRIPT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT transparent output script size",
            ));
        }

        debug!(
            "PCZT transparent output #{} scriptPubKey size: {}",
            self.transparent_output_parsed_count, script_size
        );

        self.script_bytes.clear();
        self.script_bytes.resize(script_size, 0);

        if script_size == 0 {
            self.finish_transparent_output_script(ctx, script_size)?;
            if reader.remaining_len() != 0 {
                return Err(ParserError::from_str(
                    "Unexpected data after empty PCZT transparent output scriptPubKey",
                ));
            }
            return Ok(());
        }

        if reader.remaining_len() == 0 {
            return Err(ParserError::from_str(
                "Missing PCZT transparent output scriptPubKey bytes",
            ));
        }

        self.state = PcztParserState::ProcessTransparentOutputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.parse_transparent_output_script(ctx, reader, script_size, script_size)
    }

    pub(super) fn parse_transparent_output_script(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        let offset = size - remaining_size;
        let len = ok!(reader.read(&mut self.script_bytes[offset..][..remaining_size]));
        let new_remaining_size = remaining_size.saturating_sub(len);

        if new_remaining_size != 0 {
            self.state = PcztParserState::ProcessTransparentOutputScript {
                size,
                remaining_size: new_remaining_size,
            };
            debug!(
                "Need more PCZT transparent output script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        self.finish_transparent_output_script(ctx, size)?;

        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected data after PCZT transparent output scriptPubKey",
            ));
        }

        Ok(())
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
        let mut script_pubkey = Script::default();
        script_pubkey.0.0 = script_bytes.clone();
        ok!(script_pubkey.write(ctx.hashers.scripts_hasher.as_writer()));
        debug!(
            "PCZT transparent input #{} scriptPubKey: {:?}",
            self.transparent_input_parsed_count, script_pubkey
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

        let mut script_pubkey = Script::default();
        script_pubkey.0.0 = input.script_pubkey.clone();
        let txin_sig_digest = transparent_input_txin_signature_digest(
            &input.prevout,
            &input.amount,
            &script_pubkey,
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

        let mut script_pubkey = Script::default();
        script_pubkey.0.0 = self.script_bytes.clone();
        ok!(script_pubkey.write(ctx.hashers.outputs_hasher.as_writer()));
        debug!(
            "PCZT transparent output #{} scriptPubKey: {:?}",
            self.transparent_output_parsed_count, script_pubkey
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

        self.bip32_derivation_bytes.clear();
        self.state = PcztParserState::ProcessTransparentOutputBip32Derivation {
            expected_size: None,
        };
        self.parse_transparent_output_bip32_derivation_bytes(ctx, reader, None)
    }

    pub(super) fn parse_transparent_output_bip32_derivation_bytes(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        mut expected_size: Option<usize>,
    ) -> Result<(), ParserError> {
        loop {
            let (target_size, is_header_target) = if let Some(size) = expected_size {
                (size, false)
            } else {
                match Self::parse_derivation_path_count(
                    &self.bip32_derivation_bytes,
                    ZIP32_DERIVATION_PATH_COUNT_OFFSET,
                    "Bad PCZT output bip32 derivation path length",
                )? {
                    PathCountParse::NeedMore(size) => (size, true),
                    PathCountParse::Ready {
                        path_count,
                        path_offset,
                    } => {
                        let size = path_offset + path_count * 4;
                        debug!(
                            "PCZT transparent output #{} bip32 derivation path len: {}",
                            self.transparent_output_parsed_count, path_count
                        );
                        (size, false)
                    }
                }
            };

            let missing = target_size.saturating_sub(self.bip32_derivation_bytes.len());

            if missing > 0 {
                let to_read = cmp::min(missing, reader.remaining_len());
                if to_read == 0 {
                    return Err(ParserError::from_str(
                        "Incomplete PCZT transparent output bip32 derivation APDU",
                    ));
                }

                let offset = self.bip32_derivation_bytes.len();
                self.bip32_derivation_bytes.resize(offset + to_read, 0);
                ok!(reader.read_exact(&mut self.bip32_derivation_bytes[offset..]));
            }

            if self.bip32_derivation_bytes.len() == target_size {
                if is_header_target {
                    expected_size = None;
                    continue;
                }

                self.finish_transparent_output_bip32_derivation(ctx)?;

                if reader.remaining_len() != 0 {
                    return Err(ParserError::from_str(
                        "Unexpected data after PCZT transparent output bip32 derivation",
                    ));
                }

                return Ok(());
            }
        }
    }

    fn finish_transparent_output_bip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        let derivation = mem::take(&mut self.bip32_derivation_bytes);
        let pubkey = &derivation[..COMPRESSED_PUBKEY_SIZE];
        let _seed_fingerprint =
            &derivation[COMPRESSED_PUBKEY_SIZE..ZIP32_DERIVATION_PATH_COUNT_OFFSET];
        let (path_count, path_offset) = match Self::parse_derivation_path_count(
            &derivation,
            ZIP32_DERIVATION_PATH_COUNT_OFFSET,
            "Bad PCZT output bip32 derivation path length",
        )? {
            PathCountParse::Ready {
                path_count,
                path_offset,
            } => (path_count, path_offset),
            PathCountParse::NeedMore(_) => {
                return Err(ParserError::from_str(
                    "Incomplete PCZT output bip32 derivation",
                ));
            }
        };

        let mut derivation_path = Vec::new();
        for chunk in derivation[path_offset..path_offset + path_count * 4].chunks_exact(4) {
            derivation_path.push(u32::from_le_bytes(chunk.try_into().unwrap()));
        }

        let path = ok!(Bip32Path::try_from(derivation_path.as_slice()));
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

        let public_key_with_cc = ok!(ExtendedPublicKey::try_from(&path));
        ctx.tx_info.change_pk_hash = ok!(public_key_with_cc.compressed_public_key_hash160());

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
            HexSlice(&ctx.tx_info.change_pk_hash)
        );

        self.finish_transparent_output(ctx)
    }

    fn finish_transparent_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        if let output @ (CheckDispOutput::Change | CheckDispOutput::Displayable) =
            check_output_displayable(
                &self.script_bytes,
                self.current_output_amount,
                &ctx.tx_info.change_pk_hash,
            )
        {
            let is_change = output == CheckDispOutput::Change;

            if is_change && ctx.tx_info.is_change_found {
                return Err(ParserError::from_str("Multiple change outputs detected"));
            }

            let address = ok!(Base58Address::from_output_script(&self.script_bytes)).to_string();
            debug!("PCZT transparent output address: {}", &address);

            ctx.tx_info.outputs.push(TxOutput {
                amount: self.current_output_amount,
                address,
                is_change,
            });

            if is_change {
                ctx.tx_info.is_change_found = true;
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
