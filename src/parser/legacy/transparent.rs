use crate::tx::SupportedTxVersion;

use super::*;

impl LegacyParser {
    pub fn parse_input(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let prevout = ok!(OutPoint::read(&mut *reader));

        match ctx.tx_info.tx_version() {
            SupportedTxVersion::V5 => {
                ok!(prevout.write(ctx.hashers.prevouts_hasher.as_writer()));
            }
            #[cfg(feature = "zcash_unstable")]
            SupportedTxVersion::V6 => {
                ok!(prevout.write(ctx.hashers.prevouts_hasher.as_writer()));
            }
            SupportedTxVersion::V4 => {
                ok!(prevout.write(ctx.hashers.v4_tx_hasher.as_writer()));
            }
        }

        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));

        if script_size > MAX_SCRIPT_SIZE {
            return Err(ParserError::from_str("Bad input script size"));
        }

        info!("Previous outpoint: {:?}", prevout);
        info!("Script size: {}", script_size);

        self.state = LegacyParserState::ProcessInputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.script_bytes.clear();
        // Allocate script bytes buffer
        self.script_bytes.extend(iter::repeat_n(0, script_size));

        Ok(())
    }

    pub fn parse_input_signature_mode(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        debug!("Parsing input for signature mode...");

        let trusted_input_mode = TrustedInputMode::read(reader)?;

        let TrustedInputMode::Trusted = trusted_input_mode else {
            error!("Untrusted input mode is not supported for signing");
            return Err(ParserError::from_str(
                "Untrusted input mode is not supported for signing",
            ));
        };

        let trusted_input_len = ok!(reader.read_u8()) as usize;
        if trusted_input_len != TRUSTED_INPUT_TOTAL_SIZE {
            return Err(ParserError::from_str("Invalid trusted input size"));
        }

        if reader.remaining_len() < trusted_input_len {
            return Err(ParserError::from_str("Not enough data for trusted input"));
        }

        let trusted_input = &reader.remaining_slice()[..trusted_input_len];
        let trusted_input_hmac = &trusted_input[trusted_input_len - 8..][..8];
        let mut computed_hmac = [0x00u8; 8];
        let trusted_input_key = Settings
            .trusted_input_key()
            .ok_or_else(|| ParserError::from_str("Trusted input key not set"))?;

        // Compute HMAC-SHA256 signature over the trusted input
        let mut hmac_sha256_signer = HmacSha256::new(trusted_input_key.as_ref());

        ok!(hmac_sha256_signer.update(&trusted_input[0..trusted_input_len - 8]));
        ok!(hmac_sha256_signer.finalize(&mut computed_hmac));

        info!(
            "=====> Computed trusted input HMAC: {}",
            HexSlice(&computed_hmac)
        );
        info!(
            "=====> Provided trusted input HMAC: {}",
            HexSlice(trusted_input_hmac)
        );
        if !secure_memcmp(&computed_hmac, trusted_input_hmac) {
            error!("Trusted input HMAC mismatch");
            return Err(ParserError::from_str("Trusted input HMAC mismatch"));
        }
        info!("HMACs matched");

        // Advance reader position
        ok!({
            let mut _magic = [0u8; 2];
            reader.read_exact(&mut _magic)
        });

        ok!({
            let mut _rand_bytes = [0u8; 2];
            reader.read_exact(&mut _rand_bytes)
        });

        let prevout = ok!(OutPoint::read(&mut *reader));
        info!("Previous outpoint: {:?}", prevout);
        ok!(prevout.write(ctx.hashers.prevouts_hasher.as_writer()));

        let amount = ok!({
            let mut tmp = [0u8; 8];
            ok!(reader.read_exact(&mut tmp));
            // Hash amount
            ok!(ctx.hashers.amounts_hasher.update(&tmp));
            Zatoshis::from_nonnegative_i64_le_bytes(tmp)
        });
        ctx.tx_info.total_amount = ctx.tx_info.total_amount.saturating_add(amount.into_u64());
        info!("Input amount: {:?}", amount);
        info!("New amount: {}", ctx.tx_info.total_amount);

        ok!({
            let mut _hmac = [0u8; 8];
            reader.read_exact(&mut _hmac)
        });

        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));
        info!("Script size: {}", script_size);

        if ctx.tx_state.is_tx_parsed_once {
            ok!(ctx
                .hashers
                .prevouts_hasher
                .update(&amount.to_i64_le_bytes()));
        }

        self.state = LegacyParserState::ProcessInputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.script_bytes.clear();
        // Allocate script bytes buffer
        self.script_bytes.extend(iter::repeat_n(0, script_size));

        Ok(())
    }

    pub fn parse_input_script(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        let new_remaining_size = {
            let offset = size - remaining_size;
            let len = ok!(reader.read(&mut self.script_bytes[offset..][..remaining_size]));

            remaining_size.saturating_sub(len)
        };

        if new_remaining_size != 0 {
            self.state = LegacyParserState::ProcessInputScript {
                size,
                remaining_size: new_remaining_size,
            };
            debug!(
                "Need more script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        if size != self.script_bytes.len() {
            return Err(ParserError::from_str("Bad input script len"));
        }

        let mut script_sig = Script::default();
        // NOTE: take/deallocate self.script_bytes here
        script_sig.0.0 = mem::take(&mut self.script_bytes);

        match ctx.tx_info.tx_version() {
            SupportedTxVersion::V5 => {
                ok!(script_sig.write(ctx.hashers.scripts_hasher.as_writer()));
            }
            #[cfg(feature = "zcash_unstable")]
            SupportedTxVersion::V6 => {
                ok!(script_sig.write(ctx.hashers.scripts_hasher.as_writer()));
            }
            SupportedTxVersion::V4 => {
                ok!(script_sig.write(ctx.hashers.v4_tx_hasher.as_writer()));
            }
        }

        info!("Script sig: {:?}", script_sig);

        let sequence = {
            let mut sequence = [0; 4];
            ok!(reader.read_exact(&mut sequence));
            u32::from_le_bytes(sequence)
        };
        info!("Sequence: {:X?}", sequence);

        match ctx.tx_info.tx_version() {
            SupportedTxVersion::V5 => {
                ok!(ctx.hashers.sequence_hasher.update(&sequence.to_le_bytes()));
            }
            #[cfg(feature = "zcash_unstable")]
            SupportedTxVersion::V6 => {
                ok!(ctx.hashers.sequence_hasher.update(&sequence.to_le_bytes()));
            }
            SupportedTxVersion::V4 => {
                ok!(ctx.hashers.v4_tx_hasher.update(&sequence.to_le_bytes()));
            }
        }

        if ctx.tx_state.is_tx_parsed_once {
            ok!(script_sig.write(ctx.hashers.prevouts_hasher.as_writer()));
            ok!(ctx.hashers.prevouts_hasher.update(&sequence.to_le_bytes()));
        }

        self.input_parsed_count = self.input_parsed_count.saturating_add(1);

        if self.input_count == self.input_parsed_count {
            info!("All inputs parsed");

            if self.mode == LegacyParserMode::Signature {
                if ctx.tx_state.is_tx_parsed_once {
                    let mut txin_sig_digest = [0u8; 32];
                    ok!(ctx.hashers.prevouts_hasher.finalize(&mut txin_sig_digest));
                    info!("txin sig digest {}", HexSlice(&txin_sig_digest));

                    compute_transparent_input_signature_digest(
                        ctx.tx_info,
                        &txin_sig_digest,
                        ctx.tx_info.sighash_type,
                    )?;

                    self.state = LegacyParserState::TransactionReadyToSign;
                } else {
                    finalize_signature_input_hash(ctx)?;

                    self.state = LegacyParserState::TransactionPresignReady;

                    // Skip trailing bytes if any
                    ok!(reader.advance(reader.remaining_len()));
                }

                return Ok(());
            }

            info!("Input hashing done");

            self.state = LegacyParserState::InputHashingDone;
        } else {
            self.state = LegacyParserState::WaitInput;
        }

        Ok(())
    }

    pub fn parse_input_hashing_done(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let output_count: usize = ok!(CompactSize::read_t(&mut *reader));
        info!("Output count: {}", output_count);

        if let SupportedTxVersion::V4 = ctx.tx_info.tx_version() {
            ok!(CompactSize::write(
                &mut ctx.hashers.v4_tx_hasher.as_writer(),
                output_count
            ));
        }

        self.output_count = output_count;
        self.state = LegacyParserState::WaitOutput;

        Ok(())
    }

    pub fn parse_output(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let amount = ok!({
            let mut tmp = [0u8; 8];
            ok!(reader.read_exact(&mut tmp));
            Zatoshis::from_nonnegative_i64_le_bytes(tmp)
        });

        if ctx
            .trusted_input_info
            .input_idx
            .expect("should be set at this point")
            == self.output_parsed_count as u32
        {
            ctx.trusted_input_info.amount = amount.into_u64();
            info!(
                "Found amount for trusted input: {}",
                ctx.trusted_input_info.amount
            );
        }

        match ctx.tx_info.tx_version() {
            SupportedTxVersion::V5 => {
                ok!(ctx.hashers.outputs_hasher.update(&amount.to_i64_le_bytes()));
            }
            #[cfg(feature = "zcash_unstable")]
            SupportedTxVersion::V6 => {
                ok!(ctx.hashers.outputs_hasher.update(&amount.to_i64_le_bytes()));
            }
            SupportedTxVersion::V4 => {
                ok!(ctx.hashers.v4_tx_hasher.update(&amount.to_i64_le_bytes()));
            }
        }

        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));

        if script_size > MAX_SCRIPT_SIZE {
            return Err(ParserError::from_str("Bad output script size"));
        }

        info!("Output amount: {:?}", amount);
        info!("Output script size: {}", script_size);

        self.state = LegacyParserState::ProcessOutputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.script_bytes.clear();
        self.script_bytes.extend(iter::repeat_n(0, script_size));

        Ok(())
    }

    pub fn parse_output_script(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        let new_remaining_size = {
            let offset = size - remaining_size;
            let len = ok!(reader.read(&mut self.script_bytes[offset..][..remaining_size]));

            remaining_size.saturating_sub(len)
        };

        if new_remaining_size != 0 {
            self.state = LegacyParserState::ProcessOutputScript {
                size,
                remaining_size: new_remaining_size,
            };
            info!(
                "Need more output script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        if size != self.script_bytes.len() {
            return Err(ParserError::from_str("Bad output script len"));
        }

        let mut script_pubkey = Script::default();
        // NOTE: take/deallocate self.script_bytes here
        script_pubkey.0.0 = mem::take(&mut self.script_bytes);

        match ctx.tx_info.tx_version() {
            SupportedTxVersion::V5 => {
                ok!(script_pubkey.write(&mut ctx.hashers.outputs_hasher.as_writer()));
            }
            #[cfg(feature = "zcash_unstable")]
            SupportedTxVersion::V6 => {
                ok!(script_pubkey.write(&mut ctx.hashers.outputs_hasher.as_writer()));
            }
            SupportedTxVersion::V4 => {
                ok!(script_pubkey.write(&mut ctx.hashers.v4_tx_hasher.as_writer()));
            }
        }

        info!("Output script pubkey: {:?}", script_pubkey);

        self.output_parsed_count = self.output_parsed_count.saturating_add(1);

        if self.output_count == self.output_parsed_count {
            info!("All outputs parsed");
            self.state = LegacyParserState::OutputHashingDone;
        } else {
            self.state = LegacyParserState::WaitOutput;
        }

        Ok(())
    }

    pub fn parse_output_hashing_done(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Output hashing done");

        self.sapling_spend_count = ok!(CompactSize::read_t(&mut *reader));
        self.sapling_output_count = ok!(CompactSize::read_t(&mut *reader));
        self.orchard_action_count = ok!(CompactSize::read_t(&mut *reader));
        // ZIP-229 adds a fourth pool: a v6 transaction announces its Ironwood action count
        // even when the Orchard one is zero.
        #[cfg(feature = "zcash_unstable")]
        if let SupportedTxVersion::V6 = ctx.tx_info.tx_version() {
            self.ironwood_action_count = ok!(CompactSize::read_t(&mut *reader));
        }

        info!("Sapling spend remaining: {}", self.sapling_spend_count);
        info!("Sapling output count: {}", self.sapling_output_count);
        info!("Orchard action count: {}", self.orchard_action_count);
        #[cfg(feature = "zcash_unstable")]
        info!("Ironwood action count: {}", self.ironwood_action_count);

        if self.sapling_spend_count > 0 || self.sapling_output_count > 0 {
            self.state = LegacyParserState::ProcessSapling;
            return Ok(());
        }

        self.enter_next_action_bundle(ctx, None)
    }
}
