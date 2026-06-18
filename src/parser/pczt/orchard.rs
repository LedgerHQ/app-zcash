use super::*;

impl PcztParser {
    pub(super) fn parse_orchard_actions_start(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT orchard actions start");

        let action_count: usize = ok!(CompactSize::read_t(&mut *reader));
        if action_count > MAX_PCZT_ORCHARD_ACTIONS_NUMBER {
            return Err(ParserError::from_str("Too many PCZT orchard actions"));
        }

        debug!("PCZT orchard action count: {}", action_count);

        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected PCZT orchard action data after action count",
            ));
        }

        self.pczt_finished = false;

        self.reset_orchard_bundle_state(action_count);

        if action_count == 0 {
            self.finalize_orchard_actions(ctx)?;
        } else {
            ok!(ctx
                .hashers
                .tx_compact_hasher
                .init_with_perso(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION));
            ok!(ctx
                .hashers
                .tx_memo_hasher
                .init_with_perso(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION));
            ok!(ctx
                .hashers
                .tx_non_compact_hasher
                .init_with_perso(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION));

            self.state = PcztParserState::WaitOrchardAction;
        }

        Ok(())
    }

    pub(super) fn parse_orchard_action(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        ok!(reader.read_exact(&mut self.current_orchard_cv_net));
        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .update(&self.current_orchard_cv_net));
        debug!(
            "PCZT orchard action #{} cv_net: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_orchard_cv_net)
        );

        ok!(reader.read_exact(&mut self.current_orchard_nullifier));
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .update(&self.current_orchard_nullifier));
        debug!(
            "PCZT orchard action #{} nullifier: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_orchard_nullifier)
        );

        ok!(reader.read_exact(&mut self.current_orchard_rk));
        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .update(&self.current_orchard_rk));
        debug!(
            "PCZT orchard action #{} rk: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_orchard_rk)
        );

        let mut alpha = [0u8; 32];
        ok!(reader.read_exact(&mut alpha));
        debug!(
            "PCZT orchard action #{} alpha: {}",
            self.orchard_action_parsed_count,
            HexSlice(&alpha)
        );
        self.current_orchard_alpha = Some(alpha);

        Self::ensure_orchard_apdu_group_end(reader)?;
        self.state = PcztParserState::WaitOrchardZip32Derivation;

        Ok(())
    }

    pub(super) fn parse_orchard_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        ok!(reader.read_exact(&mut self.current_orchard_cmx));
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .update(&self.current_orchard_cmx));
        debug!(
            "PCZT orchard action #{} cmx: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_orchard_cmx)
        );

        ok!(reader.read_exact(&mut self.current_orchard_ephemeral_key));
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .update(&self.current_orchard_ephemeral_key));
        debug!(
            "PCZT orchard action #{} ephemeral_key: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_orchard_ephemeral_key)
        );

        Self::ensure_orchard_apdu_group_end(reader)?;
        self.state = PcztParserState::WaitOrchardEncCiphertextLen;

        Ok(())
    }

    pub(super) fn parse_orchard_enc_ciphertext_len(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let size: usize = ok!(CompactSize::read_t(&mut *reader));

        if size != ORCHARD_ENC_CIPHERTEXT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT orchard enc_ciphertext size",
            ));
        }

        debug!(
            "PCZT orchard action #{} enc_ciphertext size: {}",
            self.orchard_action_parsed_count, size
        );

        self.state = PcztParserState::ProcessOrchardEncCiphertext;
        if reader.remaining_len() == 0 {
            return Err(ParserError::from_str(
                "Missing PCZT orchard enc_ciphertext bytes",
            ));
        }

        self.parse_orchard_enc_ciphertext(ctx, reader)
    }

    pub(super) fn parse_orchard_enc_ciphertext(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let Some(bytes) = self.read_large_orchard_vec(reader, ORCHARD_ENC_CIPHERTEXT_SIZE)? else {
            return Ok(());
        };

        self.finish_orchard_enc_ciphertext(ctx, bytes)?;
        Self::ensure_orchard_apdu_group_end(reader)
    }

    pub(super) fn parse_orchard_out_ciphertext_len(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let size: usize = ok!(CompactSize::read_t(&mut *reader));

        if size != ORCHARD_OUT_CIPHERTEXT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT orchard out_ciphertext size",
            ));
        }

        debug!(
            "PCZT orchard action #{} out_ciphertext size: {}",
            self.orchard_action_parsed_count, size
        );

        self.state = PcztParserState::ProcessOrchardOutCiphertext;
        if reader.remaining_len() == 0 {
            return Err(ParserError::from_str(
                "Missing PCZT orchard out_ciphertext bytes",
            ));
        }

        self.parse_orchard_out_ciphertext(ctx, reader)
    }

    pub(super) fn parse_orchard_out_ciphertext(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let Some(bytes) = self.read_large_orchard_vec(reader, ORCHARD_OUT_CIPHERTEXT_SIZE)? else {
            return Ok(());
        };

        self.finish_orchard_out_ciphertext(ctx, bytes)?;
        Self::ensure_orchard_apdu_group_end(reader)
    }

    pub(super) fn parse_orchard_trailer(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let flags = ok!(orchard_component::read_flags(&mut *reader));
        self.current_orchard_flags = flags.to_byte();
        debug!("PCZT orchard flags: {:02x}", self.current_orchard_flags);

        self.current_orchard_value_sum_magnitude = ok!(reader.read_u64_le());
        debug!(
            "PCZT orchard value_sum magnitude: {}",
            self.current_orchard_value_sum_magnitude
        );

        self.finish_orchard_value_sum_sign(ok!(reader.read_u8()))?;

        let mut anchor = [0u8; 32];
        ok!(reader.read_exact(&mut anchor));
        Self::ensure_orchard_apdu_group_end(reader)?;
        self.finish_orchard_anchor(ctx, &anchor)
    }

    fn ensure_orchard_apdu_group_end(reader: &ByteReader<'_>) -> Result<(), ParserError> {
        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected data after PCZT orchard APDU field group",
            ));
        }

        Ok(())
    }

    fn read_large_orchard_vec(
        &mut self,
        reader: &mut ByteReader<'_>,
        size: usize,
    ) -> Result<Option<Vec<u8>>, ParserError> {
        let missing = size.saturating_sub(self.orchard_field_bytes.len());

        if missing > 0 {
            let to_read = cmp::min(missing, reader.remaining_len());
            if to_read == 0 {
                debug!(
                    "Need more PCZT orchard Vec bytes, currently read: {}",
                    self.orchard_field_bytes.len()
                );
                return Ok(None);
            }

            let offset = self.orchard_field_bytes.len();
            self.orchard_field_bytes.resize(offset + to_read, 0);
            ok!(reader.read_exact(&mut self.orchard_field_bytes[offset..]));
        }

        if self.orchard_field_bytes.len() == size {
            Ok(Some(mem::take(&mut self.orchard_field_bytes)))
        } else {
            Ok(None)
        }
    }

    pub(super) fn reset_current_orchard_action(&mut self) {
        self.current_orchard_cv_net = [0; 32];
        self.current_orchard_nullifier = [0; 32];
        self.current_orchard_rk = [0; 32];
        self.current_orchard_cmx = [0; 32];
        self.current_orchard_ephemeral_key = [0; 32];
        self.current_orchard_enc_ciphertext.clear();
        self.current_orchard_alpha = None;
        self.current_orchard_path = None;
    }

    pub(super) fn reset_orchard_bundle_state(&mut self, action_count: usize) {
        self.orchard_action_count = action_count;
        self.orchard_action_parsed_count = 0;
        self.orchard_signing_records.clear();
        self.orchard_signed_action_count = 0;
        self.orchard_signature_digest = None;
        self.orchard_value_balance = 0;
        self.current_orchard_flags = 0;
        self.current_orchard_value_sum_magnitude = 0;
        self.reset_current_orchard_action();
        self.orchard_field_bytes.clear();
    }

    fn finish_orchard_enc_ciphertext(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        enc_ciphertext: Vec<u8>,
    ) -> Result<(), ParserError> {
        if enc_ciphertext.len() != ORCHARD_ENC_CIPHERTEXT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT orchard enc_ciphertext length",
            ));
        }

        ok!(ctx
            .hashers
            .tx_compact_hasher
            .update(&enc_ciphertext[..ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE]));

        ok!(ctx.hashers.tx_memo_hasher.update(
            &enc_ciphertext[ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE..ORCHARD_ENC_CIPHERTEXT_TAG_OFFSET]
        ));
        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .update(&enc_ciphertext[ORCHARD_ENC_CIPHERTEXT_TAG_OFFSET..]));

        debug!(
            "PCZT orchard action #{} enc_ciphertext data hashed",
            self.orchard_action_parsed_count
        );

        self.current_orchard_enc_ciphertext = enc_ciphertext;
        self.state = PcztParserState::WaitOrchardOutCiphertextLen;

        Ok(())
    }

    fn finish_orchard_out_ciphertext(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        out_ciphertext: Vec<u8>,
    ) -> Result<(), ParserError> {
        if out_ciphertext.len() != ORCHARD_OUT_CIPHERTEXT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT orchard out_ciphertext length",
            ));
        }

        let out_ciphertext: [u8; ORCHARD_OUT_CIPHERTEXT_SIZE] = out_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| ParserError::from_str("Bad PCZT orchard out_ciphertext length"))?;
        let note_ciphertext = self.current_orchard_note_ciphertext(out_ciphertext)?;

        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .update(&note_ciphertext.out_ciphertext));
        self.try_decipher_current_orchard_output(ctx, &note_ciphertext)?;

        debug!(
            "PCZT orchard action #{} non-compact data hashed",
            self.orchard_action_parsed_count
        );

        let alpha = self
            .current_orchard_alpha
            .take()
            .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?;
        let path = self
            .current_orchard_path
            .take()
            .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?;

        self.orchard_signing_records
            .push(PcztOrchardActionSigningRecord {
                alpha,
                path,
                signed: false,
            });
        self.reset_current_orchard_action();
        self.orchard_action_parsed_count = self.orchard_action_parsed_count.saturating_add(1);

        if self.orchard_action_parsed_count == self.orchard_action_count {
            self.state = PcztParserState::WaitOrchardTrailer;
        } else {
            self.state = PcztParserState::WaitOrchardAction;
        }

        Ok(())
    }

    fn current_orchard_note_ciphertext(
        &self,
        out_ciphertext: [u8; ORCHARD_OUT_CIPHERTEXT_SIZE],
    ) -> Result<TransmittedNoteCiphertext, ParserError> {
        if self.current_orchard_enc_ciphertext.len() != ORCHARD_ENC_CIPHERTEXT_SIZE {
            return Err(ParserError::from_str(
                "Missing PCZT orchard enc_ciphertext for decryption",
            ));
        }

        let enc_ciphertext: [u8; ORCHARD_ENC_CIPHERTEXT_SIZE] = self
            .current_orchard_enc_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| ParserError::from_str("Bad PCZT orchard enc_ciphertext length"))?;

        Ok(TransmittedNoteCiphertext {
            epk_bytes: self.current_orchard_ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
        })
    }

    fn current_orchard_compact_action(
        &self,
        note_ciphertext: &TransmittedNoteCiphertext,
    ) -> OrchardCompactAction {
        let mut enc_ciphertext_prefix = [0u8; ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE];
        enc_ciphertext_prefix
            .copy_from_slice(&note_ciphertext.enc_ciphertext[..ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE]);

        OrchardCompactAction {
            nullifier: self.current_orchard_nullifier,
            cmx: self.current_orchard_cmx,
            ephemeral_key: note_ciphertext.epk_bytes,
            enc_ciphertext_prefix,
        }
    }

    fn try_decipher_current_orchard_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        note_ciphertext: &TransmittedNoteCiphertext,
    ) -> Result<(), ParserError> {
        let Some(keys) = ctx.tx_info.orchard_decipher_keys.as_ref() else {
            debug!("No PCZT orchard decipher keys available");
            return Ok(());
        };

        let compact = self.current_orchard_compact_action(note_ciphertext);
        let network = keys.network;

        match decipher_compact_value(&keys.internal_ivk, &compact) {
            Ok(Some(output)) => {
                self.push_deciphered_orchard_output(ctx, output, network, true)?;
                return Ok(());
            }
            Ok(None) => debug!("PCZT orchard internal IVK decryption did not match"),
            Err(err) => debug!("PCZT orchard compact decryption failed: {:?}", err),
        }

        let action = OrchardActionCiphertext {
            compact,
            rk: self.current_orchard_rk,
            cv_net: self.current_orchard_cv_net,
            enc_ciphertext: &note_ciphertext.enc_ciphertext,
            out_ciphertext: note_ciphertext.out_ciphertext,
        };

        match decipher_value_with_ovk(&keys.external_ovk, &action) {
            Ok(Some(output)) => {
                self.push_deciphered_orchard_output(ctx, output, network, false)?;
            }
            Ok(None) => debug!("PCZT orchard external OVK recovery did not match"),
            Err(err) => debug!("PCZT orchard OVK recovery failed: {:?}", err),
        }

        Ok(())
    }

    fn push_deciphered_orchard_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        output: DecipheredOrchardOutput,
        network: NetworkType,
        is_change: bool,
    ) -> Result<(), ParserError> {
        if is_change && ctx.tx_info.is_change_found {
            return Err(ParserError::from_str("Multiple change outputs detected"));
        }

        let address =
            UnifiedAddress::try_from_items(alloc::vec![Receiver::Orchard(output.raw_address)])
                .map(|address| address.encode(&network))
                .unwrap_or_else(|_| format!("orchard:{}", HexSlice(&output.raw_address)));

        debug!(
            "PCZT orchard output address: {}, amount: {}, change: {}",
            address, output.value, is_change
        );

        ctx.tx_info.outputs.push(TxOutput {
            amount: output.value,
            address,
            is_change,
        });

        if is_change {
            ctx.tx_info.is_change_found = true;
        }

        Ok(())
    }

    fn finish_orchard_value_sum_sign(&mut self, sign_byte: u8) -> Result<(), ParserError> {
        let magnitude = i64::try_from(self.current_orchard_value_sum_magnitude)
            .map_err(|_| ParserError::from_str("PCZT orchard value_sum out of range"))?;

        self.orchard_value_balance = match sign_byte {
            0 => magnitude,
            1 => -magnitude,
            _ => return Err(ParserError::from_str("Bad PCZT orchard value_sum sign")),
        };

        debug!("PCZT orchard value balance: {}", self.orchard_value_balance);

        Ok(())
    }

    fn verify_current_orchard_rk(&self, path: &Bip32Path) -> Result<(), ParserError> {
        let alpha = self
            .current_orchard_alpha
            .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?;

        let alpha = ledger_zcash_crypto::pallas_scalar_from_repr(alpha)
            .map_err(|_| ParserError::from_str("Bad PCZT orchard alpha"))?;

        let ask = ok!(derive_orchard_ask(path));
        let randomized_ask = ask
            .randomize_ledger(&alpha)
            .map_err(|_| ParserError::from_sw(AppSW::TechnicalProblem))?;
        let expected_rk: [u8; 32] =
            (&RedpallasVerificationKey::<SpendAuth>::from(&randomized_ask)).into();

        if expected_rk != self.current_orchard_rk {
            return Err(ParserError::from_str(
                "PCZT orchard rk does not match alpha and signing key",
            ));
        }

        Ok(())
    }

    fn finish_orchard_anchor(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        anchor: &[u8; 32],
    ) -> Result<(), ParserError> {
        debug!("PCZT orchard anchor: {}", HexSlice(anchor));

        let orchard_compact_digest = finalize_and_log_hash(
            &mut ctx.hashers.tx_compact_hasher,
            "PCZT orchard compact digest",
        )?;
        let orchard_memo_digest =
            finalize_and_log_hash(&mut ctx.hashers.tx_memo_hasher, "PCZT orchard memo digest")?;
        let orchard_non_compact_digest = finalize_and_log_hash(
            &mut ctx.hashers.tx_non_compact_hasher,
            "PCZT orchard non compact digest",
        )?;

        ok!(ctx.hashers.orchard_hasher.update(&orchard_compact_digest));
        ok!(ctx.hashers.orchard_hasher.update(&orchard_memo_digest));
        ok!(ctx
            .hashers
            .orchard_hasher
            .update(&orchard_non_compact_digest));

        ok!(ctx
            .hashers
            .orchard_hasher
            .update(&[self.current_orchard_flags]));
        ok!(ctx
            .hashers
            .orchard_hasher
            .update(&self.orchard_value_balance.to_le_bytes()));
        ok!(ctx.hashers.orchard_hasher.update(anchor));
        ok!(ctx
            .hashers
            .orchard_hasher
            .finalize(&mut ctx.tx_info.orchard_digest));

        debug!(
            "PCZT orchard digest: {}",
            HexSlice(&ctx.tx_info.orchard_digest)
        );

        self.finalize_orchard_actions(ctx)
    }

    pub(super) fn parse_orchard_zip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let derivation_len = {
            let derivation = reader.remaining_slice();
            if derivation.is_empty() {
                return Err(ParserError::from_str(
                    "Missing PCZT orchard zip32 derivation bytes",
                ));
            }

            let derivation_len = derivation.len();
            self.finish_orchard_zip32_derivation(ctx, derivation)?;
            derivation_len
        };
        ok!(reader.advance(derivation_len));

        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected data after PCZT orchard zip32 derivation",
            ));
        }

        Ok(())
    }

    fn finish_orchard_zip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        derivation: &[u8],
    ) -> Result<(), ParserError> {
        let path =
            Bip32Path::try_from(derivation.get(ZIP32_SEED_FINGERPRINT_SIZE..).unwrap_or(&[]))
                .map_err(|_| ParserError::from_str("Bad PCZT orchard zip32 derivation path"))?;
        let seed_fingerprint = &derivation[..ZIP32_SEED_FINGERPRINT_SIZE];

        if !check_bip44_compliance(&path, Bip44CheckMode::OnlyCoinType) {
            return Err(ParserError::from_str(
                "PCZT orchard signing path not compliant",
            ));
        }

        debug!(
            "PCZT orchard action #{} zip32 seed fingerprint: {}",
            self.orchard_action_parsed_count,
            HexSlice(seed_fingerprint)
        );
        debug!(
            "PCZT orchard action #{} signing path: {:?}",
            self.orchard_action_parsed_count, path
        );

        let orchard_fvk = ok!(derive_orchard_fvk(&path));
        self.verify_current_orchard_rk(&path)?;
        let network = orchard_network(&path);
        ctx.tx_info.orchard_decipher_keys =
            Some(ok!(OrchardDecipherKeys::from_fvk(&orchard_fvk, network)));
        debug!(
            "PCZT orchard action #{} decipher keys prepared",
            self.orchard_action_parsed_count
        );

        self.current_orchard_path = Some(path);
        self.state = PcztParserState::WaitOrchardOutput;

        Ok(())
    }

    pub fn ensure_signature_digest_for_orchard(
        &mut self,
        tx_info: &mut TxInfo,
        action_index: usize,
    ) -> Result<(), ParserError> {
        if !self.is_finished() {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        let action = self
            .orchard_signing_records
            .get(action_index)
            .ok_or_else(|| ParserError::from_str("Bad PCZT orchard action index"))?;

        if action.signed {
            return Err(ParserError::from_str("PCZT orchard action already signed"));
        }

        if let Some(signature_digest) = self.orchard_signature_digest {
            tx_info.signature_digest = signature_digest;
        } else {
            compute_shielded_signature_digest(
                tx_info,
                self.transparent_input_count,
                self.transparent_output_count,
            )?;
            self.orchard_signature_digest = Some(tx_info.signature_digest);
        }

        debug!(
            "Computed PCZT shielded signature digest for Orchard action #{} signing: {}",
            action_index,
            HexSlice(&tx_info.signature_digest)
        );

        Ok(())
    }

    pub fn orchard_action_signing_data(
        &self,
        action_index: usize,
    ) -> Result<(&Bip32Path, [u8; 32]), ParserError> {
        if !self.is_ready_to_sign() {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        let action = self
            .orchard_signing_records
            .get(action_index)
            .ok_or_else(|| ParserError::from_str("Bad PCZT orchard action index"))?;

        Ok((&action.path, action.alpha))
    }

    pub fn orchard_signature_count(&self) -> usize {
        self.orchard_action_count
    }

    pub fn mark_orchard_action_signed(
        &mut self,
        action_index: usize,
    ) -> Result<usize, ParserError> {
        let action = self
            .orchard_signing_records
            .get_mut(action_index)
            .ok_or_else(|| ParserError::from_str("Bad PCZT orchard action index"))?;

        action.signed = true;

        self.orchard_signed_action_count = self.orchard_signed_action_count.saturating_add(1);

        Ok(self.orchard_signed_action_count)
    }

    pub fn are_orchard_signatures_done(&self) -> bool {
        self.orchard_signed_action_count >= self.orchard_signature_count()
    }

    fn finalize_orchard_actions(&mut self, ctx: &mut PcztParserCtx<'_>) -> Result<(), ParserError> {
        debug!("PCZT orchard actions hashing done");

        self.state = PcztParserState::OrchardActionsDone;
        self.review_outputs(ctx)?;

        Ok(())
    }
}
