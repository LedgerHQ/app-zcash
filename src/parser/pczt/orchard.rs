//! Orchard section of the PCZT parser.
//!
//! The state handlers are `#[inline(never)]` on purpose: inlined into the
//! `parse_orchard_actions` dispatch loop their locals merge into a single frame
//! that stays resident whichever state runs, and the deepest states (Orchard key
//! derivation, note decryption) then have no stack left on the smallest device.
//!
//! The same applies to the per-action checks `finish_current_orchard_action`
//! chains (`cv_net`, spend nullifier, output validation): each is called once, so
//! the compiler folds them into the calling handler and their buffers — a note
//! ciphertext and two Sinsemilla messages — end up resident together even though
//! they are used strictly one after another.

use super::*;
use crate::tx::TxOutputMemo;
use ::orchard::bundle::BundleVersion;
use alloc::string::ToString;
use ledger_device_sdk::hash::blake2::Blake2b_256;

pub(super) const ZCASH_MEMO_TEXT_MAX_TAG: u8 = 0xF4;
pub(super) const ZCASH_MEMO_EMPTY_TAG: u8 = 0xF6;

impl PcztParser {
    #[inline(never)]
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
            self.has_orchard_bundle = true;
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

            // V6: switch bundle-level personalization; action-level strings are unchanged.
            #[cfg(feature = "zcash_unstable")]
            if ctx.tx_info.is_v6 {
                ok!(ctx
                    .hashers
                    .orchard_hasher
                    .init_with_perso(ZCASH_ORCHARD_HASH_PERSONALIZATION_V6));
            }

            self.state = PcztParserState::WaitOrchardAction;
        }

        Ok(())
    }

    #[inline(never)]
    pub(super) fn parse_orchard_action(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        ok!(reader.read_exact(&mut self.current_action.cv_net));
        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .update(&self.current_action.cv_net));
        debug!(
            "PCZT orchard action #{} cv_net: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_action.cv_net)
        );

        ok!(reader.read_exact(&mut self.current_action.nullifier));
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .update(&self.current_action.nullifier));
        debug!(
            "PCZT orchard action #{} nullifier: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_action.nullifier)
        );

        ok!(reader.read_exact(&mut self.current_action.rk));
        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .update(&self.current_action.rk));
        debug!(
            "PCZT orchard action #{} rk: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_action.rk)
        );

        ok!(reader.read_exact(&mut self.current_action.spend_recipient));
        debug!(
            "PCZT orchard action #{} spend recipient: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_action.spend_recipient)
        );

        self.current_action.spend_value = self.read_orchard_value(
            reader,
            "Bad PCZT orchard spend value",
            "PCZT orchard spend value out of range",
        )?;
        debug!(
            "PCZT orchard action #{} spend value: {}",
            self.orchard_action_parsed_count, self.current_action.spend_value
        );

        ok!(reader.read_exact(&mut self.current_action.spend_rho));
        debug!(
            "PCZT orchard action #{} spend rho: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_action.spend_rho)
        );

        ok!(reader.read_exact(&mut self.current_action.spend_rseed));
        debug!(
            "PCZT orchard action #{} spend rseed: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_action.spend_rseed)
        );

        let mut alpha = [0u8; 32];
        ok!(reader.read_exact(&mut alpha));
        self.current_action.alpha = Some(alpha);

        Self::ensure_orchard_apdu_group_end(reader)?;
        self.state = PcztParserState::WaitOrchardZip32Derivation;

        Ok(())
    }

    #[inline(never)]
    pub(super) fn parse_orchard_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        ok!(reader.read_exact(&mut self.current_action.cmx));
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .update(&self.current_action.cmx));
        debug!(
            "PCZT orchard action #{} cmx: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_action.cmx)
        );

        ok!(reader.read_exact(&mut self.current_action.ephemeral_key));
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .update(&self.current_action.ephemeral_key));
        debug!(
            "PCZT orchard action #{} ephemeral_key: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_action.ephemeral_key)
        );

        Self::ensure_orchard_apdu_group_end(reader)?;
        self.state = PcztParserState::WaitOrchardEncCiphertextLen;

        Ok(())
    }

    #[inline(never)]
    pub(super) fn parse_orchard_output_metadata(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        const OUTPUT_METADATA_WITHOUT_RCV_LEN: usize = ORCHARD_RAW_ADDRESS_SIZE + 8 + 32;
        const OUTPUT_METADATA_WITH_RCV_LEN: usize = OUTPUT_METADATA_WITHOUT_RCV_LEN + 32;

        match reader.remaining_len() {
            OUTPUT_METADATA_WITHOUT_RCV_LEN => {
                return Err(ParserError::from_str("Missing PCZT orchard rcv"));
            }
            OUTPUT_METADATA_WITH_RCV_LEN => {}
            _ => {
                return Err(ParserError::from_str(
                    "Bad PCZT orchard output metadata length",
                ));
            }
        }

        ok!(reader.read_exact(&mut self.current_action.output_recipient));
        debug!(
            "PCZT orchard action #{} recipient: {}",
            self.orchard_action_parsed_count,
            HexSlice(&self.current_action.output_recipient)
        );

        self.current_action.output_value = self.read_orchard_value(
            reader,
            "Bad PCZT orchard output value",
            "PCZT orchard output value out of range",
        )?;
        debug!(
            "PCZT orchard action #{} output value: {}",
            self.orchard_action_parsed_count, self.current_action.output_value
        );

        let mut rseed = [0u8; 32];
        ok!(reader.read_exact(&mut rseed));
        debug!(
            "PCZT orchard action #{} output rseed: {}",
            self.orchard_action_parsed_count,
            HexSlice(&rseed)
        );
        self.current_action.output_rseed = Some(rseed);

        let mut rcv = [0u8; 32];
        ok!(reader.read_exact(&mut rcv));
        debug!(
            "PCZT orchard action #{} rcv: {}",
            self.orchard_action_parsed_count,
            HexSlice(&rcv)
        );
        self.current_action.rcv = Some(rcv);

        Self::ensure_orchard_apdu_group_end(reader)?;
        self.finish_current_orchard_action(ctx)
    }

    #[inline(never)]
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

    #[inline(never)]
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

    #[inline(never)]
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

    #[inline(never)]
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

    #[inline(never)]
    pub(super) fn parse_orchard_trailer(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        // V5 Orchard uses orchard_insecure_v1 (current mainnet, pre-NU6.2).
        // V6 Orchard uses orchard_v3 (NU6.3, enables cross-address flag bit 2).
        #[cfg(feature = "zcash_unstable")]
        let bundle_version = if ctx.tx_info.is_v6 {
            BundleVersion::orchard_v3()
        } else {
            BundleVersion::orchard_insecure_v1()
        };
        #[cfg(not(feature = "zcash_unstable"))]
        let bundle_version = BundleVersion::orchard_insecure_v1();
        let flags = ok!(orchard_component::read_flags(&mut *reader, bundle_version));
        self.current_action.flags = ok!(
            flags.to_byte(bundle_version).ok_or(()),
            "invalid Orchard flags"
        );
        debug!("PCZT orchard flags: {:02x}", self.current_action.flags);

        self.current_action.value_sum_magnitude = ok!(reader.read_u64_le());
        debug!(
            "PCZT orchard value_sum magnitude: {}",
            self.current_action.value_sum_magnitude
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

    fn read_orchard_value(
        &self,
        reader: &mut ByteReader<'_>,
        read_error: &'static str,
        range_error: &'static str,
    ) -> Result<u64, ParserError> {
        let mut value_bytes = [0u8; 8];
        reader
            .read_exact(&mut value_bytes)
            .map_err(|_| ParserError::from_str(read_error))?;
        let value = Zatoshis::from_nonnegative_i64_le_bytes(value_bytes)
            .map_err(|_| ParserError::from_str(range_error))?;
        Ok(value.into_u64())
    }

    /// Accumulates a large ciphertext field across multiple APDU packets.
    ///
    /// Uses `pool_field_bytes`, a buffer shared with `read_large_ironwood_vec`. This is
    /// safe because the state machine ensures only one pool is being parsed at a time, and
    /// each successful read drains the buffer via `mem::take`.
    fn read_large_orchard_vec(
        &mut self,
        reader: &mut ByteReader<'_>,
        size: usize,
    ) -> Result<Option<Vec<u8>>, ParserError> {
        let missing = size.saturating_sub(self.pool_field_bytes.len());

        if missing > 0 {
            let to_read = cmp::min(missing, reader.remaining_len());
            if to_read == 0 {
                debug!(
                    "Need more PCZT orchard Vec bytes, currently read: {}",
                    self.pool_field_bytes.len()
                );
                return Ok(None);
            }

            let offset = self.pool_field_bytes.len();
            self.pool_field_bytes.resize(offset + to_read, 0);
            ok!(reader.read_exact(&mut self.pool_field_bytes[offset..]));
        }

        if self.pool_field_bytes.len() == size {
            Ok(Some(mem::take(&mut self.pool_field_bytes)))
        } else {
            Ok(None)
        }
    }

    pub(super) fn reset_current_orchard_action(&mut self) {
        self.current_action.cv_net = [0; 32];
        self.current_action.nullifier = [0; 32];
        self.current_action.rk = [0; 32];
        self.current_action.spend_value = 0;
        self.current_action.spend_recipient = [0; ORCHARD_RAW_ADDRESS_SIZE];
        self.current_action.spend_rho = [0; 32];
        self.current_action.spend_rseed = [0; 32];
        self.current_action.rcv = None;
        self.current_action.output_rseed = None;
        self.current_action.cmx = [0; 32];
        self.current_action.ephemeral_key = [0; 32];
        self.current_action.out_ciphertext = None;
        self.current_action.output_recipient = [0; ORCHARD_RAW_ADDRESS_SIZE];
        self.current_action.output_value = 0;
        self.current_action.enc_ciphertext.clear();
        self.current_action.alpha = None;
        self.current_action.path = None;
        self.current_action.fvk = None;
        #[cfg(feature = "zcash_unstable")]
        {
            self.current_action.note_plaintext_version = NOTE_VERSION_ORCHARD;
        }
    }

    pub(super) fn reset_orchard_bundle_state(&mut self, action_count: usize) {
        self.orchard_action_count = action_count;
        self.orchard_action_parsed_count = 0;
        for record in self.orchard_signing_records.iter_mut() {
            record.alpha = [0u8; 32];
        }
        self.orchard_signing_records.clear();
        self.orchard_signed_action_count = 0;
        self.orchard_real_spend_count = 0;
        self.orchard_signature_digest = None;
        self.orchard_value_balance = 0;
        self.orchard_spend_value_sum = 0;
        self.orchard_output_value_sum = 0;
        self.current_action.flags = 0;
        self.current_action.value_sum_magnitude = 0;
        self.reset_current_orchard_action();
        self.pool_field_bytes.clear();
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

        self.current_action.enc_ciphertext = enc_ciphertext;
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

        ok!(ctx.hashers.tx_non_compact_hasher.update(&out_ciphertext));

        self.current_action.out_ciphertext = Some(out_ciphertext);
        self.state = PcztParserState::WaitOrchardOutputMetadata;

        Ok(())
    }

    #[inline(never)]
    fn finish_current_orchard_action(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        let out_ciphertext = self
            .current_action
            .out_ciphertext
            .ok_or_else(|| ParserError::from_str("Missing PCZT orchard out_ciphertext"))?;
        let note_ciphertext = self.current_orchard_note_ciphertext(out_ciphertext)?;

        self.verify_current_orchard_cv_net()?;
        // Dummy spends (spend_value == 0) use a throwaway key; recipient membership
        // and nullifier checks only apply to real spends the device will sign.
        //
        // `spend_value` is authenticated, not merely declared: `cv_net` binds
        // `spend_value - output_value` to the value commitment that enters the
        // txid digest, and `validate_current_orchard_output` below pins
        // `output_value` (an output the device cannot decrypt must be 0-valued
        // and match its recomputed `cmx`). A host therefore cannot disguise a
        // real spend as a dummy to dodge the checks below.
        let is_real_spend = self.current_action.spend_value != 0;
        if is_real_spend {
            let orchard_fvk = self
                .current_action
                .fvk
                .as_ref()
                .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?;
            self.verify_current_orchard_spend_nullifier(orchard_fvk)?;
            // Real spend: the device will be asked to sign this action.
            self.orchard_real_spend_count = self.orchard_real_spend_count.saturating_add(1);
        }
        self.validate_current_orchard_output(ctx, &note_ciphertext)?;

        self.orchard_spend_value_sum = self
            .orchard_spend_value_sum
            .checked_add(self.current_action.spend_value)
            .ok_or_else(|| ParserError::from_str("PCZT orchard spend value sum overflow"))?;
        self.orchard_output_value_sum = self
            .orchard_output_value_sum
            .checked_add(self.current_action.output_value)
            .ok_or_else(|| ParserError::from_str("PCZT orchard output value sum overflow"))?;

        debug!(
            "PCZT orchard action #{} non-compact data hashed",
            self.orchard_action_parsed_count
        );

        let alpha = self
            .current_action
            .alpha
            .take()
            .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?;
        let path = self
            .current_action
            .path
            .take()
            .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?;

        self.orchard_signing_records
            .push(PcztOrchardActionSigningRecord {
                alpha,
                path,
                is_real_spend,
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

    #[inline(never)]
    fn current_orchard_note_ciphertext(
        &self,
        out_ciphertext: [u8; ORCHARD_OUT_CIPHERTEXT_SIZE],
    ) -> Result<TransmittedNoteCiphertext, ParserError> {
        if self.current_action.enc_ciphertext.len() != ORCHARD_ENC_CIPHERTEXT_SIZE {
            return Err(ParserError::from_str(
                "Missing PCZT orchard enc_ciphertext for decryption",
            ));
        }

        let enc_ciphertext: [u8; ORCHARD_ENC_CIPHERTEXT_SIZE] = self
            .current_action
            .enc_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| ParserError::from_str("Bad PCZT orchard enc_ciphertext length"))?;

        Ok(TransmittedNoteCiphertext {
            epk_bytes: self.current_action.ephemeral_key,
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
            nullifier: self.current_action.nullifier,
            cmx: self.current_action.cmx,
            ephemeral_key: note_ciphertext.epk_bytes,
            enc_ciphertext_prefix,
        }
    }

    fn try_decipher_current_orchard_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        note_ciphertext: &TransmittedNoteCiphertext,
    ) -> Result<bool, ParserError> {
        let Some(keys) = ctx.tx_info.orchard_decipher_keys.as_ref() else {
            debug!("No PCZT orchard decipher keys available");
            return Ok(false);
        };

        let compact = self.current_orchard_compact_action(note_ciphertext);
        let network = keys.network;

        match decipher_compact_value(
            &keys.internal_ivk,
            &compact,
            #[cfg(feature = "zcash_unstable")]
            false, // V5 Orchard pool does not carry V3 notes
        ) {
            Ok(Some(output)) => {
                self.validate_deciphered_orchard_output(&output)?;
                self.push_deciphered_orchard_output(ctx, output, network, true)?;
                return Ok(true);
            }
            Ok(None) => debug!("PCZT orchard internal IVK decryption did not match"),
            Err(ledger_zcash_crypto::Error::OutOfMemory) => {
                return Err(ParserError::from_sw(AppSW::NotEnoughMemorySpace));
            }
            Err(err) => debug!("PCZT orchard compact decryption failed: {:?}", err),
        }

        let action = OrchardActionCiphertext {
            compact,
            rk: self.current_action.rk,
            cv_net: self.current_action.cv_net,
            enc_ciphertext: &note_ciphertext.enc_ciphertext,
            out_ciphertext: note_ciphertext.out_ciphertext,
        };

        match decipher_value_with_ovk(
            &keys.external_ovk,
            &action,
            #[cfg(feature = "zcash_unstable")]
            false, // V5 Orchard pool does not carry V3 notes
        ) {
            Ok(Some(output)) => {
                self.validate_deciphered_orchard_output(&output)?;
                self.push_deciphered_orchard_output(ctx, output, network, false)?;
                return Ok(true);
            }
            Ok(None) => debug!("PCZT orchard external OVK recovery did not match"),
            Err(ledger_zcash_crypto::Error::OutOfMemory) => {
                return Err(ParserError::from_sw(AppSW::NotEnoughMemorySpace));
            }
            Err(err) => debug!("PCZT orchard OVK recovery failed: {:?}", err),
        }

        Ok(false)
    }

    #[inline(never)]
    fn validate_current_orchard_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        note_ciphertext: &TransmittedNoteCiphertext,
    ) -> Result<(), ParserError> {
        if self.try_decipher_current_orchard_output(ctx, note_ciphertext)? {
            return Ok(());
        }

        if self.validate_current_orchard_dummy_output()? {
            return Ok(());
        }

        Err(ParserError::from_str(
            "PCZT orchard output could not be decrypted",
        ))
    }

    fn validate_current_orchard_dummy_output(&self) -> Result<bool, ParserError> {
        if self.current_action.output_value != 0 {
            return Ok(false);
        }

        let Some(rseed) = self.current_action.output_rseed else {
            return Err(ParserError::from_str("Missing PCZT orchard output rseed"));
        };

        let expected_cmx = ledger_zcash_crypto::orchard_note_commitment_bytes(
            &self.current_action.output_recipient,
            self.current_action.output_value,
            &self.current_action.nullifier,
            &rseed,
        )
        .map_err(|err| match err {
            ledger_zcash_crypto::Error::MalformedPallasBase => {
                ParserError::from_str("Bad PCZT orchard dummy nullifier")
            }
            ledger_zcash_crypto::Error::MalformedPallasPoint
            | ledger_zcash_crypto::Error::InvalidDiversifyHashPoint => {
                ParserError::from_str("Bad PCZT orchard output recipient")
            }
            ledger_zcash_crypto::Error::MalformedPallasScalar
            | ledger_zcash_crypto::Error::InvalidKeyDiscarded => {
                ParserError::from_str("Bad PCZT orchard output rseed")
            }
            _ => ParserError::from_sw(AppSW::TechnicalProblem),
        })?;

        if expected_cmx != self.current_action.cmx {
            debug!(
                "PCZT orchard dummy output cmx mismatch: expected {}, actual {}",
                HexSlice(&expected_cmx),
                HexSlice(&self.current_action.cmx)
            );
            return Err(ParserError::from_str(
                "PCZT orchard dummy output cmx mismatch",
            ));
        }

        debug!("PCZT orchard dummy output accepted");
        Ok(true)
    }

    fn validate_deciphered_orchard_output(
        &self,
        output: &DecipheredOrchardOutput,
    ) -> Result<(), ParserError> {
        if output.value != self.current_action.output_value {
            return Err(ParserError::from_str("PCZT orchard output value mismatch"));
        }

        if output.raw_address != self.current_action.output_recipient {
            debug!(
                "PCZT orchard output recipient mismatch: expected {}, decrypted {}",
                HexSlice(&self.current_action.output_recipient),
                HexSlice(&output.raw_address)
            );
            return Err(ParserError::from_str(
                "PCZT orchard output recipient mismatch",
            ));
        }

        Ok(())
    }

    fn orchard_output_memo_display(
        output: &DecipheredOrchardOutput,
        is_change: bool,
    ) -> Result<Option<TxOutputMemo>, ParserError> {
        if is_change {
            return Ok(None);
        }

        let Some(memo) = output.memo.as_ref() else {
            return Ok(None);
        };

        Self::orchard_memo_display(memo)
    }

    fn orchard_memo_display(memo: &[u8]) -> Result<Option<TxOutputMemo>, ParserError> {
        if memo.len() != ORCHARD_MEMO_SIZE {
            return Err(ParserError::from_sw(AppSW::TechnicalProblem));
        }

        if memo[0] == ZCASH_MEMO_EMPTY_TAG && memo[1..].iter().all(|byte| *byte == 0) {
            return Ok(None);
        }

        let Some(memo_len) = memo
            .iter()
            .rposition(|byte| *byte != 0)
            .map(|index| index + 1)
        else {
            return Ok(None);
        };

        if memo[0] <= ZCASH_MEMO_TEXT_MAX_TAG
            && let Ok(text) = core::str::from_utf8(&memo[..memo_len])
            && Self::is_displayable_ascii_memo(text)
        {
            return Ok(Some(TxOutputMemo::text(text.to_string())));
        }

        let mut hasher = Blake2b_256::default();
        ok!(hasher.update(memo));
        let mut hash = [0u8; 32];
        ok!(hasher.finalize(&mut hash));
        Ok(Some(TxOutputMemo::hash(format!("{}", HexSlice(&hash)))))
    }

    fn is_displayable_ascii_memo(text: &str) -> bool {
        text.bytes().all(|byte| matches!(byte, 0x20..=0x7E))
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
        let memo = Self::orchard_output_memo_display(&output, is_change)?;

        debug!(
            "PCZT orchard output address: {}, amount: {}, change: {}",
            address, output.value, is_change
        );

        ctx.tx_info.outputs.push(TxOutput {
            amount: output.value,
            address,
            is_change,
            memo,
            pool: TxPool::Orchard,
        });

        if is_change {
            ctx.tx_info.is_change_found = true;
        }

        Ok(())
    }

    #[inline(never)]
    fn verify_current_orchard_cv_net(&self) -> Result<(), ParserError> {
        let Some(rcv_bytes) = self.current_action.rcv else {
            return Err(ParserError::from_str("Missing PCZT orchard rcv"));
        };

        let value_net = i128::from(self.current_action.spend_value)
            - i128::from(self.current_action.output_value);
        let value_net = i64::try_from(value_net)
            .map_err(|_| ParserError::from_str("PCZT orchard cv_net value out of range"))?;
        let expected_cv_net = ledger_zcash_crypto::orchard_value_commitment_bytes(
            value_net, &rcv_bytes,
        )
        .map_err(|err| match err {
            ledger_zcash_crypto::Error::MalformedPallasScalar => {
                ParserError::from_str("Bad PCZT orchard rcv")
            }
            _ => ParserError::from_sw(AppSW::TechnicalProblem),
        })?;

        if expected_cv_net != self.current_action.cv_net {
            debug!(
                "PCZT orchard cv_net mismatch: expected {}, actual {}",
                HexSlice(&expected_cv_net),
                HexSlice(&self.current_action.cv_net)
            );
            return Err(ParserError::from_str("PCZT orchard cv_net mismatch"));
        }

        Ok(())
    }

    #[inline(never)]
    fn verify_current_orchard_spend_nullifier(&self, fvk: &OrchardFvk) -> Result<(), ParserError> {
        let mut diversifier = [0u8; 11];
        diversifier.copy_from_slice(&self.current_action.spend_recipient[..11]);

        let mut claimed_pk_d = [0u8; 32];
        claimed_pk_d.copy_from_slice(&self.current_action.spend_recipient[11..]);

        if !self.is_current_orchard_spend_recipient_in_fvk(fvk, &diversifier, &claimed_pk_d)? {
            return Err(ParserError::from_str(
                "PCZT orchard spend does not belong to signing key",
            ));
        }

        let fvk_bytes = fvk.to_bytes();
        let nk: [u8; 32] = fvk_bytes[32..64]
            .try_into()
            .map_err(|_| ParserError::from_sw(AppSW::TechnicalProblem))?;
        let expected_nullifier = ledger_zcash_crypto::orchard_spend_nullifier_bytes(
            &nk,
            &self.current_action.spend_recipient,
            self.current_action.spend_value,
            &self.current_action.spend_rho,
            &self.current_action.spend_rseed,
        )
        .map_err(|err| match err {
            ledger_zcash_crypto::Error::MalformedPallasBase => {
                ParserError::from_str("Bad PCZT orchard spend rho")
            }
            ledger_zcash_crypto::Error::MalformedPallasPoint
            | ledger_zcash_crypto::Error::InvalidDiversifyHashPoint => {
                ParserError::from_str("Bad PCZT orchard spend recipient")
            }
            ledger_zcash_crypto::Error::InvalidKeyDiscarded => {
                ParserError::from_str("Bad PCZT orchard spend rseed")
            }
            _ => ParserError::from_sw(AppSW::TechnicalProblem),
        })?;

        if expected_nullifier != self.current_action.nullifier {
            debug!(
                "PCZT orchard nullifier mismatch: expected {}, actual {}",
                HexSlice(&expected_nullifier),
                HexSlice(&self.current_action.nullifier)
            );
            return Err(ParserError::from_str("PCZT orchard nullifier mismatch"));
        }

        Ok(())
    }

    fn is_current_orchard_spend_recipient_in_fvk(
        &self,
        fvk: &OrchardFvk,
        diversifier: &[u8; 11],
        claimed_pk_d: &[u8; 32],
    ) -> Result<bool, ParserError> {
        let g_d = ledger_zcash_crypto::diversify_hash_ledger(diversifier)
            .map_err(|_| ParserError::from_str("Bad PCZT orchard spend recipient"))?;

        for scope in [OrchardScope::External, OrchardScope::Internal] {
            let ivk = fvk
                .to_ivk_ledger(scope)
                .map_err(|_| ParserError::from_sw(AppSW::TechnicalProblem))?;
            let ivk_bytes = ivk.to_bytes();
            let ivk_bytes: [u8; 32] = ivk_bytes[32..64]
                .try_into()
                .map_err(|_| ParserError::from_sw(AppSW::TechnicalProblem))?;
            let expected_pk_d = ledger_zcash_crypto::orchard_pk_d(&ivk_bytes, &g_d)
                .map_err(|_| ParserError::from_sw(AppSW::TechnicalProblem))?;

            if &expected_pk_d == claimed_pk_d {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn finish_orchard_value_sum_sign(&mut self, sign_byte: u8) -> Result<(), ParserError> {
        let magnitude = i64::try_from(self.current_action.value_sum_magnitude)
            .map_err(|_| ParserError::from_str("PCZT orchard value_sum out of range"))?;

        self.orchard_value_balance = match sign_byte {
            0 => magnitude,
            1 => -magnitude,
            _ => return Err(ParserError::from_str("Bad PCZT orchard value_sum sign")),
        };

        debug!("PCZT orchard value balance: {}", self.orchard_value_balance);

        let expected_value_balance =
            i128::from(self.orchard_spend_value_sum) - i128::from(self.orchard_output_value_sum);
        if expected_value_balance != i128::from(self.orchard_value_balance) {
            debug!(
                "PCZT orchard value balance mismatch: spend_sum={}, output_sum={}, value_balance={}",
                self.orchard_spend_value_sum,
                self.orchard_output_value_sum,
                self.orchard_value_balance
            );
            return Err(ParserError::from_str("PCZT orchard value_sum mismatch"));
        }

        Ok(())
    }

    fn verify_current_orchard_rk(&self, ask: &OrchardAsk) -> Result<(), ParserError> {
        let alpha = self
            .current_action
            .alpha
            .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?;

        let alpha = ledger_zcash_crypto::pallas_scalar_from_repr(alpha)
            .map_err(|_| ParserError::from_str("Bad PCZT orchard alpha"))?;

        // Compute rk bytes directly (no intermediate curve-point construction)
        // to keep the BN/point footprint low: real Orchard spends run this on a
        // BN pool already near capacity from the fvk/ask derivation.
        let expected_rk = ask
            .randomized_verification_key_bytes(&alpha)
            .map_err(|_| ParserError::from_sw(AppSW::TechnicalProblem))?;

        if expected_rk != self.current_action.rk {
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
            .update(&[self.current_action.flags]));
        ok!(ctx
            .hashers
            .orchard_hasher
            .update(&self.orchard_value_balance.to_le_bytes()));
        // V6: anchor goes to the authorizing-data digest, not the sighash.
        #[cfg(not(feature = "zcash_unstable"))]
        ok!(ctx.hashers.orchard_hasher.update(anchor));
        #[cfg(feature = "zcash_unstable")]
        if !ctx.tx_info.is_v6 {
            ok!(ctx.hashers.orchard_hasher.update(anchor));
        }
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

    #[inline(never)]
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

        // Derive FVK (and ASK for real spends) from the session-cached account
        // spending key, so the exhausting zip32_orchard_derive syscall runs at
        // most once for the whole transaction rather than once per action.
        let spend_value = self.current_action.spend_value;
        let sk = ok!(self.orchard_spending_key(&path));
        let (orchard_fvk, ask_for_rk) = if spend_value != 0 {
            let (fvk, ask) =
                derive_orchard_fvk_and_ask_from_sk(sk).map_err(ParserError::from_sw)?;
            (fvk, Some(ask))
        } else {
            // Dummy spend: throwaway key, rk check skipped.
            (ok!(derive_orchard_fvk_from_sk(sk)), None)
        };
        if let Some(ref ask) = ask_for_rk {
            self.verify_current_orchard_rk(ask)?;
        }
        let network = orchard_network(&path);
        ctx.tx_info.orchard_decipher_keys = Some(
            OrchardDecipherKeys::from_fvk(&orchard_fvk, network)
                .map_err(|_| ParserError::from_sw(AppSW::TechnicalProblem))?,
        );
        debug!(
            "PCZT orchard action #{} decipher keys prepared",
            self.orchard_action_parsed_count
        );

        self.current_action.path = Some(path);
        self.current_action.fvk = Some(orchard_fvk);
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

        // Refuse to sign a dummy padding spend. Its rk and nullifier were
        // deliberately left unverified during parsing (they derive from the
        // host's throwaway key), and the PCZT IoFinalizer already self-signed it
        // with that key — a device signature would authorize an action whose
        // spend side was never checked, and would push the device signature
        // count past the finalizer's unsigned-action count. The host is expected
        // to skip dummy indices; this enforces it rather than assuming it.
        if !action.is_real_spend {
            return Err(ParserError::from_str(
                "PCZT orchard dummy spend must not be signed by the device",
            ));
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

    // Number of Orchard spend-auth signatures the device produces for this
    // transaction: one per real spend. Dummy padding spends are signed
    // host-side and never counted here, so signing completes (and the device
    // leaves the signing screen) as soon as every real spend is signed — which
    // is zero for a transparent→shielded transaction.
    //
    // This is a quota over the same set that `orchard_signed_action_count`
    // counts: `ensure_signature_digest_for_orchard` refuses dummy indices, so a
    // signature can only ever be produced for a real spend and the two counters
    // cannot drift apart.
    //
    // Note the host-side finalizer partitions on a different predicate — an
    // action needs a device signature when its `spend_auth_sig` is `None` — and
    // the two agree only because the IoFinalizer self-signs exactly the padding
    // dummies with their `dummy_sk`. They would diverge for a real spend of a
    // zero-valued note: the device would treat it as dummy and produce no
    // signature while the finalizer still expects one, so finalization fails
    // closed on its signature-count check.
    pub fn orchard_signature_count(&self) -> usize {
        self.orchard_real_spend_count
    }

    pub fn mark_orchard_action_signed(
        &mut self,
        action_index: usize,
    ) -> Result<usize, ParserError> {
        let action = self
            .orchard_signing_records
            .get_mut(action_index)
            .ok_or_else(|| ParserError::from_str("Bad PCZT orchard action index"))?;

        if action.signed {
            return Err(ParserError::from_str("PCZT orchard action already signed"));
        }

        action.signed = true;
        action.alpha = [0u8; 32];

        self.orchard_signed_action_count = self.orchard_signed_action_count.saturating_add(1);

        // Zeroize the cached account spending key as soon as the last action is
        // signed — it is no longer needed and must not outlive its usage.
        if self.are_orchard_signatures_done() {
            self.clear_orchard_spending_key();
        }

        Ok(self.orchard_signed_action_count)
    }

    pub fn are_orchard_signatures_done(&self) -> bool {
        !self.has_orchard_bundle
            || self.orchard_signed_action_count >= self.orchard_signature_count()
    }

    fn finalize_orchard_actions(&mut self, ctx: &mut PcztParserCtx<'_>) -> Result<(), ParserError> {
        debug!("PCZT orchard actions hashing done");

        self.state = PcztParserState::OrchardActionsDone;
        // For V6, defer the user review to Ironwood finalization so that the fee display
        // includes both the Orchard and Ironwood value balances (review_outputs sums them).
        // Invariant: every V6 (NU6.3) transaction has an Ironwood bundle, so finalize_ironwood_actions
        // is always called after this point and will invoke review_outputs. A V6 PCZT without an
        // Ironwood bundle would leave outputs_reviewed = false, permanently blocking signing — this
        // is the correct fail-closed behavior for an out-of-spec transaction.
        #[cfg(feature = "zcash_unstable")]
        if ctx.tx_info.is_v6 {
            return Ok(());
        }
        self.review_outputs(ctx)?;

        // The bundle is fully parsed, so the real-spend count is final. When it
        // is zero (transparent -> shielded: every spend is dummy padding) no
        // signing request will ever follow, so the cached spending key is
        // already dead here and `mark_orchard_action_signed` — the other release
        // site — will never run. Release it now rather than leaving it in RAM
        // for the rest of the session.
        if self.are_orchard_signatures_done() {
            self.clear_orchard_spending_key();
        }

        Ok(())
    }
}
