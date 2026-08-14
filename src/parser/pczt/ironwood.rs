//! Ironwood (NU6.3 / V6) PCZT action parser.
//!
//! Structural mirror of `orchard.rs` for the second Orchard-shaped pool introduced
//! by Ironwood/NU6.3.

use super::*;
use crate::parser::personalization::{
    ZCASH_IRONWOOD_ACTIONS_COMPACT_HASH_PERSONALIZATION,
    ZCASH_IRONWOOD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
    ZCASH_IRONWOOD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION, ZCASH_IRONWOOD_HASH_PERSONALIZATION,
};
use crate::tx::TxOutputMemo;
use ::orchard::bundle::BundleVersion;
use alloc::string::ToString;
use ledger_device_sdk::hash::blake2::Blake2b_256;

const ZCASH_MEMO_TEXT_MAX_TAG: u8 = 0xF4;
const ZCASH_MEMO_EMPTY_TAG: u8 = 0xF6;

impl PcztParser {
    #[inline(never)]
    pub(super) fn parse_ironwood_actions_start(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT ironwood actions start");

        let action_count: usize = ok!(CompactSize::read_t(&mut *reader));
        if action_count > MAX_PCZT_IRONWOOD_ACTIONS_NUMBER {
            return Err(ParserError::from_str("Too many PCZT ironwood actions"));
        }

        debug!("PCZT ironwood action count: {}", action_count);

        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected PCZT ironwood action data after action count",
            ));
        }

        self.pczt_finished = false;

        if action_count == 0 {
            return Err(ParserError::from_str(
                "Ironwood bundle with zero actions is invalid",
            ));
        }

        self.has_ironwood_bundle = true;
        self.is_v6_tx = true;
        ctx.tx_info.has_ironwood_bundle = true;
        self.reset_ironwood_bundle_state(action_count);

        {
            ok!(ctx
                .hashers
                .tx_compact_hasher
                .init_with_perso(ZCASH_IRONWOOD_ACTIONS_COMPACT_HASH_PERSONALIZATION));
            ok!(ctx
                .hashers
                .tx_memo_hasher
                .init_with_perso(ZCASH_IRONWOOD_ACTIONS_MEMOS_HASH_PERSONALIZATION));
            ok!(ctx
                .hashers
                .tx_non_compact_hasher
                .init_with_perso(ZCASH_IRONWOOD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION));

            // Ironwood is always V6; re-initialize the bundle-level hasher unconditionally.
            ok!(ctx
                .hashers
                .ironwood_hasher
                .init_with_perso(ZCASH_IRONWOOD_HASH_PERSONALIZATION));

            self.state = PcztParserState::WaitIronwoodAction;
        }

        Ok(())
    }

    #[inline(never)]
    pub(super) fn parse_ironwood_action(
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
            "PCZT ironwood action #{} cv_net: {}",
            self.ironwood_action_parsed_count,
            HexSlice(&self.current_action.cv_net)
        );

        ok!(reader.read_exact(&mut self.current_action.nullifier));
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .update(&self.current_action.nullifier));
        debug!(
            "PCZT ironwood action #{} nullifier: {}",
            self.ironwood_action_parsed_count,
            HexSlice(&self.current_action.nullifier)
        );

        ok!(reader.read_exact(&mut self.current_action.rk));
        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .update(&self.current_action.rk));
        debug!(
            "PCZT ironwood action #{} rk: {}",
            self.ironwood_action_parsed_count,
            HexSlice(&self.current_action.rk)
        );

        ok!(reader.read_exact(&mut self.current_action.spend_recipient));
        debug!(
            "PCZT ironwood action #{} spend recipient: {}",
            self.ironwood_action_parsed_count,
            HexSlice(&self.current_action.spend_recipient)
        );

        self.current_action.spend_value = self.read_ironwood_value(
            reader,
            "Bad PCZT ironwood spend value",
            "PCZT ironwood spend value out of range",
        )?;
        debug!(
            "PCZT ironwood action #{} spend value: {}",
            self.ironwood_action_parsed_count, self.current_action.spend_value
        );

        ok!(reader.read_exact(&mut self.current_action.spend_rho));
        debug!(
            "PCZT ironwood action #{} spend rho: {}",
            self.ironwood_action_parsed_count,
            HexSlice(&self.current_action.spend_rho)
        );

        ok!(reader.read_exact(&mut self.current_action.spend_rseed));
        debug!(
            "PCZT ironwood action #{} spend rseed: {}",
            self.ironwood_action_parsed_count,
            HexSlice(&self.current_action.spend_rseed)
        );

        let mut alpha = [0u8; 32];
        ok!(reader.read_exact(&mut alpha));
        self.current_action.alpha = Some(alpha);

        Self::ensure_ironwood_apdu_group_end(reader)?;
        self.state = PcztParserState::WaitIronwoodZip32Derivation;

        Ok(())
    }

    #[inline(never)]
    pub(super) fn parse_ironwood_output(
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
            "PCZT ironwood action #{} cmx: {}",
            self.ironwood_action_parsed_count,
            HexSlice(&self.current_action.cmx)
        );

        ok!(reader.read_exact(&mut self.current_action.ephemeral_key));
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .update(&self.current_action.ephemeral_key));
        debug!(
            "PCZT ironwood action #{} ephemeral_key: {}",
            self.ironwood_action_parsed_count,
            HexSlice(&self.current_action.ephemeral_key)
        );

        Self::ensure_ironwood_apdu_group_end(reader)?;
        self.state = PcztParserState::WaitIronwoodEncCiphertextLen;

        Ok(())
    }

    #[inline(never)]
    pub(super) fn parse_ironwood_output_metadata(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        const OUTPUT_METADATA_WITHOUT_RCV_LEN: usize = ORCHARD_RAW_ADDRESS_SIZE + 8 + 32;
        const OUTPUT_METADATA_WITH_RCV_LEN: usize = OUTPUT_METADATA_WITHOUT_RCV_LEN + 32;
        const OUTPUT_METADATA_WITH_NOTE_VERSION_LEN: usize = OUTPUT_METADATA_WITH_RCV_LEN + 1;

        let has_note_version = match reader.remaining_len() {
            OUTPUT_METADATA_WITHOUT_RCV_LEN => {
                return Err(ParserError::from_str("Missing PCZT ironwood rcv"));
            }
            OUTPUT_METADATA_WITH_RCV_LEN => false,
            OUTPUT_METADATA_WITH_NOTE_VERSION_LEN => true,
            _ => {
                return Err(ParserError::from_str(
                    "Bad PCZT ironwood output metadata length",
                ));
            }
        };

        self.read_ironwood_output_fields(reader)?;

        if has_note_version {
            self.current_action.note_plaintext_version = ok!(reader.read_u8());
            // The Ironwood value pool carries V3 note plaintexts only, so a metadata byte
            // announcing anything else describes a note this bundle cannot hold.
            if self.current_action.note_plaintext_version != NOTE_VERSION_IRONWOOD {
                return Err(ParserError::from_str(
                    "Bad PCZT ironwood notePlaintextVersion",
                ));
            }
        }

        Self::ensure_ironwood_apdu_group_end(reader)?;
        self.finish_current_ironwood_action(ctx)
    }

    /// Reads the fields common to both the 115-byte and 116-byte output-metadata packets:
    /// `output_recipient`, `output_value`, `output_rseed`, and `rcv`.
    fn read_ironwood_output_fields(
        &mut self,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        ok!(reader.read_exact(&mut self.current_action.output_recipient));
        debug!(
            "PCZT ironwood action #{} recipient: {}",
            self.ironwood_action_parsed_count,
            HexSlice(&self.current_action.output_recipient)
        );

        self.current_action.output_value = self.read_ironwood_value(
            reader,
            "Bad PCZT ironwood output value",
            "PCZT ironwood output value out of range",
        )?;
        debug!(
            "PCZT ironwood action #{} output value: {}",
            self.ironwood_action_parsed_count, self.current_action.output_value
        );

        let mut rseed = [0u8; 32];
        ok!(reader.read_exact(&mut rseed));
        debug!(
            "PCZT ironwood action #{} output rseed: {}",
            self.ironwood_action_parsed_count,
            HexSlice(&rseed)
        );
        self.current_action.output_rseed = Some(rseed);

        let mut rcv = [0u8; 32];
        ok!(reader.read_exact(&mut rcv));
        debug!(
            "PCZT ironwood action #{} rcv: {}",
            self.ironwood_action_parsed_count,
            HexSlice(&rcv)
        );
        self.current_action.rcv = Some(rcv);

        Ok(())
    }

    pub(super) fn parse_ironwood_enc_ciphertext_len(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let size: usize = ok!(CompactSize::read_t(&mut *reader));

        if size != ORCHARD_ENC_CIPHERTEXT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT ironwood enc_ciphertext size",
            ));
        }

        debug!(
            "PCZT ironwood action #{} enc_ciphertext size: {}",
            self.ironwood_action_parsed_count, size
        );

        self.state = PcztParserState::ProcessIronwoodEncCiphertext;
        if reader.remaining_len() == 0 {
            return Err(ParserError::from_str(
                "Missing PCZT ironwood enc_ciphertext bytes",
            ));
        }

        self.parse_ironwood_enc_ciphertext(ctx, reader)
    }

    pub(super) fn parse_ironwood_enc_ciphertext(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let Some(bytes) = self.read_large_ironwood_vec(reader, ORCHARD_ENC_CIPHERTEXT_SIZE)? else {
            return Ok(());
        };

        self.finish_ironwood_enc_ciphertext(ctx, bytes)?;
        Self::ensure_ironwood_apdu_group_end(reader)
    }

    pub(super) fn parse_ironwood_out_ciphertext_len(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let size: usize = ok!(CompactSize::read_t(&mut *reader));

        if size != ORCHARD_OUT_CIPHERTEXT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT ironwood out_ciphertext size",
            ));
        }

        debug!(
            "PCZT ironwood action #{} out_ciphertext size: {}",
            self.ironwood_action_parsed_count, size
        );

        self.state = PcztParserState::ProcessIronwoodOutCiphertext;
        if reader.remaining_len() == 0 {
            return Err(ParserError::from_str(
                "Missing PCZT ironwood out_ciphertext bytes",
            ));
        }

        self.parse_ironwood_out_ciphertext(ctx, reader)
    }

    pub(super) fn parse_ironwood_out_ciphertext(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let Some(bytes) = self.read_large_ironwood_vec(reader, ORCHARD_OUT_CIPHERTEXT_SIZE)? else {
            return Ok(());
        };

        self.finish_ironwood_out_ciphertext(ctx, bytes)?;
        Self::ensure_ironwood_apdu_group_end(reader)
    }

    pub(super) fn parse_ironwood_trailer(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let flags = ok!(orchard_component::read_flags(
            &mut *reader,
            BundleVersion::ironwood_v3()
        ));
        self.current_action.flags = ok!(
            flags.to_byte(BundleVersion::ironwood_v3()).ok_or(()),
            "invalid Ironwood flags"
        );
        debug!("PCZT ironwood flags: {:02x}", self.current_action.flags);

        self.current_action.value_sum_magnitude = ok!(reader.read_u64_le());
        debug!(
            "PCZT ironwood value_sum magnitude: {}",
            self.current_action.value_sum_magnitude
        );

        self.finish_ironwood_value_sum_sign(ok!(reader.read_u8()))?;

        let mut anchor = [0u8; 32];
        ok!(reader.read_exact(&mut anchor));
        Self::ensure_ironwood_apdu_group_end(reader)?;
        self.finish_ironwood_anchor(ctx, &anchor)
    }

    fn ensure_ironwood_apdu_group_end(reader: &ByteReader<'_>) -> Result<(), ParserError> {
        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected data after PCZT ironwood APDU field group",
            ));
        }

        Ok(())
    }

    fn read_ironwood_value(
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
    /// Reuses `pool_field_bytes`, the same buffer used by `read_large_orchard_vec`. This is
    /// safe because Ironwood parsing only begins after Orchard parsing is complete (enforced by
    /// the state machine: only reachable from `OrchardActionsDone`), and each successful read
    /// drains the buffer via `mem::take`.
    fn read_large_ironwood_vec(
        &mut self,
        reader: &mut ByteReader<'_>,
        size: usize,
    ) -> Result<Option<Vec<u8>>, ParserError> {
        let missing = size.saturating_sub(self.pool_field_bytes.len());

        if missing > 0 {
            let to_read = cmp::min(missing, reader.remaining_len());
            if to_read == 0 {
                debug!(
                    "Need more PCZT ironwood Vec bytes, currently read: {}",
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

    pub(super) fn reset_current_ironwood_action(&mut self) {
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
        self.current_action.note_plaintext_version = NOTE_VERSION_IRONWOOD;
    }

    pub(super) fn reset_ironwood_bundle_state(&mut self, action_count: usize) {
        self.ironwood_action_count = action_count;
        self.ironwood_action_parsed_count = 0;
        self.ironwood_real_spend_count = 0;
        for record in self.ironwood_signing_records.iter_mut() {
            record.alpha = [0u8; 32];
        }
        self.ironwood_signing_records.clear();
        self.ironwood_signed_action_count = 0;
        self.ironwood_signature_digest = None;
        self.ironwood_value_balance = 0;
        self.ironwood_spend_value_sum = 0;
        self.ironwood_output_value_sum = 0;
        self.current_action.flags = 0;
        self.current_action.value_sum_magnitude = 0;
        self.reset_current_ironwood_action();
        self.pool_field_bytes.clear();
    }

    #[inline(never)]
    fn finish_ironwood_enc_ciphertext(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        enc_ciphertext: Vec<u8>,
    ) -> Result<(), ParserError> {
        if enc_ciphertext.len() != ORCHARD_ENC_CIPHERTEXT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT ironwood enc_ciphertext length",
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
            "PCZT ironwood action #{} enc_ciphertext data hashed",
            self.ironwood_action_parsed_count
        );

        self.current_action.enc_ciphertext = enc_ciphertext;
        self.state = PcztParserState::WaitIronwoodOutCiphertextLen;

        Ok(())
    }

    #[inline(never)]
    fn finish_ironwood_out_ciphertext(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        out_ciphertext: Vec<u8>,
    ) -> Result<(), ParserError> {
        if out_ciphertext.len() != ORCHARD_OUT_CIPHERTEXT_SIZE {
            return Err(ParserError::from_str(
                "Bad PCZT ironwood out_ciphertext length",
            ));
        }

        let out_ciphertext: [u8; ORCHARD_OUT_CIPHERTEXT_SIZE] = out_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| ParserError::from_str("Bad PCZT ironwood out_ciphertext length"))?;

        ok!(ctx.hashers.tx_non_compact_hasher.update(&out_ciphertext));

        self.current_action.out_ciphertext = Some(out_ciphertext);
        self.state = PcztParserState::WaitIronwoodOutputMetadata;

        Ok(())
    }

    #[inline(never)]
    fn finish_current_ironwood_action(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        let out_ciphertext = self
            .current_action
            .out_ciphertext
            .ok_or_else(|| ParserError::from_str("Missing PCZT ironwood out_ciphertext"))?;
        if self.current_action.enc_ciphertext.len() != ORCHARD_ENC_CIPHERTEXT_SIZE {
            return Err(ParserError::from_str(
                "Missing PCZT ironwood enc_ciphertext for decryption",
            ));
        }

        self.verify_current_ironwood_cv_net()?;
        // A dummy padding spend uses a throwaway key, so recipient membership and
        // nullifier can only be checked on real spends. `spend_value` is not merely
        // declared: `cv_net` above binds it and `validate_current_ironwood_output`
        // below pins `output_value`, so a real spend cannot pose as a dummy.
        // V2 and V3 dummies both have their cmx recomputed and verified.
        let is_real_spend = self.current_action.spend_value != 0;
        if is_real_spend {
            let ironwood_fvk = self
                .current_action
                .fvk
                .as_ref()
                .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?;
            self.verify_current_ironwood_spend_nullifier(ironwood_fvk)?;
            self.ironwood_real_spend_count = self.ironwood_real_spend_count.saturating_add(1);
        }
        // Lend the enc_ciphertext buffer out of `self` for the validation call: it already
        // lives on the heap, so borrowing it keeps 580 bytes off this frame while the
        // validation path still takes `&mut self`. It returns with its capacity intact.
        let enc_ciphertext = core::mem::take(&mut self.current_action.enc_ciphertext);
        let validated =
            self.validate_current_ironwood_output(ctx, &enc_ciphertext, &out_ciphertext);
        self.current_action.enc_ciphertext = enc_ciphertext;
        validated?;

        self.ironwood_spend_value_sum = self
            .ironwood_spend_value_sum
            .checked_add(self.current_action.spend_value)
            .ok_or_else(|| ParserError::from_str("PCZT ironwood spend value sum overflow"))?;
        self.ironwood_output_value_sum = self
            .ironwood_output_value_sum
            .checked_add(self.current_action.output_value)
            .ok_or_else(|| ParserError::from_str("PCZT ironwood output value sum overflow"))?;

        debug!(
            "PCZT ironwood action #{} non-compact data hashed",
            self.ironwood_action_parsed_count
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

        self.ironwood_signing_records
            .push(PcztIronwoodActionSigningRecord {
                alpha,
                path,
                is_real_spend,
                signed: false,
            });
        self.reset_current_ironwood_action();
        self.ironwood_action_parsed_count = self.ironwood_action_parsed_count.saturating_add(1);

        if self.ironwood_action_parsed_count == self.ironwood_action_count {
            self.state = PcztParserState::WaitIronwoodTrailer;
        } else {
            self.state = PcztParserState::WaitIronwoodAction;
        }

        Ok(())
    }

    fn current_ironwood_compact_action(&self, enc_ciphertext: &[u8]) -> OrchardCompactAction {
        let mut enc_ciphertext_prefix = [0u8; ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE];
        enc_ciphertext_prefix
            .copy_from_slice(&enc_ciphertext[..ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE]);

        OrchardCompactAction {
            nullifier: self.current_action.nullifier,
            cmx: self.current_action.cmx,
            ephemeral_key: self.current_action.ephemeral_key,
            enc_ciphertext_prefix,
        }
    }

    #[inline(never)]
    fn try_decipher_current_ironwood_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        enc_ciphertext: &[u8],
        out_ciphertext: &[u8; ORCHARD_OUT_CIPHERTEXT_SIZE],
    ) -> Result<bool, ParserError> {
        let Some(keys) = ctx.tx_info.orchard_decipher_keys.as_ref() else {
            debug!("No PCZT ironwood decipher keys available");
            return Ok(false);
        };

        let compact = self.current_ironwood_compact_action(enc_ciphertext);
        let network = keys.network;

        match decipher_compact_value(&keys.internal_ivk, &compact, NOTE_VERSION_IRONWOOD) {
            Ok(Some(output)) => {
                self.validate_deciphered_ironwood_output(&output)?;
                self.push_deciphered_ironwood_output(ctx, output, network, true)?;
                return Ok(true);
            }
            Ok(None) => debug!("PCZT ironwood internal IVK decryption did not match"),
            Err(ledger_zcash_crypto::Error::OutOfMemory) => {
                return Err(ParserError::from_sw(AppSW::NotEnoughMemorySpace));
            }
            Err(err) => debug!("PCZT ironwood compact decryption failed: {:?}", err),
        }

        let action = OrchardActionCiphertext {
            compact,
            rk: self.current_action.rk,
            cv_net: self.current_action.cv_net,
            enc_ciphertext,
            out_ciphertext: *out_ciphertext,
        };

        match decipher_value_with_ovk(&keys.external_ovk, &action, NOTE_VERSION_IRONWOOD) {
            Ok(Some(output)) => {
                self.validate_deciphered_ironwood_output(&output)?;
                self.push_deciphered_ironwood_output(ctx, output, network, false)?;
                return Ok(true);
            }
            Ok(None) => debug!("PCZT ironwood external OVK recovery did not match"),
            Err(ledger_zcash_crypto::Error::OutOfMemory) => {
                return Err(ParserError::from_sw(AppSW::NotEnoughMemorySpace));
            }
            Err(err) => debug!("PCZT ironwood OVK recovery failed: {:?}", err),
        }

        Ok(false)
    }

    #[inline(never)]
    fn validate_current_ironwood_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        enc_ciphertext: &[u8],
        out_ciphertext: &[u8; ORCHARD_OUT_CIPHERTEXT_SIZE],
    ) -> Result<(), ParserError> {
        if self.try_decipher_current_ironwood_output(ctx, enc_ciphertext, out_ciphertext)? {
            return Ok(());
        }

        if self.validate_current_ironwood_dummy_output()? {
            return Ok(());
        }

        Err(ParserError::from_str(
            "PCZT ironwood output could not be decrypted",
        ))
    }

    #[inline(never)]
    fn validate_current_ironwood_dummy_output(&self) -> Result<bool, ParserError> {
        if self.current_action.output_value != 0 {
            return Ok(false);
        }

        let Some(rseed) = self.current_action.output_rseed else {
            return Err(ParserError::from_str("Missing PCZT ironwood output rseed"));
        };

        // Ironwood dummies are V3 notes like every other note in this pool, so the commitment
        // uses the V3 trapdoor unconditionally.
        let expected_cmx = ledger_zcash_crypto::orchard_note_commitment_v3_bytes(
            &self.current_action.output_recipient,
            self.current_action.output_value,
            &self.current_action.nullifier,
            &rseed,
        )
        .map_err(Self::map_ironwood_commitment_error)?;

        if expected_cmx != self.current_action.cmx {
            debug!(
                "PCZT ironwood dummy output cmx mismatch: expected {}, actual {}",
                HexSlice(&expected_cmx),
                HexSlice(&self.current_action.cmx)
            );
            return Err(ParserError::from_str(
                "PCZT ironwood dummy output cmx mismatch",
            ));
        }

        debug!("PCZT ironwood dummy output accepted");
        Ok(true)
    }

    fn map_ironwood_commitment_error(err: ledger_zcash_crypto::Error) -> ParserError {
        match err {
            ledger_zcash_crypto::Error::MalformedPallasBase => {
                ParserError::from_str("Bad PCZT ironwood dummy nullifier")
            }
            ledger_zcash_crypto::Error::MalformedPallasPoint
            | ledger_zcash_crypto::Error::InvalidDiversifyHashPoint => {
                ParserError::from_str("Bad PCZT ironwood output recipient")
            }
            ledger_zcash_crypto::Error::MalformedPallasScalar
            | ledger_zcash_crypto::Error::InvalidKeyDiscarded => {
                ParserError::from_str("Bad PCZT ironwood output rseed")
            }
            _ => ParserError::from_sw(AppSW::TechnicalProblem),
        }
    }

    fn validate_deciphered_ironwood_output(
        &self,
        output: &DecipheredOrchardOutput,
    ) -> Result<(), ParserError> {
        if output.value != self.current_action.output_value {
            return Err(ParserError::from_str("PCZT ironwood output value mismatch"));
        }

        if output.raw_address != self.current_action.output_recipient {
            debug!(
                "PCZT ironwood output recipient mismatch: expected {}, decrypted {}",
                HexSlice(&self.current_action.output_recipient),
                HexSlice(&output.raw_address)
            );
            return Err(ParserError::from_str(
                "PCZT ironwood output recipient mismatch",
            ));
        }

        Ok(())
    }

    fn ironwood_output_memo_display(
        output: &DecipheredOrchardOutput,
        is_change: bool,
    ) -> Result<Option<TxOutputMemo>, ParserError> {
        if is_change {
            return Ok(None);
        }

        let Some(memo) = output.memo.as_ref() else {
            return Ok(None);
        };

        Self::ironwood_memo_display(memo)
    }

    fn ironwood_memo_display(memo: &[u8]) -> Result<Option<TxOutputMemo>, ParserError> {
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
            && Self::is_ironwood_displayable_ascii_memo(text)
        {
            return Ok(Some(TxOutputMemo::text(text.to_string())));
        }

        let mut hasher = Blake2b_256::default();
        ok!(hasher.update(memo));
        let mut hash = [0u8; 32];
        ok!(hasher.finalize(&mut hash));
        Ok(Some(TxOutputMemo::hash(format!("{}", HexSlice(&hash)))))
    }

    fn is_ironwood_displayable_ascii_memo(text: &str) -> bool {
        text.bytes().all(|byte| matches!(byte, 0x20..=0x7E))
    }

    fn push_deciphered_ironwood_output(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        output: DecipheredOrchardOutput,
        network: NetworkType,
        is_change: bool,
    ) -> Result<(), ParserError> {
        if is_change && ctx.tx_info.is_change_found {
            return Err(ParserError::from_str("Multiple change outputs detected"));
        }

        // Ironwood reuses the Orchard UA receiver typecode (0x03) — ZIP 229 defines no
        // distinct typecode for Ironwood; addresses are encoded identically to Orchard receivers.
        let address =
            UnifiedAddress::try_from_items(alloc::vec![Receiver::Orchard(output.raw_address)])
                .map(|address| address.encode(&network))
                // No fallback string: a recipient the user cannot check against their own
                // wallet is worse than refusing to sign.
                .map_err(|_| ParserError::from_str("Cannot encode PCZT ironwood output address"))?;
        let memo = Self::ironwood_output_memo_display(&output, is_change)?;

        debug!(
            "PCZT ironwood output address: {}, amount: {}, change: {}",
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
    fn verify_current_ironwood_cv_net(&self) -> Result<(), ParserError> {
        let Some(rcv_bytes) = self.current_action.rcv else {
            return Err(ParserError::from_str("Missing PCZT ironwood rcv"));
        };

        let value_net = i128::from(self.current_action.spend_value)
            - i128::from(self.current_action.output_value);
        let value_net = i64::try_from(value_net)
            .map_err(|_| ParserError::from_str("PCZT ironwood cv_net value out of range"))?;
        let expected_cv_net = ledger_zcash_crypto::orchard_value_commitment_bytes(
            value_net, &rcv_bytes,
        )
        .map_err(|err| match err {
            ledger_zcash_crypto::Error::MalformedPallasScalar => {
                ParserError::from_str("Bad PCZT ironwood rcv")
            }
            _ => ParserError::from_sw(AppSW::TechnicalProblem),
        })?;

        if expected_cv_net != self.current_action.cv_net {
            debug!(
                "PCZT ironwood cv_net mismatch: expected {}, actual {}",
                HexSlice(&expected_cv_net),
                HexSlice(&self.current_action.cv_net)
            );
            return Err(ParserError::from_str("PCZT ironwood cv_net mismatch"));
        }

        Ok(())
    }

    #[inline(never)]
    fn verify_current_ironwood_spend_nullifier(&self, fvk: &OrchardFvk) -> Result<(), ParserError> {
        let mut diversifier = [0u8; 11];
        diversifier.copy_from_slice(&self.current_action.spend_recipient[..11]);

        let mut claimed_pk_d = [0u8; 32];
        claimed_pk_d.copy_from_slice(&self.current_action.spend_recipient[11..]);

        if !self.is_current_ironwood_spend_recipient_in_fvk(fvk, &diversifier, &claimed_pk_d)? {
            return Err(ParserError::from_str(
                "PCZT ironwood spend does not belong to signing key",
            ));
        }

        let fvk_bytes = fvk.to_bytes();
        let nk: [u8; 32] = fvk_bytes[32..64]
            .try_into()
            .map_err(|_| ParserError::from_sw(AppSW::TechnicalProblem))?;
        let expected_nullifier = ledger_zcash_crypto::orchard_spend_nullifier_bytes_v3(
            &nk,
            &self.current_action.spend_recipient,
            self.current_action.spend_value,
            &self.current_action.spend_rho,
            &self.current_action.spend_rseed,
        )
        .map_err(|err| match err {
            ledger_zcash_crypto::Error::MalformedPallasBase => {
                ParserError::from_str("Bad PCZT ironwood spend rho")
            }
            ledger_zcash_crypto::Error::MalformedPallasPoint
            | ledger_zcash_crypto::Error::InvalidDiversifyHashPoint => {
                ParserError::from_str("Bad PCZT ironwood spend recipient")
            }
            ledger_zcash_crypto::Error::InvalidKeyDiscarded => {
                ParserError::from_str("Bad PCZT ironwood spend rseed")
            }
            _ => ParserError::from_sw(AppSW::TechnicalProblem),
        })?;

        if expected_nullifier != self.current_action.nullifier {
            debug!(
                "PCZT ironwood nullifier mismatch: expected {}, actual {}",
                HexSlice(&expected_nullifier),
                HexSlice(&self.current_action.nullifier)
            );
            return Err(ParserError::from_str("PCZT ironwood nullifier mismatch"));
        }

        Ok(())
    }

    fn is_current_ironwood_spend_recipient_in_fvk(
        &self,
        fvk: &OrchardFvk,
        diversifier: &[u8; 11],
        claimed_pk_d: &[u8; 32],
    ) -> Result<bool, ParserError> {
        let g_d = ledger_zcash_crypto::diversify_hash_ledger(diversifier)
            .map_err(|_| ParserError::from_str("Bad PCZT ironwood spend recipient"))?;

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

    fn finish_ironwood_value_sum_sign(&mut self, sign_byte: u8) -> Result<(), ParserError> {
        let magnitude = i64::try_from(self.current_action.value_sum_magnitude)
            .map_err(|_| ParserError::from_str("PCZT ironwood value_sum out of range"))?;

        self.ironwood_value_balance = match sign_byte {
            0 => magnitude,
            1 => -magnitude,
            _ => return Err(ParserError::from_str("Bad PCZT ironwood value_sum sign")),
        };

        debug!(
            "PCZT ironwood value balance: {}",
            self.ironwood_value_balance
        );

        let expected_value_balance =
            i128::from(self.ironwood_spend_value_sum) - i128::from(self.ironwood_output_value_sum);
        if expected_value_balance != i128::from(self.ironwood_value_balance) {
            debug!(
                "PCZT ironwood value balance mismatch: spend_sum={}, output_sum={}, value_balance={}",
                self.ironwood_spend_value_sum,
                self.ironwood_output_value_sum,
                self.ironwood_value_balance
            );
            return Err(ParserError::from_str("PCZT ironwood value_sum mismatch"));
        }

        Ok(())
    }

    #[inline(never)]
    fn verify_current_ironwood_rk(&self, ask: &OrchardAsk) -> Result<(), ParserError> {
        let alpha = self
            .current_action
            .alpha
            .ok_or_else(|| ParserError::from_sw(AppSW::BadState))?;

        let alpha = ledger_zcash_crypto::pallas_scalar_from_repr(alpha)
            .map_err(|_| ParserError::from_str("Bad PCZT ironwood alpha"))?;

        // Compute rk bytes directly, as the Orchard path does: no intermediate
        // curve-point construction, keeping the BN/point footprint low here.
        let expected_rk = ask
            .randomized_verification_key_bytes(&alpha)
            .map_err(|_| ParserError::from_sw(AppSW::TechnicalProblem))?;

        if expected_rk != self.current_action.rk {
            return Err(ParserError::from_str(
                "PCZT ironwood rk does not match alpha and signing key",
            ));
        }

        Ok(())
    }

    #[inline(never)]
    fn finish_ironwood_anchor(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        anchor: &[u8; 32],
    ) -> Result<(), ParserError> {
        debug!("PCZT ironwood anchor: {}", HexSlice(anchor));

        let ironwood_compact_digest = finalize_and_log_hash(
            &mut ctx.hashers.tx_compact_hasher,
            "PCZT ironwood compact digest",
        )?;
        let ironwood_memo_digest =
            finalize_and_log_hash(&mut ctx.hashers.tx_memo_hasher, "PCZT ironwood memo digest")?;
        let ironwood_non_compact_digest = finalize_and_log_hash(
            &mut ctx.hashers.tx_non_compact_hasher,
            "PCZT ironwood non compact digest",
        )?;

        ok!(ctx.hashers.ironwood_hasher.update(&ironwood_compact_digest));
        ok!(ctx.hashers.ironwood_hasher.update(&ironwood_memo_digest));
        ok!(ctx
            .hashers
            .ironwood_hasher
            .update(&ironwood_non_compact_digest));

        ok!(ctx
            .hashers
            .ironwood_hasher
            .update(&[self.current_action.flags]));
        ok!(ctx
            .hashers
            .ironwood_hasher
            .update(&self.ironwood_value_balance.to_le_bytes()));
        // Anchor goes to the authorizing-data digest only — never included in the sighash.
        ok!(ctx
            .hashers
            .ironwood_hasher
            .finalize(&mut ctx.tx_info.ironwood_digest));

        debug!(
            "PCZT ironwood digest: {}",
            HexSlice(&ctx.tx_info.ironwood_digest)
        );

        self.finalize_ironwood_actions(ctx)
    }

    pub(super) fn parse_ironwood_zip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let derivation_len = {
            let derivation = reader.remaining_slice();
            if derivation.is_empty() {
                return Err(ParserError::from_str(
                    "Missing PCZT ironwood zip32 derivation bytes",
                ));
            }

            let derivation_len = derivation.len();
            self.finish_ironwood_zip32_derivation(ctx, derivation)?;
            derivation_len
        };
        ok!(reader.advance(derivation_len));

        if reader.remaining_len() != 0 {
            return Err(ParserError::from_str(
                "Unexpected data after PCZT ironwood zip32 derivation",
            ));
        }

        Ok(())
    }

    #[inline(never)]
    fn finish_ironwood_zip32_derivation(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
        derivation: &[u8],
    ) -> Result<(), ParserError> {
        let path =
            Bip32Path::try_from(derivation.get(ZIP32_SEED_FINGERPRINT_SIZE..).unwrap_or(&[]))
                .map_err(|_| ParserError::from_str("Bad PCZT ironwood zip32 derivation path"))?;
        let seed_fingerprint = &derivation[..ZIP32_SEED_FINGERPRINT_SIZE];

        if !check_bip44_compliance(&path, Bip44CheckMode::OnlyCoinType) {
            return Err(ParserError::from_str(
                "PCZT ironwood signing path not compliant",
            ));
        }

        debug!(
            "PCZT ironwood action #{} zip32 seed fingerprint: {}",
            self.ironwood_action_parsed_count,
            HexSlice(seed_fingerprint)
        );
        debug!(
            "PCZT ironwood action #{} signing path: {:?}",
            self.ironwood_action_parsed_count, path
        );

        // Derive the FVK (and the ASK, for real spends only) from the session-cached
        // account spending key: `zip32_orchard_derive` does not reclaim its SE
        // resources between calls, so deriving per action exhausts them and the
        // next one fails with 6f00.
        let spend_value = self.current_action.spend_value;
        let sk = ok!(self.orchard_spending_key(&path));
        let (orchard_fvk, ask_for_rk) = if spend_value != 0 {
            let (fvk, ask) =
                derive_orchard_fvk_and_ask_from_sk(sk).map_err(ParserError::from_sw)?;
            (fvk, Some(ask))
        } else {
            (ok!(derive_orchard_fvk_from_sk(sk)), None)
        };
        if let Some(ref ask) = ask_for_rk {
            self.verify_current_ironwood_rk(ask)?;
        }
        let network = orchard_network(&path);
        ctx.tx_info.orchard_decipher_keys =
            Some(ok!(OrchardDecipherKeys::from_fvk(&orchard_fvk, network)));
        debug!(
            "PCZT ironwood action #{} decipher keys prepared",
            self.ironwood_action_parsed_count
        );

        self.current_action.path = Some(path);
        self.current_action.fvk = Some(orchard_fvk);
        self.state = PcztParserState::WaitIronwoodOutput;

        Ok(())
    }

    pub fn ensure_signature_digest_for_ironwood(
        &mut self,
        tx_info: &mut TxInfo,
        action_index: usize,
    ) -> Result<(), ParserError> {
        if !self.is_finished() {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        let action = self
            .ironwood_signing_records
            .get(action_index)
            .ok_or_else(|| ParserError::from_str("Bad PCZT ironwood action index"))?;

        if action.signed {
            return Err(ParserError::from_str("PCZT ironwood action already signed"));
        }

        // A dummy padding spend is parsed without its rk and nullifier checks and is
        // already self-signed host-side, so signing it would authorize an unverified
        // spend side and overshoot the expected signature count. Enforce the host's
        // contract to skip dummy indices rather than trust it.
        if !action.is_real_spend {
            return Err(ParserError::from_str(
                "PCZT ironwood dummy spend must not be signed by the device",
            ));
        }

        if let Some(signature_digest) = self.ironwood_signature_digest {
            tx_info.signature_digest = signature_digest;
        } else {
            compute_shielded_signature_digest(
                tx_info,
                self.transparent_input_count,
                self.transparent_output_count,
            )?;
            self.ironwood_signature_digest = Some(tx_info.signature_digest);
        }

        debug!(
            "Computed PCZT shielded signature digest for Ironwood action #{} signing: {}",
            action_index,
            HexSlice(&tx_info.signature_digest)
        );

        Ok(())
    }

    pub fn ironwood_action_signing_data(
        &self,
        action_index: usize,
    ) -> Result<(&Bip32Path, [u8; 32]), ParserError> {
        if !self.is_ready_to_sign() {
            return Err(ParserError::from_sw(AppSW::BadState));
        }

        let action = self
            .ironwood_signing_records
            .get(action_index)
            .ok_or_else(|| ParserError::from_str("Bad PCZT ironwood action index"))?;

        Ok((&action.path, action.alpha))
    }

    pub fn ironwood_signature_count(&self) -> usize {
        // Only real spends are signed, so the quota must exclude dummy padding
        // actions — otherwise the session would never reach "signatures done".
        self.ironwood_real_spend_count
    }

    pub fn mark_ironwood_action_signed(
        &mut self,
        action_index: usize,
    ) -> Result<usize, ParserError> {
        let action = self
            .ironwood_signing_records
            .get_mut(action_index)
            .ok_or_else(|| ParserError::from_str("Bad PCZT ironwood action index"))?;

        if action.signed {
            return Err(ParserError::from_str("PCZT ironwood action already signed"));
        }

        action.signed = true;
        action.alpha = [0u8; 32];

        self.ironwood_signed_action_count = self.ironwood_signed_action_count.saturating_add(1);

        // Both pools sign with the same account spending key, so it may only be
        // zeroized once neither of them has a signature left to produce.
        if self.are_orchard_signatures_done() && self.are_ironwood_signatures_done() {
            self.clear_orchard_spending_key();
        }

        Ok(self.ironwood_signed_action_count)
    }

    pub fn are_ironwood_signatures_done(&self) -> bool {
        !self.has_ironwood_bundle
            || self.ironwood_signed_action_count >= self.ironwood_signature_count()
    }

    fn finalize_ironwood_actions(
        &mut self,
        ctx: &mut PcztParserCtx<'_>,
    ) -> Result<(), ParserError> {
        debug!("PCZT ironwood actions hashing done");

        self.state = PcztParserState::IronwoodActionsDone;
        self.review_outputs(ctx)?;

        // V6 defers the Orchard review here, so this is the last parse step: both
        // real-spend counts are final. When no signature will follow (every spend
        // is dummy padding) `mark_*_action_signed` never runs, so release the
        // cached account spending key now instead of keeping it for the session.
        if self.are_orchard_signatures_done() && self.are_ironwood_signatures_done() {
            self.clear_orchard_spending_key();
        }

        Ok(())
    }
}
