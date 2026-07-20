//! Ironwood (NU6.3 / V6) PCZT action parser.
//!
//! Structural mirror of `orchard.rs` for the Ironwood pool. Gated entirely on
//! the `zcash_unstable` feature — see `Cargo.toml`.

#[cfg(feature = "zcash_unstable")]
use super::*;

// Stub implementations — replaced with full Ironwood action parsing in the next task.
#[cfg(feature = "zcash_unstable")]
impl PcztParser {
    pub(super) fn parse_ironwood_actions_start(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub(super) fn parse_ironwood_action(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub(super) fn parse_ironwood_zip32_derivation(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub(super) fn parse_ironwood_output(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub(super) fn parse_ironwood_enc_ciphertext_len(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub(super) fn parse_ironwood_enc_ciphertext(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub(super) fn parse_ironwood_out_ciphertext_len(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub(super) fn parse_ironwood_out_ciphertext(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub(super) fn parse_ironwood_output_metadata(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub(super) fn parse_ironwood_trailer(
        &mut self,
        _ctx: &mut PcztParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub fn ensure_signature_digest_for_ironwood(
        &mut self,
        _tx_info: &mut TxInfo,
        _action_index: usize,
    ) -> Result<(), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub fn ironwood_action_signing_data(
        &self,
        _action_index: usize,
    ) -> Result<(&Bip32Path, [u8; 32]), ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub fn ironwood_signature_count(&self) -> usize {
        self.ironwood_action_count
    }

    pub fn mark_ironwood_action_signed(
        &mut self,
        _action_index: usize,
    ) -> Result<usize, ParserError> {
        Err(ParserError::from_sw(AppSW::BadState))
    }

    pub fn are_ironwood_signatures_done(&self) -> bool {
        !self.has_ironwood_bundle
            || self.ironwood_signed_action_count >= self.ironwood_signature_count()
    }
}
