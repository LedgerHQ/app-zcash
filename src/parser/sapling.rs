use zcash_primitives::transaction::txid::ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION;
use zcash_primitives::transaction::txid::ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION;
use zcash_primitives::transaction::txid::{
    ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION, ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION,
    ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION,
};
use zcash_primitives::transaction::txid::{
    ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION, ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION,
};
use zcash_protocol::value::ZatBalance;

use super::personalization::ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION_V6;
use super::*;

const SAPLING_CMU_SIZE: usize = HASH_SIZE;
const SAPLING_EPHEMERAL_KEY_SIZE: usize = HASH_SIZE;
const SAPLING_COMPACT_ENC_CIPHERTEXT_SIZE: usize = 52;
const SAPLING_OUT_CIPHERTEXT_SIZE: usize = 16;
const SAPLING_ZKPROOF_SIZE: usize = 80;
const SAPLING_OUTPUTS_COMPACT_SIZE: usize =
    SAPLING_CMU_SIZE + SAPLING_EPHEMERAL_KEY_SIZE + SAPLING_COMPACT_ENC_CIPHERTEXT_SIZE;
const SAPLING_OUTPUTS_NONCOMPACT_SIZE: usize =
    SAPLING_CMU_SIZE + SAPLING_OUT_CIPHERTEXT_SIZE + SAPLING_ZKPROOF_SIZE;
const SAPLING_MEMO_SIZE: usize = 512;

impl Parser {
    pub fn parse_sapling(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Process sapling");

        let sapling_balance: ZatBalance = ok!({
            let mut tmp = [0u8; 8];
            ok!(reader.read_exact(&mut tmp));
            ZatBalance::from_i64_le_bytes(tmp)
        });

        info!("Sapling balance: {:?}", sapling_balance);
        self.sapling_balance = sapling_balance.into();

        if self.sapling_spend_count > 0 {
            // In v6 the Sapling anchor is authorizing data (ZIP-229), so it is neither
            // hashed into the spends non-compact digest nor streamed by the host, and
            // that digest takes its own personalization. v4 and v5 are unchanged.
            let (anchor, non_compact_personalization) = match ctx.tx_info.tx_version() {
                SupportedTxVersion::V6 => (
                    None,
                    ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION_V6,
                ),
                SupportedTxVersion::V4 | SupportedTxVersion::V5 => {
                    let mut anchor = [0u8; 32];
                    ok!(reader.read_exact(&mut anchor));
                    (
                        Some(anchor),
                        ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION,
                    )
                }
            };

            // Init hashers
            ok!(ctx
                .hashers
                .tx_compact_hasher
                .init_with_perso(ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION));
            ok!(ctx
                .hashers
                .tx_non_compact_hasher
                .init_with_perso(non_compact_personalization));

            self.state = ParserState::ProcessSaplingSpends { anchor };
        } else if self.sapling_output_count > 0 {
            // No spends
            // Get empty sapling spends digest
            let sapling_spend = {
                let mut sapling_spend = [0u8; 32];
                let mut tmp_spend_hasher = Blake2b_256::new();
                ok!(tmp_spend_hasher.init_with_perso(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION));
                ok!(tmp_spend_hasher.finalize(&mut sapling_spend));

                sapling_spend
            };

            // Update sapling hasher with empty spends digest
            ok!(ctx.hashers.sapling_hasher.update(&sapling_spend));

            // Init outputs hasher
            ok!(ctx
                .hashers
                .tx_compact_hasher
                .init_with_perso(ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION));

            self.state = ParserState::ProcessSaplingOutputsCompact;
        } else {
            self.state = ParserState::ProcessExtra;
        }

        Ok(())
    }

    pub fn parse_sapling_spends(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        anchor: Option<[u8; 32]>,
    ) -> Result<(), ParserError> {
        info!(
            "Process sapling spends, remaining: {}",
            self.sapling_spend_count - self.sapling_spend_parsed_count
        );

        // update non compact hash with cv
        ok!(ctx.hashers.tx_non_compact_hasher.update(&{
            let mut tmp = [0u8; 32];
            ok!(reader.read_exact(&mut tmp));
            tmp
        }));

        // update non compact hash with anchor, for v4 and v5 only
        if let Some(anchor) = anchor {
            ok!(ctx.hashers.tx_non_compact_hasher.update(&anchor));
        }

        // update compact hash with nullifier
        ok!(ctx.hashers.tx_compact_hasher.update(&{
            let mut tmp = [0u8; 32];
            ok!(reader.read_exact(&mut tmp));
            tmp
        }));

        // update non compact hash with rk
        ok!(ctx.hashers.tx_non_compact_hasher.update(&{
            let mut tmp = [0u8; 32];
            ok!(reader.read_exact(&mut tmp));
            tmp
        }));

        self.sapling_spend_parsed_count += 1;

        if self.sapling_spend_count == self.sapling_spend_parsed_count {
            info!("All sapling spends parsed");
            self.state = ParserState::ProcessSaplingSpendsHashing;
        }

        Ok(())
    }

    pub fn parse_sapling_spends_hashing(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Process sapling spends hashing");

        // Finalize compact and noncompact sapling spend hashes
        let mut sapling_spend_compact_digest = [0u8; 32];
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .finalize(&mut sapling_spend_compact_digest));
        debug!(
            "Sapling spend compact digest: {}",
            HexSlice(&sapling_spend_compact_digest)
        );

        let mut sapling_spend_non_compact_digest = [0u8; 32];
        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .finalize(&mut sapling_spend_non_compact_digest));
        debug!(
            "Sapling spend non compact digest: {}",
            HexSlice(&sapling_spend_non_compact_digest)
        );

        // Initialize the sapling spend digest context
        let mut tmp_spend_hasher = Blake2b_256::new();
        ok!(tmp_spend_hasher.init_with_perso(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION));
        ok!(tmp_spend_hasher.update(&sapling_spend_compact_digest,));
        ok!(tmp_spend_hasher.update(&sapling_spend_non_compact_digest,));

        let mut sapling_spend = [0u8; 32];
        ok!(tmp_spend_hasher.finalize(&mut sapling_spend));

        debug!("Sapling spend digest: {}", HexSlice(&sapling_spend));

        // Update sapling full hasher with sapling spend digest
        ok!(ctx.hashers.sapling_hasher.update(&sapling_spend));

        if self.sapling_output_count > 0 {
            // Init outputs hasher
            ok!(ctx
                .hashers
                .tx_compact_hasher
                .init_with_perso(ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION));

            self.state = ParserState::ProcessSaplingOutputsCompact;
            return Ok(());
        }

        // Spends without outputs, the shape of a Sapling deshielding transaction.
        // ZIP-244 T.3 still commits to an outputs digest and to valueBalance, so the
        // empty outputs digest stands in and the component is closed here.
        let sapling_output = {
            let mut sapling_output = [0u8; 32];
            let mut tmp_output_hasher = Blake2b_256::new();
            ok!(tmp_output_hasher.init_with_perso(ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION));
            ok!(tmp_output_hasher.finalize(&mut sapling_output));

            sapling_output
        };

        self.finish_sapling(ctx, sapling_output)
    }

    pub fn parse_sapling_outputs_compact(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!(
            "Process sapling outputs compact, remaining: {}",
            self.sapling_output_count - self.sapling_output_parsed_count
        );

        hash_reader_exact(
            reader,
            &mut ctx.hashers.tx_compact_hasher,
            SAPLING_OUTPUTS_COMPACT_SIZE,
            "Not enough data for sapling compact output",
        )?;

        self.sapling_output_parsed_count += 1;

        if self.sapling_output_count == self.sapling_output_parsed_count {
            info!("All sapling compact outputs parsed");
            // Init memo hasher
            ok!(ctx
                .hashers
                .tx_memo_hasher
                .init_with_perso(ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION));

            // memo_size = 512 each APDU will contain quarter of the memo
            self.state = ParserState::ProcessSaplingOutputsMemo {
                size: self.sapling_output_count * SAPLING_MEMO_SIZE,
                remaining_size: self.sapling_output_count * SAPLING_MEMO_SIZE,
            };
        }

        Ok(())
    }

    pub fn parse_sapling_outputs_memo(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        info!(
            "Process sapling outputs memo, remaining size: {}",
            remaining_size
        );

        let new_remaining_size =
            hash_reader_chunk(reader, &mut ctx.hashers.tx_memo_hasher, remaining_size)?;

        if new_remaining_size == 0 {
            info!("All sapling memo data parsed");

            // Init outputs non compact hasher
            ok!(ctx
                .hashers
                .tx_non_compact_hasher
                .init_with_perso(ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION));

            self.sapling_output_parsed_count = 0;
            self.state = ParserState::ProcessSaplingOutputsNonCompact;
        } else {
            self.state = ParserState::ProcessSaplingOutputsMemo {
                size,
                remaining_size: new_remaining_size,
            };
        }

        Ok(())
    }

    pub fn parse_sapling_outputs_non_compact(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!(
            "Process sapling outputs non compact, remaining: {}",
            self.sapling_output_count - self.sapling_output_parsed_count
        );

        hash_reader_exact(
            reader,
            &mut ctx.hashers.tx_non_compact_hasher,
            SAPLING_OUTPUTS_NONCOMPACT_SIZE,
            "Not enough data for sapling non compact output",
        )?;

        self.sapling_output_parsed_count += 1;

        if self.sapling_output_count == self.sapling_output_parsed_count {
            info!("All sapling non compact outputs parsed");
            self.state = ParserState::ProcessSaplingOutputHashing;
        }

        Ok(())
    }

    pub fn parse_sapling_output_hashing(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Finalize sapling outputs hashing");

        // Finalize compact, memo and noncompact sapling output hashes
        let sapling_output_compact_digest = finalize_and_log_hash(
            &mut ctx.hashers.tx_compact_hasher,
            "Sapling output compact digest",
        )?;

        let sapling_output_memo_digest = finalize_and_log_hash(
            &mut ctx.hashers.tx_memo_hasher,
            "Sapling output memo digest",
        )?;

        let sapling_output_non_compact_digest = finalize_and_log_hash(
            &mut ctx.hashers.tx_non_compact_hasher,
            "Sapling output non compact digest",
        )?;

        // Initialize the sapling output digest context
        let mut sapling_output_hasher = Blake2b_256::new();
        ok!(sapling_output_hasher.init_with_perso(ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION));

        ok!(sapling_output_hasher.update(&sapling_output_compact_digest));
        ok!(sapling_output_hasher.update(&sapling_output_memo_digest));
        ok!(sapling_output_hasher.update(&sapling_output_non_compact_digest));

        let mut sapling_output = [0u8; 32];
        ok!(sapling_output_hasher.finalize(&mut sapling_output));
        debug!("Sapling output digest: {}", HexSlice(&sapling_output));

        self.finish_sapling(ctx, sapling_output)
    }

    /// Closes the Sapling component: appends its outputs digest and its value balance
    /// to the Sapling hasher (ZIP-244 T.3), then moves on to the action bundles.
    fn finish_sapling(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        sapling_output_digest: [u8; 32],
    ) -> Result<(), ParserError> {
        // Update sapling full hasher with sapling output digest
        ok!(ctx.hashers.sapling_hasher.update(&sapling_output_digest));
        // Update sapling full hasher with sapling balance
        ok!(ctx
            .hashers
            .sapling_hasher
            .update(&self.sapling_balance.to_le_bytes()));

        self.enter_next_action_bundle(ctx, None)
    }
}
