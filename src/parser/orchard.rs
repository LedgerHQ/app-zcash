use ::orchard::bundle::commitments::{
    ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
    ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
};

use super::*;

const ORCHARD_NULLIFIER_SIZE: usize = HASH_SIZE;
const ORCHARD_CMX_SIZE: usize = HASH_SIZE;
const ORCHARD_EPHEMERAL_KEY_SIZE: usize = HASH_SIZE;
const ORCHARD_COMPACT_ENC_CIPHERTEXT_SIZE: usize = 52;
const ORCHARD_OUT_CIPHERTEXT_SIZE: usize = 16;
const ORCHARD_ZKPROOF_SIZE: usize = 80;
const ORCHARD_FLAGS_SIZE: usize = 1;
const ORCHARD_BALANCE_SIZE: usize = 8;
const ORCHARD_ACTIONS_COMPACT_SIZE: usize = ORCHARD_NULLIFIER_SIZE
    + ORCHARD_CMX_SIZE
    + ORCHARD_EPHEMERAL_KEY_SIZE
    + ORCHARD_COMPACT_ENC_CIPHERTEXT_SIZE;
const ORCHARD_ACTIONS_NONCOMPACT_SIZE: usize =
    ORCHARD_NULLIFIER_SIZE + ORCHARD_CMX_SIZE + ORCHARD_OUT_CIPHERTEXT_SIZE + ORCHARD_ZKPROOF_SIZE;
const ORCHARD_DIGEST_DATA_SIZE: usize = ORCHARD_FLAGS_SIZE + ORCHARD_BALANCE_SIZE + HASH_SIZE;
const ORCHARD_MEMO_SIZE: usize = 512;

impl Parser {
    pub fn parse_orchard_compact(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!(
            "Parsing orchard compact action {}/{}",
            self.orchard_action_parsed_count + 1,
            self.orchard_action_count
        );

        hash_reader_exact(
            reader,
            &mut ctx.hashers.tx_compact_hasher,
            ORCHARD_ACTIONS_COMPACT_SIZE,
            "Not enough data for orchard compact output",
        )?;

        self.orchard_action_parsed_count += 1;

        if self.orchard_action_parsed_count == self.orchard_action_count {
            info!("All orchard compact actions parsed");

            ok!(ctx
                .hashers
                .tx_memo_hasher
                .init_with_perso(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION));

            // memo_size = 512 each APDU will contain quarter of the memo
            self.state = ParserState::ProcessOrchardMemo {
                size: self.orchard_action_count * ORCHARD_MEMO_SIZE,
                remaining_size: self.orchard_action_count * ORCHARD_MEMO_SIZE,
            };
        }

        Ok(())
    }

    pub fn parse_orchard_memo(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        info!("Parsing orchard memo, remaining size: {}", remaining_size);

        let new_remaining_size =
            hash_reader_chunk(reader, &mut ctx.hashers.tx_memo_hasher, remaining_size)?;
        if new_remaining_size == 0 {
            info!("All orchard memos parsed");

            ok!(ctx
                .hashers
                .tx_non_compact_hasher
                .init_with_perso(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION));

            self.orchard_action_parsed_count = 0;
            self.state = ParserState::ProcessOrchardNonCompact;
        } else {
            self.state = ParserState::ProcessOrchardMemo {
                size,
                remaining_size: new_remaining_size,
            };
        }

        Ok(())
    }

    pub fn parse_orchard_noncompact(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!(
            "Parsing orchard non-compact action {}/{}",
            self.orchard_action_parsed_count + 1,
            self.orchard_action_count
        );

        hash_reader_exact(
            reader,
            &mut ctx.hashers.tx_non_compact_hasher,
            ORCHARD_ACTIONS_NONCOMPACT_SIZE,
            "Not enough data for orchard non-compact output",
        )?;

        self.orchard_action_parsed_count += 1;

        if self.orchard_action_parsed_count == self.orchard_action_count {
            info!("All orchard non-compact actions parsed");
            self.state = ParserState::ProcessOrchardHashing;
        }

        Ok(())
    }

    pub fn parse_orchard_hashing(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Finalizing orchard hashing");

        let orchard_output_compact_digest =
            finalize_and_log_hash(&mut ctx.hashers.tx_compact_hasher, "Orchard compact digest")?;

        let orchard_output_memo_digest =
            finalize_and_log_hash(&mut ctx.hashers.tx_memo_hasher, "Orchard memo digest")?;

        let orchard_output_non_compact_digest = finalize_and_log_hash(
            &mut ctx.hashers.tx_non_compact_hasher,
            "Orchard non compact digest",
        )?;

        ok!(ctx
            .hashers
            .orchard_hasher
            .update(&orchard_output_compact_digest));
        ok!(ctx
            .hashers
            .orchard_hasher
            .update(&orchard_output_memo_digest));
        ok!(ctx
            .hashers
            .orchard_hasher
            .update(&orchard_output_non_compact_digest));

        hash_reader_exact(
            reader,
            &mut ctx.hashers.orchard_hasher,
            ORCHARD_DIGEST_DATA_SIZE,
            "Not enough data for orchard digest data",
        )?;

        self.state = ParserState::ProcessExtra;

        Ok(())
    }
}
