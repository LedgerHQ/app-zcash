//! Streaming of the shielded action bundles feeding the ZIP-244 transaction ID.
//!
//! Orchard and Ironwood (ZIP-230, v6 only) share the same on-chain action layout and the
//! same three-part digest, so both are streamed by the states below. They differ only by
//! personalization and by the bundle hasher they feed. Whether the anchor belongs to the
//! transaction ID digest depends on the transaction version rather than on the bundle.

use ::orchard::bundle::commitments::{
    ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION,
    ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
    ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
};

#[cfg(feature = "zcash_unstable")]
use super::super::personalization::{
    ZCASH_IRONWOOD_ACTIONS_COMPACT_HASH_PERSONALIZATION,
    ZCASH_IRONWOOD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
    ZCASH_IRONWOOD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
};
use super::*;

pub(crate) const ORCHARD_NULLIFIER_SIZE: usize = HASH_SIZE;
pub(crate) const ORCHARD_CMX_SIZE: usize = HASH_SIZE;
pub(crate) const ORCHARD_EPHEMERAL_KEY_SIZE: usize = HASH_SIZE;
pub(crate) const ORCHARD_COMPACT_ENC_CIPHERTEXT_SIZE: usize = 52;
pub(crate) const ORCHARD_OUT_CIPHERTEXT_SIZE: usize = 16;
pub(crate) const ORCHARD_ZKPROOF_SIZE: usize = 80;
pub(crate) const ORCHARD_FLAGS_SIZE: usize = 1;
pub(crate) const ORCHARD_BALANCE_SIZE: usize = 8;
pub(crate) const ORCHARD_ACTIONS_COMPACT_SIZE: usize = ORCHARD_NULLIFIER_SIZE
    + ORCHARD_CMX_SIZE
    + ORCHARD_EPHEMERAL_KEY_SIZE
    + ORCHARD_COMPACT_ENC_CIPHERTEXT_SIZE;
pub(crate) const ORCHARD_ACTIONS_NONCOMPACT_SIZE: usize =
    ORCHARD_NULLIFIER_SIZE + ORCHARD_CMX_SIZE + ORCHARD_OUT_CIPHERTEXT_SIZE + ORCHARD_ZKPROOF_SIZE;

// flags + valueBalance, plus the anchor for a v5 Orchard bundle. In a v6 transaction both
// bundles moved the anchor to the authorizing digest, which a trusted input never computes,
// so the host streams no anchor at all.
const ACTIONS_DIGEST_DATA_SIZE: usize = ORCHARD_FLAGS_SIZE + ORCHARD_BALANCE_SIZE;
const ACTIONS_DIGEST_DATA_SIZE_V5: usize = ACTIONS_DIGEST_DATA_SIZE + HASH_SIZE;

impl ActionBundle {
    // A v6 Orchard bundle keeps the v5 action-level personalizations and only changes its
    // bundle-level one; Ironwood uses its own throughout.
    fn compact_personalization(self) -> &'static [u8; 16] {
        match self {
            ActionBundle::Orchard => ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION,
            #[cfg(feature = "zcash_unstable")]
            ActionBundle::Ironwood => ZCASH_IRONWOOD_ACTIONS_COMPACT_HASH_PERSONALIZATION,
        }
    }

    fn memos_personalization(self) -> &'static [u8; 16] {
        match self {
            ActionBundle::Orchard => ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
            #[cfg(feature = "zcash_unstable")]
            ActionBundle::Ironwood => ZCASH_IRONWOOD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
        }
    }

    fn noncompact_personalization(self) -> &'static [u8; 16] {
        match self {
            ActionBundle::Orchard => ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
            #[cfg(feature = "zcash_unstable")]
            ActionBundle::Ironwood => ZCASH_IRONWOOD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
        }
    }

    fn hasher(self, hashers: &mut Hashers) -> &mut Blake2b_256 {
        match self {
            ActionBundle::Orchard => &mut hashers.orchard_hasher,
            #[cfg(feature = "zcash_unstable")]
            ActionBundle::Ironwood => &mut hashers.ironwood_hasher,
        }
    }
}

impl LegacyParser {
    fn action_count(&self, bundle: ActionBundle) -> usize {
        match bundle {
            ActionBundle::Orchard => self.orchard_action_count,
            #[cfg(feature = "zcash_unstable")]
            ActionBundle::Ironwood => self.ironwood_action_count,
        }
    }

    /// Enters the next non-empty action bundle, or `ProcessExtra` when none is left.
    ///
    /// A v5 transaction only carries the Orchard bundle; a v6 can carry an Ironwood bundle
    /// after it. Pass the bundle that just finished (`Some(...)`), or `None` when entering
    /// the shielded section for the first time after the transparent one.
    pub(super) fn enter_next_action_bundle(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        current: Option<ActionBundle>,
    ) -> Result<(), ParserError> {
        let next = match current {
            None if self.orchard_action_count > 0 => Some(ActionBundle::Orchard),
            #[cfg(feature = "zcash_unstable")]
            None | Some(ActionBundle::Orchard) if self.ironwood_action_count > 0 => {
                Some(ActionBundle::Ironwood)
            }
            _ => None,
        };

        self.state = match next {
            Some(bundle) => {
                ok!(ctx
                    .hashers
                    .tx_compact_hasher
                    .init_with_perso(bundle.compact_personalization()));
                self.action_parsed_count = 0;
                LegacyParserState::ProcessActionsCompact { bundle }
            }
            None => LegacyParserState::ProcessExtra,
        };

        Ok(())
    }

    pub fn parse_actions_compact(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        bundle: ActionBundle,
    ) -> Result<(), ParserError> {
        let action_count = self.action_count(bundle);

        info!(
            "Parsing {:?} compact action {}/{}",
            bundle,
            self.action_parsed_count + 1,
            action_count
        );

        hash_reader_exact(
            reader,
            &mut ctx.hashers.tx_compact_hasher,
            ORCHARD_ACTIONS_COMPACT_SIZE,
            "Not enough data for shielded compact action",
        )?;

        self.action_parsed_count += 1;

        if self.action_parsed_count == action_count {
            info!("All {:?} compact actions parsed", bundle);

            ok!(ctx
                .hashers
                .tx_memo_hasher
                .init_with_perso(bundle.memos_personalization()));

            self.state = LegacyParserState::ProcessActionsMemo {
                bundle,
                size: action_count * ORCHARD_MEMO_SIZE,
                remaining_size: action_count * ORCHARD_MEMO_SIZE,
            };
        }

        Ok(())
    }

    pub fn parse_actions_memo(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        bundle: ActionBundle,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        info!(
            "Parsing {:?} memo, remaining size: {}",
            bundle, remaining_size
        );

        let new_remaining_size =
            hash_reader_chunk(reader, &mut ctx.hashers.tx_memo_hasher, remaining_size)?;
        if new_remaining_size == 0 {
            info!("All {:?} memos parsed", bundle);

            ok!(ctx
                .hashers
                .tx_non_compact_hasher
                .init_with_perso(bundle.noncompact_personalization()));

            self.action_parsed_count = 0;
            self.state = LegacyParserState::ProcessActionsNonCompact { bundle };
        } else {
            self.state = LegacyParserState::ProcessActionsMemo {
                bundle,
                size,
                remaining_size: new_remaining_size,
            };
        }

        Ok(())
    }

    pub fn parse_actions_noncompact(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        bundle: ActionBundle,
    ) -> Result<(), ParserError> {
        let action_count = self.action_count(bundle);

        info!(
            "Parsing {:?} non-compact action {}/{}",
            bundle,
            self.action_parsed_count + 1,
            action_count
        );

        hash_reader_exact(
            reader,
            &mut ctx.hashers.tx_non_compact_hasher,
            ORCHARD_ACTIONS_NONCOMPACT_SIZE,
            "Not enough data for shielded non-compact action",
        )?;

        self.action_parsed_count += 1;

        if self.action_parsed_count == action_count {
            info!("All {:?} non-compact actions parsed", bundle);
            self.state = LegacyParserState::ProcessActionsHashing { bundle };
        }

        Ok(())
    }

    pub fn parse_actions_hashing(
        &mut self,
        ctx: &mut LegacyParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        bundle: ActionBundle,
    ) -> Result<(), ParserError> {
        info!("Finalizing {:?} hashing", bundle);

        let compact_digest = finalize_and_log_hash(
            &mut ctx.hashers.tx_compact_hasher,
            "Shielded compact digest",
        )?;

        let memo_digest =
            finalize_and_log_hash(&mut ctx.hashers.tx_memo_hasher, "Shielded memo digest")?;

        let non_compact_digest = finalize_and_log_hash(
            &mut ctx.hashers.tx_non_compact_hasher,
            "Shielded non compact digest",
        )?;

        // Only a v5 Orchard bundle commits to its anchor here. In a v6 transaction both
        // bundles moved it to the authorizing digest, which a trusted input never computes,
        // so the host streams no anchor at all.
        let digest_data_size = match ctx.tx_info.tx_version() {
            #[cfg(feature = "zcash_unstable")]
            SupportedTxVersion::V6 => ACTIONS_DIGEST_DATA_SIZE,
            SupportedTxVersion::V4 | SupportedTxVersion::V5 => ACTIONS_DIGEST_DATA_SIZE_V5,
        };

        let bundle_hasher = bundle.hasher(ctx.hashers);
        ok!(bundle_hasher.update(&compact_digest));
        ok!(bundle_hasher.update(&memo_digest));
        ok!(bundle_hasher.update(&non_compact_digest));

        hash_reader_exact(
            reader,
            bundle_hasher,
            digest_data_size,
            "Not enough data for shielded digest data",
        )?;

        self.enter_next_action_bundle(ctx, Some(bundle))
    }
}
