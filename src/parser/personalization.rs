//! BLAKE2b personalization strings introduced by the v6 transaction format (ZIP-229).
//!
//! The `orchard` crate vendored on this branch predates v6 and only exposes the v5 strings,
//! so the v6 ones are defined here.
//!
//! ZIP-229 also renames the one Sapling node whose hashed content changes in v6: moving the
//! anchor to the authorizing data leaves `sapling_spends_noncompact_digest_v6` hashing only
//! `cv ‖ rk`. Every other Sapling node keeps its v5 string.

/// `sapling_spends_noncompact_digest_v6`, which omits the anchor.
pub const ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION_V6: &[u8; 16] = b"ZTxIdSSpendNH_v6";

pub const ZCASH_ORCHARD_HASH_PERSONALIZATION_V6: &[u8; 16] = b"ZTxIdOrchardH_v6";

pub const ZCASH_IRONWOOD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIronwd_H_v6";
pub const ZCASH_IRONWOOD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIrnActCH_v6";
pub const ZCASH_IRONWOOD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIrnActMH_v6";
pub const ZCASH_IRONWOOD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIrnActNH_v6";
