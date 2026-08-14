//! BLAKE2b personalization strings for ZIP-243/ZIP-244 transaction hashing.
//!
//! These constants are consensus-fixed by the Zcash protocol (ZIP-243 sighash,
//! ZIP-244 txid) and are byte-for-byte identical to the (crate-private)
//! definitions in `zcash_primitives::transaction::{txid, sighash_v5}`. They are
//! reproduced here so the app can build against the published `zcash_primitives`
//! crate, which does not expose them as public API.
//!
//! Orchard personalizations live in `orchard::bundle::commitments` (public) and
//! are imported from there directly.

// --- ZIP-244 txid tree (zcash_primitives::transaction::txid) ---

/// Prefix for the top-level txid personalization; the consensus branch id is
/// appended to form the full 16-byte personalization.
pub const ZCASH_TX_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashTxHash_";

pub const ZCASH_HEADERS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdHeadersHash";
pub const ZCASH_TRANSPARENT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTranspaHash";
pub const ZCASH_SAPLING_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSaplingHash";

pub const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdPrevoutHash";
pub const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSequencHash";
pub const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOutputsHash";

pub const ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendsHash";
pub const ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendCHash";
pub const ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendNHash";

pub const ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutputHash";
pub const ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutC__Hash";
pub const ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutM__Hash";
pub const ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutN__Hash";

// --- ZIP-243 sighash tree (zcash_primitives::transaction::sighash_v5) ---

pub const ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash___TxInHash";
pub const ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxTrAmountsHash";
pub const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxTrScriptsHash";

// --- NU6.3 / V6 personalizations ---
//
// Verified against the "Anchor commitment (version 6)" table of ZIP 229 and the
// vendored `orchard` 0.15.0 (`src/bundle/commitments.rs`); all strings are
// byte-identical. The two auth-commitment strings below are not used by the device
// (signer-only, no bindingSig computation), but are retained for verification
// completeness.

/// `sapling_spends_noncompact_digest_v6`, which omits the anchor. Every other Sapling
/// node keeps its v5 personalization in a v6 transaction.
pub const ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION_V6: &[u8; 16] = b"ZTxIdSSpendNH_v6";

/// Ironwood bundle digest personalizations per ZIP 229.
pub const ZCASH_IRONWOOD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIronwd_H_v6";
pub const ZCASH_IRONWOOD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIrnActCH_v6";
pub const ZCASH_IRONWOOD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIrnActMH_v6";
pub const ZCASH_IRONWOOD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIrnActNH_v6";
#[allow(dead_code)]
pub const ZCASH_IRONWOOD_AUTH_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthIrnwdH_v6";

/// Orchard V6 bundle-level personalizations per ZIP 229; action-level strings unchanged from V5.
pub const ZCASH_ORCHARD_HASH_PERSONALIZATION_V6: &[u8; 16] = b"ZTxIdOrchardH_v6";
#[allow(dead_code)]
pub const ZCASH_ORCHARD_AUTH_HASH_PERSONALIZATION_V6: &[u8; 16] = b"ZTxAuthOrchaH_v6";
