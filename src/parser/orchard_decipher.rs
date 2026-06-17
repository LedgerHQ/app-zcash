use ::orchard::keys::{FullViewingKey, Scope};
use zcash_protocol::consensus::NetworkType;

use crate::{AppSW, zip32::map_ledger_crypto_error};

pub(crate) use ledger_zcash_crypto::orchard::{
    DecipheredOrchardOutput, ORCHARD_ENC_CIPHERTEXT_SIZE, ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE,
    ORCHARD_OUT_CIPHERTEXT_SIZE, OrchardActionCiphertext, OrchardCompactAction,
    decipher_compact_value, decipher_value_with_ovk,
};

pub(crate) struct OrchardDecipherKeys {
    pub network: NetworkType,
    pub internal_ivk: [u8; 32],
    pub external_ovk: [u8; 32],
}

impl OrchardDecipherKeys {
    pub(crate) fn from_fvk(fvk: &FullViewingKey, network: NetworkType) -> Result<Self, AppSW> {
        let internal_ivk = fvk
            .to_ivk_ledger(Scope::Internal)
            .map_err(map_ledger_crypto_error)?
            .to_bytes();
        let external_ovk = *fvk
            .to_ovk_ledger(Scope::External)
            .map_err(map_ledger_crypto_error)?
            .as_ref();
        let mut internal_ivk_bytes = [0u8; 32];
        internal_ivk_bytes.copy_from_slice(&internal_ivk[32..]);

        Ok(Self {
            network,
            internal_ivk: internal_ivk_bytes,
            external_ovk,
        })
    }
}
