use ::orchard::keys::{FullViewingKey, Scope};
use zcash_protocol::consensus::NetworkType;
use zeroize::Zeroize;

use crate::{AppSW, zip32::map_ledger_crypto_error};

pub(crate) use ledger_zcash_crypto::orchard::{
    DecipheredOrchardOutput, ORCHARD_ENC_CIPHERTEXT_SIZE, ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE,
    ORCHARD_OUT_CIPHERTEXT_SIZE, ORCHARD_RAW_ADDRESS_SIZE, OrchardActionCiphertext,
    OrchardCompactAction, decipher_compact_value, decipher_value_with_ovk,
};

pub(crate) struct OrchardDecipherKeys {
    pub network: NetworkType,
    pub internal_ivk: [u8; 32],
    pub external_ovk: [u8; 32],
    // Derived only when a real spend needs membership validation.
    external_ivk: Option<[u8; 32]>,
}

/// These are seed-derived viewing keys: they cannot move funds, but they identify and decrypt the
/// account's own notes, so they are wiped rather than left in the static transaction context for
/// whatever runs next. Replacing or dropping the enclosing `TxInfo` triggers this.
impl Drop for OrchardDecipherKeys {
    fn drop(&mut self) {
        self.internal_ivk.zeroize();
        self.external_ovk.zeroize();
        self.external_ivk.zeroize();
    }
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
            external_ivk: None,
        })
    }

    /// Reuses the IVK for a scope. `fvk` must be the key passed to `from_fvk`;
    /// the PCZT parser enforces one account path for this cache's lifetime.
    pub(crate) fn incoming_viewing_key(
        &mut self,
        fvk: &FullViewingKey,
        scope: Scope,
    ) -> Result<&[u8; 32], AppSW> {
        if scope == Scope::Internal {
            return Ok(&self.internal_ivk);
        }
        if self.external_ivk.is_none() {
            let ivk = zeroize::Zeroizing::new(
                fvk.to_ivk_ledger(Scope::External)
                    .map_err(map_ledger_crypto_error)?
                    .to_bytes(),
            );
            self.external_ivk = Some(ivk[32..].try_into().map_err(|_| AppSW::TechnicalProblem)?);
        }
        self.external_ivk.as_ref().ok_or(AppSW::TechnicalProblem)
    }
}
