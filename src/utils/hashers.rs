use ledger_device_sdk::hash::{HashInit, ripemd::Ripemd160, sha2::Sha2_256};
use ledger_device_sdk::log::debug;

use crate::{AppSW, utils::HexSlice};

pub type Hash160 = [u8; 20];

pub trait ToHash160 {
    fn hash160(&self) -> Result<Hash160, AppSW>;
}

impl ToHash160 for [u8] {
    fn hash160(&self) -> Result<Hash160, AppSW> {
        let mut sha256 = Sha2_256::new();
        let mut sha256_output = [0u8; 32];

        sha256
            .hash(self, &mut sha256_output)
            .map_err(|_| AppSW::IncorrectData)?;

        let mut ripemd160 = Ripemd160::new();
        let mut ripemd160_output = [0u8; 20];

        ripemd160
            .hash(&sha256_output, &mut ripemd160_output)
            .map_err(|_| AppSW::IncorrectData)?;

        debug!("PubKey SHA256: {}", HexSlice(&sha256_output));
        debug!("PubKey HASH160: {}", HexSlice(&ripemd160_output));

        Ok(ripemd160_output)
    }
}
