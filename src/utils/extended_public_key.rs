use crate::{
    AppSW,
    utils::{
        bip32_path::Bip32Path,
        hashers::{Hash160, ToHash160},
    },
};

pub type CompressedPublicKey = [u8; 33];

#[derive(Clone)]
pub struct ExtendedPublicKey {
    pub public_key: [u8; 65],
    pub public_key_len: usize,
    pub chain_code: [u8; 32],
}

impl ExtendedPublicKey {
    pub fn public_key_slice(&self) -> &[u8] {
        &self.public_key[..self.public_key_len]
    }

    pub fn compressed_public_key(&self) -> Result<CompressedPublicKey, AppSW> {
        let public_key = self.public_key_slice();
        if public_key.len() != 65 {
            return Err(AppSW::IncorrectData);
        }
        let mut compressed_pk = [0u8; 33];
        compressed_pk[0] = if public_key[64] & 1 == 1 { 0x03 } else { 0x02 };
        compressed_pk[1..33].copy_from_slice(&public_key[1..33]);
        Ok(compressed_pk)
    }

    pub fn compressed_public_key_hash160(&self) -> Result<Hash160, AppSW> {
        self.compressed_public_key()?.hash160()
    }
}

impl ToHash160 for ExtendedPublicKey {
    fn hash160(&self) -> Result<Hash160, AppSW> {
        self.public_key_slice().hash160()
    }
}

impl TryFrom<&Bip32Path> for ExtendedPublicKey {
    type Error = AppSW;

    fn try_from(path: &Bip32Path) -> Result<Self, Self::Error> {
        Self::try_from(path.as_slice())
    }
}

impl TryFrom<&[u32]> for ExtendedPublicKey {
    type Error = AppSW;

    fn try_from(path: &[u32]) -> Result<Self, Self::Error> {
        use ledger_device_sdk::ecc::{Secp256k1, SeedDerive};
        let (k, cc) = Secp256k1::derive_from(path);

        let pk = k.public_key().map_err(|_| AppSW::IncorrectData)?;
        let code = cc.ok_or(AppSW::IncorrectData)?;

        let public_key = pk.pubkey;
        let public_key_len = pk.keylength;
        let chain_code = code.value;
        Ok(Self {
            public_key,
            public_key_len,
            chain_code,
        })
    }
}
