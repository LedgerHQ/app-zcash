use arrayvec::ArrayString;

pub type Base58Address = ArrayString<TRANSPARENT_ADDRESS_B58_LEN>;

use crate::{
    AppSW,
    utils::{
        hashers::{Hash160, sha256_checksum},
        output_script_is_op_return, output_script_is_regular,
    },
};

pub const TRANSPARENT_ADDRESS_B58_LEN: usize = 35;

type P2pkhPayload = [u8; 22];

// T-address P2PKH prefix (mainnet)
const P2PKH_PREFIX: [u8; 2] = [0x1C, 0xB8];
// T-address P2PKH prefix (testnet)
const _P2PKH_PREFIX: [u8; 2] = [0x1D, 0x25];

pub trait ToBase58Address {
    fn from_p2pkh_payload(
        payload: &P2pkhPayload,
    ) -> Result<ArrayString<TRANSPARENT_ADDRESS_B58_LEN>, AppSW>;
    fn from_public_key_hash(
        hash160: &Hash160,
    ) -> Result<ArrayString<TRANSPARENT_ADDRESS_B58_LEN>, AppSW>;
    fn from_output_script(script: &[u8])
    -> Result<ArrayString<TRANSPARENT_ADDRESS_B58_LEN>, AppSW>;
}

impl ToBase58Address for ArrayString<TRANSPARENT_ADDRESS_B58_LEN> {
    fn from_public_key_hash(hash160: &Hash160) -> Result<Self, AppSW> {
        let mut payload = [0u8; 22];
        payload[..2].copy_from_slice(&P2PKH_PREFIX);
        payload[2..].copy_from_slice(hash160);

        Self::from_p2pkh_payload(&payload)
    }

    fn from_output_script(script: &[u8]) -> Result<Self, AppSW> {
        let payload = output_script_to_p2pkh_payload(script)?;
        Self::from_p2pkh_payload(&payload)
    }

    fn from_p2pkh_payload(payload: &P2pkhPayload) -> Result<Self, AppSW> {
        let mut buf = [0u8; 26];

        // payload
        buf[..22].copy_from_slice(payload);

        // checksum
        let checksum = sha256_checksum(&buf[..22]);
        buf[22..26].copy_from_slice(&checksum);

        // base58 → ArrayString
        let mut out = [0u8; TRANSPARENT_ADDRESS_B58_LEN];
        let written = bs58::encode(&buf)
            .onto(&mut out[..])
            .map_err(|_| AppSW::IncorrectData)?;

        let s = core::str::from_utf8(&out[..written]).map_err(|_| AppSW::ExecutionError)?;

        ArrayString::from(s).map_err(|_| AppSW::IncorrectData)
    }
}

fn output_script_to_p2pkh_payload(script: &[u8]) -> Result<P2pkhPayload, AppSW> {
    const ADDRESS_OFFSET: usize = 3;
    const PREFIX: [u8; 2] = [0x1C, 0xB8];

    if output_script_is_op_return(script) || !output_script_is_regular(script) {
        return Err(AppSW::IncorrectData);
    }

    let mut payload = [0u8; 22];
    payload[..2].copy_from_slice(&PREFIX);
    payload[2..].copy_from_slice(&script[ADDRESS_OFFSET..ADDRESS_OFFSET + 20]);

    Ok(payload)
}
