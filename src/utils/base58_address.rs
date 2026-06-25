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

// T-address P2PKH prefix.
#[cfg(not(feature = "testnet"))]
const TRANSPARENT_ADDRESS_PREFIX: [u8; 2] = [0x1C, 0xB8];
#[cfg(feature = "testnet")]
const TRANSPARENT_ADDRESS_PREFIX: [u8; 2] = [0x1D, 0x25];

const P2PKH_PREFIX_LEN: usize = 2;
const P2PKH_HASH_LEN: usize = 20;
const P2PKH_PAYLOAD_LEN: usize = P2PKH_PREFIX_LEN + P2PKH_HASH_LEN;
const BASE58_CHECK_BUFFER_LEN: usize = P2PKH_PAYLOAD_LEN + 4;
const OUTPUT_SCRIPT_ADDRESS_OFFSET: usize = 3;

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
        let mut payload = [0u8; P2PKH_PAYLOAD_LEN];
        payload[..P2PKH_PREFIX_LEN].copy_from_slice(&TRANSPARENT_ADDRESS_PREFIX);
        payload[P2PKH_PREFIX_LEN..].copy_from_slice(hash160);

        Self::from_p2pkh_payload(&payload)
    }

    fn from_output_script(script: &[u8]) -> Result<Self, AppSW> {
        let payload = output_script_to_p2pkh_payload(script)?;
        Self::from_p2pkh_payload(&payload)
    }

    fn from_p2pkh_payload(payload: &P2pkhPayload) -> Result<Self, AppSW> {
        let mut buf = [0u8; BASE58_CHECK_BUFFER_LEN];

        // payload
        buf[..P2PKH_PAYLOAD_LEN].copy_from_slice(payload);

        // checksum
        let checksum = sha256_checksum(&buf[..P2PKH_PAYLOAD_LEN]);
        buf[P2PKH_PAYLOAD_LEN..].copy_from_slice(&checksum);

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
    if output_script_is_op_return(script) || !output_script_is_regular(script) {
        return Err(AppSW::IncorrectData);
    }

    let mut payload = [0u8; P2PKH_PAYLOAD_LEN];
    payload[..P2PKH_PREFIX_LEN].copy_from_slice(&TRANSPARENT_ADDRESS_PREFIX);
    payload[P2PKH_PREFIX_LEN..].copy_from_slice(
        &script[OUTPUT_SCRIPT_ADDRESS_OFFSET..OUTPUT_SCRIPT_ADDRESS_OFFSET + P2PKH_HASH_LEN],
    );

    Ok(payload)
}
