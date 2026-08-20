use arrayvec::ArrayString;

pub type Base58Address = ArrayString<TRANSPARENT_ADDRESS_B58_LEN>;

use crate::{
    AppSW,
    utils::{
        hashers::Hash160, output_script_is_op_return, output_script_is_p2sh,
        output_script_is_regular,
    },
    zip32::map_ledger_crypto_error,
};

pub const TRANSPARENT_ADDRESS_B58_LEN: usize = 35;

type P2pkhPayload = [u8; 22];

// T-address P2PKH prefix.
#[cfg(not(feature = "testnet"))]
const TRANSPARENT_ADDRESS_PREFIX: [u8; 2] = [0x1C, 0xB8];
#[cfg(feature = "testnet")]
const TRANSPARENT_ADDRESS_PREFIX: [u8; 2] = [0x1D, 0x25];

// T-address P2SH prefix.
#[cfg(not(feature = "testnet"))]
const P2SH_ADDRESS_PREFIX: [u8; 2] = [0x1C, 0xBD];
#[cfg(feature = "testnet")]
const P2SH_ADDRESS_PREFIX: [u8; 2] = [0x1C, 0xBA];

const P2PKH_PREFIX_LEN: usize = 2;
const P2PKH_HASH_LEN: usize = 20;
const P2PKH_PAYLOAD_LEN: usize = P2PKH_PREFIX_LEN + P2PKH_HASH_LEN;
const OUTPUT_SCRIPT_ADDRESS_OFFSET: usize = 3;
// A P2SH scriptPubKey (`a9 14 <hash160> 87`) carries its hash two bytes in, not three: it has
// no leading `OP_DUP OP_HASH160` pair, only `OP_HASH160 <push>`.
const P2SH_OUTPUT_SCRIPT_HASH_OFFSET: usize = 2;

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
        let payload = output_script_to_transparent_payload(script)?;
        Self::from_p2pkh_payload(&payload)
    }

    fn from_p2pkh_payload(payload: &P2pkhPayload) -> Result<Self, AppSW> {
        let mut prefix = [0u8; P2PKH_PREFIX_LEN];
        prefix.copy_from_slice(&payload[..P2PKH_PREFIX_LEN]);
        let mut hash = [0u8; P2PKH_HASH_LEN];
        hash.copy_from_slice(&payload[P2PKH_PREFIX_LEN..]);

        ledger_zcash_crypto::transparent_address::base58check_transparent_address(&prefix, &hash)
            .map_err(map_ledger_crypto_error)
    }
}

fn output_script_to_transparent_payload(script: &[u8]) -> Result<P2pkhPayload, AppSW> {
    if output_script_is_p2sh(script) {
        let mut payload = [0u8; P2PKH_PAYLOAD_LEN];
        payload[..P2PKH_PREFIX_LEN].copy_from_slice(&P2SH_ADDRESS_PREFIX);
        payload[P2PKH_PREFIX_LEN..].copy_from_slice(
            &script
                [P2SH_OUTPUT_SCRIPT_HASH_OFFSET..P2SH_OUTPUT_SCRIPT_HASH_OFFSET + P2PKH_HASH_LEN],
        );
        return Ok(payload);
    }

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
