use crate::consts::{UNHARDENED_MASK, ZIP32_PATH_LEN, ZIP32_PURPOSE};
use crate::utils::bip32_path::Bip32Path;
use alloc::vec::Vec;
use ledger_device_sdk::log::{debug, error};

pub mod base58_address;
pub mod bip32_path;
pub mod blake2b_256_pers;
pub mod extended_public_key;
pub mod hashers;
use crate::AppSW;

const OP_RETURN_OPCODE_INDEX: usize = 1;
const OP_RETURN_OPCODE: u8 = 0x6A;
const REGULAR_OUTPUT_SCRIPT_LEN: usize = 25;
const REGULAR_OUTPUT_PREFIX: [u8; 3] = [0x76, 0xA9, 0x14];
const REGULAR_OUTPUT_POSTFIX: [u8; 2] = [0x88, 0xAC];
const P2SH_OUTPUT_SCRIPT_MIN_LEN: usize = 23;
const P2SH_OUTPUT_PREFIX: [u8; 3] = [0xA9, 0x14, 0x00];
const P2SH_OUTPUT_POSTFIX: [u8; 2] = [0x87, 0x00];
const TRANSPARENT_ADDRESS_OFFSET: usize = 3;
const TRANSPARENT_ADDRESS_HASH_LEN: usize = 20;
const BIP44_ALLOWED_PURPOSES: [u32; 2] = [44, 32];

pub enum Endianness {
    Big,
    _Little,
}

pub fn read_u32(buffer: &[u8], endianness: Endianness, skip_sign: bool) -> Result<u32, AppSW> {
    if buffer.len() < 4 {
        return Err(AppSW::IncorrectData);
    }

    let buffer4 = buffer[..4].try_into().expect("cannot fail");

    let mut word = match endianness {
        Endianness::Big => u32::from_be_bytes(buffer4),
        Endianness::_Little => u32::from_le_bytes(buffer4),
    };

    if skip_sign {
        word &= 0x7FFF_FFFF;
    }

    Ok(word)
}

pub struct HexSlice<'a>(pub &'a [u8]);

impl core::fmt::Display for HexSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

/// Constant-time memory comparison to prevent timing attacks.
#[inline(never)]
pub fn secure_memcmp(buf1: &[u8], buf2: &[u8]) -> bool {
    if buf1.len() != buf2.len() {
        return false;
    }

    let mut error: u8 = 0;
    for i in 0..buf1.len() {
        error |= buf1[i] ^ buf2[i];
    }

    error == 0
}

pub fn output_script_is_op_return(script_pubkey: &[u8]) -> bool {
    if script_pubkey.len() <= OP_RETURN_OPCODE_INDEX {
        return false;
    }

    script_pubkey[OP_RETURN_OPCODE_INDEX] == OP_RETURN_OPCODE
}

pub fn output_script_is_regular(script_pubkey: &[u8]) -> bool {
    if script_pubkey.len() != REGULAR_OUTPUT_SCRIPT_LEN {
        return false;
    }

    if script_pubkey[..REGULAR_OUTPUT_PREFIX.len()] != REGULAR_OUTPUT_PREFIX {
        return false;
    }

    if script_pubkey[script_pubkey.len() - REGULAR_OUTPUT_POSTFIX.len()..] != REGULAR_OUTPUT_POSTFIX
    {
        return false;
    }

    true
}

pub fn output_script_is_p2sh(script_pubkey: &[u8]) -> bool {
    if script_pubkey.is_empty() {
        return false;
    }

    if script_pubkey.len() < P2SH_OUTPUT_SCRIPT_MIN_LEN {
        return false;
    }

    if script_pubkey[..P2SH_OUTPUT_PREFIX.len()] != P2SH_OUTPUT_PREFIX {
        return false;
    }

    if script_pubkey[script_pubkey.len() - 1] != P2SH_OUTPUT_POSTFIX[1] {
        return false;
    }

    true
}

#[derive(PartialEq, Debug)]
pub enum CheckDispOutput {
    None,
    Displayable,
    Change,
}

pub fn check_output_displayable(
    script_pubkey: &[u8],
    amount: u64,
    change_address: &[u8; 20],
) -> CheckDispOutput {
    debug!("Check output displayable");
    debug!("ScriptPubKey: {:02X?}", script_pubkey);

    if script_pubkey.is_empty() {
        return CheckDispOutput::None;
    }

    if amount == 0 {
        return CheckDispOutput::None;
    }

    if output_script_is_op_return(script_pubkey) || output_script_is_p2sh(script_pubkey) {
        return CheckDispOutput::None;
    }

    let script_len = script_pubkey.len();
    if script_len < TRANSPARENT_ADDRESS_OFFSET + TRANSPARENT_ADDRESS_HASH_LEN {
        return CheckDispOutput::None;
    }

    if &script_pubkey[TRANSPARENT_ADDRESS_OFFSET..][..TRANSPARENT_ADDRESS_HASH_LEN]
        == change_address
    {
        debug!("Change output detected");
        return CheckDispOutput::Change;
    }

    debug!("Displayable output detected");
    CheckDispOutput::Displayable
}

pub enum Bip44CheckMode {
    Full { is_change_path: bool },
    OnlyCoinType,
}

pub fn check_bip44_compliance(path: &Bip32Path, mode: Bip44CheckMode) -> bool {
    const HARDENED: u32 = 0x8000_0000;
    const PURPOSE_OFFSET: usize = 0;

    const BIP44_PATH_LEN: usize = 5;
    const BIP44_COIN_TYPE_OFFSET: usize = 1;
    const BIP44_ACCOUNT_OFFSET: usize = 2;
    const BIP44_CHANGE_OFFSET: usize = 3;
    const BIP44_ADDRESS_INDEX_OFFSET: usize = 4;
    #[cfg(not(feature = "testnet"))]
    const BIP44_COIN_TYPE: u32 = 133;
    #[cfg(feature = "testnet")]
    const BIP44_COIN_TYPE: u32 = 1;
    const MAX_BIP44_ACCOUNT_RECOMMENDED: u32 = 100;
    const MAX_BIP44_ADDRESS_INDEX_RECOMMENDED: u32 = 50000;

    let path = path.as_slice();
    let is_zip32 = path.len() == ZIP32_PATH_LEN && (path[0] & UNHARDENED_MASK) == ZIP32_PURPOSE;

    if is_zip32 {
        if path.len() != ZIP32_PATH_LEN {
            error!("Bad ZIP32 path len");
            return false;
        }

        if path[PURPOSE_OFFSET] != (ZIP32_PURPOSE | HARDENED) {
            error!("Bad ZIP32 purpose");
            return false;
        }

        if path[BIP44_COIN_TYPE_OFFSET] != (BIP44_COIN_TYPE | HARDENED) {
            error!("Bad ZIP32 coin type");
            return false;
        }

        if path[BIP44_ACCOUNT_OFFSET] & HARDENED == 0 {
            error!("Bad ZIP32 account");
            return false;
        }

        return true;
    } else {
        if path.len() != BIP44_PATH_LEN {
            error!("Bad Bip44 path len");
            return false;
        }

        let purpose = path[PURPOSE_OFFSET] & UNHARDENED_MASK;
        if !BIP44_ALLOWED_PURPOSES.contains(&purpose) {
            error!("Bad Bip44 purpose");
            return false;
        }

        let coin_type = path[BIP44_COIN_TYPE_OFFSET] & UNHARDENED_MASK;
        if coin_type != BIP44_COIN_TYPE {
            error!("Bad Bip44 coin type");
            return false;
        }
    }

    if let Bip44CheckMode::Full { is_change_path } = mode {
        let account = path[BIP44_ACCOUNT_OFFSET] & UNHARDENED_MASK;
        if account > MAX_BIP44_ACCOUNT_RECOMMENDED {
            error!("Bad Bip44 account");
            return false;
        }

        let change = path[BIP44_CHANGE_OFFSET];
        if change != if is_change_path { 1 } else { 0 } {
            error!("Bad Bip44 change");
            return false;
        }

        let address_index = path[BIP44_ADDRESS_INDEX_OFFSET] & UNHARDENED_MASK;
        if address_index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED {
            error!("Bad Bip44 address index");
            return false;
        }
    }

    true
}

pub fn encode_string_response(value: &str) -> Vec<u8> {
    let value_bytes = value.as_bytes();

    if value_bytes.len() > u16::MAX as usize {
        unreachable!("response length exceeds u16::MAX");
    }

    let len: u16 = value_bytes.len() as u16;

    let mut response = Vec::with_capacity(2 + value_bytes.len());
    response.extend_from_slice(&len.to_be_bytes());
    response.extend_from_slice(value_bytes);
    response
}
