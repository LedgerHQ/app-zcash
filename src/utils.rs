use crate::{
    log::{debug, error},
    utils::bip32_path::Bip32Path,
};

pub mod base58_address;
pub mod bip32_path;
pub mod blake2b_256_pers;
pub mod extended_public_key;
pub mod hashers;
use crate::AppSW;

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
    if script_pubkey.len() < 2 {
        return false;
    }

    script_pubkey[1] == 0x6A
}

pub fn output_script_is_regular(script_pubkey: &[u8]) -> bool {
    if script_pubkey.len() != 0x19 {
        return false;
    }

    // OP_DUP, OP_HASH160, address length
    const REGULAR_PREFIX: [u8; 3] = [0x76, 0xA9, 0x14];
    // OP_EQUALVERIFY, OP_CHECKSIG
    const REGULAR_POSTFIX: [u8; 2] = [0x88, 0xAC];

    if script_pubkey[0] != REGULAR_PREFIX[0]
        || script_pubkey[1] != REGULAR_PREFIX[1]
        || script_pubkey[2] != REGULAR_PREFIX[2]
    {
        return false;
    }

    if script_pubkey[script_pubkey.len() - 2] != REGULAR_POSTFIX[0]
        || script_pubkey[script_pubkey.len() - 1] != REGULAR_POSTFIX[1]
    {
        return false;
    }

    true
}

pub fn output_script_is_p2sh(script_pubkey: &[u8]) -> bool {
    if script_pubkey.is_empty() {
        return false;
    }

    // P2SH script prefix
    const P2SH_PREFIX: [u8; 3] = [0xA9, 0x14, 0x00];
    const P2SH_POSTFIX: [u8; 2] = [0x87, 0x00];

    if script_pubkey.len() < 23 {
        return false;
    }

    if script_pubkey[0] != P2SH_PREFIX[0]
        || script_pubkey[1] != P2SH_PREFIX[1]
        || script_pubkey[2] != P2SH_PREFIX[2]
    {
        return false;
    }

    if script_pubkey[script_pubkey.len() - 1] != P2SH_POSTFIX[1] {
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
    const ADDRESS_OFFSET: usize = 3;

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
    if script_len < ADDRESS_OFFSET + 20 {
        return CheckDispOutput::None;
    }

    if &script_pubkey[ADDRESS_OFFSET..][..20] == change_address {
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
    const BIP44_PATH_LEN: usize = 5;
    const BIP44_PURPOSE_OFFSET: usize = 0;
    const BIP44_COIN_TYPE_OFFSET: usize = 1;
    const BIP44_ACCOUNT_OFFSET: usize = 2;
    const BIP44_CHANGE_OFFSET: usize = 3;
    const BIP44_ADDRESS_INDEX_OFFSET: usize = 4;
    const BIP44_COIN_TYPE: u32 = 133;
    const MAX_BIP44_ACCOUNT_RECOMMENDED: u32 = 100;
    const MAX_BIP44_ADDRESS_INDEX_RECOMMENDED: u32 = 50000;

    let path = path.as_slice();

    if path.len() != BIP44_PATH_LEN {
        error!("Bad Bip44 path len");
        return false;
    }

    let purpose = path[BIP44_PURPOSE_OFFSET] & 0x7FFF_FFFF;
    if purpose != 44 && purpose != 49 && purpose != 84 {
        error!("Bad Bip44 purpose");
        return false;
    }

    let coin_type = path[BIP44_COIN_TYPE_OFFSET] & 0x7FFF_FFFF;
    if coin_type != BIP44_COIN_TYPE {
        error!("Bad Bip44 coin type");
        return false;
    }

    if let Bip44CheckMode::Full { is_change_path } = mode {
        let account = path[BIP44_ACCOUNT_OFFSET] & 0x7FFF_FFFF;
        if account > MAX_BIP44_ACCOUNT_RECOMMENDED {
            error!("Bad Bip44 account");
            return false;
        }

        let change = path[BIP44_CHANGE_OFFSET];
        if change != if is_change_path { 1 } else { 0 } {
            error!("Bad Bip44 change");
            return false;
        }

        let address_index = path[BIP44_ADDRESS_INDEX_OFFSET] & 0x7FFF_FFFF;
        if address_index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED {
            error!("Bad Bip44 address index");
            return false;
        }
    }

    true
}
