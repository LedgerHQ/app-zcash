use crate::AppSW;

pub const ZCASH_TICKER: &str = "ZEC";

pub const ZCASH_DECIMALS: u32 = 8;
pub const ZCASH_DECIMALS_DIV: u64 = 10u64.pow(ZCASH_DECIMALS);

pub const MAX_SCRIPT_SIZE: usize = 1024 * 2;
// Limit the number of transparent outputs in the legacy parser due to device memory constraints.
pub const MAX_OUTPUTS_NUMBER: usize = 8;
pub const SIGHASH_ALL: u8 = 0x01;
pub const UNHARDENED_MASK: u32 = 0x7FFF_FFFF;
pub const ZIP32_PATH_LEN: usize = 3;
pub const ZIP32_PURPOSE: u32 = 32;
#[cfg(not(feature = "testnet"))]
pub const ZCASH_BIP44_COIN_TYPE: u32 = 133;
#[cfg(feature = "testnet")]
pub const ZCASH_BIP44_COIN_TYPE: u32 = 1;

// Limit the number of PCZT transparent inputs due to device memory constraints.
pub const MAX_PCZT_TRANSPARENT_INPUTS_NUMBER: usize = 10;
// Limit the number of PCZT transparent outputs due to device memory constraints.
pub const MAX_PCZT_TRANSPARENT_OUTPUTS_NUMBER: usize = 10;
// Limit the number of PCZT orchard actions due to device memory constraints.
pub const MAX_PCZT_ORCHARD_ACTIONS_NUMBER: usize = 10;
// Limit the number of PCZT ironwood actions due to device memory constraints.
#[cfg(feature = "zcash_unstable")]
pub const MAX_PCZT_IRONWOOD_ACTIONS_NUMBER: usize = 10;

pub const ZCASH_CLA: u8 = 0xE0;
pub const INS_GET_WALLET_PUBLIC_KEY: u8 = 0x40;
pub const INS_GET_TRUSTED_INPUT: u8 = 0x42;
pub const INS_HASH_INPUT_START: u8 = 0x44;
pub const INS_HASH_SIGN: u8 = 0x48;
pub const INS_HASH_INPUT_FINALIZE_FULL: u8 = 0x4A;
pub const INS_SIGN_MESSAGE: u8 = 0x4E;
pub const INS_GET_FIRMWARE_VERSION: u8 = 0xC4;
pub const INS_GET_VK: u8 = 0x50;
pub const INS_GET_SHIELD_ADDR: u8 = 0x51;
pub const INS_PCZT_HEADER: u8 = 0x52;
pub const INS_PCZT_TRANSPARENT_INPUT: u8 = 0x53;
pub const INS_PCZT_TRANSPARENT_OUTPUT: u8 = 0x54;
pub const INS_PCZT_SIGN_TRANSPARENT: u8 = 0x55;
pub const INS_PCZT_ORCHARD_ACTION: u8 = 0x56;
pub const INS_PCZT_SIGN_ORCHARD: u8 = 0x57;
#[cfg(feature = "zcash_unstable")]
pub const INS_PCZT_IRONWOOD_ACTION: u8 = 0x58;
#[cfg(feature = "zcash_unstable")]
pub const INS_PCZT_SIGN_IRONWOOD: u8 = 0x59;

pub const P1_FIRST: u8 = 0x00;
pub const P1_NEXT: u8 = 0x80;
pub const P1_LAST: u8 = 0x01;

pub const P1_GET_PUBLIC_KEY_NO_DISPLAY: u8 = 0x00;
pub const P1_GET_PUBLIC_KEY_DISPLAY: u8 = 0x01;
pub const P1_GET_VK_FIRST: u8 = 0x00;
pub const P1_GET_VK_CONTINUE: u8 = 0x80;

pub const P1_HASH_INPUT_START_FIRST: u8 = 0x00;
pub const P1_HASH_INPUT_START_NEXT: u8 = 0x80;
pub const P2_HASH_INPUT_START_SAPLING: u8 = 0x05;
pub const P2_HASH_INPUT_START_CONTINUE: u8 = 0x80;

pub const P1_FINALIZE_FULL_MORE: u8 = 0x00;
pub const P1_FINALIZE_FULL_LAST: u8 = 0x80;
pub const P1_FINALIZE_FULL_CHANGEINFO: u8 = 0xFF;
pub const P2_FINALIZE_FULL_DEFAULT: u8 = 0x00;
pub const P2_PCZT_CONTINUE: u8 = 0x00;
pub const P2_PCZT_FINISHED: u8 = 0x01;

pub const TRUSTED_INPUT_SIZE: usize = 2 + 2 + 32 + 4 + 8; // magic + rand + txid + idx + amount
pub const TRUSTED_INPUT_TOTAL_SIZE: usize = TRUSTED_INPUT_SIZE + 8;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum P2VkMode {
    Ufvk = 0x0,
    OrchardFvk = 0x1,
}

impl TryFrom<u8> for P2VkMode {
    type Error = AppSW;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(P2VkMode::Ufvk),
            0x01 => Ok(P2VkMode::OrchardFvk),
            _ => Err(AppSW::WrongP1P2),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum P2ShieldedAddrMode {
    UAddress = 0x0,
    OrchardAddress = 0x1,
}

impl TryFrom<u8> for P2ShieldedAddrMode {
    type Error = AppSW;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(P2ShieldedAddrMode::UAddress),
            0x01 => Ok(P2ShieldedAddrMode::OrchardAddress),
            _ => Err(AppSW::WrongP1P2),
        }
    }
}

// NU6.3 / V6 transaction constants — gated until ratification (zcash_protocol 0.10.0)
// The overwintered flag (bit 31) is ORed into the transaction version in the header digest
// per ZIP-244 §T.1 and ZIP-229.
#[cfg(feature = "zcash_unstable")]
pub const OVERWINTERED_FLAG: u32 = 0x8000_0000;
#[cfg(feature = "zcash_unstable")]
pub const V6_TX_VERSION: u32 = 6;
#[cfg(feature = "zcash_unstable")]
pub const V6_VERSION_GROUP_ID: u32 = 0xD884B698;
