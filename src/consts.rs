pub const ZCASH_TICKER: &str = "ZEC";

pub const ZCASH_DECIMALS: u32 = 8;
pub const ZCASH_DECIMALS_DIV: u64 = 10u64.pow(ZCASH_DECIMALS);

pub const MAX_SCRIPT_SIZE: usize = 1024 * 2;
pub const MAX_OUTPUTS_NUMBER: usize = 8;

pub const ZCASH_CLA: u8 = 0xE0;
pub const INS_GET_WALLET_PUBLIC_KEY: u8 = 0x40;
pub const INS_GET_TRUSTED_INPUT: u8 = 0x42;
pub const INS_HASH_INPUT_START: u8 = 0x44;
pub const INS_HASH_SIGN: u8 = 0x48;
pub const INS_HASH_INPUT_FINALIZE_FULL: u8 = 0x4A;
pub const INS_SIGN_MESSAGE: u8 = 0x4E;
pub const INS_GET_FIRMWARE_VERSION: u8 = 0xC4;

pub const P1_FIRST: u8 = 0x00;
pub const P1_NEXT: u8 = 0x80;

pub const P1_GET_PUBLIC_KEY_NO_DISPLAY: u8 = 0x00;
pub const P1_GET_PUBLIC_KEY_DISPLAY: u8 = 0x01;

pub const P1_HASH_INPUT_START_FIRST: u8 = 0x00;
pub const P1_HASH_INPUT_START_NEXT: u8 = 0x80;
pub const P2_HASH_INPUT_START_SAPLING: u8 = 0x05;
pub const P2_HASH_INPUT_START_CONTINUE: u8 = 0x80;

pub const P1_FINALIZE_FULL_MORE: u8 = 0x00;
pub const P1_FINALIZE_FULL_LAST: u8 = 0x80;
pub const P1_FINALIZE_FULL_CHANGEINFO: u8 = 0xFF;
pub const P2_FINALIZE_FULL_DEFAULT: u8 = 0x00;

pub const TRUSTED_INPUT_SIZE: usize = 2 + 2 + 32 + 4 + 8; // magic + rand + txid + idx + amount
pub const TRUSTED_INPUT_TOTAL_SIZE: usize = TRUSTED_INPUT_SIZE + 8;
