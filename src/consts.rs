use crate::AppSW;

pub const ZCASH_TICKER: &str = "ZEC";

pub const ZCASH_DECIMALS: u32 = 8;
pub const ZCASH_DECIMALS_DIV: u64 = 10u64.pow(ZCASH_DECIMALS);

// Legacy path only, and wide because a trusted input is computed by parsing a whole previous
// transaction, whose outputs carry arbitrary on-chain scripts. One shared buffer, cleared per script.
pub const MAX_SCRIPT_SIZE: usize = 1024 * 2;
// PCZT path, where every transparent input's script is retained for the session. 252 is the host's
// own limit, the single-byte CompactSize boundary.
pub const MAX_PCZT_SCRIPT_SIZE: usize = 252;
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

// Transparent inputs one transaction may spend.
//
// An input costs more than a shielded action and differently: besides its record it retains its
// scriptPubKey for the whole session, the per-input signature digest consuming it. That is why this
// bound was once paired with MAX_PCZT_SCRIPT_SIZE — ten scripts of 252 bytes being what fits.
//
// The pairing is gone: an input script is now refused unless it is the 25-byte P2PKH shape, the only
// one this app can sign for, so the retained cost per input is fixed rather than host-chosen. What
// the bound has to fit is measured, not assumed — 32 inputs parse, review and sign on Nano X, with
// the run failing well above.
#[cfg(not(feature = "capacity_probe"))]
pub const MAX_PCZT_TRANSPARENT_INPUTS_NUMBER: usize = 32;
#[cfg(feature = "capacity_probe")]
pub const MAX_PCZT_TRANSPARENT_INPUTS_NUMBER: usize = MAX_PCZT_ADDRESSABLE_ACTIONS_NUMBER;
// Limit the number of PCZT transparent outputs due to device memory constraints.
pub const MAX_PCZT_TRANSPARENT_OUTPUTS_NUMBER: usize = 10;
// Notes one shielded bundle may spend. Measured on the smallest device rather than chosen: a
// transaction of this many actions parses, reviews and signs on Nano X in both shapes a wallet
// builds — notes gathered to one transparent recipient, and a shielded send with its change note —
// with the run failing well above it. It has to hold the whole balance of an account that receives
// often, since sending the maximum spends every note at once.
//
// What an action costs is a signing record and one parse; what the *review* costs is bounded
// separately by MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER, which is why this number can be this
// high. Conflating the two is what kept it at ten.
#[cfg(not(feature = "capacity_probe"))]
pub const MAX_PCZT_ORCHARD_ACTIONS_NUMBER: usize = 32;
#[cfg(not(feature = "capacity_probe"))]
pub const MAX_PCZT_IRONWOOD_ACTIONS_NUMBER: usize = 32;

// Shielded outputs one transaction may show the user, across both shielded pools.
//
// Every displayed shielded output holds an encoded unified address, an output record and its review
// fields for as long as the review is on screen, and the host decides how many there are. Past this
// count the parser refuses with a status word instead of walking into the allocator, whose
// exhaustion exits the application rather than reporting anything.
//
// Four is twice what a send can produce — one recipient, plus the change note on a transfer that
// shows no external output — and half the count the device was measured to survive, so the budget
// holds even with memo retention and address encoding at their worst. Raising it moves the review
// toward the point where the SDK's `nbPairs: fields.len() as u8` truncates and draws an empty review
// that still collects an approval; a raise therefore belongs with a fix for that, not before it.
pub const MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER: usize = 4;

// Highest action count the signing instructions can address, P2 carrying the action index in a
// single byte. A measurement build raises both shielded bounds to it so that a run ends where the
// device runs out of memory rather than where the shipped bound sits — the bound above is a figure
// chosen for memory the device was never measured against, and measuring it is what this replaces.
#[cfg(feature = "capacity_probe")]
pub const MAX_PCZT_ADDRESSABLE_ACTIONS_NUMBER: usize = 255;
#[cfg(feature = "capacity_probe")]
pub const MAX_PCZT_ORCHARD_ACTIONS_NUMBER: usize = MAX_PCZT_ADDRESSABLE_ACTIONS_NUMBER;
#[cfg(feature = "capacity_probe")]
pub const MAX_PCZT_IRONWOOD_ACTIONS_NUMBER: usize = MAX_PCZT_ADDRESSABLE_ACTIONS_NUMBER;

pub const ZCASH_CLA: u8 = 0xE0;
pub const INS_GET_WALLET_PUBLIC_KEY: u8 = 0x40;
pub const INS_GET_TRUSTED_INPUT: u8 = 0x42;
pub const INS_HASH_INPUT_START: u8 = 0x44;
pub const INS_HASH_SIGN: u8 = 0x48;
pub const INS_HASH_INPUT_FINALIZE_FULL: u8 = 0x4A;
pub const INS_GET_FIRMWARE_VERSION: u8 = 0xC4;
pub const INS_GET_VK: u8 = 0x50;
pub const INS_GET_SHIELD_ADDR: u8 = 0x51;
pub const INS_PCZT_HEADER: u8 = 0x52;
pub const INS_PCZT_TRANSPARENT_INPUT: u8 = 0x53;
pub const INS_PCZT_TRANSPARENT_OUTPUT: u8 = 0x54;
pub const INS_PCZT_SIGN_TRANSPARENT: u8 = 0x55;
pub const INS_PCZT_ORCHARD_ACTION: u8 = 0x56;
pub const INS_PCZT_SIGN_ORCHARD: u8 = 0x57;
pub const INS_PCZT_IRONWOOD_ACTION: u8 = 0x58;
pub const INS_PCZT_SIGN_IRONWOOD: u8 = 0x59;

// Measurement-only instruction, outside the range the protocol assigns and absent from a released
// application. See `crate::heap_probe` for why it must stay that way.
#[cfg(feature = "heap_probe")]
pub const INS_HEAP_PROBE: u8 = 0xF0;

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

// The overwintered flag (bit 31) is ORed into the transaction version in the header digest, per
// ZIP-244 §T.1 and ZIP-229.
pub const OVERWINTERED_FLAG: u32 = 0x8000_0000;
pub const V6_TX_VERSION: u32 = 6;
pub const V6_VERSION_GROUP_ID: u32 = 0xD884B698;
