use crate::consts::{UNHARDENED_MASK, ZCASH_BIP44_COIN_TYPE, ZIP32_PATH_LEN, ZIP32_PURPOSE};
use crate::utils::bip32_path::Bip32Path;
use alloc::vec::Vec;
use ledger_device_sdk::log::error;

pub mod base58_address;
pub mod bip32_path;
pub mod blake2b_256_pers;
pub mod extended_public_key;
pub mod hashers;
use crate::AppSW;

pub use ledger_zcash_crypto::transparent_script::{
    CheckDispOutput, check_output_displayable, output_script_is_op_return, output_script_is_p2sh,
    output_script_is_regular,
};

// The two BIP32 prefixes this app is loaded with (`package.metadata.ledger.path`): BIP-44 for the
// transparent tree, ZIP-32 for the shielded one. A path outside them is refused by the OS, and this
// is what lets the app refuse it first, with a status word.
const APP_DECLARED_PURPOSES: [u32; 2] = [44, 32];
// Purpose of the transparent tree. A five-component path is a BIP-44 path, so 44 is the only
// purpose it can carry — ZIP-32 defines no derivation at that depth. Accepting 32 here would let an
// `m/32'/133'/a'/1/i` output pass the change check and be hidden from the review screen: the same
// defect the mode-before-shape ordering below closes for the three-component form, reached through
// a different shape.
const BIP44_PURPOSE: u32 = 44;

const BIP44_PATH_LEN: usize = 5;
const BIP44_ACCOUNT_OFFSET: usize = 2;

/// The account component of a derivation path, hardening bit included.
///
/// Accepts both trees the app derives in: BIP-44 for transparent keys, ZIP-32 for shielded ones.
/// They place the account at the same depth, and a transparent and a shielded path bearing the same
/// account belong to the same wallet account — which is what lets a transparent change output be
/// compared against a shielded spend.
///
/// Returned raw on purpose. The account is what separates two key trees, so an unhardened value
/// must not compare equal to the hardened one: masking here would let `m/44'/133'/2/0/0` pass for
/// account `2'` while deriving somewhere else entirely.
pub fn derivation_account(path: &Bip32Path) -> Option<u32> {
    let path = path.as_slice();
    if path.len() != BIP44_PATH_LEN && path.len() != ZIP32_PATH_LEN {
        return None;
    }
    Some(path[BIP44_ACCOUNT_OFFSET])
}

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

pub enum Bip44CheckMode {
    Full {
        is_change_path: bool,
    },
    /// Purpose and coin type on a five-component BIP-44 path, or a ZIP-32 account path.
    OnlyCoinType,
    Zip32Only,
    /// Purpose and coin type only, at any depth: key export accepts account-level and deeper paths,
    /// so the app restricts its prefixes without dictating the shape.
    PrefixOnly,
}

pub fn check_bip44_compliance(path: &Bip32Path, mode: Bip44CheckMode) -> bool {
    const HARDENED: u32 = 0x8000_0000;
    const PURPOSE_OFFSET: usize = 0;

    const BIP44_COIN_TYPE_OFFSET: usize = 1;
    const BIP44_CHANGE_OFFSET: usize = 3;
    const BIP44_ADDRESS_INDEX_OFFSET: usize = 4;
    const MAX_BIP44_ACCOUNT_RECOMMENDED: u32 = 100;
    const MAX_BIP44_ADDRESS_INDEX_RECOMMENDED: u32 = 50000;

    const BIP44_PREFIX_LEN: usize = 2;

    let path = path.as_slice();
    let is_zip32_shape =
        path.len() == ZIP32_PATH_LEN && (path[0] & UNHARDENED_MASK) == ZIP32_PURPOSE;

    // The mode decides which shape is acceptable, so it is consulted before the shape: a ZIP-32
    // account path has no change, account or address-index component for `Full` to constrain.
    match mode {
        Bip44CheckMode::PrefixOnly => {
            if path.len() < BIP44_PREFIX_LEN {
                error!("Path too short to carry a prefix");
                return false;
            }

            // Compared hardening bit included. The app declares `44'/133'` and `32'/133'`, so an
            // unhardened prefix is a path the OS will not derive — and it answers that by taking the
            // app down, not by a status word. Masking the bit off here let such a path through the
            // one check standing between the host and the derivation.
            //
            // Only the two prefix components are constrained: key export legitimately takes paths of
            // any depth from two components up, and the shortest of them, `44'/133'`, is what Ledger
            // Live asks for to build the account xpub.
            if !APP_DECLARED_PURPOSES.contains(&(path[PURPOSE_OFFSET] & UNHARDENED_MASK))
                || path[PURPOSE_OFFSET] & HARDENED == 0
            {
                error!("Bad purpose");
                return false;
            }

            if path[BIP44_COIN_TYPE_OFFSET] != (ZCASH_BIP44_COIN_TYPE | HARDENED) {
                error!("Bad coin type");
                return false;
            }

            return true;
        }
        Bip44CheckMode::Zip32Only => {
            if !is_zip32_shape {
                error!("Path is not a ZIP32 path");
                return false;
            }
        }
        Bip44CheckMode::Full { .. } => {
            if is_zip32_shape {
                error!("ZIP32 path where a full BIP44 path is required");
                return false;
            }
        }
        // Shielded derivations arrive as ZIP-32 account paths, transparent ones as BIP-44.
        Bip44CheckMode::OnlyCoinType => {}
    }

    if is_zip32_shape {
        if path[PURPOSE_OFFSET] != (ZIP32_PURPOSE | HARDENED) {
            error!("Bad ZIP32 purpose");
            return false;
        }

        if path[BIP44_COIN_TYPE_OFFSET] != (ZCASH_BIP44_COIN_TYPE | HARDENED) {
            error!("Bad ZIP32 coin type");
            return false;
        }

        if path[BIP44_ACCOUNT_OFFSET] & HARDENED == 0 {
            error!("Bad ZIP32 account");
            return false;
        }

        return true;
    }

    if path.len() != BIP44_PATH_LEN {
        error!("Bad Bip44 path len");
        return false;
    }

    // BIP-44 hardens purpose, coin type and account. Comparing them with the hardening bit masked
    // off equates `m/44/133/…` with `m/44'/133'/…`, which derive unrelated keys: the app would
    // vouch for an address the wallet does not own. The OS refuses to derive a path outside the
    // ones the app declares, but it answers that refusal by aborting the app rather than by a
    // status word, so the check has to be exact here.
    if path[PURPOSE_OFFSET] != (BIP44_PURPOSE | HARDENED) {
        error!("Bad Bip44 purpose");
        return false;
    }

    if path[BIP44_COIN_TYPE_OFFSET] != (ZCASH_BIP44_COIN_TYPE | HARDENED) {
        error!("Bad Bip44 coin type");
        return false;
    }

    if let Bip44CheckMode::Full { is_change_path } = mode {
        if path[BIP44_ACCOUNT_OFFSET] & HARDENED == 0 {
            error!("Bip44 account is not hardened");
            return false;
        }

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

        // Change and address index are the non-hardened half of BIP-44, and both are read unmasked:
        // a hardened value exceeds the bound below on its own, so it cannot pass for the small
        // index it would be mistaken for.
        let address_index = path[BIP44_ADDRESS_INDEX_OFFSET];
        if address_index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED {
            error!("Bad Bip44 address index");
            return false;
        }
    }

    true
}

pub fn encode_string_response(value: &str) -> Result<Vec<u8>, AppSW> {
    let value_bytes = value.as_bytes();

    // The response length is a u16 on the wire. No caller passes anything near that, but a length
    // that cannot be encoded is an error to report, not a reason to exit the app.
    let len: u16 = u16::try_from(value_bytes.len()).map_err(|_| AppSW::TechnicalProblem)?;

    let mut response = Vec::with_capacity(2 + value_bytes.len());
    response.extend_from_slice(&len.to_be_bytes());
    response.extend_from_slice(value_bytes);
    Ok(response)
}
