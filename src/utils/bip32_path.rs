use crate::AppSW;
use core::mem::size_of;

pub const MAX_ZCASH_BIP32_PATH: usize = 10;
pub const BIP32_BYTES_PER_SEGMENT: usize = size_of::<u32>();

/// BIP32 derivation path stored as a vector of u32 components.
///
/// Each component represents one level in the path (e.g., m/44'/1'/0'/0/0 has 5 components).
/// Hardened derivation is indicated by setting the high bit (>= 0x80000000).
#[derive(Default, Debug)]
pub struct Bip32Path {
    path: [u32; MAX_ZCASH_BIP32_PATH],
    path_len: u8,
}

impl Bip32Path {
    pub fn as_slice(&self) -> &[u32] {
        &self.path[..self.path_len as usize]
    }
    pub fn from_dpath(dpath_len: usize, dpath: &[u8]) -> Result<Self, AppSW> {
        if dpath.len() < dpath_len * BIP32_BYTES_PER_SEGMENT || dpath_len > MAX_ZCASH_BIP32_PATH {
            return Err(AppSW::WrongApduLength);
        }

        let mut path = [0u32; MAX_ZCASH_BIP32_PATH];

        let (chunks, _) =
            dpath[..dpath_len * BIP32_BYTES_PER_SEGMENT].as_chunks::<{ BIP32_BYTES_PER_SEGMENT }>();

        for (i, chunk) in chunks.iter().enumerate() {
            path[i] = u32::from_be_bytes(*chunk);
        }

        Ok(Bip32Path {
            path,
            path_len: dpath_len as u8,
        })
    }
}

impl TryFrom<&[u8]> for Bip32Path {
    type Error = AppSW;

    /// Constructs a [`Bip32Path`] from APDU-encoded bytes.
    ///
    /// # Format
    ///
    /// - First byte: Number of path components (e.g., 5 for m/44'/1'/0'/0/0)
    /// - Remaining bytes: Big-endian u32 components (4 bytes each)
    ///
    /// # Example
    ///
    /// For path m/44'/1'/0'/0/0:
    /// ```text
    /// [0x05, 0x8000002C, 0x80000001, 0x80000000, 0x00000000, 0x00000000]
    /// ```
    ///
    /// # Note
    ///
    /// This uses `Vec` for dynamic allocation, which is fine for normal APDU handlers
    /// but CANNOT be used in swap's `check_address` or `get_printable_amount` due to
    /// BSS memory sharing with the Exchange app.
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.is_empty() {
            return Err(AppSW::WrongApduLength);
        }

        let path_len = data[0] as usize;
        let body = &data[1..];

        if body.len() != path_len * 4 {
            return Err(AppSW::WrongApduLength);
        }

        let (chunks, _) = body.as_chunks::<4>();

        let mut path = [0u32; MAX_ZCASH_BIP32_PATH];
        for (i, chunk) in chunks.iter().enumerate() {
            path[i] = u32::from_be_bytes(*chunk);
        }

        Ok(Bip32Path {
            path,
            path_len: path_len as u8,
        })
    }
}
