use arrayvec::ArrayString;
use ledger_device_sdk::hash::{HashInit, sha2::Sha2_256};

use crate::Error;

pub const TRANSPARENT_ADDRESS_B58_LEN: usize = 35;

const PREFIX_LEN: usize = 2;
const HASH_LEN: usize = 20;
const PAYLOAD_LEN: usize = PREFIX_LEN + HASH_LEN;
const CHECKSUM_LEN: usize = 4;
const BASE58_CHECK_BUFFER_LEN: usize = PAYLOAD_LEN + CHECKSUM_LEN;

fn double_sha256_checksum(input: &[u8]) -> Result<[u8; CHECKSUM_LEN], Error> {
    let mut h1 = Sha2_256::new();
    let mut o1 = [0u8; 32];
    h1.hash(input, &mut o1)?;

    let mut h2 = Sha2_256::new();
    let mut o2 = [0u8; 32];
    h2.hash(&o1, &mut o2)?;

    Ok([o2[0], o2[1], o2[2], o2[3]])
}

/// Encodes a transparent address as Base58Check: `prefix || hash160`, followed by a
/// double-SHA256 checksum. Used for both P2PKH and P2SH transparent addresses, which share
/// the same 22-byte payload shape and differ only in the version prefix.
pub fn base58check_transparent_address(
    prefix: &[u8; 2],
    hash160: &[u8; 20],
) -> Result<ArrayString<TRANSPARENT_ADDRESS_B58_LEN>, Error> {
    let mut buf = [0u8; BASE58_CHECK_BUFFER_LEN];
    buf[..PREFIX_LEN].copy_from_slice(prefix);
    buf[PREFIX_LEN..PAYLOAD_LEN].copy_from_slice(hash160);

    let checksum = double_sha256_checksum(&buf[..PAYLOAD_LEN])?;
    buf[PAYLOAD_LEN..].copy_from_slice(&checksum);

    let mut out = [0u8; TRANSPARENT_ADDRESS_B58_LEN];
    let written = bs58::encode(&buf)
        .onto(&mut out[..])
        .map_err(|_| Error::OutOfMemory)?;

    // `bs58`'s alphabet is pure ASCII, and `written` is bounded by `out.len()`, the
    // `ArrayString`'s own capacity: neither conversion below can fail.
    let s = core::str::from_utf8(&out[..written]).expect("cannot fail");
    Ok(ArrayString::from(s).expect("cannot fail"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_device_sdk::testing::TestType;

    #[test_case]
    const MAINNET_P2SH_REFERENCE_VECTOR: TestType = TestType {
        modname: module_path!(),
        name: "mainnet_p2sh_reference_vector",
        f: || {
            let prefix = [0x1C, 0xBD];
            let hash160: [u8; 20] = match hex_20("217e3298b6a963a8722b0e7c7d8f3aff1d9472bd") {
                Some(h) => h,
                None => return Err(()),
            };

            let address = match base58check_transparent_address(&prefix, &hash160) {
                Ok(address) => address,
                Err(_) => return Err(()),
            };

            if address.as_str() != "t3MciQaJ4pe9zHywiRjRHCnK2nibbtzPuiP" {
                return Err(());
            }
            Ok(())
        },
    };

    #[test_case]
    const MAINNET_P2PKH_REGRESSION_VECTOR: TestType = TestType {
        modname: module_path!(),
        name: "mainnet_p2pkh_regression_vector",
        f: || {
            let prefix = [0x1C, 0xB8];
            let hash160 = [0x11u8; 20];

            let address = match base58check_transparent_address(&prefix, &hash160) {
                Ok(address) => address,
                Err(_) => return Err(()),
            };

            if address.as_str() != "t1KRqwQhktLV4BjbNLiuH6pb3AMoszZKcQB" {
                return Err(());
            }
            Ok(())
        },
    };

    #[test_case]
    const TESTNET_P2PKH_VECTOR: TestType = TestType {
        modname: module_path!(),
        name: "testnet_p2pkh_vector",
        f: || {
            let prefix = [0x1D, 0x25];
            let hash160 = [0x22u8; 20];

            let address = match base58check_transparent_address(&prefix, &hash160) {
                Ok(address) => address,
                Err(_) => return Err(()),
            };

            if address.as_str() != "tmCpqCKUnC1h1v5LHQkJAvVjug3WVePS7t7" {
                return Err(());
            }
            Ok(())
        },
    };

    #[test_case]
    const TESTNET_P2SH_VECTOR: TestType = TestType {
        modname: module_path!(),
        name: "testnet_p2sh_vector",
        f: || {
            let prefix = [0x1C, 0xBA];
            let hash160 = [0x33u8; 20];

            let address = match base58check_transparent_address(&prefix, &hash160) {
                Ok(address) => address,
                Err(_) => return Err(()),
            };

            if address.as_str() != "t2BDXmmsa8ioiznxVC9kE166rEmZMnhPPBs" {
                return Err(());
            }
            Ok(())
        },
    };

    fn hex_20(hex: &str) -> Option<[u8; 20]> {
        if hex.len() != 40 {
            return None;
        }

        let mut out = [0u8; 20];
        for i in 0..20 {
            out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(out)
    }
}
