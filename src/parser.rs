use ::orchard::bundle::commitments::ZCASH_ORCHARD_V5_HASH_PERSONALIZATION;
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::hash::blake2::Blake2b_256;
use ledger_device_sdk::log::debug;

use crate::utils::HexSlice;
use error::ok;
use reader::ByteReader;

pub(crate) mod compute;
mod error;
pub(crate) mod legacy;
pub(crate) mod orchard_decipher;
mod pczt;
pub(crate) mod personalization;
pub(crate) mod reader;

pub use error::{ParserError, ParserSourceError};
pub use legacy::{
    LegacyOutputParser, LegacyOutputParserCtx, LegacyParser, LegacyParserCtx, LegacyParserMode,
};
pub use pczt::{PcztParser, PcztParserCtx};

pub(crate) const HASH_SIZE: usize = 32;
pub(crate) const ORCHARD_MEMO_SIZE: usize = 512;

pub(crate) fn hash_reader_chunk(
    reader: &mut ByteReader<'_>,
    hasher: &mut Blake2b_256,
    remaining_size: usize,
) -> Result<usize, ParserError> {
    let to_read = core::cmp::min(remaining_size, reader.remaining_len());
    ok!(hasher.update(&reader.remaining_slice()[..to_read]));
    ok!(reader.advance(to_read));
    Ok(remaining_size - to_read)
}

pub(crate) fn hash_reader_exact(
    reader: &mut ByteReader<'_>,
    hasher: &mut Blake2b_256,
    size: usize,
    err_msg: &'static str,
) -> Result<(), ParserError> {
    if reader.remaining_len() < size {
        return Err(ParserError::from_str(err_msg));
    }

    ok!(hasher.update(&reader.remaining_slice()[..size]));
    ok!(reader.advance(size));
    Ok(())
}

pub(crate) fn finalize_and_log_hash(
    hasher: &mut Blake2b_256,
    label: &str,
) -> Result<[u8; HASH_SIZE], ParserError> {
    let mut hash = [0u8; HASH_SIZE];
    ok!(hasher.finalize(&mut hash));
    debug!("{}: {}", label, HexSlice(&hash));
    Ok(hash)
}
