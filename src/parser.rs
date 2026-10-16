use ::orchard::bundle::commitments::ZCASH_ORCHARD_V5_HASH_PERSONALIZATION;
use alloc::string::String;
use core::fmt::Write as _;
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::hash::blake2::Blake2b_256;
use ledger_device_sdk::log::debug;

use crate::AppSW;
use crate::tx::{TxInfo, TxOutputMemo};
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

/// Whether a memo can be shown as text rather than hashed or hex-encoded.
///
/// Printable ASCII only. This is also what keeps a NUL byte out of the retained text: the review
/// hands each value to the C layer as a NUL-terminated string, and an interior NUL panics the
/// build of it — an app exit the host would choose. Widening this to non-ASCII UTF-8 would have to
/// keep excluding it.
pub(crate) fn is_displayable_memo_text(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| matches!(byte, 0x20..=0x7E))
}

/// Keep a transparent OP_RETURN output's data for the review.
///
/// Shown as text when [`is_displayable_memo_text`] allows it, as hexadecimal otherwise: either way
/// all of it, since the script check admits at most 80 bytes.
///
/// Refused under swap. There the Exchange approval stands in for the review and names no memo, so
/// one would be signed without the user ever seeing it.
pub(crate) fn accept_op_return(
    tx_info: &mut TxInfo,
    data: &[u8],
    in_swap: bool,
) -> Result<(), ParserError> {
    if in_swap {
        return Err(ParserError::from_str(
            "OP_RETURN output not supported in swap",
        ));
    }

    if tx_info.op_return.is_some() {
        return Err(ParserError::from_str("Multiple OP_RETURN outputs"));
    }

    let is_text = is_displayable_memo_text(data);
    let mut value = String::new();
    value
        .try_reserve_exact(if is_text { data.len() } else { 2 * data.len() })
        .map_err(|_| ParserError::from_sw(AppSW::NotEnoughMemorySpace))?;

    let label = if is_text {
        // Printable ASCII, so valid UTF-8 one byte per character.
        value.extend(data.iter().map(|byte| char::from(*byte)));
        "Memo"
    } else {
        for byte in data {
            // Writes into the capacity reserved just above, so it cannot reach the allocator again.
            let _ = write!(&mut value, "{byte:02x}");
        }
        "Memo (hex)"
    };

    tx_info.op_return = Some(TxOutputMemo { label, value });
    Ok(())
}
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
