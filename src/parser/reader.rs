use core::cmp;

use corez::io::Error as IoError;
use corez::io::ErrorKind as IoErrorKind;
use corez::io::Read;
use corez::io::Result;
use ledger_device_sdk::log::debug;

pub struct ByteReader<'b> {
    buf: &'b [u8],
    pos: usize,
}

impl<'b> ByteReader<'b> {
    pub fn new(buf: &'b [u8]) -> Self {
        ByteReader { buf, pos: 0 }
    }

    pub fn remaining_len(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn _remaining_debug(&self) {
        debug!(
            "Remaining bytes (len {}) {:X?}",
            self.remaining_len(),
            &self.buf[self.pos..]
        );
    }

    pub fn remaining_slice(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    pub fn advance(&mut self, n: usize) -> Result<()> {
        let remaining = self.buf.len() - self.pos;
        if n > remaining {
            return Err(IoError::new(
                IoErrorKind::UnexpectedEof,
                "not enough bytes to skip",
            ));
        }
        self.pos += n;
        Ok(())
    }
}

impl Read for ByteReader<'_> {
    fn read(&mut self, buf: &'_ mut [u8]) -> Result<usize> {
        let remaining = self.buf.len() - self.pos;
        let to_read = cmp::min(remaining, buf.len());
        buf[..to_read].copy_from_slice(&self.buf[self.pos..self.pos + to_read]);
        self.pos += to_read;

        Ok(to_read)
    }
}

/// Little-endian primitive reads on top of [`Read`].
///
/// Replaces the (crate-private) `zcash_primitives::encoding::ReadBytesExt` so
/// the app can build against the published `zcash_primitives` crate. The
/// blanket impl makes these methods available on any `Read`er, including
/// [`ByteReader`].
pub trait ReadBytesExt: Read {
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_u64_le(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

impl<R: Read + ?Sized> ReadBytesExt for R {}
