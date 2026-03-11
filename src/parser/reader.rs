use core::cmp;

use core2::io::Error as IoError;
use core2::io::ErrorKind as IoErrorKind;
use core2::io::Read;
use core2::io::Result;
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
