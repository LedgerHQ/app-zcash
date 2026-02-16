use core::ptr;
use core2::io::Write;

use ledger_device_sdk::hash::{blake2::Blake2b_256, HashInit as _};
use ledger_secure_sdk_sys::{cx_blake2b_init2_no_throw, cx_blake2b_t, cx_hash_t};

use crate::{log::error, utils::HexSlice};

pub trait Blake2b256Personalization {
    fn init_with_perso(&mut self, personalization: &[u8]);
}

impl Blake2b256Personalization for Blake2b_256 {
    fn init_with_perso(&mut self, perso: &[u8]) {
        assert_eq!(
            perso.len(),
            16,
            "Blake2b256 personalization must be 16 bytes"
        );

        let ctx = self.as_ctx_mut() as *mut _;

        unsafe {
            init_blake2b256_with_perso(ctx, perso.as_ptr(), perso.len());
        }
    }
}

pub struct Blake2b256IoWriter<'w>(&'w mut Blake2b_256);

pub trait AsWriter<'w> {
    fn as_writer(&'w mut self) -> Blake2b256IoWriter<'w>;
}

impl<'w> AsWriter<'w> for Blake2b_256 {
    fn as_writer(&'w mut self) -> Blake2b256IoWriter<'w> {
        Blake2b256IoWriter(self)
    }
}

impl Write for Blake2b256IoWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> core2::io::Result<usize> {
        self.0.update(buf).map_err(|err| {
            error!("Blake2b256IoWriter write error {:?}", err);
            core2::io::Error::new(core2::io::ErrorKind::Other, "Blake2b256 update error")
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> core2::io::Result<()> {
        unimplemented!("flush is not supported for Blake2b256IoWriter")
    }
}

// SAFETY: calling FFI `cx_blake2b_init2_no_throw` with a valid pointer to `cx_blake2b_t`
//
//  ```C
//  cx_err_t cx_blake2b_init2_no_throw(cx_blake2b_t *hash,
//                         size_t        size,
//                         uint8_t      *salt,
//                         size_t        salt_len,
//                         uint8_t      *perso,
//                         size_t        perso_len)
//  ```
unsafe fn init_blake2b256_with_perso(ctx: *mut cx_hash_t, perso: *const u8, perso_len: usize) {
    let _err = cx_blake2b_init2_no_throw(
        ctx as *mut cx_blake2b_t,
        256,
        ptr::null_mut(),
        0,
        perso as _,
        perso_len,
    );
}

use ledger_device_sdk::hash::sha2::Sha2_256;

pub struct Sha256IoWriter<'w>(&'w mut Sha2_256);

pub trait AsWriterB<'w> {
    fn as_writer(&'w mut self) -> Sha256IoWriter<'w>;
}

impl<'w> AsWriterB<'w> for Sha2_256 {
    fn as_writer(&'w mut self) -> Sha256IoWriter<'w> {
        Sha256IoWriter(self)
    }
}

impl Sha256IoWriter<'_> {
    pub fn dbg_update(&mut self, buf: &[u8]) -> core2::io::Result<()> {
        //debug!("MOO: {}", HexSlice(buf));

        self.0.update(buf).map_err(|err| {
            error!("Sha256IoWriter update error {:?}", err);
            core2::io::Error::new(core2::io::ErrorKind::Other, "Sha256 update error")
        })
    }
}

impl Write for Sha256IoWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> core2::io::Result<usize> {
        //debug!("MOO: {}", HexSlice(buf));

        self.0.update(buf).map_err(|err| {
            error!("Sha256IoWriter write error {:?}", err);
            core2::io::Error::new(core2::io::ErrorKind::Other, "Sha256 update error")
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> core2::io::Result<()> {
        unimplemented!("flush is not supported for Sha256IoWriter")
    }
}
