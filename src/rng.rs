//! Fail-closed access to the hardware random number generator.
//!
//! `ledger_device_sdk::random::rand_bytes` is built on `cx_rng_no_throw`, which the C SDK declares
//! as `void cx_rng_no_throw(uint8_t *buffer, size_t len)`: despite the `_no_throw` name it exposes
//! no status, so a caller cannot tell a successful draw from a failed one. Callers draw into
//! freshly zeroed buffers, so a failure yields all-zero "randomness" that looks like a valid draw.
//! Neither consumer in this app can tolerate that:
//!
//! * a zero seed makes a RedPallas nonce a public function of the verification key and the message,
//!   which discloses the spend authorizing key from a single signature;
//! * a zero trusted-input HMAC key is persisted to NVM on first boot and lets the host forge
//!   trusted inputs for the lifetime of the installation.
//!
//! The OS does provide a fallible entry point — `cx_err_t cx_get_random_bytes(void *, size_t)` from
//! `os_random.h` — so this module draws through it and checks the status the way the SDK does for
//! its other `cx_err_t` syscalls.

use ledger_device_sdk::log::error;
use ledger_device_sdk::sys::{CX_OK, cx_get_random_bytes};

use crate::AppSW;

/// Fills `dest` with random bytes, reporting a failure instead of leaving `dest` unchanged.
///
/// Prefer this over `ledger_device_sdk::random::rand_bytes` for any value whose secrecy or
/// unpredictability is load-bearing.
pub fn fill_bytes(dest: &mut [u8]) -> Result<(), AppSW> {
    if dest.is_empty() {
        return Ok(());
    }

    // SAFETY: `dest` is a valid, uniquely borrowed slice of `dest.len()` initialized bytes, and
    // `cx_get_random_bytes` writes at most `dest.len()` bytes into it.
    let status = unsafe { cx_get_random_bytes(dest.as_mut_ptr().cast(), dest.len()) };

    if status != CX_OK {
        error!("cx_get_random_bytes failed: {}", status);
        return Err(AppSW::RngFailure);
    }

    Ok(())
}
