use core::panic::PanicInfo;

use ledger_device_sdk::io;
use ledger_device_sdk::log::error;

static mut SWAP_COMM: *mut io::Comm = core::ptr::null_mut();

static mut SWAP_PANIC_HANDLER: Option<fn(&PanicInfo) -> !> = None;

pub fn get_swap_panic_handler() -> Option<fn(&PanicInfo) -> !> {
    unsafe { SWAP_PANIC_HANDLER }
}

// Set the panic handler for the swap app
// SAFETY: should be used only in lib swap call, after app is initialized
pub(crate) unsafe fn set_swap_panic_handler(handler: fn(&PanicInfo) -> !) {
    unsafe {
        SWAP_PANIC_HANDLER = Some(handler);
    }
}

/// Registers the transport for the swap panic handler.
///
/// # Safety
/// `comm` must stay valid until the app returns to Exchange, and every `&mut Comm` the app uses
/// must derive from it.
pub(crate) unsafe fn set_swap_comm(comm: *mut io::Comm) {
    unsafe { SWAP_COMM = comm };
}

pub(crate) fn swap_panic_handler(info: &PanicInfo) -> ! {
    error!("Swap panic happened! {:#?}", info);

    // SAFETY: the interrupted `Comm` borrow is never resumed, and the reply restarts at offset
    // zero with the status word alone, so nothing it left half-written is sent.
    unsafe {
        if !SWAP_COMM.is_null() {
            let _ = (*SWAP_COMM).begin_response().send(io::StatusWords::Panic);
        }
    }

    unsafe { ledger_device_sdk::sys::os_lib_end() }
}
