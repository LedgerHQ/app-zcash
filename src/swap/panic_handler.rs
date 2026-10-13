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

/// Retain the initialized transport for the diverging swap panic handler.
///
/// # Safety
/// `comm` must stay valid until the app returns to Exchange, and every `&mut Comm` the app uses
/// must be derived from this same pointer. The handler's reborrow then only ends a borrow that
/// is never used again, since the handler does not return.
pub(crate) unsafe fn set_swap_comm(comm: *mut io::Comm) {
    unsafe { SWAP_COMM = comm };
}

pub(crate) fn swap_panic_handler(info: &PanicInfo) -> ! {
    error!("Swap panic happened! {:#?}", info);

    // A fresh Comm has no transport. Use the registered static instance, as the
    // SDK's exiting panic handler does, but return to Exchange afterward.
    //
    // SAFETY: a panic raised inside a `Comm` method leaves that method's borrow on the stack
    // below this frame, mid-update. The reply restarts staging at offset zero and carries the
    // status word alone, so nothing that method left in the buffer is sent, and no frame below
    // runs again once control returns to Exchange.
    unsafe {
        if !SWAP_COMM.is_null() {
            let _ = (*SWAP_COMM).begin_response().send(io::StatusWords::Panic);
        }
    }

    unsafe { ledger_device_sdk::sys::os_lib_end() }
}
