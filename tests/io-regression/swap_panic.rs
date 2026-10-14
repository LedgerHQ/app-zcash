//! Exercise the application's actual panic handler, including a failed error reply.
#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate self as ledger_device_sdk;

#[path = "swap_panic_handler.rs"]
mod handler;

#[link(name = "c")]
unsafe extern "C" {
    fn exit(status: i32) -> !;
}

#[macro_export]
macro_rules! error {
    ($($args:tt)*) => {{ let _ = core::format_args!($($args)*); }};
}
pub mod log {
    pub use crate::error;
}

// Mirror the SDK's two send contracts. The SDK fixture separately runs the real
// SDK implementations with a failing transport to keep this contract checked.
pub mod io {
    pub struct Comm;
    pub enum StatusWords {
        Panic,
    }
    #[derive(Debug)]
    pub struct IoError;
    pub struct Response;

    impl Comm {
        pub fn send(&mut self, _: &[u8], reply: StatusWords) -> Result<(), IoError> {
            self.begin_response().send(reply).unwrap();
            Ok(())
        }
        pub fn begin_response(&mut self) -> Response {
            Response
        }
    }
    impl Response {
        pub fn send(self, _: StatusWords) -> Result<(), IoError> {
            unsafe {
                super::ATTEMPTS += 1;
            }
            if cfg!(send_failure) {
                Err(IoError)
            } else {
                Ok(())
            }
        }
    }
}
pub mod sys {
    pub unsafe fn os_lib_end() -> ! {
        unsafe { super::exit(if super::ATTEMPTS == 1 { 0 } else { 1 }) }
    }
}

static mut COMM: io::Comm = io::Comm;
static mut ATTEMPTS: usize = 0;
static mut PANICKING: bool = false;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        if PANICKING {
            exit(2);
        }
        PANICKING = true;
    }
    handler::swap_panic_handler(info)
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i32 {
    unsafe {
        handler::set_swap_comm(&raw mut COMM);
    }
    panic!("original swap failure");
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
