//! Run the actual SDK command decoder and review callbacks with a scripted OS/transport.
#![allow(dead_code, unused_imports, non_camel_case_types)]

extern crate self as ledger_secure_sdk_sys;

use std::cell::RefCell;
use std::collections::VecDeque;

#[path = "sdk_io/mod.rs"]
mod io_new;
use io_new as io;
#[path = "sdk_seph.rs"]
mod sdk_seph;

// Only platform bindings and the legacy status/header definitions are substituted.
pub const OS_IO_PACKET_TYPE_NONE: u8 = 0;
pub const OS_IO_PACKET_TYPE_SEPH: u8 = 1;
pub const OS_IO_PACKET_TYPE_SE_EVT: u8 = 2;
pub const OS_IO_PACKET_TYPE_RAW_APDU: u8 = 3;
pub const OS_IO_PACKET_TYPE_USB_HID_APDU: u8 = 4;
pub const OS_IO_PACKET_TYPE_USB_WEBUSB_APDU: u8 = 5;
pub const OS_IO_PACKET_TYPE_BLE_APDU: u8 = 6;
pub const SEPROXYHAL_TAG_TICKER_EVENT: u32 = 0x0e;
pub const SEPROXYHAL_TAG_BUTTON_PUSH_EVENT: u32 = 5;
pub const SEPROXYHAL_TAG_FINGER_EVENT: u32 = 0x0c;
pub const SEPROXYHAL_TAG_ITC_EVENT: u32 = 0x1f;
pub const ITC_UX_ASK_BLE_PAIRING: u8 = 1;
pub const ITC_UX_BLE_PAIRING_STATUS: u8 = 2;
pub const ITC_UX_REDISPLAY: u8 = 3;
pub const BOLOS_TAG_APPNAME: u32 = 1;
pub const BOLOS_TAG_APPVERSION: u32 = 2;

mod io_legacy {
    #[derive(Clone, Copy, Debug)]
    pub struct ApduHeader {
        pub cla: u8,
        pub ins: u8,
        pub p1: u8,
        pub p2: u8,
    }
    pub enum Event<T> {
        Command(T),
    }
    #[derive(Debug)]
    pub struct Reply(pub u16);
    impl From<std::convert::Infallible> for Reply {
        fn from(value: std::convert::Infallible) -> Self {
            match value {}
        }
    }
    #[repr(u16)]
    #[derive(Clone, Copy)]
    pub enum StatusWords {
        Ok = 0x9000,
        BadLen = 0x6700,
        BadCla = 0x6e00,
        BadIns = 0x6d00,
        CmdNotAccepted = 0x6901,
        Panic = 0xe000,
    }
    impl From<StatusWords> for Reply {
        fn from(value: StatusWords) -> Self {
            Self(value as u16)
        }
    }
    pub const BOLOS_INS_GET_VERSION: u8 = 1;
    pub const BOLOS_INS_QUIT: u8 = 0xa7;
    pub const BOLOS_INS_SET_PKI_CERT: u8 = 6;
    pub struct PkiLoadCertificateError;
    impl From<u32> for PkiLoadCertificateError {
        fn from(_: u32) -> Self {
            Self
        }
    }
    pub struct SyscallError;
    impl From<PkiLoadCertificateError> for SyscallError {
        fn from(_: PkiLoadCertificateError) -> Self {
            Self
        }
    }
    impl From<SyscallError> for Reply {
        fn from(_: SyscallError) -> Self {
            Self(0x6f00)
        }
    }
}

struct Packet {
    bytes: Vec<u8>,
}
#[derive(Default)]
struct Os {
    incoming: VecDeque<Packet>,
    replies: Vec<(u8, Vec<u8>)>,
    builtin_calls: usize,
    review_callback: Option<fn() -> bool>,
    fail_send: bool,
}
thread_local! { static OS: RefCell<Os> = RefCell::new(Os::default()); }

mod seph {
    pub use super::sdk_seph::*;
    pub fn io_rx(buffer: &mut [u8], _: bool) -> i32 {
        super::OS.with_borrow_mut(|os| {
            let packet = os.incoming.pop_front().expect("unexpected receive");
            buffer[..packet.bytes.len()].copy_from_slice(&packet.bytes);
            packet.bytes.len() as i32
        })
    }
    pub fn io_tx(transport: u8, buffer: &[u8], length: usize) -> i32 {
        super::OS.with_borrow_mut(|os| os.replies.push((transport, buffer[..length].to_vec())));
        super::OS.with_borrow(|os| if os.fail_send { -1 } else { length as i32 })
    }
}
mod io_callbacks {
    pub fn nbgl_register_callbacks(
        next: fn() -> bool,
        _: fn() -> Option<super::io_legacy::ApduHeader>,
        _: fn(super::io_legacy::Reply),
    ) {
        super::OS.with_borrow_mut(|os| os.review_callback = Some(next));
    }
}
pub unsafe fn os_registry_get_current_app_tag(_: u32, _: *mut u8, _: u32) -> u32 {
    OS.with_borrow_mut(|os| os.builtin_calls += 1);
    0
}
pub unsafe fn os_flags() -> u32 {
    0
}
pub fn exit_app(_: u8) -> ! {
    panic!("unexpected quit command")
}
#[derive(Default)]
pub struct cx_ecfp_384_public_key_t;
pub unsafe fn os_pki_load_certificate(
    _: u8,
    _: *mut u8,
    _: usize,
    _: *mut u8,
    _: *mut u8,
    _: *mut cx_ecfp_384_public_key_t,
) -> u32 {
    panic!("unexpected certificate command")
}

const APP_CLA: u8 = 0xe0;
const APP_INS: u8 = 0xc4;
const VERSION: [u8; 5] = [APP_CLA, APP_INS, 0, 0, 0];
const USB: u8 = OS_IO_PACKET_TYPE_USB_HID_APDU;
const BLE: u8 = OS_IO_PACKET_TYPE_BLE_APDU;

fn enqueue(transport: u8, data: &[u8]) {
    let mut bytes = vec![transport];
    bytes.extend_from_slice(data);
    OS.with_borrow_mut(|os| os.incoming.push_back(Packet { bytes }));
}
fn reset() {
    OS.with_borrow_mut(|os| *os = Os::default());
}

#[test]
fn fallible_reply_returns_transport_errors_without_panicking() {
    reset();
    OS.with_borrow_mut(|os| os.fail_send = true);
    let mut comm = io::Comm::<273>::new();
    assert!(matches!(
        comm.begin_response().send(io::StatusWords::Panic),
        Err(io::CommError::IoError)
    ));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = comm.send(&[], io::StatusWords::Panic);
        }))
        .is_err()
    );
}

#[test]
fn builtins_and_errors_follow_published_sdk_behavior() {
    reset();
    enqueue(USB, &[0xb0, 1, 0, 0, 0]);
    enqueue(USB, &[0xff, APP_INS, 0, 0, 0]);
    enqueue(USB, &[APP_CLA, APP_INS, 0, 0, 2, 1]);
    enqueue(USB, &VERSION);
    let mut comm = io::Comm::<273>::new();
    comm.set_expected_cla(APP_CLA);
    let _ = comm.next_command();
    OS.with_borrow(|os| {
        let statuses: Vec<_> = os
            .replies
            .iter()
            .map(|(_, bytes)| &bytes[bytes.len() - 2..])
            .collect();
        assert_eq!(statuses, [&[0x90, 0x00], &[0x6e, 0x00], &[0x67, 0x00]]);
        assert_eq!(os.builtin_calls, 2);
    });
}

#[test]
fn overlapping_review_commands_preserve_the_original_reply() {
    reset();
    static STORAGE: io::CommStorage = io::CommStorage::new();
    let comm = io::init_comm(&STORAGE);
    enqueue(USB, &VERSION);
    let comm = comm.next_command().into_comm();
    let callback = OS.with_borrow(|os| os.review_callback.unwrap());
    let mut expected = Vec::new();
    for transport in [
        OS_IO_PACKET_TYPE_RAW_APDU,
        USB,
        OS_IO_PACKET_TYPE_USB_WEBUSB_APDU,
        BLE,
    ] {
        enqueue(transport, &VERSION);
        assert!(!callback());
        expected.push((transport, vec![0x69, 0x01]));
    }
    comm.send(&[42], io::StatusWords::Ok).unwrap();
    expected.push((USB, vec![42, 0x90, 0x00]));
    OS.with_borrow(|os| assert_eq!(os.replies, expected));
}
