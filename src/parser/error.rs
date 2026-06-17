use alloc::string::String;
use corez::io::Error as IoError;

use ledger_device_sdk::hash::HashError;
use ledger_device_sdk::hmac::HMACError;
use ledger_device_sdk::libcall::SwapAppErrorCodeTrait;
use ledger_device_sdk::libcall::swap::SwapError;

use zcash_protocol::value::BalanceError;

use crate::AppSW;
use crate::swap::SwapAppErrorCode;

// NOTE: `#[allow(unused)]` is used due to false positive unused warnings, as it is only used for debug logs.
// Derived `Debug` impls don't count towards "using" code in Rust compiler.
#[allow(unused)]
#[derive(Debug)]
pub enum ParserSourceError {
    Io(IoError),
    Hash(HashError),
    Hmac(HMACError),
    Balance(BalanceError),
    Custom(&'static str),
    AppSW(AppSW),
    SwapError {
        common_code: u8,
        app_code: u8,
        message: Option<String>,
    },
    UserDenied,
}

impl From<IoError> for ParserSourceError {
    fn from(e: IoError) -> Self {
        ParserSourceError::Io(e)
    }
}

impl From<HashError> for ParserSourceError {
    fn from(e: HashError) -> Self {
        ParserSourceError::Hash(e)
    }
}

impl From<HMACError> for ParserSourceError {
    fn from(e: HMACError) -> Self {
        ParserSourceError::Hmac(e)
    }
}

impl From<BalanceError> for ParserSourceError {
    fn from(e: BalanceError) -> Self {
        ParserSourceError::Balance(e)
    }
}

impl From<&'static str> for ParserSourceError {
    fn from(e: &'static str) -> Self {
        ParserSourceError::Custom(e)
    }
}

impl From<AppSW> for ParserSourceError {
    fn from(e: AppSW) -> Self {
        ParserSourceError::AppSW(e)
    }
}

impl From<SwapError<SwapAppErrorCode>> for ParserSourceError {
    fn from(e: SwapError<SwapAppErrorCode>) -> Self {
        ParserSourceError::SwapError {
            common_code: e.common_code as u8,
            app_code: e.app_code.as_u8(),
            message: e.message,
        }
    }
}

#[derive(Debug)]
pub struct ParserError {
    pub source: ParserSourceError,
    // NOTE: `#[allow(unused)]` is used due to false positive unused warnings, as it is only used for debug logs.
    #[allow(unused)]
    pub file: &'static str,
    // NOTE: `#[allow(unused)]` is used due to false positive unused warnings, as it is only used for debug logs.
    #[allow(unused)]
    pub line: u32,
}

impl ParserError {
    #[track_caller]
    pub fn from_str(reason: &'static str) -> ParserError {
        ParserError {
            source: reason.into(),
            file: file!(),
            line: line!(),
        }
    }

    #[track_caller]
    pub fn from_sw(sw: AppSW) -> ParserError {
        ParserError {
            source: sw.into(),
            file: file!(),
            line: line!(),
        }
    }

    #[track_caller]
    pub fn user() -> ParserError {
        ParserError {
            source: ParserSourceError::UserDenied,
            file: file!(),
            line: line!(),
        }
    }
}

macro_rules! _ok {
    ($expr:expr) => {{
        match $expr {
            Ok(v) => Ok(v),
            Err(e) => Err(ParserError {
                source: e.into(),
                file: file!(),
                line: line!(),
            }),
        }?
    }};
    ($expr:expr, $reason:literal) => {{
        match $expr {
            Ok(v) => Ok(v),
            Err(()) => Err(ParserError {
                source: $reason.into(),
                file: file!(),
                line: line!(),
            }),
        }?
    }};
}

pub(super) use _ok as ok;
