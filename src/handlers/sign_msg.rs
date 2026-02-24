use ledger_device_sdk::io::Comm;

use crate::{handlers::sign_tx::TxContext, AppSW};

pub fn handler_sign_msg(
    _comm: &mut Comm,
    _ctx: &mut TxContext,
    _first: bool,
    _next: bool,
) -> Result<(), AppSW> {
    Err(AppSW::InsNotSupported)
}
