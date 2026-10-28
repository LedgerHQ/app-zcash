use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::NbglChoice;

use crate::AppSW;
use crate::app_ui::{load_glyph, sign::try_format};

/// Ask before checking an output against another account of the seed: the check's outcome reaches
/// the host before the user reviews the transaction.
pub fn ui_confirm_own_account_check(comm: &mut Comm, account: u32) -> Result<bool, AppSW> {
    let message = try_format(format_args!(
        "Check Account index {}?",
        u64::from(account) + 1
    ))?;

    Ok(NbglChoice::new().glyph(load_glyph()).show(
        comm,
        &message,
        "The wallet will learn whether an output pays this account of yours, before you review the transaction.",
        "Allow",
        "Reject",
    ))
}
