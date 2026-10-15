use ledger_device_sdk::libcall::swap::CheckAddressParams;

use ledger_device_sdk::sys::{check_address_parameters_t, libargs_s__bindgen_ty_1, libargs_t};

const DPATH_STAGE_SIZE: usize = 16;

/// patched version of swap::get_check_address_params to support legacy path
/// differs in the path, which contains extra byte
pub fn get_check_address_params<
    const COIN_CONFIG_BUF_SIZE: usize,
    const ADDRESS_BUF_SIZE: usize,
    const ADDRESS_EXTRA_ID_BUF_SIZE: usize,
>(
    arg0: u32,
) -> CheckAddressParams<COIN_CONFIG_BUF_SIZE, ADDRESS_BUF_SIZE, ADDRESS_EXTRA_ID_BUF_SIZE> {
    //  --8<-- [end:get_check_address_params]

    use ledger_device_sdk::info;
    info!("=> get_check_address_params_legacy");

    let mut libarg: libargs_t = libargs_t::default();

    let arg = arg0 as *const u32;

    // SAFETY: `arg0` is the `os_lib_call` argument the OS passes to a library-mode entry point. The
    // OS is the only writer, and by that contract it points at a `libargs_s` of at least five words
    // (`id`, `command`, `chain_config`, then the union) whose union member is a valid
    // `check_address_parameters_t`. The caller is app-exchange, which the OS refuses to lib-call
    // unless it is at least as trusted as this app, so these reads are as trustworthy as the OS
    // handover itself. Nothing here validates the *contents*: the derivation path and the reference
    // address are attacker-influenced data and are checked by `check_address` afterwards.
    libarg.id = unsafe { *arg };
    libarg.command = unsafe { *arg.add(1) };
    libarg.unused = unsafe { *arg.add(2) };

    libarg.__bindgen_anon_1 = unsafe { *(arg.add(3) as *const libargs_s__bindgen_ty_1) };

    let params: check_address_parameters_t =
        unsafe { *(libarg.__bindgen_anon_1.check_address as *const check_address_parameters_t) };

    let mut check_address_params: CheckAddressParams<
        COIN_CONFIG_BUF_SIZE,
        ADDRESS_BUF_SIZE,
        ADDRESS_EXTRA_ID_BUF_SIZE,
    > = Default::default();

    info!("==> GET_COIN_CONFIG_LENGTH");
    check_address_params.coin_config_len = params.coin_configuration_length as usize;

    info!("==> GET_COIN_CONFIG");
    // SAFETY: distinct frames, and the length is clamped to the destination buffer.
    unsafe {
        params.coin_configuration.copy_to_nonoverlapping(
            check_address_params.coin_config.as_mut_ptr(),
            check_address_params
                .coin_config_len
                .min(COIN_CONFIG_BUF_SIZE),
        );
    }

    // `address_parameters` carries the component count at offset 1 and the path from offset 2.
    info!("==> GET_DPATH_LENGTH");
    check_address_params.dpath_len =
        DPATH_STAGE_SIZE.min(unsafe { *(params.address_parameters.add(1)) as usize });

    info!("==> GET_DPATH");
    for i in 0..check_address_params.dpath_len * 4 {
        check_address_params.dpath[i] = unsafe { *(params.address_parameters.add(2 + i)) };
    }

    info!("==> GET_REF_ADDRESS");
    let (address, address_len) =
        read_c_string::<ADDRESS_BUF_SIZE>(params.address_to_check as *const i8);
    check_address_params.ref_address = address;
    check_address_params.ref_address_len = address_len;

    check_address_params.result = unsafe {
        &(*(libarg.__bindgen_anon_1.check_address as *mut check_address_parameters_t)).result
            as *const i32 as *mut i32
    };

    check_address_params
}

//  --8<-- [end:error_code_api]

/// Reads a null-terminated C string into a fixed-size buffer and returns it with its length.
///
/// A string that does not fit comes back empty rather than cut short: a prefix of the reference
/// address is not the address Exchange holds, so the check it feeds must fail rather than compare
/// something else.
fn read_c_string<const N: usize>(ptr: *const i8) -> ([u8; N], usize) {
    let mut buffer = [0u8; N];

    if ptr.is_null() {
        return (buffer, 0);
    }

    let mut length = 0usize;
    let mut c = unsafe { *ptr.add(length) };

    while c != '\0' as i8 && length < N {
        buffer[length] = c as u8;
        length += 1;
        c = unsafe { *ptr.add(length) };
    }

    if c != '\0' as i8 {
        use ledger_device_sdk::warn;

        warn!("C string longer than its buffer");
        return ([0u8; N], 0);
    }

    (buffer, length)
}

#[cfg(test)]
mod tests {
    use super::read_c_string;
    use ledger_device_sdk::testing::TestType;

    /// A string that fills its buffer exactly is read whole; one byte longer comes back empty, so
    /// the address check it feeds compares nothing rather than a prefix.
    #[test_case]
    const READ_C_STRING_REFUSES_A_STRING_LONGER_THAN_ITS_BUFFER: TestType = TestType {
        modname: module_path!(),
        name: "read_c_string_refuses_a_string_longer_than_its_buffer",
        f: || {
            let fits = *b"t1abc\0";
            let too_long = *b"t1abcd\0";

            let (buffer, length) = read_c_string::<5>(fits.as_ptr() as *const i8);
            if length != 5 || &buffer[..length] != b"t1abc" {
                return Err(());
            }

            let (buffer, length) = read_c_string::<5>(too_long.as_ptr() as *const i8);
            if length != 0 || buffer != [0u8; 5] {
                return Err(());
            }
            Ok(())
        },
    };
}
