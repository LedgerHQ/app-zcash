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
    unsafe {
        params.coin_configuration.copy_to_nonoverlapping(
            check_address_params.coin_config.as_mut_ptr(),
            check_address_params
                .coin_config_len
                .min(COIN_CONFIG_BUF_SIZE),
        );
    }

    // this is original part of sdk function which was patched
    // info!("==> GET_DPATH_LENGTH");
    // check_address_params.dpath_len =
    //     DPATH_STAGE_SIZE.min(unsafe { *(params.address_parameters as *const u8) as usize });

    // info!("==> GET_DPATH");
    // for i in 1..1 + check_address_params.dpath_len * 4 {
    //     check_address_params.dpath[i - 1] = unsafe { *(params.address_parameters.add(i)) };
    // }

    // patch begin
    info!("==> GET_DPATH_LENGTH");
    check_address_params.dpath_len =
        DPATH_STAGE_SIZE.min(unsafe { *(params.address_parameters.add(1)) as usize });

    info!("==> GET_DPATH");
    for i in 0..check_address_params.dpath_len * 4 {
        check_address_params.dpath[i] = unsafe { *(params.address_parameters.add(2 + i)) };
    }
    // patch end

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

/// Helper function to read a null-terminated C string into a fixed-size buffer
/// Returns the buffer and the actual length read
/// Prints a warning if truncation occurs
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

    // Check if truncation occurred
    if c != '\0' as i8 && length == N {
        use ledger_device_sdk::warn;

        warn!("C string truncated");
    }

    (buffer, length)
}
