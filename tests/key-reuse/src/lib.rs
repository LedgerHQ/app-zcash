#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(ledger_device_sdk::testing::sdk_test_runner)]
#![reexport_test_harness_main = "test_main"]

#[cfg(test)]
mod tests {
    use ff::Field;
    use ledger_device_sdk::testing::TestType;
    use orchard::keys::{FullViewingKey, SpendingKey};
    use pasta_curves::pallas;

    include!("vectors.rs");

    #[test_case]
    const COMBINED_KEYS_MATCH_SOFTWARE: TestType = TestType {
        modname: module_path!(),
        name: "combined_keys_match_software_for_both_signs",
        f: || {
            for (seed, expected_fvk, expected_ask, expected_rk) in VECTORS {
                let sk = SpendingKey::ledger_from_bytes(&[seed; 32]).map_err(|_| ())?;
                let (fvk, ask) = FullViewingKey::ledger_try_from_with_ask(&sk).map_err(|_| ())?;
                let actual: [u8; 32] = ask
                    .randomize_ledger(&pallas::Scalar::ZERO)
                    .map_err(|_| ())?
                    .into();
                if fvk.to_bytes() != expected_fvk
                    || actual != expected_ask
                    || ask
                        .randomized_verification_key_bytes(&pallas::Scalar::ONE)
                        .map_err(|_| ())?
                        != expected_rk
                {
                    return Err(());
                }
            }
            Ok(())
        },
    };
}

#[cfg(test)]
#[panic_handler]
fn test_panic_handler(info: &core::panic::PanicInfo) -> ! {
    if let Some(loc) = info.location() {
        ledger_device_sdk::log::error!("Key test panic at {}:{}", loc.file(), loc.line());
    }
    ledger_device_sdk::exit_app(1)
}

#[cfg(test)]
#[unsafe(no_mangle)]
fn sample_main() {
    test_main();
}
