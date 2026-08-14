pub(crate) fn reverse_copy<const N: usize>(dst: &mut [u8; N], src: &[u8; N]) {
    let mut i = 0;
    while i < N {
        dst[i] = src[N - 1 - i];
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::reverse_copy;
    use ledger_device_sdk::testing::TestType;

    /// Reversing must fill the destination back-to-front and leave the source intact.
    #[test_case]
    const REVERSE_COPY_REVERSES_ALL_BYTES: TestType = TestType {
        modname: module_path!(),
        name: "reverse_copy_reverses_all_bytes",
        f: || {
            let src = [1u8, 2, 3, 4, 5];
            let mut dst = [0u8; 5];

            reverse_copy(&mut dst, &src);

            if dst != [5, 4, 3, 2, 1] || src != [1u8, 2, 3, 4, 5] {
                return Err(());
            }
            Ok(())
        },
    };

    /// A single byte is its own reverse.
    #[test_case]
    const REVERSE_COPY_HANDLES_SINGLE_BYTE: TestType = TestType {
        modname: module_path!(),
        name: "reverse_copy_handles_single_byte",
        f: || {
            let src = [42u8; 1];
            let mut dst = [0u8; 1];

            reverse_copy(&mut dst, &src);

            if dst != src {
                return Err(());
            }
            Ok(())
        },
    };

    /// The zero-length case must not index out of bounds.
    #[test_case]
    const REVERSE_COPY_HANDLES_EMPTY_ARRAYS: TestType = TestType {
        modname: module_path!(),
        name: "reverse_copy_handles_empty_arrays",
        f: || {
            let src = [0u8; 0];
            let mut dst = [0u8; 0];

            reverse_copy(&mut dst, &src);

            if dst != src {
                return Err(());
            }
            Ok(())
        },
    };
}
