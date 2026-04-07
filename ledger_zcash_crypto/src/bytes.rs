pub(crate) fn reverse_copy<const N: usize>(dst: &mut [u8; N], src: &[u8; N]) {
    let mut i = 0;
    while i < N {
        dst[i] = src[N - 1 - i];
        i += 1;
    }
}

// NOTE: These tests can only be run manually by calling test functions from device code.
#[cfg(test)]
mod tests {
    use super::reverse_copy;

    #[test]
    fn reverse_copy_reverses_all_bytes() {
        let src = [1u8, 2, 3, 4, 5];
        let mut dst = [0u8; 5];

        reverse_copy(&mut dst, &src);

        assert_eq!(dst, [5, 4, 3, 2, 1]);
        assert_eq!(src, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn reverse_copy_handles_single_byte() {
        let src = [42u8; 1];
        let mut dst = [0u8; 1];

        reverse_copy(&mut dst, &src);

        assert_eq!(dst, src);
    }

    #[test]
    fn reverse_copy_handles_empty_arrays() {
        let src = [];
        let mut dst = [];

        reverse_copy(&mut dst, &src);

        assert_eq!(dst, []);
    }
}
