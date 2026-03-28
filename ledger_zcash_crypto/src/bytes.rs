pub(crate) fn reverse_copy<const N: usize>(dst: &mut [u8; N], src: &[u8; N]) {
    let mut i = 0;
    while i < N {
        dst[i] = src[N - 1 - i];
        i += 1;
    }
}
