use ledger_device_sdk::ecc::math::CurveDomainParam;
use pasta_curves::{Fp, Fq};

use crate::{Error, canonical_pallas_element_bytes_be};

pub(crate) const PALLAS_BYTES: usize = 32;

// Pallas base/scalar moduli come from Orchard's vendored circuit/domain data:
// - vendor/orchard/src/circuit_description
// - vendor/orchard/book/src/design/commitment-tree.md
const PALLAS_BASE_MODULUS_U64X4: [u64; 4] = [
    0x992d30ed00000001,
    0x224698fc094cf91b,
    0x0000000000000000,
    0x4000000000000000,
];

// Montgomery R^2 mod p for the Pallas base field, stored here as four
// little-endian u64 limbs.
const PALLAS_BASE_R2_U64X4: [u64; 4] = [
    0x8c78ecb30000000f,
    0xd7d30dbd8b0de0e7,
    0x7797a99bc3c95d18,
    0x096d41af7b9cb714,
];

// Montgomery -p^{-1} mod 2^64 derived from the low limb of the base modulus.
const PALLAS_BASE_INV: u64 = 0x992d30ecffffffff;
const PALLAS_SCALAR_MODULUS_U64X4: [u64; 4] = [
    0x8c46eb2100000001,
    0x224698fc0994a8dd,
    0x0000000000000000,
    0x4000000000000000,
];

// Montgomery R^2 mod n for the Pallas scalar field, stored here as four
// little-endian u64 limbs.
const PALLAS_SCALAR_R2_U64X4: [u64; 4] = [
    0xfc9678ff0000000f,
    0x67bb433d891a16e3,
    0x7fae231004ccf590,
    0x096d41af7ccfdaa9,
];

// Montgomery -n^{-1} mod 2^64 derived from the low limb of the scalar modulus.
const PALLAS_SCALAR_INV: u64 = 0x8c46eb20ffffffff;

// Converts a canonical little-endian field/scalar encoding into the Montgomery
// limb form `pasta_curves` stores internally.
//
// This is done in software rather than through the SDK's `MontCtx`: the hardware
// path holds a `MontCtx` plus three `Bn` handles at once, and the callers run
// inside Orchard parsing where the `cx_bn` pool is already close to capacity.
pub(crate) fn repr_to_montgomery_u64x4(
    repr: &[u8; 32],
    modulus_param: CurveDomainParam,
    malformed_error: Error,
) -> Result<[u64; 4], Error> {
    canonical_pallas_element_bytes_be(repr, modulus_param, malformed_error)?;

    let repr_u64x4 = repr_to_u64x4(repr);
    let (modulus, r2, inv) = pallas_montgomery_params(modulus_param);
    let wide = mul_u64x4(&repr_u64x4, &r2);

    Ok(montgomery_reduce_u64x8(wide, modulus, inv))
}

pub(crate) fn byte_to_fp(bytes: &[u64; 4]) -> Fp {
    debug_assert_eq!(core::mem::size_of::<[u64; 4]>(), core::mem::size_of::<Fp>());
    debug_assert_eq!(
        core::mem::align_of::<[u64; 4]>(),
        core::mem::align_of::<Fp>()
    );

    // SAFETY: This reinterprets the given bytes as an `Fp` element. Is safe because FP use `repr(transparent)` with same [u64; 4] layout
    unsafe { core::ptr::read(bytes as *const [u64; 4] as *const Fp) }
}

pub(crate) fn byte_to_fq(bytes: &[u64; 4]) -> Fq {
    debug_assert_eq!(core::mem::size_of::<[u64; 4]>(), core::mem::size_of::<Fq>());
    debug_assert_eq!(
        core::mem::align_of::<[u64; 4]>(),
        core::mem::align_of::<Fq>()
    );

    // SAFETY: This reinterprets the given bytes as an `Fq` element. Is safe because FQ use `repr(transparent)` with same [u64; 4] layout
    unsafe { core::ptr::read(bytes as *const [u64; 4] as *const Fq) }
}

pub(crate) fn repr_to_u64x4(repr: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_le_bytes(repr[0..8].try_into().unwrap()),
        u64::from_le_bytes(repr[8..16].try_into().unwrap()),
        u64::from_le_bytes(repr[16..24].try_into().unwrap()),
        u64::from_le_bytes(repr[24..32].try_into().unwrap()),
    ]
}

pub(crate) fn pallas_montgomery_params(
    modulus_param: CurveDomainParam,
) -> ([u64; 4], [u64; 4], u64) {
    match modulus_param {
        CurveDomainParam::Field => (
            PALLAS_BASE_MODULUS_U64X4,
            PALLAS_BASE_R2_U64X4,
            PALLAS_BASE_INV,
        ),
        CurveDomainParam::Order => (
            PALLAS_SCALAR_MODULUS_U64X4,
            PALLAS_SCALAR_R2_U64X4,
            PALLAS_SCALAR_INV,
        ),
        _ => unreachable!("unsupported Pallas Montgomery domain parameter"),
    }
}

pub(crate) fn mul_u64x4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];
    let mut i = 0;
    while i < 4 {
        let mut carry = 0u64;
        let mut j = 0;
        while j < 4 {
            let k = i + j;
            let tmp = (a[i] as u128) * (b[j] as u128) + (out[k] as u128) + (carry as u128);
            out[k] = tmp as u64;
            carry = (tmp >> 64) as u64;
            j += 1;
        }

        let mut k = i + 4;
        while carry != 0 {
            let tmp = (out[k] as u128) + (carry as u128);
            out[k] = tmp as u64;
            carry = (tmp >> 64) as u64;
            k += 1;
        }

        i += 1;
    }

    out
}

pub(crate) fn montgomery_reduce_u64x8(limbs: [u64; 8], modulus: [u64; 4], inv: u64) -> [u64; 4] {
    let [r0, r1, r2, r3, r4, r5, r6, r7] = limbs;

    let k = r0.wrapping_mul(inv);
    let (_, carry) = mac_u64(r0, k, modulus[0], 0);
    let (r1, carry) = mac_u64(r1, k, modulus[1], carry);
    let (r2, carry) = mac_u64(r2, k, modulus[2], carry);
    let (r3, carry) = mac_u64(r3, k, modulus[3], carry);
    let (r4, carry2) = adc_u64(r4, 0, carry);

    let k = r1.wrapping_mul(inv);
    let (_, carry) = mac_u64(r1, k, modulus[0], 0);
    let (r2, carry) = mac_u64(r2, k, modulus[1], carry);
    let (r3, carry) = mac_u64(r3, k, modulus[2], carry);
    let (r4, carry) = mac_u64(r4, k, modulus[3], carry);
    let (r5, carry2) = adc_u64(r5, carry2, carry);

    let k = r2.wrapping_mul(inv);
    let (_, carry) = mac_u64(r2, k, modulus[0], 0);
    let (r3, carry) = mac_u64(r3, k, modulus[1], carry);
    let (r4, carry) = mac_u64(r4, k, modulus[2], carry);
    let (r5, carry) = mac_u64(r5, k, modulus[3], carry);
    let (r6, carry2) = adc_u64(r6, carry2, carry);

    let k = r3.wrapping_mul(inv);
    let (_, carry) = mac_u64(r3, k, modulus[0], 0);
    let (r4, carry) = mac_u64(r4, k, modulus[1], carry);
    let (r5, carry) = mac_u64(r5, k, modulus[2], carry);
    let (r6, carry) = mac_u64(r6, k, modulus[3], carry);
    let (r7, _) = adc_u64(r7, carry2, carry);

    subtract_modulus_if_needed([r4, r5, r6, r7], modulus)
}

fn subtract_modulus_if_needed(limbs: [u64; 4], modulus: [u64; 4]) -> [u64; 4] {
    let (d0, borrow) = sbb_u64(limbs[0], modulus[0], 0);
    let (d1, borrow) = sbb_u64(limbs[1], modulus[1], borrow);
    let (d2, borrow) = sbb_u64(limbs[2], modulus[2], borrow);
    let (d3, borrow) = sbb_u64(limbs[3], modulus[3], borrow);

    let (d0, carry) = adc_u64(d0, modulus[0] & borrow, 0);
    let (d1, carry) = adc_u64(d1, modulus[1] & borrow, carry);
    let (d2, carry) = adc_u64(d2, modulus[2] & borrow, carry);
    let (d3, _) = adc_u64(d3, modulus[3] & borrow, carry);

    [d0, d1, d2, d3]
}

fn adc_u64(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

fn sbb_u64(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

fn mac_u64(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

#[cfg(test)]
mod tests {
    use super::repr_to_montgomery_u64x4;
    use crate::Error;
    use ledger_device_sdk::ecc::math::CurveDomainParam;
    use ledger_device_sdk::testing::TestType;

    fn scalar_limbs_to_le_bytes(limbs: [u64; 4]) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limbs[i].to_le_bytes());
        }
        bytes
    }

    /// Known-answer test for the software Montgomery conversion: `42` in the
    /// Pallas scalar field must produce this exact limb encoding. The expected
    /// value comes from the SDK's hardware `MontCtx` conversion, which this
    /// implementation replaced — it pins the software path to the hardware
    /// result it must reproduce.
    #[test_case]
    const REPR_TO_MONTGOMERY_KNOWN_ANSWER: TestType = TestType {
        modname: module_path!(),
        name: "repr_to_montgomery_known_answer",
        f: || {
            let mut repr = [0u8; 32];
            repr[0] = 42;

            let base = repr_to_montgomery_u64x4(
                &repr,
                CurveDomainParam::Field,
                Error::MalformedPallasBase,
            )
            .map_err(|_| ())?;
            if base == [0u64; 4] {
                return Err(());
            }

            let scalar = repr_to_montgomery_u64x4(
                &repr,
                CurveDomainParam::Order,
                Error::MalformedPallasScalar,
            )
            .map_err(|_| ())?;

            if scalar_limbs_to_le_bytes(scalar)
                != *b"\x59\xff\xff\xff\x78\x9d\xbc\x7d\x79\xd7\x05\xc0\x95\x33\xf2\xa3\xe9\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x3f"
            {
                return Err(());
            }

            Ok(())
        },
    };
}
