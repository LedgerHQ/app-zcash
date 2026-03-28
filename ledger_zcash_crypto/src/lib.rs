#![no_std]

pub mod redpallas;

use ledger_device_sdk::{
    bn::Bn,
    ecc::{
        CxError,
        math::{CurveDomainParam, Pallas},
    },
    hash::HashError,
    sys,
    log::debug,
};
use pasta_curves::{Fp, Fq, pallas};

#[cfg(feature = "montgomery_fallback")]
use repr_to_montgomery_u64x4_pasta as repr_to_montgomery_u64x4;

#[cfg(not(feature = "montgomery_fallback"))]
use repr_to_montgomery_u64x4_ledger_sdk as repr_to_montgomery_u64x4;

const PRF_EXPAND_PERSONALIZATION: [u8; 16] = *b"Zcash_ExpandSeed";
const ORCHARD_ASK_DOMAIN_SEPARATOR: u8 = 0x06;
const ORCHARD_NK_DOMAIN_SEPARATOR: u8 = 0x07;
const ORCHARD_RIVK_DOMAIN_SEPARATOR: u8 = 0x08;
const PALLAS_BASE_BYTES: usize = 32;
const PRF_EXPAND_BYTES: usize = 64;
const PALLAS_BASE_MODULUS_U64X4: [u64; 4] = [
    0x992d30ed00000001,
    0x224698fc094cf91b,
    0x0000000000000000,
    0x4000000000000000,
];
const PALLAS_BASE_R2_U64X4: [u64; 4] = [
    0x8c78ecb30000000f,
    0xd7d30dbd8b0de0e7,
    0x7797a99bc3c95d18,
    0x096d41af7b9cb714,
];
const PALLAS_BASE_INV: u64 = 0x992d30ecffffffff;
const PALLAS_SCALAR_MODULUS_U64X4: [u64; 4] = [
    0x8c46eb2100000001,
    0x224698fc0994a8dd,
    0x0000000000000000,
    0x4000000000000000,
];
const PALLAS_SCALAR_R2_U64X4: [u64; 4] = [
    0xfc9678ff0000000f,
    0x67bb433d891a16e3,
    0x7fae231004ccf590,
    0x096d41af7ccfdaa9,
];
const PALLAS_SCALAR_INV: u64 = 0x8c46eb20ffffffff;

pub fn debug_print(str: &str) {
    debug!("{}", str);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Cx(CxError),
    Hash(HashError),
    MalformedPallasBase,
    MalformedPallasScalar,
    InvalidKeyDiscarded,
}

impl From<CxError> for Error {
    fn from(value: CxError) -> Self {
        Self::Cx(value)
    }
}

impl From<HashError> for Error {
    fn from(value: HashError) -> Self {
        Self::Hash(value)
    }
}

/// Computes the Orchard `ask` bytes as:
/// `to_scalar(PrfExpand::ORCHARD_ASK.with(&sk))`.
///
/// The returned bytes are the canonical little-endian encoding of the reduced
/// Pallas scalar, matching Orchard's `pallas::Scalar::to_repr()`.
pub fn orchard_ask(sk: &[u8; 32]) -> Result<[u8; 32], Error> {
    let uniform = prf_expand_orchard_ask(sk)?;
    to_pallas_scalar_bytes(&uniform)
}

/// Computes the Orchard `nk` bytes as:
/// `to_base(PrfExpand::ORCHARD_NK.with(&sk))`.
///
/// The returned bytes are the canonical little-endian encoding of the reduced
/// Pallas base-field element, matching Orchard's `pallas::Base::to_repr()`.
pub fn orchard_nk(sk: &[u8; 32]) -> Result<[u8; 32], Error> {
    let uniform = prf_expand_orchard_nk(sk)?;
    to_pallas_base_bytes(&uniform)
}

/// Computes the Orchard `rivk` bytes as:
/// `to_scalar(PrfExpand::ORCHARD_RIVK.with(&sk))`.
///
/// The returned bytes are the canonical little-endian encoding of the reduced
/// Pallas scalar, matching Orchard's `pallas::Scalar::to_repr()`.
pub fn orchard_rivk(sk: &[u8; 32]) -> Result<[u8; 32], Error> {
    let uniform = prf_expand_orchard_rivk(sk)?;
    to_pallas_scalar_bytes(&uniform)
}

/// Ledger-SDK equivalent of `pallas::Scalar::from_repr(repr)`.
///
/// Accepts only canonical little-endian encodings strictly smaller than the
/// Pallas scalar-field modulus.
pub fn pallas_scalar_from_repr(repr: [u8; 32]) -> Result<pallas::Scalar, Error> {
    Ok(byte_to_fq(&repr_to_montgomery_u64x4(
        &repr,
        CurveDomainParam::Order,
        Error::MalformedPallasScalar,
    )?))
}

/// Ledger-SDK equivalent of `pallas::Base::from_repr(repr)`.
///
/// Accepts only canonical little-endian encodings strictly smaller than the
/// Pallas base-field modulus.
pub fn pallas_base_from_repr(repr: [u8; 32]) -> Result<pallas::Base, Error> {
    Ok(byte_to_fp(&repr_to_montgomery_u64x4(
        &repr,
        CurveDomainParam::Field,
        Error::MalformedPallasBase,
    )?))
}

/// Computes `PrfExpand::ORCHARD_ASK.with(sk)`.
pub fn prf_expand_orchard_ask(sk: &[u8; 32]) -> Result<[u8; PRF_EXPAND_BYTES], Error> {
    prf_expand_with_domain_separator(sk, ORCHARD_ASK_DOMAIN_SEPARATOR)
}

/// Computes `PrfExpand::ORCHARD_NK.with(sk)`.
pub fn prf_expand_orchard_nk(sk: &[u8; 32]) -> Result<[u8; PRF_EXPAND_BYTES], Error> {
    prf_expand_with_domain_separator(sk, ORCHARD_NK_DOMAIN_SEPARATOR)
}

/// Computes `PrfExpand::ORCHARD_RIVK.with(sk)`.
pub fn prf_expand_orchard_rivk(sk: &[u8; 32]) -> Result<[u8; PRF_EXPAND_BYTES], Error> {
    prf_expand_with_domain_separator(sk, ORCHARD_RIVK_DOMAIN_SEPARATOR)
}

fn prf_expand_with_domain_separator(
    sk: &[u8; 32],
    domain_separator: u8,
) -> Result<[u8; PRF_EXPAND_BYTES], Error> {
    let mut state: sys::cx_blake2b_t = Default::default();
    let mut personalization = PRF_EXPAND_PERSONALIZATION;
    let mut input = [0u8; 33];
    let mut output = [0u8; PRF_EXPAND_BYTES];

    input[..32].copy_from_slice(sk);
    input[32] = domain_separator;

    let err = unsafe {
        sys::cx_blake2b_init2_no_throw(
            &mut state,
            512,
            core::ptr::null_mut(),
            0,
            personalization.as_mut_ptr(),
            personalization.len(),
        )
    };
    if err != sys::CX_OK {
        return Err(HashError::from(err).into());
    }

    let err = unsafe {
        sys::cx_hash_no_throw(
            &mut state.header,
            sys::CX_LAST,
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    if err != sys::CX_OK {
        return Err(HashError::from(err).into());
    }

    Ok(output)
}

/// Reduces a 64-byte little-endian uniform value modulo the Pallas scalar field order.
///
/// This is the Ledger-SDK equivalent of Orchard's `to_scalar(...)`.
pub fn to_pallas_scalar_bytes(uniform_le: &[u8; PRF_EXPAND_BYTES]) -> Result<[u8; 32], Error> {
    reduce_uniform_le_bytes_mod_pallas(uniform_le, CurveDomainParam::Order)
}

/// Reduces a 64-byte little-endian uniform value modulo the Pallas base field modulus.
///
/// This is the Ledger-SDK equivalent of Orchard's `to_base(...)`.
pub fn to_pallas_base_bytes(uniform_le: &[u8; PRF_EXPAND_BYTES]) -> Result<[u8; 32], Error> {
    reduce_uniform_le_bytes_mod_pallas(uniform_le, CurveDomainParam::Field)
}

fn canonical_pallas_element_bytes_be(
    bytes_le: &[u8; 32],
    modulus_param: CurveDomainParam,
    malformed_error: Error,
) -> Result<[u8; 32], Error> {
    let mut bytes_be = [0u8; PALLAS_BASE_BYTES];
    reverse_copy(&mut bytes_be, bytes_le);

    let element = Bn::alloc_init(&bytes_be)?;
    let mut modulus = Bn::alloc(PALLAS_BASE_BYTES)?;
    Pallas::domain_parameter_bn(modulus_param, &mut modulus)?;

    if element.cmp_bn(&modulus)? != core::cmp::Ordering::Less {
        return Err(malformed_error);
    }

    Ok(bytes_be)
}

#[cfg(not(feature = "montgomery_fallback"))]
fn repr_to_montgomery_u64x4_ledger_sdk(
    repr: &[u8; 32],
    modulus_param: CurveDomainParam,
    malformed_error: Error,
) -> Result<[u64; 4], Error> {
    debug!("repr_to_montgomery_u64x4: input repr (LE) {}", hex::encode(repr));
    let repr_be = canonical_pallas_element_bytes_be(repr, modulus_param, malformed_error)?;

    debug!("repr_to_montgomery_u64x4: canonical BE bytes {}", hex::encode(repr_be));

    let value = Bn::alloc_init(&repr_be)?;
    let mut modulus = Bn::alloc(PALLAS_BASE_BYTES)?;
    Pallas::domain_parameter_bn(modulus_param, &mut modulus)?;

    let mut mont = ledger_device_sdk::bn::MontCtx::alloc(PALLAS_BASE_BYTES)?;
    mont.init(&modulus)?;

    let mont_value = Bn::alloc(PALLAS_BASE_BYTES)?;
    mont.to_montgomery(&mont_value, &value)?;

    let mut mont_be = [0u8; PALLAS_BASE_BYTES];
    mont_value.export(&mut mont_be)?;
    debug!("repr_to_montgomery_u64x4: montgomery BE bytes {}", hex::encode(mont_be));

    let mut mont_le = [0u8; PALLAS_BASE_BYTES];
    reverse_copy(&mut mont_le, &mont_be);

    Ok(repr_to_u64x4(&mont_le))
}

#[cfg(feature = "montgomery_fallback")]
fn repr_to_montgomery_u64x4_pasta(
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

fn reduce_uniform_le_bytes_mod_pallas(
    uniform_le: &[u8; PRF_EXPAND_BYTES],
    modulus_param: CurveDomainParam,
) -> Result<[u8; 32], Error> {
    let mut uniform_be = [0u8; PRF_EXPAND_BYTES];
    reverse_copy(&mut uniform_be, uniform_le);

    let wide = Bn::alloc_init(&uniform_be)?;
    let mut modulus = Bn::alloc(PALLAS_BASE_BYTES)?;
    Pallas::domain_parameter_bn(modulus_param, &mut modulus)?;

    let reduced = Bn::alloc(PALLAS_BASE_BYTES)?;
    reduced.reduce(&wide, &modulus)?;

    let mut reduced_be = [0u8; PALLAS_BASE_BYTES];
    reduced.export(&mut reduced_be)?;

    let mut reduced_le = [0u8; PALLAS_BASE_BYTES];
    reverse_copy(&mut reduced_le, &reduced_be);

    Ok(reduced_le)
}

fn reverse_copy<const N: usize>(dst: &mut [u8; N], src: &[u8; N]) {
    let mut i = 0;
    while i < N {
        dst[i] = src[N - 1 - i];
        i += 1;
    }
}

// SAFETY: This relies on the internal representation of `pasta_curves::Fp` being exactly 4 u64 limbs in little-endian order, which is currently true but not guaranteed by the type system. We should consider adding safe APIs to `pasta_curves` for this kind of conversion if we need it in more places.
fn byte_to_fp(bytes: &[u64; 4]) -> Fp {
    unsafe { core::ptr::read(bytes as *const [u64; 4] as *const Fp) }
}

// SAFETY: This relies on the internal representation of `pasta_curves::Fq` being exactly 4 u64 limbs in little-endian order, which is currently true but not guaranteed by the type system.
fn byte_to_fq(bytes: &[u64; 4]) -> Fq {
    unsafe { core::ptr::read(bytes as *const [u64; 4] as *const Fq) }
}

fn repr_to_u64x4(repr: &[u8; 32]) -> [u64; 4] {
    let r= [
        u64::from_le_bytes(repr[0..8].try_into().unwrap()),
        u64::from_le_bytes(repr[8..16].try_into().unwrap()),
        u64::from_le_bytes(repr[16..24].try_into().unwrap()),
        u64::from_le_bytes(repr[24..32].try_into().unwrap()),
    ];

    r
}

fn pallas_montgomery_params(modulus_param: CurveDomainParam) -> ([u64; 4], [u64; 4], u64) {
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

fn mul_u64x4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
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

fn montgomery_reduce_u64x8(limbs: [u64; 8], modulus: [u64; 4], inv: u64) -> [u64; 4] {
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
pub mod tests {
    use super::{
        Error, repr_to_montgomery_u64x4_ledger_sdk,
        repr_to_montgomery_u64x4_pasta
    };
    use ledger_device_sdk::ecc::math::CurveDomainParam;

    #[test]
    pub fn test_repr_to_montgomery_u64x4() {
        let mut repr = [0u8; 32];
        repr[0] = 42;

        let actual_base =
            repr_to_montgomery_u64x4_ledger_sdk(&repr, CurveDomainParam::Field, Error::MalformedPallasBase)
                .unwrap();

        assert_ne!(actual_base, [0u64; 4]);

        let actual_scalar =
            repr_to_montgomery_u64x4_ledger_sdk(&repr, CurveDomainParam::Order, Error::MalformedPallasScalar)
                .unwrap();


        assert_ne!(actual_scalar,[0u64; 4]);

        let mut res_actual_scalar: [u8; 32] = Default::default();
        for i in 0..4 {
            res_actual_scalar[i*8..(i+1)*8].copy_from_slice(&actual_scalar[i].to_le_bytes());
        }

        // Res: 0x59ffffff789dbc7d79d705c09533f2a3e9ffffffffffffffffffffffffffff3f
        assert_eq!(res_actual_scalar, *b"\x59\xff\xff\xff\x78\x9d\xbc\x7d\x79\xd7\x05\xc0\x95\x33\xf2\xa3\xe9\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x3f");
    }

    #[test]
    pub fn test_repr_to_montgomery_u64x4_pasta() {
        let mut repr = [0u8; 32];
        repr[0] = 42;

        let actual_base = repr_to_montgomery_u64x4_pasta(
            &repr,
            CurveDomainParam::Field,
            Error::MalformedPallasBase,
        )
        .unwrap();
        assert_ne!(actual_base, [0u64; 4]);

        let actual_scalar = repr_to_montgomery_u64x4_pasta(
            &repr,
            CurveDomainParam::Order,
            Error::MalformedPallasScalar,
        )
        .unwrap();
        assert_ne!(actual_scalar, [0u64; 4]);

        let mut res_actual_scalar = [0u8; 32];
        for i in 0..4 {
            res_actual_scalar[i * 8..(i + 1) * 8].copy_from_slice(&actual_scalar[i].to_le_bytes());
        }

        // Res: 0x59ffffff789dbc7d79d705c09533f2a3e9ffffffffffffffffffffffffffff3f
        assert_eq!(res_actual_scalar, *b"\x59\xff\xff\xff\x78\x9d\xbc\x7d\x79\xd7\x05\xc0\x95\x33\xf2\xa3\xe9\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x3f");
    }
}
