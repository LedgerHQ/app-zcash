#![no_std]

mod bytes;
mod montgomery;
pub mod redpallas;

use ledger_device_sdk::{
    bn::Bn,
    ecc::{
        CxError,
        math::{CurveDomainParam, Pallas},
    },
    hash::{
        HashError, HashInit as _,
        blake2::{Blake2b_512, Blake2bWithPerso},
    },
    log::debug,
};
use montgomery::{PALLAS_BYTES, byte_to_fp, byte_to_fq, repr_to_montgomery_u64x4};
use pasta_curves::pallas;

const PRF_EXPAND_PERSONALIZATION: [u8; 16] = *b"Zcash_ExpandSeed";
const ORCHARD_ASK_DOMAIN_SEPARATOR: u8 = 0x06;
const ORCHARD_NK_DOMAIN_SEPARATOR: u8 = 0x07;
const ORCHARD_RIVK_DOMAIN_SEPARATOR: u8 = 0x08;
const PRF_EXPAND_BYTES: usize = 64;

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
    let mut personalization = PRF_EXPAND_PERSONALIZATION;
    let mut input = [0u8; 33];
    let mut output = [0u8; PRF_EXPAND_BYTES];

    input[..32].copy_from_slice(sk);
    input[32] = domain_separator;

    let mut blake2b = Blake2b_512::new_with_salt_and_perso(None, Some(&mut personalization));
    blake2b.hash(&input, &mut output)?;

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
    let mut bytes_be = [0u8; PALLAS_BYTES];
    bytes::reverse_copy(&mut bytes_be, bytes_le);

    let element = Bn::alloc_init(&bytes_be)?;
    let mut modulus = Bn::alloc(PALLAS_BYTES)?;
    Pallas::domain_parameter_bn(modulus_param, &mut modulus)?;

    if element.cmp_bn(&modulus)? != core::cmp::Ordering::Less {
        return Err(malformed_error);
    }

    Ok(bytes_be)
}

fn reduce_uniform_le_bytes_mod_pallas(
    uniform_le: &[u8; PRF_EXPAND_BYTES],
    modulus_param: CurveDomainParam,
) -> Result<[u8; 32], Error> {
    let mut uniform_be = [0u8; PRF_EXPAND_BYTES];
    bytes::reverse_copy(&mut uniform_be, uniform_le);

    let wide = Bn::alloc_init(&uniform_be)?;
    let mut modulus = Bn::alloc(PALLAS_BYTES)?;
    Pallas::domain_parameter_bn(modulus_param, &mut modulus)?;

    let reduced = Bn::alloc(PALLAS_BYTES)?;
    reduced.reduce(&wide, &modulus)?;

    let mut reduced_be = [0u8; PALLAS_BYTES];
    reduced.export(&mut reduced_be)?;

    let mut reduced_le = [0u8; PALLAS_BYTES];
    bytes::reverse_copy(&mut reduced_le, &reduced_be);

    Ok(reduced_le)
}
