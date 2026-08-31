#![no_std]
#![feature(custom_test_frameworks)]
#![cfg_attr(test, no_main)]
#![cfg_attr(test, test_runner(ledger_device_sdk::testing::sdk_test_runner))]
#![cfg_attr(test, reexport_test_harness_main = "test_main")]

extern crate alloc;

mod bytes;
mod hashtocurve;
mod montgomery;
pub mod orchard;
mod poseidon;
mod poseidon_fp;
pub mod redpallas;
mod sinsemilla;
pub mod transparent_address;
pub mod transparent_script;

pub use crate::hashtocurve::diversify_hash_ledger;
use crate::sinsemilla::sinsemilla_short_commit;
use ff::{Field, PrimeField};
use ledger_device_sdk::{
    bn::Bn,
    ecc::{
        CurvesId, CxError,
        math::{CurveDomainParam, EcPoint},
    },
    hash::{
        HashError, HashInit as _,
        blake2::{Blake2b_512, Blake2bWithPerso},
    },
    log::debug,
};
use montgomery::{PALLAS_BYTES, byte_to_fp, byte_to_fq, repr_to_montgomery_u64x4};
use pasta_curves::pallas;
use zeroize::Zeroizing;

// Orchard key material is derived via PrfExpand with the fixed
// "Zcash_ExpandSeed" personalization.
const PRF_EXPAND_PERSONALIZATION: [u8; 16] = *b"Zcash_ExpandSeed";
const ORCHARD_COMMIT_IVK_PERSONALIZATION: &str = "z.cash:Orchard-CommitIvk";
const L_ORCHARD_BASE: usize = 255;
const ORCHARD_COMMIT_IVK_MESSAGE_BITS: usize = 2 * L_ORCHARD_BASE;

// Domain separators selecting Orchard ask/nk/rivk derivations inside
// PrfExpand(sk || domain_separator).
const ORCHARD_ASK_DOMAIN_SEPARATOR: u8 = 0x06;
const ORCHARD_NK_DOMAIN_SEPARATOR: u8 = 0x07;
const ORCHARD_RIVK_DOMAIN_SEPARATOR: u8 = 0x08;
const ORCHARD_DK_OVK_DOMAIN_SEPARATOR: u8 = 0x82;
const ORCHARD_RIVK_INTERNAL_DOMAIN_SEPARATOR: u8 = 0x83;
const ORCHARD_ESK_DOMAIN_SEPARATOR: u8 = 0x04;
const ORCHARD_RCM_DOMAIN_SEPARATOR: u8 = 0x05;
const ORCHARD_PSI_DOMAIN_SEPARATOR: u8 = 0x09;
// ZIP 2005 §3.2.1 (Ironwood): V3 note plaintext version byte (lead byte of the enc_ciphertext
// plaintext) and quantum-recoverable rcm domain separator. Callers name the version they expect,
// so this one only selects the V3 commitment formula once a plaintext is in hand.
pub(crate) const NOTE_VERSION_IRONWOOD: u8 = 0x03;
const ORCHARD_QR_RCM_DOMAIN_SEPARATOR: u8 = 0x0B;
const PRF_EXPAND_BYTES: usize = 64;
const ORCHARD_VALUE_COMMITMENT_VALUE_BASEPOINT_BYTES: [u8; 32] = [
    0x67, 0x43, 0xf9, 0x3a, 0x6e, 0xbd, 0xa7, 0x2a, 0x8c, 0x7c, 0x5a, 0x2b, 0x7f, 0xa3, 0x04, 0xfe,
    0x32, 0xb2, 0x9b, 0x4f, 0x70, 0x6a, 0xa8, 0xf7, 0x42, 0x0f, 0x3d, 0x8e, 0x7a, 0x59, 0x70, 0x2f,
];
const ORCHARD_VALUE_COMMITMENT_RANDOMNESS_BASEPOINT_BYTES: [u8; 32] = [
    0x91, 0x5a, 0x3c, 0x88, 0x68, 0xc6, 0xc3, 0x0e, 0x2f, 0x80, 0x90, 0xee, 0x45, 0xd7, 0x6e, 0x40,
    0x48, 0x20, 0x8d, 0xea, 0x5b, 0x23, 0x66, 0x4f, 0xbb, 0x09, 0xa4, 0x0f, 0x55, 0x44, 0xf4, 0x07,
];

pub fn _debug_print(str: &str) {
    debug!("{}", str);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Cx(CxError),
    Hash(HashError),
    MalformedPallasBase,
    MalformedPallasPoint,
    MalformedPallasScalar,
    InvalidKeyDiscarded,
    InvalidDiversifyHashPoint,
    UnsupportedSinsemillaDomain,
    OutOfMemory,
    Base58EncodeFailed,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PallasAffinePointBytes {
    pub x: [u8; 32],
    pub y: [u8; 32],
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

impl From<redpallas::Error> for Error {
    fn from(value: redpallas::Error) -> Self {
        match value {
            redpallas::Error::MalformedSigningKey => Self::MalformedPallasScalar,
            redpallas::Error::MalformedVerificationKey => Self::MalformedPallasPoint,
            redpallas::Error::Cx(err) => Self::Cx(err),
            redpallas::Error::Hash(err) => Self::Hash(err),
        }
    }
}

/// Computes the Orchard `ask` bytes as:
/// `to_scalar(PrfExpand::ORCHARD_ASK.with(&sk))`.
///
/// The returned bytes are the canonical little-endian encoding of the reduced
/// Pallas scalar, matching Orchard's `pallas::Scalar::to_repr()`.
pub fn orchard_ask(sk: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let uniform = prf_expand_orchard_ask(sk)?;
    to_pallas_scalar_bytes(&uniform)
}

/// Computes the Orchard `nk` bytes as:
/// `to_base(PrfExpand::ORCHARD_NK.with(&sk))`.
///
/// The returned bytes are the canonical little-endian encoding of the reduced
/// Pallas base-field element, matching Orchard's `pallas::Base::to_repr()`.
pub fn orchard_nk(sk: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let uniform = prf_expand_orchard_nk(sk)?;
    to_pallas_base_bytes(&uniform)
}

/// Computes the Orchard `rivk` bytes as:
/// `to_scalar(PrfExpand::ORCHARD_RIVK.with(&sk))`.
///
/// The returned bytes are the canonical little-endian encoding of the reduced
/// Pallas scalar, matching Orchard's `pallas::Scalar::to_repr()`.
pub fn orchard_rivk(sk: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let uniform = prf_expand_orchard_rivk(sk)?;
    to_pallas_scalar_bytes(&uniform)
}

/// Computes the Orchard internal `rivk` bytes as:
/// `to_scalar(PrfExpand::ORCHARD_RIVK_INTERNAL.with(&rivk, &ak, &nk))`.
///
/// The returned bytes are the canonical little-endian encoding of the reduced
/// Pallas scalar, matching Orchard's `pallas::Scalar::to_repr()`.
pub fn orchard_rivk_internal(
    rivk: &[u8; 32],
    ak: &[u8; 32],
    nk: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let uniform = prf_expand_orchard_rivk_internal(rivk, ak, nk)?;
    to_pallas_scalar_bytes(&uniform)
}

/// The Orchard `(dk, ovk)` pair, each half wiped when the caller drops it.
pub type OrchardDkOvk = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// Computes the Orchard `(dk, ovk)` pair as:
/// `PrfExpand::ORCHARD_DK_OVK.with(&rivk, &ak, &nk)`.
///
/// The returned tuple contains the raw byte encodings of:
/// - `dk`: the first 32 bytes of the PRF output
/// - `ovk`: the last 32 bytes of the PRF output
pub fn orchard_dk_ovk(
    rivk: &[u8; 32],
    ak: &[u8; 32],
    nk: &[u8; 32],
) -> Result<OrchardDkOvk, Error> {
    let expanded = prf_expand_orchard_dk_ovk(rivk, ak, nk)?;
    Ok(split_prf_expand_bytes(&expanded))
}

/// Computes the Orchard diversified transmission key bytes `pk_d` as:
/// `KA^Orchard(ivk, g_d)`.
///
/// Inputs must be the canonical Orchard encodings of:
/// - `ivk`: Orchard incoming viewing key scalar value encoded as
///   `NonZeroPallasBase::to_bytes()`
/// - `g_d`: Orchard diversified base point encoded as `repr_P(g_d)`
///
/// The returned bytes are the canonical compressed point encoding of `pk_d`,
/// matching `DiversifiedTransmissionKey::to_bytes()`.
pub fn orchard_pk_d(ivk: &[u8; 32], g_d: &[u8; 32]) -> Result<[u8; 32], Error> {
    let ivk = pallas_base_from_repr(*ivk)?;
    if bool::from(ivk.is_zero()) {
        return Err(Error::InvalidKeyDiscarded);
    }

    let mut pk_d = pallas_point_from_bytes(g_d)?;
    let ivk_bytes = Zeroizing::new(ivk.to_repr());
    pk_d.rnd_scalarmul(&canonical_scalar_bytes_be(&ivk_bytes)?)?;
    pallas_point_to_bytes(&pk_d)
}

/// Computes `ValueCommit^Orchard(value, rcv)` using precomputed Orchard value
/// commitment basepoints.
///
/// `value` is the signed net action value, `spend.value - output.value`.
/// `rcv` must be a canonical little-endian Pallas scalar encoding.
pub fn orchard_value_commitment_bytes(value: i64, rcv: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut sum = value_commitment_value_term(value)?;

    if *rcv != [0; 32] {
        let rcv_be = canonical_scalar_bytes_be(rcv)?;
        let rcv_term = pallas_basepoint_mul(
            &ORCHARD_VALUE_COMMITMENT_RANDOMNESS_BASEPOINT_BYTES,
            &rcv_be,
        )?;
        sum = match sum {
            Some(value_term) => Some(pallas_point_add(&value_term, &rcv_term)?),
            None => Some(rcv_term),
        };
    }

    match sum {
        Some(point) => pallas_point_to_bytes(&point),
        None => Ok([0; 32]),
    }
}

pub fn orchard_spend_nullifier_bytes(
    nk: &[u8; 32],
    raw_address: &[u8; orchard::ORCHARD_RAW_ADDRESS_SIZE],
    value: u64,
    rho: &[u8; 32],
    rseed: &[u8; 32],
) -> Result<[u8; 32], Error> {
    orchard::spend_nullifier_bytes(nk, raw_address, value, rho, rseed)
}

/// V3 (ZIP 2005 / Ironwood) variant of [`orchard_spend_nullifier_bytes`].
///
/// Use this when recomputing the nullifier of a V3 spend note inside a PCZT;
/// V2 and V3 notes share the same Sinsemilla message structure but derive the
/// commitment trapdoor (rcm) differently.
pub fn orchard_spend_nullifier_bytes_v3(
    nk: &[u8; 32],
    raw_address: &[u8; orchard::ORCHARD_RAW_ADDRESS_SIZE],
    value: u64,
    rho: &[u8; 32],
    rseed: &[u8; 32],
) -> Result<[u8; 32], Error> {
    orchard::spend_nullifier_bytes_v3(nk, raw_address, value, rho, rseed)
}

pub fn orchard_note_commitment_bytes(
    raw_address: &[u8; orchard::ORCHARD_RAW_ADDRESS_SIZE],
    value: u64,
    rho: &[u8; 32],
    rseed: &[u8; 32],
) -> Result<[u8; 32], Error> {
    orchard::note_commitment_bytes(raw_address, value, rho, rseed)
}

/// Computes the V3 (ZIP 2005 / Ironwood) note commitment for a dummy output.
///
/// Identical Sinsemilla message as V2 (`g_d ‖ pk_d ‖ value ‖ rho ‖ psi`) but the
/// trapdoor uses the quantum-recoverable rcm derivation (domain separator 0x0B,
/// fields g_d ‖ pk_d ‖ value_le ‖ rho ‖ psi hashed alongside rseed).
pub fn orchard_note_commitment_v3_bytes(
    recipient: &[u8; orchard::ORCHARD_RAW_ADDRESS_SIZE],
    value: u64,
    nullifier: &[u8; 32],
    rseed: &[u8; 32],
) -> Result<[u8; 32], Error> {
    orchard::orchard_note_commitment_v3(recipient, value, nullifier, rseed)
}

/// Parses a compressed Pallas point encoding and rejects the identity.
///
/// Returns canonical little-endian affine coordinates on success.
pub fn nonidentity_pallas_point_from_bytes(
    encoded: &[u8; 32],
) -> Result<PallasAffinePointBytes, Error> {
    if *encoded == [0; 32] {
        return Err(Error::MalformedPallasPoint);
    }

    let point = match pallas_point_from_bytes(encoded) {
        Ok(point) => point,
        Err(Error::Cx(CxError::InvalidPoint | CxError::PointAtInfinity)) => {
            return Err(Error::MalformedPallasPoint);
        }
        Err(err) => return Err(err),
    };

    if pallas_point_to_bytes(&point)? != *encoded {
        return Err(Error::MalformedPallasPoint);
    }

    let mut x_be = [0u8; 32];
    let mut y_be = [0u8; 32];
    point.export(&mut x_be, &mut y_be)?;

    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    bytes::reverse_copy(&mut x, &x_be);
    bytes::reverse_copy(&mut y, &y_be);

    Ok(PallasAffinePointBytes { x, y })
}

/// Computes the Orchard `ivk` bytes from serialized `ak`, `nk`, and `rivk` as:
/// `Commit^ivk(ak, nk, rivk)`.
///
/// Inputs must be canonical little-endian encodings of:
/// - `ak`: Orchard spend validating key x-coordinate (`I2LEOSP_256(ak)`)
/// - `nk`: Orchard nullifier deriving key
/// - `rivk`: Orchard commit randomness
///
/// The returned bytes are the canonical little-endian encoding of the non-zero
/// Orchard `ivk` base-field element, matching `NonZeroPallasBase::to_bytes()`.
pub fn orchard_ivk(
    ak: &[u8; 32],
    nk: &[u8; 32],
    rivk: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let ak = pallas_base_from_repr(*ak)?;
    let nk = pallas_base_from_repr(*nk)?;
    let rivk = pallas_scalar_from_repr(*rivk)?;

    let Some(ivk) = orchard_commit_ivk(&ak, &nk, &rivk)? else {
        return Err(Error::InvalidKeyDiscarded);
    };
    if bool::from(ivk.is_zero()) {
        return Err(Error::InvalidKeyDiscarded);
    }

    Ok(Zeroizing::new(ivk.to_repr()))
}

// Isolated from its caller: `message` alone is 510 bytes and the builder below holds ~1020,
// which must not coalesce into a frame that already carries note or ciphertext buffers.
#[inline(never)]
fn orchard_commit_ivk(
    ak: &pallas::Base,
    nk: &pallas::Base,
    rivk: &pallas::Scalar,
) -> Result<Option<pallas::Base>, Error> {
    let message = orchard_commit_ivk_message(ak, nk);
    sinsemilla_short_commit(ORCHARD_COMMIT_IVK_PERSONALIZATION, &message, rivk)
}

#[inline(never)]
fn orchard_commit_ivk_message(
    ak: &pallas::Base,
    nk: &pallas::Base,
) -> [bool; ORCHARD_COMMIT_IVK_MESSAGE_BITS] {
    let mut message = [false; ORCHARD_COMMIT_IVK_MESSAGE_BITS];
    let ak_bits = pallas_base_le_bits(ak);
    let nk_bits = pallas_base_le_bits(nk);

    message[..L_ORCHARD_BASE].copy_from_slice(&ak_bits);
    message[L_ORCHARD_BASE..].copy_from_slice(&nk_bits);

    message
}

fn pallas_base_le_bits(base: &pallas::Base) -> [bool; L_ORCHARD_BASE] {
    repr_to_truncated_le_bits::<L_ORCHARD_BASE>(&base.to_repr())
}

fn repr_to_truncated_le_bits<const N: usize>(repr: &[u8; 32]) -> [bool; N] {
    let mut bits = [false; N];
    let mut i = 0;

    while i < N {
        bits[i] = ((repr[i / 8] >> (i % 8)) & 1) == 1;
        i += 1;
    }

    bits
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
pub fn prf_expand_orchard_ask(sk: &[u8; 32]) -> Result<Zeroizing<[u8; PRF_EXPAND_BYTES]>, Error> {
    prf_expand_with_domain_separator(sk, ORCHARD_ASK_DOMAIN_SEPARATOR)
}

/// Computes `PrfExpand::ORCHARD_NK.with(sk)`.
pub fn prf_expand_orchard_nk(sk: &[u8; 32]) -> Result<Zeroizing<[u8; PRF_EXPAND_BYTES]>, Error> {
    prf_expand_with_domain_separator(sk, ORCHARD_NK_DOMAIN_SEPARATOR)
}

/// Computes `PrfExpand::ORCHARD_RIVK.with(sk)`.
pub fn prf_expand_orchard_rivk(sk: &[u8; 32]) -> Result<Zeroizing<[u8; PRF_EXPAND_BYTES]>, Error> {
    prf_expand_with_domain_separator(sk, ORCHARD_RIVK_DOMAIN_SEPARATOR)
}

/// Computes `PrfExpand::ORCHARD_RIVK_INTERNAL.with(rivk, ak, nk)`.
pub fn prf_expand_orchard_rivk_internal(
    rivk: &[u8; 32],
    ak: &[u8; 32],
    nk: &[u8; 32],
) -> Result<Zeroizing<[u8; PRF_EXPAND_BYTES]>, Error> {
    prf_expand_with_domain_separator_and_inputs(
        rivk,
        ORCHARD_RIVK_INTERNAL_DOMAIN_SEPARATOR,
        &[&ak[..], &nk[..]],
    )
}

/// Computes `PrfExpand::ORCHARD_DK_OVK.with(rivk, ak, nk)`.
pub fn prf_expand_orchard_dk_ovk(
    rivk: &[u8; 32],
    ak: &[u8; 32],
    nk: &[u8; 32],
) -> Result<Zeroizing<[u8; PRF_EXPAND_BYTES]>, Error> {
    prf_expand_with_domain_separator_and_inputs(
        rivk,
        ORCHARD_DK_OVK_DOMAIN_SEPARATOR,
        &[&ak[..], &nk[..]],
    )
}

fn prf_expand_with_domain_separator(
    sk: &[u8; 32],
    domain_separator: u8,
) -> Result<Zeroizing<[u8; PRF_EXPAND_BYTES]>, Error> {
    prf_expand_with_domain_separator_and_inputs(sk, domain_separator, &[])
}

/// The 64-byte PRF output is the pre-image of a secret scalar on every call site in this crate, so
/// zeroization is carried by the return type: a caller that binds it holds a wiped buffer without
/// having to remember to wrap it.
fn prf_expand_with_domain_separator_and_inputs(
    sk: &[u8],
    domain_separator: u8,
    inputs: &[&[u8]],
) -> Result<Zeroizing<[u8; PRF_EXPAND_BYTES]>, Error> {
    let mut personalization = PRF_EXPAND_PERSONALIZATION;
    let mut output = Zeroizing::new([0u8; PRF_EXPAND_BYTES]);

    let mut blake2b = Blake2b_512::new_with_salt_and_perso(None, Some(&mut personalization))?;
    blake2b.update(sk)?;
    blake2b.update(&[domain_separator])?;
    for input in inputs {
        blake2b.update(input)?;
    }
    blake2b.finalize(&mut *output)?;

    Ok(output)
}

fn split_prf_expand_bytes(
    bytes: &[u8; PRF_EXPAND_BYTES],
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut lhs = Zeroizing::new([0u8; 32]);
    let mut rhs = Zeroizing::new([0u8; 32]);
    lhs.copy_from_slice(&bytes[..32]);
    rhs.copy_from_slice(&bytes[32..]);
    (lhs, rhs)
}

/// Reduces a 64-byte little-endian uniform value modulo the Pallas scalar field order.
///
/// This is the Ledger-SDK equivalent of Orchard's `to_scalar(...)`.
pub fn to_pallas_scalar_bytes(
    uniform_le: &[u8; PRF_EXPAND_BYTES],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    reduce_uniform_le_bytes_mod_pallas(uniform_le, CurveDomainParam::Order)
}

/// Reduces a 64-byte little-endian uniform value modulo the Pallas base field modulus.
///
/// This is the Ledger-SDK equivalent of Orchard's `to_base(...)`.
pub fn to_pallas_base_bytes(
    uniform_le: &[u8; PRF_EXPAND_BYTES],
) -> Result<Zeroizing<[u8; 32]>, Error> {
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
    CurvesId::Pallas.domain_parameter_bn(modulus_param, &mut modulus)?;

    if element.cmp_bn(&modulus)? != core::cmp::Ordering::Less {
        return Err(malformed_error);
    }

    Ok(bytes_be)
}

fn canonical_scalar_bytes_be(bytes_le: &[u8; 32]) -> Result<[u8; 32], Error> {
    canonical_pallas_element_bytes_be(
        bytes_le,
        CurveDomainParam::Order,
        Error::MalformedPallasScalar,
    )
}

fn value_commitment_value_term(value: i64) -> Result<Option<EcPoint>, Error> {
    if value == 0 {
        return Ok(None);
    }

    let mut scalar_be = [0u8; 32];
    scalar_be[24..].copy_from_slice(&value.unsigned_abs().to_be_bytes());
    let term = pallas_basepoint_mul(&ORCHARD_VALUE_COMMITMENT_VALUE_BASEPOINT_BYTES, &scalar_be)?;

    if value.is_negative() {
        let mut negated = pallas_point_to_bytes(&term)?;
        negated[31] ^= 0x80;
        Ok(Some(pallas_point_from_bytes(&negated)?))
    } else {
        Ok(Some(term))
    }
}

fn pallas_basepoint_mul(
    basepoint_bytes: &[u8; 32],
    scalar_bytes_be: &[u8; 32],
) -> Result<EcPoint, Error> {
    let mut point = pallas_point_from_bytes(basepoint_bytes)?;
    point.rnd_scalarmul(scalar_bytes_be)?;
    Ok(point)
}

fn pallas_point_add(lhs: &EcPoint, rhs: &EcPoint) -> Result<EcPoint, Error> {
    let mut sum = EcPoint::new(CurvesId::Pallas)?;
    sum.add(lhs, rhs)?;
    Ok(sum)
}

fn reduce_uniform_le_bytes_mod_pallas(
    uniform_le: &[u8; PRF_EXPAND_BYTES],
    modulus_param: CurveDomainParam,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut uniform_be = Zeroizing::new([0u8; PRF_EXPAND_BYTES]);
    bytes::reverse_copy(&mut uniform_be, uniform_le);

    let wide = Bn::alloc_init(&*uniform_be)?;
    let mut modulus = Bn::alloc(PALLAS_BYTES)?;
    CurvesId::Pallas.domain_parameter_bn(modulus_param, &mut modulus)?;

    let reduced = Bn::alloc(PALLAS_BYTES)?;
    reduced.reduce(&wide, &modulus)?;

    let mut reduced_be = Zeroizing::new([0u8; PALLAS_BYTES]);
    reduced.export(&mut *reduced_be)?;

    let mut reduced_le = Zeroizing::new([0u8; PALLAS_BYTES]);
    bytes::reverse_copy(&mut reduced_le, &reduced_be);

    Ok(reduced_le)
}

fn pallas_point_from_bytes(encoded: &[u8; 32]) -> Result<EcPoint, Error> {
    let (x_be, sign) = decode_pallas_point_encoding(encoded);
    let mut point = EcPoint::new(CurvesId::Pallas)?;
    point.decompress(&x_be, sign)?;
    Ok(point)
}

fn pallas_point_to_bytes(point: &EcPoint) -> Result<[u8; 32], Error> {
    let mut x_be = [0u8; 32];
    let sign = point.compress(&mut x_be)?;
    Ok(encode_pallas_point_bytes(&x_be, sign))
}

fn decode_pallas_point_encoding(encoded: &[u8; 32]) -> ([u8; 32], u32) {
    let mut x_le = *encoded;
    let sign = (x_le[31] >> 7) as u32;
    x_le[31] &= 0x7f;

    let mut x_be = [0u8; 32];
    bytes::reverse_copy(&mut x_be, &x_le);
    (x_be, sign)
}

fn encode_pallas_point_bytes(x_be: &[u8; 32], sign: u32) -> [u8; 32] {
    let mut x_le = [0u8; 32];
    bytes::reverse_copy(&mut x_le, x_be);
    x_le[31] |= ((sign & 1) as u8) << 7;
    x_le
}

// On-device unit-test entry point. The C runtime provided by the Ledger SDK
// calls `sample_main`, which here simply runs the generated test harness.
#[cfg(test)]
#[unsafe(no_mangle)]
fn sample_main() {
    test_main();
}

#[cfg(test)]
#[panic_handler]
fn test_panic_handler(info: &core::panic::PanicInfo) -> ! {
    ledger_device_sdk::testing::test_panic(info)
}
