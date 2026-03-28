use core::cmp::Ordering;

use ledger_device_sdk::{
    bn::Bn,
    ecc::{
        CurvesId, CxError,
        math::{CurveDomainParam, EcPoint, Pallas},
    },
};
use pasta_curves::pallas;

use crate::{
    bytes::reverse_copy,
    montgomery::{byte_to_fp, montgomery_reduce_u64x8, mul_u64x4, pallas_montgomery_params, repr_to_u64x4},
};

const ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES: [u8; 32] = [
    99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12, 95, 68, 95, 62, 124,
    24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
];

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    MalformedSigningKey,
    MalformedVerificationKey,
    Cx(CxError),
}

impl From<CxError> for Error {
    fn from(value: CxError) -> Self {
        Self::Cx(value)
    }
}

/// Minimal RedPallas spend-auth verification key representation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SpendAuthVerificationKey {
    bytes: [u8; 32],
    point: pallas::Point,
}

impl SpendAuthVerificationKey {
    pub fn into_parts(self) -> ([u8; 32], pallas::Point) {
        (self.bytes, self.point)
    }
}

impl From<SpendAuthVerificationKey> for [u8; 32] {
    fn from(value: SpendAuthVerificationKey) -> Self {
        value.bytes
    }
}

impl From<&SpendAuthVerificationKey> for [u8; 32] {
    fn from(value: &SpendAuthVerificationKey) -> Self {
        value.bytes
    }
}

impl SpendAuthVerificationKey {
    pub fn point(&self) -> pallas::Point {
        self.point
    }
}

/// Minimal RedPallas spend-auth signing key representation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SpendAuthSigningKey {
    bytes: [u8; 32],
    verification_key: SpendAuthVerificationKey,
}

impl SpendAuthSigningKey {
    pub fn verification_key_bytes(&self) -> [u8; 32] {
        self.verification_key.bytes
    }
}

impl From<SpendAuthSigningKey> for [u8; 32] {
    fn from(value: SpendAuthSigningKey) -> Self {
        value.bytes
    }
}

impl From<&SpendAuthSigningKey> for [u8; 32] {
    fn from(value: &SpendAuthSigningKey) -> Self {
        value.bytes
    }
}

impl SpendAuthSigningKey {
    pub fn verification_key(&self) -> SpendAuthVerificationKey {
        self.verification_key
    }
}

impl From<&SpendAuthSigningKey> for SpendAuthVerificationKey {
    fn from(value: &SpendAuthSigningKey) -> Self {
        value.verification_key()
    }
}

/// Creates a minimal RedPallas spend-authorizing signing key from canonical
/// scalar bytes.
pub fn spendauth_signing_key(scalar_bytes_le: [u8; 32]) -> Result<SpendAuthSigningKey, Error> {
    let scalar_bytes_be = canonical_scalar_bytes_be(&scalar_bytes_le)?;
    let verification_key = spendauth_verification_key_from_scalar_be(&scalar_bytes_be)?;

    Ok(SpendAuthSigningKey {
        bytes: scalar_bytes_le,
        verification_key,
    })
}

fn canonical_scalar_bytes_be(scalar_bytes_le: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut scalar_bytes_be = [0u8; 32];
    reverse_copy(&mut scalar_bytes_be, scalar_bytes_le);

    let scalar = Bn::alloc_init(&scalar_bytes_be)?;
    let mut order = Bn::alloc(32)?;
    Pallas::domain_parameter_bn(CurveDomainParam::Order, &mut order)?;

    if scalar.cmp_bn(&order)? != Ordering::Less {
        return Err(Error::MalformedSigningKey);
    }

    Ok(scalar_bytes_be)
}

fn spendauth_verification_key_from_scalar_be(
    scalar_bytes_be: &[u8; 32],
) -> Result<SpendAuthVerificationKey, Error> {
    let (basepoint_x_be, basepoint_sign) = decode_pallas_point_encoding(&ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES);

    let mut point = EcPoint::new(CurvesId::Pallas)?;
    point.decompress(&basepoint_x_be, basepoint_sign)?;
    point.rnd_scalarmul(scalar_bytes_be)?;

    let mut x_be = [0u8; 32];
    let sign = point.compress(&mut x_be)?;

    Ok(SpendAuthVerificationKey {
        bytes: encode_pallas_point_bytes(&x_be, sign),
        point: point_from_sdk_point(&point)?,
    })
}

fn point_from_sdk_point(point: &EcPoint) -> Result<pallas::Point, Error> {
    let mut x_be = [0u8; 32];
    let mut y_be = [0u8; 32];
    point.export(&mut x_be, &mut y_be)?;

    let mut x_le = [0u8; 32];
    let mut y_le = [0u8; 32];
    reverse_copy(&mut x_le, &x_be);
    reverse_copy(&mut y_le, &y_be);

    Ok(projective_point(
        base_from_canonical_repr_unchecked(x_le),
        base_from_canonical_repr_unchecked(y_le),
        base_from_canonical_repr_unchecked(one_bytes()),
    ))
}

fn one_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    bytes
}

#[repr(C)]
struct ProjectivePointLayout {
    x: pallas::Base,
    y: pallas::Base,
    z: pallas::Base,
}

fn projective_point(x: pallas::Base, y: pallas::Base, z: pallas::Base) -> pallas::Point {
    debug_assert_eq!(
        core::mem::size_of::<ProjectivePointLayout>(),
        core::mem::size_of::<pallas::Point>(),
    );
    debug_assert_eq!(
        core::mem::align_of::<ProjectivePointLayout>(),
        core::mem::align_of::<pallas::Point>(),
    );

    // SAFETY: This bridges from SDK-exported affine coordinates into the
    // current `pasta_curves` projective layout `(x, y, z)`. It relies on the
    // pinned `pasta_curves` 0.5 point representation used in this workspace.
    unsafe { core::mem::transmute(ProjectivePointLayout { x, y, z }) }
}

fn base_from_canonical_repr_unchecked(repr: [u8; 32]) -> pallas::Base {
    let repr_u64x4 = repr_to_u64x4(&repr);
    let (modulus, r2, inv) = pallas_montgomery_params(CurveDomainParam::Field);
    let wide = mul_u64x4(&repr_u64x4, &r2);
    let mont = montgomery_reduce_u64x8(wide, modulus, inv);
    byte_to_fp(&mont)
}

fn decode_pallas_point_encoding(encoded: &[u8; 32]) -> ([u8; 32], u32) {
    let mut x_le = *encoded;
    let sign = (x_le[31] >> 7) as u32;
    x_le[31] &= 0x7f;

    let mut x_be = [0u8; 32];
    reverse_copy(&mut x_be, &x_le);
    (x_be, sign)
}

fn encode_pallas_point_bytes(x_be: &[u8; 32], sign: u32) -> [u8; 32] {
    let mut x_le = [0u8; 32];
    reverse_copy(&mut x_le, x_be);
    x_le[31] |= ((sign & 1) as u8) << 7;
    x_le
}
