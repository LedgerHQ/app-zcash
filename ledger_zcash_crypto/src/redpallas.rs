use core::cmp::Ordering;

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
};
use pasta_curves::pallas;

use crate::{
    bytes::reverse_copy,
    montgomery::{
        byte_to_fp, montgomery_reduce_u64x8, mul_u64x4, pallas_montgomery_params, repr_to_u64x4,
    },
};

// Orchard SpendAuthSig basepoint encoding
const ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES: [u8; 32] = [
    0x63, 0xc9, 0x75, 0xb8, 0x84, 0x72, 0x1a, 0x8d, 0x0c, 0xa1, 0x70, 0x7b, 0xe3, 0x0c, 0x7f, 0x0c,
    0x5f, 0x44, 0x5f, 0x3e, 0x7c, 0x18, 0x8d, 0x3b, 0x06, 0xd6, 0xf1, 0x28, 0xb3, 0x23, 0x55, 0xb7,
];
const REDPALLAS_HSTAR_PERSONALIZATION: [u8; 16] = *b"Zcash_RedPallasH";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    MalformedSigningKey,
    MalformedVerificationKey,
    Cx(CxError),
    Hash(HashError),
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

/// RedPallas spend-auth verification key representation.
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

/// RedPallas spend-auth signing key representation.
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

/// Creates a RedPallas spend-authorizing signing key from canonical
/// scalar bytes.
pub fn spendauth_signing_key(scalar_bytes_le: [u8; 32]) -> Result<SpendAuthSigningKey, Error> {
    let scalar_bytes_be = canonical_scalar_bytes_be(&scalar_bytes_le)?;
    let verification_key = spendauth_verification_key_from_scalar_be(&scalar_bytes_be)?;

    Ok(SpendAuthSigningKey {
        bytes: scalar_bytes_le,
        verification_key,
    })
}

/// Randomizes a RedPallas spend-authorizing signing key by computing
/// `(scalar + randomizer) mod q` with Ledger SDK big-number primitives,
/// then deriving the corresponding verification key with Ledger SDK Pallas
/// point multiplication.
pub fn spendauth_randomized_signing_key(
    scalar_bytes_le: [u8; 32],
    randomizer_bytes_le: [u8; 32],
) -> Result<SpendAuthSigningKey, Error> {
    let scalar_bytes_be = canonical_scalar_bytes_be(&scalar_bytes_le)?;
    let randomizer_bytes_be = canonical_scalar_bytes_be(&randomizer_bytes_le)?;

    let scalar = Bn::alloc_init(&scalar_bytes_be)?;
    let randomizer = Bn::alloc_init(&randomizer_bytes_be)?;
    let mut order = Bn::alloc(32)?;
    CurvesId::Pallas.domain_parameter_bn(CurveDomainParam::Order, &mut order)?;

    let randomized = Bn::alloc(32)?;
    randomized.mod_add(&scalar, &randomizer, &order)?;

    let mut randomized_bytes_be = [0u8; 32];
    randomized.export(&mut randomized_bytes_be)?;

    let mut randomized_bytes_le = [0u8; 32];
    reverse_copy(&mut randomized_bytes_le, &randomized_bytes_be);

    spendauth_signing_key(randomized_bytes_le)
}

/// Creates a RedPallas spend authorization signature using Ledger SDK hashing,
/// Pallas point multiplication, and big-number scalar arithmetic.
pub fn spendauth_sign(
    signing_key: &SpendAuthSigningKey,
    random_bytes: &[u8; 80],
    msg: &[u8],
) -> Result<[u8; 64], Error> {
    let scalar_bytes_be = canonical_scalar_bytes_be(&signing_key.bytes)?;
    let pk_bytes = signing_key.verification_key_bytes();

    let nonce_bytes_le = redpallas_hstar(&[random_bytes, &pk_bytes, msg])?;
    let nonce_bytes_be = canonical_scalar_bytes_be(&nonce_bytes_le)?;
    let r_bytes = spendauth_basepoint_mul_bytes_from_scalar_be(&nonce_bytes_be)?;

    let challenge_bytes_le = redpallas_hstar(&[&r_bytes, &pk_bytes, msg])?;
    let challenge_bytes_be = canonical_scalar_bytes_be(&challenge_bytes_le)?;

    let nonce = Bn::alloc_init(&nonce_bytes_be)?;
    let challenge = Bn::alloc_init(&challenge_bytes_be)?;
    let scalar = Bn::alloc_init(&scalar_bytes_be)?;
    let mut order = Bn::alloc(32)?;
    CurvesId::Pallas.domain_parameter_bn(CurveDomainParam::Order, &mut order)?;

    let challenge_mul_scalar = Bn::alloc(32)?;
    challenge_mul_scalar.mod_mul(&challenge, &scalar, &order)?;

    let s = Bn::alloc(32)?;
    s.mod_add(&nonce, &challenge_mul_scalar, &order)?;

    let mut s_bytes_be = [0u8; 32];
    s.export(&mut s_bytes_be)?;

    let mut s_bytes_le = [0u8; 32];
    reverse_copy(&mut s_bytes_le, &s_bytes_be);

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_bytes);
    signature[32..].copy_from_slice(&s_bytes_le);

    Ok(signature)
}

fn canonical_scalar_bytes_be(scalar_bytes_le: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut scalar_bytes_be = [0u8; 32];
    reverse_copy(&mut scalar_bytes_be, scalar_bytes_le);

    let scalar = Bn::alloc_init(&scalar_bytes_be)?;
    let mut order = Bn::alloc(32)?;
    CurvesId::Pallas.domain_parameter_bn(CurveDomainParam::Order, &mut order)?;

    if scalar.cmp_bn(&order)? != Ordering::Less {
        return Err(Error::MalformedSigningKey);
    }

    Ok(scalar_bytes_be)
}

fn spendauth_verification_key_from_scalar_be(
    scalar_bytes_be: &[u8; 32],
) -> Result<SpendAuthVerificationKey, Error> {
    let (bytes, point) = spendauth_basepoint_mul_from_scalar_be(scalar_bytes_be)?;

    Ok(SpendAuthVerificationKey {
        bytes,
        point: point_from_sdk_point(&point)?,
    })
}

fn spendauth_basepoint_mul_bytes_from_scalar_be(
    scalar_bytes_be: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let (bytes, _) = spendauth_basepoint_mul_from_scalar_be(scalar_bytes_be)?;
    Ok(bytes)
}

fn spendauth_basepoint_mul_from_scalar_be(
    scalar_bytes_be: &[u8; 32],
) -> Result<([u8; 32], EcPoint), Error> {
    let (basepoint_x_be, basepoint_sign) =
        decode_pallas_point_encoding(&ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES);

    let mut point = EcPoint::new(CurvesId::Pallas)?;
    point.decompress(&basepoint_x_be, basepoint_sign)?;
    point.rnd_scalarmul(scalar_bytes_be)?;

    let mut x_be = [0u8; 32];
    let sign = point.compress(&mut x_be)?;

    Ok((encode_pallas_point_bytes(&x_be, sign), point))
}

fn redpallas_hstar(chunks: &[&[u8]]) -> Result<[u8; 32], Error> {
    let mut personalization = REDPALLAS_HSTAR_PERSONALIZATION;
    let mut output = [0u8; 64];
    let mut hasher = Blake2b_512::new_with_salt_and_perso(None, Some(&mut personalization))?;

    for chunk in chunks {
        hasher.update(chunk)?;
    }
    hasher.finalize(&mut output)?;

    reduce_uniform_le_bytes_mod_pallas_order(&output)
}

fn reduce_uniform_le_bytes_mod_pallas_order(uniform_le: &[u8; 64]) -> Result<[u8; 32], Error> {
    let mut uniform_be = [0u8; 64];
    reverse_copy(&mut uniform_be, uniform_le);

    let wide = Bn::alloc_init(&uniform_be)?;
    let mut order = Bn::alloc(32)?;
    CurvesId::Pallas.domain_parameter_bn(CurveDomainParam::Order, &mut order)?;

    let reduced = Bn::alloc(32)?;
    reduced.reduce(&wide, &order)?;

    let mut reduced_bytes_be = [0u8; 32];
    reduced.export(&mut reduced_bytes_be)?;

    let mut reduced_bytes_le = [0u8; 32];
    reverse_copy(&mut reduced_bytes_le, &reduced_bytes_be);

    Ok(reduced_bytes_le)
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
