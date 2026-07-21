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
// Orchard BindingSig basepoint encoding
const ORCHARD_BINDINGSIG_BASEPOINT_BYTES: [u8; 32] = [
    0x91, 0x5a, 0x3c, 0x88, 0x68, 0xc6, 0xc3, 0x0e, 0x2f, 0x80, 0x90, 0xee, 0x45, 0xd7, 0x6e, 0x40,
    0x48, 0x20, 0x8d, 0xea, 0x5b, 0x23, 0x66, 0x4f, 0xbb, 0x09, 0xa4, 0x0f, 0x55, 0x44, 0xf4, 0x07,
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

/// RedPallas binding verification key representation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BindingVerificationKey {
    bytes: [u8; 32],
    point: pallas::Point,
}

impl BindingVerificationKey {
    pub fn into_parts(self) -> ([u8; 32], pallas::Point) {
        (self.bytes, self.point)
    }

    pub fn point(&self) -> pallas::Point {
        self.point
    }
}

impl From<BindingVerificationKey> for [u8; 32] {
    fn from(value: BindingVerificationKey) -> Self {
        value.bytes
    }
}

impl From<&BindingVerificationKey> for [u8; 32] {
    fn from(value: &BindingVerificationKey) -> Self {
        value.bytes
    }
}

/// RedPallas binding signing key representation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BindingSigningKey {
    bytes: [u8; 32],
    verification_key: BindingVerificationKey,
}

impl BindingSigningKey {
    pub fn verification_key_bytes(&self) -> [u8; 32] {
        self.verification_key.bytes
    }

    pub fn verification_key(&self) -> BindingVerificationKey {
        self.verification_key
    }
}

impl From<BindingSigningKey> for [u8; 32] {
    fn from(value: BindingSigningKey) -> Self {
        value.bytes
    }
}

impl From<&BindingSigningKey> for [u8; 32] {
    fn from(value: &BindingSigningKey) -> Self {
        value.bytes
    }
}

impl From<&BindingSigningKey> for BindingVerificationKey {
    fn from(value: &BindingSigningKey) -> Self {
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

/// Creates a RedPallas binding signing key from canonical scalar bytes.
pub fn binding_signing_key(scalar_bytes_le: [u8; 32]) -> Result<BindingSigningKey, Error> {
    let scalar_bytes_be = canonical_scalar_bytes_be(&scalar_bytes_le)?;
    let verification_key = binding_verification_key_from_scalar_be(&scalar_bytes_be)?;

    Ok(BindingSigningKey {
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

    // Scope the Bn objects so they are freed before calling spendauth_signing_key.
    // Without this block, scalar/randomizer/order/randomized remain alive across
    // the tail call, which pushes the concurrent Bn count past the SDK pool limit
    // and causes Bn::alloc inside spendauth_signing_key to return CxError.
    let randomized_bytes_le = {
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
        randomized_bytes_le
    };

    spendauth_signing_key(randomized_bytes_le)
}

/// Creates a RedPallas spend authorization signature using Ledger SDK hashing,
/// Pallas point multiplication, and big-number scalar arithmetic.
pub fn spendauth_sign(
    signing_key: &SpendAuthSigningKey,
    random_bytes: &[u8; 80],
    msg: &[u8],
) -> Result<[u8; 64], Error> {
    redpallas_sign(
        &signing_key.bytes,
        &signing_key.verification_key_bytes(),
        &ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES,
        random_bytes,
        msg,
    )
}

/// Creates a RedPallas binding signature using Ledger SDK hashing, Pallas point
/// multiplication, and big-number scalar arithmetic.
pub fn binding_sign(
    signing_key: &BindingSigningKey,
    random_bytes: &[u8; 80],
    msg: &[u8],
) -> Result<[u8; 64], Error> {
    redpallas_sign(
        &signing_key.bytes,
        &signing_key.verification_key_bytes(),
        &ORCHARD_BINDINGSIG_BASEPOINT_BYTES,
        random_bytes,
        msg,
    )
}

fn redpallas_sign(
    scalar_bytes_le: &[u8; 32],
    pk_bytes: &[u8; 32],
    basepoint_bytes: &[u8; 32],
    random_bytes: &[u8; 80],
    msg: &[u8],
) -> Result<[u8; 64], Error> {
    let scalar_bytes_be = canonical_scalar_bytes_be(scalar_bytes_le)?;
    let nonce_bytes_le = redpallas_hstar(&[random_bytes, pk_bytes, msg])?;
    let nonce_bytes_be = canonical_scalar_bytes_be(&nonce_bytes_le)?;
    let r_bytes = basepoint_mul_bytes_from_scalar_be(basepoint_bytes, &nonce_bytes_be)?;

    let challenge_bytes_le = redpallas_hstar(&[&r_bytes, pk_bytes, msg])?;
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
    let (bytes, point) =
        basepoint_mul_from_scalar_be(&ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES, scalar_bytes_be)?;

    Ok(SpendAuthVerificationKey {
        bytes,
        point: point_from_sdk_point(&point)?,
    })
}

fn binding_verification_key_from_scalar_be(
    scalar_bytes_be: &[u8; 32],
) -> Result<BindingVerificationKey, Error> {
    let (bytes, point) =
        basepoint_mul_from_scalar_be(&ORCHARD_BINDINGSIG_BASEPOINT_BYTES, scalar_bytes_be)?;

    Ok(BindingVerificationKey {
        bytes,
        point: point_from_sdk_point(&point)?,
    })
}

fn basepoint_mul_bytes_from_scalar_be(
    basepoint_bytes: &[u8; 32],
    scalar_bytes_be: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let (bytes, _) = basepoint_mul_from_scalar_be(basepoint_bytes, scalar_bytes_be)?;
    Ok(bytes)
}

fn basepoint_mul_from_scalar_be(
    basepoint_bytes: &[u8; 32],
    scalar_bytes_be: &[u8; 32],
) -> Result<([u8; 32], EcPoint), Error> {
    let (basepoint_x_be, basepoint_sign) = decode_pallas_point_encoding(basepoint_bytes);

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

pub(crate) fn point_from_sdk_point(point: &EcPoint) -> Result<pallas::Point, Error> {
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

pub(crate) fn projective_point(x: pallas::Base, y: pallas::Base, z: pallas::Base) -> pallas::Point {
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

pub(crate) fn base_from_canonical_repr_unchecked(repr: [u8; 32]) -> pallas::Base {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_device_sdk::testing::TestType;

    /// Little-endian scalar encoding of a small `u8` value.
    fn scalar_from_u8(n: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        bytes
    }

    /// A full-width, non-trivial scalar guaranteed to be canonical: the most
    /// significant little-endian byte is left at 0, so the value is < 2^248,
    /// well below the Pallas scalar-field order.
    fn wide_canonical_scalar(seed: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let mut i = 0;
        while i < 31 {
            bytes[i] = seed.wrapping_add(i as u8) | 1;
            i += 1;
        }
        bytes
    }

    fn signing_keys_eq(a: &SpendAuthSigningKey, b: &SpendAuthSigningKey) -> bool {
        <[u8; 32]>::from(a) == <[u8; 32]>::from(b)
            && a.verification_key_bytes() == b.verification_key_bytes()
    }

    /// Randomizing with a zero randomizer must yield exactly the plain signing
    /// key derived from the same scalar.
    #[test_case]
    const RANDOMIZE_WITH_ZERO_IS_IDENTITY: TestType = TestType {
        modname: module_path!(),
        name: "randomize_with_zero_is_identity",
        f: || {
            let scalar = scalar_from_u8(9);
            let randomized = spendauth_randomized_signing_key(scalar, [0u8; 32]).map_err(|_| ())?;
            let plain = spendauth_signing_key(scalar).map_err(|_| ())?;
            if !signing_keys_eq(&randomized, &plain) {
                return Err(());
            }
            Ok(())
        },
    };

    /// `(scalar + randomizer)` with small operands stays below the field order,
    /// so the randomized key must equal the signing key of the plain sum.
    #[test_case]
    const RANDOMIZE_MATCHES_SCALAR_SUM: TestType = TestType {
        modname: module_path!(),
        name: "randomize_matches_scalar_sum",
        f: || {
            // 5 + 7 = 12, all far below the field order => (a + r) mod q == a + r.
            let randomized = spendauth_randomized_signing_key(scalar_from_u8(5), scalar_from_u8(7))
                .map_err(|_| ())?;
            let expected = spendauth_signing_key(scalar_from_u8(12)).map_err(|_| ())?;
            if !signing_keys_eq(&randomized, &expected) {
                return Err(());
            }
            Ok(())
        },
    };

    /// Regression test for the Bn allocator exhaustion fix: with full-width
    /// scalars the temporary `Bn` values allocated while computing the
    /// randomized scalar must be freed before the tail call to
    /// `spendauth_signing_key`. Otherwise the concurrent `Bn` count exceeds the
    /// SDK pool limit and `Bn::alloc` inside `spendauth_signing_key` fails with
    /// `CxError`, which surfaces here as an `Err`.
    #[test_case]
    const RANDOMIZE_WIDE_SCALARS_DOES_NOT_EXHAUST_BN_POOL: TestType = TestType {
        modname: module_path!(),
        name: "randomize_wide_scalars_does_not_exhaust_bn_pool",
        f: || {
            let scalar = wide_canonical_scalar(0x11);
            let randomizer = wide_canonical_scalar(0x42);
            spendauth_randomized_signing_key(scalar, randomizer).map_err(|_| ())?;
            Ok(())
        },
    };
}
