use ledger_device_sdk::{
    bn::Bn,
    debug,
    ecc::{CurvesId, CxError, math::EcPoint},
    hash::{
        HashInit as _,
        blake2::{Blake2b_512, Blake2bWithPerso},
    },
};

use crate::{Error, bytes::reverse_copy, to_pallas_base_bytes};

// `hash_to_field_pallas` below is a Ledger-port of `pasta_curves::hashtocurve::hash_to_field`.
// In the original code these are `R_IN_BYTES = 128` and `CHUNKLEN = 64`.
const BLAKE2B_BLOCK_BYTES: usize = 128;
const BLAKE2B_HASH_BYTES: usize = 64;

// `pasta_curves` uses `let personal = [0u8; 16]`; we keep the same all-zero
// BLAKE2b personalization so the XMD expansion matches upstream exactly.
const BLAKE2B_ZERO_PERSONALIZATION: [u8; 16] = [0; 16];

// Domain separation pieces copied from `pasta_curves` hash-to-curve for Pallas.
const PALLAS_CURVE_ID: &str = "pallas";
const HASH_TO_CURVE_SUFFIX: &[u8] = b"_XMD:BLAKE2b_SSWU_RO_";

// Orchard-specific DST prefix, from `orchard::constants::KEY_DIVERSIFICATION_PERSONALIZATION`:
// "SWU hash-to-curve personalization for the group hash for key diversification".
const ORCHARD_DIVERSIFY_HASH_PERSONALIZATION: &str = "z.cash:Orchard-gd";

// Tonelli-Shanks parameters for the Pallas base field, copied from
// `pasta_curves::fields::fp.rs`.
const PALLAS_S: u32 = 32;

// `(t - 1) // 2` where `t * 2^s + 1 = p` with `t` odd.
// Used by `sqrt()` to raise into the Tonelli-Shanks exponent.
const PALLAS_T_MINUS1_OVER2: [u64; 4] = [
    0x04a67c8dcc969876,
    0x0000000011234c7e,
    0x0000000000000000,
    0x0000000020000000,
];

// Pallas base field modulus `p`, from `pasta_curves::fields::fp.rs`:
// `p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`.
const PALLAS_MODULUS: Fp = Fp::from_raw([
    0x992d30ed00000001,
    0x224698fc094cf91b,
    0x0000000000000000,
    0x4000000000000000,
]);

// Coefficients of the auxiliary `iso-pallas` curve, copied from
// `pasta_curves::curves.rs` (`new_curve_impl!(IsoEp, ..., "iso-pallas", a, b, ...)`).
const ISO_PALLAS_A: Fp = Fp::from_raw([
    0x92bb4b0b657a014b,
    0xb74134581a27a59f,
    0x49be2d7258370742,
    0x18354a2eb0ea8c9c,
]);
const ISO_PALLAS_B: Fp = Fp::from_raw([1265, 0, 0, 0]);

// SSWU parameter for Pallas, from `pasta_curves::curves::Ep`.
// Original upstream comment: `Z = -13`.
const PALLAS_Z: Fp = Fp::from_raw([
    0x992d30ecfffffff4,
    0x224698fc094cf91b,
    0x0000000000000000,
    0x4000000000000000,
]);

// Precomputed square root used by the optimized SSWU map.
// Original upstream comment: `(F::ROOT_OF_UNITY.invert().unwrap() * z).sqrt().unwrap()`.
const PALLAS_THETA: Fp = Fp::from_raw([
    0xca330bcc09ac318e,
    0x51f64fc4dc888857,
    0x4647aef782d5cdc8,
    0x0f7bdb65814179b4,
]);

// `GENERATOR^t where t * 2^s + 1 = p` with `t` odd; in other words, this is a `2^s` root of unity.
// Used by Tonelli-Shanks in `sqrt()` and by `sqrt_ratio()`.
const PALLAS_ROOT_OF_UNITY: Fp = Fp::from_raw([
    0xbdad6fabd87ea32f,
    0xea322bf2b7bb7584,
    0x362120830561f81a,
    0x2bce74deac30ebda,
]);

// Constants for the degree-3 isogeny from `iso-pallas` to `pallas`, copied from
// `pasta_curves::curves::Ep::ISOGENY_CONSTANTS`.
const PALLAS_ISOGENY_CONSTANTS: [Fp; 13] = [
    Fp::from_raw([
        0x775f6034aaaaaaab,
        0x4081775473d8375b,
        0xe38e38e38e38e38e,
        0x0e38e38e38e38e38,
    ]),
    Fp::from_raw([
        0x8cf863b02814fb76,
        0x0f93b82ee4b99495,
        0x267c7ffa51cf412a,
        0x3509afd51872d88e,
    ]),
    Fp::from_raw([
        0x0eb64faef37ea4f7,
        0x380af066cfeb6d69,
        0x98c7d7ac3d98fd13,
        0x17329b9ec5253753,
    ]),
    Fp::from_raw([
        0xeebec06955555580,
        0x8102eea8e7b06eb6,
        0xc71c71c71c71c71c,
        0x1c71c71c71c71c71,
    ]),
    Fp::from_raw([
        0xc47f2ab668bcd71f,
        0x9c434ac1c96b6980,
        0x5a607fcce0494a79,
        0x1d572e7ddc099cff,
    ]),
    Fp::from_raw([
        0x2aa3af1eae5b6604,
        0xb4abf9fb9a1fc81c,
        0x1d13bf2a7f22b105,
        0x325669becaecd5d1,
    ]),
    Fp::from_raw([
        0x5ad985b5e38e38e4,
        0x7642b01ad461bad2,
        0x4bda12f684bda12f,
        0x1a12f684bda12f68,
    ]),
    Fp::from_raw([
        0xc67c31d8140a7dbb,
        0x07c9dc17725cca4a,
        0x133e3ffd28e7a095,
        0x1a84d7ea8c396c47,
    ]),
    Fp::from_raw([
        0x02e2be87d225b234,
        0x1765e924f7459378,
        0x303216cce1db9ff1,
        0x3fb98ff0d2ddcadd,
    ]),
    Fp::from_raw([
        0x93e53ab371c71c4f,
        0x0ac03e8e134eb3e4,
        0x7b425ed097b425ed,
        0x025ed097b425ed09,
    ]),
    Fp::from_raw([
        0x5a28279b1d1b42ae,
        0x5941a3a4a97aa1b3,
        0x0790bfb3506defb6,
        0x0c02c5bcca0e6b7f,
    ]),
    Fp::from_raw([
        0x4d90ab820b12320a,
        0xd976bbfabbc5661d,
        0x573b3d7f7d681310,
        0x17033d3c60c68173,
    ]),
    Fp::from_raw([
        0x992d30ecfffffde5,
        0x224698fc094cf91b,
        0x0000000000000000,
        0x4000000000000000,
    ]),
];

#[derive(Copy, Clone, Eq, PartialEq)]
struct Fp([u8; 32]);

impl Fp {
    const ZERO: Self = Self([0; 32]);
    const ONE: Self = Self::from_raw([1, 0, 0, 0]);

    const fn from_raw(limbs: [u64; 4]) -> Self {
        Self(limbs_to_le_bytes(limbs))
    }

    fn from_uniform_be_bytes(bytes_be: &[u8; BLAKE2B_HASH_BYTES]) -> Result<Self, Error> {
        let mut bytes_le = *bytes_be;
        bytes_le.reverse();
        Ok(Self(to_pallas_base_bytes(&bytes_le)?))
    }

    fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }

    fn is_odd(&self) -> bool {
        (self.0[0] & 1) == 1
    }

    fn add(&self, rhs: &Self) -> Result<Self, Error> {
        let a = self.to_bn()?;
        let b = rhs.to_bn()?;
        let p = field_modulus_bn()?;
        let result = Bn::alloc(32)?;
        result.mod_add(&a, &b, &p)?;
        Self::from_bn(&result)
    }

    fn sub(&self, rhs: &Self) -> Result<Self, Error> {
        let a = self.to_bn()?;
        let b = rhs.to_bn()?;
        let p = field_modulus_bn()?;
        let result = Bn::alloc(32)?;
        result.mod_sub(&a, &b, &p)?;
        Self::from_bn(&result)
    }

    fn mul(&self, rhs: &Self) -> Result<Self, Error> {
        let a = self.to_bn()?;
        let b = rhs.to_bn()?;
        let p = field_modulus_bn()?;
        let result = Bn::alloc(32)?;
        result.mod_mul(&a, &b, &p)?;
        Self::from_bn(&result)
    }

    fn square(&self) -> Result<Self, Error> {
        self.mul(self)
    }

    fn double(&self) -> Result<Self, Error> {
        self.add(self)
    }

    fn neg(&self) -> Result<Self, Error> {
        Fp::ZERO.sub(self)
    }

    fn invert(&self) -> Result<Option<Self>, Error> {
        if self.is_zero() {
            return Ok(None);
        }

        let a = self.to_bn()?;
        let p = field_modulus_bn()?;
        let result = Bn::alloc(32)?;
        match result.mod_invert_nprime(&a, &p) {
            Ok(()) => Ok(Some(Self::from_bn(&result)?)),
            Err(CxError::NotInvertible) => Ok(None),
            Err(err) => Err(Error::Cx(err)),
        }
    }

    fn sqrt(&self) -> Result<Option<Self>, Error> {
        if self.is_zero() {
            return Ok(Some(Fp::ZERO));
        }

        let w = self.pow_vartime(&PALLAS_T_MINUS1_OVER2)?;
        let mut v = PALLAS_S;
        let mut x = w.mul(self)?;
        let mut b = x.mul(&w)?;
        let mut z = PALLAS_ROOT_OF_UNITY;

        while b != Fp::ONE {
            let mut k = 1;
            let mut b2k = b.square()?;

            while k < v {
                if b2k == Fp::ONE {
                    break;
                }

                b2k = b2k.square()?;
                k += 1;
            }

            if k == v {
                return Ok(None);
            }

            let mut w = z;
            let mut j = k + 1;
            while j < v {
                w = w.square()?;
                j += 1;
            }

            let z_new = w.square()?;
            x = x.mul(&w)?;
            b = b.mul(&z_new)?;
            z = z_new;
            v = k;
        }

        if x.square()? == *self {
            Ok(Some(x))
        } else {
            Ok(None)
        }
    }

    fn pow_vartime(&self, exp: &[u64; 4]) -> Result<Self, Error> {
        let mut result = Fp::ONE;
        let mut found_one = false;

        let mut limb_idx = exp.len();
        while limb_idx > 0 {
            limb_idx -= 1;
            let limb = exp[limb_idx];

            let mut bit_idx = 64usize;
            while bit_idx > 0 {
                bit_idx -= 1;

                if found_one {
                    result = result.square()?;
                }

                if ((limb >> bit_idx) & 1) == 1 {
                    found_one = true;
                    result = result.mul(self)?;
                }
            }
        }

        Ok(result)
    }

    fn to_bn(&self) -> Result<Bn, Error> {
        Ok(Bn::alloc_init(&self.to_be_bytes())?)
    }

    fn to_be_bytes(&self) -> [u8; 32] {
        let mut be = [0u8; 32];
        reverse_copy(&mut be, &self.0);
        be
    }

    fn from_bn(bn: &Bn) -> Result<Self, Error> {
        let mut be = [0u8; 32];
        bn.export(&mut be)?;

        let mut le = [0u8; 32];
        reverse_copy(&mut le, &be);
        Ok(Self(le))
    }
}

#[derive(Copy, Clone)]
struct JacobianPoint {
    x: Fp,
    y: Fp,
    z: Fp,
}

impl JacobianPoint {
    const fn identity() -> Self {
        Self {
            x: Fp::ZERO,
            y: Fp::ZERO,
            z: Fp::ZERO,
        }
    }

    fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    fn double_iso_pallas(&self) -> Result<Self, Error> {
        if self.is_identity() {
            return Ok(Self::identity());
        }

        let xx = self.x.square()?;
        let yy = self.y.square()?;
        let a = yy.square()?;
        let zz = self.z.square()?;
        let s = self.x.add(&yy)?.square()?.sub(&xx)?.sub(&a)?;
        let s = s.double()?;
        let m = xx
            .double()?
            .add(&xx)?
            .add(&ISO_PALLAS_A.mul(&zz.square()?)?)?;
        let x3 = m.square()?.sub(&s.double()?)?;
        let a8 = a.double()?.double()?.double()?;
        let y3 = m.mul(&s.sub(&x3)?)?.sub(&a8)?;
        let z3 = self.y.add(&self.z)?.square()?.sub(&yy)?.sub(&zz)?;

        Ok(Self {
            x: x3,
            y: y3,
            z: z3,
        })
    }

    fn add_iso_pallas(&self, rhs: &Self) -> Result<Self, Error> {
        if self.is_identity() {
            return Ok(*rhs);
        }
        if rhs.is_identity() {
            return Ok(*self);
        }

        let z1z1 = self.z.square()?;
        let z2z2 = rhs.z.square()?;
        let u1 = self.x.mul(&z2z2)?;
        let u2 = rhs.x.mul(&z1z1)?;
        let s1 = self.y.mul(&z2z2)?.mul(&rhs.z)?;
        let s2 = rhs.y.mul(&z1z1)?.mul(&self.z)?;

        if u1 == u2 {
            if s1 == s2 {
                self.double_iso_pallas()
            } else {
                Ok(Self::identity())
            }
        } else {
            let h = u2.sub(&u1)?;
            let i = h.double()?.square()?;
            let j = h.mul(&i)?;
            let r = s2.sub(&s1)?.double()?;
            let v = u1.mul(&i)?;
            let x3 = r.square()?.sub(&j)?.sub(&v)?.sub(&v)?;
            let s1j = s1.mul(&j)?.double()?;
            let y3 = r.mul(&v.sub(&x3)?)?.sub(&s1j)?;
            let z3 = self
                .z
                .add(&rhs.z)?
                .square()?
                .sub(&z1z1)?
                .sub(&z2z2)?
                .mul(&h)?;

            Ok(Self {
                x: x3,
                y: y3,
                z: z3,
            })
        }
    }

    fn to_compressed_bytes(&self) -> Result<Option<[u8; 32]>, Error> {
        if self.is_identity() {
            return Ok(None);
        }

        let Some(zinv) = self.z.invert()? else {
            return Ok(None);
        };
        let zinv2 = zinv.square()?;
        let x = self.x.mul(&zinv2)?;
        let y = self.y.mul(&zinv2)?.mul(&zinv)?;

        let mut point = EcPoint::new(CurvesId::Pallas)?;
        point.init(&x.to_be_bytes(), &y.to_be_bytes())?;

        let mut x_be = [0u8; 32];
        let sign = point.compress(&mut x_be)?;
        Ok(Some(encode_pallas_point_bytes(&x_be, sign)))
    }
}

pub fn diversify_hash_ledger(d: &[u8; 11]) -> Result<[u8; 32], Error> {
    if let Some(g_d) = hash_to_curve_pallas(ORCHARD_DIVERSIFY_HASH_PERSONALIZATION, d)? {
        return Ok(g_d);
    }

    hash_to_curve_pallas(ORCHARD_DIVERSIFY_HASH_PERSONALIZATION, &[])?
        .ok_or(Error::InvalidDiversifyHashPoint)
}

fn hash_to_curve_pallas(domain_prefix: &str, message: &[u8]) -> Result<Option<[u8; 32]>, Error> {
    let [u0, u1] = hash_to_field_pallas(domain_prefix, message)?;
    let q0 = map_to_curve_simple_swu_iso_pallas(&u0)?;
    let q1 = map_to_curve_simple_swu_iso_pallas(&u1).inspect_err(|e| {
        debug!("map_to_curve_simple_swu_iso_pallas failed for u1: {:?}", e);
        debug!("u1: {:?}", u1.to_be_bytes());
    })?;
    iso_map_pallas(&q0.add_iso_pallas(&q1)?)?.to_compressed_bytes()
}

fn hash_to_field_pallas(domain_prefix: &str, message: &[u8]) -> Result<[Fp; 2], Error> {
    let dst_len =
        (1 + HASH_TO_CURVE_SUFFIX.len() + PALLAS_CURVE_ID.len() + domain_prefix.len()) as u8;
    let zero_block = [0u8; BLAKE2B_BLOCK_BYTES];
    let len_block = [0u8, (BLAKE2B_HASH_BYTES * 2) as u8, 0u8];
    let counter_1 = [1u8];
    let counter_2 = [2u8];
    let dst_len_block = [dst_len];
    let mut xor_b0_b1 = [0u8; BLAKE2B_HASH_BYTES];

    let b0 = blake2b_512_hash_chunks(&[
        &zero_block,
        message,
        &len_block,
        domain_prefix.as_bytes(),
        b"-",
        PALLAS_CURVE_ID.as_bytes(),
        HASH_TO_CURVE_SUFFIX,
        &dst_len_block,
    ])?;
    let b1 = blake2b_512_hash_chunks(&[
        &b0,
        &counter_1,
        domain_prefix.as_bytes(),
        b"-",
        PALLAS_CURVE_ID.as_bytes(),
        HASH_TO_CURVE_SUFFIX,
        &dst_len_block,
    ])?;

    let mut i = 0;
    while i < BLAKE2B_HASH_BYTES {
        xor_b0_b1[i] = b0[i] ^ b1[i];
        i += 1;
    }

    let b2 = blake2b_512_hash_chunks(&[
        &xor_b0_b1,
        &counter_2,
        domain_prefix.as_bytes(),
        b"-",
        PALLAS_CURVE_ID.as_bytes(),
        HASH_TO_CURVE_SUFFIX,
        &dst_len_block,
    ])?;

    Ok([
        Fp::from_uniform_be_bytes(&b1)?,
        Fp::from_uniform_be_bytes(&b2)?,
    ])
}

fn blake2b_512_hash_chunks(chunks: &[&[u8]]) -> Result<[u8; BLAKE2B_HASH_BYTES], Error> {
    let mut personalization = BLAKE2B_ZERO_PERSONALIZATION;
    let mut output = [0u8; BLAKE2B_HASH_BYTES];
    let mut hasher = Blake2b_512::new_with_salt_and_perso(None, Some(&mut personalization))?;

    for chunk in chunks {
        hasher.update(chunk)?;
    }
    hasher.finalize(&mut output)?;

    Ok(output)
}

fn map_to_curve_simple_swu_iso_pallas(u: &Fp) -> Result<JacobianPoint, Error> {
    let z_u2 = PALLAS_Z.mul(&u.square()?)?;
    let ta = z_u2.square()?.add(&z_u2)?;
    let num_x1 = ISO_PALLAS_B.mul(&ta.add(&Fp::ONE)?)?;
    let div = if ta.is_zero() { PALLAS_Z } else { ta.neg()? }.mul(&ISO_PALLAS_A)?;
    let num2_x1 = num_x1.square()?;
    let div2 = div.square()?;
    let div3 = div2.mul(&div)?;
    let num_gx1 = num2_x1
        .add(&ISO_PALLAS_A.mul(&div2)?)?
        .mul(&num_x1)?
        .add(&ISO_PALLAS_B.mul(&div3)?)?;
    let num_x2 = z_u2.mul(&num_x1)?;

    let (gx1_square, y1) = sqrt_ratio(&num_gx1, &div3)?;
    let y2 = PALLAS_THETA.mul(&z_u2)?.mul(u)?.mul(&y1)?;
    let num_x = if gx1_square { num_x1 } else { num_x2 };
    let mut y = if gx1_square { y1 } else { y2 };

    if u.is_odd() != y.is_odd() {
        y = y.neg()?;
    }

    Ok(JacobianPoint {
        x: num_x.mul(&div)?,
        y: y.mul(&div3)?,
        z: div,
    })
}

fn sqrt_ratio(num: &Fp, div: &Fp) -> Result<(bool, Fp), Error> {
    if num.is_zero() {
        return Ok((true, Fp::ZERO));
    }
    if div.is_zero() {
        return Ok((false, Fp::ZERO));
    }

    let Some(div_inverse) = div.invert()? else {
        return Ok((false, Fp::ZERO));
    };
    let quotient = num.mul(&div_inverse)?;

    if let Some(sqrt) = quotient.sqrt()? {
        return Ok((true, sqrt));
    }

    let adjusted = PALLAS_ROOT_OF_UNITY.mul(&quotient)?;
    let Some(sqrt) = adjusted.sqrt()? else {
        return Err(Error::InvalidDiversifyHashPoint);
    };

    Ok((false, sqrt))
}

fn iso_map_pallas(point: &JacobianPoint) -> Result<JacobianPoint, Error> {
    let z2 = point.z.square()?;
    let z3 = z2.mul(&point.z)?;
    let z4 = z2.square()?;
    let z6 = z3.square()?;

    let num_x = PALLAS_ISOGENY_CONSTANTS[0]
        .mul(&point.x)?
        .add(&PALLAS_ISOGENY_CONSTANTS[1].mul(&z2)?)?
        .mul(&point.x)?
        .add(&PALLAS_ISOGENY_CONSTANTS[2].mul(&z4)?)?
        .mul(&point.x)?
        .add(&PALLAS_ISOGENY_CONSTANTS[3].mul(&z6)?)?;
    let div_x = z2
        .mul(&point.x)?
        .add(&PALLAS_ISOGENY_CONSTANTS[4].mul(&z4)?)?
        .mul(&point.x)?
        .add(&PALLAS_ISOGENY_CONSTANTS[5].mul(&z6)?)?;

    let num_y = PALLAS_ISOGENY_CONSTANTS[6]
        .mul(&point.x)?
        .add(&PALLAS_ISOGENY_CONSTANTS[7].mul(&z2)?)?
        .mul(&point.x)?
        .add(&PALLAS_ISOGENY_CONSTANTS[8].mul(&z4)?)?
        .mul(&point.x)?
        .add(&PALLAS_ISOGENY_CONSTANTS[9].mul(&z6)?)?
        .mul(&point.y)?;
    let div_y = point
        .x
        .add(&PALLAS_ISOGENY_CONSTANTS[10].mul(&z2)?)?
        .mul(&point.x)?
        .add(&PALLAS_ISOGENY_CONSTANTS[11].mul(&z4)?)?
        .mul(&point.x)?
        .add(&PALLAS_ISOGENY_CONSTANTS[12].mul(&z6)?)?
        .mul(&z3)?;

    let zo = div_x.mul(&div_y)?;
    let xo = num_x.mul(&div_y)?.mul(&zo)?;
    let yo = num_y.mul(&div_x)?.mul(&zo.square()?)?;

    Ok(JacobianPoint {
        x: xo,
        y: yo,
        z: zo,
    })
}

fn field_modulus_bn() -> Result<Bn, Error> {
    Ok(Bn::alloc_init(&PALLAS_MODULUS.to_be_bytes())?)
}

fn encode_pallas_point_bytes(x_be: &[u8; 32], sign: u32) -> [u8; 32] {
    let mut x_le = [0u8; 32];
    reverse_copy(&mut x_le, x_be);
    x_le[31] |= ((sign & 1) as u8) << 7;
    x_le
}

const fn limbs_to_le_bytes(limbs: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;

    while i < 4 {
        let limb = limbs[i];
        out[i * 8] = limb as u8;
        out[i * 8 + 1] = (limb >> 8) as u8;
        out[i * 8 + 2] = (limb >> 16) as u8;
        out[i * 8 + 3] = (limb >> 24) as u8;
        out[i * 8 + 4] = (limb >> 32) as u8;
        out[i * 8 + 5] = (limb >> 40) as u8;
        out[i * 8 + 6] = (limb >> 48) as u8;
        out[i * 8 + 7] = (limb >> 56) as u8;
        i += 1;
    }

    out
}
