//! Orchard note, nullifier and value-commitment derivations.
//!
//! The commitment entry points here are `#[inline(never)]`: each builds a
//! `[bool; NOTE_COMMITMENT_MESSAGE_BITS]` Sinsemilla message on the stack, and
//! folded into their caller two of those (the nullifier's commitment and the
//! output's `cmx`) become resident together even though they are computed one
//! after the other — which overflows the Nano X stack.

use alloc::{boxed::Box, vec::Vec};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInPlace};
use ff::{Field, PrimeField};
use ledger_device_sdk::hash::{
    HashInit as _,
    blake2::{Blake2b_256, Blake2bWithPerso},
};
use pasta_curves::pallas;

use crate::NOTE_VERSION_ORCHARD;
use crate::{
    Error, ORCHARD_ESK_DOMAIN_SEPARATOR, ORCHARD_PSI_DOMAIN_SEPARATOR,
    ORCHARD_RCM_DOMAIN_SEPARATOR, PRF_EXPAND_BYTES,
    bytes::reverse_copy,
    pallas_base_from_repr, pallas_basepoint_mul, pallas_point_from_bytes, pallas_point_to_bytes,
    pallas_scalar_from_repr, prf_expand_with_domain_separator_and_inputs,
    redpallas::point_from_sdk_point,
    sinsemilla::{extract_p_pallas, sinsemilla_short_commit, sinsemilla_short_commit_point},
    to_pallas_base_bytes, to_pallas_scalar_bytes,
};
#[cfg(feature = "zcash_unstable")]
use crate::{NOTE_VERSION_IRONWOOD, ORCHARD_QR_RCM_DOMAIN_SEPARATOR};

pub const ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE: usize = 52;
pub const ORCHARD_MEMO_SIZE: usize = 512;
pub const ORCHARD_NOTE_PLAINTEXT_SIZE: usize =
    ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE + ORCHARD_MEMO_SIZE;
pub const ORCHARD_AEAD_TAG_SIZE: usize = 16;
pub const ORCHARD_ENC_CIPHERTEXT_SIZE: usize = ORCHARD_NOTE_PLAINTEXT_SIZE + ORCHARD_AEAD_TAG_SIZE;
pub const ORCHARD_OUT_PLAINTEXT_SIZE: usize = 64;
pub const ORCHARD_OUT_CIPHERTEXT_SIZE: usize = ORCHARD_OUT_PLAINTEXT_SIZE + ORCHARD_AEAD_TAG_SIZE;
pub const ORCHARD_RAW_ADDRESS_SIZE: usize = 43;

const HASH_SIZE: usize = 32;
const DIVERSIFIER_SIZE: usize = 11;
const VALUE_SIZE: usize = 8;
const NOTE_VALUE_OFFSET: usize = 1 + DIVERSIFIER_SIZE;
const RSEED_OFFSET: usize = NOTE_VALUE_OFFSET + VALUE_SIZE;
const L_ORCHARD_BASE: usize = 255;
const NOTE_COMMITMENT_MESSAGE_BITS: usize = 32 * 8 + 32 * 8 + 64 + L_ORCHARD_BASE + L_ORCHARD_BASE;
const PRF_OCK_ORCHARD_PERSONALIZATION: [u8; 16] = *b"Zcash_Orchardock";
const KDF_ORCHARD_PERSONALIZATION: [u8; 16] = *b"Zcash_OrchardKDF";
const NOTE_COMMITMENT_PERSONALIZATION: &str = "z.cash:Orchard-NoteCommit";
const ORCHARD_NULLIFIER_K_BASEPOINT_BYTES: [u8; HASH_SIZE] = [
    0x75, 0xca, 0x47, 0xe4, 0xa7, 0x6a, 0x6f, 0xd3, 0x9b, 0xdb, 0xb5, 0xcc, 0x92, 0xb1, 0x7e, 0x5e,
    0xcf, 0xc9, 0xf4, 0xfa, 0x71, 0x55, 0x37, 0x2e, 0x8d, 0x19, 0xa8, 0x9c, 0x16, 0xaa, 0xe7, 0x25,
];

#[derive(Clone, Copy, Debug)]
pub struct OrchardCompactAction {
    pub nullifier: [u8; HASH_SIZE],
    pub cmx: [u8; HASH_SIZE],
    pub ephemeral_key: [u8; HASH_SIZE],
    pub enc_ciphertext_prefix: [u8; ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE],
}

#[derive(Clone, Copy, Debug)]
pub struct OrchardActionCiphertext<'a> {
    pub compact: OrchardCompactAction,
    pub rk: [u8; HASH_SIZE],
    pub cv_net: [u8; HASH_SIZE],
    pub enc_ciphertext: &'a [u8],
    pub out_ciphertext: [u8; ORCHARD_OUT_CIPHERTEXT_SIZE],
}

#[derive(Debug)]
pub struct DecipheredOrchardOutput {
    pub value: u64,
    pub raw_address: [u8; ORCHARD_RAW_ADDRESS_SIZE],
    // Keep the 512-byte memo off stack-sensitive Orchard return paths.
    pub memo: Option<Box<[u8]>>,
}

pub fn decipher_value_with_ovk(
    ovk: &[u8; HASH_SIZE],
    action: &OrchardActionCiphertext<'_>,
) -> Result<Option<DecipheredOrchardOutput>, Error> {
    try_output_recovery_with_ovk(ovk, action)
}

pub fn decipher_compact_value(
    ivk: &[u8; HASH_SIZE],
    compact: &OrchardCompactAction,
) -> Result<Option<DecipheredOrchardOutput>, Error> {
    try_compact_note_decryption_with_ivk(ivk, compact)
}

#[inline(never)]
pub fn spend_nullifier_bytes(
    nk: &[u8; HASH_SIZE],
    raw_address: &[u8; ORCHARD_RAW_ADDRESS_SIZE],
    value: u64,
    rho: &[u8; HASH_SIZE],
    rseed: &[u8; HASH_SIZE],
) -> Result<[u8; HASH_SIZE], Error> {
    let rho = pallas_base_from_repr(*rho)?;
    let _esk = orchard_esk(rseed, &rho)?;

    let mut diversifier = [0u8; DIVERSIFIER_SIZE];
    diversifier.copy_from_slice(&raw_address[..DIVERSIFIER_SIZE]);

    let mut pk_d = [0u8; HASH_SIZE];
    pk_d.copy_from_slice(&raw_address[DIVERSIFIER_SIZE..]);
    if !is_valid_nonidentity_pallas_point(&pk_d)? {
        return Err(Error::MalformedPallasPoint);
    }

    let g_d = crate::diversify_hash_ledger(&diversifier)?;
    let cm = note_commitment_point(&g_d, &pk_d, value, &rho, rseed)?;
    let psi = pallas_base_from_repr(orchard_psi(rseed, &rho)?)?;
    let nk = pallas_base_from_repr(*nk)?;
    let prf_nf = crate::poseidon::p128pow5t3_hash_len2(nk, rho);
    let nullifier_scalar = pallas_scalar_from_repr((prf_nf + psi).to_repr())?;

    let nullifier_point = if bool::from(nullifier_scalar.is_zero()) {
        cm
    } else {
        // The commitment `cm` is already a pure-Rust point, so converting the
        // scalar-mul result and adding in software keeps exactly one SDK point
        // alive here; adding with SDK points would hold three at once (cm, the
        // scalar-mul result, the sum). The `cx_bn` pool is a small shared budget
        // with no documented ceiling, and Speculos does not model it, so this
        // path keeps its footprint minimal by construction rather than against a
        // measured limit.
        let nullifier_k_ec = pallas_basepoint_mul(
            &ORCHARD_NULLIFIER_K_BASEPOINT_BYTES,
            &scalar_bytes_be(&nullifier_scalar),
        )?;
        point_from_sdk_point(&nullifier_k_ec)? + cm
    };

    Ok(extract_p_pallas(&nullifier_point).to_repr())
}

#[inline(never)]
pub fn note_commitment_bytes(
    raw_address: &[u8; ORCHARD_RAW_ADDRESS_SIZE],
    value: u64,
    rho: &[u8; HASH_SIZE],
    rseed: &[u8; HASH_SIZE],
) -> Result<[u8; HASH_SIZE], Error> {
    let rho = pallas_base_from_repr(*rho)?;
    let _esk = orchard_esk(rseed, &rho)?;

    let mut diversifier = [0u8; DIVERSIFIER_SIZE];
    diversifier.copy_from_slice(&raw_address[..DIVERSIFIER_SIZE]);

    let mut pk_d = [0u8; HASH_SIZE];
    pk_d.copy_from_slice(&raw_address[DIVERSIFIER_SIZE..]);
    if !is_valid_nonidentity_pallas_point(&pk_d)? {
        return Err(Error::MalformedPallasPoint);
    }

    let g_d = crate::diversify_hash_ledger(&diversifier)?;
    note_commitment(&g_d, &pk_d, value, &rho, rseed)
}

fn try_output_recovery_with_ovk(
    ovk: &[u8; HASH_SIZE],
    action: &OrchardActionCiphertext<'_>,
) -> Result<Option<DecipheredOrchardOutput>, Error> {
    let rho = match pallas_base_from_repr(action.compact.nullifier) {
        Ok(rho) => rho,
        Err(_) => return Ok(None),
    };

    if pallas_base_from_repr(action.compact.cmx).is_err() {
        return Ok(None);
    }

    let ock = prf_ock_orchard(
        ovk,
        &action.cv_net,
        &action.compact.cmx,
        &action.compact.ephemeral_key,
    )?;

    let mut out_plaintext = [0u8; ORCHARD_OUT_PLAINTEXT_SIZE];
    if !chacha20poly1305_decrypt(&ock, &action.out_ciphertext, &mut out_plaintext) {
        return Ok(None);
    }

    let mut pk_d = [0u8; HASH_SIZE];
    let mut esk = [0u8; HASH_SIZE];
    pk_d.copy_from_slice(&out_plaintext[..HASH_SIZE]);
    esk.copy_from_slice(&out_plaintext[HASH_SIZE..ORCHARD_OUT_PLAINTEXT_SIZE]);

    if !is_valid_nonidentity_pallas_point(&pk_d)? || !is_valid_nonzero_pallas_scalar(&esk) {
        return Ok(None);
    }

    let shared_secret = key_agreement(&esk, &pk_d)?;
    let k_enc = kdf_orchard(&shared_secret, &action.compact.ephemeral_key)?;

    let mut note_plaintext = [0u8; ORCHARD_NOTE_PLAINTEXT_SIZE];
    if !chacha20poly1305_decrypt(&k_enc, action.enc_ciphertext, &mut note_plaintext) {
        return Ok(None);
    }

    let mut note_plaintext_prefix = [0u8; ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE];
    note_plaintext_prefix.copy_from_slice(&note_plaintext[..ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE]);
    let mut memo = Vec::new();
    memo.try_reserve_exact(ORCHARD_MEMO_SIZE)
        .map_err(|_| Error::OutOfMemory)?;
    memo.extend_from_slice(&note_plaintext[ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE..]);
    let memo = memo.into_boxed_slice();

    parse_and_validate_note_plaintext(
        &action.compact,
        &note_plaintext_prefix,
        &pk_d,
        Some(&esk),
        &rho,
        Some(memo),
    )
}

fn try_compact_note_decryption_with_ivk(
    ivk: &[u8; HASH_SIZE],
    compact: &OrchardCompactAction,
) -> Result<Option<DecipheredOrchardOutput>, Error> {
    let rho = match pallas_base_from_repr(compact.nullifier) {
        Ok(rho) => rho,
        Err(_) => return Ok(None),
    };

    if pallas_base_from_repr(compact.cmx).is_err() {
        return Ok(None);
    }

    let ivk = match pallas_base_from_repr(*ivk) {
        Ok(ivk) if !bool::from(ivk.is_zero()) => ivk,
        _ => return Ok(None),
    };

    if !is_valid_nonidentity_pallas_point(&compact.ephemeral_key)? {
        return Ok(None);
    }

    let shared_secret = key_agreement(&ivk.to_repr(), &compact.ephemeral_key)?;
    let k_enc = kdf_orchard(&shared_secret, &compact.ephemeral_key)?;

    let mut note_plaintext_prefix = compact.enc_ciphertext_prefix;
    chacha20_decrypt_compact(&k_enc, &mut note_plaintext_prefix);

    let Some(diversifier) = parse_note_plaintext_diversifier(&note_plaintext_prefix) else {
        return Ok(None);
    };

    let g_d = match crate::diversify_hash_ledger(&diversifier) {
        Ok(g_d) => g_d,
        Err(_) => return Ok(None),
    };
    let pk_d = crate::orchard_pk_d(&ivk.to_repr(), &g_d)?;

    parse_and_validate_note_plaintext(compact, &note_plaintext_prefix, &pk_d, None, &rho, None)
}

fn parse_and_validate_note_plaintext(
    compact: &OrchardCompactAction,
    plaintext: &[u8; ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE],
    pk_d: &[u8; HASH_SIZE],
    expected_esk: Option<&[u8; HASH_SIZE]>,
    rho: &pallas::Base,
    memo: Option<Box<[u8]>>,
) -> Result<Option<DecipheredOrchardOutput>, Error> {
    let Some(note_plaintext) = parse_note_plaintext_prefix(plaintext) else {
        return Ok(None);
    };

    let derived_esk = orchard_esk(&note_plaintext.rseed, rho)?;
    if let Some(esk) = expected_esk
        && !bytes_eq(&derived_esk, esk)
    {
        return Ok(None);
    }

    let g_d = match crate::diversify_hash_ledger(&note_plaintext.diversifier) {
        Ok(g_d) => g_d,
        Err(_) => return Ok(None),
    };

    let derived_epk = key_agreement(&derived_esk, &g_d)?;
    if !bytes_eq(&derived_epk, &compact.ephemeral_key) {
        return Ok(None);
    }

    // Recompute and verify the note commitment. For V3 (Ironwood / ZIP 2005), the
    // quantum-recoverable rcm derivation additionally binds g_d, pk_d, and value, which
    // prevents a malicious host from swapping cmx to commit to a different recipient
    // while presenting a valid enc_ciphertext for the device's IVK.
    #[cfg(not(feature = "zcash_unstable"))]
    let cmx = note_commitment(&g_d, pk_d, note_plaintext.value, rho, &note_plaintext.rseed)?;
    #[cfg(feature = "zcash_unstable")]
    let cmx = if plaintext[0] == NOTE_VERSION_IRONWOOD {
        note_commitment_v3(&g_d, pk_d, note_plaintext.value, rho, &note_plaintext.rseed)?
    } else {
        note_commitment(&g_d, pk_d, note_plaintext.value, rho, &note_plaintext.rseed)?
    };
    if !bytes_eq(&cmx, &compact.cmx) {
        return Ok(None);
    }

    let mut raw_address = [0u8; ORCHARD_RAW_ADDRESS_SIZE];
    raw_address[..DIVERSIFIER_SIZE].copy_from_slice(&note_plaintext.diversifier);
    raw_address[DIVERSIFIER_SIZE..].copy_from_slice(pk_d);

    Ok(Some(DecipheredOrchardOutput {
        value: note_plaintext.value,
        raw_address,
        memo,
    }))
}

fn prf_ock_orchard(
    ovk: &[u8; HASH_SIZE],
    cv: &[u8; HASH_SIZE],
    cmx: &[u8; HASH_SIZE],
    ephemeral_key: &[u8; HASH_SIZE],
) -> Result<[u8; HASH_SIZE], Error> {
    let mut personalization = PRF_OCK_ORCHARD_PERSONALIZATION;
    let mut output = [0u8; HASH_SIZE];

    let mut blake2b = Blake2b_256::new_with_salt_and_perso(None, Some(&mut personalization))?;
    blake2b.update(ovk)?;
    blake2b.update(cv)?;
    blake2b.update(cmx)?;
    blake2b.update(ephemeral_key)?;
    blake2b.finalize(&mut output)?;

    Ok(output)
}

fn kdf_orchard(
    shared_secret: &[u8; HASH_SIZE],
    ephemeral_key: &[u8; HASH_SIZE],
) -> Result<[u8; HASH_SIZE], Error> {
    let mut personalization = KDF_ORCHARD_PERSONALIZATION;
    let mut output = [0u8; HASH_SIZE];

    let mut blake2b = Blake2b_256::new_with_salt_and_perso(None, Some(&mut personalization))?;
    blake2b.update(shared_secret)?;
    blake2b.update(ephemeral_key)?;
    blake2b.finalize(&mut output)?;

    Ok(output)
}

fn chacha20poly1305_decrypt<const PLAINTEXT_SIZE: usize>(
    key: &[u8; HASH_SIZE],
    ciphertext: &[u8],
    plaintext: &mut [u8; PLAINTEXT_SIZE],
) -> bool {
    if ciphertext.len() != PLAINTEXT_SIZE + ORCHARD_AEAD_TAG_SIZE {
        return false;
    }

    plaintext.copy_from_slice(&ciphertext[..PLAINTEXT_SIZE]);
    let tag: &[u8; ORCHARD_AEAD_TAG_SIZE] = match ciphertext[PLAINTEXT_SIZE..].try_into() {
        Ok(tag) => tag,
        Err(_) => return false,
    };

    ChaCha20Poly1305::new(key.into())
        .decrypt_in_place_detached((&[0u8; 12]).into(), &[], plaintext, tag.into())
        .is_ok()
}

fn chacha20_decrypt_compact(
    key: &[u8; HASH_SIZE],
    plaintext: &mut [u8; ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE],
) {
    let nonce = [0u8; 12];
    let mut chacha = ChaCha20::new(key.into(), (&nonce).into());
    chacha.seek(64);
    chacha.apply_keystream(plaintext);
}

fn key_agreement(
    scalar_bytes_le: &[u8; HASH_SIZE],
    point_bytes: &[u8; HASH_SIZE],
) -> Result<[u8; HASH_SIZE], Error> {
    let scalar_bytes_be = canonical_scalar_bytes_be(scalar_bytes_le)?;
    let mut point = pallas_point_from_bytes(point_bytes)?;
    point.rnd_scalarmul(&scalar_bytes_be)?;
    pallas_point_to_bytes(&point)
}

fn canonical_scalar_bytes_be(bytes_le: &[u8; HASH_SIZE]) -> Result<[u8; HASH_SIZE], Error> {
    let scalar = pallas_scalar_from_repr(*bytes_le)?;
    if bool::from(scalar.is_zero()) {
        return Err(Error::MalformedPallasScalar);
    }

    let mut bytes_be = [0u8; HASH_SIZE];
    reverse_copy(&mut bytes_be, bytes_le);
    Ok(bytes_be)
}

fn is_valid_nonzero_pallas_scalar(bytes: &[u8; HASH_SIZE]) -> bool {
    match pallas_scalar_from_repr(*bytes) {
        Ok(scalar) => !bool::from(scalar.is_zero()),
        Err(_) => false,
    }
}

fn is_valid_nonidentity_pallas_point(bytes: &[u8; HASH_SIZE]) -> Result<bool, Error> {
    if *bytes == [0u8; HASH_SIZE] {
        return Ok(false);
    }

    let point = match pallas_point_from_bytes(bytes) {
        Ok(point) => point,
        Err(_) => return Ok(false),
    };

    if point.is_at_infinity()? {
        return Ok(false);
    }

    Ok(pallas_point_to_bytes(&point)? == *bytes)
}

fn orchard_esk(rseed: &[u8; HASH_SIZE], rho: &pallas::Base) -> Result<[u8; HASH_SIZE], Error> {
    let uniform = prf_expand_rseed_with_rho(rseed, ORCHARD_ESK_DOMAIN_SEPARATOR, rho)?;
    let esk = to_pallas_scalar_bytes(&uniform)?;

    if !is_valid_nonzero_pallas_scalar(&esk) {
        return Err(Error::InvalidKeyDiscarded);
    }

    Ok(esk)
}

fn orchard_psi(rseed: &[u8; HASH_SIZE], rho: &pallas::Base) -> Result<[u8; HASH_SIZE], Error> {
    let uniform = prf_expand_rseed_with_rho(rseed, ORCHARD_PSI_DOMAIN_SEPARATOR, rho)?;
    to_pallas_base_bytes(&uniform)
}

fn orchard_rcm(rseed: &[u8; HASH_SIZE], rho: &pallas::Base) -> Result<[u8; HASH_SIZE], Error> {
    let uniform = prf_expand_rseed_with_rho(rseed, ORCHARD_RCM_DOMAIN_SEPARATOR, rho)?;
    to_pallas_scalar_bytes(&uniform)
}

fn prf_expand_rseed_with_rho(
    rseed: &[u8; HASH_SIZE],
    domain_separator: u8,
    rho: &pallas::Base,
) -> Result<[u8; PRF_EXPAND_BYTES], Error> {
    prf_expand_with_domain_separator_and_inputs(rseed, domain_separator, &[&rho.to_repr()])
}

struct OrchardNotePlaintextPrefix {
    diversifier: [u8; DIVERSIFIER_SIZE],
    value: u64,
    rseed: [u8; HASH_SIZE],
}

fn parse_note_plaintext_diversifier(
    plaintext: &[u8; ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE],
) -> Option<[u8; DIVERSIFIER_SIZE]> {
    parse_note_plaintext_prefix(plaintext).map(|parsed| parsed.diversifier)
}

fn parse_note_plaintext_prefix(
    plaintext: &[u8; ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE],
) -> Option<OrchardNotePlaintextPrefix> {
    // The version byte is the only structural difference between V2 and V3 note formats.
    #[cfg(not(feature = "zcash_unstable"))]
    if plaintext[0] != NOTE_VERSION_ORCHARD {
        return None;
    }
    #[cfg(feature = "zcash_unstable")]
    if plaintext[0] != NOTE_VERSION_ORCHARD && plaintext[0] != NOTE_VERSION_IRONWOOD {
        return None;
    }

    let mut diversifier = [0u8; DIVERSIFIER_SIZE];
    diversifier.copy_from_slice(&plaintext[1..NOTE_VALUE_OFFSET]);

    let mut value_bytes = [0u8; VALUE_SIZE];
    value_bytes.copy_from_slice(&plaintext[NOTE_VALUE_OFFSET..RSEED_OFFSET]);
    let value = u64::from_le_bytes(value_bytes);

    let mut rseed = [0u8; HASH_SIZE];
    rseed.copy_from_slice(
        &plaintext[RSEED_OFFSET..RSEED_OFFSET + ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE - RSEED_OFFSET],
    );

    Some(OrchardNotePlaintextPrefix {
        diversifier,
        value,
        rseed,
    })
}

#[inline(never)]
fn note_commitment(
    g_d: &[u8; HASH_SIZE],
    pk_d: &[u8; HASH_SIZE],
    value: u64,
    rho: &pallas::Base,
    rseed: &[u8; HASH_SIZE],
) -> Result<[u8; HASH_SIZE], Error> {
    let psi = orchard_psi(rseed, rho)?;
    let rcm = orchard_rcm(rseed, rho)?;
    let rcm = pallas_scalar_from_repr(rcm)?;

    let mut message = [false; NOTE_COMMITMENT_MESSAGE_BITS];
    let mut offset = 0;
    append_le_bits(&mut message, &mut offset, g_d, 32 * 8);
    append_le_bits(&mut message, &mut offset, pk_d, 32 * 8);
    append_le_bits(&mut message, &mut offset, &value.to_le_bytes(), 64);
    append_le_bits(&mut message, &mut offset, &rho.to_repr(), L_ORCHARD_BASE);
    append_le_bits(&mut message, &mut offset, &psi, L_ORCHARD_BASE);

    let Some(cmx) = sinsemilla_short_commit(NOTE_COMMITMENT_PERSONALIZATION, &message, &rcm)?
    else {
        return Err(Error::InvalidKeyDiscarded);
    };

    Ok(cmx.to_repr())
}

/// Derives the quantum-recoverable rcm for a V3 (Ironwood / ZIP 2005) note.
///
/// Per ZIP 2005 §3.2.1:
///
/// ```text
/// rcm_v3 = ToScalar^Orchard(
///   PRF^expand_rseed([0x0B] ‖ g_d ‖ pk_d ‖ I2LEOSP_64(v) ‖ rho ‖ psi)
/// )
/// ```
///
/// Unlike the V2 rcm derivation (which only takes rseed and rho), the V3 trapdoor
/// additionally commits to the recipient's `g_d` and `pk_d` and to the note `value`,
/// providing post-quantum binding of the note commitment to all note fields.
#[cfg(feature = "zcash_unstable")]
fn orchard_rcm_v3(
    rseed: &[u8; HASH_SIZE],
    g_d: &[u8; HASH_SIZE],
    pk_d: &[u8; HASH_SIZE],
    value: u64,
    rho: &pallas::Base,
    psi: &[u8; HASH_SIZE],
) -> Result<[u8; HASH_SIZE], Error> {
    let value_bytes = value.to_le_bytes();
    let rho_repr = rho.to_repr();
    let uniform = prf_expand_with_domain_separator_and_inputs(
        rseed,
        ORCHARD_QR_RCM_DOMAIN_SEPARATOR,
        &[g_d, pk_d, &value_bytes, &rho_repr, psi],
    )?;
    to_pallas_scalar_bytes(&uniform)
}

/// Derives the note commitment for a V3 (Ironwood / ZIP 2005) note.
///
/// The Sinsemilla message is identical to V2 — `(g_d, pk_d, value, rho, psi)` — but the
/// trapdoor `rcm` uses the quantum-recoverable derivation from `orchard_rcm_v3`, which
/// binds the trapdoor to all note fields and therefore ties `cmx` to the specific recipient.
#[cfg(feature = "zcash_unstable")]
#[inline(never)]
pub(crate) fn orchard_note_commitment_v3(
    recipient: &[u8; ORCHARD_RAW_ADDRESS_SIZE],
    value: u64,
    nullifier: &[u8; HASH_SIZE],
    rseed: &[u8; HASH_SIZE],
) -> Result<[u8; HASH_SIZE], Error> {
    let rho = pallas_base_from_repr(*nullifier)?;

    let mut diversifier = [0u8; DIVERSIFIER_SIZE];
    diversifier.copy_from_slice(&recipient[..DIVERSIFIER_SIZE]);

    let mut pk_d = [0u8; HASH_SIZE];
    pk_d.copy_from_slice(&recipient[DIVERSIFIER_SIZE..]);
    if !is_valid_nonidentity_pallas_point(&pk_d)? {
        return Err(Error::MalformedPallasPoint);
    }

    let g_d = crate::diversify_hash_ledger(&diversifier)?;
    note_commitment_v3(&g_d, &pk_d, value, &rho, rseed)
}

#[cfg(feature = "zcash_unstable")]
#[inline(never)]
fn note_commitment_v3(
    g_d: &[u8; HASH_SIZE],
    pk_d: &[u8; HASH_SIZE],
    value: u64,
    rho: &pallas::Base,
    rseed: &[u8; HASH_SIZE],
) -> Result<[u8; HASH_SIZE], Error> {
    let psi = orchard_psi(rseed, rho)?;
    let rcm = orchard_rcm_v3(rseed, g_d, pk_d, value, rho, &psi)?;
    let rcm = pallas_scalar_from_repr(rcm)?;

    let mut message = [false; NOTE_COMMITMENT_MESSAGE_BITS];
    let mut offset = 0;
    append_le_bits(&mut message, &mut offset, g_d, 32 * 8);
    append_le_bits(&mut message, &mut offset, pk_d, 32 * 8);
    append_le_bits(&mut message, &mut offset, &value.to_le_bytes(), 64);
    append_le_bits(&mut message, &mut offset, &rho.to_repr(), L_ORCHARD_BASE);
    append_le_bits(&mut message, &mut offset, &psi, L_ORCHARD_BASE);

    let Some(cmx) = sinsemilla_short_commit(NOTE_COMMITMENT_PERSONALIZATION, &message, &rcm)?
    else {
        return Err(Error::InvalidKeyDiscarded);
    };

    Ok(cmx.to_repr())
}

#[inline(never)]
fn note_commitment_point(
    g_d: &[u8; HASH_SIZE],
    pk_d: &[u8; HASH_SIZE],
    value: u64,
    rho: &pallas::Base,
    rseed: &[u8; HASH_SIZE],
) -> Result<pallas::Point, Error> {
    let psi = orchard_psi(rseed, rho)?;
    let rcm = orchard_rcm(rseed, rho)?;
    let rcm = pallas_scalar_from_repr(rcm)?;

    let mut message = [false; NOTE_COMMITMENT_MESSAGE_BITS];
    let mut offset = 0;
    append_le_bits(&mut message, &mut offset, g_d, 32 * 8);
    append_le_bits(&mut message, &mut offset, pk_d, 32 * 8);
    append_le_bits(&mut message, &mut offset, &value.to_le_bytes(), 64);
    append_le_bits(&mut message, &mut offset, &rho.to_repr(), L_ORCHARD_BASE);
    append_le_bits(&mut message, &mut offset, &psi, L_ORCHARD_BASE);

    sinsemilla_short_commit_point(NOTE_COMMITMENT_PERSONALIZATION, &message, &rcm)?
        .ok_or(Error::InvalidKeyDiscarded)
}

fn scalar_bytes_be(scalar: &pallas::Scalar) -> [u8; HASH_SIZE] {
    let mut bytes_be = [0u8; HASH_SIZE];
    reverse_copy(&mut bytes_be, &scalar.to_repr());
    bytes_be
}

fn append_le_bits(message: &mut [bool], offset: &mut usize, bytes: &[u8], bit_len: usize) {
    for bit_index in 0..bit_len {
        message[*offset + bit_index] = ((bytes[bit_index / 8] >> (bit_index % 8)) & 1) == 1;
    }
    *offset += bit_len;
}

fn bytes_eq(lhs: &[u8; HASH_SIZE], rhs: &[u8; HASH_SIZE]) -> bool {
    let mut diff = 0u8;
    for (l, r) in lhs.iter().zip(rhs.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}

/// Unit tests for the V3 (ZIP 2005) note commitment path.
///
/// These tests run under Speculos — the `ledger_zcash_crypto` crate links against
/// `ledger_device_sdk` which does not compile on a native macOS / Linux host.
/// Run with:
///   `cargo test -p ledger_zcash_crypto -- orchard::tests --nocapture`
/// from a Speculos session configured with `runner = "speculos -m apex_p"`.
///
/// The note parameters here match the constants used in the Python Ragger tests in
/// `tests/standalone/test_pczt_ironwood.py` (`_DUMMY_NULLIFIER`, `_DUMMY_RSEED`,
/// `_INTERNAL_RECIPIENT`, `_DUMMY_CHANGE_VALUE`) so that both test layers exercise
/// the same commitment computation.
#[cfg(test)]
mod tests {
    use super::*;

    // `_DUMMY_NULLIFIER` from test_pczt_ironwood.py
    const DUMMY_NULLIFIER: [u8; 32] = [
        0x57, 0xaa, 0xd2, 0x67, 0x0e, 0x2e, 0x4d, 0xf6, 0x7c, 0xa8, 0x55, 0xc5, 0x39, 0x73, 0xdb,
        0x38, 0xe7, 0x94, 0x2e, 0xfa, 0x8e, 0x90, 0x6e, 0xe9, 0x61, 0xad, 0xb7, 0x19, 0x55, 0xaa,
        0x84, 0x23,
    ];
    // `_DUMMY_RSEED` from test_pczt_ironwood.py
    const DUMMY_RSEED: [u8; 32] = [
        0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];
    // First 11 bytes of `_INTERNAL_RECIPIENT` from test_pczt_ironwood.py
    const INTERNAL_DIVERSIFIER: [u8; 11] = [
        0xed, 0xe3, 0xd2, 0xce, 0x08, 0xc1, 0x1d, 0x8c, 0x5c, 0x7b, 0xfe,
    ];
    // Bytes 11..43 of `_INTERNAL_RECIPIENT` from test_pczt_ironwood.py
    const INTERNAL_PK_D: [u8; 32] = [
        0x68, 0x14, 0xce, 0xda, 0xfd, 0x96, 0xc1, 0x60, 0xc3, 0xd8, 0x79, 0xcb, 0x27, 0x09, 0x46,
        0xf1, 0xab, 0x6f, 0xdf, 0x44, 0x2a, 0x15, 0x64, 0x8d, 0x7c, 0x0b, 0x3c, 0x9f, 0xd0, 0x52,
        0xe2, 0x0a,
    ];
    // `_DUMMY_CHANGE_VALUE` from test_pczt_ironwood.py
    const VALUE: u64 = 10000;

    /// `note_commitment_v3` must produce a result that differs from `note_commitment`
    /// for the same `(g_d, pk_d, value, rho, rseed)` inputs.
    ///
    /// The two functions share the same Sinsemilla message but use different trapdoors:
    /// - V2: `rcm = ToScalar(PRF_expand(rseed, [0x05] ‖ rho))`
    /// - V3: `rcm_v3 = ToScalar(PRF_expand(rseed, [0x0B] ‖ g_d ‖ pk_d ‖ value_le ‖ rho ‖ psi))`
    ///
    /// If the two formulas were accidentally identical, the clear-signing bypass
    /// (`test_pczt_ironwood_v3_note_tampered_cmx_rejected`) would not be caught.
    #[cfg(feature = "zcash_unstable")]
    #[test]
    fn note_commitment_v3_differs_from_v2_for_same_inputs() {
        let rho = pallas_base_from_repr(DUMMY_NULLIFIER)
            .expect("DUMMY_NULLIFIER encodes a valid Pallas base field element");
        let g_d = crate::diversify_hash_ledger(&INTERNAL_DIVERSIFIER)
            .expect("INTERNAL_DIVERSIFIER is a valid Orchard diversifier");

        let cmx_v2 = note_commitment(&g_d, &INTERNAL_PK_D, VALUE, &rho, &DUMMY_RSEED)
            .expect("V2 note_commitment must succeed for valid inputs");
        let cmx_v3 = note_commitment_v3(&g_d, &INTERNAL_PK_D, VALUE, &rho, &DUMMY_RSEED)
            .expect("note_commitment_v3 must succeed for valid inputs");

        // The V3 rcm derivation additionally commits to g_d, pk_d, and value, so the
        // two formulas must yield distinct commitments for the same note fields.
        assert_ne!(
            cmx_v2, cmx_v3,
            "note_commitment_v3 must produce a distinct cmx from note_commitment \
             (rcm derivations differ: V2 binds only rseed+rho, V3 also binds g_d+pk_d+value)"
        );
    }

    /// `note_commitment_v3` must be deterministic: identical inputs produce identical output.
    #[cfg(feature = "zcash_unstable")]
    #[test]
    fn note_commitment_v3_is_deterministic() {
        let rho = pallas_base_from_repr(DUMMY_NULLIFIER)
            .expect("DUMMY_NULLIFIER encodes a valid Pallas base field element");
        let g_d = crate::diversify_hash_ledger(&INTERNAL_DIVERSIFIER)
            .expect("INTERNAL_DIVERSIFIER is a valid Orchard diversifier");

        let cmx_first = note_commitment_v3(&g_d, &INTERNAL_PK_D, VALUE, &rho, &DUMMY_RSEED)
            .expect("first call to note_commitment_v3 must succeed");
        let cmx_second = note_commitment_v3(&g_d, &INTERNAL_PK_D, VALUE, &rho, &DUMMY_RSEED)
            .expect("second call to note_commitment_v3 must succeed");

        assert_eq!(
            cmx_first, cmx_second,
            "note_commitment_v3 must be deterministic"
        );
    }
}
