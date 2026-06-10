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

use crate::{
    Error, ORCHARD_ESK_DOMAIN_SEPARATOR, ORCHARD_PSI_DOMAIN_SEPARATOR,
    ORCHARD_RCM_DOMAIN_SEPARATOR, PRF_EXPAND_BYTES, bytes::reverse_copy, pallas_base_from_repr,
    pallas_point_from_bytes, pallas_point_to_bytes, pallas_scalar_from_repr,
    prf_expand_with_domain_separator_and_inputs, sinsemilla::sinsemilla_short_commit,
    to_pallas_base_bytes, to_pallas_scalar_bytes,
};

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

#[derive(Clone, Copy, Debug)]
pub struct DecipheredOrchardOutput {
    pub value: u64,
    pub raw_address: [u8; ORCHARD_RAW_ADDRESS_SIZE],
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

    parse_and_validate_note_plaintext(
        &action.compact,
        &note_plaintext_prefix,
        &pk_d,
        Some(&esk),
        &rho,
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

    parse_and_validate_note_plaintext(compact, &note_plaintext_prefix, &pk_d, None, &rho)
}

fn parse_and_validate_note_plaintext(
    compact: &OrchardCompactAction,
    plaintext: &[u8; ORCHARD_NOTE_PLAINTEXT_PREFIX_SIZE],
    pk_d: &[u8; HASH_SIZE],
    expected_esk: Option<&[u8; HASH_SIZE]>,
    rho: &pallas::Base,
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

    let cmx = note_commitment(&g_d, pk_d, note_plaintext.value, rho, &note_plaintext.rseed)?;
    if !bytes_eq(&cmx, &compact.cmx) {
        return Ok(None);
    }

    let mut raw_address = [0u8; ORCHARD_RAW_ADDRESS_SIZE];
    raw_address[..DIVERSIFIER_SIZE].copy_from_slice(&note_plaintext.diversifier);
    raw_address[DIVERSIFIER_SIZE..].copy_from_slice(pk_d);

    Ok(Some(DecipheredOrchardOutput {
        value: note_plaintext.value,
        raw_address,
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
    if plaintext[0] != 0x02 {
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
