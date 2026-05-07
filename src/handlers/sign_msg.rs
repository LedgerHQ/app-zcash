use ledger_device_sdk::io::Comm;
use ledger_device_sdk::{
    ecc::{Secp256k1, SeedDerive as _},
    hash::{HashInit as _, sha2::Sha2_256},
    log::error,
};

use crate::{
    AppSW,
    tx::TxContext,
    utils::{Bip44CheckMode, check_bip44_compliance, bip32_path::Bip32Path},
};

const SIGN_MESSAGE_PREFIX: &[u8] = b"Zcash Signed Message:\n";

pub fn handler_sign_msg(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    next: bool,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if first {
        if data.is_empty() {
            return finalize_signature(comm, ctx);
        }
        let is_complete = parse_first_chunk_and_hash(ctx, data)?;
        comm.append(&[0x00]);
        if is_complete {
            comm.append(&[0x00]);
        }
        return Ok(());
    }

    if next {
        let is_complete = hash_message_chunk(ctx, data)?;
        comm.append(&[0x00]);
        if is_complete {
            comm.append(&[0x00]);
        }
        Ok(())
    } else {
        Err(AppSW::WrongP1P2)
    }
}

fn reset_signing_session(ctx: &mut TxContext) {
    ctx.message_signing = Default::default();
}

fn parse_first_chunk_and_hash(ctx: &mut TxContext, data: &[u8]) -> Result<bool, AppSW> {
    if data.is_empty() {
        return Err(AppSW::WrongApduLength);
    }

    let path_len = data[0] as usize;
    let path_byte_len = path_len
        .checked_mul(4)
        .and_then(|len| len.checked_add(1))
        .ok_or(AppSW::WrongApduLength)?;

    let message_len_offset = path_byte_len;
    let first_chunk_offset = message_len_offset
        .checked_add(2)
        .ok_or(AppSW::WrongApduLength)?;

    if data.len() < first_chunk_offset {
        return Err(AppSW::WrongApduLength);
    }

    let path: Bip32Path = data[..path_byte_len].try_into()?;
    if !check_bip44_compliance(&path, Bip44CheckMode::OnlyCoinType) {
        error!("Sign message path not Bip44 compliant");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    let message_len =
        u16::from_be_bytes([data[message_len_offset], data[message_len_offset + 1]]);
    if message_len == 0 {
        error!("Message length cannot be zero");
        return Err(AppSW::IncorrectData);
    }

    reset_signing_session(ctx);
    ctx.message_signing.message_len = message_len;
    ctx.message_signing.key_path = Some(path);
    ctx.message_signing.hash_full = Sha2_256::new();

    let prefix_len = SIGN_MESSAGE_PREFIX.len() as u8;
    ctx.message_signing
        .hash_full
        .update(&[prefix_len])
        .map_err(|_| AppSW::TechnicalProblem)?;
    ctx.message_signing
        .hash_full
        .update(SIGN_MESSAGE_PREFIX)
        .map_err(|_| AppSW::TechnicalProblem)?;

    let (compact_len, compact_len_size) = encode_compact_size_u16(message_len);
    ctx.message_signing
        .hash_full
        .update(&compact_len[..compact_len_size])
        .map_err(|_| AppSW::TechnicalProblem)?;

    hash_message_chunk(ctx, &data[first_chunk_offset..])
}

fn encode_compact_size_u16(value: u16) -> ([u8; 3], usize) {
    if value < 0xFD {
        ([value as u8, 0, 0], 1)
    } else {
        ([0xFD, (value & 0x00FF) as u8, (value >> 8) as u8], 3)
    }
}

fn hash_message_chunk(ctx: &mut TxContext, chunk: &[u8]) -> Result<bool, AppSW> {
    if ctx.message_signing.message_len == 0 {
        error!("No sign message session initialized");
        return Err(AppSW::IncorrectData);
    }

    let chunk_len: u16 = chunk.len().try_into().map_err(|_| AppSW::IncorrectData)?;
    let new_hashed_len = ctx
        .message_signing
        .hashed_len
        .checked_add(chunk_len)
        .ok_or(AppSW::IncorrectData)?;

    if new_hashed_len > ctx.message_signing.message_len {
        reset_signing_session(ctx);
        error!("Message chunk exceeds declared message length");
        return Err(AppSW::IncorrectData);
    }

    ctx.message_signing
        .hash_full
        .update(chunk)
        .map_err(|_| AppSW::TechnicalProblem)?;
    ctx.message_signing.hashed_len = new_hashed_len;

    Ok(ctx.message_signing.hashed_len == ctx.message_signing.message_len)
}

fn finalize_signature(comm: &mut Comm, ctx: &mut TxContext) -> Result<(), AppSW> {
    if ctx.message_signing.message_len == 0
        || ctx.message_signing.hashed_len != ctx.message_signing.message_len
    {
        error!("Cannot sign: message is not fully received");
        reset_signing_session(ctx);
        return Err(AppSW::IncorrectData);
    }

    let path = ctx.message_signing.key_path.ok_or(AppSW::BadState)?;

    let mut first_hash = [0u8; 32];
    ctx.message_signing
        .hash_full
        .finalize(&mut first_hash)
        .map_err(|_| AppSW::TechnicalProblem)?;

    let mut second_hash = [0u8; 32];
    let mut second_round = Sha2_256::new();
    second_round
        .hash(&first_hash, &mut second_hash)
        .map_err(|_| AppSW::TechnicalProblem)?;

    let (private_key, _chain_code) = Secp256k1::derive_from(path.as_slice());
    let (mut sig, sig_len, info) = private_key
        .deterministic_sign(&second_hash)
        .map_err(|_| AppSW::TechnicalProblem)?;

    if info != 0 {
        sig[0] |= 0x01;
    }

    comm.append(&sig[..sig_len as usize]);
    reset_signing_session(ctx);

    Ok(())
}
