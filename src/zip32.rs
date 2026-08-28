use orchard::keys::SpendingKey as OrchardSk;
use zcash_protocol::consensus::NetworkType;

use ledger_device_sdk::ecc::Pallas;
use ledger_device_sdk::ecc::Secret;
use ledger_device_sdk::log::error;

use crate::utils::extended_public_key::ExtendedPublicKey;
use crate::{AppSW, utils::bip32_path::Bip32Path};

pub use orchard::keys::FullViewingKey as OrchardFvk;
pub use orchard::keys::SpendAuthorizingKey as OrchardAsk;

pub fn map_ledger_crypto_error(err: ledger_zcash_crypto::Error) -> AppSW {
    match err {
        ledger_zcash_crypto::Error::InvalidKeyDiscarded => AppSW::Deny,
        ledger_zcash_crypto::Error::OutOfMemory => AppSW::NotEnoughMemorySpace,
        _ => AppSW::TechnicalProblem,
    }
}

pub fn orchard_network(path: &Bip32Path) -> NetworkType {
    // m_Orchard / 32' / 1' / account'
    if let Some(coin_type) = path.as_slice().get(1)
        && *coin_type == 1 + 0x8000_0000
    {
        return NetworkType::Test;
    }
    NetworkType::Main
}

// Derives the Orchard FullViewingKey bytes for the given coin type and account.
pub fn derive_orchard_fvk_bytes(sk: Secret<32>) -> Result<OrchardFvk, AppSW> {
    let sk = OrchardSk::ledger_from_bytes(sk.as_ref().try_into().unwrap())
        .map_err(map_ledger_crypto_error)?;

    OrchardFvk::ledger_try_from(&sk).map_err(map_ledger_crypto_error)
}

// Derives the transparent account public key bytes for the BIP44 path
// `m/44'/<coin_type>'/<account>'`.
//
// Returns 65 bytes: [chain_code (32 bytes) | compressed_pubkey (33 bytes)]
pub fn derive_transparent_account_pubkey(path: &Bip32Path) -> Result<[u8; 65], AppSW> {
    let extended_public_key = ExtendedPublicKey::try_from(path)?;
    let compressed_public_key = extended_public_key.compressed_public_key()?;

    let mut result = [0u8; 65];
    result[..32].copy_from_slice(&extended_public_key.chain_code);
    result[32..].copy_from_slice(&compressed_public_key);

    Ok(result)
}

// `zip32_orchard_derive` is a Secure-Element key-derivation syscall whose
// internal resources are not fully reclaimed between successive calls within a
// power cycle; a handful of consecutive calls exhausts them and the next call
// fails with a CxError surfaced as `TechnicalProblem` (6f00). The account
// Orchard spending key is invariant across every action of a transaction, so
// it must be derived at most once and reused — see `PcztParser`, which caches
// the result and passes it to the `*_from_sk` helpers below. This function is
// the single derivation site; do not call it per action.
pub fn derive_orchard_sk_bytes(path: &Bip32Path) -> Result<Secret<32>, AppSW> {
    consume_orchard_derivation_budget()?;

    let path_slice = path.as_slice();

    // `None` for the chain code: nothing here uses it, and asking for it made the Secure Element
    // write a secret into a plain stack buffer that no `Drop` reaches — the syscall answers a `None`
    // with a null pointer and a zero length, so the value is never materialized rather than
    // materialized and wiped.
    let sk = Pallas::zip32_orchard_derive(path_slice, None, None)
        .map_err(|_| AppSW::TechnicalProblem)?;

    Ok(sk)
}

/// Ceiling on the Orchard derivations one run of the app may request.
///
/// The address and viewing-key endpoints derive before any display, and their no-display form takes
/// no user action at all, so a host alone decides how many times the syscall above runs. Left
/// uncounted, it drains the resources the Secure Element does not reclaim until the next power
/// cycle, and every later derivation — including the ones a transaction needs — comes back as a
/// technical error.
///
/// Fifty is set against observed use rather than against the Secure Element's own threshold, which
/// is undocumented: a Ledger Live sync derives none, and the heaviest session measured stays around
/// fifteen. Should the real threshold prove lower, this bounds the drain and names it instead of
/// preventing it — which is still the difference between a diagnosable refusal and an app that
/// fails everywhere afterwards for no stated reason.
const MAX_ORCHARD_DERIVATIONS: u32 = 50;

/// Reset by the app exiting, not by this code: the count is deliberately not clearable from the
/// wire, or a host would clear it between requests.
static mut ORCHARD_DERIVATIONS: u32 = 0;

fn consume_orchard_derivation_budget() -> Result<(), AppSW> {
    // SAFETY: the app is single-threaded and this is its only accessor.
    let spent = unsafe {
        ORCHARD_DERIVATIONS = ORCHARD_DERIVATIONS.saturating_add(1);
        ORCHARD_DERIVATIONS
    };

    if spent > MAX_ORCHARD_DERIVATIONS {
        error!("Orchard derivation budget exhausted: {}", spent);
        // Deliberately not the technical error the exhausted syscall itself returns: a caller that
        // hits the ceiling should be able to tell a spent budget, which a restart clears, from a
        // derivation that genuinely failed.
        return Err(AppSW::NotEnoughMemorySpace);
    }

    Ok(())
}

// Builds an `OrchardSk` from already-derived key bytes, WITHOUT invoking
// `zip32_orchard_derive`. Used with a key cached by the PCZT parser.
fn orchard_sk_from_bytes(sk_bytes: &Secret<32>) -> Result<OrchardSk, AppSW> {
    OrchardSk::ledger_from_bytes(sk_bytes.as_ref().try_into().unwrap())
        .map_err(map_ledger_crypto_error)
}

pub fn derive_orchard_fvk(path: &Bip32Path) -> Result<OrchardFvk, AppSW> {
    let sk = derive_orchard_sk_bytes(path)?;
    let orchard_fvk = derive_orchard_fvk_bytes(sk)?;

    Ok(orchard_fvk)
}

// FVK derivation from a cached spending key (no `zip32_orchard_derive`).
pub fn derive_orchard_fvk_from_sk(sk_bytes: &Secret<32>) -> Result<OrchardFvk, AppSW> {
    let sk = orchard_sk_from_bytes(sk_bytes)?;
    let fvk = OrchardFvk::ledger_try_from(&sk).map_err(map_ledger_crypto_error)?;
    Ok(fvk)
}

// FVK + ASK derivation from a cached spending key (no `zip32_orchard_derive`).
pub fn derive_orchard_fvk_and_ask_from_sk(
    sk_bytes: &Secret<32>,
) -> Result<(OrchardFvk, OrchardAsk), AppSW> {
    let sk = orchard_sk_from_bytes(sk_bytes)?;
    let fvk = OrchardFvk::ledger_try_from(&sk).map_err(map_ledger_crypto_error)?;
    let ask = OrchardAsk::ledger_try_from(&sk).map_err(map_ledger_crypto_error)?;
    Ok((fvk, ask))
}

// ASK derivation from a cached spending key (no `zip32_orchard_derive`).
pub fn derive_orchard_ask_from_sk(sk_bytes: &Secret<32>) -> Result<OrchardAsk, AppSW> {
    let sk = orchard_sk_from_bytes(sk_bytes)?;
    OrchardAsk::ledger_try_from(&sk).map_err(map_ledger_crypto_error)
}
