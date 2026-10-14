//! Prints `tests/testnet/testnet_vectors.py`'s reference values for account 0 of the Speculos
//! default seed.
//!
//! Usage: `ledger-testnet-vectors [coin_type]`, coin type 1 by default. Run with 133, it prints the
//! mainnet values of the same derivations, which `tests/standalone` pins independently: that is
//! what ties this generator to the device's derivation.
//!
//! The Orchard action is the standalone single-spend fixture's: one note of 300000 zats spent from
//! the external address, one zero-value output to the internal address, alpha 1. Its anchor is not
//! derived here: the device cannot relate an anchor to a note, so the testnet vectors reuse the
//! standalone fixture's value as is.

use orchard::keys::{FullViewingKey, Scope, SpendValidatingKey, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho};
use orchard::value::{NoteValue, ValueCommitTrapdoor, ValueCommitment};
use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;
use transparent::keys::AccountPrivKey;
use zcash_address::unified::{Address, Encoding, Fvk, Receiver, Revision, Ufvk, Uitem};
use zcash_protocol::consensus::{MAIN_NETWORK, NetworkType, TEST_NETWORK};
use zip32::AccountId;

const SPECULOS_DEFAULT_MNEMONIC: &str = "glory promote mansion idle axis finger extra february uncover one trip \
     resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin";

const SPEND_VALUE: u64 = 300_000;

/// A 32-byte field whose first byte is `first` and every other byte zero, the fixture's shape.
fn leading(first: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0] = first;
    bytes
}

/// BIP-39 seed of a mnemonic with an empty passphrase.
fn bip39_seed(mnemonic: &str) -> [u8; 64] {
    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(mnemonic.as_bytes(), b"mnemonic", 2048, &mut seed);
    seed
}

fn py_bytes(name: &str, bytes: &[u8]) {
    println!("{name} = bytes.fromhex(\"{}\")", hex::encode(bytes));
}

fn main() {
    let coin_type: u32 = std::env::args()
        .nth(1)
        .map(|arg| arg.parse().expect("coin type must be an integer"))
        .unwrap_or(1);
    let network = match coin_type {
        1 => NetworkType::Test,
        133 => NetworkType::Main,
        _ => panic!("coin type must be 1 or 133"),
    };

    let seed = bip39_seed(SPECULOS_DEFAULT_MNEMONIC);
    let sk = SpendingKey::from_zip32_seed(&seed, coin_type, AccountId::ZERO)
        .expect("account 0 derives");
    let fvk = FullViewingKey::from(&sk);
    let external = fvk.address_at(0u32, Scope::External);
    let internal = fvk.address_at(0u32, Scope::Internal);

    let account_pubkey = match network {
        NetworkType::Test => AccountPrivKey::from_seed(&TEST_NETWORK, &seed, AccountId::ZERO),
        _ => AccountPrivKey::from_seed(&MAIN_NETWORK, &seed, AccountId::ZERO),
    }
    .expect("transparent account 0 derives")
    .to_account_pubkey()
    .serialize();
    let ufvk = Ufvk::try_from_items(
        Revision::R0,
        vec![
            Uitem::Data(Fvk::Orchard(fvk.to_bytes())),
            Uitem::Data(Fvk::P2pkh(
                account_pubkey.try_into().expect("an account public key is 65 bytes"),
            )),
        ],
    )
    .expect("valid UFVK items");
    let uaddress = Address::try_from_items(
        Revision::R0,
        vec![Uitem::Data(Receiver::Orchard(external.to_raw_address_bytes()))],
    )
    .expect("valid unified address items");

    println!("UFVK_ACCOUNT_0 = \"{}\"", ufvk.encode(&network));
    println!("UADDRESS_ACCOUNT_0 = \"{}\"", uaddress.encode(&network));
    py_bytes("ORCHARD_RAW_ADDRESS_ACCOUNT_0", &external.to_raw_address_bytes());
    py_bytes("ORCHARD_INTERNAL_RECIPIENT_ACCOUNT_0", &internal.to_raw_address_bytes());
    py_bytes("ORCHARD_FVK_ACCOUNT_0", &fvk.to_bytes());

    // The spent note, to the external address.
    let spend_rho = Rho::from_bytes(&leading(0x06)).expect("canonical rho");
    let spend_rseed = RandomSeed::from_bytes(leading(0x1a), &spend_rho).expect("valid rseed");
    let spent = Note::from_parts(external, NoteValue::from_raw(SPEND_VALUE), spend_rho, spend_rseed, NoteVersion::V2)
        .expect("valid note");
    let nullifier = spent.nullifier(&fvk);

    // The zero-value output to the internal address, its rho the spend's nullifier.
    let output_rho = Rho::from_bytes(&nullifier.to_bytes()).expect("a nullifier is a canonical rho");
    let output_rseed = RandomSeed::from_bytes(leading(0x2e), &output_rho).expect("valid rseed");
    let output = Note::from_parts(internal, NoteValue::from_raw(0), output_rho, output_rseed, NoteVersion::V2)
        .expect("valid note");
    let cmx = ExtractedNoteCommitment::from(output.commitment());

    let rcv = ValueCommitTrapdoor::from_bytes(leading(0x42)).expect("canonical rcv");
    let value_balance = NoteValue::from_raw(SPEND_VALUE) - NoteValue::from_raw(0);
    let cv_net = ValueCommitment::derive(value_balance, rcv);

    let alpha = pallas::Scalar::from_repr(leading(0x01)).expect("canonical alpha");
    let rk: [u8; 32] = (&SpendValidatingKey::from(fvk.clone()).randomize(&alpha)).into();

    println!();
    py_bytes("ORCHARD_NULLIFIER", &nullifier.to_bytes());
    py_bytes("ORCHARD_CMX", &cmx.to_bytes());
    py_bytes("ORCHARD_CV_NET", &cv_net.to_bytes());
    py_bytes("ORCHARD_RK_ALPHA_1", &rk);
}
