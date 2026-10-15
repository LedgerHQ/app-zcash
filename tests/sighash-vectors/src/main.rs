//! ZIP 244 signature digests of the `fixtures.json` PCZTs under NU7 and NU6.3, computed with
//! `zcash_primitives` independently of the firmware.
//!
//! Run outside the repository so its `.cargo/config.toml` (device `core` rebuild) does not apply:
//!
//! ```sh
//! HOST=$(rustc -vV | awk '/^host:/ {print $2}')
//! cd /tmp && cargo run --manifest-path <repo>/tests/sighash-vectors/Cargo.toml \
//!   --target "$HOST" --target-dir /tmp/sighash-host -- <repo>/tests/sighash-vectors/fixtures.json
//! ```

use std::{env, fs};

use nonempty::NonEmpty;
use orchard::{
    Action, Anchor,
    bundle::{Bundle, BundleVersion, EffectsOnly, Flags},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    primitives::redpallas::{SpendAuth, VerificationKey},
    value::ValueCommitment,
};
use serde::Deserialize;
use transparent::{
    address::Script,
    bundle::{
        Authorization as TransparentAuthorization, Bundle as TransparentBundle, OutPoint, TxIn,
        TxOut,
    },
    sighash::{SighashType, SignableInput as TransparentInput, TransparentAuthorizingContext},
};
use zcash_note_encryption::note_bytes::NoteBytesData;
use zcash_primitives::transaction::{
    Authorization, TransactionData,
    sighash::{SignableInput, signature_hash},
    txid::TxIdDigester,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::{ZatBalance, Zatoshis},
};

#[derive(Deserialize)]
struct Fixture {
    transparent_inputs: Vec<InputFields>,
    transparent_outputs: Vec<OutputFields>,
    ironwood: Option<BundleFields>,
}

#[derive(Deserialize)]
struct InputFields {
    txid: String,
    index: u32,
    value: u64,
    script: String,
    sequence: u32,
}

#[derive(Deserialize)]
struct OutputFields {
    value: u64,
    script: String,
}

#[derive(Deserialize)]
struct BundleFields {
    flags: u8,
    value_balance: i64,
    anchor: String,
    actions: Vec<ActionFields>,
}

#[derive(Deserialize)]
struct ActionFields {
    cv_net: String,
    nullifier: String,
    rk: String,
    cmx: String,
    ephemeral_key: String,
    enc_ciphertext: String,
    out_ciphertext: String,
}

/// Outputs spent by the transparent inputs, which the transparent digest commits to.
#[derive(Debug)]
struct SpentOutputs(Vec<TxOut>);

impl TransparentAuthorization for SpentOutputs {
    type ScriptSig = ();
}

impl TransparentAuthorizingContext for SpentOutputs {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.0.iter().map(|output| output.value()).collect()
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.0.iter().map(|output| output.script_pubkey().clone()).collect()
    }
}

/// Effects only: proofs and signatures enter neither the txid nor the signature digest.
struct Unsigned;

impl Authorization for Unsigned {
    type TransparentAuth = SpentOutputs;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = EffectsOnly;
}

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn script(hex: &str) -> Script {
    let code = hex::decode(hex).unwrap();
    let mut encoded = vec![u8::try_from(code.len()).unwrap()];
    encoded.extend(code);
    Script::read(&encoded[..]).unwrap()
}

fn ironwood_bundle(fields: &BundleFields) -> Bundle<EffectsOnly, ZatBalance> {
    let version = BundleVersion::ironwood_v3();
    let actions: Vec<_> = fields
        .actions
        .iter()
        .map(|action| {
            Action::from_parts(
                Nullifier::from_bytes(&bytes(&action.nullifier)).unwrap(),
                VerificationKey::<SpendAuth>::try_from(bytes::<32>(&action.rk)).unwrap(),
                ExtractedNoteCommitment::from_bytes(&bytes(&action.cmx)).unwrap(),
                TransmittedNoteCiphertext {
                    epk_bytes: bytes(&action.ephemeral_key),
                    enc_ciphertext: NoteBytesData(bytes(&action.enc_ciphertext)),
                    out_ciphertext: bytes(&action.out_ciphertext),
                },
                ValueCommitment::from_bytes(&bytes(&action.cv_net)).unwrap(),
                (),
            )
            .unwrap()
        })
        .collect();
    Bundle::from_parts(
        NonEmpty::from_vec(actions).unwrap(),
        Flags::from_byte(fields.flags, version).unwrap(),
        ZatBalance::from_i64(fields.value_balance).unwrap(),
        Anchor::from_bytes(bytes(&fields.anchor)).unwrap(),
        EffectsOnly,
        version,
    )
    .unwrap()
}

fn transaction(fixture: &Fixture, branch: BranchId) -> TransactionData<Unsigned> {
    let vin = fixture
        .transparent_inputs
        .iter()
        .map(|input| TxIn::from_parts(OutPoint::new(bytes(&input.txid), input.index), (), input.sequence))
        .collect::<Vec<_>>();
    let spent = fixture
        .transparent_inputs
        .iter()
        .map(|input| TxOut::new(Zatoshis::from_u64(input.value).unwrap(), script(&input.script)))
        .collect();
    let vout = fixture
        .transparent_outputs
        .iter()
        .map(|output| TxOut::new(Zatoshis::from_u64(output.value).unwrap(), script(&output.script)))
        .collect::<Vec<_>>();
    let transparent = (!vin.is_empty() || !vout.is_empty())
        .then(|| TransparentBundle { vin, vout, authorization: SpentOutputs(spent) });

    TransactionData::from_parts_v6(
        branch,
        0,
        BlockHeight::from_u32(0),
        transparent,
        None,
        None,
        fixture.ironwood.as_ref().map(ironwood_bundle),
    )
}

fn shielded_sighash(tx: &TransactionData<Unsigned>) -> [u8; 32] {
    *signature_hash(tx, &SignableInput::Shielded, &tx.digest(TxIdDigester)).as_ref()
}

fn transparent_sighash(tx: &TransactionData<Unsigned>, fixture: &Fixture) -> [u8; 32] {
    let first = &fixture.transparent_inputs[0];
    let script_pubkey = script(&first.script);
    let input = TransparentInput::from_parts(
        tx.transparent_bundle().unwrap(),
        SighashType::ALL,
        0,
        &script_pubkey,
        &script_pubkey,
        Zatoshis::from_u64(first.value).unwrap(),
    )
    .unwrap();
    *signature_hash(tx, &SignableInput::Transparent(input), &tx.digest(TxIdDigester)).as_ref()
}

fn main() {
    let path = env::args().nth(1).expect("path to fixtures.json");
    let fixtures: std::collections::BTreeMap<String, Fixture> =
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();

    for (branch_name, branch) in [("NU7", BranchId::Nu7), ("NU6_3", BranchId::Nu6_3)] {
        let payment = &fixtures["ironwood_payment"];
        println!(
            "_{branch_name}_IRONWOOD_PAYMENT_SIGHASH = bytes.fromhex(\"{}\")",
            hex::encode(shielded_sighash(&transaction(payment, branch)))
        );
        let transparent_only = &fixtures["transparent_only"];
        println!(
            "_{branch_name}_TRANSPARENT_ONLY_SIGHASH = bytes.fromhex(\"{}\")",
            hex::encode(transparent_sighash(&transaction(transparent_only, branch), transparent_only))
        );
    }
}
