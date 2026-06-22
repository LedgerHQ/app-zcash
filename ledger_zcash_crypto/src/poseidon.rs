use ff::{Field, PrimeField};
use pasta_curves::pallas;

// Mirrors Orchard's PRF^nfOrchard(nk, rho) implementation:
// vendor/orchard/src/spec.rs uses
// halo2_poseidon::Hash<_, P128Pow5T3, ConstantLength<2>, 3, 2>.
// The final generic parameters are width T = 3 and rate = 2; see
// halo2_poseidon-0.1.0/src/lib.rs `Hash<F, S, D, T, RATE>`.
const P128POW5T3_WIDTH: usize = 3;
const P128POW5T3_RATE: usize = 2;
const P128POW5T3_INPUT_LEN: usize = 2;
const P128POW5T3_OUTPUT_INDEX: usize = 0;
const P128POW5T3_PARTIAL_SBOX_INDEX: usize = 0;
const P128POW5T3_CAPACITY_INDEX: usize = P128POW5T3_RATE;

// P128Pow5T3 is Poseidon-128 over the Pasta fields with the x^5 S-box,
// R_F = 8 full rounds and R_P = 56 partial rounds. These values come from
// halo2_poseidon-0.1.0/src/p128pow5t3.rs `impl Spec<Fp, 3, 2> for P128Pow5T3`.
const P128POW5T3_FULL_ROUNDS: usize = 8;
const P128POW5T3_PARTIAL_ROUNDS: usize = 56;
const P128POW5T3_HALF_FULL_ROUNDS: usize = P128POW5T3_FULL_ROUNDS / 2;
const P128POW5T3_TOTAL_ROUNDS: usize = P128POW5T3_FULL_ROUNDS + P128POW5T3_PARTIAL_ROUNDS;
const P128POW5T3_PARTIAL_ROUNDS_END: usize =
    P128POW5T3_HALF_FULL_ROUNDS + P128POW5T3_PARTIAL_ROUNDS;
const P128POW5T3_SBOX_EXPONENT: u64 = 5;

// halo2_poseidon::ConstantLength<L> encodes the input length into the capacity
// element as L * 2^64 + (output_len - 1); see
// halo2_poseidon-0.1.0/src/lib.rs `ConstantLength::initial_capacity_element`.
// Orchard's PRF^nfOrchard uses ConstantLength<2> and outputs one field element,
// so output_len - 1 is zero.
const P128POW5T3_OUTPUT_LEN: u128 = 1;
const P128POW5T3_CAPACITY_TAG: u128 =
    (P128POW5T3_INPUT_LEN as u128) << 64 | (P128POW5T3_OUTPUT_LEN - 1);

type PoseidonState = [pallas::Base; P128POW5T3_WIDTH];
type PoseidonRoundConstants = [pallas::Base; P128POW5T3_WIDTH];

pub(crate) fn p128pow5t3_hash_len2(first: pallas::Base, second: pallas::Base) -> pallas::Base {
    let mut state = [pallas::Base::ZERO; P128POW5T3_WIDTH];
    state[..P128POW5T3_INPUT_LEN].copy_from_slice(&[first, second]);
    state[P128POW5T3_CAPACITY_INDEX] = pallas::Base::from_u128(P128POW5T3_CAPACITY_TAG);
    p128pow5t3_permute(&mut state);
    state[P128POW5T3_OUTPUT_INDEX]
}

fn p128pow5t3_permute(state: &mut PoseidonState) {
    let mut round = 0;
    while round < P128POW5T3_HALF_FULL_ROUNDS {
        full_round(state, &crate::poseidon_fp::ROUND_CONSTANTS[round]);
        round += 1;
    }

    while round < P128POW5T3_PARTIAL_ROUNDS_END {
        partial_round(state, &crate::poseidon_fp::ROUND_CONSTANTS[round]);
        round += 1;
    }

    while round < P128POW5T3_TOTAL_ROUNDS {
        full_round(state, &crate::poseidon_fp::ROUND_CONSTANTS[round]);
        round += 1;
    }
}

fn full_round(state: &mut PoseidonState, round_constants: &PoseidonRoundConstants) {
    for i in 0..P128POW5T3_WIDTH {
        state[i] = pow5(state[i] + round_constants[i]);
    }
    apply_mds(state);
}

fn partial_round(state: &mut PoseidonState, round_constants: &PoseidonRoundConstants) {
    for i in 0..P128POW5T3_WIDTH {
        state[i] += round_constants[i];
    }
    state[P128POW5T3_PARTIAL_SBOX_INDEX] = pow5(state[P128POW5T3_PARTIAL_SBOX_INDEX]);
    apply_mds(state);
}

fn pow5(value: pallas::Base) -> pallas::Base {
    value.pow_vartime([P128POW5T3_SBOX_EXPONENT])
}

fn apply_mds(state: &mut PoseidonState) {
    let input = *state;
    for (row, output) in crate::poseidon_fp::MDS.iter().zip(state.iter_mut()) {
        let mut value = pallas::Base::ZERO;
        for (coefficient, input) in row.iter().zip(input.iter()) {
            value += *coefficient * *input;
        }
        *output = value;
    }
}
