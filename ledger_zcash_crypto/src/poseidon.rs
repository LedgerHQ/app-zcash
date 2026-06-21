use ff::{Field, PrimeField};
use pasta_curves::pallas;

pub(crate) fn p128pow5t3_hash_len2(first: pallas::Base, second: pallas::Base) -> pallas::Base {
    let mut state = [first, second, pallas::Base::from_u128(2u128 << 64)];
    p128pow5t3_permute(&mut state);
    state[0]
}

fn p128pow5t3_permute(state: &mut [pallas::Base; 3]) {
    let mut round = 0;
    while round < 4 {
        full_round(state, &crate::poseidon_fp::ROUND_CONSTANTS[round]);
        round += 1;
    }

    while round < 60 {
        partial_round(state, &crate::poseidon_fp::ROUND_CONSTANTS[round]);
        round += 1;
    }

    while round < 64 {
        full_round(state, &crate::poseidon_fp::ROUND_CONSTANTS[round]);
        round += 1;
    }
}

fn full_round(state: &mut [pallas::Base; 3], round_constants: &[pallas::Base; 3]) {
    for i in 0..3 {
        state[i] = pow5(state[i] + round_constants[i]);
    }
    apply_mds(state);
}

fn partial_round(state: &mut [pallas::Base; 3], round_constants: &[pallas::Base; 3]) {
    for i in 0..3 {
        state[i] += round_constants[i];
    }
    state[0] = pow5(state[0]);
    apply_mds(state);
}

fn pow5(value: pallas::Base) -> pallas::Base {
    value.pow_vartime([5])
}

fn apply_mds(state: &mut [pallas::Base; 3]) {
    let input = *state;
    for (row, output) in crate::poseidon_fp::MDS.iter().zip(state.iter_mut()) {
        *output = row[0] * input[0] + row[1] * input[1] + row[2] * input[2];
    }
}
