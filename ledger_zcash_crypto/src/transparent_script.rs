use ledger_device_sdk::log::debug;

// The parsers hand over a bare script body, so the OP_RETURN opcode is its first byte.
const OP_RETURN_OPCODE_INDEX: usize = 0;
const OP_RETURN_OPCODE: u8 = 0x6A;
const OP_PUSHDATA1: u8 = 0x4C;
// The largest direct push opcode: it pushes the 75 bytes that follow it.
const OP_PUSH_MAX_DIRECT: u8 = 0x4B;
/// The largest OP_RETURN script the network relays: zcashd's `MAX_OP_RETURN_RELAY`, which Zebra's
/// `DEFAULT_MAX_DATACARRIER_BYTES` matches. OP_RETURN, OP_PUSHDATA1 and its length byte leave 80
/// bytes of data.
pub const MAX_OP_RETURN_SCRIPT_LEN: usize = 83;
const REGULAR_OUTPUT_SCRIPT_LEN: usize = 25;
const REGULAR_OUTPUT_PREFIX: [u8; 3] = [0x76, 0xA9, 0x14];
const REGULAR_OUTPUT_POSTFIX: [u8; 2] = [0x88, 0xAC];
// A P2SH scriptPubKey is exactly `OP_HASH160 <20-byte push> <hash160> OP_EQUAL`.
const P2SH_OUTPUT_SCRIPT_LEN: usize = 23;
const P2SH_OUTPUT_PREFIX: [u8; 2] = [0xA9, 0x14];
const P2SH_OUTPUT_POSTFIX: u8 = 0x87;
const TRANSPARENT_ADDRESS_OFFSET: usize = 3;
const TRANSPARENT_ADDRESS_HASH_LEN: usize = 20;

pub fn output_script_is_op_return(script_pubkey: &[u8]) -> bool {
    if script_pubkey.is_empty() {
        return false;
    }

    script_pubkey[OP_RETURN_OPCODE_INDEX] == OP_RETURN_OPCODE
}

/// Where the data of an OP_RETURN script starts, if the script is exactly OP_RETURN followed by
/// one push of at least one byte, within the relay limit.
///
/// The data runs to the end of the script, so what the review shows is everything the output
/// carries: a second push, a non-push opcode or bytes past the declared length are refused rather
/// than left off the screen.
pub fn op_return_data_offset(script_pubkey: &[u8]) -> Option<usize> {
    if script_pubkey.len() > MAX_OP_RETURN_SCRIPT_LEN || !output_script_is_op_return(script_pubkey)
    {
        return None;
    }

    let (data_offset, data_len) = match *script_pubkey.get(1)? {
        len @ 1..=OP_PUSH_MAX_DIRECT => (2, usize::from(len)),
        OP_PUSHDATA1 => (3, usize::from(*script_pubkey.get(2)?)),
        _ => return None,
    };

    if data_len == 0 || script_pubkey.len() != data_offset + data_len {
        return None;
    }

    Some(data_offset)
}

pub fn output_script_is_regular(script_pubkey: &[u8]) -> bool {
    if script_pubkey.len() != REGULAR_OUTPUT_SCRIPT_LEN {
        return false;
    }

    if script_pubkey[..REGULAR_OUTPUT_PREFIX.len()] != REGULAR_OUTPUT_PREFIX {
        return false;
    }

    if script_pubkey[script_pubkey.len() - REGULAR_OUTPUT_POSTFIX.len()..] != REGULAR_OUTPUT_POSTFIX
    {
        return false;
    }

    true
}

pub fn output_script_is_p2sh(script_pubkey: &[u8]) -> bool {
    if script_pubkey.len() != P2SH_OUTPUT_SCRIPT_LEN {
        return false;
    }

    if script_pubkey[..P2SH_OUTPUT_PREFIX.len()] != P2SH_OUTPUT_PREFIX {
        return false;
    }

    script_pubkey[script_pubkey.len() - 1] == P2SH_OUTPUT_POSTFIX
}

#[derive(PartialEq, Debug)]
pub enum CheckDispOutput {
    None,
    Displayable,
    Change,
    /// A zero-value OP_RETURN carrying one push of data, which starts at `data_offset`.
    OpReturn {
        data_offset: usize,
    },
}

pub fn check_output_displayable(
    script_pubkey: &[u8],
    amount: u64,
    change_address: Option<&[u8; 20]>,
) -> CheckDispOutput {
    debug!("Check output displayable");
    debug!("ScriptPubKey: {:02X?}", script_pubkey);

    if script_pubkey.is_empty() {
        return CheckDispOutput::None;
    }

    // An OP_RETURN output is unspendable: any value it carries is burned, so only a zero-value
    // one is accepted, and only in the single-push form whose data the review can show in full.
    if output_script_is_op_return(script_pubkey) {
        return match op_return_data_offset(script_pubkey) {
            Some(data_offset) if amount == 0 => CheckDispOutput::OpReturn { data_offset },
            _ => CheckDispOutput::None,
        };
    }

    if amount == 0 {
        return CheckDispOutput::None;
    }

    if output_script_is_p2sh(script_pubkey) {
        return CheckDispOutput::Displayable;
    }

    // Otherwise it's only displayable if it's actually P2PKH-shaped, not just
    // long enough to look like one.
    if !output_script_is_regular(script_pubkey) {
        return CheckDispOutput::None;
    }

    if change_address.is_some_and(|change_address| {
        &script_pubkey[TRANSPARENT_ADDRESS_OFFSET..][..TRANSPARENT_ADDRESS_HASH_LEN]
            == change_address
    }) {
        debug!("Change output detected");
        return CheckDispOutput::Change;
    }

    debug!("Displayable output detected");
    CheckDispOutput::Displayable
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_device_sdk::testing::TestType;

    fn p2sh_script(hash: &[u8; 20]) -> [u8; P2SH_OUTPUT_SCRIPT_LEN] {
        let mut script = [0u8; P2SH_OUTPUT_SCRIPT_LEN];
        script[..P2SH_OUTPUT_PREFIX.len()].copy_from_slice(&P2SH_OUTPUT_PREFIX);
        script[P2SH_OUTPUT_PREFIX.len()..P2SH_OUTPUT_PREFIX.len() + 20].copy_from_slice(hash);
        script[P2SH_OUTPUT_SCRIPT_LEN - 1] = P2SH_OUTPUT_POSTFIX;
        script
    }

    fn p2pkh_script(hash: &[u8; 20]) -> [u8; REGULAR_OUTPUT_SCRIPT_LEN] {
        let mut script = [0u8; REGULAR_OUTPUT_SCRIPT_LEN];
        script[..REGULAR_OUTPUT_PREFIX.len()].copy_from_slice(&REGULAR_OUTPUT_PREFIX);
        script[REGULAR_OUTPUT_PREFIX.len()..REGULAR_OUTPUT_PREFIX.len() + 20].copy_from_slice(hash);
        script[REGULAR_OUTPUT_SCRIPT_LEN - REGULAR_OUTPUT_POSTFIX.len()..]
            .copy_from_slice(&REGULAR_OUTPUT_POSTFIX);
        script
    }

    #[test_case]
    const P2SH_IS_DISPLAYABLE_WITH_NO_CHANGE_ADDRESS: TestType = TestType {
        modname: module_path!(),
        name: "p2sh_is_displayable_with_no_change_address",
        f: || {
            let script = p2sh_script(&[0x11; 20]);

            if check_output_displayable(&script, 1, None) != CheckDispOutput::Displayable {
                return Err(());
            }
            Ok(())
        },
    };

    /// A P2SH script can never be reported as change, even if the 20 bytes at the P2PKH
    /// change offset (3) inside it happen to equal the change address passed in.
    #[test_case]
    const P2SH_IS_NEVER_CHANGE_EVEN_ON_OFFSET_3_COINCIDENCE: TestType = TestType {
        modname: module_path!(),
        name: "p2sh_is_never_change_even_on_offset_3_coincidence",
        f: || {
            let script = p2sh_script(&[0x22; 20]);

            let mut coincidental_change_address = [0u8; TRANSPARENT_ADDRESS_HASH_LEN];
            coincidental_change_address.copy_from_slice(
                &script[TRANSPARENT_ADDRESS_OFFSET..][..TRANSPARENT_ADDRESS_HASH_LEN],
            );

            let result = check_output_displayable(&script, 1, Some(&coincidental_change_address));

            if result != CheckDispOutput::Displayable {
                return Err(());
            }
            Ok(())
        },
    };

    #[test_case]
    const P2PKH_STILL_DETECTED_AS_CHANGE: TestType = TestType {
        modname: module_path!(),
        name: "p2pkh_still_detected_as_change",
        f: || {
            let hash = [0x33; 20];
            let script = p2pkh_script(&hash);

            if check_output_displayable(&script, 1, Some(&hash)) != CheckDispOutput::Change {
                return Err(());
            }
            Ok(())
        },
    };

    #[test_case]
    const P2PKH_NOT_CHANGE_WHEN_ADDRESS_DIFFERS: TestType = TestType {
        modname: module_path!(),
        name: "p2pkh_not_change_when_address_differs",
        f: || {
            let script = p2pkh_script(&[0x44; 20]);
            let other_address = [0x55; 20];

            if check_output_displayable(&script, 1, Some(&other_address))
                != CheckDispOutput::Displayable
            {
                return Err(());
            }
            Ok(())
        },
    };

    /// OP_RETURN, OP_PUSHDATA1, then `N` data bytes.
    const fn op_return_pushdata1<const LEN: usize>(data_len: u8) -> [u8; LEN] {
        let mut script = [0x41u8; LEN];
        script[0] = OP_RETURN_OPCODE;
        script[1] = OP_PUSHDATA1;
        script[2] = data_len;
        script
    }

    /// A zero-value OP_RETURN holding exactly one push is a memo, whether the push is direct or
    /// goes through OP_PUSHDATA1, up to the 80 bytes (83 in all) the network relays.
    #[test_case]
    const OP_RETURN_SINGLE_PUSH_IS_A_MEMO: TestType = TestType {
        modname: module_path!(),
        name: "op_return_single_push_is_a_memo",
        f: || {
            let direct = [OP_RETURN_OPCODE, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
            let short_pushdata1 = op_return_pushdata1::<8>(5);
            let largest = op_return_pushdata1::<MAX_OP_RETURN_SCRIPT_LEN>(80);
            let cases: [(&[u8], usize); 3] = [(&direct, 2), (&short_pushdata1, 3), (&largest, 3)];

            for (script, data_offset) in cases {
                if check_output_displayable(script, 0, None)
                    != (CheckDispOutput::OpReturn { data_offset })
                {
                    return Err(());
                }
            }
            Ok(())
        },
    };

    /// Refused: an OP_RETURN carrying value (it would be burned), a script past the relay limit,
    /// and anything but exactly one non-empty push of the declared length: no data, an empty
    /// push, a push shorter or longer than the script, two pushes, a non-push opcode.
    #[test_case]
    const OP_RETURN_OTHER_FORMS_ARE_REFUSED: TestType = TestType {
        modname: module_path!(),
        name: "op_return_other_forms_are_refused",
        f: || {
            let memo = [OP_RETURN_OPCODE, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
            if check_output_displayable(&memo, 1, None) != CheckDispOutput::None {
                return Err(());
            }

            let too_long = op_return_pushdata1::<{ MAX_OP_RETURN_SCRIPT_LEN + 1 }>(81);
            let cases: [&[u8]; 8] = [
                &too_long,
                &[OP_RETURN_OPCODE],
                &[OP_RETURN_OPCODE, 0x00],
                &[OP_RETURN_OPCODE, OP_PUSHDATA1, 0x00],
                &[OP_RETURN_OPCODE, OP_PUSHDATA1],
                &[OP_RETURN_OPCODE, 0x05, 0x41, 0x41, 0x41, 0x41],
                &[OP_RETURN_OPCODE, 0x01, 0x41, 0x01, 0x41],
                &[OP_RETURN_OPCODE, 0x51],
            ];

            for script in cases {
                if check_output_displayable(script, 0, None) != CheckDispOutput::None {
                    return Err(());
                }
            }
            Ok(())
        },
    };

    /// Neither P2PKH- nor P2SH-shaped, and too short to carry a hash at the P2PKH offset:
    /// refused, not displayed.
    #[test_case]
    const UNRECOGNIZED_SCRIPT_IS_NOT_DISPLAYABLE: TestType = TestType {
        modname: module_path!(),
        name: "unrecognized_script_is_not_displayable",
        f: || {
            let script = [0x51u8; 5];

            if check_output_displayable(&script, 1, None) != CheckDispOutput::None {
                return Err(());
            }
            Ok(())
        },
    };

    /// Right length to hold a hash at the P2PKH offset, but the wrong prefix/postfix:
    /// refused, not displayed as if it were a real P2PKH script.
    #[test_case]
    const WRONG_SHAPE_AT_P2PKH_LENGTH_IS_NOT_DISPLAYABLE: TestType = TestType {
        modname: module_path!(),
        name: "wrong_shape_at_p2pkh_length_is_not_displayable",
        f: || {
            let script = [0x51u8; REGULAR_OUTPUT_SCRIPT_LEN];

            if check_output_displayable(&script, 1, None) != CheckDispOutput::None {
                return Err(());
            }
            Ok(())
        },
    };
}
