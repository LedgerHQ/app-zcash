import pytest
from application_client.zcash_command_sender import (
    CLA,
    MAX_PCZT_TRANSPARENT_INPUTS,
    P1,
    Errors,
    InsType,
)
from ragger.error import ExceptionRAPDU


# Ensure the app returns an error when a bad CLA is used
def test_bad_cla(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA + 1, ins=InsType.GET_VERSION)
    assert e.value.status == Errors.SW_CLA_NOT_SUPPORTED


# Ensure the app returns an error when a bad INS is used.
#
# GET_APP_NAME (0x04) belongs here rather than with the P1/P2 cases: this app does not implement it.
# The reply to an instruction the dispatcher never routed must not depend on P1/P2, since those bytes
# have no semantics until an instruction claims them — so every shape of an unimplemented INS answers
# InsNotSupported.
@pytest.mark.parametrize(
    ("p1", "p2"),
    [(P1.P1_FIRST, 0x00), (P1.P1_FIRST + 1, 0x01), (P1.P1_FIRST, 0x02)],
    ids=["zero_p1p2", "nonzero_p1", "nonzero_p2"],
)
def test_bad_ins(backend, p1, p2):
    for ins in (0xFF, InsType.GET_APP_NAME):
        with pytest.raises(ExceptionRAPDU) as e:
            backend.exchange(cla=CLA, ins=ins, p1=p1, p2=p2)
        assert e.value.status == Errors.SW_INS_NOT_SUPPORTED


# Ensure the app returns an error when a bad P1 or P2 is used on an instruction it does route.
def test_wrong_p1p2(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.GET_VERSION, p1=P1.P1_FIRST + 1, p2=0x01)
    assert e.value.status == Errors.SW_WRONG_P1P2
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.GET_VERSION, p1=P1.P1_FIRST, p2=0x02)
    assert e.value.status == Errors.SW_WRONG_P1P2
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.PCZT_SIGN_TRANSPARENT,
            p1=P1.P1_FIRST,
            p2=MAX_PCZT_TRANSPARENT_INPUTS,
        )
    assert e.value.status == Errors.SW_WRONG_P1P2


def test_hash_sign_rejects_legacy_shielded_modes(backend):
    for mode in (0x02, 0x03):
        with pytest.raises(ExceptionRAPDU) as e:
            backend.exchange(cla=CLA, ins=InsType.HASH_SIGN, p1=mode, p2=0x00, data=b"\x00")
        assert e.value.status == Errors.SW_WRONG_P1P2


# Ensure the app returns an error when a bad data length is used
def test_wrong_data_length(backend):
    # APDUs must be at least 4 bytes: CLA, INS, P1, P2.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange_raw(bytes.fromhex("E00300"))
    assert e.value.status == Errors.SW_WRONG_APDU_LENGTH
    # APDUs advertises a too long length
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange_raw(bytes.fromhex("E003000005"))
    assert e.value.status == Errors.SW_WRONG_APDU_LENGTH


# Ensure a P1 outside the documented contract is refused rather than silently treated as a
# continuation. docs/APDU.md specifies two values for each of these multi-packet instructions, and a
# third one reaching a handler means the handler runs against a context its first packet never set up.
#
# P2 is pinned to a value docs/APDU.md documents for the instruction, so the rejection can only come
# from P1. With an undocumented P2 as well, the case would pass even against an app that validated
# only one of the two bytes.
@pytest.mark.parametrize(
    ("ins", "documented_p2"),
    [
        (InsType.GET_TRUSTED_INPUT, 0x00),
        (InsType.HASH_INPUT_START, 0x05),  # Sapling variant
        (InsType.HASH_INPUT_FINALIZE_FULL, 0x00),
    ],
    ids=["get_trusted_input", "hash_input_start", "hash_input_finalize_full"],
)
def test_undocumented_p1_refused(backend, ins, documented_p2):
    UNDOCUMENTED_P1 = 0x01

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=ins, p1=UNDOCUMENTED_P1, p2=documented_p2, data=b"abcde")
    assert e.value.status == Errors.SW_WRONG_P1P2
