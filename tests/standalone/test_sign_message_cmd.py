import pytest

from ragger.error import ExceptionRAPDU
from ragger.bip import pack_derivation_path

from application_client.zcash_command_sender import CLA, Errors, InsType, P1, P2, ZcashCommandSender
from application_client.zcash_response_unpacker import unpack_get_public_key_response
from application_client.zcash_verify_sign import check_message_signature_validity


def test_sign_message_ok(backend):
    path = "m/44'/133'/0'/0/0"
    message = b"ledger-zcash-sign-message"

    client = ZcashCommandSender(backend)
    pubkey_resp = client.get_public_key(path=path).data
    public_key, _, _ = unpack_get_public_key_response(pubkey_resp)

    signature = client.sign_message(path=path, message=message).data
    assert check_message_signature_validity(public_key, signature, message)


def test_sign_message_chunked_ok(backend):
    path = "m/44'/133'/0'/0/1"
    message = bytes(range(256)) * 3

    client = ZcashCommandSender(backend)
    pubkey_resp = client.get_public_key(path=path).data
    public_key, _, _ = unpack_get_public_key_response(pubkey_resp)

    signature = client.sign_message(path=path, message=message).data
    assert check_message_signature_validity(public_key, signature, message)


def test_sign_message_rejects_empty_message(backend):
    path = "m/44'/133'/0'/0/0"
    path_bytes = pack_derivation_path(path)

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.SIGN_MESSAGE,
            p1=P1.P1_FIRST,
            p2=P2.P2_NONE,
            data=path_bytes + b"\x00\x00",
        )

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_sign_message_rejects_invalid_chunk_length(backend):
    path = "m/44'/133'/0'/0/0"
    message = b"abc"
    path_bytes = pack_derivation_path(path)

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.SIGN_MESSAGE,
            p1=P1.P1_FIRST,
            p2=P2.P2_NONE,
            data=path_bytes + len(message).to_bytes(2, byteorder="big") + b"abcd",
        )

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
