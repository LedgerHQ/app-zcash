# pylint: disable=C0301

import struct
from enum import Enum

import pytest

from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

from application_client.zcash_command_sender import (
    ZcashCommandSender,
    Errors,
    HashSignMode,
)
from application_client.zcash_response_unpacker import (
    unpack_get_public_key_response,
    unpack_trusted_input_response,
)
from application_client.zcash_transaction import convert_raw_tx_v5_orchard_to_app_format
from application_client.zcash_utils import write_varint
from application_client.zcash_verify_sign import (
    check_orchard_binding_signature_validity,
    check_tx_v5_signature_validity,
    nu5_signature_digests,
    nu5_txid_digests,
)


def extension(cls):
    def wrapper(func):
        setattr(cls, func.__name__, func)
        return func

    return wrapper


# Special approve navigation that doesn't wait for the last screen,
# as it is a "transaction signed" shown after all inputs signed and not after the review is finished.
@extension(NavigateWithScenario)
def review_approve(self):
    scenario = NavigationScenarioData(
        self.device, self.backend, UseCase.TX_REVIEW, True
    )
    # Don't wait for last USE_CASE_STATUS_DISMISS screen
    if self.device.touchable:
        scenario.validation = scenario.validation[:-1]

    self.navigator.navigate_until_text_and_compare(
        navigate_instruction=scenario.navigation,
        validation_instructions=scenario.validation,
        text=scenario.pattern,
        path=self.screenshot_path,
        test_case_name=self.test_name,
        screen_change_after_last_instruction=False,
    )


ORCHARD_SIGNING_PATH = "m/32'/133'/0'"
ORCHARD_ALPHA = (1).to_bytes(32, byteorder="little")
NU5_BRANCH_ID = 0xC2D6D0B4
NU6_2_BRANCH_ID = 0x5437F330
BINDING_SIGNING_KEY = bytes.fromhex(
    "1f00000000000000000000000000000000000000000000000000000000000000"
)


class ChangeOrShieldedPathKind(Enum):
    TRANSPARENT_CHANGE_PATH = "m/44'/133'/0'/1/0"
    SHIELDED_DEFAULT_PATH = "m/32'/133'/0'"


def _build_transparent_tx_v5(
    locktime: int,
    expiry: int,
    inputs: list[dict],
    outputs: list[dict],
    branch_id: int,
) -> bytes:
    tx = b""
    tx += struct.pack("<I", 0x80000005)
    tx += struct.pack("<I", 0x26A7270A)
    tx += struct.pack("<I", branch_id)
    tx += struct.pack("<I", locktime)
    tx += struct.pack("<I", expiry)

    tx += write_varint(len(inputs))
    for txin in inputs:
        tx += txin["prev_txid"]
        tx += struct.pack("<I", txin["prev_vout"])
        tx += write_varint(len(txin["script"]))
        tx += txin["script"]
        tx += struct.pack("<I", txin["sequence"])

    tx += write_varint(len(outputs))
    for txout in outputs:
        tx += struct.pack("<Q", txout["value"])
        tx += write_varint(len(txout["script"]))
        tx += txout["script"]

    tx += write_varint(0)
    tx += write_varint(0)
    tx += write_varint(0)
    return tx


def _with_v5_branch_id(tx: bytes, branch_id: int) -> bytes:
    return tx[:8] + struct.pack("<I", branch_id) + tx[12:]


def _assert_hash_sign_authsign(
    client: ZcashCommandSender,
    expected_auth_sig: bytes,
) -> None:
    auth_sig = client.hash_sign(
        path=ORCHARD_SIGNING_PATH,
        mode=HashSignMode.SpendAuthSig,
        prepare=False,
        orchard_alpha=ORCHARD_ALPHA,
    ).data

    assert auth_sig == expected_auth_sig, auth_sig.hex()


def _assert_hash_sign_binding_sig(
    client: ZcashCommandSender,
    signature_digest: bytes,
) -> None:
    binding_sig = client.hash_sign(
        path=ORCHARD_SIGNING_PATH,
        mode=HashSignMode.BindingSig,
        prepare=False,
        binding_signing_key=BINDING_SIGNING_KEY,
    ).data

    assert check_orchard_binding_signature_validity(
        binding_signing_key=BINDING_SIGNING_KEY,
        signature=binding_sig,
        msg=signature_digest,
    )


def _assert_real_orchard_only_sign_digest(
    backend,
    scenario_navigator: NavigateWithScenario,
    raw_tx_hex: str,
    expected_auth_sig: bytes,
    change_or_shielded_path_kind: ChangeOrShieldedPathKind,
) -> None:
    tx_bytes = convert_raw_tx_v5_orchard_to_app_format(bytes.fromhex(raw_tx_hex), [])
    locktime = int.from_bytes(tx_bytes[12:16], byteorder="little")
    expiry = int.from_bytes(tx_bytes[16:20], byteorder="little")
    sighash_type = 0x01

    client = ZcashCommandSender(backend)

    with client.hash_input(
        transaction=tx_bytes,
        trusted_inputs=[],
        change_or_shielded_path=change_or_shielded_path_kind.value,
    ):
        scenario_navigator.review_approve()

    digest = client.hash_sign(
        path="m/44'/133'/0'/0/2",
        locktime=locktime,
        expiry=expiry,
        sighash_type=sighash_type,
        mode=HashSignMode.Digest,
    ).data

    expected_digest = nu5_signature_digests(
        tx_bytes=tx_bytes,
        input_index=None,
        input_amounts=[],
        sighash_type=sighash_type,
    )["final_digest"]

    assert digest == expected_digest
    _assert_hash_sign_authsign(client, expected_auth_sig)
    _assert_hash_sign_binding_sig(client, expected_digest)


def test_sign_tx_v5_simple(backend, scenario_navigator: NavigateWithScenario):
    LOCKTIME = 0x00
    EXPIRY = 0x00
    SIGHASH_TYPE = 0x01
    PREVOUT_TX_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c200000000f9081a000198cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b48304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b469c616e758230a5ffffffff021595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88aca245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac000000"
    )

    TX_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c2"
        + LOCKTIME.to_bytes(4, byteorder="big").hex()
        + EXPIRY.to_bytes(4, byteorder="big").hex()  # header
        + "01"
        + "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"
        + "00000000"  # hash + prevout idx
        + "19"
        + "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000"  # input scriptPubKey + sequence
        + "01"
        + "958ddd0400000000"  # output amount
        + "19"
        + "76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"  # output scriptPubKey
        + "000000"  # empty sapling and orchard
    )

    path = "m/44'/133'/0'/0/2"

    trusted_input_idx = 0

    client = ZcashCommandSender(backend)

    # Get txid
    trusted_input = client.get_trusted_input(PREVOUT_TX_BYTES, trusted_input_idx).data

    response = client.get_public_key(path=path).data
    public_key, _, _ = unpack_get_public_key_response(response)

    # Start hashing TX
    with client.hash_input(transaction=TX_BYTES, trusted_inputs=[trusted_input]):
        scenario_navigator.review_approve()

    # Finalize and sign
    resp = client.hash_sign(
        path=path, locktime=LOCKTIME, expiry=EXPIRY, sighash_type=SIGHASH_TYPE
    ).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(
        public_key, signature, TX_BYTES, input_index=0, input_amounts=[81630485]
    )


def test_sign_tx_v5_nu6_2_trusted_input_and_tx(
    backend, scenario_navigator: NavigateWithScenario
):
    locktime = 0
    expiry = 0
    sighash_type = 0x01
    input_amount = 81_630_485
    send_amount = 81_628_565
    path = "m/44'/133'/0'/0/1"
    input_script_pubkey = bytes.fromhex(
        "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac"
    )
    output_script_pubkey = bytes.fromhex(
        "76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"
    )

    prevout_tx_bytes = _build_transparent_tx_v5(
        locktime=locktime,
        expiry=expiry,
        branch_id=NU6_2_BRANCH_ID,
        inputs=[
            {
                "prev_txid": bytes.fromhex("11" * 32),
                "prev_vout": 0,
                "script": bytes.fromhex("6a"),
                "sequence": 0xFFFFFFFF,
            }
        ],
        outputs=[
            {
                "value": input_amount,
                "script": input_script_pubkey,
            }
        ],
    )
    prevout_txid = nu5_txid_digests(prevout_tx_bytes)["final_digest"]

    tx_bytes = _build_transparent_tx_v5(
        locktime=locktime,
        expiry=expiry,
        branch_id=NU6_2_BRANCH_ID,
        inputs=[
            {
                "prev_txid": prevout_txid,
                "prev_vout": 0,
                "script": input_script_pubkey,
                "sequence": 0,
            }
        ],
        outputs=[
            {
                "value": send_amount,
                "script": output_script_pubkey,
            }
        ],
    )

    assert prevout_tx_bytes[8:12] == struct.pack("<I", NU6_2_BRANCH_ID)
    assert tx_bytes[8:12] == struct.pack("<I", NU6_2_BRANCH_ID)

    expected_digest = nu5_signature_digests(
        tx_bytes=tx_bytes,
        input_index=0,
        input_amounts=[input_amount],
        sighash_type=sighash_type,
    )["final_digest"]
    nu5_branch_digest = nu5_signature_digests(
        tx_bytes=_with_v5_branch_id(tx_bytes, NU5_BRANCH_ID),
        input_index=0,
        input_amounts=[input_amount],
        sighash_type=sighash_type,
    )["final_digest"]
    assert expected_digest != nu5_branch_digest

    client = ZcashCommandSender(backend)

    trusted_input = client.get_trusted_input(prevout_tx_bytes, 0).data
    trusted_txid, trusted_input_idx, trusted_amount, _, _ = (
        unpack_trusted_input_response(trusted_input)
    )
    assert trusted_txid == prevout_txid
    assert trusted_input_idx == 0
    assert trusted_amount == input_amount

    response = client.get_public_key(path=path).data
    public_key, _, _ = unpack_get_public_key_response(response)

    with client.hash_input(transaction=tx_bytes, trusted_inputs=[trusted_input]):
        scenario_navigator.review_approve()

    digest = client.hash_sign(
        path=path,
        locktime=locktime,
        expiry=expiry,
        sighash_type=sighash_type,
        mode=HashSignMode.Digest,
    ).data
    assert digest == expected_digest

    resp = client.hash_sign(path=path, mode=HashSignMode.Sign, prepare=False).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(
        public_key,
        signature,
        tx_bytes,
        input_index=0,
        input_amounts=[input_amount],
        sighash_type=sighash_type,
    )


def test_sign_tx_v5_change(backend, scenario_navigator):
    LOCKTIME = 0x00
    EXPIRY = 0x00
    SIGHASH_TYPE = 0x01
    PREVOUT_TX_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c200000000f9081a000198cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b48304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b469c616e758230a5ffffffff021595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88aca245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac000000"
    )

    TX_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c2"
        + LOCKTIME.to_bytes(4, byteorder="big").hex()
        + EXPIRY.to_bytes(4, byteorder="big").hex()  # header
        + "01"
        + "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"
        + "00000000"  # hash + prevout idx
        + "19"
        + "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000"  # input scriptPubKey + sequence
        + "02"
        + "005a620200000000"  # output amount
        + "19"
        + "76a9147d352e6e9a926965c677327443d86cb0bdf8b1e988ac"  # output scriptPubKey
        + "c11b7b0200000000"  # change output amount
        + "19"
        + "76a914adee44a1e8d1bbfd9e000bdcc4d99849abe339f588ac"  # change output scriptPubKey
        + "000000"  # empty sapling and orchard
    )

    path = "m/44'/133'/0'/0/0"
    change_path = "m/44'/133'/0'/1/0"

    trusted_input_idx = 0

    client = ZcashCommandSender(backend)

    # Get txid
    trusted_input = client.get_trusted_input(PREVOUT_TX_BYTES, trusted_input_idx).data

    response = client.get_public_key(path=path).data
    public_key, _, _ = unpack_get_public_key_response(response)

    with client.hash_input(
        transaction=TX_BYTES,
        trusted_inputs=[trusted_input],
        change_or_shielded_path=change_path,
    ):
        scenario_navigator.review_approve()

    # Finalize and sign
    resp = client.hash_sign(
        path=path, locktime=LOCKTIME, expiry=EXPIRY, sighash_type=SIGHASH_TYPE
    ).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(
        public_key, signature, TX_BYTES, input_index=0, input_amounts=[81630485]
    )


def test_sign_tx_refuse(backend, scenario_navigator):
    LOCKTIME = 0x00
    EXPIRY = 0x00
    PREVOUT_TX_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c200000000f9081a000198cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b48304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b469c616e758230a5ffffffff021595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88aca245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac000000"
    )

    TX_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c2"
        + LOCKTIME.to_bytes(4, byteorder="big").hex()
        + EXPIRY.to_bytes(4, byteorder="big").hex()  # header
        + "01"
        + "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"
        + "00000000"  # hash + prevout idx
        + "19"
        + "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000"  # input scriptPubKey + sequence
        + "01"
        + "958ddd0400000000"  # output amount
        + "19"
        + "76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"  # output scriptPubKey
        + "000000"  # empty sapling and orchard
    )

    trusted_input_idx = 0

    client = ZcashCommandSender(backend)

    # Get txid
    trusted_input = client.get_trusted_input(PREVOUT_TX_BYTES, trusted_input_idx).data

    # Start hashing TX
    with pytest.raises(ExceptionRAPDU) as e:
        with client.hash_input(transaction=TX_BYTES, trusted_inputs=[trusted_input]):
            scenario_navigator.review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_sign_tx_v5_old(backend, scenario_navigator):
    TXID_LEN = 112
    KEY_LEN = 268
    SIG_LEN = 142
    EXPECTED_SIG = "304402202b22627d88f9ecebf2ab586ffa970232cddad6eabb3289fa1359b2bc9f5554bc02207cfba5db7c01b89c5d540dcb1ada67d485ab1638c2151eaa78b4d368059c007801"

    transport = ZcashCommandSender(backend)

    # 42 - Trusted Input
    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04280002598cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04280003248304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800032c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b46"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000b9c616e758230a5ffffffff")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000102")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e0428000221595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800022a245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, txid = transport.exchange_raw("e0428000090000000004f9081a00")
    txid = txid.hex()
    print(f"MAY: txid: {txid}")
    assert sw == 0x9000
    assert len(txid) == TXID_LEN

    # Get pub key
    sw, key = transport.exchange_raw(
        "e040000015058000002c80000085800000000000000000000002"
    )
    key = key.hex()
    assert sw == 0x9000
    assert len(key) == KEY_LEN
    key = key[4:70]

    # Send trusted inputs
    sw, _ = transport.exchange_raw("e04400050d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480053b0138" + txid + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480801d76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480050400000000")
    assert sw == 0x9000

    # Send outputs and review
    with transport.exchange_async_raw(
        "e04a80002301958ddd04000000001976a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"
    ):
        scenario_navigator.review_approve()

    sw = transport.get_async_response().status
    assert sw == 0x9000

    # Send extra header data
    sw, _ = transport.exchange_raw("e04800000b0000000000000100000000")
    assert sw == 0x9000

    # Send trusted inputs for final hash computation
    sw, _ = transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480801d76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000"
    )
    assert sw == 0x9000

    # Sign hash
    sw, sig = transport.exchange_raw(
        "e04800001f058000002c8000008580000000000000000000000200000000000100000000"
    )
    assert sw == 0x9000
    sig = sig.hex()
    assert len(sig) == SIG_LEN
    assert sig == EXPECTED_SIG


def test_sign_tx_v5_mult_inputs_old(backend, scenario_navigator):
    TXID_LEN = 112
    KEY_LEN = 268
    SIGS = [
        "31440220489d5ffa46530ec64ae523be7559058fab452a2c8d03215179f33ed63e69fa0c02201b3301c4dd20dc318e49e9d0ed6a7e9433ddda6f5755834c7064d7ff332d057a01",
        "304502210090836743d963b93ee1974f764fda3e1a0f4b1662805b894bc6c4b5dd66b5d00e02203c356c71247050269150b4a8e62d0c04845dec5324308e50a6c06e0a44282c2901",
        "3145022100a4cc9821cf530a179cf2bcf767644ff62e0b0cf79a5701101914be6c215b0bcc02202d2ac5ef2289caa7fafc94ce38b2e46baf5987b86193e0251f4cf2585c174ccd01",
    ]

    transport = ZcashCommandSender(backend)

    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e0428000257acad6b8eec3158ecee566c0f08ff721d94d44b0cf66ee220ad4f9d1692d2ab5000000006a"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04280003247304402200d6900cafe4189b9dfebaa965584f39e07cf6086ed5a97c84a5a76035dddcf7302206263c8b7202227e0ab33dd"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800032263e04f7a4384d34daa9279bfdebb03bf4b62123590121023e7c3ab4b4a42466f2c72c79afd426a0714fed74f884cd11abb4"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000ad76a72fa4a6900000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000101")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800022957edd04000000001976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, txid1 = transport.exchange_raw("e042800009000000000400000000")
    txid1 = txid1.hex()
    assert sw == 0x9000
    assert len(txid1) == TXID_LEN

    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04280002558b3391f27adce90eb8e0ae7e082449204c6d5c3843378e538c8770928d49ca3000000006b"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04280003248304502210093d8c71d5cbb31d5f76090b332f66fc1fb2451c97575918a9376b803eca7c63f02207e238a6a437b8724431e"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800032da7ac9ef4dccef15c63b00f6f5fcde17f1398e254c77012103d12cb12682e34df4d936479f282c75834d612071fc2ccd26a3"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000bb7589c3f9917cb00000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000101")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e0428000220a1c1b00000000001976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, txid2 = transport.exchange_raw("e042800009000000000400000000")
    txid2 = txid2.hex()
    assert sw == 0x9000
    assert len(txid2) == TXID_LEN

    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800025b5026481bfd3417f4a179e2094a944a60aaad5b2726544ca1a2c920fb65c9401000000006b"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800032483045022100959e27972de3908493b0ce7041734289a724cb0b5d8a2955de3fe3e953f77a2c0220162c40dcefeb9e30a88d"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800032043c3f20ca17423e6ad212cbf981e2bad05cbd10c7e5012102e8b6d05d227349a7bc993a7d3d6d019207c471209363e994e9"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000b9d25e70b43f97a00000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000101")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800022889a2d00000000001976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, txid3 = transport.exchange_raw("e042800009000000000400000000")
    txid3 = txid3.hex()
    assert sw == 0x9000
    assert len(txid3) == TXID_LEN

    sw, key1 = transport.exchange_raw(
        "e040000015058000002c80000085800000020000000000000002"
    )
    key1 = key1.hex()
    assert sw == 0x9000
    assert len(key1) == KEY_LEN
    key1 = key1[4:70]

    sw, key2 = transport.exchange_raw(
        "e040000015058000002c80000085800000020000000000000002"
    )
    key2 = key2.hex()
    assert sw == 0x9000
    assert len(key2) == KEY_LEN
    key2 = key2[4:70]

    sw, key3 = transport.exchange_raw(
        "e040000015058000002c80000085800000020000000000000002"
    )
    key3 = key3.hex()
    assert sw == 0x9000
    assert len(key3) == KEY_LEN
    key3 = key3[4:70]

    sw, _ = transport.exchange_raw("e04400050d050000800a27a726b4d0d6c203")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid1 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid2 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid3 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000"
    )
    assert sw == 0x9000

    # Send outputs and review
    with transport.exchange_async_raw(
        "e04a8000230117222605000000001976a9147340a80cad7353cff25bad918e73837c2e2863eb88ac"
    ):
        scenario_navigator.review_approve()

    sw = transport.get_async_response().status
    assert sw == 0x9000

    sw, _ = transport.exchange_raw("e04800000b0000000000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid1 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000"
    )
    assert sw == 0x9000
    sw, sig1 = transport.exchange_raw(
        "e04800001f058000002c8000008580000002000000000000000200000000000100000000"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid2 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000"
    )
    assert sw == 0x9000
    sw, sig2 = transport.exchange_raw(
        "e04800001f058000002c8000008580000002000000000000000200000000000100000000"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid3 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000"
    )
    assert sw == 0x9000
    sw, sig3 = transport.exchange_raw(
        "e04800001f058000002c8000008580000002000000000000000200000000000100000000"
    )
    assert sw == 0x9000

    assert [sig1.hex(), sig2.hex(), sig3.hex()] == SIGS


def test_sign_tx_v5_mult_outputs_old(backend, scenario_navigator):
    TXID_LEN = 112
    KEY_LEN = 268
    SIG = "3045022100867fdc2d2873b15bc19a42df288a257aff08ba74b9e2eefd1245e69b05a181b302200b876a40a9339b8b8333c332319dbe5329af363628e0fd4847b281719986dc7b01"

    transport = ZcashCommandSender(backend)

    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e0428000257acad6b8eec3158ecee566c0f08ff721d94d44b0cf66ee220ad4f9d1692d2ab5000000006a"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04280003247304402200d6900cafe4189b9dfebaa965584f39e07cf6086ed5a97c84a5a76035dddcf7302206263c8b7202227e0ab33dd"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800032263e04f7a4384d34daa9279bfdebb03bf4b62123590121023e7c3ab4b4a42466f2c72c79afd426a0714fed74f884cd11abb4"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000ad76a72fa4a6900000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000101")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800022957edd04000000001976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, txid1 = transport.exchange_raw("e042800009000000000400000000")
    txid1 = txid1.hex()
    assert sw == 0x9000
    assert len(txid1) == TXID_LEN

    sw, key = transport.exchange_raw(
        "e040000015058000002c80000085800000020000000000000002"
    )
    key = key.hex()
    assert sw == 0x9000
    assert len(key) == KEY_LEN
    key = key[4:70]

    sw, _ = transport.exchange_raw("e04400050d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480053b0138" + txid1 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000"
    )
    assert sw == 0x9000

    sw, _ = transport.exchange_raw("e04480050400000000")
    assert sw == 0x9000

    # Send outputs and review
    sw, _ = transport.exchange_raw(
        "e04aff0015058000002c80000085800000020000000100000000"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04a00003202005a6202000000001976a9147d352e6e9a926965c677327443d86cb0bdf8b1e988acc11b7b02000000001976a91456464d"
    )
    assert sw == 0x9000

    with transport.exchange_async_raw(
        "e04a800013f31771790b77502f55895a396a64e74da588ac"
    ):
        scenario_navigator.review_approve()

    sw = transport.get_async_response().status
    assert sw == 0x9000

    sw, _ = transport.exchange_raw("e04800000b0000000000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid1 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000"
    )
    assert sw == 0x9000
    sw, sig = transport.exchange_raw(
        "e04800001f058000002c8000008580000002000000000000000200000000000100000000"
    )
    assert sw == 0x9000

    assert sig.hex() == SIG


def test_sign_tx_with_v4_nu6_input(backend, scenario_navigator):
    transport = ZcashCommandSender(backend)

    sw, _ = transport.exchange_raw("e042000011000000000400008085202f895510e7c801")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e042800025b53e61d09f49b165a21fed754ab228e789193d664cd4ab026ccccaf6b30740ba1e0000006a"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04280003247304402202ffcfd634ae68631af2435b537d33e86a0a38338e3841aecf6d0f54cadef979f0220469c7cd94d52be1183e4f9"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04280003275035388254a4b49a22bee691f8b3d32e65b05167e012102529734fe55e9de06341c90ab8dc11f144ddcfaed136f49edcdb2"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000a875bfb0eadb3ffffffff")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000102")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04280002262e52a03000000001976a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04280002201ae8700000000001976a9149014582e6407d13434d7dac8bb53e4616356501688ac"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000
    sw, txid_raw = transport.exchange_raw(
        "e042800014000000000f000000000000000000000000000000"
    )

    print(f"V4 NU6: txid: {txid_raw.hex()}")

    txid = txid_raw[4 : 4 + 32 + 4 + 8]
    txid = txid.hex()
    # https://api.blockchair.com/zcash/raw/transaction/3e5a39fa931ed6266042d7553f68d365cbb5da358fb0cffa0e66a3259ce8d30a
    assert (
        txid
        == "0ad3e89c25a3660efacfb08f35dab5cb65d3683f55d7426026d61e93fa395a3e0000000062e52a0300000000"
    )

    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e040000015058000002c80000085800000040000000000000000"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400050d050000800a27a7265510e7c801")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480053b0138" + txid_raw.hex() + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480051d76a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac00000000"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04aff0015058000002c80000085800000040000000100000000"
    )
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04a0000320280969800000000001976a9147678416cb82a4a716dd1ee6b332744ba2a1f11c488ac30db8e02000000001976a914c628ce"
    )
    assert sw == 0x9000

    with transport.exchange_async_raw(
        "e04a8000138ff6367f0ea6763f1c1d865329af0715ac88ac"
    ):
        scenario_navigator.review_approve()

    sw = transport.get_async_response().status
    assert sw == 0x9000

    sw, _ = transport.exchange_raw("e04800000b0000000000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a7265510e7c801")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid_raw.hex() + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04480801d76a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac00000000"
    )
    assert sw == 0x9000
    sw, sig = transport.exchange_raw(
        "e04800001f058000002c8000008580000004000000000000000000000000000100000000"
    )
    assert sw == 0x9000
    assert (
        sig.hex()
        == "31440220488d0fca08431682cd5f10968a72affdd569f61a4a358f73edf05d0fb4a3e1a702204722751bd7d27f999ed714694ad024465d54c288a9cc560559d9594914d92ac501"
    )


def test_sign_tx_v5_transparent_to_orchard_simple(backend, scenario_navigator):
    TX_PREVOUT = "050000800a27a726b4d0d6c20000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01a0860100000000001976a91419650e98310b2cc27f00a9d0c4580386553da2e488ac000000"

    TX_STR = "050000800a27a726b4d0d6c2000000000000000001cf67287a7f4820dc2dd57503b3a5e940b4c1b322024cee5e8ffbece7f217f4bf000000006a473044022078b3051d53853b8cc0b1167da56b4839880847e1cb39553cb724d564b069ea740220208455fe9cd13aad139d983467bc862b8a65fe0b477fcb872a298f1ac5174ac5012102749c3f99dd136601daa824ecf40ae144c1a7de432bf22dbb23c81c7b6077d431ffffffff0000000239ceba3e81ae3415fb4a519978f4bbc75e5a1d101ce0d6bc91d035f614a9f68b3768e7c28954fec9791e472e02881cb6b2c3f6d744c4eeb0f248eef01f6fb53dde43004dfe82c370356e830569bc2136374339101ab3170a9e5f01da0346340189b07d697d3ef14edf006d9a39472371ddba49a58ff23026c8656e9cc4edd437b2592149ac97670466fc5eff6657dd79cf20d551b31446dd49fbf9d4b1f3a2309ea84a733e8edebc00e516d1c077675494b2b58fbbb78cd4106d1378c0181c729a4606ed2b0e9aa6a84c1eb445964a7363bc9c2eccf8758e4ae1e8d3453b1de676dd06164b76f275627998f50cf6e54e6b19d04bf3a37a207fbd5ac65db7fffa8a0d2ea64f095fd1bd4b72808ff012d94dbf00480123c1ac26d5392277f20322af0595bb9d44d5964b95a859e630d90ea82695b163220a255a5eeb591a9df8d592957e5e0555a178a4aca3bfbc7ae23914c97edbc2c4ab1c5bee7220f220ed869eca8f90ea9646551767d12cb6f7d8d1c51f6f4e5989c24ec7829e2efc2d9945644fcb541ea1ba9a0a9a119e92c5452d5383f381f62501a0deeb0999e659fa2bdfa8036a6849aa67a7a70b0f3028332ba1177ef129df4dd708c85a63a956653ebfd65b174889ad84065da7dbf1c46a225b77e45caf0218cef2b6f879ab20c8c40345e75d2db634645badfecade82c07af4d110c042bd26060d9927e0d8257c68dd27163994356007842dc7334f16a82cce83bb5ce428e10adcf4e9077292eea6133c3933eba031dd73c3ded25c8d1fc7185df3b5974be79428d20b5c84d81e06be531d987971af721c29787e0217ca27462c9a64f1ad03d05581952f25505ec056e1663bafc81d36d2663309e126b647353b6938d96b6a82f187a87543ea43319c51b3617eba6815c7986b7825bd6b95b41ffeabf57265866fb47336207174b2617f30887962bddd79a710cc1f3e821d5819b826bc9317b85d3aa1fe62da28e93233dbd44f1ce12f998f0ae82832c5b7b8d85bd3bcaa36267c9ab28720765b26d6104f3b3cd84b39eb3dff77f836a1c9a911890a7c8c6466ef5a2ac7547509b19a25f10cbe193d8d97b9c54d2aaca820303bebbcc4c398d71345c10b5b4b68552bd12bf00eb14cef7a532490b3fa9acf86e7e4c7871b0d9ffece64195308cdc3403af4673ace0fed752a34cc424fcaacce45fb199f2daa682b1a9ce8c102ea6504c18be633d23429b3625c42005fa15d4597632a4493fd132958cdabfbb6985d998ab1c00ac66861552116d0b3dc27a86ff398b955097853a03489062efb70a19197884a035e1d364339a66d7ac01c0823e5a4099400b1f9865ec8845843d7f95a9caea50a30a922a064a3c41dfe8be3a6422b9c77babce7a9456b470802d25939471165f40990746c68752aa72deb0de06d92e8a9e8279a7a07976ddd5a4ea656b5d0126c0cf6767fc439549b6cb4dbd119651352f7ee7bd1f2687ab2da8fa9041d164730b950d828a6b4d540cf0a329cca8edc30fc27a35f1990caf739bbd701bd05428edb3ea8badec1136b581241d951a3f29cdb49ab29aa477f3c52beaeb1c55a190f37841ab60d6d0754ac4458deb10f6e0be101731f5176c4b2845e5c50d5121994bd8ee07f6085a54e3838c2fe6bfbf8212bc8a128d4aea5522b5e3245312037fe0852e226dcbf5488a388ec83f78875976f7de2588573130788ae5c7e98d080bef6d2b6e914520f56506e4b0a57469d07ae89697c7bbd041bcdd33079fdb6ec87dfbdad29e2e369d398b34858626f9829ad3e167e001932148c7ad0f3cb0d66edb322bbbd96f7f68d9b54e88a61d24dd69788de009a48a97d85554008a1139170b35d8d1b09a5d0eb75d1a36d1a825db2138a627cbcdfbd89303fa71f417c21d1562e8cd73d5bcc3ab2f26edcf818fc592ad22d5bf17d139b5573dd1f7ec2567cd66d44b4e06d54079308d0af1c98131b0290c215b72110522038c15fe2090e67f6f6bb865096f10e58ac570624773c2755bbe261c9889846b35f143285476f798f8364301a60e401da8320a939b0d3a4ef260fab9c6349cfad8e993a7de877cdb42933810abc881f74eb3bd1a9301bf9b425750e004287f7c2df4d1ae98f1e17f44f6f306e1f65e0512ecf602ee6c0c4d7ec642f81a1a0c6895324e6013d947ebe29d365f9a23f86f7d227f9633230386bd3eb242d4c6ccbc830c2c8a23444b273723a0f83d07519cc818d0e2b3e563c7a14e0ca5ddccb095d2a0a4303731b403d83da0643377426365a7639f770c5cd49fd95fa982e6017a4da75050c85f0503b7f150270a0feffffffffffae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82ffd601c2493dec4309737e5f931e660f3fac9cba84642ccb90a59f929cfe8a68513413ba0e2edd762f3a69652cc31d265fb0141ab85336fc5108eb940bff64074f9379e0d9081096dbd271cd311e40ba626f02621a9ddb5dad311a932d61cef82a22825f532daf9f2059eaf9bac3aba79f3a30f57ce27bd65c1608d611e8072b6267f985c40d044b310319098720517962a63200c9e7da2808f588cb1f39ed4860f868cb4e23aa2b89a1882c67169031994cd576ca7077952cddbc433d391920696bc9e0aeb74b357a43ff817d6fdb44346d4299723e0eda5ec5d702f6aa2e1c19bd13625bbdf14b00cd8a50c907eaf8b44d10553a17eededdd97cddd183574e9795e85738250341388929fe09f82781a25c2dee6469df6aa00f30ab753d7f4806b758559e3bbcb4477b6fcc882f2120d20829cae2c2f2e333f584ab21d88136d663cb65fb17125943bcaf2d0c6ee4ab3d8122e4ca639b570d3579c8353aa1bd25e2b8eade9956128bc88799279800e8866f4ea863429f4e5d26fe98426ef26cd015c1710d107ccd9d0bd44581dd830e9c1f5bd2afa29825985c386121275fe47e3c000ff8efc5a8cc79863addec6db941b114ba802aa5efb67c9c8d50988f954c5a1a3a2332644ec56bc33e20ef573c1c033e39cb9ef6fbf28480d5724025d18b8f52b7618167cb4dd4da150aed787364212c354fe98194977f9e09f1d6ca1e8ab1327ab2226d940af0f9da620882b704af80588af599a336120c454047848236cbd2ead8abe5cbdf0aba310b9fea3af5f621b09a6cec8011d27ace447ece4a05d59225bde7df34506740a0dbfbf813e343609f119aac2fa21d5a39842f26ac9e35ba8ddb3555e7230b521deb3b3d15bec2ae955f99eb8b443469a070da827d96fce05406729f4a1d9a899706f91ff7feb517857db73226b0b7867a8c3cd19df499616ac145bc3e0aa15e290b0bb142bfd24b7120b760194de2e13884fed025f0feaabee337499fd8b75024539c867fa6999b583844684ad5fc60e6965ed2ae7504ea27cb4c5e2f82354f1fb34d4624072a7bfa831fde0503837d8d4260c9f0c424dbdc6786417e76a7f5c2890be319d6e2b9e2a79d2bb17ab637c41527146ab3b70a40d9075b35413f6bec2dba8ebd9e81d2438fac53708df21c58813a91d8d6c63a300b5dd536e7bc03aab4fc8a130ab5c5662e4dc8d4e93e836d6e2f8730f5bbe11e4a1bf7a08fa829c9812ffca9f46295fc3b3695849d646bb31c5803439bb562bbff352a65288947cbc844f76307778edf1dfd49c7edff6a9b91185903250b510b45e8cd52d3e45070dbb9fad86e6269d240ed6ed5b1d348102775a16614967a3989515fc791efe2b55d50010a60b32f5bdea40449ccc88d09f4c3950bde1472098f330cd51df28ee9e8a42a0da5da0df2778d6ed62627a634277b2cd6853cc9f36da957d834c2c71730f29c39ff0c3936112b89244e1bce6fc5c734ffe09778b611f5010981e666bc701e8f25d720fbdf6fdf2a9c56b97e2ae4ee8b232216816460b04d41b09e030039e711eee823f559505f36f3224b48a53caeb1278b18b9fb93fab105774236b6619e62ac281ec192d8f8f390f0d88d6c37caf0b16f902bcaa8610b8b4d6ffd016ace02a168a6a6cb25087a788cbc9af829362cbe2296d094049ba0c3ce23e1684a9e1bafec42b5fec1841bb3fff92142af0b17c96487da1c9113eeb110f7080fa4cff641f5ccbdca26bbdacaab9fcb2b4ce00bbccff8eb3ce58208415d864f626027b2747e1159bc6d180da89156a3cb4de7185c1c2a3a81047aa2d5f94eb6e4761ecc6794ec4dfab6024cca2a3ad629a9a867996b00b07f6deca68969f482fd07b05a4f707cf7fb9236a9e0b7a8ba361143773aa956c3ad1232795dc8480008565ad5992161ac5fef11e8b8f5eb518b6986ae09e139b2240e2ef7448b50ae473a48a4674cd8174ce79c77120b5f4af9c3dc25080586c0dc2ce8564d5611d893641cf60ace3f715f6e954098517c477f1dd1fa037e2ba8c9a1eb731633a92df1ae017af977b5aac9ca93985323cd2a8a2ee32a448c4ee985419ac51ac1877a4705c3e6d308f7b1c1bcc90c9b69e62a2303ae45508aad98667cef105f3026f0a1b6d949694d4ea1cae16a2b738c90a63690dd2ce92d8172b9168b273ab80cc38efd4c269d4c1c59fb3831fba4259f27e7bf58c9d9e882d382c25d0143e0f2b80d864d6d24e14db56acb2e10b235652e3e20754071ffbb8082da3f73e53f1848c550783eb55c4d88b4578c14286b5a395cf75dba6891016b8297919205511e9cf3eeffa5f0a76ac2937a2908f84e979855a1e49743a3fad39aff95ca7858848a86da4b79c86aca1a9a745ab2eb3f5b9f116eed278d7f99b89ef192b51e144b3f9ede0c06f717681996811c432d131ce0304c3eee47406dd3a54b16b5ac676922e13fa2f293c65a01c05a2798b711e1990eb486be2430952325e33cf38f9a0f08df881c9437a0d65b255d9bfd95dd0c1c853dab79d4d620a3148ec739c60d28bbc031172c7eafaf1bbf6d4096f6d37dd22660622b670e51c1b0f09766d3a8d7cdef029b1cff1ecceb58591b80883bce5f8e9c3a2e7499d3032069d6ba3524154ccfbfb4007922a1fbad0176c6f84f36a6d6976128e123bc9207806d95ea4f0e004abebb0c199aa6dc8b5a1411de1b545b13470f7ef6c213f00122ecf296e75640848e6414b4875010fe994fe1413a6b084123bd3a36e8f7f0e5c69a52bf1c35b52e0281184e188f3c9322da6235080814bb91bb9bdff7bb4286935fc042e110e2c17d5ce0d7be56f7dcd2ecfc6aade05db7f08af7201861f1602ff47ce866543a5b660be96e980a960dc59fb523b3b6696b8ad3a48bc2afe08cc251764ab3cb038c20040234c6e6f67639ec37ac4ea1293702c825b2163b93a85ebebbd99f37fff916dd8650d8c512abb4f83564209525e3be367498969053d7760e2384519bec1a7007cdc2e364b3396782a05db1c3e708515a9f10bcc573ea2df9f58181c81ae9bfc82bd5b2e4074339f59809a118dfcedf60c1dd110be26cb14b64e3807152d07cd486ee33eba1099f61dfe4930ddc4e778dc4916089c3023664b2e7f521f539f905883468b005f8e81ea0ed286faff6d73775a71a5b02de035c0ca5d99a4658049f08d81d5a571c011dc7f99877454c187ed97d55b3827591d6daf192a5d7f94c96a4b60a0bbe5893535929a3d3f437a903e6e2dbd983f57e0589e152a82d3b0037a0d8dbd0a3293f584581cce55111b5e7d309408e0266dc2fedbb7799d28804a8f7b7ff5ac36cb877419e9efd316051447087fd9cd24cc0d92fd541090963acfa36b624f816b1b4e7c6a3eacd80c9f23228d6e08dc31d6fab94f763cab314f71de1d75bc8acb02b896b52a9d7ef9131030e88117750f953556f043796c73c8e14b5071ccf16168ec8cdd6079fd4577817cade883f60493b1036f5df2e11c213bf17ce4045300aee10088e0541a66a9cf068a16b10c32d2ae5e536d9838feb5612237ef0b5ce01254394d7aca903a1d89c170bf0810135e1e9320ac073f0a661980c328bb4803335c0a13463683ec3a5c3b946f7a5d217fd8f821241b8895076557872d52d81087ecaa6ab09ebc788be0123d4dc9d51600da679dae91a917b2743ae8af39b8d83eada3c8ba8861c4a7eb7db89bb3a13ff22ff5beeb1365600340d499297541d7c94405372cb08bc00df173ec58fce42350e6851f62b28822c76d617f3ff3ae0af4493350e3f8678d5ef2a4f30121c1037547e29360ecf7207c72077bedb23399f2b2ac2e6ef5354bae4b45941759f906787482fcad2f99dad37bc71bff712fab4f66e89bf9de6bd63979a3021f736c09591a349eaf5b1e7bf84658f01baad3caf9d2343e111e1b6d3ee6b07f7e674c1190e77e00093e488ee0c452902c8fd52248bc14cb4073579a1f6c52f117541a0cc8e39c089efac7dfcd4382cbeb82c932846b6e6101543acb2f8455b5ccbeb718aa25c7e715dff881a00809dc5d659912e85bdfac2d413ce09cad9fd391e90314b6807fa2cdc40fb8999d05c5f11690921ba141108647752032673a41df84b42c9bff55734c5d58b16f82c573c3011a964418a308b4d732597849ee3a3643763fb1a81619e7c1d3875d068bf7f0151ae8ad6df90bb6722284d2d73ad1427e2c03db1abd87b42a6b68030114e9ecafbd1df20ba71ce888c98069133036b7455033407c6d7e884b454a8121f6c9cef9992357216fdac0d558d66a763feb932a092466fa5e10545272ac8c83b377fd9c621ece8047996a95de83ae3302e08433ff1bb272a2adce60de2e839c94e3aa24cdd367a67641396b78b6739f6522bb2a3b1b39ef3f3f3dc063822c8b2acf52265114e372ce83620e5bfbf05d5dbf95a4733258bad007521c787277b8f03822c8cf3b0ef082c78b38fd66eb9344f76e538f0b2471c0aa0a1dd1e0937db2ecf7148108836c89170d069c6f2483e1bec4c2ea32033add3365097a93c220de3125688370427d02a11448508e851bd4561aab520a23ba07368df1a5658eda85b724951d065408455cdedc68b4c4c0b08b087cab3f59b165a8ce5c4669e565c220efa85d0c7b93fc757838cfa19a8d935547e1633de5c07ec69ed835c31877250cbb3b94d26ed7afc6d6602d6c8e0dae788988080a4b6c8cb61271b0e0aae5fc7703abaf2f6eb6006efe59ab66bb4099e509252026ab7d1f318087b6381c6cf12039e1185c814685887b58aaa6639bce877121323d7c061abce673963f13cdd6047cd68eed14ff9150dd68a799ec2178ac8f828f33b33643c2ec189ca57e4ab78d8536416e52b328d4acaf2b843aa0d9ad34aab324ac36afcac1f91dc3983366379129f2282b24c9987568bf208275126fdb63170cb1cc338798b7a1f473388dac3c226492e11ff9404651c3deaae7a6442b4fc7164c35c81bdfe935bbd6014899002a79299a3b97901ed31c2839c727abb7267d169db8627ce36056fcfad1072d22c10b156ba124e31c69770ed63f12d3bdbd570def3024f9c9ca838fb3de770c544e5e41e88056d711f35bc856c20b120f74960f40f11ca00f8bff46b981001454d7f790a3989baf91c92a4d1d562a290de2aa00b2b0d5c64fe3a7352b92aeda7157f35aa47ef662cb0242a8b3b9a1e0ad0ae63fd2a565b746d37311a1069d1388ee3594e933773b18da64f128ad71a0b97c0e349c57d414d678e00cec0d732f0459bae23e00c404d4088dfb8c87801b4360b534ee89f0a7f100f128909d65ccc3cdf3b9e2ad6387fc051dd8e657fa21855d4c37ca7931898962cf2124318ab1cc8992b3f6baab4644977ca32108f569da5aeb3e1ef6e868c0c5778d3eaf089fa28f042fd33a9e2815fc88f355ca72ce0701c438c6d34f9c7dc904d95b4d24b95181dad7023312c27c5a37d3a39bae79c82285311a7c2350688a475a3a6f026691e9d61ee653286bb2eaeacc0461d368cafd2428cbe4b28bd6d23d74bcb57187a8663aca58fb3b069136d98160b666a1ebdc35219451c2d5c067737f56dfa618d6f23e217d2e5c1f3a3fe710d3711ed250df7404d0b4e09fcc7bed452ef245a9f2c1aa0e961f589ac38aba80e1957c3b5e4459284cd16af0067a360fc819271c3d304fd0e7484abf77d58a53fec42b1e6aa23d0846dd3ec78aa9ff561eda516e8bffca658523d8839debf553bb448efb0be7e81485a7d0e7dd858b6b86e5f22e95bd831033658419a4a3fcd448ca4a62997f8834c27aba1d99e039f60b572a08b6646c9cbdfd67621dd7f01e6d1a3a171dc22e3b8b58f1f5f66d8a17d9bc1b2c12835557330902ce8aa4e5a5dfed28ec3c0a84249eec8d170d913441fccc2f53439e3add4a4b6209f5a749cc9a8061b287b086367c5bbd93d379b1c2fc67e65f6450938b97deb062686499c383762c679872e327ece5f8b69c47727094ee7d8bfe96b2d9a99f811d2632d71d267bc354d29ab5379566785daac975e891f25ae53e9dad09578b03cd96cb7181957afa2df31c36298c585f62c98c612a70c53df86545e00d6d97dc4004e7aa82d104e24134f7232002e6ddf2afb2c6b4ddb4bd1bab5ff49f2328012d877fe6e3e7247b7fa3f6152010ddc96fffd1ec83c4ee69f5d827ca6be2254a9d5162d2cb222f53bcbddc322b499179cf0c1b327e4e842e20d7e7ac482f8d6d908b73cdb18bf760166e1cec22b69792131142fa34337354cd9feb57648f02106d6171a55bbdb8912dd85cd30eabc7a31e3b3070d447e13ef07cc6c47a3a8b070ff57fb6e022702811978a033175d6c022f3fbbab6dfaeebfad850037bae459775952d2dbcc319d3fcaad1fa13db598da05496e9fbe045d8acd60643eac733759a86e63710ef6f61a859047422cbaf596f7cd33a0b75d2f461c8dc90e2f6951cb01dd70b1f45ebe76a4be1c83e174b4707d85cb439b4afedf61807188014a3e9429c30db7671b320771a460c1a719443351feebaa3f1b99c63e36c93418af3a9e1ebbf55ab54c47d0898c05c2a53612a82d41454f5882f06b1a98d4bebed52d64dcbf9f6f37ddde4c6fb014f29c25dbb9fb16508111f81749be168f81c788512ffaa9a301828d5860bda7a942590937298b63d177f2f9edc3d3af7cada483cba84d24ece123f0a1a5c2377ea26f172a6138ab53df85ddf45ca1ae2dc7a8d8555c8300d06476bf9344e3f7ad83a9cf884386d99bbf75fee067c989c9407dc973c8acc7f49e5257d88660a96b117674555725950b5c397e2267a9febb9cbcd33fcf15663418e7c9dcfde8824d23728507f31baec0f1b6f52c11acac454bd7740253bf2930e27915a5fb63c05b52fb8607b6c087db9ddfd273754747d7ce96ceb4a6c052207d9027cd1669ef1281d720eef12d2c757b5dcfcc779940499800670aab8272f5d208a71c7542e1bae1e6d682b309b3f8273301526666893806f8f979e7e29c8a244fd1dcefe5d0e4e2111a4c39123e9eea036ade0a2243d6013591f7c1367565a06f599ceffa2fec72c6386c3bfd68d57fdcf00b233571be24c9888cc52e17e7c0ed7f992409cbe1f32dc9a43008caefa856f59e413dae16ba4b1a5f7bfe09ee7b28e2a7ea1b6d1671719e7c605020e328ad4babc83724a1e8afe375a1c4ea6b2d04f08ac0e8c7d451b3488cb4f654d89e55111354aa59dfe69258c8d3fae89fb6131c031ec0e612f346854f1ab26fcfae2986344d9d202df5367c92df875a88ec3d0a8f77fa25e022806bbd1de02f0322fb41b304b77321c9b637717af7b075a33000cddc738462d2c9894c82a5811310abeb4a23ac24b90eaf2ad5607d872a805d34f38093c1ed91f49292b1185392358b26416ead073d37c1bdfc0e575d1876bcdad480c287c5615e7a9483df67ba7372360ebcf013eb533964aef17c76a7251561cdd9195ca261dab321dca988ffc1b46af4ac641e389609e3da25c667a91729680b792c3909636026991a30c788cd9a3495bddbf06482ac5f65fe93a332b5d8bddc8b1ed3aab2414fea91049e04f55fc89b953e118188669b0948024677eeb42a94c7aee456a02b544f31bf7a5bdb9750400ac0394d2b2e411622525012973fea716bcb43ec5359b30e8fb152c73d39af50090758f2f9486cc05b6033f72139258b36dc19ccd18d4e607978c2439855716714a2b38792e66c32734b030e519d61b9be42cb99f20913de3219fb331ec6bdb739d6e03f4c72f596b545702863db36919bdf34dce1ee1a3b0a17d9621c171e075e3cbb59c7dca0dba2f122bb182bda6d1d6e2567f351ada9347c6a493ab24a772a61990a370ed4c26badcc0fbb6484f5006670c2016a75f38fd66a54b189568a74eaef72b48d4e4258b7e3d29110c71982e29c4f5169d5ed7bfc5b9f891524b0524cafc0f6e9404b313726a6bf37a3923a6b3ce0b3adcf9291dafe9a100e5416484677394085ec4b15a2c3c36ee64df4d4fc7920406782801b72c0b481072750b96ff96a87eb44409825aefb1cef408c174e8638635d27db4a26c6bf2b825eb6af158a9900bec53f2be2b79cc8d70cff57066a28635c4819adaff3c016ec47d51335cd7e13fcbb8bba6d78c214fdbd5311152318c027cdcf5e06cb81c502a91175a7f676bdfc8e54ff7a0318b5e9fb0d06299d78e22ae59a1d7594303cc9532fccb583957a9601981b1481ce0738d5825cab9ba0a37b33e3d1efc09f2a67036a3b0a93a7224afad235e51c4842e132e8246aeb16a09029b05ecbf6ec837a1b8548505a41aeb740191c4f717d11c6a85bf2ff34d6113b0bfb3fb9690d98293e89c07ac2745b068bb61c12aae8ccba60ad4169b1e2737155abf743c21babd02e85781b485fa1893ccf907301993c7db99d6f5027fdd29ed331c771269111311663fb6a72c14a9a04156aba838f061c34a27ca7afd582a06fb003b1bcb3380b1eaa521bfa232453c6cce15788f00cb2647be6439bb2d288dc267c77771f6bb69b79d303e6a45da14c0da652c67066aeb0002d68216120b395fbcdde620b5f8cec589fbb380e2f01a7a64f3a0b8c01ba82c489dd3482b3b005ae1947135f750edf6f9bf0e2a461998572c268c2adc81aa9ecc9efd21a337328b4eb1769337e198b0dbfbe90fb47ff26087d91b391641b37da96035143a1cb9f75cf84d3c17698531295071961b091b2ebd29a5a116305837bd6f2a8cf9349f952fb0fa7f76092f4ba1dd43e3e601509514a62a539047f071a6a3bea0ce0ff898636005dc758ded83dc39ad3a0c455ff0e42a160f1c24ca530cf7569cb5255023dc6aebd2b840dd42afd13b11342188f44d096a549bbc9896dd9e92fc620a997cfca6b5682de766e31f102a29c87777d63a70f900d8f68a4880c0b1f59b2c27c78d5837361582979f10fc7ec3f234876e99a7b78bbac0f17cc819d31c1b3c347e024ef7e8a44c2215c86d16b23010b8d222be98aa74931c860ff2308864387a560b450af6807165ddfe28438ee12ae9e19507b199441730e9533856777c029df488ab56a8e2705418110fc5b27f6fa1a7c57bbe6f514903dfc7a1b5f869216dd2af7fec3800809e0c9a789798a856cdccd7890948bb4d8d5f893ff645d22d824f52c8393a28b20e89c0673ae32df7d152c4c133801ed4278474bac5cf75ad1d41a0054fa33cd67bb3135c5b7ab1e215f2e80d10319d69f1b34ac2e4850faf24f870ba6bfe2c201d464947af943f64694dad83d2382599adc9eb9d199df985c87de22f03793f258237ce4868aad93ee8a3cb21b3a0b61b0929f3c141771f329f050972ca717487ddcbc72755934f86284c7e063ff67a0c2a95a3336975aaad40278c4c774f7346bb204f29ff143e5e1b535703d0f075d3e521897be518d035629bdc03e1d84dcb8ce3da3e35154e525e73880a3b0673be421faaac79049a1d9157defeca544058debd2d386822b2b816dd2328b1d38cb22d973032a63d633c44539a949d6e18fe7e65eb1373345a363f83b8ed583ff5ecac90023514831abeb4f6c82742d6d79bc4072ec221223d19dae40112fddfa3a1009394d4e0f7a8ba86d370b00ed72e851532b18ce2cf1f60fc4d2334f1d4508ac6f879c74522c9ac23ff8aa3b193c1dde06dfac93618dfa45d88af42a1c81ba7936bc30172bbab8aa9306593d1fd25eb85b8c734c555dcefd7a0318471b53f5d238df9753b252e18b0a677d423e4244436eb30be90a9084a9cdd3247add614b047abf31cc136df13f1552060c271d3dafa319637d3bfa5ecbba851c567f773ebc7e93889d40b5231bf065850c4949b5ac95c2c1c0ce56db8b194c8703651af88f58b26fe43b989b4d613cf652787a8f427c6eeab03fae82e65d774195023edff1fc97aad1d560eac51da774acff150553beacf0b275ae8e9857df457ca903e6418912a072769722d5c7775fe7423731f1242320ff12fe19d90a110d6cb0f22629b76dcaa3a39fb1de7fc5e188bae52feae1b438bb3975961cc1e2df11e6e1ffd069bae7a381f8ab7306d86be931f04c450a5f31ea5f9841cd3c22842adf9ccc41d7b30a87213f724aa0a421850970b1f6fcdd05d0ea74b191f4e3430656f28ac3d5e9f55a8ce7591020cf63d396306f803ac8bad782820bf9414923419bae3f4c51eeedb1a3821a3fc917858dfdd176287c450bbd18b320fbd97323e0ce043e8366e5c71e0622b16229a6d39b829aa3005078a7c11c9afeedd8cccfdfb009f8301bad0a81856e2170c1c58472a3aacf0c47653f2fc2faa8a5647664fa35f75de85bdf3c76f04c2948368c248889de8ec126a6798b19101327c99d1c334944899d3a8a756f2ddfb01ad8163f62e4705cb6414cb0908e2a91274f7afa85424acd8f6809117339fd720da13cf5f2bad9a0f206108d1c9916ab612d26875ecb382b33a710b43f5dad637de0a9da1bf05f45abd2e5e219723ecdac08742d097bf5a856759d6037061e92f3d1219537973a1d0882667de1fe41815ef9eb4181fc54dc884f94103199d3516"
    EXPECTED_AUTH_SIG = bytes.fromhex(
        "56DDBE2F1512F9F0A038F435B5BCBC3DEC75B54347DB1EDD3E149F516B91F8B79AA3F435862F77AEF7BE5D334196ED4C44389CD4DA9A473CA7AB9A9C08C6A22D"
    )

    tx_prevout_bytes = bytes.fromhex(TX_PREVOUT)
    raw_tx_bytes = bytes.fromhex(TX_STR)
    tx_bytes = convert_raw_tx_v5_orchard_to_app_format(raw_tx_bytes, tx_prevout_bytes)
    locktime = int.from_bytes(tx_bytes[12:16], byteorder="little")
    expiry = int.from_bytes(tx_bytes[16:20], byteorder="little")
    sighash_type = 0x01

    path = "m/44'/133'/0'/0/2"
    client = ZcashCommandSender(backend)

    trusted_input = client.get_trusted_input(tx_prevout_bytes, 0).data
    _, _, input_amount, _, _ = unpack_trusted_input_response(trusted_input)

    with client.hash_input(
        transaction=tx_bytes,
        trusted_inputs=[trusted_input],
        change_or_shielded_path="m/32'/133'/0'",
    ):
        scenario_navigator.review_approve()

    digest = client.hash_sign(
        path=path,
        locktime=locktime,
        expiry=expiry,
        sighash_type=sighash_type,
        mode=HashSignMode.Digest,
    ).data

    expected_transparent_digest = nu5_signature_digests(
        tx_bytes=tx_bytes,
        input_amounts=[input_amount],
        sighash_type=sighash_type,
        input_index=0,
    )["final_digest"]
    expected_shielded_digest = nu5_signature_digests(
        tx_bytes=tx_bytes,
        input_amounts=[input_amount],
        sighash_type=sighash_type,
        input_index=None,
    )["final_digest"]

    assert digest == expected_transparent_digest
    _assert_hash_sign_authsign(client, EXPECTED_AUTH_SIG)
    _assert_hash_sign_binding_sig(client, expected_shielded_digest)


def test_sign_tx_v5_transparent_to_orchard_with_change(backend, scenario_navigator):
    TX_PREVOUT = "050000800a27a726b4d0d6c20000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01a0860100000000001976a91419650e98310b2cc27f00a9d0c4580386553da2e488ac000000"

    TX_STR = "050000800a27a726b4d0d6c2000000000000000001cf67287a7f4820dc2dd57503b3a5e940b4c1b322024cee5e8ffbece7f217f4bf000000006a473044022026aa0a495caadd31113fd067ad7e947d7e859e0f05ced80c7cced0bb3959ee87022052846a583ae9b67d6e47cb4f86d054848d987c00c08cbf333dbd46549df96f31012102749c3f99dd136601daa824ecf40ae144c1a7de432bf22dbb23c81c7b6077d431ffffffff000000027f6abc5384841cd9bc7e27ee61431d5a3b6999b0f953b36ceeb67c3fd18ce9803768e7c28954fec9791e472e02881cb6b2c3f6d744c4eeb0f248eef01f6fb53d306050373d1a6fb3c4bd05888e2a900c1c81948d0653c90ea957fd43afd3a3b18b6787b72f8d0dad4afe69a1d1a50686438c0246f07793c73583dcdc22456c05c2faaf0661ac0993c4f03bc6f396ed82de28ace166b922003c41117f7eed38330c60cfe0c8fe459fc53344bd278154b331d35e2e243665a41ea9cb5908f783159953ef6dae2ab240fbf9d329dc3d4ce92ec9c70588f698abc2feddd07a4cb2a0be91f50b347c07ca32e224fbbc1d9cbba2cb956466fa0b4570dfa4a32825b8fed0517bfd025bdd3aaa37aab60f2730f251a65fe52e20c2fd11d6d9714701f0abfc10576beef57f1198b194c902ebc1ef3e4b34fa6ac9bce472eda5cc55ef576173127bd6c5f55def93ef3e401c868731dcb187960abfdc8f2a7e5d9d57db363f3a9337b192be26a9e0271b1aa4f89090875f3f1a242d361cfeb5ba5ce9c885d5c190544b0256d6e8916b39e7dc463d0bca1b319479d6001bc4a37d75ade16b59823f16180b0a8c357f3791b48a41c6bcb8295773c3bc6286df42e067f186ab1a3d318122db44c8078aeb11d31282728a8207cc1f54239a02c23d99780b22f55baeaed7d2f71f2cff6177523ea496551ec7d2a325afab69b02b239929d101cc2862f063c5a5cec2756aeb981d45972235c0e2cf23596b4b36dc0196b37a4f60dbf0021e78fd92bb962d6a8154ea9c3924939cbce570309bc75bc768957dda0bfdd1264bf227ba183931ae7b13017cd36053c4b23916b50add78324e651159cb1b776d8e4f09ddf1ef745188d0dd175b47694a361b48be291b4eae6335508d5e3cdedceebb3627aaad7fa76c55f4522556fb54447eeac9a9a24753e34c13f3f531a903f5b668ca3fab010acf8d872c817fe06553f73748bbc301aeff3ab155176f7439f2fc48596c1124ad16f8783a59a90f61f75ec9166b59702c88cae7aac422e8d2ce5d34c277dc90fe4434b091e8125187ded0dbb32b6f92127b23910169aab39f405f522f452174cb4269ccf1ea910b9b35c8fad645e72705cc1ceaf136ea8222615a7cf3c4dcb8d2b0556558ce82968ad72c26805b9bd3edd1e1a56cab175ab20f2d9e70cb5bbca060ea594e13cdb70076279f2daa682b1a9ce8c102ea6504c18be633d23429b3625c42005fa15d4597632a422d852b786b80b97a198b58784c20e3d6f7a12562f9b6cefb1b8c30ebf231a6fd972ff25ca24c9a59f03842dbc62b9373e2cd6a6f0ca197a5a827bb0734771031e17cef9606ac592a340a5a21de0f6ad05117e3b25075e41a714615c7232aadf177281cfe1c462ef14856275b951219739629ab20ad22d7ae85ca116c9a338dab4f5132171a20f617022d8575ed5c6856000cfacbde054dd940f3060225ca56e397873c9d87fbd100c2e26680cfa31b669862e6f23633560e157826ca76cf7946d31b6769ce1f8c83f0618e2ac8c96c0c837108ad21f0046f08ce2d15b9f1956bb2c9773e4abded3b6a0c31af6faa2e20e522ca1aa9f3eaca64b8940c967fc4bb9719881bd3c5abfccf6f9d1cd838ec62b496b2c6e29824107674dfd732368f89f8a77d035e3db0531964352717e9f4633ec01cacaa7f462782ddc2ed78ac101a31bf101c81153314dcb29370b142460a5ded2b1e4b40e1b343b0217639578a60097df8ec6d94ae0513b08a2ce142c6ac5a9cc5411af71cbeb57245d6b3b51e773adddfdc6b10713b13bdaff505bfed6a8184e3f63482592349f947b75d75bdaeb5d28eac0b5113277f8c81864b2b0ae446423e4d5cc3388be1e67077cb4a09847940439f6eaef9501db5086e7acab01953e3ed00fd02944dd97f8b076843b489d552bcb51da1745ad22cb1219eadd1b62f3321e5e178f9b85d6b57ffc9e7b20905bfec8d37391c097d62d97a491131d1324461cbb2d932e487c3716b5e1032e530b7607344fb56217a568cd36c36b55c481aa6f0d0aa2f689bdd55fdd83a5f7a3155625513dc86cfaa5136a32cbe57e5ad69b1d00d1563fc6d781d819bb54661babae08bd8c2d7e966097612ecf7049e19901252bc6807dc6cb343d5b4360a39076c328c7952402ca51d0b7e4775d4d5109ffd98933c84d65daebc01f102a4ae76573390afa9ddb93e03002dbd3ac38d745ce2d3968478b2bb2784af3f91c7d25b3d687871f8338247dc65b1653f5dac66dd95c5775383a36beeab079ed29df204ecb5b534c1da9c05b203557ee9540ea5532f02e88cfeffffffffffae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82ffd601c96ee4fd56003946732f1f42e1c7138a839cde5b3a4d6a6a64f86772c3d102a0393d0c6d52e7f8bc265920382645044a0a3df4094c69a757b09e6aa0e90e4db2b269a5aad852afa0371e4cbfe5622558b6fe484e47367683a1912c53c27458695f210ae097008f62c87330174e546076388819aa5f5e26806f7af00fed57a6c3c825789839f7200b1867b3496c71938dfe58b965598c33f4d75e6d7891b6d0d3c0c4280855696a43c598ba462bc2f7a311f81a7da8c3b23b02f42dfe77b3379b773050ae6313b425754b1b52fd5d2684806ef7ebb136aa0426864ba7768a82b1df60cfd5d23a34af318d2f6fa6802fa8d0264632b4f4cc7e0a7541380124b888965dc1aa2f78e8939006f41c056439ea7dcd7002b931925540af006994b7bc48c2f99f57fa5b25a1fef0c75b926d10dc1c558bce7382e71071770cb3308b5072b796c90c358c9e0f9660df81ddbc8c81ac95ff23702701d0e94f8d70b65c9683d971c75410eb4cb12598a9b581578706b340fef420d895033209cda93849bf185a1d49ea8ff6b9a8082996acf95cb796fb39506b4a1d0998a25e689d00dbbb42501fb9d0ecea01123c19bba786a608eab05293960395e3e99390d0b058b87d4a3286051e24e593a25b7ce4e9268dcb23a8c4f2acfd6c869e299126d8c8e2f3e9d0bcb4ab75092a3668c986661724ceba2a1960249ffa54f1f57ca28e23df79d28c61999fcba3e386f5ef91e358346fa1e9d5c685088bbe57d046f7f6f83315697b2aa553e977df81f4bcb6c960f1f1c29f57ecef2a89ff1fefcf04e8722ad3c9df01534b0c342f2ba30469b7ef23ee864a4a650b6b8baf99c8363e8d3588e573412d6f1d5fc9365a453b041b10e577374cc23d8debb84b86a0529775e11fb8f95cc4db221a8c740952a798e665828396c5184dc4b87cec3bae00df6c1b30f2a2f6d10f30ef06c04282eed2dc1402d6f5545ccf69d51ae0512ad74446905d4b11fa25748f9a251b8b59613198577d7e8de64ef5d5c9b0613521d6593b50c951f21d8f94f29242d2bf44a7b6a6f87e60a45583be46c5d81162c28526d66b52ab7982c682baa2e5841450adad35e2a3401c43a199a9893643e9a6d78b30e4485bf95799b6301754cd479076f4ef132b6f943866863ea3dc08932b46e51e003025b37de6a040cde1017decaafa19b70ec7c333cf63876a4233bc0c166c586f427d788a72ae95696a06646c52b5c7d6749a208ba9d156d51d2c0622ca306d243af76b3af539f7883e5415523fc4da1b4248075b8efa6eb953684acec849fda96222e2b6c858861c010611f7f643ada34226c7f330b8fe1937a9a95dad6b5bf9ad12c0502a100d6f58a110eed5d8fbe4ce8147ff88f876f15e69abf9cd46c0f796b463d0e189cabb19d707edf06335d651902401ad7434183e0f29d3ff44df5c0f98a05676cf1310d86e83b320cface61a5311c194274f4c7811bc425959568134db83475a5c6377237ce73bf327280e4cf29ed227ca698cd6d666e3492bde1addb7a3fb85a2bc2b04403c7026f41eb3cde48ecd53fad0c1bbd3a262b1d37b4191d410869e7c35ca2871fffdf699ea6b36d8a84825fb965d828baa49a5481575baf0d93c50649c666c54fa6393cf83cfbd077c55e0b1a58adf76bd6ff79f136275e3c1b819cf0c3e5d62aa21fdab86906a74007f383e3959419a777fd858ab52fa354a64e2c9dd9485e39bffc7cb23e40e1a9e66df04949848794d77a1d52f67a56a5349414320e964462376f47cc9d8ca815aa0d7b2ddda46503d2f6febf656fcae31d2a8e6ba11ee0a507c3362fd2f9ef4ba75b915442cf78425fc57b410cb434c9bc6e265f93ec07d0d238ab8cc4a3ca029b15da1a8b40a141f9cc1f9b93600c7a9a96d4c4bd7d4fa1df4cb12b794406066574bda0807b38e0742a97db04c075f5a200786cef54f05ec3a1f7bb149208d471ff3da787df2edc715210721c8a25e92b20c60da250f64279d8bf5d59be320990704653a31d6b04f422b795ffd8df2f211ee0f32407582bbe056dbe829a5e7bed99377b2fdba0a50156cd48e53f0dde0301b696b5ac410309a73b82d224d6611d4182bec06152d7aa0c41d60a2a3e17bda60d08328c616deee31e125dd5642a90753f57e2f24618f670b211c08217f79595153164647c6dcb8881e2b0e7ed0757d4705943502d95da5ea70b398f3ef104c6263efc31e5fe1776461d19d9cf9ec1459d61e2b161055f283b0a51da802882ae6cc57d3d45c441d718335d7c6c25787cdbb72a85fffb2358aea2b3b79642238fbfc84ad0097e4c9fc305af52624bf8bd111b121dc2f162767c67e4bace149309e3701eb93b38ea8e7f12736dcc748e4f7580444e26d304b2297891b3a55120c35a21fbece61558210f0f527e40c5624f5ef84ad3a1071392790cdfdbbb28242848ab37b72e82cf31d55d20c2899ad60b77320225597c8526a32d55b3b89c0ddd19daec0997a2dddb0b084b19620b83dd535ca42724ac4558b2b041ff807a1fe5478ce75d00589e5fb9c2ad61a80c6acf4d4a2b441dd269cec15d7159e4e30087f18aa03c5ed85f741ed5018b800c4122e1d4a0bc01cf930fbd5dff96132e3f066d7fcaaa0b4241d6881e49cd981c2060d93c9dadf938129fb9daa0d4c63f072d688025c35aaa4af6068f439eb25c2b0744e8e60218782902b9685ff788090650fe7a5af976c06dd69e78dbb2467bc6bd6c74f9aff70c97bf832e98471caa22155fe4b209941056ff2d5243e0cbf2bf1ae442ed1ca32f59ac6c0ebdd29e9212cf60f6388a857d43c6b104331d752c9d47a228fc720f38b76d647a8d25fae63bc7609bd3f2f2e0763773536193cc0c1a744c06fbc9ef00a078d043dddb75d538e954f385bf651b6d905a6810f5d907396502592737eb94bdfaa801bef2e4c431dba6eebdb2e175fa0d81638085d2055b5965db03eb91ce8eb0ec6bb2eaf6e30100a8c2931b7974e4be35b2101610c756f617e0d97ecb162edc6d5a66e7e0821e75be081f5f357ae59ced5443059792ccaf5e755653971a0700966fd4b61c2b31e636da602f11abe3149b818346d9ccbfb67957325e9f2ff5e2a138b125fcaf11e7be87bbb6532503e66b3282e57c3b2ce08e53fa18aed29072381b9f6ea7f33e3c99b18ed16c29ea60a104caf1bb7f03466bcae1fd2f1064830486c114056e3d85779d106be9cc2445dc2d838f9604b4376de03c7ee3c239e6f5a4dd66c18d20c5e25944b07ec36487444bc9999aa81c71263331c97e78489a3ec83a6413391c657069f92db3fdd3ef853dcb64790f1c6a5fb3ee22e085a2b56b40e39b396c0509270955b29f7361fa380d35aede0f727b6edeee04b858f9649819a071f1483f5dd2c049265253d679755194ca8255d1994498b9b66fade63f90653383390e379fbaae968e93f562d992da53298405478a2b316568872020a4013f869e553d2a795890461b8ad4d51174ad07417fb6a6b7531668ea8486aeceffe70bcc1e92136698af8693f7a4ca3cd7b74e8ed6c9d4757a25b7d14d8ec58f1ad47910a81826627d2e8d77988aaa93078d1e9b3d8993042375386f8696f1c1e848fcd9623924b38161abc682d908a9544140922c04ce01035f0deab686cd0819ad73a0b47209f1391b47d19bda9b8fb4ea00763e8725497cd7a5c3647cd538a11f9fca66ab299c709bc9b3aaa3629c77ce10e864528ed43e5eb5c7bd24ff4060ed2d43af033df2e2ed4cf05974d96a9b8f575d71ec69e2a08e09d7749c5909f424dad9fcdb2af7633aac7ba8a66c3cfc486043f4c0d50e9c0a0d43fc51c3c981f6860ba32d178e57717f47eb7297d2a394b90baeea5d0475766c498eb2ba08b17a4c19c90b33cd7657770354272afc8f6c1180d2e515a05a48505060ba8cc7b805f0b8fd532389f65f60f30eb2cfcba41a1e306c1ba07c054fba4832ee64809db955ed83ad2226487f03be1b9ca65dc8490ee690cc62d68ece8e82d7525d0a7fa27169c7b30758a34787f373245b8e1f191a3019481b919656f8463a69ce902c31860eed1c2c40a5444f8e93e19e298ef09d1814fa5ad2857e79ba452d2490ccd95804888a2a6774f048c03dd4197a76dcb101b6cbbe9652bedf7ceccd7a95866bfbe3a0fa24f2d803e7caed0d532c740939f2c77aad76ad736d53975ffa33458f5c2cdf841bf6ef3a9ec050b7c5703043f008d7c9fc052d74051f609ebdd628dec89e289d2288f281421a4de1d928140098100f4fe0eabcab8c8aecccff0099cea303f55d37d6f4e18362b57be0228ece33a0569cb49b29c72d5720a3a22126aa0507dcb8269869ee776d1d7391024f611f0df244cb6828854327fe34ffcfedaf900036d43e6f9e1074f2c35a3ced6db70223ac31f8fcc91f2e5e86df166cf904594f81ce346dc32e88d9de6104dc021d36e381d65c1a0baa13810148fb046b76b156c3f2326613b809a40d92c2cbbb98de4ae075d29258ec792c8c3279479bcd368c3e2724d487adf4449df50bb01c45ee1f0fdf8d79fa530fac72a312094c01aa21d3f621e38a8ad8c969e53059e7c83e7bc18d23931179470e3de7a6ae3821ad6bb6721823ec2f956ba2632fe46dea3c2b6f8208bcab65d9ff852f8ecb1b20523b777d1a03eea11a53215cca4f3382b9db1981e5b1a181618ec805eb6dd6e5c5a3950f0b53b819e393b6e0e648734dfe61522ac619ddfe8a9856bbf96f741d78b9348214402f76c3d1c016a9817e1bc30a7ee970f38af8eee71c78aea7e6c03cb4537d13f32ff8fb7df4b4a87df09830ab01a5bb3f966ac5ee3b90d221da8e59c579433dfb8359f22a6f7a832d51b2e8ac7e744c267114c962767f1a6ceb5628075c9f2e7c28aba5d44acd86300a3023a369ffe26ee617d7f29fcb673bf1b24dc50c9c2b8ac58b2dbcd8d551420f5d38b0a344204a904770c1d46fa19470fd820f540b03281451368cfb1858bf6cabd26b258efdf95e4ef7ec0d30c61207dc3efdbef52926675b0bdf451fc0898aa13fe5b0ac2722a3b8e3b8ca855520cc86813a68530b51280171d19ad5be1971c1271cce72675bb647c29e06bfcffac7d567e7c32b18fe9c0aa3d77e39ff0aa522ccc61bcf93efd95a7ffdb507fc0013612f54b59f0aa213f23c56eafa35b029c447f7f277a32c6b1c8e43bec5ce78b1b519df449426bcca2bb305f5038b1535893f928a436ac9b52f59f32719acd1b1f1e7420ac22f555ee2d401b1f661cfe33267279b7d56e9e00e77b2dbc281e55816f1fb85e811bc622643fa5b8429399cd2b8ad98b5f6eacac0e5c7527c33a3202a30d6428012aabcb2a8707b1b5203aeb0aa825e92bae690a98837f1fcc43171fd09c335a83c901b366937b6e22d619d7c512a404fa81e029f1888a0cfcec44d3810f5f4d5301353aa4eca0df353ae3228e7d3599492e63bc1a88ffc7ba38184f3a99fa5e41b0305643cf3076ed6213d2447d592bfb6c322a2639adfbe3de63ed63625fa6a0ed7d86f63f12667e566a2963d4416d71fa1df28168b9f6780eccf5f4fdd2cf90134d8d9428bc88c57b4210feec012852b1465aa3356145aafbd923b0d2230be2e38ee7ed81d780cdfe9c4d231bcd353363606fb71af11084c11c1a4d42775b619ccbbb901d07a3974ce2cc1a62048b93f6eae01f443846b553cc09e9d71ebfb0af8fec07e8ed0a07227d436f9bbfd3e4973f3a8298f2d7155be7c008fd5bc060a6f56b3fa345df9dc76556c35f739130525669d8600ccdadf75a3e66a25d54b2b8c6445519005869d09916ae8cd6a2ac83ec0d4bdb8d35324f887b999232fe217d31c10da5eabd3f802dd1807f32623f3b382e6feba68710929afa1950d6e121b5a3350bafbad12af654604cb475cb9c47a7d71aca67046c1c0016c1076766a0c985cdb6404321620923992916a5ee330ff0284a8161cdc1f47cd792102b0f43da5864c3283657d80a28c68345f6e0de2999ac680bc6eec43f7aecf3d174fe814b38756fdb1b23638d7de036ffb8d694601576d0a115e9458c0ebbe3880015631fcd91a2f359dd0f331192edd867a58a0c5c459ba50195eb52d99aa46bcaa41170a9013411989fc58905a5a4882da60d969284ec16c4665bee3f8316a2d910a19a8c0c478089fd95e99de3ceb4d0e04e527b880cf20f3fa82fcf223176900dc02880f41eba5fea8f78e57d5cc376cc9748fc26eefda289bc9dec84f0f3cb6fb3bad85ff98d7433352bd306915bd9a7455d310f49fd9640fa4dddc0cfac99a1c2cb11553c9b6ab3134b6373fc24620dc411a188025de02b313d09ce5908340970f9bfba3036050167f120aef33adf6cd40870c52ab6d74b3dcb4842b21b63db80111464fd37d6734c819835b2570007f6daabefb82a0c2312b5082847a57d1c212689317012e19dbdd3a1a2890bdd017186f14f3c4f5f09e383dcd5bd74a0c4c12019e9c35b65504718745b9cf39acb9d423646ede4c3954450f7f78794b7fad211b4dfae37381d00fec6404abcaa74fc8fd0412bb45ff8f5fdb65efd042201a0a29e10b92cbcb903decc088ac86a48d8314ddb2c4de495cc52ed960e5c36da833e965c070146162f9624a9d03397cf21d1e4f1d821b8905e77ef8be6ce6e7e2065d12a00039c5f2f3a1f2aa82c2b3ef5bbc0374ac86bedc3705c519ae4335e8392cfc90b987ca8343e05038cea202b969168be1a7d3a851c693f7b57dfca39c043699238cfb3a114a13b97bb84db29fa273d83013d5465abe2034e457c655b727abd12c087a1b545e526b015a70794b2ba940308af3a0150d93f5330206fb2926841bc21319f6b81cbb5a9fc1469f131a413486aa73189892055db898a86a883e1b034c2c91a14575bc1b9e2315391b844ce342011d4b36514910b92aa215892bf607793a05a1068bf18216c7ecf269fcf971cfa636d4701d68100f472dc9d6114c04c53ac2f342c21cb81dd86895e9571859303cd75b815b461306ea7fae8d05feaaf7c7c1ff6cbf7e14f3187338bcec7f7227b66a525ea6f877a7640ba1e10f956e466356969e58cf234f72fb03b7951cf1797c388c0d93ae4b8b052dd6953d7a93189da62948c1ebee2aa922f5186be667bc6d9109b6bdfc1650a693a483052357eea0cd1c82f18acb3f57aedb9796d1129202d7511bcf994f9b1675652b2dc03cea9324b839365ea4f56e56aa2951dcd86f9ea8b6fd426a5c93ffb7dc3516f6207f283330ef8b8fdb74ad6cd697344595930d554f1fdc2fb31f0435c2263ce6573dd1fbdfd180faeab8077b06a2c4ef7b3f5f28bc0e8f8eff229ee980de0666a8c1b042e361a8672da6254eae9fc0f9a25958777647b43607ef27a3579f3ff47cb50db146dca1d7d107ac7fbfb587649d8d79dcc6be410736b8a53b0a2809589c62c91e5e909bd273df2d6ce28bf683b24e5a36b3f5b3f01384d9746e0724bb41556801df134b6f35cf98bac176e94f0a4f85f0a2c7686c69812b37590b2555ecf087efabdceec19532bd77e007e9b21a6db4c9f7f2e13e81c23b0aec8c0111bfc58a67aab6ed9aac503e101d01fda19651ea2b011f8b2bf7fdcc313d832007dac399eeb38d41578f2b3aba32c2e13529886948ccd3ae079c9cf29a628022ec1a6a37afd387c001b3abeb39d04f9d01ea946b94817718dd8499a72ae82618bfb44109f89cf7e15ea949b210e6cfda0b624047ce551d4b16702927be151531be2cac4bb64f1eff7b74e63c434e055b174d6177eff3c486cdb19d0372292f08f2ce3f8c8704f42b1ae5cd00a82d3696e618533b4ab5d023af36f59f73f92a14d992f48c2be68cbc9e12d37fe05c0cd33d48934181433f495c6813e9c2787028e809608da2049f08b7ea991f8f6376b644dd788fd000226600d567d7adbf19300856edc972fd73473731033408936c1125e3b9d2c432fb7871bc77b5566ac408e73ad43e68311001a7b952f64980a5b99eaecffb24c0f5005c8958189ec595336dc8c48ddcbad6bbfa7b4ec9225190806fb8217e4f79bdb78d4e00751a2124186f8c05d33ce3307dc506f758e90cceb96b1fd9807da35c542eb3efa88b4dce19946697511adc91c6075bb519e217996b85b395cda378861fbaa57e9b91d56f07bc9dceaef9c8eafeb48cfcfc61104cf9839ce61414d2517b4cd3b13ca9761b22a227aed99d246418f5627770905ee3722e22619f17d64e02c1643bf689931715adad938c7d30e3b9597f01d3cc993ebe6d4567a9b12a217c1d793bb0aeb63b2bf8bf446fbae05a647e054f2d5557967e6788eb1eaa448bdd1113a08b6c423103553873ca1ffd1ba3accc6d324a70ba5b6de0a500dde590c0246ff2c0059b663a12f232bc88a42a5ee08d3811d672eec2b6da0048488afb70844b4799543edc2ba68771f16cb879e89be99421c2b34125512ec5f5582ad4b259e39c221b99b80e0e1ef1d35623ad9a9ce0182e7dd82ee3141f3861bd7f286cf1ebc1ac2c28700f77ab024b8eb4c79e33d165a7aa54eb16507566b4b60678d39ffb9e12e87f9b249082591d5063894f3d2dc9ce091fcbe8c8d850b627dbafe54aea8a8bbcd1240d1fed0375365d205c31606c64628d2a2ab2b306c9331da1a4c734298f5a405330d5c90da83e90b6a4b0bd256f9b651395272f6fa4d9abb157641fb5553084f80e039a81e315da3662b8c9326280ecf951e878519a4ffdcc5052f16917ea46273e398e853fa9010f2ca55cee8c6e93cce1ef15a49cbc04453815d1e89ffe180601e4d8f1cae23c19be6808e6519224bf05d50938d8077aec8cca7c6eed4ab90707a5afa6a88dff96fe8f04761b0d5a149241f2776597fbca50065231ea296160311a8585a14ea2079ee7371346c9f1ccc93237f8850ac68631fb25d8ba45497c08baa7d742057da94433d64289f903f43acab65949f10727c2e640b1d2a46ea5370bead55a5e295c6df268b9338662c785d089330e1fff30afaabf4741095c840bc6b444d5a5ee8915fb37a319159996fbcf2712758cbb34bb61880cedce54db2b732a9c64e4da0f408aab4d1fd806bbed9c29e5cb3b5514254889ff1cb70c1d16ae42b3f09a0a51fb9d2def52442595664f365b96b2eadac9ce3a3f52e5e92713fcffa49d2e8097a60e0e8677541d95b72875b83a722a2c4ca26ddbb75f87c1277d9936e416dcb0578b1e14a9f3497aa92d22e5a1ff159d67059665bf0fd33d004b0e8da9be5e7d704e5998d574c836e4f8f204220e2b432eeb78c009c303f81ab6bcdfaff154bacb7476de29c7ea890cfda8f0a781dcc22c6f726d04354dac228d90645804c62a12ac6c888a0dfc407d80f0b9c5cb9c84b9b738c001a61c0c21177919dccffca9e4864372932444dcdde8defa3dc240b7f93f248b3e4d38058879f371cbb18c4b42f557c3c9020fc78f27c5831da01be5bdcdf014b283bbb5b0924bad53bdc75a043db0436d30c14d68ed6dfb53682e9563ad88a25c0a92f8bc2453a91fe66d6830a932e9bb256d44d6250f3a31420e02d964afb5dab49a6a0f31c4f86b300d47559cb9043903533a330dde59f339848a9b0894654859238ca6ac967c0dcef2607ed97ebba030f4ac5acc32a2242f1ca708f009b2693050f322a6dec2629792ef8095ed7e1e9326216639e96df691d0f5b9e4e662cd9b0465a11feb9d743c2ba12072b09fd0e64976c8a14391cd22bfbd83dc138db1e1ebbba3ec6afb3033e9072336762fe8ed7f620041104939935f391a15b618f68ba163149a9a14e070b069a7fee1a39ffd8dabb3e0181690e59f2dc42094f5fdbf140c19d7226726765b0c78b2fc8e5c251668a46d5bc000fa8cfb67e1c5e8740dbc58983860667f693de3945e1234faddbabd6b6d00a6d382b06e4e2ac44acf0dcd64227b177d91b199f3cf81369283faa048c9dba46cb0e30d11ea966c96e2ceb213b96256c73adacae8e2c35be83540194d881785f62bebc82bef99867ea2b88e79994ad9acfd055e4c8f00138a3b3cad33e1e8ce4514dcf5672e5530020e81946f8362c273b6e99bba893ad86fac952499c40b1913663cdafe693b17b7b5d9be1c2fd686c6eb9841ada5d0aeedb5e9ba23dc3f07d048100a55e41c22790bfb8880bf15abb781a4cc8adf640c412c1fd7efcefcbf828c373e354fb28a3bffaec7f3858e4fb1ebf41857e0591048f71aa5f91d146462e3a3b1ada5aed5b68e20f3c60c1c86efb9ce3b230a3d7b6a08f332726a340d01424643c03e6a18a07f9a0aeb1c80f805383b088944aaba15d4dd7bff0f5de77e59cb8d3ee13b19dc36a7783414eaf9a0b703eac932d6127471f14ce12c5e76e451980ed2e5395c0d2101d72c3039587100e75de1658fc18daf85290b54665918b38ac1af925bef16417cc5c03a12dc6bccf5259043080c134ce4ad5dfe8dae72a53c3b5ae2930876b741f6cc1a1ca520e82feb446bf496d33854f93292974d6f02ad799a65d23fff0b550e5c29c4e3d2854c5897a948935502806ecc686f733d960f306e6a51080fb0c699870c"
    EXPECTED_AUTH_SIG = bytes.fromhex(
        "1B3A31634A0424044389256DBCA0D563824CA11FFDCB7EF0585E66C0DE9A1E861C12CFB414B2A7B3ABF61A728BF696B46D5ABEA9C62D09F2B3FEFA069AC89C32"
    )

    tx_prevout_bytes = bytes.fromhex(TX_PREVOUT)
    raw_tx_bytes = bytes.fromhex(TX_STR)
    tx_bytes = convert_raw_tx_v5_orchard_to_app_format(raw_tx_bytes, tx_prevout_bytes)
    locktime = int.from_bytes(tx_bytes[12:16], byteorder="little")
    expiry = int.from_bytes(tx_bytes[16:20], byteorder="little")
    sighash_type = 0x01

    path = "m/44'/133'/0'/0/2"
    client = ZcashCommandSender(backend)

    trusted_input = client.get_trusted_input(tx_prevout_bytes, 0).data
    _, _, input_amount, _, _ = unpack_trusted_input_response(trusted_input)

    with client.hash_input(
        transaction=tx_bytes,
        trusted_inputs=[trusted_input],
        change_or_shielded_path="m/32'/133'/0'",
    ):
        scenario_navigator.review_approve()

    digest = client.hash_sign(
        path=path,
        locktime=locktime,
        expiry=expiry,
        sighash_type=sighash_type,
        mode=HashSignMode.Digest,
    ).data

    expected_transparent_digest = nu5_signature_digests(
        tx_bytes=tx_bytes,
        input_amounts=[input_amount],
        sighash_type=sighash_type,
        input_index=0,
    )["final_digest"]
    expected_shielded_digest = nu5_signature_digests(
        tx_bytes=tx_bytes,
        input_amounts=[input_amount],
        sighash_type=sighash_type,
        input_index=None,
    )["final_digest"]

    assert digest == expected_transparent_digest
    _assert_hash_sign_authsign(client, EXPECTED_AUTH_SIG)
    _assert_hash_sign_binding_sig(client, expected_shielded_digest)


def test_sign_tx_v5_orchard_to_transparent_simple(backend, scenario_navigator):
    TX_STR = "050000800a27a726b4d0d6c200000000000000000001d06c0400000000001976a914424242424242424242424242424242424242424288ac000002de086e9d8c3e879e951dc2b4eeb71cc5fe3c034699a4ab6f6fa88a53e7a97427ad55957c9deceaee264e52a66c4aff7d5a9100f88c36cb9f1ef39726ab4400063ff6805f58f687f59c1b5c3cc2c022642f5c20fbf46ba9ccef045770a7e04f803560d8f99b83a9b769595813639e4b0f8e483f0fc217eeedba658e29bae6a9209a32bfd04ca5fc04b87116119201021029bf83d4db0f7fc68c570f7e093beb0f05606a55b7686cd42a991a1386cf5dbdba9a0bd4754a586861b8bb805332ac07c9be780971fe9791ea947c5214a3ff29fa8216c8271f7f628f9154573fe45d0defcbd67dbaf6a7f5279e6198385eab7999ccae6e6420fedd3c051887edbeb4b0badcdc601c7ac281d8399cd4d482bd3766cd611923a3298b56f1a3d7bc8bd39455cea8151b04429befbf98520c66d2ed57d638d157ab9c994c298188cf2fa1935c7e4abc4a84d99335de77b25b747b3d757f8e9d90cfac6e42dd3a152ec52cb4eaa4285e860ca14dc4b7eefda3e2a2350376da56c4e9b9adc534589cc55f8612d808f556af5bb4483d2b02d723ec7daa7236bb8de917747e997e03e1bc1c5009a63538c966b68d62fa934cae9f6aa19d06845a368b75e6a2f19ecacc2e6e2520fbab710b8c8726d5f9fb3cc2686f5eba0b60208d1a72526594b2305e55d0634e3c15a6b0234554ab6f496998766d2466aa4292d26e3f34b48b8a8f8bb734e085e62700ed282d57d548af65465325915511c6353432c2ffb510f84debbe32eb423e21b3fa1ce56ea30e38f65a37bbaf9c33fb0b9accb73e07806da9331eebff92aa50ceaea89512ab35d87adc6bbbd02b3f976b9b3256fd06163a0eb20aa4f8a84e93fd5d1f20de1cb364e01ed0a2f36b321b7b6c45418554093e7e9519dc436e59cc02cdf1fd23e59f2a7bf970a3b355741ac53d5a4c3b8850905ae273604305b40dc59050c55a466f183ca24869d4d20dc0e846a3d4c6a0254ef02f1520e50f8f5be9c285f0730a67547ee32103b1a5c8594a5f02e7b3fd61a1d8b1a33bfaf7e91f505040b85ce64c4191976c2db2b671518d0155a81d57beaf402f31e4775e2ec60e2d473fee77e126e541c7d40d7b6442b2655933efc835a1d976aa90b3b03217673049af5d867d8980265f1bf10a7ecf5b5d08b228c0e51ed7061c103f06582d6303fc20689de1dedffc26460f469602b982d68f3363b4843cb568dedbf4d966d1d7876a2edfd758d126efe1a8bd1836620f16ce121283e430b7c95be852155b347b3656e520627f40582e13f971bf3119a69215e26687dad4221bf57714aae9e61a69cda0f3407632a94053389dd8b623052c3b8b1315ba08045e9efe3a3979a4f7bd320b4cb6e0437cf32308c5d87b87339bfdf9e41de825407a0eb79aaac9e66a2426247e07fee995d3ea68b5e9538a7e80143bb49a62e0a001a5bf510593f790e4f55c080c39bac1391741d756bedd81eb33bd87f7b8339fcff2951c3a2716d1a653e866cca0556714db01f23b116d550e9f6739efe37c262214d0620bd59c52839c647d56173d78e15d7e171e65ac9e1249ccebe4e1d52ace166bb07f0b20445452c75d5f59a11aa9e490859dce7c108037b53cb3bfd9a242b88ce23625bc0a2e3f88b04abfd60a962186b99335bfd40448f724abfa2b8b804f3c544edc7c0bdb2020ba8b5ce8fcd59da9fa9837640f7079503a6b36fcbfe1399a5baedf8b40a223ffb63c675db73aa7d29a20fa692b5cb20b1e3f504c8b60e616fd05ea2b0983f05d51ffa5b2563e480efb7d5665f77f38f6db2f913b2334034a02e25b0e8898a94967bf596a19556dfd061de393c29ff2e8d6460d26546a3ba68315957f332ccb120a9a7656bc0bda47677be3f998e51bf542ca4d3c213fa33c0ad7beb60bc46da16838015183d32ad91c9071b5ee9d1dacbee5a24af746457ffd6f614341e39f45be9596498ba355d14c1e0e83c8d73f4351c21c4b026fd911e77af3efe8cca37adb2680ffa4b0039449470c7c198170edc8ed44e803ff84c039372566806661d2d274ef222f19a364e1b5b4921eb9c8f7959dc1ad859867d4f4597286647f202876b78d0f699bfe38bbda4e8e4835d7350732e6f0ca6697400933065cccbf3b807fd7cf4a16e2faa553e9ac7f672717cb45eb34bbf4f32cf6e91c8cdb623e75099d5e0eb3887e538d6e6fc102d854395af9eb750713d45b7caa405813743e6e145a48fc7d6b89933a39a56fe9c7d29accc793f8c8c30e217e69e897bc157278f341042b3d8b1b92c9134b96c36901b28157ab2de75219edd12bd522a34eabf1fab201e093040000000000699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109fd601c0a5e999bb3a39bd86ddd9d8466609a087a4e2bf7fe6e4761287349928f85c8abbc317089aeadb8b4afa62fa00595810f609205ef34e7f5288aaaade32d361b393f54405d53c096daafb5f57258eed52dfd3ea190f956bb069a880a99adaf98b75cc545e35c6708c6b31b502837e23af223ccba3162c046b1aaa3dcf406db640dc8d6bc8112372eb74cd499cb52e6377105fcc2329ae6ad8a9b46c5f5a34837979acbc6869ba9faca3c9ecbc96696d348522659b38d64cb7bca3c68858463da8289db91717b5b60d5d5958221e38faec9b72ceadcc14798aa23623d8e75b97eb0b247df3efc43f347ff6c1bd5f98e0517ce97592115d75e11b41636549046d5254399fe1d586bdf4ac45609841bd7172408c68d19522a20a4fee2a028261eb6948937674ca710e2b77a20f70cfa0b262ea8b24920301184dd03092083c7a805bee5dcc77811a501ab5126ca6a9e7933636c8453fe5af45b9e5f99b71cff0cac2303a2a43a46b849d6a13e1f75c56c1f0beb9778bbe5b82392b37f566263d5203fec63237edcb4c9ebb384e2707417f69697ad195823135c7a7e4a386c34350d1460b85c515ccb778988e18b1d1f957e5c904b9133fc44db410b31daf33a6d82961c392b6aa2be616c7de9bf1fbe9f7dd708eb41769c149349095a12eabad17223f5759a67bf8a7b377387557a3a7e880f2b6c6f1f3a5f716eae328e06298196022bb03e616e96c1c1c6a8ed5a5751c794a9964d1b1fe915d9878af4ba73a0ea2823b3493bd0cb2431a9e3143f99db623452fd6788b131c3e021f85fee63ac0f87c8145021ed8ed730313170a9d766eb088feb9c8e5e0e17e2cbb236a0c894f8a09c72acba9afe0c353619f200fcc5c5aa2a92a93f6f34a3fb1f9bf7cdb3f54bbed8a36fd5801c548f515000be2fb20ed2dcb5c7758772e52954a515a2606415b8c2657c3fe52a405ed5f160f24e99228a836287776243b5b178140f7829183038eab179f2531f9f9fc07da87dcb2f00d3b0cafe6f0463443330ad4d901d47540ab6642a7bec4cad57d41a72dbd9e9dd7579442ed12580fd0d9b15c6a09903e321ad25a8ac35a8a023859dd89a92c8f7b998930d39107ebd7f3d43915a1c07a8a19009f128fbadab7da0124630823871d00d32b22661265efdffadce15a0ffd897188b5ad02b31fc6676be8a51b037d3defb197414d5735723f82932280a3a579c8ce331fa0ce79757fda2b9977c849bb43fce2d73058c40e5231d5564f4d5bda0f3853c791b19c8f204efbc8ba7003986a39ece0994eec4209c6414fd5f9a1dae98b28de5429978c239434a66faecab4421ca7b7b3102fd455f94db6b36704c1cb90cf38bbd634ddc535fecb03c996fd3951dce201ac679b332936ab9642aff1729c02cbba15c7040807fcf7ed96862c0dedff42d53ff8805b81efb58272387a51de7452204e40dc04f3972b69c470afc5f57fd88063895ce41c4195a131c2830381f61ad0f719cb14e94acee18704f7f2fb343f9f0d78cdc76b1214f8b7021346642c9ed65f7a3d69f4bbd6c74b6eae738e3c8bb2ef254b9dff36e36800dac27b7863f99131438537e75083b231d2268215b32722a67179ea78f1f51126f65bc3494be193b24a7cf3a754286f4b8c3763fe64dc86df635ead3eb4641c327341bb48b84d3b669cf88953d35944c2b7005e879e5b5df7fa805c5b0c2c0d04e9cabaf08f99aa05e9267c9783dcca785664b69546e4d10ce3134e18e1c1a5e1e8808734798ac9c3b4d89e5d2ac82eb35d9e30406d08d3e069809570f8d0e2ee93032fa94591452c740a6b836e314752f353ed26fa18067bfcc70b2eb68d7c5379b1ad21b1129005351dadba754c464bf6cb8f0d2e80d9b92bf38ad2d8b6944f6d4bd2c4d1734cf2b2c3a4d64b4afda9494dd931283ae93499fe1860b73621e89119daeba983e5106ce7beb9cac53042958148e80dc86a8a4ab8269bda4efa5eb8a8fcdf54b137d68ad4f633f48f9680518603dd9fa5a8dd9ab858af4ec03f4a6a8bbd5f3a0c7c561c97a86780596da31e667f868739b90c0fc82069e12ce5b49cd2fa998408f34fe45e511a9c9a8053bd3dffc74b88b5e612a177f39aa837b1033884028a5602f0223f97fe781cb1704ce7f9eb9c856ade15458996342551e19a99e342a581fd8cdbef894dc2ebc3ced4c6afebfbdac49aa6fa7a337a3898a194a9a4d95c32c4250552ee76c45e4e39d3a08466a2fe496ad4c2431678e90e067ecaa9d0a68f8a2d079c71cb90730cf59a5547f2d7bc61224f2e57eaf5b0c0e3ff78dc008d435c9adc41b8682a9d5f884d537706a3cbbc82b9bf661e516d45ff5f9974ebb15478c952ead38bf754c762f630efa650195265f8f53adae2bece01055be8c6c9d24d73f5cf98804fce6d004c5a54ab4c62d3c7203ab954d0b0a0f2b8c0f783bb4f623b695c66da4675ee57f10172065e67fdd1424d0411d039ce7ab732f9cdd532393591f0a9ecc2740c50a3868c3e0c73834104543df6b4b6dd3c94f2aa847ce80e4c286324f4f00e44cd7ea34abf9aeffdf724276c46dfc9f8a14d4207672ea57f9685603dba06d9a4c643031b13c18b547e7af6ada61f644430a13149e04ceede7e3f2948a16ba6607c19c5c3a2b47310f65faf8590c08aaaf5a123e31948bd08b3ce96b5b14a5280fbbe7d62d47871885929d92f1c4771961221b17ef0c9baebfcc0693bd929861a68b33b0e11c27042021c7407c501b596a1b88061d8d1d2ba0fa9445c7d91fa43e1466ffb624bf7a19f7f34f631b1743116d77398f8d1269e4f3ecd18342c1d915967f42c71f33cba62271715b12f3ad9d82e41c5e2dbaf2ed8e4e6b613a286796a1400b85e5ee6b8a2b7dc9f2be2354ce9dc60ade8e8aa7f3b1204dae5d97da40ea0f1c944a66e844865546ae652425dea6dd0d932ffd7c9f59d5535e9baa2cf34d1fd1b6bfeb489b5ca9f143f8558c445140046433c6289b02689f3d5a7c555ed9f840cef58c26a31d8f95f7accdd690a9323e07e705e4e276dd4330497a85fcf26bc7093fb483b95dff5b86e6c3f95874b812bbca3bb11c1b1bef7fca09d3b1b7a13684e0f94fa3170321f79a51eb1455da11fc9e75e817b327341b7b46e9e04c9dd97cdb133552799b97f330e83cc59b9d2446a751eeeb3adc91e693f009ea406a59cffc605dd40c1f90e873e44130eabc3ca243be43698b8be76e4401320cc3e912cf59d2420b24c38f84cb268e7192da118e92d37c5f240f0c7859ec3fdefbc6a9a1abf4c330f89fa7ba75712e60093738648e76d54acdcd685ae7a2817eb6596bd22072ee1b53f439646aff1e343db90fc63be0af7d9296b8cefd3207e59cfd8d544996017c0b235ab7f3c6f584b419382e43789a4bf189938088a3d9156f1e07116d2831b20f1913331ea7be2842f1370755275e0b8aeae41a9447cf859056ef4d2287299771e9d7f79c9ced1698032c30b8611bce6ddd149d1a7732a06420f8523cdeb584442e990620a4b9d4b39506c4cc1fee7aaed9866a0b68ec5d55dbfcae500f53c959e5ad88c0fcd0c03c2a3b2a2dfc3a5821cf952b65f5510c0dcb7bbb112990c0b7b6e3743b9c88ba21a60116809175c89eb5f1dac0b489902791f56b2130699173b19536218c32a203a1306203b1a558cf5e8c77cee435f16e5077b8dbd4040f9d1062fb98e66a169bfc151d1f4a18292cd7485ecf6ba1291ba98d7e1a6ca54b23307735792bde69a8d03e1d39c4376e3ca6aebe49bc6a15e6b94bf6724dcbc1aa658dd8bca73f767c8138c98031147b902f7bc266ca38b6c572d3c85d8990545a1f5e577674223b8f313e37de24385afa012ed626865cf356a9d66a6f94c1d670304bc23655df0ee49c04a9f2b87b5ccbd2be2f7045735bff168c85d5a1c8bb02de609f98fb906853a33ad5ce68e86ef547004ff1a36372d56755f19003ccec728507724e0587ffc4c134a6ab94c79726e1e60eaa9d365271d5567038526df10d44c7a7178d75c2caae005f8629a27a07bc63aaa70a951f05137598ba9485d3424ffad0064a0247e313182c1c6f551b4662902709a6468fc0d77dbdc101c60b9e84e5c2d5b2da188f3d0cf623cb705856ebc498d095c338d5d0632b4ccb7d9026961999c5bee54d2362284aac3eb8bc8adc8813662d054f221c67a471eb423883a07ac05e6c61e0c49a2fa6fb04be609b7e64a7911a3e67acb17209336810ad2de3de0f5e2aace6fd382ce18213297ee2c8ef2a67def4ea30efd30df67f02d4bb997fb0cef24a6594d00e0c034ab35a9bc60816783bfb40408351b106b8d46e3a9136923001d51f39f50bf87ef98ac196f425c4e9b8c9a132da53870b8a458d1dffcac3c97af973d67a369aa8630c0f7155372cb4233b5329f2f8ad9f35935b25cd6d96d9e56f2778092c146e70065546e5f3bccdfa9f921a00d6b70a4cd6763dee90dce719c6c173c9323b304464260934d82c8bc147c433e9c9e9e75d93fb5b04bde2bf9945f7862911a01ce96040dcf5c03fc8f72b0e7052ce0887ccb606e2503e21e0add152bb1c21cb6e89e03a781bcd6e9affe1c72bc2aebf0982417993bf6bcd2d8bd17b9e8c3ec3ea97b811df482c63dddec4423e08493ac38d660c8ead28b4777d11c2b9d40c135488e431fa6c616da75cae2461dedc08144d5f396c06aae6c0498d93612d1479f25888af756589053a7ec4dc3c1fd9e7ebda11caceb02a5003e3e80c39671abf15570e60973e1efb3b1bb0439c3bf7402cc9ff3efc59b595899a50a5966434a8ef377ac60a627f80fe8c55a7fba4137cf58e92bc983f5a631ae139400d472f4b187aa02ac3b8eb173f9b9cdf93d07c396f79507fe11cae02b9c69970edc31113b1ca68409e77ab7b8766878df46ae00d6a2b516d5f53ed4d915e16855394183aaa5003a640e69886b2a165ca6f71364e0c9f74190160665f494d25bef4153c8e3b14971f45503b7c2d16edbbcbb531ffd98eeae07f860d235b7f09afaa7c369f1e47263fa5e7c8a2ada10d1d775f055b66eb25acd297c1d6ddbe786944a53c32636b66c266555cd441b63da74fc7f9855373c8a02827128c899b08b049c935f7bffdfc16756df6939246470092081f019550adb4e8eedac44abe350124d21f6e921d31407a412bc90accd89173e6be83eab68020bc58f253ac2f76a416ad34ddc40bd18365ecb39a92eecb1fab0b42f403444c5b498e91f4700ae52f32ea31650cf319669c4bbac7cfbe5d01538a63872cc3fb14ea6e6a6e57fc7767c1c1003419f1baa1def85fe82545370b754cc8342d7e8ed32b00fe5552ca7fc40e820973d5533187dd2ff93ea880e24184fd51485211a603c3b70b2b4d14e6dd83352bc37c9e4046f73f103ebb83e4eb571647a0beef1c4cf31f951a9c9b4b92a63d2fc11f1f9d7ddd8b18da009f4296801c2de6bfca6f6a9bf9be4d2b54b7157482330a9989c87053ea132b10f1f27b82a24062886656573d1790f78965cbe01ac803c962bca649356cc66b43d5dd9c296e9c61b04bb3db675acab561afcf458c5531bc7dd54a8a2580d3c94ee17a5a1ac601c93a24aa9cbdc345bd691548e04a1a07ea68b78ebf2b71cbb8f8e7811263418cc495aaaac9ec1bc4d32c72f448d09a34382ff9e6a12d3ec71d7e8ca6236e232de53cd333fc14f1ef9b661539c1bda413dc5df7d48c46924f01b38e0fc54f6b9d033f5749332025f5af1e9ec77e786320fc57adeab2d2f4f1fb57ecdb167a91791702bab3c0989257ed246d4a423ce30d9cb498772a262cc281d62a07bdab49918a17d4185266849eb4567d753c15fb1f8b45d7ff74747da2b3e0d5016d81e43cce02b5540f387c79846be1afb23072288641eaee4f278058c6b23f3535d84fd1a8f139e03a09bc7e13dd5b758afd252ee718d014b653cfd0db03718dffc2a20e1929a8f4d7092e32b7e6256e34ec9a3fb2594b0e523f99794c2dc4c9569bde2d82c21589565250fda8946a9bdbf2fd01bd7d50278b98e4d540f64151bb82e978a41d7e91b39954a2d74d9563f50db721f8b1def079b4fcba0e6956a38150e9039da25100e4138c9588085f30e8c4650cefc8a19a90899fdbb9fd6a42ef709ec7a16ebb2d38ce20d3b36c13b31af9513ddc8a165ef05844884af580cd24028d3e750fc4b1c963a760dc902734d7a5a412681f706506ccb4dbc3fe3280aae7a4ef94ced31a20b91d591720cc770a5ce31ce1755db21d17b76b5e249a03a772b03a238dd734bf0809f8b119b236344cd40dc9d02c0af564cc0083d63a930eb3c7582b613df07ee2bcf3bd6b7ac033a8870357ff8105dda374f486c8b4fd40f1a6489cb15a26b0193be1b22233d3394ebd02d8640b3e9c4971a60c1e84e821ad107baf8216954fbdd20bdff2f61f1c3173333ee761104ddd5dcad2cc4aa6a0c4fe832aa5e6d21cad2e5cb74005088d909a3dca32f1da30ff889426dd7707d000251d45fbcaac18a135783d1525e5e787540132301cd687c9bc955dd0b3d833f769ec57cd1b73aa6adad0469796824468db098cef3785dd3247487ffdc82a7d5da4e603a67b54ba48248c002cd822f33e7f34171f9ec0b7afe32c577b491cee5a254ff14bbaeb13aec15f0f5b94ccf30ce229bb91f056a6f194d5d91a716412270d34b4ddb73b1450de78cae579b4ddb169161c2d1e96de756adcb8e2f039c3eed714036a341dc0a23fdfc32546a73ddb7930d83e83da6147260c851749fef3d376747b49cdd03ce54f85ddf11a84fd4605227cec25fdea54534e3b7d4d4146fbf80be136399f1226bd2bbcc16881c1365921fa89f0b56658a0d37cabc9f367c215ee0839134a0dfbb04b5f89585a863b250bdefb250f15b43969c6d36d2ce181518d3ab7768919e18b83b62b5ca8aca2f828dc6f08ec53ed034b5ec80cb721e66d7976a6d15e47bc3414b2a2bdb41da07f09f973709c49620e3ec5e0688419341e3132506ae7aac51d0823af54b92dea3d1b64d91d3295379452f2b93f6f65c5fe3347bb5a39892fd71b4fcfb05361c9cb17448536caa6a353968115a3ecf6ccf303096b66c85fd273c868add828737c60349be7d1bb2baedf245560938564cf5e352d94059d00a347aa6487a01e07fd892b624737fb889318cd7ca725ecbec846888c82bede732fe36c9fdcf8e3f2311b219a0b59a60f11820a3af0ac181b961a79b064ee8ec1671ad67189e58d8dfa023b6042910c334d3d26c0288ed41f4794d1085749c9d0d93b18705be4207aac91072bee0c6a01aa8e12bb9a3d0d191ee1f9d1172bf447e2c704a0e24a831ad86e3105a96fccf0b9f1a9359122768d6f081affa3099e2bfda6f843e3322be14533039e3527304f9f4ca8f49d9949904ee2a55c500bf5d33dc234abbbdf208da0841aad595e1cc3a75ed4a19187089c4a9aafa15ec665a6122f6dee666a4a907b591489c953e27ec5de95e3f7e514104418e20ec99ddf8298ea2345fdeb3bba95b70ba78ec50835f39c7ee4b8c9d7ccca650a2ce2930360c2dca47f48e85b3cfa9202e4ccfc7aa2c4a32b9ee47c8af3cdd164ba76ba5ffb06646d683841e713daa018a7497e888c36a34f34987e71808b135ec2bf9a233faa60531b33185f0c3084363e2a4257bb8d13f13a16c0e7e5a83407c53e0ce7c4cc62d998ca7d31add3fa163195a1b0d2a57d5150d66bc8c8b7502abf591dfe2208e399be20dd04ac1e2d27e986f554300a5cec6adf93a4cbe99a07c552ba5cfb2f6cea16123092f8e13f2283f1816fa8499c45351154c1e6fe86246a323ada0b480e269f5f76644850d93e9e7ef02eb22161fa721962be36e8a0ceecd9d241d26242a14bd13a7e8a94f1230cceda19d74af028a4abb756f7f111a2b19220b59b78848d6396c68a41643d31921363f1422f15881129228881af21de6ce1f1d252163afb0fdeeb1745d313111eac905e9bbc505d6bcaae16cdb703e13775dd06acf7169db4a7bdb7b1e3a8042b2ceab619ff2855daf08c14b0c8bccf853785775718d9696ecd2c5d49f8452ff16979e829e3e474552e64c2e4e4279174ee7e9656765da42e7e54bf0a46800b9f3dcbc8eb3dd1c7dd4d3aa36ff2803d321506e216a01c343c4dce64ea139b27f142b3771f28750196c75f8918a8e5259b919cb641a3a882c9944123fe11cd2de5e6c87280cae2cbb6dd7f10614ca95968ee33fb0f0b489810fd2db73a1bc43109d04fcb15a25d5d9df4e5c70bd2ac92a3b1776b9fcfa8a863c22cdcf8ea6804d4ab7c889c70cccc9faca62da291c7ce1c5205b3b2ceb60da57dfdc7004eae342c500b27777ecbe10d1050b88feb9b8401d646f032c253c213ce1da057064f26587f13dbe09dd93cb76104ad1ccdcd65f1e9c6fd3981d58dd54064b8e15ccb32197465ec3cc949ea214df78591f135044702285409c9d72e9aefb9f0d3ae6a30e7afd8698cb3df67219aa149e6034f3bde9899bcdec6e72426f8c07fa759321b42aff3f513828254d7f5060c508e09b46aaff325bfb24105b7dd3295dfe6272cad2a2ca8130af7ce4142fa555f515d59f00b4a9fe57275f133840c0c14a21a1c881af6220f2a5d0547f6fea71f730d50ea1e1717102e39f6d76ea5f11731ae3c7cdb6f1108f1d187eed8af12354f90b1a85f67079c37d3bf12667b9bed85072281fd5bcd380a2bc7f1bc093871f9dc2f492cd2cd99c34db36a6e99bdd3f5b11ce9ef92d906d2eb28748397c5c54db56ef2ff6e1fd3667ea4065a18fb6cbb9401651bd0838dd5d5012ab53eb1ae68bb646ccec7b7e9147fed3dd294e0ed36b527135805bf7db58d5eac6632244dce1d1316b8fc20bd4a938b91aa438547097037fa83d5ea5703edd011b84b8eaf8754c459728f2f0ca13a06a74b9d4ecf82fc14dd88efe30caab9e2481e472220a629832856d7a18ee8af14c8ed8069ad2ce025af2392cad2467e13cc6a9439fec9494e5a652ae7924614edeafca1e4c23838260920c9d33240d595183142172f6c4606dbda8a8f3e1497b34f7ca0f94d60571cf157ec40deea47cced042c84e24c7d787798577da1e1440ecdd037a2d7c1a512d77eb6d725fa93c5e73a654c035d2c0f4eb222cf5bdcf1c9453dcbdf127a593bcc29bcd5d3379fa69af16b34770ffa5da2b2162cf7bbd52cee256ee58673718df3cbbd73e6cd8f6c7cf2e6608a3e2f34eb77b1a1c11b9dfb8b3437b008d1832325ab30d3f11cea3325053723659d325a2b1cc2b67ef163efd98f8144e6c4ad0c117f059f1edfe615939acb73dfd473fab0983bf9e0d6109a769882e235278b3d6765657c4f89617e1869ffe610f3b9ec887957c70aaeafe4e1a6ee24d567862a047ece217c628f1f5e516e615c7c14d3fb261032407806d3c20a79d4d06e68015c0c89d4014fa352ad4637690bb292d7554e1b98edd20d3dc26529f902ce3226529f078084893928703d479fc3a20af188e778d98bf8e1cb14c85d77093d0401c69f4b66ded9c49ef0ef4edf2ae4a88943010c9deaef21eb49431de3214f3d2eb6e44c9c68e5be9fc06d5e6353f959a440ac65571532830d10393c4cd2a2ae8f675081fcc62f951569ee0836010e235c918a4091d55121d7053ea39fae04b426631c63924232f86b12a0f8bba4d53940ec86caa1e3d3923a4c23b6f239ab26099ab8c7a3dd8427baa809119e2b4a2256a7b81d158d387d808188c6e3a93e69af79e8818ea5e5c1a8eac301e098a28dc239c434df4b4734762dae13e36c90d1a6eaef745c6fd7bc804021a5c9b44d65ed6766585ed4a8d428326dae22a960a20cd07e14b4842107db1b2acab8392b871167c50ef6d3eda060ee57ed03504420b55342e7f9826865e6863942427635087d6b84798c2c5114210523dfbee35afb1b8ffa923b2865cf6303e6fe233689f19f495ae65f4a38e35e73487aa9d33b012bde2db0e5af22ab58a83f8b32b7577634bc77f1892df01896eadc8612a4a513a88666332b8cc8d16ef93587bf8aac26117a177073b783b6162f46ee03663b22041e5c07c28d39410097cc1467a465e287d9e2fdbe20f669fef92b2e5af1f9f7b39ccf2eb8277152f8ae81226d1c57ca1b0a9c1a08dad4c865ed673afbc07f32941b3e19667ae060e3ec65f492f4acad994b07cd26a7d76b96b6959724576c4e2341a81653655f4b693abba926cf1bd49e7ceee15c954c8bc118c6f75f6a2f001748af43fe5a40e29eb786085b82d63d894f81e74c959177d7dfcbdd5bca004213f266c72c82c76319b4e4b510fbcb25a54df93a8f6dc98d972893d83d10110b939458a8cb8c18a5406f49cfe54a73dd5ed5a5c40aa468d2c2c40361afd17191072f4f9e1a25708b2d249a45c1442b88672c003f3320e6bb5995763068228e84b4d10b8220d1f1a594a4c677603e58174fd5586ea68a66a52b38bad1d3932ca429cc614f1790925e4a436fcda362d2586ffff19e41b8d5f0413a2c5d43db7d4bb7b732e40bfba2228bc1f5156821a1b2968c97eb3fdeb2a8478031cba0bf11e92d"
    EXPECTED_AUTH_SIG = bytes.fromhex(
        "4B0BC7A8C4353F9B10F1A6FA309A079A3599A5C942C57A6769F721263674B702E885BE455ED6926B90CD54C406DEA2072456251F9E9B074A4CE3AA890BED3D0D"
    )
    _assert_real_orchard_only_sign_digest(
        backend,
        scenario_navigator,
        TX_STR,
        EXPECTED_AUTH_SIG,
        ChangeOrShieldedPathKind.SHIELDED_DEFAULT_PATH,
    )


def test_sign_tx_v5_orchard_to_transparent_with_change(backend, scenario_navigator):
    TX_STR = "050000800a27a726b4d0d6c200000000000000000001d06c0400000000001976a914424242424242424242424242424242424242424288ac0000022f5aae0b9f187db35774b6a8881705bbcf2eb0ac7be56ad2ac927d9c3e899521d68f3363b4843cb568dedbf4d966d1d7876a2edfd758d126efe1a8bd1836620fb349d7cef117ee3c00a5b3f04688064df7384ee69e9996c0b99393dc26ba2bb049109401ee3ec99022f47483fafd1cc786b3a24a03924bc6d0c0fdc7fb076015e97dd4f52670c52acbbd6316a5fca101b0c33a71a3a79445d3cdb58363be2f939194a8602be00f4e035fbd6c598f2c16e47c5c68809fdca0e2d9db0ee960e59e93a1f7b4b49c4bd36421f94194747c6a0ff0a2cf20d7bbf703d46b67ce11ea6ec2986a632513646a8a3d49722a2a6b85b4d7040a4321f323859be6f87ea980d3a9e4f0ff0d5b652fd2485f967f16dc83348bdc78e63cdc60edf0d768fddd71aef72b9c7db1d17f7ba4df42a68cc4a011004baaa6829309237a0cb4ed6d38c1569b7344b56db6f69ac9ec1dabae44521f97abb45b5fadadbc8e623cc4e07716dd488e4ea5d268ae04fe39c267e140389fa010c91acfd2fa8c702cdb4a9b7d20b0e7d1fb8006b7dc576a6a98b825ec85819abf910df99a5bbb3e0c7ff28b7007fb081571d4e6bca0290dda73b60522328401cd1978b1495c24e7784713897b608e36383b254c4c4eb2d7ea590c302d3cf1447433ab09f6cf66cf9a7275bd7cf10ce9fbc4127eabd378af66184b74a48cb794ac46255d53584b024404da66848b4a94a8b48266e01f2934890d172a818e9bca6c7cc3662f040620e3f2a0a1c5093df1a02f47f04b5e370c51460af8abdcb24b808dcbd5597cba7f21ff1773101e81d61b82dd319fe4b45416af9987793e4ac959dfa73acd3499519395657398c31e7887f9ba0033deebac685737ed4f96c3686fe169026f7a460f576f50b9b8de6ac4a6f7d0dded364ffc92edf0be4d926647684cdb72c307377a99aee9b168557a792f8d10254968d598c0626ceaf658257b7d9511dbb78925687e77c80f1ac460e85a861c52539f645cd595a273e204d2ab987610b3f86f79365dc20153e5c4c32f9f30889bdd58eda5ad9518dc15cea267120236d9eb964c6ed3b197ca532d3a9581c77bf27c359f3f3b1666e3ac3504c17e2473fe1431e8c761680da3a6c7386815cc717ae741604fa5d5a5fe79cb3879aa7af6a33ef5236a0bbf46dee6b44320fc293f5ee3238fbbcca7d7a6c9b20ac2da6138ad55957c9deceaee264e52a66c4aff7d5a9100f88c36cb9f1ef39726ab440006cb487269f6ff211f30c951e3c530546990d7a2ac2728f76415079b8c3b6bcd8346ba59eb9cbbf5fa129c29fa0c6733af5ecec1d80d8e450a93f6d910ce608f111a16e26f7c5ec1caeb3549893749a2e912ffcafe0dffa3ba6d78a4656c477c10ba475e732850138870cbe28ab73c29d1d7d29973715d6102287b77420dfa8715486f999f66729d3891ed6f0cde043013091bb28437ad9f57306ac3b8694da7727796ee570d690fd6dae42c5cf15f5751b38130f7c48683852605d68cc3448000af3386156a3e4c4e5522dd9decb8687d2dab1cb544f50ce1296f93933c47fe6fae027fafc9c01194ae1a7987a42f526679154910e352fb45b91dd93922097db44592d185a3e98e621ba913f6085c2a11af6b42bca643ad9120e35b35748e2a4f6af7dccc64eade91713ff27c0eed03caee6e85953bd38fc0ed76c189b2957ae1fd56121aef7de9e9e95d9413301aa70ac858a4f4b78cfb0670c40dfd4f65cd6d6aaffd4b32b4de820b0160b2a5d2012bfee7b6315d1299be3faac1fd92f43cde408f81192d9e68170cd5dfffdf55b4e5557a8ee39fe65bd27cc9c9a852415acfbee22577e1f24a4244c1180477111a88992a98450334f3da859d38403cc8328d4bdcc344fd3dd93e659213b8967edca63e3976121df1b59affd328307778ba1368b41e4782bb7094153321dd7f9f691a503dfe3e8ab40a280a189f9f6fb0d9009d1d48db883f63dfff7f1945168942dc46a1a673bda727405aab3076599d8dc5a8d047fdc02c33b74baa189bfdc5fddd93ff0a78708013f723af3dc89c91c44cb88c190b531092a10bd4caa277347d03651ed81826682bf26f6557ada37f0d4d9a4e9259880dda9928099ab729136a0eb1bf47891789c814c32b738886d3caed34787fa3cfa5fbd766ed2454e365b32d2fbfa2dc96f359bbcb4008563438b4adb5e507ce2c67f43c51278361143bcb44e4b7344bb1159eca9482e81ccdbec33e372dc5930073e0c5721afd2b37a2a19bc8d00074e7d37de2ef118a1aa39602c1a15e4a784b2b137917be051e62ea4c42af7c34e1035880040000000000699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109fd601cc4b073b76ebc94a246bc5a25ba51d065a845213d2e8e715f766aa9cb2b032302010288f0f218c2645d3167560c93a8475474702a780ee3f62391487e51646e038317e2fbdec254db0a2a3d45a3f2c395aa4ed9b37f144e0d054aeb28d3f0e999b00dc10b4602707870eed0d2d719c6d64eb8591f83807e809147a63afa7811229a6aa9e3f5a1399210fcf23fe64c4e56d261f092dc7071989f92721ef32e518813143289358c9ba24c28751ebaa6521b539339748376ca16db29f64b35675c04532c3576f117bf3aabcf838f4208bb8623d1aacde8b56379d5c8c44ad95bb53df0c64d1fc7f32a96275aa5adfd0566589e85c8daac2867bbf71ba911f14e670a83033d5ae2115f3bee5d918dc9ec7eaebf112097bf5e785b494809e951c00919111b9be3c5b4d5d0bd7470ecff2c0ea5d3e1c5a81b2ad97dff6ddad2627bebad28d046e9620b1a9e1413669813d8d879048d2cef6988a2957d91950cf35752873820d6bfb8c3f786e7d2447546ebcc2b63db98d2cf73bd358ddee4479b08b2b20538f4ef526f67ceff4f774daabe9d534fef4e73e428aa726d9bed83af6a36aab8688473a92b5887209a82cdfd9716a219588c2e68d102c7cf9ec34832bc9516825f194f1dfec77eb53f1f7597e67f22245a086b8f171aa4d7131ef74b96a2b0f4de3bc2799e9d3969d5a0a03dbe422521f3c2c1598178d03bd23b973de1b738bd85f008472324e7c37e1e7f5fb2a8d7442272ccb9e726cd90da6fabe97b5fa1967dcf76a89c3f4fe83281c9fdc7875d47db7baa5a8bf204469dffb9128fe9aa66d87d286e68933322ff3c4b8ec414f2bca510e20b5fb5838ddf61d254cede082381591d1e325d3822a657854c1e152e4f328c80fda6f660961884feb173272a54b8b9886075cc4b2a2b40b46661f724e8c58394ffc3689a4235fe67c08e268eb6927d1939180e0e7f68ae4a7162ee4b1809d2e3cc4316ff61038fd8cdbde53dec2d0f5a85aad829fc77548d83cc98847b520ebe0d14eb415b30675b8b9f9993d346ae102ef90eb29a32e516ae1cb1e06af51173a3db2fb5cecdac746eb5e209e38669aeeec3a9e09ce9c76554650f7eb5ede7bad955a0c0ed9e4d8e620fa20dfbcc353900fb72577f7e201b0b47a506b078374417b90ec35a84a0e213bad2ae2026380164f79f2ddb1c72d4446625ffc293370a2235b6d51183d0dfe8c748858362ba2cf1953dfe542e02b547c7e3bbcdb49f134e1a2675f3fa73a202cf253c65bc8033a34e2cd9fe3e2d94f0d07e7b66de23e1c044dd083db4e26eee6ece0bfcd53548e70db0668c3b6807c96a79dd28708950c48ba10fda5936c8935919a9bbd90629e6621fc02d6fcbecf7faab0827b27c16526edbf1b221b41921387aac2a8559c231bcb2acad3759b137ca3cb4738ed1ed2b9aa0d29cb8e0ad5ae64b23049ede571bef067418541e85da938120d8edb839123e58318765895d09573c84808a957af5376445bc31722b543e5268aaa85dab5782ccca6b59003b76cdac3313515f47653b8d7b21ae40686ca0d266256a00d547997ef0798ab654d60160ab3c0fb5c584bd003f6a3b7536f44ed7033903d239bc2061f33b3076d9a16da58cdd536b61df51a888ecba334edec33677f10b0bafb7ecb1a7412ec83ee6d0d21cc5ab4306d4ee68cd43c1d0280087883d34cd9f6d2498733d62c61b7a89bf780424a6aeab4c51cb21fe18051494b8108b28bfaed352f71fb499d4be8c2ddcbb9359bccc16e7798db7ec93499ff27af8e92140b34473db31f82a3401766c425498ddbab10715bff397ab48232c08736fb4aee1aef77404393563057b768741dca10261be187bfed1a9e771801f6b3143a7dbee16328d2b600752b19b008daeef06b814388c958d41a3438c847ae8fdd069a9f7919c0f9dfacd624b1de47c112a3ce94399e82d7c3b09ae7f5c57045bb15036dd25f288e17a32d292cbed3820a9a8b1c6ef35b4d7f20a97c93ba4fc59ae575e4ccbf97ac8f20821edb5bb2254df0fcc9e15bc6e8a044228e2beabaf9efcf78366ad8f57f7fbc7f482927ff21d6d993ce0407b2b3ec3601c5ee254c44072a9c62f3d65c81eeabf797b816f16d1dfa82cd2c6043bb034bc6a8591ce87edf6b742133eafbf1841c32265b358f8e743ae680991a33ecf18434288186b069bb23afe31bae83ecc4d76aad290211a1e310a21de4bb1289f2141bef52468e2dd31a7b8b7b45b31b49d9417088365a68c0f906e6ca247f9872138c6fd3c249887c02696b1c8eb74df371e8fd71a4b577fa40dd945c3c0086ae10e7c2cdecf34e82b517a2b0ffa99f1ee5971082a6900eace1c39079c991de18e08e7d5ea780d426cf9e0857c237d5f6267676ff559afe2f393daf796da6a1109cf364f121749f9443e64a1f2a62fe9af2a22cc5b20d52efc0f4ad6cb44484e06e15a96249684912f0a449d7a4b7683f0edbd23f408900b7612574c1025596a9dc311b4a195b685274730eece5f54f1fed7d0f14c75c19ec60a708ff5b61de808620235950592916d3e9774f30a3bb6104a0d48ad36bfd74f3f8cc1199de93bafe2b0f9325a62dffacf4ffd9fdd5ebdc55688e911e91cd6c321750ee7634a8ccf3803f58164aa741315466fbd0350c2017a7d63270db6204205c817c28706cef21fb0ecbeddcc56cdc359183ea05be7ae4b71295bb324d5070ab242c75be14166846ea0dee24d11e565055ce7e7ef1c86539a2feb0203d15312bc8680e5c3f831eff5e14f7c92c918ab6e67f75ad67a5bc9841d5f137bd27e201dcce072bd05d471a480ec717873763eb9839871f3459b75b6e87a40301299107d689eb23df3f49ecf71ac41b65880a6a0f34e9a0c826ad84e0dd79d5240292af04579d7dbccec0b072109bca2abea165bca9b179e2ff4f6e0da9138b58af92ebe529c76f80f9d8f1646b3224ac27c8d04ef42457e394bb4f520d97a030fa3347d79315700366ccc278935a1a4dbb18979c443603501c73dbc1eb4a841d0b501332c8a09ff50e684c06735e3695ecc33d4b53392bfe3c02fa4720498c451f935c21f0459bf99eb33f1a369680515568fe2c99815dd2dfd865dd8a9ba5cfe9c33de1e6c2ceb43e794129c76a5efc9ebb0d36f4468f552f8517537441e7455a730833d4af59933f83c320264e36d5e7cea6a01767f90ecf7b64c2b9743038b143cf8ec72051222404c8b13672cb08206273eeaea481bd67ccf3643bc6dacc30915bc8fec63b58eae9ffe7ee10f9a88899823aafbb96a703df4f1fe162315f4fa0d7aa7486148feb1641e380cf2df96e9e8cbf4777590da9e5bfd818e74eab9ea1d1b6c4b8404328c771c8682e0ff850e1bcd301de473f921638817115ed0053a3fb0c2cf4ec8e3f04075f6b66a8ca1d83802f53a4d48aa6b7b03d444882309493477e06a992eb88a745469b8e64a47fa484a7d5c98419f918104c8b778484e6d3a8301360e700fb3b4e6b5363679a36d5cc3d6b60a04a8beb46685551a93789c1944e25e235cc175468d1cf8fb02cb484c8fcadce78d48ab160b30b0d2cd98151e6c8a6700754efde0948c6f0554cfbe0a57f48bec92d663335cf0bcc4f92bd217fc5c7f45457e293e4bd0005c764d7468af364b1b031a9f438cf432c64809931191a246339a11cc1a893a1c8761c83f32e49937e403d37e4e7724d03ad74ae513157e96074f7cbd25f96cabf7ab66c1fb0e4cfcaa208ec2becf6583f46685110f9231a9278512cfc4f1961217732f8719bae87b9508addea236fdcddba2422624830c89c8178f21df454d434ae436604a14795b3da203a3d2057ef96965e0231521c6cf56c2f960ed72e130ad415137c5986d31b3ba7cb79e83734db82df1d20a8e83300a939d685f8a63a0947c3e76932e31eebec01478800c7f4bb07e2f82297bbc90e392edd6bd8e20f3c1358893c082bfc0ceb071e9f4167ad2faf25d4632ec9c8206c257585231b7c7a7443e65245be450bff0da2ee89270fb005e7eed35c4d09d414efb59abd2e04e3771b628d3e465915ac57ca5f79b7c13e578a4fc29f26b78ba4901662f807dba7ce58bc4236dcb3bd527c02870894a82090095403eef02109b6d36d2e98afda485a794cbc479717727962c412766845dba5575c5384fcaf1ea151e126506e621d8c39ca047af3f5694e5a31ee21a93bd33f188f62b23a27e3fa13545202ce5fac30d25a399951f37bb213a92e69ed6d7b17940d83c90caddf7a8c8bbf99df908d85434f664f349fe7ee68338dbad0d2c345bd6a7384f471134411b11e2f293d0465fd267e26371193198c92d458d03e5ddee53b4162fd93a6fd93bb9945a77ea1ac4f907d7466abc6445c75936e5f47d1939850b28d943e73c7924aff51e2520af6263a6bca7e596704118b6fa04b50927a81148062dd3509cd8cf4e0fb38174205c603931ec40441dd143ddfe1e9a93c5bdfcad3495de2489351936940e9704a35620e6452232d24ccdc8a9fcc99c4a76abcb33396fe4e7d671b448ebf9143382c9f1fdedfd8cf9b4143dce3adc62d4c3e6de3e1849a618ccbc3e14b511d1870aa0b4a0fcd588feeb6922494fb82d70ac0cbae1365cf96c65e58cf761330aaf3d64cf99aff928e77c36d0e9c8aa1c85817e88811b99f6e904609bb85c5c8ec8eedd52a0fc158838f68d3fe665f9f2897c2be8981e2be3197e361b7a03cb1e71f4ce3f23fbf3cd0482855f3088b67c36e3cd039a321e5ad0a1ee7f8c0cdb4a6a0c60dbbccabd4771539d4831a40f6513d873211435635eba461855041205d751bc28b2e7a275756c53e221559641bdcf480130aa078ace5d9f61c8fd7c5fc0c972466b4a8c3f828b1aef2af5372e2d79cd0844e412ccd186f5c2e506b3e0216c4b37f53c9f5536157b3be0cd1d1f4d62e3be3c0125c1131fc26f065889f98e7ebb9b14ec83873b28fecdcfb8318232d22e85770607d70c414eca2c45fa5319b27605c66c037febc72cb4ed7d810e7bfd75024f8930f3cb6818d2c94c37ffd4b2bcd494118019ec67553a9f125f8a318bccc8ba7037157876bb1cab9fb16d7725359a8a893a9c72a5e2fceb1036dbc7171a279c2533d332ab9a0eddf7710dcc431a618c0e1c9a681ba596b09c693f1656aa4cb460006e8109a778108820e981958f2d2bc3bad4f9a37ca41c0cb0cbf9b0ba8f99df2d9068d220f3360f9534eaeaf16e35f1d35ca80af27c13d44f47d99c57e52fe52690b5457a8cb6aece6f16ac72be04864e3e82b4370d57d4fc0f59399e442fe9031a0f27b0a84804d29d47020bbfc14d973d85f485e9a211ba1612a1229c8dc331474ca055b9710af2d690f3e8e3f042a9e106cca122383901758d17758cb9b337be952f0441bf387984d177d6d3dad8fbc5edef0b96e3f0903d31472feded9436293c81b7ff62edd75d2dd89d45e77c85438b46d2fc4f231b265f9712d18e1607aaf076390225213cdf7396f69fbeaab5899b973d1fcd15281e55925298834e0cb49ce54a9d4782ef0cbf4b31cf107fad2c1168653047c229268770f1fddd951621c08541559922e00663040ed5e2ed67697fa082ffafd8b4ea11d968f2b48b0591f6283b44a47f9a4b9fec2b79a885ad301c071fc70bb4b9750a240013f47d05a8db59b4c0865c6d9e300e1c864a46f6ea9e5fddff86e2ff88210d3059018a0fe0603a38d30a84916fdffe3af76be34c856382b887418e0351f9c76fc92e1a25a3277789e59beabaf4cbbe91175cd63cab581422d336c5d1c1d7a580a79eec30662756b703e891721b73198f152cab09d7e48c9d34534e4504cddaf8c7108912d3a17eda4c2be246bde5966a27ad118529a20ff1d599e3f22ebbdfc762da5d2ac1c5f428bdcaf74e69cdfbf20db6a010cd4b384be37c01ce684c7d398d12a93e9bb14c3ab6618e551497a003fe4b83819dd1c43a3e7cb637da4ce92985b3721b5c1fb856af542a92dab26cea268d51eb92dd0fb191c8ee9248d10d248ec8030499d5ad430cc1c2a4664ec69ab42f46f85c9fd33bf318d8e7cb9261f374761f265fcbd941df1f3f1c4d795add6bf03fb3668fb9289d43b20de3f4d1a8265f4a22c91c6e2041eefcfb908da4dbd9c9e68387f8a728b978d97556cbfbd112147e0deca279f19dcdd01acb020631887def3b339b5b5a70b7d36741aebe247a38ca1f1d4a4bdf7f0397578495f4a5d6cf2f2e1acd9c9e328a8341e2b86203d68f590885871d41be582f03c4b6d2c6775b36748bf9ec9d7c876fdcac487091ae89e133ba6e2ca70fd900634f091936c8dee507e1a5050e05231c2a50f9d35e413f101bc4944148455abacdc5ce87d11c20d9b50b6d698cd7f0921348c13db4c843f503309f8f94eebc454b40ac9eda2fc5d57dbb69a710167ce8d062561ff3e8957a072b3856809270650b2129a1fa373a4c7f688ad94308ad23ddfeb5f0b0a7b7b32de99afec7d0539d32eb17872fe33295c6b6fe2c6e2463895d44692b15136e020b9740f4140dd264699acdea77566caa2a272201da82b3209077f8ba168e15381d0a01131cece19feae00445baa0a2353201b13aac69b9a3f9f11cd177dd8bb622afbd22b40b72ba8f5be8eb87369441924a7f7931d4063c1c149730eada60101a3b2685e5779780e4f9a747b424c97238f4adda9687a4a806a92d518277cc33060f48e80a4dcc11543ef5edc9247d9e591ce3e700da984a9a8825efc8d08566346c76c01a8a3a9bd196fe8ed93e43057e3e02b73600609c586031602d7d49ac00ae3077f0bfbea35b8a10fe4539d1b9d7f413f5bfa8a8ed3fb5ad807b04a23328519b26d7e556ac8651492afe7d5305b852cffb413bc2b229352f81366cd9e227387c0d9c091b7728e82ab6f582a2d35ab0c5ccde4ddea6e4c17dbfe5f4313e39fd8a5633742829ccfc5bb91f3f935ab81da500713c2f415e110e2148afcb583aca5712344b1125cdd28db0fa0ee575129696737f6ab1c06af46d2d96f67062003308bbec956c1df1623f5fdc1b8a9668f7f490c66d23dc9d329b38aef0d98b017cb6171052b9789cb1163d2e4005c0ed05400d8fed029d0730c72924f536a63b633570d68f1d1a9ff72f303b185b73cb457b38b57b856c5f665bb4cf10b9ee0fca2ac0fc6fc20c5a13d507737d21d0253071e3bbc54f84723c8829b1d7b177148c1036524d8822869a7e1cbb6a96fe0ba255df1e3c182b727504270e72089929f6f036adb65561f24a98998e15f6e0d182eff1317e19b5fd51e6847cb1b4020acc98f27518a000eae9193e6f5596ee6fa395faadd48aef09c0379e7ba479242400c7b11d9ed5e35bd1e4568973f3138ce703dbcef26ff30a3d08f9118c2e17384c7c4991b13e395bd7baf404ecd3ba01b87ac42c0d7fc1bebe6c7a1723706f29e2b08ab9656daf8b7284523dc9b169cea8b4845d4b0e37e00604f8fe2d966404ec77b53fe22339e4021f70f7ef9ee38f12e05fe198e1115fb43f93264c22d20666f32751b24608c9bc5d9cc981da700fa932e48196b1abd42058bd7cff0fda357030683c728b8d00581cfd19a35ce91ed7e0e4af2a85cf98f447fbd20008493538465ae6b24b1ec0fecc030802523b0d85f7f5335961b9ce5e8f0e1e7e9dd413a04e798933de7892f37cc3f8851f5cae0a284cfeb67e1249721b7a9ef373c030c7ff78554e4eb04ee9037bb3c47360d2000d4d67c8c6267df7b47683cd8fa12ff8d35fbac473a95a4d54376bfa452826cb2cb542508fb7bc6a7f6a0f4eaab82da57815d6c7eb679f6e5d1dd02d8a290c319e4698aef94da35bdc84d8e880283d8cba2a47f3ffa58b4622781360b375b8ed5191842e78adac22b6cb6f4e1cd628f9eee5a32ab6cc5fcd7f75235470ba19c81a316cb48c5ba5b423097c203a5e1031e8a80aaa0d2496c3898b045189a3ffb8ea157a044bea96504012c5bf3e282cdd6354c9f8c93fd6d72cdfc54d218bb9384fb22aa6ea670f14a3c369edf243159e9354cbe7f79cda58d76d3f4f98156b2384ede1d513e66c59fa53f409efe21ed35b6d2466b3f38d1baccf18c3463eb6c84ec4e1d470e77fdf23104cd9539815767dfc90315723cbd96717b10465e9f0ee6a470631b71bfab5e1e3ffb9e7fe31a09bcabafcd1eaf07d6afc47f363d41ca423f66523cf00b815a5f76b970714273654a4f0321d94d1d70574c2beb10aacd5a629f3ce1d9f758c9ae3d721e0031bbd1ef1155619aa63190268c6f7c7970a86298322396ecaea6c15d9ec308b743fc8637b2afe689280581999c855f98264c582f6e248e033ddf2dc8fd1dea8e235a85a5dacf920732d334d6077808ff4365bb4ad3965212c89720fbe04f8653d181dea4cea6cc7f313e4d097ddf717460510965ebd3a1d21ced8f2df176f937c09e477186f2584d207fe9800b1a40d718df771354797de2b8b837ff47802bd9b3848f8114131956ba6a976a342b0ffb80e22c1232c1643e9ba3a97d6104f94c425142050092d0aea75644a4c4ea5989c2d184c24e74f534737fe37984ad753c93860e89de4cd849aebd5f911fd516ba9356394bd829098fe78165c505544c79f160ca008e519fb60ca010a926057d1c8960926b37e8982e071da5f77e968f55d34bbaacaf6101786f4b77c28b54fb3acabb6d65364d4eb0de027ffc39771183500178a056ef9bc95737d9652f7d284c21cb4384bccdc232568f6a85492fbe8243ee41683ef75858356f05b819e573c107660016d7f6d639dd7e9ca8c2d0fc7873bb9e3d83f94984e459edad38375bbb380a6e8117e04f18db9284d8280782baf01ad3a83b77c17cd68f9aaf95f88a9267ebc7aae26fe1356e5c79c1b3dc01ecf14c66483539e810af0c118e65e5ea048ad85c64b2073ad6a6404ab1a1ada5087917b49a92036686f652c5c4ffa18b2571e1f35adfeb81917ab2251ac802bfbeb04754db971c9c3677cc4f4f58ea2bf38aadc29c74af92b2746a47a5949ac4f491ca68957b527f04d25acc248dd9b9c0a39808da387bb61a0a28a196794af4c513eef03ba03ddf928d5b9b48be8b7bd1b77e48b68549486a3aebf9beae1a9811a1e02ed97473f0beae7ec29688df694050391a6854e38efec4935c7230aae79a7274eb552885949e17f53eef04e4790bf602273a27ba4b91bf962c432e4d8dcada50a30000c56e906f8f31f9b765bdbbd2e4ad4b640094f86627fc92af2537357b8594edadbd4fa2f6911b80f28e29ff70a7c96960b2a139cfe6d0986c2dea8b3349845010528e9bc20a833094ef7bb50bb8947a0afecadaeddd3c3b63654a1833c8b5b423ab9ce4e4056989723d8bf99d669f168a5514bd844d03da60375f8f49937f8eaed714a922d07941bf57cd03113567201864cd790d53766b718a7a38bacc52361ad9baa4d6d1b3261b4fe39d0ac18731fad126697d86fd6978b6a89c82a0292c6057922a7316a0bdd187734463de7dee06b1aee8783f2c9736f5a8a98b95022edae1b55524034d52bb67e51e809e2ccdd7368b7786c653bf22db11e232777723d9f270f75034135444a929f59e8605cb9c8d2613299913482cc1010f028dd7a9b0f2f749c071ed0e1743dd7d4407df93d730908d1575e6aa95fb67f28b4dbb35bd536b904f4d99e694b1104d466fb3ac10bdfde4f6c56c50d7702f8038394cd851b8958535ba83706ce47bb8d5d9f31e1e6ae5399f89a701d91519490aa29ef088b24480024eedbb3cda4b3dcf0ddc82fb3a4bdb02f0c849af797457d0f801fdb296dc36fbea269acc95e71550c76610c1f36b443f5174ae69adc91f6b391178ac78a8689bf93e3b641efabe15a325e8de00d4ce7ed849129428502d8050b2716604fa42712dbc7e190baa8466bcc4433db12123c59632d4390300db91fa4ddc77f4d3a03bf8ad4b8187042a20d9fb945135b2033ab1b90c2333443d69b553ead7317bb1c31443dd2b759d4ae3135efbf9e8db5b76e35678156cf27592554bb70b3117de9a64c72a8e5d428b8cb6ecb453f20e03504179f2b455e871d8e6117af1be22769e24ebb81ad7bbf87494b251e58d454153472ba35bafaef12b09c3f0480330ebdf42e05023764ae198e2748b1984d648bc125a6101433fa991d47f9cf28f9d1953dece93b45bc215908f3609be29f428556b7310ec453b208a0fbe4dc67652730b738c8fea8f6d4ffd0e4af99d1bb6dbe03c31867d1d18923179e2c227f1a4132217c48402fd225ddb2f5d30f1f6b59a0104e062bfcc17361172a8f6a07f959aec5506cc813fd54631dc7bd6c9b413a46cd985514e34b7dea0f2ad9d80ce0eeef844abffc32000cba13407677d6f5b8fba3b6d9ba8c72966219162f4cd064e383f4baf378c119482c4612268d39511c9189c93b9d5b4b3045b0f404b298ba14d20efbbeeec9ab7e609a6e63cb6e52878d292294926cc489680c2947f8899f75417a7a390fdf8557a17d5da37344b5964e47c35c85d428d4223f1bffa72366205cced37e0b46a2d5db348a2d510afd4d9ec3c1492644cfdf251d"
    EXPECTED_AUTH_SIG = bytes.fromhex(
        "FE32D099B7C4198083B82C4ED97F168B44D0A76D395834A316EEE5AD3785892EF45D15727D41AEA0D5FCDF0A1DFC3AE1418E6770EBBC1D1E516D6BB67EF2CF38"
    )
    _assert_real_orchard_only_sign_digest(
        backend,
        scenario_navigator,
        TX_STR,
        EXPECTED_AUTH_SIG,
        ChangeOrShieldedPathKind.SHIELDED_DEFAULT_PATH,
    )


def test_sign_tx_v5_orchard_to_transparent_with_transparent_change(
    backend, scenario_navigator
):
    TX_STR = "050000800a27a726b4d0d6c200000000000000000002d06c0400000000001976a914424242424242424242424242424242424242424288ac88130000000000001976a914adee44a1e8d1bbfd9e000bdcc4d99849abe339f588ac000002de086e9d8c3e879e951dc2b4eeb71cc5fe3c034699a4ab6f6fa88a53e7a97427ad55957c9deceaee264e52a66c4aff7d5a9100f88c36cb9f1ef39726ab4400063ff6805f58f687f59c1b5c3cc2c022642f5c20fbf46ba9ccef045770a7e04f803560d8f99b83a9b769595813639e4b0f8e483f0fc217eeedba658e29bae6a9209a32bfd04ca5fc04b87116119201021029bf83d4db0f7fc68c570f7e093beb0f05606a55b7686cd42a991a1386cf5dbdba9a0bd4754a586861b8bb805332ac07c9be780971fe9791ea947c5214a3ff29fa8216c8271f7f628f9154573fe45d0defcbd67dbaf6a7f5279e6198385eab7999ccae6e6420fedd3c051887edbeb4b0badcdc601c7ac281d8399cd4d482bd3766cd611923a3298b56f1a3d7bc8bd39455cea8151b04429befbf98520c66d2ed57d638d157ab9c994c298188cf2fa1935c7e4abc4a84d99335de77b25b747b3d757f8e9d90cfac6e42dd3a152ec52cb4eaa4285e860ca14dc4b7eefda3e2a2350376da56c4e9b9adc534589cc55f8612d808f556af5bb4483d2b02d723ec7daa7236bb8de917747e997e03e1bc1c5009a63538c966b68d62fa934cae9f6aa19d06845a368b75e6a2f19ecacc2e6e2520fbab710b8c8726d5f9fb3cc2686f5eba0b60208d1a72526594b2305e55d0634e3c15a6b0234554ab6f496998766d2466aa4292d26e3f34b48b8a8f8bb734e085e62700ed282d57d548af65465325915511c6353432c2ffb510f84debbe32eb423e21b3fa1ce56ea30e38f65a37bbaf9c33fb0b9accb73e07806da9331eebff92aa50ceaea89512ab35d87adc6bbbd02b3f976b9b3256fd06163a0eb20aa4f8a84e93fd5d1f20de1cb364e01ed0a2f36b321b7b6c45418554093e7e9519dc436e59cc02cdf1fd23e59f2a7bf970a3b355741ac53d5a4c3b8850905ae273604305b40dc59050c55a466f183ca24869d4d20dc0e846a3d4c6a0254ef02f1520e50f8f5be9c285f0730a67547ee32103b1a5c8594a5f02e7b3fd61a1d8b1a33bfaf7e91f505040b85ce64c4191976c2db2b671518d0155a81d57beaf402f31e4775e2ec60e2d473fee77e126e541c7d40d7b6442b2655933efc835a1d976aa90b3b03217673049af5d867d8980265f1bf10a7ecf5b5d08b228c0e51ed7061c103f06582d6303fc20689de1dedffc26460f469602b982d68f3363b4843cb568dedbf4d966d1d7876a2edfd758d126efe1a8bd1836620f16ce121283e430b7c95be852155b347b3656e520627f40582e13f971bf3119a69215e26687dad4221bf57714aae9e61a69cda0f3407632a94053389dd8b623052c3b8b1315ba08045e9efe3a3979a4f7bd320b4cb6e0437cf32308c5d87b87339bfdf9e41de825407a0eb79aaac9e66a2426247e07fee995d3ea68b5e9538a7e80143bb49a62e0a001a5bf510593f790e4f55c080c39bac1391741d756bedd81eb33bd87f7b8339fcff2951c3a2716d1a653e866cca0556714db01f23b116d550e9f6739efe37c262214d0620bd59c52839c647d56173d78e15d7e171e65ac9e1249ccebe4e1d52ace166bb07f0b20445452c75d5f59a11aa9e490859dce7c108037b53cb3bfd9a242b88ce23625bc0a2e3f88b04abfd60a962186b99335bfd40448f724abfa2b8b804f3c544edc7c0bdb2020ba8b5ce8fcd59da9fa9837640f7079503a6b36fcbfe1399a5baedf8b40a223ffb63c675db73aa7d29a20fa692b5cb20b1e3f504c8b60e616fd05ea2b0983f05d51ffa5b2563e480efb7d5665f77f38f6db2f913b2334034a02e25b0e8898a94967bf596a19556dfd061de393c29ff2e8d6460d26546a3ba68315957f332ccb120a9a7656bc0bda47677be3f998e51bf542ca4d3c213fa33c0ad7beb60bc46da16838015183d32ad91c9071b5ee9d1dacbee5a24af746457ffd6f614341e39f45be9596498ba355d14c1e0e83c8d73f4351c21c4b026fd911e77af3efe8cca37adb2680ffa4b0039449470c7c198170edc8ed44e803ff84c039372566806661d2d274ef222f19a364e1b5b4921eb9c8f7959dc1ad859867d4f4597286647f202876b78d0f699bfe38bbda4e8e4835d7350732e6f0ca6697400933065cccbf3b807fd7cf4a16e2faa553e9ac7f672717cb45eb34bbf4f32cf6e91c8cdb623e75099d5e0eb3887e538d6e6fc102d854395af9eb750713d45b7caa405813743e6e145a48fc7d6b89933a39a56fe9c7d29accc793f8c8c30e217e69e897bc157278f341042b3d8b1b92c9134b96c36901b28157ab2de75219edd12bd522a34eabf1fab201e093040000000000699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109fd601c0a5e999bb3a39bd86ddd9d8466609a087a4e2bf7fe6e4761287349928f85c8abbc317089aeadb8b4afa62fa00595810f609205ef34e7f5288aaaade32d361b393f54405d53c096daafb5f57258eed52dfd3ea190f956bb069a880a99adaf98b75cc545e35c6708c6b31b502837e23af223ccba3162c046b1aaa3dcf406db640dc8d6bc8112372eb74cd499cb52e6377105fcc2329ae6ad8a9b46c5f5a34837979acbc6869ba9faca3c9ecbc96696d348522659b38d64cb7bca3c68858463da8289db91717b5b60d5d5958221e38faec9b72ceadcc14798aa23623d8e75b97eb0b247df3efc43f347ff6c1bd5f98e0517ce97592115d75e11b41636549046d5254399fe1d586bdf4ac45609841bd7172408c68d19522a20a4fee2a028261eb6948937674ca710e2b77a20f70cfa0b262ea8b24920301184dd03092083c7a805bee5dcc77811a501ab5126ca6a9e7933636c8453fe5af45b9e5f99b71cff0cac2303a2a43a46b849d6a13e1f75c56c1f0beb9778bbe5b82392b37f566263d5203fec63237edcb4c9ebb384e2707417f69697ad195823135c7a7e4a386c34350d1460b85c515ccb778988e18b1d1f957e5c904b9133fc44db410b31daf33a6d82961c392b6aa2be616c7de9bf1fbe9f7dd708eb41769c149349095a12eabad17223f5759a67bf8a7b377387557a3a7e880f2b6c6f1f3a5f716eae328e06298196022bb03e616e96c1c1c6a8ed5a5751c794a9964d1b1fe915d9878af4ba73a0ea2823b3493bd0cb2431a9e3143f99db623452fd6788b131c3e021f85fee63ac0f87c8145021ed8ed730313170a9d766eb088feb9c8e5e0e17e2cbb236a0c894f8a09c72acba9afe0c353619f200fcc5c5aa2a92a93f6f34a3fb1f9bf7cdb3f54bbed8a36fd5801c548f515000be2fb20ed2dcb5c7758772e52954a515a2606415b8c2657c3fe52a405ed5f160f24e99228a836287776243b5b178140f7829183038eab179f2531f9f9fc07da87dcb2f00d3b0cafe6f0463443330ad4d901d47540ab6642a7bec4cad57d41a72dbd9e9dd7579442ed12580fd0d9b15c6a09903e321ad25a8ac35a8a023859dd89a92c8f7b998930d39107ebd7f3d43915a1c07a8a19009f128fbadab7da0124630823871d00d32b22661265efdffadce15a0ffd897188b5ad02b31fc6676be8a51b037d3defb197414d5735723f82932280a3a579c8ce331fa0ce79757fda2b9977c849bb43fce2d73058c40e5231d5564f4d5bda0f3853c791b19c8f204efbc8ba7003986a39ece0994eec4209c6414fd5f9a1dae98b28de5429978c239434a66faecab4421ca7b7b3102fd455f94db6b36704c1cb90cf38bbd634ddc535fecb03c996fd3951dce201ac679b332936ab9642aff1729c02cbba15c7040807fcf7ed96862c0dedff42d53ff8805b81efb58272387a51de7452204e40dc04f3972b69c470afc5f57fd88063895ce41c4195a131c2830381f61ad0f719cb14e94acee18704f7f2fb343f9f0d78cdc76b1214f8b7021346642c9ed65f7a3d69f4bbd6c74b6eae738e3c8bb2ef254b9dff36e36800dac27b7863f99131438537e75083b231d2268215b32722a67179ea78f1f51126f65bc3494be193b24a7cf3a754286f4b8c3763fe64dc86df635ead3eb4641c327341bb48b84d3b669cf88953d35944c2b7005e879e5b5df7fa805c5b0c2c0d04e9cabaf08f99aa05e9267c9783dcca785664b69546e4d10ce3134e18e1c1a5e1e8808734798ac9c3b4d89e5d2ac82eb35d9e30406d08d3e069809570f8d0e2ee93032fa94591452c740a6b836e314752f353ed26fa18067bfcc70b2eb68d7c5379b1ad21b1129005351dadba754c464bf6cb8f0d2e80d9b92bf38ad2d8b6944f6d4bd2c4d1734cf2b2c3a4d64b4afda9494dd931283ae93499fe1860b73621e89119daeba983e5106ce7beb9cac53042958148e80dc86a8a4ab8269bda4efa5eb8a8fcdf54b137d68ad4f633f48f9680518603dd9fa5a8dd9ab858af4ec03f4a6a8bbd5f3a0c7c561c97a86780596da31e667f868739b90c0fc82069e12ce5b49cd2fa998408f34fe45e511a9c9a8053bd3dffc74b88b5e612a177f39aa837b1033884028a5602f0223f97fe781cb1704ce7f9eb9c856ade15458996342551e19a99e342a581fd8cdbef894dc2ebc3ced4c6afebfbdac49aa6fa7a337a3898a194a9a4d95c32c4250552ee76c45e4e39d3a08466a2fe496ad4c2431678e90e067ecaa9d0a68f8a2d079c71cb90730cf59a5547f2d7bc61224f2e57eaf5b0c0e3ff78dc008d435c9adc41b8682a9d5f884d537706a3cbbc82b9bf661e516d45ff5f9974ebb15478c952ead38bf754c762f630efa650195265f8f53adae2bece01055be8c6c9d24d73f5cf98804fce6d004c5a54ab4c62d3c7203ab954d0b0a0f2b8c0f783bb4f623b695c66da4675ee57f10172065e67fdd1424d0411d039ce7ab732f9cdd532393591f0a9ecc2740c50a3868c3e0c73834104543df6b4b6dd3c94f2aa847ce80e4c286324f4f00e44cd7ea34abf9aeffdf724276c46dfc9f8a14d4207672ea57f9685603dba06d9a4c643031b13c18b547e7af6ada61f644430a13149e04ceede7e3f2948a16ba6607c19c5c3a2b47310f65faf8590c08aaaf5a123e31948bd08b3ce96b5b14a5280fbbe7d62d47871885929d92f1c4771961221b17ef0c9baebfcc0693bd929861a68b33b0e11c27042021c7407c501b596a1b88061d8d1d2ba0fa9445c7d91fa43e1466ffb624bf7a19f7f34f631b1743116d77398f8d1269e4f3ecd18342c1d915967f42c71f33cba62271715b12f3ad9d82e41c5e2dbaf2ed8e4e6b613a286796a1400b85e5ee6b8a2b7dc9f2be2354ce9dc60ade8e8aa7f3b1204dae5d97da40ea0f1c944a66e844865546ae652425dea6dd0d932ffd7c9f59d5535e9baa2cf34d1fd1b6bfeb489b5ca9f143f8558c445140046433c6289b02689f3d5a7c555ed9f840cef58c26a31d8f95f7accdd690a9323e07e705e4e276dd4330497a85fcf26bc7093fb483b95dff5b86e6c3f95874b812bbca3bb11c1b1bef7fca09d3b1b7a13684e0f94fa3170321f79a51eb1455da11fc9e75e817b327341b7b46e9e04c9dd97cdb133552799b97f330e83cc59b9d2446a751eeeb3adc91e693f009ea406a59cffc605dd40c1f90e873e44130eabc3ca243be43698b8be76e4401320cc3e912cf59d2420b24c38f84cb268e7192da118e92d37c5f240f0c7859ec3fdefbc6a9a1abf4c330f89fa7ba75712e60093738648e76d54acdcd685ae7a2817eb6596bd22072ee1b53f439646aff1e343db90fc63be0af7d9296b8cefd3207e59cfd8d544996017c0b235ab7f3c6f584b419382e43789a4bf189938088a3d9156f1e07116d2831b20f1913331ea7be2842f1370755275e0b8aeae41a9447cf859056ef4d2287299771e9d7f79c9ced1698032c30b8611bce6ddd149d1a7732a06420f8523cdeb584442e990620a4b9d4b39506c4cc1fee7aaed9866a0b68ec5d55dbfcae500f53c959e5ad88c0fcd0c03c2a3b2a2dfc3a5821cf952b65f5510c0dcb7bbb112990c0b7b6e3743b9c88ba21a60116809175c89eb5f1dac0b489902791f56b2130699173b19536218c32a203a1306203b1a558cf5e8c77cee435f16e5077b8dbd4040f9d1062fb98e66a169bfc151d1f4a18292cd7485ecf6ba1291ba98d7e1a6ca54b23307735792bde69a8d03e1d39c4376e3ca6aebe49bc6a15e6b94bf6724dcbc1aa658dd8bca73f767c8138c98031147b902f7bc266ca38b6c572d3c85d8990545a1f5e577674223b8f313e37de24385afa012ed626865cf356a9d66a6f94c1d670304bc23655df0ee49c04a9f2b87b5ccbd2be2f7045735bff168c85d5a1c8bb02de609f98fb906853a33ad5ce68e86ef547004ff1a36372d56755f19003ccec728507724e0587ffc4c134a6ab94c79726e1e60eaa9d365271d5567038526df10d44c7a7178d75c2caae005f8629a27a07bc63aaa70a951f05137598ba9485d3424ffad0064a0247e313182c1c6f551b4662902709a6468fc0d77dbdc101c60b9e84e5c2d5b2da188f3d0cf623cb705856ebc498d095c338d5d0632b4ccb7d9026961999c5bee54d2362284aac3eb8bc8adc8813662d054f221c67a471eb423883a07ac05e6c61e0c49a2fa6fb04be609b7e64a7911a3e67acb17209336810ad2de3de0f5e2aace6fd382ce18213297ee2c8ef2a67def4ea30efd30df67f02d4bb997fb0cef24a6594d00e0c034ab35a9bc60816783bfb40408351b106b8d46e3a9136923001d51f39f50bf87ef98ac196f425c4e9b8c9a132da53870b8a458d1dffcac3c97af973d67a369aa8630c0f7155372cb4233b5329f2f8ad9f35935b25cd6d96d9e56f2778092c146e70065546e5f3bccdfa9f921a00d6b70a4cd6763dee90dce719c6c173c9323b304464260934d82c8bc147c433e9c9e9e75d93fb5b04bde2bf9945f7862911a01ce96040dcf5c03fc8f72b0e7052ce0887ccb606e2503e21e0add152bb1c21cb6e89e03a781bcd6e9affe1c72bc2aebf0982417993bf6bcd2d8bd17b9e8c3ec3ea97b811df482c63dddec4423e08493ac38d660c8ead28b4777d11c2b9d40c135488e431fa6c616da75cae2461dedc08144d5f396c06aae6c0498d93612d1479f25888af756589053a7ec4dc3c1fd9e7ebda11caceb02a5003e3e80c39671abf15570e60973e1efb3b1bb0439c3bf7402cc9ff3efc59b595899a50a5966434a8ef377ac60a627f80fe8c55a7fba4137cf58e92bc983f5a631ae139400d472f4b187aa02ac3b8eb173f9b9cdf93d07c396f79507fe11cae02b9c69970edc31113b1ca68409e77ab7b8766878df46ae00d6a2b516d5f53ed4d915e16855394183aaa5003a640e69886b2a165ca6f71364e0c9f74190160665f494d25bef4153c8e3b14971f45503b7c2d16edbbcbb531ffd98eeae07f860d235b7f09afaa7c369f1e47263fa5e7c8a2ada10d1d775f055b66eb25acd297c1d6ddbe786944a53c32636b66c266555cd441b63da74fc7f9855373c8a02827128c899b08b049c935f7bffdfc16756df6939246470092081f019550adb4e8eedac44abe350124d21f6e921d31407a412bc90accd89173e6be83eab68020bc58f253ac2f76a416ad34ddc40bd18365ecb39a92eecb1fab0b42f403444c5b498e91f4700ae52f32ea31650cf319669c4bbac7cfbe5d01538a63872cc3fb14ea6e6a6e57fc7767c1c1003419f1baa1def85fe82545370b754cc8342d7e8ed32b00fe5552ca7fc40e820973d5533187dd2ff93ea880e24184fd51485211a603c3b70b2b4d14e6dd83352bc37c9e4046f73f103ebb83e4eb571647a0beef1c4cf31f951a9c9b4b92a63d2fc11f1f9d7ddd8b18da009f4296801c2de6bfca6f6a9bf9be4d2b54b7157482330a9989c87053ea132b10f1f27b82a24062886656573d1790f78965cbe01ac803c962bca649356cc66b43d5dd9c296e9c61b04bb3db675acab561afcf458c5531bc7dd54a8a2580d3c94ee17a5a1ac601c93a24aa9cbdc345bd691548e04a1a07ea68b78ebf2b71cbb8f8e7811263418cc495aaaac9ec1bc4d32c72f448d09a34382ff9e6a12d3ec71d7e8ca6236e232de53cd333fc14f1ef9b661539c1bda413dc5df7d48c46924f01b38e0fc54f6b9d033f5749332025f5af1e9ec77e786320fc57adeab2d2f4f1fb57ecdb167a91791702bab3c0989257ed246d4a423ce30d9cb498772a262cc281d62a07bdab49918a17d4185266849eb4567d753c15fb1f8b45d7ff74747da2b3e0d5016d81e43cce02b5540f387c79846be1afb23072288641eaee4f278058c6b23f3535d84fd1a8f139e03a09bc7e13dd5b758afd252ee718d014b653cfd0db03718dffc2a20e1929a8f4d7092e32b7e6256e34ec9a3fb2594b0e523f99794c2dc4c9569bde2d82c21589565250fda8946a9bdbf2fd01bd7d50278b98e4d540f64151bb82e978a41d7e91b39954a2d74d9563f50db721f8b1def079b4fcba0e6956a38150e9039da25100e4138c9588085f30e8c4650cefc8a19a90899fdbb9fd6a42ef709ec7a16ebb2d38ce20d3b36c13b31af9513ddc8a165ef05844884af580cd24028d3e750fc4b1c963a760dc902734d7a5a412681f706506ccb4dbc3fe3280aae7a4ef94ced31a20b91d591720cc770a5ce31ce1755db21d17b76b5e249a03a772b03a238dd734bf0809f8b119b236344cd40dc9d02c0af564cc0083d63a930eb3c7582b613df07ee2bcf3bd6b7ac033a8870357ff8105dda374f486c8b4fd40f1a6489cb15a26b0193be1b22233d3394ebd02d8640b3e9c4971a60c1e84e821ad107baf8216954fbdd20bdff2f61f1c3173333ee761104ddd5dcad2cc4aa6a0c4fe832aa5e6d21cad2e5cb74005088d909a3dca32f1da30ff889426dd7707d000251d45fbcaac18a135783d1525e5e787540132301cd687c9bc955dd0b3d833f769ec57cd1b73aa6adad0469796824468db098cef3785dd3247487ffdc82a7d5da4e603a67b54ba48248c002cd822f33e7f34171f9ec0b7afe32c577b491cee5a254ff14bbaeb13aec15f0f5b94ccf30ce229bb91f056a6f194d5d91a716412270d34b4ddb73b1450de78cae579b4ddb169161c2d1e96de756adcb8e2f039c3eed714036a341dc0a23fdfc32546a73ddb7930d83e83da6147260c851749fef3d376747b49cdd03ce54f85ddf11a84fd4605227cec25fdea54534e3b7d4d4146fbf80be136399f1226bd2bbcc16881c1365921fa89f0b56658a0d37cabc9f367c215ee0839134a0dfbb04b5f89585a863b250bdefb250f15b43969c6d36d2ce181518d3ab7768919e18b83b62b5ca8aca2f828dc6f08ec53ed034b5ec80cb721e66d7976a6d15e47bc3414b2a2bdb41da07f09f973709c49620e3ec5e0688419341e3132506ae7aac51d0823af54b92dea3d1b64d91d3295379452f2b93f6f65c5fe3347bb5a39892fd71b4fcfb05361c9cb17448536caa6a353968115a3ecf6ccf303096b66c85fd273c868add828737c60349be7d1bb2baedf245560938564cf5e352d94059d00a347aa6487a01e07fd892b624737fb889318cd7ca725ecbec846888c82bede732fe36c9fdcf8e3f2311b219a0b59a60f11820a3af0ac181b961a79b064ee8ec1671ad67189e58d8dfa023b6042910c334d3d26c0288ed41f4794d1085749c9d0d93b18705be4207aac91072bee0c6a01aa8e12bb9a3d0d191ee1f9d1172bf447e2c704a0e24a831ad86e3105a96fccf0b9f1a9359122768d6f081affa3099e2bfda6f843e3322be14533039e3527304f9f4ca8f49d9949904ee2a55c500bf5d33dc234abbbdf208da0841aad595e1cc3a75ed4a19187089c4a9aafa15ec665a6122f6dee666a4a907b591489c953e27ec5de95e3f7e514104418e20ec99ddf8298ea2345fdeb3bba95b70ba78ec50835f39c7ee4b8c9d7ccca650a2ce2930360c2dca47f48e85b3cfa9202e4ccfc7aa2c4a32b9ee47c8af3cdd164ba76ba5ffb06646d683841e713daa018a7497e888c36a34f34987e71808b135ec2bf9a233faa60531b33185f0c3084363e2a4257bb8d13f13a16c0e7e5a83407c53e0ce7c4cc62d998ca7d31add3fa163195a1b0d2a57d5150d66bc8c8b7502abf591dfe2208e399be20dd04ac1e2d27e986f554300a5cec6adf93a4cbe99a07c552ba5cfb2f6cea16123092f8e13f2283f1816fa8499c45351154c1e6fe86246a323ada0b480e269f5f76644850d93e9e7ef02eb22161fa721962be36e8a0ceecd9d241d26242a14bd13a7e8a94f1230cceda19d74af028a4abb756f7f111a2b19220b59b78848d6396c68a41643d31921363f1422f15881129228881af21de6ce1f1d252163afb0fdeeb1745d313111eac905e9bbc505d6bcaae16cdb703e13775dd06acf7169db4a7bdb7b1e3a8042b2ceab619ff2855daf08c14b0c8bccf853785775718d9696ecd2c5d49f8452ff16979e829e3e474552e64c2e4e4279174ee7e9656765da42e7e54bf0a46800b9f3dcbc8eb3dd1c7dd4d3aa36ff2803d321506e216a01c343c4dce64ea139b27f142b3771f28750196c75f8918a8e5259b919cb641a3a882c9944123fe11cd2de5e6c87280cae2cbb6dd7f10614ca95968ee33fb0f0b489810fd2db73a1bc43109d04fcb15a25d5d9df4e5c70bd2ac92a3b1776b9fcfa8a863c22cdcf8ea6804d4ab7c889c70cccc9faca62da291c7ce1c5205b3b2ceb60da57dfdc7004eae342c500b27777ecbe10d1050b88feb9b8401d646f032c253c213ce1da057064f26587f13dbe09dd93cb76104ad1ccdcd65f1e9c6fd3981d58dd54064b8e15ccb32197465ec3cc949ea214df78591f135044702285409c9d72e9aefb9f0d3ae6a30e7afd8698cb3df67219aa149e6034f3bde9899bcdec6e72426f8c07fa759321b42aff3f513828254d7f5060c508e09b46aaff325bfb24105b7dd3295dfe6272cad2a2ca8130af7ce4142fa555f515d59f00b4a9fe57275f133840c0c14a21a1c881af6220f2a5d0547f6fea71f730d50ea1e1717102e39f6d76ea5f11731ae3c7cdb6f1108f1d187eed8af12354f90b1a85f67079c37d3bf12667b9bed85072281fd5bcd380a2bc7f1bc093871f9dc2f492cd2cd99c34db36a6e99bdd3f5b11ce9ef92d906d2eb28748397c5c54db56ef2ff6e1fd3667ea4065a18fb6cbb9401651bd0838dd5d5012ab53eb1ae68bb646ccec7b7e9147fed3dd294e0ed36b527135805bf7db58d5eac6632244dce1d1316b8fc20bd4a938b91aa438547097037fa83d5ea5703edd011b84b8eaf8754c459728f2f0ca13a06a74b9d4ecf82fc14dd88efe30caab9e2481e472220a629832856d7a18ee8af14c8ed8069ad2ce025af2392cad2467e13cc6a9439fec9494e5a652ae7924614edeafca1e4c23838260920c9d33240d595183142172f6c4606dbda8a8f3e1497b34f7ca0f94d60571cf157ec40deea47cced042c84e24c7d787798577da1e1440ecdd037a2d7c1a512d77eb6d725fa93c5e73a654c035d2c0f4eb222cf5bdcf1c9453dcbdf127a593bcc29bcd5d3379fa69af16b34770ffa5da2b2162cf7bbd52cee256ee58673718df3cbbd73e6cd8f6c7cf2e6608a3e2f34eb77b1a1c11b9dfb8b3437b008d1832325ab30d3f11cea3325053723659d325a2b1cc2b67ef163efd98f8144e6c4ad0c117f059f1edfe615939acb73dfd473fab0983bf9e0d6109a769882e235278b3d6765657c4f89617e1869ffe610f3b9ec887957c70aaeafe4e1a6ee24d567862a047ece217c628f1f5e516e615c7c14d3fb261032407806d3c20a79d4d06e68015c0c89d4014fa352ad4637690bb292d7554e1b98edd20d3dc26529f902ce3226529f078084893928703d479fc3a20af188e778d98bf8e1cb14c85d77093d0401c69f4b66ded9c49ef0ef4edf2ae4a88943010c9deaef21eb49431de3214f3d2eb6e44c9c68e5be9fc06d5e6353f959a440ac65571532830d10393c4cd2a2ae8f675081fcc62f951569ee0836010e235c918a4091d55121d7053ea39fae04b426631c63924232f86b12a0f8bba4d53940ec86caa1e3d3923a4c23b6f239ab26099ab8c7a3dd8427baa809119e2b4a2256a7b81d158d387d808188c6e3a93e69af79e8818ea5e5c1a8eac301e098a28dc239c434df4b4734762dae13e36c90d1a6eaef745c6fd7bc804021a5c9b44d65ed6766585ed4a8d428326dae22a960a20cd07e14b4842107db1b2acab8392b871167c50ef6d3eda060ee57ed03504420b55342e7f9826865e6863942427635087d6b84798c2c5114210523dfbee35afb1b8ffa923b2865cf6303e6fe233689f19f495ae65f4a38e35e73487aa9d33b012bde2db0e5af22ab58a83f8b32b7577634bc77f1892df01896eadc8612a4a513a88666332b8cc8d16ef93587bf8aac26117a177073b783b6162f46ee03663b22041e5c07c28d39410097cc1467a465e287d9e2fdbe20f669fef92b2e5af1f9f7b39ccf2eb8277152f8ae81226d1c57ca1b0a9c1a08dad4c865ed673afbc07f32941b3e19667ae060e3ec65f492f4acad994b07cd26a7d76b96b6959724576c4e2341a81653655f4b693abba926cf1bd49e7ceee15c954c8bc118c6f75f6a2f001748af43fe5a40e29eb786085b82d63d894f81e74c959177d7dfcbdd5bca004213ccf2c62909720806c78313a08ffc43bb272cc3bac7ad9d8140c40f8c2f80a8b626f4000506647adb16aabc3ccbdcb78179fda5c82da7ff77a6e2c8e755558f1e1196ac6dbac95b8a81507b20c45e4b46731358c166e938a8b90f11ae6689d89d5b962969913d561d24f0361591605d0a542da22f39ad6db84e1d1328bdf271383b8e5aaeaf5a47f56bff4ca36da16cfa330a9c9681a496ac87c13009725a0890244105adc80eba2b96a029977c1ef4914fc7d01c5af8f9ea221297d520fd761a"
    EXPECTED_AUTH_SIG = bytes.fromhex(
        "965388DA6CF71F61E7A9A114BBD022D1410A34558FD1C88CBBEF370250AF66BCAF5F74F543BBD9888BB7FA0F4F09119DA01522B0B3723065046C8D1823C1CD36"
    )
    _assert_real_orchard_only_sign_digest(
        backend,
        scenario_navigator,
        TX_STR,
        EXPECTED_AUTH_SIG,
        ChangeOrShieldedPathKind.TRANSPARENT_CHANGE_PATH,
    )


def test_sign_tx_v5_orchard_to_orchard_simple(backend, scenario_navigator):
    TX_STR = "050000800a27a726b4d0d6c2000000000000000000000000020ce5eae9c123a3373634630e258b5e534b3e7c6148ca5a6c04c61bbfa76663b0d68cef8d52a164d092d8bd4a616458187f7703ce6ce5ee9ded3fde2df4c569127066f527f7fe9c4ec6d4c57bf76d6851db115b60d707a2e49b12a92d0248b7079db7163d3fa5a001ba00b42c73589b9791682089f2ef0a14f4ea0d7790cf1e01b8734861bcf115a70efbcb60f711782e71a8ebc0e5ebc1a7b9f97e1c20f5c22e2e90cfc9aea8db3cd1a2ba6f05d5776f98f9f4f88aba54edb4f5726e9b83b48b6c32bba462fedcc4f7169f785bbc88bb1d99a393f9548b9bce5648c802b993a4525fc75d4cbd4765a841bd8ea6ff745db31ec35f53924049b5246dfc34f6f4f2cd222ff54cd895d7d040bc97a2d8546901ea4ff93f7b09c704329cd621c136889b2f76fe2cc0bcbf23683e81ff7b010fc549ac82773a05d5684482fe9d18408b51656cfe4bb7e7807de829f41c43f26c92f9029e737642c3b3ef0c78c44ee29f0412591603774de7d60096d8e3de1f2635858fcd3c4b9da1c48c287c9a1dc82731e4582db0c9320935b5d10d40c76ab1a17126876c8426f3f007c9e5f7e4b3f52fd4457dc12dfdbc9e2929f362c5f31aa1922bb7aa9f3a988e5f2d86c2b45b0762cae8a2788df8f97766347a65b57fbf2e5699d16bd9a534d3efb8b0e7ccf903f366dab7c8b79f1e7e6df4051ec617e73c7c90caf9ddec1933f3db3d0fbce8dd46ac2d5b9c405c517f14b26f7f24800757ca71d7efb7cc59e46723400e5755b7c87618c97d1367218705121cafb95066caf710e1edf4f7eadba33518e950ae6dfec59c276cc76fbace4bf09ba248e831484c5fc87a1565563727f1f17efdd0a3a498747a867c033c013d3989170bcc95c36a94ad0ab0bfa48623dd124009abbad78251eb4e884a6446938240d025ea877416442cba30a78871ed2baf0af149c15306171f88e2dfb7dc4d0b555f0636bee0d97c9a7afd1e40f4a04bd4c39fa1b307717ce1af12ade0598579e9121a61d6195c58c952b18e1a014df59f729b40283438235bf3795cfffb3ae4fd4c5e28ad5034e2565e4ad326e72458a799cc34f11226fa19ae7b68f1aaf0e1495a6f9b8b41ef2d6b2af71372725172043233b519c1363d0648dda6fc5154a882cc717524d93e7c3c1a88eb3f897cda9bf68454c33f627e0150f974f22af9cd961d04ebc9036bc895fc3ea087e60269ff25114682610a6b0d716f191fbf2acf767d2de63de4b95a0047172d229822aa14a6bffe3405ab48f4e8d14f27c5b286be6c4e95f2a00e5abee185cf8de2955a4298f602e4bcf508f55a68cc6c79a5379dda08cab1fec7f6280ddc203d51b8edd935c9445d9c808d2e53585bc1eeaebf5823c9a5e70eb05b12b35968123a64513c8bf026ae9e1f8c583c3a7807c785632475c220cb9f02316004c1d6a76906f5de4a4f63dcb8777f68a1a4c6f2be9a0094814e13cf6916da676168a3b924e4c043f1c868069ace284843795f0d83ff10bd763ece39246b5ab27fc67c86ec2f5320415f6489a910a72879a92eb9fa832eed9cb6f71cc24fadf4ed44496f706cf1c21ed78046fce7ad3a01b9b17050e587a7daf6a41ef2134c1bc2c1fe16deaba223e227505c7b0491fa6fbc7baf22017c8726569152dde1b735aed3b786d296825b3cb9c074db032be356ab8151a5f01209e53cdf107c9ad0c1b2152209b77aee5a58759ad670d440602e8852336a53dda64eeef8751243afd4052d564bbda0e69c5f66af4ac2d13740f788bb835de948b34b193e8d2731d7abb1e79de14e088c49b007283857fd6b127c3e7c5c585c616a968fd18895988a572fc02d2e859dd584f9fa1ed872794cf349f543f1a3e3516371fddc2a7f294c5c1dce2f35b1fd6e3ca23f8baebca46c1042def754f639f63073d410e8d46fb22a9cf3e8ed46144f78de1f53b9e773d46b9ce22e7887b7d3adcc791e797248e30ca9b950399f9dfb9a5c6bad17882f74e4c4ab21cc52dd6b1e4e8a81edc96fe06710e17fcaad305d94bb384a8c92858da56539745c23e29b33e0bad34599df32bacf36aa29c7b0446e1b669358c5da0c065c0313bd67dcbfe6a68f5aae445b168f95436874e18be427a78dce3e42f463045fd00197bdbd686adc41802fc558a1de5e195542deb4096374c6fa91ab7c51b798a863fd17f0ada698de32cf5d544d90c09baf321b301923172c05ed37d0ce897cd69922ac249175c1e5e0e718ba94390a7fbe9d74dc128f391595899a3553339b9fe083b7e298091fb0c6d8a813b748f92ecd4d0767efb694d6a230181801226d7351b203204e000000000000c5e1408579e67cf16b5d19479408fa035a7db4fe3060123d139eba8523bc9633fd601cb1c6ac6adfd1ab23d5cc53be49ca5d57e49d3150eb71e44f5e79e55eb5a65dac2cad43cb8541b46a914d2bf2dbf884d9522a81f8284b8e60424b56003f4a6334e2e01c1aa1c5c09405c1f38bd79b50380d271d3aad5c8e9463c9de65171b32a72e88000d724f4494538567e2247ad0fbb160489a416f1d4ad4ec902c669a6bac164b66513b83410dc7f12f1f300787ade1232acf377337f307f331b5acdca8bf3f935eb3b5e9f1aa63b2d03e0bd94cfde2b9d69847250d3ee7cf2ec0a381fc06ccc1b3597df2dad79198ec810360a1af8ffe914a6839005318cd7686bbd9e4a711d3aaff293da026682851da28144d09a2ee513530513ac165837639984f3d86a084692dd684c8bb2dcedbe87c67c71a4b8c60fa09ec563abf3d828726f0d22d72c8402e894be5676665bffc6ead20a2018832e1c6ecad2f9e19f16a511c52190ab94db65ca3c1186b0c736d24ad2f459e2c48cb31db02336b09487140bc300a3bea1047179792a56e382c0b5d9128f66b0b058ea7e1d7c153ef94fbae2c0a9678c315eb67f8f4f5f93d388e0ad79b4e55ca58f92716d861efdd23513ea3e494113c71598e9b555a511e973fa53c7de7891e6c520586d67bb12b276cba2c8423cf948fe184e88feb2afac3a8783eb5c5d9b6fdb9619cb83da8d69fa5d7e7b21affb64f21b9c7caf511c4792a46d3a275ccd911423efb7f098aca4b683e8152bc8b6c347642e1bae9bbdc9a5260a6b66a98e661ae4ed82ce884d1a752f4d79c1da619b46a9f903ba5ac3d930223c3aa526874d29db4b4573d947244b327435f05f94bd33d8fb303500eb1f531d9ad5a6e777e81b6645f9add7a6383dd913fc80b75798e9c20158a31adf6765b64105cb7a7c217273b7d4e6dda3aa2fa658e5e9fd05e0c430f1069587106b1230a518b0145be5ba2a82f602864beb7a9da761f3b82ef183f164b6e0f6c061b899b3b6bd209e8f33a3cb8280a7cfd7d35356b803d78bfac5918d74630a98f6a3b64c52ee8e54196dd59c4d1780d89c52a67c4cc1937728b99af7aebfe5f08b8fb9aeaa5868345678669173b1d531f401bf10afe3bf814eea3ec0e3d19bc584f7c60eef532a315b7aa315b607bf7c630da904cf60a267eb99f20a6dcd59b2c9ae93f34cccb247034aa61e5e4d1ff4142fdf2a912201c178d8217777e5d3462e489dcbb7b8ea3c3c987dd26b44bfc21fe9d73714baff9dfc46e84579a5c8ed432b53527717d87ed2a1af87e1fd98e096aaf41efb3b0bf55c9641a971ff1614ff66bd8c24881e7da315e77d85787001f143a6860221514e2f96e2215bacc9712980017227375f79f847ff8c8f61df7e2c3e1bbb5ef9b4476e118c21a6e6dff8511eb1633a7db7f34e4759cf7e2db58831df5822dc48968bd7c55793dc892bba846e1babf7614d88d2484e1dfb56227331a8bbb5687aecd7936a9f2423a30adf0765c16e83dac96436877e795f5e8dc32b53ee449ada220e4f8496d129c4805bc179f8e2f05a533b9931963b5c9cbb3bd034f96ce5319c67d5eca88379df9524cb7def959e487fbfe3d9b09c5668b9cea25912c42e9066ccf41325eeadf789c0e13e31a420b67092a43ae50cd5aa86620ae3e94f31ea92f9b04384e4c1e4b6046b379350785ebf0a3f9c333fa48d76542979286cde8be5db513b77e189949637bc93b410823db7d21ed7dc05a1ad64619a99a0cd2c02383e70a55bffd5ab7e2762f17f5944410147db6fa3e44ceff56fa69bbec9819356d1134beb2df32e5f0c1b7a8172fbfc8de817435c5b828e7d632709b14bee68465f194c792588ce28bb0c76984f0d5469fd276ab34b16e4c3a05e5899bb081b5b7b7cc4ebbad24f0c6cb9dfc79bcac3be2cf44a69c4f6e4773d3e24ce4253e1ba0ddc8b125c7086535d73177f981a1c0f72672354432f17c0940ff5d936ed43d8fd618543cafa37a85b0ed757b6673e90ee0b19ce32a424511efbe12fe8e6ca4a3601f5609853d36f176f76e8a2fc14b936cbfb46daa7825dae85ce2ee674732c18c0f5877cd653b0e3842e949ddc990d41842dad8a9b93e8b18112f7e01352563cf5bc66647344101c7332bd6869d25cbe1ac29fae9454ccf4cadb333096734f097da0048eee783b28ca8450bf38ce1edaae243e103d0684977fbec6d388bbff3228a287af9b8d8ce1bf6c634b55fdcb5eb75d78fd7840972b2c432143f7b104fba41c3d18128892a2ed98d60c3c83fff9a97c39e81d3d8b95f27a20f606f1172e639f20fd57eeb05c45b40f4464ab6ea7472b36f91007d2a8d8884a37e6f0e283c3f2c07fcdc02a62bcb8b77c89ae79f60bff4460a69a674d84a72522ebe963f9f5b9f8ea95399578b810de3f264f113d218705f371950cb7cb2813020349122ca26715502a8c7a3e8ffe170b4961c88c2929ee0b6132f7edf01b9b92fd403573e12729182b49ab1f2c8d08ddfd6e4e80316b0894e2ee4590297e5718b501062d989431314e07cfcf7742bb20e2b9371fb5f4c69da8798dcf4e51ddadbf108cf6e16054ef40b8ba2839c46d4163d3f286f44b1b9b24f7f958c7cc7d48a6718aac24fdb889990ab44861ccd98d71ec797f1be0c335bd063aebbf769d7e20f0b1279130b63c0c6a1ca5ab3ed713e4565a6c163ccccfa1ef602c2e41e3ff43723d1381d6c832597c95604bc3aaf439af3e01bf5c1398ff3c5ae5d672379d29d215a8ee7b18e55f8dea97701b35ed78c9bd9a093b5d85e3217c70bf61a4d248a10b46252b539afabd83ddc8d9943dbaf591146a0ea7796ec916435f2a4f2d77e00e0574c2e44f6b6d026d64d19cc2b5426c369fba7e6b9563a78b3ac775756b335829ed089dbdd11b4a0aaf7557a472b1119c5bc23b29c53bff93eaee748a8431ce5f66c7956e54be51967d797255499e7acd8596df7f47930d4675b5530b04612c8935f5e958daf4eeb14be08c4679d5fd207d4784063ae03e936bbb77534a512ded8ad550de033af4562b0f9ec6140c1b75f90618cd8cda4a2e865672538760be0cb8f32fd8fab50b61c3e04605f1a304d37be81ce79bd3996763a628ebccc08ac510733d49dff038a0fc5dc8e73c03c2c5598e6ccf836f5b15bfab5f3acb93ca3b0610112ca7d906b9e8774b918d40c7cf18694475961a971c6daec9106b30adc78b4a5b23a96d0a6c03aeea9bf21b7487ca99b40a68918299a3868e3a2e7037559fb13a4d094fcac4dbb70ca603f591b490557ce1baf061276bdf78934d23733c36c1883625a6caa53a3945c0d3289a6134798fb60982c82671899c1c2593f533c54f23e8187da694098789e8305577d4442527330ed5b44e0320b2d53970a562ca1e82cd0388b76d36a398bbf0972956d8f4e036e5940fb58f2a2d7fbd3178026c82cefaa15d9ddd8c1b2f344c5fa87a10505924e110958cad91726396114db244273b45c000d85a2c8f2331c39680a19bdad1ce73790ae5bd206e75e042cb97c2ea1cb32ecdbbed23a9454d28bea8d51cd4fe3f859fd3e2bccd58ee8ff18f943d44ceae9a776df229fd9dfc2688a2f522228fa5a811922588e2aa5324823642ab39606df4d88f6da7c86531c3e5022534b8293d852f9b79d8f92bda3e909a1d4b2b08035f9c1d947451f5f09af16447e0d48e4dbe0891219c64f9260f0388a04f1902966dcfb3c644ccfe8b60551281f3e85410dcfecfce32dcf0febc20ca6bec95c27961130666b88bf1ae3cffd257a49b61d63a7dee703e3401d557d237003d7897eb3548080e4cc8388253093064328c32688114299f64c6e9fcb290410de2bb33c6cd78244466f82db4f8b2762370e234d29489fe6fdfa6c2910b22b8846c080027209a32fd97a5eee7b5db915dd13f058448834172cc0e76e1bc93ca0b80623795844d8f3ac04be811882108cfed4486fc9a70d243904d7b0eed714078b75abe662d9b14a4aaa38c5b481a43d5af6ef566b649ccb7c1c5ec1f37228227add26dbf6c9ae438ad38433b18f7341ee3248337ae29ed003342e4df01c0c1ed598f21712adf401dd587d75ad18c4105d27dfd3a685479c713bf3bc61d615884f28ebaa401142093829fde7747d86ad795414bfd8b539e56b41c39142ef3e27c3471efc97d5d0622e5bd1d204af74a9a8e1df5c33478d5b8bf41e51f8a70dfdddaee215b783ae99baa705e034ccfa54a36c5a04321760caaa267b7c22bc29d9df101c1dd7f806c14ea19aa0911005a2e2126a1197b82c90483b2dc3ed331e5d6f2c6becc15daa2627c7c0e638c77e04c951d3648b675e50b72b4897f4ff3a4aea7f1f58c2be157a818631e991932dc2941293effc63ba24ea46fc33e06916d4efe9278ca1232e83dde0a0e3a275e3c3aab49cf35f84807ff1d88774cc8018669a440760c262cada36f227f7d47024b7641322b7e7c2f982d72cb1473d29279b543275ad7886ead00d594c9820c0e667bf3badf9a90a0ad2403d203ed56925035990136fb0dd5f28cf3c4273b2970006d26454ee314d92696829f2a4db931d5e8f422c492c6f6ef23e4395ab83eda3a089ebff1715079ce85d583387a85f2e254d95482c78bb6fb6601b2d2d4b0f7492f0fa476808361c8fa8c033777e5319fb7c7935c6026306b1c2c72a5b2b3521ad5e84eaefc463945444301d6f5f462c1054b62ff238e0a1841375bb73257cf5e0a09db73fb8caeba85740430b5a2b2a17d513149158b0a94c3db0c6454bda6f0f7677be5f19b3cedc50fd708334a2099939c0bb1bf6f85658e68a6be4cfe3cda8188ad3224ea9c62f7875903b31c52a935cea1c41f4c79e94cdbbcaf5c16050a13b5234acc3db7abeea9b923911d6319ded6ca3a392fafa9091ffcecfb86ded516a8ed047e134ce632ebe5896104513c7bad4227b6e3406027e91fc74c8f6509cc9eb3a471a1bccb9a2474280801e24230c42a733072cd2c869cd4a2382fb862d5ce5b7b99d1de4c4b38b0cf45ffc24500883735346c948eade6f0878c50f7e9a199a31fbed08fa2d9f87b7b953d73d9770f647a61396b3abea2f8559f5f737077393d0353c643c4e47f3cd73aad63cac862e55fa4ed103ffb587ff2b1238d2516066691bee8b3224004ccb2b125c21943947ecafc274061a79a6eb7b9e2a902f787d39d1672cdf9cef48ccaa128b0aab19edde2664ffdeecfdaef5b51ffb71f051592179b48cf87c346c4945299622cecb0bb2c5206c26ba5ab48061d06f03db5babf0d2286c0ef8fdc4ad2cd21609eb7a534036b0a4bd1be15204e49688e7e747d5144c6449ae7d90ca727f6bb12c260fb62fd1839301b5876d4a74fa0ffac8404e22a3872eaa91f16299869af12027c8e8332fae604df423cbf92acaeecb90a7a792650fdbe49c9b95b3ac06cd3f62cafb175c49632d58b1ecf4f5004caaeda192bf47f8b7a968e3f2e77384913500216d75c09bc4d0221aa4a155d0c30033e723331aa15bfdc2c83ee6e1016425e084a81ed72c408310bff746cc616eff5c3eea0b403a4c90575a8d049c7dec0c6e8ab88b80988084a5233ade3d908ecd0fd63e7e7c1414046f8038baaa1095228d378092a6a36fac53d64d0726fedadf942335cfe0066ca556baee94981dfb180de981632a364b5edfbfbdf25fe443cd6f9433017ce14094dbb83bd86167531c2eb2a5bbc2ff1fa0514d0767c8f07f38ce21215631a2a860e4cbf6d66d0bd407150109c83661545853f5edeac2457bc11999bf68f539605ee462b1fade455b365d74ce30959a2884cfe4a26613dbe3bbb9b20dccd35ca97ef86a587ad6f347333baee7b72ea384fa243b20eda0afdbfbc1871044f807dead244cd145a5cf93008dd5cbea889bbb3a68f6312a69197a6b97d6f8045fa523118c634e5fe32f1d2191da6ff99f48e0610972c533333359298753b85c5641bfb470634d21c64b182c5d5b44ab4aa38b23316c2ae12de1036f83bd2f41bb79a8d6e73498c98a75780f547bf3c1dde75d862eaae876d3422180772ac75e2d838c5dbcc46c3cf3f3e20f88d649eff8e094a0933e4cb38c77872ea6f0e1cfe4f28b6965343a28b9cbc72cb2a3d8fe33e28be4a77bc4ba4b86e2021179123da927daa4ee1aa837ebcd4d0f2a6abae228a04a66ce2999936175ae09768273a3ed3cf2f3124a5b2d6a880d2fb592bc1fb280b9ff5cb2cbda3c737ff5abef7188655158d2258f06342f7edd3d12f300407aa80a2baecb326174252db2a4522a99a44ce3f30b700d4411bc6d25a5c6a2d6233bd9d5ef5d7f725d79ee84f612f6fa45f65d46825f522b29194e27ab733b4fbf91ffa1ad3f4d7694b5ea4d0a13b64a63cae97377a8b0e7db975406d3df700dfb692dfb5f82674c4a8ed67e8e2505a40746947f24a2964e21ff232844f5fc43e905c70f1787fc1367e012b05eeb9783533168461cf42a10a34a1c2fe2ea8176a1420e0f9f87c6d76e033f995955a668e5815a0b7ebd4e11ca83942816e2d4e2bbce7260b3d6cd387d91974ba3d2dd97de59cfe1252fca09baba7238fb38b2651bf7bf3834086dc8d2b37cdca2d52a3e569bef7e1035cf66f38e47243634f201042df5f701982c71f1fe127206117a4a5ee94b0f2042aeb1b94613026f059176c816de23e15f93c27092afa270d001ebc17377b8a0952dd05f9b65067d9dbb42f11b843e46b0128a8e8599ccc4d37f169734b1ea598143a5bf039a0eca4a7886551d6baf67ac38c02a56c4c89c515d7dd343e34175895e0629812f07efbea628a05adb73115b3f226fa5a91f901cb0efee2ac4733a77295b08449003a2de632389494b1248971e245f4a5cc74c575897b02cacc1e0e954e9d09a3e2b4718d47641e56bead05cab1e992fa4fc8d2b98fede79cc97f2344ad5001c943f4bf8633dd5c57882330499ecb93a4fc0c0ad49b0cf15f4bd5ceef8d6f3350a1b519b85da4520526d25cc243ae76b7aceec433012d08f9857f2ba2f19f04b9618856af858282681c0dbf0aca3bf260ed40512753f72bafb36bb4ba85c4d5c960a9b771f5d3ea9f106e16634bda60da0a416aff608a6d23b6d485b9f342ee2913395a11d99529aeff88f6b7fa6a41b408352df74f6d01ca2574a2f6a2168aa7d29748e0143cb504c72d40569ad7fdef7d6b9398532b1a13b6598da5a9ebcd27a21d9444b94955187d1cc56cd82164d4124ef9227e0cb22bc27d163916a574b93374f4f37508dfff2454aa31224e22a5f4de36ab2fad90a13d633ce694cb0c04b02d60835744bdc24c44dcab1aa650a3b60a2c1384e83938cef3e099cea24b4d6317fbee437df3a2e5f66d1920d1ecc62148ff4cf1259c2d9a334f669d97e08423b82ddb9de6e6bb6f3ad6933f9df9b4e6e8124b33259b9165df9f969b7a08191011634ef069db27093955e56c5754ad851ea622f1e381bd73233c6d345f3f9250599b1f7e6c06998a26322438482bdf950849be4048954eb4e1552c2e5c8ce2c29bcdd2667139859540bfa84c7076d6373915f4e27f679d45b1fcc3fe071aecf065025808f27379329b5ee068036fc908b3b90bb02cac799fcca2adeb69c013005d3bbe6614b1d4ef06680e57f28f19f0bb9fb4f3b46e70977c7ca0c29640e6e321a7f1600e61775fc43c4cd14da43f6c7fe0f067a16c84deaa62884081f3a9639429a6593b68b47aa66c56ea989a97684f2cdbe7f1ceae058ae40374e8690501feb22f618b8cff506ad8a9eb3db348ed8f702bd2517a39776d2243776c76f3a265221244d443baf66f792da336ba13ef20598e95eb30680d7be2674eba335cb390211984ecb6e2e1d9c1d3af901a46aad7ea97c51f419984b3db961b4ec0d0023fef93cea8e89c304c82ec74a950f85449f76e4a5298b0f0ea6f6ad96f5ce8c3f480b4a7d0682c5fe5c6fe25a2dcb1db4f91e8ff9c00d2673d4ba400f332f10202b03cedb2e25410a5b61a96d6ed264acf4262172c02754a2fc5fe64b5b9ed73e61e189715f03dd515378af262c228aaf3e118823c8f70bf2ae4b9cc418bcf02c6fcb42112f37c53fa8b26abfbdd9e6e0c974f5d05cfc2b8059d4a2652b2beb0bbc2c46c54858183447554b99b8278993e6e5d38b91e581720b71ef0368487e031649751b431af42826014ea1ea63410848b868fc5b9958c4f2c2370ac8fce7237f6426115c59c8c05d9cd042f39777bb16e48b7a061331414120bd53fea4aa34a643c22e39c50b5e5cf0b6cf83a7d7352110fa3167d88e123b18038b8d86803901099ec27a0ac107351d3c5eeb62d1c5b7bc0204829624819c7d0087f0a11e2b46a348b98af2b6724d73e6645d91854df0ef942f02d66cf9b69f3d2a5267ca21fbffa404a4a45a7aa2e0e9f9ff42f85fe4acfbef0feb06ff0ca8cda1f0fb9b27d9259444817965570adbf794a66ffc64622bd2a081ab90bf338f987d53ca313abf3b2ac101fea764ef7dc0fc847d8d93f6720159f99ca6345babe301a064480397a9b28af36855187df9f06ff99abf4ef2d306ba0493410b8883a2153c997c2312f5a12d989d1cb5377113652f5856953c282e977b7a8ea01719d771cf69553ad233a1f6c054f0eef13f429009b70305d357c30fba380f0d23b6ba2c38c52202f96e2d892292ab55b8e20ca9d8c9447366c690aeb8906042093eb5dfbfc8162dcb4263138a9fe0a2f4ef472b7d4d55dcf0a517db3ca3bc66800734f01da3c4003b1770c3f6fd5b865010677fe381a54957cdaec0d09383848ef0f9fc03fd5d04e7b2d91be159fe17508fe687acd654c191a40f2537fdc1fddf718a6ac99acb1d357c1e904bd42470a5915cdc3babfa144a9a5bf9bec5c1c4609a7fa7f74dcb26a1997d3d0bfae93f688cfc8fb1d8bcc229d16a2e6b2c4e2af2f6f0cf82f59c353e373ec0eabd5a543a67a7d6c104bd32cf6b4b9f6d45c2e7973b911d0fb76d1ba0cab8e9a541d6270ffa99e34a7a5b0631f9ccae6d60ec25738c0151d1ca8c3956e38757bb04a2afc6e14e893b73802a84430c51da6f4f03b6e2085b1c294339ae86c0b3d5f893e462514f7d839910cb84b8a66a439e16ad4a52806091fc1d3ce9556bee43d41c38cff04ef4bdad9f93fd2a7295768dd83478399e4a64782601f2c0eb53ecc7c3e93859ea85ade088c84e8c4a95a2f4e9307aea8374728a16289cd8973434a7530bcf1eac74e9c157cb0c9f68d1bb455c0467257a455d0118a6e12be966faab31e0c4b6be97c2627832b45448ea9fa64ceff915c2d49f70d8a5decf1d2a31a6670224aa83e4be475acff72399a0b70ad3139d13e698ca7a312779e5d76544376ea293dc2ea1fbbe5c258a582bd539d76307e710608ce8c9e799f554ab16b2e27eb87fb6599473c67884ea08bb9a57eb7dd28012832ed468d5beb23c58a668a09c97f4f15088d29c5fbb1d7a7390ab7d370495005e95d81503b34123c4fe520ee683c4ff17dc7c146d80bfbb795ba4a900209d9d20cf0e26eb9d9df647ddcaa6ed6c5821fece3aea2b3543a80b7cf1ba2f4b9f59a01020a00f1658f6c86e7f40135f12b70c277d572d139dc87ef3fcc70cab3dc5fc4db4136fad0b6feb8415363d34ebb3af490d37a5b5edc8857266a0dbb917d2cb1bca92b13d1a0b2b39c5010b7b03259ecb4cbd87a1bcc10c3bc363b7d294045e802a278da547058aeacbbeebdd105b1317aab2835744110cc3d16cfc76eb243b9b460f45249b1bb61e2153de4d15edf5b33b3a20d9c4247313b4592ff7d7c807d834da260c21b981f4d743e64470a7d5a155d7507b0f16f008dc0d305c666ab43708489c07247652af2144e2b937e4d2e1f4f44f1f09a15a1d71e967cb7b05f61f83fdb289409b93a00e8fcde8560d5fba8f26a381a45b77fca60541795fe57b82b25dcc3c8573852dd585ca87ddb22b752842adb5680b98862c8c77787ab9d7c35b571d398c9af4707fd3d966266d5e19d9d3b96ac12e10f396bd1d06a4d4056b5edefe0f43f99d6c06d3fa8524af9b4f9dfed893e735fb41f9f7d4d03b0f2ac951c82988294c0ec202e0c677e69026edc65fff87e76688d3d6fef41a6ca054a16d314d1aeace09e991e059da7876fb3a44c6402abfe684d577cecc1a7c5d3043f074579d7da6c2ba42f47a471c6eb93c8100ddfbbec9aaf91e4d616fe30f673a9e9ee2ab27a7ad151194701c13d1f8e41ee09ad856dfceef722623201f3754fe4d39241330d0c67fb9cfd803e94dcab514f086f3435718f870b4b393eaeb550aab1bbf17f3ff65c006b4976b2362749e38b6088381e9e356efa1fd3a27058211bb38611fdfa15c7568577cc24a9fa10b037ddbe2248d3691c35a1e70d2a3349478b56abd9c8c5c6ccba3bc47e6218389a93a3a80b69c64162642851d6f0782200f6dcf092ca0cc76fc83c8b0e7e2a41ab5d59ca4ea146523b588e4b5ba57ac091531b08828e8969a5925098e12eb1bce1b93201a1e275e1d7753332beea281e5c8695a0cbf6918a08ad46795726bb11a4c4267a0c3f4897c12ae51b690386efe69d0a09cd32d47192992ba72367ec5eb08b201f943df81f19f2f38c032524a349966c318"
    EXPECTED_AUTH_SIG = bytes.fromhex(
        "6F1D0C15CFAAC4DF766D3946BD4E16D62599F06264E9005D7831DD999BC6660003642BBAEF3B9266DF23EAD8A49A15EC7A06B6213C877164802A8F8B278E6317"
    )
    _assert_real_orchard_only_sign_digest(
        backend,
        scenario_navigator,
        TX_STR,
        EXPECTED_AUTH_SIG,
        ChangeOrShieldedPathKind.SHIELDED_DEFAULT_PATH,
    )


def test_sign_tx_v5_orchard_to_orchard_with_change(backend, scenario_navigator):
    TX_STR = "050000800a27a726b4d0d6c200000000000000000000000002f61b81d4d82e61c245f59ba77c6822b937132e5b794224f95db8433063994f22fc3ea087e60269ff25114682610a6b0d716f191fbf2acf767d2de63de4b95a0094fd0a5cd314b70ef0576cef0dd21bd9a4d3919ac801e7199fa1b8be6bd6f3b2ab272660436c13c8a53f357335612f49ba61c2476651a1b3135881c4fe0a773d4c7314227c0199b9311470468981d47713a5f5109369edd7153a470751b070ac46cbe07c7c443635f101d481bc111642eae701694f6a8e503b163f6eeba752f8336e93a1264d9dc138e450182f6f34c179f577ded73a34e805405edf459ca3c204b704ab6e12a9d98fd58bdd6f23f5175b5f88d4ce8e1ce6e15f5e8ac33001a4a3ee0ac641c5738cd851fb6db8cb7b0eb8cf72e831585b5b4071477e7f8e92fe23f3c8496b283ac227be5219a333b4703efc604dda4752fe7cc2d3a9974d5159017b90d5e1c815db1c8cddab91dacd715c66b7666272178a28c7a7d05b763a9c6525e6f35810852bb77f69245068819d634f0d637101afcd9a3ecc2c17371f269d37d42f543169f9cdbd02be2092bf5eb263dc787fda8a811681303fefb65e7c81fa7fd537d108060d8f56a42577cf45dc57fff563cc7b4d167da96b625e66d02789924cacbf7c5a876383e49573624ab52261d19a49f635e501a15109575562bdd3500eee5681ce00f176fbe9bf9aa607969ef9e124f6932b24f40045a7067d4791794300f875eca146b9a0f7356292e5501511332dad6cc50948e1eae208131f1328ee84d62d916a22239e3f373ee994966cac76aee4a5f4e4d14f2462c98e828f38c8e95bef12a5ca50060e3a5203df81f10d7946e33f51072117403bb2d74cff0d58d66530aefe2c84ccc6c37b2baf77ea7b3ad66d0bc463912de82033f96265aa7c5c9a46a09d9389274dc52c202652b3d09629163416e2deba86e1c556ad1513c9d42e02aea10416c071ad579e6fd813e30210494d918f808664391eebcc501aaa9e8884573bea0f67a8061fe5e531f1ffbbc14da40961ec0d05695c32aebd8ecddbdf7cc4e1b5e89044eca85547ed7adea0e88738fcab767b03993ede592eb18c2dec1e20c9fd22fed35be298d2621734ddf17176aa51b836e5cd43ff1220854bca515559ddb184b318f65198e890a8807b19b7ceb6a1d588209a62d08e1c13f309e61381f767a59328ff91e4191d98a3d68cef8d52a164d092d8bd4a616458187f7703ce6ce5ee9ded3fde2df4c569122d62ebc4f70e798fad2fff9b7873cdd476cbb3ca1623943b7ba69732295378a5e960b02f6b6e0e58008aac76cd99b4690541a867fbc6f5d52606262264fdda2ea5d064724cd7eeea8058bc46f0b99e3f166acb7533b2bb7f0e71455800438e365b7222cdbc3dc4a72cb76e55c1c4035e6ea3ff9b9a8bdc64535e22fd54618a048b61985ca54d154083d92fe9c95806024e214cdd82b1419499387c93bddee1a25b5eb1999aaec9967fe85d7bc41f8c634b7f1b02f140b4947e56bf5e77e84e7a0becac4421ec825a90ef2febfa2099635bdfee145e441d4a98e8accb8608bcc88f2abe8f8503fafc165490f4687fe1687245f731ce2e558513fba50f8a9e079e3599c266fb02ce396472c527fda66e2b4c4c0e7617ccce6aa26ec1312f77c580331dadbf96d9fc7b13277f54cae948938653cfe56a7f695c90764662978ffabbe286b947653498bc4968f62a91f11c94199e23c7906175482480dbbbe8188755590f8084babfca2b9044b4c1c0e84a18f7043b47a6001807170ad5e4b8ab680661407645b2c5ec8740dc69da49255364d4278db9f0bc63ea98e64634114d8bebfabffa57ff61c2509db5431284c16ab926e5c0ba2c219282a7c9ed03c36d9659c0bb1be59b7570935ea2d7352aa11022500cf9b4a6d1ecc556bab49118999663de5f2a22cd78819f5778e3599416ab150f42440ccc761c955dc15f49eab0fd20467a5aae9c6f84dfd14528df46af4da2f0a5ddefa4552be915c564ce720e7d26e1d3261a9bfe568fa1929d3c4da13d2a87eefa955d35aa0a99fdca301d52c3b0ecdb59c275510b7323ff4c46e3e6bf4bdcea7dddd4b9f5349f508b5c62adb529c23f91af42e960a0322ddb6c010b1915f0512db34feabac23fc42294f00f18f6225bd7614e7dadd74d61d8c2d40f8bd02294e262448e7984b7205d3bc6256b751c73042b08abc376d9c33581d1a74aba93b503b2911846ab7d77e8ed96f0210c4ffabb09e81a728fff021f90784cbb2c8b3dd3b7f62491e02618c25a3f819836aed45fcf707a379e4b11b65aaf7f6283c250fcd6031027000000000000c5e1408579e67cf16b5d19479408fa035a7db4fe3060123d139eba8523bc9633fd601c8df8eb94502574e7bf9308a357abd3534d0a8e614c44778960ac798f3436701588de74fa5680dc8039048995a44eecf86ce30c47844548f2d8b5e6fe3881f701050f4f12eb7ccac9cfb591325be6029e751666103e9eca14d859c9fced9b85803546cd25e7c6300cc619f8d104d45e194f53b0df6c63e5395545d5dfd65c3932b0783aebca5d05d6288186ab5a93c9caa06d0e2e20789cf1de057f1155c6428d06e5709d0eabd35ef8a8c2a6f29a5ceea0bd9a3ddf6d770ef7a7bb88e387e683e783f926a375d6ce9ffff496faf7372dd1ab47d857422ee52115493a0ea426b5133aaf1ecfc9698c911037221daf645ee4d3c5f9d820afd2d0cba02f18172d09ef0db53be31ea70b39aad934d5c1633a928be06a46ef10fe3afedf0571c8c58c1538b9605c0bf8f27e4cba540f86af2ff5d10a940b95d5c2457bed074695a238067195994c361174dfbcb795ac71ac18dbd598f639c46e5bf0e861d38162aa31953e2204e5d4c0330171b0cc4aeffbd03375218f78e98d5ea11f9101f90aa9325976415e864b98b8b9001f34a0e9c5fc3845a38128df93a3f2c095306f0fc026dc9d75a0e41e1e5098de9e8309730ae6ae4ed6ed0250e03b96be835728b416908b0f76b66a8e97a15b1d8ca8ebaf19ce8ddf2dc3362e2bb9e5eec7676dd3070c970750bc14af505cfd3bbd2989ef6e1d13ede93f51fa6057095e3d5e4ab3d424ec5924d00da583f8505909a702133a8993b366b4b668e1f7e36110bbbb3ab83a678ea296e0129ce64764a48c64573e27744f0c57feb8ea6cc863fd1ef923d8336a9815ec0f2de0119d80b8c2966110acdd00e7d76efad3ccd93313dc1ecacc8c81c8330448af7b3b22213a9ae73d9f7e9819845026fa3faecb46b3fe31ae21a926d06f30a614c6daaecc8feacbb1a1b53e1fc6883a5c16e482cdb2a941a2ea121dfafca3048c03d3af681d46a654eeecd2661f7aa9ad31de39901a7c182d8222a1813c0a21061a797beb36a2d5f0cad7e3fd23eeaf16f01ed920ccdd98bf02b5366853c4422434b0757601d9de2b9cca3a702cb4a85f84256eb796573cfc3a8860e965495896178600b378ab6adec2fa7244db4cb741f3336a45606061ac6329d4a10470f9d1ac904e90c2cd4f55d55f55475da1e9be8998dde3a1ecfabcc4bc34fed16568aa35215a847d21d0243aad2e81fe5b3505a103f2bd1c07b88e8d1f7d919e547aae8e4e9a31ce79712c3458109cf64038061158f54d619ff79eb43bc177132c6288ac92b15641dac6f59ff8932f028028966ea7e0827291e876843aa9acd35e99429e089d59de5a5a1eeb06d3c950aea6e6d1014b868eff5310088b42473d8f42a0a059eeb7f91af2f05d633090e1e16fc4d44750bebeb2a604c51903c36fa800813ff9cf0fc1cf70a952da2ee2f8dc96e6d89e292e7de1b70cde8a10690fb27458bc223e71bed126a6b9838119d385d62f58899b82532ba08cc78344935877a4f0571f4c2852a4c379f63317432317d3cb83a33d320e45f9d0ec130947d50839bd9f8028c6ed8e9b0a0be67ca4e97cb4bfa715c3f2334caff9280a9f69b59f497c937a7647c79ca7b9e1f7c4ee2e85f862540f8bc2adf736ecb6824581b8f1b5cc9de7085bc96627d7fb26cc3c5f607ad7c539bb8f252235cee084a25f60c3760f7b2aa891a3a0541e59083d67edf420c6ff8e99455c5289772727db7593e127c0af14c2b96f5358acac1ffeb20ae37b9b8cb1363fac21a33d52324ae2105d03d38c0d4b136b8c96d374c72db24887f6093a9b4e2022c87f441d3e971f581daf431a4d3fcb088ff03daba7a292d8db68a8cc70d3a8a1cc9ead1a203fb7e553c61056ab0f7f47c4dade3daa742db0cd5a60853ef9d517d5de1f922d8c4ecd59d920ce57244c20e55710c09fb9f6f23e92b2a6f67ea7ba1f764d2b3f1584c5e2bf09e5bae90c6f1a7bd40654283ae0dee00859bb71c24ded5380660c8eba5f112d7198043798b21092d51ef2a91185785e14332ae482d6d855d649a140c4838e865c549a8a4e479f61f4a5da1acab4bcd37d085b368da9ed5b3002a871483d71d8fff1dea2468f4bcc5b23eaa6826714f941ce027241c8d4bf4170a338566b9c8e65caa6fc614fb48ffb5e049ab134252f97fd3699cb950b52f2e23c10ce2d3beccfa26210f1c1cb75d3a76f932d0c4dee26dc26b49bd8b9dac75818ecaa2236de40f6be352584873dbe414cf2d4cc896228617e06c2309a6465673233a00646029db878cb360d57ad1488cb01b383aacfc989eaa4de6c301e9689318ac96e1f7660d6b76947050c37abb2c11640e60747da6cdab36dfb3143da0a2f7d8c3d307ac52b919cba51758a127d2eae75a9af374db3b2df9e7a5478906434a8e4fc3e819e8c0262bd9e585e0f555f1a10073af65308dd0d42a3b61d33fa2681d5b1558043d35fe589ee21ac109225f3d14dc960cf27eff4f93666e5dade09b63e35bfb77a8f49197761740c4cc6d5ac4579b03511653d825b17a4cacdb60fc127c54c29b7754449efa2eb3b27eaef5ba348d892a78c40e414c0e65bc4263ce29aed425ddf338114dbfec0e51391543305ad96d9efdbeae059403356ff782985aa9c9cce4ba298c0858dedaf6090f823046073e86ee4d435e97228b974d23b84760ab4b5c137015ddba1ae846601980fd9233e395b83ba018071aa0b7b2f202f917856f6e3eaf41b022646d27ad14645c7710cb16903cd03644f75af53f728a9bcc2aa631558f29723fe2a57bb7c22d2ed6da998804a56d3a462cae2cec83888b411c331a8a16027a31904afade0fdf8242cb30e54229f0160bcce1ffda0185a9b1422573c6f0e8ea66cba9b03820f7dec8c66bb9751de96712d03cef8d936ca5cbfa1a8d6c9a4b05a1162279d508e28c1c3bec6a68c8c75318c9904582514e04c58723fab8121d74e7f657834e6e445bcaa06f3d159b05e5a68a4313e213da3dcd8451b992b0989e9fc3b57b49820153d1f58f3c2d9a970217caf62db2e1ef06cef7349c0fa89565339c09fc20d800ba112790de2018ce2b7c6bacd138a04b2a227a73e14b5ea8a6a6023742e642d7d9fef83113e625d3a4acbc93207ae2ce1f64d6fd9845d86c47d73c2459cd0eb2214a3d8c40823fa1883a96ad76de70753f842e6e8a1f5474bc64fd9fc67c32f2730d031a1e6f4a2fbf0442869c0821d48acb6dbea61bac6cf55feac83371e8608916e4746c32ca1f1f58b472d91ec213c0ddf6c05a73423219a27577774289a2e00f5588a0e592dfd6ecbef9123cb3f9dac2dd709025bc877e5277af0746e507e60604242ed3f70a0cfc91f60f9992f211c90360e677e4f41c9d2efe1303f1e568f3ea0c9b4fdfbb8e09ce936d8863c57bc56939e80bf8476648b600ff4e13b22abdb83d125ec80e843b3920d91de3ecdfafe12f1a4bccca798d180eb6094cee9a27e513703e018befb1487044f820cebf28545a3d67de95eef5d984f80fdce88d88c1e538f315ced23f6d6658cdb07244e1f604fb70bf023ab68edb0a93f190014048ab4d90ee8847d0b2ed31ce31ef3819b32c1928610470f63109b50d0e11d11dbc7d9809bd572322b18b3f6d43c65631de7cdd43f7ad98607fbde7581ef34dfc820fd82be76530566622504e0019c62372360a4617a01388562da396b6a9724313d2b2dedea54d84b062ee58a31019390fd75cfd923b39e6e829d9a45837e5bf07571aea1f5a8a91e77ca4d260bed2aa42c86dce5de867736b19ff3f803d4f48d036c2ed83d1d7acfa695ed833139f521a75eee5723792c2bc53b6532d8c1d602bbce5fa3125c76dd272ad6c33783acf2fbf07156fc15264b00bcb5bdb60285d17ec7046b0367402f5f58765b3cfaeff19f94bfa5890b2c184ab84d76681b29831dc1f4ac6cf8cf632968a88d220f695e64567826cee9cb7a142d3155ea2b9dac7112784bd3fdcf11769e685b2e843a45462f5af4b4092770bff84c2fcfa85a051d693fdfd28087fb2a0aa5f70945c0304e157b45c1f60fef142070ebf1ca2782db17e16b520c63dab0c90cbd24bff1db0620b5223784f2c133e67a9feb93b07a8c1eeabd560162620a446d9f1e1fadbcc3bf825a3e1f7406515f0eac12686c53f64d265a687f01d0ebafd19c28302cab9f53aa40465b6eee7bc53d739fd2b70288f5e146df2751f9e8a7f26c2dcb5c439229ea41302cc40bfc026f360878054bc769398117967765801b889e3f2147933a9684eb15703b677a28efaf622e59a0074a08c5b713241046fc6c16234216388f5ca8362af9e4e768f5678e1c479851d083ed9b60977c7b69506359171753a85c56958ce7b694cef74af31463e50450a70ab8d4c4c986487536397235b71f978fabf0d8424e670595f82ff463e397d8be5ed6332178cb7fa7ed970b0dc5bc1e2011b7631be6b8049e7ffdf1ba46c6e049ba97830f5bc267e66a35153d797bf2f8544797b3f3bff622ad23837aa3c3e33df10c3c1657f7f0a8d7027f1735e43ed40b343ac07bc3b1f5ecb24cd48cf83dca8ad3f80e3a982b69cb60743a014855cecbc8c5f751e7b6b6ee9003282a2bd7eaf1d4400e7b6cffd73a324c0ef38f45685f626a14e948d037b81e5105af54f8bcbbc001fb15ab9d9d4edddf291f526332b237bd943b625a8752e3f15aab0dbecf3098b9512fa0f0ba3ba0980523929dfd1ae0e8d6b01f7d2ce0d45f000f95890333de9514849f404cd09f7f302f493072999a25904ad992307ce1f5ab07527722db98d804e0c0e675d2b1a5104ba2f1f5ae1b8c91d5360338e8ab9c4188dab0ce1c5a875c2dbdc6236eba6d09d06896b46ee707b6df61411f4eec0aa438a66549647378ec8aaaf9a7fe46653e447fa86fe3da9be0247164925be92be880e39f4ef08cf8e8182cae11e45cb213e67d95345fa06565b2ef8ac08a7facab4efb6a723f46cd7e160f0d945232860c1c0adc7459f8abb28d24f13024ed70b2978e730da29b204b3f7d1097ef1d291e80f367cd37eb4866383f0f5cc050fc779969f8dad948b0e7fb854fc477a8f30cb78a1e5ca330e77b285440156608cf6be3ca12fa52eba886ba1dd5698800b42030cd7b8286d962ef16196b58cf5b9a67e4cb80c131e4a8347d3dd644b2c17b3c71beefef8d228ab07f847e6c8fe561ed643764e7086e05a5aa6724e78936ef2c55a29b3aa4905831a19c6ae566078fb7c681495a23e4c67d52770750933cee19bcd411c0e2b929eef0136d0bf91843102edb67e5b971011095c7495b4e329b2760816958cf0e531ac18bedb5e474d48b623c2c600bdf8b376170242fb7f89a191b5c103bfd502f5b09ef9c1ab30abd36539f9349e20cee23a992657b1c04500bcc6de91b3bcd6fa1b1bcc89f310c6ba5a04363889350b636ccc18eb77b65a502557687903be189c789afc19509f200223c823650e8deaf183398339f48964a13b69bdd0f1aeb7edc9e021208f1f03d00df4d241ff65e18b1471fef348f80ef274e62855339ebfcabd140182f0fa2bccb860cbaadbca37dfdd5da18e7ca13c0357ef76cd326e320f62e19868f59270dca360127c8e16d8e7f3ca394d854600e335edbbb4bbcd044f9ab078e350b462d68afe374cbd444a4aa538809f47a27b112afc0a68deb48567dc7b961a9d84f03066b14fb736ee34479c738a573f344c72980451c709cc545334ac4884d8b6c17b915191cf973850583ab7096e9d1a4cb15bc2466dbe76b34da20d200c7877d11f2556e2f842a6695263386252fbc426705ecfb04faf5dbb6af86e07c05b0e5f2dc737a0710b0e9f332d2f75179841fe4232cd46aee110342b0bd4ea5c0d9393f15668673d68726000017db36bc67868629b968403f826411ebe76d119263fa557ca33553d4af9e373fada83566eea2aa381fcc2325f4bc230ba594a2be73c0f1bf218aac89d277ca3dfdd5f0294ae09d10ab5de2210694a0fdedb1f0d242a4da1976455f550bcb84e2e010c17599cfb3174e2b3fa7ac929db2de075fa24625fc887d4bec3d1e3e601befdf668efaeb9207d00496973bbe91089b61b468f0cb637466cb0713ea7e753074993d08a0c60834f0d50f0a66039b74e1ab5f237c76f9669c97aead6f2bdf39bf04d39fe633c223253528f1b85dc565a6ec9c67255eecba10b48aeb7e6f04d583e000a0cce2fb326d3d6b7264a5ec52d63be31f7bcc5a884e2c43d0e5f294d71b115a7b05205720a40fd9ad0faa43af138457708d252651d54b7919f3acead55fd5d1b82806952bee022e99ee9e2722161b307d7b4de6a097852a6f9891d7b4e4bd00add29aa32187fca5fb92d665ce1b91b87606c9226772d592ee10be732f45690d653af3071c665d2af52a44ab5aa838943059898c1f59e2e2df3297c329448147f2c547ba3fc1e79ae0158213362fd929ec59faad0262c05857b88b675c61f98fd65024350af9b413bcdc235f6e0a7373dde91b9fde9f6a074671368779662a92bd6ebd3d181e633ee4427ce2e536654ef7fb2c02b73b2e0c32e046d914911101a1fe2be019b9b92714e8a6740860e639b93e24c9102adf47d71a719fb8bcd1dbc977d57709b00ae0a7c292795b6f38b1970e1cddef47bd0d3e3b0312f3133524717abbc30faa6854e2314c1e8c1707503fd14c468b4a620796fc92b1ac6c73c2bac3cd1238353dd73709ec90c12e787c91fd12dd67c597a53176a3175b29ae769023b6cc38cf289bd0141b1b89214bb2b4625b8e743dceaffd1b835c99c9c93e0302194522142541d2595c3466e383d2e7157e890d4dce9a793c00a419caf59aea4bfffe23d2a7bcf02e738750cb17bbd03afa537fe8411cd90ab8cb5b2036c57d5578ec10e639606efcea0ef5442cb7b22d8cc3490b817b407df6b32273bed155d280ef135cb97c10540ab70e43b4e837d7cf9710a8ea89ed4533eaa423bb6e66046cce387f075d7a1cafc44d271e6e27594003e141432f6d6016ac776c25d2c10ff8c51d4aca66d083fc54736678250227c7dd9c7b25770afeaded3bea5b289eaf2a8b125a14eec089cd619b4bc7f25cac20200bc961657a72a835aa7b20572b46d23c18d6fad13e050a358822fa3d93d0fd77ab9e53903521dfa7c1c1d2f178bd181c00403a369e698703edd42477d1a9ff580429ac933e0e1068a99a702884703e580ebfcb49cd3cf2740916190d27f8305f0138ef75b390c1bfae18d7e3eb3b3315139c3f6faf17c7c64906d0f41b437612567b8b671b6de4c0d337c46518d9faa0331972b217a1d39b7b45889f8101ed9eed6ac5b0f54a3d783b3a51765727b4460d22f8ac39c173952fe35b7d7ca346aa41926644ae90baff781a3f55501b509f2ff81d6e2d84d8deb01df148fb444f8bfa38dfbc9b1bd8e53aeb88b15de2045219d23746b4ad1c74085680e72d08a8c6e7f4629295130778b641f75bd781e8110d31ce1dfa270ac95b6300d4e1971696bd186983c773a6f20c92154fad32c97e3428c5a6f77b44898c29dbcd10895547deead99753630afd79ece77146279dd329bcd5ad0e64c1e317788272e1a662045aa27a01d464e8006c305aebfabdaf2c17a5a40aa4f328d5e9d867ba83fe73745b94be4a036661943bb7570d6efe38b5238777c6c149df14ed498c92da4b0ee6b6715ee4b7dae26548fc357ff1cc95f33b86a53d0a3d1537f274c91d0557307e3104f56725085d13710aa3f7bd334c792e1fd0642f8c8476e93db39600dd8b5abd400c39cfc168fe1955e2bbebefc5893a88aa80e27b8c8798b4913ee89a9181d6d6df91d7dce06cd09338900a75dd4c2442c8d05af61dc2b8c5a0b104071166de2af75b797db6570d86c39930343c0e36d9a69e1144381cfb4f2dcc281ce2f42dd242be2a416d47bf72c0f763b1b88f110f253ba780966f66a120d1f7910f4750793dda1297bd17f873136ac603dd3a1dd9c8f21deb201daf9ff169461eb77ceef526064b398249d665d833413e7efa1a1b120b9dcc1bbe6b8b6fd3de0b252e880a5063e6150471f5410b8e28b56e9020623c4dc65df3e377d925927dfaebd8b65ff5569288c47bec34311e1bdd191d01df37f3ec64e07a7721b594686878eb8b84af4d390393fa9c652195ce47e78e24c03fd23503c91cf609fb0f6e104158f9a8a1506d187cb6077762146bb7b4982ddd799d144ffa05eb02d41f1259acf60e459fed592a47e1edebe90c847dd2af2e09f9cf9c35cf76b37755aad21fa501fb8b5937218d9095a88da18fb01e390c3f9e88f9e5c52a2d06a69552f2f93e6d492fa213d371183181ac59fa9b53fad33c8e1b39edf9c5d82185aaaa79bdc2422243bc0f5445c3c97a279bb2bed40d9713d590f6b7a32903b63f9451b1ab909088fd043898c7a1ec526a7b8ddbf88d5439e4872f3bbf46656dc5a3a8d23c96eaf60876c28cb5ce32b9c815ef163f1cff02aece414c21478f3063561d7cf09923e3bc4d96a271e8b1b36654fde8d6f2750fc0581138aa481740a6ecb32a345b20e7f3d264589413d2ef5408488f999f7f3f12e3d60657887c948ba8c8945138b3e7790afe73571618075ae5c98d13855e35996283ea28b918c3e401c3cc89baac19a93c6bfa62735151c59a582ecc47171b956e65d25e8761d09d06aec5f03295ce383fef5a72632461009756fbe801a6292e5d62528589c8d3bb2a29b76319efb5dd6996757a1b64180d7892967d6a4c19bb065320a3e8047759fda99f5aa14c9ab839a61084f15d446ef647a1fe57cc150cb7b18e87e7a9d0e4cbadb494fd1a1b505c90a5eaf6592f00c66e9f1b49060ca0d5a1ab4549116fa454071badedfc3f53787d0d96b54b9466dec6053b099c24a27da14a085ec2eba135d481468c72ff7e7fb947751d0e26965ccb343e626abd99c4387c12ed05777cdd0507bcac8b05bd2b53ce70417c7b50696f5f7966cc25be0c0670408c1a6203001936a32fd6e9bb1040d2976ccd3e20995ebc66508d3a03fa41b84af303ec920b068c9faee3b4e74f3c809706c983e60fdface81ade2e748ac90a7202f43471f0171104a2dc14b294986cf197bd142723bc530ad6163fc158eddbfbf1f024e0ce816366fb9e5d3881695057d9423694406068c8d94e2786b32482b489986ca37e13a117a1889de35a3d09b4001d3de8ca66e55dc8be9222191a586396c1f36d386c34753c9386fefe7c9cdce230eb008b3138abeac805257b63ff2cb5efe8889b93ad3757cce62c94af6f0a7769146cf4717c559e7bbf24864d5b11697e2aa89f6ed94bcfbb384aa95d935b4a5520658016814d42d5bac596d1856f7245b78a4de31f19604e692b59c934a5e3e6895a3803f4cd3aaebde4c5f834462649fd1224f043bcd3db09350cb814f9bdd4d66a984354359b5ea87cfb82e94c3dcafbfd84e4e3cf0e2a92dc7b6c0620c92b26a393e78db8486995be0411e2d16a1d470764ca9dd7b862f0b55326eecf607f9c060ee8eff63cf6861db6f525248ae7cbb2b8149c8dd6cd4c3bd93d48ce772883facc119ed5acd714109706e84659a26c9357469798c54f8907372ad6344974c6c56bf15434231d0436fbc2b846f4ad2e5526af6c4705bf4b9193d551f98beb964e219be7bd070736346dd4edf90ec261f79b83a709a9f1061a66f4e3a7b5ab2de0bc44764951cfb4f1bca0aed255fbf2b0216837dff477a0a6b43eb56c91e6c74db9b929398d889b5058e8bb5665f0c40d39a738450652d7b7ea3f9fd674d9b458c73fed79665ab4c9b9dbba74d73f592c2affe34512e64f39a59577f22eeac28c36bfa23438263c8c5b5d0a7f18f07e0138fd46fd89ece8ecb0030919a5bc5878b25b9c4e2de490e0419ca27e393a970855bdd4f030d45ce54b2bc531c7910bc6bcbd36e4d41fb51b9ee23519cca41f1b4936a6d148400b118469c21ae68ea9c75ac5ac0e3c2fac8e0cec430ee85e712c5acebcbc51972031aa1a4b7854578130e81e5d24608da2b882da1b2002e0cbe8cad493d171d0e398edea2d2fa1e7d18f8782549b30781343c0b87c3085a281631705c702c787258c4ed4cc9ad3dcb4d664cdcdd6e67396dd4730c19f577880dc28a5252a1835ff8cd208193f6896c2ad36218f4cb3150e7ca1e548f5c5908126c7818f2dd2e397f4ee9341e1b8792c40d29c38e09176bfcbef9fe57d39c062f1235a277ba5949c8785b452bc4777ad12f7a479343c711a7f40f9cb5b366215ff443056d558c9b3a9cefcdfb0b1f40b57a5a62ee413b41e337b78398ba1eeb714002c8156fc4005469765844d969fb3e77c60cd6363782b0063457b62cc9d1dcee8252fef5bd2fa562bc503d7bde33200dcd62c38dfde221dc4621ff5ca032fd04d0e79a12f190d6cb8a84014fe748ae580f1c9f17562bd7ecc376839b968d7be4fe1b657853d470d250c26bf75774ded48b3102644ae20e39a82f777334347b19a7f27499fcacbd6a9d706fd870b6166f8e560410af70354dabbd8ac7ed0f24afce0c5ee9220138ec442839f0346904ce562da5b6e7229"
    EXPECTED_AUTH_SIG = bytes.fromhex(
        "F1C4F455ECED5DAD4865BEDCDF1B41B694F71D3F90B6B05B6FEB77EFD415A50F2A43C42DE6FA030FC48F2A92A218DF5DFF5845CC234D606FE7307B7D2368D508"
    )
    _assert_real_orchard_only_sign_digest(
        backend,
        scenario_navigator,
        TX_STR,
        EXPECTED_AUTH_SIG,
        ChangeOrShieldedPathKind.SHIELDED_DEFAULT_PATH,
    )
