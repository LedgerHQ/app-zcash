# pylint: disable=C0301

import struct

import pytest
from application_client.zcash_command_sender import Errors, ZcashCommandSender
from application_client.zcash_response_unpacker import (
    unpack_get_public_key_response,
    unpack_trusted_input_response,
)
from application_client.zcash_utils import write_varint
from application_client.zcash_verify_sign import (
    check_tx_v5_signature_validity,
    nu5_txid_digests,
)
from ecdsa.keys import BadSignatureError
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

NU5_BRANCH_ID = 0xC2D6D0B4
NU6_2_BRANCH_ID = 0x5437F330
NU6_3_BRANCH_ID = 0x37A5165B


def extension(cls):
    def wrapper(func):
        setattr(cls, func.__name__, func)
        return func

    return wrapper


# Special approve navigation that doesn't wait for the last screen,
# as it is a "transaction signed" shown after all inputs signed and not after the review is finished.
@extension(NavigateWithScenario)
def review_approve(self):
    scenario = NavigationScenarioData(self.device, self.backend, UseCase.TX_REVIEW, True)
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
    client.hash_input(transaction=TX_BYTES, trusted_inputs=[trusted_input])

    # Review covers the header too, so it happens on the first HASH_SIGN APDU
    with client.hash_sign_header(locktime=LOCKTIME, expiry=EXPIRY, sighash_type=SIGHASH_TYPE):
        scenario_navigator.review_approve()

    # Finalize and sign
    resp = client.hash_sign(path=path, locktime=LOCKTIME, expiry=EXPIRY, sighash_type=SIGHASH_TYPE).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(public_key, signature, TX_BYTES, input_index=0, input_amounts=[81630485])


def test_sign_tx_v5_nu6_2_trusted_input_and_tx(backend, scenario_navigator: NavigateWithScenario):
    locktime = 0
    expiry = 0
    sighash_type = 0x01
    input_amount = 81_630_485
    send_amount = 81_628_565
    path = "m/44'/133'/0'/0/1"
    input_script_pubkey = bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac")
    output_script_pubkey = bytes.fromhex("76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac")

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

    assert prevout_tx_bytes[8:12] == struct.pack("<I", NU6_2_BRANCH_ID)

    client = ZcashCommandSender(backend)

    trusted_input = client.get_trusted_input(prevout_tx_bytes, 0).data
    trusted_txid, trusted_input_idx, trusted_amount, _, _ = unpack_trusted_input_response(trusted_input)
    assert trusted_input_idx == 0
    assert trusted_amount == input_amount

    tx_bytes = _build_transparent_tx_v5(
        locktime=locktime,
        expiry=expiry,
        branch_id=NU6_2_BRANCH_ID,
        inputs=[
            {
                "prev_txid": trusted_txid,
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

    assert tx_bytes[8:12] == struct.pack("<I", NU6_2_BRANCH_ID)

    response = client.get_public_key(path=path).data
    public_key, _, _ = unpack_get_public_key_response(response)

    client.hash_input(transaction=tx_bytes, trusted_inputs=[trusted_input])

    with client.hash_sign_header(locktime=locktime, expiry=expiry, sighash_type=sighash_type):
        scenario_navigator.review_approve()

    resp = client.hash_sign(
        path=path,
        locktime=locktime,
        expiry=expiry,
        sighash_type=sighash_type,
    ).data
    signature = resp[:-1]
    assert resp[-1] == sighash_type

    assert check_tx_v5_signature_validity(
        public_key,
        signature,
        tx_bytes,
        input_index=0,
        input_amounts=[input_amount],
        sighash_type=sighash_type,
    )

    with pytest.raises(BadSignatureError):
        check_tx_v5_signature_validity(
            public_key,
            signature,
            _with_v5_branch_id(tx_bytes, NU5_BRANCH_ID),
            input_index=0,
            input_amounts=[input_amount],
            sighash_type=sighash_type,
        )

def test_sign_tx_v5_nu6_3_trusted_input_and_tx(backend, scenario_navigator: NavigateWithScenario):
    locktime = 0
    expiry = 0
    sighash_type = 0x01
    input_amount = 81_630_485
    send_amount = 81_628_565
    path = "m/44'/133'/0'/0/1"
    input_script_pubkey = bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac")
    output_script_pubkey = bytes.fromhex("76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac")

    prevout_tx_bytes = _build_transparent_tx_v5(
        locktime=locktime,
        expiry=expiry,
        branch_id=NU6_3_BRANCH_ID,
        inputs=[{
            "prev_txid": bytes.fromhex("11" * 32),
            "prev_vout": 0,
            "script": bytes.fromhex("6a"),
            "sequence": 0xFFFFFFFF,
        }],
        outputs=[{
            "value": input_amount,
            "script": input_script_pubkey,
        }],
    )
    prevout_txid = nu5_txid_digests(prevout_tx_bytes)["final_digest"]

    tx_bytes = _build_transparent_tx_v5(
        locktime=locktime,
        expiry=expiry,
        branch_id=NU6_3_BRANCH_ID,
        inputs=[{
            "prev_txid": prevout_txid,
            "prev_vout": 0,
            "script": input_script_pubkey,
            "sequence": 0,
        }],
        outputs=[{
            "value": send_amount,
            "script": output_script_pubkey,
        }],
    )

    assert prevout_tx_bytes[8:12] == struct.pack("<I", NU6_3_BRANCH_ID)
    assert tx_bytes[8:12]         == struct.pack("<I", NU6_3_BRANCH_ID)

    client = ZcashCommandSender(backend)

    trusted_input = client.get_trusted_input(prevout_tx_bytes, 0).data
    trusted_txid, trusted_input_idx, trusted_amount, _, _ = unpack_trusted_input_response(trusted_input)
    assert trusted_txid      == prevout_txid
    assert trusted_input_idx == 0
    assert trusted_amount    == input_amount

    response = client.get_public_key(path=path).data
    public_key, _, _ = unpack_get_public_key_response(response)

    client.hash_input(transaction=tx_bytes, trusted_inputs=[trusted_input])

    with client.hash_sign_header(locktime=locktime, expiry=expiry, sighash_type=sighash_type):
        scenario_navigator.review_approve()

    resp = client.hash_sign(
        path=path,
        locktime=locktime,
        expiry=expiry,
        sighash_type=sighash_type,
    ).data
    signature = resp[:-1]
    assert resp[-1] == sighash_type

    assert check_tx_v5_signature_validity(
        public_key,
        signature,
        tx_bytes,
        input_index=0,
        input_amounts=[input_amount],
        sighash_type=sighash_type,
    )

    with pytest.raises(BadSignatureError):
        check_tx_v5_signature_validity(
            public_key,
            signature,
            _with_v5_branch_id(tx_bytes, NU6_2_BRANCH_ID),
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

    client.hash_input(transaction=TX_BYTES, trusted_inputs=[trusted_input], change_path=change_path)

    with client.hash_sign_header(locktime=LOCKTIME, expiry=EXPIRY, sighash_type=SIGHASH_TYPE):
        scenario_navigator.review_approve()

    # Finalize and sign
    resp = client.hash_sign(path=path, locktime=LOCKTIME, expiry=EXPIRY, sighash_type=SIGHASH_TYPE).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(public_key, signature, TX_BYTES, input_index=0, input_amounts=[81630485])


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
    client.hash_input(transaction=TX_BYTES, trusted_inputs=[trusted_input])

    with pytest.raises(ExceptionRAPDU) as e:
        with client.hash_sign_header(locktime=LOCKTIME, expiry=EXPIRY):
            scenario_navigator.review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_sign_tx_v5_old(backend, scenario_navigator):
    TXID_LEN = 112
    KEY_LEN = 268
    SIG_LEN = 142
    EXPECTED_SIG = "304402202b22627d88f9ecebf2ab586ffa970232cddad6eabb3289fa1359b2bc9f5554bc02207cfba5db7c01b89c5d540dcb1ada67d485ab1638c2151eaa78b4d368059c007801"  # noqa: E501

    transport = ZcashCommandSender(backend)

    # 42 - Trusted Input
    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280002598cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b")
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
    sw, _ = transport.exchange_raw("e0428000221595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800022a245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, txid = transport.exchange_raw("e0428000090000000004f9081a00")
    txid = txid.hex()
    print(f"MAY: txid: {txid}")
    assert sw == 0x9000
    assert len(txid) == TXID_LEN

    # Get pub key
    sw, key = transport.exchange_raw("e040000015058000002c80000085800000000000000000000002")
    key = key.hex()
    assert sw == 0x9000
    assert len(key) == KEY_LEN
    key = key[4:70]

    # Send trusted inputs
    sw, _ = transport.exchange_raw("e04400050d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480053b0138" + txid + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480050400000000")
    assert sw == 0x9000

    # Send outputs
    sw, _ = transport.exchange_raw("e04a80002301958ddd04000000001976a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac")
    assert sw == 0x9000

    # Send extra header data, which carries the validity window and triggers the review
    with transport.exchange_async_raw("e04800000b0000000000000100000000"):
        scenario_navigator.review_approve()

    sw = transport.get_async_response().status
    assert sw == 0x9000

    # Send trusted inputs for final hash computation
    sw, _ = transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000")
    assert sw == 0x9000

    # Sign hash
    sw, sig = transport.exchange_raw("e04800001f058000002c8000008580000000000000000000000200000000000100000000")
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
    sw, _ = transport.exchange_raw("e0428000257acad6b8eec3158ecee566c0f08ff721d94d44b0cf66ee220ad4f9d1692d2ab5000000006a")
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
    sw, _ = transport.exchange_raw("e042800022957edd04000000001976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, txid1 = transport.exchange_raw("e042800009000000000400000000")
    txid1 = txid1.hex()
    assert sw == 0x9000
    assert len(txid1) == TXID_LEN

    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280002558b3391f27adce90eb8e0ae7e082449204c6d5c3843378e538c8770928d49ca3000000006b")
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
    sw, _ = transport.exchange_raw("e0428000220a1c1b00000000001976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, txid2 = transport.exchange_raw("e042800009000000000400000000")
    txid2 = txid2.hex()
    assert sw == 0x9000
    assert len(txid2) == TXID_LEN

    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800025b5026481bfd3417f4a179e2094a944a60aaad5b2726544ca1a2c920fb65c9401000000006b")
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
    sw, _ = transport.exchange_raw("e042800022889a2d00000000001976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, txid3 = transport.exchange_raw("e042800009000000000400000000")
    txid3 = txid3.hex()
    assert sw == 0x9000
    assert len(txid3) == TXID_LEN

    sw, key1 = transport.exchange_raw("e040000015058000002c80000085800000020000000000000002")
    key1 = key1.hex()
    assert sw == 0x9000
    assert len(key1) == KEY_LEN
    key1 = key1[4:70]

    sw, key2 = transport.exchange_raw("e040000015058000002c80000085800000020000000000000002")
    key2 = key2.hex()
    assert sw == 0x9000
    assert len(key2) == KEY_LEN
    key2 = key2[4:70]

    sw, key3 = transport.exchange_raw("e040000015058000002c80000085800000020000000000000002")
    key3 = key3.hex()
    assert sw == 0x9000
    assert len(key3) == KEY_LEN
    key3 = key3[4:70]

    sw, _ = transport.exchange_raw("e04400050d050000800a27a726b4d0d6c203")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid1 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid2 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid3 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000")
    assert sw == 0x9000

    # Send outputs
    sw, _ = transport.exchange_raw("e04a8000230117222605000000001976a9147340a80cad7353cff25bad918e73837c2e2863eb88ac")
    assert sw == 0x9000

    # The extra header data carries the validity window and triggers the review
    with transport.exchange_async_raw("e04800000b0000000000000100000000"):
        scenario_navigator.review_approve()

    sw = transport.get_async_response().status
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid1 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000")
    assert sw == 0x9000
    sw, sig1 = transport.exchange_raw("e04800001f058000002c8000008580000002000000000000000200000000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid2 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000")
    assert sw == 0x9000
    sw, sig2 = transport.exchange_raw("e04800001f058000002c8000008580000002000000000000000200000000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid3 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000")
    assert sw == 0x9000
    sw, sig3 = transport.exchange_raw("e04800001f058000002c8000008580000002000000000000000200000000000100000000")
    assert sw == 0x9000

    assert [sig1.hex(), sig2.hex(), sig3.hex()] == SIGS


def test_sign_tx_v5_mult_outputs_old(backend, scenario_navigator):
    TXID_LEN = 112
    KEY_LEN = 268
    SIG = "3045022100867fdc2d2873b15bc19a42df288a257aff08ba74b9e2eefd1245e69b05a181b302200b876a40a9339b8b8333c332319dbe5329af363628e0fd4847b281719986dc7b01"  # noqa: E501

    transport = ZcashCommandSender(backend)

    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e0428000257acad6b8eec3158ecee566c0f08ff721d94d44b0cf66ee220ad4f9d1692d2ab5000000006a")
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
    sw, _ = transport.exchange_raw("e042800022957edd04000000001976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, txid1 = transport.exchange_raw("e042800009000000000400000000")
    txid1 = txid1.hex()
    assert sw == 0x9000
    assert len(txid1) == TXID_LEN

    sw, key = transport.exchange_raw("e040000015058000002c80000085800000020000000000000002")
    key = key.hex()
    assert sw == 0x9000
    assert len(key) == KEY_LEN
    key = key[4:70]

    sw, _ = transport.exchange_raw("e04400050d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480053b0138" + txid1 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000")
    assert sw == 0x9000

    sw, _ = transport.exchange_raw("e04480050400000000")
    assert sw == 0x9000

    # Send outputs and review
    sw, _ = transport.exchange_raw("e04aff0015058000002c80000085800000020000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04a00003202005a6202000000001976a9147d352e6e9a926965c677327443d86cb0bdf8b1e988acc11b7b02000000001976a91456464d"
    )
    assert sw == 0x9000

    sw, _ = transport.exchange_raw("e04a800013f31771790b77502f55895a396a64e74da588ac")
    assert sw == 0x9000

    # The extra header data carries the validity window and triggers the review
    with transport.exchange_async_raw("e04800000b0000000000000100000000"):
        scenario_navigator.review_approve()

    sw = transport.get_async_response().status
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid1 + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04800001f058000002c8000008580000002000000000000000200000000000100000000")
    assert sw == 0x9000

    assert sig.hex() == SIG


def test_sign_tx_with_v4_nu6_input(backend, scenario_navigator):
    transport = ZcashCommandSender(backend)

    sw, _ = transport.exchange_raw("e042000011000000000400008085202f895510e7c801")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800025b53e61d09f49b165a21fed754ab228e789193d664cd4ab026ccccaf6b30740ba1e0000006a")
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
    sw, _ = transport.exchange_raw("e04280002262e52a03000000001976a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280002201ae8700000000001976a9149014582e6407d13434d7dac8bb53e4616356501688ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000
    sw, txid_raw = transport.exchange_raw("e042800014000000000f000000000000000000000000000000")

    print(f"V4 NU6: txid: {txid_raw.hex()}")

    txid = txid_raw[4 : 4 + 32 + 4 + 8]
    txid = txid.hex()
    # https://api.blockchair.com/zcash/raw/transaction/3e5a39fa931ed6266042d7553f68d365cbb5da358fb0cffa0e66a3259ce8d30a
    assert txid == "0ad3e89c25a3660efacfb08f35dab5cb65d3683f55d7426026d61e93fa395a3e0000000062e52a0300000000"

    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e040000015058000002c80000085800000040000000000000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400050d050000800a27a7265510e7c801")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480053b0138" + txid_raw.hex() + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480051d76a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac00000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04aff0015058000002c80000085800000040000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw(
        "e04a0000320280969800000000001976a9147678416cb82a4a716dd1ee6b332744ba2a1f11c488ac30db8e02000000001976a914c628ce"
    )
    assert sw == 0x9000

    sw, _ = transport.exchange_raw("e04a8000138ff6367f0ea6763f1c1d865329af0715ac88ac")
    assert sw == 0x9000

    # The extra header data carries the validity window and triggers the review
    with transport.exchange_async_raw("e04800000b0000000000000100000000"):
        scenario_navigator.review_approve()

    sw = transport.get_async_response().status
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a7265510e7c801")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid_raw.hex() + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac00000000")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04800001f058000002c8000008580000004000000000000000000000000000100000000")
    assert sw == 0x9000
    assert (
        sig.hex()
        == "31440220488d0fca08431682cd5f10968a72affdd569f61a4a358f73edf05d0fb4a3e1a702204722751bd7d27f999ed714694ad024465d54c288a9cc560559d9594914d92ac501"  # noqa: E501
    )


# A trusted-input round over one real mainnet transaction, up to but excluding the packet that
# declares the shielded component counts. The tests below reuse it and vary exactly one field, so
# that a rejection can only come from the field under test.
#
# Layout of the first packet: requested output index (4 bytes, big-endian), then the V5 header
# (version, version group id, consensus branch id) and the input count.
_V5_TRUSTED_INPUT_HEADER_AND_COUNT = "050000800a27a726b4d0d6c201"
_V5_TRUSTED_INPUT_BODY = [
    "e04280002598cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b",
    "e04280003248304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736",
    "e042800032c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b46",
    "e04280000b9c616e758230a5ffffffff",
    "e04280000102",  # two transparent outputs
    "e0428000221595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac",
    "e042800022a245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac",
]
# Shielded component counts: nSpendsSapling, nOutputsSapling, nActionsOrchard — all zero here.
_V5_TRUSTED_INPUT_NO_SHIELDED = "e042800003000000"
# locktime, extra-data length, expiry height. The packet that completes the round.
_V5_TRUSTED_INPUT_EXTRA = "e0428000090000000004f9081a00"


def _send_v5_trusted_input_prefix(transport, requested_output_index: int) -> None:
    index = requested_output_index.to_bytes(4, byteorder="big").hex()
    first_packet = "e0420000" + "11" + index + _V5_TRUSTED_INPUT_HEADER_AND_COUNT

    for apdu in [first_packet] + _V5_TRUSTED_INPUT_BODY:
        sw, _ = transport.exchange_raw(apdu)
        assert sw == 0x9000


def test_trusted_input_rejects_out_of_range_output_index(backend):
    """A trusted input is only vouched for once the requested output has actually been seen.

    The HMAC that seals a trusted input makes the device's word final: the signing round reads the
    amount straight out of the blob. Returning one for an index the transaction does not have would
    seal an amount of zero as if it had been read from the chain, so the round has to fail instead.

    The transaction carries two outputs, so index 2 is one past the end.
    """
    transport = ZcashCommandSender(backend)

    _send_v5_trusted_input_prefix(transport, requested_output_index=2)

    sw, _ = transport.exchange_raw(_V5_TRUSTED_INPUT_NO_SHIELDED)
    assert sw == 0x9000

    with pytest.raises(ExceptionRAPDU) as e:
        transport.exchange_raw(_V5_TRUSTED_INPUT_EXTRA)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_trusted_input_rejects_unbounded_shielded_count(backend):
    """A host-declared shielded component count is bounded like every other count in this parser.

    Left unbounded it drives the streamed shielded sections, and `count * memo_size` would wrap a
    32-bit `usize` — silently shrinking the memo section rather than failing. The ceiling sits far
    above anything a real transaction carries, so only a count meant to make the parser loop is
    refused.

    65536 is above the ceiling and is the smallest value the five-byte CompactSize form encodes
    canonically, so the rejection cannot come from a non-canonical encoding instead.
    """
    OVER_CEILING_SAPLING_SPEND_COUNT = "fe00000100"
    counts = OVER_CEILING_SAPLING_SPEND_COUNT + "00" + "00"

    transport = ZcashCommandSender(backend)

    _send_v5_trusted_input_prefix(transport, requested_output_index=0)

    with pytest.raises(ExceptionRAPDU) as e:
        transport.exchange_raw("e0428000" + "07" + counts)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_trusted_input_rejects_v4_transaction_with_shielded_components(backend):
    """A V4 txid covers the whole V4 serialisation, shielded fields included — and this parser only
    feeds the transparent part to the V4 hasher; the shielded parsers feed the ZIP-244 digest tree,
    which has no meaning for V4.

    So a V4 transaction carrying Sapling components would yield a txid that matches no transaction on
    chain, sealed inside a valid HMAC, and the signature built on it would reference an outpoint that
    does not exist. Refusing is the only honest answer until the V4 serialisation is covered.

    This is the V4 NU6 vector from test_sign_tx_with_v4_nu6_input with one field changed: one Sapling
    spend declared instead of none.
    """
    ONE_SAPLING_SPEND = "e042800003010000"

    transport = ZcashCommandSender(backend)

    for apdu in [
        "e042000011000000000400008085202f895510e7c801",
        "e042800025b53e61d09f49b165a21fed754ab228e789193d664cd4ab026ccccaf6b30740ba1e0000006a",
        "e04280003247304402202ffcfd634ae68631af2435b537d33e86a0a38338e3841aecf6d0f54cadef979f0220469c7cd94d52be1183e4f9",
        "e04280003275035388254a4b49a22bee691f8b3d32e65b05167e012102529734fe55e9de06341c90ab8dc11f144ddcfaed136f49edcdb2",
        "e04280000a875bfb0eadb3ffffffff",
        "e04280000102",
        "e04280002262e52a03000000001976a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac",
        "e04280002201ae8700000000001976a9149014582e6407d13434d7dac8bb53e4616356501688ac",
    ]:
        sw, _ = transport.exchange_raw(apdu)
        assert sw == 0x9000

    with pytest.raises(ExceptionRAPDU) as e:
        transport.exchange_raw(ONE_SAPLING_SPEND)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


# The legacy signing round up to, but excluding, the change-information packet. Reused by the test
# below so that a rejection can only come from the derivation path under test. Same vector as
# test_sign_tx_with_v5_nu5_input.
_LEGACY_TRUSTED_INPUT_ROUND = [
    "e04200001100000000050000800a27a726b4d0d6c201",
    "e0428000257acad6b8eec3158ecee566c0f08ff721d94d44b0cf66ee220ad4f9d1692d2ab5000000006a",
    "e04280003247304402200d6900cafe4189b9dfebaa965584f39e07cf6086ed5a97c84a5a76035dddcf7302206263c8b7202227e0ab33dd",
    "e042800032263e04f7a4384d34daa9279bfdebb03bf4b62123590121023e7c3ab4b4a42466f2c72c79afd426a0714fed74f884cd11abb4",
    "e04280000ad76a72fa4a6900000000",
    "e04280000101",
    "e042800022957edd04000000001976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac",
    "e042800003000000",
]
# The path this vector legitimately uses for its change output: m/44'/133'/2'/1/0.
_LEGACY_VALID_CHANGE_PATH = "058000002c80000085800000020000000100000000"


def _open_legacy_change_info_state(transport) -> None:
    for apdu in _LEGACY_TRUSTED_INPUT_ROUND:
        sw, _ = transport.exchange_raw(apdu)
        assert sw == 0x9000

    sw, trusted_input = transport.exchange_raw("e042800009000000000400000000")
    assert sw == 0x9000
    trusted_input = trusted_input.hex()
    assert len(trusted_input) == 112

    for apdu in [
        "e04400050d050000800a27a726b4d0d6c201",
        "e04480053b0138" + trusted_input + "19",
        "e04480801d76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000",
        "e04480050400000000",
    ]:
        sw, _ = transport.exchange_raw(apdu)
        assert sw == 0x9000


@pytest.mark.parametrize(
    "change_path",
    [
        # A ZIP-32 account path: the shielded shape, which carries no change component at all. It
        # must not satisfy a check whose whole purpose is to constrain that component.
        pytest.param("03800000208000008580000000", id="zip32_account_path"),
        # Change index 0 — a receive path, not a change path.
        pytest.param("058000002c80000085800000020000000000000000", id="receive_path"),
        # Account 101', one past the accepted ceiling.
        pytest.param("058000002c80000085800000650000000100000000", id="account_over_ceiling"),
        # Address index 50001, one past the accepted ceiling.
        pytest.param("058000002c8000008580000002000000010000c351", id="address_index_over_ceiling"),
    ],
)
def test_legacy_change_info_rejects_non_change_path(backend, change_path):
    """The change-information packet is what removes an output from the review screen.

    An output the device treats as change is dropped from the amounts, addresses and memos the user
    approves, so the path granting that status has to be a genuine BIP-44 change path. Each case
    below differs from the vector's own valid path in exactly one component, except the first, which
    is the shielded shape and has no change component to constrain.

    The PCZT path has the same guard and its own test; this covers the legacy one, which needs a
    single APDU to reach it.
    """
    transport = ZcashCommandSender(backend)

    _open_legacy_change_info_state(transport)

    with pytest.raises(ExceptionRAPDU) as e:
        transport.exchange_raw(
            "e04aff00" + f"{len(bytes.fromhex(change_path)):02x}" + change_path
        )

    assert e.value.status == Errors.SW_CONDITIONS_OF_USE_NOT_SATISFIED


def test_legacy_change_info_accepts_the_vector_change_path(backend):
    """Counterpart to the rejections above: the same state, the vector's own change path, accepted.

    Without it a regression that refused every path would leave the four negative cases green.
    """
    transport = ZcashCommandSender(backend)

    _open_legacy_change_info_state(transport)

    sw, _ = transport.exchange_raw(
        "e04aff00" + f"{len(bytes.fromhex(_LEGACY_VALID_CHANGE_PATH)):02x}" + _LEGACY_VALID_CHANGE_PATH
    )
    assert sw == 0x9000


def test_legacy_continuation_rejects_a_round_before_the_review(backend):
    """A signing continuation must not restart hashing while the review round is still open.

    HASH_INPUT_START with P1_FIRST + P2_CONTINUE is the signing round: it deliberately keeps the
    output amounts and change classification the review round accumulated, and only replaces the
    input parser. But while ``is_tx_parsed_once`` is still false, parsing the header also
    re-initialises the V5 hashers, which empties the outputs digest.

    A host could exploit that split: declare output 1 as change, send this APDU, then finalize with
    output 2 alone. The fee shown to the user would be computed from outputs 1 and 2 with output 1
    filtered out as change, while the signature would commit to output 2 only — so the value of
    output 1 would go to the miner instead of back to the user.

    The same shape sent at its legitimate point, after the review is approved, is exercised by the
    multi-input tests above, which is what keeps this from passing by rejecting every continuation.
    """
    transport = ZcashCommandSender(backend)

    # Leaves the app mid review round: one input hashed, outputs not yet finalized or approved.
    _open_legacy_change_info_state(transport)

    with pytest.raises(ExceptionRAPDU) as e:
        transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")

    assert e.value.status == Errors.SW_BAD_STATE
