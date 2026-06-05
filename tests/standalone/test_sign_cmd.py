# pylint: disable=C0301

import struct

import pytest

from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

from application_client.zcash_command_sender import ZcashCommandSender, Errors, HashSignMode
from application_client.zcash_response_unpacker import (
    unpack_get_public_key_response,
    unpack_trusted_input_response,
)
from application_client.zcash_transaction import convert_raw_tx_v5_orchard_to_app_format
from application_client.zcash_verify_sign import (
    check_orchard_binding_signature_validity,
    check_tx_v5_signature_validity,
    nu5_signature_digests,
    nu5_txid_digests,
)
from application_client.zcash_utils import write_varint

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
        screen_change_after_last_instruction=False)


ORCHARD_SIGNING_PATH = "m/32'/133'/0'"
NU5_BRANCH_ID = 0xC2D6D0B4
NU6_2_BRANCH_ID = 0x5437F330
BINDING_SIGNING_KEY = bytes.fromhex(
    "1f00000000000000000000000000000000000000000000000000000000000000"
)


def _repeated(byte: int, size: int) -> bytes:
    return bytes([byte & 0xFF]) * size


def _build_orchard_bundle(action_count: int, value_balance: int, seed: int = 0x40) -> bytes:
    bundle = write_varint(0) + write_varint(0) + write_varint(action_count)

    for idx in range(action_count):
        bundle += _repeated(seed + idx, 32 + 32 + 32 + 52)

    for idx in range(action_count):
        bundle += _repeated(seed + 0x20 + idx, 512)

    for idx in range(action_count):
        bundle += _repeated(seed + 0x40 + idx, 32 + 32 + 16 + 80)

    if action_count > 0:
        bundle += b"\x03"
        bundle += value_balance.to_bytes(8, byteorder="little", signed=True)
        bundle += _repeated(seed + 0x60, 32)

    return bundle


def _build_tx_v5(locktime: int, expiry: int, inputs: list[dict], outputs: list[dict], orchard_value_balance: int) -> bytes:
    tx = b""
    tx += struct.pack("<I", 0x80000005)
    tx += struct.pack("<I", 0x26A7270A)
    tx += struct.pack("<I", 0xC8E71055)
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

    tx += _build_orchard_bundle(action_count=1, value_balance=orchard_value_balance)
    return tx


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
    ).data[:64]

    assert auth_sig == expected_auth_sig


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
) -> None:
    tx_bytes = convert_raw_tx_v5_orchard_to_app_format(bytes.fromhex(raw_tx_hex), [])
    locktime = int.from_bytes(tx_bytes[12:16], byteorder="little")
    expiry = int.from_bytes(tx_bytes[16:20], byteorder="little")
    sighash_type = 0x01

    client = ZcashCommandSender(backend)

    with client.hash_input(transaction=tx_bytes, trusted_inputs=[]):
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
        "050000800a27a726b4d0d6c2" + LOCKTIME.to_bytes(4, byteorder="big").hex() + EXPIRY.to_bytes(4, byteorder="big").hex() + # header
        "01" + "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a" + "00000000" + # hash + prevout idx
        "19" + "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000" + #input scriptPubKey + sequence
        "01" + "958ddd0400000000" + # output amount
        "19" + "76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac" + # output scriptPubKey
        "000000" # empty sapling and orchard
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
    resp = client.hash_sign(path=path, locktime=LOCKTIME, expiry=EXPIRY, sighash_type=SIGHASH_TYPE).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(
        public_key,
        signature,
        TX_BYTES,
        input_index=0,
        input_amounts=[81630485]
    )

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
        branch_id=NU6_2_BRANCH_ID,
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
    trusted_txid, trusted_input_idx, trusted_amount, _, _ = unpack_trusted_input_response(trusted_input)
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
        "050000800a27a726b4d0d6c2" + LOCKTIME.to_bytes(4, byteorder="big").hex() + EXPIRY.to_bytes(4, byteorder="big").hex() + # header
        "01" + "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a" + "00000000" + # hash + prevout idx
        "19" + "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000" + #input scriptPubKey + sequence
        "02" + "005a620200000000" + # output amount
        "19" + "76a9147d352e6e9a926965c677327443d86cb0bdf8b1e988ac" + # output scriptPubKey
        "c11b7b0200000000" + # change output amount
        "19" + "76a914adee44a1e8d1bbfd9e000bdcc4d99849abe339f588ac" + # change output scriptPubKey
        "000000" # empty sapling and orchard
    )

    path = "m/44'/133'/0'/0/0"
    change_path = "m/44'/133'/0'/1/0"

    trusted_input_idx = 0

    client = ZcashCommandSender(backend)

    # Get txid
    trusted_input = client.get_trusted_input(PREVOUT_TX_BYTES, trusted_input_idx).data

    response = client.get_public_key(path=path).data
    public_key, _, _ = unpack_get_public_key_response(response)

    with client.hash_input(transaction=TX_BYTES, trusted_inputs=[trusted_input], change_path=change_path):
        scenario_navigator.review_approve()

    # Finalize and sign
    resp = client.hash_sign(path=path, locktime=LOCKTIME, expiry=EXPIRY, sighash_type=SIGHASH_TYPE).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(
        public_key,
        signature,
        TX_BYTES,
        input_index=0,
        input_amounts=[81630485]
    )

def test_sign_tx_v5_transparent_to_orchard(backend, scenario_navigator):
    EXPECTED_AUTH_SIG = bytes.fromhex("A41879FFC0B32C7C5ACC231759C5935AFCFA3EFCCFDA04F400CE5D7A2F505B13936CFD4C4C5B55AAD706476A58B76768D42F57F75F1A68032A62C2FFC0EBFA2D")

    locktime = 0
    expiry = 0
    sighash_type = 0x01
    prevout_tx_bytes = bytes.fromhex(
        "050000800a27a726b4d0d6c200000000f9081a000198cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b48304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b469c616e758230a5ffffffff021595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88aca245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac000000"
    )

    tx_bytes = _build_tx_v5(
        locktime=locktime,
        expiry=expiry,
        inputs=[{
            "prev_txid": bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"),
            "prev_vout": 0,
            "script": bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac"),
            "sequence": 0,
        }],
        outputs=[],
        orchard_value_balance=-81_620_485,
    )

    path = "m/44'/133'/0'/0/2"
    client = ZcashCommandSender(backend)

    trusted_input = client.get_trusted_input(prevout_tx_bytes, 0).data

    with client.hash_input(transaction=tx_bytes, trusted_inputs=[trusted_input]):
        scenario_navigator.review_approve()

    digest = client.hash_sign(
        path=path,
        locktime=locktime,
        expiry=expiry,
        sighash_type=sighash_type,
        mode=HashSignMode.Digest,
    ).data

    expected_digest = nu5_signature_digests(
        tx_bytes=tx_bytes,
        input_index=0,
        input_amounts=[81_630_485],
        sighash_type=sighash_type,
    )["final_digest"]

    assert digest == expected_digest
    _assert_hash_sign_authsign(client, EXPECTED_AUTH_SIG)
    _assert_hash_sign_binding_sig(client, expected_digest)

def test_sign_tx_v5_orchard_to_transparent(backend, scenario_navigator):
    EXPECTED_AUTH_SIG = bytes.fromhex("B8300605F413E7CD3426F63B9FDE79594949BF57CC952CF32ED2486507773CA281353538C4AB6AE8C6597D2DB403BDC8285382BB0824E3055A661FEF64813008")

    locktime = 0
    expiry = 0
    sighash_type = 0x01
    tx_bytes = _build_tx_v5(
        locktime=locktime,
        expiry=expiry,
        inputs=[],
        outputs=[{
            "value": 1_085_000,
            "script": bytes.fromhex("76a914e58749ee655c0e39ae3ce063a33fb9edc86d23dd88ac"),
        }],
        orchard_value_balance=1_095_904,
    )

    path = "m/44'/133'/0'/0/2"
    client = ZcashCommandSender(backend)

    with client.hash_input(transaction=tx_bytes, trusted_inputs=[]):
        scenario_navigator.review_approve()

    digest = client.hash_sign(
        path=path,
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
    _assert_hash_sign_authsign(client, EXPECTED_AUTH_SIG)
    _assert_hash_sign_binding_sig(client, expected_digest)

def test_sign_tx_v5_orchard_to_orchard(backend, scenario_navigator):
    EXPECTED_AUTH_SIG = bytes.fromhex("4D5D13165FB9FC0B419DA7CA7BFE6384B528237093D7F6D460566F0BC5A8EE2FDEDE8A2A467D3E67EDAF3395921DF4CB6C01D8B3200CE98B21F5327D26515510")

    locktime = 0
    expiry = 0
    sighash_type = 0x01
    tx_bytes = _build_tx_v5(
        locktime=locktime,
        expiry=expiry,
        inputs=[],
        outputs=[],
        orchard_value_balance=10_000,
    )

    path = "m/44'/133'/0'/0/2"
    client = ZcashCommandSender(backend)

    with client.hash_input(transaction=tx_bytes, trusted_inputs=[]):
        scenario_navigator.review_approve()

    digest = client.hash_sign(
        path=path,
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
    _assert_hash_sign_authsign(client, EXPECTED_AUTH_SIG)
    _assert_hash_sign_binding_sig(client, expected_digest)


def test_sign_tx_v5_transparent_to_orchard_real(backend, scenario_navigator):
    TX_PREVOUT = "050000800a27a726f04dec4d000000000000000003fd16e46e4af3e3e73987d8c3af6828157ac2ec65af65ab7001fe04ed46f90269000000006a47304402203083e4e394d2a967f44a7d2eac6a176ab981fd71037e4a5fae3a9d0a258b5776022054f9a2a37923adcf5f2cd51b9cd171368ba52b91b433f4e840dff1d7ddfc7fce0121028cd25f41a34d2b1c831ec7e6304207bb5018f5a428e7996979e0c46e74780703ffffffff0094b4d6e3861d76160676b3d87cbe187fe8b52720dad630aa85511e58e02da9000000006b483045022100c23c872248bbb25a078be2f2676590c489b2552c01d334218ab35104aec22148022063edf8e3c76e3ed3e5c83e0d82f94b7e81b7c375ffd0824c92313971d3cab5f70121028cd25f41a34d2b1c831ec7e6304207bb5018f5a428e7996979e0c46e74780703ffffffff2f683e72cf16d05d712966f0d7abf1e30bf5d59779d14509026a22ca408f7415000000006b483045022100fff61a408c128f320c6f483cc90dd2df1dc14f5fe4e47c4db1744969b716ea1a02203399080f4156e7b1818fc773437a7ea9891e4edf1ca4220971401e734fd5847f0121028cd25f41a34d2b1c831ec7e6304207bb5018f5a428e7996979e0c46e74780703ffffffff02cf3e7605000000001976a914481d713d2c660ae85c376deda7aa31457c96eb9488ac04130300000000001976a9144a8c4a21a1cd793ef4bc176fedf70d44f1a8b9ba88ac000000"
    TX_STR = "050000800a27a726f04dec4d088132001c813200013fb481d4b4c656d332bbbf1df76feaa88660fde8c7450c549bc726936fd1c499000000006a47304402207e2a525a91a074bf790ed7e4293ee23da76816bdd6af1ea3432906e1e70a8ee202201e02c9b19f3cf87d664049996694acefdbaee1f46b7b68ce9ace06fe26f5fbe301210263c30851c8ee7e4fa89e7928ad105cf3678fbf876b6bec5b78ee76be63dd3c99ffffffff000000026d61fd352d4a77706a8bd6f94443f43bdb41f2553e5c6f34af0681fafb3357986fc0c30dae739160f7cad8b64fc7dba022e14a9eac4ca9d8804658dfe028d224fa1bc4c36758db9eb28688dca62f0be48637b84ce3da9a5cfa5996e7ae5f9537bb70cba2686136772ff0345d702ce2008ce2af2a41d1bb1c46dd4d0de71a2727d1af59ae851120ccc00e6344057b957c960221eb961792c32198c1809bcffe2054c73107fdcb9bf534d102f16b81554e942a1660b026fc544350a90f0d57f0665a408cb8c5a79499ac170aee894acd7bd11f957db4aacbb702cf289db264d4a14d994a734d481cdef72db1295edde12ad0ce9de74b7e3512522c1a0b056062c95cf3e4579a5315909c10d0a2b35edc4048cce5593db6181493bb0d7d9f162e12c35978292beefe7573eb2551852a022f630da41617f5cc1de50cdb17f97c45563df5fc33a2a0e0cbbf4e21b95ff6770596349a2467c2b4aa8140e3af9f683d72e9ba125b93d8807367c86fe0958a134433ea56149592297683079e59e40e00654d688aa2a8704cbaf81cf770ab4fb89b1267775e4632f9c08f509ae96c603d087c502dc30250a33cf8c538cea10d8bd5e76688b92d2f6bd031d0e81d993063af52c9d3924a359ba6082ab8c09b43b76b5eb78b955bb6d86f21d9779a9cd1db53d8087753110ab1c6af93e2d5bae07d9dade5b14210ffb765fd0543cd6f2008d5236fa79dfda3a66e6ab7a70af3bb4a33ab1c153ed90136056db9956d31ce98aff1067faf48c150dd3f236a7abc665d3c80a5d27df750e93bedaf5003f0ca5f47082e2290bb63adcde8d42d8724119b0063054358be5b287befa6f9973815850ca9387c5a7171da753aff34b2e74e584542be707bf9736cf15b710c9725004d2a46a900aaede976902ebad632f2ed441d6928dc333098c29a4a22ce95a1dd37016b2268a7bf57c56c2c1d830c6738e9795caa36ae5894b7d67bb9e1c988a864401efbe5d79fe175d5e58bc653a6822db41d9ad95383f355d5a0b24996f6126b72c38fb1eb1f80322403c80615c3e35d6db8c8f45577b00410c8820e31a21d9d44857898168c0e16b92c86afe29e38125c212234acfef95043f636238d6b538d5b6ed247b7e6c0a280f5d912b9ee06e23bede01b8597b49de6de5e0fa14d26dae52af7f35d4b71f96e7d33610b85f4b84c9492920951427bb6e3a09beaff333162a7c5819cf3d5f208b3ac25b1dfc5430bfe606409ee07771e385defdf44ac9759536daee4ca09b66e5523e9dd587d16333dba04b6a2c07ea2f594fad91218de6a26c28f00117ffc5803e331eee52585be5e51bb1cbdd86fc1b0dfd832ac4bc17c9dc548a6506dbef1999c34961949ab2482cf8aad22172b393c4fd8cf90de994e42cc41a754421df2075198564de88f585ab2db04d974f3a33d48d01257032a8b8574fed1e5b75dbfaec99b7df9558059f4029c3fb2d16ad5d690286ddbb668003ce0a81282f9ea26eacc65d68ff25830632f4119b927651ecedaa1975c6a165ee0505320c3537720fc344594008503b4694310e4e68a57f568c8d09d63b8d0d3f6351c3a4f02832ea89898a6a5cc85ad6040ffd4e0b28e50f2f1914037331ed8ad4561ac967b9eb979bdfe190cc5987a37ec0978d85ff6c13cb7d56775eeeeebf14658f9a2b2975b1a377f475ff20cbdfbbbd6dc64e5bae5c7120dcd179a6e27ce4670b5991d3ab0d5812d46523664638753fd8d0397e5e5f947e4a7181a7c6bb83ccc99e6287f6c115016dea16801a0c1db14b0e0717b7766b8f94844392cf29961f84bc61e4fa2c54b499bdd2511be9d03a56efe37380e8ac1cc9592e15bc70e669f819d98e1e18a0bb0a1e5e8f6a08564b2bafaac68893e7a134375b9233cdfd5fd4e200abd43cfaeaac28b488b54112af53cfd9a2a92b25dc46d72c22cf03c94a242377005d5c2040d0d517b6cdd812693119ebbaf633db3494bb88a58f77799f56b16799b9b292167c630cd173d49734ee32c0bba6682d19aabeef76aba79eb7f516f33759c30ae22f07f0288ffeca0c47fe5c76bda59f4a77dfeeb53b0c9a7fe59da1061b177e1ddae4bf23a0c4709b80853dcb0d7530738cbcf822877de490e8421014f7b857e9fc2e8c23997bb4eaf19396146ef1c07f3ac89f0b66d591f997b0afaaf70929f400b1f0fe21976a9a09c408ca765ec4b877fa8d9f7373c2c160d9714617cbb9920299c85fb1024542bf8b6ff177a464bc652b8ff66b5fe3c8c77b0388c9f6bbd8d12b5952da7f8d72eeac27dbe0ee0849dc70aad5d81ee4c311621047ab103c9fb89faffffffffce4ab933f8af352a66e99a0593b42201113f3a163d98ab8d18d44860d610e315fd601c3eed3c96ea250fae4f01499e5c159da53ddbe13c853ed95c3b09f8f3ef29c238a133cb3fe9179b2d59cb4ccda2232b9f4d3b7daf0e15d46eb46cefb98669d9a477ae0f2ec487989c57348e89ca1a8cc35f6beb6a2313a4515711553b92fa251d37abb0a42d7e29f17cd90a2dec2eb4d6be14156c097d80a3c02b5bd812ef66314ebf9378a7ecb030e29098e3253e8f83c704f6f150cee4bd66a426ef39c453061091c6b57289c66a3aa1fbd9b7460e56fe6bb45eb206cfe398b183085fb353a6e321d72fb6301b0bbbf75293089075f81ff9e9f36518f442569464468f87e68bbaf5a2ad09aaa5abfb20f690bf8bcfa0d25c6465d038148431a1ee5d63f95281e7abd471321e5912eabfabaa1075b18b555746f58290449004affbaf42de5a35d035dcd5164dff59818eeda61505cd16ecf03824ee91e5baf2007892ca72eb063d38eaf63f68322a535a175f7079e1ba18a6e66a093e686b525fe1da63c5feab0473e1153d1ce6549dddee0c40f9873e34570dc480d77354d8e7acc9646b619c76da78ce89eb36860ddcb21286ce2031ea52952ae20a164957c537a1e843e58c3e99c34f9cdb09c77dcdd172c4ef514f30f20de0fad8ca8e963de4db7e9afbb95a7b4f850f67c8be18e7fa97f9f3dd04942d16f79b0d2361b6bc0161277f2492596bfd3f2b283f68be2fd327558c11934f4aa730868011bd559d6029b34bcabe5a1a40a37fb8d9b016f2b4dbe6814d80d2e8153f9c4bcb55944c056fc750df99eb12d8e530fcd0aa2cbdcccb5fc948917882573454f0b77a9bca2e283c8171211b119f01fa9f6ca647ffa2b9a46e75aa561b9e7f6d89ea5d46dba05c391707079ada0ad07fc41ae98427ddcfbd7db54e37953db22bff081cccaed3f6a1fe462118f0038ea237e38d89426cf6644ab413631ac0cee99a5cbd97345aff943a5f0909b08c3d2a78155c97d3f3aec3d802ebc52a63d8755924186b2cce7e325388a8794f8f81fccd28079c506d313909f9f26ba6a68361473fef1c28f6126dcaa118a3376877671755dc846086dad40a69e26be4897ef0703a4af9baf0cc376cc22ad51248feb9b198b005f23c2d4cb7d076a886af5458b8662a8ce6347588ea042ab7bf7503443a71e161830c29ed5fd31b5ef2008a9d390d398612d10761b8d88a8922e101fc4146bc885095235482782cf1eef157a02911464df66109c01b15afbd989a35f69b10ae5c8d84de9af0311467268c9154fc1b3afdbd20c1b931053231084c73691da121c533170c2d41eac50e7ba0b5650fbb80edb980c67f4bc0a8357c77f9ab8a1b8bdc7af41dc12b094e1d63fca18fbf3894dbf73d3a50aa542657418ffe53ca1857bf0a40abd9305c32382b4d4c0dc1ac4dc677bbeb4c70d01da9b3249be60596b1c75de79d962a1d5ad022f82867bbc9878e7275491f36ad2f497d615c75ef23f6108b509c8b16b4e0ef152454783ad97771bb8853d987c122eaa8ae6df36bfc83a15bb864bbd8e1d2a9031eaf9001d158c69f77e3c3c621132706e319ce45e8904e77cfd5bf6349888e158d83fdf874b5348f80660c95102ddeaa4744a99c2b448eab6d7c1a3f5c069f62baedc1ab2ccfc0a7d6e4de532b2528fbe0cefe5b076b008981fdb14a29c0b20554993e8aa662b2955fa76c90efae1af6ee11e2af6ec5ba7a35645efcf5b9b78750b2ef1a79c74399a87bd3d68728ee67b3fc5814059aa567355e88b14d8356932724ca89534817c4b46a1dc555ba46c45ad67670f327a8a1e7166c6e46870638f3d6ec9e48be8c5a18671ef696a3d94b4afa740d10c6fc131af510b9a4486951c682be1a42ac251f8073ec288685c54ba9063a5408fc43281af0168f51d292c03a3a0b8a08720bc1cb8b6d6724bdece4fa5b99cd56a631b436af334c94ba5b33cabe5ad2ff4bf1cbc1a785525db556baca70ef881486b0b0df4a4e5416c83233fe12a8e1a7d7dce710bead43f0152869a0b1908098ada1cc99c81e03975cdbbff55bd7567108057ed9738edf139aa7aa9f637dde4ab8ea073df0dc41379dd818a09ce2c22e13a5a5536a3c605c3b80dc9ae9ea5ad6793516c362e173a7e042bd087117dbb8e77aed04519a14e805ba29f4734d6485d5cc9bf80ed5b8bce495745096ddcec5a881aaa2889197719c66b0eda84c0c8898837e8634bd0ba78b020536fdf5ba74f3aa943c656d8423b5d6ac1e5332998aecc19516600b5bdb5ad222d6311116d6cde7b51d1aebc780869ed31775327362fbab4550808d65bea56b17837ceac868fc65430bb5ecd74291104c970f2d9e2c27b3f0064f10614b1f3a2efb1b33561c365512d5cd443ed2935f74fda79b01c7acfad323630bbe519a9a4a42eb884569012cc646d2155c5d97d67de7c1a7e00ee829f82b81f1f85b58c732bc6c58614df632d6bba6ea34cc2bed9bf24e78c0aacdafff8300d181e013dda1cb1f39a092ad5c21a7cd0fb956278e34292226ce56debc064fdf07233310358a2009b63581d602e944f5e577900e89fb91629120c0e5c620d5c3680ee67c612ab471af02ff2ba9dc5c4a017e27192af00689e056162b0392f94a2e96a0d4ce4abeb1f27d097b3de0b216339dbf1004d8ec73ea659165544d18f765603317c8e24a20139da3b330fdd39b01f7d41a022695278f60fb7e531e37b60abf698a4dbeb76b335f5b858d3c1001f94c2f273241b17276676bfa1af7b2aec52959510b01f9aad54d48d2844ea14f63ee3400306d2d81ecbbf82b0f6f2bdf1f80ed326a8dfb3d00b11e023f69f5c6d3fac239b0176da9540bbf0ac4d1a7e6837994a0e6bad8509f3bac0bcaa681d546b4c126184b8c7939cd9dc0f913793d91648efdb806b0f9531a6a42a25902e4ec055723babd5c0f77a892ec41043705f6d162c5d55e7d07abc966337406e2ebc7dd9a0186d997de1973594bab59e0eed17083e55450193dcb4189bb3d872559c27bbb3011f44e972f0605d3c122a7609d817b50d56a018ff24dd61d61f3672ba720b71a21b700d68673119f399d109d22f949394ef1cd601b82eea84e3cf70def62aa121f98af4eff1def1ca7a69f5647e69a05b7fe7ecf1e978165e294ebea27cca312bb3a20609665931625a4f992a50461929a4ccc12c612ba6f96eeb2e9b18b923b27b8d1b0fa909700a25c0f3a439667ef76f42d354a0f4ea55ddb871e3802423c9b217d61c76060fc923bb17b4015f92f3341bc8faf63ed3768c21dbc9f3112114996ccaa3ca703710e0e5aa91dd47f198d66f001847eb531bdf34b0e406c4301cb26f3a3511f64f21a77e078c9d84e638704757b81bdb4fd2d8848127639f628d6760f158e4c3d773f0e15b10d04b660f76c15fafd0cb22e933c756aa698f319f61537b4370de2239fe247f3a6e8ca168b5b9d68a635cbe33ba5d4c6f61f8e103629f5667d63a84faa4e8b5f47d17d70647f7c21f8cc1c2daa1d4d4d2eb7632606abf192ef0815a3833064f98748a4d23a597d521bbd96b51fe20f931dd4791c9bdf604f61439b6096f5c0980c7c05bedac401b2523a06b89064772d6b53fd1c389f57e682e4658745e4298078be800059bb7964d9cd2b5def73610232658926544701deac61a44ae4197ee38f896e3d987e48b8fb66d89b0f6c1d6715e29018d6b70c335cc1b3faa31b4dc28d0e20dec2a5289ee7bec9e35adb41a478f1cd0bc1bd8ec599b45c40dc4709fdf330ecf8e72cf70cf05317b7d11a0e141c623b0092f90dc13aac3689e9f9bc12732dc690b85ad837f98ed34d9ba4e0efca7c2d20ddb710588f6afd2f292c2ecfabe1797544b3fe5d3a5f30a20d36fa6a44e66015d892b00f03b3a0abc71b0979aba59cd1afd6b078f1af935d442fa0d152d29806d3f93ed8743f93be1a66b99418076098316493291a4c550617b2522decec2f200c5dd81f70d4c2b3329a2e14322f7ee68f5f0fbf254cc4c609c52c7055cd2330ac2f7188507df0a6987cd34b8e709aaf05f50be69c780f7038e781b29438c304411378f20af900dbb5e6a383aa8c6fcbeb07d08894636b33825359e3b95279211bbb8d2f3d323691bf1b325aac1397c4e1712d8dfa2293ecbf33e5a781daed02742e24eb5d5ee3a350225243f740cf937b218739848d14ec6173d298fd0fc2192fc9fe24a7c5f65d4a4bbea4916b439cc311a79dd9553f0a1c1fed5c04cb30378a27256ef42a1cd727316fb7dde28f8f87fd4ee218d9f2ff3beadd397336bf34c47f9f08ce79e64574d6e0d7a4b301305ddd78c2ec4746a9cea3e97e78d9643538838dce5115a55e1efd279a00ba063c9b3f8172198350255c2845a3847d0724cce3f20260e285b392fae4599fbec5579095fc3fcb1084908ec93d61b938d90f063b9ad3c20756fc2de2b8e91c862c93eb0e16a1f5fdbd75427ed89850b7b416cf52e8feb4b9403894140b3932b4b85ec00d6efb95b5f042ee9b5a0efe3e0f0c661e68f7b8558cbbaf97d25869eefbd154a4d0933c68cb573279973ed1de5f33a77efb9b9d7fdef32890eddb3dd7125fcbe2d0081382f62bf489d331c3c24b29a2bb5b14938556070ae3aa5317a21f4fc4413fd5db9eb4e243886f469930b7131e9a104353c5544279bb0789598ffce8a024039e9769c110507f8c40fd8a680acec84b15ab5ce38918223526e2df98a64c3a6109d86bf6b75931552f95aa0e20685cab76def2649eb99da48c2d73c134a4eb1daeafa0ffe65995c4a8a0196a11629446bffe4671e1200a0f6218cf430dc4ef0f7ae574e3255fb52dd8f7d41239fcbaaa7155c72b7f88e374a895584a00496290bef74a42479c914c11899ecf0ebfecdd68d623ae7eaa2794e38ba8682059f15c5f07fbb54f030c7f438060fc386d032fc825aedf63788f2a66e37bfc647d85c3008c43e02f83e85e71fc3bdc2f28cc790c4bf0702a3bbea90b0fbfcd32ee45192c697a1f24071cea81dbf8ea375f02f103045cfd3cdaf247427839de91449113abe68e2121ff9fcd897bd7670bf2fa1e4bd1fbbef6c71121e94e880e23d3176ad9ac3000894edf951df5227739e621b307450a983e298654580cba325388efa7fd01003636b393210651abbe2a840b00cd37d7c2e9b7b91dfc08adf5fce86769270a7d2ddbccf41910a79cf432e6038c6666bd603d7b7ff4e3d545d5ca347e3e76132aaa29b7756130d330f31c5f00725ad5b746f9ee3ecf1b26da197c538175c83e36e85e535cfe5805f6832700699134836ff96bdc26c22efeefdc6bc9505e186df18281420a8acdd5d52e1abfc9c9fd9e0f67be54afb7c5907c92fef979ee28bbb65f5b5c1e04469d906613d68ccc64fab749862cc20af14d26b347be52d0e3a5e0f03caddc20074eaa0a1d102ad83553cf8131bbf35f7150eb70f9b6e86da8baa222db77a255938c62d826750686f5b8e4909a5f98a162aacd2ebe57462627f44634a8a9047b1fbb7cea39ae1cbee0e1a0ea4c1807af72ec49cda9a481cff00d2265726deb55588c8a353abc1ea3f2d953b4eb966a762faa979bdd76d621170f23a2e7157a423525a80719143a6659f7d668bdb6c4399257af3cbee3ef4753c728f9d2a5aa4e950547560f33f62a6ead40a313a157f3ed6ad80c53969fb2ab1826029be425055afd5a910a97af4ab023f09f3c89d67e423f59cb22e0de450466d2a3da99bb8a8789cf6d074c55def22ca0212a96af0b2149c09cc410eceeeb2d1f80622f26304aa63e401f485a857932bb4fe8c12016697c0bfaee061cffb476da425ad99afea30346363fb6818ec9e2704250302524f41a97d0b37aca0791f6a6930cfb99c747ae63fe057e1390c884483d7323630a2083eca14a5d04eadaf1e7571320848e9e59d6411949efc71e3f3b6a3ab40b11f66aa88307d52d913d8b7a4d4b0a42f7c4834a61252e459288440e7bb793cda3bd4ab9dcc7bee000665b76460b25fe6f0a265fdf0d961c0148d5e3a313be3bacb8877ae8f478ea78a2c9607e33f38569f588f6ab23ea77f92f184e2ee14fee96bdb73710fc62b36c0ddb72b5ff8e3893a00fef7c2eecb9727e5ec0f831fc78d9a5b249bb5a02ec9e66b5a933413d83db2bb16b810fec309ba55c53709bb6256a2e08dfa20a316c226f7a082ad2ba504723bfd9d23f736cb76bf7f14fcb29cbf451914fc4f6debd06cf6ef63cd7eca7c9a4effc460f4a4be301d2cff1398361d5d6af3d3a2d1c24ac3dcae79a9a546e637e81419e00fd5c81c791d3bd22e729cd447d507c36c2d54bd1e2ff81628868bca080988300eff56a4448bd130741e2f1007d1f02a6c739ca8899023aa10767d68c2fbe29098f3d364d5d13e2b26b36ef0094bba81ae1f6ddde538596422970740738a9d42545e7b7c4d5d1e0b79fad5dac1e45c2377885aa2536d209175381235323aabf0807cfc3fbc006e4230ce3820c5a344b89cd4448ed76bbf02bc34b82e740e0632df0f034a11e8b33506f91ebeae9d0e236e9daa0e14b217040d2d0e33422fcb43148fe9b5030158c2d8660a3e3dbfc62039f1b93866eaa7ec8b6b184961280ae17ea9aa11a373d30ac5a60a4a9d958f5c44a3775f70bc856039e696e28867e3528d6154aefe1dc72a5877dbf7f6dd53a6197f1be85fbb4064884d070d78a752533acd62b6a1aba1a8354ad182cbd5e3308cd869084aff7f9fde22e0db2a7da452a2f42e7eb78dc12104894411bccb192f85ddcfea0663038ed1fa6638bd24f0a052981abe53ab04337f3e3b1da4cf2a14ba8ade7795d76b0e0b2dfe5581dbef80ab04bccb6fd01d4f91a2da20cd412b99db1b269241cb58e4c11945c3bd6679e31aab11285282c8d7cf0a57de4c26486d0ccdfb29248c8104ba957af08f0a6d4377bd84396fa9d779e7e5495bd8dd10207737ed6ffedabce02245576659af34206fe42808c213d3c4439fdfb8144a117297e3dd37e56279cd5a7029574e522c01df3661741774fb7a3535c9b297c7ea5ac2dac7c73ae4d953318022343d22eb732b361bbf0ba18e5fea19898bdac5650b5076b30a3e7354ae3cf3ac2e90a03b519d3cef1ff1ce812f74ad4496209b50a055f6eda1f6f38cad425382179cd1fff265f602454d36457d600758cfebec82028577005734a7c77822b83270a413be32d9baf56e63d7486a943bf7b733597610b58ac7dcb4f259ad13dd712ec9d6f3528160148415bccac3fb4b2445b0b68a6ba307e198f87abed096494db9e5088773988cefadd12c813bce01f32712cf1bab07d037723de75c67343ea27bbe25f5608ca783b93311889704a8e12629cf6dc1ffa07c394c210db9645a4191874d641173b93d5bee1a47a256cce0fdb977a947274623ce9809cf55c75bf8b403c75f12110cef91ba361c6614a47ad287e5291df1d125a57e2f09e5c7242e808ff170718b7f1a6e0678735fafbe8bd3244865320ea594461ff455514893ecae12e5ea326b1710e790d3affab95b2a21ad44282fbe051cf186e9821142de520a8fbcbdc02739db032bc7226a56cc95cae76b6d103e7c7693ca291f882609626bdd23414225a549c3db3543835fedfc3e02580a255c4601a8e6d736f0fe823ac16de4b9f17ccfc31c23db6f90090e4076f8ba9f40ce2c5fa17a150a9480d0b76924f6a8801902f57d8c81f6230a6fa0fa2da35e19dbd54d96344bf552bcbca3b6a276cec03b2580ab0a186e442462abd3719a16a27a9113f92d9202faf3211931b11b63e0633e6aa526dc794b4f5ffa68b86c19d3c9dfa5cdcf0ed2fb37789cc074714a6342318009790d45908cdc3d1136a5f94aef33db7c342af4e359b95c2460869cb30d3dbb5ead43d37a05545e24c213523a2cb161a6c9ff7a935e771f363f9b56b2dbc1992177aa6c90a4e90c65dc6732ac032e94bd0202f782649ea0f39eb35ac387663ec81744c1604f0edae7645fa02d6ef7201c6b6c9c9fe9b30cc48d1cad231d5b2289c881751ad649f02a5728a4a0b894986b7f94f27495a0964abfb1505233122064223f90f27e5990ebabfa714e2922537e857abe14bfd0e9486cef0c70c6b407dc59ee87a1cd7822d91b1d2fa7aa3421cdab9c5b8cd66d54afc5f3e7f0d5606ff06b0dfef53557b609aca380403a072568f92a34abde24f02284739a42e6211a44527f1c8e466598055d0f72b4c3998d6da4fb1f53df6f0eb6bd0da1510365d97d31e6108f8214dbf1c67b97f5b4197a870815260da5b9a9d1a118acf1f3d3e7da5b28f8fe3cdbada15eea38d11f6c9d3dd346b887288386bf7276dac0ea3513e68f5ffb9c3a8f5c637e175e435ffa7a964c49ade24fc57e0563a109a343ba64ca7c6b33d4067276781f0a6118328e1ab1ad1093af058bff905890eeb16221b69c93bb12b18f82e0406717008a28e1a6aa52bf56ea5aca5e37fae29883cb4a1fcd784c071e38c56aab0ca2c47c66816f02c70569aace03e7d32189f50131539a717efe06a021885b8423e9f79cd3361e8564769483520d1e1c602e93e32a9f6f26bceb79b805c42e8f3e582bf9955437598f3ac6c633ce1ca5bd55b350dfbf1334c0d0cf4b23c7e35020ee96a0306e69dd9e75b299fed3fe8f4304afb2986f4133e4ed11e02bbe15d3a0c3e7386b2e2edd41d0fda58c29b113bb25df90c8deed23a868512114adf4b7b7eca7d30707526ce561cfe19b3b534f413d5c018b801d1e00cfcc1bddb7761f59470a69eb9e052c2e78999d165bd5e64dd671e209bd9e6e7d657e48b9bcb95eb67b491826b4df938bde566f9a3b70f7678203f19a444068cc379fb6b4f868d0716af3132c746829488f64543e5942488de82482cd00e7ff9dd91d20074e8dc166de7865557a1b93aa24f97db0554bc0d2db0242fa0370b798a5aee7415052298d5b4f40a7163ea519d63b719b2f1a50c3507269be53e5e2f139608d87eddeacdc90e9a337931224271a0212e958884a29bd74d0ef2f5412550bdc038446533c60936ac549a3e4b1c21a3a741f68f47c77a56753f52665e4018ecbcd2aeee604937289a71d7c66f45d37f1c1c0b05856c41debb321abf1998219b8a4915e35e6e1024da0fd6c0516578fb1ba9be91e2ec0194922edf816621f83cbbb73d669ece7b09adb15c21e359419ae6e77480074d44aa560575da816ce776d8fb8cfac73a8a3afbfe053f60183a0e3f3c26ec8ec8428d940de3e5321c4e1a30ff646973fe368ac6b85ae5901f5c064de918b016273fc76627fe49a8cc77ae2ca583461a72df90ea16defa96f2dd9fbb8033bc590f3c1da1220113ee7ec44329bcd4b77ce1ebab59b0b386e623c8402b57200973a6aa843f1aa37b30b82a6ca2d0686e06a4c8591a0da6aa4ea3b84138449a12845526a76b872571246219cc53154fd427b7992510b05e3196065d2637af02a41cac2a26a7bc6091762c58a29d8ce7b2b1a7ba3b24d9e165a8ea7be24b0b3d0fdd43fa0689a1f484999d7e276645b63d9032764c05e8d5d65495897b8dc9fae09beb8bbfd6ad732b556e19da3a40ad21c0ba5b9871357223970a696993c7ebf4e66e7dd08a870ea1cc5d773add03aacbbe4afd66a7b26362704e0db054865102e2db78ff38862bf217bc5aadfaea2ae67a905443d6c09d09a7d6bbbb7c0171b398cb7dc95632a274fc9130ed2146c7ae1046ea31ca04dd4e9bc7c14266cfff2ad179199617845fe4d5b59ffa0e2f3c23843353cccff2ae5b4f9715e70541c3f7320d34eea1359a643db7f0a4d49d1bd0536d46618ee1043b3a28fc660ebfe07a66656208b81217e76d5d220493166fa8e0c6465711e39938196957c19351cc106ed1239d4637aa96567ef0740c0ec3141b3e2368f0cf0072e5f629e88617e382a1ceca8734bfc8ec44bf4a697d97ba1ed9740a922bbad0d5628bc59d894f4104d79653146d05a0d7d48ebf7e4ec5e49884726bf26514a6fd20ee260f4d592c61d933808f5c1a39d0dc92a244872817e79216f8847ff6493af08f8d69e2af40238a969a9e389edaca79b42847b008e087b885477a1c9ee0fafb49b0231382f1dea74509ab650b799da48f06bb67ee001962c95c0cfc63b3a9514ec76257db98ec069bbe03820b1d1b93bb7b8e0d82f70b9cdd44e0641a8ba70a55e82e00b2aaaab5e464121e9e2cb2cca69e7a684df74bc4fc6df9b04d38981eed63c9f6e97f640c7179e49fadaca64f1e3ba21817e8503977a476fed024bfc2989cc367b52ed70b40d254fe3c7885f6e90851e4d36964d752e16554f6b3ef6581ed52ff36f7ce6b29f4b00e2c2da82a04d3bc9390dbe736e26935474732b903d4ff9be2715fb6fd05c6a81482d81fb6eb24f5ac94f7ad0a5e754829383255b8635cf7fb8ef04b7a27ae9cdc1b53f620934b33ba9bb70e5db6e385e1948f0dd58d8acab39116bb903c563e1d14be0a843a1409398bddecff50164d0bc4396b9b9883161bce9ff1318a5bd2d12bab1de6bc2d50c92695bcead76d22ff9d423ce0496f9c555d3ba3731a2f13cf2484a1d9705839e9d6d7088f171043d1991a2036a7c4107dda9be44be31e87343c"
    EXPECTED_AUTH_SIG = bytes.fromhex("1392e841dcd3ab5e0bb4f13ee20dacd969cc53190bc17fcd97c1b08f8eca5aa91b5c43a52f778c24c96742b6d78034baae6b46facac75f776418bf1901635816")

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

    with client.hash_input(transaction=tx_bytes, trusted_inputs=[trusted_input]):
        scenario_navigator.review_approve()

    digest = client.hash_sign(
        path=path,
        locktime=locktime,
        expiry=expiry,
        sighash_type=sighash_type,
        mode=HashSignMode.Digest,
    ).data

    expected_digest = nu5_signature_digests(
        tx_bytes=tx_bytes,
        input_amounts=[input_amount],
        sighash_type=sighash_type,
        input_index=0,
    )["final_digest"]

    assert digest == expected_digest
    _assert_hash_sign_authsign(client, EXPECTED_AUTH_SIG)
    _assert_hash_sign_binding_sig(client, expected_digest)

def test_sign_tx_v5_orchard_to_transparent_real(backend, scenario_navigator):
    TX_STR = "050000800a27a726f04dec4d000000003e813200000100c817a8040000001976a914c0b7590ae34bcc5bc5c8017f53554243daea06d988ac000002e54cd1cabe91f7db0799c9ad4507ef8fe66fa81e7820b29ed8bf9eb1edb6aa3f693d6bb313274fbb3d90c226e1d3c66d57720325e422a8fdb4643787a7a4f80d58ebd56dbf82340177a4247138c9dd3123146db41ac95c4736060c444e4b04a76855fb3259cfae5daec1e81fbdc6457e357954f972d6268fc2fe7a9018997c35dcf9695795522bd49ab6bde4a10db65c28734ae1c143ff9931ea779d0e5cd4166c6560725ae779e63b3671c593665adc548c2070fffae83684e5b66cd3d4457acea8ff307e02f647302a5d7de9776834572e1f2f4e9e70a0a6f0aa1b9aa71418bedd057121d69876574ad1eace4839be651a16398c675d2f40a5961d29fe5ccd9b3fe86b3aa7ca2ba8da3da98a16d097761d2f6b44f342f33763bcb472b43d82776c0a49df3b005cb37032908b2018c9c69368297d9c47cf2864e7e7c230c1b7d9ad60b1257da837d728195961df51f3d9ebf533d0798c25137579d39f144bc08f39a9203b831150eba5df269d34a86e6b6521886d8a0d03cf6e01f2a93742f256d60b52817c026a86d8c79345f809cb3fe283ce4b624229e438865d18a3b9bb9c0907b14d520efd71e8c5a50995f6081a815c5bd7fa83d2f3ec847e03bcf79ed584eb9a0130c590bd23c7a11d47f37a98b70676834b7ad84404985d76ecbc9e8edfceb3cfe5751626995631547318e578f1eadd68679a2b88949b593700a977e5d4193d402830ede4e3ba35eecbc00aef0f04d11050e159fcdfce21c8d8e638dafb6009764c5e42684f4c51d07a9791241dd7c15b71393a8a5947cbd0e2b4acc9df36a4d898b915dec866329c659707d89c2b91b73ceb91fb0a944efe4d370da8df09a4746b981754f25fadf01997bf370d7309b7d43cc49e73e380b00737fe7589658a2e854d9feea3ad81c4baf99d7356c1d8626084156554d49247fbdfb685fb51d7a3048d9c76dcbacce34d81da49df706ad9d1d8e924142170ac31c6e4537cbeb829ac1e012775b91a41987e1ae91f9c08520efd45f4c85e7db0d68ba381080bb0fecddff2c756ef3d9f132d09388b9dcf1c0b008af3990f97d4c8bb2aea85e17eb7f08031d67a4779faa6cbbeeda984474267cf74397a70c33e4b36f8aa3d7af4a4ba10f01b4224336511bd193c4963cd43fcd52f5c74e7dcdc658bedf3828c2c1b7b997c4d33424fa1f4abd942d5090e4ea47bce229f8265f659f6b322f13ddc43e6e131a13cfb4ae02725d8e50213176d10b88cbc9c02952fee41ad1424b8a4cf08b40fc1e3d230b38b794ce5c1bc0b0b3f5889a75b741a65b9c0d5f4a58fbfa5533853fdbcf8fd042ec16d6afba22715ef7857eb4bdf441c3417ded3edb86a48621fe90a65da481527ac494987028ff66841d73d492c6774f508b1d567630e3c3e1be2a736830512f83aa2095d2fd9bbbc75714f4d76477afe008d925c9fac6a6081c3b2eae740e920f1a07466b57b9db407976451dfe7795d3e25d8ffcc05d6f983fcb0901a6d5fc32c6b219c03421fc9ee9cf70bfc7bfee00376f3333f8c6a8dea61fb6d6f650796dad32b9b3cf001430e077876b33c84c3530fdf49f9b159d0ae77c6395c6ede2b38c0a6d1bc1cdbc94566d36992b8a4bf4233dea44dc339edce4fb1de2fe2d74740cdad83d56235d0df3fe3b0a17cdd943c8431ef596fd7453d7a4c3c9209a44309653ac506777b1d75076551dafd2883c30ed5d37c44a0287e2017e6e3b94db9e4326bc4822af32f91794cd53db52b607c33c981aaeb59c4b9f23130550a6f4e40a7bf0b349727728e3a32f55f9b56bc37550b08747524e3174c9ac1f07693539169050125fefc386aebb51d03e5a14dfa40c2b381cd6415c0056377366b9e7bbcf26a188711a18ae5c2a2f30a3b0c313593d8555c1880abea1a7066ec376594422dba1f4571fc98f6e567e35a66f258444b54d9a20b52d5b8e5af48e577c825abe106a30c023b3edbbf2bfa16fbeeaed9df151cd007cb3e16ee5b1311f843349a8be2cfc66768c0d66520d7be60773ba876031566cbef1c8b4a5fc114a1b082bdf5a3f2c8e73688010b4f0a0b69bddf8c1b070f8157598d60e7fefe0d116c6c14be94307932e42593f5bc23522b745cda0ba199a1e95adf1c89f00e60ef13a4fd5cec5995d4bd4f3d72509a48b34edf3c653ae0f8d218aaccad88fc6a5fd013ab28a93cff43a23616bebf87830aaee7d649a62baa620117af02f00ea27835ba51f30da4ff58fb0db4c84db684935dc6f46df4c7c08ed0bb36a3d511fb247da4f2c8182798667aa01f95fb1988e74d1d850854e2ca1887a83e2603980218a804000000faa4f305ce52c55ae53a100af9afbf97ae95a311164eaefb2b099dc9c881ce33fd601cc66ef7b194b971c37f12551b3913cd4ddac6e6be6bcaa0df44c67bf7654c54158087c843ebc92358ae1f1ab69391b86509d26b8e26e1d646c18cc5f429fbcd803e0d75a851043a5682a8d4761ad3fcda8d310137c9bfb24407a30fe37d54883a108ca37efb4a7a575340eb528f71f17d7bc1bcf671a9888ce3bc70ddd161438f68af89478417519f162674d32cacec017d052daf60c3b4d5f1b4bf11339ae50cf4996c34ac258bffdda90e8bf5f1172a84df9da522a3b83e58c5e6620881813e0abb40e7d5e0d735b10b71258e0162f5c6470ec8eb7cbddd21dd8cd97e71a11cf07b78d1f75b516694e0caeea199f9d28eee309ce036b1b9b2dc8a71f4773199d8eae3a98cac49bf1ce62a703bb7e252e671d031ccca05e178efa0347ce9fba73b162cfcc19818e4f4c64b3dee15041084ebd7c4dac130190e1f364e757393329da20ff8f26e695a291393735bc36f529b3ba156119110f43d5c368374769893c953edfd1ed324f6d0532c5fe2129c999f938d484a694bbd9fe1b20180e92099abf69f8f3cdc8113b83e4863e93dc7349b3e6d24d60951627de515857c818326b3fd46f440f3d310934259847a22d4ace51e3c99f8c092414eb01e1196f3a81ea4a975f2f54f84ed1818a66814cb96ee928fda854f07c73832c229b412162c26d24a6f77cc1ad1b44347b1d2d2deef2840a2ec680a877ab380f4529de91078308d1ed3f22b6d9cc64979f9258256702aad96e141d06555bf34ec5b6c68cfa994c227e0adb1d82bf7eaf7d8283e1e91bbd144ed41749e2bf79c89e3c0ec97be0a4429d59f97044bc9f46b207742210156c2bbb6421097d2a83498d8b86412a232345e79bf71932cb72a8d2768aac14be72a784c2913390a3c71744ff6738ac887a1cb47c2dddf484e0968ca26aeb579f159955b40f5fef96b57824efdc5e5c808105b57c21ca1fc94414ca2ab4992b110d148c1d02631a3dcc7190badcd2ac92a4780a9fae2c6d8b0b908059ee2f8e010d514dbcbcd66ef25f1d6c00ad0815f0fde171603491d257f9d328d92928fa1e69f889d21b581991b5624105c6f053739dd31129631e576ba070564a654f7715b805923f05cd633e07dc2c6b15d84663ff65044d81491f0032fa672481e6f7845e1d9856d05665293b076416a334771a3d1963bcae381b11ce873e505305181cbb8871fd8797031d1c69adc3a1c2df7a62807b3985b4ed4f5fc24f3c47c6890f75b2a1b02c84184dd649744ea8932b3196f14f5730bb32e501e794ad47a017199d8c9bd8b9bec05297ec74c561c323f3c5d883ce24b6de242a0269056dedb64d5f2bf9e5d65caa2549f4bdbc9310546bc9caf1a52b38274b80b616694630e75e3616714eddf0ff3cf6b28027c1e299f905e0e7ec3ca0478747aa54df72636d81824867299f6be9e51a118b4162344f90e3160417decbb76144288919e7df375fb248ef4aad4a5155e701ad36975b639358b9ae32755c8b8a1be14e66b530033fbdf6fd4da290023330ff1db0648c8c694c998061baf2e95da2d7be015a67b8142f401d6b50f5b5a26dbd3cfea055fbba4fe197b94a3584d397cda8814e5ff794cd3ce569ef60e217d6eadd4a98054af9c22f9b3ef6c2730f510b1a1f5604d0b25b7c540f447f12146832d43205e4d17aeb3a5ff0505039a9652730ec47f1e6540ed01137fdeae711251473e3632f1380b536c0d600ba7b8e006c709d7f9cf8ea307204c7cd53d82c3dc0d861fb789e7a49abe5d6ce00be25c5fc78b8ecac3fc21d698fdc167714794003ac1e7f436218c1f4a67c751e18a21eabee1cb3b2a1041c579e144551695753c0e457d7addbdabd3720b90c41c5e652772080c6816a3f252def36fb2c1d40d6989180e2591002a6004d444f42b4b9ada02b99a14a35cbf38ecbfe929e51da0b81599021a1b1b8fba0aba767e1df11aaaeafbb27b5f994aaea2e0989f667795db50c4aa1a248e95a5175dad76b976990d017225c5a8c318e351c4fce2dd86c3763b9da90e76242932447682b88fddee2cdcbc3870fc5f3f3591e6d96af1fdfbe5d97cf858c494b92cc2abe0891740f864b5c2ab21bea802eebfc55c2daedb0cfcf6add572a0c63c980dc7476cf09c04308b5ba9c923a09fc2d4fff04967520c6df52b904338693e165487ef9155abcdc2b1ecf456176d6cdbbf7b3da878504575c854da809c68bc8df8c88d07069b62c4486a0137421b908c6a211c7062c6b01e4f39517dec1fb7594ab83f4987c0524e2cee811dece1d6e050480398adf24f447345d524011f81559716ecd8131cdcd3ce73259dcc49572cae7decd721347d78a7d7d369888914d9addbed999cc2a9bccd89de932e855ec935b7364539e25173834d063dc72686f01f2c36aefba6b3b2d8a9ada320008baa92c1d6c18e68c1bcc934df3803052ae6e7a5048768926f7333b15bf3fcbb3a331f58478d90848e18ef1cb8ca8dff3fbbb8a5322f599e1afc87454965ea76bd46f97be6a688437ef3c3d28e3c338501033f685408eeeec07b35949c59876a3028c63304881507f373edd0cf1ffe2c14ff60ad27ab7375e75ad44758f01637b0a53f3e04f3c18ba0b774444faac3e90b8ce6c7ad5ee588617b0a0d40b37e170c149dffd22f4ac72e42af10147d650800cba69e114d81b12e89a24fd314f077ae5d6440db96891d1bb7a2a2f7d30f8f03a32a5ce34f5cc5f9828fd7112467e022995881b6ac708513837634d79f088e32adae50f40ef8f6558cb3c53890ce2d68f5df5df8f8602a4ad18fb97770c19c2bf55771e3fb51207e70deccc7e7c42fe39ed9905f2ee3484eedb5644bb4326822dacec90ccc9c9a7230a3fb2dfb108d28da89cd73bf9629757717c0807bc04c1b53699fc06f15b46f7a3cee467ff86b9b8ae3cecb460e999d82b127454d0c6002ecc03ee0225ff1275b88cfdabacba91e7084a35ddf9cb8123ca09d689f47653df8b5db8a07c7961fb95f344ee40edae292333709e720708e51020cd3dea6260f48c3169a8bd787fa92481c4b188824d15bf529d73c32cd2aead6be797be10b39a0f59fbb6f6a4a3a57d1644b44f492282b9e91dcc4b313ef2cea52b9d03f1934326e824e42b996235ab644a123eba2bf8885b9442801c3603625cd88e38a430b780f9b8ef02223c251f821ba531346238c3213ad3458e4f06e78554ddb240f2af8dee95652c2b6ed35e645af349c2662bd7b9c998572877384e42c4cb1fae112af700bf57240291738498bfb2e0a9389dba57c894cab66f9fa2c7d87c4bfdc221f1da9461d9bf781aed609b5075e70f7518af7dc87d3f97f6c180914b2c79d0c70139158c207c5cea98f01dd79a8f532f7be1966ea9dc9b82fbc2688a503ed2bad470f1ce6fb25283aeff12effeead9626500a9213805b3eae577290fb85922b71570e4a217ac4021d449511a897fcb0317ea06e8f1631e0ea3366f63480063d86d1d1fbd72a637d7f7b7d7c5d2e1a3aabd361b478f604e41780739b3fcafe1b9ee1907bc5e8d7e3f8688aaf9abbfcf6b8623d3f3cc1a093a99961ca8f4e453a0e84d21fe4ac6e86a5d96fb83c670a8b61c726700a5490ace324ba63f174dc1e31850853109bde023e209dfafb7a4927ad88e75fa6f2b1df951d32402f9c381c25893cde4dc49401b03ad6e625f4f195fdd09cdca13933c572caeba5b584dc1267b7d1f613a4d2f6d5a4f4cebf5e926a3fde917559b3c658fc737f8a87722909c8527c6db6dfce431eb50e1722d9d2fdbbaad33f842885ea78de4cbed124d63df36ecbd2d5e1e3144011a2d9bd54690858389c67a3a39d67adf4b22b63711f0f470f58e0004eec8ea14a2c001f63bd33ac64814b0ac6ec24dca5b20b83f69c3be1e736a8f13eadda8c48b0fd30ed8f0a989361642398d5d4c549dd2abce49433583c56e9f935624d46cc18f61630db4f1d5e10ccb3c555545a9d0438aa0b82183f9fe746d5aa1f802c855759bb797f32f731e3e06885d73cecc7ec18b41f933c3bb4914c1af4599cc8d49df4356ae09157cef1a06b0f6200c7b993ab9ee5080b70426c0d4e0088a6088508a913fa4bb357fa17bf8eb7af93c0d735ab2bbf5610581ffae46bd232892479aa703b6760e50a8a587c968a457fae3c232cdd9d9735dcce94a5bebdb04d88aaae68fb51c10d0c3a7235f597008f8660b5663bb5681c37626be3eab2346ef99c75368e4b8b38e5240a076c653d41c1e662726d09c31af8a9485e4ece74153886dec275c0e82bc21224964f1f194827f3c2b11aabdd29e5b8926c06783f4ec927204519268038f1e7e708cad85026b2c7c3176da7910a927a36c80e5fbaed4d5f68992a6601184387b99535818f168eff3e17ab93a73271ae3fc9f2580a2d097d250629ff3b8c5e298be4e73545a1c9377af952fc82081708d0eb608b91cfa4d84a55ce12b72557ea85dee6a706eb47fbb5df8595602d9ed691a02fb6fe71317637dcdc48927d8ced10f91b27f0d3d1b6230043359f095104ea9ab10bc08348ff588a75687cc0d2432ce851f15d089f11d8fdb744072fe4d5ce6adb55d2982298ec98400f6ed3cb40028723f8cc276c7acaa00a0c3a39bdb4969dcace2fa81822d43c4ce5b19c7d86773adfb3aba09027035775b7791f79aacce9b1ef638e4dae188fcfd75e346a018bdb5aeaa561d96c96c757cccc3394860929f96fac75b22aef6c37619079032ed74cb0d65926a940e2aead42653b07163ed1d6ed3cf3c0f17b721bd05267bc908d908590e9b244bf70ac49870830cb4c472d03d7b597f02e5cde2b3cb70f7ac18b6a6560c81b53bf5e9a0a8af333f3957a7d6202dc32ce324df700f55841c89d63f2ccebf146435b426ebd9840037973f6863fe34bca94cc501cd6eede0a44df2e95880f93d8984893b21c1f7e31ac97cdd035ea5404578925025434611740ee7e8808e0ee273c912acc76bab03a0f1537a916e5ca622cb1f1ca85b54e57742b61b329f3935f45f831fc6f41520c3af79b2906390607252a5fc218057299134fa0ca2899caf8b940106279e1803d6e133ca90b7f4a0a85d7f821104443f92ab268781357b3519603d3b5a93b7538bb842273f8b43058beebb5bd8d408490b19184d529d02f91e279fcf1bcab58273462a5888ab67b0a8dca16d4a5b159963f2ff5c9b000124d8cadf9f1b89a981818bc53a60d8c7154123cff8566f8123490660bfc297ec4a14e184cde55e8a32e7cc0f5f869da4803a854534a6bd95589de8ce528756397c638e6753cfbad6a2c7f04b1e6bcacbe5c3773f7d1d5bc5153a6c5604921a7ff1510133f8b2404b62f3935665f399b71df8edf0e99fd059846eb3735d1b0c80863b04c0414458da51a5f241954f60904a03a845cdd5b1ecb55d86505b7cbcb06c1e15cc1b3d721c50ffd61f8059af50c881ebb7b7f5aec20a34f3af475add926c560fa16e7d684690a66abaf9a83840e5276993ea9fcb0b7bf8ca6953c4215467c9641e80a9cee733dea2f2e45c002d5b8bf7a7ae17a1a528d4893926e8cd9d2782871daf13a1c9a17ec3707d82732d86795ec7b22c22552a718752fd3333a355b7cebf3ad3026093136af492d384c3a5c23fafe811d404d2b8491e18b06c376f2af96a35ab33ec72f65c5a9382b4c39ba25a6b1c2b09f823aa3ba395f1ee74c4f55d2d329c513d72070f6fe6170cb4c315398d6d1ff59ab648710fac9720e285d7687b0805364701ebdf5052d6cc7519d97b29a04e2fa79b4c39b4303fca2a72bf8b344599505413deefadf1dccf7fa6e8212368b1a809f1ff918520c0c4aa988b8a001dfe1e99519d8a58a6939dbcab0de9c259e9738af9eb9b23727a85ccab9bce155b04d13880db6e5fbdc7a16e1c61002eb6265ab1f166fec392362c0116559efbd6ce5d7521c91899465fea6436a5301a5b3468a66670bc2564621e7ad1193b59556a334193c1a570ed9a410348761b647212e21d7ce92b464f4ac4326adc4ac56b17166030c53416083052a3ecbe438eac8fbdd37fda765a10c5ef296c1d8631a8965e41c17670a07b1c3abf863b6ee4c8f44b2b671d393f1cdc13b02dd9cf0f6f119911b297508348dd24cfb4252570ed850b2c220478218c8f76c2333ae57566ebdd274236b5c1accff12f8d8609b9ba9a22f913c19ec5d1f6817960a464f32fdf35f41019769bfc5e155e9d1dd0c36cfb61a7ad464c5cff5e1efef880d027e25a2db8218785d8e4a748d96b0a5b262a54696190d181acb2e3abd44a0a96bd423eac1132b3bfe65639b219dbaba6a5a88595a168870a1c2162d5eaab03cb095f8baf8f43f1c3a5b8d8ccc2b76f4c4abc52b77b01c4d7e5b544c834fcd1abd639995172a3a78e78e3fd5bf3cc7f788ebd80b552eb10b2723ec98815e5a63523ea3e6ae2718089cddd930bafc6a187ad369d8d79dc6cb0d963f32ca9228f4a413ab7fd175254b5e37f85af6d26339f83f8916a70927989211df0acd2d8c9f673bd02de4e3060f62dfd6ee8a55a7b008a53c04991f7889a7a334ab0a82bfcebbe0962a841f020563a501c24b7bcf95d64c6ab1da88a2ae2e07e50861ca1856911a28a39e6830c60d3f524622e04b25f4fa8ca1da001001605c6d0062c877f2d1462ece8dac1b2151d26d25984691b52d5e40e2ea34cc216502fe13f4df753cb45f15f8cb012ffcdf6c9f908301070daba3ee5214237f0e4b7ac4ce1e2aca9f20cbd1def8bc1b3dc4ca0103557e73c79f7504b2d2d53cef1f05c0e6121cf52e61594b57ce9c0deaee259d7221dfaea6aa448e88d4d8c31dc25dc168f8a73454ace0a44073861adb1338cdbbf037ce0369a187c9111145387bc7153d657838cab1ebdbbf5f4b2a0edafbd9eb16317f017a55e6d6ea297eba581624330a08b97a101f877b991e0c2e6601691a960da3a0459a0fdaf35358f2a8c6ed0d25ad7ab881d3efd8b93027b460dae6bfd73d46c4622980980490ba5706b0c33cf3c79fecca31a50edeb20c7c748f68454f0117298057fcd04c076b2c43c7ce06f9f9306d0c675c50731e23dc46bfb41a613a7e69a92c9055f45bf0ec5e18815174df33f6c283d291311a04a4a00e8aad745a921697144df99dabd4dcd01cf779af1137d8b8c7501c7f410ea9df0c7ac2e47d34000523f05612c90b9163518dd747b8d165de7be4d7e91a1b4aadd6283897dff8a7f09186ff983dbff16397c705488b50f273838320abb13e85620472a902421161b5f7a690cf0b90e88888582152b2f2cdf415ae8b08ac1b754070796a277db2d6ce85c7da7b0d3197c75104577e91fd09be7fd2c18fcb06c7b94073cb986f9571d1d11efb88da46f4a7c6faf82bdcde565b47068e07be13ebcfed79d8f600179d9dec04449e9b7dd744c4143b14f8ef4ad1801ac7d33c00a62ddd1c9f81597a19ec1cc503baccd014ac706739d4c1c1740b061bbdacbe22c0e07d1169c691ee62a988826603efcf29187ab231d29e899481e54cd470e40f23a7e503c0217efde4ce4b9558543a8341d348b1e9db5fdaafce5227d1778310b52a0480de186b8e79c64cfc8bc64130602e584d3baf6c6e0028797be5f93b12c663e92da22d6be398174fdaeaeba35b6b60681133187eba8c57a95c84467b2803d7b7c1b07c48c670db4838bcf3982053e03b8be4fdaf7f4376075406ac7709a2c609abda38d0d18aafeb99ecf00134d9615caf16a106d3d45907f0b7b6f31d78cdfc07b095d41a67264fced27dc22c297d1fe8fb99e5cab97331c7c8a97522d9cb3c2cf33ac433b0309ff35c25a1c7e4a34fc14b2874a07b713432b1baf506ee96ee7c73e6f826b6ad17bea190ae7bfe691c52cccc46da542b7d433787e034b41e2ec67f4e1ba95cbf4b929f13cab46deb17ee8dfeb8730bee0d5c1be8c60ae8d886ba64ed3b74b6091b16be8dbae7fdf0bd22b9a16d7d16cd483bcfa42c20083e1420335016bb799d60799a747791241746ce2845c659a71485b8ff5a673bc2434ae3ebbdad8c2cc8e0d646e69399962709c51c6032197c0f6d2aac22a82d9017688fa0230ad58e5c5a844a515cd4365360ede60f5ba82dc2de819d979b396b3b259e18c64e1fa765ab645289eaffc60297ac5bfbc4625347d13665dc52133c3f2ef6d3b1fc9769559e3854b53359d2fa83aa76db1da5ef1efba4f0de3d1468e1a4b580852416e192b2ecb57f52b2fe3c4068ff41d8fba8f9088a464df329a32219ddd0bef20d88a66fdf395c89e5aa4745a0641f9320efe73d8f6fea6011625c84ee17da50e22fd5c051594c55e723442de685a28f30a24dc622bd68aa0037d50043b9b183c2a8ac5a73e1ff5a2f95b1d7cc8631f007e0351acfbe6bff1dc445201df2b9f10bbfbdf48f98a5536c0f7af87e3bf135930ab5560b01be872b3fab788b9efed0f54513ddc0762601710511e112ea8e00c134b99e63702c4418a998dad6979e7d64134a37fb1199d2cf93b646ce4d4ef9cd503ce7813a1ca722f11b64dbb507598b8788bd61ce013976531263a85580fadea4d00585eb15010d7493047dd5185bba75016ca53bfa84540e4bc0534e15a100c42a5c4d96286e0ac3765cd246c6ba731b7de0693fbbe0055aa1655dc0458025b1c869c300486d378bae9dfcb6b8f4dbb01ea44f4dd1c9a8a8b193cfd1b3a51cb75c7dca538b520712bae2f78746fd9c5125736d9d1e8fcec454cc80cecb477e7d5035e76959242fefffe328906d6977eafee29559cb9a3f8f9f25db96fbd6a893a8d7b57698c200734b2d7914af4960b28428545fcc905ca2e0ed99acb8a8b0168e20750a17b32bf3828143052da94053c35b3535e910c21e64228c07f203ba09959ef6e42493195bd6ee866dae8ecdf438d02444075b4b2a20890f7c16cc2163654bf3342f90af6520c4b923e60ac20f99ecb322138165e02492e876ffed38a9bba29768f0b7353184a1347c245a492aea4e9883d141d60d9a5f89412d8105d86a28639d52051af5406b8409553e19c7f58ad61c2c0275b41be956bbb749fe6e751125b93668184fe5a0eddadaa979c929bc625d8e000115aae09d74bfdae02da176b0d540251bfc64a46ebeb3cf25166f566afee54fc502119fb78f9452fe2c974490d8479e14bfbb0814a8a4e2739a143d5fbb3bd664528e9f81b1684bfbce0fa7873496c7a40e09abddc59f5d4b7dc750af1744b39ddd469d4294b739090c4332edf9a09b0735a0bea8ac06c9462bbfbb54c677d8c7f44c8869146c330bb489cf470c1e8e3f0afefbe8a6f6bc42c332a35729fea05fa90d945194e7e8547fe54eeafeb1281df188587a00445c31a0a7b02c345c2c4c32e4a5f0d52ea2e872f2520d91a959365fdcfccbcbd37b6eea9b2e10e4ddb98b638e8f9bd2b1ea90b313e884cd4f56b82d1ad945cf51de8fb1482eb400ba6c76a23b5893778749679b607115b8586001dacd1ff54c71de9ec83dec3d969fa43e14a2ced9491d00f61e0a9d052d02653e719eeeac421421c03684b4251e31f96fe693c82575c8a425068fe10b54de020090e8ef4744f20860578bec12a1af8f9feba79cebf429039e2aa44c3c531829a936ed2fecfb574d16d6fe50c1432dfe96cea2fec4aff20b126c3f8982feee661a2359ea0c67290e7cd1f02819607814562e831a6d7145232a062fcc6b9a357a06a0cf1d2f302f0f2fe792c17ab1d0c924eff7bc69d6c31529e816275d66d81ba6ee8900eea33771f32e2d8a8579caa222cb8b5c63fa6bd5d5f254bb273755b52cc9aee1651afd24b7672864b8a31e958afdc8af01f9fc222698f71f14f3a4c11c884de102e52f477a1b28694ba7c38989cbae97c680c3f2890a6dc3b6b86bc6a6f47eb8dcafddf9c140dc33b25c4bf076485dda270be9e9aa3916a792c12cf5bda42a563ff9c9d651d47a68eb585c6ed50258519f300614c4a5a2b3de144765ab59a443048f6cfb5dedd5d9b861424eacdc7acaafbf0350f0d5accbf93b84e225b126417f57b6b47ac9d2916fcbf57294ddc01888d0a57013ea7ba21442f3f0b0b9460e0461ce1099fc1bd9c4f641145c95dd9dfb5752f03a734a24fd94f18d2243479b5951a0e3426e012da7dc11477aa90ca5a32bdcdbe7d9a8f432395da7bc19c79e21002a6a40e7fdb3d5e6bbfd12d66f4f4502fcdfab2a70456b079ea4296a38df5eb8622fa8ccd5a90963ffe5b4aea9de544d33a34fc2df4dd716621516803be038ce246aac914658b2895f3fab27bb6558dc3d22b20d587404e929ab3ded6b604c8942d47248b3dccd00f6a4ba21e40ff3048aad10df46bc6ec590a12357e05f5b17afa242667a7443cb461bac20be1331f321715a93ad8e75960a4d09380c26e6e562de4104abc98486c0f1970ee083b38a0234d9e4c822c372391b80473d13fe325c523f9eb11bf09ea5ea0180eba53198edd43c800de8f201e9c523f728e9ad8821485dbf656108cdd1890601aa5a541b703add937258e12ba3453355cad2ffd346e62b36b0b53b4fffacf06469a904098cf0c32fdcdbc86226c225"
    EXPECTED_AUTH_SIG = bytes.fromhex("6184561f1398b6a0425599a541f61013c778b8ee51ff3aa09a89c64a0792c696b07767d8c002396a3cb81e20efe576fe110d2d27712a41a2205aba8132d54227")
    _assert_real_orchard_only_sign_digest(backend, scenario_navigator, TX_STR, EXPECTED_AUTH_SIG)


def test_sign_tx_v5_orchard_to_orchard_real(backend, scenario_navigator):
    TX_STR = "050000800a27a726f04dec4d0000000033833200000000000ef91ec132a22b2f9faaf3edd27a3c24d8ab14e339444d31ff6547f4e53f2eef27b8a50167ac28e265b6d4eca620d9b22131844a76aa552db1c55e276a9079c00aa0f2aa414d3bb7d3cb19a4dfe69a0070c7cc1b78d800abd3689af99fd9ac689863b0c68b4831fefa68ab62ec3fc7d5a665b934a9fca32ca9e32e317265e47e3d604743ea279446914ff85c7a7c9c1fedb679f852fac9d37c0b90ce0d7563ebb981e2583bc664e40800a7904099b73ea06bc4c7eba1341992a09cf2d22df87513a8cf13681713df32c2e7b083bdeff464f7de1a1537f0c28195ed1532f5b9126f172405bced59b549cb0525871bb9fe0e1ac80361a55bad6418b5b9d81ac5ebaab3baee96e2b7b83fd15287d06d17b55bff64504e81eb255f4490ceaa95665130d277439f33a95355b235399964ae6137e680dd1982b03f4c22ebab18fbb8612ef7afefd36daf19e5b66b68950fc54500671fc2d28feb21440a8ead291b7490c21e188a6c19b70842060f360470514f0ea45c913f9a7b2fa42f847457bb6d61bfa1f12380975edc481c4671df9e99e87a5380c78192fcac22feb6bd60acd965796c2723b7adc13bf70b212f67e1998d32e82f03a09aaedcc43723122b296d54f6872006bf259ad4b3860ac176e3caeea6ff8d8beaedbf7ec69d2776d4830f83ee23c7de0c92e54722ebdc73eaf67b4d0fa9b3810719cc5a3fb6d080d96b8b9d68f811256a5494339cacda9c990de20c60c5fe56d795ea1e211467810a1ef17446aca765f0f8b4e820159713478cac56387c94d9ac13a855a0f51966d561cf69f1051be4dd596fd0961a0142292a6187fb5618c43854593e59b6e57dee9a017724185ff70a2e32fa091206ab27ee876b8880cab82f903b8e7a7543107f433dbb8d35b9e33ac42b942f1bc140d51d78b37b3af9ec9f73e472a1a3a8900c88b9dfd04632a02682893176418fa1d539c1c69ff5bbc5a9492845939e1d15663550f7d2f1fcf0301bce17f5885b04dfb71cd4ddd35e0ac1994f8d77c883eabecc8800f60da6c57096741a4c84faac105817f943306fdf01ba40a87ce2530075da518e86c94a675d71585a3f0d9972b455ae8dd1bb6ef87226e40632257ede72780c4320907de2d95b4f4834b44a6986f28b598b2e5c9dd35e2c67f687e2ba0a8bc292e1982fd2c045bde6c05b757e83843253aa59449a10d1e02f81d5f9a9038c1d95d71eb8fb18f864234d9334fb564a9b293cc8b4df0d2d55630da4d0a996795ef4262924531379e0c15fa687c47ed57b701884d508a4c841ffca12e50f94a8167352413ded70fd40c581f804c100208e443c812235247541b2513ab84371f2164bc81d8f3eacd2aea16fbb779b68f6c9e9099ef2778fe71c3ecb5481054a0bc9a8589bfd8173b94bd6b87f229ba26172ae3002a11961920d69b818d1321012a733da7d8737c049f05b9fbc29e16613028198d02d2bf47ceef9830f1c38d7aac9737dbb4d6fd998c2aa8180c13eeaa609d740f57dfad01f5da7c7971e64450ff1d2ae87e7ef6c94defb543f940f1c3a5f14355d1c333191a5f79ed54e14f4dd0420c21a862efc7d02abaa6b35a4c89a072731428106dc8406755bb7bc692a4c0537c1dba363e53153509bbe9f4a782fc1e92186896e40a3b170a0ced7515ebd35bc35f77247fd43c7300db5415e0535592f6a71a97e90d1294ab77db8899515eb221e4e8cedfafad11aa9001d666d670504c7227387bc84b63f831f2b63b971bcd4d9599d69a5d74d2830e815868193f1eb8442d9db8789f1b3f2d05925140b2e25c80693c587f8194125ece4ccbf46eb738e538e98c15738555a2c6b0d41d2fc921dd028cd34872678937270444045cbea7f3f115680ff972cf51401782a06e0afb8b073fcb1ea16b56b83c8847e10ecbc37877ec9eefc6d83b127752fa26dc8b4ca34f2e3fccd57a53162d57ae9cd61e641c2154ed16f5be68608077cc4fcecb0a716f58c9063a237ffede65955bf8bc954b161bc517b2a6fbfcb2d2b53451de883d203fa0e8c7fe49e4839124d830186fc44f6ff802ddd6f9f4f4098a6f8eceff72997a88236d520eea7ab16076303ea8b63522362a5a1214bf4500eb78fe1e09510ed58c30ca1a53a1c7039aaa258c46fe4bab9b4c660d00446f94782d400568a2b1ba3c8176d887bd4136806010e6e40b25a1a0f1778746ffc4f8df862057ef28320120d9473664a70239705fac73f5cb0b1db65bbed1ee4948321af24e9c9cb17dae03c1fe73edd5fc3c06bf67d787f76699f3e51badd28d962818ca48a7c778df7bd0cc326e67b938ccbe822995470bd042bf5b7273c63a25fd387554d86ea07e7bc2c9024bb9f71a82a9732bd59d23d48471f2bceb482d436b3770f83a981ebe5e4d704f7bc3ad2d8faa48e6916f7a6c62609b085c0a45d6bfba0d8a3b2122f20c444bedd10189ce8d612274b3e2a47716105daff4e543815c7b74ac5328afe7ba500e97262352e839446e3b1becc0b17b5e2509aadd8403b8606ce11960d697cb7dccc1fe5a9e54387ecb0366508256b9df523588a300930624a4f74dbc0f82a15b35c9f0b81bdce06cb6d2492345adb4d9ffa44c382a66c13827afb14aa966d5384cb5dd5cf83a440b090f4e829bed275f47d61c4c64a80e26aec98e4c09ff49cb7348d0e9220f908e4f7a74f218b54a508e35c8d32209e39cc25c5b891c996a1b3585798635a00d6baea81c8cec729314aab718920b36c6b1c565fe56d493340d9d4bb2d4ee0452fab5272803316e1f347daeba7bd056ad2bfe90e39569aedd9485e892c4ed4e36bf70ed58427e1139d8446b3344048c00d4068a6f7c96604bd18951d645dfb3164a27cf3d67106f22e349811f3a8f94477468e34352c67c329ccbeb7cdb1643bf1a7baa00b6771056b61eb1117e12a163bf78eb88a079eb5744428e03bcd15c113ae6f48ebac398321515823c84d61d739be9c8ce3485e7be28cbb64c0bb8b7bf7b7396996c7b4084b1e7b5b7b9e204a37fd512ae573bd190a87bc0cf39f8b424fdd2660736dc53693d34961a47f02c529cfaee0559ede53beb739e13437b70f4cc2336622332317a52eaa049085c81d5175261f949d41579af59c86f0ce0ea50e56eeca1ada7b3cabc2cd93a04a4fdbdd794a0fa448f9b288b5f6d2d3e4ca9160d394687ccc6a4727cff3670e157d3b121244ee575588ac5a6fb0538a130b1334ec47d91d83bf61812bab40ced45675246cbff6b0992c7ec3afa5954bf04c49226dff0c96cec1065bfa3ff06c09c268a06210466d69eb5fb6f82d829729dffd1110b79fff632c1dde2c020f48c57fdeffaa6c65e2c8c223075f225b3d7e013591c84cf49c3917972de27d6e4eb436e661b0c2e695138bdb1000c5e529c0ee87b63cc668293ded04160a72185cdb8598febe1cc6a41cecb97c74eacf043742411209eff6af6e8ebdd769ef314d775ba135eea575e2695fd3141f7bd8aab2acde7b5d5e9f81d554af807b2c0abf6684f23903bfa441135e3765f11326435b9a8bdb45aff45a7fb14d02eb96a5ec1d05ed53077bf43daf61116a31544211298309f47c0a5b3f4be47907971c7f4d65eacc6b15277605c9f600a1ecf592fe9da2e5c727c3b4a85eaea6e392bd486a8d4ce7520a1318b259e1e89ee2273ef65cffec801adf588aef6ffab4a0ea9f516f3936c00f53e974483c79adc727554405a14b338d46ad60aa18b2782a0bc190d5967d64192c044307d34da50958f35b4262e2429fa59af37ec488e1e4724864ffb5ae9a74d80bb980358e6362238f5989a6f4dba23598acb2fb6abd53478b6b08124f9a74d064aba4d7c6aca771a34eb77c7795585b5ab723f42e9c32e52ef343211a4544a1ec46c4b261a7148a392fd91cb31c24846420fec0a41b01bfba851d3f80ad4dc7504f8c18f0f18e7ea5c1645be7c906dbc0dc903bdb5e38d80d0c67a5d3f0b9865f70423500de3da965031f6cd228bbbef864842870d7557b2eab911a49e907b880a2513c77f16b4f39bacac3e0f119775a8ebc0e35904211c7fb10d241d28785fc482b8692d919a3bc11b8c63521d341a5dbf6aef5f32ad83139699ac87ca26b423e8f0cdd0243f878b3d30a5024a3b7880693f373abf1f7d11f323c3de63c6838fd08e56bb80c042feb0f9562916505f4c14bff9986d5df82e92c2f77f052fd7cb0caede9471a76b7762a3af728defa580f66c7e9aa274231b73cb8957614cbcf1bf7be4e91952c571fe480bcb345c13c5e1be51f3cb1b9debd94e65d11ccc082067d297d424bd370a1aeaad1f3610b66c4d62804388352d4da755a69134d1cbf5bfafd87b704b7649568783f814af03b3139a5f133039301db2a28906e4fd45326bbd699a6502a2220b0fee94a162bd480e28330622c2aae22aeb3dae47696cea1f376a7524e1dbdb6e50707d40f1185c2301b7a475e64192c1d74232af95e41a487aec5081c1389d4ad34281441c7b556601cc847362d67dc5f1f288beec8b70cbb092e4d0092e101f7887c1b8255c8177e2faf27d8b5b0c670d2c92bc1ef5ba849aeebbb5e98577ade7372b1a9aeca395fb0d46e315a79392b279d32019c1f1f3a0e672ae894207ee4a708cc28cf1503e17f1bf10ea7d0345c890b309b32ae6f1c966f89db847cac1264ca69f6e26b9fb5cb503ba5f9e48ccf5916970e388ca4b789ef6ed7c949b0861011d615aa8b1113d13cd205cdc7108f9b89cb670d38c8c7f0fcf344b701634cc362ef08e1c182253500a977d3deb4bdb8042032f2ce178ddbb1811f5f07d21e0ded579675a0ab0f5d303947809e9381baf52a7db55267f53c28d803c941fd5f9a29dee87ea8c59fc3028db26781c47e0613e12aff29d6ce0479c08998ef5654eb6a1c1f8b1f5a771b0087587c130fd47ad25348049761ae434f974cb00d5fafc1ecda011d01037cb1160ef5880fc0d52fd4e5b6218fa2ad64deb8ea670ff5aeba8ae57af777e79fec9a79eb99443bbf1bc0d7867b0e858d5cf84682faa1d99c9355bbbc64ad07358212e5b72bd9935cf73850f7a97d021db22dbaf7f11fbf6ab34adf02734783e848d2c102dc536fe945a845e78d953e34de8985c54d3b7c24cb5dfb7918990399d2b5f7826b86a6837db28a414b312654fb00f6bf2cd9d95e3dd716e9df2338a382cc9e483f2cf663a1d027a1140fee308e0238b7c02d17f20683449c2238afa509c2a2d0fb8b437c5d73562d1b502d2ea5c1a6409b31702ee5dc6371a0108b4dd6705144f5ac2a4dc6946aa1b09fdb166e684fd03f3ab7160c77b9154f158674e3e8c8f0294dede49cf4fb07255929233fb303d7fb0e4988185844f90a82e4f4db29b0fd8f716e402c94b610bb56b40c44ecff89a2e23e384e5219d11cdc80f8dd50832902395f6feef304f028db831ac20b95485a4196239cf6d372febd69af6a09b03b119d6102c6e130fe5096a5200378b2788a2a0cce6d4df3861ff64fc7a59e090fb6905af9ee2025dacac55777371408d2269f6e57b2f853fc3a328fc699ad08afd5ab120ee0a96cbeebad269ef89148015483d60e89d48fdbc8ebe3436146b63a55caee6018e7f5ccc3ca6f64bd94e89f3cde7392d0c39ff6c6e955df704e09ba10580450e54563dbc2bc15a4e6ca6d477f07761c178b8e934e562b49deaf2c0fa907ead793c5b9c5b23afc205f1ca05f6588f85161f16628e4d60acf7ffffff439a339ff5e138bd230e6cf5d87d555ae2a300194c318b993ddebb3ccc747c36aaaac9a1a5e74638561ed76e754c86eec54cee620b196db9194589416c46ed876bd31ceda90ba74ea2b7e92c52ccd18867a3e7894b41b65d89d78149eb1d9338dc6e787b06e962ebb9f1b2ac37bd01d39db7ba18d66ee2493fde04b1f7d0f2b9f3a826e5c2e09e418537f4c6016a2af0ab064092b8f072dde8e0035ff9450e559f8d1b3b63c347855b1cac61df7f1902c0fd36eda56aaebde6899d03977256d14e955c71790dd2db94cd5b06118257035d09bb7c3ded298c68905dd9774dd838ae85c712a8425242b3904d1ac79bc961a04bc3b97dbaa9be03dd52cc8a8f09a65ebecd3355c983b2c7809de94fc9d102b087f8dfaf891d8b45f9732462b84bce3cd8987b6034e2b4b34ac2857943c1e8ebcb5219b92e19d3fcfe78bdd013c4776db91dca6b5b3233713a79f8c3ec49d5569e59d6d4daf72468269c7fd5e3040fed463d51403995ec85e85b27f78ef27f75a943b328f2f2d0cce916813aa4a36cd536b7f6bee91d752377723b078b88fc88cb05d86ffc9436ef5b7ebd44bb8ea8093866eb836e9b3cf59182c983670b53b8f84c1289a31bcfb4b6f4cff34c71e3c5e02ee77d0dac9e776f3e7c738b7d0c8ad5c149549e3f2b054f59fe3e3d10beb8d92076ab3fce78b92a6ba535f671f36ee207a455cb1e31804de2214943168e4fb5b8e5c5196d79be13c12302caf74505be2217fab287d37e4ab209523f39aebc8b52905b6f3d18819056aedc0ddafcee8577a1a14a91721d0d0c9e0ffa89a7c0db4f5ea294c4843fbfef12b0208ea7b32ee30675ac56feaf411a0e74a8db15c948a24713e9290537dd2b36e1f3b057fbf163ca2a15508df1fc32e4ddd530a8185d7a2c333fb38bd5586639910685278548c18b156ed2478f925095f07f70b734573e34a3439ed05776bebefa6e6f5e1b8ef37e02e3925be067c12aa2274bd0acf2339a5b20dd05b711cc6fa0ba73c1a2f2083d4e51641cda3f08238edf95e80aba927ce31743985658d3421d0788efb8a1a11c6da31ee15faf64fde6068a2d1f1d459523c8a74c08337dbf654f88eeebfa6c5a51bab8508d9fb2c1ce6c37715ce0a8794a43dfb693ebfb4dfe0961b307bfa835f55f13bbc98080d703f744564c7589263f06affb883fe399ccbc3d2e918270e85ac59215af1cc600c870124885062081e8904d6613ee9b37211d0bd757eee77d53729516a8e4804cc7159ddb5b963cc2bd3c3f546edd16177552bc6906e10c7720977c69713c8baa28f46055df5cf6229b8c704f9039e66ef4de16b6a3efebf26466dee7bb05fea3e734aa5574b324a11f454fd2ba51740fbc94bb942f1502d49a6bb535d0d3820ef07b471cecd452b37025292f1cadc0013c2229dd0adbbfa6c393630a144b7c63579945af916bd15a661cee0a6a1a59ab911ccebe9b58314e8094bab7f530253abb5704383a7fcd5cfe6a32153309b86221f3533104852baeb0ded8d3dba6f5909afde0d4ad237dccb9fa8c4989f74165fc4ff1ca1ded5142505e369fde15cf44a537287bde9e392e258756edeb01998e19f6bd371c4eb832e72612a670d4398c7fcbe1bb9e393b628f86314100705d2f3afb52fe2bb89fc577058cabe9309063286d459249a506f79c9b902ff525a1f0e1be200254b7d0c4cae8ddc742f9441d353d3247594c5d1ca4cb80d3070910630a11a2aecf7ce3ed1561bb18baecc3691e0dc7ae4fc14c6969c7fa6172852dae04566baa64ecc64ccd57e6177827baba30bfea6076d3e0d45b5652d6e2ff34f697792d87a4b9bc091e466afaf50db8c9826e6293f9c16686d7cf273f6edfd291ddf3617c26a48835eb3b42e5d09a81287413a113541dda427b82fac156ad1ce0b1c10371a3b0e0d16bcb806ea2d68de76206c931584d639e5e1a8350a4f4ffdd0796c8cd7e4659a2527a1fdf530b97756bad030256307ceb6c7e6ae84d45a52b09f492dd7a636559642f17b902decfc41a0c4bb1e885fc6a3c35e424faf9e578dbd949ec70638852fea211a0ce9a69bd375c8c70aba246cdff9ac7bc0409201f7f348a491692fac08544ddcbd9d4227f66365e053c5c182eb22b43122fe3f98052beafb9226bfb660243d89ece7e9d82bd97790abb740c9a15ad5f7abe2604fa581f5df17da84e532ef7654be2c647645f856c3e4ec75fd2b81339a9fba219cd3acfc6c60ae9fba2f64f13bc87b70a99ea017d32b96827edb1c2cab13552238e5fea58872ae1944fac5229a1ec4bd55db196d5209aaeb15bf342fb44b30f9ef042c4829c558b08bf3117ab6a7db0ab9515831fdbbe4f2a1e3e55e4acf33f87eca16d1356165bfc451c710d8b6be9fd115e4c42fcaf7eaa36d6fbd0fc0f3fe460f651e95a59e24bca1039cf2b0f88c277f7aefbf85b5c6550e0351159042eddf8d3f634a86a8ef2ae9380e9821657691a1869d366d2760fbe4ef51581c39a9978dbef92642fda31a5971ebaaa1714e25dddfd06c32938f1f812b184256a37df4331167885ef9a74f7ab97cf93de35bee6cfab043d4408578cbab658909440adae5b15eafdea338d43c4f31cbb15dac391eb98d9912495cad8ef8c0069d5f6948d8bf896ffe929f0caf0a12acaea66597936fc08e0e5a132e9e33f7a7ce5b423c572c6318738a1bfccb4230feae2f22fe60923520a853b80987bdc08b9417393516d9bd513e7aa4a7807e81a5423357491b9254179439116105729e61b2602c1306a24de6c67893ace6a50aade2acb191b21d6bac8df88a8663dad2e3a501797082803dd25aa6af6c9d293299b40c4bde6195f3405b385a4120745f8697872729ca0b610497d6e074bf3123f50648fea474d74c9f3f9f4be277db806498316d8d751c86676394c9a0ecc2ed2c24026d30989661a668ea3cbd1d3820a85bfeaae764cb8148f393429af9616e873f39286a76c8e12d00287aeaaa2ea47e3e8dc5f9cc0650d33e3b824d930251d9c1e2ff22a6314582d0646a6ee219d3449231e546db0fc79987f403a7c7a1c1fc27b8fe6061401e31cbcdd7ae75e90c1a6d314d2780442cf1c0be92afc7f76fbc3da428f08ba30663ff48bea741dbfa8341fb7dcad06634a261efce828e9b5b0f5261bac7880c4b9b0fbdd8922a8addf1da2b7835b19db13c69c0eea2683df8365c4a2786aec6dcba5642114db90358b90795ab318874a2a11e4ccbdcc4de5be76c87af186e683775c5c8c46c35f20012f0a63abee08f8b7ac375147b7f374c6f6f9d3e6db11bfa95441a936de9416498514ef6bd2938bc923736113f2cda47f808cf7966450874da000a5aa65024e8ee9bd8b059e2ff0dd7294323259523ffc3357624660ed84f612595004653f56a8ce9c0e317d9351b9c6a0a7cea1311c26bfb1862237bafbe4c6db6bf779119e3dd5f4da42a076d7cc57bcad777a34d3057f4d588220c717bd67cc6b6172dd7f0792bd798ba480f979e52cb5939ebeb66cd2d508df9eef94f71b98910ff304cf0e196322741fcf33138ab369566ac08dea97ecc3b2ff410b36d48d2bf2c97c47f927a0fd9be2b4680bf3544977e90ac7fe49ee0d4c14f925c471b43fe832c5ea5945c44787b3616f8b0281cb8390e501e448a14db046c5692174f76318512c516d46137a39b1e348b871821860ca9fd7f1111e4c387789928b1749497c0df44483c0bfb0e043322176d1fc49e3c33fda2644299c4bdb31a47f6109454f1fbf5cf7d5bebd0fd81ad55ac2affb48039628d37448ec124ac75709ade5bb71d90dd62639f0f32931af4f05fc5bb59f3daba45866d83938c4e7d02e31582f42ecb31a7f5ce417b89315eca47df5669c685bcb7bd5bbdad6f9571a4e1069633efcb189875be870a072098cf350a0d7ddadfe221ef5642bf92fb977ed76f5b9f2bec7ef398b051e2284dc695735ce4459583eefaa39ac1399d3e315865e810402cd596a53d5dacf8f41d894ba387647cbe6400a30c6ab7cd23af8b5b2e4eec51a915f7a132aeed02a4d4a583685f4fd642854e30dacc2b0756c5045a4419d3bb4a64b73565e70698691e0024e63600034f05fce4a6a2fe849b1f905b3245780992d134264fa72a39b195d9eb7c2ded6d5acd5fd59c36e4bb931d1718b53aa16885146e5eb82d425865a55598a586493dea7ed98aa57427bfa1258679f29b80be4f847db95c8345fb37c713f22e9301a3843f21aadfd9710aded21fe32e93ac6fea8614b8b754049cc61533fab4c00500545376acbb399738fdbf8ddbfdb778ac896018808f290bb0ad77270995d00f0ec815e093b5ca8004e8610b8a9e8211bd8bfefa29774b57b0d35d75354cb6c1ef815563df65a3179ca682ce782cf95d678f390b7ccfeeeb54c5df5d0ccc52bb1e2aa51eb075d35b2fa356f8c978adeae18f1f8ed08978a6a695710039a12b3ce2c607679951d44ef70ad60282cbd10cbe40aaff58f45603fd7fee4e81ba8393d9f6948060c743c6874be4a774c278b2953f4d8bfef6301dd058d5ab175eaba4c8d8880f682c8d6ae54328015f9bee96af727eaa646072c68a85290532e7205507c14ba804a627a9bf31955dd0f75631fe62b73e4d6f215867af187e7676954aa726e61ef8fb51bb99c56ee9a6c57b106ace129f08b72ce5e73fefe52b2b57715e03334dbba46b54567782d655da435b9a6d278588a3441d8222af70ea1a14a35a433fd280d53b838d585bf2ffcf86a531abb187b00e075bad4f2e48ba723f841806c1b829e5303a2cda0fb61e823faae9efc0ba7928df4d8c5d06a9924bb64fcfe42adb172ef7af94ca18eccceeb0551e9bb45b77a5f24e6b389c6b4fb1dd9bc7550aba5aafcf83ef09fa2b15652fcc778fdf2e3bff2b945f9a1083a9ac73a2802bb50a7794b55bb50456b2c20f1610211e1df48bab195b545ed25468a19956259068ad177783d1bea6e8b7cc76a057d65eb1bfa91e1bbbc7b029d1026b7161e27c77307044124eea04d922bf6ee3a8145494c52033e66aa1249782a697acd427e55536f92d9e94cc06bedc37980a2b0de8ca4b00fab3ff7fa303f582ed258344af62c254cbc44ed8ac4e01cd6a13f352306d3d4469694672e699396e3d4ed360ff55c8863c364f5ad279799e386145f02469a6aceb15f0a4507cbad8a2c6f45606106e0f356dbb6ebf3a12f678ace16a92d9bcf278e4d909eead5c53304cf0619cc86a9a63e51dabac8a1428ca50fe0fa7be9d5f864c907554c2ca682e7b901135696d8131f2b8712c56586a96626e4fbcec927d1a396add34999ee6cab6a3778b026ca1cdded2ba7cd72f95cceb877be38aed75758afdb96b2c45c24cf4905393924a193c79d94991d561ff8e4e6c18e83caba598b64f5841d5af3d45f14092da56fc2df6ea23e5d4bf335eb6f643b88972f752cffcc1ad4521b4518fc695fd43a56c427be8ecb29590458ee621651563ade539a2056643e36e426a18bb3beaabb6792ed350a6e1c4ba4aed3f12fefc6ba5a2dfe07d134023822f17415f1ae1ad075e312dfc7f8bd60e66027904fa4f29ae78468fdc6ae3594c0286b5f9d93f208dabe6f50873693b71c7e7aa4a44c0664f3c710dadd36e88ec749352d7e3e0317641b510ad2df600e280331d204f1f67c6499871ccdc977b8201c387e092a19b9e779bcce6f50a526794cf57e4b502fe3e1dfd54483f1d7e989d05e2f31a722426dbe3aa8d3b24c1ce89386936002c02d1eec17f38c8e0b9c4bc30fcbff47009f797deb3cd6d46fe5b660990a1f1af12a9e09c2cbdbebf28f67adce6e9d346222730473b1110470184bbb4b3b265086c399ca1e0df9d0b27bf3087d4d2be4a7b2f4522833441b17e74383afafeebbb34a64d83aec79fd74072ad535279f17e84926057a6b46b921040a23740c2ce14cb2d4e44c89922e32d189eda528ade38ba2f0cc05664211b0a40ae21f0c1ebd64a1763b5184d7d746754743a9015cd93c0253f21327f9b13dab3009c10470e2898256f0d4ec26e21ce5d8356593c1c1f9d367449ae11be76e4509f11323bf65a55e6d69f30d999e33f24e2b86e92fa6040afe4ac905299960f93331fa63f6eaff3c6b4ca9788f6ad8ea903906c1b50b72026e696ff43ec621cfefe88f84d0780a7c72f6cbb8822382b9e0d8e6bf5f550260375e2db0d8326a2a0dbf6a7140c36ef1477b1f6969c76e61d93f80750c2214a3a2a9454217b5aeb64a210fcab9e838665f121de2f1719fd4501bae9fe6902fbf2922ee1e8a98912b785856ed7f126506a7bc3f6ba1ea1965f9aa92e246f8f84bc477f6f71ba0df66a885e3b53ad442bb6fa5340cfa25da79190e7bdd77ce97d5c0cb43ab8b532110a80fb1d45625d00519e340ae1ea959b0d0f55232d6ff2b2a000d6f9adc2ff034bc6e4923632a10f2c8861007e7bfa6897e9aa074c59d57bb06a6ad3833184d80af6370a3599e1c7fa02b8b5b849311c960a8ede208db0d7cc255836f61c9119a6bd8439ecd8973e7b8180b52da9256de74f867939431d8e366dbb8b6265ce19f47c8600aeb9e3f46a8e07ddd42b70578773ee422bbe990d671204819173daded02cdd9233c4af0ec07c07e30177555787d7ea108777c848f9a1a8a2e46aefda30fb77b5786dd5d33c2dddca460cdb0256834d283ad35eca159ede2fd267144e8967a89e452e4107d3982ece1d780d485058f35678c4e49106b0380eb55ab4dadd5b95e730b079341f6b540792ff13cf39a2d181938fd1e258a7f3cca86d977602742ce054e73cac5d2a4886ce4ad8dffa28a36c58e00c2b40b9c0274aa313960f0a939d70584144ae93d160cb09afa9727720e4d2d0d90d4076dfc81e9b5b13c3d5d2dfd3144b3bb1b42e6c1c9a13a1b82afbf8b8228d3c2e6c0d0d4bf4edfeb945708476d8c1d7c97694a6d49481a017dd21826f0a15515b60353aa355b63475b6c65a8902f444f74c1fd9583131d3666462744aff37cb94cb978d6e4888dface832594a0c01500d1c23be407d1b9126e95faaf1d7876b7c09f509c31a679b0408f732d04140f2299125b0009fc7f9a00cd640eaebd3f1d28562dbf70e65e98841cd86c26ebf128d81f015266a31e026b6c825d4d69776b90ed86f3c69a76b0de69237533b626b58c2ddfc38f9f2b9d39e3771d265274541094d1213fbc6ae1dd87b9c2c01a6bf43ec81f714e1b9cacb6070099aed4559502aa0e4c98b5563342ea33f470f1c7a771ddaa18c999bec352aff8f49e3a5b4592ddc316acdfb2163253d30434d80afd6137e744ad647c76f5cd4d7a74e690082876ca718c25b34057d26e465e296fdb73bce75c4582b794840da3c53a7dbe3ebee27c617c9b8a7e0d2eafc86621e0db268982cd0c832ca8eb409a64b0fcffa5c68ef0f1d66b11f20a7b9662fd77aa11a65c8f26e6176ec2921c1962719f7fd7e871001cc89dd139df5495f9cdad7fdf6bc9755eac2280adf32efe9e767461729bf19d8464f429ab93c37ce4ea057a1aca26781dc50c45be7dedbe740e82d196660a7d42b661ebfb5e9070f5ce6faea9f9d758c48131cd5924f9fc84abb44b6b585022889de53c5f0bbd9f618104dd5b883eeb18e0a9e76ffdd0665ba54abf52139c8cbf44130c6eb859b4610075b4a29a19bf692ca9f7a4a7aaac1aafd36b90f55fbbb0a40ce8da0f618ed7483455b7eecd05bf22d7e5b3322c38eae355c2558497c2b690ef2e7ce928cd0d49f0e9264262f60df07178898c7309bed3e4dbd51ffc51f41af7d9bbb898d348e139072db13309383005151fafaa0f668ec918978dad58702b87f5b20785359485a289cab631e0a3029ea11fe533be6e5d3ab9d314db8e4ef72d0375f26617e9d64886ffb4dcdd0dbf0ee11dc5e0ac45c3e577b0991f00f60a91f55b6908aee4fc6cdaaeb7e14d676a205ff9f5b0b46e6e28b4dd57b836dd9cfb04ecbed695b08669628c6e74f125872591d1c9ccdefaf02f3e2cfff8b809ba5c1a05bb933c5264eb24c149dfacaee18fa22ec8820186d75498a3350f00ba6f38d218cb7c6874dcc170c17afaeab51bfda579b5fd8cfea5afb15b884514b9597eb4fd7bd452ab32344b3f772ada094622764c743529c840727d6a1ae9ef7b203e110ffccdfa4d910f25e4be5ad37382e1fd981fe5b5f8555aadb08f11fc4d3e7e8d845b0d8bd71034f8d9e04d067c6eded4f41165afe856f0ceb5c46f20b1b5661b19c86da3ee977b653cdbc569ffa4bf86ae30f014cc3c7c573e381ce3f55e5733d2e51d7fca0a60b521f990c1476cf2ea6152edcc749ff9ac7d485d592411e33a43fc7aa87b628cc9ed8ed698f425708ee97d9f5608d5cb2b0790bf60e3b2ada59328cda42d81be8c3fbe803ec0cd159473d9cbd9ef84bf22707e0b72b50e4a50090a7026bbaea0c54a6017128ecd1ff576f104e29dcf7cd99d798b12400fa5b7831aa5ceb612ccf847e3954e248e82efd8379307927df4feecf90993546c9a19b3bdb52c9cf79785e29c1899a571029823f23d4225027b9e043777afadf47bd4b623933224925dc1f6b18cbe5a11448ad44d93397f546a6ccb5bac50eccc94c1118271132c18c7d68068ab79368ce1e1c340fbbafac8a42e5d17c463c7698f1fab8322e2fb40c1d4208b3cd981bfc91229c38e554c7c9613045ceea11f00978f349be3f2916b230dde20883da8d1f6997daa20e621c4384edc7eab77dce5d52972990c19bc8efa14002c82e49738d98bd523d8d39fc44c232211637c6cdd4342d80df39cf4c4761ac3aba09b2dcc57ce56794f4c86974de172e3212c1d092d42b0cc38d7f8b07a2656ffe7a4005c50cbd1ed99bba51f91f0366a0a9cbc4fe77b561bab4ab066a8aed830108b18673e6d8161fb58a1738a91c9c1b714bf307c0e61c2de12c15d40783e02aa162abc3e3b343e3051820efcee85cd6396661af3d5e19da7f38bd1d3e44ad72e0d3eca3b798997873e332e8c4bd08387ac51ab0028d776e9e8754984a215340ad36051afc433aa288bec04309516505426d8e7c9c8b02c12d526f49e5835d6b19a3ea2250e514a3734c2752e7548960ac76b1b4dccd611e6a916dd75de101c242d7eee8e9080ccdd9b247e2bee6136a7f9930e9c80c4d79d0dee123336d3ec7cacd18bfc29978cd087c37abf524193be6098012ee855048394c37bee7310f1a922048f36711325dac0250857a8e094979c56bdd5913faca11ec38842984c466ac8e4cd81bd8c9ba34489b028afbad92be961f90529209e53ba6767ac1b9cc1510a7524f33c1c934dedc1d78898e6cdb7b9def2a1ba3c717bc2372100cca4379873f40d8c944c85f9d22b2c830442327801d0c33ede02c0d4c0a83c4e88f0b91134e34105fc5e8af16e21148d96bb49c686e754e79447697438ac262db43dc3172e5f679bddd094844df20e452fdad318aba8f02b28038dd06d55196d11593c43177ee19cbdb791305678ec1f3b16cd4c8bff0936fe2ca20530179baa3235180d2a55f9607044d1b321430ede75568ca74432122d3bbc4a4196334c86860193c2696dfe69daaff377d7aa6c6190d14811eabff1ffce159cb0810c46cf2390154e3b217815e165981b51579db0572a11ed64dcde33421bbbcad3143504b53b4614986644532c3afd486cf19dcc2829417de44df04a8dc80405b0f817db063dac21f978cc75303b9423ecad3b75509ebcf4d0063a1a0a4626ed7026d7d6c81632cabb5c3eeb0916fec3edbb7feb2ff4cb5d565ed7342a4dbd726fc35a13343a7713d5b4f2298655f50df3003ea8368b89ec20377074da038dc1290b1fd52a3d86454aa93dc1bf8b50b9aef7925e93e1dc051751efe5588002f5f9251c5399db06a01c9de07d2aff38d6c1a0783f77fba328996e6b9fd94261c51ff016da954ff6f66727e39d36c923343b0088591956b1ee84577527d26ce7b0717b72be03baa26ad7ed537954235c30d3e388d898e0e23b0a42359b966f977da46016c68def0b384701a0bce546f85ca8e0f98b13815e103ca375e7a0560e28bccdcb61db26cf42bd2149716c7806eb06941cb967d1c74e41b350904543e653e93ca2c87726488217b70fd91afe540353d7806d9a307c5fabe760ba057d5b0453513c7e122fe2731ba9e8c379ee4fc386b64db3fa1537916ba5ebf88423bb339bb9838587e9edbfa0599fa68ba64dac3ae27fd3dde0f7817be4be99e157fb72bdaf2c13311469bb2e826a0dbac40c5ebd59d596bc0762f9b3e907658276a4317aff08f1c2c4a4de65d251712e1d876a4af7202e3b462386ffb34caaa75c09928900323adffde6496dea6c7047a051f37eb2cb8d756736ea6bed1b2d88bede092c29699105e557c72b2f6731b33ff68d16c5749b8885707550926dd8a8c5f4059d5c30ff2b33a48b692be011b3bae49f8f95d159690d0ec72c82835470c1ee287813630704394974d6c99058e7a37708b08d94a01d1ecf83d3a9320d01cc166ba35d0f0c2793203701101000000000075ab73871a16264a3a554e5f641cb1f73fd1c92e3b15962aeb025c06712ca604fde0860dae90ef34c82d487496f190be76e29c0f13f2aad2f0d2b7932f8c7500a46d102af0516ca49c8c38b314eacee1f4feb44c88393b6c9446136c074ebe03959d9b8ceab7ef474d148e3728f479347e56561447b2c50190ffdcf9b86e108d8aa20dcfa64056c517c17b6368a21d706e2b7952c9b73a9e1df2457205fc2cd5b4831e6eb5c8e9edd745b01e90080f7c96e1be0caa37873df7fe1b79043c0c668b5439acedc713f8b3909b7fb86e1b9e05b0e5f9140eb6f68ce7786152e0a2da13e3025aa97182327c5a9300d83ea5d1597dcbbb80b3198fe6312dba5853bd01e58fa7f40a8d69896ab29479c2a3e85d76cd48974100655e4572496417297512cb6d8f39da1d434a981a1607307d9607adf5bc2c80f39ef4455484c993e1fe06269084f6958cc4778a074650a00775dabef24c7c5c857f02ce4a9203db5bc2777eff0abaef1363242f7afc89983ab6ae4abd384de1431741553544300c7e434bb8aaa2936ac3034c71357c2f4116d9342db20086da58564e583835f083b7ba3b729ca9d1b29739907c7ac78e7edc98123eb29d70d86202cbfd143a0576fb4fde094b2e156b7b87813ce8f7d74104a4c91629c70a3b98a24f9a3a5bb7cb3560dc74b1134eedaf67c6ec0b0022aeb8ee562196cafd1e22fb7439154d1ac1474e2ab8481ec32ebb6e61933662b2ad33e6747ddc0acba7af8684ae3aff3ebbd5041d4b812f9fb7590915395b9f3d817794837f0a574fa64e993d4ba09973d620f6a4f0ef95f9129572ee388182b3b0d1ad8f63a378b37d1937338c41307e72d04141f3309c773d54c04fb79d204e0512617634cc242d7b9b270afb938f477348f6ec630f8d007c26ba05443b8e1644af9197e90ec830ccbcc19378c37dfd861e9c4dc7ada4162ded9c70536fa70768c3f5fcb78fbcb9bb63239d957cc8c8199da720eb6a91dc6933679fd3091147d9794f96fa867f6a234e6ac456f4d7be289ada34650084499e1d457f59e52c7e3d197f5a8fd4b87aeaf6272c4663c3a75f9c6e154e72a2c1e972483bf0433e135a9452b05fdb488356fcc2907f679c48a18fe2865bf1b681a368a0b750b94edbd64be05c42f24ed4723828611c41b06608385e7531ca99c9f5f5cafc9c77f03c77872ea73fc281b292a98fa405a78880997aa975f78d342303106d868b5006ccec84b3436a6b604b1ef12a0cdcda14cc014453c18a0031fff8f79c2231cff467fd09fc9ff86f7bd60576abf6813c8869328cda95455504b647a9d38026ca667717ffe8082a991e210c07d729649a17986a415f5f93f13c8557d63cd2f8faf56aff094cd8fd49193258f7789b7e5ca18f22071ef738c78efa78a023972252adc8871c758b47ece29009ca720d91cff05ea534f19e1340871e095a9b8cabe170a41c44f86e0c7e0c3212321b11561bc50a6b08573a59b93eac5efb1d522f0aac2961dde067ae9ad6b505c7c982f0052b13ecfce35276802b75f4cc61579ad5eac59e73fc06d5f30126f665b479a8af13ee371be93f85b1147939eb7f494ebd46287cff0a01b36877c8b8af309756a7b57301899130b17435034995ecccc83e4cf786f74945972438d078e7294019dc5721b0fecb1f259b25d44fa85d9b484fd1b487ca9bafe670f6902fd447089f17c0ed473f09bdddba827e94be1453ad0d21c23e08f58de622ce7227cf6e8ee7861e9432845b0e886b1d638d2247bbd0ba62baad1bcf4bf935a08c92a60ab6a044b6d6bf9228a85eb53737aa022b735a0be083773186a58f503b1fc7ce92f6f9af7eafa55d10afb27b8ff2c7cd45cc5841ea66cf97b02b42733070b7ec2ca747e2ceee6dd972ee58d41108fb7c4ed49a79e88bab21db24c40b4d3ce5483ae57af60763bbbc258caea81fca26359e16c41e9e74adfc8df2eb3bc6ab32bb976789a15eb9985bda47cb1bb6bbfca1fb280a9f222ec1e6f027d05c6c181b5796acfda9287341342c89bef72cc402b5cd013180a58259ddd862b84039abcdf8f325645af834522f90df17333e18b784e3a775bf974a6023ffc95870a5e8e96312ea9e1b38226b637750733c2c61130331395cc72390128523cc5fc60b59d4ff74a3e04491e443e11f44aff3b975e1c9f739213d1a07bce1b1ebba5f5019148899280f659ed844353ad4c84896d0c5faa305492abe8d7105c1026f579fc0cbb0a5e098eae3a6e82f56adfb87bb5618ed9b4fe04e54657760fee992de474ddb5bde0de0b6cffb961ade6364c206225465704681e1d609f9d9b825f56d583f1f3e23ebcfb5fbde23951fd9e58fa7793945a6b2439266e3836ebed2a403d352c71029e1abe18067457fb3e2902123eaaff7897e6611231036818c6cfbc7b11ee2234ea7647b7ec39d7555bfcbb81da9c8070d37cf84a75b02875893eabd1b549180c2327c40e0d69dfa90dbcec7b084cd22c5c82186c6ff254434eb9c59348cf44e2391e17831142c732dec79759bdeb9a9413ae1bf71db4c3101cc63d381fe2f9b6e01457d07cb35e92ee9bcb5310796776b67a585ced2418690e1b457ac423b000c797ec5bbf44e7f3e7fb90734c9a8793078598ddfeafc6745e245576c3524b278dc29fb1426dd42d1a0afb995bdf845ab337f78fbc29590f145b52ee28d96c9295f853bd3d4976e1b7e79f9b30006c937db74f82cc5a07a3715c914a343d3e9eb9b400cc46d38f25cca0169a9cac42e071f87a7ea139a795c8a950f7b15f1d4a58ca23db68e1d8c2b532d7ba4d91a2bb6e50575b811aff94ecf690cf5a80bb29361af724be0f5d2422f043b8d81be40ae76264dbf5ac1d98d75f41d83c5ee0718684db84a9c769b427fab60b7b00b21a380a184f8e482319d6d50b9be60618b206464fbf53405a43d969bf639e46beb51311033ce2612b5d59e36b72aa0c61ef680354c7e6b88faf6a6d6de897330cce9ae547c835b0e1e209a42a0718df462bc311cf5d99306823b6f193cb42f9987cf462bf3aeacef48d9e8f306e847f25d70ee4db1b4ba39dce4cb3a71bd8253e22b141f6ce91bf7670049b2234393af942fce7d0c02408b74aaae4d6c2181915852494b7f3458995eac102838d7169be286e7ec1cdfde7f336826716d07bcd4425e68691c7de07f1033414d9e0f9ef8df97964e3326f241e33c3f48f01e0c62e943b0049c0abae368e0277f99c8519223a19b59807e29267574995cb11d79711d03b95fd02d0cbab77ec1d82fdd8c3b8c0e04fdebc036287434fb3859879eb2eabbcd25c02d5a7aff08e4e926b4399b15d87cdb7be8de337915fca7ccbd8be31b8fcdbae8b53ff1281cdcf93ad55648b6889ed4628cf547a537763b02065a283836fa61d82a9f2d896c83bd4fb8f7bff9c0cbb7764ecca900e9ff6719be86cc91c6022b5d33935c62b7d7eacc740e1d28f7fbff765d70fd83a694afe4bd826e64fa3abb736bfe3fdeeec343680c2e4d0c0c582449e94e930c81228c4c053874653c28eef3c2b1886ea4d65f3ac11926efd74268cee13be55f19a1bc7510cf0bf72f63400fb9829486d5b6fd407e4c8bc11735e01e55340b9e3b2e72e9366bd36ed065bf381b3f57d0a29ce9f583e41f4177125a91000e1a6d133c947c191b3085e203531f42c5804a822ae4ba8da2ebbd485a9ad64f38ab4e86a18d930e44a2b62f73d39a6e11ee03cc5ca4e14dd34a5b54f77c2f35f6ac33e8ec0a40b4012b92c99de446e3f86fd72570759f8887c0941b912bbfcb95c6adb3686dbe17abb185955194babb1ab19678444c45bf4c9610a6e3d477c2e7ccec4ac068fb313d598105eba5ecf037843c7be8e760217e748919bb44b7471dbfcb1a401d0b2b4ed5bcad6c5f8f6b29f9459eb679eb293d66b01f46e782e37601c389e6e95c90e508494516243a5951591ef7ce3676436e7f3ea18adb7d296b78bc27baf4791d60705344ec01d8de53bc2ed75f61ac0378829389c2796908c974e2aac039e3931974d6f0006ce53be23c25d8a193ef5c5fadf2242cb597206de6503af04fc732450e558776f9e85ee33cd2c237e0314a191549edea9fada176c7a06c50faa1969ea67ca7e4c8f85dbbc51e71463bc0a1a4b952e68a77cca31e683caecd602d32bbd23703347551dbc0359378e38de8679101ee9a275099ba95715990b2e82625b74a49aee4dd7360ee6b34bab773aa0b452550af64894e0622b70109ecaa8c10a8659555846a06a991f1e6af4a5a632ed556eaab6481d50b796cc7c3448fa091e9a7fcc5b94e30a8c5b7723e9984ac2665e90402de5af561415e1447f8028c2fd5c7a71a588f2b6436a3452240e3a595a0864ca67cca21f487c9d3d09f15f110ce2e00a21c8d450c4617b31348f45218ce4b8f62f3df4dacd5da107bf39c4abd9a644d7e8f1c2a7d0550c280b3f35ad90a0a85d8c8f99d24619282baf9e2e41fd0e453bef111612c1e389e6c84225e8bb177a6dc8b4df476d0f62ed53ddaa19b0620007f55561a4975c3bb6ea9a84ea0ad155ab09939857b8a361541d3607f1980b3fef8ba64f256ec6a8685e27b2dfc0cc34ecb700958bc861b0e96a98b4c8b31ab4e29b7397b7f37b41fb99bac6b4c51c665abbd22d7c0fa50db36a47ac1a95408084b0e38ac9a6fb55781f16abddc9c6399f5072417f41700092dcdf896aaa75f5a02deeb1f8144079b2f9488da908e1d8aeaf3f4c880dca7bbdfa8884086d89935b271b66ef7314da061c1528e71bd1d9697c33c560b356a0794e7e060251387955575e832f588c4b87e46a2a4f94c3e4c2ba90bcd2a41bcc480c072fb0f2af99aa634fd94e39a4555b649b1b25c9cc6e0516c1b16aebd6b251792deb98633652b652cd9bfb7116ffb84bdaef52b5084c1e4dfa764b9e3a6749533e5290a443055b2714a3cb4b89ce4c7fcfe9a29fa337b229fdec93564a5455dfb47459e7fb42410d10a1e33a3d27623a028a42f88459415eaa0c61e0943660336f2388d47601dae2c6bb15fcebe3d667bb5ad5fab3c79f034f5c63c38d46713fda4c7a8e8a71ce624e1f21df05c164de87d3e32dfd347a65b9c866d4b4241bb62888d883284d53805459f4d4c403ade4ffdd0223593e6f98bd3e600428709de8833113f66a94f37072bdd380ef416dd57a17347d9fe6832e64f011949e283f965eb67bc3bd26d1ba3fb53c11b6059d39f850408c1e7e85654dcd3012ea2a28b815ea9ae666a6b520babfca9af246473c070d2ab5d686c0a9a2a81c42261d7ed8bfe3820c8606dad0f8e7593049af120050533092129e95c2a2bb2f4a704fbf690338701723a3fd2ee422105d77d76f9da07349512ff5db9ff51ce3b1b6fb795af3b6e895c461296793f0cf8cae0215138c00b37b2dec866b7429cd963ebcc60f007d5a4ff9b4d745da0566c909aa85a59a8bd608925fbf31979ba898caaad729f4c2013ed2164d290700844d2407c35689454a0d3eab2b9ee79e6a5698311b612be6a015ae69c7b7afebeba93517ed0ee84becb4d609d16219403a458c0f094d483788707a7309401720ac367ee02ccd043a9cd88a340ad5d9394c9b8874ec8fed53d8fa7921882606d6a1105d0c1ed5966f193be331065715bd450e2660d6f850db93d59408d10fa62604e80c5b78d2ddda530771558cbe57bb9c61ce9096bf013f1ab8bee65a9fa9c6fe754c290bc106face7a6130abf5217c8b6af69ff00904490b62f334cd7f81941cbffb25cb0e371efc65e8a81c016186c8cf18574d0257a56af8eeb62ffd361fd541e80da4a1e4445e9a3968dbd677718af934c6b6e1541e885564879ee65b1a6ca9ce39f57f8fc888aca2adce3d5e2ff6e74dbc6f8b7c7118a9cab47908a3ab14378062f30f73ab6ea596a0f002c0cb8199fb7b6a7dfd4ae9ef2ffecba3dcc88d87e24f752ebc37bdd1ca76c6c328554bf902058974149ac20a1f94405a1c5dcf77fd9f24dc38819c551d5e84efcae73e68afd2c2282186296eef2c5452809d2aee604af79bfe01c4ba1fc52e4e1072c84537d3b778a0f8c2131464ae758bedd1eb52949fed9ad32915ec754812a6bd55525d30b7ebb7c953c4b42f9cd23d88fc07ad2a44f1a86673fe742f867156e4325b2f7f537a690a5a5217694751a288e2e03b7003e12a3ba75e4430c8aa2930a8d54a8cd772172a7230dd3e822e20ec09978187ac3be6e6018c597bb1c032a156cbd37ebe47f18983d23e2e501c5a3eb0ba706574511c3de9ea7d2e93bdc085150a45a8094d13802aeca8e2a5d96433194bab7631315e1dbf1a1f00470d1cff6e3ee44c9d1741dec15c75738b6af1f627fe30ced1a1af004c7f0fa5ccec9873bc582a4e109960d7f9133cf206e17d9238523c7cc7fce8cf331317708aa072c69c0153610683e5004b9eef817e1d658832e113d40ea14b6a90cc0260a75072c2d7ff613d70f5b967ea545d4edf3aac9124b94ac6d7f36c5a265e79e9e4d73c1ffb62e55c9937f33d5293e4ede37e3191623801e9230e7bcdfc8f9ee619f3ac0a2596cad316e677dfc31047572c7a931b2c1eceef98b7b80c3f46c56ccca3cc161a34296d0148c184ba05d8d54d0136d216de0dd19119a9ff769dd41b3a95166f45c2ff2d135a7895e34ecec68ad07e5fdb761c87e84d642b4466db9e2146b58b89b912d895ab14c4ea39b76ce2f6fe771d1187581ddeae3113e481f416ff25a660489ff7d0983731d9e11c4ad6ce14c59e2878ffe8e8045d1e3b4de0046b4464d8c4d753c7481048ba179a49f46340f93de80cca49eebf1467751adf5c979ea9b94aafda05da61f723ba3d6ff501cb2b945bedca7c39c2e02f5beb32db6ef1bc8e4540c2848451d84a9d5f75448920dc4c62d7ca6fb65eab9c0c85227a26d60f5373e8567d1822c16bedd89786b1e3934f6469bb57f53b972f24b5fe2b70988cb0730266a39fd4837be12e1795180ef3fa82064ac02ccdb87bbdfb2acbb0cafc08cede6455f43fd3111e398e84bf54da70dcfbfbf2269c8d8d935f463d9276e8b445623237bc2e15184f569374d7532bac3afffb45f5f9a77f6a4919a44ba535794683c8ad24f97a6a84e5ef4a72bb1307c12ff18af737ce215576dc6f958e1c5240a247d92ae45a3a99d14d7e3f66c975892f7f7235e55ef18f55ac257211335959cd15fa343510f287fe0bc8dbd12c97de0331065943842e13a12b5d05cbac9b2b88077bd229f9a3232a127968cb894c7fe142c7e0b356304eb62f9a422bdb2cac883b431e7d5f917faa10729481cf012c44c3897058a793a0044db81289fa2ab66ad0b742b86d481c2b5430a3c489535c92fb1ddcda2da2071e04d24140a85a6348969c1eb5d4b915b07a670591e185534a83f3312b29b065caa5c835e0c61e2d1d10c7b6f66251785f4430cc6b705464d027eb903599a821ddd0af9876da0af335e117b14a9a7a61aab630bcf8c42eb593737af0b86cb45a864cc2772eafe3df721bd61353ff33e580ed12d91dda72754a463ebc2b6926fbd457ca9c97734e6686691f3dc76e39f9057a16c791f95c2c03bafd6f2ace14992c76ec62cd60f06a0e426fc6afc8ead9652b5caf5ca40ca59196e68211255266b00e0ee8b61e6ca76cdeee0bccf4f0c1565bb3d5f1501f408c182a6a2fee3f385d803f16879b48625cf41daba06ff9289bc2a92bbfea199173fc94dc26d09f8d9c346ef5750755a04aa6d9ad4ae16919a9395ee60c7ef26321c710709e028c348aaf6f55ae1adf4e1bb542eeb1a98a90945caef97a7ec6b6cce74acfdfeaef6c65f494520da397314c0d5efad40ce1d5c48896ca0b2976eebe9661c653e1116f493494950ce9ffa7b50b33534aa7abaf0f7d20c4d1f30b16a37ed1776dbdd2e3d6ea9ddf4570828e296e23c15b0d704264b73a247ce3aa12d1cc6870d12ddbbcd5149e1a31176be5e0465a1213d97203bd871353acd1bf3a84b8009a04af95671c1f93c539a3986758c206734fcc68275767935584b319bebd7065ee9f6c748e54aff145591310add1107e67dac9a936f1ad5f3354b4c04c66779dba5993966028c4804a0da2ca1c23bc754bbfc2232502686f7009ae2a8f94a08f1407994478c84758f6853e530eced67c1470f86b1bb8ba0940e9a9393553f632725c1594c394027b2b3f9284311f975761e595e236c99eeb9fb69e2002a049b3525e852ec5398eca5f04262b0bc1fce4515436b24b8bcb364f147eba90aa8f9f92b846a96398cfd5cb18fbb093b89209110ae493f0dfeae958bb1b4fab16642244f97275399cd18d7817a991772f4c92a579b2c363b085368a92a27a884caf752fc58bc6f43e8386b4427b074620e9ce1220a76349d5e9a2db5ec07eb81cc2b7b81d0ce037971396d43d0d6ab72ea3bf8d17098a28fc2a7eeb9b8d6413c297195821a476db54c592d87db940ca197941ad30b5b06eeaa9ed8a0f5b88507b6ec5fd648e7c2a27df8f74b27eb6df678eae28485bd293bef02848fced01e771286803efad23b1f87bf1995b43249b3479ebf5ceb2cbe382f6a1f8f7ea08595589a96cfec22b923fc976825289fb8ae0a15e896b6b134247c6607354d5c259dfddd93e8a5a724e3e0932e1b29624c77f58e96a888cc1c628f49f9e0641874ff5d4cef40d61767b416325356e88e5d63f14f4f622252812413f628e017e7bc8124f9e29428fe1d0c7a725f1a7ebcb70f6141b3878ba020aa1c9e43d9225c66b3f19f9afb2a891325231b567120d6a20eddda108fa1333c4f99b6ad76cbbce9f326d92fe263795f190eb23eaa7b58b7eee11de4f5419a181a3c7547e8fbd21b4672a6279d4547fa8c54f81a9c091677f3f358413ea59a0c9f1648f55cf879871effab073f4acf48920e5f3fc65fa2d35a57597b899e7891ba90ae98dd580fc4662984d58d0099950c9b87b930956cfc57b00bcfc879e4b03013e520e4c841fa2619de46fabb00846fe8e8e0e9d2b71de4cff1d7e6a88fb486c06e70ce7d6a6f38b6a6fc20b6063696034520f1fabb060b777dec9974b3199933f64aa79a04719183c66cc245c99f7e3074899a7be21897e968b0c3a3f30cf69312a580e46a50fa95615c387870a9151fcb61ab4af880b8c287d13aa942a6b89503eb5e8cc130798d89606d50751bc2f1fbb606698e229aa79f06c3d849040f9fff2731b4dce8e54998601de83264e0e7db1581c3be143124e050d7dc59333792a54e06be1a80bea20fe1e0fb46bb64f47d720b6c7aad18b10b7250b94c0506bf24c7efb7026e35cdf9622b83343611ae96f90a02f110dce1ffe56c133ea94c66e0036e78681a8a73687bdbd6ae6b436245902dd97c00f6e6175e668a1bb5c9623503857ed90564646cb727d2907441c0188584bd429a9a9d624505b4bea6d8e452eda7a0b6037bc50e24acd9401d799f0aef7941517721eebb5ed98688b5ecc0b8475dbaa2a9b23c47e507799c3c573dd31d86d321ef259f3a8907a6688333aec136baaa90ea5d88ab03d2a7f4dddcb36904c00229971a427f616cc04ba38698857c15592cbff3ea392bf228d3cafaad92945bbb74d467805ad59798d73e435ad2f39731d26735cbfa1fb861eff2cc4d95fe8872f76b5e99530b470d6fbec140f72ab642017c56fe1530a3adc82e8dfdbb536c045f3da3d024f028519fa4b8c39557aa29a93414804e0724f8233e905c7a05c6e1d7d0a82a8f45fa48e600db9435b278ba69d6ff58f981f78b5b1da23809b1e332c481415edf750cc479a898e4420ca0e39c22ea6c8dc573af78a5571695c187509d03bb704272621d38b9fba861c947fc8772f7f84851ea62a488e8890cf5999c94b114321fb033fcf3a6491808a7502b39d27decac49df214a1f77c7debad3bac39c09e87d406ff678bf6c375c1bf4231b20cd3e335ce3bca56d4c429730a6974f92301cc6eb5b084109878f440ab4b8e87bee22acea7a62ce755cbfdfe46c0b63d4cd75adc38f6e6110a9bc8b19888ae4aa49c86527ee115f174a4b83a059f9829350c5215d85b33e32e2a9dfc131b7919313cfa228247829aaf8dc731b77fd59b1e7e6f15ab223b539b16bf8dc75263633c1fd683c1099b963d2d570a38108a6406f82e8041138fd33993b590163c48aa7b4716f5aaf78413dbcb6bcbf6cd1782c5e620bceba1cbf9edc9a7188f3a7e0f959d0b441fe73625b82776f2c2dd7f2bdcb533399065af2199e67ca99c9b47a3dc131dec5bfc205143ab2c397523c1ff98363770852da55ac20f0605430c149d8680ac15d456240fbf7db971667df761bafdd6c0dbe19bd3bee8e41ca5d09334ccef79788e2bbd8747852f5392d614059ad00498e914bd181e9c96aeebdf0c95274d673835b55cbb651fa81ace7e4827f2f08c6df56583fb036f31290e04455f97623bc87ff9a11d99764baf8cd7fbb07c098c00d9d54b410852fdb7e440493880b5068b35dcdd5285a2dfe860433c40e5ffd243ef529202f0d68b3b1821fd9fe8b2e34f6a4e195eefebe51c400bc2f382d2f1ff461a21f13ce5cbddfff661fedee9fac66987dbfffd0a12ca9deeba010528e9fb559faae0cfed8c57ee553099c1b7380c9b0837872207b47fa0bea7e6ce15005322f3c27b6b49a7722798f3212d70ff0321e33e246387be748367ffe5af7acb3dc18d5fc93e73215de33d49cd936817a51b916297692feb13ade3899bfe1d223c2420a7c8bec7c97a1c50c9caf0275f3f78fd67cf0c43c8e86b90855aaf9b56bfd8f97eeaafe9bca6063c4aacfe17d3396304cca878676d2a2f283110ab09208e176c65193fb19c3c93c75c9b2d15b4e81138cc348533e35b1b7dcc335f19d40c2e574e4304eb62acef09bc0d5601a094efce1493b51c9e16612824f229e73e77faa720a1659e8f620e7b08a45eb52b5af9e1ead98e9a38a1cf7cfea2e4931512cc016a5102e76cc917cfeefe14a44f1360294a1286f10bf7f9c4c63195592f9bf31b308948b3d1fab902486615c2c9a2e4822b50b0aa3edd77da65731bf1926b54bb6273d03140d37800f1dc8ff133a7b2b24558e6a5c3444596277a55b1f46c356ca471dd1dc697f1328b8ec8b23b13806c782e407cbd67f78508300621301724761c52a91464f69343f6476f849170808a0b8d8b9455d5132294e5080ba4a1fd9c6699cf4df308cc3fd3cd874695778e6c09f329e18407d57edc81d95bf1e274036f2befecc813809aee3d88c5d335bdf63c2d13c307cbf59f9d0aff163ddb671346f30f4016c3d2afcc077fa62fce05c9d456ba54ca5a1a619c36564253ef0b535828007126b8a800021e5b958367b1cabe4ea1e70d534ec177d07ed75e0fa5a6f652e3a85e336179a568f59c020aa57609e5c0469b1657096a017151a755469e690221edc3b41dbac999b542ed8a4a8ae1c14d83831d3a1d2c9c68f7be4d7d7f01884b8745e8077c945942a0b114e19510693196202f0fbc4895a3d8fa4bf86e3eca58c683b7795a837ed09a8188b385dd0c7c4b61d426339ea9fb8113f120e3d0121e157a810173b377840ca47faf4ea9e505db1c0b27e0343f17f2bfa56e016b723171fa46f44b540bdb75088974ed44579b899d5e66ef46e4b16b17f29fa27049dfae2c2ab1f2f4fbec561526651b668c3386fb8530942aba342363254d6bb46afba43a26f4a39047a9cc6f75b135cbdf8441cb9ed173501688c00333249ac3406a77c608b69ca093056a844f64a6965fc811acb6822f62002cc3c58c521e9bdb2e0c8e99e57ecedc5ff814ea255e7edbd9834e2d235562698a261206102c7398c2d3ce1392797dd5362153da4a26d1e2a20c2ff8505c4fb040a5ad6eb6e255d97c9832bb3eeeb33fd7e37b9c2c65fbbf549a396a13505076aa186ad823e107691d505662a86ff3b69e8b531a9c7a9ca65d42b7b46bb908ce1ca322760b50fb41475a2b635e04afe8ba71e6ee965ac8773337e1c242965dafb6a99d9f740caf113a2c37a7ddb1aef0daa891a8c9dd219f842ee652cd41544b00952c6452ae5fcacc73c0fd4f8bb9eda9960b9de1874c4a26a20dc4c6553762baf99d392f4adc482c0ed2545fa81c13610e3093d8806266586823cc30674a999d142a1dc56b5f8a295f5fda2f67dbbeafcb998fe0d4fc8133295348c38c0cf3cd61b68c19db7de211a2c0478f8adcb65c90d9cd27a2f9f8485d1a0836311619e63f1992903a1c5b16ee7bfdc1a8e3498eefbf15d959c1e9037e6204db9b4ed2b00efd4e3fc62a41b5c255ad4ac110b56850265ae3fcd652a782eab876b4d0ccbd028d75c4c182c87844c73219822281c285eda72eefc4412392e04611d0668cbbcba2f30f5da4ab5364fa698f77b82b069edbd65daf45cae07afd01d630f63e8c9a605f131946f94e3606647c2ed641586e4ec0a3d2e5f98d9762281140ae83edeeb411d5ef95c0bf0713d7e05c9276d810bd80bd0cd5b1f66a4132737035c7e4e80d8712aaa110f29360dc8ea0f47e654a0030daf409fe96e7ceed85cde91af97030af84048cfbaa73a9190c036eb65cf514e9f953bae6135c03e268afcb58067c183ced7bc97a14537d3554cd85730dfa49ea71d8a2897cadc6d9ad5d9907e771721429810d939c743a9df328213b2779dd00b1848ada1a6fad13cac0f843203a906167ed9571c3b6bc749a8ef6c3bcebf78f423c1f3dbc645d983fd46ee6c08a6b0e9eaf2648f666459974b665e1164dc22f6004445a3441de6af6477dc6b39a9c2253148ba980c390a4d56ec4ffbc078cc77e7bb7e9d8d4ab300a6d2448e058e43c602457eaeb111a960a4e2fc9092426aaa3d55a6cf69ffbfd2f84b3f393fc4b5721300f032da2afb34f9688ee9174360f0b9841b4d9fd55c9eb65dfc9ff75cb9b44c27e48fe99d4e275135527d95f8c2c876ea90f3ca6bbb60ecaa777afb667db68c3b3d30d3403df340cf69e237f50f563668ee5c4bb17dd15e9040ca0d4a381f115c303ca8210b610527b11009f2cc95348e26e4d0ff662643862ee3999892e41562578db47117b5df2c23ce18355994e13e05351533eecdc76525c5d51e826abd9fd203d0598be2c16ffa9efd55fa458ea6abddb2d80c9055f0b15eb85518e1881e103def72f968be6e73f922150482191582211e5c748314e541b00691522f5833f911ffc524cf4958a1d13969a66cc63188efec35a666ac5fa424cb3309b0981d543f2a428ec824b02b2edbffd1219ef7581363be3f8dd4ca6127268890c2083dff29cc7d00a3fbad2866f5dc042976f4a47da6054f525b43becfe4abf5aabf7eb512c92aec80d2ecde771f33dd8c3afd8f18a2a02fcbcf85b320d200f9cff29cbc276b7e6f232c7e239941fa1b92c64cf04f1bc405451f13888100bdd4d9ff95f6a97ef40056c847f17bb2af2fcbb5935a6df72d1175e7be3ab3f0a6671118a91f07d163643f0d04c39c1fb29b33f5c5be0046a0c3f9fc326f7fb5dfa28266a63d9318dfccdd8fa5c223eede20619f10c680218bb712144df40a9c6fb82006112c38e20c69db222cb723dfe8db997cc2c3da6c0bbdb194ad5023a4baf409ecf068150f6733fc15abddf4f56e16ba5199075f1030bf08736d73495f3deac92a6fa49757e41e65519f9ec3b565ff8270b705d9069b687a3025d0f66302f60c302f63029e06ca6fa6138ecb73dc59b69e90b8eb6f053038d6dc2a0f8288e6a2bd7b102d03653d034a33b4e1788aea04e54d67e46439f716f578685e94168320ee826d1847dff4a543389d55010f97b134d27fd7431d4e8215605291184d855ac37a25baad6f9857293758b25a29d2013e5a276fa0f0328a00bc57c5458f02fa1a7088bd869739fb082a826c2fcda9356e3f8ad4d89fbba2e2d8fa666139d7331e2cbf315352a7305e17c81bc0408efb39a47974373de5c93f56c4d49783aaaae278088a5c10fedc85eeebb7138d31ceda88445e9eb2c8dffb8a35b59e6b154546381f9798afc75a9e471d0087e46613d11280ed84b40ba5b417acabebf1ac13856ea115cc64c4de7fc7fd3a4d0724c08c0bcb9a3f66b8306b029a4956fb980dd48d8a22cb0509f78475e1adf3c684d6095cfeb0e0e75995bed743b0e8be671cc2f46627c54facf6e2dd3b2efd060999aba8687c6a4db2042e895a55becd8942ff694724d90b5e6af0ce7b787d620e5c6384172bd5cb2c0588a8af68df09d33bbdf6801f93ad6395cccbcef962d7560eee29eb53af472ae082505c0de930fa864f00b01cef7f99f9b5d28db08074e6786ee2d2720b02848496adbe0d847689f5019d1c25b7ca39b23009ac4b37555fe3d6b0ab29c259d289f8be131b870bc0504a82a13a2be5be70cad2f1615a334a399a50e551a5023bed7eb201d97f0c9680cdf5c18faccdf6904362635638c053ba1c657b98cefa0688be9b975fe442e27cac9a3e1c6ba9fc807956384d71ed4c41d30811940fd21ef4e218c3280b145bacd7bdcd2cf5be77c7db5c808e6ffa5092bc9595fdab4231d85af246c9fa5f3706674cfb124bb757debee8e0b73e26ed0d1468f249a1174a3ac1f0b824157147f2b498bf14a156fd8abcdddb91504bace7fec9eb0455bf295d1e42b11cad28466772a70836cbfdd89a0ca4ac29ec19bfe9e73c61a8ecdc0a1ad55e02b7d88a248fb6a47e034d35a398c98a5c2205543340a854b2444dcbd90d36f041e9cfd5d6ee9499f90eca8427ccc255a1fbaeae87b80997b7713c5c9f21a743fe9d30b47ae72cf95c00784a472a9602fb60ae6b3f4cee84e04826eb017565c80e6764a3a87e47417c2594e8ebc08148f857122815ef0d51e0ebcb03a28be5ec9156aeb93b099e1fbd2c15f94ab35d77e6f1b881c94f2d148e7228ca86e33439183fa22a975b61c5391afa86e6aba1533618dbdb505f5f04f8854f8c92e9efd73027101b81261bc64b0990c34d19e27aed02043cfa7fcd6a2cbb1ed8faeceb76324baa406f4512a23a274a801f770eada9a2b571752dd7dcd41d73fe2696141e44abbd4714813ef341032efcbbcc92a57e71f0f93fdc72d578125a03de8bf31ca77c1af4a1df44faae2841c003a7b56b84e038a3c2d81147f47b527b8b3fc85789c9a82bf0cb3f939f1c8be448a15a6f7aa3cab06639afabfbae80d8f773ce06dc13b0adc49a47698a2c1e28cfd1df63b379f88483595ded4334907e0914757684eca6681c49f9b9113157c0607a9d3814b52bae7445ec39bd9a1b674307e8cbaeac21f00895f7a8ed1f35d0c0ca54aeb512b8ab5c79ba0cf391db74a896130b970e36ab4ab4fcfb971a5f7be4d75c36401f9abc94c1d182429443f69fc82e6bd70f4b761cbb85ec8212c6333312d16ef91b33b54d7de8fe4685c7da125c25bc19611b15d62cdce8012cd4c0bf11dea01cd8a3f322e707906b47984bc863063dd95280d56d71ee21121349828761e4b7fabd68918ba529cf5b28b2261492eea8f885619e4be1ddf4251000f1df11dc7227c0cde599cbc9d572fc50f1349aa61d54c3e6b5ad185732910626049b8a809284af3c5f419f93c5af89a79bc46e1b260b87a1d7d76b41ec1d2bf4b23c553d1b81a0c392b3f0a27591104d24af6e58c438aa6968623a0e29d32afb9251fafd453781015cb4d015acb204c9f6d22104f5b2c731d3823905a7db3724091e6c9384bba759fb70d35832d84d4e863aeb941ed228c7c0b6db9a2b9c00fa7964abdba81e5ed2d95978184c2564788b121c6a8e3e680a1fe393a5a36f316c42ea97d458f4ad28434f20e45797054edc6a2502515b5d0a846489a48e3e1ffa45a42ebf997c34ae1383c24650b5015933aaa1803dbf9cb749d791e169a332f94aef027c3a61b32b84d623c2dea4ec83addbf771cdb01f72afce4f5db89c28422c9a00a4b83ec5f8d12d7aae33bc44d2b9baaa01190aab47dd3ebf21d8f61b56fe492f34fa0ed51ef297694be4abb4acc1d565e448e220a206515b1de857203c7c76c5b0653c9a495b142e6f616789bd92539a8bb4f0ca0a102488c427a92fd3bc67a3beaa2ff82d5342b30694be639dd31c3af05719b18b0c03ca0165501ea8cb4e972ecca3fed83b85380996dbceeb566e433d3f9ec4c68757487d0216291aefb861d1f851c56b95ddfca22bd14470bdecb3c336376f3a13af19ec38fc2cdc75224c304ebc36d27cdbac4d594c13a72117c98b9b7a1818e8f4dec6d3ff11ac81ed1880150f71f4eaebb58aa8454d55423dcd3d8a998bc604833f919e5306229ecd5358bc49e18200416ff0306fe40db3f5cbff7cddfb85dbb95ee8adc11dd83548ecc6b1278b941f2777efbcdd101ac427828f94a99060e61f1633d3a30c5ba9a9c5a58d9229a4d5e3e08f4418b257dfa4505ab9442b1dff524a4d343a146873b66fc2ea6b41b49538dc259e116d5db38cf1dc61882450133e75f6fbdc35aeccca1a41e6593091d2c8a9b4f00f11b729701baedebe2bc63e535170808b1a4ed1c359c70c624cb8cba23f221a9881ba435d59a35bc13e79b906546ff24d3f3533a3192e499ad724d63c0d4695a575d28a19541f2551d1de9da125404d6d1d632cb880eb160d8d24f1c54aa6618e241aba31caa883794f7cb616a348b680337d7f32c513b383b34d76d627aa65873525e89008ba9b9236459cf95dce97b21d77aa638ae6d78c9f2ec4597e9360ee10ffd965fc0eb3fcc67a1abf8a09f60234cff18504d7a69c5cac7c2665d768344c4fe6da195ccb4df9de38501253868809262ed71a8beba92b219637dbaee2199f42c1700600af3e55eac6fd187d3c0a369a79469435165a6905ff58ed8e902d6024fbae87ace73f6ec6bd92557b3c9e3a4dc467ebbc4ac87affe3a4d226d0c08f7f4cc386a5d7614b0a7be87e4f20d112dc9b437665ea361b3d62f5e38d2273f90accf5332175cb3fca35416fba57e828729366778b300c15b71c445241f636bfa86f2e2658ac07bd15841d2d7e6f3002821fdb32ff305d6bc2965e001f877e59667e81f28ea57ea45a43ae5ee86c072032f1a335e95819a78d86adbb863011df83701dc9c24b82cbf414ce16438ea63720718194dbfaa52defc4ddb28473977265eca126334453887aef78b679d1fa119a6c855df6364a837f1d91ecd081c309f24bb0d5a98255ec4a9f13b160005c12e91abf86a43be723a827c93011b05b946e8d0dbc241640e446803a6170202311f1580bc60558123e92dcbaffe8a4762e280d13ac3dd78b9f63d918bf7e0fcf25bb25915ed2abed309dce7b306d1d145f3a895b97968cb932024230e070bd5b34f36a93099329e571286fd8f2d32d1f1cabf92258d094c72ca0869e20781c2d376bccdd277c9dda003aecb1912bd5e0d9a860dec7e67745f74656772c95896033b79248b1b655280681976f33ef26a8d138df8ea1634b3e75144926648001af26a813f3ae57bd53b21e6ccc3706a0391a913cff971d842771086f107524772e1c267f5c6ae205784917321a5cbc3b323ae19cd14b0de75454b2ddfee7ee306b3314f43404e3a96faf80c5db5e576ff5b369f5e434d51804b67efb0c08c062e628f3fefc2d080d8cb6539b4ab650aadddbd4123975a25a175d6901a9ff29cfb30610a82626dfd126976db899a778af0051996f00daf3522e2c6f7f9484f7eb1e1aed1bc0d593e75cdba5cc9c179c3a2a96da6c126ad6b1e68ae5cc363be9baec31790635939a5a8e550d8c2b3d695f89b10a185966042b921c061a592582af8b0de4867bc6ebe6f93c60148913e4419c4b6ec1ae44b8eee7fbbd07c0f62714731d0c61856a0e8f8a76679a805d1500bdb8f340699f01d0cfb59af674b17ab713075c8eef835af1ef93559b95c9185d324cbce293c1b7b9a48a4b8227d6dbe3ae0f4cc78fbd7886b0540eb6c7088e692258934f8f640ecf4912792e4145a618130a7a974a37f928c327941f487294d77adfde5abc12364cb7f68975be77d86f8d12e7c9a8fa395dc4299b6305673e66c72e96f6044a5c27e12141d736e6ef520e0e19738ba072e0b123b516ad68db1969487cf274abced79f25c9f54dd057c5541085ffd566022332341a406a34e64cf06d21a14fb11eff9d63a1f4368a42672e0080a05fd930a64da316e37d1c82584aa9e9b3902efc484eb01c6c26e9736efb044908ba36a339cb540350aaf6bc44c2717ff43322a3c19346008f8e452934a9245497bc933bd5dac1ceefe22dd146cf8c6cb0b7a9abe6af03386bbfe35f1b083474b6612fd4e7bf112d553dd395a5d2c9c5658bb6faf0db1987d4f96e065b642f3d0fc1dc426b7a9df55b0c220d959ae4f5cf621a34c24c85d45c0b23bb55d62dec34a0ad6c0f00326f280efa2dd6cbc97f423c42656dd2009481d32e67bb703d4b57eb0627b8fef2d71d1df4c220c9e0684a1278b8e086c9de58eae7178e280db2d787293a4f6e6292e278ef870272b7495901ccfc583e1c5659814e219bf83ca70a234366995728d82f171fbc3bcb8774e5687a30351bbb6301bfeea10aff29249e5efff41cfc8a7ffcb963fce5d148f17c7cea9b12d1a10aaa7a8e64daaf32cd2373929a5b7f1e64fc808a08d5a8112868de1c3d81b064092d08f7321adf2868eccd86c432c51f36b499900ae3962f2328a5f34e496ffe6b5298aa08ef022f02d19734a0aa579fecbb2ef2119fe215d5bcc6bd1b15e323157aa59a7cf60118fb2c0f0837b7f741e2846e4420ec6dccdf50828113c9004018c3523fd46c4e258287d6b07c3a126730b2595f20f0950f7363f785831f53f6d109fa8714a4803ff44b8eb0842a446e33249138f9828d2415ec0e56bc57b0b9cc89c49707df59107a46a897ae7578e089aba6f84a7a801fd5d32a8aa1f3f76859ae33ff8698fd2f9bf9df7075a72618dc18d60d53cebebd8b22abe8f76ade28b452f336c4db7e14adb4e183d9bf5f6a266c2e1008e2237f0dfe1844e1c20f5744fb6f91fce51813ef7f08db5de966e15582ade8640c846be8aad5c1193542dd8e68f1f5c704fb3328d5b0c3d8d47351136156f24d3d4c59b2420e694b8540dd593dee5c7c34382d09cbd2d371d006b6dfdf443d08c089d4db0a300e6eb343524cb1f51fada816118742ae03bccd2b33df03c659f7e336abe04d739f5236f7c75e4926e897c808296637fa9f893216e31deaa8052dbc246e93b58d90fe9afdfb224f10bb7852c91f5fac26f038ea0a1e142b26c9db028495471a3941a6807411037b3217eff19c3b3586b265721b8ce44551c8d5bf1fb5415c99c28804f9208ebc0572196728693b84c9e265df6d45b1f791dfe5c39b1989ab61a3039fb9b7863a5add945904e83c2d8891f25810cf8d53d7b23621aaac687bab1d21ded9720f8038226e1440873822a80c0dc8555ee8c60e090dd7f45a4581ee0c4d1168101537f0fe0c0f2bcf2dededcd583153bcd8a2944e88f51d6e14c7fa446b1a56c550bea8cee7d3eb7b220959e51ffca45f9fa3e5c1300a9eaa8e30ca7fdfbf659d87c690a873a2f53a06096ae108110ab41481238fb088658bd6a2e9b49787978ea79d0f5e4a9db9850bcb6a2cd42add55500be28c1f932a96c63265e2bb2214119754220b234259e708960e4a1d8ba7c5127028ccaa74d11b4fdc5e1b9f3e963e7490fecd541a3529260b92920ac28b882b1ea7ea81f9a223fe862524168202bed699fd8b52292d4e09327a0d03b491be8fba431fb6188e5fbf2c9005af7fe20d46e6c3b78e5de3ff250edfe18e5c3398f05773370f333b244f557fb68ad702c4ee1e8caa3ebfaade02690aa212ec94578037fdb2e0cfdb766a10683ba2cbf11625a74dab685e9aca1dbebf56c8d539d5a4125732877e9d89b11594367e60413922059e280ed46cf23d8b8d2e4c9079e7713255ab0e7c258261296f4e78ba8ce5e43922a91d0630fb3fabf1be39a467c1b718c7a321bf571de87ab1266999e827e4b83d9e91643705252615953ce51165bf2352ae2e63c64841cde662e147e7b57c80713d6b871be92bacca7ff3ee7ad835ce45d4ed7d361e06f0ef8fcfe43b1b1d6ff881ca12013b2613cc92d55451549e10bd314004da60dcb639049d786ce78bfff8759c754a5207f0163d45621ee114407d187d49fd719f57133d9c69f13e4119a03f71c296151f3675caa0ec52fce59d166d1efadab5cbd74dd5e6af31427ef0b73386d2492a17615e5be55973e61251939743178fddbc8ef2344c97307e9c01fc30912b793132f6c5b92d6dc80974f57c2cf1d40475ea9e17fc84e11b3b3d3574c1b04dc0341c377dec3ba23a25a37eae69e8079c203642117c16f2e7724644e9a3673c6a9d0e7d7fc05c6460337ff1998cf168002457268eca98ec00ef1cd596534ce0b365148bf245776e22831e70ab56e040edb97cc28a9386bb47b2ba7847766b1231c81d3de5b9551182b0348be5726e9e0341f5094a6c052f573dfb3cbfcbd82e0a3606e7eadb1c3988e22f253b25642fe8bcd57b5e4103b763af5092793071abf85d123a0d7462c7dda96068d238aa99da7f65c97bdac4d679ac256e708603e92e820002ce053ac5d49b75fa2fa6aa1b4666e3529ca42b70d113fb0cf140a8095ac3144c1ea7d64b9d46b31b896ae1aedd800f221d132b8eac2da247a67cef8179d7142a206c4cbefc4ad69bfc2e2e30b93c0049b88585dd42dbb25ce812a493d758140f5f7e5f33f38ccf271bf082396c99f1b1135518f49144e0ede070bdbf68f9167ff01b54baf02a02b96f95aaf61a86ce7448651b968a6ea01558e350e00a203c403b5bd124fc928aee12a0460c6e230ffee0aec41cd984c9c19308b6f105c30762f3952ae2dba791683307f96f197804853b9b3be46e463adbc4ac07d4ee8121f3c6ff8c3f1e331c120112ef2867397c05837410a789e8feab6087c48055a92ea0e2f9942f78896e7353e00db862fb7b71d51a60167782695d547fa742375e1feb51c4452bbe545573a87d7144019262a27f3befb80500d5ad69b8c38da54531f2bb2fb4bca0e48bd6c7a7cabb5751ae5f416604f8834c9e953cde90b747b1127ff14e1454585abfe162583916a86d754ce3ab2c21aeeb3e8e1891aea1861a1f270ed8dcfe2344ab0d331c6d2c8be27a8d5b0d948c609f22d3164f275097231e6aed6854a01cda781ffb68d850363ed9d840a5002848d7f80fd88aee469bf71842c23611cc57650d1c8d32663859ee9a4f21f79f10aba835f685b885c6bd6915d103e96bca87c06951ce76d6420820726ec85b9d10e91201f49c079d9247c63be7d0489ee2d8447a79749f1ee267e5ba331e97e58d9180567ea0e9d76ea6a605db2f306fe190f4c223cb135a7fef9a5534a87f43cccacf03d871decc82610008436eda57b68d5a7f92dcb357238391cf09c4d034148b039f43c55fa718b18804165fd6712c7541e06be5b4f3ef8b1ad332c402f6ccf41f6ea0c23b117dc8b21b0ee4044bb77105691c18fa2faf91380639ea39c532d2c9393b2804b37f4adc02c11a329feb55a5c12b7086e8bff52fc296bf71121b7ade66a74d46c82fb4fe333f8f3d9323ce1cfd0e8e1dfb1c86552a2129c1c81258f35ed73be81dd097450cdb7dc782fa980813508c010bb13452b7d179bcf5bc0bf910584e9dd4b8cb3602a7782a1432aa7a3d673e2af14b13079a89f76bfb980766015b3428a3f577e92a8858eb2c4319ba5300bc42cf919e87f9ff656edaaaf162defd5c556446288718877e7b2dda3aead94121b2e4ed5809e0dde092382f1eb1f3a88cb6102ccd373d0f8736910f1a768c7e9756cd17f572ddaf34e98447637b1356604d21b87e6c300aa9479d7b59198cbb9e209de6fdfa039f471ae5c25eb64cb345d1158341180ca6fdc9468c88d32657c00f40c0a8df5f8d57b2f32b3e8e20fbe8480cc6319b17a4b8d223757f7ffe413907bf69ca7570d81408278813e984813b0e49fb66cd205fea011e2d5b665d13d9649479138a3ee0d024a1d52bff217680c816c083c5293107d747635629dbb5a05e18a1bbd079c3a1af94e59c3e9552a51f607caae93458b269958d5a5331e3ddc9974d4d3c750a73b36ef18abdcec283d1a31a127a2d83a4689dd4e51d74bec3d5f68f0f9065d88269b5d54b38db8e3aa3e01db5942a6be3d215a048c3b0daf61ace606f40b62371cd01c03b16f2d8d19e2792d54806b9fcb4155a882e074a937231ff66a9f96df935b4edea819ab7df05f1dc11731466836cd9281355bd65ff313d98e81ce24e34e96ef1a586091f33182aaa759b21f83ef8c9123f30beb6e12fedaa4cf712e6161301ae42e7f46fa881bc20e86526b5735d6a53e4edd3d92a5a921944b5bdbc58dcf179702a7d84ffdcbc4fc95f2aeb95d65665723b54cf9864912dddcebbc6e770e4bff131afad42b7887660db0c44d3aabf31f2e4bfe590488fda325c5b383a9c702778b22f63664652ad2c7b21778b360d4839e4ef9933b88d3b0243bb66b0ff0052e66085b76a641bdf21e524b5c6c26eff216c3470cbd22c92058a2bd8930bee16ca4cd81136273ce6285a35a78bc36a5485674d7ebb21a1f7529c9ea326af9278cdc5c36094d11cf5984b2bdc9a5352e48490ed9e26c792d8f53cd205dd5c0eeef9c27215947ba300034531248f49974ba2fdfcbd039c356c36cdc8cafecac96947df79ca1d3a48c31bbe19eb4463a3e1ad4976d2ae8a73f620342b3f9b405bf8408970b67e597a6ba32d3b0d17ccfc2ea1920d8cd028714506a4206fe05088a35a32779c32aab7e29d360539e0f5481134a7cc796206241e6b379e4aad681cc6cd054879a858e22cc9302bfe831c855d345de3c4770199e6e3693b2aa7cf0a22c41e859192aec513e9cc37cc9359d138fd1bebbdec969176167ead214e35c0e1143ba7502ca88337f9751590bae38970766c0d618211c48431d015fbb908fcf60f585506db7537f45d7f03c67b271f6c30ba23f6f869743334b0bab9d29acedd1f28e6f7adec95a0f58d243e92db1f960bcb8b69fc7c244af80a4346f381f45a3ed03a4523727e75899f2e2e5b1a296286bb4aef198951583a02184ab120e0f571955eb8e5ab36006db10cb3cc36ce5aa8095c1cf8e01c6073e59a8cd36e22f7dbed82815f83db4825ca0c030822b356a8b2bf9a987a2f74bf632c3ebfa35e83a3569b4bedf5d220738f255e2a5c8f3ffa259d4abd890f942d6b17498ecde59591734a24a01abc3024ba0e34963ce3d1c8b4ec6ba26620079b3b038bc46587653e913ee346cf786db0d30d93d9dd5d9ea8d04d56493475c571dbf3245443b64b02f3b096fd53a2b4c8b70d07e9cedf4b84608316f841dc14e510572b59579f332a7d13e028df96cb0f5f1c10584a1db75d343211c5a82a84d0100ebe3af1699456506e9cdec8acd5340324fd3c366aed100c6028268ee2c25bb2ddb046a3505a1b627213db7e60314e7c15fdf90c68470bc99b068495da3adf47c060f87729eef0ee44375b0fc9d227802eaef2111efe93ae58df34d9fbccabe1de653f411b0e2b0011ce832ba505b99c395313be7a0c621dd573aa47cfa90d7274fb1ba08e995ee1f487d66db232cb1e1e0ecc8d432ab021f0251bc9630d572e0ec3cb59764053c9a4ad4544f1a2940b3dbab57e57e2b1ddde5105c7ef5b4b18be087f4c5f1c0b1aa89c53534f9d5e532f6fc025587c41541e4d9b3c173385069e9ccd289c2ff616840ad4eec8c70f713765318da917e4bdf0cc150abd0f60bf12aa6a28b310094715dbfe37938ff8353f5b3175839d1569a1fe18af9599ff212235c7a79e1e5835e626443b142e14371e042ac5f96e9b1cf0947bb22d0112400c55b46dd10dfb1c40f77409762ecf983e31d948624f8cde485b57c07f330d314b8cc1add074cd921d5de69378ac3748127a88b5732a2e5318bbadb070b0f27a7bd5e06dcd233cccfb3452e7dc320e321c795dfdfbbae08d6c31126ac2f4be0f0985246986e2198ee19a9cd414492ea3340804e03ecee3147849ec94134fed5884da85c44ea75b1a5a5703944f4a4057123d46aa9687ce4938d863417577a784cbeeeaca197a16017a332261f912622d00a6b4c107571c80fa2d5216f2bb6f1e2c916d382eb9c272ab4acd078321c98f364d6d0d36bc63e84b1a8256b06963232d9fb734fb7fce4e0e21489299c645a0128de3d23c258c0dd04e823a47c5fff5ad02865e15c95d7748fd4c9b747ec0f6163e44ca8df5be2da44bf760d438ebde658fbaf38e1c46766f36a9b3954f3a0c2e38e644195e0b7e4c94c76169a2d1cffed4094fb46ba52729ca4f4bf945c35e2b331508eb72685968e422b106ddbf2ac06975a742aff04fed5d77162a74c7bb1c23f57886ede9da9605669d276e6c05a40c0b891030fdccbcd090f5864ea2913644e35500dceece697758e3132f29ea6ab0bebcdd7836b67dff13582e569bd01d7039ada513ec9966d6b8b376478b52ead8219ced31c204e1e3a1d2fa406953013c74ec3a892f0a86abc665eccb0187d2ccc8b7c13fa960bd4b365def6d16671468b4a5d2d9635e29746f759cc825f1d4659f5a8876ea1a38a108f5e955074815c1e13703999a2e66157c4f0ee8f6b1800477c6d003040ec3208afc090d7c902a305beaa80b69767aaac27c034caf244e10c5450b94c0177f1880f2292f1f521f673d7c253dc9b9711248ae7de38a83896720af496db8c4256aed80248525041e8c474d451f39afbd5d71d93bc7d4ba3b37e2e9776600ee27af45aa0ad360772ddbc6282f1b5c68ab1046d313aca1cc81897e0d783288f0f606814f0d823b4b0a8f80bfe549dc2ed952405394f9c41d1940066d99467a3131a308fab39b08ea2294b7fad462b460ebdadd2176520f3379c54c16285a39335cf8cca53ab8c07e2421b8c8523400e891034ca067bba91a0ec2bb7102f2ce183598557fb39b98d60bf2b1c909c2958854408daca3776a904e3397cf3c074bcecc5c386c7db303d53fec96f4184fd5dac5a2e7f09b3622d01797206d1c6216fae91e9499f45654a4049152b5a49375dfe1fdde3a585bb87b63f43673bb2063552675ccce8aeb5d2d04d2cd4e867c24f38ddd302f51da22391f7ea10699f11b73b458e1e3c013aad92a10b87fa7e8de8542217d4f338c5534ecf34922d6c0ea2d3c403f44b7d35b102e1639f0aac428e686b1d7ad048b419f98151467b66d812b6b1384b26ecce4861836cf71f0a42d757a9f59f1878e8c6ffa34a655b8fcc046ba43ea070acd440c391d5c69390efd4cee37ada43ce61b8d556f1afb39620f050540e49cff5c38c50260ff74241ab13dc9fe4af5b9f4c4c0cf64413d39525cf91a30d53f66595a752c286371a843f6b809af4cca99103a3730e4e2a8c8d46a30c16abd25d5b4a9f017acce948c1bc9094723c04cf40bbf9fa7bafe08a1b35895acfc6ba14792cad72935ea2e03abfb955a0a0485a498ddc8e0fea20625e495179c5c1bd907d84c0f223242c90ceef6150e7deed18ed31bde7b67fdea0badcc1497f807ef9054e2d31424f1da569dadbe750cb907647f091197266473a5d01a5004c03e362606e82d182da4de87a79d8edda308468563717a944ffd1cc85012603ed10cb836fbd3983805fbf8373057d6aa394891273ac1a6f042789d0e327c975911bffc4fa17ac726b24a8c0e7c19aaa8852cf496a83f9fe6935dc6cbb72b3b4cd252150f742e7e2f393c1986ab4bdc0dd9b51c77c311d5944d17a2985b8df7120b674e248e34950a402b33780bbb3b529e3626279d21e6204bffb058124402c7ebf4f7b4eaf2af045c4692e708cb1c5e8d9b34b314f75d0050a5d76661f06b39c3064c160568c0139eda2c57b08f4b07bd06a8837427ce720ed5e5804a534af1b153f9696f7f8603c03d2cb4662ca1eb8efd5db16903ced92c2e2982aef0153f831e927a2bf36520da7a227eded42cd348d909eb3eaf640a651315d77680148100b7a79462071f0d5e90ebc59945df3910193582d7b65c582c3f3fe249d5bc25658a66cdee9b0c0bb81f3ae9fb6400288d622d506a3daa13e32cad3e116ab13eb7e5b8773813a32769d727fb4b942435b1a5d0be383334a5f2243e5514056e99d4f1ccf5f3b5321da2154592010d182c2998d2c89e11900a9dc49a7698da8066a5e07307a501413ffb586d5947d1656306304b84eab4c080136bdffdd0d8ad4d3bc4d9bfd36bb11fef85930750f7385344b849ca0efacb43c8f1b9ded85511154643141520544b304dfe519df55b81df5b63354c497e0c116ad320a380359c348c5c6fbd362e5812e501093fbd73baebd326a69724acfcb1f721f2f5ff21e7225f5e1de8628d5236de430b2312d4e5e9575d1e2956fe5b2825b65b0183f957c6873b6c4c35c5b21099b5cd7c6426140f6bb44926e3b3f3c0cd562c2729de78a2b084b3a47cf3a03aeb156650940d86486466e00df17bd2f9f0ed407e6a09dadee61f4677479ff73e823aa7f7e239cdae2a5ac09879c53e7bbc3a0abfb198227c1a08f656fb42c32290308e8c645131335b07ee9bfb310aca051306cfc925c0727bf65fd19df64205d7914c72c8e9cdf01309448e41713e91abb70aaa678a9cbc589e2771e67b9911144d6e08b282f71ce2090e4354c04bbe95c4c05f1f6b3a57911e65821f7603287c50b61ad71be9213b060162d4c3bf3cba2c7e2f13f43eb3fb72be9f15ed1028c4a50b67188433c68500738e71411821deae58dee3670292c19e41cb3256ca32b3213b62e30d2204ff14395515b500e135d1bc602c5df725fe0f27d426170c3846eda03ee057c1b75020b266c6da18c3fd5b4f158a3f1aed2c9b4028fa548c1815cb7d097131acbc6bd027903d2695924abddcc3adb6cb62b9f25fb5e946360aa87188ff0a98888eb4db4bf2d098b4e03174b19c5a2d0819ea01d953086a5b1f7ed9658ebafe48344fc9f239bf90343cb2a3c1fc7a73d666699d4672e04e3a2448f4c51c235174654b1ff324ba051e6050f50fd6d75c4971a3f7115466f2dc1f065a1ff41dd5d9e931594550597e579130544153efccc16017c2d8a186900e3aaabd5a8a5a164c182d29c95682cc962dc928e3f260c108110ca817e27e52633f54dc8b13a30ae34f6503fcd5f08cf388aee3b3f716192a31e5e7e8caa7bbab0bdc4f6aaeef4a72b02b95b231fa466631c86f3d2a888733707b75e40b8dc1e20b01b90f5296e49fcc280491f1ac90373a3d53640cc4096a7d67775fe106b7c9353fa235a179587a24d2512b0d30f60731adfeac2d741b06400574a2baec082f087e5e3e0f345e169e04efb0649dc7058566a27ab0a0f0d17cb21e71749a42e527b743f41f6b24c88335764ccc9071248c633a687dc2903c29c0cbefa8071ba6082f9cc3f619c712f94b60d11eee9294e90fed6def0a76f731fe8ad3eacbb9db383d66988867ad9cfb01b07751e29fdaf9541a1739e15cf937ac4b10fecf75e339f961efe786b64fb3041994c1d016683dd8aa8980072addcb7e1a2a2badca922c3a47680ea9efae88de3a6e7dcedb9a82bebaa0c22ded131378a68bafc33885200714f5e31a560ed36d23407106dbfa9fc8df2c4592a824f166d3cc491f670208e31e6178e3d7d4032e90a102c3de1ec59d324edf1894b9dda4579751305d883f0cfa964c2d445908cec9800cf6f40ea4e8b391cea1495de774e1de06e826be01f0d528944d6d9a5d94132e20445071c8b6434cf3d4d1bc8d78d028c386378e2d9b5faf527b10453c155b17ce18c68f4fdea503ffc690f0e9c8d888535e39d0138bf71a4233f44c03582da3630fef6bc8365c856a3d20b1d0af2df1057bbc6f2edfbd6be83fb39f0782d689e21318ea08c7893c20cd057b0248a13f40f1eccb3b925fb293b56c7c1a8fa8e7906a00495f04a9f3aeb1cc72986456e7715c68d32a91c6034c34ccc503712c4d9064e6dadb1d9dfa6f2136e403e2e27cc701f2422f0deaae672e947451c987f44332ef90f8ee03a24cc6df3e7cdd62f68baff6f43706b1c2d34cfe7bacf3eb220194ba58edbdb697c4bbf00f926968f4fd2f5b7b0cf80904fb48313318877043f277b8a9bebb1d9bfa61ffb92720305f9d76c1833840ddbc27e1f79a2db115198e97691fd6f05bba40ec97986fb46b47a4b2951e1c79d94209ea2a426bbc1bd067be6166ce99a5ed969880a596f204928ea94d492177393defd88340676d86d20ae43692310ff3300ccdd4be9abb60649a1874402b41e7c152cef204fdb94cc26b177d00c283ff28326f40c8f1feb3df94dbe03d371009e0754027fd008baf11f34956e09344c15ea05e2d40fc530c8f3db4ef171279b7aaca10005fb13b85460e2ff69632757e39fa425a15743903a20aab9c8522cfa0a759fd26740811696fcd20835ab9a0e169f9f08df4520b494225111c12163348e3cb177f7ad285ecee8ac617d3afa00b0ae1ceef0a4aaa9d3a741f133c3b881b23ae5593085bd3cf5eb77d831407641809bce741a020f2c0acc6565c98289123258e5dc5e361c22ab8a198219fdfa5cb31de8196d864e62f0b602919b6173ea580369a4860248ce45de98bcff0aa8ca177f96816946baeecc02da392c811eb7760a5aee403b48c3873b4ed13acd0d0e4fa735e37f6aa936c4200ffd98d3146dd696a85fe008b209b4a157c334908edee162ad809c287e6228d0858a2f4382df82e7b7c4c4aef2af475a8d328a1e79f9f8229d00b4f436179ed97cc14633f63c70c821b3b5b7537cf8a0266029985bb48e74528d5e2a6296182f0cabd5339859f8f4771b458e377c78b148303b4513c93c7d2a02313d56b80fd155d159521f52d8ec223008760df6cd7df507484deab964bf714a44c1340107bcbcf103636b9b6544640ff4971eb4f0f85e572571033c1d04238d5b3c9e43adef9adf3131a92075ca5388ad9068f3df58ee86c7c2085013d28aacd04aa856729335e01de3339e363c99d766377b16623f450473c1655ca5c04840cec5f8b9149963e8fc8252ef13615153ce0ccc6f2157df54a8eee369a42633573be8d49a937968db0902d1b746979218e90132b14ee19383dd993db77e20a08a2f3dec2123638a4ef8e1083403a2aca3b1830611db2f125606c438426dafcbccfdfd54a1d186c1d4bad2af45077827079f494f4bf4ada127922199822dcff51ce07db43d2534174cc073cd9a78ac41752dd895bb6b25b89c1f0e8b7a888ddf34cb12fb4f1027328ae3128d20ce887693323e64d780f0517e2d77201aa7537509ff27a3b7b0e821522581986e9e6e06dd2e999eff663516a608bdbe033083453c5a76f5be48b5b1d45b33ee985b96dcecc5613d9e775ad28eaab5077a05388feb167400d077e50347cc407ae92170e450419f10d72c1b1e912c686407eac1a2ee70397c1b3b310dae8b924293d181d266073bdb07d2674a1fb138491d7a2f6d0defe5e644ae36533ac1c32e51d9fe0fcc903d35e471d208afb18d395b69abe6920a2fc6e4ac1643b67c920191f294319e536e22648056ad14f7d9064ad034e7ab9b7b1357c2ce2b968a70943900b4357e24627c5f932d08ca7058a933daeac3a9d2e8610827d553f1ed32558beb2ac620fa8ef3b95e6e9047c21ac8925ab9d438d9082283115c0127c9a3e45a57c6ac2db0d2ffeeda43aca9bccdde0d6bca67e2461beaea2a9e3e0acaa0fcefc5a12dac1aebafc60ada43acf7f4a3913f710f85470d2b68ddefa0e64ba3606515f9951634604b20da2b5160a3e562abd8594f0bbd252292d4d2a50604c19c7b4c3e19816bf971d62d387ec99be3eaa1b194a6dfc70019dcae08758029b2e08c9b5b89e39b927e8394d83430e6aee7038378e1f709e0f8f7e0f1ae501983f18161ede6330364c34695bfcde0c5c4b271f60e2bc3e717380f6855603817923e44d081ffbf4bb14608ba68fc3988e81815a18f792d5b0a94c2afdc5db6da7065b9aa5627ac98a222da7068373f4d512d7d37c20679ebd9e1120b44937531c10050e998a4ba8f1814e0e2aed00e7c33242146dd1414bbd94ebdc13977ad5e114bf293b404ae103de968ac79af561434cf02f3a03e0e8f9d0462dd0fd25dd613bdcb2db3f4f972838c3996ad94b52b31ab107c8db4755403ee4c608165447a9344c8e75f12d7bbf7dedac8d9fec65e705b7fb051c65788b90b87da946c2239727fc2ff9bf9f31f9aaed69837b0407f93ae7baaadff499b0356675b9cb1fe36e306b3ed539b93a8a52970a53294d5ebe0c411a7161fc09d9201bf2da0ad0e49b310f56de2f969e26851d7bb23d6effd153beed815ea5e3a468a02785646062ae14f2a7cf91a2274f2a05ea51bd0b16c4aeb161c2c8c436dfcd7a7b5eb58f8cf83f6da50d22b9bdea8badb5517c788461d98683e58645d0edef2847b39a115c6a1cf70490c758ceec5ba063ef37e771b99cb05f01c595c7c32d2fc8f3a1387a4621196085f400cc0c83b08af63505b52848ef5676c067b3289fde56dbc2db200d190df0f0ad6a791b6119ee58565cf24c7bae0f6a4447f14a89a5f1d4cce9397d29ecf2760bf25d104e6b8c010e5bae09bc3f7ac974de25ceaa9c43a0a17f0c9a0a3b01806b83eac1c2705e64047ff81b58af222edd00d92444db8ddb8bd261930712139ee62da22ce7b8ea7d2bb639cad17f7af13ce7e60561dfdc668bd80ccc0b4b04b3c584634e4be75335bb1de68cfb88f06b70d235c2d1d5b0b99e9738261860a99f60eadaa747af94d464010adadd202f396d09de55b56a816489969af211539f14c2a235fc9e97a752726757b5a0c2baf7acd3390ae8c4a4f8905717ff0dcdcec9a5956887fa13d72fa02fe13a121dc4f4294b04a3a501aae2ce31e07600c7de40f2d1b109e877b5339cb2657f6dce7a1c9542a7df36586a4f61e1c6a6331915656a88a8cbdf1ec86d52816877c2b7927584a8bd7ad9d571cc638cba330f8fbbe1d6b2a927a8ba751d5679c43b30f3a57238c88d0c6f9be8fa8a641d3935551d9cae11b4fade23f5d1706a37cde4edee26181540d06d93deb520df04bc06b6b08e70c012719c5cd2af7402c4a5c3301069b0539b610c598316045aefc42320329397dfcea21c31211ef82f4f654f6f43ab79fcf08f5cc3fd69b28cd8343e4f284a55bd788701d7cacdb8e3e546cfe918e6e6ad4b3390197d15101efb992ca9d51c6b63f95781ee35390925a4036c88e7bfe5199d2d9f7e48318876f84908e75371236e7515d5f8470c6cac68df26c943fd7240bc85a60f5c2153b0880618527f8105f846d8a48312482766da3cce2fb435162a2909e726ef2d5f5cddcb0bbe8fda1a190a6b0168ddcb4515f38b203574846aa346a0d934d06e5ed55f7119c973a2bddd98ea352cebd382b793f75226ee051313f5278d2e4c509788446a3ae97fb638665c85fbd00cb66a361d3b002ec050d5a48358521298365a5a269d363df29cc4e1dea389261580ec6d92a7068502447eb8a8bada6147ec7fe1f4aa37e8da70779cef8fa4fa5714d711608e94e327b0a2642e6e9c0d340d232e818d07ea4a1b224c9f50e01fd6edec505ee759c2f25b52e2c81547aeaa2a5560447f28fc984d70b0f5c457a323e24d5017950577c80a870276ea9e6aecc0632b4ccf0dbf6620d3c7e09218945214f2e8eec90f82fa9a87b209f529c623dc5b73b1a01a75becf5361e7e756cf6a49b2a5a2fa8c6237627ca6a3d17c7b5c72e372302d035023ad5fcbb6e814d2f0112283796fae54d43abd4e9a83ef33df51f1f6847d3321c80aea374bf3170b51bc89a216ed9108446aa601e145e6e4e6869fa9e71e1407d2babff70c7087b1b7e445ca946c09897ce9020ee9e7eef5a13e6012c99003cae778f392be506ea702a23b0e28efba0284ab1a7848b5d88ee03eab18a75926a139c88cd028666e29e3e8a519c99f79f1f0b9f1af86d582a8635ff58f664b20b6f2d9ccabfb89207a6783ad23d921a7d794c1e05369da80b9acd4a4e2e0e531df9d9549204dda8dc902a66789d139c4d6cd4388ec0058ef2c5ec19759a3ae01df5cec68ef17f4cb1c64cf55aab2335a857d164049a7196308c8762c3e2efc2d0557c971ed1cb0fc0073e3fcf9a60efd7ba7ad0fa1ddc6dc111898087af5dc12020bb947eda002f3c7ce7130ee967ed04df65ad9646e10f09c85ae0a33c905235e781d56c24c946ad5c0be50ef1a94feab645139919d75dd7970550e4656ae2e9f54364961f2bfabf9b6fb9561e7924ce623fac261258e97aa5ffb1d52c41f20b460c4284dfc4d39b12375f93c0428b3ebdde4981f50b6df4729f0af59012e225b6b9d3020397e4b4b708ceb6bcc1202bebb935db0a5ded91c3c7702cd44272b1d175ba7e9c18b7a1d47cec61e0b7f46cb65b9cf183c22d9911981f4cc57171dbe32d2f6b486c62484fc706d31684594b3daeb95b0a707a866c6d7d0c1e2f106e12d04ba945b674515b4c3ae9d4ea2bafaefbe97eb2a6cadda3212c6ea33113d27f1bfea8833a4ec1c45620656cc956d40683ddaea8bee536889b6e93561b62237e91fb2dc7b4bfc1cfb64f0049d300075bf92f72ea3e156c801132ec43928015044aacc0a30af6c2000d7607ad7e65172050a845982f8d7f9475ca9f785831c3251c01567ba4c133f1e75f50d6d4c44f9717cc40e413de6e63144cc0b2d0211af73fcd31cdc891a39905b646149c2dbebc1226bdb7610edf79491e1e2a6aa1ad6ce977e6ff60db2a2c7eca01532c602fee8dba01a843b5bc2ba6666f03af21920eed8ce9d9458cfa89f577404d8fa9a9e0085b21cf2ef0746edc8ed3275493961dddf0d45d9367e2ef87c28cab6b806c6c18c6d77d387f00bb25d592797e43fa4b146102015c420d00ae74606e97048b92a8977d0876a8a328f58f5454f3235dc5efc549374aa299cc029dbc1999ca665ec2361e226b380cab7f09449c7613948014c20cf09abf8ee50a6a0380adf24cb23e4b87e3dbd3c23e989b8eb1b522ca60322873e148264f35caf9fd1298f1177b5be5ea9fc660ac0dce1303f9655239682ddf7878b7c60e15231ed09f316798c0eeff5d11afa03ec7ae8af00dc151f1229c0f73a5cb471e94b4e46a54dacae3654fcf146d3d3734d0725a04f81a118eb9bb6e2e54b163d7d3073495bea73b1b138425e9f5d528869dffee4707cd10b4700b566ad92df233bd9aeaa459de85e0fa13dc99bc2eefc6caec3de2f57113776b7427bccf8722522778b37b0f7dbf41cb47626a8d6c3c8a7f890a35d2e052f7a7c90a384e363dca66523e976c7c6c7393f1594606f8d52ab1729700ad7253fe8f48f5373a3c57a5ad5f0779de43d34caed0a702604450c595de9d98ae5ca034d9a8fb840cfa4a9da966fde5ed839b37048cc91ae3086bb12b530f3dc54962d48404107b15a4a95445d6366460df2962a1872a7260e95a17a54d01445b69e02139a3997332e08f6defcda2e2e3b1d096485863ab583210624df0bef13b086189ed86fec9139e237d45511bf58c8221f727aa38352c09c3c157ffe7bd5b06202a4b515366ce5c97da5a8d4a9909372feff059b23cf41e62fa0a5331edcf591206845ef98b1e858b2ce6badee2c075b8b7e01dabfcceba961d6562aeafbe8ea3e6a370eecf28dd6fbbd1869078850f5bb09c24fb1c5f9a0157774f23dd5fee20d3c788acb0bda84c9e5c8f35e5a11528f1937f95e131951e3358cd409eec95d13fb2ded55f9a6f6fd4f06898c6f2500c04500e33e4c724b750d93e230d0b3cc251c521eab73e8c04e7a5dd16416f508d391c78f1007a3609dd477b34aa5af441cb9ce71f31e40e49d885b47ceed3099f5108ec9067cad3929ab1dcd2b28754c16d196d5e2d8804734fba86644eef04a50ebc149c8e0d0a0bb4e741502a53b3715e309398770bb697183e48521f15c08b7f9c0b765df0a480d05d143e2eb67031f89f76379f48a568cc0e493462451cead77a8d3e683a6f11402a4d751aa8a4125539c095d175285a9e6ee8d79949e2904546b589764a45890804bc91c099c0c362e994d658c60b32116d702eb5de3a5ebf2f6f3a181748100650ee0c6ea919531a965a1de89aa1f322469a1282b3b917e9b4ee98f5281863235df9d6bf41faa1bc5d45a164b92323bbfb4713b3970b9a4333ef8400fe381522bd6e4bec06b0419560255e4655222a59dd5427472ab42fbd8d0964b69f85a3efc63be9ffdeb0401c32bc4b7d440baf4e88f5cf9db164b932b8032b6b0148fa2fdcb0e19db489836ce75bef2dff284ff3f3bab968fc1181969051dd1c9842c9919b09d1710e9c41c939b6cf141d6b4d1ecd1ae348286e1408168c6ed9d3db5878435d9b1f3df3208a28e81ff5c5469ca72578a65925b010d0d9b277caed8e0856ec69e12f75df913073dd244ba85e6f3e4b82cd111d01591d03c54db9104deabbcf4a5acc159c005ff654d1ef39bb384882412a0b211f57f13765eb0b13535afed81345c441f332471b1218d46ba810f8d69a260919bd9f80d0c08ea91640809caca5b85fa71a61f0b617944649f3fecb012f043ba5e0f6f2ee93f824e3b75033fb5a9c5e8d4682d79faeca81d5bac003db9d3653579c73a725a8337217cb45035cb15ae0aaaec271378e9e376f385f90f4104f601e68d05bd90e03793ec0c99e5c93f40d9936e19b1a4380ee00eb9eedac500a987142f7dfb83a7594d31e254162e2919f012770d1a7b7e5e7474ccf9b03583023ff7cc6c6d75ea036ddcb7e144f91c4f9778a0346fc705368460c6647b97c8314223a8f572231430a00b801b76810b31dd62a53d17bbfd3a9fcf16bdca75fbf8173f0c6b09cc94b1c7d52c3031102f7d5d997c3f2ee9ca9db8e3541505ff409df4667bc2c651246e69781f5eebacb874b9e7fe14da0c18f986a49a3257b56485c5bf7384d34af7cf372dd60c6f8fa4abf044e8174343666ecf809cecffc2a1263d26a1347cba40ffcec503e717121be0e53774177382d57aff7335e5565608deb6dffd02b01fb35a15759ea669da22ffee8c782292a31b2d5ebf917d363e91ac6cde2d73b63a0e4301599b11bfdb527062d56d00b41c1efb8cffa891a30562e1414a69970e12025d9489d4f791ac4691d8586101513916a4dae789b575a2ff11f7e366540556661073bfa5b0da24538930edb60c00ec2b34f59bf8b12cf16d6544940e5dca27d57fa70698c2a9c7bc5bc60d97321fdf2c05cfbb48c070f3987f946eb11c8a9d0ec56da0dec7c8e5d7a06406e2102e610fa3feccb5b21e80bf42f5a0a0e79683b7d46ee97cb2795383426963001c57253a3ac383ddd7e4ca6836dc4f56e12d14b749f357bc99f7638b77ccf8af0595d9fc8bca412ed7fee4c3ba67fa3ebf96e29d840d659cf7777268d580d9613b8b5a52ac415af2463151b25712d8e1a07ca74130a8b3592cd5c7b862d8fac701ac63153120a46e39cc90e07d289a65323b5f9d355876fd7f2c975c06e79df73d6a5baeaadd493e0932c8ce6387188fe4c3ca7b0399e7078fd80d06b20b47cb0179a130de1d35211d080d9ee1cafd807043a68fab0cf6514f457f91008164a524b224af42df92858c9c38be710c836c3d40019172f958402d62f54c9afd961d21fccc132af56d8eff5db4ed9bb55ac4644f1486a12baa43590ee07403bab47c0c943059baaa37fa67b3f220ea72768fb76585866c4ca0ed19212f8ac939ede4086ccc4998380e71ea0a46555f848e56a6881070df50b658457a8b4d508ec58e0bef4ece3af2da37b977569160d9f14bf579d656ac55289d1a76d3beae1b14043d98645fb5d5da24c56009814a32b809662807c5997ffaddff67bf2236e4f9462f9a42f5a6f5118fb8674c6d2b104f01251982d3bfec24315f500278fd9126800b60d1fee6dc68a0ad813b71368d0a1d026d0faa397349a00ed920b7a69d27d63a71bdb9f2d314f1d5e31b46352125b05c91a52536d5b8757a6ec567474c65a327aaa31c5a3995b6d007de1f3b933cc78f3db2b136ed5016137a87fec80089f12a5d59ce79e4adcd39819d8701d27f0c39972e10badee30ba88666fba8ce7488233942d091d8f90607aaab5111ddb7ff140b5452ad77eae71c3fa01f927dbfd92acf112310ee4d39ba90cb49343d0cd69f535d050d00bf3199d678ced022ef1416008bf886ca5385d4f19452a1f55688e301d5925ef10595bfbfd83fe61c62341d78334521c2dafd75222a3cf27caab39ca8684eaf6ba96213d0006052136ffe20c0396596e5ad4f8af11080db1be0da2a95346d0d078b472b23337af80d9d09034c833871aec3dc7d12dbbd527b367b26a325c1b0af2a62e0db3827d097b4d926c98afa4a06ab74dcd98542aaa84d21522391df97e2abd2d31a6489c8053e2b16a646860989d4866882c9242e76854940a8f8e3dd74bc9de2e5a0fb1a2c25d805042c7f9713c3f0605ed7fd7450276bbe32850ff4bc0979672763f14d9e74783f30f9f0425536b2529f31bf45d2f489816869b633fb6c90b8a7af84317c347e23268b4b91cdaf2e9e20470b14deda943e786b15bbfa95d46517f5877999a3d50f40c50538202468107491e4ac10431e27f7879a2aef36564ef31bf5080365190b5904ee275f3dc7040dd6ae45586b0df7911b0de3e2df893c470d53a14cc13b33aa01ef07c754ce6589fdd6c36f1817cd65ccfe38adaf1fb0b509a87e2eb9200406d81e9f70a71633e53d2375d05cccbfb63292b525cdd7f4bca9815c2110f919311f8db2b1b34dfa6c89a5bbb9353ff3f6559758457eed19d660d46309701f167e3d31cc8ddf3cd3ad42b7aae4772903e92aa0432ca5c629bad3af5deea9d70d30be52568b6258b0d21dcd23d842cbbd1bbc54f0edc91c3f82ef49db15dc5724bcf5ce43df4d42c72707e28f37f6d995bb565daceec8136e0765410211e8e1260edfcdd1f4b2b2cd068308e61e8f54696708ca20c4fa2c461427bbb02a08841c1bd0703e760dd21747dc85bcebd40ed6c658750200c494bb5da0be8ebca75d09a45a0246d461e057beb8bd4f53996e28815013ad3fec082daf379f916ca15423e90a171037d2f8125088bb8b3df4de697c1e0f5a6a45680210bbd0f3b813ab1eab75024ea4dd6087a20e2f3b821fc701cbca57b161c148afcc7e4d2138c30521756a53b8a46d1a4dec664eca057a7386887775190bd61340abc2c4c6cf3d5b0fe43f520da03ab6f60a4a881fac9467ea903d5f86f594cc0cd421759e126a5a27d60c996f3e69b6b7e5886102a8a08e28d2490500448859a6e73d067cf794c31541fef13259304ad4efa82e32d1400dc82e19a0bd2e416ce2f85c0fb2c7758b0dffbea8430c57dc2542f4ffae382451b81507da516dbb8727b502edc20ab4ff14780392333aed15dbd525fca3804668e4e8ea21d5c1de88feb23b6c4b1e8c8204c431771d91027240399b68381a17d6f2471231ae65f1e3ae08823112ba151c12bd8acbd2e45e790644f71b24309cfdb2f4030d756db385fe13b53fd3941236244b2b12dde89003fbfd02ce6056bdfdc72ae97f5584141486811b9d5d85334b0168bc9993e40a93441196c50baebdfa02a67c56a2129afc29e0cff3d89bb592114f7b3fc1f99f3f1edd0be921bfea1ec51092f112fec2f61a17ea45d79358dd28e057511260088f5ecb6abf6c78478de254d5675276074bdb3b80d1e2b2659b3e38c7f6e8da49205256ed6ca7c085aa4c631aca818449edcb3d6b5dfc0ca0d30ebccec0f0ea54a42c56f365492b742b16d28659554e08f6cb91608970562cea21ff3f9543a14334f152055d10a7e8f4257154a8eb11948310fa041f92a1a1b82a9ab2067e5332b9088f790c48b66b571b8c56228a0836804a5b3356f6f7e9f60e28f102a452fd04418c3115f901e43fdad0d6f25203213abb607040c5cabcc7048c0c6298bb9df5da4736f001558fea391f306c5756b83522a480ab642116012e0972b298e9e32b2477501c2ab5b7aa8680b60917705b96d4e35ea9e6f493b816200f7d75a0cb056cabab757686c3f35842d9a9295438ad2123baddd68f2aa538e8cd0b23417d5c21fd40f8d3bcca3bc2921345c8a6af9a46f07a39ed5f6f792888cc44753243adc64511f22fe53563588bfe0c6bd3fbe6983373a2fd9547302dbdb2077689bdfd50f48d33cf478ae766ae92b80cc9b4abc458634d92c7d8b4208922089c4711bc9fb04b886a156e61b32a8ee61ac78281438a85d1ae4d7ad030513f06773913aa6a1548b927968d8d1c72871962225ca417552363375139fd11e5aa918cfe24bb0c98d87abdc1d1c6dc1e67d655c23c47dc7a0f4d1c4140031fca8ed8740c13254e0497547ab52048dbc518c3c8474281a6442f55ff7f5498167afbc7744390181611f21880d358a37cd92099a46fd631eac43eacacee1a7709370b8aec1fe7224a62052ad3a05ed60ae411e93970d17809d3523ad2b2ca001f99af6c9302ebb957ea3280836a53a98f795a2ca0323c95c8b6cc7455fea53822430b89596fc782051dcabfe1cade5007c758d54dcb2a5a1318657bdeb8f36228a2a831b2cb06e0e4f063f575e9c3af913766270a825bdd4cbc6ef2aa7b79771d3cc6350ad06f98e5b4f073346b6d85fa51eef6b35e50f6127d5557421af539355882274c067065d78ea6d505dabfff95c84533a6bb1aed3f8946330ce5b2d039e65cf38c5bb7b414b2c4e954739bceee7f5639d5c8f7b67ce66d8cdb87cf2c3d9162b75ca18e11c772886b9fc7aa7e5bada8bad284035c34c55a5e58a209663706d621595031914e0b0331342c643fa328183a95168f121dff3e85d57627bd129e4da484c166ad5614b30f70b4fc6dfc00cee9510be1a2272de97dccce85d236e58b10f5eada9333bc3b84a1f1d93a59b1d405a7954801cc23f87a9e562a210dc58cd01f1c2ed6fac43eecc103006bc995e5419ce87e0826335b5ea7d48a96352d556cf4b2bb5f2da5e884ea29aa8669f5ea3cbc0d04bef4edf3dd4ddbf865269ea3a2d80abf32e78553a8aa14d524feea626d42c425bcd2eb3dd4224385443807899c2ec6f74e6d6892287adc492a6bd4ebaee81fe07db0f85da0f3ec81673ca7507ae8000bd67f98be02433c78af2b055fae8f316c8829a5bf16acbce79f18d207e73c9f20da3435c69f296610f64126a5acc6fa6c3e84211d948cbd73b72845ba46585a9483e1725ac6da47f459160972c15a94f8dca342cc9a4299664c2e016921764b02aebf6f218e1b80ef35d7a7b4f41b511b79d2b02c94b42014ef06a4a95cdfdfa16401fff19b7621d2fb042739cdf54219583aedc59954e2abf302b54127b280da64a5547476d5e57480e7f73187fd8aa70d4691a888f74d63fe0bceb2de67ef9ffed976e45a5ae8dcd6ef7a84df985b71ed5770ce614992dde7291dba7f76685dc9ee6bab5a03a30fae914a1842b095b2b961efcbccd80e5acf3a56c89d9cbe2f54ccd860f778cd9eb659bed521261ad10743e69fb8872e7f7123f1483e8c15b8cf4687a365dc44f6e6146597eef31ab339e7b0d5f78273a822261412d46266de98cbd555bdf4acf50984bf518ff0b3a70b9c4f28d145a95cf0189d9b7e36e63c182cd85bde6f67c8167f4a5dd29e77dbe1eef2c004566ade5021de0bd7d94676bdef043497157ecf616aeb25b0b9e3337abbe6379d5e852bc02fe590394de03557cb0bf9e6bb2339ec0732f0155e6f57984c3733364511e13f12505b5ab12bae414ccdf6886cd06e4a393bef8743436f9e1b1194106df9b6bc1df2a90b154496c27aac0cf2a0a6ecfe9776fb88efcca8b79d5bcaed0bb9ff662d4d9c8a1a979a7134dc0f95e2752f44998b2a428830b6fd2157852c947ad88611fa801ae21050e7ae6fcb867c17721b2a2c0c9e2855463133f96d39e67b0d83234a3c6a3f5a7e6358b9ce675cb758888e953affb608464e3001c532d4423bce1b93115fcddb9a6f426312e587100c1744e9c7a652f53cc4f792a6910394e7282d8feaab7756e635c6b7807baf4cd746400e7cf7f88941bc6da304a047648f951eca653e89f96f8ed6af1a8c8a44c52452874a148cecd1895aa40d997ec2e93b0f7448b4edbd35dc2f36d82b65e735360cdad8dce194d4df55aff3de6b47c76a3918a1254cd7c6671ec9a6968b366e31ace27eed9b69daf504f680f8f15b0e0e1a747871b68d0c7609f3a5e9493d894ad52a01cd5944b119a211fb2f6828a0d903625a986e0020832d06fb9c8bf947e940e9d1dd5a4f65a8e6aa6234312e242f31e5664ccefeb2cf15afcd8c72858eea92f2473529a29fc63c42719d4d3b6c1b2c10c6b29c6130414b5d15a51a26eeecf33841b46bcdaef2187c96cc709bb79921eb75d69f817fe6089394900992baabaa1cd740af4780853eaefde2cd4bae9424bc36537f465dbb44f83777cddc881f988af7f9fad3915e2cf73d365f5110882a7f9d3a7b002437d380c39cbbd5b603c221047cd431cfb6c0a2c6be5c50fe533ba8efdaa364cab519277ea3f9da3e2d10449e72cbe7d8261a0b0d1c59215fc93bc6a9bf5c4c2b9e9401c1cfda77285f7a3adfa2a8707fb3624266f53fb9e7771e905255b9cb0a4b24237585034090fdac557acd1a88cd858b422003c87f7b1626395806ffce626fbb73a7e96c9b9acd4c3b3752888e6a65e8a69e48f05a40370d48edf9290f6e40b3b262d9e8184f93caf29cd9749636dfb83495edef2539a3324a697cbe7787e775474133953e9527402e7bb39e307fada3dad84fab8455723fcb12efe9cd137596388bb320956bdd7dd8cd61e4cf162e882e7a29fa971aea36bf1bfe99e04e6925c017c9bcf937f8bc7ee4ce84899c52c685ab4412e7772d1b9f613506291f447108b9a9c7e8351897279756c1e33ba4022767a2eff1559e07ecfd5057679ebf34eac8f586a9f70af4029b811c81721d063afc588ef7a94127ea934d4829b5a2ec6ce3f0eb5b23817c2073d47a1231be1c85af4f6a4d9c942fc7c6271188540dafc3034c3dfee3e7791a9cbfe7e10b0ce5768de08dd22d6532be9dcb217e1dc965b57422ead3f3c38decacc1a7861c3e854464fea7a4d8520acb7ba5fe2ee971bdf5ec284cabf6970f01367654621171b576abdb565f46bf20d54e7412f8d1ffc4fef975695c1cbaf57ba2ec4f4b99b729ff4c2c003498752bbeda0a84e7ee06f40c7141f2a4e87e1eb47dbc6e7497b7784bccd5e30f3e2c39599e164b7a291fe379edec1ba646f5bcd1a2b605bb45a6abf468e1dae7850e1c49d2379a2dfbd7eca32006783dd81efc2f44e6cd910c15708800b09272ee49303072fdd24f1ad2ba10cfbaa737128f6e91fac94935b61d4f4765190e48e4ae25935a75c619a29a59d193b5b023b1afc6f361c8892bb715608f66617be965a912eb81c3b66f367e54de8937bcc60cf694fdddb07ad6d28f974d9e1d5dff9afc1fb8b54ac4afb0853106ee9c3571ea68121b911be019cdd5577b3c04906a90540afe49838d9edf6cf07ff040bd2c4f303b78145b25ffd2ce9566910595e58cee2eb78eaaefea28cb5aeab9f65d5042462d60adf81d5e53a0522b3459c86ef1221f19e62a7312c32c36b844a3b7b7c6db25aee39f2222a916460a2ae426b49e2d3dcebab4adc640ce9dbdebbbc251e4a20f24a47f4d677c0c6d7685a073dc994b04b0fff7ff972efc6c51cf0151e8ea7380368aebf45deec2220eb1b7dce93b9128e7fa57e244821c0a222a930e3f41564bea1b23112b44b17d54ead7fb9325b608fe8e4f3b66d45448b0355cfb8fd06383b23c66b639eabb507108d85f8993fa1460a8051e9d28894afb6c7a65cbc526a857156f674011645030e26a9d0ed9300b3b88a005fdb1f047d249ce73450ca65024b1894958ab40bf1e33f37f6d82d50ced4acf03dd1d727c7fdcf9ea305c38d0dde0537faa56338b16fd7a3dec028a1e5b5b899332b2c119f5449ea3b4608ecaecf5ab8d003681fc692438bdd90fdc3544bcd0dc6f80efd5a27fd1dbbadfb0545406ffa2530e8b7c422ac8fb8c5881259b467bfae9a86c1a8cd1558268a8ea47a63bbe52e02f5ba5dbcd1554f40d0b0cf99f55a3de19a071a0d63e903fd93e8518beaf783c02114c2f91fd4d06b56d37bc5b770dbd417e32ef4b0b149291e6f83dac08d80966deb49eeb27f99902190fefc89f166e81bba8772c7869a3679d9e631a3020220ab5223c56242313b04b110c2a38ee8fd193bf9d629c2728fc6b00723170b689877bb3e0436584e6da0e28c216384cbccb1c1693f84992c9760317a4f85a5918dfc30a243f4acd5723f900e19184c6fcc81c40af436a073910b174de926d60b90e5aaa42b21dd509b40e21835580daee9db0f272842e6ee080fc4ec95db864803e39d808e571d0f534912e4d8f4fd8f5c6ae559e68657468e9a125e5ef856e12bfe268619f5cbfd0299d14f8f8fc0998b10526651b00323234e0ccb61d8cb3fe94bd3623199721286a78344825d13533605be24cf61297c094bc30bc2d3cf6f5c0171a0a4f7b0cfc23130bdf85bb1d78b98fad4c0cf723abf1e323acb36933811fe02b5baad4b1c605a01458c3dbcbe8bbeb612c2fd4c161c38768783adfd1022c1ac8612705308b48cc28e14f7d19a35bffdb3e01b15a8b7fbdd0a1f310e46c4e6b387c7a7616dce6d937700ffcf62a5ccbb1e0cb5281a6cbb6a45c326955c1932b4b73d7a5bb3ce36b3c37f7c416de8cbb45cc8c91f7b124c729eafe136ff3b6d333a0553d97d3cc07128d604977c681d46973cdefd27fa4b6d44751614d0843750fc6480d75b92772063bc96fcf81a68a0de6bebe14b9ad09b127210810c53b179f16889c95cd538d372cbd73427d3fac11490eb11438675d3a2a9b0a4c2963dfd0dfef7ad058740603a6d4d9ca829fa04d0786efc077a7c9da35726d46f94c681e12d9ac60e6cf6827d602cd02a43336ebb03aecb61cd5774f8959aef079c005552e03f1b5e58fa117bacfe573b8c17f4ae88df70646359c6a4f8027d895c2dfd17ebdfa3dcdc8e220af11f38146b6a1f6511bb6d6e5ca1ab33d9cee69d0189812247f9f5f640fa63a5da35b433c36ce132b349781abd7fbba103116e3e6fde83e1038287985efc11236b3079b7ecccc8f6dfa8041c5ff163c19b1e829d3f18d9f2ddaf0b082fded3eea0d0436738132e092350c34794406e3c89796445da7f0b35e2e2244eeeda036be2a062dd094ad3343e0835ba6337ff38892ac7e4b39838854b83ed7a76a4e005ed91e2b1c8fcf1eb34bf0fd207362d8459c762359b48a0f1762bee415ec681f862ce45ba88151c04929bc87abee2f80a023fe2b695f514fa2ed9326c6abe020f6e14778e47afae9772488be1c49153199cdc5b710790550758803479c99571a05ebfa380be2399db5a72b75ce9d3543ce1ce4a898c0eef46644b73540d34c250831e5801768849e39bb3a7c838416fe38568f5eeeb084b7876334f9edd2662e3b7da08db67a97c923d115c8b2ebd2adb487b30915baf23d3128ec990f72732010e8762711d7fcab17d2c1a87c322874c36b45ada3a75502dc160d3d164c531dd6418a10f683850b48110b14d5e745bddc7be00072cd5ba0eb3dd401beac5825457c0e9dc747dbbfd168bd0e8ddee0e31ef481064fd7a6fd4748b71a9d813826d7560e6a36bb8d6cea19c04c881e452dc97b83a4ad2a9bed7847d78c2b7a6e335a7ae83a1687fd90e42199854fa4bbb6bac3c8ebc6b4ec286a0900f1e662f60921fa0c9b0d295a099db769021a637747e658d840923742d02342ec93c56036370215d64501bb2bdb4a9f63a6062766d93c9b146e30bfaafe7b55a3e1acd98932be105493c7bb9881b11be18b577f4db0cae364c804e9f2a397d32b703456cc2e729a306f7e5bd0ee200456a86c1c723f64b2271f7a841366f2a2f1298e42ba37dd64668a374c28961c8c20b1ba7b41ce363be10fd0a9d68afc46f263f91f470454932fa881ce5fd6a3c27546785715ec9649603399fe11c6351a3438110b013ad39cb3019a87af3f4e4cfb71bd40fe7a94a1debfda02f5c5dc8b91657894392a6ce312174ed7efbebe31320269b9c1f660622f386d566c4f686c7e2bd77b0733bf30b343cdd869e37949c5279c4d64c575b348f3019ffcdd0fb539eef47685193cb8dfd234ad019eeef079f218e00aacb683f60383ca406be8ad29115d091e28c145f8423467ed36ec8b0ef74b4267e94be5df5359d391f401bea3d1ebabf6066fa31358f6bf7e1cb8359db7071e49f3bad1c6193d58038b273a4a160ed8ad225020b94a6e9b21d71e873e5e858f0e76aecb261f59053e2b281288df06afe931e41e665fcd2e8231599f26ef8d779cdfc8f8c36ea6074f308237310383460829a5a9c803f8fd295ebdeec8aa39f99a76ef7d3ec821fc2101eb6a231730e79f357bb0cc0a17c5a499a276bab6114171713feb8a03a35b009a354088c3571f031aa428fbf1ff86bdf7ea1fd1b16b2b1016522d97b5e5372be3a8a15df1c0cdfb1821f890fd66999e89bea0d88ee02b06c3ce96830f768fa2a36e9d167a6b223c3e01d07e452118f6182d57e5479fd86f1ca42286e5c954eab241f9aa476f66501b335a6e34406295e4881187662d4d8ca44cae20ea1bcf51d15599719d6edf900bc11d06cf049ad680d4daf9bd51d675a588e69b811bbd6a9213d13eb60b60622230e2d6075e92d00be9286302fb50bfd3ff3c0014f92e8a24c5b7c7b31b6bf31cdfaa25941d5e4b1002cbdc0d4a5e2e39d2e78be9b0b1bb60adc259daef44501010011223f0f3d74272a9e3f023d495131b8e9c4caaadb15e356891ac96791415aa941c249e21923e4f8c336594f856b5079a1b248997f1e0b177cd5cde2f7212e5c4ff6301cab619981afe1a95701e434c8327ad37b8f54137b79671a08a741d13a5b561cfdf67e911ce4f7c6c55dc48247208615cc0ccc45a7d247268115901d50ea57ff376c47d4d726e9e016ad9b8fa5739264686d4b40d81184f7703c01b8a0d2cd15ef58fae6ec1d88af418a16789435d3ebe12353fbc7e22b5388b9a35eaaf10ea21ecd78f94b99f4c17990e770fb082d2bc772ba7a9992790df50a611518ea56614c64bf333c2355dd23ee1561cf65ebbe3fbc303e8d70a593adef43d0e43e0778371ddc3ef02bd7e724e3b994b41820929b83c520b1b6a73badca1292b9a5311dcfbee157b683595a5e139144ead84f13ab327097b2812a8f27eba17bb61409996f552b1b2c7c5deb08f68044d4a473c5e0db20b5b85478c8a9d4d2da8e9fc59ceabb2847d8c60a38019c7374ac5e25d7526a49a8f3170a74c0c3b0e711f17d99c8485ff2e9e76ae28dfcecb877f343dc8827bcb0e2f912bbd0d2b2f903bf90e906c169fa2b1afe27d9aa3c186b44f7fad92d4962efeb6ea65a47a272e999fdef1a59394a498b668515c3000ffa71938d2a2a6e795c051021729961a798d36750314fa04f5de9eeda9d3cc840d33bb5500ca8479d52ff96ea43c223cf65905a66be0049e7ae3c9de5d6124be8461f8dac6ea7358490bd0641fa4d50692efddbf16d95efe8f0f4733ff5291756dd0425bcb42e0e873ea860581efef366d4c2171d7a1456fbf9bc9cbbfd00a38d5b1b2f10ec9ae753ae8ae39a942d4016ef80145dd3200d2e8525e340701d9c58b118bdaa25b48edea7d9fb0217f9f34b13da15cc7237abdaeee3b0c433dc8fb8cb61f69a124b01c396ac1a410b3c60255ca982e13817e2c96160cb17aad0829bc164103413af434ff821fcecac411240c87ccc2574d404ca858f901c98a382194d18e31824f4645c731e18a3d19db07987d7d74b0aaccacdb23a719daa962b61526c24c9b5acbbc0a80bce17147612791bfd9bbe63a88c384a5a5c9441bd76ffd8623150965a8e1cec88ea2732da10442ccb57da4f47cd7279f83f3cffb27c7dc93ef2cd182821eb2fa7a05546c05185c3c8d5fd90254fd0f7a7d0ed978dac409de10b0a8f253cbaf2a80eefc257021446f8eaea8b455fdac92bd168a1fc201ec1010636d2851c8bdc721ae36df48235425e61ce0d9a96ceae78ddc400047b7ab1a32df1b5525de32da96112a40f2286d154764087e2160676b33c06127ed1a55f8ae25bb8dcab7fbd57916a1d8630736ccc86017f46e0148030c0be5e8630ba72e81810ac78f72202c6993bab21c16ca513affa3946b9c01b17569529382fb68d210ee7cda95327f299d6dfec15e23d713ab87da4d722100795f31dd2d3dc444f54d7dbac3650d39257290bf72681ffc37b77fed7ed10f6806de9fecf90a855891655de28c96b69d571d0e88c4b4315d106f7e546950e2a38fe6756d1f9d4caa8daa2f09e932f6ca406d3da3038833c243811c29f15bf40743ca2735b2bd03a9d33aead535a1e2d4b9411fdd1b8905d2f41e9bc2cbc35e5a41611eabe557f07e9900d81a70bcb2ab208ca41dcb2f1f7874684654a7b4710f39ab666626a7f985a574f52790f7d27299e946c13ba833408592a3ccc1d37f9eebeeb5322e6ce5496f6f23fc268e6384f2db3707ad9710f38d80e8271b9533cfd58ac1105e2d3c15814ba9ac8b3b3e881536478dab5324c49fcf457fc5d51b3c9c50d4e2ed9045c60e4528e8468ac692964c8063244e3bea7a2176cb1878415da92c3d19f72dce1c87b1bbfedb333ad668ad1aa6c9e62090928248a16a643dea0ee9ba686b72ed8b028d597a43099a74547d906b30bd1ceedd17eba4db43c39cc1e910ec76cd0abc509f7ff1880913fbd4e95700f98d25065914d246b6ab435a9449a6c6f21cb08ff15f248032250f57eabaea46330e1991403df5a25f227d2c5050fa49e94f9bc5493b294393a805eca88203beab43251acd21a634293d891be72eccde57b1981f21a17b25696d24fe2952575c9a8b176a239319a0588f54853c051d9f519b98052b6d583858e4176828485d242d283326e5b7d24f379399ddab67a890864965245bd653ef92b4021a3effb709d6c2304ca76adca8112326cc0db97688a809ee5a50f91153838d0f3aa4226666ad92228351d06d074bf555874dc85a0d5958131a30c027f243ce3ec984f8b431f64f15033cbb18821bcbb068335cf32346ee549899545188279870bff20035b95db81a6cbac2953a48fca4a0bf64381634dc8c02c7b811b378008d819434bdfe51ef34b78cf4453b78fd9efb1cae6bc422009246add917f828f465a087174c355d641a3e59d7c75e7277f0642098d84f400392038d5e618658deaa4e98564d0a6f2608c96e641e2ceee1e7ffbce0d31bfa4bfa29011a3577f9f61e4b9c88ba43650d346c3921d94de3f63076df5c894e74911555ba65b91289f90c93946b247afc701beac0bc12f23db32884548f43b53b29ca8a7cbae9dfbfdff7302c8a52da00c43bc00ed98c426b5fb7f27471e533ed3238ca2dbc6031e0f49aa1a2b4fa313bc304d2dcc267173b2cc0f8ea0fcd413905444195bbdb3613035d89b5f328f5022111af6f006a6f3e3e71450c53971a604855c337c1225801f3ce3f0172c99c08422d8c3aeb4c4ea1ac215dca83d4af3b7ca84f6a9f374055f0faf046ad85f0aee21ed90dfc6689e3c7dbbe5267f9e5e398edc89bcdafb6f72e49654d6ec049b3cd00a9277282db40d3e5d42e713865a3cf2debfdc808519bced0c02c7c911d11ca2ee81526b4df3a5155b5cffbc50118c6345a8809543ee04885fb4bcec333e5501425f234e075cb57397b88c687140a7a019211f42760a4569c2f8d24956016392d16a447be594739d41ed5bd4abfadfd633ea9978bbc72c4450118b01c910bb51ed40540a68a6eec398cc5db8c66cf62f5e734687c8c4931972068c1a33e6efd11fc4e28eff802b5d6d213640a0629766ce12f0d4550c20ca52f5498d5ce727d2aeee7546f4d1b7b8b9bbad08bb880b284a78aa7aa886c7f587889b3152d35d9be5d821a878ca1136f78b4e4f40d91393c2b4c49bfe4b09d648fb429f92bde752053fb8ba945dbc48b88d6ae3b6327e297e908c35675ab16cc96c810fc701027152da68ded2ea181fa07db69ff2760952fdb6c2074092cea9b68a73e92c322ad92c83e5a7e9474af54263794a7f74dbe1ea6d05e453b0b3912931872dbc547a48b8017bf094fe464b93f96ce7b835bb96760917f765dc02116fa685e601c686018d4a419ae5c42a12981458b66115573df6b5c2e2302b4dce066dda008661dbd31d996ba29a94bfe6325ae1df581653878ab22d23475c1f50ecac5f615151e6d10281487ae3fd5f42a4ac46b70053870e827ac3344851a2484d92345c207823e0bc4edfc51d0172d0acaaed3bd791aa07d58053beda99feeab71f723c34091433f6c6a4ff56918ae5f3dbcadd97ec377e62ee69c9a271a62a7fb470d16f007d305949b5e74414f956080434d13a4bc3ebf9e06972da379db265f1d643286ff498437a8ac7f2f4efe8e66c5f33949b2b54be6410b3f375e51a424ebf33a7fde208596ed4585aca14590acb8f474356b3e7c243f0a8907af9053ad8fd0bed3c4062675fc2542ea21f6f4bf06cef85358ec75f8e08118905dba54cafdb8c4c8a3d4a177ac73a7b847ac067cd79658d8dcd0a274180d580f7f6290ac9712ccb710b5a8c9f61bbd1a16e061b88f1bb6dc9e0996142188936d4042a5da1498aa201ada27c75ea8ff77e60f07a98491880b1be9f4f4282086df56e3f39f5fc640cb9076171ecf8a1af63ab5be397c11f93f1f53dda775445d07f7a9d046a53e30e228bb8bd0517e9fb56a120e38e77f22ea04ba23ddf6be11334762811a6061eafd22c52a062bb23626f4cbc81368013e3217e03eb99c67a8d084cd433d1976a94a6a100743c2699b5af10bb740a1f80e287b7d52adecfa68127ddfb5e5430cbc5cde5b0b5019c3b325dd9f2d9e31c586cc1770293100c423fa018501709a98ac9d7e8a018dadfc07bbdfd3da3d671487546885a32ea80862bb68023aa00cacb2952113872d5fd46981b9feb5e372c1a5800d897c42e8d1d9a56c09a1458a3c52d5d7df2708c69029334a343fc7ae7268bb97e790d544a5bca4066fe1c8857c735fe050844bf74eb0b26f9f96fdb87d780c02d99bf57c4e8a93c1a8d1a98adf3b592405358660688e6924d14bd329f5991b4d7d990e5bb4b000191c836b88dd5ab7b7b696a124315f2953ca8605f9c5f094f46c00b8f3067ba01a261848f34ab8468b0a172379207a889f51e6410cba6b11ea5d2d35cd93202697dcef91a600a86664b685f8f23fd7ba2b414c5b683198c5b69dce875afdca7ddb1ec7e591c75f38a4de2ddb464863374a8bcffc77e681182fc0d446d71569740d14015471b6ef8f8559b0fd4921219bfcf7932a9c130e1b42fadc8a030267c96824c9dad3f31496d26b2709ea2bd46d633b589e54786eb667014126874cd622fbe4daa34c2817fad5e3aa6006b0adca7b9801f06c3b7dccfb23ca9f48c2c5f0a8a1fcf58d0f4929de7e34c688afdbe5befa038af760cd288dd43765027980f2fda80018da8ba4e2e264a0f4c8e379330669a7b5c585b9c0623dec8453243ce2eb6c2f8cd7327945ea0a09f40a0679949eefa1c6d91fb6b04235d671cfc8670fb29db2c3e483e063ce12aa5d3085ddd4f4a46466ec7d546bb21c8a2962f1b3b3964d0be57312867c025e305626ca5b5136b993c0178d3afd8fd46356dc8860e8727e564bad9f10425c17b76af6da15c549f4226850348a00cbfa5c7f7e38ddb15e213cc439680f46d0d31de8ceba81399162663ba85b2733c134f11fef2464edd14567d7c7758cc6dbc813cc7fc615d11f2d1f9f7076b874702389e1818dc6c28566252d498013878fa23fc4474ea5837f14d814e6ba2aa15d2b75df833856584b10b5af00f53bd92153804160bc34445944251990e4945a157290b725b1b255b6757d9086f5fa756c3a28c5242fa54529c12a2fd3c3be514a8f863a33a46aa4513177ae0d36dd7084ad355f38d66e258c3b14102ab28d261dca1a9f9b24547e1f7ecb632ae27c2ddcc917358ae909f00b307bbd0af7e5051f01b9bca6b630092e91d2ce749483e4f335119bac7e1a1ca58ca3229e524c05283d73bf7a50cab91d85806b8092410abf732e129022442c18acd23b7e7126c77db693c15321f17dec87114df46d3ddc183da3f5d4f750ff344115f72f96b67b2ffcbfded2b76128f0a3bd45257c986e57a009"
    EXPECTED_AUTH_SIG = bytes.fromhex("48c21c429dd557317fd89d47b1b6ea35f494fb79eddb1d2069682a3aca887db88c23e6b3622ffc990be01a1faa33ea0e18f70db82ac631ceb29cc1bdf4955906")
    _assert_real_orchard_only_sign_digest(backend, scenario_navigator, TX_STR, EXPECTED_AUTH_SIG)

def test_sign_tx_refuse(backend, scenario_navigator):
    LOCKTIME = 0x00
    EXPIRY = 0x00
    PREVOUT_TX_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c200000000f9081a000198cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b48304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b469c616e758230a5ffffffff021595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88aca245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac000000"
    )

    TX_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c2" + LOCKTIME.to_bytes(4, byteorder="big").hex() + EXPIRY.to_bytes(4, byteorder="big").hex() + # header
        "01" + "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a" + "00000000" + # hash + prevout idx
        "19" + "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000" + #input scriptPubKey + sequence
        "01" + "958ddd0400000000" + # output amount
        "19" + "76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac" + # output scriptPubKey
        "000000" # empty sapling and orchard
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
    sw, _ = transport.exchange_raw("e04280002598cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280003248304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800032c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b46")
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

    # Send outputs and review
    with transport.exchange_async_raw("e04a80002301958ddd04000000001976a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"):
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
            "3145022100a4cc9821cf530a179cf2bcf767644ff62e0b0cf79a5701101914be6c215b0bcc02202d2ac5ef2289caa7fafc94ce38b2e46baf5987b86193e0251f4cf2585c174ccd01"
            ]

    transport = ZcashCommandSender(backend)

    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e0428000257acad6b8eec3158ecee566c0f08ff721d94d44b0cf66ee220ad4f9d1692d2ab5000000006a")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280003247304402200d6900cafe4189b9dfebaa965584f39e07cf6086ed5a97c84a5a76035dddcf7302206263c8b7202227e0ab33dd")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800032263e04f7a4384d34daa9279bfdebb03bf4b62123590121023e7c3ab4b4a42466f2c72c79afd426a0714fed74f884cd11abb4")
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
    sw, _ = transport.exchange_raw("e04280003248304502210093d8c71d5cbb31d5f76090b332f66fc1fb2451c97575918a9376b803eca7c63f02207e238a6a437b8724431e")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800032da7ac9ef4dccef15c63b00f6f5fcde17f1398e254c77012103d12cb12682e34df4d936479f282c75834d612071fc2ccd26a3")
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
    sw, _ = transport.exchange_raw("e042800032483045022100959e27972de3908493b0ce7041734289a724cb0b5d8a2955de3fe3e953f77a2c0220162c40dcefeb9e30a88d")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800032043c3f20ca17423e6ad212cbf981e2bad05cbd10c7e5012102e8b6d05d227349a7bc993a7d3d6d019207c471209363e994e9")
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

    # Send outputs and review
    with transport.exchange_async_raw("e04a8000230117222605000000001976a9147340a80cad7353cff25bad918e73837c2e2863eb88ac"):
        scenario_navigator.review_approve()

    sw = transport.get_async_response().status
    assert sw == 0x9000

    sw, _ = transport.exchange_raw("e04800000b0000000000000100000000")
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
    SIG = "3045022100867fdc2d2873b15bc19a42df288a257aff08ba74b9e2eefd1245e69b05a181b302200b876a40a9339b8b8333c332319dbe5329af363628e0fd4847b281719986dc7b01"

    transport = ZcashCommandSender(backend)

    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e0428000257acad6b8eec3158ecee566c0f08ff721d94d44b0cf66ee220ad4f9d1692d2ab5000000006a")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280003247304402200d6900cafe4189b9dfebaa965584f39e07cf6086ed5a97c84a5a76035dddcf7302206263c8b7202227e0ab33dd")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800032263e04f7a4384d34daa9279bfdebb03bf4b62123590121023e7c3ab4b4a42466f2c72c79afd426a0714fed74f884cd11abb4")
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
    sw, _ = transport.exchange_raw("e04a00003202005a6202000000001976a9147d352e6e9a926965c677327443d86cb0bdf8b1e988acc11b7b02000000001976a91456464d")
    assert sw == 0x9000

    with transport.exchange_async_raw("e04a800013f31771790b77502f55895a396a64e74da588ac"):
        scenario_navigator.review_approve()

    sw = transport.get_async_response().status
    assert sw == 0x9000

    sw, _ = transport.exchange_raw("e04800000b0000000000000100000000")
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
    sw, _ = transport.exchange_raw("e04280003247304402202ffcfd634ae68631af2435b537d33e86a0a38338e3841aecf6d0f54cadef979f0220469c7cd94d52be1183e4f9")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280003275035388254a4b49a22bee691f8b3d32e65b05167e012102529734fe55e9de06341c90ab8dc11f144ddcfaed136f49edcdb2")
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

    txid = txid_raw[4:4+32 + 4 + 8]
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
    sw, _ = transport.exchange_raw("e04a0000320280969800000000001976a9147678416cb82a4a716dd1ee6b332744ba2a1f11c488ac30db8e02000000001976a914c628ce")
    assert sw == 0x9000

    with transport.exchange_async_raw("e04a8000138ff6367f0ea6763f1c1d865329af0715ac88ac"):
        scenario_navigator.review_approve()

    sw = transport.get_async_response().status
    assert sw == 0x9000

    sw, _ = transport.exchange_raw("e04800000b0000000000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a7265510e7c801")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid_raw.hex() + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac00000000")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04800001f058000002c8000008580000004000000000000000000000000000100000000")
    assert sw == 0x9000
    assert sig.hex() == "31440220488d0fca08431682cd5f10968a72affdd569f61a4a358f73edf05d0fb4a3e1a702204722751bd7d27f999ed714694ad024465d54c288a9cc560559d9594914d92ac501"
