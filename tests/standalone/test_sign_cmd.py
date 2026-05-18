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

    with client.hash_input(
        transaction=tx_bytes,
        trusted_inputs=[],
        change_path="m/32'/133'/0'"
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
    TX_PREVOUT = "050000800a27a726b4d0d6c20000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01a0860100000000001976a91419650e98310b2cc27f00a9d0c4580386553da2e488ac000000"

    TX_STR = "050000800a27a726b4d0d6c2000000000000000001cf67287a7f4820dc2dd57503b3a5e940b4c1b322024cee5e8ffbece7f217f4bf000000006a473044022078b3051d53853b8cc0b1167da56b4839880847e1cb39553cb724d564b069ea740220208455fe9cd13aad139d983467bc862b8a65fe0b477fcb872a298f1ac5174ac5012102749c3f99dd136601daa824ecf40ae144c1a7de432bf22dbb23c81c7b6077d431ffffffff0000000239ceba3e81ae3415fb4a519978f4bbc75e5a1d101ce0d6bc91d035f614a9f68b3768e7c28954fec9791e472e02881cb6b2c3f6d744c4eeb0f248eef01f6fb53dde43004dfe82c370356e830569bc2136374339101ab3170a9e5f01da0346340189b07d697d3ef14edf006d9a39472371ddba49a58ff23026c8656e9cc4edd437b2592149ac97670466fc5eff6657dd79cf20d551b31446dd49fbf9d4b1f3a2309ea84a733e8edebc00e516d1c077675494b2b58fbbb78cd4106d1378c0181c729a4606ed2b0e9aa6a84c1eb445964a7363bc9c2eccf8758e4ae1e8d3453b1de676dd06164b76f275627998f50cf6e54e6b19d04bf3a37a207fbd5ac65db7fffa8a0d2ea64f095fd1bd4b72808ff012d94dbf00480123c1ac26d5392277f20322af0595bb9d44d5964b95a859e630d90ea82695b163220a255a5eeb591a9df8d592957e5e0555a178a4aca3bfbc7ae23914c97edbc2c4ab1c5bee7220f220ed869eca8f90ea9646551767d12cb6f7d8d1c51f6f4e5989c24ec7829e2efc2d9945644fcb541ea1ba9a0a9a119e92c5452d5383f381f62501a0deeb0999e659fa2bdfa8036a6849aa67a7a70b0f3028332ba1177ef129df4dd708c85a63a956653ebfd65b174889ad84065da7dbf1c46a225b77e45caf0218cef2b6f879ab20c8c40345e75d2db634645badfecade82c07af4d110c042bd26060d9927e0d8257c68dd27163994356007842dc7334f16a82cce83bb5ce428e10adcf4e9077292eea6133c3933eba031dd73c3ded25c8d1fc7185df3b5974be79428d20b5c84d81e06be531d987971af721c29787e0217ca27462c9a64f1ad03d05581952f25505ec056e1663bafc81d36d2663309e126b647353b6938d96b6a82f187a87543ea43319c51b3617eba6815c7986b7825bd6b95b41ffeabf57265866fb47336207174b2617f30887962bddd79a710cc1f3e821d5819b826bc9317b85d3aa1fe62da28e93233dbd44f1ce12f998f0ae82832c5b7b8d85bd3bcaa36267c9ab28720765b26d6104f3b3cd84b39eb3dff77f836a1c9a911890a7c8c6466ef5a2ac7547509b19a25f10cbe193d8d97b9c54d2aaca820303bebbcc4c398d71345c10b5b4b68552bd12bf00eb14cef7a532490b3fa9acf86e7e4c7871b0d9ffece64195308cdc3403af4673ace0fed752a34cc424fcaacce45fb199f2daa682b1a9ce8c102ea6504c18be633d23429b3625c42005fa15d4597632a4493fd132958cdabfbb6985d998ab1c00ac66861552116d0b3dc27a86ff398b955097853a03489062efb70a19197884a035e1d364339a66d7ac01c0823e5a4099400b1f9865ec8845843d7f95a9caea50a30a922a064a3c41dfe8be3a6422b9c77babce7a9456b470802d25939471165f40990746c68752aa72deb0de06d92e8a9e8279a7a07976ddd5a4ea656b5d0126c0cf6767fc439549b6cb4dbd119651352f7ee7bd1f2687ab2da8fa9041d164730b950d828a6b4d540cf0a329cca8edc30fc27a35f1990caf739bbd701bd05428edb3ea8badec1136b581241d951a3f29cdb49ab29aa477f3c52beaeb1c55a190f37841ab60d6d0754ac4458deb10f6e0be101731f5176c4b2845e5c50d5121994bd8ee07f6085a54e3838c2fe6bfbf8212bc8a128d4aea5522b5e3245312037fe0852e226dcbf5488a388ec83f78875976f7de2588573130788ae5c7e98d080bef6d2b6e914520f56506e4b0a57469d07ae89697c7bbd041bcdd33079fdb6ec87dfbdad29e2e369d398b34858626f9829ad3e167e001932148c7ad0f3cb0d66edb322bbbd96f7f68d9b54e88a61d24dd69788de009a48a97d85554008a1139170b35d8d1b09a5d0eb75d1a36d1a825db2138a627cbcdfbd89303fa71f417c21d1562e8cd73d5bcc3ab2f26edcf818fc592ad22d5bf17d139b5573dd1f7ec2567cd66d44b4e06d54079308d0af1c98131b0290c215b72110522038c15fe2090e67f6f6bb865096f10e58ac570624773c2755bbe261c9889846b35f143285476f798f8364301a60e401da8320a939b0d3a4ef260fab9c6349cfad8e993a7de877cdb42933810abc881f74eb3bd1a9301bf9b425750e004287f7c2df4d1ae98f1e17f44f6f306e1f65e0512ecf602ee6c0c4d7ec642f81a1a0c6895324e6013d947ebe29d365f9a23f86f7d227f9633230386bd3eb242d4c6ccbc830c2c8a23444b273723a0f83d07519cc818d0e2b3e563c7a14e0ca5ddccb095d2a0a4303731b403d83da0643377426365a7639f770c5cd49fd95fa982e6017a4da75050c85f0503b7f150270a0feffffffffffae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82ffd601c2493dec4309737e5f931e660f3fac9cba84642ccb90a59f929cfe8a68513413ba0e2edd762f3a69652cc31d265fb0141ab85336fc5108eb940bff64074f9379e0d9081096dbd271cd311e40ba626f02621a9ddb5dad311a932d61cef82a22825f532daf9f2059eaf9bac3aba79f3a30f57ce27bd65c1608d611e8072b6267f985c40d044b310319098720517962a63200c9e7da2808f588cb1f39ed4860f868cb4e23aa2b89a1882c67169031994cd576ca7077952cddbc433d391920696bc9e0aeb74b357a43ff817d6fdb44346d4299723e0eda5ec5d702f6aa2e1c19bd13625bbdf14b00cd8a50c907eaf8b44d10553a17eededdd97cddd183574e9795e85738250341388929fe09f82781a25c2dee6469df6aa00f30ab753d7f4806b758559e3bbcb4477b6fcc882f2120d20829cae2c2f2e333f584ab21d88136d663cb65fb17125943bcaf2d0c6ee4ab3d8122e4ca639b570d3579c8353aa1bd25e2b8eade9956128bc88799279800e8866f4ea863429f4e5d26fe98426ef26cd015c1710d107ccd9d0bd44581dd830e9c1f5bd2afa29825985c386121275fe47e3c000ff8efc5a8cc79863addec6db941b114ba802aa5efb67c9c8d50988f954c5a1a3a2332644ec56bc33e20ef573c1c033e39cb9ef6fbf28480d5724025d18b8f52b7618167cb4dd4da150aed787364212c354fe98194977f9e09f1d6ca1e8ab1327ab2226d940af0f9da620882b704af80588af599a336120c454047848236cbd2ead8abe5cbdf0aba310b9fea3af5f621b09a6cec8011d27ace447ece4a05d59225bde7df34506740a0dbfbf813e343609f119aac2fa21d5a39842f26ac9e35ba8ddb3555e7230b521deb3b3d15bec2ae955f99eb8b443469a070da827d96fce05406729f4a1d9a899706f91ff7feb517857db73226b0b7867a8c3cd19df499616ac145bc3e0aa15e290b0bb142bfd24b7120b760194de2e13884fed025f0feaabee337499fd8b75024539c867fa6999b583844684ad5fc60e6965ed2ae7504ea27cb4c5e2f82354f1fb34d4624072a7bfa831fde0503837d8d4260c9f0c424dbdc6786417e76a7f5c2890be319d6e2b9e2a79d2bb17ab637c41527146ab3b70a40d9075b35413f6bec2dba8ebd9e81d2438fac53708df21c58813a91d8d6c63a300b5dd536e7bc03aab4fc8a130ab5c5662e4dc8d4e93e836d6e2f8730f5bbe11e4a1bf7a08fa829c9812ffca9f46295fc3b3695849d646bb31c5803439bb562bbff352a65288947cbc844f76307778edf1dfd49c7edff6a9b91185903250b510b45e8cd52d3e45070dbb9fad86e6269d240ed6ed5b1d348102775a16614967a3989515fc791efe2b55d50010a60b32f5bdea40449ccc88d09f4c3950bde1472098f330cd51df28ee9e8a42a0da5da0df2778d6ed62627a634277b2cd6853cc9f36da957d834c2c71730f29c39ff0c3936112b89244e1bce6fc5c734ffe09778b611f5010981e666bc701e8f25d720fbdf6fdf2a9c56b97e2ae4ee8b232216816460b04d41b09e030039e711eee823f559505f36f3224b48a53caeb1278b18b9fb93fab105774236b6619e62ac281ec192d8f8f390f0d88d6c37caf0b16f902bcaa8610b8b4d6ffd016ace02a168a6a6cb25087a788cbc9af829362cbe2296d094049ba0c3ce23e1684a9e1bafec42b5fec1841bb3fff92142af0b17c96487da1c9113eeb110f7080fa4cff641f5ccbdca26bbdacaab9fcb2b4ce00bbccff8eb3ce58208415d864f626027b2747e1159bc6d180da89156a3cb4de7185c1c2a3a81047aa2d5f94eb6e4761ecc6794ec4dfab6024cca2a3ad629a9a867996b00b07f6deca68969f482fd07b05a4f707cf7fb9236a9e0b7a8ba361143773aa956c3ad1232795dc8480008565ad5992161ac5fef11e8b8f5eb518b6986ae09e139b2240e2ef7448b50ae473a48a4674cd8174ce79c77120b5f4af9c3dc25080586c0dc2ce8564d5611d893641cf60ace3f715f6e954098517c477f1dd1fa037e2ba8c9a1eb731633a92df1ae017af977b5aac9ca93985323cd2a8a2ee32a448c4ee985419ac51ac1877a4705c3e6d308f7b1c1bcc90c9b69e62a2303ae45508aad98667cef105f3026f0a1b6d949694d4ea1cae16a2b738c90a63690dd2ce92d8172b9168b273ab80cc38efd4c269d4c1c59fb3831fba4259f27e7bf58c9d9e882d382c25d0143e0f2b80d864d6d24e14db56acb2e10b235652e3e20754071ffbb8082da3f73e53f1848c550783eb55c4d88b4578c14286b5a395cf75dba6891016b8297919205511e9cf3eeffa5f0a76ac2937a2908f84e979855a1e49743a3fad39aff95ca7858848a86da4b79c86aca1a9a745ab2eb3f5b9f116eed278d7f99b89ef192b51e144b3f9ede0c06f717681996811c432d131ce0304c3eee47406dd3a54b16b5ac676922e13fa2f293c65a01c05a2798b711e1990eb486be2430952325e33cf38f9a0f08df881c9437a0d65b255d9bfd95dd0c1c853dab79d4d620a3148ec739c60d28bbc031172c7eafaf1bbf6d4096f6d37dd22660622b670e51c1b0f09766d3a8d7cdef029b1cff1ecceb58591b80883bce5f8e9c3a2e7499d3032069d6ba3524154ccfbfb4007922a1fbad0176c6f84f36a6d6976128e123bc9207806d95ea4f0e004abebb0c199aa6dc8b5a1411de1b545b13470f7ef6c213f00122ecf296e75640848e6414b4875010fe994fe1413a6b084123bd3a36e8f7f0e5c69a52bf1c35b52e0281184e188f3c9322da6235080814bb91bb9bdff7bb4286935fc042e110e2c17d5ce0d7be56f7dcd2ecfc6aade05db7f08af7201861f1602ff47ce866543a5b660be96e980a960dc59fb523b3b6696b8ad3a48bc2afe08cc251764ab3cb038c20040234c6e6f67639ec37ac4ea1293702c825b2163b93a85ebebbd99f37fff916dd8650d8c512abb4f83564209525e3be367498969053d7760e2384519bec1a7007cdc2e364b3396782a05db1c3e708515a9f10bcc573ea2df9f58181c81ae9bfc82bd5b2e4074339f59809a118dfcedf60c1dd110be26cb14b64e3807152d07cd486ee33eba1099f61dfe4930ddc4e778dc4916089c3023664b2e7f521f539f905883468b005f8e81ea0ed286faff6d73775a71a5b02de035c0ca5d99a4658049f08d81d5a571c011dc7f99877454c187ed97d55b3827591d6daf192a5d7f94c96a4b60a0bbe5893535929a3d3f437a903e6e2dbd983f57e0589e152a82d3b0037a0d8dbd0a3293f584581cce55111b5e7d309408e0266dc2fedbb7799d28804a8f7b7ff5ac36cb877419e9efd316051447087fd9cd24cc0d92fd541090963acfa36b624f816b1b4e7c6a3eacd80c9f23228d6e08dc31d6fab94f763cab314f71de1d75bc8acb02b896b52a9d7ef9131030e88117750f953556f043796c73c8e14b5071ccf16168ec8cdd6079fd4577817cade883f60493b1036f5df2e11c213bf17ce4045300aee10088e0541a66a9cf068a16b10c32d2ae5e536d9838feb5612237ef0b5ce01254394d7aca903a1d89c170bf0810135e1e9320ac073f0a661980c328bb4803335c0a13463683ec3a5c3b946f7a5d217fd8f821241b8895076557872d52d81087ecaa6ab09ebc788be0123d4dc9d51600da679dae91a917b2743ae8af39b8d83eada3c8ba8861c4a7eb7db89bb3a13ff22ff5beeb1365600340d499297541d7c94405372cb08bc00df173ec58fce42350e6851f62b28822c76d617f3ff3ae0af4493350e3f8678d5ef2a4f30121c1037547e29360ecf7207c72077bedb23399f2b2ac2e6ef5354bae4b45941759f906787482fcad2f99dad37bc71bff712fab4f66e89bf9de6bd63979a3021f736c09591a349eaf5b1e7bf84658f01baad3caf9d2343e111e1b6d3ee6b07f7e674c1190e77e00093e488ee0c452902c8fd52248bc14cb4073579a1f6c52f117541a0cc8e39c089efac7dfcd4382cbeb82c932846b6e6101543acb2f8455b5ccbeb718aa25c7e715dff881a00809dc5d659912e85bdfac2d413ce09cad9fd391e90314b6807fa2cdc40fb8999d05c5f11690921ba141108647752032673a41df84b42c9bff55734c5d58b16f82c573c3011a964418a308b4d732597849ee3a3643763fb1a81619e7c1d3875d068bf7f0151ae8ad6df90bb6722284d2d73ad1427e2c03db1abd87b42a6b68030114e9ecafbd1df20ba71ce888c98069133036b7455033407c6d7e884b454a8121f6c9cef9992357216fdac0d558d66a763feb932a092466fa5e10545272ac8c83b377fd9c621ece8047996a95de83ae3302e08433ff1bb272a2adce60de2e839c94e3aa24cdd367a67641396b78b6739f6522bb2a3b1b39ef3f3f3dc063822c8b2acf52265114e372ce83620e5bfbf05d5dbf95a4733258bad007521c787277b8f03822c8cf3b0ef082c78b38fd66eb9344f76e538f0b2471c0aa0a1dd1e0937db2ecf7148108836c89170d069c6f2483e1bec4c2ea32033add3365097a93c220de3125688370427d02a11448508e851bd4561aab520a23ba07368df1a5658eda85b724951d065408455cdedc68b4c4c0b08b087cab3f59b165a8ce5c4669e565c220efa85d0c7b93fc757838cfa19a8d935547e1633de5c07ec69ed835c31877250cbb3b94d26ed7afc6d6602d6c8e0dae788988080a4b6c8cb61271b0e0aae5fc7703abaf2f6eb6006efe59ab66bb4099e509252026ab7d1f318087b6381c6cf12039e1185c814685887b58aaa6639bce877121323d7c061abce673963f13cdd6047cd68eed14ff9150dd68a799ec2178ac8f828f33b33643c2ec189ca57e4ab78d8536416e52b328d4acaf2b843aa0d9ad34aab324ac36afcac1f91dc3983366379129f2282b24c9987568bf208275126fdb63170cb1cc338798b7a1f473388dac3c226492e11ff9404651c3deaae7a6442b4fc7164c35c81bdfe935bbd6014899002a79299a3b97901ed31c2839c727abb7267d169db8627ce36056fcfad1072d22c10b156ba124e31c69770ed63f12d3bdbd570def3024f9c9ca838fb3de770c544e5e41e88056d711f35bc856c20b120f74960f40f11ca00f8bff46b981001454d7f790a3989baf91c92a4d1d562a290de2aa00b2b0d5c64fe3a7352b92aeda7157f35aa47ef662cb0242a8b3b9a1e0ad0ae63fd2a565b746d37311a1069d1388ee3594e933773b18da64f128ad71a0b97c0e349c57d414d678e00cec0d732f0459bae23e00c404d4088dfb8c87801b4360b534ee89f0a7f100f128909d65ccc3cdf3b9e2ad6387fc051dd8e657fa21855d4c37ca7931898962cf2124318ab1cc8992b3f6baab4644977ca32108f569da5aeb3e1ef6e868c0c5778d3eaf089fa28f042fd33a9e2815fc88f355ca72ce0701c438c6d34f9c7dc904d95b4d24b95181dad7023312c27c5a37d3a39bae79c82285311a7c2350688a475a3a6f026691e9d61ee653286bb2eaeacc0461d368cafd2428cbe4b28bd6d23d74bcb57187a8663aca58fb3b069136d98160b666a1ebdc35219451c2d5c067737f56dfa618d6f23e217d2e5c1f3a3fe710d3711ed250df7404d0b4e09fcc7bed452ef245a9f2c1aa0e961f589ac38aba80e1957c3b5e4459284cd16af0067a360fc819271c3d304fd0e7484abf77d58a53fec42b1e6aa23d0846dd3ec78aa9ff561eda516e8bffca658523d8839debf553bb448efb0be7e81485a7d0e7dd858b6b86e5f22e95bd831033658419a4a3fcd448ca4a62997f8834c27aba1d99e039f60b572a08b6646c9cbdfd67621dd7f01e6d1a3a171dc22e3b8b58f1f5f66d8a17d9bc1b2c12835557330902ce8aa4e5a5dfed28ec3c0a84249eec8d170d913441fccc2f53439e3add4a4b6209f5a749cc9a8061b287b086367c5bbd93d379b1c2fc67e65f6450938b97deb062686499c383762c679872e327ece5f8b69c47727094ee7d8bfe96b2d9a99f811d2632d71d267bc354d29ab5379566785daac975e891f25ae53e9dad09578b03cd96cb7181957afa2df31c36298c585f62c98c612a70c53df86545e00d6d97dc4004e7aa82d104e24134f7232002e6ddf2afb2c6b4ddb4bd1bab5ff49f2328012d877fe6e3e7247b7fa3f6152010ddc96fffd1ec83c4ee69f5d827ca6be2254a9d5162d2cb222f53bcbddc322b499179cf0c1b327e4e842e20d7e7ac482f8d6d908b73cdb18bf760166e1cec22b69792131142fa34337354cd9feb57648f02106d6171a55bbdb8912dd85cd30eabc7a31e3b3070d447e13ef07cc6c47a3a8b070ff57fb6e022702811978a033175d6c022f3fbbab6dfaeebfad850037bae459775952d2dbcc319d3fcaad1fa13db598da05496e9fbe045d8acd60643eac733759a86e63710ef6f61a859047422cbaf596f7cd33a0b75d2f461c8dc90e2f6951cb01dd70b1f45ebe76a4be1c83e174b4707d85cb439b4afedf61807188014a3e9429c30db7671b320771a460c1a719443351feebaa3f1b99c63e36c93418af3a9e1ebbf55ab54c47d0898c05c2a53612a82d41454f5882f06b1a98d4bebed52d64dcbf9f6f37ddde4c6fb014f29c25dbb9fb16508111f81749be168f81c788512ffaa9a301828d5860bda7a942590937298b63d177f2f9edc3d3af7cada483cba84d24ece123f0a1a5c2377ea26f172a6138ab53df85ddf45ca1ae2dc7a8d8555c8300d06476bf9344e3f7ad83a9cf884386d99bbf75fee067c989c9407dc973c8acc7f49e5257d88660a96b117674555725950b5c397e2267a9febb9cbcd33fcf15663418e7c9dcfde8824d23728507f31baec0f1b6f52c11acac454bd7740253bf2930e27915a5fb63c05b52fb8607b6c087db9ddfd273754747d7ce96ceb4a6c052207d9027cd1669ef1281d720eef12d2c757b5dcfcc779940499800670aab8272f5d208a71c7542e1bae1e6d682b309b3f8273301526666893806f8f979e7e29c8a244fd1dcefe5d0e4e2111a4c39123e9eea036ade0a2243d6013591f7c1367565a06f599ceffa2fec72c6386c3bfd68d57fdcf00b233571be24c9888cc52e17e7c0ed7f992409cbe1f32dc9a43008caefa856f59e413dae16ba4b1a5f7bfe09ee7b28e2a7ea1b6d1671719e7c605020e328ad4babc83724a1e8afe375a1c4ea6b2d04f08ac0e8c7d451b3488cb4f654d89e55111354aa59dfe69258c8d3fae89fb6131c031ec0e612f346854f1ab26fcfae2986344d9d202df5367c92df875a88ec3d0a8f77fa25e022806bbd1de02f0322fb41b304b77321c9b637717af7b075a33000cddc738462d2c9894c82a5811310abeb4a23ac24b90eaf2ad5607d872a805d34f38093c1ed91f49292b1185392358b26416ead073d37c1bdfc0e575d1876bcdad480c287c5615e7a9483df67ba7372360ebcf013eb533964aef17c76a7251561cdd9195ca261dab321dca988ffc1b46af4ac641e389609e3da25c667a91729680b792c3909636026991a30c788cd9a3495bddbf06482ac5f65fe93a332b5d8bddc8b1ed3aab2414fea91049e04f55fc89b953e118188669b0948024677eeb42a94c7aee456a02b544f31bf7a5bdb9750400ac0394d2b2e411622525012973fea716bcb43ec5359b30e8fb152c73d39af50090758f2f9486cc05b6033f72139258b36dc19ccd18d4e607978c2439855716714a2b38792e66c32734b030e519d61b9be42cb99f20913de3219fb331ec6bdb739d6e03f4c72f596b545702863db36919bdf34dce1ee1a3b0a17d9621c171e075e3cbb59c7dca0dba2f122bb182bda6d1d6e2567f351ada9347c6a493ab24a772a61990a370ed4c26badcc0fbb6484f5006670c2016a75f38fd66a54b189568a74eaef72b48d4e4258b7e3d29110c71982e29c4f5169d5ed7bfc5b9f891524b0524cafc0f6e9404b313726a6bf37a3923a6b3ce0b3adcf9291dafe9a100e5416484677394085ec4b15a2c3c36ee64df4d4fc7920406782801b72c0b481072750b96ff96a87eb44409825aefb1cef408c174e8638635d27db4a26c6bf2b825eb6af158a9900bec53f2be2b79cc8d70cff57066a28635c4819adaff3c016ec47d51335cd7e13fcbb8bba6d78c214fdbd5311152318c027cdcf5e06cb81c502a91175a7f676bdfc8e54ff7a0318b5e9fb0d06299d78e22ae59a1d7594303cc9532fccb583957a9601981b1481ce0738d5825cab9ba0a37b33e3d1efc09f2a67036a3b0a93a7224afad235e51c4842e132e8246aeb16a09029b05ecbf6ec837a1b8548505a41aeb740191c4f717d11c6a85bf2ff34d6113b0bfb3fb9690d98293e89c07ac2745b068bb61c12aae8ccba60ad4169b1e2737155abf743c21babd02e85781b485fa1893ccf907301993c7db99d6f5027fdd29ed331c771269111311663fb6a72c14a9a04156aba838f061c34a27ca7afd582a06fb003b1bcb3380b1eaa521bfa232453c6cce15788f00cb2647be6439bb2d288dc267c77771f6bb69b79d303e6a45da14c0da652c67066aeb0002d68216120b395fbcdde620b5f8cec589fbb380e2f01a7a64f3a0b8c01ba82c489dd3482b3b005ae1947135f750edf6f9bf0e2a461998572c268c2adc81aa9ecc9efd21a337328b4eb1769337e198b0dbfbe90fb47ff26087d91b391641b37da96035143a1cb9f75cf84d3c17698531295071961b091b2ebd29a5a116305837bd6f2a8cf9349f952fb0fa7f76092f4ba1dd43e3e601509514a62a539047f071a6a3bea0ce0ff898636005dc758ded83dc39ad3a0c455ff0e42a160f1c24ca530cf7569cb5255023dc6aebd2b840dd42afd13b11342188f44d096a549bbc9896dd9e92fc620a997cfca6b5682de766e31f102a29c87777d63a70f900d8f68a4880c0b1f59b2c27c78d5837361582979f10fc7ec3f234876e99a7b78bbac0f17cc819d31c1b3c347e024ef7e8a44c2215c86d16b23010b8d222be98aa74931c860ff2308864387a560b450af6807165ddfe28438ee12ae9e19507b199441730e9533856777c029df488ab56a8e2705418110fc5b27f6fa1a7c57bbe6f514903dfc7a1b5f869216dd2af7fec3800809e0c9a789798a856cdccd7890948bb4d8d5f893ff645d22d824f52c8393a28b20e89c0673ae32df7d152c4c133801ed4278474bac5cf75ad1d41a0054fa33cd67bb3135c5b7ab1e215f2e80d10319d69f1b34ac2e4850faf24f870ba6bfe2c201d464947af943f64694dad83d2382599adc9eb9d199df985c87de22f03793f258237ce4868aad93ee8a3cb21b3a0b61b0929f3c141771f329f050972ca717487ddcbc72755934f86284c7e063ff67a0c2a95a3336975aaad40278c4c774f7346bb204f29ff143e5e1b535703d0f075d3e521897be518d035629bdc03e1d84dcb8ce3da3e35154e525e73880a3b0673be421faaac79049a1d9157defeca544058debd2d386822b2b816dd2328b1d38cb22d973032a63d633c44539a949d6e18fe7e65eb1373345a363f83b8ed583ff5ecac90023514831abeb4f6c82742d6d79bc4072ec221223d19dae40112fddfa3a1009394d4e0f7a8ba86d370b00ed72e851532b18ce2cf1f60fc4d2334f1d4508ac6f879c74522c9ac23ff8aa3b193c1dde06dfac93618dfa45d88af42a1c81ba7936bc30172bbab8aa9306593d1fd25eb85b8c734c555dcefd7a0318471b53f5d238df9753b252e18b0a677d423e4244436eb30be90a9084a9cdd3247add614b047abf31cc136df13f1552060c271d3dafa319637d3bfa5ecbba851c567f773ebc7e93889d40b5231bf065850c4949b5ac95c2c1c0ce56db8b194c8703651af88f58b26fe43b989b4d613cf652787a8f427c6eeab03fae82e65d774195023edff1fc97aad1d560eac51da774acff150553beacf0b275ae8e9857df457ca903e6418912a072769722d5c7775fe7423731f1242320ff12fe19d90a110d6cb0f22629b76dcaa3a39fb1de7fc5e188bae52feae1b438bb3975961cc1e2df11e6e1ffd069bae7a381f8ab7306d86be931f04c450a5f31ea5f9841cd3c22842adf9ccc41d7b30a87213f724aa0a421850970b1f6fcdd05d0ea74b191f4e3430656f28ac3d5e9f55a8ce7591020cf63d396306f803ac8bad782820bf9414923419bae3f4c51eeedb1a3821a3fc917858dfdd176287c450bbd18b320fbd97323e0ce043e8366e5c71e0622b16229a6d39b829aa3005078a7c11c9afeedd8cccfdfb009f8301bad0a81856e2170c1c58472a3aacf0c47653f2fc2faa8a5647664fa35f75de85bdf3c76f04c2948368c248889de8ec126a6798b19101327c99d1c334944899d3a8a756f2ddfb01ad8163f62e4705cb6414cb0908e2a91274f7afa85424acd8f6809117339fd720da13cf5f2bad9a0f206108d1c9916ab612d26875ecb382b33a710b43f5dad637de0a9da1bf05f45abd2e5e219723ecdac08742d097bf5a856759d6037061e92f3d1219537973a1d0882667de1fe41815ef9eb4181fc54dc884f94103199d3516"
    EXPECTED_AUTH_SIG = bytes.fromhex("35690DB2D4983EB5C80BE375066B18B1297F66C70CD61BB2045608E74273D98366F35E77420FE32730F6D277458EEF1FE70223A156E72451375DC2293FEBED32")

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
        change_path="m/32'/133'/0'",
    ):
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

def test_sign_tx_v5_transparent_to_orchard_with_change(backend, scenario_navigator):
    TX_PREVOUT = "050000800a27a726b4d0d6c20000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01a0860100000000001976a91419650e98310b2cc27f00a9d0c4580386553da2e488ac000000"

    TX_STR = "050000800a27a726b4d0d6c2000000000000000001cf67287a7f4820dc2dd57503b3a5e940b4c1b322024cee5e8ffbece7f217f4bf000000006a473044022026aa0a495caadd31113fd067ad7e947d7e859e0f05ced80c7cced0bb3959ee87022052846a583ae9b67d6e47cb4f86d054848d987c00c08cbf333dbd46549df96f31012102749c3f99dd136601daa824ecf40ae144c1a7de432bf22dbb23c81c7b6077d431ffffffff000000027f6abc5384841cd9bc7e27ee61431d5a3b6999b0f953b36ceeb67c3fd18ce9803768e7c28954fec9791e472e02881cb6b2c3f6d744c4eeb0f248eef01f6fb53d306050373d1a6fb3c4bd05888e2a900c1c81948d0653c90ea957fd43afd3a3b18b6787b72f8d0dad4afe69a1d1a50686438c0246f07793c73583dcdc22456c05c2faaf0661ac0993c4f03bc6f396ed82de28ace166b922003c41117f7eed38330c60cfe0c8fe459fc53344bd278154b331d35e2e243665a41ea9cb5908f783159953ef6dae2ab240fbf9d329dc3d4ce92ec9c70588f698abc2feddd07a4cb2a0be91f50b347c07ca32e224fbbc1d9cbba2cb956466fa0b4570dfa4a32825b8fed0517bfd025bdd3aaa37aab60f2730f251a65fe52e20c2fd11d6d9714701f0abfc10576beef57f1198b194c902ebc1ef3e4b34fa6ac9bce472eda5cc55ef576173127bd6c5f55def93ef3e401c868731dcb187960abfdc8f2a7e5d9d57db363f3a9337b192be26a9e0271b1aa4f89090875f3f1a242d361cfeb5ba5ce9c885d5c190544b0256d6e8916b39e7dc463d0bca1b319479d6001bc4a37d75ade16b59823f16180b0a8c357f3791b48a41c6bcb8295773c3bc6286df42e067f186ab1a3d318122db44c8078aeb11d31282728a8207cc1f54239a02c23d99780b22f55baeaed7d2f71f2cff6177523ea496551ec7d2a325afab69b02b239929d101cc2862f063c5a5cec2756aeb981d45972235c0e2cf23596b4b36dc0196b37a4f60dbf0021e78fd92bb962d6a8154ea9c3924939cbce570309bc75bc768957dda0bfdd1264bf227ba183931ae7b13017cd36053c4b23916b50add78324e651159cb1b776d8e4f09ddf1ef745188d0dd175b47694a361b48be291b4eae6335508d5e3cdedceebb3627aaad7fa76c55f4522556fb54447eeac9a9a24753e34c13f3f531a903f5b668ca3fab010acf8d872c817fe06553f73748bbc301aeff3ab155176f7439f2fc48596c1124ad16f8783a59a90f61f75ec9166b59702c88cae7aac422e8d2ce5d34c277dc90fe4434b091e8125187ded0dbb32b6f92127b23910169aab39f405f522f452174cb4269ccf1ea910b9b35c8fad645e72705cc1ceaf136ea8222615a7cf3c4dcb8d2b0556558ce82968ad72c26805b9bd3edd1e1a56cab175ab20f2d9e70cb5bbca060ea594e13cdb70076279f2daa682b1a9ce8c102ea6504c18be633d23429b3625c42005fa15d4597632a422d852b786b80b97a198b58784c20e3d6f7a12562f9b6cefb1b8c30ebf231a6fd972ff25ca24c9a59f03842dbc62b9373e2cd6a6f0ca197a5a827bb0734771031e17cef9606ac592a340a5a21de0f6ad05117e3b25075e41a714615c7232aadf177281cfe1c462ef14856275b951219739629ab20ad22d7ae85ca116c9a338dab4f5132171a20f617022d8575ed5c6856000cfacbde054dd940f3060225ca56e397873c9d87fbd100c2e26680cfa31b669862e6f23633560e157826ca76cf7946d31b6769ce1f8c83f0618e2ac8c96c0c837108ad21f0046f08ce2d15b9f1956bb2c9773e4abded3b6a0c31af6faa2e20e522ca1aa9f3eaca64b8940c967fc4bb9719881bd3c5abfccf6f9d1cd838ec62b496b2c6e29824107674dfd732368f89f8a77d035e3db0531964352717e9f4633ec01cacaa7f462782ddc2ed78ac101a31bf101c81153314dcb29370b142460a5ded2b1e4b40e1b343b0217639578a60097df8ec6d94ae0513b08a2ce142c6ac5a9cc5411af71cbeb57245d6b3b51e773adddfdc6b10713b13bdaff505bfed6a8184e3f63482592349f947b75d75bdaeb5d28eac0b5113277f8c81864b2b0ae446423e4d5cc3388be1e67077cb4a09847940439f6eaef9501db5086e7acab01953e3ed00fd02944dd97f8b076843b489d552bcb51da1745ad22cb1219eadd1b62f3321e5e178f9b85d6b57ffc9e7b20905bfec8d37391c097d62d97a491131d1324461cbb2d932e487c3716b5e1032e530b7607344fb56217a568cd36c36b55c481aa6f0d0aa2f689bdd55fdd83a5f7a3155625513dc86cfaa5136a32cbe57e5ad69b1d00d1563fc6d781d819bb54661babae08bd8c2d7e966097612ecf7049e19901252bc6807dc6cb343d5b4360a39076c328c7952402ca51d0b7e4775d4d5109ffd98933c84d65daebc01f102a4ae76573390afa9ddb93e03002dbd3ac38d745ce2d3968478b2bb2784af3f91c7d25b3d687871f8338247dc65b1653f5dac66dd95c5775383a36beeab079ed29df204ecb5b534c1da9c05b203557ee9540ea5532f02e88cfeffffffffffae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82ffd601c96ee4fd56003946732f1f42e1c7138a839cde5b3a4d6a6a64f86772c3d102a0393d0c6d52e7f8bc265920382645044a0a3df4094c69a757b09e6aa0e90e4db2b269a5aad852afa0371e4cbfe5622558b6fe484e47367683a1912c53c27458695f210ae097008f62c87330174e546076388819aa5f5e26806f7af00fed57a6c3c825789839f7200b1867b3496c71938dfe58b965598c33f4d75e6d7891b6d0d3c0c4280855696a43c598ba462bc2f7a311f81a7da8c3b23b02f42dfe77b3379b773050ae6313b425754b1b52fd5d2684806ef7ebb136aa0426864ba7768a82b1df60cfd5d23a34af318d2f6fa6802fa8d0264632b4f4cc7e0a7541380124b888965dc1aa2f78e8939006f41c056439ea7dcd7002b931925540af006994b7bc48c2f99f57fa5b25a1fef0c75b926d10dc1c558bce7382e71071770cb3308b5072b796c90c358c9e0f9660df81ddbc8c81ac95ff23702701d0e94f8d70b65c9683d971c75410eb4cb12598a9b581578706b340fef420d895033209cda93849bf185a1d49ea8ff6b9a8082996acf95cb796fb39506b4a1d0998a25e689d00dbbb42501fb9d0ecea01123c19bba786a608eab05293960395e3e99390d0b058b87d4a3286051e24e593a25b7ce4e9268dcb23a8c4f2acfd6c869e299126d8c8e2f3e9d0bcb4ab75092a3668c986661724ceba2a1960249ffa54f1f57ca28e23df79d28c61999fcba3e386f5ef91e358346fa1e9d5c685088bbe57d046f7f6f83315697b2aa553e977df81f4bcb6c960f1f1c29f57ecef2a89ff1fefcf04e8722ad3c9df01534b0c342f2ba30469b7ef23ee864a4a650b6b8baf99c8363e8d3588e573412d6f1d5fc9365a453b041b10e577374cc23d8debb84b86a0529775e11fb8f95cc4db221a8c740952a798e665828396c5184dc4b87cec3bae00df6c1b30f2a2f6d10f30ef06c04282eed2dc1402d6f5545ccf69d51ae0512ad74446905d4b11fa25748f9a251b8b59613198577d7e8de64ef5d5c9b0613521d6593b50c951f21d8f94f29242d2bf44a7b6a6f87e60a45583be46c5d81162c28526d66b52ab7982c682baa2e5841450adad35e2a3401c43a199a9893643e9a6d78b30e4485bf95799b6301754cd479076f4ef132b6f943866863ea3dc08932b46e51e003025b37de6a040cde1017decaafa19b70ec7c333cf63876a4233bc0c166c586f427d788a72ae95696a06646c52b5c7d6749a208ba9d156d51d2c0622ca306d243af76b3af539f7883e5415523fc4da1b4248075b8efa6eb953684acec849fda96222e2b6c858861c010611f7f643ada34226c7f330b8fe1937a9a95dad6b5bf9ad12c0502a100d6f58a110eed5d8fbe4ce8147ff88f876f15e69abf9cd46c0f796b463d0e189cabb19d707edf06335d651902401ad7434183e0f29d3ff44df5c0f98a05676cf1310d86e83b320cface61a5311c194274f4c7811bc425959568134db83475a5c6377237ce73bf327280e4cf29ed227ca698cd6d666e3492bde1addb7a3fb85a2bc2b04403c7026f41eb3cde48ecd53fad0c1bbd3a262b1d37b4191d410869e7c35ca2871fffdf699ea6b36d8a84825fb965d828baa49a5481575baf0d93c50649c666c54fa6393cf83cfbd077c55e0b1a58adf76bd6ff79f136275e3c1b819cf0c3e5d62aa21fdab86906a74007f383e3959419a777fd858ab52fa354a64e2c9dd9485e39bffc7cb23e40e1a9e66df04949848794d77a1d52f67a56a5349414320e964462376f47cc9d8ca815aa0d7b2ddda46503d2f6febf656fcae31d2a8e6ba11ee0a507c3362fd2f9ef4ba75b915442cf78425fc57b410cb434c9bc6e265f93ec07d0d238ab8cc4a3ca029b15da1a8b40a141f9cc1f9b93600c7a9a96d4c4bd7d4fa1df4cb12b794406066574bda0807b38e0742a97db04c075f5a200786cef54f05ec3a1f7bb149208d471ff3da787df2edc715210721c8a25e92b20c60da250f64279d8bf5d59be320990704653a31d6b04f422b795ffd8df2f211ee0f32407582bbe056dbe829a5e7bed99377b2fdba0a50156cd48e53f0dde0301b696b5ac410309a73b82d224d6611d4182bec06152d7aa0c41d60a2a3e17bda60d08328c616deee31e125dd5642a90753f57e2f24618f670b211c08217f79595153164647c6dcb8881e2b0e7ed0757d4705943502d95da5ea70b398f3ef104c6263efc31e5fe1776461d19d9cf9ec1459d61e2b161055f283b0a51da802882ae6cc57d3d45c441d718335d7c6c25787cdbb72a85fffb2358aea2b3b79642238fbfc84ad0097e4c9fc305af52624bf8bd111b121dc2f162767c67e4bace149309e3701eb93b38ea8e7f12736dcc748e4f7580444e26d304b2297891b3a55120c35a21fbece61558210f0f527e40c5624f5ef84ad3a1071392790cdfdbbb28242848ab37b72e82cf31d55d20c2899ad60b77320225597c8526a32d55b3b89c0ddd19daec0997a2dddb0b084b19620b83dd535ca42724ac4558b2b041ff807a1fe5478ce75d00589e5fb9c2ad61a80c6acf4d4a2b441dd269cec15d7159e4e30087f18aa03c5ed85f741ed5018b800c4122e1d4a0bc01cf930fbd5dff96132e3f066d7fcaaa0b4241d6881e49cd981c2060d93c9dadf938129fb9daa0d4c63f072d688025c35aaa4af6068f439eb25c2b0744e8e60218782902b9685ff788090650fe7a5af976c06dd69e78dbb2467bc6bd6c74f9aff70c97bf832e98471caa22155fe4b209941056ff2d5243e0cbf2bf1ae442ed1ca32f59ac6c0ebdd29e9212cf60f6388a857d43c6b104331d752c9d47a228fc720f38b76d647a8d25fae63bc7609bd3f2f2e0763773536193cc0c1a744c06fbc9ef00a078d043dddb75d538e954f385bf651b6d905a6810f5d907396502592737eb94bdfaa801bef2e4c431dba6eebdb2e175fa0d81638085d2055b5965db03eb91ce8eb0ec6bb2eaf6e30100a8c2931b7974e4be35b2101610c756f617e0d97ecb162edc6d5a66e7e0821e75be081f5f357ae59ced5443059792ccaf5e755653971a0700966fd4b61c2b31e636da602f11abe3149b818346d9ccbfb67957325e9f2ff5e2a138b125fcaf11e7be87bbb6532503e66b3282e57c3b2ce08e53fa18aed29072381b9f6ea7f33e3c99b18ed16c29ea60a104caf1bb7f03466bcae1fd2f1064830486c114056e3d85779d106be9cc2445dc2d838f9604b4376de03c7ee3c239e6f5a4dd66c18d20c5e25944b07ec36487444bc9999aa81c71263331c97e78489a3ec83a6413391c657069f92db3fdd3ef853dcb64790f1c6a5fb3ee22e085a2b56b40e39b396c0509270955b29f7361fa380d35aede0f727b6edeee04b858f9649819a071f1483f5dd2c049265253d679755194ca8255d1994498b9b66fade63f90653383390e379fbaae968e93f562d992da53298405478a2b316568872020a4013f869e553d2a795890461b8ad4d51174ad07417fb6a6b7531668ea8486aeceffe70bcc1e92136698af8693f7a4ca3cd7b74e8ed6c9d4757a25b7d14d8ec58f1ad47910a81826627d2e8d77988aaa93078d1e9b3d8993042375386f8696f1c1e848fcd9623924b38161abc682d908a9544140922c04ce01035f0deab686cd0819ad73a0b47209f1391b47d19bda9b8fb4ea00763e8725497cd7a5c3647cd538a11f9fca66ab299c709bc9b3aaa3629c77ce10e864528ed43e5eb5c7bd24ff4060ed2d43af033df2e2ed4cf05974d96a9b8f575d71ec69e2a08e09d7749c5909f424dad9fcdb2af7633aac7ba8a66c3cfc486043f4c0d50e9c0a0d43fc51c3c981f6860ba32d178e57717f47eb7297d2a394b90baeea5d0475766c498eb2ba08b17a4c19c90b33cd7657770354272afc8f6c1180d2e515a05a48505060ba8cc7b805f0b8fd532389f65f60f30eb2cfcba41a1e306c1ba07c054fba4832ee64809db955ed83ad2226487f03be1b9ca65dc8490ee690cc62d68ece8e82d7525d0a7fa27169c7b30758a34787f373245b8e1f191a3019481b919656f8463a69ce902c31860eed1c2c40a5444f8e93e19e298ef09d1814fa5ad2857e79ba452d2490ccd95804888a2a6774f048c03dd4197a76dcb101b6cbbe9652bedf7ceccd7a95866bfbe3a0fa24f2d803e7caed0d532c740939f2c77aad76ad736d53975ffa33458f5c2cdf841bf6ef3a9ec050b7c5703043f008d7c9fc052d74051f609ebdd628dec89e289d2288f281421a4de1d928140098100f4fe0eabcab8c8aecccff0099cea303f55d37d6f4e18362b57be0228ece33a0569cb49b29c72d5720a3a22126aa0507dcb8269869ee776d1d7391024f611f0df244cb6828854327fe34ffcfedaf900036d43e6f9e1074f2c35a3ced6db70223ac31f8fcc91f2e5e86df166cf904594f81ce346dc32e88d9de6104dc021d36e381d65c1a0baa13810148fb046b76b156c3f2326613b809a40d92c2cbbb98de4ae075d29258ec792c8c3279479bcd368c3e2724d487adf4449df50bb01c45ee1f0fdf8d79fa530fac72a312094c01aa21d3f621e38a8ad8c969e53059e7c83e7bc18d23931179470e3de7a6ae3821ad6bb6721823ec2f956ba2632fe46dea3c2b6f8208bcab65d9ff852f8ecb1b20523b777d1a03eea11a53215cca4f3382b9db1981e5b1a181618ec805eb6dd6e5c5a3950f0b53b819e393b6e0e648734dfe61522ac619ddfe8a9856bbf96f741d78b9348214402f76c3d1c016a9817e1bc30a7ee970f38af8eee71c78aea7e6c03cb4537d13f32ff8fb7df4b4a87df09830ab01a5bb3f966ac5ee3b90d221da8e59c579433dfb8359f22a6f7a832d51b2e8ac7e744c267114c962767f1a6ceb5628075c9f2e7c28aba5d44acd86300a3023a369ffe26ee617d7f29fcb673bf1b24dc50c9c2b8ac58b2dbcd8d551420f5d38b0a344204a904770c1d46fa19470fd820f540b03281451368cfb1858bf6cabd26b258efdf95e4ef7ec0d30c61207dc3efdbef52926675b0bdf451fc0898aa13fe5b0ac2722a3b8e3b8ca855520cc86813a68530b51280171d19ad5be1971c1271cce72675bb647c29e06bfcffac7d567e7c32b18fe9c0aa3d77e39ff0aa522ccc61bcf93efd95a7ffdb507fc0013612f54b59f0aa213f23c56eafa35b029c447f7f277a32c6b1c8e43bec5ce78b1b519df449426bcca2bb305f5038b1535893f928a436ac9b52f59f32719acd1b1f1e7420ac22f555ee2d401b1f661cfe33267279b7d56e9e00e77b2dbc281e55816f1fb85e811bc622643fa5b8429399cd2b8ad98b5f6eacac0e5c7527c33a3202a30d6428012aabcb2a8707b1b5203aeb0aa825e92bae690a98837f1fcc43171fd09c335a83c901b366937b6e22d619d7c512a404fa81e029f1888a0cfcec44d3810f5f4d5301353aa4eca0df353ae3228e7d3599492e63bc1a88ffc7ba38184f3a99fa5e41b0305643cf3076ed6213d2447d592bfb6c322a2639adfbe3de63ed63625fa6a0ed7d86f63f12667e566a2963d4416d71fa1df28168b9f6780eccf5f4fdd2cf90134d8d9428bc88c57b4210feec012852b1465aa3356145aafbd923b0d2230be2e38ee7ed81d780cdfe9c4d231bcd353363606fb71af11084c11c1a4d42775b619ccbbb901d07a3974ce2cc1a62048b93f6eae01f443846b553cc09e9d71ebfb0af8fec07e8ed0a07227d436f9bbfd3e4973f3a8298f2d7155be7c008fd5bc060a6f56b3fa345df9dc76556c35f739130525669d8600ccdadf75a3e66a25d54b2b8c6445519005869d09916ae8cd6a2ac83ec0d4bdb8d35324f887b999232fe217d31c10da5eabd3f802dd1807f32623f3b382e6feba68710929afa1950d6e121b5a3350bafbad12af654604cb475cb9c47a7d71aca67046c1c0016c1076766a0c985cdb6404321620923992916a5ee330ff0284a8161cdc1f47cd792102b0f43da5864c3283657d80a28c68345f6e0de2999ac680bc6eec43f7aecf3d174fe814b38756fdb1b23638d7de036ffb8d694601576d0a115e9458c0ebbe3880015631fcd91a2f359dd0f331192edd867a58a0c5c459ba50195eb52d99aa46bcaa41170a9013411989fc58905a5a4882da60d969284ec16c4665bee3f8316a2d910a19a8c0c478089fd95e99de3ceb4d0e04e527b880cf20f3fa82fcf223176900dc02880f41eba5fea8f78e57d5cc376cc9748fc26eefda289bc9dec84f0f3cb6fb3bad85ff98d7433352bd306915bd9a7455d310f49fd9640fa4dddc0cfac99a1c2cb11553c9b6ab3134b6373fc24620dc411a188025de02b313d09ce5908340970f9bfba3036050167f120aef33adf6cd40870c52ab6d74b3dcb4842b21b63db80111464fd37d6734c819835b2570007f6daabefb82a0c2312b5082847a57d1c212689317012e19dbdd3a1a2890bdd017186f14f3c4f5f09e383dcd5bd74a0c4c12019e9c35b65504718745b9cf39acb9d423646ede4c3954450f7f78794b7fad211b4dfae37381d00fec6404abcaa74fc8fd0412bb45ff8f5fdb65efd042201a0a29e10b92cbcb903decc088ac86a48d8314ddb2c4de495cc52ed960e5c36da833e965c070146162f9624a9d03397cf21d1e4f1d821b8905e77ef8be6ce6e7e2065d12a00039c5f2f3a1f2aa82c2b3ef5bbc0374ac86bedc3705c519ae4335e8392cfc90b987ca8343e05038cea202b969168be1a7d3a851c693f7b57dfca39c043699238cfb3a114a13b97bb84db29fa273d83013d5465abe2034e457c655b727abd12c087a1b545e526b015a70794b2ba940308af3a0150d93f5330206fb2926841bc21319f6b81cbb5a9fc1469f131a413486aa73189892055db898a86a883e1b034c2c91a14575bc1b9e2315391b844ce342011d4b36514910b92aa215892bf607793a05a1068bf18216c7ecf269fcf971cfa636d4701d68100f472dc9d6114c04c53ac2f342c21cb81dd86895e9571859303cd75b815b461306ea7fae8d05feaaf7c7c1ff6cbf7e14f3187338bcec7f7227b66a525ea6f877a7640ba1e10f956e466356969e58cf234f72fb03b7951cf1797c388c0d93ae4b8b052dd6953d7a93189da62948c1ebee2aa922f5186be667bc6d9109b6bdfc1650a693a483052357eea0cd1c82f18acb3f57aedb9796d1129202d7511bcf994f9b1675652b2dc03cea9324b839365ea4f56e56aa2951dcd86f9ea8b6fd426a5c93ffb7dc3516f6207f283330ef8b8fdb74ad6cd697344595930d554f1fdc2fb31f0435c2263ce6573dd1fbdfd180faeab8077b06a2c4ef7b3f5f28bc0e8f8eff229ee980de0666a8c1b042e361a8672da6254eae9fc0f9a25958777647b43607ef27a3579f3ff47cb50db146dca1d7d107ac7fbfb587649d8d79dcc6be410736b8a53b0a2809589c62c91e5e909bd273df2d6ce28bf683b24e5a36b3f5b3f01384d9746e0724bb41556801df134b6f35cf98bac176e94f0a4f85f0a2c7686c69812b37590b2555ecf087efabdceec19532bd77e007e9b21a6db4c9f7f2e13e81c23b0aec8c0111bfc58a67aab6ed9aac503e101d01fda19651ea2b011f8b2bf7fdcc313d832007dac399eeb38d41578f2b3aba32c2e13529886948ccd3ae079c9cf29a628022ec1a6a37afd387c001b3abeb39d04f9d01ea946b94817718dd8499a72ae82618bfb44109f89cf7e15ea949b210e6cfda0b624047ce551d4b16702927be151531be2cac4bb64f1eff7b74e63c434e055b174d6177eff3c486cdb19d0372292f08f2ce3f8c8704f42b1ae5cd00a82d3696e618533b4ab5d023af36f59f73f92a14d992f48c2be68cbc9e12d37fe05c0cd33d48934181433f495c6813e9c2787028e809608da2049f08b7ea991f8f6376b644dd788fd000226600d567d7adbf19300856edc972fd73473731033408936c1125e3b9d2c432fb7871bc77b5566ac408e73ad43e68311001a7b952f64980a5b99eaecffb24c0f5005c8958189ec595336dc8c48ddcbad6bbfa7b4ec9225190806fb8217e4f79bdb78d4e00751a2124186f8c05d33ce3307dc506f758e90cceb96b1fd9807da35c542eb3efa88b4dce19946697511adc91c6075bb519e217996b85b395cda378861fbaa57e9b91d56f07bc9dceaef9c8eafeb48cfcfc61104cf9839ce61414d2517b4cd3b13ca9761b22a227aed99d246418f5627770905ee3722e22619f17d64e02c1643bf689931715adad938c7d30e3b9597f01d3cc993ebe6d4567a9b12a217c1d793bb0aeb63b2bf8bf446fbae05a647e054f2d5557967e6788eb1eaa448bdd1113a08b6c423103553873ca1ffd1ba3accc6d324a70ba5b6de0a500dde590c0246ff2c0059b663a12f232bc88a42a5ee08d3811d672eec2b6da0048488afb70844b4799543edc2ba68771f16cb879e89be99421c2b34125512ec5f5582ad4b259e39c221b99b80e0e1ef1d35623ad9a9ce0182e7dd82ee3141f3861bd7f286cf1ebc1ac2c28700f77ab024b8eb4c79e33d165a7aa54eb16507566b4b60678d39ffb9e12e87f9b249082591d5063894f3d2dc9ce091fcbe8c8d850b627dbafe54aea8a8bbcd1240d1fed0375365d205c31606c64628d2a2ab2b306c9331da1a4c734298f5a405330d5c90da83e90b6a4b0bd256f9b651395272f6fa4d9abb157641fb5553084f80e039a81e315da3662b8c9326280ecf951e878519a4ffdcc5052f16917ea46273e398e853fa9010f2ca55cee8c6e93cce1ef15a49cbc04453815d1e89ffe180601e4d8f1cae23c19be6808e6519224bf05d50938d8077aec8cca7c6eed4ab90707a5afa6a88dff96fe8f04761b0d5a149241f2776597fbca50065231ea296160311a8585a14ea2079ee7371346c9f1ccc93237f8850ac68631fb25d8ba45497c08baa7d742057da94433d64289f903f43acab65949f10727c2e640b1d2a46ea5370bead55a5e295c6df268b9338662c785d089330e1fff30afaabf4741095c840bc6b444d5a5ee8915fb37a319159996fbcf2712758cbb34bb61880cedce54db2b732a9c64e4da0f408aab4d1fd806bbed9c29e5cb3b5514254889ff1cb70c1d16ae42b3f09a0a51fb9d2def52442595664f365b96b2eadac9ce3a3f52e5e92713fcffa49d2e8097a60e0e8677541d95b72875b83a722a2c4ca26ddbb75f87c1277d9936e416dcb0578b1e14a9f3497aa92d22e5a1ff159d67059665bf0fd33d004b0e8da9be5e7d704e5998d574c836e4f8f204220e2b432eeb78c009c303f81ab6bcdfaff154bacb7476de29c7ea890cfda8f0a781dcc22c6f726d04354dac228d90645804c62a12ac6c888a0dfc407d80f0b9c5cb9c84b9b738c001a61c0c21177919dccffca9e4864372932444dcdde8defa3dc240b7f93f248b3e4d38058879f371cbb18c4b42f557c3c9020fc78f27c5831da01be5bdcdf014b283bbb5b0924bad53bdc75a043db0436d30c14d68ed6dfb53682e9563ad88a25c0a92f8bc2453a91fe66d6830a932e9bb256d44d6250f3a31420e02d964afb5dab49a6a0f31c4f86b300d47559cb9043903533a330dde59f339848a9b0894654859238ca6ac967c0dcef2607ed97ebba030f4ac5acc32a2242f1ca708f009b2693050f322a6dec2629792ef8095ed7e1e9326216639e96df691d0f5b9e4e662cd9b0465a11feb9d743c2ba12072b09fd0e64976c8a14391cd22bfbd83dc138db1e1ebbba3ec6afb3033e9072336762fe8ed7f620041104939935f391a15b618f68ba163149a9a14e070b069a7fee1a39ffd8dabb3e0181690e59f2dc42094f5fdbf140c19d7226726765b0c78b2fc8e5c251668a46d5bc000fa8cfb67e1c5e8740dbc58983860667f693de3945e1234faddbabd6b6d00a6d382b06e4e2ac44acf0dcd64227b177d91b199f3cf81369283faa048c9dba46cb0e30d11ea966c96e2ceb213b96256c73adacae8e2c35be83540194d881785f62bebc82bef99867ea2b88e79994ad9acfd055e4c8f00138a3b3cad33e1e8ce4514dcf5672e5530020e81946f8362c273b6e99bba893ad86fac952499c40b1913663cdafe693b17b7b5d9be1c2fd686c6eb9841ada5d0aeedb5e9ba23dc3f07d048100a55e41c22790bfb8880bf15abb781a4cc8adf640c412c1fd7efcefcbf828c373e354fb28a3bffaec7f3858e4fb1ebf41857e0591048f71aa5f91d146462e3a3b1ada5aed5b68e20f3c60c1c86efb9ce3b230a3d7b6a08f332726a340d01424643c03e6a18a07f9a0aeb1c80f805383b088944aaba15d4dd7bff0f5de77e59cb8d3ee13b19dc36a7783414eaf9a0b703eac932d6127471f14ce12c5e76e451980ed2e5395c0d2101d72c3039587100e75de1658fc18daf85290b54665918b38ac1af925bef16417cc5c03a12dc6bccf5259043080c134ce4ad5dfe8dae72a53c3b5ae2930876b741f6cc1a1ca520e82feb446bf496d33854f93292974d6f02ad799a65d23fff0b550e5c29c4e3d2854c5897a948935502806ecc686f733d960f306e6a51080fb0c699870c"
    EXPECTED_AUTH_SIG = bytes.fromhex("35690DB2D4983EB5C80BE375066B18B1297F66C70CD61BB2045608E74273D98366F35E77420FE32730F6D277458EEF1FE70223A156E72451375DC2293FEBED32")

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
        change_path="m/32'/133'/0'",
    ):
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
    TX_STR = "050000800a27a726b4d0d6c2000000000000000000000000020ce5eae9c123a3373634630e258b5e534b3e7c6148ca5a6c04c61bbfa76663b0d68cef8d52a164d092d8bd4a616458187f7703ce6ce5ee9ded3fde2df4c569127066f527f7fe9c4ec6d4c57bf76d6851db115b60d707a2e49b12a92d0248b7079db7163d3fa5a001ba00b42c73589b9791682089f2ef0a14f4ea0d7790cf1e01b8734861bcf115a70efbcb60f711782e71a8ebc0e5ebc1a7b9f97e1c20f5c22e2e90cfc9aea8db3cd1a2ba6f05d5776f98f9f4f88aba54edb4f5726e9b83b48b6c32bba462fedcc4f7169f785bbc88bb1d99a393f9548b9bce5648c802b993a4525fc75d4cbd4765a841bd8ea6ff745db31ec35f53924049b5246dfc34f6f4f2cd222ff54cd895d7d040bc97a2d8546901ea4ff93f7b09c704329cd621c136889b2f76fe2cc0bcbf23683e81ff7b010fc549ac82773a05d5684482fe9d18408b51656cfe4bb7e7807de829f41c43f26c92f9029e737642c3b3ef0c78c44ee29f0412591603774de7d60096d8e3de1f2635858fcd3c4b9da1c48c287c9a1dc82731e4582db0c9320935b5d10d40c76ab1a17126876c8426f3f007c9e5f7e4b3f52fd4457dc12dfdbc9e2929f362c5f31aa1922bb7aa9f3a988e5f2d86c2b45b0762cae8a2788df8f97766347a65b57fbf2e5699d16bd9a534d3efb8b0e7ccf903f366dab7c8b79f1e7e6df4051ec617e73c7c90caf9ddec1933f3db3d0fbce8dd46ac2d5b9c405c517f14b26f7f24800757ca71d7efb7cc59e46723400e5755b7c87618c97d1367218705121cafb95066caf710e1edf4f7eadba33518e950ae6dfec59c276cc76fbace4bf09ba248e831484c5fc87a1565563727f1f17efdd0a3a498747a867c033c013d3989170bcc95c36a94ad0ab0bfa48623dd124009abbad78251eb4e884a6446938240d025ea877416442cba30a78871ed2baf0af149c15306171f88e2dfb7dc4d0b555f0636bee0d97c9a7afd1e40f4a04bd4c39fa1b307717ce1af12ade0598579e9121a61d6195c58c952b18e1a014df59f729b40283438235bf3795cfffb3ae4fd4c5e28ad5034e2565e4ad326e72458a799cc34f11226fa19ae7b68f1aaf0e1495a6f9b8b41ef2d6b2af71372725172043233b519c1363d0648dda6fc5154a882cc717524d93e7c3c1a88eb3f897cda9bf68454c33f627e0150f974f22af9cd961d04ebc9036bc895fc3ea087e60269ff25114682610a6b0d716f191fbf2acf767d2de63de4b95a0047172d229822aa14a6bffe3405ab48f4e8d14f27c5b286be6c4e95f2a00e5abee185cf8de2955a4298f602e4bcf508f55a68cc6c79a5379dda08cab1fec7f6280ddc203d51b8edd935c9445d9c808d2e53585bc1eeaebf5823c9a5e70eb05b12b35968123a64513c8bf026ae9e1f8c583c3a7807c785632475c220cb9f02316004c1d6a76906f5de4a4f63dcb8777f68a1a4c6f2be9a0094814e13cf6916da676168a3b924e4c043f1c868069ace284843795f0d83ff10bd763ece39246b5ab27fc67c86ec2f5320415f6489a910a72879a92eb9fa832eed9cb6f71cc24fadf4ed44496f706cf1c21ed78046fce7ad3a01b9b17050e587a7daf6a41ef2134c1bc2c1fe16deaba223e227505c7b0491fa6fbc7baf22017c8726569152dde1b735aed3b786d296825b3cb9c074db032be356ab8151a5f01209e53cdf107c9ad0c1b2152209b77aee5a58759ad670d440602e8852336a53dda64eeef8751243afd4052d564bbda0e69c5f66af4ac2d13740f788bb835de948b34b193e8d2731d7abb1e79de14e088c49b007283857fd6b127c3e7c5c585c616a968fd18895988a572fc02d2e859dd584f9fa1ed872794cf349f543f1a3e3516371fddc2a7f294c5c1dce2f35b1fd6e3ca23f8baebca46c1042def754f639f63073d410e8d46fb22a9cf3e8ed46144f78de1f53b9e773d46b9ce22e7887b7d3adcc791e797248e30ca9b950399f9dfb9a5c6bad17882f74e4c4ab21cc52dd6b1e4e8a81edc96fe06710e17fcaad305d94bb384a8c92858da56539745c23e29b33e0bad34599df32bacf36aa29c7b0446e1b669358c5da0c065c0313bd67dcbfe6a68f5aae445b168f95436874e18be427a78dce3e42f463045fd00197bdbd686adc41802fc558a1de5e195542deb4096374c6fa91ab7c51b798a863fd17f0ada698de32cf5d544d90c09baf321b301923172c05ed37d0ce897cd69922ac249175c1e5e0e718ba94390a7fbe9d74dc128f391595899a3553339b9fe083b7e298091fb0c6d8a813b748f92ecd4d0767efb694d6a230181801226d7351b203204e000000000000c5e1408579e67cf16b5d19479408fa035a7db4fe3060123d139eba8523bc9633fd601cb1c6ac6adfd1ab23d5cc53be49ca5d57e49d3150eb71e44f5e79e55eb5a65dac2cad43cb8541b46a914d2bf2dbf884d9522a81f8284b8e60424b56003f4a6334e2e01c1aa1c5c09405c1f38bd79b50380d271d3aad5c8e9463c9de65171b32a72e88000d724f4494538567e2247ad0fbb160489a416f1d4ad4ec902c669a6bac164b66513b83410dc7f12f1f300787ade1232acf377337f307f331b5acdca8bf3f935eb3b5e9f1aa63b2d03e0bd94cfde2b9d69847250d3ee7cf2ec0a381fc06ccc1b3597df2dad79198ec810360a1af8ffe914a6839005318cd7686bbd9e4a711d3aaff293da026682851da28144d09a2ee513530513ac165837639984f3d86a084692dd684c8bb2dcedbe87c67c71a4b8c60fa09ec563abf3d828726f0d22d72c8402e894be5676665bffc6ead20a2018832e1c6ecad2f9e19f16a511c52190ab94db65ca3c1186b0c736d24ad2f459e2c48cb31db02336b09487140bc300a3bea1047179792a56e382c0b5d9128f66b0b058ea7e1d7c153ef94fbae2c0a9678c315eb67f8f4f5f93d388e0ad79b4e55ca58f92716d861efdd23513ea3e494113c71598e9b555a511e973fa53c7de7891e6c520586d67bb12b276cba2c8423cf948fe184e88feb2afac3a8783eb5c5d9b6fdb9619cb83da8d69fa5d7e7b21affb64f21b9c7caf511c4792a46d3a275ccd911423efb7f098aca4b683e8152bc8b6c347642e1bae9bbdc9a5260a6b66a98e661ae4ed82ce884d1a752f4d79c1da619b46a9f903ba5ac3d930223c3aa526874d29db4b4573d947244b327435f05f94bd33d8fb303500eb1f531d9ad5a6e777e81b6645f9add7a6383dd913fc80b75798e9c20158a31adf6765b64105cb7a7c217273b7d4e6dda3aa2fa658e5e9fd05e0c430f1069587106b1230a518b0145be5ba2a82f602864beb7a9da761f3b82ef183f164b6e0f6c061b899b3b6bd209e8f33a3cb8280a7cfd7d35356b803d78bfac5918d74630a98f6a3b64c52ee8e54196dd59c4d1780d89c52a67c4cc1937728b99af7aebfe5f08b8fb9aeaa5868345678669173b1d531f401bf10afe3bf814eea3ec0e3d19bc584f7c60eef532a315b7aa315b607bf7c630da904cf60a267eb99f20a6dcd59b2c9ae93f34cccb247034aa61e5e4d1ff4142fdf2a912201c178d8217777e5d3462e489dcbb7b8ea3c3c987dd26b44bfc21fe9d73714baff9dfc46e84579a5c8ed432b53527717d87ed2a1af87e1fd98e096aaf41efb3b0bf55c9641a971ff1614ff66bd8c24881e7da315e77d85787001f143a6860221514e2f96e2215bacc9712980017227375f79f847ff8c8f61df7e2c3e1bbb5ef9b4476e118c21a6e6dff8511eb1633a7db7f34e4759cf7e2db58831df5822dc48968bd7c55793dc892bba846e1babf7614d88d2484e1dfb56227331a8bbb5687aecd7936a9f2423a30adf0765c16e83dac96436877e795f5e8dc32b53ee449ada220e4f8496d129c4805bc179f8e2f05a533b9931963b5c9cbb3bd034f96ce5319c67d5eca88379df9524cb7def959e487fbfe3d9b09c5668b9cea25912c42e9066ccf41325eeadf789c0e13e31a420b67092a43ae50cd5aa86620ae3e94f31ea92f9b04384e4c1e4b6046b379350785ebf0a3f9c333fa48d76542979286cde8be5db513b77e189949637bc93b410823db7d21ed7dc05a1ad64619a99a0cd2c02383e70a55bffd5ab7e2762f17f5944410147db6fa3e44ceff56fa69bbec9819356d1134beb2df32e5f0c1b7a8172fbfc8de817435c5b828e7d632709b14bee68465f194c792588ce28bb0c76984f0d5469fd276ab34b16e4c3a05e5899bb081b5b7b7cc4ebbad24f0c6cb9dfc79bcac3be2cf44a69c4f6e4773d3e24ce4253e1ba0ddc8b125c7086535d73177f981a1c0f72672354432f17c0940ff5d936ed43d8fd618543cafa37a85b0ed757b6673e90ee0b19ce32a424511efbe12fe8e6ca4a3601f5609853d36f176f76e8a2fc14b936cbfb46daa7825dae85ce2ee674732c18c0f5877cd653b0e3842e949ddc990d41842dad8a9b93e8b18112f7e01352563cf5bc66647344101c7332bd6869d25cbe1ac29fae9454ccf4cadb333096734f097da0048eee783b28ca8450bf38ce1edaae243e103d0684977fbec6d388bbff3228a287af9b8d8ce1bf6c634b55fdcb5eb75d78fd7840972b2c432143f7b104fba41c3d18128892a2ed98d60c3c83fff9a97c39e81d3d8b95f27a20f606f1172e639f20fd57eeb05c45b40f4464ab6ea7472b36f91007d2a8d8884a37e6f0e283c3f2c07fcdc02a62bcb8b77c89ae79f60bff4460a69a674d84a72522ebe963f9f5b9f8ea95399578b810de3f264f113d218705f371950cb7cb2813020349122ca26715502a8c7a3e8ffe170b4961c88c2929ee0b6132f7edf01b9b92fd403573e12729182b49ab1f2c8d08ddfd6e4e80316b0894e2ee4590297e5718b501062d989431314e07cfcf7742bb20e2b9371fb5f4c69da8798dcf4e51ddadbf108cf6e16054ef40b8ba2839c46d4163d3f286f44b1b9b24f7f958c7cc7d48a6718aac24fdb889990ab44861ccd98d71ec797f1be0c335bd063aebbf769d7e20f0b1279130b63c0c6a1ca5ab3ed713e4565a6c163ccccfa1ef602c2e41e3ff43723d1381d6c832597c95604bc3aaf439af3e01bf5c1398ff3c5ae5d672379d29d215a8ee7b18e55f8dea97701b35ed78c9bd9a093b5d85e3217c70bf61a4d248a10b46252b539afabd83ddc8d9943dbaf591146a0ea7796ec916435f2a4f2d77e00e0574c2e44f6b6d026d64d19cc2b5426c369fba7e6b9563a78b3ac775756b335829ed089dbdd11b4a0aaf7557a472b1119c5bc23b29c53bff93eaee748a8431ce5f66c7956e54be51967d797255499e7acd8596df7f47930d4675b5530b04612c8935f5e958daf4eeb14be08c4679d5fd207d4784063ae03e936bbb77534a512ded8ad550de033af4562b0f9ec6140c1b75f90618cd8cda4a2e865672538760be0cb8f32fd8fab50b61c3e04605f1a304d37be81ce79bd3996763a628ebccc08ac510733d49dff038a0fc5dc8e73c03c2c5598e6ccf836f5b15bfab5f3acb93ca3b0610112ca7d906b9e8774b918d40c7cf18694475961a971c6daec9106b30adc78b4a5b23a96d0a6c03aeea9bf21b7487ca99b40a68918299a3868e3a2e7037559fb13a4d094fcac4dbb70ca603f591b490557ce1baf061276bdf78934d23733c36c1883625a6caa53a3945c0d3289a6134798fb60982c82671899c1c2593f533c54f23e8187da694098789e8305577d4442527330ed5b44e0320b2d53970a562ca1e82cd0388b76d36a398bbf0972956d8f4e036e5940fb58f2a2d7fbd3178026c82cefaa15d9ddd8c1b2f344c5fa87a10505924e110958cad91726396114db244273b45c000d85a2c8f2331c39680a19bdad1ce73790ae5bd206e75e042cb97c2ea1cb32ecdbbed23a9454d28bea8d51cd4fe3f859fd3e2bccd58ee8ff18f943d44ceae9a776df229fd9dfc2688a2f522228fa5a811922588e2aa5324823642ab39606df4d88f6da7c86531c3e5022534b8293d852f9b79d8f92bda3e909a1d4b2b08035f9c1d947451f5f09af16447e0d48e4dbe0891219c64f9260f0388a04f1902966dcfb3c644ccfe8b60551281f3e85410dcfecfce32dcf0febc20ca6bec95c27961130666b88bf1ae3cffd257a49b61d63a7dee703e3401d557d237003d7897eb3548080e4cc8388253093064328c32688114299f64c6e9fcb290410de2bb33c6cd78244466f82db4f8b2762370e234d29489fe6fdfa6c2910b22b8846c080027209a32fd97a5eee7b5db915dd13f058448834172cc0e76e1bc93ca0b80623795844d8f3ac04be811882108cfed4486fc9a70d243904d7b0eed714078b75abe662d9b14a4aaa38c5b481a43d5af6ef566b649ccb7c1c5ec1f37228227add26dbf6c9ae438ad38433b18f7341ee3248337ae29ed003342e4df01c0c1ed598f21712adf401dd587d75ad18c4105d27dfd3a685479c713bf3bc61d615884f28ebaa401142093829fde7747d86ad795414bfd8b539e56b41c39142ef3e27c3471efc97d5d0622e5bd1d204af74a9a8e1df5c33478d5b8bf41e51f8a70dfdddaee215b783ae99baa705e034ccfa54a36c5a04321760caaa267b7c22bc29d9df101c1dd7f806c14ea19aa0911005a2e2126a1197b82c90483b2dc3ed331e5d6f2c6becc15daa2627c7c0e638c77e04c951d3648b675e50b72b4897f4ff3a4aea7f1f58c2be157a818631e991932dc2941293effc63ba24ea46fc33e06916d4efe9278ca1232e83dde0a0e3a275e3c3aab49cf35f84807ff1d88774cc8018669a440760c262cada36f227f7d47024b7641322b7e7c2f982d72cb1473d29279b543275ad7886ead00d594c9820c0e667bf3badf9a90a0ad2403d203ed56925035990136fb0dd5f28cf3c4273b2970006d26454ee314d92696829f2a4db931d5e8f422c492c6f6ef23e4395ab83eda3a089ebff1715079ce85d583387a85f2e254d95482c78bb6fb6601b2d2d4b0f7492f0fa476808361c8fa8c033777e5319fb7c7935c6026306b1c2c72a5b2b3521ad5e84eaefc463945444301d6f5f462c1054b62ff238e0a1841375bb73257cf5e0a09db73fb8caeba85740430b5a2b2a17d513149158b0a94c3db0c6454bda6f0f7677be5f19b3cedc50fd708334a2099939c0bb1bf6f85658e68a6be4cfe3cda8188ad3224ea9c62f7875903b31c52a935cea1c41f4c79e94cdbbcaf5c16050a13b5234acc3db7abeea9b923911d6319ded6ca3a392fafa9091ffcecfb86ded516a8ed047e134ce632ebe5896104513c7bad4227b6e3406027e91fc74c8f6509cc9eb3a471a1bccb9a2474280801e24230c42a733072cd2c869cd4a2382fb862d5ce5b7b99d1de4c4b38b0cf45ffc24500883735346c948eade6f0878c50f7e9a199a31fbed08fa2d9f87b7b953d73d9770f647a61396b3abea2f8559f5f737077393d0353c643c4e47f3cd73aad63cac862e55fa4ed103ffb587ff2b1238d2516066691bee8b3224004ccb2b125c21943947ecafc274061a79a6eb7b9e2a902f787d39d1672cdf9cef48ccaa128b0aab19edde2664ffdeecfdaef5b51ffb71f051592179b48cf87c346c4945299622cecb0bb2c5206c26ba5ab48061d06f03db5babf0d2286c0ef8fdc4ad2cd21609eb7a534036b0a4bd1be15204e49688e7e747d5144c6449ae7d90ca727f6bb12c260fb62fd1839301b5876d4a74fa0ffac8404e22a3872eaa91f16299869af12027c8e8332fae604df423cbf92acaeecb90a7a792650fdbe49c9b95b3ac06cd3f62cafb175c49632d58b1ecf4f5004caaeda192bf47f8b7a968e3f2e77384913500216d75c09bc4d0221aa4a155d0c30033e723331aa15bfdc2c83ee6e1016425e084a81ed72c408310bff746cc616eff5c3eea0b403a4c90575a8d049c7dec0c6e8ab88b80988084a5233ade3d908ecd0fd63e7e7c1414046f8038baaa1095228d378092a6a36fac53d64d0726fedadf942335cfe0066ca556baee94981dfb180de981632a364b5edfbfbdf25fe443cd6f9433017ce14094dbb83bd86167531c2eb2a5bbc2ff1fa0514d0767c8f07f38ce21215631a2a860e4cbf6d66d0bd407150109c83661545853f5edeac2457bc11999bf68f539605ee462b1fade455b365d74ce30959a2884cfe4a26613dbe3bbb9b20dccd35ca97ef86a587ad6f347333baee7b72ea384fa243b20eda0afdbfbc1871044f807dead244cd145a5cf93008dd5cbea889bbb3a68f6312a69197a6b97d6f8045fa523118c634e5fe32f1d2191da6ff99f48e0610972c533333359298753b85c5641bfb470634d21c64b182c5d5b44ab4aa38b23316c2ae12de1036f83bd2f41bb79a8d6e73498c98a75780f547bf3c1dde75d862eaae876d3422180772ac75e2d838c5dbcc46c3cf3f3e20f88d649eff8e094a0933e4cb38c77872ea6f0e1cfe4f28b6965343a28b9cbc72cb2a3d8fe33e28be4a77bc4ba4b86e2021179123da927daa4ee1aa837ebcd4d0f2a6abae228a04a66ce2999936175ae09768273a3ed3cf2f3124a5b2d6a880d2fb592bc1fb280b9ff5cb2cbda3c737ff5abef7188655158d2258f06342f7edd3d12f300407aa80a2baecb326174252db2a4522a99a44ce3f30b700d4411bc6d25a5c6a2d6233bd9d5ef5d7f725d79ee84f612f6fa45f65d46825f522b29194e27ab733b4fbf91ffa1ad3f4d7694b5ea4d0a13b64a63cae97377a8b0e7db975406d3df700dfb692dfb5f82674c4a8ed67e8e2505a40746947f24a2964e21ff232844f5fc43e905c70f1787fc1367e012b05eeb9783533168461cf42a10a34a1c2fe2ea8176a1420e0f9f87c6d76e033f995955a668e5815a0b7ebd4e11ca83942816e2d4e2bbce7260b3d6cd387d91974ba3d2dd97de59cfe1252fca09baba7238fb38b2651bf7bf3834086dc8d2b37cdca2d52a3e569bef7e1035cf66f38e47243634f201042df5f701982c71f1fe127206117a4a5ee94b0f2042aeb1b94613026f059176c816de23e15f93c27092afa270d001ebc17377b8a0952dd05f9b65067d9dbb42f11b843e46b0128a8e8599ccc4d37f169734b1ea598143a5bf039a0eca4a7886551d6baf67ac38c02a56c4c89c515d7dd343e34175895e0629812f07efbea628a05adb73115b3f226fa5a91f901cb0efee2ac4733a77295b08449003a2de632389494b1248971e245f4a5cc74c575897b02cacc1e0e954e9d09a3e2b4718d47641e56bead05cab1e992fa4fc8d2b98fede79cc97f2344ad5001c943f4bf8633dd5c57882330499ecb93a4fc0c0ad49b0cf15f4bd5ceef8d6f3350a1b519b85da4520526d25cc243ae76b7aceec433012d08f9857f2ba2f19f04b9618856af858282681c0dbf0aca3bf260ed40512753f72bafb36bb4ba85c4d5c960a9b771f5d3ea9f106e16634bda60da0a416aff608a6d23b6d485b9f342ee2913395a11d99529aeff88f6b7fa6a41b408352df74f6d01ca2574a2f6a2168aa7d29748e0143cb504c72d40569ad7fdef7d6b9398532b1a13b6598da5a9ebcd27a21d9444b94955187d1cc56cd82164d4124ef9227e0cb22bc27d163916a574b93374f4f37508dfff2454aa31224e22a5f4de36ab2fad90a13d633ce694cb0c04b02d60835744bdc24c44dcab1aa650a3b60a2c1384e83938cef3e099cea24b4d6317fbee437df3a2e5f66d1920d1ecc62148ff4cf1259c2d9a334f669d97e08423b82ddb9de6e6bb6f3ad6933f9df9b4e6e8124b33259b9165df9f969b7a08191011634ef069db27093955e56c5754ad851ea622f1e381bd73233c6d345f3f9250599b1f7e6c06998a26322438482bdf950849be4048954eb4e1552c2e5c8ce2c29bcdd2667139859540bfa84c7076d6373915f4e27f679d45b1fcc3fe071aecf065025808f27379329b5ee068036fc908b3b90bb02cac799fcca2adeb69c013005d3bbe6614b1d4ef06680e57f28f19f0bb9fb4f3b46e70977c7ca0c29640e6e321a7f1600e61775fc43c4cd14da43f6c7fe0f067a16c84deaa62884081f3a9639429a6593b68b47aa66c56ea989a97684f2cdbe7f1ceae058ae40374e8690501feb22f618b8cff506ad8a9eb3db348ed8f702bd2517a39776d2243776c76f3a265221244d443baf66f792da336ba13ef20598e95eb30680d7be2674eba335cb390211984ecb6e2e1d9c1d3af901a46aad7ea97c51f419984b3db961b4ec0d0023fef93cea8e89c304c82ec74a950f85449f76e4a5298b0f0ea6f6ad96f5ce8c3f480b4a7d0682c5fe5c6fe25a2dcb1db4f91e8ff9c00d2673d4ba400f332f10202b03cedb2e25410a5b61a96d6ed264acf4262172c02754a2fc5fe64b5b9ed73e61e189715f03dd515378af262c228aaf3e118823c8f70bf2ae4b9cc418bcf02c6fcb42112f37c53fa8b26abfbdd9e6e0c974f5d05cfc2b8059d4a2652b2beb0bbc2c46c54858183447554b99b8278993e6e5d38b91e581720b71ef0368487e031649751b431af42826014ea1ea63410848b868fc5b9958c4f2c2370ac8fce7237f6426115c59c8c05d9cd042f39777bb16e48b7a061331414120bd53fea4aa34a643c22e39c50b5e5cf0b6cf83a7d7352110fa3167d88e123b18038b8d86803901099ec27a0ac107351d3c5eeb62d1c5b7bc0204829624819c7d0087f0a11e2b46a348b98af2b6724d73e6645d91854df0ef942f02d66cf9b69f3d2a5267ca21fbffa404a4a45a7aa2e0e9f9ff42f85fe4acfbef0feb06ff0ca8cda1f0fb9b27d9259444817965570adbf794a66ffc64622bd2a081ab90bf338f987d53ca313abf3b2ac101fea764ef7dc0fc847d8d93f6720159f99ca6345babe301a064480397a9b28af36855187df9f06ff99abf4ef2d306ba0493410b8883a2153c997c2312f5a12d989d1cb5377113652f5856953c282e977b7a8ea01719d771cf69553ad233a1f6c054f0eef13f429009b70305d357c30fba380f0d23b6ba2c38c52202f96e2d892292ab55b8e20ca9d8c9447366c690aeb8906042093eb5dfbfc8162dcb4263138a9fe0a2f4ef472b7d4d55dcf0a517db3ca3bc66800734f01da3c4003b1770c3f6fd5b865010677fe381a54957cdaec0d09383848ef0f9fc03fd5d04e7b2d91be159fe17508fe687acd654c191a40f2537fdc1fddf718a6ac99acb1d357c1e904bd42470a5915cdc3babfa144a9a5bf9bec5c1c4609a7fa7f74dcb26a1997d3d0bfae93f688cfc8fb1d8bcc229d16a2e6b2c4e2af2f6f0cf82f59c353e373ec0eabd5a543a67a7d6c104bd32cf6b4b9f6d45c2e7973b911d0fb76d1ba0cab8e9a541d6270ffa99e34a7a5b0631f9ccae6d60ec25738c0151d1ca8c3956e38757bb04a2afc6e14e893b73802a84430c51da6f4f03b6e2085b1c294339ae86c0b3d5f893e462514f7d839910cb84b8a66a439e16ad4a52806091fc1d3ce9556bee43d41c38cff04ef4bdad9f93fd2a7295768dd83478399e4a64782601f2c0eb53ecc7c3e93859ea85ade088c84e8c4a95a2f4e9307aea8374728a16289cd8973434a7530bcf1eac74e9c157cb0c9f68d1bb455c0467257a455d0118a6e12be966faab31e0c4b6be97c2627832b45448ea9fa64ceff915c2d49f70d8a5decf1d2a31a6670224aa83e4be475acff72399a0b70ad3139d13e698ca7a312779e5d76544376ea293dc2ea1fbbe5c258a582bd539d76307e710608ce8c9e799f554ab16b2e27eb87fb6599473c67884ea08bb9a57eb7dd28012832ed468d5beb23c58a668a09c97f4f15088d29c5fbb1d7a7390ab7d370495005e95d81503b34123c4fe520ee683c4ff17dc7c146d80bfbb795ba4a900209d9d20cf0e26eb9d9df647ddcaa6ed6c5821fece3aea2b3543a80b7cf1ba2f4b9f59a01020a00f1658f6c86e7f40135f12b70c277d572d139dc87ef3fcc70cab3dc5fc4db4136fad0b6feb8415363d34ebb3af490d37a5b5edc8857266a0dbb917d2cb1bca92b13d1a0b2b39c5010b7b03259ecb4cbd87a1bcc10c3bc363b7d294045e802a278da547058aeacbbeebdd105b1317aab2835744110cc3d16cfc76eb243b9b460f45249b1bb61e2153de4d15edf5b33b3a20d9c4247313b4592ff7d7c807d834da260c21b981f4d743e64470a7d5a155d7507b0f16f008dc0d305c666ab43708489c07247652af2144e2b937e4d2e1f4f44f1f09a15a1d71e967cb7b05f61f83fdb289409b93a00e8fcde8560d5fba8f26a381a45b77fca60541795fe57b82b25dcc3c8573852dd585ca87ddb22b752842adb5680b98862c8c77787ab9d7c35b571d398c9af4707fd3d966266d5e19d9d3b96ac12e10f396bd1d06a4d4056b5edefe0f43f99d6c06d3fa8524af9b4f9dfed893e735fb41f9f7d4d03b0f2ac951c82988294c0ec202e0c677e69026edc65fff87e76688d3d6fef41a6ca054a16d314d1aeace09e991e059da7876fb3a44c6402abfe684d577cecc1a7c5d3043f074579d7da6c2ba42f47a471c6eb93c8100ddfbbec9aaf91e4d616fe30f673a9e9ee2ab27a7ad151194701c13d1f8e41ee09ad856dfceef722623201f3754fe4d39241330d0c67fb9cfd803e94dcab514f086f3435718f870b4b393eaeb550aab1bbf17f3ff65c006b4976b2362749e38b6088381e9e356efa1fd3a27058211bb38611fdfa15c7568577cc24a9fa10b037ddbe2248d3691c35a1e70d2a3349478b56abd9c8c5c6ccba3bc47e6218389a93a3a80b69c64162642851d6f0782200f6dcf092ca0cc76fc83c8b0e7e2a41ab5d59ca4ea146523b588e4b5ba57ac091531b08828e8969a5925098e12eb1bce1b93201a1e275e1d7753332beea281e5c8695a0cbf6918a08ad46795726bb11a4c4267a0c3f4897c12ae51b690386efe69d0a09cd32d47192992ba72367ec5eb08b201f943df81f19f2f38c032524a349966c318"
    EXPECTED_AUTH_SIG = bytes.fromhex("9b57ef804f5cbea4a910399f99082a098ccdb9af4a1acf864518eb6a003fbabf6281ec9be091b7aff41013e158dd50d5c575472dae78082bbe0e414b640ded1f")
    _assert_real_orchard_only_sign_digest(backend, scenario_navigator, TX_STR, EXPECTED_AUTH_SIG)

def test_sign_tx_v5_orchard_to_orchard_with_change(backend, scenario_navigator):
    TX_STR = "050000800a27a726b4d0d6c200000000000000000000000002f61b81d4d82e61c245f59ba77c6822b937132e5b794224f95db8433063994f22fc3ea087e60269ff25114682610a6b0d716f191fbf2acf767d2de63de4b95a0094fd0a5cd314b70ef0576cef0dd21bd9a4d3919ac801e7199fa1b8be6bd6f3b2ab272660436c13c8a53f357335612f49ba61c2476651a1b3135881c4fe0a773d4c7314227c0199b9311470468981d47713a5f5109369edd7153a470751b070ac46cbe07c7c443635f101d481bc111642eae701694f6a8e503b163f6eeba752f8336e93a1264d9dc138e450182f6f34c179f577ded73a34e805405edf459ca3c204b704ab6e12a9d98fd58bdd6f23f5175b5f88d4ce8e1ce6e15f5e8ac33001a4a3ee0ac641c5738cd851fb6db8cb7b0eb8cf72e831585b5b4071477e7f8e92fe23f3c8496b283ac227be5219a333b4703efc604dda4752fe7cc2d3a9974d5159017b90d5e1c815db1c8cddab91dacd715c66b7666272178a28c7a7d05b763a9c6525e6f35810852bb77f69245068819d634f0d637101afcd9a3ecc2c17371f269d37d42f543169f9cdbd02be2092bf5eb263dc787fda8a811681303fefb65e7c81fa7fd537d108060d8f56a42577cf45dc57fff563cc7b4d167da96b625e66d02789924cacbf7c5a876383e49573624ab52261d19a49f635e501a15109575562bdd3500eee5681ce00f176fbe9bf9aa607969ef9e124f6932b24f40045a7067d4791794300f875eca146b9a0f7356292e5501511332dad6cc50948e1eae208131f1328ee84d62d916a22239e3f373ee994966cac76aee4a5f4e4d14f2462c98e828f38c8e95bef12a5ca50060e3a5203df81f10d7946e33f51072117403bb2d74cff0d58d66530aefe2c84ccc6c37b2baf77ea7b3ad66d0bc463912de82033f96265aa7c5c9a46a09d9389274dc52c202652b3d09629163416e2deba86e1c556ad1513c9d42e02aea10416c071ad579e6fd813e30210494d918f808664391eebcc501aaa9e8884573bea0f67a8061fe5e531f1ffbbc14da40961ec0d05695c32aebd8ecddbdf7cc4e1b5e89044eca85547ed7adea0e88738fcab767b03993ede592eb18c2dec1e20c9fd22fed35be298d2621734ddf17176aa51b836e5cd43ff1220854bca515559ddb184b318f65198e890a8807b19b7ceb6a1d588209a62d08e1c13f309e61381f767a59328ff91e4191d98a3d68cef8d52a164d092d8bd4a616458187f7703ce6ce5ee9ded3fde2df4c569122d62ebc4f70e798fad2fff9b7873cdd476cbb3ca1623943b7ba69732295378a5e960b02f6b6e0e58008aac76cd99b4690541a867fbc6f5d52606262264fdda2ea5d064724cd7eeea8058bc46f0b99e3f166acb7533b2bb7f0e71455800438e365b7222cdbc3dc4a72cb76e55c1c4035e6ea3ff9b9a8bdc64535e22fd54618a048b61985ca54d154083d92fe9c95806024e214cdd82b1419499387c93bddee1a25b5eb1999aaec9967fe85d7bc41f8c634b7f1b02f140b4947e56bf5e77e84e7a0becac4421ec825a90ef2febfa2099635bdfee145e441d4a98e8accb8608bcc88f2abe8f8503fafc165490f4687fe1687245f731ce2e558513fba50f8a9e079e3599c266fb02ce396472c527fda66e2b4c4c0e7617ccce6aa26ec1312f77c580331dadbf96d9fc7b13277f54cae948938653cfe56a7f695c90764662978ffabbe286b947653498bc4968f62a91f11c94199e23c7906175482480dbbbe8188755590f8084babfca2b9044b4c1c0e84a18f7043b47a6001807170ad5e4b8ab680661407645b2c5ec8740dc69da49255364d4278db9f0bc63ea98e64634114d8bebfabffa57ff61c2509db5431284c16ab926e5c0ba2c219282a7c9ed03c36d9659c0bb1be59b7570935ea2d7352aa11022500cf9b4a6d1ecc556bab49118999663de5f2a22cd78819f5778e3599416ab150f42440ccc761c955dc15f49eab0fd20467a5aae9c6f84dfd14528df46af4da2f0a5ddefa4552be915c564ce720e7d26e1d3261a9bfe568fa1929d3c4da13d2a87eefa955d35aa0a99fdca301d52c3b0ecdb59c275510b7323ff4c46e3e6bf4bdcea7dddd4b9f5349f508b5c62adb529c23f91af42e960a0322ddb6c010b1915f0512db34feabac23fc42294f00f18f6225bd7614e7dadd74d61d8c2d40f8bd02294e262448e7984b7205d3bc6256b751c73042b08abc376d9c33581d1a74aba93b503b2911846ab7d77e8ed96f0210c4ffabb09e81a728fff021f90784cbb2c8b3dd3b7f62491e02618c25a3f819836aed45fcf707a379e4b11b65aaf7f6283c250fcd6031027000000000000c5e1408579e67cf16b5d19479408fa035a7db4fe3060123d139eba8523bc9633fd601c8df8eb94502574e7bf9308a357abd3534d0a8e614c44778960ac798f3436701588de74fa5680dc8039048995a44eecf86ce30c47844548f2d8b5e6fe3881f701050f4f12eb7ccac9cfb591325be6029e751666103e9eca14d859c9fced9b85803546cd25e7c6300cc619f8d104d45e194f53b0df6c63e5395545d5dfd65c3932b0783aebca5d05d6288186ab5a93c9caa06d0e2e20789cf1de057f1155c6428d06e5709d0eabd35ef8a8c2a6f29a5ceea0bd9a3ddf6d770ef7a7bb88e387e683e783f926a375d6ce9ffff496faf7372dd1ab47d857422ee52115493a0ea426b5133aaf1ecfc9698c911037221daf645ee4d3c5f9d820afd2d0cba02f18172d09ef0db53be31ea70b39aad934d5c1633a928be06a46ef10fe3afedf0571c8c58c1538b9605c0bf8f27e4cba540f86af2ff5d10a940b95d5c2457bed074695a238067195994c361174dfbcb795ac71ac18dbd598f639c46e5bf0e861d38162aa31953e2204e5d4c0330171b0cc4aeffbd03375218f78e98d5ea11f9101f90aa9325976415e864b98b8b9001f34a0e9c5fc3845a38128df93a3f2c095306f0fc026dc9d75a0e41e1e5098de9e8309730ae6ae4ed6ed0250e03b96be835728b416908b0f76b66a8e97a15b1d8ca8ebaf19ce8ddf2dc3362e2bb9e5eec7676dd3070c970750bc14af505cfd3bbd2989ef6e1d13ede93f51fa6057095e3d5e4ab3d424ec5924d00da583f8505909a702133a8993b366b4b668e1f7e36110bbbb3ab83a678ea296e0129ce64764a48c64573e27744f0c57feb8ea6cc863fd1ef923d8336a9815ec0f2de0119d80b8c2966110acdd00e7d76efad3ccd93313dc1ecacc8c81c8330448af7b3b22213a9ae73d9f7e9819845026fa3faecb46b3fe31ae21a926d06f30a614c6daaecc8feacbb1a1b53e1fc6883a5c16e482cdb2a941a2ea121dfafca3048c03d3af681d46a654eeecd2661f7aa9ad31de39901a7c182d8222a1813c0a21061a797beb36a2d5f0cad7e3fd23eeaf16f01ed920ccdd98bf02b5366853c4422434b0757601d9de2b9cca3a702cb4a85f84256eb796573cfc3a8860e965495896178600b378ab6adec2fa7244db4cb741f3336a45606061ac6329d4a10470f9d1ac904e90c2cd4f55d55f55475da1e9be8998dde3a1ecfabcc4bc34fed16568aa35215a847d21d0243aad2e81fe5b3505a103f2bd1c07b88e8d1f7d919e547aae8e4e9a31ce79712c3458109cf64038061158f54d619ff79eb43bc177132c6288ac92b15641dac6f59ff8932f028028966ea7e0827291e876843aa9acd35e99429e089d59de5a5a1eeb06d3c950aea6e6d1014b868eff5310088b42473d8f42a0a059eeb7f91af2f05d633090e1e16fc4d44750bebeb2a604c51903c36fa800813ff9cf0fc1cf70a952da2ee2f8dc96e6d89e292e7de1b70cde8a10690fb27458bc223e71bed126a6b9838119d385d62f58899b82532ba08cc78344935877a4f0571f4c2852a4c379f63317432317d3cb83a33d320e45f9d0ec130947d50839bd9f8028c6ed8e9b0a0be67ca4e97cb4bfa715c3f2334caff9280a9f69b59f497c937a7647c79ca7b9e1f7c4ee2e85f862540f8bc2adf736ecb6824581b8f1b5cc9de7085bc96627d7fb26cc3c5f607ad7c539bb8f252235cee084a25f60c3760f7b2aa891a3a0541e59083d67edf420c6ff8e99455c5289772727db7593e127c0af14c2b96f5358acac1ffeb20ae37b9b8cb1363fac21a33d52324ae2105d03d38c0d4b136b8c96d374c72db24887f6093a9b4e2022c87f441d3e971f581daf431a4d3fcb088ff03daba7a292d8db68a8cc70d3a8a1cc9ead1a203fb7e553c61056ab0f7f47c4dade3daa742db0cd5a60853ef9d517d5de1f922d8c4ecd59d920ce57244c20e55710c09fb9f6f23e92b2a6f67ea7ba1f764d2b3f1584c5e2bf09e5bae90c6f1a7bd40654283ae0dee00859bb71c24ded5380660c8eba5f112d7198043798b21092d51ef2a91185785e14332ae482d6d855d649a140c4838e865c549a8a4e479f61f4a5da1acab4bcd37d085b368da9ed5b3002a871483d71d8fff1dea2468f4bcc5b23eaa6826714f941ce027241c8d4bf4170a338566b9c8e65caa6fc614fb48ffb5e049ab134252f97fd3699cb950b52f2e23c10ce2d3beccfa26210f1c1cb75d3a76f932d0c4dee26dc26b49bd8b9dac75818ecaa2236de40f6be352584873dbe414cf2d4cc896228617e06c2309a6465673233a00646029db878cb360d57ad1488cb01b383aacfc989eaa4de6c301e9689318ac96e1f7660d6b76947050c37abb2c11640e60747da6cdab36dfb3143da0a2f7d8c3d307ac52b919cba51758a127d2eae75a9af374db3b2df9e7a5478906434a8e4fc3e819e8c0262bd9e585e0f555f1a10073af65308dd0d42a3b61d33fa2681d5b1558043d35fe589ee21ac109225f3d14dc960cf27eff4f93666e5dade09b63e35bfb77a8f49197761740c4cc6d5ac4579b03511653d825b17a4cacdb60fc127c54c29b7754449efa2eb3b27eaef5ba348d892a78c40e414c0e65bc4263ce29aed425ddf338114dbfec0e51391543305ad96d9efdbeae059403356ff782985aa9c9cce4ba298c0858dedaf6090f823046073e86ee4d435e97228b974d23b84760ab4b5c137015ddba1ae846601980fd9233e395b83ba018071aa0b7b2f202f917856f6e3eaf41b022646d27ad14645c7710cb16903cd03644f75af53f728a9bcc2aa631558f29723fe2a57bb7c22d2ed6da998804a56d3a462cae2cec83888b411c331a8a16027a31904afade0fdf8242cb30e54229f0160bcce1ffda0185a9b1422573c6f0e8ea66cba9b03820f7dec8c66bb9751de96712d03cef8d936ca5cbfa1a8d6c9a4b05a1162279d508e28c1c3bec6a68c8c75318c9904582514e04c58723fab8121d74e7f657834e6e445bcaa06f3d159b05e5a68a4313e213da3dcd8451b992b0989e9fc3b57b49820153d1f58f3c2d9a970217caf62db2e1ef06cef7349c0fa89565339c09fc20d800ba112790de2018ce2b7c6bacd138a04b2a227a73e14b5ea8a6a6023742e642d7d9fef83113e625d3a4acbc93207ae2ce1f64d6fd9845d86c47d73c2459cd0eb2214a3d8c40823fa1883a96ad76de70753f842e6e8a1f5474bc64fd9fc67c32f2730d031a1e6f4a2fbf0442869c0821d48acb6dbea61bac6cf55feac83371e8608916e4746c32ca1f1f58b472d91ec213c0ddf6c05a73423219a27577774289a2e00f5588a0e592dfd6ecbef9123cb3f9dac2dd709025bc877e5277af0746e507e60604242ed3f70a0cfc91f60f9992f211c90360e677e4f41c9d2efe1303f1e568f3ea0c9b4fdfbb8e09ce936d8863c57bc56939e80bf8476648b600ff4e13b22abdb83d125ec80e843b3920d91de3ecdfafe12f1a4bccca798d180eb6094cee9a27e513703e018befb1487044f820cebf28545a3d67de95eef5d984f80fdce88d88c1e538f315ced23f6d6658cdb07244e1f604fb70bf023ab68edb0a93f190014048ab4d90ee8847d0b2ed31ce31ef3819b32c1928610470f63109b50d0e11d11dbc7d9809bd572322b18b3f6d43c65631de7cdd43f7ad98607fbde7581ef34dfc820fd82be76530566622504e0019c62372360a4617a01388562da396b6a9724313d2b2dedea54d84b062ee58a31019390fd75cfd923b39e6e829d9a45837e5bf07571aea1f5a8a91e77ca4d260bed2aa42c86dce5de867736b19ff3f803d4f48d036c2ed83d1d7acfa695ed833139f521a75eee5723792c2bc53b6532d8c1d602bbce5fa3125c76dd272ad6c33783acf2fbf07156fc15264b00bcb5bdb60285d17ec7046b0367402f5f58765b3cfaeff19f94bfa5890b2c184ab84d76681b29831dc1f4ac6cf8cf632968a88d220f695e64567826cee9cb7a142d3155ea2b9dac7112784bd3fdcf11769e685b2e843a45462f5af4b4092770bff84c2fcfa85a051d693fdfd28087fb2a0aa5f70945c0304e157b45c1f60fef142070ebf1ca2782db17e16b520c63dab0c90cbd24bff1db0620b5223784f2c133e67a9feb93b07a8c1eeabd560162620a446d9f1e1fadbcc3bf825a3e1f7406515f0eac12686c53f64d265a687f01d0ebafd19c28302cab9f53aa40465b6eee7bc53d739fd2b70288f5e146df2751f9e8a7f26c2dcb5c439229ea41302cc40bfc026f360878054bc769398117967765801b889e3f2147933a9684eb15703b677a28efaf622e59a0074a08c5b713241046fc6c16234216388f5ca8362af9e4e768f5678e1c479851d083ed9b60977c7b69506359171753a85c56958ce7b694cef74af31463e50450a70ab8d4c4c986487536397235b71f978fabf0d8424e670595f82ff463e397d8be5ed6332178cb7fa7ed970b0dc5bc1e2011b7631be6b8049e7ffdf1ba46c6e049ba97830f5bc267e66a35153d797bf2f8544797b3f3bff622ad23837aa3c3e33df10c3c1657f7f0a8d7027f1735e43ed40b343ac07bc3b1f5ecb24cd48cf83dca8ad3f80e3a982b69cb60743a014855cecbc8c5f751e7b6b6ee9003282a2bd7eaf1d4400e7b6cffd73a324c0ef38f45685f626a14e948d037b81e5105af54f8bcbbc001fb15ab9d9d4edddf291f526332b237bd943b625a8752e3f15aab0dbecf3098b9512fa0f0ba3ba0980523929dfd1ae0e8d6b01f7d2ce0d45f000f95890333de9514849f404cd09f7f302f493072999a25904ad992307ce1f5ab07527722db98d804e0c0e675d2b1a5104ba2f1f5ae1b8c91d5360338e8ab9c4188dab0ce1c5a875c2dbdc6236eba6d09d06896b46ee707b6df61411f4eec0aa438a66549647378ec8aaaf9a7fe46653e447fa86fe3da9be0247164925be92be880e39f4ef08cf8e8182cae11e45cb213e67d95345fa06565b2ef8ac08a7facab4efb6a723f46cd7e160f0d945232860c1c0adc7459f8abb28d24f13024ed70b2978e730da29b204b3f7d1097ef1d291e80f367cd37eb4866383f0f5cc050fc779969f8dad948b0e7fb854fc477a8f30cb78a1e5ca330e77b285440156608cf6be3ca12fa52eba886ba1dd5698800b42030cd7b8286d962ef16196b58cf5b9a67e4cb80c131e4a8347d3dd644b2c17b3c71beefef8d228ab07f847e6c8fe561ed643764e7086e05a5aa6724e78936ef2c55a29b3aa4905831a19c6ae566078fb7c681495a23e4c67d52770750933cee19bcd411c0e2b929eef0136d0bf91843102edb67e5b971011095c7495b4e329b2760816958cf0e531ac18bedb5e474d48b623c2c600bdf8b376170242fb7f89a191b5c103bfd502f5b09ef9c1ab30abd36539f9349e20cee23a992657b1c04500bcc6de91b3bcd6fa1b1bcc89f310c6ba5a04363889350b636ccc18eb77b65a502557687903be189c789afc19509f200223c823650e8deaf183398339f48964a13b69bdd0f1aeb7edc9e021208f1f03d00df4d241ff65e18b1471fef348f80ef274e62855339ebfcabd140182f0fa2bccb860cbaadbca37dfdd5da18e7ca13c0357ef76cd326e320f62e19868f59270dca360127c8e16d8e7f3ca394d854600e335edbbb4bbcd044f9ab078e350b462d68afe374cbd444a4aa538809f47a27b112afc0a68deb48567dc7b961a9d84f03066b14fb736ee34479c738a573f344c72980451c709cc545334ac4884d8b6c17b915191cf973850583ab7096e9d1a4cb15bc2466dbe76b34da20d200c7877d11f2556e2f842a6695263386252fbc426705ecfb04faf5dbb6af86e07c05b0e5f2dc737a0710b0e9f332d2f75179841fe4232cd46aee110342b0bd4ea5c0d9393f15668673d68726000017db36bc67868629b968403f826411ebe76d119263fa557ca33553d4af9e373fada83566eea2aa381fcc2325f4bc230ba594a2be73c0f1bf218aac89d277ca3dfdd5f0294ae09d10ab5de2210694a0fdedb1f0d242a4da1976455f550bcb84e2e010c17599cfb3174e2b3fa7ac929db2de075fa24625fc887d4bec3d1e3e601befdf668efaeb9207d00496973bbe91089b61b468f0cb637466cb0713ea7e753074993d08a0c60834f0d50f0a66039b74e1ab5f237c76f9669c97aead6f2bdf39bf04d39fe633c223253528f1b85dc565a6ec9c67255eecba10b48aeb7e6f04d583e000a0cce2fb326d3d6b7264a5ec52d63be31f7bcc5a884e2c43d0e5f294d71b115a7b05205720a40fd9ad0faa43af138457708d252651d54b7919f3acead55fd5d1b82806952bee022e99ee9e2722161b307d7b4de6a097852a6f9891d7b4e4bd00add29aa32187fca5fb92d665ce1b91b87606c9226772d592ee10be732f45690d653af3071c665d2af52a44ab5aa838943059898c1f59e2e2df3297c329448147f2c547ba3fc1e79ae0158213362fd929ec59faad0262c05857b88b675c61f98fd65024350af9b413bcdc235f6e0a7373dde91b9fde9f6a074671368779662a92bd6ebd3d181e633ee4427ce2e536654ef7fb2c02b73b2e0c32e046d914911101a1fe2be019b9b92714e8a6740860e639b93e24c9102adf47d71a719fb8bcd1dbc977d57709b00ae0a7c292795b6f38b1970e1cddef47bd0d3e3b0312f3133524717abbc30faa6854e2314c1e8c1707503fd14c468b4a620796fc92b1ac6c73c2bac3cd1238353dd73709ec90c12e787c91fd12dd67c597a53176a3175b29ae769023b6cc38cf289bd0141b1b89214bb2b4625b8e743dceaffd1b835c99c9c93e0302194522142541d2595c3466e383d2e7157e890d4dce9a793c00a419caf59aea4bfffe23d2a7bcf02e738750cb17bbd03afa537fe8411cd90ab8cb5b2036c57d5578ec10e639606efcea0ef5442cb7b22d8cc3490b817b407df6b32273bed155d280ef135cb97c10540ab70e43b4e837d7cf9710a8ea89ed4533eaa423bb6e66046cce387f075d7a1cafc44d271e6e27594003e141432f6d6016ac776c25d2c10ff8c51d4aca66d083fc54736678250227c7dd9c7b25770afeaded3bea5b289eaf2a8b125a14eec089cd619b4bc7f25cac20200bc961657a72a835aa7b20572b46d23c18d6fad13e050a358822fa3d93d0fd77ab9e53903521dfa7c1c1d2f178bd181c00403a369e698703edd42477d1a9ff580429ac933e0e1068a99a702884703e580ebfcb49cd3cf2740916190d27f8305f0138ef75b390c1bfae18d7e3eb3b3315139c3f6faf17c7c64906d0f41b437612567b8b671b6de4c0d337c46518d9faa0331972b217a1d39b7b45889f8101ed9eed6ac5b0f54a3d783b3a51765727b4460d22f8ac39c173952fe35b7d7ca346aa41926644ae90baff781a3f55501b509f2ff81d6e2d84d8deb01df148fb444f8bfa38dfbc9b1bd8e53aeb88b15de2045219d23746b4ad1c74085680e72d08a8c6e7f4629295130778b641f75bd781e8110d31ce1dfa270ac95b6300d4e1971696bd186983c773a6f20c92154fad32c97e3428c5a6f77b44898c29dbcd10895547deead99753630afd79ece77146279dd329bcd5ad0e64c1e317788272e1a662045aa27a01d464e8006c305aebfabdaf2c17a5a40aa4f328d5e9d867ba83fe73745b94be4a036661943bb7570d6efe38b5238777c6c149df14ed498c92da4b0ee6b6715ee4b7dae26548fc357ff1cc95f33b86a53d0a3d1537f274c91d0557307e3104f56725085d13710aa3f7bd334c792e1fd0642f8c8476e93db39600dd8b5abd400c39cfc168fe1955e2bbebefc5893a88aa80e27b8c8798b4913ee89a9181d6d6df91d7dce06cd09338900a75dd4c2442c8d05af61dc2b8c5a0b104071166de2af75b797db6570d86c39930343c0e36d9a69e1144381cfb4f2dcc281ce2f42dd242be2a416d47bf72c0f763b1b88f110f253ba780966f66a120d1f7910f4750793dda1297bd17f873136ac603dd3a1dd9c8f21deb201daf9ff169461eb77ceef526064b398249d665d833413e7efa1a1b120b9dcc1bbe6b8b6fd3de0b252e880a5063e6150471f5410b8e28b56e9020623c4dc65df3e377d925927dfaebd8b65ff5569288c47bec34311e1bdd191d01df37f3ec64e07a7721b594686878eb8b84af4d390393fa9c652195ce47e78e24c03fd23503c91cf609fb0f6e104158f9a8a1506d187cb6077762146bb7b4982ddd799d144ffa05eb02d41f1259acf60e459fed592a47e1edebe90c847dd2af2e09f9cf9c35cf76b37755aad21fa501fb8b5937218d9095a88da18fb01e390c3f9e88f9e5c52a2d06a69552f2f93e6d492fa213d371183181ac59fa9b53fad33c8e1b39edf9c5d82185aaaa79bdc2422243bc0f5445c3c97a279bb2bed40d9713d590f6b7a32903b63f9451b1ab909088fd043898c7a1ec526a7b8ddbf88d5439e4872f3bbf46656dc5a3a8d23c96eaf60876c28cb5ce32b9c815ef163f1cff02aece414c21478f3063561d7cf09923e3bc4d96a271e8b1b36654fde8d6f2750fc0581138aa481740a6ecb32a345b20e7f3d264589413d2ef5408488f999f7f3f12e3d60657887c948ba8c8945138b3e7790afe73571618075ae5c98d13855e35996283ea28b918c3e401c3cc89baac19a93c6bfa62735151c59a582ecc47171b956e65d25e8761d09d06aec5f03295ce383fef5a72632461009756fbe801a6292e5d62528589c8d3bb2a29b76319efb5dd6996757a1b64180d7892967d6a4c19bb065320a3e8047759fda99f5aa14c9ab839a61084f15d446ef647a1fe57cc150cb7b18e87e7a9d0e4cbadb494fd1a1b505c90a5eaf6592f00c66e9f1b49060ca0d5a1ab4549116fa454071badedfc3f53787d0d96b54b9466dec6053b099c24a27da14a085ec2eba135d481468c72ff7e7fb947751d0e26965ccb343e626abd99c4387c12ed05777cdd0507bcac8b05bd2b53ce70417c7b50696f5f7966cc25be0c0670408c1a6203001936a32fd6e9bb1040d2976ccd3e20995ebc66508d3a03fa41b84af303ec920b068c9faee3b4e74f3c809706c983e60fdface81ade2e748ac90a7202f43471f0171104a2dc14b294986cf197bd142723bc530ad6163fc158eddbfbf1f024e0ce816366fb9e5d3881695057d9423694406068c8d94e2786b32482b489986ca37e13a117a1889de35a3d09b4001d3de8ca66e55dc8be9222191a586396c1f36d386c34753c9386fefe7c9cdce230eb008b3138abeac805257b63ff2cb5efe8889b93ad3757cce62c94af6f0a7769146cf4717c559e7bbf24864d5b11697e2aa89f6ed94bcfbb384aa95d935b4a5520658016814d42d5bac596d1856f7245b78a4de31f19604e692b59c934a5e3e6895a3803f4cd3aaebde4c5f834462649fd1224f043bcd3db09350cb814f9bdd4d66a984354359b5ea87cfb82e94c3dcafbfd84e4e3cf0e2a92dc7b6c0620c92b26a393e78db8486995be0411e2d16a1d470764ca9dd7b862f0b55326eecf607f9c060ee8eff63cf6861db6f525248ae7cbb2b8149c8dd6cd4c3bd93d48ce772883facc119ed5acd714109706e84659a26c9357469798c54f8907372ad6344974c6c56bf15434231d0436fbc2b846f4ad2e5526af6c4705bf4b9193d551f98beb964e219be7bd070736346dd4edf90ec261f79b83a709a9f1061a66f4e3a7b5ab2de0bc44764951cfb4f1bca0aed255fbf2b0216837dff477a0a6b43eb56c91e6c74db9b929398d889b5058e8bb5665f0c40d39a738450652d7b7ea3f9fd674d9b458c73fed79665ab4c9b9dbba74d73f592c2affe34512e64f39a59577f22eeac28c36bfa23438263c8c5b5d0a7f18f07e0138fd46fd89ece8ecb0030919a5bc5878b25b9c4e2de490e0419ca27e393a970855bdd4f030d45ce54b2bc531c7910bc6bcbd36e4d41fb51b9ee23519cca41f1b4936a6d148400b118469c21ae68ea9c75ac5ac0e3c2fac8e0cec430ee85e712c5acebcbc51972031aa1a4b7854578130e81e5d24608da2b882da1b2002e0cbe8cad493d171d0e398edea2d2fa1e7d18f8782549b30781343c0b87c3085a281631705c702c787258c4ed4cc9ad3dcb4d664cdcdd6e67396dd4730c19f577880dc28a5252a1835ff8cd208193f6896c2ad36218f4cb3150e7ca1e548f5c5908126c7818f2dd2e397f4ee9341e1b8792c40d29c38e09176bfcbef9fe57d39c062f1235a277ba5949c8785b452bc4777ad12f7a479343c711a7f40f9cb5b366215ff443056d558c9b3a9cefcdfb0b1f40b57a5a62ee413b41e337b78398ba1eeb714002c8156fc4005469765844d969fb3e77c60cd6363782b0063457b62cc9d1dcee8252fef5bd2fa562bc503d7bde33200dcd62c38dfde221dc4621ff5ca032fd04d0e79a12f190d6cb8a84014fe748ae580f1c9f17562bd7ecc376839b968d7be4fe1b657853d470d250c26bf75774ded48b3102644ae20e39a82f777334347b19a7f27499fcacbd6a9d706fd870b6166f8e560410af70354dabbd8ac7ed0f24afce0c5ee9220138ec442839f0346904ce562da5b6e7229"
    EXPECTED_AUTH_SIG = bytes.fromhex("848ab1c68bd4a88f1df4090c749a45eeabbe23e8b8b61d17ddc713e9cf9c949b09fdd84bcd0cf5ffc3df88f15c3f75824e27c78e1ef0158d7c65901ab9f13001")
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
