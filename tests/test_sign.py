from hashlib import sha256
import json
from pathlib import Path
from typing import Tuple, List, Dict, Any
import pytest

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der

from bitcoin_client.hwi.serialization import CTransaction
from bitcoin_client.exception import ConditionOfUseNotSatisfiedError
from utils import automation


@automation("tests/automations/accept.json")
def test_NU5_signature(cmd, transport):
    TXID_LEN = 112
    KEY_LEN = 268
    SIG_LEN = 142
    EXPECTED_SIG = "304402202b22627d88f9ecebf2ab586ffa970232cddad6eabb3289fa1359b2bc9f5554bc02207cfba5db7c01b89c5d540dcb1ada67d485ab1638c2151eaa78b4d368059c007801"

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

    sw, txid = transport.exchange_raw("e0428000090000000004f9081a00")
    txid = txid.hex()
    assert sw == 0x9000
    assert len(txid) == TXID_LEN

    sw, key = transport.exchange_raw("e040000015058000002c80000085800000000000000000000002")
    key = key.hex()
    assert sw == 0x9000
    assert len(key) == KEY_LEN
    key = key[4:70]

    sw, _ = transport.exchange_raw("e04400050d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480053b0138" + txid + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480050400000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04a80002301958ddd04000000001976a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04800000b0000000000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000")
    assert sw == 0x9000

    sw, sig = transport.exchange_raw("e04800001f058000002c8000008580000000000000000000000200000000000100000000")
    assert sw == 0x9000
    sig = sig.hex()
    assert len(sig) == SIG_LEN
    assert sig == "304402202b22627d88f9ecebf2ab586ffa970232cddad6eabb3289fa1359b2bc9f5554bc02207cfba5db7c01b89c5d540dcb1ada67d485ab1638c2151eaa78b4d368059c007801"


@automation("tests/automations/accept.json")
def test_NU5_signature_mult_inputs(cmd, transport):
    TXID_LEN = 112
    KEY_LEN = 268
    SIGS = [
            "31440220489d5ffa46530ec64ae523be7559058fab452a2c8d03215179f33ed63e69fa0c02201b3301c4dd20dc318e49e9d0ed6a7e9433ddda6f5755834c7064d7ff332d057a01",
            "304502210090836743d963b93ee1974f764fda3e1a0f4b1662805b894bc6c4b5dd66b5d00e02203c356c71247050269150b4a8e62d0c04845dec5324308e50a6c06e0a44282c2901",
            "3145022100a4cc9821cf530a179cf2bcf767644ff62e0b0cf79a5701101914be6c215b0bcc02202d2ac5ef2289caa7fafc94ce38b2e46baf5987b86193e0251f4cf2585c174ccd01"
            ]

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
    sw, _ = transport.exchange_raw("e04a8000230117222605000000001976a9147340a80cad7353cff25bad918e73837c2e2863eb88ac")
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


@automation("tests/automations/accept.json")
def test_NU5_signature_mult_outputs(cmd, transport):
    TXID_LEN = 112
    KEY_LEN = 268
    SIG = "3045022100867fdc2d2873b15bc19a42df288a257aff08ba74b9e2eefd1245e69b05a181b302200b876a40a9339b8b8333c332319dbe5329af363628e0fd4847b281719986dc7b01"

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
    sw, _ = transport.exchange_raw("e04aff0015058000002c80000085800000020000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04a00003202005a6202000000001976a9147d352e6e9a926965c677327443d86cb0bdf8b1e988acc11b7b02000000001976a91456464d")
    assert sw == 0x009000
    sw, _ = transport.exchange_raw("e04a800013f31771790b77502f55895a396a64e74da588ac")
    assert sw == 0x00009000
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


@automation("tests/automations/accept.json")
def test_NU6_with_tx_version_4(cmd, transport):
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
    sw, txid = transport.exchange_raw("e042800014000000000f000000000000000000000000000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e040000015058000002c80000085800000040000000000000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400050d050000800a27a7265510e7c801")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480053b0138" + txid.hex() + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480051d76a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac00000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04aff0015058000002c80000085800000040000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04a0000320280969800000000001976a9147678416cb82a4a716dd1ee6b332744ba2a1f11c488ac30db8e02000000001976a914c628ce")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04a8000138ff6367f0ea6763f1c1d865329af0715ac88ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04800000b0000000000000100000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04400800d050000800a27a7265510e7c801")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480803b0138" + txid.hex() + "19")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04480801d76a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac00000000")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04800001f058000002c8000008580000004000000000000000000000000000100000000")
    assert sw == 0x9000
    assert sig.hex() == "31440220488d0fca08431682cd5f10968a72affdd569f61a4a358f73edf05d0fb4a3e1a702204722751bd7d27f999ed714694ad024465d54c288a9cc560559d9594914d92ac501"

def test_NU5_signature_orchard_input_note(cmd, transport):
    sw, sig = transport.exchange_raw("b001000000")
    assert sw == 0x01055a6361736805322e332e3201029000
    sw, sig = transport.exchange_raw("e040000015058000002c80000085800000010000000000000001")
    assert sw == 0x41048ddaf0918c79a22c095af0c7700923d80d07b9d614ce132ae75bc4fbeecebddb809e284082059bf69992b18d398a328dd917773c0d5fa6b5948d3b7a9bfd924b237431613166435a69474539467833426679316865457847334c7a3261755566666e7a79f159e77b829e0715d27d0b4b9e5f3a51d1d959188ecc6d38bf85f15bf6292ed69000
    sw, sig = transport.exchange_raw("b001000000")
    assert sw == 0x01055a6361736805322e332e3201029000
    sw, sig = transport.exchange_raw("e04200001100000000050000800a27a7265510e7c800")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280000101")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800022488e1000000000001976a914e58749ee655c0e39ae3ce063a33fb9edc86d23dd88ac")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003200000000fdb7236fe32c00730701f6e2e1feffc2021707919aaced34d5e43c13a5010695cd9d333c19bf310746abef4d8a77")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032fdd55fc303a306f3953f794a95bb8f14d9c94b59d63f792b9e6f9133be659f9cc8b53fc1a26f2e1a9e4e132dd0e78df56be5")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d06688f103b2a9856f1ec074084e8a91d7008cbed27a00a4e4a816f66e2772c5e04b3f876c08671af32842982bcc7f344410")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d8eb50a2b166e7b00f6a4e7ff64cb368d84fa789ff76ee84fae0912e178422fff4dc220610589d344a461acaf9487f231d50")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003291575a7deec69f9cdccec92a537b5c996e60a6c16f8502f1e4c873bc88dd2eb2036ba2bfa9cc7b515d721844ce251df61955")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032f78c4e84bff6fdc62404cfbd3bd360b5020bae564e47594ef6cbb4687065749579ab477623d2752f38f30eda3d2231a513b0")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032238b4f45101b2378b50acf8877b182bce2b994ff166cb95f6d319e2b50a0eb432ef7fc556a0e66752fe8ebb0b4184c38820c")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032733fccbeee6e78f3b72f8d61838721f689c4a6a6b1cf8f0fb6bfa1bbdf860ac1631567de443b9cdde8ccdb458b12413f1a1c")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032c90966b40d34249e60eb49d24d9476c89e19721a2d32ce4dbf125a6ffc0a3a9bf3423328ae97e7a2227a08da8e4d1d5031e9")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d2a6ee04c8d800b1ce42e223d6a16afb88657a46663d7256288e6949b751b4df845a9f544a2366e7976f9ff491e4779dc414")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003231393c7ad99747b2470f24302b28df856506a16ec7b88e77e2c37e2a7a7580d0d6122c63e2f34b63de3011526e6ce4b16bfe")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003243eed07a5364f230d0689c7cc97a2945a7a7e8e8535fa147e665e20bce1d8370e96be7629f34aa72d2a9031c90faf92b8383")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032ed3c51065378b01e143fa64a2eb8322fcf01207c740437b9a9470a67815e541ee1cc3da71349c9092bc296e2d20da0401203")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003245717b18df4bb6559caca87349389d9b5567267c640f8289f6caf7c701dc11d0decd9996c47227cc6418c3b13bedd9f4086c")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000327b874b96f0e15bbd6793ba29bd74a4f969f75697e1a817ddba599b2878885724727a32624758df64f86e09d78667e26b4ada")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d05f7d8a539a15e7e19eff71fd29a71c6f58bf920456d8a1348f1225fc1d0b1abbc25bce80a645839d272389faf7a0d4367d")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032cff461a64922b85186de7534bdac9739c57bd8dccd9c0b543a2c1cb1a2edbdbcc7541c03dab9665eda1bc07682ce3dcf4f22")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003293e1bba1aabdbfeb2464739ae16a84f5840e498b935bce15d2900a592d33446c14e9b9bfd8d05b4e24d0142a9027b8a15f11")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032e25d9efd7886e96a214344bbd44c046b223bd1ee5f0b636c5e07d3bec60fed5d37c0d46a2384516ecb02520a8dc06f83f747")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032504078569c55a0290ea78f4a3b765cd00d69a3f60ad695b42d652b285caf3aea639aadb694e24f374ee493445fdb428c95de")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000326016203993655595c7785d3a0c912bfd6af29601429fb773514ed6eb27f376f56384f52c65f9090fa4627cf17b3c4c577685")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032b1aa7f19ddb6c0596f48447d7aa8253d8faca7bf9bfdb76217500e6a9f1fb794c2c5dba36a4d7efafdbc74d28b7b6f362343")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003212a1e3a99bb412bbe14ebc9e94287994e7846e14ac765809eef7e87289665d0089ed4f3399d547f9156ed34a0598852d52a4")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032daff4096ebd3998e748de36a262e718514577baf7ad16d6be978d382ff83fceefd37cc18940c9f9d7f88e1797023fdd4a017")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032721e876088c86121667780e9a32ed92c749bb018e06157b1c7dcd81d7d35de08e3886338b1c6309b15b099c98281ebb79662")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032526753596f9c5784ef6306c04cadf30f3fa650c2ce49bea66bbbe67580585f7e21cc4d04a16b0f2a3729881307020ee35efa")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032c01ae6a79a209dfdc911d4119a57ee9184ac38ccba8475d39c40010d2ae5fbb61fa0b0846cdff83afb9f35e63331743fe8b7")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032098da2e58e0ce97593e9cab30bf362537a49ebe30469fc08aad3e75c9ccdd067d73afa042656a1395d15197f98d3ed1034e0")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032552d852202e4eb34b89b801b10d0402a9d698897e6f9d650f685064794d16c7f93755da6db19cd37de31a41746bbb43199e8")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003232f0e7f5f675470e9df5d3afc38716873cb0ade0c4b0e1b5e6275d3adf97e260b10fb74fc379407ccb329c4e06645d80c4ab")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032188a7d952a3e631dc16f1ec82e2c5cafd39005006737d047c276aa7ef03325d4405c9e2bd86ad616d9d343dc8cf2b4543a43")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000327be4de0d544dd47d91d7e218a16ee75597137e5f4d95e868a9a0939cc41f3d36bae7c2e769f5a6c5607b6f314d667d1a7dd9")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003251ae5351c98c4595cce67cec410a6609a15472670b6841cc12719e645b97aad11afce304cb7ffe866cd9297717de348d25c6")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003203e0c81000000000006cfe8df49885ea5ba8005b075db957a0f11d524a1f226a2da39e912e990ca93efd601cd5c5ad704c15")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032a04d2ac2359779c862da0f836c50496a8f453bcf553a7c4d62a37fee67ec8a20a36f81af6aba26e3d9696bf00ed53ee920b7")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003249bdc33b851f41aed3dd6487f52cc7263f6a32375325505d5ccaa2f5b4beec689469eef841d21487db101eb42638a141e0cf")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000321d40ea7e25d577e5f21365e2bb51f7a21512c2a47bbd37a6f5f83d4deccc7751c2530d2d155d82d6476dd011affc56387722")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032ec908730a29085e5990bcfde4cab6146b4e2826b6fd9c2995f251acf5ef68949d32789b09a55c11cbed7b01af860cd329d5d")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000325ec9a23e869ab2632dc34a7f3ac9735eefa22300bb996a9ef5b307cc451f1b4e99cfe1fe53a1b985699d8b255899e9647eb3")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032b12095175c378ccf525fdba70abb1def63b46caf43aeaad7ee8bc042ea241f191747475d7878319168767b24b59cccf338e6")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032093ccccb7b3c16b8b90e1910e1206245f97f3f0078d66021ce66b6071d207ea411765258432fa2ea05b25bddcfa1f1a6b5d2")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032900dae28c2bddc6f9a19e0ef43abf1616a2f6cab86e69bccb79d491e81b10e00680ebaec48565fb31e236e998a6a97cbc57b")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032b21d6a5c86aba37b1a9bbf196ce20c7f2242b4c92a742e9d98da45374f63c9b7b2b2e59c60d6dfd54e2a34821f60a7677722")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003288b9b23b28444bf4117d4e8651c48f9131ecaab2ddcd6c9e46aaae1e307f8406e6bb3361b3cf3bdf19341b4365a3c34f6cde")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003236c1dbe6daaacfbbff6187d52600c4c0c52468c3ff4bed76dc6303b836511c109aa8bc999f0af3c09630c43ab401d39dc534")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000322b2958f3d82920e8ebbba512fed1169b63c11197caf4cd9f4be729c61f3100545ad8ce3e4cd4c2cd70fc1de379bfb8c27802")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000320a9af20a8355a778a34410c7bfd06704fa80384c017e4a5c3ebc4890ce9154c1e11fe6b3576d16b1e7d3e8869d1a1076b30c")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003294e92c7df3506420a649483f7470e6972c31257bb276fcbf66dbf0c26cf4269d08f05437cf731635a579765ca8d036140373")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032b133d01c02a8ebee4f28bc59de4ed82eedf5c261bd83deb4dc782fd79e8c5cd2de4137a0f4c9078efc4712ec89effa7c2f31")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000329dfee6a7f24e50ca37969dab0a59f2ffd09620dba8281496370aba99b897739f556f7862ec61faae13a57528ec038977e55d")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000325d4f6eaa8af4a5ed07e777f04ffe23e696da446cc837db724f8262ac150f9b7591d4ec4757a9f6ff6cc051933e270a0d7b5d")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d4dff2d5511d8e1b2627561acc636524e0861e42cd461cf064908ee09664a20b34f717b4f8081014149cdc13dc1ec3921c51")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000325e2f4095dcc63b4fa4167527d2da7458b6b86ebf2e1fe7762fc07df50a31998bf8635b093687afdb91e7603e73dc92eaab38")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032f95aa2bb22e7f5404440880b828b4c07f58210a35c600364afc87065eac9ad971cb3deb446c3a4287657737c870e5575af7d")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d4d9ffa4ce4c240431fc3f64d0ed0a3f102e7b37e98ee68bb3e549b5b466613571ab4f05ef939dfd3ff4e6c3748c924bb0a4")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003229202a697dc7231aaf2f14a690546cb6d2b53a648bd1943543f7840e48ff33914f2813b872d02bc2b8a5d595f6a71a932bf7")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032f3deb4ee014ce963470f8ae73a9ceb9c35004c20161626ad7546624837e7afd777f03a8ac908ae5fc57b02284bb190ee5708")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032e94f62af336eba956288b3cdd7e85408b36a078090079bba6c287eaa70646278ec2a56491cccbd6f737417fc555233a5ef54")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d44d69283da5d291dea4b5e0f3a6fb1a9b887eb3c0f2b9e47cf7cf232815b3326624e97026dfdf1f84bccc30502a1930d966")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032ca2012c9e617f9b349c14bbb2dbb3107188f37eb8e5219bd606665df1c03aa2b6a25369e0cb09343a8d0982dafb23468668e")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003221f436c17b361460874df27c18cca020bee6d6b0db86be0bc8611b03c8e599b1dae4b2b4b40c6ef37b3139ebfedf99b75403")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003214cbbcc435c94c45c0dc7e21f6dc871f652cfc1a970a0b56986e513927dd2211fc05875303667cb9adc9e0eee42f2706a81e")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003266b4bcd51fb27cc4d1c95fbe87e0835c1e77a19c7ecd141435d9379e765ea7ad720388b4448b50736a5d49eeb2f7b78d09ad")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032e267fc01fcab778d776973ce278c603780652b9ef734db74ba3b6eed35bb8fba1e1e3da7c12a73bee0487f452b78611cf412")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032375971ec669646a4550bd5aeaa2a6799a36233d42d80547ce842b7fa1abe794950f4cdb6b365b3b2c769643f1bb82c147bb5")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032389f25517f8268cd60e13babd06b69c1b828526a5500b8b1f7d681fd1b4feca57eac252dc061914887b3ab86e5c63de17065")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000320eb0ec3745af205df4453cde141c89e5fa100892ec26569700a37c597fa277eec6953ac9afc3f0f2d64d9d3661e5e28534f5")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032918a2534a89a111d7880e9dc8ea0beff8321b68d2cf4c6c9171eb0da4136026d0403a590dd5f108042aabdfb73790f4795e6")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032c6dac200f1f4c75a9b55aec182048b033cb9c71b08185919dee9a8e82af7793681a1a84944bfdee76d96eebe79a4dd45df0f")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000321f3b8e105089beecac213b5fee8e7cab1f0ee916b8d6eece63a8d20c3202d9205aa20c3d1ffa692e3a95708d9f514590050e")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032b7ce283905cf7493e998073e450132a1bc3950bed82beea95966f6b8204394f6427687ab6de5e83f12a6370902b2032b7831")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032cc74ae508e071327ad01d93035abbef6e58ef9a13b3ee316099cd1d243b1df05560a2eaf615edcc8479a976e529830e972a9")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d9f7315f3233b7c37f021550a411338dea755498964ffca3451002cdc154a008bb52ffa53963b8f25906798f7c32340d97ea")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032857f902ecf5d3e681b233c75388da7dc11d524c603797eb02bf98e063f5fe0f2fb5c96c8301cfb309ed819391a870cdebef0")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032f22440fddf2487c19e3949126efefd5dbeee6dc36cebfb57c54530f18a4d5f93d931244099874ea0db0f0ff45d77e21e2003")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032e276f43dd851aacd1fd07afe25189dfbbe30ab28548eb3255afbff73bda03e499062d8643df50420306091df3238e68a4cd3")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000320dc9b7296a3244c5735ea40d4ef0daf27506537f5abcc09f068f7e69f6473a3253acafb814064fe00d39a80e103949bf80aa")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000326041e87232a7be02215bda1f39fbf0360c70422f44157f9ecf678891ea5aa43ef905c2ddb1d637317eeea25907b3163fa6ad")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032c70a604ba7f76316ca8a1bacd6d5e2a4ae23661dc182bf920cc649bd6f5818416d3f6bab8e597e029c3d776f6b39b0f35e73")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d2d0178e1d23f2068987d5f91b884f29515868b6a8a301428e59756466379ebcc281f0d68f5dc8cd96dbe62bf8d6691329d1")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003224113e21d95208e56deb4c6f4c993474741c6d0ab6588229a5e615f90935082a171d07777da118dd0efc1f07fe7cde872062")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032a1948369980481998896ec258671f14cecb4755ec6a44c9513002ffe0b02949cbf40ea18e451d936954f752eb80cd99628b8")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032b38bed40ecf9084aa469ee53108fb5ce438cc149b92ca6c58c12e749d2ed3b5861f07fedd07403a71e3578571f6e5c21c044")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032e8125d796a5093184589324ed4cf0293104a47fa858bdbef26d421682ab04b2b74779d23135e3d22e14941a07f49b7864507")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000328999a9d67eb844b2d6544ab6b14990440418e619b401ea2ff98ecbba72e8a98206cf82658e16a11a884867a51c51e72d32e0")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003215642c0690dae0b061cd48784120565b3e034ba605974aec9a8bc2917c2f940ce2a00a0f7e54ac3fbb8766a07e1fd5261258")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d672c25f520495df32ff1f6866641e52870a614e352b3907e5db7c2e6b00dc11f81268ca68888d7f2feb3f943d000fb3bd35")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000320223d17de58a677eb905977bbde952b0b5bebaec4ed0d14d3dee2f079a62e5087261319974b1ffa5bc3fadec9684985246e9")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000324ca7bdaadfd13a7e6795fbbfcb2988d1f2cbc009ed550d4bc6260058b1532f196191f6ce6b28cc9b0d058728903501369d92")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000327b34f5ccd7b9b13ccd9f62e89825bed84f9a5e6c413f6ee824926b06f02642e13654a55e2fb6d640065d737654426a323519")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000322791fe455e7354b66c09686055731179a9d21bab30677a48e06798f4601ce226678f0880919fd3df9e1a623a129d7f3ee391")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003205e2a1bda3119723bf1f47846cbe45a502a8c0e6bff68c13c618d3c4d95e5d75b61a38acbad936077f2799694f9201259250")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000326db5787e83364a5065d545a58d965f6661717574a82b87f97f39733fde5ba7ea21c93e6f712f286c7fc6b4378165b2c8fe8a")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d2d4bb7a37c744bca19e9ae07f3b34c59a17970f57dfa8f2a157b91b4ed7126c3180c16b22f8f8ba4b8cac786811066303c7")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000324a22a9c22f5f07e5789a1f7ff7592f21dd5361e00ee1fc31c580f274ac5a78239f151ff9792bfff8411debd1edd5bd550861")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032f5f208bfb08c414e2834cc69d1e3b9015c28766b903f130c23c070185d1054b9ba9313eace3fa86e47649171ee62122568f7")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032fba88e6a6428e94b0714be9500980d8e91ab903c043b8433c3c8ebea760dd3273cc6f383764b0710addb2777230e6d51cd7d")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032eaf426c7f1ee7127f9d0e23767c86dc5dbcd4e88aa8c0bfeaf94cc1de1971a3352e4a0aae1325fd1103458202d7debc24348")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032433b06752aceeea49b3118d51cf327909fdaf41812e0311e4021624d6c5f87657a34b9caa616ad28c86ebf0da68b7bfe1fe5")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032969294c9b113562f4655178f5c9bf8d4b684c50766a21c3a984fe58001530f54f2ef1532ba0d5f1d514d8fe81665dcc95e5c")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032b153b9705bbc78761e29eb6b0ff09c3b2c5bcdc6dd3d926ab2b2f653b9005e9d1433ab43572cfdbbf611444d8091627b6409")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003239d52f1292b3ced5de416f8c60bd64ccaa20fa7d8cb94259d7e88830a0691b9a22f7082d11689d8998b8e047aed7b184645a")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003214f3830d179d0d35d88d3b8bf1cf8669a433094a089149c334b77587c0e41dc54987e9df45903a856f2c9703beef4e0be435")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032247a446b38ab68f5c5f63e020085540e66097321062a8a74e294893bc5a0fe13460ad4b39f09d9bf49be2d60f4d200822797")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032995b713445c9d7fce361351d4713560a8c5d15a30b7902818ee95e1c2ff0c6e74b36862f462477503090b124ff3e21eea237")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032384dc9b10c8910e4682bf322e2cf388a5e561c9c50fe894f26c8e31039f3419ee9919baa6dddba19b45cf71c11bcee972ac1")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000328166b3d7f5577716e229901eb9430f83f822023cf1dd7a310b47c31a9494d7c38cecd702167d272d4116643ca94736daf257")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032834dcbb552df1d0fd831da3805d5777f806d879637aacb30af22c2de3f6bd824c7700f01cc94ac2a0fbb17a5a21bbf7e517c")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003287bc57c594292ca253704afcc982d3be8aa28b64201b48b46471262def9f322c3393b5dbf2014ba9bcc66d51f51b91db3008")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032c8c770667dc94def246a8472446d6e9fb3636d0f1b812a22d0944a91ac33bf99fb2cd4a5486bfafd70203f821bbdb79a80ba")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000321d1814de24df9a61f00fa046cf611e1486d5606b8bc2ff108ace735d65c7696e1813c561033352397360bce27d0e113e77de")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032fa1e77adc2400e1ee4b4e272b5873a2ac5454b79a2a7e06f1912218049d4e215d6b2ebc455a216782a0cfbff50956a312087")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000325a49855c1ff02adfd86741bb2331e7dd75f23955424ca6015171c2169214a320aedab0d3d8a5fba05417bab631bdfa3eed70")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003287292ae0e6ceb497f535400eef28c74559ebc516039804a116a17b04fa75fcc535b4143e21adab455df2c616f20fab76f5cf")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000328f8217461945e9af871ecd4632e8cb34fe5d910d68bca784912e130d3c5effd5edf46f4e3f8e317f569ed9a7b2195a19d291")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003287871c55c38cac04111d6ded0a3cd44fb479bb976009977f55b17e92e4422e79b602cddc5596443135716e75d3714bbaf5b4")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003276ab8c93f9342979a38e88dcd289fab2a07c61f7ab229ff02d4544c8226a6de1b8946def21e719a22379ccabee41c8508566")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000322f5da201947be59450eecd88e841537690aeab3cd98a2ae9897705c77b96a8fa6eda2c2ec5b3206e08ccdc204d011abbfc7b")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032577902bccd5f5f6422173b4f7fe975f4c93ef95e43cd0fdad843606b2710b07d5da288b2fde5ff93de35eb0b0c2ce1560c2c")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032c316c6fab0f7a60ee7dc20eca539b8c2bf85cecad5fd13a6c0a29273f6cdc01a011a8441c79ff4beb3016c2677a641938e8b")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003295d6771a40673e0c79489dfe32329fc852d1453e04dc3163a3c1a3eb71a3b98dbba4e4e51fac00a8242485d40329247513b0")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032839dfc095cf65a17dab8acf67d3789a975bb03edeb32d6119f0a5b3cdb2b92c50a3b6d66a7f8a5f7d4b60c83237d0fa27615")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032f696d73ff5dd49dfe626ec3962e1d65c4a4b373442c34946144d2d383c043bdc5874808b21be3dffe320a1e7061c3aaf181b")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003282721d3b7764a719fafc5d23d05aabd33f3edf6d403aa526025d1fc491c446750334ab4fbd9fb1cba986a300d3d81fbe64bd")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003207d122a17e3ecd8e24ab6e3c37b87d2701653dec669b48d96fde97d9090e9ea332a4f6c76b1d4ec8a5c5ccf3df6cb6a2cafb")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032840a2d981d2873bba28c7e45e98a7825e824523dd52bd35bdfc236e2001cf3bfaacc4c60530e9805eaf633000f7ca39aa60d")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032861826d94c3dbf897468fffe88755f4492555e06c2d58758c102e4538488bfe95b3b74a448e72b1959fd7b19f2b52bc7ee08")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032dc85c1231a5fd3c1dfc2d9e279c46008a84a8aa8be6f959bd3b0e96416a7a7b40ce4c8fbd27ca9fde72b2064dc693a258e85")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000323ad12a0f9be8aa724b5d4ce6819f20a200ac89d3c15ad6db02810c782d19a6b5b7e9b62fffc71dee4bb6bf121452ef3cacc9")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032637948b5b2ee04848e755629a3f730b100f11bf8e095a17b78b570ec7ec54e1ba2446d26c0bb151fd171cd3e5b8c161af853")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032051f967d9c96149b683c2c1dbc249d7208f9f10c58d463bd713f0d8997a334c35911a960cd57e1b8fcdf291ba69b90e3249d")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032aa6d3e2141a7691c0307150b953981c7861f22481a4f03fa769d1157ddc93f6bdc149b7023c31114496ba83514254b466a0b")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032349d2007c21fc547aff700a389268d76327676c9873fe760b71d62f785c737820fe5d3356eda490a8ffb7562f11e2b0dfa7a")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000323bcf7f2fcf2a801b263226c91031f8edbcb935731556aeccdb4d97893ca29e946d05803b016433dc20beaf83b9b60f9fbde4")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003290e1a0618cfed53407024890ead6991d811ddb5cd14d21982a1d99e9d72bb27b11d3102fd02d3d7027308073639a1ff1ec39")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032ca038c5eeb8cf5603f19e83be3bfc574842e85935a20a414a851efed6998cb00ae827d33c2eb2b0f51616cbfcf0cd02e8bc0")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000320559c3827d43aca756b7e36407254c3a107674a41989d69c0cd25cf220eb3a4228468b9693668e2e946d9aa9bf2e8105c738")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032fececb3486787007a292d4bad2a760015933c855b555be96b2e2622256bda6255e2ca7969696199b919ac7e22568387efec3")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000322f29270c36771c8be834fa1aac834db84a72dc1584299ed9ce45083ea53f074a9b5d55ad8c8ccc7e181666ac1e8f7a469b68")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032a90a4b93384ac3b01a4304e1b07d66632a88d3abc620c436b4e815fc33ebacf7304889b98dccaf28b8028b7bc4c934345b0a")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003297ab79db601379a32b057b96e5334ea15d2af585c7cbf568c28ed622ad96c728e523e228310b9b661ccaf9bc5dc5edd625aa")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032ff6ad87de4f4be746c56e774303e12a2f7fac1310622e009b611c5bfe9653bcf8c01982c57ff41bf8f4e5ac7628f99fdae13")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000328a1e66f684cbbbfa218d9d7104781e227262d50bd284f2096977e276e11fe107ec150bb605f614dbcbb6fb08d9c8184dbdbe")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003282699f83701c088f183a507c6477c00093a19b36d9dbd36ff25536dad0705158bda21cc9050f7523cb209fc6d79f310f01cc")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032c74c567654af502b57622b4db5203fef095dd55653035f889f03001b3a06e9c231eb35ef006a64f46cd7710db19075e49d72")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003237bffbbcd6896d91d994d91e787b723e28a93e423e5a325371b290d39f9fe4647217a9661616006b6d4bb82098d7c269e9de")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032b3d97c74c011e06a6a0ccb56de92c98e96dc19bb723626e1d8030346f9a7dfb040e76e6b1d6500bfc425cdd224f4112e16b2")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032754026e4c05a7a2c9ae96e1ba8791975ef756d9703b19d6f86da0142ebe2c90971560f32940fae0590c25f255a69f91c75dd")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003244b4fc3b84934c71c12fc1f6d16acbddb69bbb048331567efd6763c060f8ab2bf6651cd06dbab9219205c83c36b8de23b2de")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032076d383587a18f5f01e76b2a6fa9d604bf3e98db4c70daaeba79fe44b91af0c2ef1fc53340852ddd0b47dffea8ad65cfdfc8")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d159515965133b6481294e75c2855857f604fa4fd35891ecccd20289b6ae9ddb60586949156d624a29ea3c6358ec25544302")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032564b8e9b00deccab5cdb9820e4767ec6826b33314ca067699e6c69da9d5fad0ea62213285d486355305db1d5b2391392217e")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003238d4d87d4243c83afe2e26aa7609b4e95ff8dc4f41bc6430d76430d7bdfdf5a32e897b41ac3496c3745b86fdd62dd9c53d8f")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032e84b0aff97416e68f880fea9d0536880a99c8268013eda4619d636067017fcad5ad979f2255fa57a574c4792cfaf017a45d2")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032519d4018c64a00e6c42352c84e4fc4ff9c2cac9eb59b7ec56f28faaf249d9cfbc22e3653db54cba6ce27d6d8867c6bbbd6d0")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000327fa1c3c816038ad534ad63c6e9a112f5534a0f390bdc6c05dc8d19f3502003dbbee74c074254945c7232e994df7cdfbbd0c2")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003255fb520c7e07115c8d44baea44595ceabd857d690b049cddbadaad43c33a624fd764dd90862b997b149f2305364a4ef9eefd")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032c670e59092e7fbe38915266946a4ab6f07f0d42b03306cf678ee6802f5ab6df79101413f581cfa56b429d59096eaf1399b30")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000323532522688ca0ae363c770c70ffc1764230b61648ed1e14d742cb19bd70611cfbe3c0ca0c2654e2f1777e8bed1b49bd9e51d")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003246dd6634123f0c7a0d7314fd311e973b415b5d3436ceb5c2060f629522d102b2b48b596cbc19530387929d136ee6953da9ab")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000327617e040e534c4a880bfb7d13722df1696e358582b519d402fa05a61911458f6efff4f32669a6a8b948b42a6f0354a9c9659")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032d118c8495ee25a5b2243643073b4a7abc0ff40fad3daa844445c0c909147682a07a4964c6cd9372795d555083d3b28857703")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003271d5fbb78a797badd7554d1659c2dc7fbb00b107b39f2d562701d8c86d2f77946d257fd65f72a3536d1c76d80f8728927bf0")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032c53be34a9dcb2c1dabcca9cfa9f84e36dd3b5039fcf106e4489715d6aa6ef387d8c38391ad61c21111493cb5080461b7cbe6")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003286777f0e619764b3a9be2414c7ec1ee212d474ca45256e4ed49637644e812d06151bbe44124ad4ef5287a8ac15b74f84c1c7")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000324dbc86ad368631c85e1eb74cfb97fb9320e0ad1a8c224f9cd415f364146a1ceb95e1d40cb8c15cd38c8a9f0684903439a5b7")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000326d9ac5247a3607082b56e44b9c3f63f785b0f1ad2b241cb2a3dac103a9b0de108b8b67ce4302b57036e62f589cbe480503a8")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003239e0915b4bef0a77356125ed548f8c84aee8e5f7e9bb268b0536d44b0a87363cc191262f52c972f8273ad17bf229c2c4a943")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032362f3438723255e488cf89c555a0f777064de46030fc625d7ee4de4b6ee3ab3dade0b6a52dcaf6209150dba2450d1fe8eea8")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032fcd70c9d097be7cf5e24dadf3cb733a2e28b6736d6398e0a3bef0a3f095c276b8bfd13d3e26ccc9bbfc6c666c93b7c2400b6")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000324f0a35a00a60d2cb1931d861e38fd79c430f9fe170528ef6e6a71ef3b409a2e2c8fd6435c8d6ba914a19e852dc3768bb2732")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000322eb99047dff1e290e89234b0351b15d2ebf86b61831cbd2ac23dc5e9f083c3bdd87538e66e6f5f1516704762b8682366a6c1")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04280003266b73622f59da30b2c09f3d4255888abb6b51c3637eeaf6cd4554603e18c01f96f1cdd1afabfb449cf1104c92d651a8ce98a")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032da871074e6bdd4ba0c23c35e043a2bbadad8cc2017dcd0c3bc2b2ec18b9458661febda501634272de858af18a67b17d22a46")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032eb3ceb5379a1f9228cd88179aa118eba2bc15d311087881e19904cbb967945eb7d0e22875d854b37e3a6b6c7f16d6791dfec")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032212bbd902936f8c1e9f59d8093b56494cab299f7cb68f0aba306a598c0ce08b873e5c2c9841dec93abdd209bf2cbce89de0d")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000326b8f5ec9716a891c198f15e5b6f7e14aee20e4b33924f430e381785f72b1edf025900551ecbeaf42381a8f02b815e9944a2d")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032987a429d704ca191c778373d0357cbff6a814947bf2188ef16810dd1ab2abfd8fa8e8e55e5d50d508658fd0e7986e1939b96")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032894a895d419022731078be994dee157ab6e06dd578e0d665490c23f51b139b9802bffc0baff177652e37d1b7c8cf744feff1")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032ef1acb003f803530c89d60b899bc3e54079da17c5cc487ccc555ab83ebd36d44b401f772169dea21bd14563007373e0e55ca")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000321a084d35fa557ef0c66a57f708912193a6cb1f924d28037c98e42a44153fe28ddb7023aa8bc77a60806c4a0d8be104a42004")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e042800032dda77aa056165106b0b13510dd97514e3bd5f4059b2f9b525b565bc798020e4582c6060248c8075628cd39d663497ade707a")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e0428000324be75a347b27ef86fb9d73f1fec0d2c877b42f28b999406f533b158ed8c2b05180966c375922eaffb8a096c4ae9eed2b073d")
    assert sw == 0x3200c3ae3a432e4d8b16f615f20578f59bb1c7aae9aa5d5804dc797f0d652f997e84b6fa00000000488e1000000000006afe191e73ec03839000
    sw, sig = transport.exchange_raw("e040000015058000002c80000085800000010000000000000000")
    assert sw == 0x41043ae1203a68dc462d508414743e1b06308f06d61604368bc83bd3bfe580adb80ee5a6f7e8366cf1d85f494481324d98f016424c49d00301f30b97cdcf705ba417237431656f45704a34524e4a476f313144714b5348704c32364a78666b5445323537553162907186e91952df6e922a4ec72ff97e80087a35b839ee2c4d1e4c27b17b088d9000
    sw, sig = transport.exchange_raw("e04400050d050000800a27a7265510e7c801")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04480053b01383200c3ae3a432e4d8b16f615f20578f59bb1c7aae9aa5d5804dc797f0d652f997e84b6fa00000000488e1000000000006afe191e73ec038319")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04480051d76a914e58749ee655c0e39ae3ce063a33fb9edc86d23dd88ac00000000")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04aff0015058000002c80000085800000010000000100000000")
    assert sw == 0x9000
    sw, sig = transport.exchange_raw("e04a00003202400d0300000000001976a914a96e684ec46cd8a2f98d6ef4b847c0ee88395e9388ac560d0a00000000001976a9143cd4f5")
    assert sw == 0x6985

    # sw, _ = transport.exchange_raw("e04280000101")
    # assert sw == 0x9000
    # sw, _ = transport.exchange_raw("e04200001100000000050000800a27a7265510e7c800")
    # assert sw == 0x01055a6361736805322e332e3201029000
    # sw, _ = transport.exchange_raw("b001000000")
    # assert sw == 0x41048ddaf0918c79a22c095af0c7700923d80d07b9d614ce132ae75bc4fbeecebddb809e284082059bf69992b18d398a328dd917773c0d5fa6b5948d3b7a9bfd924b237431613166435a69474539467833426679316865457847334c7a3261755566666e7a79f159e77b829e0715d27d0b4b9e5f3a51d1d959188ecc6d38bf85f15bf6292ed69000
    # sw, sig = transport.exchange_raw("e040000015058000002c80000085800000010000000000000001")
    # assert sw == 0x01055a6361736805322e332e3201029000
    # sw, sig = transport.exchange_raw("b001000000")
    # assert sw == 0x9000
