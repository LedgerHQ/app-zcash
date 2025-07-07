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
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, txid = transport.exchange_raw("e0428000090000000004f9081a00")
    txid = txid.hex()
    print(f"MAY: txid: {txid}")
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
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000
    sw, txid = transport.exchange_raw("e042800014000000000f000000000000000000000000000000")
    print(f"NU6: txid: {txid.hex()}")
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
