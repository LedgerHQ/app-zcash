import hashlib

import pytest
from application_client.pczt import (
    PcztGlobal,
    PcztOrchardAction,
    PcztOrchardBundle,
    PcztTransparentInput,
    PcztTransparentOutput,
    pczt_transaction_bytes,
)
from application_client.zcash_command_sender import Errors, ZcashCommandSender
from application_client.zcash_response_unpacker import unpack_get_public_key_response
from application_client.zcash_utils import (
    T_ADDRESS_TESTNET_VERSION_BYTES,
    ripemd160,
    t_address_from_pubkey,
)
from application_client.zcash_verify_sign import (
    check_orchard_spendauth_signature_validity,
    check_tx_v5_signature_validity,
    nu5_signature_digests,
)
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario

from .helpers import p2pkh_script, review_approve
from .testnet_vectors import (
    ORCHARD_ALPHA,
    ORCHARD_ANCHOR,
    ORCHARD_CMX,
    ORCHARD_CV_NET,
    ORCHARD_INTERNAL_RECIPIENT_ACCOUNT_0,
    ORCHARD_NULLIFIER,
    ORCHARD_RAW_ADDRESS_ACCOUNT_0,
    ORCHARD_RCV,
    ORCHARD_RK_ALPHA_1,
    ORCHARD_RSEED,
    ORCHARD_SPEND_RHO,
    ORCHARD_SPEND_RSEED,
    ORCHARD_SPEND_VALUE,
)

TESTNET_GLOBAL = PcztGlobal(coin_type=1)
INPUT_PATH = "m/44'/1'/0'/0/2"
CHANGE_PATH = "m/44'/1'/0'/1/0"
RECIPIENT_HASH = bytes.fromhex("42" * 20)
PREVOUT_TXID = bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a")


def _hash160(public_key: bytes) -> bytes:
    compressed = (b"\x02" if public_key[64] % 2 == 0 else b"\x03") + public_key[1:33]
    return ripemd160(hashlib.sha256(compressed).digest())


def _input_and_outputs(client: ZcashCommandSender):
    public_key, address, _ = unpack_get_public_key_response(client.get_public_key(path=INPUT_PATH).data)
    assert address == t_address_from_pubkey(public_key, T_ADDRESS_TESTNET_VERSION_BYTES)

    txin = PcztTransparentInput(
        prevout_txid=PREVOUT_TXID,
        prevout_index=0,
        value=81630485,
        script_pubkey=p2pkh_script(_hash160(public_key)),
        sequence=bytes.fromhex("00000000"),
        signing_path=INPUT_PATH,
    )
    recipient = PcztTransparentOutput(
        value=40000000,
        script_pubkey=p2pkh_script(RECIPIENT_HASH),
    )
    change_public_key, _, _ = unpack_get_public_key_response(client.get_public_key(path=CHANGE_PATH).data)
    change = PcztTransparentOutput(
        value=41628485,
        script_pubkey=p2pkh_script(_hash160(change_public_key)),
        signing_path=CHANGE_PATH,
    )
    return public_key, txin, [recipient, change]


def test_sign_transparent_testnet(backend, scenario_navigator: NavigateWithScenario):
    client = ZcashCommandSender(backend)
    public_key, txin, outputs = _input_and_outputs(client)
    tx_bytes = pczt_transaction_bytes(TESTNET_GLOBAL, [txin], outputs)

    with client.send_pczt(pczt_global=TESTNET_GLOBAL, transparent_inputs=[txin], transparent_outputs=outputs):
        review_approve(scenario_navigator, "test_sign_transparent_testnet")

    signature = client.pczt_sign_transparent(input_index=0).data[:-1]

    assert check_tx_v5_signature_validity(
        public_key, signature, tx_bytes, input_index=0, input_amounts=[txin.value]
    )


def test_sign_pczt_mainnet_coin_type_refused(backend):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PcztGlobal(coin_type=133),
            transparent_inputs=[],
            transparent_outputs=[],
        ):
            pass

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0
    # The app is still answering.
    assert client.get_public_key(path="m/44'/1'/0'/0/0").data


def test_sign_pczt_mainnet_input_path_refused(backend):
    client = ZcashCommandSender(backend)
    _, txin, outputs = _input_and_outputs(client)
    txin.signing_path = "m/44'/133'/0'/0/2"

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(pczt_global=TESTNET_GLOBAL, transparent_inputs=[txin], transparent_outputs=outputs):
            pass

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert client.get_public_key(path="m/44'/1'/0'/0/0").data


def _orchard_bundle() -> PcztOrchardBundle:
    action = PcztOrchardAction(
        cv_net=ORCHARD_CV_NET,
        nullifier=ORCHARD_NULLIFIER,
        spend_recipient=ORCHARD_RAW_ADDRESS_ACCOUNT_0,
        spend_rho=ORCHARD_SPEND_RHO,
        spend_rseed=ORCHARD_SPEND_RSEED,
        rk=ORCHARD_RK_ALPHA_1,
        alpha=ORCHARD_ALPHA,
        signing_path="m/32'/1'/0'",
        cmx=ORCHARD_CMX,
        ephemeral_key=bytes(32),
        enc_ciphertext=bytes(580),
        out_ciphertext=bytes(80),
        rcv=ORCHARD_RCV,
        rseed=ORCHARD_RSEED,
        spend_value=ORCHARD_SPEND_VALUE,
        value=0,
        recipient=ORCHARD_INTERNAL_RECIPIENT_ACCOUNT_0,
    )
    return PcztOrchardBundle(actions=[action], flags=3, value_balance=ORCHARD_SPEND_VALUE, anchor=ORCHARD_ANCHOR)


def test_sign_orchard_testnet(backend, scenario_navigator: NavigateWithScenario):
    client = ZcashCommandSender(backend)
    bundle = _orchard_bundle()
    output = PcztTransparentOutput(
        value=299000,
        script_pubkey=p2pkh_script(RECIPIENT_HASH),
    )
    tx_bytes = pczt_transaction_bytes(TESTNET_GLOBAL, [], [output], bundle)

    with client.send_pczt(
        pczt_global=TESTNET_GLOBAL, transparent_inputs=[], transparent_outputs=[output], orchard_bundle=bundle
    ):
        review_approve(scenario_navigator, "test_sign_orchard_testnet")

    signature = client.pczt_sign_orchard(action_index=0).data

    assert len(signature) == 64
    digest = nu5_signature_digests(tx_bytes, [])["final_digest"]
    assert check_orchard_spendauth_signature_validity(bundle.actions[0].rk, signature, digest)


def test_sign_orchard_mainnet_account_refused(backend):
    client = ZcashCommandSender(backend)
    bundle = _orchard_bundle()
    bundle.actions[0].signing_path = "m/32'/133'/0'"
    output = PcztTransparentOutput(
        value=299000,
        script_pubkey=p2pkh_script(RECIPIENT_HASH),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=TESTNET_GLOBAL, transparent_inputs=[], transparent_outputs=[output], orchard_bundle=bundle
        ):
            pass

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert client.get_public_key(path="m/44'/1'/0'/0/0").data
