"""Each signing path has the shape of the key it names.

A transparent signature comes from a five-component BIP-44 path with a hardened account; an Orchard
or Ironwood spend authorization from a ZIP-32 account path. Any other shape names a key no wallet
derives for that purpose, so the app refuses it, whatever else the path gets right. Every refusal
here has a control that differs only in the path and is accepted.
"""

import pytest
from application_client.pczt import (
    PcztGlobal,
    PcztOrchardAction,
    PcztOrchardBundle,
    PcztTransparentInput,
)
from application_client.zcash_command_sender import CLA, Errors, InsType, ZcashCommandSender
from legacy_flow import hash_sign_apdu, open_legacy_signing
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario

from .test_network_separation import _approve_without_comparing

HARDENED = 0x8000_0000
PURPOSE_BIP44 = 44 | HARDENED
PURPOSE_ZIP32 = 32 | HARDENED
COIN_TYPE = 133 | HARDENED


@pytest.mark.parametrize(
    "path, accepted",
    [
        ([PURPOSE_BIP44, COIN_TYPE, HARDENED, 0, 2], True),
        ([PURPOSE_ZIP32, COIN_TYPE, HARDENED], False),
        ([PURPOSE_BIP44, COIN_TYPE, 5, 0, 2], False),
    ],
    ids=["bip44", "zip32_account_path", "unhardened_account"],
)
def test_legacy_signing_path_shape(backend, scenario_navigator: NavigateWithScenario, path, accepted):
    """HASH_SIGN after an approved review, naming the key by the path under test."""
    transport = ZcashCommandSender(backend)
    open_legacy_signing(transport, lambda: _approve_without_comparing(scenario_navigator))
    apdu = hash_sign_apdu(path)

    if accepted:
        sw, signature = transport.exchange_raw(apdu)
        assert sw == 0x9000
        assert signature
        return

    with pytest.raises(ExceptionRAPDU) as e:
        transport.exchange_raw(apdu)
    assert e.value.status == Errors.SW_CONDITIONS_OF_USE_NOT_SATISFIED
    assert len(e.value.data) == 0


@pytest.mark.parametrize(
    "signing_path, accepted",
    [
        ("m/44'/133'/0'/0/2", True),
        ("m/32'/133'/0'", False),
        ("m/44'/133'/5/0/2", False),
    ],
    ids=["bip44", "zip32_account_path", "unhardened_account"],
)
def test_pczt_transparent_input_path_shape(backend, signing_path, accepted):
    """The input packet carrying the path is accepted or refused on the path alone."""
    client = ZcashCommandSender(backend)
    txin = PcztTransparentInput(
        prevout_txid=bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"),
        prevout_index=0,
        value=81630485,
        script_pubkey=bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac"),
        sequence=bytes.fromhex("00000000"),
        signing_path=signing_path,
    )
    client._send_pczt_header(PcztGlobal())

    if accepted:
        client._send_pczt_transparent_inputs([txin])
        return

    with pytest.raises(ExceptionRAPDU) as e:
        client._send_pczt_transparent_inputs([txin])
    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0


@pytest.mark.parametrize(
    "signing_path, accepted",
    [
        ("m/32'/133'/0'", True),
        ("m/44'/133'/0'/0/0", False),
    ],
    ids=["zip32_account_path", "bip44"],
)
def test_pczt_orchard_action_path_shape(backend, signing_path, accepted):
    """The account path rides in its own packet, the second of each action, and is judged there."""
    action = PcztOrchardAction(
        cv_net=bytes(32),
        nullifier=bytes(32),
        spend_recipient=bytes(43),
        spend_rho=bytes(32),
        spend_rseed=bytes(32),
        rk=bytes(32),
        alpha=bytes(32),
        signing_path=signing_path,
        cmx=bytes(32),
        ephemeral_key=bytes(32),
        enc_ciphertext=bytes(580),
        out_ciphertext=bytes(80),
        rcv=bytes(32),
    )
    bundle = PcztOrchardBundle(actions=[action], flags=3, value_balance=0, anchor=bytes(32))
    client = ZcashCommandSender(backend)
    client._send_pczt_header(PcztGlobal())
    client._send_pczt_transparent_inputs([])
    client._send_pczt_transparent_outputs_sync([])
    packets = client._build_pczt_orchard_action_packets(bundle)

    def send(index: int) -> None:
        p1 = client._pczt_chunk_p1(index, len(packets))
        backend.exchange(cla=CLA, ins=InsType.PCZT_ORCHARD_ACTION, p1=p1, data=packets[index])

    # The action count, then the spend fields.
    send(0)
    send(1)

    if accepted:
        send(2)
        return

    with pytest.raises(ExceptionRAPDU) as e:
        send(2)
    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0
