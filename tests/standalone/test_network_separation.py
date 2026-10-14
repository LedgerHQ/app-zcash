"""The mainnet build refuses every testnet path, coin type `1'`.

The two builds are told apart by their coin type alone: the mainnet one declares `44'/133'` and
`32'/133'`, the testnet one `44'/1'` and `32'/1'`. The testnet suite checks that its build refuses
`133'`; these check the converse, on every command that takes a path. A refusal has to come back as
a status word: left to the OS, the derivation would take the app down instead of answering.
"""

import pytest
from application_client.pczt import (
    PcztGlobal,
    PcztOrchardAction,
    PcztOrchardBundle,
    PcztTransparentInput,
)
from application_client.zcash_command_sender import (
    CLA,
    P1,
    Errors,
    GetShieldedAddressMode,
    GetVkMode,
    InsType,
    ZcashCommandSender,
)
from legacy_flow import hash_sign_apdu, open_legacy_signing
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

HARDENED = 0x8000_0000
MAINNET_PUBLIC_KEY_PATH = "m/44'/133'/0'/0/0"


def _assert_still_answering(client: ZcashCommandSender) -> None:
    assert client.get_public_key(path=MAINNET_PUBLIC_KEY_PATH).data


@pytest.mark.parametrize(
    "path",
    ["m/44'/1'/0'/0/0", "m/44'/1'", "m/32'/1'/0'"],
    ids=["testnet_account", "testnet_prefix", "testnet_shielded"],
)
def test_testnet_paths_refused_for_public_key(backend, path):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_public_key(path=path)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0
    _assert_still_answering(client)


def test_testnet_path_refused_for_orchard_fvk(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.GET_VK,
            p1=P1.P1_GET_VK_FIRST,
            p2=GetVkMode.ORCHARD_FVK,
            data=pack_derivation_path("m/32'/1'/0'"),
        )

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0


@pytest.mark.parametrize(
    "orchard_path, transparent_path",
    [
        ("m/32'/1'/0'", "m/44'/1'/0'"),
        ("m/32'/133'/0'", "m/44'/1'/0'"),
        ("m/32'/1'/0'", "m/44'/133'/0'"),
    ],
    ids=["both_testnet", "testnet_transparent", "testnet_shielded"],
)
def test_testnet_paths_refused_for_ufvk(backend, orchard_path, transparent_path):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.GET_VK,
            p1=P1.P1_GET_VK_FIRST,
            p2=GetVkMode.UFVK,
            data=pack_derivation_path(orchard_path) + pack_derivation_path(transparent_path),
        )

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0


@pytest.mark.parametrize(
    "mode, orchard_path, transparent_path",
    [
        (GetShieldedAddressMode.ORCHARD_RAW_ADDRESS, "m/32'/1'/0'", None),
        (GetShieldedAddressMode.UADDRESS, "m/32'/1'/0'", "m/44'/133'/0'"),
        (GetShieldedAddressMode.UADDRESS, "m/32'/133'/0'", "m/44'/1'/0'"),
    ],
    ids=["raw_address", "unified_address_testnet_shielded", "unified_address_testnet_transparent"],
)
def test_testnet_path_refused_for_shielded_address(backend, mode, orchard_path, transparent_path):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_shielded_address(path=orchard_path, mode=mode, transparent_path=transparent_path)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0
    _assert_still_answering(client)


def test_pczt_testnet_coin_type_refused(backend):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(pczt_global=PcztGlobal(coin_type=1), transparent_inputs=[], transparent_outputs=[]):
            pass

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0
    _assert_still_answering(client)


def test_pczt_testnet_input_path_refused(backend):
    client = ZcashCommandSender(backend)
    txin = PcztTransparentInput(
        prevout_txid=bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"),
        prevout_index=0,
        value=81630485,
        script_pubkey=bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac"),
        sequence=bytes.fromhex("00000000"),
        signing_path="m/44'/1'/0'/0/2",
    )

    client._send_pczt_header(PcztGlobal())
    with pytest.raises(ExceptionRAPDU) as e:
        client._send_pczt_transparent_inputs([txin])

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0
    _assert_still_answering(client)


def test_pczt_testnet_orchard_account_refused(backend):
    """The account path rides in its own packet, the second of each action, so it is refused there."""
    action = PcztOrchardAction(
        cv_net=bytes(32),
        nullifier=bytes(32),
        spend_recipient=bytes(43),
        spend_rho=bytes(32),
        spend_rseed=bytes(32),
        rk=bytes(32),
        alpha=bytes(32),
        signing_path="m/32'/1'/0'",
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
    with pytest.raises(ExceptionRAPDU) as e:
        send(2)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0
    _assert_still_answering(client)


@pytest.mark.parametrize("coin_type", [133, 1], ids=["mainnet", "testnet"])
def test_legacy_signing_follows_the_coin_type(backend, scenario_navigator: NavigateWithScenario, coin_type):
    """The legacy transaction is reviewed and ready to sign; HASH_SIGN then names the key.

    The mainnet key signs and the testnet one is refused, over the same round, so the refusal can
    only come from the path. The review is the one `test_sign_tx_v5_old` compares, so its screens
    are not compared again here.
    """
    transport = ZcashCommandSender(backend)
    open_legacy_signing(transport, lambda: _approve_without_comparing(scenario_navigator))
    apdu = hash_sign_apdu([44 | HARDENED, coin_type | HARDENED, HARDENED, 0, 2])

    if coin_type == 133:
        sw, signature = transport.exchange_raw(apdu)
        assert sw == 0x9000
        assert signature
        return

    with pytest.raises(ExceptionRAPDU) as e:
        transport.exchange_raw(apdu)
    assert e.value.status == Errors.SW_CONDITIONS_OF_USE_NOT_SATISFIED
    assert len(e.value.data) == 0


def _approve_without_comparing(scenario_navigator: NavigateWithScenario) -> None:
    scenario = NavigationScenarioData(scenario_navigator.device, scenario_navigator.backend, UseCase.TX_REVIEW, True)
    if scenario_navigator.device.touchable:
        scenario.validation = scenario.validation[:-1]
    scenario_navigator.navigator.navigate_until_text(
        navigate_instruction=scenario.navigation,
        validation_instructions=scenario.validation,
        text=scenario.pattern,
        screen_change_after_last_instruction=False,
    )
