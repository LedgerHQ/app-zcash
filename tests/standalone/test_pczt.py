# pylint: disable=C0301

import pytest

from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

from application_client.zcash_command_sender import (
    Errors,
    PcztTransparentInput,
    PcztTransparentOutput,
    ZcashCommandSender,
)
from application_client.zcash_response_unpacker import unpack_get_public_key_response
from application_client.zcash_verify_sign import check_tx_v5_signature_validity


PREVOUT_TXID = bytes.fromhex(
    "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"
)
PREVOUT_INDEX = 0
INPUT_VALUE = 81630485
INPUT_SCRIPT_PUBKEY = bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac")
INPUT_SEQUENCE = bytes.fromhex("00000000")
PCZT_TRANSPARENT_INPUT = PcztTransparentInput(
    prevout_txid=PREVOUT_TXID,
    prevout_index=PREVOUT_INDEX,
    value=INPUT_VALUE,
    script_pubkey=INPUT_SCRIPT_PUBKEY,
    sequence=INPUT_SEQUENCE,
)
SIMPLE_OUTPUT = PcztTransparentOutput(
    value=int.from_bytes(bytes.fromhex("958ddd0400000000"), byteorder="little"),
    script_pubkey=bytes.fromhex("76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"),
)
CHANGE_RECIPIENT_OUTPUT = PcztTransparentOutput(
    value=int.from_bytes(bytes.fromhex("005a620200000000"), byteorder="little"),
    script_pubkey=bytes.fromhex("76a9147d352e6e9a926965c677327443d86cb0bdf8b1e988ac"),
)
CHANGE_OUTPUT = PcztTransparentOutput(
    value=int.from_bytes(bytes.fromhex("c11b7b0200000000"), byteorder="little"),
    script_pubkey=bytes.fromhex("76a914adee44a1e8d1bbfd9e000bdcc4d99849abe339f588ac"),
)


def _review_approve(
    scenario_navigator: NavigateWithScenario,
    snapshot_test_name: str,
) -> None:
    scenario = NavigationScenarioData(
        scenario_navigator.device,
        scenario_navigator.backend,
        UseCase.TX_REVIEW,
        True,
    )

    if scenario_navigator.device.touchable:
        scenario.validation = scenario.validation[:-1]

    scenario_navigator.navigator.navigate_until_text_and_compare(
        navigate_instruction=scenario.navigation,
        validation_instructions=scenario.validation,
        text=scenario.pattern,
        path=scenario_navigator.screenshot_path,
        test_case_name=snapshot_test_name,
        screen_change_after_last_instruction=False,
    )


def test_pczt_sign_tx_v5_simple(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    locktime = 0x00
    expiry = 0x00
    tx_bytes = bytes.fromhex(
        "050000800a27a726b4d0d6c2" + locktime.to_bytes(4, byteorder="big").hex() + expiry.to_bytes(4, byteorder="big").hex() +
        "01" + "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a" + "00000000" +
        "19" + "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000" +
        "01" + "958ddd0400000000" +
        "19" + "76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac" +
        "000000"
    )
    path = "m/44'/133'/0'/0/2"

    client = ZcashCommandSender(backend)

    response = client.get_public_key(path=path).data
    public_key, _, _ = unpack_get_public_key_response(response)

    with client.send_pczt(
        transaction=tx_bytes,
        transparent_inputs=[PCZT_TRANSPARENT_INPUT],
        transparent_outputs=[SIMPLE_OUTPUT],
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_simple")

    resp = client.pczt_sign_transparent(path=path, input_index=0).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(
        public_key,
        signature,
        tx_bytes,
        input_index=0,
        input_amounts=[INPUT_VALUE],
    )


def test_pczt_sign_tx_v5_change(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    locktime = 0x00
    expiry = 0x00
    tx_bytes = bytes.fromhex(
        "050000800a27a726b4d0d6c2" + locktime.to_bytes(4, byteorder="big").hex() + expiry.to_bytes(4, byteorder="big").hex() +
        "01" + "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a" + "00000000" +
        "19" + "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000" +
        "02" + "005a620200000000" +
        "19" + "76a9147d352e6e9a926965c677327443d86cb0bdf8b1e988ac" +
        "c11b7b0200000000" +
        "19" + "76a914adee44a1e8d1bbfd9e000bdcc4d99849abe339f588ac" +
        "000000"
    )
    path = "m/44'/133'/0'/0/0"
    change_path = "m/44'/133'/0'/1/0"

    client = ZcashCommandSender(backend)

    response = client.get_public_key(path=path).data
    public_key, _, _ = unpack_get_public_key_response(response)

    with client.send_pczt(
        transaction=tx_bytes,
        transparent_inputs=[PCZT_TRANSPARENT_INPUT],
        transparent_outputs=[CHANGE_RECIPIENT_OUTPUT, CHANGE_OUTPUT],
        change_or_shielded_path=change_path,
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_change")

    resp = client.pczt_sign_transparent(path=path, input_index=0).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(
        public_key,
        signature,
        tx_bytes,
        input_index=0,
        input_amounts=[INPUT_VALUE],
    )


def test_pczt_sign_tx_refuse(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    locktime = 0x00
    expiry = 0x00
    tx_bytes = bytes.fromhex(
        "050000800a27a726b4d0d6c2" + locktime.to_bytes(4, byteorder="big").hex() + expiry.to_bytes(4, byteorder="big").hex() +
        "01" + "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a" + "00000000" +
        "19" + "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000" +
        "01" + "958ddd0400000000" +
        "19" + "76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac" +
        "000000"
    )

    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            transaction=tx_bytes,
            transparent_inputs=[PCZT_TRANSPARENT_INPUT],
            transparent_outputs=[SIMPLE_OUTPUT],
        ):
            scenario_navigator.review_reject(test_name="test_sign_tx_refuse")

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0
