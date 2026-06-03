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
MULT_INPUT_SCRIPT_PUBKEY = bytes.fromhex("76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac")
MULT_INPUT_SEQUENCE = bytes.fromhex("00000000")
MULT_INPUTS = [
    PcztTransparentInput(
        prevout_txid=bytes.fromhex("9484c71dd0b3690b6b7d018577e253143139e70bc2ed5aafbc34ea88f6a157ab"),
        prevout_index=0,
        value=81624725,
        script_pubkey=MULT_INPUT_SCRIPT_PUBKEY,
        sequence=MULT_INPUT_SEQUENCE,
    ),
    PcztTransparentInput(
        prevout_txid=bytes.fromhex("28ca5b91000f74b9adbb3f467adf1088caf7f334192895e59a540067531d7136"),
        prevout_index=0,
        value=1776650,
        script_pubkey=MULT_INPUT_SCRIPT_PUBKEY,
        sequence=MULT_INPUT_SEQUENCE,
    ),
    PcztTransparentInput(
        prevout_txid=bytes.fromhex("0b2218186261dda6d04db9c41c5aff38a75548ad85170a7ba530a30cec0d1da8"),
        prevout_index=0,
        value=2988680,
        script_pubkey=MULT_INPUT_SCRIPT_PUBKEY,
        sequence=MULT_INPUT_SEQUENCE,
    ),
]
MULT_INPUTS_OUTPUT = PcztTransparentOutput(
    value=int.from_bytes(bytes.fromhex("1722260500000000"), byteorder="little"),
    script_pubkey=bytes.fromhex("76a9147340a80cad7353cff25bad918e73837c2e2863eb88ac"),
)
MULT_OUTPUTS_RECIPIENT_OUTPUT = PcztTransparentOutput(
    value=int.from_bytes(bytes.fromhex("005a620200000000"), byteorder="little"),
    script_pubkey=bytes.fromhex("76a9147d352e6e9a926965c677327443d86cb0bdf8b1e988ac"),
)
MULT_OUTPUTS_CHANGE_OUTPUT = PcztTransparentOutput(
    value=int.from_bytes(bytes.fromhex("c11b7b0200000000"), byteorder="little"),
    script_pubkey=bytes.fromhex("76a91456464df31771790b77502f55895a396a64e74da588ac"),
)
V4_NU6_INPUT = PcztTransparentInput(
    prevout_txid=bytes.fromhex("0ad3e89c25a3660efacfb08f35dab5cb65d3683f55d7426026d61e93fa395a3e"),
    prevout_index=0,
    value=int.from_bytes(bytes.fromhex("62e52a0300000000"), byteorder="little"),
    script_pubkey=bytes.fromhex("76a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac"),
    sequence=bytes.fromhex("00000000"),
)
V4_NU6_RECIPIENT_OUTPUT = PcztTransparentOutput(
    value=int.from_bytes(bytes.fromhex("8096980000000000"), byteorder="little"),
    script_pubkey=bytes.fromhex("76a9147678416cb82a4a716dd1ee6b332744ba2a1f11c488ac"),
)
V4_NU6_CHANGE_OUTPUT = PcztTransparentOutput(
    value=int.from_bytes(bytes.fromhex("30db8e0200000000"), byteorder="little"),
    script_pubkey=bytes.fromhex("76a914c628ce8ff6367f0ea6763f1c1d865329af0715ac88ac"),
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

def test_pczt_sign_tx_v5_mult_inputs(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    expected_sigs = [
        "31440220489d5ffa46530ec64ae523be7559058fab452a2c8d03215179f33ed63e69fa0c02201b3301c4dd20dc318e49e9d0ed6a7e9433ddda6f5755834c7064d7ff332d057a01",
        "304502210090836743d963b93ee1974f764fda3e1a0f4b1662805b894bc6c4b5dd66b5d00e02203c356c71247050269150b4a8e62d0c04845dec5324308e50a6c06e0a44282c2901",
        "3145022100a4cc9821cf530a179cf2bcf767644ff62e0b0cf79a5701101914be6c215b0bcc02202d2ac5ef2289caa7fafc94ce38b2e46baf5987b86193e0251f4cf2585c174ccd01",
    ]
    locktime = 0x00
    expiry = 0x00
    tx_bytes = bytes.fromhex(
        "050000800a27a726b4d0d6c2" + locktime.to_bytes(4, byteorder="big").hex() + expiry.to_bytes(4, byteorder="big").hex() +
        "03" +
        "9484c71dd0b3690b6b7d018577e253143139e70bc2ed5aafbc34ea88f6a157ab" + "00000000" +
        "19" + "76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000" +
        "28ca5b91000f74b9adbb3f467adf1088caf7f334192895e59a540067531d7136" + "00000000" +
        "19" + "76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000" +
        "0b2218186261dda6d04db9c41c5aff38a75548ad85170a7ba530a30cec0d1da8" + "00000000" +
        "19" + "76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000" +
        "01" + "1722260500000000" +
        "19" + "76a9147340a80cad7353cff25bad918e73837c2e2863eb88ac" +
        "000000"
    )
    path = "m/44'/133'/2'/0/2"

    client = ZcashCommandSender(backend)

    with client.send_pczt(
        transaction=tx_bytes,
        transparent_inputs=MULT_INPUTS,
        transparent_outputs=[MULT_INPUTS_OUTPUT],
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_mult_inputs_old")

    signatures = [
        client.pczt_sign_transparent(path=path, input_index=input_index).data
        for input_index in range(len(MULT_INPUTS))
    ]

    assert [signature.hex() for signature in signatures] == expected_sigs


def test_pczt_sign_tx_v5_mult_outputs(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    expected_sig = "3045022100867fdc2d2873b15bc19a42df288a257aff08ba74b9e2eefd1245e69b05a181b302200b876a40a9339b8b8333c332319dbe5329af363628e0fd4847b281719986dc7b01"
    locktime = 0x00
    expiry = 0x00
    tx_bytes = bytes.fromhex(
        "050000800a27a726b4d0d6c2" + locktime.to_bytes(4, byteorder="big").hex() + expiry.to_bytes(4, byteorder="big").hex() +
        "01" + "9484c71dd0b3690b6b7d018577e253143139e70bc2ed5aafbc34ea88f6a157ab" + "00000000" +
        "19" + "76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000" +
        "02" + "005a620200000000" +
        "19" + "76a9147d352e6e9a926965c677327443d86cb0bdf8b1e988ac" +
        "c11b7b0200000000" +
        "19" + "76a91456464df31771790b77502f55895a396a64e74da588ac" +
        "000000"
    )
    path = "m/44'/133'/2'/0/2"
    change_path = "m/44'/133'/2'/1/0"

    client = ZcashCommandSender(backend)

    response = client.get_public_key(path=path).data
    public_key, _, _ = unpack_get_public_key_response(response)

    with client.send_pczt(
        transaction=tx_bytes,
        transparent_inputs=[MULT_INPUTS[0]],
        transparent_outputs=[MULT_OUTPUTS_RECIPIENT_OUTPUT, MULT_OUTPUTS_CHANGE_OUTPUT],
        change_or_shielded_path=change_path,
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_mult_outputs_old")

    resp = client.pczt_sign_transparent(path=path, input_index=0).data

    assert resp.hex() == expected_sig
    assert check_tx_v5_signature_validity(
        public_key,
        resp[:-1],
        tx_bytes,
        input_index=0,
        input_amounts=[MULT_INPUTS[0].value],
    )


def test_pczt_sign_tx_with_v4_nu6_input(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    expected_sig = "31440220488d0fca08431682cd5f10968a72affdd569f61a4a358f73edf05d0fb4a3e1a702204722751bd7d27f999ed714694ad024465d54c288a9cc560559d9594914d92ac501"
    locktime = 0x00
    expiry = 0x00
    tx_bytes = bytes.fromhex(
        "050000800a27a7265510e7c8" + locktime.to_bytes(4, byteorder="big").hex() + expiry.to_bytes(4, byteorder="big").hex() +
        "01" + "0ad3e89c25a3660efacfb08f35dab5cb65d3683f55d7426026d61e93fa395a3e" + "00000000" +
        "19" + "76a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac00000000" +
        "02" + "8096980000000000" +
        "19" + "76a9147678416cb82a4a716dd1ee6b332744ba2a1f11c488ac" +
        "30db8e0200000000" +
        "19" + "76a914c628ce8ff6367f0ea6763f1c1d865329af0715ac88ac" +
        "000000"
    )
    path = "m/44'/133'/4'/0/0"
    change_path = "m/44'/133'/4'/1/0"

    client = ZcashCommandSender(backend)

    with client.send_pczt(
        transaction=tx_bytes,
        transparent_inputs=[V4_NU6_INPUT],
        transparent_outputs=[V4_NU6_RECIPIENT_OUTPUT, V4_NU6_CHANGE_OUTPUT],
        change_or_shielded_path=change_path,
    ):
        _review_approve(scenario_navigator, "test_sign_tx_with_v4_nu6_input")

    resp = client.pczt_sign_transparent(path=path, input_index=0).data

    assert resp.hex() == expected_sig
