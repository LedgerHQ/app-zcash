# pylint: disable=C0301

import pytest

from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

from application_client.zcash_command_sender import (
    Errors,
    PcztGlobal,
    PcztOrchardAction,
    PcztOrchardBundle,
    PcztTransparentInput,
    PcztTransparentOutput,
    ZcashCommandSender,
)
from application_client.zcash_response_unpacker import unpack_get_public_key_response
from application_client.zcash_utils import write_varint
from application_client.zcash_verify_sign import (
    check_tx_v5_signature_validity,
)

PCZT_ORCHARD_RK_ALPHA_1 = bytes.fromhex(
    "e95982b73ab0c2137ec354cce448a75ef39ec0cbdf6907be6df3495297834f89"
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


def _pczt_transaction_bytes(
    pczt_global: PcztGlobal,
    transparent_inputs: list[PcztTransparentInput],
    transparent_outputs: list[PcztTransparentOutput],
    orchard_bundle: PcztOrchardBundle | None = None,
) -> bytes:
    tx = bytearray(pczt_global.tx_header_bytes())
    tx.extend(write_varint(len(transparent_inputs)))

    for txin in transparent_inputs:
        tx.extend(txin.prevout_txid)
        tx.extend(txin.prevout_index.to_bytes(4, byteorder="little"))
        tx.extend(write_varint(len(txin.script_pubkey)))
        tx.extend(txin.script_pubkey)
        tx.extend(txin.sequence)

    tx.extend(write_varint(len(transparent_outputs)))
    for txout in transparent_outputs:
        tx.extend(txout.value.to_bytes(8, byteorder="little"))
        tx.extend(write_varint(len(txout.script_pubkey)))
        tx.extend(txout.script_pubkey)

    tx.extend(write_varint(0))
    tx.extend(write_varint(0))

    if orchard_bundle is None:
        tx.extend(write_varint(0))
        return bytes(tx)

    tx.extend(write_varint(len(orchard_bundle.actions)))

    for action in orchard_bundle.actions:
        tx.extend(action.nullifier)
        tx.extend(action.cmx)
        tx.extend(action.ephemeral_key)
        tx.extend(action.enc_ciphertext[:52])

    for action in orchard_bundle.actions:
        tx.extend(action.enc_ciphertext[52:564])

    for action in orchard_bundle.actions:
        tx.extend(action.cv_net)
        tx.extend(action.rk)
        tx.extend(action.enc_ciphertext[564:])
        tx.extend(action.out_ciphertext)

    tx.extend(orchard_bundle.flags.to_bytes(1, byteorder="little"))
    tx.extend(orchard_bundle.value_balance.to_bytes(8, byteorder="little", signed=True))
    tx.extend(orchard_bundle.anchor)

    return bytes(tx)


def _sign_remaining_orchard_actions(
    client: ZcashCommandSender,
    orchard_bundle: PcztOrchardBundle,
) -> None:
    for action_index in range(1, len(orchard_bundle.actions)):
        auth_sig = client.pczt_sign_orchard(action_index=action_index).data
        assert len(auth_sig) == 64


def _assert_pczt_orchard_sign_digest(
    backend,
    scenario_navigator: NavigateWithScenario,
    snapshot_test_name: str,
    pczt_global: PcztGlobal,
    expected_auth_sig: bytes,
    transparent_outputs: list[PcztTransparentOutput],
    orchard_bundle: PcztOrchardBundle,
    transparent_input: PcztTransparentInput | None = None,
    prevout_tx: bytes | None = None,
) -> None:
    client = ZcashCommandSender(backend)
    transparent_inputs = [] if transparent_input is None else [transparent_input]
    if prevout_tx is not None:
        # Temporary RNG alignment with the legacy HASH_SIGN flow.
        _ = client.get_trusted_input(prevout_tx, 0).data

    with client.send_pczt(
        pczt_global=pczt_global,
        transparent_inputs=transparent_inputs,
        transparent_outputs=transparent_outputs,
        orchard_bundle=orchard_bundle,
    ):
        _review_approve(scenario_navigator, snapshot_test_name)

    if transparent_input is None or prevout_tx is not None:
        auth_sig = client.pczt_sign_orchard(action_index=0).data
        assert auth_sig == expected_auth_sig, auth_sig.hex()
        _sign_remaining_orchard_actions(client, orchard_bundle)
        if transparent_input is None:
            return
        transparent_sig = client.pczt_sign_transparent(input_index=0).data
    else:
        transparent_sig = client.pczt_sign_transparent(input_index=0).data
        auth_sig = client.pczt_sign_orchard(action_index=0).data
        assert auth_sig == expected_auth_sig, auth_sig.hex()
        _sign_remaining_orchard_actions(client, orchard_bundle)

    response = client.get_public_key(path=transparent_input.signing_path).data
    public_key, _, _ = unpack_get_public_key_response(response)
    tx_bytes = _pczt_transaction_bytes(
        pczt_global,
        [transparent_input],
        transparent_outputs,
        orchard_bundle,
    )

    assert check_tx_v5_signature_validity(
        public_key,
        transparent_sig[:-1],
        tx_bytes,
        input_index=0,
        input_amounts=[transparent_input.value],
    )


def test_pczt_rejects_wrong_coin_type(
    backend,
):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PcztGlobal(coin_type=0),
            transparent_inputs=[],
            transparent_outputs=[],
        ):
            pass

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0


def test_pczt_sign_tx_v5_simple(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    PCZT_GLOBAL = PcztGlobal()
    PATH = "m/44'/133'/0'/0/2"
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"),
        prevout_index=0,
        value=81630485,
        script_pubkey=bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac"),
        sequence=bytes.fromhex("00000000"),
        signing_path="m/44'/133'/0'/0/2",
    )
    TRANSPARENT_OUTPUT = PcztTransparentOutput(
        value=81628565,
        script_pubkey=bytes.fromhex("76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"),
    )
    TX_BYTES = _pczt_transaction_bytes(PCZT_GLOBAL, [TRANSPARENT_INPUT], [TRANSPARENT_OUTPUT])

    client = ZcashCommandSender(backend)

    response = client.get_public_key(path=PATH).data
    public_key, _, _ = unpack_get_public_key_response(response)

    with client.send_pczt(
        pczt_global=PCZT_GLOBAL,
        transparent_inputs=[TRANSPARENT_INPUT],
        transparent_outputs=[TRANSPARENT_OUTPUT],
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_simple")

    resp = client.pczt_sign_transparent(input_index=0).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(
        public_key,
        signature,
        TX_BYTES,
        input_index=0,
        input_amounts=[TRANSPARENT_INPUT.value],
    )


def test_pczt_sign_tx_v5_old(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    EXPECTED_SIG = "304402202b22627d88f9ecebf2ab586ffa970232cddad6eabb3289fa1359b2bc9f5554bc02207cfba5db7c01b89c5d540dcb1ada67d485ab1638c2151eaa78b4d368059c007801"
    PCZT_GLOBAL = PcztGlobal()
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"),
        prevout_index=0,
        value=81630485,
        script_pubkey=bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac"),
        sequence=bytes.fromhex("00000000"),
        signing_path="m/44'/133'/0'/0/2",
    )
    TRANSPARENT_OUTPUT = PcztTransparentOutput(
        value=81628565,
        script_pubkey=bytes.fromhex("76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"),
    )

    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_GLOBAL,
        transparent_inputs=[TRANSPARENT_INPUT],
        transparent_outputs=[TRANSPARENT_OUTPUT],
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_old")

    resp = client.pczt_sign_transparent(input_index=0).data

    assert resp.hex() == EXPECTED_SIG


def test_pczt_sign_tx_v5_change(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    PCZT_GLOBAL = PcztGlobal()
    PATH = "m/44'/133'/0'/0/0"
    CHANGE_PATH = "m/44'/133'/0'/1/0"
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"),
        prevout_index=0,
        value=81630485,
        script_pubkey=bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac"),
        sequence=bytes.fromhex("00000000"),
        signing_path="m/44'/133'/0'/0/0",
    )
    RECIPIENT_OUTPUT = PcztTransparentOutput(
        value=40000000,
        script_pubkey=bytes.fromhex("76a9147d352e6e9a926965c677327443d86cb0bdf8b1e988ac"),
    )
    CHANGE_OUTPUT = PcztTransparentOutput(
        value=41622465,
        script_pubkey=bytes.fromhex("76a914adee44a1e8d1bbfd9e000bdcc4d99849abe339f588ac"),
        signing_path=CHANGE_PATH,
    )
    TRANSPARENT_OUTPUTS = [RECIPIENT_OUTPUT, CHANGE_OUTPUT]
    TX_BYTES = _pczt_transaction_bytes(PCZT_GLOBAL, [TRANSPARENT_INPUT], TRANSPARENT_OUTPUTS)

    client = ZcashCommandSender(backend)

    response = client.get_public_key(path=PATH).data
    public_key, _, _ = unpack_get_public_key_response(response)

    with client.send_pczt(
        pczt_global=PCZT_GLOBAL,
        transparent_inputs=[TRANSPARENT_INPUT],
        transparent_outputs=TRANSPARENT_OUTPUTS,
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_change")

    resp = client.pczt_sign_transparent(input_index=0).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(
        public_key,
        signature,
        TX_BYTES,
        input_index=0,
        input_amounts=[TRANSPARENT_INPUT.value],
    )


def test_pczt_sign_tx_v5_change_hash_not_sticky(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    # Regression test for a clear-signing bug where the per-output change hash leaked
    # across outputs. Output #0 is a *recipient* (script pays address A) but carries a
    # change bip32_derivation for path P (deriving address H, with H != A); this sets the
    # parser's change_pk_hash to H while output #0 itself is correctly shown as a payment
    # to A. Output #1 pays address H and has *no* derivation of its own. Before the fix
    # the stale change_pk_hash (H) caused output #1 to be classified as change and hidden
    # from the user. After the fix change_pk_hash is unset at the start of every output,
    # so output #1 (no derivation) is shown as a normal payment. The golden snapshots
    # capture that BOTH outputs are displayed.
    PCZT_GLOBAL = PcztGlobal()
    PATH = "m/44'/133'/0'/0/0"
    CHANGE_PATH = "m/44'/133'/0'/1/0"
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"),
        prevout_index=0,
        value=81630485,
        script_pubkey=bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac"),
        sequence=bytes.fromhex("00000000"),
        signing_path=PATH,
    )
    # Recipient output (address A) that nonetheless carries a change derivation for
    # CHANGE_PATH (which derives address H = adee44a1...e339f5).
    RECIPIENT_WITH_CHANGE_DERIVATION = PcztTransparentOutput(
        value=40000000,
        script_pubkey=bytes.fromhex("76a9147d352e6e9a926965c677327443d86cb0bdf8b1e988ac"),
        signing_path=CHANGE_PATH,
    )
    # Output paying the change address H, with NO derivation of its own. Must not inherit
    # the previous output's change classification.
    PAYMENT_TO_CHANGE_ADDRESS = PcztTransparentOutput(
        value=41628565,
        script_pubkey=bytes.fromhex("76a914adee44a1e8d1bbfd9e000bdcc4d99849abe339f588ac"),
    )
    TRANSPARENT_OUTPUTS = [RECIPIENT_WITH_CHANGE_DERIVATION, PAYMENT_TO_CHANGE_ADDRESS]
    TX_BYTES = _pczt_transaction_bytes(PCZT_GLOBAL, [TRANSPARENT_INPUT], TRANSPARENT_OUTPUTS)

    client = ZcashCommandSender(backend)

    response = client.get_public_key(path=PATH).data
    public_key, _, _ = unpack_get_public_key_response(response)

    with client.send_pczt(
        pczt_global=PCZT_GLOBAL,
        transparent_inputs=[TRANSPARENT_INPUT],
        transparent_outputs=TRANSPARENT_OUTPUTS,
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_change_hash_not_sticky")

    resp = client.pczt_sign_transparent(input_index=0).data
    signature = resp[:-1]

    assert check_tx_v5_signature_validity(
        public_key,
        signature,
        TX_BYTES,
        input_index=0,
        input_amounts=[TRANSPARENT_INPUT.value],
    )


def test_pczt_sign_tx_refuse(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    PCZT_GLOBAL = PcztGlobal()
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"),
        prevout_index=0,
        value=81630485,
        script_pubkey=bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac"),
        sequence=bytes.fromhex("00000000"),
        signing_path="m/44'/133'/0'/0/2",
    )
    TRANSPARENT_OUTPUT = PcztTransparentOutput(
        value=81628565,
        script_pubkey=bytes.fromhex("76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"),
    )

    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_GLOBAL,
            transparent_inputs=[TRANSPARENT_INPUT],
            transparent_outputs=[TRANSPARENT_OUTPUT],
        ):
            scenario_navigator.review_reject(test_name="test_sign_tx_refuse")

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_pczt_sign_tx_v5_mult_inputs(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    EXPECTED_SIGS = [
        "31440220489d5ffa46530ec64ae523be7559058fab452a2c8d03215179f33ed63e69fa0c02201b3301c4dd20dc318e49e9d0ed6a7e9433ddda6f5755834c7064d7ff332d057a01",
        "304502210090836743d963b93ee1974f764fda3e1a0f4b1662805b894bc6c4b5dd66b5d00e02203c356c71247050269150b4a8e62d0c04845dec5324308e50a6c06e0a44282c2901",
        "3145022100a4cc9821cf530a179cf2bcf767644ff62e0b0cf79a5701101914be6c215b0bcc02202d2ac5ef2289caa7fafc94ce38b2e46baf5987b86193e0251f4cf2585c174ccd01",
    ]
    PCZT_GLOBAL = PcztGlobal()
    TRANSPARENT_INPUTS = [
        PcztTransparentInput(
            prevout_txid=bytes.fromhex("9484c71dd0b3690b6b7d018577e253143139e70bc2ed5aafbc34ea88f6a157ab"),
            prevout_index=0,
            value=81624725,
            script_pubkey=bytes.fromhex("76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"),
            sequence=bytes.fromhex("00000000"),
            signing_path="m/44'/133'/2'/0/2",
        ),
        PcztTransparentInput(
            prevout_txid=bytes.fromhex("28ca5b91000f74b9adbb3f467adf1088caf7f334192895e59a540067531d7136"),
            prevout_index=0,
            value=1776650,
            script_pubkey=bytes.fromhex("76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"),
            sequence=bytes.fromhex("00000000"),
            signing_path="m/44'/133'/2'/0/2",
        ),
        PcztTransparentInput(
            prevout_txid=bytes.fromhex("0b2218186261dda6d04db9c41c5aff38a75548ad85170a7ba530a30cec0d1da8"),
            prevout_index=0,
            value=2988680,
            script_pubkey=bytes.fromhex("76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"),
            sequence=bytes.fromhex("00000000"),
            signing_path="m/44'/133'/2'/0/2",
        ),
    ]
    TRANSPARENT_OUTPUT = PcztTransparentOutput(
        value=86385175,
        script_pubkey=bytes.fromhex("76a9147340a80cad7353cff25bad918e73837c2e2863eb88ac"),
    )
    TX_BYTES = _pczt_transaction_bytes(PCZT_GLOBAL, TRANSPARENT_INPUTS, [TRANSPARENT_OUTPUT])

    client = ZcashCommandSender(backend)
    public_keys = [
        unpack_get_public_key_response(client.get_public_key(path=inp.signing_path).data)[0]
        for inp in TRANSPARENT_INPUTS
    ]

    with client.send_pczt(
        pczt_global=PCZT_GLOBAL,
        transparent_inputs=TRANSPARENT_INPUTS,
        transparent_outputs=[TRANSPARENT_OUTPUT],
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_mult_inputs_old")

    signatures = [
        client.pczt_sign_transparent(input_index=input_index).data
        for input_index in range(len(TRANSPARENT_INPUTS))
    ]

    assert [signature.hex() for signature in signatures] == EXPECTED_SIGS
    for input_index, signature in enumerate(signatures):
        assert check_tx_v5_signature_validity(
            public_keys[input_index],
            signature[:-1],
            TX_BYTES,
            input_index=input_index,
            input_amounts=[inp.value for inp in TRANSPARENT_INPUTS],
        )


def test_pczt_sign_tx_v5_transparent_input_no_replay(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    # Regression test: signing the same transparent input twice must be rejected.
    # Before the fix the signed-input counter was incremented unconditionally, so
    # repeatedly signing input #0 could reach total_input_count and prematurely mark
    # the PCZT finished while input #1 was never signed. The parser now tracks a
    # per-input `signed` flag (mirroring the Orchard per-action guard).
    PCZT_GLOBAL = PcztGlobal()
    TRANSPARENT_INPUTS = [
        PcztTransparentInput(
            prevout_txid=bytes.fromhex("9484c71dd0b3690b6b7d018577e253143139e70bc2ed5aafbc34ea88f6a157ab"),
            prevout_index=0,
            value=81624725,
            script_pubkey=bytes.fromhex("76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"),
            sequence=bytes.fromhex("00000000"),
            signing_path="m/44'/133'/2'/0/2",
        ),
        PcztTransparentInput(
            prevout_txid=bytes.fromhex("28ca5b91000f74b9adbb3f467adf1088caf7f334192895e59a540067531d7136"),
            prevout_index=0,
            value=1776650,
            script_pubkey=bytes.fromhex("76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"),
            sequence=bytes.fromhex("00000000"),
            signing_path="m/44'/133'/2'/0/2",
        ),
    ]
    TRANSPARENT_OUTPUT = PcztTransparentOutput(
        value=83399455,
        script_pubkey=bytes.fromhex("76a9147340a80cad7353cff25bad918e73837c2e2863eb88ac"),
    )

    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_GLOBAL,
        transparent_inputs=TRANSPARENT_INPUTS,
        transparent_outputs=[TRANSPARENT_OUTPUT],
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_transparent_input_no_replay")

    # First signature for input #0 succeeds.
    first_signature = client.pczt_sign_transparent(input_index=0).data
    assert len(first_signature) > 0

    # Re-signing the SAME input must be rejected, not silently counted.
    with pytest.raises(ExceptionRAPDU) as e:
        client.pczt_sign_transparent(input_index=0)
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_sign_tx_orchard_action_count_limit(
    backend,
):
    # Regression test: the Orchard action count is bounded by MAX_ORCHARD_ACTIONS (10),
    # mirroring the transparent input/output limits. A bundle declaring more actions must
    # be rejected at the action-count check, before any per-action allocation grows the
    # signing-records vector (heap-exhaustion guard on a ~24 KB-RAM device).
    PCZT_GLOBAL = PcztGlobal()
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"),
        prevout_index=0,
        value=81630485,
        script_pubkey=bytes.fromhex("76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac"),
        sequence=bytes.fromhex("00000000"),
        signing_path="m/44'/133'/0'/0/2",
    )
    TRANSPARENT_OUTPUT = PcztTransparentOutput(
        value=81628565,
        script_pubkey=bytes.fromhex("76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"),
    )

    def _dummy_orchard_action() -> PcztOrchardAction:
        # The action-count check fires before any field is parsed, so zero-filled
        # fields of the correct size are sufficient; they only need to serialize.
        return PcztOrchardAction(
            cv_net=bytes(32),
            nullifier=bytes(32),
            rk=bytes(32),
            alpha=bytes(32),
            signing_path="m/32'/133'/0'",
            cmx=bytes(32),
            ephemeral_key=bytes(32),
            enc_ciphertext=bytes(580),
            out_ciphertext=bytes(80),
        )

    # MAX_ORCHARD_ACTIONS is 6; declare one more to trip the bound.
    too_many_actions = PcztOrchardBundle(
        actions=[_dummy_orchard_action() for _ in range(11)],
        flags=0,
        value_balance=0,
        anchor=bytes(32),
    )

    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_GLOBAL,
            transparent_inputs=[TRANSPARENT_INPUT],
            transparent_outputs=[TRANSPARENT_OUTPUT],
            orchard_bundle=too_many_actions,
        ):
            pytest.fail("Device accepted a PCZT with too many Orchard actions")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_sign_tx_orchard_rk_mismatch_rejected(
    backend,
):
    bad_rk = bytes([PCZT_ORCHARD_RK_ALPHA_1[0] ^ 1]) + PCZT_ORCHARD_RK_ALPHA_1[1:]
    orchard_bundle = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes(32),
                nullifier=bytes(32),
                rk=bad_rk,
                alpha=(1).to_bytes(32, byteorder="little"),
                signing_path="m/32'/133'/0'",
                cmx=bytes(32),
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(80),
            )
        ],
        flags=0,
        value_balance=0,
        anchor=bytes(32),
    )

    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PcztGlobal(),
            transparent_inputs=[],
            transparent_outputs=[],
            orchard_bundle=orchard_bundle,
        ):
            pytest.fail("Device accepted a PCZT Orchard action with mismatched rk")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_sign_tx_v5_mult_outputs(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    EXPECTED_SIG = "3045022100867fdc2d2873b15bc19a42df288a257aff08ba74b9e2eefd1245e69b05a181b302200b876a40a9339b8b8333c332319dbe5329af363628e0fd4847b281719986dc7b01"
    PCZT_GLOBAL = PcztGlobal()
    PATH = "m/44'/133'/2'/0/2"
    CHANGE_PATH = "m/44'/133'/2'/1/0"
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("9484c71dd0b3690b6b7d018577e253143139e70bc2ed5aafbc34ea88f6a157ab"),
        prevout_index=0,
        value=81624725,
        script_pubkey=bytes.fromhex("76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"),
        sequence=bytes.fromhex("00000000"),
        signing_path="m/44'/133'/2'/0/2",
    )
    RECIPIENT_OUTPUT = PcztTransparentOutput(
        value=40000000,
        script_pubkey=bytes.fromhex("76a9147d352e6e9a926965c677327443d86cb0bdf8b1e988ac"),
    )
    CHANGE_OUTPUT = PcztTransparentOutput(
        value=41622465,
        script_pubkey=bytes.fromhex("76a91456464df31771790b77502f55895a396a64e74da588ac"),
        signing_path=CHANGE_PATH,
    )
    TRANSPARENT_OUTPUTS = [RECIPIENT_OUTPUT, CHANGE_OUTPUT]
    TX_BYTES = _pczt_transaction_bytes(PCZT_GLOBAL, [TRANSPARENT_INPUT], TRANSPARENT_OUTPUTS)

    client = ZcashCommandSender(backend)

    response = client.get_public_key(path=PATH).data
    public_key, _, _ = unpack_get_public_key_response(response)

    with client.send_pczt(
        pczt_global=PCZT_GLOBAL,
        transparent_inputs=[TRANSPARENT_INPUT],
        transparent_outputs=TRANSPARENT_OUTPUTS,
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_mult_outputs_old")

    resp = client.pczt_sign_transparent(input_index=0).data

    assert resp.hex() == EXPECTED_SIG
    assert check_tx_v5_signature_validity(
        public_key,
        resp[:-1],
        TX_BYTES,
        input_index=0,
        input_amounts=[TRANSPARENT_INPUT.value],
    )



def test_pczt_sign_tx_v5_transparent_to_orchard_simple(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    ORCHARD_SIGNING_PATH = "m/32'/133'/0'"
    ORCHARD_ALPHA = (1).to_bytes(32, byteorder="little")
    TX_PREVOUT_BYTES = bytes.fromhex("050000800a27a726b4d0d6c20000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01a0860100000000001976a91419650e98310b2cc27f00a9d0c4580386553da2e488ac000000")
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("cf67287a7f4820dc2dd57503b3a5e940b4c1b322024cee5e8ffbece7f217f4bf"),
        prevout_index=0,
        value=100000,
        script_pubkey=bytes.fromhex("76a91419650e98310b2cc27f00a9d0c4580386553da2e488ac"),
        sequence=bytes.fromhex("ffffffff"),
        signing_path="m/44'/133'/0'/0/2",
    )
    TRANSPARENT_OUTPUTS = []
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes.fromhex("39ceba3e81ae3415fb4a519978f4bbc75e5a1d101ce0d6bc91d035f614a9f68b"),
                nullifier=bytes.fromhex("3768e7c28954fec9791e472e02881cb6b2c3f6d744c4eeb0f248eef01f6fb53d"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("89b07d697d3ef14edf006d9a39472371ddba49a58ff23026c8656e9cc4edd437"),
                ephemeral_key=bytes.fromhex("b2592149ac97670466fc5eff6657dd79cf20d551b31446dd49fbf9d4b1f3a230"),
                enc_ciphertext=bytes.fromhex("9ea84a733e8edebc00e516d1c077675494b2b58fbbb78cd4106d1378c0181c729a4606ed2b0e9aa6a84c1eb445964a7363bc9c2eccf8758e4ae1e8d3453b1de676dd06164b76f275627998f50cf6e54e6b19d04bf3a37a207fbd5ac65db7fffa8a0d2ea64f095fd1bd4b72808ff012d94dbf00480123c1ac26d5392277f20322af0595bb9d44d5964b95a859e630d90ea82695b163220a255a5eeb591a9df8d592957e5e0555a178a4aca3bfbc7ae23914c97edbc2c4ab1c5bee7220f220ed869eca8f90ea9646551767d12cb6f7d8d1c51f6f4e5989c24ec7829e2efc2d9945644fcb541ea1ba9a0a9a119e92c5452d5383f381f62501a0deeb0999e659fa2bdfa8036a6849aa67a7a70b0f3028332ba1177ef129df4dd708c85a63a956653ebfd65b174889ad84065da7dbf1c46a225b77e45caf0218cef2b6f879ab20c8c40345e75d2db634645badfecade82c07af4d110c042bd26060d9927e0d8257c68dd27163994356007842dc7334f16a82cce83bb5ce428e10adcf4e9077292eea6133c3933eba031dd73c3ded25c8d1fc7185df3b5974be79428d20b5c84d81e06be531d987971af721c29787e0217ca27462c9a64f1ad03d05581952f25505ec056e1663bafc81d36d2663309e126b647353b6938d96b6a82f187a87543ea43319c51b3617eba6815c7986b7825bd6b95b41ffeabf57265866fb47336207174b2617f30887962bddd79a710cc1f3e821d5819b826bc9317b85d3aa1fe62da28e93233dbd44f1ce12f998f0ae82832c5b7b8d85bd3bcaa36267c9ab28720765b26d6104f3b"),
                out_ciphertext=bytes.fromhex("3cd84b39eb3dff77f836a1c9a911890a7c8c6466ef5a2ac7547509b19a25f10cbe193d8d97b9c54d2aaca820303bebbcc4c398d71345c10b5b4b68552bd12bf00eb14cef7a532490b3fa9acf86e7e4c7"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
            PcztOrchardAction(
                cv_net=bytes.fromhex("871b0d9ffece64195308cdc3403af4673ace0fed752a34cc424fcaacce45fb19"),
                nullifier=bytes.fromhex("9f2daa682b1a9ce8c102ea6504c18be633d23429b3625c42005fa15d4597632a"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("55097853a03489062efb70a19197884a035e1d364339a66d7ac01c0823e5a409"),
                ephemeral_key=bytes.fromhex("9400b1f9865ec8845843d7f95a9caea50a30a922a064a3c41dfe8be3a6422b9c"),
                enc_ciphertext=bytes.fromhex("77babce7a9456b470802d25939471165f40990746c68752aa72deb0de06d92e8a9e8279a7a07976ddd5a4ea656b5d0126c0cf6767fc439549b6cb4dbd119651352f7ee7bd1f2687ab2da8fa9041d164730b950d828a6b4d540cf0a329cca8edc30fc27a35f1990caf739bbd701bd05428edb3ea8badec1136b581241d951a3f29cdb49ab29aa477f3c52beaeb1c55a190f37841ab60d6d0754ac4458deb10f6e0be101731f5176c4b2845e5c50d5121994bd8ee07f6085a54e3838c2fe6bfbf8212bc8a128d4aea5522b5e3245312037fe0852e226dcbf5488a388ec83f78875976f7de2588573130788ae5c7e98d080bef6d2b6e914520f56506e4b0a57469d07ae89697c7bbd041bcdd33079fdb6ec87dfbdad29e2e369d398b34858626f9829ad3e167e001932148c7ad0f3cb0d66edb322bbbd96f7f68d9b54e88a61d24dd69788de009a48a97d85554008a1139170b35d8d1b09a5d0eb75d1a36d1a825db2138a627cbcdfbd89303fa71f417c21d1562e8cd73d5bcc3ab2f26edcf818fc592ad22d5bf17d139b5573dd1f7ec2567cd66d44b4e06d54079308d0af1c98131b0290c215b72110522038c15fe2090e67f6f6bb865096f10e58ac570624773c2755bbe261c9889846b35f143285476f798f8364301a60e401da8320a939b0d3a4ef260fab9c6349cfad8e993a7de877cdb42933810abc881f74eb3bd1a9301bf9b425750e004287f7c2df4d1ae98f1e17f44f6f306e1f65e0512ecf602ee6c0c4d7ec642f81a1a0c6895324e6013d947ebe29d365f9a23f86f7d227f9633230386bd3eb"),
                out_ciphertext=bytes.fromhex("242d4c6ccbc830c2c8a23444b273723a0f83d07519cc818d0e2b3e563c7a14e0ca5ddccb095d2a0a4303731b403d83da0643377426365a7639f770c5cd49fd95fa982e6017a4da75050c85f0503b7f15"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
        ],
        flags=2,
        value_balance=-90000,
        anchor=bytes.fromhex("ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f"),
    )
    PCZT_GLOBAL = PcztGlobal()
    EXPECTED_AUTH_SIG = bytes.fromhex("4CBFA1990B917FEDFB50CA9DE95A98D9967B6D4426D603A45C97F02AAB737A86E8CA5DA7ABA8AAEA1314333380C389B90707760CF671A14043C7ED2B0EB3D435")

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_transparent_to_orchard_simple",
        PCZT_GLOBAL,
        EXPECTED_AUTH_SIG,
        TRANSPARENT_OUTPUTS,
        ORCHARD_BUNDLE,
        transparent_input=TRANSPARENT_INPUT,
        prevout_tx=TX_PREVOUT_BYTES,
    )

def test_pczt_sign_tx_v5_transparent_to_orchard_with_change(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    ORCHARD_SIGNING_PATH = "m/32'/133'/0'"
    ORCHARD_ALPHA = (1).to_bytes(32, byteorder="little")
    TX_PREVOUT_BYTES = bytes.fromhex("050000800a27a726b4d0d6c20000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01a0860100000000001976a91419650e98310b2cc27f00a9d0c4580386553da2e488ac000000")
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("cf67287a7f4820dc2dd57503b3a5e940b4c1b322024cee5e8ffbece7f217f4bf"),
        prevout_index=0,
        value=100000,
        script_pubkey=bytes.fromhex("76a91419650e98310b2cc27f00a9d0c4580386553da2e488ac"),
        sequence=bytes.fromhex("ffffffff"),
        signing_path="m/44'/133'/0'/0/2",
    )
    TRANSPARENT_OUTPUTS = []
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes.fromhex("7f6abc5384841cd9bc7e27ee61431d5a3b6999b0f953b36ceeb67c3fd18ce980"),
                nullifier=bytes.fromhex("3768e7c28954fec9791e472e02881cb6b2c3f6d744c4eeb0f248eef01f6fb53d"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("8b6787b72f8d0dad4afe69a1d1a50686438c0246f07793c73583dcdc22456c05"),
                ephemeral_key=bytes.fromhex("c2faaf0661ac0993c4f03bc6f396ed82de28ace166b922003c41117f7eed3833"),
                enc_ciphertext=bytes.fromhex("0c60cfe0c8fe459fc53344bd278154b331d35e2e243665a41ea9cb5908f783159953ef6dae2ab240fbf9d329dc3d4ce92ec9c70588f698abc2feddd07a4cb2a0be91f50b347c07ca32e224fbbc1d9cbba2cb956466fa0b4570dfa4a32825b8fed0517bfd025bdd3aaa37aab60f2730f251a65fe52e20c2fd11d6d9714701f0abfc10576beef57f1198b194c902ebc1ef3e4b34fa6ac9bce472eda5cc55ef576173127bd6c5f55def93ef3e401c868731dcb187960abfdc8f2a7e5d9d57db363f3a9337b192be26a9e0271b1aa4f89090875f3f1a242d361cfeb5ba5ce9c885d5c190544b0256d6e8916b39e7dc463d0bca1b319479d6001bc4a37d75ade16b59823f16180b0a8c357f3791b48a41c6bcb8295773c3bc6286df42e067f186ab1a3d318122db44c8078aeb11d31282728a8207cc1f54239a02c23d99780b22f55baeaed7d2f71f2cff6177523ea496551ec7d2a325afab69b02b239929d101cc2862f063c5a5cec2756aeb981d45972235c0e2cf23596b4b36dc0196b37a4f60dbf0021e78fd92bb962d6a8154ea9c3924939cbce570309bc75bc768957dda0bfdd1264bf227ba183931ae7b13017cd36053c4b23916b50add78324e651159cb1b776d8e4f09ddf1ef745188d0dd175b47694a361b48be291b4eae6335508d5e3cdedceebb3627aaad7fa76c55f4522556fb54447eeac9a9a24753e34c13f3f531a903f5b668ca3fab010acf8d872c817fe06553f73748bbc301aeff3ab155176f7439f2fc48596c1124ad16f8783a59a90f61f75ec9166b59702c88cae7aac422e8d2ce5d"),
                out_ciphertext=bytes.fromhex("34c277dc90fe4434b091e8125187ded0dbb32b6f92127b23910169aab39f405f522f452174cb4269ccf1ea910b9b35c8fad645e72705cc1ceaf136ea8222615a7cf3c4dcb8d2b0556558ce82968ad72c"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
            PcztOrchardAction(
                cv_net=bytes.fromhex("26805b9bd3edd1e1a56cab175ab20f2d9e70cb5bbca060ea594e13cdb7007627"),
                nullifier=bytes.fromhex("9f2daa682b1a9ce8c102ea6504c18be633d23429b3625c42005fa15d4597632a"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("fd972ff25ca24c9a59f03842dbc62b9373e2cd6a6f0ca197a5a827bb07347710"),
                ephemeral_key=bytes.fromhex("31e17cef9606ac592a340a5a21de0f6ad05117e3b25075e41a714615c7232aad"),
                enc_ciphertext=bytes.fromhex("f177281cfe1c462ef14856275b951219739629ab20ad22d7ae85ca116c9a338dab4f5132171a20f617022d8575ed5c6856000cfacbde054dd940f3060225ca56e397873c9d87fbd100c2e26680cfa31b669862e6f23633560e157826ca76cf7946d31b6769ce1f8c83f0618e2ac8c96c0c837108ad21f0046f08ce2d15b9f1956bb2c9773e4abded3b6a0c31af6faa2e20e522ca1aa9f3eaca64b8940c967fc4bb9719881bd3c5abfccf6f9d1cd838ec62b496b2c6e29824107674dfd732368f89f8a77d035e3db0531964352717e9f4633ec01cacaa7f462782ddc2ed78ac101a31bf101c81153314dcb29370b142460a5ded2b1e4b40e1b343b0217639578a60097df8ec6d94ae0513b08a2ce142c6ac5a9cc5411af71cbeb57245d6b3b51e773adddfdc6b10713b13bdaff505bfed6a8184e3f63482592349f947b75d75bdaeb5d28eac0b5113277f8c81864b2b0ae446423e4d5cc3388be1e67077cb4a09847940439f6eaef9501db5086e7acab01953e3ed00fd02944dd97f8b076843b489d552bcb51da1745ad22cb1219eadd1b62f3321e5e178f9b85d6b57ffc9e7b20905bfec8d37391c097d62d97a491131d1324461cbb2d932e487c3716b5e1032e530b7607344fb56217a568cd36c36b55c481aa6f0d0aa2f689bdd55fdd83a5f7a3155625513dc86cfaa5136a32cbe57e5ad69b1d00d1563fc6d781d819bb54661babae08bd8c2d7e966097612ecf7049e19901252bc6807dc6cb343d5b4360a39076c328c7952402ca51d0b7e4775d4d5109ffd98933c84d65daebc01f102a4ae765733"),
                out_ciphertext=bytes.fromhex("90afa9ddb93e03002dbd3ac38d745ce2d3968478b2bb2784af3f91c7d25b3d687871f8338247dc65b1653f5dac66dd95c5775383a36beeab079ed29df204ecb5b534c1da9c05b203557ee9540ea5532f"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
        ],
        flags=2,
        value_balance=-95000,
        anchor=bytes.fromhex("ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f"),
    )
    PCZT_GLOBAL = PcztGlobal()
    EXPECTED_AUTH_SIG = bytes.fromhex("E0548945F5B7EF0F7A9DD02FD7653ABA695C9A06AC8359597461826B47081E075DEC3DDC1BDD09C3347DF56DC3CCECED8C26DEE5ACFAB7FB379495CA6C660A08")

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_transparent_to_orchard_with_change",
        PCZT_GLOBAL,
        EXPECTED_AUTH_SIG,
        TRANSPARENT_OUTPUTS,
        ORCHARD_BUNDLE,
        transparent_input=TRANSPARENT_INPUT,
        prevout_tx=TX_PREVOUT_BYTES,
    )

def test_pczt_sign_tx_v5_orchard_to_transparent_simple(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    ORCHARD_SIGNING_PATH = "m/32'/133'/0'"
    ORCHARD_ALPHA = (1).to_bytes(32, byteorder="little")
    TRANSPARENT_OUTPUTS = [
        PcztTransparentOutput(
            value=290000,
            script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
        ),
    ]
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes.fromhex("de086e9d8c3e879e951dc2b4eeb71cc5fe3c034699a4ab6f6fa88a53e7a97427"),
                nullifier=bytes.fromhex("ad55957c9deceaee264e52a66c4aff7d5a9100f88c36cb9f1ef39726ab440006"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("3560d8f99b83a9b769595813639e4b0f8e483f0fc217eeedba658e29bae6a920"),
                ephemeral_key=bytes.fromhex("9a32bfd04ca5fc04b87116119201021029bf83d4db0f7fc68c570f7e093beb0f"),
                enc_ciphertext=bytes.fromhex("05606a55b7686cd42a991a1386cf5dbdba9a0bd4754a586861b8bb805332ac07c9be780971fe9791ea947c5214a3ff29fa8216c8271f7f628f9154573fe45d0defcbd67dbaf6a7f5279e6198385eab7999ccae6e6420fedd3c051887edbeb4b0badcdc601c7ac281d8399cd4d482bd3766cd611923a3298b56f1a3d7bc8bd39455cea8151b04429befbf98520c66d2ed57d638d157ab9c994c298188cf2fa1935c7e4abc4a84d99335de77b25b747b3d757f8e9d90cfac6e42dd3a152ec52cb4eaa4285e860ca14dc4b7eefda3e2a2350376da56c4e9b9adc534589cc55f8612d808f556af5bb4483d2b02d723ec7daa7236bb8de917747e997e03e1bc1c5009a63538c966b68d62fa934cae9f6aa19d06845a368b75e6a2f19ecacc2e6e2520fbab710b8c8726d5f9fb3cc2686f5eba0b60208d1a72526594b2305e55d0634e3c15a6b0234554ab6f496998766d2466aa4292d26e3f34b48b8a8f8bb734e085e62700ed282d57d548af65465325915511c6353432c2ffb510f84debbe32eb423e21b3fa1ce56ea30e38f65a37bbaf9c33fb0b9accb73e07806da9331eebff92aa50ceaea89512ab35d87adc6bbbd02b3f976b9b3256fd06163a0eb20aa4f8a84e93fd5d1f20de1cb364e01ed0a2f36b321b7b6c45418554093e7e9519dc436e59cc02cdf1fd23e59f2a7bf970a3b355741ac53d5a4c3b8850905ae273604305b40dc59050c55a466f183ca24869d4d20dc0e846a3d4c6a0254ef02f1520e50f8f5be9c285f0730a67547ee32103b1a5c8594a5f02e7b3fd61a1d8b1a33bfaf7e91f5050"),
                out_ciphertext=bytes.fromhex("40b85ce64c4191976c2db2b671518d0155a81d57beaf402f31e4775e2ec60e2d473fee77e126e541c7d40d7b6442b2655933efc835a1d976aa90b3b03217673049af5d867d8980265f1bf10a7ecf5b5d"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
            PcztOrchardAction(
                cv_net=bytes.fromhex("08b228c0e51ed7061c103f06582d6303fc20689de1dedffc26460f469602b982"),
                nullifier=bytes.fromhex("d68f3363b4843cb568dedbf4d966d1d7876a2edfd758d126efe1a8bd1836620f"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("9215e26687dad4221bf57714aae9e61a69cda0f3407632a94053389dd8b62305"),
                ephemeral_key=bytes.fromhex("2c3b8b1315ba08045e9efe3a3979a4f7bd320b4cb6e0437cf32308c5d87b8733"),
                enc_ciphertext=bytes.fromhex("9bfdf9e41de825407a0eb79aaac9e66a2426247e07fee995d3ea68b5e9538a7e80143bb49a62e0a001a5bf510593f790e4f55c080c39bac1391741d756bedd81eb33bd87f7b8339fcff2951c3a2716d1a653e866cca0556714db01f23b116d550e9f6739efe37c262214d0620bd59c52839c647d56173d78e15d7e171e65ac9e1249ccebe4e1d52ace166bb07f0b20445452c75d5f59a11aa9e490859dce7c108037b53cb3bfd9a242b88ce23625bc0a2e3f88b04abfd60a962186b99335bfd40448f724abfa2b8b804f3c544edc7c0bdb2020ba8b5ce8fcd59da9fa9837640f7079503a6b36fcbfe1399a5baedf8b40a223ffb63c675db73aa7d29a20fa692b5cb20b1e3f504c8b60e616fd05ea2b0983f05d51ffa5b2563e480efb7d5665f77f38f6db2f913b2334034a02e25b0e8898a94967bf596a19556dfd061de393c29ff2e8d6460d26546a3ba68315957f332ccb120a9a7656bc0bda47677be3f998e51bf542ca4d3c213fa33c0ad7beb60bc46da16838015183d32ad91c9071b5ee9d1dacbee5a24af746457ffd6f614341e39f45be9596498ba355d14c1e0e83c8d73f4351c21c4b026fd911e77af3efe8cca37adb2680ffa4b0039449470c7c198170edc8ed44e803ff84c039372566806661d2d274ef222f19a364e1b5b4921eb9c8f7959dc1ad859867d4f4597286647f202876b78d0f699bfe38bbda4e8e4835d7350732e6f0ca6697400933065cccbf3b807fd7cf4a16e2faa553e9ac7f672717cb45eb34bbf4f32cf6e91c8cdb623e75099d5e0eb3887e538d6e6fc102d854395af9"),
                out_ciphertext=bytes.fromhex("eb750713d45b7caa405813743e6e145a48fc7d6b89933a39a56fe9c7d29accc793f8c8c30e217e69e897bc157278f341042b3d8b1b92c9134b96c36901b28157ab2de75219edd12bd522a34eabf1fab2"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
        ],
        flags=1,
        value_balance=300000,
        anchor=bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109"),
    )
    PCZT_GLOBAL = PcztGlobal()
    EXPECTED_AUTH_SIG = bytes.fromhex("223EC7633D1ECF322FB8CC00AD426CB01A2C4760AC5EDEA5F6A8715914ACCE917403B2CDE4A1C3A547C01E1F6874A92531405ACAF2B91E70AE4A1038DAC0472D")

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_orchard_to_transparent_simple",
        PCZT_GLOBAL,
        EXPECTED_AUTH_SIG,
        TRANSPARENT_OUTPUTS,
        ORCHARD_BUNDLE,
    )

def test_pczt_sign_tx_v5_orchard_to_transparent_with_change(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    ORCHARD_SIGNING_PATH = "m/32'/133'/0'"
    ORCHARD_ALPHA = (1).to_bytes(32, byteorder="little")
    TRANSPARENT_OUTPUTS = [
        PcztTransparentOutput(
            value=290000,
            script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
        ),
    ]
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes.fromhex("2f5aae0b9f187db35774b6a8881705bbcf2eb0ac7be56ad2ac927d9c3e899521"),
                nullifier=bytes.fromhex("d68f3363b4843cb568dedbf4d966d1d7876a2edfd758d126efe1a8bd1836620f"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("49109401ee3ec99022f47483fafd1cc786b3a24a03924bc6d0c0fdc7fb076015"),
                ephemeral_key=bytes.fromhex("e97dd4f52670c52acbbd6316a5fca101b0c33a71a3a79445d3cdb58363be2f93"),
                enc_ciphertext=bytes.fromhex("9194a8602be00f4e035fbd6c598f2c16e47c5c68809fdca0e2d9db0ee960e59e93a1f7b4b49c4bd36421f94194747c6a0ff0a2cf20d7bbf703d46b67ce11ea6ec2986a632513646a8a3d49722a2a6b85b4d7040a4321f323859be6f87ea980d3a9e4f0ff0d5b652fd2485f967f16dc83348bdc78e63cdc60edf0d768fddd71aef72b9c7db1d17f7ba4df42a68cc4a011004baaa6829309237a0cb4ed6d38c1569b7344b56db6f69ac9ec1dabae44521f97abb45b5fadadbc8e623cc4e07716dd488e4ea5d268ae04fe39c267e140389fa010c91acfd2fa8c702cdb4a9b7d20b0e7d1fb8006b7dc576a6a98b825ec85819abf910df99a5bbb3e0c7ff28b7007fb081571d4e6bca0290dda73b60522328401cd1978b1495c24e7784713897b608e36383b254c4c4eb2d7ea590c302d3cf1447433ab09f6cf66cf9a7275bd7cf10ce9fbc4127eabd378af66184b74a48cb794ac46255d53584b024404da66848b4a94a8b48266e01f2934890d172a818e9bca6c7cc3662f040620e3f2a0a1c5093df1a02f47f04b5e370c51460af8abdcb24b808dcbd5597cba7f21ff1773101e81d61b82dd319fe4b45416af9987793e4ac959dfa73acd3499519395657398c31e7887f9ba0033deebac685737ed4f96c3686fe169026f7a460f576f50b9b8de6ac4a6f7d0dded364ffc92edf0be4d926647684cdb72c307377a99aee9b168557a792f8d10254968d598c0626ceaf658257b7d9511dbb78925687e77c80f1ac460e85a861c52539f645cd595a273e204d2ab987610b3f86f79365dc20153e5c4c32f9f3088"),
                out_ciphertext=bytes.fromhex("9bdd58eda5ad9518dc15cea267120236d9eb964c6ed3b197ca532d3a9581c77bf27c359f3f3b1666e3ac3504c17e2473fe1431e8c761680da3a6c7386815cc717ae741604fa5d5a5fe79cb3879aa7af6"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
            PcztOrchardAction(
                cv_net=bytes.fromhex("a33ef5236a0bbf46dee6b44320fc293f5ee3238fbbcca7d7a6c9b20ac2da6138"),
                nullifier=bytes.fromhex("ad55957c9deceaee264e52a66c4aff7d5a9100f88c36cb9f1ef39726ab440006"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("46ba59eb9cbbf5fa129c29fa0c6733af5ecec1d80d8e450a93f6d910ce608f11"),
                ephemeral_key=bytes.fromhex("1a16e26f7c5ec1caeb3549893749a2e912ffcafe0dffa3ba6d78a4656c477c10"),
                enc_ciphertext=bytes.fromhex("ba475e732850138870cbe28ab73c29d1d7d29973715d6102287b77420dfa8715486f999f66729d3891ed6f0cde043013091bb28437ad9f57306ac3b8694da7727796ee570d690fd6dae42c5cf15f5751b38130f7c48683852605d68cc3448000af3386156a3e4c4e5522dd9decb8687d2dab1cb544f50ce1296f93933c47fe6fae027fafc9c01194ae1a7987a42f526679154910e352fb45b91dd93922097db44592d185a3e98e621ba913f6085c2a11af6b42bca643ad9120e35b35748e2a4f6af7dccc64eade91713ff27c0eed03caee6e85953bd38fc0ed76c189b2957ae1fd56121aef7de9e9e95d9413301aa70ac858a4f4b78cfb0670c40dfd4f65cd6d6aaffd4b32b4de820b0160b2a5d2012bfee7b6315d1299be3faac1fd92f43cde408f81192d9e68170cd5dfffdf55b4e5557a8ee39fe65bd27cc9c9a852415acfbee22577e1f24a4244c1180477111a88992a98450334f3da859d38403cc8328d4bdcc344fd3dd93e659213b8967edca63e3976121df1b59affd328307778ba1368b41e4782bb7094153321dd7f9f691a503dfe3e8ab40a280a189f9f6fb0d9009d1d48db883f63dfff7f1945168942dc46a1a673bda727405aab3076599d8dc5a8d047fdc02c33b74baa189bfdc5fddd93ff0a78708013f723af3dc89c91c44cb88c190b531092a10bd4caa277347d03651ed81826682bf26f6557ada37f0d4d9a4e9259880dda9928099ab729136a0eb1bf47891789c814c32b738886d3caed34787fa3cfa5fbd766ed2454e365b32d2fbfa2dc96f359bbcb4008563438b4adb5e507ce"),
                out_ciphertext=bytes.fromhex("2c67f43c51278361143bcb44e4b7344bb1159eca9482e81ccdbec33e372dc5930073e0c5721afd2b37a2a19bc8d00074e7d37de2ef118a1aa39602c1a15e4a784b2b137917be051e62ea4c42af7c34e1"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
        ],
        flags=3,
        value_balance=295000,
        anchor=bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109"),
    )
    PCZT_GLOBAL = PcztGlobal()
    EXPECTED_AUTH_SIG = bytes.fromhex("36F43F8402821E188ABA691E735233E2D0C8132C4B25B75F21ABC543D11F86920666C23227051EBB50B2096CB32FC02FD060ED9E17006C57E6376C68E5AFF73C")

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_orchard_to_transparent_with_change",
        PCZT_GLOBAL,
        EXPECTED_AUTH_SIG,
        TRANSPARENT_OUTPUTS,
        ORCHARD_BUNDLE,
    )

def test_pczt_sign_tx_v5_orchard_to_transparent_with_transparent_change(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    ORCHARD_SIGNING_PATH = "m/32'/133'/0'"
    ORCHARD_ALPHA = (1).to_bytes(32, byteorder="little")
    TRANSPARENT_OUTPUTS = [
        PcztTransparentOutput(
            value=290000,
            script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
        ),
        PcztTransparentOutput(
            value=5000,
            script_pubkey=bytes.fromhex("76a914adee44a1e8d1bbfd9e000bdcc4d99849abe339f588ac"),
            signing_path="m/44'/133'/0'/1/0",
        ),
    ]
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes.fromhex("de086e9d8c3e879e951dc2b4eeb71cc5fe3c034699a4ab6f6fa88a53e7a97427"),
                nullifier=bytes.fromhex("ad55957c9deceaee264e52a66c4aff7d5a9100f88c36cb9f1ef39726ab440006"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("3560d8f99b83a9b769595813639e4b0f8e483f0fc217eeedba658e29bae6a920"),
                ephemeral_key=bytes.fromhex("9a32bfd04ca5fc04b87116119201021029bf83d4db0f7fc68c570f7e093beb0f"),
                enc_ciphertext=bytes.fromhex("05606a55b7686cd42a991a1386cf5dbdba9a0bd4754a586861b8bb805332ac07c9be780971fe9791ea947c5214a3ff29fa8216c8271f7f628f9154573fe45d0defcbd67dbaf6a7f5279e6198385eab7999ccae6e6420fedd3c051887edbeb4b0badcdc601c7ac281d8399cd4d482bd3766cd611923a3298b56f1a3d7bc8bd39455cea8151b04429befbf98520c66d2ed57d638d157ab9c994c298188cf2fa1935c7e4abc4a84d99335de77b25b747b3d757f8e9d90cfac6e42dd3a152ec52cb4eaa4285e860ca14dc4b7eefda3e2a2350376da56c4e9b9adc534589cc55f8612d808f556af5bb4483d2b02d723ec7daa7236bb8de917747e997e03e1bc1c5009a63538c966b68d62fa934cae9f6aa19d06845a368b75e6a2f19ecacc2e6e2520fbab710b8c8726d5f9fb3cc2686f5eba0b60208d1a72526594b2305e55d0634e3c15a6b0234554ab6f496998766d2466aa4292d26e3f34b48b8a8f8bb734e085e62700ed282d57d548af65465325915511c6353432c2ffb510f84debbe32eb423e21b3fa1ce56ea30e38f65a37bbaf9c33fb0b9accb73e07806da9331eebff92aa50ceaea89512ab35d87adc6bbbd02b3f976b9b3256fd06163a0eb20aa4f8a84e93fd5d1f20de1cb364e01ed0a2f36b321b7b6c45418554093e7e9519dc436e59cc02cdf1fd23e59f2a7bf970a3b355741ac53d5a4c3b8850905ae273604305b40dc59050c55a466f183ca24869d4d20dc0e846a3d4c6a0254ef02f1520e50f8f5be9c285f0730a67547ee32103b1a5c8594a5f02e7b3fd61a1d8b1a33bfaf7e91f5050"),
                out_ciphertext=bytes.fromhex("40b85ce64c4191976c2db2b671518d0155a81d57beaf402f31e4775e2ec60e2d473fee77e126e541c7d40d7b6442b2655933efc835a1d976aa90b3b03217673049af5d867d8980265f1bf10a7ecf5b5d"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
            PcztOrchardAction(
                cv_net=bytes.fromhex("08b228c0e51ed7061c103f06582d6303fc20689de1dedffc26460f469602b982"),
                nullifier=bytes.fromhex("d68f3363b4843cb568dedbf4d966d1d7876a2edfd758d126efe1a8bd1836620f"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("9215e26687dad4221bf57714aae9e61a69cda0f3407632a94053389dd8b62305"),
                ephemeral_key=bytes.fromhex("2c3b8b1315ba08045e9efe3a3979a4f7bd320b4cb6e0437cf32308c5d87b8733"),
                enc_ciphertext=bytes.fromhex("9bfdf9e41de825407a0eb79aaac9e66a2426247e07fee995d3ea68b5e9538a7e80143bb49a62e0a001a5bf510593f790e4f55c080c39bac1391741d756bedd81eb33bd87f7b8339fcff2951c3a2716d1a653e866cca0556714db01f23b116d550e9f6739efe37c262214d0620bd59c52839c647d56173d78e15d7e171e65ac9e1249ccebe4e1d52ace166bb07f0b20445452c75d5f59a11aa9e490859dce7c108037b53cb3bfd9a242b88ce23625bc0a2e3f88b04abfd60a962186b99335bfd40448f724abfa2b8b804f3c544edc7c0bdb2020ba8b5ce8fcd59da9fa9837640f7079503a6b36fcbfe1399a5baedf8b40a223ffb63c675db73aa7d29a20fa692b5cb20b1e3f504c8b60e616fd05ea2b0983f05d51ffa5b2563e480efb7d5665f77f38f6db2f913b2334034a02e25b0e8898a94967bf596a19556dfd061de393c29ff2e8d6460d26546a3ba68315957f332ccb120a9a7656bc0bda47677be3f998e51bf542ca4d3c213fa33c0ad7beb60bc46da16838015183d32ad91c9071b5ee9d1dacbee5a24af746457ffd6f614341e39f45be9596498ba355d14c1e0e83c8d73f4351c21c4b026fd911e77af3efe8cca37adb2680ffa4b0039449470c7c198170edc8ed44e803ff84c039372566806661d2d274ef222f19a364e1b5b4921eb9c8f7959dc1ad859867d4f4597286647f202876b78d0f699bfe38bbda4e8e4835d7350732e6f0ca6697400933065cccbf3b807fd7cf4a16e2faa553e9ac7f672717cb45eb34bbf4f32cf6e91c8cdb623e75099d5e0eb3887e538d6e6fc102d854395af9"),
                out_ciphertext=bytes.fromhex("eb750713d45b7caa405813743e6e145a48fc7d6b89933a39a56fe9c7d29accc793f8c8c30e217e69e897bc157278f341042b3d8b1b92c9134b96c36901b28157ab2de75219edd12bd522a34eabf1fab2"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
        ],
        flags=1,
        value_balance=300000,
        anchor=bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109"),
    )
    PCZT_GLOBAL = PcztGlobal()
    EXPECTED_AUTH_SIG = bytes.fromhex("114943BF307F040230E2744A432CB083586B8BB46272BA9A7C853FAA3A967635C609924EAA55E78205004E65BD5EB4CDDAF0E94EBFF953DA740A92AC0A79F32B")

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_orchard_to_transparent_with_transparent_change",
        PCZT_GLOBAL,
        EXPECTED_AUTH_SIG,
        TRANSPARENT_OUTPUTS,
        ORCHARD_BUNDLE,
    )

def test_pczt_sign_tx_v5_orchard_to_orchard_simple(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    ORCHARD_SIGNING_PATH = "m/32'/133'/0'"
    ORCHARD_ALPHA = (1).to_bytes(32, byteorder="little")
    TRANSPARENT_OUTPUTS = []
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes.fromhex("0ce5eae9c123a3373634630e258b5e534b3e7c6148ca5a6c04c61bbfa76663b0"),
                nullifier=bytes.fromhex("d68cef8d52a164d092d8bd4a616458187f7703ce6ce5ee9ded3fde2df4c56912"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("9db7163d3fa5a001ba00b42c73589b9791682089f2ef0a14f4ea0d7790cf1e01"),
                ephemeral_key=bytes.fromhex("b8734861bcf115a70efbcb60f711782e71a8ebc0e5ebc1a7b9f97e1c20f5c22e"),
                enc_ciphertext=bytes.fromhex("2e90cfc9aea8db3cd1a2ba6f05d5776f98f9f4f88aba54edb4f5726e9b83b48b6c32bba462fedcc4f7169f785bbc88bb1d99a393f9548b9bce5648c802b993a4525fc75d4cbd4765a841bd8ea6ff745db31ec35f53924049b5246dfc34f6f4f2cd222ff54cd895d7d040bc97a2d8546901ea4ff93f7b09c704329cd621c136889b2f76fe2cc0bcbf23683e81ff7b010fc549ac82773a05d5684482fe9d18408b51656cfe4bb7e7807de829f41c43f26c92f9029e737642c3b3ef0c78c44ee29f0412591603774de7d60096d8e3de1f2635858fcd3c4b9da1c48c287c9a1dc82731e4582db0c9320935b5d10d40c76ab1a17126876c8426f3f007c9e5f7e4b3f52fd4457dc12dfdbc9e2929f362c5f31aa1922bb7aa9f3a988e5f2d86c2b45b0762cae8a2788df8f97766347a65b57fbf2e5699d16bd9a534d3efb8b0e7ccf903f366dab7c8b79f1e7e6df4051ec617e73c7c90caf9ddec1933f3db3d0fbce8dd46ac2d5b9c405c517f14b26f7f24800757ca71d7efb7cc59e46723400e5755b7c87618c97d1367218705121cafb95066caf710e1edf4f7eadba33518e950ae6dfec59c276cc76fbace4bf09ba248e831484c5fc87a1565563727f1f17efdd0a3a498747a867c033c013d3989170bcc95c36a94ad0ab0bfa48623dd124009abbad78251eb4e884a6446938240d025ea877416442cba30a78871ed2baf0af149c15306171f88e2dfb7dc4d0b555f0636bee0d97c9a7afd1e40f4a04bd4c39fa1b307717ce1af12ade0598579e9121a61d6195c58c952b18e1a014df59f729b40283438235b"),
                out_ciphertext=bytes.fromhex("f3795cfffb3ae4fd4c5e28ad5034e2565e4ad326e72458a799cc34f11226fa19ae7b68f1aaf0e1495a6f9b8b41ef2d6b2af71372725172043233b519c1363d0648dda6fc5154a882cc717524d93e7c3c"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
            PcztOrchardAction(
                cv_net=bytes.fromhex("1a88eb3f897cda9bf68454c33f627e0150f974f22af9cd961d04ebc9036bc895"),
                nullifier=bytes.fromhex("fc3ea087e60269ff25114682610a6b0d716f191fbf2acf767d2de63de4b95a00"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("e185cf8de2955a4298f602e4bcf508f55a68cc6c79a5379dda08cab1fec7f628"),
                ephemeral_key=bytes.fromhex("0ddc203d51b8edd935c9445d9c808d2e53585bc1eeaebf5823c9a5e70eb05b12"),
                enc_ciphertext=bytes.fromhex("b35968123a64513c8bf026ae9e1f8c583c3a7807c785632475c220cb9f02316004c1d6a76906f5de4a4f63dcb8777f68a1a4c6f2be9a0094814e13cf6916da676168a3b924e4c043f1c868069ace284843795f0d83ff10bd763ece39246b5ab27fc67c86ec2f5320415f6489a910a72879a92eb9fa832eed9cb6f71cc24fadf4ed44496f706cf1c21ed78046fce7ad3a01b9b17050e587a7daf6a41ef2134c1bc2c1fe16deaba223e227505c7b0491fa6fbc7baf22017c8726569152dde1b735aed3b786d296825b3cb9c074db032be356ab8151a5f01209e53cdf107c9ad0c1b2152209b77aee5a58759ad670d440602e8852336a53dda64eeef8751243afd4052d564bbda0e69c5f66af4ac2d13740f788bb835de948b34b193e8d2731d7abb1e79de14e088c49b007283857fd6b127c3e7c5c585c616a968fd18895988a572fc02d2e859dd584f9fa1ed872794cf349f543f1a3e3516371fddc2a7f294c5c1dce2f35b1fd6e3ca23f8baebca46c1042def754f639f63073d410e8d46fb22a9cf3e8ed46144f78de1f53b9e773d46b9ce22e7887b7d3adcc791e797248e30ca9b950399f9dfb9a5c6bad17882f74e4c4ab21cc52dd6b1e4e8a81edc96fe06710e17fcaad305d94bb384a8c92858da56539745c23e29b33e0bad34599df32bacf36aa29c7b0446e1b669358c5da0c065c0313bd67dcbfe6a68f5aae445b168f95436874e18be427a78dce3e42f463045fd00197bdbd686adc41802fc558a1de5e195542deb4096374c6fa91ab7c51b798a863fd17f0ada698de32cf5d544d90c09baf32"),
                out_ciphertext=bytes.fromhex("1b301923172c05ed37d0ce897cd69922ac249175c1e5e0e718ba94390a7fbe9d74dc128f391595899a3553339b9fe083b7e298091fb0c6d8a813b748f92ecd4d0767efb694d6a230181801226d7351b2"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
        ],
        flags=3,
        value_balance=20000,
        anchor=bytes.fromhex("c5e1408579e67cf16b5d19479408fa035a7db4fe3060123d139eba8523bc9633"),
    )
    PCZT_GLOBAL = PcztGlobal()
    EXPECTED_AUTH_SIG = bytes.fromhex("AF5B24CDFC02F69C61C692D21D4872DF709AEE4DBFFB07C9ECF6656A69893E0C316C1354EFF6F649F2DE374DD60A9BEF067ABF4D098B7C1C6E21A0F17D0B873A")

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_orchard_to_orchard_simple",
        PCZT_GLOBAL,
        EXPECTED_AUTH_SIG,
        TRANSPARENT_OUTPUTS,
        ORCHARD_BUNDLE,
    )

def test_pczt_sign_tx_v5_orchard_to_orchard_with_change(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    ORCHARD_SIGNING_PATH = "m/32'/133'/0'"
    ORCHARD_ALPHA = (1).to_bytes(32, byteorder="little")
    TRANSPARENT_OUTPUTS = []
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes.fromhex("f61b81d4d82e61c245f59ba77c6822b937132e5b794224f95db8433063994f22"),
                nullifier=bytes.fromhex("fc3ea087e60269ff25114682610a6b0d716f191fbf2acf767d2de63de4b95a00"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("ab272660436c13c8a53f357335612f49ba61c2476651a1b3135881c4fe0a773d"),
                ephemeral_key=bytes.fromhex("4c7314227c0199b9311470468981d47713a5f5109369edd7153a470751b070ac"),
                enc_ciphertext=bytes.fromhex("46cbe07c7c443635f101d481bc111642eae701694f6a8e503b163f6eeba752f8336e93a1264d9dc138e450182f6f34c179f577ded73a34e805405edf459ca3c204b704ab6e12a9d98fd58bdd6f23f5175b5f88d4ce8e1ce6e15f5e8ac33001a4a3ee0ac641c5738cd851fb6db8cb7b0eb8cf72e831585b5b4071477e7f8e92fe23f3c8496b283ac227be5219a333b4703efc604dda4752fe7cc2d3a9974d5159017b90d5e1c815db1c8cddab91dacd715c66b7666272178a28c7a7d05b763a9c6525e6f35810852bb77f69245068819d634f0d637101afcd9a3ecc2c17371f269d37d42f543169f9cdbd02be2092bf5eb263dc787fda8a811681303fefb65e7c81fa7fd537d108060d8f56a42577cf45dc57fff563cc7b4d167da96b625e66d02789924cacbf7c5a876383e49573624ab52261d19a49f635e501a15109575562bdd3500eee5681ce00f176fbe9bf9aa607969ef9e124f6932b24f40045a7067d4791794300f875eca146b9a0f7356292e5501511332dad6cc50948e1eae208131f1328ee84d62d916a22239e3f373ee994966cac76aee4a5f4e4d14f2462c98e828f38c8e95bef12a5ca50060e3a5203df81f10d7946e33f51072117403bb2d74cff0d58d66530aefe2c84ccc6c37b2baf77ea7b3ad66d0bc463912de82033f96265aa7c5c9a46a09d9389274dc52c202652b3d09629163416e2deba86e1c556ad1513c9d42e02aea10416c071ad579e6fd813e30210494d918f808664391eebcc501aaa9e8884573bea0f67a8061fe5e531f1ffbbc14da40961ec0d05695c32aebd8ecd"),
                out_ciphertext=bytes.fromhex("dbdf7cc4e1b5e89044eca85547ed7adea0e88738fcab767b03993ede592eb18c2dec1e20c9fd22fed35be298d2621734ddf17176aa51b836e5cd43ff1220854bca515559ddb184b318f65198e890a880"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
            PcztOrchardAction(
                cv_net=bytes.fromhex("7b19b7ceb6a1d588209a62d08e1c13f309e61381f767a59328ff91e4191d98a3"),
                nullifier=bytes.fromhex("d68cef8d52a164d092d8bd4a616458187f7703ce6ce5ee9ded3fde2df4c56912"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("e960b02f6b6e0e58008aac76cd99b4690541a867fbc6f5d52606262264fdda2e"),
                ephemeral_key=bytes.fromhex("a5d064724cd7eeea8058bc46f0b99e3f166acb7533b2bb7f0e71455800438e36"),
                enc_ciphertext=bytes.fromhex("5b7222cdbc3dc4a72cb76e55c1c4035e6ea3ff9b9a8bdc64535e22fd54618a048b61985ca54d154083d92fe9c95806024e214cdd82b1419499387c93bddee1a25b5eb1999aaec9967fe85d7bc41f8c634b7f1b02f140b4947e56bf5e77e84e7a0becac4421ec825a90ef2febfa2099635bdfee145e441d4a98e8accb8608bcc88f2abe8f8503fafc165490f4687fe1687245f731ce2e558513fba50f8a9e079e3599c266fb02ce396472c527fda66e2b4c4c0e7617ccce6aa26ec1312f77c580331dadbf96d9fc7b13277f54cae948938653cfe56a7f695c90764662978ffabbe286b947653498bc4968f62a91f11c94199e23c7906175482480dbbbe8188755590f8084babfca2b9044b4c1c0e84a18f7043b47a6001807170ad5e4b8ab680661407645b2c5ec8740dc69da49255364d4278db9f0bc63ea98e64634114d8bebfabffa57ff61c2509db5431284c16ab926e5c0ba2c219282a7c9ed03c36d9659c0bb1be59b7570935ea2d7352aa11022500cf9b4a6d1ecc556bab49118999663de5f2a22cd78819f5778e3599416ab150f42440ccc761c955dc15f49eab0fd20467a5aae9c6f84dfd14528df46af4da2f0a5ddefa4552be915c564ce720e7d26e1d3261a9bfe568fa1929d3c4da13d2a87eefa955d35aa0a99fdca301d52c3b0ecdb59c275510b7323ff4c46e3e6bf4bdcea7dddd4b9f5349f508b5c62adb529c23f91af42e960a0322ddb6c010b1915f0512db34feabac23fc42294f00f18f6225bd7614e7dadd74d61d8c2d40f8bd02294e262448e7984b7205d3bc6256b751c73042b"),
                out_ciphertext=bytes.fromhex("08abc376d9c33581d1a74aba93b503b2911846ab7d77e8ed96f0210c4ffabb09e81a728fff021f90784cbb2c8b3dd3b7f62491e02618c25a3f819836aed45fcf707a379e4b11b65aaf7f6283c250fcd6"),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
            ),
        ],
        flags=3,
        value_balance=10000,
        anchor=bytes.fromhex("c5e1408579e67cf16b5d19479408fa035a7db4fe3060123d139eba8523bc9633"),
    )
    PCZT_GLOBAL = PcztGlobal()
    EXPECTED_AUTH_SIG = bytes.fromhex("37BDBE4BD6FE9BEEA2AC75B6733A3ADA62D9937A864A9EFE935DE7470399BD06C623F10DB34AC960A95343CAE26CF49FB411DC90564C603DD376EC12076DA20B")

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_orchard_to_orchard_with_change",
        PCZT_GLOBAL,
        EXPECTED_AUTH_SIG,
        TRANSPARENT_OUTPUTS,
        ORCHARD_BUNDLE,
    )


def test_pczt_sign_tx_with_v4_nu6_input(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    EXPECTED_SIG = "31440220488d0fca08431682cd5f10968a72affdd569f61a4a358f73edf05d0fb4a3e1a702204722751bd7d27f999ed714694ad024465d54c288a9cc560559d9594914d92ac501"
    PCZT_GLOBAL = PcztGlobal(consensus_branch_id=0xC8E71055)
    CHANGE_PATH = "m/44'/133'/4'/1/0"
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("0ad3e89c25a3660efacfb08f35dab5cb65d3683f55d7426026d61e93fa395a3e"),
        prevout_index=0,
        value=53142882,
        script_pubkey=bytes.fromhex("76a914c91bd3bb62b6abbb0005ea78613c0c4f11330b4a88ac"),
        sequence=bytes.fromhex("00000000"),
        signing_path="m/44'/133'/4'/0/0",
    )
    RECIPIENT_OUTPUT = PcztTransparentOutput(
        value=10000000,
        script_pubkey=bytes.fromhex("76a9147678416cb82a4a716dd1ee6b332744ba2a1f11c488ac"),
    )
    CHANGE_OUTPUT = PcztTransparentOutput(
        value=42916656,
        script_pubkey=bytes.fromhex("76a914c628ce8ff6367f0ea6763f1c1d865329af0715ac88ac"),
        signing_path=CHANGE_PATH,
    )

    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_GLOBAL,
        transparent_inputs=[TRANSPARENT_INPUT],
        transparent_outputs=[RECIPIENT_OUTPUT, CHANGE_OUTPUT],
    ):
        _review_approve(scenario_navigator, "test_sign_tx_with_v4_nu6_input")

    resp = client.pczt_sign_transparent(input_index=0).data

    assert resp.hex() == EXPECTED_SIG
