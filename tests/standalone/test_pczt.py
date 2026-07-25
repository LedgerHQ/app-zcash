# pylint: disable=C0301

import pytest
from application_client.pczt import (
    PcztGlobal,
    PcztOrchardAction,
    PcztOrchardBundle,
    PcztTransparentInput,
    PcztTransparentOutput,
)
from application_client.zcash_command_sender import (
    Errors,
    ZcashCommandSender,
)
from application_client.zcash_response_unpacker import unpack_get_public_key_response
from application_client.zcash_utils import write_varint
from application_client.zcash_verify_sign import (
    check_tx_v5_signature_validity,
)
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

PCZT_ORCHARD_ALPHA_1 = (1).to_bytes(32, byteorder="little")
PCZT_ORCHARD_RK_ALPHA_1 = bytes.fromhex("e95982b73ab0c2137ec354cce448a75ef39ec0cbdf6907be6df3495297834f89")
PCZT_ORCHARD_EXTERNAL_RECIPIENT = bytes.fromhex(
    "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d"
)
PCZT_ORCHARD_INTERNAL_RECIPIENT = bytes.fromhex(
    "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a"
)
PCZT_ORCHARD_ACCOUNT0_SPEND_RECIPIENT = bytes.fromhex(
    "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02"
)
PCZT_ORCHARD_ACCOUNT0_SPEND_RHO = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000")
PCZT_ORCHARD_ACCOUNT0_SPEND_RSEED = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000")
PCZT_ORCHARD_ACCOUNT0_SPEND_NULLIFIER = bytes.fromhex("f5fdf1d1ef02c98a48475d2a8b96f0eabc1306da508ecef07aa4324463783e35")


def _strict_orchard_action(
    fixture: dict[str, object],
    signing_path: str = "m/32'/133'/0'",
    alpha: bytes = PCZT_ORCHARD_ALPHA_1,
) -> PcztOrchardAction:
    return PcztOrchardAction(
        cv_net=bytes.fromhex(fixture["cv_net"]),
        nullifier=bytes.fromhex(fixture["nullifier"]),
        spend_recipient=bytes.fromhex(fixture["spend_recipient"]),
        spend_rho=bytes.fromhex(fixture["spend_rho"]),
        spend_rseed=bytes.fromhex(fixture["spend_rseed"]),
        rk=PCZT_ORCHARD_RK_ALPHA_1,
        alpha=alpha,
        signing_path=signing_path,
        cmx=bytes.fromhex(fixture["cmx"]),
        ephemeral_key=bytes.fromhex(fixture["ephemeral_key"]),
        enc_ciphertext=bytes.fromhex(fixture["enc_ciphertext"]),
        out_ciphertext=bytes.fromhex(fixture["out_ciphertext"]),
        rcv=bytes.fromhex(fixture["rcv"]),
        rseed=bytes.fromhex(fixture["rseed"]),
        spend_value=fixture["spend_value"],
        value=fixture["value"],
        recipient=bytes.fromhex(fixture["recipient"]),
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


def _sign_all_orchard_actions(
    client: ZcashCommandSender,
    orchard_bundle: PcztOrchardBundle,
) -> list[bytes]:
    # The device produces a spend-auth signature only for real spends. Dummy
    # padding spends (spend_value == 0) are signed host-side by the PCZT
    # IoFinalizer and never counted by the device, which completes the signing
    # session as soon as every real spend is signed. This mirrors the host (DMK)
    # contract; the device also rejects a dummy index outright, which
    # test_pczt_sign_tx_v5_orchard_dummy_spend_signature_is_refused covers.
    auth_sigs = []
    for action_index, action in enumerate(orchard_bundle.actions):
        if action.spend_value == 0:
            continue
        auth_sig = client.pczt_sign_orchard(action_index=action_index).data
        assert len(auth_sig) == 64
        auth_sigs.append(auth_sig)
    return auth_sigs


def _assert_pczt_orchard_sign_digest(
    backend,
    scenario_navigator: NavigateWithScenario,
    snapshot_test_name: str,
    pczt_global: PcztGlobal,
    expected_auth_sigs: bytes | list[bytes],
    transparent_outputs: list[PcztTransparentOutput],
    orchard_bundle: PcztOrchardBundle,
    transparent_input: PcztTransparentInput | None = None,
    prevout_tx: bytes | None = None,
) -> None:
    client = ZcashCommandSender(backend)
    transparent_inputs = [] if transparent_input is None else [transparent_input]
    input_amounts = [txin.value for txin in transparent_inputs]
    expected_auth_sigs = (
        [expected_auth_sigs] if isinstance(expected_auth_sigs, bytes) else expected_auth_sigs
    )
    if prevout_tx is not None:
        # Temporary RNG alignment with the legacy HASH_SIGN flow.
        _ = client.get_trusted_input(prevout_tx, 0).data
    transparent_public_keys = []
    for txin in transparent_inputs:
        response = client.get_public_key(path=txin.signing_path).data
        public_key, _, _ = unpack_get_public_key_response(response)
        transparent_public_keys.append(public_key)

    with client.send_pczt(
        pczt_global=pczt_global,
        transparent_inputs=transparent_inputs,
        transparent_outputs=transparent_outputs,
        orchard_bundle=orchard_bundle,
    ):
        _review_approve(scenario_navigator, snapshot_test_name)

    tx_bytes = _pczt_transaction_bytes(
        pczt_global,
        transparent_inputs,
        transparent_outputs,
        orchard_bundle,
    )
    transparent_sigs = [
        client.pczt_sign_transparent(input_index=input_index).data
        for input_index, _ in enumerate(transparent_inputs)
    ]
    auth_sigs = _sign_all_orchard_actions(client, orchard_bundle)

    assert [sig.hex() for sig in auth_sigs] == [
        sig.hex() for sig in expected_auth_sigs
    ], [sig.hex() for sig in auth_sigs]

    for input_index, (txin, transparent_sig) in enumerate(
        zip(transparent_inputs, transparent_sigs)
    ):
        assert check_tx_v5_signature_validity(
            transparent_public_keys[input_index],
            transparent_sig[:-1],
            tx_bytes,
            input_index=input_index,
            input_amounts=input_amounts,
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
    EXPECTED_SIG = "304402202b22627d88f9ecebf2ab586ffa970232cddad6eabb3289fa1359b2bc9f5554bc02207cfba5db7c01b89c5d540dcb1ada67d485ab1638c2151eaa78b4d368059c007801"  # noqa: E501
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


def test_pczt_rejects_transparent_output_derivation_pubkey_path_mismatch(
    backend,
):
    client = ZcashCommandSender(backend)

    OUTPUT = PcztTransparentOutput(
        value=41628565,
        script_pubkey=bytes.fromhex("76a914adee44a1e8d1bbfd9e000bdcc4d99849abe339f588ac"),
        signing_path="m/44'/133'/0'/1/0",
        bip32_derivation_pubkey=client._compressed_pubkey_from_path("m/44'/133'/0'/0/0"),
    )

    client._send_pczt_header(PcztGlobal())
    client._send_pczt_transparent_inputs([])

    with pytest.raises(ExceptionRAPDU) as e:
        client._send_pczt_transparent_outputs_sync([OUTPUT])

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0


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
        unpack_get_public_key_response(client.get_public_key(path=inp.signing_path).data)[0] for inp in TRANSPARENT_INPUTS
    ]

    with client.send_pczt(
        pczt_global=PCZT_GLOBAL,
        transparent_inputs=TRANSPARENT_INPUTS,
        transparent_outputs=[TRANSPARENT_OUTPUT],
    ):
        _review_approve(scenario_navigator, "test_sign_tx_v5_mult_inputs_old")

    signatures = [client.pczt_sign_transparent(input_index=input_index).data for input_index in range(len(TRANSPARENT_INPUTS))]

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
            spend_recipient=bytes(43),
            spend_rho=bytes(32),
            spend_rseed=bytes(32),
            rk=bytes(32),
            alpha=bytes(32),
            signing_path="m/32'/133'/0'",
            cmx=bytes(32),
            ephemeral_key=bytes(32),
            enc_ciphertext=bytes(580),
            out_ciphertext=bytes(80),
            rcv=bytes(32),
        )

    # MAX_PCZT_ORCHARD_ACTIONS_NUMBER is 10; declare one more to trip the bound.
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
                spend_recipient=PCZT_ORCHARD_ACCOUNT0_SPEND_RECIPIENT,
                spend_rho=PCZT_ORCHARD_ACCOUNT0_SPEND_RHO,
                spend_rseed=PCZT_ORCHARD_ACCOUNT0_SPEND_RSEED,
                rk=bad_rk,
                alpha=(1).to_bytes(32, byteorder="little"),
                signing_path="m/32'/133'/0'",
                cmx=bytes(32),
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(80),
                rcv=bytes(32),
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


def test_pczt_sign_tx_orchard_missing_rcv_rejected(
    backend,
):
    orchard_bundle = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes(32),
                nullifier=PCZT_ORCHARD_ACCOUNT0_SPEND_NULLIFIER,
                spend_recipient=PCZT_ORCHARD_ACCOUNT0_SPEND_RECIPIENT,
                spend_rho=PCZT_ORCHARD_ACCOUNT0_SPEND_RHO,
                spend_rseed=PCZT_ORCHARD_ACCOUNT0_SPEND_RSEED,
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                alpha=(1).to_bytes(32, byteorder="little"),
                signing_path="m/32'/133'/0'",
                cmx=bytes(32),
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(80),
                rcv=bytes(32),
            )
        ],
        flags=0,
        value_balance=0,
        anchor=bytes(32),
    )

    client = ZcashCommandSender(backend)
    client._send_pczt_header(PcztGlobal())
    client._send_pczt_transparent_inputs([])
    client._send_pczt_transparent_outputs_sync([])

    with pytest.raises(ExceptionRAPDU) as e:
        with client._send_pczt_orchard_actions(
            orchard_bundle,
            pczt_finished=True,
            include_rcv=False,
        ):
            pytest.fail("Device accepted a PCZT Orchard action without rcv")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_sign_tx_orchard_cv_net_mismatch_rejected(
    backend,
):
    orchard_bundle = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes.fromhex("39ceba3e81ae3415fb4a519978f4bbc75e5a1d101ce0d6bc91d035f614a9f68b"),
                nullifier=PCZT_ORCHARD_ACCOUNT0_SPEND_NULLIFIER,
                spend_recipient=PCZT_ORCHARD_ACCOUNT0_SPEND_RECIPIENT,
                spend_rho=PCZT_ORCHARD_ACCOUNT0_SPEND_RHO,
                spend_rseed=PCZT_ORCHARD_ACCOUNT0_SPEND_RSEED,
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                alpha=(1).to_bytes(32, byteorder="little"),
                signing_path="m/32'/133'/0'",
                cmx=bytes(32),
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(80),
                rcv=bytes(32),
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
            pytest.fail("Device accepted a PCZT Orchard action with mismatched cv_net")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_sign_tx_orchard_bad_rcv_rejected(
    backend,
):
    orchard_bundle = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes(32),
                nullifier=PCZT_ORCHARD_ACCOUNT0_SPEND_NULLIFIER,
                spend_recipient=PCZT_ORCHARD_ACCOUNT0_SPEND_RECIPIENT,
                spend_rho=PCZT_ORCHARD_ACCOUNT0_SPEND_RHO,
                spend_rseed=PCZT_ORCHARD_ACCOUNT0_SPEND_RSEED,
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                alpha=(1).to_bytes(32, byteorder="little"),
                signing_path="m/32'/133'/0'",
                cmx=bytes(32),
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(80),
                rcv=bytes([0xFF]) * 32,
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
            pytest.fail("Device accepted a PCZT Orchard action with invalid rcv")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_sign_tx_orchard_zero_value_undecryptable_rejected(
    backend,
):
    orchard_bundle = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes(32),
                nullifier=PCZT_ORCHARD_ACCOUNT0_SPEND_NULLIFIER,
                spend_recipient=PCZT_ORCHARD_ACCOUNT0_SPEND_RECIPIENT,
                spend_rho=PCZT_ORCHARD_ACCOUNT0_SPEND_RHO,
                spend_rseed=PCZT_ORCHARD_ACCOUNT0_SPEND_RSEED,
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                alpha=(1).to_bytes(32, byteorder="little"),
                signing_path="m/32'/133'/0'",
                cmx=bytes(32),
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(80),
                rcv=bytes(32),
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
            pytest.fail("Device accepted an undecryptable zero-valued Orchard output")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_sign_tx_orchard_dummy_cmx_mismatch_rejected(
    backend,
):
    bad_cmx = bytes.fromhex("825f806345d7c2ae67fe186120cc5b8a370c2cedb55ccf76527e9efa43c94d30")
    bad_cmx = bytes([bad_cmx[0] ^ 1]) + bad_cmx[1:]
    orchard_bundle = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes.fromhex("00b3324110776396d31646041679fd6530d57c353c6be0a93a0cd55b30aa6d8b"),
                nullifier=bytes.fromhex("08f337fd695cb5ca2ad7ced8ec14afed06d2f8a0e5e3d8b58dffbc69e4f81b2f"),
                spend_recipient=PCZT_ORCHARD_ACCOUNT0_SPEND_RECIPIENT,
                spend_rho=bytes.fromhex("0600000000000000000000000000000000000000000000000000000000000000"),
                spend_rseed=bytes.fromhex("1a00000000000000000000000000000000000000000000000000000000000000"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                alpha=(1).to_bytes(32, byteorder="little"),
                signing_path="m/32'/133'/0'",
                cmx=bad_cmx,
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(80),
                rcv=bytes.fromhex("4200000000000000000000000000000000000000000000000000000000000000"),
                rseed=bytes.fromhex("2e00000000000000000000000000000000000000000000000000000000000000"),
                spend_value=300000,
                value=0,
                recipient=PCZT_ORCHARD_INTERNAL_RECIPIENT,
            )
        ],
        flags=3,
        value_balance=300000,
        anchor=bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109"),
    )

    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PcztGlobal(),
            transparent_inputs=[],
            transparent_outputs=[],
            orchard_bundle=orchard_bundle,
        ):
            pytest.fail("Device accepted a dummy Orchard output with mismatched cmx")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_sign_tx_orchard_dummy_bad_rseed_rejected(
    backend,
):
    orchard_bundle = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes.fromhex("00b3324110776396d31646041679fd6530d57c353c6be0a93a0cd55b30aa6d8b"),
                nullifier=bytes.fromhex("08f337fd695cb5ca2ad7ced8ec14afed06d2f8a0e5e3d8b58dffbc69e4f81b2f"),
                spend_recipient=PCZT_ORCHARD_ACCOUNT0_SPEND_RECIPIENT,
                spend_rho=bytes.fromhex("0600000000000000000000000000000000000000000000000000000000000000"),
                spend_rseed=bytes.fromhex("1a00000000000000000000000000000000000000000000000000000000000000"),
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                alpha=(1).to_bytes(32, byteorder="little"),
                signing_path="m/32'/133'/0'",
                cmx=bytes.fromhex("825f806345d7c2ae67fe186120cc5b8a370c2cedb55ccf76527e9efa43c94d30"),
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(80),
                rcv=bytes.fromhex("4200000000000000000000000000000000000000000000000000000000000000"),
                rseed=bytes([0xFF]) * 32,
                spend_value=300000,
                value=0,
                recipient=PCZT_ORCHARD_INTERNAL_RECIPIENT,
            )
        ],
        flags=3,
        value_balance=300000,
        anchor=bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109"),
    )

    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PcztGlobal(),
            transparent_inputs=[],
            transparent_outputs=[],
            orchard_bundle=orchard_bundle,
        ):
            pytest.fail("Device accepted a dummy Orchard output with invalid rseed")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_sign_tx_orchard_nullifier_mismatch_rejected(
    backend,
):
    bad_nullifier = bytes([PCZT_ORCHARD_ACCOUNT0_SPEND_NULLIFIER[0] ^ 1]) + PCZT_ORCHARD_ACCOUNT0_SPEND_NULLIFIER[1:]
    orchard_bundle = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes(32),
                nullifier=bad_nullifier,
                spend_recipient=PCZT_ORCHARD_ACCOUNT0_SPEND_RECIPIENT,
                spend_rho=PCZT_ORCHARD_ACCOUNT0_SPEND_RHO,
                spend_rseed=PCZT_ORCHARD_ACCOUNT0_SPEND_RSEED,
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                alpha=(1).to_bytes(32, byteorder="little"),
                signing_path="m/32'/133'/0'",
                cmx=bytes(32),
                ephemeral_key=bytes(32),
                enc_ciphertext=bytes(580),
                out_ciphertext=bytes(80),
                rcv=bytes(32),
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
            pytest.fail("Device accepted a PCZT Orchard action with mismatched nullifier")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_sign_tx_v5_mult_outputs(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    EXPECTED_SIG = "3045022100867fdc2d2873b15bc19a42df288a257aff08ba74b9e2eefd1245e69b05a181b302200b876a40a9339b8b8333c332319dbe5329af363628e0fd4847b281719986dc7b01"  # noqa: E501
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
    TX_PREVOUT_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c20000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01a0860100000000001976a91419650e98310b2cc27f00a9d0c4580386553da2e488ac000000"
    )
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("cf67287a7f4820dc2dd57503b3a5e940b4c1b322024cee5e8ffbece7f217f4bf"),
        prevout_index=0,
        value=100000,
        script_pubkey=bytes.fromhex("76a91419650e98310b2cc27f00a9d0c4580386553da2e488ac"),
        sequence=bytes.fromhex("ffffffff"),
        signing_path="m/44'/133'/0'/0/2",
    )
    TRANSPARENT_OUTPUTS = []
    ORCHARD_ACTION = {
        "cv_net": "fd87b590de6e73dbf0372fc4e80e4c9a44c6f9b196fd296165276b15f38ca7be",
        "nullifier": "781c4faf960206510fdc72739267fa193d9e012dbc68998d35539837e520ae2a",
        "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
        "spend_rho": "0100000000000000000000000000000000000000000000000000000000000000",
        "spend_rseed": "1500000000000000000000000000000000000000000000000000000000000000",
        "cmx": "8fa021d7ce7e10ac828106e295d0daaec54ca3101f22054e90a4bb9b61a38000",
        "ephemeral_key": "7895cdaf491fc7b6754bbe1339eab4f4d142e59fff9cf8d3820217f1e940801b",
        "enc_ciphertext": "ffebe7c7d7f8e08fd0baffb71f54ca6fad3b8a1b1702be187bcc24f1874a48bc3013c44c8d0aaadfbdbebeb31c3eda96e539d9856c6b2c38ce2af66b080c355856dc67bf61319f0f1ac890a1cc543f49d32d30b47241d1632e6dcba30492b6a7bdbaafb9f9dd1e68c2ac12d17b485aed2fb8ba6162f4ec70f8b3c045c4db74fd7861cfb6ce2dc74c2a4219fa429332ed86e891aeca5cf2dfd0517f99fee0f0ddcc5a1a2729bac0626f895a1b572fa8eddaf3b72d2cbb6c1681aeb865740d439b7c90334512faa315207d540eb411dfe8d38b3f6673cb65e12816f42bee50abb966437fa386c34ac54611c86cc093ddee1cfe098903f3be4a8de20de1c48fdbd8ca8a9900eeee734dfff526c39ad353a81de786deb8278bdc870b9d65cc99422e54d0bf7e8e0fcf88a0a701ee59195aaa130b8950bf39bc598520f913af4bf770dfcf37e1ed4d19549759e1642945affbe385eb80497b9652e33a5366667b4fd9c212b061c6c2c47d3f289dee39fea4eba73faf6c91428ca0b97d2be3feb7c0e1ea5ee0250aed9a96d7fe9e91c525f46debe71ddbbc0f8d05576ea27a2249f5b9a341561772b6b480404d5e839af42a56d71f20ad5538214b9925f7931d926017353759398d25a5a2611cf243ff44f732cdc57312b7dfe386118a1e9377f36d7ee312be7ce3c0efa96228a83653a607e00d556f8e04defbb39a2179bb2ed8a0389bb157c75913236e6f9ddf21dcc7108b804c1fa194b2603058e03da7ab3f6ee5dacb4fc3769879d72fc21f68116f0af304142361c4e2a86f36e76407a699d61e18fdae6c",  # noqa: E501
        "out_ciphertext": "9964518f9947818c4b75d0aad44fd05bb75a2ed34ff2a915c080e829a150cd8491272ea43bf99db6fc677560484f7667c8ee7307c1acc44873068ef0475b940a62834f31fad9a486f183a5e2d030a01b",  # noqa: E501
        "rcv": "3d00000000000000000000000000000000000000000000000000000000000000",
        "rseed": "2900000000000000000000000000000000000000000000000000000000000000",
        "spend_value": 0,
        "value": 90000,
        "recipient": "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
    }
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[_strict_orchard_action(ORCHARD_ACTION)],
        flags=3,
        value_balance=-90000,
        anchor=bytes.fromhex("ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f"),
    )
    PCZT_GLOBAL = PcztGlobal()
    # All Orchard spends are dummy padding (spend_value == 0), signed host-side;
    # the device produces no Orchard spend-auth signature for this transfer.
    EXPECTED_AUTH_SIG: list[bytes] = []

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


def test_pczt_sign_tx_v5_transparent_to_orchard_with_memo(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    TX_PREVOUT_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c20000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01a0860100000000001976a91419650e98310b2cc27f00a9d0c4580386553da2e488ac000000"
    )
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("cf67287a7f4820dc2dd57503b3a5e940b4c1b322024cee5e8ffbece7f217f4bf"),
        prevout_index=0,
        value=100000,
        script_pubkey=bytes.fromhex("76a91419650e98310b2cc27f00a9d0c4580386553da2e488ac"),
        sequence=bytes.fromhex("ffffffff"),
        signing_path="m/44'/133'/0'/0/2",
    )
    TRANSPARENT_OUTPUTS = []
    ORCHARD_ACTION = {
        "cv_net": "fd87b590de6e73dbf0372fc4e80e4c9a44c6f9b196fd296165276b15f38ca7be",
        "nullifier": "781c4faf960206510fdc72739267fa193d9e012dbc68998d35539837e520ae2a",
        "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
        "spend_rho": "0100000000000000000000000000000000000000000000000000000000000000",
        "spend_rseed": "1500000000000000000000000000000000000000000000000000000000000000",
        "cmx": "8fa021d7ce7e10ac828106e295d0daaec54ca3101f22054e90a4bb9b61a38000",
        "ephemeral_key": "7895cdaf491fc7b6754bbe1339eab4f4d142e59fff9cf8d3820217f1e940801b",
        # Decrypts through the external OVK to ASCII memo: "PCZT Orchard memo test".
        "enc_ciphertext": "ffebe7c7d7f8e08fd0baffb71f54ca6fad3b8a1b1702be187bcc24f1874a48bc3013c44c8d0aaadfbdbebeb31c3eda96e539d9853c28766cee658408606d473c76b102d20e11eb6a69bc90a1cc543f49d32d30b47241d1632e6dcba30492b6a7bdbaafb9f9dd1e68c2ac12d17b485aed2fb8ba6162f4ec70f8b3c045c4db74fd7861cfb6ce2dc74c2a4219fa429332ed86e891aeca5cf2dfd0517f99fee0f0ddcc5a1a2729bac0626f895a1b572fa8eddaf3b72d2cbb6c1681aeb865740d439b7c90334512faa315207d540eb411dfe8d38b3f6673cb65e12816f42bee50abb966437fa386c34ac54611c86cc093ddee1cfe098903f3be4a8de20de1c48fdbd8ca8a9900eeee734dfff526c39ad353a81de786deb8278bdc870b9d65cc99422e54d0bf7e8e0fcf88a0a701ee59195aaa130b8950bf39bc598520f913af4bf770dfcf37e1ed4d19549759e1642945affbe385eb80497b9652e33a5366667b4fd9c212b061c6c2c47d3f289dee39fea4eba73faf6c91428ca0b97d2be3feb7c0e1ea5ee0250aed9a96d7fe9e91c525f46debe71ddbbc0f8d05576ea27a2249f5b9a341561772b6b480404d5e839af42a56d71f20ad5538214b9925f7931d926017353759398d25a5a2611cf243ff44f732cdc57312b7dfe386118a1e9377f36d7ee312be7ce3c0efa96228a83653a607e00d556f8e04defbb39a2179bb2ed8a0389bb157c75913236e6f9ddf21dcc7108b804c1fa194b2603058e03da7ab3f6ee5dacb4fc3769879d72fc21f68116f0af30414236191a3d962f29d7edab27b8e9ebd96e21f",  # noqa: E501
        "out_ciphertext": "9964518f9947818c4b75d0aad44fd05bb75a2ed34ff2a915c080e829a150cd8491272ea43bf99db6fc677560484f7667c8ee7307c1acc44873068ef0475b940a62834f31fad9a486f183a5e2d030a01b",  # noqa: E501
        "rcv": "3d00000000000000000000000000000000000000000000000000000000000000",
        "rseed": "2900000000000000000000000000000000000000000000000000000000000000",
        "spend_value": 0,
        "value": 90000,
        "recipient": "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
    }
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[_strict_orchard_action(ORCHARD_ACTION)],
        flags=3,
        value_balance=-90000,
        anchor=bytes.fromhex("ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f"),
    )
    PCZT_GLOBAL = PcztGlobal()
    # All Orchard spends are dummy padding (spend_value == 0), signed host-side;
    # the device produces no Orchard spend-auth signature for this transfer.
    EXPECTED_AUTH_SIG: list[bytes] = []

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_transparent_to_orchard_with_memo",
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
    TX_PREVOUT_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c20000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01a0860100000000001976a91419650e98310b2cc27f00a9d0c4580386553da2e488ac000000"
    )
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("cf67287a7f4820dc2dd57503b3a5e940b4c1b322024cee5e8ffbece7f217f4bf"),
        prevout_index=0,
        value=100000,
        script_pubkey=bytes.fromhex("76a91419650e98310b2cc27f00a9d0c4580386553da2e488ac"),
        sequence=bytes.fromhex("ffffffff"),
        signing_path="m/44'/133'/0'/0/2",
    )
    TRANSPARENT_OUTPUTS = []
    RECIPIENT_ORCHARD_ACTION = {
        "cv_net": "53996c104a264c17582dcb0292ced66dbba909ec10c67d6a47ec3ef3aaa2c0a8",
        "nullifier": "6209c5be5e2e174eceba581599d0d4fc3cd3bc97494cf829675de17559bfea17",
        "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
        "spend_rho": "0200000000000000000000000000000000000000000000000000000000000000",
        "spend_rseed": "1600000000000000000000000000000000000000000000000000000000000000",
        "cmx": "58235845190f45e7038e42be9a36ba75a57dd5d0aa5b116ec70aa273fcfc700a",
        "ephemeral_key": "ba15ebdadf4cff31a909e9bdbe2cfb6af9f2de87d09fbabc81438bfeba33ee3f",
        "enc_ciphertext": "c331b211b1c19bbdc6250181e279c09ce4340a4bb771b3ea4e752c972e40a488a009c741c8cd93aef5cfe853d749e02fb4502073c7be09948a8d3b82ad18dcccd7b52b988ca37f230d711f9eb4d9bf5c90c4282b8295c5bd832e82b29cff45edf415dc1c5ad22e35e9e6ed48cb6857e617e7a7d324c881719f70b3d7926881e1bc84eedb578a2438a1c7bdc075be3dce88ad78b5455c5c554a98870e742d03c7351386f702d1f1272f3a3bf40377aa0ac2647c0d57820b039345823bd767e93e94e23fe21a338cf57ef841bd06f06ef17556dc19517c34b358879bf945b2152bd615d6163d1b9f432533ed77a274b9094e793500ef184f612dd3814aa367bd45e53a63ddb85af78897556f1281a9cb1f3fbea704b3c570023c397c9421012ec2acf1d7dda3056195bcf1028befefbde4dd07f41ec3346893834cd9a4c7effd4f81cb0cb90bdd096cee6d63bc8e40a66b92a7597ed3e628e26c10b01fdf3622d3290ba3f19341d59d8a755704115cb54bc7159034ae5ec8eb5d9aeffbca4a44f4a7645088e994af9d2dc2c7e50edfbed4d460a92c5b745a956f2fc15c0a79ad89c27eeb8cd15a4692ff32c073ad9cde54ecb020dc2329f86d4edb0f942d79e4251a43549778a5da8e89acb671f399783774c1510a9895f3113d8a2d14766be9657f603574f3726158444f64592cc0efec2c0dc21eaac0f64a3dca8a6127e105b9dc581c13bcd4ea6ecdb684ef3f81b060e26952eb21fd6acafd79b189445cfbde816366bac051b4e07d6321c669b8f9643e734dc1c11d82e729354dd34702d48383e447da",  # noqa: E501
        "out_ciphertext": "51bfcdc33143947f41974344b8d524e32acefc5112859612da87b29ca1d646efb4aad8567f9f9df2acf464150352a8aeb7710ba8f9edcf26b6c99ed28da661473fb5410f343bab9b5ffa3fa030bf94d0",  # noqa: E501
        "rcv": "3e00000000000000000000000000000000000000000000000000000000000000",
        "rseed": "2a00000000000000000000000000000000000000000000000000000000000000",
        "spend_value": 0,
        "value": 90000,
        "recipient": "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
    }
    CHANGE_ORCHARD_ACTION = {
        "cv_net": "33ef48fc34e684c82ff9ee9d88cdc9761bb45fd3361ae04b5da2328f712d2703",
        "nullifier": "808981a1e1e1116c5d73810a3c09a2ab8051fc9fe192470866e5853004aaaf13",
        "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
        "spend_rho": "0300000000000000000000000000000000000000000000000000000000000000",
        "spend_rseed": "1700000000000000000000000000000000000000000000000000000000000000",
        "cmx": "85b20955b27f6e8a2ad94f5a4926ac434ef441349c778ad549a22c4ea7141630",
        "ephemeral_key": "1590a0d7151f0d62b21fc28978222f5efb0b9ea0b0dff95a6c2e210f44e226bd",
        "enc_ciphertext": "07a29fbda6c36bafeb6b2b3dce86af1662d0775082e76122de2c84216ec97e5c850767b7dc136af4dd2e36ef19200e60a99dfcda4e87f912c0d4f81cd471aa3521fba18b38755489c71576e4aa2707b7ee93be1e8e7442fdbaf76861df11c0d3b92626570cb1cf2b4c863a85e473523c2a20d2b82e90b6fa4b03f6dbceee469819ce888ffabbd87b54b081bd2ccc4292a3494a454b9fc5496b561e78158a59e0311c8125574a43f8d3d82fc080fbf107561bda0b5eead7ed896ec5c58449354bb4feb2e9e4c9e04e75e5bcf933a9e00ccbc69ac1aa5d6510aca854fb4cb838027f301bfee6197e2b884ddc66c673d425048408f36c7c932c50fc889cee6a6d94b78ecb4872e7568e58d30d9bb9e424ee883abc437f5f6336e0c5a2a72beebcdc38a75e62ffb1c1c9f059a65b7cd3c04d985b6d611bba777e6378656170e60439b941e2b6c2fd4a25cc6f142593cee329880aea4cb0e7a8d3f885aafd1d1b79016636757628dafcacddddc861381123bdb2705823d79c1008c7e13bed7bd7b0f6fbd2567e691f94acc13b62be4509a907e89bbae9f2e50af92434f5d7f63ad183b8d4f7b328303f55220a0e364212ede963a0bdb753b7849ad9d2692aceec476dcda50c35b4c68fd48854626bf2fdd1b80480132f0dc57a4d84aa84a34306b8ff683e4602b52fa1cc254174f4aba9fb6b0a28323880fa23d7144a124192954e2ae8c95d79b248f4f855f2e1d7c9cff0eda6f81ade2d8204a186a8ea6b8910badd07a2ddff0d830cb6501b768bf827088a951aeab13bb7c006430a2aba8ffc6f236abaa9c9",  # noqa: E501
        "out_ciphertext": "69368b3bc476a79d8c7783b2f8c73fb738016bb7b0345f300920855807168ae39991f2f15ecb065a9d883bafa431e2ca44fd42e064fd08b158bd1576d9be47afa2818de7a9d4dd000421a39e72d4bb32",  # noqa: E501
        "rcv": "3f00000000000000000000000000000000000000000000000000000000000000",
        "rseed": "2b00000000000000000000000000000000000000000000000000000000000000",
        "spend_value": 0,
        "value": 5000,
        "recipient": "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a",
    }
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[
            _strict_orchard_action(RECIPIENT_ORCHARD_ACTION),
            _strict_orchard_action(CHANGE_ORCHARD_ACTION),
        ],
        flags=3,
        value_balance=-95000,
        anchor=bytes.fromhex("ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f"),
    )
    PCZT_GLOBAL = PcztGlobal()
    # Both Orchard actions (recipient + change) are dummy padding
    # (spend_value == 0), signed host-side; the device produces no Orchard
    # spend-auth signature for this transfer.
    EXPECTED_AUTH_SIG: list[bytes] = []

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


def test_pczt_sign_tx_v5_transparent_to_orchard_self_transfer_displays_internal(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    TX_PREVOUT_BYTES = bytes.fromhex(
        "050000800a27a726b4d0d6c20000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01a0860100000000001976a91419650e98310b2cc27f00a9d0c4580386553da2e488ac000000"
    )
    TRANSPARENT_INPUT = PcztTransparentInput(
        prevout_txid=bytes.fromhex("cf67287a7f4820dc2dd57503b3a5e940b4c1b322024cee5e8ffbece7f217f4bf"),
        prevout_index=0,
        value=100000,
        script_pubkey=bytes.fromhex("76a91419650e98310b2cc27f00a9d0c4580386553da2e488ac"),
        sequence=bytes.fromhex("ffffffff"),
        signing_path="m/44'/133'/0'/0/2",
    )
    TRANSPARENT_OUTPUTS = []
    CHANGE_ORCHARD_ACTION = {
        "cv_net": "33ef48fc34e684c82ff9ee9d88cdc9761bb45fd3361ae04b5da2328f712d2703",
        "nullifier": "808981a1e1e1116c5d73810a3c09a2ab8051fc9fe192470866e5853004aaaf13",
        "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
        "spend_rho": "0300000000000000000000000000000000000000000000000000000000000000",
        "spend_rseed": "1700000000000000000000000000000000000000000000000000000000000000",
        "cmx": "85b20955b27f6e8a2ad94f5a4926ac434ef441349c778ad549a22c4ea7141630",
        "ephemeral_key": "1590a0d7151f0d62b21fc28978222f5efb0b9ea0b0dff95a6c2e210f44e226bd",
        "enc_ciphertext": "07a29fbda6c36bafeb6b2b3dce86af1662d0775082e76122de2c84216ec97e5c850767b7dc136af4dd2e36ef19200e60a99dfcda4e87f912c0d4f81cd471aa3521fba18b38755489c71576e4aa2707b7ee93be1e8e7442fdbaf76861df11c0d3b92626570cb1cf2b4c863a85e473523c2a20d2b82e90b6fa4b03f6dbceee469819ce888ffabbd87b54b081bd2ccc4292a3494a454b9fc5496b561e78158a59e0311c8125574a43f8d3d82fc080fbf107561bda0b5eead7ed896ec5c58449354bb4feb2e9e4c9e04e75e5bcf933a9e00ccbc69ac1aa5d6510aca854fb4cb838027f301bfee6197e2b884ddc66c673d425048408f36c7c932c50fc889cee6a6d94b78ecb4872e7568e58d30d9bb9e424ee883abc437f5f6336e0c5a2a72beebcdc38a75e62ffb1c1c9f059a65b7cd3c04d985b6d611bba777e6378656170e60439b941e2b6c2fd4a25cc6f142593cee329880aea4cb0e7a8d3f885aafd1d1b79016636757628dafcacddddc861381123bdb2705823d79c1008c7e13bed7bd7b0f6fbd2567e691f94acc13b62be4509a907e89bbae9f2e50af92434f5d7f63ad183b8d4f7b328303f55220a0e364212ede963a0bdb753b7849ad9d2692aceec476dcda50c35b4c68fd48854626bf2fdd1b80480132f0dc57a4d84aa84a34306b8ff683e4602b52fa1cc254174f4aba9fb6b0a28323880fa23d7144a124192954e2ae8c95d79b248f4f855f2e1d7c9cff0eda6f81ade2d8204a186a8ea6b8910badd07a2ddff0d830cb6501b768bf827088a951aeab13bb7c006430a2aba8ffc6f236abaa9c9",  # noqa: E501
        "out_ciphertext": "69368b3bc476a79d8c7783b2f8c73fb738016bb7b0345f300920855807168ae39991f2f15ecb065a9d883bafa431e2ca44fd42e064fd08b158bd1576d9be47afa2818de7a9d4dd000421a39e72d4bb32",  # noqa: E501
        "rcv": "3f00000000000000000000000000000000000000000000000000000000000000",
        "rseed": "2b00000000000000000000000000000000000000000000000000000000000000",
        "spend_value": 0,
        "value": 5000,
        "recipient": "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a",
    }
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[_strict_orchard_action(CHANGE_ORCHARD_ACTION)],
        flags=3,
        value_balance=-5000,
        anchor=bytes.fromhex("ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f"),
    )
    PCZT_GLOBAL = PcztGlobal()
    # The Orchard spend is dummy padding (spend_value == 0), signed host-side;
    # the device produces no Orchard spend-auth signature for this transfer.
    EXPECTED_AUTH_SIG: list[bytes] = []

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_transparent_to_orchard_self_transfer_displays_internal",
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
    TRANSPARENT_OUTPUTS = [
        PcztTransparentOutput(
            value=290000,
            script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
        ),
    ]
    ORCHARD_ACTION = {
        "cv_net": "24631b59abdde690d7e6b62cfeac6619efb7753dc873d9dbfdd4af58f0c50e98",
        "nullifier": "2e552e9315c89ecbf8016a8dfaa325ef90dedc59df4b0a42e5ff5cee0bbed821",
        "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
        "spend_rho": "0400000000000000000000000000000000000000000000000000000000000000",
        "spend_rseed": "1800000000000000000000000000000000000000000000000000000000000000",
        "cmx": "f4f6493954ecd47be87e5fdebb99db614dfaf1825717f23c4b0438688d831a04",
        "ephemeral_key": "00" * 32,
        "enc_ciphertext": "00" * 580,
        "out_ciphertext": "00" * 80,
        "rcv": "4000000000000000000000000000000000000000000000000000000000000000",
        "rseed": "2c00000000000000000000000000000000000000000000000000000000000000",
        "spend_value": 300000,
        "value": 0,
        "recipient": "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a",
    }
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[_strict_orchard_action(ORCHARD_ACTION)],
        flags=3,
        value_balance=300000,
        anchor=bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109"),
    )
    PCZT_GLOBAL = PcztGlobal()
    EXPECTED_AUTH_SIG = bytes.fromhex(
        "c9c9c463d2e9b29fd40cdf442913115e64bfb2fb52a6873486f191f0062bcd3783304527181d6ed316281d1680ebb4da4dd0822932091ab36676a1440e7f0820"
    )

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
    TRANSPARENT_OUTPUTS = [
        PcztTransparentOutput(
            value=290000,
            script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
        ),
    ]
    CHANGE_ORCHARD_ACTION = {
        "cv_net": "6dc30a9161336a15dc711399c28ec43c6553c5d2080d26f3dd5a5b92205a8a3f",
        "nullifier": "6adb0656945a7d10a3e3ea9770bb6908028b215744c3eb97cebc2f26b0d5a93f",
        "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
        "spend_rho": "0500000000000000000000000000000000000000000000000000000000000000",
        "spend_rseed": "1900000000000000000000000000000000000000000000000000000000000000",
        "cmx": "d39997b4db9c319c4e4c1d0263ca722097cb450e19d082ccb1a0110293468a20",
        "ephemeral_key": "0a9c9de85198786097f3ab9f2b898b8dfc2abfc54c1c4e11ec1ebabb54b9df20",
        "enc_ciphertext": "a2fd467e666d966bb8db3c421e429e77fbb8caaa499ef55cde5e7541149852c6c193ffaf27839972dd372573751f471a7b6481c4fb5125aa1c9411a6304604ca224f8a272aeed0f0a8dcf77e22c436c720b070849ce8362daa7d168baad887f65679d9e2b753cba4da655b47c6c1f9a8b4286205338561689571ddde3eacd8fd148ddfe722213653b2935dd73379fe1569599462774c62e27dc06b5f2adce5a27681bbbc2cf0e48ba1959003a670a0f986f67d0069d3dc7d49cd3fe9be4f66dda188ab123bca4fcb4c38355943cb6b9864b13939f81f206be2b6570f61ddc66081d26b4eddc1d6beff4471e8648cdbf7dc1ae19021f0ca119373572c2aaf04c827bdb118b3514bec74c0f2fc2bc77c1b529f22fa536c5173e12b76763f742f714c901cd020a3acbfad5d0410464b61716d33a6a0d439551d15140fb24f2721e2812ffdec5a47bc0634299d826c9fc7e5a61a17b36541880e2a49914592b3ea3f873bb7d736fd782a2408f2836cbeacedfe754aae6e48762e07ed5269a8398a5332e83ff5901a77a7bf6eb76e356e48e41eb5af51fb8206d85b50244ed1dd5ba6cfe562d5c9c54e2825c43174e8df3779dcc5777e40692d4c82750eaa5e745f9547f4fe1d0661cc259b1cf4f8c14a2d91360499e5224e9bca03871f823ef5966f01cd900f73387b3acaaa2978c047c75e076e2f44ef9b89a59858b0fdc9d511a2ea3726f95a18d598f2c324a738c2b36b1a2057db72d1efae06d835cf4aa697e7845de1a8585da38f0673cb5c0f6e78588c330132524ee45f0559ee2011d155fbab30a904",  # noqa: E501
        "out_ciphertext": "e286df1b466593e4e7c588800d2c19228169f267b7a3b112186fda3ef85e826e1c2e61a30ed454d001f4e9152828db088e40b314c385cb12d3cb9cf8b2c11a36b00699af2d03d73934f674f33a6cc5c7",  # noqa: E501
        "rcv": "4100000000000000000000000000000000000000000000000000000000000000",
        "rseed": "2d00000000000000000000000000000000000000000000000000000000000000",
        "spend_value": 300000,
        "value": 5000,
        "recipient": "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a",
    }
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[_strict_orchard_action(CHANGE_ORCHARD_ACTION)],
        flags=3,
        value_balance=295000,
        anchor=bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109"),
    )
    PCZT_GLOBAL = PcztGlobal()
    EXPECTED_AUTH_SIG = bytes.fromhex(
        "8d1572632d414bbc6028a263ca52f28aae838c2728f0d6f772e528a4a24193130d34e1c1d949dbc519e5c62345f38d627ff0e6987bb60c8a1920f0b707dd5331"
    )

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_orchard_to_transparent_with_change",
        PCZT_GLOBAL,
        EXPECTED_AUTH_SIG,
        TRANSPARENT_OUTPUTS,
        ORCHARD_BUNDLE,
    )


def test_pczt_sign_tx_v5_orchard_to_transparent_self_transfer_displays_internal(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    TRANSPARENT_OUTPUTS = [
        PcztTransparentOutput(
            value=5000,
            script_pubkey=bytes.fromhex("76a914adee44a1e8d1bbfd9e000bdcc4d99849abe339f588ac"),
            signing_path="m/44'/133'/0'/1/0",
        ),
    ]
    ORCHARD_ACTION = {
        "cv_net": "00b3324110776396d31646041679fd6530d57c353c6be0a93a0cd55b30aa6d8b",
        "nullifier": "08f337fd695cb5ca2ad7ced8ec14afed06d2f8a0e5e3d8b58dffbc69e4f81b2f",
        "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
        "spend_rho": "0600000000000000000000000000000000000000000000000000000000000000",
        "spend_rseed": "1a00000000000000000000000000000000000000000000000000000000000000",
        "cmx": "825f806345d7c2ae67fe186120cc5b8a370c2cedb55ccf76527e9efa43c94d30",
        "ephemeral_key": "00" * 32,
        "enc_ciphertext": "00" * 580,
        "out_ciphertext": "00" * 80,
        "rcv": "4200000000000000000000000000000000000000000000000000000000000000",
        "rseed": "2e00000000000000000000000000000000000000000000000000000000000000",
        "spend_value": 300000,
        "value": 0,
        "recipient": "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a",
    }
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[_strict_orchard_action(ORCHARD_ACTION)],
        flags=3,
        value_balance=300000,
        anchor=bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109"),
    )
    PCZT_GLOBAL = PcztGlobal()
    EXPECTED_AUTH_SIG = bytes.fromhex(
        "921b4aeb91bbf22745cac4523f5a780c839dd999bb5a4629e232f639d33cec16f07dcb235432a39b694fdfc7783dc8fd3ca3e7eb753773c26483691d6c945c1e"
    )

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_orchard_to_transparent_self_transfer_displays_internal",
        PCZT_GLOBAL,
        EXPECTED_AUTH_SIG,
        TRANSPARENT_OUTPUTS,
        ORCHARD_BUNDLE,
    )


def test_pczt_sign_tx_v5_orchard_to_transparent_with_transparent_change(
    backend,
    scenario_navigator: NavigateWithScenario,
):
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
    ORCHARD_ACTION = {
        "cv_net": "00b3324110776396d31646041679fd6530d57c353c6be0a93a0cd55b30aa6d8b",
        "nullifier": "08f337fd695cb5ca2ad7ced8ec14afed06d2f8a0e5e3d8b58dffbc69e4f81b2f",
        "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
        "spend_rho": "0600000000000000000000000000000000000000000000000000000000000000",
        "spend_rseed": "1a00000000000000000000000000000000000000000000000000000000000000",
        "cmx": "825f806345d7c2ae67fe186120cc5b8a370c2cedb55ccf76527e9efa43c94d30",
        "ephemeral_key": "00" * 32,
        "enc_ciphertext": "00" * 580,
        "out_ciphertext": "00" * 80,
        "rcv": "4200000000000000000000000000000000000000000000000000000000000000",
        "rseed": "2e00000000000000000000000000000000000000000000000000000000000000",
        "spend_value": 300000,
        "value": 0,
        "recipient": "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a",
    }
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[_strict_orchard_action(ORCHARD_ACTION)],
        flags=3,
        value_balance=300000,
        anchor=bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109"),
    )
    PCZT_GLOBAL = PcztGlobal()
    EXPECTED_AUTH_SIG = bytes.fromhex(
        "082db120e7231c0ae1deef3644b22520efa27830b7af56ba6d98fe53ed52da8f5304969c04047adc11901c33408cc4dff466487aeca5b94fa0f788bc5f956f1c"
    )

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        "test_sign_tx_v5_orchard_to_transparent_with_transparent_change",
        PCZT_GLOBAL,
        EXPECTED_AUTH_SIG,
        TRANSPARENT_OUTPUTS,
        ORCHARD_BUNDLE,
    )


def test_pczt_sign_tx_v5_orchard_to_orchard_unrecoverable_output_rejected(
    backend,
):
    ORCHARD_SIGNING_PATH = "m/32'/133'/0'"
    ORCHARD_ALPHA = (1).to_bytes(32, byteorder="little")
    TRANSPARENT_OUTPUTS = []
    ORCHARD_BUNDLE = PcztOrchardBundle(
        actions=[
            PcztOrchardAction(
                cv_net=bytes.fromhex("0ce5eae9c123a3373634630e258b5e534b3e7c6148ca5a6c04c61bbfa76663b0"),
                nullifier=bytes.fromhex("d68cef8d52a164d092d8bd4a616458187f7703ce6ce5ee9ded3fde2df4c56912"),
                spend_recipient=PCZT_ORCHARD_ACCOUNT0_SPEND_RECIPIENT,
                spend_rho=PCZT_ORCHARD_ACCOUNT0_SPEND_RHO,
                spend_rseed=PCZT_ORCHARD_ACCOUNT0_SPEND_RSEED,
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("9db7163d3fa5a001ba00b42c73589b9791682089f2ef0a14f4ea0d7790cf1e01"),
                ephemeral_key=bytes.fromhex("b8734861bcf115a70efbcb60f711782e71a8ebc0e5ebc1a7b9f97e1c20f5c22e"),
                enc_ciphertext=bytes.fromhex(
                    "2e90cfc9aea8db3cd1a2ba6f05d5776f98f9f4f88aba54edb4f5726e9b83b48b6c32bba462fedcc4f7169f785bbc88bb1d99a393f9548b9bce5648c802b993a4525fc75d4cbd4765a841bd8ea6ff745db31ec35f53924049b5246dfc34f6f4f2cd222ff54cd895d7d040bc97a2d8546901ea4ff93f7b09c704329cd621c136889b2f76fe2cc0bcbf23683e81ff7b010fc549ac82773a05d5684482fe9d18408b51656cfe4bb7e7807de829f41c43f26c92f9029e737642c3b3ef0c78c44ee29f0412591603774de7d60096d8e3de1f2635858fcd3c4b9da1c48c287c9a1dc82731e4582db0c9320935b5d10d40c76ab1a17126876c8426f3f007c9e5f7e4b3f52fd4457dc12dfdbc9e2929f362c5f31aa1922bb7aa9f3a988e5f2d86c2b45b0762cae8a2788df8f97766347a65b57fbf2e5699d16bd9a534d3efb8b0e7ccf903f366dab7c8b79f1e7e6df4051ec617e73c7c90caf9ddec1933f3db3d0fbce8dd46ac2d5b9c405c517f14b26f7f24800757ca71d7efb7cc59e46723400e5755b7c87618c97d1367218705121cafb95066caf710e1edf4f7eadba33518e950ae6dfec59c276cc76fbace4bf09ba248e831484c5fc87a1565563727f1f17efdd0a3a498747a867c033c013d3989170bcc95c36a94ad0ab0bfa48623dd124009abbad78251eb4e884a6446938240d025ea877416442cba30a78871ed2baf0af149c15306171f88e2dfb7dc4d0b555f0636bee0d97c9a7afd1e40f4a04bd4c39fa1b307717ce1af12ade0598579e9121a61d6195c58c952b18e1a014df59f729b40283438235b"
                ),
                out_ciphertext=bytes.fromhex(
                    "f3795cfffb3ae4fd4c5e28ad5034e2565e4ad326e72458a799cc34f11226fa19ae7b68f1aaf0e1495a6f9b8b41ef2d6b2af71372725172043233b519c1363d0648dda6fc5154a882cc717524d93e7c3c"
                ),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
                spend_value=100000,
                value=180000,
                recipient=PCZT_ORCHARD_EXTERNAL_RECIPIENT,
                rcv=bytes(32),
            ),
            PcztOrchardAction(
                cv_net=bytes.fromhex("1a88eb3f897cda9bf68454c33f627e0150f974f22af9cd961d04ebc9036bc895"),
                nullifier=bytes.fromhex("fc3ea087e60269ff25114682610a6b0d716f191fbf2acf767d2de63de4b95a00"),
                spend_recipient=PCZT_ORCHARD_ACCOUNT0_SPEND_RECIPIENT,
                spend_rho=PCZT_ORCHARD_ACCOUNT0_SPEND_RHO,
                spend_rseed=PCZT_ORCHARD_ACCOUNT0_SPEND_RSEED,
                rk=PCZT_ORCHARD_RK_ALPHA_1,
                cmx=bytes.fromhex("e185cf8de2955a4298f602e4bcf508f55a68cc6c79a5379dda08cab1fec7f628"),
                ephemeral_key=bytes.fromhex("0ddc203d51b8edd935c9445d9c808d2e53585bc1eeaebf5823c9a5e70eb05b12"),
                enc_ciphertext=bytes.fromhex(
                    "b35968123a64513c8bf026ae9e1f8c583c3a7807c785632475c220cb9f02316004c1d6a76906f5de4a4f63dcb8777f68a1a4c6f2be9a0094814e13cf6916da676168a3b924e4c043f1c868069ace284843795f0d83ff10bd763ece39246b5ab27fc67c86ec2f5320415f6489a910a72879a92eb9fa832eed9cb6f71cc24fadf4ed44496f706cf1c21ed78046fce7ad3a01b9b17050e587a7daf6a41ef2134c1bc2c1fe16deaba223e227505c7b0491fa6fbc7baf22017c8726569152dde1b735aed3b786d296825b3cb9c074db032be356ab8151a5f01209e53cdf107c9ad0c1b2152209b77aee5a58759ad670d440602e8852336a53dda64eeef8751243afd4052d564bbda0e69c5f66af4ac2d13740f788bb835de948b34b193e8d2731d7abb1e79de14e088c49b007283857fd6b127c3e7c5c585c616a968fd18895988a572fc02d2e859dd584f9fa1ed872794cf349f543f1a3e3516371fddc2a7f294c5c1dce2f35b1fd6e3ca23f8baebca46c1042def754f639f63073d410e8d46fb22a9cf3e8ed46144f78de1f53b9e773d46b9ce22e7887b7d3adcc791e797248e30ca9b950399f9dfb9a5c6bad17882f74e4c4ab21cc52dd6b1e4e8a81edc96fe06710e17fcaad305d94bb384a8c92858da56539745c23e29b33e0bad34599df32bacf36aa29c7b0446e1b669358c5da0c065c0313bd67dcbfe6a68f5aae445b168f95436874e18be427a78dce3e42f463045fd00197bdbd686adc41802fc558a1de5e195542deb4096374c6fa91ab7c51b798a863fd17f0ada698de32cf5d544d90c09baf32"
                ),
                out_ciphertext=bytes.fromhex(
                    "1b301923172c05ed37d0ce897cd69922ac249175c1e5e0e718ba94390a7fbe9d74dc128f391595899a3553339b9fe083b7e298091fb0c6d8a813b748f92ecd4d0767efb694d6a230181801226d7351b2"
                ),
                alpha=ORCHARD_ALPHA,
                signing_path=ORCHARD_SIGNING_PATH,
                spend_value=200000,
                value=100000,
                recipient=PCZT_ORCHARD_INTERNAL_RECIPIENT,
                rcv=bytes(32),
            ),
        ],
        flags=3,
        value_balance=20000,
        anchor=bytes.fromhex("c5e1408579e67cf16b5d19479408fa035a7db4fe3060123d139eba8523bc9633"),
    )
    PCZT_GLOBAL = PcztGlobal()

    client = ZcashCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=TRANSPARENT_OUTPUTS,
            orchard_bundle=ORCHARD_BUNDLE,
        ):
            pass

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def _mixed_real_and_dummy_orchard_bundle() -> PcztOrchardBundle:
    """Orchard bundle with a real spend at index 0 and the dummy padding change
    spend (spend_value == 0) at index 1.

    Shared by the signing test and the test asserting the device refuses to sign
    a dummy index, so both drive the exact same actions and ordering.
    """
    RECIPIENT_ORCHARD_ACTION = {
        "cv_net": "2bbcd0793d399b207b228ca760f2b51ac8d6866e2649b3c3ff1e67b454c5a6bf",
        "nullifier": "a554dda140773e5cdf5234e36227ab659452e8102d4de726c8a72fa182d94203",
        "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
        "spend_rho": "0700000000000000000000000000000000000000000000000000000000000000",
        "spend_rseed": "1b00000000000000000000000000000000000000000000000000000000000000",
        "cmx": "4b335e40a9dc718f353cb4d0e6614c59dd00fda6a37e704c08b2b8f3da1d9b1e",
        "ephemeral_key": "3f2ebdad40909b5114a62ae394fa47b03521a8e335ca83c0d8ab25b36593fd24",
        "enc_ciphertext": "061a91562732f49247090c3b9b62b76ac5c0e032362822f23416efc60c105aef10b0a7da0f85bbac92e4d3e3fcf5e366034081d9bec64d07dce0fef608c4f573ae37bf3fe54809903b0b93e27be25ef0853860f9711cad533b47d7cb4bf07677df752316252004a9a43880f45eb0dd99e1b16cfaf39ed94d7559a7057df6d12341c3e9450f9687b0bdec3c6a5028dc730b025b25e5481964d788cb827bf7b989835b56e41f448e42b3c55eb7a422cfdc49e32c97145f1820bf830571f349a807abac8c91f60ae21b676573d66a56ca2fe53fa7aebdb4f0076d618442c1bff1db245fc7597af34f081db5539036b73b7ab02435d1278efd359fccdd1f52151d3cc5f477f07120685cc3bf5efd23e99f31842b3234168c6b37d912f35cb0b847a1f5947212a4e2a5596f8b41a0d6442c5d3eb2ee679acc9e0b4507a806397f1efb5422d77459ea2509af8b360f1a973e1df62b4d849fd6ab3f90547f9a3c3cc0805609fd0cb6a560bd39a77c57e9796833ecf4d77b45f8450f7fe516ca82004b6601200ce39460b688002df97d50660b5e5026a784e2fa071ea81570ba5020f1d0f473fb269b806fdaeabad975345f20d9299fc2c005986037164b858a8deeff07932df5ef5a3a23676227b631161edfcfd0d2bd29aaddefb6ff2950e9ca7b7d23208dc80d25d2869ea80a149f8fae83d7cd03374ea71acaa0fddaca47dab649d81a99c32e67774c27723983886a67528a22d1a1d339dfbd6e81c11e83c9a17fee47439124fcfe5353aff39c2de30a1681ae3d2636c8c049ceab035cf9dbd396aa580dce3c",  # noqa: E501
        "out_ciphertext": "d6a12d5f0f1702bc0e6978fdf44779c741dea7c2b8cdf9bda2cf8780e440c838adc5f97076237d279044d859aa2efe4f0ea97a236ed869a351da9947a7717c00b3cb4d967086b9a05b5318b22b731ea8",  # noqa: E501
        "rcv": "4300000000000000000000000000000000000000000000000000000000000000",
        "rseed": "2f00000000000000000000000000000000000000000000000000000000000000",
        "spend_value": 200000,
        "value": 180000,
        "recipient": "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
    }
    CHANGE_ORCHARD_ACTION = {
        "cv_net": "af7b9a0ad90cecf9dbcf08d1057da0bf8451a189cc8dfa758e1543cffb5edb97",
        "nullifier": "57aad2670e2e4df67ca855c53973db38e7942efa8e906ee961adb71955aa8423",
        "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
        "spend_rho": "0800000000000000000000000000000000000000000000000000000000000000",
        "spend_rseed": "1c00000000000000000000000000000000000000000000000000000000000000",
        "cmx": "4d5af089ac858234d3472b545efe5796a609792d06bf18dbb8b3841ac0e9e031",
        "ephemeral_key": "92f7498c759a77b4065f9389d345c755ba241e68f0d8bf6d78f443257167d79f",
        "enc_ciphertext": "183f95348800b0c01daaa128c74ed5a4904024192330114b7b59460db6e332321425e9875e96bf7c1ba1bcb751ab6d8b494bd4b4e2587e177c9b083bf3a015a5879b69eaf2380c26d60501ff825be33eebc8ff3a86dfb04dd6fd1e814ea5e486148518ed256ea064267fbf9bc41ec6f8bf6da17b2bd9a81b42cb92dc398a5876333e64826b62a61dba4a5d9e740cdb6f0f1ac7e5f3bd8bff60c30088334491263b61f88b5e102eeb2d539ca32e45ce8600bcaf37368a2696528ee5e5cc52f8cf52df2c7e98f682ce6a4036527adce9f167df7f90200f3cdc9b451bdb4e36c3a46c2a2c42a0f0036161040267ef5dd267721db87f5b910dccf72afc67e059450db2b3df4789348ca72ddc5c310c4504c3779c5cca6a4ff94a73da8ee09dc06adc1856654b4be95e0adcf4510a0506b8b604bbd7fc340206728018f602060be3966cc0c91f601680b6e9e0f1132188cc217fef595b57c761b9292546d1dfe7148c42e4b8140cb364c23d1f0af6f794daf89c07927ea2d3be5f31ecf3f7d4dd973db806e3c0ef7cfb461848ba8562283c18c572f5e12d20ad8fff16cd0b58530501154a79458a28d2666707938915c95d854a3de8aee39a34d35c65a4e903b6135107726842ff150afa92243751606ec24fc0df246979f93c612a1f694b52863bb652226ceb520984aabda5c9fc60969589d9c894f3deceb448d04f3e61386430275eb4a64cacdf40704ccde93ae6573c1cd02b0bcfa689cf5de779cd2cf47ec13bb2e19c0d736fc0d0b7523b46487a1457e23dc1b473f1846475dc9544a81429c9caa51f3d",  # noqa: E501
        "out_ciphertext": "9f38b7e5c9bee88aa9be8bb44a386bd90fb6f915820f4a6469e120f2764774a3936e69063b514e83e587b9bd7b049d94d002c21dca9e8fa33b75aae1d584e8f4b77a0389e104596e2002aac2571fe384",  # noqa: E501
        "rcv": "4400000000000000000000000000000000000000000000000000000000000000",
        "rseed": "3000000000000000000000000000000000000000000000000000000000000000",
        "spend_value": 0,
        "value": 10000,
        "recipient": "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a",
    }
    return PcztOrchardBundle(
        actions=[
            _strict_orchard_action(RECIPIENT_ORCHARD_ACTION),
            _strict_orchard_action(CHANGE_ORCHARD_ACTION),
        ],
        flags=3,
        value_balance=10000,
        anchor=bytes.fromhex("c5e1408579e67cf16b5d19479408fa035a7db4fe3060123d139eba8523bc9633"),
    )


# Both tests below review the same bundle, so they share its review snapshots.
_ORCHARD_TO_ORCHARD_SNAPSHOTS = "test_sign_tx_v5_orchard_to_orchard_with_change"


def test_pczt_sign_tx_v5_orchard_to_orchard_with_change(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    TRANSPARENT_OUTPUTS = []
    ORCHARD_BUNDLE = _mixed_real_and_dummy_orchard_bundle()
    PCZT_GLOBAL = PcztGlobal()
    # Action 0 is a real spend (spend_value != 0), signed by the device.
    # Action 1 is the dummy change spend (spend_value == 0), signed host-side;
    # the device produces no spend-auth signature for it.
    EXPECTED_AUTH_SIG = [
        bytes.fromhex("8e02f26bee1e1a0635692338689b25753059fcc73ba63f8742cd6fcb6a2f972966b8f0f4243826a4a5d413e64d8fdabde9e242c2ac0e4f4bd7ef35b297d6d138"),
    ]

    _assert_pczt_orchard_sign_digest(
        backend,
        scenario_navigator,
        _ORCHARD_TO_ORCHARD_SNAPSHOTS,
        PCZT_GLOBAL,
        EXPECTED_AUTH_SIG,
        TRANSPARENT_OUTPUTS,
        ORCHARD_BUNDLE,
    )


def test_pczt_sign_tx_v5_orchard_dummy_spend_signature_is_refused(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """The device must refuse to produce a spend-auth signature for a dummy
    padding spend.

    Dummy actions are parsed without the rk and nullifier checks — those derive
    from the host's throwaway key and cannot pass — and the PCZT IoFinalizer
    already self-signs them. A device signature would therefore authorize an
    action whose spend side was never verified, and would push the device
    signature count past the finalizer's unsigned-action count. The host is
    expected to skip dummy indices; this asserts the device does not depend on
    it and rejects the request instead of hanging or signing.
    """
    ORCHARD_BUNDLE = _mixed_real_and_dummy_orchard_bundle()
    PCZT_GLOBAL = PcztGlobal()
    DUMMY_ACTION_INDEX = 1
    assert ORCHARD_BUNDLE.actions[DUMMY_ACTION_INDEX].spend_value == 0

    client = ZcashCommandSender(backend)
    with client.send_pczt(
        pczt_global=PCZT_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[],
        orchard_bundle=ORCHARD_BUNDLE,
    ):
        _review_approve(scenario_navigator, _ORCHARD_TO_ORCHARD_SNAPSHOTS)

    # Requested before the real spend at index 0, so the signing session is still
    # open: the rejection comes from the dummy check, not from a finished session.
    with pytest.raises(ExceptionRAPDU) as e:
        client.pczt_sign_orchard(action_index=DUMMY_ACTION_INDEX)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_sign_tx_v5_orchard_divergent_signing_path_rejected(
    backend,
):
    """All Orchard actions of a PCZT belong to one account, so the device derives
    the spending key once (from the first action's path) and reuses it.

    An action declaring a different path must be rejected rather than served the
    cached key: otherwise the device would derive the FVK from one path while
    deriving the network from another, and sign with a key the declared path does
    not produce.
    """
    ORCHARD_BUNDLE = _mixed_real_and_dummy_orchard_bundle()
    # Same coin type (so this is not caught by the coin-type check), different
    # account index.
    ORCHARD_BUNDLE.actions[1].signing_path = "m/32'/133'/1'"
    PCZT_GLOBAL = PcztGlobal()

    client = ZcashCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            orchard_bundle=ORCHARD_BUNDLE,
        ):
            pytest.fail("Device accepted Orchard actions with divergent signing paths")

    assert e.value.status == Errors.SW_BAD_STATE
