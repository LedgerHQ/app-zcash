# pylint: disable=C0301

import pytest
from application_client.pczt import (
    PcztGlobal,
    PcztIronwoodAction,
    PcztIronwoodBundle,
    PcztOrchardAction,
    PcztOrchardBundle,
)
from application_client.zcash_command_sender import (
    Errors,
    ZcashCommandSender,
)
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

# NU6.3 (Ironwood) network identifiers
_V6_TX_VERSION = 6
_V6_VERSION_GROUP_ID = 0xD884B698
_NU6_3_BRANCH_ID = 0x37A5165B  # BranchId::Nu6_3

PCZT_V6_GLOBAL = PcztGlobal(
    tx_version=_V6_TX_VERSION,
    version_group_id=_V6_VERSION_GROUP_ID,
    consensus_branch_id=_NU6_3_BRANCH_ID,
)

# Ironwood uses the same RedPallas key derivation as Orchard; these constants are shared.
_SIGNING_PATH = "m/32'/133'/0'"
_ALPHA = (1).to_bytes(32, byteorder="little")
# rk = SpendAuthKey(m/32'/133'/0') * alpha (alpha=1, Speculos deterministic seed)
_RK_ALPHA_1 = bytes.fromhex("e95982b73ab0c2137ec354cce448a75ef39ec0cbdf6907be6df3495297834f89")
_INTERNAL_RECIPIENT = bytes.fromhex(
    "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a"
)
_SPEND_RECIPIENT = bytes.fromhex(
    "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02"
)

# Precomputed action fields that pass all device validation checks.
# cv_net = Commitment(rcv, value=0); nullifier = NullifierDerive(key, spend_rho);
# cmx = NoteCommitment(recipient, value=0, rseed) — verified against device derivation.
_CV_NET = bytes.fromhex("00b3324110776396d31646041679fd6530d57c353c6be0a93a0cd55b30aa6d8b")
_NULLIFIER = bytes.fromhex("08f337fd695cb5ca2ad7ced8ec14afed06d2f8a0e5e3d8b58dffbc69e4f81b2f")
_CMX = bytes.fromhex("825f806345d7c2ae67fe186120cc5b8a370c2cedb55ccf76527e9efa43c94d30")
_RCV = bytes.fromhex("4200000000000000000000000000000000000000000000000000000000000000")
_RSEED = bytes.fromhex("2e00000000000000000000000000000000000000000000000000000000000000")
_SPEND_RHO = bytes.fromhex("0600000000000000000000000000000000000000000000000000000000000000")
_SPEND_RSEED = bytes.fromhex("1a00000000000000000000000000000000000000000000000000000000000000")

# In V6 neither the Orchard nor the Ironwood anchor enters the sighash.
_ORCHARD_ANCHOR_A = bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109")


def _valid_ironwood_action() -> PcztIronwoodAction:
    return PcztIronwoodAction(
        cv_net=_CV_NET,
        nullifier=_NULLIFIER,
        spend_recipient=_SPEND_RECIPIENT,
        spend_rho=_SPEND_RHO,
        spend_rseed=_SPEND_RSEED,
        rk=_RK_ALPHA_1,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=_CMX,
        ephemeral_key=bytes(32),
        enc_ciphertext=bytes(580),
        out_ciphertext=bytes(80),
        rcv=_RCV,
        rseed=_RSEED,
        spend_value=300000,
        value=0,
        recipient=_INTERNAL_RECIPIENT,
    )


def _valid_ironwood_bundle(anchor: bytes = bytes(32)) -> PcztIronwoodBundle:
    return PcztIronwoodBundle(
        actions=[_valid_ironwood_action()],
        flags=3,
        value_balance=300000,
        anchor=anchor,
    )


def _valid_orchard_action() -> PcztOrchardAction:
    return PcztOrchardAction(
        cv_net=_CV_NET,
        nullifier=_NULLIFIER,
        spend_recipient=_SPEND_RECIPIENT,
        spend_rho=_SPEND_RHO,
        spend_rseed=_SPEND_RSEED,
        rk=_RK_ALPHA_1,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=_CMX,
        ephemeral_key=bytes(32),
        enc_ciphertext=bytes(580),
        out_ciphertext=bytes(80),
        rcv=_RCV,
        rseed=_RSEED,
        spend_value=300000,
        value=0,
        recipient=_INTERNAL_RECIPIENT,
    )


def _valid_orchard_bundle(anchor: bytes = _ORCHARD_ANCHOR_A) -> PcztOrchardBundle:
    return PcztOrchardBundle(
        actions=[_valid_orchard_action()],
        flags=3,
        value_balance=300000,
        anchor=anchor,
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


def test_pczt_ironwood_bundle_signing(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """Ironwood-only V6 transaction: device accepts the bundle and returns a 64-byte spendAuthSig."""
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[],
        ironwood_bundle=_valid_ironwood_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_ironwood_bundle_signing")

    auth_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(auth_sig) == 64


def test_pczt_migration_orchard_to_ironwood(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """V6 migration tx with both Orchard and Ironwood bundles: both pools sign independently."""
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[],
        orchard_bundle=_valid_orchard_bundle(),
        ironwood_bundle=_valid_ironwood_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_migration_orchard_to_ironwood")

    orchard_sig = client.pczt_sign_orchard(action_index=0).data
    assert len(orchard_sig) == 64

    ironwood_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(ironwood_sig) == 64


def test_pczt_ironwood_unknown_branch_id_rejected(
    backend,
):
    """Unknown consensus_branch_id is rejected at PCZT header parsing."""
    client = ZcashCommandSender(backend)

    bad_global = PcztGlobal(
        tx_version=_V6_TX_VERSION,
        version_group_id=_V6_VERSION_GROUP_ID,
        consensus_branch_id=0xDEADBEEF,
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=bad_global,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=_valid_ironwood_bundle(),
        ):
            pytest.fail("Device accepted a PCZT with unknown branch ID")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_orchard_path_unaffected(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """Regression: V5 Orchard-only PCZT still signs correctly after Ironwood code was added."""
    v5_global = PcztGlobal()  # tx_version=5, consensus_branch_id=0xC2D6D0B4 (Nu5)

    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=v5_global,
        transparent_inputs=[],
        transparent_outputs=[],
        orchard_bundle=_valid_orchard_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_orchard_path_unaffected")

    auth_sig = client.pczt_sign_orchard(action_index=0).data
    assert len(auth_sig) == 64


def test_pczt_ironwood_user_rejection(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """User rejects the V6 Ironwood signing review; device returns Deny, no sig emitted."""
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=_valid_ironwood_bundle(),
        ):
            scenario_navigator.review_reject(test_name="test_pczt_ironwood_user_rejection")

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_pczt_ironwood_zero_actions_rejected(
    backend,
):
    """An Ironwood bundle with zero actions is rejected before the state machine advances."""
    client = ZcashCommandSender(backend)

    empty_ironwood = PcztIronwoodBundle(
        actions=[],
        flags=0,
        value_balance=0,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=empty_ironwood,
        ):
            pytest.fail("Device accepted a zero-action Ironwood bundle")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_v5_finished_marker_regression(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """V5 Orchard PCZT with the FINISHED flag set on the last action chunk still produces a valid signature."""
    v5_global = PcztGlobal()

    client = ZcashCommandSender(backend)

    # send_pczt without ironwood_bundle uses P2_PCZT_FINISHED on the last Orchard packet.
    with client.send_pczt(
        pczt_global=v5_global,
        transparent_inputs=[],
        transparent_outputs=[],
        orchard_bundle=_valid_orchard_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_v5_finished_marker_regression")

    auth_sig = client.pczt_sign_orchard(action_index=0).data
    assert len(auth_sig) == 64


def test_pczt_v6_orchard_anchor_exclusion_regression(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """V6: the Orchard anchor is excluded from the sighash — changing its value must not alter the signature.

    Two V6 migration PCZTs with identical fields but different Orchard anchors must produce
    the same Orchard spendAuthSig. If the anchor were included in the Orchard digest the
    signatures would differ.
    """
    anchor_a = _ORCHARD_ANCHOR_A
    anchor_b = bytes([anchor_a[0] ^ 0xFF]) + anchor_a[1:]

    def _sign_orchard_then_finish(anchor: bytes, test_name: str) -> bytes:
        client = ZcashCommandSender(backend)
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            orchard_bundle=_valid_orchard_bundle(anchor=anchor),
            ironwood_bundle=_valid_ironwood_bundle(),
        ):
            _review_approve(scenario_navigator, test_name)
        orchard_sig = client.pczt_sign_orchard(action_index=0).data
        # Complete the PCZT so the device resets before the next invocation.
        client.pczt_sign_ironwood(action_index=0)
        return orchard_sig

    sig_a = _sign_orchard_then_finish(anchor_a, "test_pczt_v6_orchard_anchor_exclusion_a")
    sig_b = _sign_orchard_then_finish(anchor_b, "test_pczt_v6_orchard_anchor_exclusion_b")

    assert sig_a == sig_b, (
        "Orchard spendAuthSig changed when Orchard anchor changed — "
        f"Orchard anchor incorrectly included in V6 sighash: {sig_a.hex()} != {sig_b.hex()}"
    )
