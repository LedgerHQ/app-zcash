# pylint: disable=C0301

import pytest
from application_client.pczt import (
    PcztGlobal,
    PcztIronwoodAction,
    PcztIronwoodBundle,
    PcztOrchardAction,
    PcztOrchardBundle,
    PcztTransparentOutput,
)
from application_client.zcash_command_sender import (
    CLA,
    Errors,
    InsType,
    P1,
    P2,
    ZcashCommandSender,
)
from application_client.zcash_utils import write_varint
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

# Transparent output used by tests that need a displayable output.
# Ironwood-only (one pool): orchard_vb=0 + ironwood_vb=300000 - 299000 = 1000 fee.
_TRANSPARENT_OUTPUT_299K = PcztTransparentOutput(
    value=299000,
    script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
)
# V6 migration (two pools): orchard_vb=300000 + ironwood_vb=300000 - 599000 = 1000 fee.
_TRANSPARENT_OUTPUT_599K = PcztTransparentOutput(
    value=599000,
    script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
)


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
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
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
        transparent_outputs=[_TRANSPARENT_OUTPUT_599K],
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
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
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
            transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
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
            pass  # Rejection arrives in async response, checked on context-manager exit

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
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
        orchard_bundle=_valid_orchard_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_v5_finished_marker_regression")

    auth_sig = client.pczt_sign_orchard(action_index=0).data
    assert len(auth_sig) == 64


# Expected Orchard spendAuthSig for a V6 migration PCZT on a freshly started Speculos
# session (deterministic RNG starting point, Speculos default seed).  The value is
# constant regardless of the Orchard anchor because NU6.3 excludes the anchor from the
# sighash — only the authorising-data digest includes it, not the sighash.
_EXPECTED_V6_ORCHARD_SIG = bytes.fromhex(
    "43b8257c89b3214f1f6e2cae79e512985531e1958d0da6ab08ef10b962c2220"
    "30245bdb39e65246d3d8525a64931cda3b2b05a984009f7e864318d57a47f2c19"
)

# Second anchor: first byte flipped so the Orchard anchor bytes differ in every bit
# that the first byte carries, giving an easy regression signal.
_ORCHARD_ANCHOR_B = bytes([_ORCHARD_ANCHOR_A[0] ^ 0xFF]) + _ORCHARD_ANCHOR_A[1:]


@pytest.mark.parametrize(
    "anchor,test_name",
    [
        (_ORCHARD_ANCHOR_A, "test_pczt_v6_orchard_anchor_exclusion_a"),
        (_ORCHARD_ANCHOR_B, "test_pczt_v6_orchard_anchor_exclusion_b"),
    ],
    ids=["anchor_a", "anchor_b"],
)
def test_pczt_v6_orchard_anchor_exclusion_regression(
    backend,
    scenario_navigator: NavigateWithScenario,
    anchor: bytes,
    test_name: str,
):
    """V6: the Orchard anchor is excluded from the sighash — changing its value must not alter the signature.

    Each parametrised invocation runs in its own Speculos session (fresh deterministic RNG
    start state).  If the Orchard anchor were included in the V6 sighash the signature
    would differ from _EXPECTED_V6_ORCHARD_SIG; if it is correctly excluded both anchors
    produce the same signature.
    """
    client = ZcashCommandSender(backend)
    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_599K],
        orchard_bundle=_valid_orchard_bundle(anchor=anchor),
        ironwood_bundle=_valid_ironwood_bundle(),
    ):
        _review_approve(scenario_navigator, test_name)
    orchard_sig = client.pczt_sign_orchard(action_index=0).data
    assert orchard_sig == _EXPECTED_V6_ORCHARD_SIG, (
        "Orchard spendAuthSig changed when Orchard anchor changed — "
        f"Orchard anchor incorrectly excluded from V6 sighash.\n"
        f"anchor={anchor.hex()}\n"
        f"got:  {orchard_sig.hex()}\n"
        f"want: {_EXPECTED_V6_ORCHARD_SIG.hex()}"
    )


def test_pczt_ironwood_before_orchard_rejected(backend):
    """IRONWOOD_ACTION sent before Orchard completes is rejected with BadState.

    After PCZT_HEADER the parser is in WaitTransparentInput, not OrchardActionsDone.
    Sending PCZT_IRONWOOD_ACTION at that point must return SW_BAD_STATE, ensuring
    the host cannot skip the mandatory Orchard step in the V6 command sequence.
    """
    client = ZcashCommandSender(backend)
    client._send_pczt_header(PCZT_V6_GLOBAL)

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.PCZT_IRONWOOD_ACTION,
            p1=P1.P1_FIRST,
            p2=P2.P2_NONE,
            data=write_varint(1),
        )

    assert e.value.status == Errors.SW_BAD_STATE


def test_pczt_ironwood_sign_replay_rejected(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """A second SIGN_IRONWOOD for the same action after completion is rejected.

    After all Ironwood signatures are produced the parser is reset; a replay
    of SIGN_IRONWOOD must be rejected rather than producing a second signature.
    """
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
        ironwood_bundle=_valid_ironwood_bundle(),
    ):
        _review_approve(scenario_navigator, "test_pczt_ironwood_sign_replay_rejected")

    auth_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(auth_sig) == 64

    with pytest.raises(ExceptionRAPDU) as e:
        client.pczt_sign_ironwood(action_index=0)

    assert e.value.status == Errors.SW_DENY
