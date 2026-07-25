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
    P1,
    P2,
    Errors,
    InsType,
    ZcashCommandSender,
)
from application_client.zcash_transaction import split_tx_v5_for_hash_input
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

# Same, for a dummy padding spend (spend_value = 0) whose output is the change note:
# cv_net = Commitment(_DUMMY_RCV, -_DUMMY_CHANGE_VALUE), and the ciphertexts decrypt
# to that note under the device keys. The action encoding, value commitment and note
# decryption are identical in both pools, so these are the Orchard padding vectors.
_DUMMY_CHANGE_VALUE = 10000
_DUMMY_CV_NET = bytes.fromhex("af7b9a0ad90cecf9dbcf08d1057da0bf8451a189cc8dfa758e1543cffb5edb97")
_DUMMY_NULLIFIER = bytes.fromhex("57aad2670e2e4df67ca855c53973db38e7942efa8e906ee961adb71955aa8423")
_DUMMY_CMX = bytes.fromhex("4d5af089ac858234d3472b545efe5796a609792d06bf18dbb8b3841ac0e9e031")
_DUMMY_RCV = bytes.fromhex("4400000000000000000000000000000000000000000000000000000000000000")
_DUMMY_RSEED = bytes.fromhex("3000000000000000000000000000000000000000000000000000000000000000")
_DUMMY_SPEND_RHO = bytes.fromhex("0800000000000000000000000000000000000000000000000000000000000000")
_DUMMY_SPEND_RSEED = bytes.fromhex("1c00000000000000000000000000000000000000000000000000000000000000")
_DUMMY_EPHEMERAL_KEY = bytes.fromhex("92f7498c759a77b4065f9389d345c755ba241e68f0d8bf6d78f443257167d79f")
_DUMMY_ENC_CIPHERTEXT = bytes.fromhex(
    "183f95348800b0c01daaa128c74ed5a4904024192330114b7b59460db6e332321425e9875e96bf7c1ba1bcb751ab6d8b494bd4b4e2587e177c9b083bf3a015a5879b69eaf2380c26d60501ff825be33eebc8ff3a86dfb04dd6fd1e814ea5e486148518ed256ea064267fbf9bc41ec6f8bf6da17b2bd9a81b42cb92dc398a5876333e64826b62a61dba4a5d9e740cdb6f0f1ac7e5f3bd8bff60c30088334491263b61f88b5e102eeb2d539ca32e45ce8600bcaf37368a2696528ee5e5cc52f8cf52df2c7e98f682ce6a4036527adce9f167df7f90200f3cdc9b451bdb4e36c3a46c2a2c42a0f0036161040267ef5dd267721db87f5b910dccf72afc67e059450db2b3df4789348ca72ddc5c310c4504c3779c5cca6a4ff94a73da8ee09dc06adc1856654b4be95e0adcf4510a0506b8b604bbd7fc340206728018f602060be3966cc0c91f601680b6e9e0f1132188cc217fef595b57c761b9292546d1dfe7148c42e4b8140cb364c23d1f0af6f794daf89c07927ea2d3be5f31ecf3f7d4dd973db806e3c0ef7cfb461848ba8562283c18c572f5e12d20ad8fff16cd0b58530501154a79458a28d2666707938915c95d854a3de8aee39a34d35c65a4e903b6135107726842ff150afa92243751606ec24fc0df246979f93c612a1f694b52863bb652226ceb520984aabda5c9fc60969589d9c894f3deceb448d04f3e61386430275eb4a64cacdf40704ccde93ae6573c1cd02b0bcfa689cf5de779cd2cf47ec13bb2e19c0d736fc0d0b7523b46487a1457e23dc1b473f1846475dc9544a81429c9caa51f3d"
)  # noqa: E501
_DUMMY_OUT_CIPHERTEXT = bytes.fromhex(
    "9f38b7e5c9bee88aa9be8bb44a386bd90fb6f915820f4a6469e120f2764774a3936e69063b514e83e587b9bd7b049d94d002c21dca9e8fa33b75aae1d584e8f4b77a0389e104596e2002aac2571fe384"
)  # noqa: E501

# Legacy V5 transaction and its prevout, used to drive the legacy signing path
# against leftover V6 state.
_LEGACY_V5_PREVOUT_TX = bytes.fromhex(
    "050000800a27a726b4d0d6c200000000f9081a000198cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b48304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b469c616e758230a5ffffffff021595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88aca245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac000000"
)  # noqa: E501
_LEGACY_V5_TX = bytes.fromhex(
    "050000800a27a726b4d0d6c2"  # version, version group id, consensus branch id
    + (0).to_bytes(4, byteorder="big").hex()  # locktime
    + (0).to_bytes(4, byteorder="big").hex()  # expiry
    + "01"  # one input
    + "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a"
    + "00000000"  # prevout hash and index
    + "19"
    + "76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000"  # scriptPubKey, sequence
    + "01"  # one output
    + "958ddd0400000000"  # amount
    + "19"
    + "76a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"  # scriptPubKey
    + "000000"  # empty sapling and orchard bundles
)

# In V6 neither the Orchard nor the Ironwood anchor enters the sighash.
_ORCHARD_ANCHOR_A = bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109")

# Transparent output used by tests that need a displayable output.
# Ironwood-only (one pool): orchard_vb=0 + ironwood_vb=300000 - 299000 = 1000 fee.
_TRANSPARENT_OUTPUT_299K = PcztTransparentOutput(
    value=299000,
    script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
)
# Ironwood bundle carrying a dummy padding spend: ironwood_vb=290000 - 289000 = 1000 fee.
_TRANSPARENT_OUTPUT_289K = PcztTransparentOutput(
    value=289000,
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


def _valid_ironwood_bundle_2_actions() -> PcztIronwoodBundle:
    """Two-action Ironwood bundle for replay-guard tests that must not reset on first sign."""
    return PcztIronwoodBundle(
        actions=[_valid_ironwood_action(), _valid_ironwood_action()],
        flags=3,
        value_balance=600000,
        anchor=bytes(32),
    )


def _dummy_ironwood_action() -> PcztIronwoodAction:
    """Dummy padding spend (spend_value == 0) whose output is the change note."""
    return PcztIronwoodAction(
        cv_net=_DUMMY_CV_NET,
        nullifier=_DUMMY_NULLIFIER,
        spend_recipient=_SPEND_RECIPIENT,
        spend_rho=_DUMMY_SPEND_RHO,
        spend_rseed=_DUMMY_SPEND_RSEED,
        rk=_RK_ALPHA_1,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=_DUMMY_CMX,
        ephemeral_key=_DUMMY_EPHEMERAL_KEY,
        enc_ciphertext=_DUMMY_ENC_CIPHERTEXT,
        out_ciphertext=_DUMMY_OUT_CIPHERTEXT,
        rcv=_DUMMY_RCV,
        rseed=_DUMMY_RSEED,
        spend_value=0,
        value=_DUMMY_CHANGE_VALUE,
        recipient=_INTERNAL_RECIPIENT,
    )


def _mixed_real_and_dummy_ironwood_bundle() -> PcztIronwoodBundle:
    """Real spend at index 0, dummy padding spend at index 1."""
    actions = [_valid_ironwood_action(), _dummy_ironwood_action()]
    return PcztIronwoodBundle(
        actions=actions,
        value_balance=sum(action.spend_value - action.value for action in actions),
        flags=3,
        anchor=bytes(32),
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


def test_pczt_ironwood_dummy_spend_signature_is_refused(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """The device must refuse to produce a spend-auth signature for an Ironwood
    dummy padding spend, as it already does for Orchard.

    Dummy actions are parsed without the rk and nullifier checks — those derive
    from the host's throwaway key and cannot pass — and the PCZT IoFinalizer
    already self-signs them. Signing one would authorize an action whose spend
    side was never verified.

    The refusal aborts the signing session (the review approval is dropped), so a
    host must skip dummy indices rather than probe them.
    """
    client = ZcashCommandSender(backend)
    IRONWOOD_BUNDLE = _mixed_real_and_dummy_ironwood_bundle()
    DUMMY_ACTION_INDEX = 1
    assert IRONWOOD_BUNDLE.actions[DUMMY_ACTION_INDEX].spend_value == 0

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_289K],
        ironwood_bundle=IRONWOOD_BUNDLE,
    ):
        _review_approve(scenario_navigator, "test_pczt_ironwood_dummy_spend_signature_is_refused")

    # Requested before the real spend at index 0, so the signature quota is not
    # exhausted: the rejection comes from the dummy check, not from a done session.
    with pytest.raises(ExceptionRAPDU) as e:
        client.pczt_sign_ironwood(action_index=DUMMY_ACTION_INDEX)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_v6_header_then_legacy_continuation_rejected(backend):
    """A legacy continuation must not inherit the V6 state of an abandoned PCZT flow.

    A continuation deliberately keeps the previous round's transaction state, so a
    host can chain a V6 PCZT header into it and drive the legacy parser with a V6
    transaction version — a state the legacy path cannot represent.
    """
    client = ZcashCommandSender(backend)

    trusted_input = client.get_trusted_input(_LEGACY_V5_PREVOUT_TX, 0).data

    client._send_pczt_header(PCZT_V6_GLOBAL)

    client.tx_chunks = split_tx_v5_for_hash_input(_LEGACY_V5_TX)
    client.trusted_inputs = [trusted_input]

    with pytest.raises(ExceptionRAPDU) as e:
        client._send_trusted_inputs_and_header(continue_hashing=True)

    assert e.value.status == Errors.SW_BAD_STATE


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


def test_pczt_ironwood_sign_replay_in_session_rejected(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """In-session SIGN_IRONWOOD replay (before all actions are signed) is rejected by the guard.

    Uses a 2-action bundle so the parser is not reset after the first sign.  The second
    call for action 0 must be caught by the action.signed guard inside
    ensure_signature_digest_for_ironwood, not by a parser-reset check.
    """
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_599K],
        ironwood_bundle=_valid_ironwood_bundle_2_actions(),
    ):
        _review_approve(
            scenario_navigator, "test_pczt_ironwood_sign_replay_in_session_rejected"
        )

    # First sign of action 0 succeeds; parser is NOT reset (action 1 still pending).
    auth_sig = client.pczt_sign_ironwood(action_index=0).data
    assert len(auth_sig) == 64

    # Replay of action 0 must be caught by the action.signed guard inside
    # ensure_signature_digest_for_ironwood, which maps to SW_INVALID_TRANSACTION (0x6A80).
    # (SW_DENY / 0x6985 applies only to the post-reset path where is_finished() == false.)
    with pytest.raises(ExceptionRAPDU) as e:
        client.pczt_sign_ironwood(action_index=0)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


# Expected Ironwood spendAuthSig for a V6 Ironwood-only PCZT on a freshly started Speculos
# session (deterministic RNG starting point, Speculos default seed).  Constant regardless of
# the Ironwood anchor because NU6.3 excludes the anchor from the sighash — only the
# authorising-data digest includes it, not the sighash.
_EXPECTED_V6_IRONWOOD_SIG = bytes.fromhex(
    "390f0a730f1fb07b224c8432cc03ecbb3d9226d44a9c495cd9ec78c51202f01"
    "1af897ec56a71924698d02be022a6f34d84dbd24ed372a454615d9788c7d5b40a"
)


@pytest.mark.parametrize(
    "anchor,test_name",
    [
        (bytes(32), "test_pczt_v6_ironwood_anchor_exclusion_a"),
        (bytes([0xFF]) + bytes(31), "test_pczt_v6_ironwood_anchor_exclusion_b"),
    ],
    ids=["anchor_a", "anchor_b"],
)
def test_pczt_v6_ironwood_anchor_exclusion_regression(
    backend,
    scenario_navigator: NavigateWithScenario,
    anchor: bytes,
    test_name: str,
):
    """V6: Ironwood anchor excluded from sighash — changing it must not alter the signature.

    Each parametrised invocation runs in its own Speculos session (fresh deterministic RNG).
    If the Ironwood anchor were included in the V6 sighash the signature would differ from
    _EXPECTED_V6_IRONWOOD_SIG; if correctly excluded both anchors produce the same signature.
    """
    client = ZcashCommandSender(backend)
    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
        ironwood_bundle=_valid_ironwood_bundle(anchor=anchor),
    ):
        _review_approve(scenario_navigator, test_name)
    ironwood_sig = client.pczt_sign_ironwood(action_index=0).data
    assert ironwood_sig == _EXPECTED_V6_IRONWOOD_SIG, (
        "Ironwood spendAuthSig changed when Ironwood anchor changed — "
        f"Ironwood anchor incorrectly included in V6 sighash.\n"
        f"anchor={anchor.hex()}\n"
        f"got:  {ironwood_sig.hex()}\n"
        f"want: {_EXPECTED_V6_IRONWOOD_SIG.hex()}"
    )


# ---------------------------------------------------------------------------
# Negative / malicious-input tests for the Ironwood validation paths (F3+F4)
# ---------------------------------------------------------------------------


def test_pczt_ironwood_cv_net_mismatch_rejected(backend):
    """Ironwood action with a cv_net that does not match Commitment(rcv, spend_value-output_value) is rejected.

    The device recomputes cv_net from the provided rcv and value fields; if it differs from the
    transmitted cv_net the transaction is rejected with SW_INVALID_TRANSACTION.
    """
    client = ZcashCommandSender(backend)
    bad_bundle = PcztIronwoodBundle(
        actions=[
            PcztIronwoodAction(
                cv_net=bytes(32),  # wrong: all-zero, doesn't match Commitment(_RCV, 300000)
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
        ],
        flags=3,
        value_balance=300000,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=bad_bundle,
        ):
            pass  # device rejects synchronously during action parsing, before review
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_nullifier_mismatch_rejected(backend):
    """Ironwood action with a nullifier that doesn't match NullifierDerive(fvk, spend_note) is rejected.

    The device derives the expected nullifier from the spend note fields and the signing key's FVK.
    """
    client = ZcashCommandSender(backend)
    bad_bundle = PcztIronwoodBundle(
        actions=[
            PcztIronwoodAction(
                cv_net=_CV_NET,
                nullifier=bytes(32),  # wrong: all-zero, doesn't match the derived nullifier
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
        ],
        flags=3,
        value_balance=300000,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=bad_bundle,
        ):
            pass
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_wrong_enc_ciphertext_length_rejected(backend):
    """Ironwood action with enc_ciphertext length != 580 is rejected before action parsing completes.

    The device enforces ORCHARD_ENC_CIPHERTEXT_SIZE = 580; any other length returns SW_INVALID_TRANSACTION.
    """
    client = ZcashCommandSender(backend)
    bad_bundle = PcztIronwoodBundle(
        actions=[
            PcztIronwoodAction(
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
                enc_ciphertext=bytes(500),  # wrong: 500 != 580
                out_ciphertext=bytes(80),
                rcv=_RCV,
                rseed=_RSEED,
                spend_value=300000,
                value=0,
                recipient=_INTERNAL_RECIPIENT,
            )
        ],
        flags=3,
        value_balance=300000,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=bad_bundle,
        ):
            pass
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_wrong_out_ciphertext_length_rejected(backend):
    """Ironwood action with out_ciphertext length != 80 is rejected before action parsing completes.

    The device enforces ORCHARD_OUT_CIPHERTEXT_SIZE = 80; any other length returns SW_INVALID_TRANSACTION.
    """
    client = ZcashCommandSender(backend)
    bad_bundle = PcztIronwoodBundle(
        actions=[
            PcztIronwoodAction(
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
                out_ciphertext=bytes(50),  # wrong: 50 != 80
                rcv=_RCV,
                rseed=_RSEED,
                spend_value=300000,
                value=0,
                recipient=_INTERNAL_RECIPIENT,
            )
        ],
        flags=3,
        value_balance=300000,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=bad_bundle,
        ):
            pass
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_ironwood_max_actions_exceeded_rejected(backend):
    """An Ironwood bundle with 11 actions (> MAX_PCZT_IRONWOOD_ACTIONS_NUMBER = 10) is rejected.

    The device checks the action count immediately on the header packet; 11 actions returns
    SW_INVALID_TRANSACTION before any action field is parsed.
    """
    client = ZcashCommandSender(backend)
    oversize_bundle = PcztIronwoodBundle(
        actions=[_valid_ironwood_action()] * 11,
        flags=3,
        value_balance=300000 * 11,
        anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[],
            ironwood_bundle=oversize_bundle,
        ):
            pass
    assert e.value.status == Errors.SW_INVALID_TRANSACTION


@pytest.mark.skip(
    reason="Requires a Pallas-valid (rk, alpha) pair where rk is deliberately wrong — "
           "needs Pallas group arithmetic unavailable in this test harness. "
           "Rejection verified by code inspection: ironwood.rs verify_current_ironwood_rk() "
           "recomputes rk = SpendAuthorizationKey(path).randomize(alpha) and returns an error "
           "on mismatch before any signature is produced."
)
def test_pczt_ironwood_rk_mismatch_rejected(backend):
    pass


@pytest.mark.skip(
    reason="Requires constructing a bundle whose per-action spend_value or output_value sum "
           "exceeds i64::MAX (9223372036854775807) with a matching cv_net — needs Pallas "
           "commitment arithmetic unavailable in this test harness. "
           "Rejection verified by code inspection: ironwood.rs finish_current_ironwood_action() "
           "uses checked_add on the running sums (spend/output), and the value balance magnitude "
           "is cast via i64::try_from() which errors on overflow."
)
def test_pczt_ironwood_value_sum_overflow_rejected(backend):
    pass
