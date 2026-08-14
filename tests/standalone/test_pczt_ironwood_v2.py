# pylint: disable=C0301
"""
Self-contained Ragger/Speculos tests for the Ironwood PCZT signing flow.

Scenario: V6 transaction with 0 transparent inputs, 1 transparent output, an empty Orchard
bundle (needed to advance the state machine to OrchardActionsDone) and 2 Ironwood actions,
both real spends.

The APDU sequence, the INS codes and the version rules are specified in docs/PCZT_APDU.md.

One non-obvious framing detail: write_varint(580) is 3 bytes, so the first enc_ciphertext
packet carries 3 length bytes plus 252 data bytes; the firmware reads the CompactSize from
that first packet and accumulates the remainder across the following ones.
"""

import pytest
from application_client.pczt import (
    PcztGlobal,
    PcztIronwoodAction,
    PcztIronwoodBundle,
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
from application_client.zcash_utils import write_varint
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

# ---------------------------------------------------------------------------
# Network identifiers for NU6.3 (Ironwood) — V6 transaction
# ---------------------------------------------------------------------------
_V6_TX_VERSION: int = 6
_V6_VERSION_GROUP_ID: int = 0xD884B698
_NU6_3_BRANCH_ID: int = 0x37A5165B  # BranchId::Nu6_3 in zcash_protocol

PCZT_V6_GLOBAL = PcztGlobal(
    tx_version=_V6_TX_VERSION,
    version_group_id=_V6_VERSION_GROUP_ID,
    consensus_branch_id=_NU6_3_BRANCH_ID,
)

# ---------------------------------------------------------------------------
# Signing path and key material
# Ironwood uses the same ZIP-32 Orchard key derivation as the Orchard pool
# (m/32'/<coin_type>'/<account>'), with coin_type=133 for mainnet.
# ---------------------------------------------------------------------------
_SIGNING_PATH = "m/32'/133'/0'"
_ALPHA = (1).to_bytes(32, byteorder="little")
# rk = SpendAuthorizationKey(m/32'/133'/0').randomize(alpha=1)
# Verified against Speculos deterministic seed.
_RK_ALPHA_1 = bytes.fromhex("e95982b73ab0c2137ec354cce448a75ef39ec0cbdf6907be6df3495297834f89")

# ---------------------------------------------------------------------------
# Spend note vectors for a real spend (spend_value != 0).
# These are the vectors used throughout the Ironwood test suite.
# Verified: NullifierDerive(fvk_from_spend_key(m/32'/133'/0'), spend_note) ==
#           _NULLIFIER, and cv_net == Commitment(rcv=_RCV, value=300000-0).
# ---------------------------------------------------------------------------
_INTERNAL_RECIPIENT = bytes.fromhex(
    "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a"
)
_SPEND_RECIPIENT = bytes.fromhex(
    "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02"
)
_CV_NET = bytes.fromhex("00b3324110776396d31646041679fd6530d57c353c6be0a93a0cd55b30aa6d8b")
_NULLIFIER = bytes.fromhex("ed37cc733c228dc3dda2cf088ba646f9d204adc9d8d6f95ec36126eb742c3a10")
_CMX = bytes.fromhex("aa5a6343c80fff74db58be9d847515ab8456837633b6cdf52305544bc5107c31")
_RCV = bytes.fromhex("4200000000000000000000000000000000000000000000000000000000000000")
_RSEED = bytes.fromhex("2e00000000000000000000000000000000000000000000000000000000000000")
_SPEND_RHO = bytes.fromhex("0600000000000000000000000000000000000000000000000000000000000000")
_SPEND_RSEED = bytes.fromhex("1a00000000000000000000000000000000000000000000000000000000000000")

# ---------------------------------------------------------------------------
# Transparent output for the 2-action bundle.
# Two actions at spend_value=300000 each → ironwood_vb = 600000.
# Fee = ironwood_vb (600000) - transparent_output (599000) = 1000 zats.
# ---------------------------------------------------------------------------
_TRANSPARENT_OUTPUT_599K = PcztTransparentOutput(
    value=599000,
    script_pubkey=bytes.fromhex("76a914424242424242424242424242424242424242424288ac"),
)

# Empty Orchard bundle used to advance the state machine to OrchardActionsDone.
# V6 transactions must traverse the Orchard parse path (even with zero actions)
# before the firmware accepts INS_PCZT_IRONWOOD_ACTION (0x58).
_EMPTY_ORCHARD_BUNDLE = PcztOrchardBundle(
    actions=[],
    flags=0,
    value_balance=0,
    anchor=bytes(32),
)


# ---------------------------------------------------------------------------
# Helper: construct a valid Ironwood action (real spend, spend_value=300000).
# output_value=0, so the firmware uses the dummy-output path for cmx
# verification: NoteCommitment(recipient=_INTERNAL_RECIPIENT, value=0,
# nullifier=_NULLIFIER, rseed=_RSEED) must equal _CMX.
# enc_ciphertext and out_ciphertext are all-zero placeholders; the device
# accepts them because output_value=0 triggers the dummy-output shortcut.
# ---------------------------------------------------------------------------
def _real_ironwood_action() -> PcztIronwoodAction:
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


def _two_real_spends_bundle() -> PcztIronwoodBundle:
    """Ironwood bundle with two identical real spends and no dummy padding.

    Both actions use the same spend vectors — this is cryptographically invalid
    (double-spend by reusing the same nullifier) but the firmware only verifies
    each action's nullifier against its own note data, not for uniqueness across
    actions. The duplicate is therefore accepted at the PCZT parse layer.

    value_balance = 2 * 300000 = 600000 (Ironwood pool spends 600000 zats).
    With _TRANSPARENT_OUTPUT_599K = 599000, the fee is exactly 1000 zats.
    """
    return PcztIronwoodBundle(
        actions=[_real_ironwood_action(), _real_ironwood_action()],
        flags=3,
        value_balance=600000,
        anchor=bytes(32),
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


# ---------------------------------------------------------------------------
# Happy-path test: 0 transparent inputs, 1 transparent output, 2 Ironwood
# actions (both real spends).  Verifies:
#   1. V6 PCZT header (PCZT_VERSION_2) is accepted.
#   2. Empty Orchard bundle advances the state machine to OrchardActionsDone.
#   3. Both Ironwood action APDU groups are parsed without error.
#   4. The review screen is shown after the trailer packet.
#   5. INS_PCZT_SIGN_IRONWOOD (0x59) returns a 64-byte spendAuthSig for each
#      real spend; the session is only closed after both are signed.
# ---------------------------------------------------------------------------
def test_pczt_ironwood_v2_two_actions_sign_both(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """Full happy path: V6 Ironwood PCZT with 2 real spends, signed sequentially.

    APDU packet count for this scenario:
      Header       : 1 packet
      Inputs       : 1 packet  (varint(0))
      Outputs      : 4 packets (varint(1) + value + script + bip32_derivation)
      Orchard      : 1 packet  (varint(0) + trailer)
      Ironwood     : 18 packets (1 header + 2 × 8 action packets + 1 trailer)
                     P1: FIRST, NEXT×16, LAST; last gets P2=FINISHED
    """
    client = ZcashCommandSender(backend)
    bundle = _two_real_spends_bundle()

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_599K],
        orchard_bundle=_EMPTY_ORCHARD_BUNDLE,
        ironwood_bundle=bundle,
    ):
        _review_approve(scenario_navigator, "test_pczt_ironwood_v2_two_actions_sign_both")

    # Sign action 0 (first real spend).  The parser is NOT reset because
    # action 1 still awaits its signature (ironwood_signed_count=1 < real_spend_count=2).
    sig_action_0 = client.pczt_sign_ironwood(action_index=0).data
    assert len(sig_action_0) == 64, (
        f"Expected 64-byte spendAuthSig for action 0, got {len(sig_action_0)}"
    )

    # Sign action 1 (second real spend).  The parser is reset here because all
    # real spends are now signed (ironwood_signed_count=2 == real_spend_count=2).
    sig_action_1 = client.pczt_sign_ironwood(action_index=1).data
    assert len(sig_action_1) == 64, (
        f"Expected 64-byte spendAuthSig for action 1, got {len(sig_action_1)}"
    )


# ---------------------------------------------------------------------------
# Regression: in-session replay of action 0 (before action 1 is signed)
# must fail with SW_INVALID_TRANSACTION.  mark_ironwood_action_signed sets
# action.signed=True; ensure_signature_digest_for_ironwood catches it.
#
# The replay is attempted BEFORE signing action 1 to avoid triggering the
# "all signatures done" path — which shows a status screen and the home
# screen, blocking any subsequent APDU until user interaction.
# ---------------------------------------------------------------------------
def test_pczt_ironwood_v2_replay_in_session_rejected(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """In-session replay of action 0 (action 1 still unsigned) is rejected.

    mark_ironwood_action_signed() sets action.signed=True after each sign.
    A second call for action 0 while action 1 is still pending hits the guard
    inside ensure_signature_digest_for_ironwood and returns SW_INVALID_TRANSACTION
    (0x6A80 = AppSW::IncorrectData), matching the V5 Orchard equivalent:
    test_pczt_ironwood_sign_replay_in_session_rejected in test_pczt_ironwood.py.
    """
    client = ZcashCommandSender(backend)
    bundle = _two_real_spends_bundle()

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[],
        transparent_outputs=[_TRANSPARENT_OUTPUT_599K],
        orchard_bundle=_EMPTY_ORCHARD_BUNDLE,
        ironwood_bundle=bundle,
    ):
        _review_approve(
            scenario_navigator,
            "test_pczt_ironwood_v2_replay_in_session_rejected",
        )

    # First sign of action 0 succeeds; action 1 is still unsigned.
    sig_0 = client.pczt_sign_ironwood(action_index=0).data
    assert len(sig_0) == 64, (
        f"Expected 64-byte spendAuthSig for action 0, got {len(sig_0)}"
    )

    # Replay of action 0 while action 1 is still pending must be rejected.
    # ensure_signature_digest_for_ironwood sees action.signed==True and returns
    # "PCZT ironwood action already signed" → AppSW::IncorrectData (0x6A80).
    with pytest.raises(ExceptionRAPDU) as e:
        client.pczt_sign_ironwood(action_index=0)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


# ---------------------------------------------------------------------------
# Discrepancy documentation: PCZT_VERSION_1 rejected for V6 transactions.
#
# The Python test-client (ZcashCommandSender._build_pczt_header_and_global_payload)
# automatically selects pczt_version=2 when tx_version==6, matching what the
# ironwood worktree firmware requires.  This test verifies that if the caller
# forces pczt_version=1 for a V6 transaction the firmware returns
# SW_INVALID_TRANSACTION (0x6A80).
#
# This is the root cause of the failing APDU in the task context log:
#   => e05200002250435a54020000000600000098b684d85b16a537...
#   <= 6a80
# That APDU uses pczt_version=2 (bytes 5-8 = 02000000) but was sent to the
# develop-branch build which lacks the zcash_unstable feature and therefore
# accepts only PCZT_VERSION_1.  Against this ironwood worktree the same
# pczt_version=2 header is accepted.  Forcing pczt_version=1 on a V6 tx
# triggers the check at common.rs:96:
#   if is_v6 && self.pczt_version != PCZT_VERSION_2 { return Err(...) }
# ---------------------------------------------------------------------------
def test_pczt_ironwood_v2_version1_rejected_for_v6(backend):
    """PCZT_VERSION_1 is rejected for a V6 (Ironwood) transaction header.

    The ironwood worktree firmware accepts PCZT_VERSION_2 for V6 and
    PCZT_VERSION_1 for V5 — versions cannot be mixed.
    """
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL,
            transparent_inputs=[],
            transparent_outputs=[_TRANSPARENT_OUTPUT_599K],
            ironwood_bundle=_two_real_spends_bundle(),
            pczt_version=1,  # force incorrect version for a V6 tx
        ):
            pytest.fail("Device accepted PCZT_VERSION_1 for a V6 transaction")

    assert e.value.status == Errors.SW_INVALID_TRANSACTION


# ---------------------------------------------------------------------------
# Verify that the empty Orchard bundle (the state-machine bridge) cannot be
# skipped: sending INS_PCZT_IRONWOOD_ACTION directly after transparent outputs
# must return SW_BAD_STATE (0xB007).
# ---------------------------------------------------------------------------
def test_pczt_ironwood_v2_skipping_orchard_phase_rejected(backend):
    """INS_PCZT_IRONWOOD_ACTION before Orchard completes returns SW_BAD_STATE.

    The state machine expects WaitOrchardAction (or OrchardActionsDone) before
    it will accept an Ironwood action packet.  Sending the ironwood action-count
    packet while in WaitOrchardAction — without an empty Orchard trailer —
    must be rejected.
    """
    client = ZcashCommandSender(backend)
    client._send_pczt_header(PCZT_V6_GLOBAL)
    client._send_pczt_transparent_inputs([])
    client._send_pczt_transparent_outputs_sync([_TRANSPARENT_OUTPUT_599K])
    # Do NOT send the Orchard bundle; go straight to Ironwood.

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.PCZT_IRONWOOD_ACTION,
            p1=P1.P1_FIRST,
            p2=P2.P2_NONE,
            data=write_varint(2),  # 2 Ironwood actions
        )

    assert e.value.status == Errors.SW_BAD_STATE
