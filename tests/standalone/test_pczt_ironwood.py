# pylint: disable=C0301

"""
Ragger tests for Ironwood (NU6.3) PCZT parsing commands (INS 0x58, 0x59).

These tests require hardware / Speculos with zcash_unstable feature enabled.
They are marked as skip until a suitable Ironwood test vector is available.
"""

import pytest

# ---------------------------------------------------------------------------
# Constants reused across stubs
# ---------------------------------------------------------------------------

IRONWOOD_SIGNING_PATH = "m/32'/133'/0'"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dummy_ironwood_bundle():
    """Return a minimal PcztIronwoodBundle placeholder for import-time checks."""
    from application_client.pczt import PcztIronwoodBundle, PcztIronwoodAction  # noqa: PLC0415

    action = PcztIronwoodAction(
        cv_net=bytes(32),
        nullifier=bytes(32),
        spend_recipient=bytes(43),
        spend_rho=bytes(32),
        spend_rseed=bytes(32),
        rk=bytes(32),
        alpha=bytes(32),
        signing_path=IRONWOOD_SIGNING_PATH,
        cmx=bytes(32),
        ephemeral_key=bytes(32),
        enc_ciphertext=bytes(596),
        out_ciphertext=bytes(80),
        rcv=bytes(32),
        rseed=bytes(32),
    )
    bundle = PcztIronwoodBundle(
        actions=[action],
        flags=0,
        value_balance=0,
        anchor=bytes(32),
    )
    return bundle


# ---------------------------------------------------------------------------
# Import-time smoke test (no device required)
# ---------------------------------------------------------------------------


def test_ironwood_dataclasses_importable():
    """PcztIronwoodAction and PcztIronwoodBundle can be imported and instantiated."""
    from application_client.pczt import PcztIronwoodBundle, PcztIronwoodAction  # noqa: PLC0415

    action = PcztIronwoodAction(
        cv_net=bytes(32),
        nullifier=bytes(32),
        spend_recipient=bytes(43),
        spend_rho=bytes(32),
        spend_rseed=bytes(32),
        rk=bytes(32),
        alpha=bytes(32),
        signing_path=IRONWOOD_SIGNING_PATH,
        cmx=bytes(32),
        ephemeral_key=bytes(32),
        enc_ciphertext=bytes(596),
        out_ciphertext=bytes(80),
        rcv=bytes(32),
        rseed=bytes(32),
    )
    assert len(action.cv_net) == 32
    assert len(action.nullifier) == 32
    assert len(action.alpha) == 32

    bundle = PcztIronwoodBundle(
        actions=[action],
        flags=0,
        value_balance=-1_000,
        anchor=bytes(32),
    )
    assert len(bundle.actions) == 1
    assert bundle.value_balance == -1_000


def test_ironwood_command_sender_has_ironwood_methods():
    """ZcashCommandSender exposes the Ironwood APDU methods."""
    from application_client.zcash_command_sender import ZcashCommandSender, InsType  # noqa: PLC0415

    assert hasattr(ZcashCommandSender, "_send_pczt_ironwood_actions"), (
        "_send_pczt_ironwood_actions missing from ZcashCommandSender"
    )
    assert hasattr(ZcashCommandSender, "pczt_sign_ironwood"), (
        "pczt_sign_ironwood missing from ZcashCommandSender"
    )
    assert hasattr(InsType, "PCZT_IRONWOOD_ACTION"), (
        "InsType.PCZT_IRONWOOD_ACTION missing"
    )
    assert InsType.PCZT_IRONWOOD_ACTION == 0x58
    assert hasattr(InsType, "PCZT_SIGN_IRONWOOD"), (
        "InsType.PCZT_SIGN_IRONWOOD missing"
    )
    assert InsType.PCZT_SIGN_IRONWOOD == 0x59


# ---------------------------------------------------------------------------
# Device / Speculos tests (skipped until test vector available)
# ---------------------------------------------------------------------------


@pytest.mark.skip(
    reason="Ironwood test vector pending — re-enable when NU6.3 Speculos binary is available"
)
def test_pczt_ironwood_parse_single_action(backend, scenario_navigator):
    """Device accepts a single Ironwood action and returns a valid signing record."""
    from application_client.zcash_command_sender import ZcashCommandSender  # noqa: PLC0415

    client = ZcashCommandSender(backend)
    bundle = _dummy_ironwood_bundle()
    with client._send_pczt_ironwood_actions(bundle, pczt_finished=True):
        scenario_navigator.review_approve()
    # Assertion: no APDU exception raised; response reviewed after this point


@pytest.mark.skip(
    reason="Ironwood test vector pending — re-enable when NU6.3 Speculos binary is available"
)
def test_pczt_ironwood_sign_action(backend, scenario_navigator):
    """INS 0x59 returns a 64-byte RedPallas signature for action index 0."""
    from application_client.zcash_command_sender import ZcashCommandSender  # noqa: PLC0415

    client = ZcashCommandSender(backend)
    bundle = _dummy_ironwood_bundle()
    with client._send_pczt_ironwood_actions(bundle, pczt_finished=False):
        scenario_navigator.review_approve()
    response = client.pczt_sign_ironwood(action_index=0)
    assert len(response.data) == 64, (
        f"Expected 64-byte RedPallas signature, got {len(response.data)} bytes"
    )


@pytest.mark.skip(
    reason="Ironwood test vector pending — re-enable when NU6.3 Speculos binary is available"
)
def test_pczt_v6_migration_tx_parse_both_bundles(backend, scenario_navigator):
    """A V6 migration tx with both Orchard and Ironwood bundles is parsed and signed."""
    pytest.skip("No V6 migration test vector available yet")


@pytest.mark.skip(
    reason="Ironwood test vector pending — re-enable when NU6.3 Speculos binary is available"
)
def test_pczt_ironwood_zero_actions_rejected(backend):
    """INS 0x58 with zero actions in the bundle is rejected with a ParserError."""
    from application_client.pczt import PcztIronwoodBundle  # noqa: PLC0415
    from application_client.zcash_command_sender import ZcashCommandSender  # noqa: PLC0415
    from ragger.error import ExceptionRAPDU  # noqa: PLC0415

    client = ZcashCommandSender(backend)
    empty_bundle = PcztIronwoodBundle(
        actions=[],
        flags=0,
        value_balance=0,
        anchor=bytes(32),
    )
    with pytest.raises(ExceptionRAPDU):
        with client._send_pczt_ironwood_actions(empty_bundle, pczt_finished=True):
            pass
