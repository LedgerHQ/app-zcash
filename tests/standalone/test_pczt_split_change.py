"""Shielded change split across several notes, in the Orchard pool and across both shielded pools."""
import hashlib

import pytest
from application_client.pczt import (
    PcztGlobal,
    PcztIronwoodBundle,
    PcztOrchardBundle,
    PcztTransparentInput,
    PcztTransparentOutput,
)
from application_client.zcash_command_sender import Errors, ZcashCommandSender
from application_client.zcash_utils import ripemd160
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario

from .test_pczt import _mixed_real_and_dummy_orchard_bundle
from .test_pczt_ironwood import (
    PCZT_V6_GLOBAL,
    _OWN_CHANGE_PATH,
    _TRANSPARENT_INPUT_11K,
    _TRANSPARENT_INPUT_100K,
    _dummy_ironwood_action,
    _walk_review,
)


def _orchard_split_change_bundle(change_notes: int, with_recipient: bool = True) -> PcztOrchardBundle:
    base = _mixed_real_and_dummy_orchard_bundle()
    recipient = [base.actions[0]] if with_recipient else []
    actions = recipient + [_mixed_real_and_dummy_orchard_bundle().actions[1] for _ in range(change_notes)]
    return PcztOrchardBundle(
        actions=actions,
        flags=base.flags,
        value_balance=sum(a.spend_value - a.value for a in actions),
        anchor=base.anchor,
    )


def _ironwood_change_bundle(change_notes: int) -> PcztIronwoodBundle:
    actions = [_dummy_ironwood_action() for _ in range(change_notes)]
    return PcztIronwoodBundle(
        actions=actions,
        value_balance=sum(a.spend_value - a.value for a in actions),
        flags=3,
        anchor=bytes(32),
    )


def _refused(client: ZcashCommandSender, **pczt) -> ExceptionRAPDU:
    # The refusal comes with the last packet, answered when the block exits.
    with pytest.raises(ExceptionRAPDU) as error:
        with client.send_pczt(**pczt):
            pass
    assert not error.value.data
    return error.value


def test_pczt_orchard_change_notes_count_against_the_output_budget(backend):
    """A sixth change note beside one recipient is a seventh retained shielded output: refused."""
    error = _refused(
        ZcashCommandSender(backend),
        pczt_global=PcztGlobal(),
        transparent_inputs=[_TRANSPARENT_INPUT_100K],
        transparent_outputs=[],
        orchard_bundle=_orchard_split_change_bundle(6),
    )
    assert error.status == Errors.SW_NOT_ENOUGH_MEMORY_SPACE


def test_pczt_orchard_shield_into_too_many_notes_refused(backend):
    """A fifth revealed note would put a fifth shielded output on the review: refused."""
    error = _refused(
        ZcashCommandSender(backend),
        pczt_global=PcztGlobal(),
        transparent_inputs=[_TRANSPARENT_INPUT_100K],
        transparent_outputs=[],
        orchard_bundle=_orchard_split_change_bundle(5, with_recipient=False),
    )
    assert error.status == Errors.SW_NOT_ENOUGH_MEMORY_SPACE


def test_pczt_orchard_transparent_and_shielded_change_refused(backend):
    client = ZcashCommandSender(backend)
    pubkey = client._compressed_pubkey_from_path(_OWN_CHANGE_PATH)  # pylint: disable=W0212
    own_change = PcztTransparentOutput(
        value=1000,
        script_pubkey=bytes.fromhex("76a914") + ripemd160(hashlib.sha256(pubkey).digest()) + bytes.fromhex("88ac"),
        signing_path=_OWN_CHANGE_PATH,
    )
    error = _refused(
        client,
        pczt_global=PcztGlobal(),
        transparent_inputs=[_TRANSPARENT_INPUT_100K],
        transparent_outputs=[own_change],
        orchard_bundle=_orchard_split_change_bundle(1),
    )
    assert error.status == Errors.SW_INVALID_TRANSACTION


def test_pczt_orchard_split_change_in_another_account_yields_no_signature(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """The change notes return to account 0 while the signed transparent input belongs to account 1."""
    foreign_account_input = PcztTransparentInput(
        prevout_txid=_TRANSPARENT_INPUT_11K.prevout_txid,
        prevout_index=_TRANSPARENT_INPUT_11K.prevout_index,
        value=_TRANSPARENT_INPUT_11K.value,
        script_pubkey=_TRANSPARENT_INPUT_11K.script_pubkey,
        sequence=_TRANSPARENT_INPUT_11K.sequence,
        signing_path="m/44'/133'/1'/0/0",
    )
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PcztGlobal(),
        transparent_inputs=[foreign_account_input],
        transparent_outputs=[],
        orchard_bundle=_orchard_split_change_bundle(3),
    ):
        _walk_review(scenario_navigator, approve=True)

    with pytest.raises(ExceptionRAPDU) as error:
        client.pczt_sign_transparent(input_index=0)

    assert error.value.status == Errors.SW_CONDITIONS_OF_USE_NOT_SATISFIED
    assert not error.value.data


def test_pczt_split_change_across_both_pools_counts_against_one_budget(backend):
    """Four Orchard and three Ironwood outputs exceed the budget although neither pool alone does."""
    error = _refused(
        ZcashCommandSender(backend),
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[_TRANSPARENT_INPUT_100K],
        transparent_outputs=[],
        orchard_bundle=_orchard_split_change_bundle(3),
        ironwood_bundle=_ironwood_change_bundle(3),
    )
    assert error.status == Errors.SW_NOT_ENOUGH_MEMORY_SPACE


def test_pczt_split_change_across_both_pools_signs(
    backend,
    scenario_navigator: NavigateWithScenario,
):
    """One recipient and five change notes spread over both pools fill the budget, and sign."""
    client = ZcashCommandSender(backend)

    with client.send_pczt(
        pczt_global=PCZT_V6_GLOBAL,
        transparent_inputs=[_TRANSPARENT_INPUT_100K],
        transparent_outputs=[],
        orchard_bundle=_orchard_split_change_bundle(2),
        ironwood_bundle=_ironwood_change_bundle(3),
    ):
        _walk_review(scenario_navigator, approve=True)

    assert len(client.pczt_sign_orchard(action_index=0).data) == 64
    assert len(client.pczt_sign_transparent(input_index=0).data) >= 70
