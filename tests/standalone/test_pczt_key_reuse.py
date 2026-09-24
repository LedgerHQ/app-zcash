"""Account-bound authorizing-key reuse across distinct notes and parser resets."""
import pytest
from application_client.pczt import PcztGlobal, pczt_transaction_bytes
from application_client.zcash_command_sender import Errors, ZcashCommandSender
from application_client.zcash_verify_sign import (
    ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES,
    _pallas_point_add,
    _pallas_point_from_bytes,
    _pallas_point_to_bytes,
    check_orchard_spendauth_signature_validity,
    nu5_signature_digests,
)
from ragger.error import ExceptionRAPDU
from .test_pczt import _mixed_real_and_dummy_orchard_bundle, _review_approve
from .test_pczt_ironwood import (
    PCZT_V6_GLOBAL,
    _TRANSPARENT_OUTPUT_299K,
    _ironwood_bundle_with_external_recipient,
    _valid_ironwood_action,
    _valid_orchard_bundle,
)


def _distinct_spends(pool, dummy_first):
    """Combine existing valid notes with different rho/rseed/nullifiers and alpha."""
    if pool == "orchard":
        bundle = _mixed_real_and_dummy_orchard_bundle()
        first = _valid_orchard_bundle().actions[0]
    else:
        bundle = _ironwood_bundle_with_external_recipient()
        first = _valid_ironwood_action()
    second, dummy = bundle.actions
    # Existing second.rk uses alpha=1. Add G to get the public alpha=2 key.
    second.alpha = (2).to_bytes(32, "little")
    second.rk = _pallas_point_to_bytes(_pallas_point_add(
        _pallas_point_from_bytes(second.rk),
        _pallas_point_from_bytes(ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES),
    ))
    assert first.nullifier != second.nullifier and first.spend_rho != second.spend_rho
    assert first.rk != second.rk
    bundle.actions = ([dummy] if dummy_first else []) + [first, second]
    bundle.value_balance = sum(a.spend_value - a.value for a in bundle.actions)
    return bundle


def _send_and_verify(client, navigator, pool, bundle):
    global_fields = PcztGlobal() if pool == "orchard" else PCZT_V6_GLOBAL
    outputs = [_TRANSPARENT_OUTPUT_299K]
    with client.send_pczt(
        pczt_global=global_fields, transparent_inputs=[], transparent_outputs=outputs,
        **{f"{pool}_bundle": bundle},
    ):
        _review_approve(navigator, "key_reuse", compare=False)
    digest = None
    if pool == "orchard":
        tx = pczt_transaction_bytes(global_fields, [], outputs, bundle)
        digest = nu5_signature_digests(tx, [])["final_digest"]
    sign = client.pczt_sign_orchard if pool == "orchard" else client.pczt_sign_ironwood
    for index, action in enumerate(bundle.actions):
        if action.spend_value:
            signature = sign(action_index=index).data
            assert len(signature) == 64
            if digest is not None:
                assert check_orchard_spendauth_signature_validity(action.rk, signature, digest)


@pytest.mark.parametrize("pool", ["orchard", "ironwood"])
@pytest.mark.parametrize("dummy_first", [False, True])
def test_pczt_key_reuse_distinct_spends(backend, scenario_navigator, pool, dummy_first):
    client = ZcashCommandSender(backend)
    _send_and_verify(client, scenario_navigator, pool, _distinct_spends(pool, dummy_first))


@pytest.mark.parametrize("pool", ["orchard", "ironwood"])
@pytest.mark.parametrize("field", ["rk", "signing_path"])
def test_pczt_key_reuse_failure_then_new_transaction(backend, scenario_navigator, pool, field):
    client = ZcashCommandSender(backend)
    bundle = _distinct_spends(pool, True)
    if field == "rk":
        bundle.actions[-1].rk = bundle.actions[-2].rk
        expected = Errors.SW_INVALID_TRANSACTION
    else:
        bundle.actions[-1].signing_path = "m/32'/133'/1'"
        expected = Errors.SW_BAD_STATE
    with pytest.raises(ExceptionRAPDU) as error:
        with client.send_pczt(
            pczt_global=PcztGlobal() if pool == "orchard" else PCZT_V6_GLOBAL,
            transparent_inputs=[], transparent_outputs=[_TRANSPARENT_OUTPUT_299K],
            **{f"{pool}_bundle": bundle},
        ):
            pytest.fail("Malformed second spend reached review")
    assert error.value.status == expected and not error.value.data
    _send_and_verify(client, scenario_navigator, pool, _distinct_spends(pool, False))
