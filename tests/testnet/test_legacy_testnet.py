"""The testnet build refuses a mainnet key on the legacy transparent signing commands.

Two of them carry a derivation path: the change-information packet, which takes an output off the
review, and HASH_SIGN, which names the key that signs. Both ship in the testnet build and both must
refuse coin type `133'`. GET_TRUSTED_INPUT carries no path: it vouches for a previous transaction's
output amount whatever the network, so it has nothing to refuse here.
"""

import pytest
from application_client.zcash_command_sender import Errors, ZcashCommandSender
from legacy_flow import change_info_apdu, hash_sign_apdu, open_legacy_change_info, open_legacy_signing
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario

from .helpers import review_approve

HARDENED = 0x8000_0000


@pytest.mark.parametrize("coin_type", [1, 133], ids=["testnet", "mainnet"])
def test_legacy_change_info_follows_the_coin_type(backend, coin_type):
    transport = ZcashCommandSender(backend)
    open_legacy_change_info(transport)
    apdu = change_info_apdu([44 | HARDENED, coin_type | HARDENED, 2 | HARDENED, 1, 0])

    if coin_type == 1:
        sw, _ = transport.exchange_raw(apdu)
        assert sw == 0x9000
        return

    with pytest.raises(ExceptionRAPDU) as e:
        transport.exchange_raw(apdu)
    assert e.value.status == Errors.SW_CONDITIONS_OF_USE_NOT_SATISFIED


@pytest.mark.parametrize("coin_type", [1, 133], ids=["testnet", "mainnet"])
def test_legacy_signing_follows_the_coin_type(backend, scenario_navigator: NavigateWithScenario, coin_type):
    """The transaction is reviewed and ready to sign; HASH_SIGN then names the key.

    The testnet key signs and the mainnet one is refused, over the same round, so the refusal can
    only come from the path. The review itself is not under test, so its screens are not compared.
    """
    transport = ZcashCommandSender(backend)
    open_legacy_signing(transport, lambda: review_approve(scenario_navigator, None, compare=False))
    apdu = hash_sign_apdu([44 | HARDENED, coin_type | HARDENED, HARDENED, 0, 2])

    if coin_type == 1:
        sw, signature = transport.exchange_raw(apdu)
        assert sw == 0x9000
        assert signature
        return

    with pytest.raises(ExceptionRAPDU) as e:
        transport.exchange_raw(apdu)
    assert e.value.status == Errors.SW_CONDITIONS_OF_USE_NOT_SATISFIED
    assert len(e.value.data) == 0
