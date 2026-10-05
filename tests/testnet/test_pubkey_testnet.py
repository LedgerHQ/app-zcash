import pytest
from application_client.zcash_command_sender import (
    CLA,
    P1,
    Errors,
    GetVkMode,
    InsType,
    ZcashCommandSender,
)
from application_client.zcash_response_unpacker import unpack_get_public_key_response
from application_client.zcash_utils import T_ADDRESS_TESTNET_VERSION_BYTES, t_address_from_pubkey
from ragger.bip import CurveChoice, calculate_public_key_and_chaincode, pack_derivation_path
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario


def test_get_public_key_testnet(backend):
    for path in ["m/44'/1'", "m/44'/1'/0'/0/0", "m/44'/1'/7'/1/3"]:
        client = ZcashCommandSender(backend)
        public_key, address, chain_code = unpack_get_public_key_response(client.get_public_key(path=path).data)

        ref_public_key, ref_chain_code = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)

        assert public_key.hex() == ref_public_key
        assert chain_code.hex() == ref_chain_code
        assert address == t_address_from_pubkey(bytes.fromhex(ref_public_key), T_ADDRESS_TESTNET_VERSION_BYTES)
        assert address.startswith("tm")


def test_get_public_key_testnet_confirm(backend, scenario_navigator: NavigateWithScenario):
    client = ZcashCommandSender(backend)
    path = "m/44'/1'/0'/0/0"

    with client.get_public_key_with_confirmation(path=path):
        scenario_navigator.address_review_approve()

    public_key, address, _ = unpack_get_public_key_response(client.get_async_response().data)

    ref_public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
    assert public_key.hex() == ref_public_key
    assert address == t_address_from_pubkey(bytes.fromhex(ref_public_key), T_ADDRESS_TESTNET_VERSION_BYTES)


def test_get_public_key_testnet_confirm_refused(backend, scenario_navigator: NavigateWithScenario):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_public_key_with_confirmation(path="m/44'/1'/0'/0/0"):
            scenario_navigator.address_review_reject()

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


# The testnet build declares `44'/1'` and `32'/1'` only. A mainnet path must come back as a status
# word: left to the OS, the derivation would take the app down instead of answering.
@pytest.mark.parametrize(
    "path",
    [
        "m/44'/133'/0'/0/0",
        "m/44'/133'",
        "m/32'/133'/0'",
        "m/44'/60'/0'/0/0",
        "m/44'/1/0'/0/0",  # coin type not hardened
    ],
    ids=["mainnet_account", "mainnet_prefix", "mainnet_shielded", "ethereum", "unhardened_coin_type"],
)
def test_mainnet_paths_refused_for_public_key(backend, path):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_public_key(path=path)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0
    # The app is still answering.
    assert client.get_public_key(path="m/44'/1'/0'/0/0").data


@pytest.mark.parametrize("path", ["m/32'/133'/0'", "m/32'/0'/0'"], ids=["mainnet_coin_type", "bitcoin_coin_type"])
def test_mainnet_paths_refused_for_orchard_fvk(backend, path):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.GET_VK,
            p1=P1.P1_GET_VK_FIRST,
            p2=GetVkMode.ORCHARD_FVK,
            data=pack_derivation_path(path),
        )

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0
