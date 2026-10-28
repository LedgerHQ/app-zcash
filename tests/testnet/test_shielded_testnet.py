import pytest
from application_client.zcash_command_sender import (
    CLA,
    P1,
    Errors,
    GetShieldedAddressMode,
    GetVkMode,
    InsType,
    ZcashCommandSender,
)
from application_client.zcash_response_unpacker import unpack_len_prefixed_utf8_response
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

from .testnet_vectors import (
    ORCHARD_FVK_ACCOUNT_0,
    ORCHARD_RAW_ADDRESS_ACCOUNT_0,
    UADDRESS_ACCOUNT_0,
    UFVK_ACCOUNT_0,
)


def _approve_ufvk(scenario_navigator: NavigateWithScenario):
    # The UFVK status screen only appears once every response chunk has been fetched.
    scenario = NavigationScenarioData(
        scenario_navigator.device, scenario_navigator.backend, UseCase.ADDRESS_CONFIRMATION, True
    )
    if scenario_navigator.device.touchable:
        scenario.validation = scenario.validation[:-1]

    scenario_navigator.navigator.navigate_until_text_and_compare(
        navigate_instruction=scenario.navigation,
        validation_instructions=scenario.validation,
        text=scenario.pattern,
        path=scenario_navigator.screenshot_path,
        test_case_name=scenario_navigator.test_name,
        screen_change_after_last_instruction=False,
    )


def test_get_ufvk_testnet(backend, scenario_navigator: NavigateWithScenario):
    client = ZcashCommandSender(backend)

    with client.get_vk_with_confirmation(
        path="m/32'/1'/0'",
        transparent_path="m/44'/1'/0'",
        mode=GetVkMode.UFVK,
        navigate=lambda: _approve_ufvk(scenario_navigator),
    ) as response:
        response = response.data

    ufvk = unpack_len_prefixed_utf8_response(response)
    assert ufvk.startswith("uviewtest1")
    assert ufvk == UFVK_ACCOUNT_0


def test_get_orchard_fvk_testnet(backend, scenario_navigator: NavigateWithScenario):
    client = ZcashCommandSender(backend)

    with client.get_vk_with_confirmation(
        path="m/32'/1'/0'",
        mode=GetVkMode.ORCHARD_FVK,
        navigate=scenario_navigator.address_review_approve,
    ) as response:
        response = response.data

    assert response == ORCHARD_FVK_ACCOUNT_0


def test_get_orchard_raw_address_testnet(backend):
    client = ZcashCommandSender(backend)

    response = client.get_shielded_address(path="m/32'/1'/0'", mode=GetShieldedAddressMode.ORCHARD_RAW_ADDRESS).data

    assert response == ORCHARD_RAW_ADDRESS_ACCOUNT_0


def test_get_orchard_uaddress_testnet(backend):
    client = ZcashCommandSender(backend)

    response = client.get_shielded_address(
        path="m/32'/1'/0'",
        transparent_path="m/44'/1'/0'/0/0",
        mode=GetShieldedAddressMode.UADDRESS,
    ).data

    address = unpack_len_prefixed_utf8_response(response)
    assert address.startswith("utest1")
    assert address == UADDRESS_ACCOUNT_0


# A viewing key or address for a mainnet account must be refused, not derived.
@pytest.mark.parametrize(
    "orchard_path, transparent_path",
    [
        ("m/32'/133'/0'", "m/44'/133'/0'"),
        ("m/32'/1'/0'", "m/44'/133'/0'"),
        ("m/32'/133'/0'", "m/44'/1'/0'"),
    ],
    ids=["both_mainnet", "mainnet_transparent", "mainnet_shielded"],
)
def test_mainnet_paths_refused_for_ufvk(backend, orchard_path, transparent_path):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.GET_VK,
            p1=P1.P1_GET_VK_FIRST,
            p2=GetVkMode.UFVK,
            data=pack_derivation_path(orchard_path) + pack_derivation_path(transparent_path),
        )

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0


def test_mainnet_path_refused_for_orchard_address(backend):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_shielded_address(path="m/32'/133'/0'", mode=GetShieldedAddressMode.ORCHARD_RAW_ADDRESS)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0
