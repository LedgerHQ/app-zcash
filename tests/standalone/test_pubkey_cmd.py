import pytest

from application_client.zcash_command_sender import GetShieldedAddressMode, ZcashCommandSender, Errors, GetVkMode
from application_client.zcash_response_unpacker import (
    unpack_get_public_key_response,
    unpack_len_prefixed_utf8_response,
)
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU
from application_client.zcash_utils import t_address_from_pubkey
from ragger.navigator import NavigateWithScenario, NavInsID
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase


def extension(cls):
    def wrapper(func):
        setattr(cls, func.__name__, func)
        return func
    return wrapper

# Special approve navigation that doesn't wait for the last screen,
# as the UFVK status screen is shown only after all response chunks are fetched.
@extension(NavigateWithScenario)
def review_approve_ufvk(self):
    scenario = NavigationScenarioData(self.device, self.backend, UseCase.ADDRESS_CONFIRMATION, True)

    if self.device.touchable:
        scenario.validation = scenario.validation[:-1]

    self.navigator.navigate_until_text_and_compare(
        navigate_instruction=scenario.navigation,
        validation_instructions=scenario.validation,
        text=scenario.pattern,
        path=self.screenshot_path,
        test_case_name=self.test_name,
        screen_change_after_last_instruction=False,
    )

# In this test we check that the GET_PUBLIC_KEY works in non-confirmation mode
def test_get_public_key_no_confirm(backend):
    for path in ["m/44'/133'/0'/0/0", "m/44'/133'/0/0/0", "m/44'/133'/911'/0/0", "m/44'/133'/255/255/255", "m/44'/133'/2147483647/0/0/0/0/0/0/0"]:
        client = ZcashCommandSender(backend)
        response = client.get_public_key(path=path).data
        public_key, address, chain_code = unpack_get_public_key_response(response)

        ref_public_key, ref_chain_code = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
        ref_t_address = t_address_from_pubkey(bytes.fromhex(ref_public_key))

        assert public_key.hex() == ref_public_key
        assert address == ref_t_address
        assert chain_code.hex() == ref_chain_code


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode
def test_get_public_key_confirm_accepted(backend, scenario_navigator: NavigateWithScenario):
    client = ZcashCommandSender(backend)
    path = "m/44'/133'/0'/0/0"

    with client.get_public_key_with_confirmation(path=path):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().data
    public_key, address, chain_code = unpack_get_public_key_response(response)

    ref_public_key, ref_chain_code = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
    ref_t_address = t_address_from_pubkey(bytes.fromhex(ref_public_key))

    assert public_key.hex() == ref_public_key
    assert address == ref_t_address
    assert chain_code.hex() == ref_chain_code


# In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
def test_get_public_key_confirm_refused(backend, scenario_navigator):
    client = ZcashCommandSender(backend)
    path = "m/44'/133'/0'/0/0"

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_public_key_with_confirmation(path=path):
            scenario_navigator.address_review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0

def test_get_ufvk_confirm_accepted(backend, scenario_navigator):
    REF_UFVK_ACC_0 = "uview1zkk7f8hp2m5v09kq7h29vkgngwhhvgy2ey32cy5j0kp69g7ju2vqjvnue03u99z382rtkgvj3f8vtqdtxfxvgjytezgt39dqc0lyt2sj084jdq4md69snc3wxdcl8uah8sxw3rrt9pnxnfl3r4xnczapts7gr4l0cuell7dcjv36gkdcsl4axps827xt6fgmfl78zlhddec72tn2p0eqnpkuy7a08puhj97v0ahxuqlyzmyqtldqnc0p3696d9ww8x6mpd56mz6w32twryevru2rx34lf8dtqsp50gar"

    client = ZcashCommandSender(backend)

    with client.get_vk_with_confirmation(
        path="m/32'/133'/0'",
        mode=GetVkMode.UFVK,
        navigate=scenario_navigator.review_approve_ufvk,
    ) as response:
        response = response.data

    ufvk = unpack_len_prefixed_utf8_response(response)
    assert ufvk == REF_UFVK_ACC_0

def test_get_ufvk_confirm_accepted_acc1(backend, scenario_navigator):
    REF_UFVK_ACC_1 = "uview15lcx60j8zufp6qe5xveppqjjw3ukg5n90ln8uhgdxukp60tejk626763gffftfw4a2mjkxy4s9mpjdd6ckfkecz846jdvth57djchnpq7699v09g7eu9xnyyfeqtvm5jxhvpn6dxkzqq3726xwhxmn458a8hd2agvl30r2kz9cde8d8nd3e7akdkufuzp3hyule9v0w3a6qx5p5fx8qa3wvjcj9qg9ypnr56m672rsv9y8fqn20usqzhxmrnmm2jf7gnh8kdk68dyvej9jlsm522w24jvce0lcqpn3mf"

    client = ZcashCommandSender(backend)
    with client.get_vk_with_confirmation(
        path="m/32'/133'/1'",
        mode=GetVkMode.UFVK,
        navigate=scenario_navigator.review_approve_ufvk,
    ) as response:
        response = response.data

    ufvk = unpack_len_prefixed_utf8_response(response)
    assert ufvk == REF_UFVK_ACC_1

def test_get_ufvk_confirm_refused(backend, scenario_navigator):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_vk_with_confirmation(
            path="m/32'/133'/0'",
            mode=GetVkMode.UFVK,
            navigate=scenario_navigator.address_review_reject,
        ):
            pass

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_get_orchard_fvk_confirm_accepted(backend, scenario_navigator):
    REF_ORCHARD_FVK_ACC_0 = bytes.fromhex(
        "e129bb7d06ed69a5ac01a664482ec9987fd19c40940bf76d98eb8b952974852949b0128d5072f9f92c7f7e8eb49a5434d2c04b67a30a55946d8322df3e484426f6151235e5897d34196943cb8f968312f1c8fba9ed82830b59f801b6de5da835"
    )

    client = ZcashCommandSender(backend)

    with client.get_vk_with_confirmation(
        path="m/32'/133'/0'",
        mode=GetVkMode.ORCHARD_FVK,
        navigate=scenario_navigator.address_review_approve,
    ) as response:
        response = response.data

    assert response == REF_ORCHARD_FVK_ACC_0

def test_get_orchard_fvk_confirm_accepted_acc1(backend, scenario_navigator):
    REF_ORCHARD_FVK_ACC_1 = bytes.fromhex(
        "60efdc2aee5ec6fc6632655b5fef524275f11e2486fbb757253772b95e95b0259ca56bd0928f774c00663ef101075663eef4643346bc9171c0800c23c2e8c809880c97b34333ac38e48af5f0ee64c721c9a1847138a874d42b5ee72b41ab6e1e"
    )

    client = ZcashCommandSender(backend)

    with client.get_vk_with_confirmation(
        path="m/32'/133'/1'",
        mode=GetVkMode.ORCHARD_FVK,
        navigate=scenario_navigator.address_review_approve,
    ) as response:
        response = response.data

    assert response == REF_ORCHARD_FVK_ACC_1

def test_get_orchard_fvk_confirm_refused(backend, scenario_navigator):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_vk_with_confirmation(
            path="m/32'/133'/0'",
            mode=GetVkMode.ORCHARD_FVK,
            navigate=scenario_navigator.address_review_reject,
        ):
            pass

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_get_orchard_address_raw(backend):
    REF_ORCHARD_ADDRESS_RAW_ACC_0 = bytes.fromhex("4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02")
    REF_ORCHARD_ADDRESS_RAW_ACC_1 = bytes.fromhex("cbe41c85c42eb0d78831b01da5822dfb185550af3ad0436670f4e3b1a634b8b468c6867162c2db1bba96a2")

    client = ZcashCommandSender(backend)
    orchard_address_raw = client.get_shielded_address(path="m/32'/133'/0'", mode=GetShieldedAddressMode.ORCHARD_RAW_ADDRESS).data
    assert orchard_address_raw == REF_ORCHARD_ADDRESS_RAW_ACC_0

    client = ZcashCommandSender(backend)
    orchard_address_raw = client.get_shielded_address(path="m/32'/133'/1'", mode=GetShieldedAddressMode.ORCHARD_RAW_ADDRESS).data
    assert orchard_address_raw == REF_ORCHARD_ADDRESS_RAW_ACC_1


def test_get_orchard_uaddress_no_confirm(backend):
    REF_ORCHARD_ADDRESS_ACC_0 = "u1u2h4ce7e2cn3z4nzur95muq2dl4da9x8h8kdp2l80gm9nl9raj8zzpx79ycjnfvar4v5exea5pqr5y9qsnlp0cdunwf9yjjx5c4q7ar9"
    REF_ORCHARD_ADDRESS_ACC_1 = "u1n4d94z4l9zs0kxhhytwyktg3rsmr9u0eagt3kn78j9m3lmnuzswuwn63az5jzfwqmvrfn0g8s3rvvg0wr0pklnkejm6d69hv8u5g6w9e"

    client = ZcashCommandSender(backend)
    response = client.get_shielded_address(path="m/32'/133'/0'", mode=GetShieldedAddressMode.UADDRESS).data
    orchard_address = unpack_len_prefixed_utf8_response(response)
    assert orchard_address == REF_ORCHARD_ADDRESS_ACC_0

    client = ZcashCommandSender(backend)
    response = client.get_shielded_address(path="m/32'/133'/1'", mode=GetShieldedAddressMode.UADDRESS).data
    orchard_address = unpack_len_prefixed_utf8_response(response)
    assert orchard_address == REF_ORCHARD_ADDRESS_ACC_1


def test_get_orchard_uaddress_confirm_accepted(backend, scenario_navigator):
    REF_ORCHARD_ADDRESS_ACC_0 = "u1u2h4ce7e2cn3z4nzur95muq2dl4da9x8h8kdp2l80gm9nl9raj8zzpx79ycjnfvar4v5exea5pqr5y9qsnlp0cdunwf9yjjx5c4q7ar9"

    client = ZcashCommandSender(backend)
    path = "m/32'/133'/0'"

    with client.get_shielded_address_with_confirmation(path=path, mode=GetShieldedAddressMode.UADDRESS):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().data
    orchard_address = unpack_len_prefixed_utf8_response(response)
    assert orchard_address == REF_ORCHARD_ADDRESS_ACC_0


def test_get_orchard_uaddress_confirm_refused(backend, scenario_navigator):
    client = ZcashCommandSender(backend)
    path = "m/32'/133'/0'"

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_shielded_address_with_confirmation(path=path, mode=GetShieldedAddressMode.UADDRESS):
            scenario_navigator.address_review_reject()

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0
