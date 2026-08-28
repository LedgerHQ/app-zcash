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
from application_client.zcash_response_unpacker import (
    unpack_get_public_key_response,
    unpack_len_prefixed_utf8_response,
)
from application_client.zcash_utils import t_address_from_pubkey
from ragger.bip import CurveChoice, calculate_public_key_and_chaincode, pack_derivation_path
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
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
    for path in [
        # The prefix alone, which is what Ledger Live asks for to build the account xpub. The
        # prefix check must keep accepting it: it is the shortest path the app answers.
        "m/44'/133'",
        "m/44'/133'/0'/0/0",
        "m/44'/133'/0/0/0",
        "m/44'/133'/911'/0/0",
        "m/44'/133'/255/255/255",
        "m/44'/133'/2147483647/0/0/0/0/0/0/0",
    ]:
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
    REF_UFVK_ACC_0 = "uview1zkk7f8hp2m5v09kq7h29vkgngwhhvgy2ey32cy5j0kp69g7ju2vqjvnue03u99z382rtkgvj3f8vtqdtxfxvgjytezgt39dqc0lyt2sj084jdq4md69snc3wxdcl8uah8sxw3rrt9pnxnfl3r4xnczapts7gr4l0cuell7dcjv36gkdcsl4axps827xt6fgmfl78zlhddec72tn2p0eqnpkuy7a08puhj97v0ahxuqlyzmyqtldqnc0p3696d9ww8x6mpd56mz6w32twryevru2rx34lf8dtqsp50gar"  # noqa: E501

    client = ZcashCommandSender(backend)

    with client.get_vk_with_confirmation(
        path="m/32'/133'/0'",
        transparent_path="m/44'/133'/0'",
        mode=GetVkMode.UFVK,
        navigate=scenario_navigator.review_approve_ufvk,
    ) as response:
        response = response.data

    ufvk = unpack_len_prefixed_utf8_response(response)
    assert ufvk == REF_UFVK_ACC_0


def test_get_ufvk_confirm_accepted_acc1(backend, scenario_navigator):
    REF_UFVK_ACC_1 = "uview15lcx60j8zufp6qe5xveppqjjw3ukg5n90ln8uhgdxukp60tejk626763gffftfw4a2mjkxy4s9mpjdd6ckfkecz846jdvth57djchnpq7699v09g7eu9xnyyfeqtvm5jxhvpn6dxkzqq3726xwhxmn458a8hd2agvl30r2kz9cde8d8nd3e7akdkufuzp3hyule9v0w3a6qx5p5fx8qa3wvjcj9qg9ypnr56m672rsv9y8fqn20usqzhxmrnmm2jf7gnh8kdk68dyvej9jlsm522w24jvce0lcqpn3mf"  # noqa: E501

    client = ZcashCommandSender(backend)
    with client.get_vk_with_confirmation(
        path="m/32'/133'/1'",
        transparent_path="m/44'/133'/1'",
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
            transparent_path="m/44'/133'/0'",
            mode=GetVkMode.UFVK,
            navigate=scenario_navigator.address_review_reject,
        ):
            pass

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_get_ufvk_requires_transparent_path(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.GET_VK,
            p1=P1.P1_GET_VK_FIRST,
            p2=GetVkMode.UFVK,
            data=pack_derivation_path("m/32'/133'/0'"),
        )

    assert e.value.status == Errors.SW_APP_WRONG_APDU_LENGTH
    assert len(e.value.data) == 0


def test_get_ufvk_account_mismatch(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.GET_VK,
            p1=P1.P1_GET_VK_FIRST,
            p2=GetVkMode.UFVK,
            data=pack_derivation_path("m/32'/133'/0'") + pack_derivation_path("m/44'/133'/1'"),
        )

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0


# A path outside the app's two declared prefixes must come back as a status word. Leaving it to the
# OS is not equivalent: the derivation syscall aborts the app rather than answering, and the caller
# cannot tell a refusal from a crash.
@pytest.mark.parametrize(
    "path",
    [
        "m/44'/60'/0'/0/0",  # Ethereum coin type
        "m/44'/0'/0'/0/0",  # Bitcoin coin type
        "m/49'/133'/0'/0/0",  # right coin type, purpose the app does not declare
        "m/133'/0'",  # coin type in the purpose position
        # The declared prefixes are hardened. Read with the hardening bit masked off these are the
        # app's own prefixes, yet they name a different subtree the OS will not derive — and it
        # refuses by taking the app down, so the check has to catch them first.
        "m/44/133'/0'/0/0",
        "m/44'/133/0'/0/0",
        "m/32/133'/0'",
    ],
    ids=[
        "ethereum",
        "bitcoin",
        "undeclared_purpose",
        "coin_type_as_purpose",
        "unhardened_purpose",
        "unhardened_coin_type",
        "unhardened_zip32_purpose",
    ],
)
def test_get_public_key_rejects_out_of_prefix_path(backend, path):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_public_key(path=path)

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0


# The Orchard FVK is derived from this path and exposes the account's whole shielded history, so the
# restriction applies in this mode exactly as it does in the unified one — a viewing key must not be
# exported for a path the app has no derivation for.
@pytest.mark.parametrize(
    "path",
    [
        "m/44'/133'/0'/0/0",  # BIP-44 shape where a ZIP-32 account path is required
        "m/32'/133'/0'/0/0",  # right prefix, but not an account path
        "m/32'/60'/0'",  # ZIP-32 shape, wrong coin type
        "m/32'/133'/0",  # account not hardened
    ],
    ids=["bip44_shape", "too_deep", "wrong_coin_type", "unhardened_account"],
)
def test_get_orchard_fvk_rejects_non_zip32_path(backend, path):
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


def test_orchard_derivations_are_capped(backend):
    """The no-display address endpoint derives an Orchard key before any user action can intervene.

    The Secure Element does not reclaim what that derivation consumes until the next power cycle, so
    a host repeating the request drains the resource and every later derivation fails — including
    the ones a transaction needs. The budget turns that open drain into a bounded one that reports
    itself with its own status word rather than with the technical error an exhausted syscall
    returns.

    Fifty derivations must still go through: a session of normal use stays far below that, and the
    endpoint would be unusable if the ceiling bit earlier.
    """
    client = ZcashCommandSender(backend)
    path = "m/32'/133'/0'"

    for _ in range(50):
        client.get_shielded_address(path=path, mode=GetShieldedAddressMode.ORCHARD_RAW_ADDRESS)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_shielded_address(path=path, mode=GetShieldedAddressMode.ORCHARD_RAW_ADDRESS)

    assert e.value.status == Errors.SW_NOT_ENOUGH_MEMORY_SPACE
    assert len(e.value.data) == 0


def test_get_orchard_address_raw(backend):
    REF_ORCHARD_ADDRESS_RAW_ACC_0 = bytes.fromhex(
        "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02"
    )
    REF_ORCHARD_ADDRESS_RAW_ACC_1 = bytes.fromhex(
        "cbe41c85c42eb0d78831b01da5822dfb185550af3ad0436670f4e3b1a634b8b468c6867162c2db1bba96a2"
    )

    client = ZcashCommandSender(backend)
    orchard_address_raw = client.get_shielded_address(path="m/32'/133'/0'", mode=GetShieldedAddressMode.ORCHARD_RAW_ADDRESS).data
    assert orchard_address_raw == REF_ORCHARD_ADDRESS_RAW_ACC_0

    client = ZcashCommandSender(backend)
    orchard_address_raw = client.get_shielded_address(path="m/32'/133'/1'", mode=GetShieldedAddressMode.ORCHARD_RAW_ADDRESS).data
    assert orchard_address_raw == REF_ORCHARD_ADDRESS_RAW_ACC_1


def test_get_orchard_uaddress_no_confirm(backend):
    REF_ORCHARD_ADDRESS_ACC_0 = (
        "u1u2h4ce7e2cn3z4nzur95muq2dl4da9x8h8kdp2l80gm9nl9raj8zzpx79ycjnfvar4v5exea5pqr5y9qsnlp0cdunwf9yjjx5c4q7ar9"
    )
    REF_ORCHARD_ADDRESS_ACC_1 = (
        "u1n4d94z4l9zs0kxhhytwyktg3rsmr9u0eagt3kn78j9m3lmnuzswuwn63az5jzfwqmvrfn0g8s3rvvg0wr0pklnkejm6d69hv8u5g6w9e"
    )

    client = ZcashCommandSender(backend)
    response = client.get_shielded_address(
        path="m/32'/133'/0'",
        transparent_path="m/44'/133'/0'/0/0",
        mode=GetShieldedAddressMode.UADDRESS,
    ).data
    orchard_address = unpack_len_prefixed_utf8_response(response)
    assert orchard_address == REF_ORCHARD_ADDRESS_ACC_0

    client = ZcashCommandSender(backend)
    response = client.get_shielded_address(
        path="m/32'/133'/1'",
        transparent_path="m/44'/133'/1'/0/0",
        mode=GetShieldedAddressMode.UADDRESS,
    ).data
    orchard_address = unpack_len_prefixed_utf8_response(response)
    assert orchard_address == REF_ORCHARD_ADDRESS_ACC_1


def test_get_orchard_uaddress_confirm_accepted(backend, scenario_navigator):
    REF_ORCHARD_ADDRESS_ACC_0 = (
        "u1u2h4ce7e2cn3z4nzur95muq2dl4da9x8h8kdp2l80gm9nl9raj8zzpx79ycjnfvar4v5exea5pqr5y9qsnlp0cdunwf9yjjx5c4q7ar9"
    )

    client = ZcashCommandSender(backend)
    path = "m/32'/133'/0'"

    with client.get_shielded_address_with_confirmation(
        path=path,
        transparent_path="m/44'/133'/0'/0/0",
        mode=GetShieldedAddressMode.UADDRESS,
    ):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().data
    orchard_address = unpack_len_prefixed_utf8_response(response)
    assert orchard_address == REF_ORCHARD_ADDRESS_ACC_0


def test_get_orchard_uaddress_confirm_refused(backend, scenario_navigator):
    client = ZcashCommandSender(backend)
    path = "m/32'/133'/0'"

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_shielded_address_with_confirmation(
            path=path,
            transparent_path="m/44'/133'/0'/0/0",
            mode=GetShieldedAddressMode.UADDRESS,
        ):
            scenario_navigator.address_review_reject()

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_get_orchard_uaddress_requires_transparent_path(backend):
    client = ZcashCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_shielded_address(path="m/32'/133'/0'", mode=GetShieldedAddressMode.UADDRESS)

    assert e.value.status == Errors.SW_APP_WRONG_APDU_LENGTH
    assert len(e.value.data) == 0


def test_get_orchard_uaddress_account_mismatch(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.GET_SHIELDED_ADDRESS,
            p1=P1.P1_GET_PUBLIC_KEY_NO_DISPLAY,
            p2=GetShieldedAddressMode.UADDRESS,
            data=pack_derivation_path("m/32'/133'/0'") + pack_derivation_path("m/44'/133'/1'/0/0"),
        )

    assert e.value.status == Errors.SW_INVALID_TRANSACTION
    assert len(e.value.data) == 0
