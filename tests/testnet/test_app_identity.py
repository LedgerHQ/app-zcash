from application_client.zcash_command_sender import ZcashCommandSender
from application_client.zcash_response_unpacker import unpack_get_app_and_version_response
from ragger.navigator import NavInsID


# The home screen of the testnet build names the app and says it is testnet-only.
def test_app_mainmenu_testnet(device, navigator, test_name, default_screenshot_path):
    if device.is_nano:
        instructions = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK]
    else:
        instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavInsID.USE_CASE_SUB_SETTINGS_EXIT,
        ]
    navigator.navigate_and_compare(
        default_screenshot_path,
        test_name,
        instructions,
        screen_change_before_first_instruction=False,
    )


# BOLOS answers with the name recorded in the binary's install parameters, so this shows the build
# variant's name reached the binary and not only the home screen.
def test_app_name_is_testnet(backend):
    client = ZcashCommandSender(backend)

    app_name, _ = unpack_get_app_and_version_response(client.get_app_and_version().data)

    assert app_name == "Zcash Test"
