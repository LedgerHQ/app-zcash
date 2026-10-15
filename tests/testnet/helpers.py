"""Navigation helpers shared by the testnet tests."""

from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

# OP_DUP OP_HASH160 <push 20> ... OP_EQUALVERIFY OP_CHECKSIG
P2PKH_SCRIPT_PREFIX = bytes.fromhex("76a914")
P2PKH_SCRIPT_SUFFIX = bytes.fromhex("88ac")


def p2pkh_script(pubkey_hash: bytes) -> bytes:
    return P2PKH_SCRIPT_PREFIX + pubkey_hash + P2PKH_SCRIPT_SUFFIX


def review_approve(
    scenario_navigator: NavigateWithScenario, snapshot_test_name: str | None, *, compare: bool = True
) -> None:
    """Approve a transaction review, comparing each screen with its snapshot unless told not to."""
    scenario = NavigationScenarioData(
        scenario_navigator.device,
        scenario_navigator.backend,
        UseCase.TX_REVIEW,
        True,
    )

    if scenario_navigator.device.touchable:
        scenario.validation = scenario.validation[:-1]

    if not compare:
        scenario_navigator.navigator.navigate_until_text(
            navigate_instruction=scenario.navigation,
            validation_instructions=scenario.validation,
            text=scenario.pattern,
            screen_change_after_last_instruction=False,
        )
        return

    scenario_navigator.navigator.navigate_until_text_and_compare(
        navigate_instruction=scenario.navigation,
        validation_instructions=scenario.validation,
        text=scenario.pattern,
        path=scenario_navigator.screenshot_path,
        test_case_name=snapshot_test_name,
        screen_change_after_last_instruction=False,
    )
