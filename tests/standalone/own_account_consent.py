"""Answers to the consent screen shown before an output is checked against another account of the seed."""

from collections.abc import Callable

from ragger.navigator import NavigateWithScenario, NavInsID


def own_account_consent(scenario_navigator: NavigateWithScenario, approve: bool = True) -> Callable[[int], None]:
    """Navigate the consent screen for each prompted account, comparing it with its golden snapshots."""
    navigator = scenario_navigator.navigator

    def answer(account: int) -> None:
        snapshots = f"own_account_consent_{'allow' if approve else 'reject'}_account_{account}"
        if scenario_navigator.device.touchable:
            navigator.navigate_and_compare(
                path=scenario_navigator.screenshot_path,
                test_case_name=snapshots,
                instructions=[NavInsID.USE_CASE_CHOICE_CONFIRM if approve else NavInsID.USE_CASE_CHOICE_REJECT],
                screen_change_after_last_instruction=False,
            )
            return
        # The sub-message spans a varying number of pages ahead of `Allow` and `Reject`.
        navigator.navigate_until_text_and_compare(
            navigate_instruction=NavInsID.RIGHT_CLICK,
            validation_instructions=[NavInsID.BOTH_CLICK],
            text="^Allow$" if approve else "^Reject$",
            path=scenario_navigator.screenshot_path,
            test_case_name=snapshots,
            screen_change_after_last_instruction=False,
        )

    return answer
