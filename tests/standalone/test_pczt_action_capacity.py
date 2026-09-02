# pylint: disable=C0301

"""How many Orchard actions a PCZT bundle can actually carry through parse, review and signing.

`MAX_PCZT_ORCHARD_ACTIONS_NUMBER` bounds the bundle, and the suite exercises that bound only from
the outside: a declared count above it is refused at the count packet, before one action is parsed.
Nothing asserts that a bundle *at* the bound goes through. These tests drive the whole flow at
several action counts, so the figure is backed by what the device does rather than by the constant
alone.

They answer two questions that need different builds. Up to the shipped bound, a released build
answers whether the bound in the code is one the device honours. Past it, only a build carrying the
`capacity_probe` feature answers where the device itself stops — the shipped bound cannot be
measured from behind, since it is what stops the run first.

Every action is the same real spend repeated. The device recomputes each action's `rk`, `cv_net`,
recipient and nullifier from the signing key, and holds no record of the nullifiers it has seen, so
repetition is accepted and keeps the action count the single variable: each action then costs the
parser the same work and the same signing record, and a failure at some count is a capacity result
rather than a property of one particular note.

Repeating a spend that pays an *external* recipient also makes this the expensive shape for the
review, which keeps one displayed output per action — a consolidation of many notes into one
recipient costs the device strictly less.
"""

from enum import StrEnum
from typing import NamedTuple

import pytest
from application_client.pczt import (
    PcztGlobal,
    PcztOrchardAction,
    PcztOrchardBundle,
    PcztTransparentOutput,
)
from application_client.zcash_command_sender import (
    Errors,
    ZcashCommandSender,
)
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

# Mirrors MAX_PCZT_ORCHARD_ACTIONS_NUMBER in src/consts.rs, the bound a released build carries.
_SHIPPED_MAX_ORCHARD_ACTIONS = 32

# Mirrors MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER: shielded outputs one transaction may show.
_MAX_SHIELDED_DISPLAYED_OUTPUTS = 4

# Counts a released build accepts. The powers of two below the bound show where a cost that grows
# with the action count starts to bite, which a single run at the bound cannot distinguish from a
# fixed one.
_SHIPPED_ACTION_COUNTS = [1, 2, 4, 8, 16, 24, _SHIPPED_MAX_ORCHARD_ACTIONS]

# Counts past the shipped bound, driven only by a build that raises it. The bound was set from these
# runs: 32 carried both wallet shapes, 48 did not.
_RAISED_ACTION_COUNTS = [48, 64]

_ALPHA = (1).to_bytes(32, byteorder="little")
_RK = bytes.fromhex("e95982b73ab0c2137ec354cce448a75ef39ec0cbdf6907be6df3495297834f89")
_SIGNING_PATH = "m/32'/133'/0'"
_ANCHOR = bytes.fromhex("c5e1408579e67cf16b5d19479408fa035a7db4fe3060123d139eba8523bc9633")

# Spends flag and outputs flag, the bundle shape a real spend needs.
_FLAGS = 3

# A real Orchard spend of the test seed's account 0 paying an external recipient, with the fields
# the device recomputes and checks. Its own end-to-end coverage lives in test_pczt.py; here it is
# the unit that gets repeated.
_SPEND_VALUE = 200000
_OUTPUT_VALUE = 180000
_ACTION_FIELDS = {
    "cv_net": "2bbcd0793d399b207b228ca760f2b51ac8d6866e2649b3c3ff1e67b454c5a6bf",
    "nullifier": "a554dda140773e5cdf5234e36227ab659452e8102d4de726c8a72fa182d94203",
    "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
    "spend_rho": "0700000000000000000000000000000000000000000000000000000000000000",
    "spend_rseed": "1b00000000000000000000000000000000000000000000000000000000000000",
    "cmx": "4b335e40a9dc718f353cb4d0e6614c59dd00fda6a37e704c08b2b8f3da1d9b1e",
    "ephemeral_key": "3f2ebdad40909b5114a62ae394fa47b03521a8e335ca83c0d8ab25b36593fd24",
    "enc_ciphertext": "061a91562732f49247090c3b9b62b76ac5c0e032362822f23416efc60c105aef10b0a7da0f85bbac92e4d3e3fcf5e366034081d9bec64d07dce0fef608c4f573ae37bf3fe54809903b0b93e27be25ef0853860f9711cad533b47d7cb4bf07677df752316252004a9a43880f45eb0dd99e1b16cfaf39ed94d7559a7057df6d12341c3e9450f9687b0bdec3c6a5028dc730b025b25e5481964d788cb827bf7b989835b56e41f448e42b3c55eb7a422cfdc49e32c97145f1820bf830571f349a807abac8c91f60ae21b676573d66a56ca2fe53fa7aebdb4f0076d618442c1bff1db245fc7597af34f081db5539036b73b7ab02435d1278efd359fccdd1f52151d3cc5f477f07120685cc3bf5efd23e99f31842b3234168c6b37d912f35cb0b847a1f5947212a4e2a5596f8b41a0d6442c5d3eb2ee679acc9e0b4507a806397f1efb5422d77459ea2509af8b360f1a973e1df62b4d849fd6ab3f90547f9a3c3cc0805609fd0cb6a560bd39a77c57e9796833ecf4d77b45f8450f7fe516ca82004b6601200ce39460b688002df97d50660b5e5026a784e2fa071ea81570ba5020f1d0f473fb269b806fdaeabad975345f20d9299fc2c005986037164b858a8deeff07932df5ef5a3a23676227b631161edfcfd0d2bd29aaddefb6ff2950e9ca7b7d23208dc80d25d2869ea80a149f8fae83d7cd03374ea71acaa0fddaca47dab649d81a99c32e67774c27723983886a67528a22d1a1d339dfbd6e81c11e83c9a17fee47439124fcfe5353aff39c2de30a1681ae3d2636c8c049ceab035cf9dbd396aa580dce3c",  # noqa: E501
    "out_ciphertext": "d6a12d5f0f1702bc0e6978fdf44779c741dea7c2b8cdf9bda2cf8780e440c838adc5f97076237d279044d859aa2efe4f0ea97a236ed869a351da9947a7717c00b3cb4d967086b9a05b5318b22b731ea8",  # noqa: E501
    "rcv": "4300000000000000000000000000000000000000000000000000000000000000",
    "rseed": "2f00000000000000000000000000000000000000000000000000000000000000",
    "recipient": "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
}


# A real Orchard spend whose Orchard output is a zero-valued dummy: the value leaves the shielded
# pool through a transparent output instead. Repeating it is the consolidation shape — the notes
# spent grow with the action count while the review keeps showing one recipient — which is what a
# wallet builds when it gathers several notes to pay one address.
_CONSOLIDATION_SPEND_VALUE = 300000
_CONSOLIDATION_ACTION_FIELDS = {
    "cv_net": "24631b59abdde690d7e6b62cfeac6619efb7753dc873d9dbfdd4af58f0c50e98",
    "nullifier": "2e552e9315c89ecbf8016a8dfaa325ef90dedc59df4b0a42e5ff5cee0bbed821",
    "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
    "spend_rho": "0400000000000000000000000000000000000000000000000000000000000000",
    "spend_rseed": "1800000000000000000000000000000000000000000000000000000000000000",
    "cmx": "f4f6493954ecd47be87e5fdebb99db614dfaf1825717f23c4b0438688d831a04",
    "ephemeral_key": "00" * 32,
    "enc_ciphertext": "00" * 580,
    "out_ciphertext": "00" * 80,
    "rcv": "4000000000000000000000000000000000000000000000000000000000000000",
    "rseed": "2c00000000000000000000000000000000000000000000000000000000000000",
    "recipient": "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a",
}
_CONSOLIDATION_ANCHOR = bytes.fromhex("699c780066f179ff12b26a5ec5b1af3d418eb0eadec3d3b18f10c91d97b33109")

# The single transparent recipient the consolidated value pays, and the only output its review
# shows whatever the action count.
_CONSOLIDATION_OUTPUT_VALUE = 290000
_CONSOLIDATION_OUTPUT_SCRIPT = bytes.fromhex("76a914424242424242424242424242424242424242424288ac")


def _consolidation_action() -> PcztOrchardAction:
    return PcztOrchardAction(
        cv_net=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["cv_net"]),
        nullifier=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["nullifier"]),
        spend_recipient=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["spend_recipient"]),
        spend_rho=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["spend_rho"]),
        spend_rseed=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["spend_rseed"]),
        rk=_RK,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["cmx"]),
        ephemeral_key=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["ephemeral_key"]),
        enc_ciphertext=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["enc_ciphertext"]),
        out_ciphertext=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["out_ciphertext"]),
        rcv=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["rcv"]),
        rseed=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["rseed"]),
        spend_value=_CONSOLIDATION_SPEND_VALUE,
        value=0,
        recipient=bytes.fromhex(_CONSOLIDATION_ACTION_FIELDS["recipient"]),
    )


def _consolidation_bundle(action_count: int) -> PcztOrchardBundle:
    return PcztOrchardBundle(
        actions=[_consolidation_action() for _ in range(action_count)],
        flags=_FLAGS,
        value_balance=action_count * _CONSOLIDATION_SPEND_VALUE,
        anchor=_CONSOLIDATION_ANCHOR,
    )


def _orchard_action() -> PcztOrchardAction:
    return PcztOrchardAction(
        cv_net=bytes.fromhex(_ACTION_FIELDS["cv_net"]),
        nullifier=bytes.fromhex(_ACTION_FIELDS["nullifier"]),
        spend_recipient=bytes.fromhex(_ACTION_FIELDS["spend_recipient"]),
        spend_rho=bytes.fromhex(_ACTION_FIELDS["spend_rho"]),
        spend_rseed=bytes.fromhex(_ACTION_FIELDS["spend_rseed"]),
        rk=_RK,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=bytes.fromhex(_ACTION_FIELDS["cmx"]),
        ephemeral_key=bytes.fromhex(_ACTION_FIELDS["ephemeral_key"]),
        enc_ciphertext=bytes.fromhex(_ACTION_FIELDS["enc_ciphertext"]),
        out_ciphertext=bytes.fromhex(_ACTION_FIELDS["out_ciphertext"]),
        rcv=bytes.fromhex(_ACTION_FIELDS["rcv"]),
        rseed=bytes.fromhex(_ACTION_FIELDS["rseed"]),
        spend_value=_SPEND_VALUE,
        value=_OUTPUT_VALUE,
        recipient=bytes.fromhex(_ACTION_FIELDS["recipient"]),
    )


def _repeated_orchard_bundle(action_count: int) -> PcztOrchardBundle:
    """Bundle of `action_count` copies of the same real spend.

    The device checks the bundle's declared value balance against the spend and output sums it
    accumulated, so the balance has to follow the action count.
    """
    return PcztOrchardBundle(
        actions=[_orchard_action() for _ in range(action_count)],
        flags=_FLAGS,
        value_balance=action_count * (_SPEND_VALUE - _OUTPUT_VALUE),
        anchor=_ANCHOR,
    )


# ── The z→z shape a wallet actually builds ─────────────────────────────────────
#
# Neither profile above is it. Consolidation shows no shielded output at all — its value leaves
# through a transparent one — and fan-out shows one per action, which no send flow produces:
# `mapOutputs` in coin-zcash emits exactly one recipient and the builder adds the change note. So a
# real z→z bundle of N actions carries one displayed recipient output, one hidden change output, and
# N-2 dummy outputs beside the notes being spent. That is the shape a raised bound has to clear.
#
# Assembled from vectors this suite already verifies end to end, because each action's `cv_net` binds
# its own spend and output values: an action cannot borrow the spend of one fixture and the output of
# another. Its consequence is that the value balance is whatever the repeated spends sum to, so the
# fee the review displays is not a realistic one — the *shape* is what this measures, not the
# economics.

# Real spend paying an external Orchard recipient: the one output the review displays.
_Z2Z_RECIPIENT_ACTION_FIELDS = {
    "cv_net": "2bbcd0793d399b207b228ca760f2b51ac8d6866e2649b3c3ff1e67b454c5a6bf",
    "nullifier": "a554dda140773e5cdf5234e36227ab659452e8102d4de726c8a72fa182d94203",
    "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
    "spend_rho": "0700000000000000000000000000000000000000000000000000000000000000",
    "spend_rseed": "1b00000000000000000000000000000000000000000000000000000000000000",
    "cmx": "4b335e40a9dc718f353cb4d0e6614c59dd00fda6a37e704c08b2b8f3da1d9b1e",
    "ephemeral_key": "3f2ebdad40909b5114a62ae394fa47b03521a8e335ca83c0d8ab25b36593fd24",
    "enc_ciphertext": "061a91562732f49247090c3b9b62b76ac5c0e032362822f23416efc60c105aef10b0a7da0f85bbac92e4d3e3fcf5e366034081d9bec64d07dce0fef608c4f573ae37bf3fe54809903b0b93e27be25ef0853860f9711cad533b47d7cb4bf07677df752316252004a9a43880f45eb0dd99e1b16cfaf39ed94d7559a7057df6d12341c3e9450f9687b0bdec3c6a5028dc730b025b25e5481964d788cb827bf7b989835b56e41f448e42b3c55eb7a422cfdc49e32c97145f1820bf830571f349a807abac8c91f60ae21b676573d66a56ca2fe53fa7aebdb4f0076d618442c1bff1db245fc7597af34f081db5539036b73b7ab02435d1278efd359fccdd1f52151d3cc5f477f07120685cc3bf5efd23e99f31842b3234168c6b37d912f35cb0b847a1f5947212a4e2a5596f8b41a0d6442c5d3eb2ee679acc9e0b4507a806397f1efb5422d77459ea2509af8b360f1a973e1df62b4d849fd6ab3f90547f9a3c3cc0805609fd0cb6a560bd39a77c57e9796833ecf4d77b45f8450f7fe516ca82004b6601200ce39460b688002df97d50660b5e5026a784e2fa071ea81570ba5020f1d0f473fb269b806fdaeabad975345f20d9299fc2c005986037164b858a8deeff07932df5ef5a3a23676227b631161edfcfd0d2bd29aaddefb6ff2950e9ca7b7d23208dc80d25d2869ea80a149f8fae83d7cd03374ea71acaa0fddaca47dab649d81a99c32e67774c27723983886a67528a22d1a1d339dfbd6e81c11e83c9a17fee47439124fcfe5353aff39c2de30a1681ae3d2636c8c049ceab035cf9dbd396aa580dce3c",  # noqa: E501
    "out_ciphertext": "d6a12d5f0f1702bc0e6978fdf44779c741dea7c2b8cdf9bda2cf8780e440c838adc5f97076237d279044d859aa2efe4f0ea97a236ed869a351da9947a7717c00b3cb4d967086b9a05b5318b22b731ea8",  # noqa: E501
    "rcv": "4300000000000000000000000000000000000000000000000000000000000000",
    "rseed": "2f00000000000000000000000000000000000000000000000000000000000000",
    "recipient": "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
}
_Z2Z_RECIPIENT_SPEND_VALUE = 200000
_Z2Z_RECIPIENT_OUTPUT_VALUE = 180000

# Change note returning to the signing account, kept off the review. Its spend side is dummy padding.
_Z2Z_CHANGE_ACTION_FIELDS = {
    "cv_net": "af7b9a0ad90cecf9dbcf08d1057da0bf8451a189cc8dfa758e1543cffb5edb97",
    "nullifier": "57aad2670e2e4df67ca855c53973db38e7942efa8e906ee961adb71955aa8423",
    "spend_recipient": "4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02",
    "spend_rho": "0800000000000000000000000000000000000000000000000000000000000000",
    "spend_rseed": "1c00000000000000000000000000000000000000000000000000000000000000",
    "cmx": "4d5af089ac858234d3472b545efe5796a609792d06bf18dbb8b3841ac0e9e031",
    "ephemeral_key": "92f7498c759a77b4065f9389d345c755ba241e68f0d8bf6d78f443257167d79f",
    "enc_ciphertext": "183f95348800b0c01daaa128c74ed5a4904024192330114b7b59460db6e332321425e9875e96bf7c1ba1bcb751ab6d8b494bd4b4e2587e177c9b083bf3a015a5879b69eaf2380c26d60501ff825be33eebc8ff3a86dfb04dd6fd1e814ea5e486148518ed256ea064267fbf9bc41ec6f8bf6da17b2bd9a81b42cb92dc398a5876333e64826b62a61dba4a5d9e740cdb6f0f1ac7e5f3bd8bff60c30088334491263b61f88b5e102eeb2d539ca32e45ce8600bcaf37368a2696528ee5e5cc52f8cf52df2c7e98f682ce6a4036527adce9f167df7f90200f3cdc9b451bdb4e36c3a46c2a2c42a0f0036161040267ef5dd267721db87f5b910dccf72afc67e059450db2b3df4789348ca72ddc5c310c4504c3779c5cca6a4ff94a73da8ee09dc06adc1856654b4be95e0adcf4510a0506b8b604bbd7fc340206728018f602060be3966cc0c91f601680b6e9e0f1132188cc217fef595b57c761b9292546d1dfe7148c42e4b8140cb364c23d1f0af6f794daf89c07927ea2d3be5f31ecf3f7d4dd973db806e3c0ef7cfb461848ba8562283c18c572f5e12d20ad8fff16cd0b58530501154a79458a28d2666707938915c95d854a3de8aee39a34d35c65a4e903b6135107726842ff150afa92243751606ec24fc0df246979f93c612a1f694b52863bb652226ceb520984aabda5c9fc60969589d9c894f3deceb448d04f3e61386430275eb4a64cacdf40704ccde93ae6573c1cd02b0bcfa689cf5de779cd2cf47ec13bb2e19c0d736fc0d0b7523b46487a1457e23dc1b473f1846475dc9544a81429c9caa51f3d",  # noqa: E501
    "out_ciphertext": "9f38b7e5c9bee88aa9be8bb44a386bd90fb6f915820f4a6469e120f2764774a3936e69063b514e83e587b9bd7b049d94d002c21dca9e8fa33b75aae1d584e8f4b77a0389e104596e2002aac2571fe384",  # noqa: E501
    "rcv": "4400000000000000000000000000000000000000000000000000000000000000",
    "rseed": "3000000000000000000000000000000000000000000000000000000000000000",
    "recipient": "ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a",
}
_Z2Z_CHANGE_OUTPUT_VALUE = 10000

_Z2Z_ANCHOR = bytes.fromhex("c5e1408579e67cf16b5d19479408fa035a7db4fe3060123d139eba8523bc9633")


def _action_from(fields: dict[str, str], spend_value: int, output_value: int) -> PcztOrchardAction:
    """Build an action from a verified field set, with `rk` and `alpha` this suite's signing key."""
    return PcztOrchardAction(
        cv_net=bytes.fromhex(fields["cv_net"]),
        nullifier=bytes.fromhex(fields["nullifier"]),
        spend_recipient=bytes.fromhex(fields["spend_recipient"]),
        spend_rho=bytes.fromhex(fields["spend_rho"]),
        spend_rseed=bytes.fromhex(fields["spend_rseed"]),
        rk=_RK,
        alpha=_ALPHA,
        signing_path=_SIGNING_PATH,
        cmx=bytes.fromhex(fields["cmx"]),
        ephemeral_key=bytes.fromhex(fields["ephemeral_key"]),
        enc_ciphertext=bytes.fromhex(fields["enc_ciphertext"]),
        out_ciphertext=bytes.fromhex(fields["out_ciphertext"]),
        rcv=bytes.fromhex(fields["rcv"]),
        rseed=bytes.fromhex(fields["rseed"]),
        spend_value=spend_value,
        value=output_value,
        recipient=bytes.fromhex(fields["recipient"]),
    )


def _z_to_z_bundle(action_count: int) -> PcztOrchardBundle:
    """A z→z bundle of `action_count` actions carrying `action_count - 1` real spends.

    One action pays the recipient, one carries the change note, and the rest spend a note against a
    dummy output. Only one change output is allowed, so the shape holds at every count.
    """
    if action_count < 2:
        raise ValueError("a z→z bundle needs a recipient action and a change action")

    spend_only_count = action_count - 2
    actions = [
        _action_from(_Z2Z_RECIPIENT_ACTION_FIELDS, _Z2Z_RECIPIENT_SPEND_VALUE, _Z2Z_RECIPIENT_OUTPUT_VALUE),
        *(
            _action_from(_CONSOLIDATION_ACTION_FIELDS, _CONSOLIDATION_SPEND_VALUE, 0)
            for _ in range(spend_only_count)
        ),
        _action_from(_Z2Z_CHANGE_ACTION_FIELDS, 0, _Z2Z_CHANGE_OUTPUT_VALUE),
    ]
    spend_sum = _Z2Z_RECIPIENT_SPEND_VALUE + spend_only_count * _CONSOLIDATION_SPEND_VALUE
    output_sum = _Z2Z_RECIPIENT_OUTPUT_VALUE + _Z2Z_CHANGE_OUTPUT_VALUE

    return PcztOrchardBundle(
        actions=actions,
        flags=_FLAGS,
        value_balance=spend_sum - output_sum,
        anchor=_Z2Z_ANCHOR,
    )


def _approve_review(scenario_navigator: NavigateWithScenario) -> None:
    """Walk the review to its end and approve it, without comparing screens.

    The screens are the same ones the shape-specific tests in test_pczt.py compare against golden
    snapshots; only their number changes here, so pinning a snapshot set per action count would
    guard nothing these tests are about and would grow the reference set with every count added.
    """
    scenario = NavigationScenarioData(
        scenario_navigator.device,
        scenario_navigator.backend,
        UseCase.TX_REVIEW,
        True,
    )

    if scenario_navigator.device.touchable:
        scenario.validation = scenario.validation[:-1]

    scenario_navigator.navigator.navigate_until_text(
        navigate_instruction=scenario.navigation,
        validation_instructions=scenario.validation,
        text=scenario.pattern,
        screen_change_after_last_instruction=False,
    )


class HeapProbe(NamedTuple):
    """What a measurement build reports about its heap and the bounds it was built with."""

    largest_free_block: int
    max_orchard_actions: int
    max_ironwood_actions: int


def _heap_probe(client: ZcashCommandSender) -> HeapProbe | None:
    """Read the device's heap probe, or None on a build that carries none.

    A build without the `heap_probe` cargo feature has no such instruction and refuses it, which is
    the expected answer rather than a failure — see test_heap_probe_absent_unless_measuring.
    """
    try:
        response = client.heap_probe()
    except ExceptionRAPDU as error:
        if error.status == Errors.SW_INS_NOT_SUPPORTED:
            return None
        raise

    assert len(response.data) == 8
    return HeapProbe(
        largest_free_block=int.from_bytes(response.data[0:4], byteorder="big"),
        max_orchard_actions=int.from_bytes(response.data[4:6], byteorder="big"),
        max_ironwood_actions=int.from_bytes(response.data[6:8], byteorder="big"),
    )


class Shape(StrEnum):
    """Which bundle shape a run drives; see each builder for what it costs the device."""

    # One displayed output per action. No send flow builds it — the expensive bound.
    FAN_OUT = "fan-out"
    # Notes gathered into one transparent recipient; no displayed shielded output.
    CONSOLIDATION = "consolidation"
    # One recipient, one hidden change note, the rest spends: what a z→z send builds.
    Z_TO_Z = "z-to-z"


def _drive_bundle(
    backend,
    scenario_navigator: NavigateWithScenario,
    action_count: int,
    shape: Shape = Shape.FAN_OUT,
) -> HeapProbe | None:
    """Parse, review and sign a bundle of `action_count` real spends; report the heap it left.

    The signatures are only checked for shape. Their correctness is what the shape-specific tests in
    test_pczt.py establish against known vectors, and cannot be restated here: the spend-auth
    signature covers a digest over the whole bundle, so it differs at every action count, and
    RedPallas draws a fresh nonce per signature, so two actions of one bundle do not agree either.
    """
    client = ZcashCommandSender(backend)

    transparent_outputs: list[PcztTransparentOutput] = []
    if shape is Shape.CONSOLIDATION:
        orchard_bundle = _consolidation_bundle(action_count)
        transparent_outputs = [
            PcztTransparentOutput(
                value=_CONSOLIDATION_OUTPUT_VALUE,
                script_pubkey=_CONSOLIDATION_OUTPUT_SCRIPT,
            )
        ]
    elif shape is Shape.Z_TO_Z:
        orchard_bundle = _z_to_z_bundle(action_count)
    else:
        orchard_bundle = _repeated_orchard_bundle(action_count)

    with client.send_pczt(
        pczt_global=PcztGlobal(),
        transparent_inputs=[],
        transparent_outputs=transparent_outputs,
        orchard_bundle=orchard_bundle,
    ):
        _approve_review(scenario_navigator)

    # Sampled here rather than after signing: the device releases the whole parser state as soon as
    # the last real spend is signed, so a later reading would report a fresh heap. Here the session
    # still holds every signing record, output and retained memo the bundle produced.
    probe = _heap_probe(client)

    # Only real spends are signed on device. A dummy padding spend (spend_value == 0) is signed
    # host-side by the PCZT IoFinalizer, and the device refuses its index outright — asking for one
    # both breaks the contract and strands the session, since the device completes signing as soon
    # as the real spends are done.
    signed = 0
    for action_index, action in enumerate(orchard_bundle.actions):
        if action.spend_value == 0:
            continue
        auth_sig = client.pczt_sign_orchard(action_index=action_index).data
        assert len(auth_sig) == 64, f"action {action_index} of {action_count}"
        signed += 1

    assert signed == sum(1 for action in orchard_bundle.actions if action.spend_value != 0)

    return probe


def _report(record_property, action_count: int, shape: Shape, probe: HeapProbe | None) -> None:
    if probe is None:
        return
    record_property("largest_free_heap_block", probe.largest_free_block)
    print(f"\n[capacity] {shape} actions={action_count} largest free heap block={probe.largest_free_block} B")


def test_pczt_shielded_display_budget_admits_its_full_count(
    backend,
    scenario_navigator: NavigateWithScenario,
    record_property,
):
    """A transaction showing exactly the budgeted number of shielded outputs goes through.

    The boundary from the accepting side: the budget is spent, not exceeded.
    """
    probe = _drive_bundle(backend, scenario_navigator, _MAX_SHIELDED_DISPLAYED_OUTPUTS)
    _report(record_property, _MAX_SHIELDED_DISPLAYED_OUTPUTS, Shape.FAN_OUT, probe)


def test_pczt_shielded_display_budget_refuses_one_output_too_many(backend):
    """One shielded output past the budget is refused with a status word, and nothing is signed.

    This is the boundary that matters. Before the budget existed, a bundle of this shape exhausted
    the heap somewhere around the ninth displayed output and the allocator's panic handler *exited
    the application* — no status word, the host left waiting on a device that had returned to its
    dashboard. Refusing here is what makes that failure closed and reportable.

    No wallet flow reaches it: `mapOutputs` in coin-zcash emits exactly one recipient, so this is a
    bundle only a buggy or hostile host builds. The device treats APDUs as untrusted input, which is
    why it must refuse rather than exit.
    """
    client = ZcashCommandSender(backend)
    over_budget = _repeated_orchard_bundle(_MAX_SHIELDED_DISPLAYED_OUTPUTS + 1)

    with pytest.raises(ExceptionRAPDU) as error:
        with client.send_pczt(
            pczt_global=PcztGlobal(),
            transparent_inputs=[],
            transparent_outputs=[],
            orchard_bundle=over_budget,
        ):
            pytest.fail("Device accepted more displayed shielded outputs than the budget allows")

    assert error.value.status == Errors.SW_NOT_ENOUGH_MEMORY_SPACE


@pytest.mark.parametrize("action_count", _SHIPPED_ACTION_COUNTS)
def test_pczt_orchard_consolidation_carries_its_declared_action_count(
    backend,
    scenario_navigator: NavigateWithScenario,
    action_count: int,
    record_property,
):
    """`action_count` notes gathered into one transparent recipient parse, review and sign.

    The shape a wallet builds when it spends several notes to pay one address, and the one the
    action bound decides for a user: every action past the first buys another note to spend, not
    another recipient to show.
    """
    probe = _drive_bundle(backend, scenario_navigator, action_count, shape=Shape.CONSOLIDATION)
    _report(record_property, action_count, Shape.CONSOLIDATION, probe)


@pytest.mark.parametrize("action_count", _RAISED_ACTION_COUNTS)
def test_pczt_orchard_consolidation_beyond_the_shipped_bound(
    backend,
    scenario_navigator: NavigateWithScenario,
    action_count: int,
    record_property,
):
    """Where consolidating more notes than the shipped bound stops working.

    Same instrument and same reading as the fan-out run beyond the bound; this is the shape the
    bound actually costs a user, so it is the one a raised bound has to clear.
    """
    probe = _heap_probe(ZcashCommandSender(backend))
    if probe is None:
        pytest.skip("application built without the heap_probe feature")
    if probe.max_orchard_actions <= _SHIPPED_MAX_ORCHARD_ACTIONS:
        pytest.skip(f"application bounds Orchard bundles at {probe.max_orchard_actions} actions")

    probe = _drive_bundle(backend, scenario_navigator, action_count, shape=Shape.CONSOLIDATION)
    _report(record_property, action_count, Shape.CONSOLIDATION, probe)


@pytest.mark.parametrize("action_count", [count for count in _SHIPPED_ACTION_COUNTS if count >= 2])
def test_pczt_orchard_z_to_z_carries_its_declared_action_count(
    backend,
    scenario_navigator: NavigateWithScenario,
    action_count: int,
    record_property,
):
    """The shape a z→z send builds, at every count a released build accepts.

    `action_count - 1` notes spent, one recipient shown, one change note hidden. This is the profile
    whose limit decides what a user can spend, so it is the one a bound must be set from.
    """
    probe = _drive_bundle(backend, scenario_navigator, action_count, shape=Shape.Z_TO_Z)
    _report(record_property, action_count, Shape.Z_TO_Z, probe)


@pytest.mark.parametrize("action_count", _RAISED_ACTION_COUNTS)
def test_pczt_orchard_z_to_z_beyond_the_shipped_bound(
    backend,
    scenario_navigator: NavigateWithScenario,
    action_count: int,
    record_property,
):
    """Where a z→z send larger than the shipped bound stops working."""
    probe = _heap_probe(ZcashCommandSender(backend))
    if probe is None:
        pytest.skip("application built without the heap_probe feature")
    if probe.max_orchard_actions <= _SHIPPED_MAX_ORCHARD_ACTIONS:
        pytest.skip(f"application bounds Orchard bundles at {probe.max_orchard_actions} actions")

    probe = _drive_bundle(backend, scenario_navigator, action_count, shape=Shape.Z_TO_Z)
    _report(record_property, action_count, Shape.Z_TO_Z, probe)


def test_pczt_orchard_bundle_above_the_bound_is_refused(backend):
    """One action past the build's own bound is refused, before any per-action allocation.

    Guards the bound from the other side than the tests above: raising it must move this rejection
    point with it, not remove it.
    """
    client = ZcashCommandSender(backend)
    probe = _heap_probe(client)
    bound = _SHIPPED_MAX_ORCHARD_ACTIONS if probe is None else probe.max_orchard_actions
    orchard_bundle = _repeated_orchard_bundle(bound + 1)

    with pytest.raises(ExceptionRAPDU) as error:
        with client.send_pczt(
            pczt_global=PcztGlobal(),
            transparent_inputs=[],
            transparent_outputs=[],
            orchard_bundle=orchard_bundle,
        ):
            pytest.fail("Device accepted a PCZT with more Orchard actions than the bound allows")

    assert error.value.status == Errors.SW_INVALID_TRANSACTION


def test_heap_probe_absent_unless_measuring(backend):
    """A released build answers nothing on the heap-probe instruction.

    The figure it returns moves with how many shielded outputs decrypted under the user's viewing
    key and how much memo text the review kept, which the wire format withholds on purpose. This is
    what keeps a measurement build from being shipped unnoticed; it is skipped on one, where the
    instruction answering is the point.
    """
    client = ZcashCommandSender(backend)

    try:
        response = client.heap_probe()
    except ExceptionRAPDU as error:
        assert error.status == Errors.SW_INS_NOT_SUPPORTED
        return

    pytest.skip(f"application built with the heap_probe feature (answered {len(response.data)} bytes)")
