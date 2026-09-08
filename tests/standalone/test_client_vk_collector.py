"""Guards on the test client's viewing-key response collector.

These exercise the host side only, with a stub backend standing in for the device, because the
failure they cover is a host that never returns: a device announcing more bytes than it will send
used to keep the collector asking for continuations forever. A device test cannot reach that, since
the real app always delivers what it announces.
"""

import pytest
from application_client.zcash_command_sender import (
    MAX_APDU_LEN,
    MAX_VK_CONTINUATIONS,
    GetVkMode,
    ZcashCommandSender,
)
from ragger.backend.interface import RAPDU

SW_OK = 0x9000


class StubBackend:
    """Answers GET_VK continuations from a scripted list, and counts the calls."""

    def __init__(self, continuations: list[bytes]) -> None:
        self._continuations = list(continuations)
        self.exchanges = 0

    def exchange(self, **_kwargs) -> RAPDU:
        self.exchanges += 1
        if not self._continuations:
            # Standing in for a device that keeps answering an exhausted stream.
            return RAPDU(SW_OK, b"")
        return RAPDU(SW_OK, self._continuations.pop(0))


def _first_response(announced_len: int, payload: bytes) -> RAPDU:
    return RAPDU(SW_OK, announced_len.to_bytes(2, byteorder="big") + payload)


def test_collector_assembles_a_response_spanning_one_continuation():
    tail = b"\xbb" * 47
    backend = StubBackend([tail])
    client = ZcashCommandSender(backend)  # type: ignore[arg-type]

    head = b"\xaa" * MAX_APDU_LEN
    collected = client._collect_ufvk_response(  # pylint: disable=protected-access
        _first_response(MAX_APDU_LEN + len(tail), head), GetVkMode.UFVK
    )

    assert collected.data == (MAX_APDU_LEN + len(tail)).to_bytes(2, byteorder="big") + head + tail
    assert backend.exchanges == 1


def test_collector_refuses_a_length_beyond_what_it_will_assemble():
    backend = StubBackend([])
    client = ZcashCommandSender(backend)  # type: ignore[arg-type]

    announced = MAX_APDU_LEN * (MAX_VK_CONTINUATIONS + 1) + 1
    with pytest.raises(ValueError, match="beyond the"):
        client._collect_ufvk_response(  # pylint: disable=protected-access
            _first_response(announced, b"\xaa" * MAX_APDU_LEN), GetVkMode.UFVK
        )

    # Refused on the announcement alone: no continuation was ever sent.
    assert backend.exchanges == 0


def test_collector_stops_when_a_continuation_carries_nothing():
    backend = StubBackend([])
    client = ZcashCommandSender(backend)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="no data"):
        client._collect_ufvk_response(  # pylint: disable=protected-access
            _first_response(MAX_APDU_LEN + 10, b"\xaa" * MAX_APDU_LEN), GetVkMode.UFVK
        )

    assert backend.exchanges == 1


def test_collector_stops_when_continuations_never_complete_the_response():
    # Every continuation makes progress, so the empty-data guard never fires; only the
    # continuation ceiling ends this.
    backend = StubBackend([b"\x01"] * (MAX_VK_CONTINUATIONS + 5))
    client = ZcashCommandSender(backend)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="after"):
        client._collect_ufvk_response(  # pylint: disable=protected-access
            _first_response(MAX_APDU_LEN + 100, b"\xaa" * MAX_APDU_LEN), GetVkMode.UFVK
        )

    assert backend.exchanges == MAX_VK_CONTINUATIONS
