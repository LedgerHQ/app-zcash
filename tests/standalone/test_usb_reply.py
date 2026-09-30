"""USB replies and pending review regression tests."""
import concurrent.futures
import contextlib
import types
import socket
import pytest
from ragger.backend.speculos import SpeculosBackend
from ragger.utils import RAPDU
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase
from application_client.zcash_command_sender import ZcashCommandSender, Errors
from .test_pczt_ironwood import (
    PCZT_V6_GLOBAL, _mixed_real_and_dummy_ironwood_bundle,
)

VERSION = bytes.fromhex('e0c4000000')


def test_usb_reply_independent_of_new_ticker(backend):
    if not isinstance(backend, SpeculosBackend):
        pytest.skip("This test requires Speculos ticker control")
    expected = backend.exchange_raw(VERSION).data
    backend.pause_ticker()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        try:
            result = pool.submit(backend.exchange_raw, VERSION)
            assert result.result(timeout=2).data == expected
            for _ in range(8):
                result = pool.submit(backend.exchange_raw, VERSION)
                assert result.result(timeout=2).data == expected
        finally:
            # Resume before waiting for the worker, including on assertion failure.
            backend.resume_ticker()
    assert backend.exchange_raw(VERSION).data == expected


@pytest.fixture
def usb_stream(backend, monkeypatch):
    if not isinstance(backend, SpeculosBackend):
        pytest.skip("This overlap test uses the emulator APDU stream")
    # The HTTP transport owns one pending response per request. Use one TCP
    # reader so a rejected intruder cannot replace the outstanding review reply.
    with socket.create_connection(("127.0.0.1", backend._apdu_port), timeout=30) as stream:
        def read_exact(count):
            data = b""
            while len(data) < count:
                part = stream.recv(count - len(data))
                if not part:
                    raise EOFError("Emulator APDU stream closed")
                data += part
            return data

        def receive(self):
            size = int.from_bytes(read_exact(4), "big")
            assert size <= 4096
            answer = read_exact(size + 2)
            result = RAPDU(int.from_bytes(answer[-2:], "big"), answer[:-2])
            if self.is_raise_required(result):
                raise ExceptionRAPDU(result.status, result.data)
            return result

        def send(self, data=b""):
            stream.sendall(len(data).to_bytes(4, "big") + data)

        def exchange(self, data=b"", **kwargs):
            send(self, data)
            return receive(self)

        @contextlib.contextmanager
        def review(self, data=b""):
            self._last_async_response = None
            send(self, data)
            yield False
            self._last_async_response = receive(self)

        monkeypatch.setattr(backend, "exchange_raw", types.MethodType(exchange, backend))
        monkeypatch.setattr(backend, "exchange_async_raw", types.MethodType(review, backend))
        yield


@pytest.mark.parametrize('approve', [True, False])
def test_usb_reply_overlap_preserves_review(backend, scenario_navigator, usb_stream, approve):
    client = ZcashCommandSender(backend)
    def review():
        with client.send_pczt(
            pczt_global=PCZT_V6_GLOBAL, transparent_inputs=[], transparent_outputs=[],
            ironwood_bundle=_mixed_real_and_dummy_ironwood_bundle(),
        ):
            backend.wait_for_text_on_screen('Review transaction', timeout=20)
            for query in [lambda: backend.exchange_raw(VERSION), lambda: client.pczt_sign_ironwood(action_index=0)]:
                with pytest.raises(ExceptionRAPDU) as rejected:
                    query()
                assert rejected.value.status == 0x6901
                assert not rejected.value.data
            with pytest.raises(ExceptionRAPDU) as malformed:
                backend.exchange_raw(bytes.fromhex("e0c400000201"))
            assert malformed.value.status == Errors.SW_WRONG_APDU_LENGTH
            assert not malformed.value.data
            assert backend.exchange_raw(bytes.fromhex("b001000000")).status == 0x9000
            scenario = NavigationScenarioData(
                scenario_navigator.device, backend, UseCase.TX_REVIEW, approve,
            )
            if approve and scenario_navigator.device.touchable:
                # This app has no approval status screen (same as its fixture helper).
                scenario.validation = scenario.validation[:-1]
            scenario_navigator.navigator.navigate_until_text(
                navigate_instruction=scenario.navigation,
                validation_instructions=scenario.validation,
                text=scenario.pattern,
                timeout=20,
                # The explicit text wait above already consumed the first change.
                screen_change_before_first_instruction=False,
                screen_change_after_last_instruction=not approve,
            )
    if approve:
        review()
        assert len(client.pczt_sign_ironwood(action_index=0).data) == 64
    else:
        with pytest.raises(ExceptionRAPDU) as rejected:
            review()
        assert rejected.value.status == Errors.SW_DENY
        assert not rejected.value.data
        backend.wait_for_home_screen(timeout=10)
        with pytest.raises(ExceptionRAPDU) as denied:
            client.pczt_sign_ironwood(action_index=0)
        assert denied.value.status == Errors.SW_CONDITIONS_OF_USE_NOT_SATISFIED
        assert not denied.value.data
    # Both control and candidate have a transient post-sign status screen.
    # Check readiness after that screen rather than racing a new APDU into it.
    if approve:
        backend.wait_for_home_screen(timeout=10)
    assert backend.exchange_raw(VERSION).status == 0x9000



def test_address_reply_survives_overlapping_command(backend, scenario_navigator, usb_stream):
    client = ZcashCommandSender(backend)
    path = "m/44'/133'/0'/0/0"
    expected = client.get_public_key(path=path).data
    with client.get_public_key_with_confirmation(path=path):
        backend.wait_for_text_on_screen("Verify", timeout=20)
        with pytest.raises(ExceptionRAPDU) as rejected:
            backend.exchange_raw(VERSION)
        assert rejected.value.status == 0x6901
        assert not rejected.value.data
        scenario = NavigationScenarioData(
            scenario_navigator.device, backend, UseCase.ADDRESS_CONFIRMATION, True,
        )
        scenario_navigator.navigator.navigate_until_text(
            navigate_instruction=scenario.navigation,
            validation_instructions=scenario.validation,
            text=scenario.pattern,
            timeout=20,
            screen_change_before_first_instruction=False,
        )
    assert client.get_async_response().data == expected
